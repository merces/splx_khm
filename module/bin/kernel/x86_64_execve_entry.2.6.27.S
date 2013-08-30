/*
 *  linux/arch/x86_64/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002  Andi Kleen SuSE Labs
 *  Copyright (C) 2000  Pavel Machek <pavel@suse.cz>
 */

/*
 * entry.S contains the system-call and fault low-level handling routines.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after an interrupt and after each system call.
 * 
 * Normal syscalls and interrupts don't save a full stack frame, this is 
 * only done for syscall tracing, signals or fork/exec et.al.
 * 
 * A note on terminology:	 
 * - top of stack: Architecture defined interrupt frame from SS to RIP 
 * at the top of the kernel process stack.	
 * - partial stack frame: partially saved registers upto R11.
 * - full stack frame: Like partial stack frame, but all register saved. 
 *
 * Some macro usage:
 * - CFI macros are used to generate dwarf2 unwind information for better
 * backtraces. They don't change any code.
 * - SAVE_ALL/RESTORE_ALL - Save/restore all registers
 * - SAVE_ARGS/RESTORE_ARGS - Save/restore registers that C functions modify.
 * There are unfortunately lots of special cases where some registers
 * not touched. The macro is a big mess that should be cleaned up.
 * - SAVE_REST/RESTORE_REST - Handle the registers not saved by SAVE_ARGS.
 * Gives a full stack frame.
 * - ENTRY/END Define functions in the symbol table.
 * - FIXUP_TOP_OF_STACK/RESTORE_TOP_OF_STACK - Fix up the hardware stack
 * frame that is otherwise undefined after a SYSCALL
 * - TRACE_IRQ_* - Trace hard interrupt state for lock debugging.
 * - errorentry/paranoidentry/zeroentry - Define exception entry points.
 */

#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/asm-offsets.h>
#include <asm/msr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/hw_irq.h>
#include <asm/page.h>
#include <asm/irqflags.h>
#include <asm/paravirt.h>
#include <asm/ftrace.h>

/* Avoid __ASSEMBLER__'ifying <linux/audit.h> just for this.  */
#include <linux/elf-em.h>
#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_LE	   0x40000000

	.code64

#ifdef CONFIG_FTRACE
#ifdef CONFIG_DYNAMIC_FTRACE
ENTRY(mcount)

	subq $0x38, %rsp
	movq %rax, (%rsp)
	movq %rcx, 8(%rsp)
	movq %rdx, 16(%rsp)
	movq %rsi, 24(%rsp)
	movq %rdi, 32(%rsp)
	movq %r8, 40(%rsp)
	movq %r9, 48(%rsp)

	movq 0x38(%rsp), %rdi
	subq $MCOUNT_INSN_SIZE, %rdi

.globl mcount_call
mcount_call:
	call ftrace_stub

	movq 48(%rsp), %r9
	movq 40(%rsp), %r8
	movq 32(%rsp), %rdi
	movq 24(%rsp), %rsi
	movq 16(%rsp), %rdx
	movq 8(%rsp), %rcx
	movq (%rsp), %rax
	addq $0x38, %rsp

	retq
END(mcount)

ENTRY(ftrace_caller)

	/* taken from glibc */
	subq $0x38, %rsp
	movq %rax, (%rsp)
	movq %rcx, 8(%rsp)
	movq %rdx, 16(%rsp)
	movq %rsi, 24(%rsp)
	movq %rdi, 32(%rsp)
	movq %r8, 40(%rsp)
	movq %r9, 48(%rsp)

	movq 0x38(%rsp), %rdi
	movq 8(%rbp), %rsi
	subq $MCOUNT_INSN_SIZE, %rdi

.globl ftrace_call
ftrace_call:
	call ftrace_stub

	movq 48(%rsp), %r9
	movq 40(%rsp), %r8
	movq 32(%rsp), %rdi
	movq 24(%rsp), %rsi
	movq 16(%rsp), %rdx
	movq 8(%rsp), %rcx
	movq (%rsp), %rax
	addq $0x38, %rsp

.globl ftrace_stub
ftrace_stub:
	retq
END(ftrace_caller)

#else /* ! CONFIG_DYNAMIC_FTRACE */
ENTRY(mcount)
	cmpq $ftrace_stub, ftrace_trace_function
	jnz trace
.globl ftrace_stub
ftrace_stub:
	retq

trace:
	/* taken from glibc */
	subq $0x38, %rsp
	movq %rax, (%rsp)
	movq %rcx, 8(%rsp)
	movq %rdx, 16(%rsp)
	movq %rsi, 24(%rsp)
	movq %rdi, 32(%rsp)
	movq %r8, 40(%rsp)
	movq %r9, 48(%rsp)

	movq 0x38(%rsp), %rdi
	movq 8(%rbp), %rsi
	subq $MCOUNT_INSN_SIZE, %rdi

	call   *ftrace_trace_function

	movq 48(%rsp), %r9
	movq 40(%rsp), %r8
	movq 32(%rsp), %rdi
	movq 24(%rsp), %rsi
	movq 16(%rsp), %rdx
	movq 8(%rsp), %rcx
	movq (%rsp), %rax
	addq $0x38, %rsp

	jmp ftrace_stub
END(mcount)
#endif /* CONFIG_DYNAMIC_FTRACE */
#endif /* CONFIG_FTRACE */

#ifndef CONFIG_PREEMPT
#define retint_kernel retint_restore_args
#endif	

#ifdef CONFIG_PARAVIRT
ENTRY(native_usergs_sysret64)
	swapgs
	sysretq
#endif /* CONFIG_PARAVIRT */


.macro TRACE_IRQS_IRETQ offset=ARGOFFSET
#ifdef CONFIG_TRACE_IRQFLAGS
	bt   $9,EFLAGS-\offset(%rsp)	/* interrupts off? */
	jnc  1f
	TRACE_IRQS_ON
1:
#endif
.endm

/*
 * C code is not supposed to know about undefined top of stack. Every time 
 * a C function with an pt_regs argument is called from the SYSCALL based 
 * fast path FIXUP_TOP_OF_STACK is needed.
 * RESTORE_TOP_OF_STACK syncs the syscall state after any possible ptregs
 * manipulation.
 */        	
		
	/* %rsp:at FRAMEEND */ 
	.macro FIXUP_TOP_OF_STACK tmp
	movq	%gs:pda_oldrsp,\tmp
	movq  	\tmp,RSP(%rsp)
	movq    $__USER_DS,SS(%rsp)
	movq    $__USER_CS,CS(%rsp)
	movq 	$-1,RCX(%rsp)
	movq	R11(%rsp),\tmp  /* get eflags */
	movq	\tmp,EFLAGS(%rsp)
	.endm

	.macro RESTORE_TOP_OF_STACK tmp,offset=0
	movq   RSP-\offset(%rsp),\tmp
	movq   \tmp,%gs:pda_oldrsp
	movq   EFLAGS-\offset(%rsp),\tmp
	movq   \tmp,R11-\offset(%rsp)
	.endm

	.macro FAKE_STACK_FRAME child_rip
	/* push in order ss, rsp, eflags, cs, rip */
	xorl %eax, %eax
	pushq $__KERNEL_DS /* ss */
	CFI_ADJUST_CFA_OFFSET	8
	/*CFI_REL_OFFSET	ss,0*/
	pushq %rax /* rsp */
	CFI_ADJUST_CFA_OFFSET	8
	CFI_REL_OFFSET	rsp,0
	pushq $(1<<9) /* eflags - interrupts on */
	CFI_ADJUST_CFA_OFFSET	8
	/*CFI_REL_OFFSET	rflags,0*/
	pushq $__KERNEL_CS /* cs */
	CFI_ADJUST_CFA_OFFSET	8
	/*CFI_REL_OFFSET	cs,0*/
	pushq \child_rip /* rip */
	CFI_ADJUST_CFA_OFFSET	8
	CFI_REL_OFFSET	rip,0
	pushq	%rax /* orig rax */
	CFI_ADJUST_CFA_OFFSET	8
	.endm

	.macro UNFAKE_STACK_FRAME
	addq $8*6, %rsp
	CFI_ADJUST_CFA_OFFSET	-(6*8)
	.endm

	.macro	CFI_DEFAULT_STACK start=1
	.if \start
	CFI_STARTPROC	simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA	rsp,SS+8
	.else
	CFI_DEF_CFA_OFFSET SS+8
	.endif
	CFI_REL_OFFSET	r15,R15
	CFI_REL_OFFSET	r14,R14
	CFI_REL_OFFSET	r13,R13
	CFI_REL_OFFSET	r12,R12
	CFI_REL_OFFSET	rbp,RBP
	CFI_REL_OFFSET	rbx,RBX
	CFI_REL_OFFSET	r11,R11
	CFI_REL_OFFSET	r10,R10
	CFI_REL_OFFSET	r9,R9
	CFI_REL_OFFSET	r8,R8
	CFI_REL_OFFSET	rax,RAX
	CFI_REL_OFFSET	rcx,RCX
	CFI_REL_OFFSET	rdx,RDX
	CFI_REL_OFFSET	rsi,RSI
	CFI_REL_OFFSET	rdi,RDI
	CFI_REL_OFFSET	rip,RIP
	/*CFI_REL_OFFSET	cs,CS*/
	/*CFI_REL_OFFSET	rflags,EFLAGS*/
	CFI_REL_OFFSET	rsp,RSP
	/*CFI_REL_OFFSET	ss,SS*/
	.endm
/*
 * A newly forked process directly context switches into this.
 */ 	
/* rdi:	prev */	


/*
 * System call entry. Upto 6 arguments in registers are supported.
 *
 * SYSCALL does not save anything on the stack and does not change the
 * stack pointer.
 */
		
/*
 * Register setup:	
 * rax  system call number
 * rdi  arg0
 * rcx  return address for syscall/sysret, C arg3 
 * rsi  arg1
 * rdx  arg2	
 * r10  arg3 	(--> moved to rcx for C)
 * r8   arg4
 * r9   arg5
 * r11  eflags for syscall/sysret, temporary for C
 * r12-r15,rbp,rbx saved by C code, not touched. 		
 * 
 * Interrupts are off on entry.
 * Only called from user space.
 *
 * XXX	if we had a free scratch register we could save the RSP into the stack frame
 *      and report it properly in ps. Unfortunately we haven't.
 *
 * When user can change the frames always force IRET. That is because
 * it deals with uncanonical addresses better. SYSRET has trouble
 * with them due to bugs in both AMD and Intel CPUs.
 */ 			 		


	
ENTRY(execveHook)
	CFI_STARTPROC
	popq %r11
	CFI_ADJUST_CFA_OFFSET -8
	CFI_REGISTER rip, r11
	SAVE_REST
	FIXUP_TOP_OF_STACK %r11
	movq %rsp, %rcx
	call execveHook_X86_64
	RESTORE_TOP_OF_STACK %r11
	movq %rax,RAX(%rsp)
	RESTORE_REST
	jmp *p_int_ret_from_sys_call
	CFI_ENDPROC
END(execveHook)
	

/*
 * initial frame state for interrupts and exceptions
 */
	.macro _frame ref
	CFI_STARTPROC simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA rsp,SS+8-\ref
	/*CFI_REL_OFFSET ss,SS-\ref*/
	CFI_REL_OFFSET rsp,RSP-\ref
	/*CFI_REL_OFFSET rflags,EFLAGS-\ref*/
	/*CFI_REL_OFFSET cs,CS-\ref*/
	CFI_REL_OFFSET rip,RIP-\ref
	.endm

/* initial frame state for interrupts (and exceptions without error code) */
#define INTR_FRAME _frame RIP
/* initial frame state for exceptions with error code (and interrupts with
   vector already pushed) */
#define XCPT_FRAME _frame ORIG_RAX

/* 
 * Interrupt entry/exit.
 *
 * Interrupt entry points save only callee clobbered registers in fast path.
 *	
 * Entry runs with interrupts off.	
 */ 

/* 0(%rsp): interrupt number */ 
	.macro interrupt func
	cld
	SAVE_ARGS
	leaq -ARGOFFSET(%rsp),%rdi	# arg1 for handler
	pushq %rbp 
	CFI_ADJUST_CFA_OFFSET	8
	CFI_REL_OFFSET		rbp, 0
	movq %rsp,%rbp
	CFI_DEF_CFA_REGISTER	rbp
	testl $3,CS(%rdi)
	je 1f
	SWAPGS
	/* irqcount is used to check if a CPU is already on an interrupt
	   stack or not. While this is essentially redundant with preempt_count
	   it is a little cheaper to use a separate counter in the PDA
	   (short of moving irq_enter into assembly, which would be too
	    much work) */
1:	incl	%gs:pda_irqcount
	cmoveq %gs:pda_irqstackptr,%rsp
	push    %rbp			# backlink for old unwinder
	/*
	 * We entered an interrupt context - irqs are off:
	 */
	TRACE_IRQS_OFF
	call \func
	.endm




