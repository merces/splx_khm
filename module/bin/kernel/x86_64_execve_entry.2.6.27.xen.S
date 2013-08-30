/*
 *  linux/arch/x86_64/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002  Andi Kleen SuSE Labs
 *  Copyright (C) 2000  Pavel Machek <pavel@suse.cz>
 *  Jun Nakajima <jun.nakajima@intel.com>
 *  Asit Mallick <asit.k.mallick@intel.com>
 *      Modified for Xen
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
#include <asm/ftrace.h>
#include <asm/errno.h>
#include <xen/interface/xen.h>
#include <xen/interface/features.h>

/* Avoid __ASSEMBLER__'ifying <linux/audit.h> just for this.  */
#include <linux/elf-em.h>
#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_LE	   0x40000000

	.code64

#ifdef CONFIG_FTRACE
#ifdef CONFIG_DYNAMIC_FTRACE

#endif /* CONFIG_DYNAMIC_FTRACE */
#endif /* CONFIG_FTRACE */

#ifndef CONFIG_PREEMPT
#define retint_kernel retint_restore_args
#endif	
.macro TRACE_IRQS_IRETQ offset=ARGOFFSET
#ifdef CONFIG_TRACE_IRQFLAGS
	bt   $9,EFLAGS-\offset(%rsp)	/* interrupts off? */
	jnc  1f
	TRACE_IRQS_ON
1:
#endif
.endm

NMI_MASK = 0x80000000
	
/*
 * C code is not supposed to know about undefined top of stack. Every time 
 * a C function with an pt_regs argument is called from the SYSCALL based 
 * fast path FIXUP_TOP_OF_STACK is needed.
 * RESTORE_TOP_OF_STACK syncs the syscall state after any possible ptregs
 * manipulation.
 */        	
		
	/* %rsp:at FRAMEEND */ 
	.macro FIXUP_TOP_OF_STACK tmp
	movq    $__USER_CS,CS(%rsp)
	movq 	$-1,RCX(%rsp)
	.endm

	.macro RESTORE_TOP_OF_STACK tmp,offset=0
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

	.macro	CFI_DEFAULT_STACK start=1,adj=0
	.if \start
	CFI_STARTPROC	simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA	rsp,SS+8 - \adj*ARGOFFSET
	.else
	CFI_DEF_CFA_OFFSET SS+8 - \adj*ARGOFFSET
	.endif
	.if \adj == 0
	CFI_REL_OFFSET	r15,R15
	CFI_REL_OFFSET	r14,R14
	CFI_REL_OFFSET	r13,R13
	CFI_REL_OFFSET	r12,R12
	CFI_REL_OFFSET	rbp,RBP
	CFI_REL_OFFSET	rbx,RBX
	.endif
	CFI_REL_OFFSET	r11,R11 - \adj*ARGOFFSET
	CFI_REL_OFFSET	r10,R10 - \adj*ARGOFFSET
	CFI_REL_OFFSET	r9,R9 - \adj*ARGOFFSET
	CFI_REL_OFFSET	r8,R8 - \adj*ARGOFFSET
	CFI_REL_OFFSET	rax,RAX - \adj*ARGOFFSET
	CFI_REL_OFFSET	rcx,RCX - \adj*ARGOFFSET
	CFI_REL_OFFSET	rdx,RDX - \adj*ARGOFFSET
	CFI_REL_OFFSET	rsi,RSI - \adj*ARGOFFSET
	CFI_REL_OFFSET	rdi,RDI - \adj*ARGOFFSET
	CFI_REL_OFFSET	rip,RIP - \adj*ARGOFFSET
	/*CFI_REL_OFFSET	cs,CS - \adj*ARGOFFSET*/
	/*CFI_REL_OFFSET	rflags,EFLAGS - \adj*ARGOFFSET*/
	CFI_REL_OFFSET	rsp,RSP - \adj*ARGOFFSET
	/*CFI_REL_OFFSET	ss,SS - \adj*ARGOFFSET*/
	.endm

        /*
         * Must be consistent with the definition in arch-x86/xen-x86_64.h:
         *     struct iret_context {
         *        u64 rax, r11, rcx, flags, rip, cs, rflags, rsp, ss;
         *     };
         * with rax, r11, and rcx being taken care of in the hypercall stub.
         */
	.macro HYPERVISOR_IRET flag
	testb $3,1*8(%rsp)
	jnz   2f
	testl $NMI_MASK,2*8(%rsp)
	jnz   2f

	cmpb  $0,(xen_features+XENFEAT_supervisor_mode_kernel)(%rip)
	jne   1f

	/* Direct iret to kernel space. Correct CS and SS. */
	orl   $3,1*8(%rsp)
	orl   $3,4*8(%rsp)
1:	iretq

2:	/* Slow iret via hypervisor. */
	andl  $~NMI_MASK, 2*8(%rsp)
	pushq $\flag
	jmp  hypercall_page + (__HYPERVISOR_iret * 32)
	.endm

/*  ===========================================================================
 #  The following code section is copied from the "stub_execve" entry in the
 #  entry.S file with the modifications listed below:
 #  - Change the entry name "stub_execve" to "execveHook"
 #  - Change the call of "sys_execve" to "execveHook_X86_64"
 #  - Change the symbol "int_ret_from_sys_call" to "*p_int_ret_from_sys_call"
 #  ===========================================================================
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

