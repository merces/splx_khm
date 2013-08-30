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
#include <linux/stringify.h>
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
#include <asm/page_types.h>
#include <asm/irqflags.h>
#include <asm/paravirt.h>
#include <asm/ftrace.h>
#include <asm/percpu.h>
/* Avoid __ASSEMBLER__'ifying <linux/audit.h> just for this.  */
#include <linux/elf-em.h>
#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_LE	   0x40000000
	.code64

/*
 * C code is not supposed to know about undefined top of stack. Every time
 * a C function with an pt_regs argument is called from the SYSCALL based
 * fast path FIXUP_TOP_OF_STACK is needed.
 * RESTORE_TOP_OF_STACK syncs the syscall state after any possible ptregs
 * manipulation.
 */

	/* %rsp:at FRAMEEND */

//	.macro FIXUP_TOP_OF_STACK tmp offset=0
//	movq PER_CPU_VAR(old_rsp),\tmp
//	movq \tmp,RSP+\offset(%rsp)
//	movq $__USER_DS,SS+\offset(%rsp)
//	movq $__USER_CS,CS+\offset(%rsp)
//	movq $-1,RCX+\offset(%rsp)
//	movq R11+\offset(%rsp),\tmp  /* get eflags */
//	movq \tmp,EFLAGS+\offset(%rsp)
//	.endm

//	.macro RESTORE_TOP_OF_STACK tmp offset=0
//	movq RSP+\offset(%rsp),\tmp
//	movq \tmp,PER_CPU_VAR(old_rsp)
//	movq EFLAGS+\offset(%rsp),\tmp
//	movq \tmp,R11+\offset(%rsp)
//	.endm


/*
 * Copy from stub_execve
 *ENTRY(stub_execve)
 * 	CFI_STARTPROC
 *	popq %r11
 *	CFI_ADJUST_CFA_OFFSET -8
 *	CFI_REGISTER rip, r11
 *	SAVE_REST
 *	FIXUP_TOP_OF_STACK %r11
 *	movq %rsp, %rcx
 *	call sys_execve
 *	RESTORE_TOP_OF_STACK %r11
 *	movq %rax,RAX(%rsp)
 *	RESTORE_REST
 *	jmp int_ret_from_sys_call
 *	CFI_ENDPROC
 *END(stub_execve)
 */

//Not support execveHook on x86_64 platform for non-xen kernel 2.6.32+
//The reason is per_cpu__oldrsp can't be accessed
ENTRY(execveHook)
	CFI_STARTPROC
	popq %r11
	CFI_ADJUST_CFA_OFFSET -8
	CFI_REGISTER rip, r11
	SAVE_REST
	//FIXUP_TOP_OF_STACK %r11
	movq %rsp, %rcx
	call execveHook_X86_64
	//RESTORE_TOP_OF_STACK %r11
	movq %rax,RAX(%rsp)
	RESTORE_REST
	jmp *p_int_ret_from_sys_call
	CFI_ENDPROC
END(execveHook)

