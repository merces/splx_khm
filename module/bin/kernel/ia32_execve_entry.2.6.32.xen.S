/*
 * Compatibility mode system call entry point for x86-64. 
 * 		
 * Copyright 2000-2002 Andi Kleen, SuSE Labs.
 */		 

#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/asm-offsets.h>
#include <asm/current.h>
#include <asm/errno.h>
#include <asm/ia32_unistd.h>	
#include <asm/thread_info.h>	
#include <asm/segment.h>
#include <asm/irqflags.h>
#include <linux/linkage.h>

/* Avoid __ASSEMBLER__'ifying <linux/audit.h> just for this.  */
#include <linux/elf-em.h>
#define AUDIT_ARCH_I386		(EM_386|__AUDIT_ARCH_LE)
#define __AUDIT_ARCH_LE	   0x40000000

#define IA32_NR_syscalls ((ia32_syscall_end - ia32_sys_call_table)/8)

	.macro IA32_ARG_FIXUP noebp=0
	movl	%edi,%r8d
	.if \noebp
	jmp	ia32_common
	.else
	movl	%ebp,%r9d
ia32_common:
	.endif
	xchg	%ecx,%esi
	movl	%ebx,%edi
	movl	%edx,%edx	/* zero extension */
	.endm 

	/* clobbers %eax */	
	.macro  CLEAR_RREGS offset=0, _r9=rax
	xorl 	%eax,%eax
	movq	%rax,\offset+R11(%rsp)
	movq	%rax,\offset+R10(%rsp)
	movq	%\_r9,\offset+R9(%rsp)
	movq	%rax,\offset+R8(%rsp)
	.endm

	/*
	 * Reload arg registers from stack in case ptrace changed them.
	 * We don't reload %eax because syscall_trace_enter() returned
	 * the value it wants us to use in the table lookup.
	 */
	.macro LOAD_ARGS32 offset, _r9=0
	.if \_r9
	movl \offset+16(%rsp),%r9d
	.endif
	movl \offset+40(%rsp),%ecx
	movl \offset+48(%rsp),%edx
	movl \offset+56(%rsp),%esi
	movl \offset+64(%rsp),%edi
	.endm
	.macro CFI_STARTPROC32 simple
	CFI_STARTPROC	\simple
	CFI_UNDEFINED	r8
	CFI_UNDEFINED	r9
	CFI_UNDEFINED	r10
	CFI_UNDEFINED	r11
	CFI_UNDEFINED	r12
	CFI_UNDEFINED	r13
	CFI_UNDEFINED	r14
	CFI_UNDEFINED	r15
	.endm

	.macro PTREGSCALL label, func, arg
	.globl \label
\label:
	leaq \func(%rip),%rax
	leaq -ARGOFFSET+8(%rsp),\arg	/* 8 for return address */
	jmp  ia32_ptregs_common	
	.endm

	CFI_STARTPROC32


	//PTREGSCALL stub32_execve, sys32_execve, %rcx
    PTREGSCALL stub32_execveHook, IA32_execveHook, %rcx

ENTRY(ia32_ptregs_common)
	popq %r11
	CFI_ENDPROC
	CFI_STARTPROC32	simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA	rsp,SS+8-ARGOFFSET
	CFI_REL_OFFSET	rax,RAX-ARGOFFSET
	CFI_REL_OFFSET	rcx,RCX-ARGOFFSET
	CFI_REL_OFFSET	rdx,RDX-ARGOFFSET
	CFI_REL_OFFSET	rsi,RSI-ARGOFFSET
	CFI_REL_OFFSET	rdi,RDI-ARGOFFSET
	CFI_REL_OFFSET	rip,RIP-ARGOFFSET
/*	CFI_REL_OFFSET	cs,CS-ARGOFFSET*/
/*	CFI_REL_OFFSET	rflags,EFLAGS-ARGOFFSET*/
	CFI_REL_OFFSET	rsp,RSP-ARGOFFSET
/*	CFI_REL_OFFSET	ss,SS-ARGOFFSET*/
	SAVE_REST
	call *%rax
	RESTORE_REST
	jmp  ia32_sysret	/* misbalances the return cache */
	CFI_ENDPROC
END(ia32_ptregs_common)

/*  ===========================================================================
 #  The following code is copied from the "ia32_sysret" label in the 
 #  ia32entry.S file with the modification listed below:
 #   - Change the symbol "int_ret_from_sys_call" to "*p_int_ret_from_sys_call" 
 #  ===========================================================================
 */
ia32_sysret:
	movq %rax,RAX-ARGOFFSET(%rsp)
	CLEAR_RREGS -ARGOFFSET
	jmp *p_int_ret_from_sys_call 

