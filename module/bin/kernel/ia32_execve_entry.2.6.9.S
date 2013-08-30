/* Kernel Hook Module for Trend Micro ServerProtect for Linux  */
/* Copyright (C) 2007 Trend Micro Incorporated.                */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 */
/*  ===========================================================================
 #  The following code section (macro and entry definitions) is copied from the
 #  linux/arch/x86_64/ia32/ia32entry.S file. The copied code section ensures 
 #  that the "ia32_sysret" label to be modified will work properly. Locate the
 #  corresponding code section from your Linux kernel source.
 #  ===========================================================================
 */

/*
 * Compatibility mode system call entry point for x86-64. 
 * 		
 * Copyright 2000-2002 Andi Kleen, SuSE Labs.
 */		 

#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/offset.h>
#include <asm/current.h>
#include <asm/errno.h>
#include <asm/ia32_unistd.h>	
#include <asm/thread_info.h>	
#include <asm/segment.h>
#include <asm/vsyscall32.h>
#include <linux/linkage.h>

	.macro PTREGSCALL label, func, arg
	.globl \label
\label:
	leaq \func(%rip),%rax
	leaq -ARGOFFSET+8(%rsp),\arg	/* 8 for return address */
	jmp  ia32_ptregs_common	
	.endm
        
/*  ===========================================================================
 #  Add the following line
 #  ===========================================================================
 */
        
	PTREGSCALL stub32_execveHook, IA32_execveHook, %rcx

ENTRY(ia32_ptregs_common)
	CFI_STARTPROC
	popq %r11
	SAVE_REST
	call *%rax
	RESTORE_REST
	jmp  ia32_sysret	/* misbalances the return cache */
	CFI_ENDPROC


/*  ===========================================================================
 #  The following code is copied from the "ia32_sysret" label in the 
 #  ia32entry.S file with the modification listed below:
 #   - Change the symbol "int_ret_from_sys_call" to "*p_int_ret_from_sys_call" 
 #  ===========================================================================
 */

ia32_sysret:
	movq %rax,RAX-ARGOFFSET(%rsp)
	jmp *p_int_ret_from_sys_call 

	
