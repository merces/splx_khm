/* Kernel Hook Module for Trend Micro ServerProtect for Linux  */
/* Copyright (C) 2012 Trend Micro Incorporated.                */

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

#ifndef __HOOK_IA32_H_INCLUDED__
#define __HOOK_IA32_H_INCLUDED__
#include <asm/compat.h>
extern asmlinkage long IA32_openHook(const char __user *filename, 
								int flags, int mode);
extern asmlinkage long IA32_closeHook(unsigned int fd);
extern asmlinkage long IA32_exitHook(int error_code);
extern asmlinkage long IA32_execveHook(char __user *name, compat_uptr_t __user *argv,
			     compat_uptr_t __user *envp, struct pt_regs *regs);

#if 0
asmlinkage long sys32_execve(char __user *name, compat_uptr_t __user *argv,
			     compat_uptr_t __user *envp, struct pt_regs *regs)
{
	long error;
	char * filename;

	filename = getname(name);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		return error;
	error = compat_do_execve(filename, argv, envp, regs);
	if (error == 0)
		current->ptrace &= ~PT_DTRACE;
	putname(filename);
	return error;
}
#endif

extern asmlinkage long (*IA32_orig_open)(const char *,int, int);
extern asmlinkage long (*IA32_orig_close)(unsigned int);
extern asmlinkage long (*IA32_orig_exit)(int);
extern asmlinkage long (*IA32_orig_execve)(char *, char __user * __user *,
									  char __user * __user *, struct pt_regs);
extern asmlinkage long (*IA32_orig_syscall)(void);
#if 0
extern int (*IA32_orig_compat_do_execve)(char * ,
							 char __user *,
							 char __user *,
							 struct pt_regs * );
#endif
extern long (*IA32_orig_compat_do_execve)(char __user *name, compat_uptr_t __user *,
			     compat_uptr_t __user *, struct pt_regs *);

/*
extern stub_execve_hook(char __user *name, char __user * __user *argv,
						char __user * __user *envp, struct pt_regs regs);
*/


#endif

