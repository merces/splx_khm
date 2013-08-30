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

#ifndef __HOOK_X86_64_H_INCLUDED__
#define __HOOK_X86_64_H_INCLUDED__
extern asmlinkage long openHook(const char __user *filename, 
								int flags, int mode);
extern asmlinkage long closeHook(unsigned int fd);
extern asmlinkage long exitHook(int error_code);
extern asmlinkage long (*orig_open)(const char *,int, int);
extern asmlinkage long (*orig_close)(unsigned int);
extern asmlinkage long (*orig_exit)(int);
extern asmlinkage long (*orig_execve)(char *, char __user * __user *,
									  char __user * __user *, struct pt_regs);
extern asmlinkage long (*orig_syscall)(void);
extern asmlinkage long (*orig_getpgid)(pid_t);
extern int (*orig_do_execve)(char * ,
							 char __user *__user *,
							 char __user *__user *,
							 struct pt_regs * );
extern stub_execve_hook(char __user *name, char __user * __user *argv,
						char __user * __user *envp, struct pt_regs regs);
#endif

