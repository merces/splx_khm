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

/* 
 * This file contains the system call numbers of the ia32 port, 
 * beacuse linux kernel have not list all of ia32 port in ia32_unistd.h from 2.6.18,
 * so we only add syscalls here where hook module need to know the number.
 * This should be otherwise in sync with asm-i386/unistd.h. 
*/

#ifndef SPLXMOD_IA32_UNISTD_H
#define SPLXMOD_IA32_UNISTD_H
#include	<asm/ia32_unistd.h>

#ifndef __NR_ia32_exit
#define __NR_ia32_exit		  1
#endif

#ifndef __NR_ia32_open
#define __NR_ia32_open		  5
#endif

#ifndef __NR_ia32_close
#define __NR_ia32_close		  6
#endif

#ifndef __NR_ia32_execve
#define __NR_ia32_execve		 11
#endif


#endif

