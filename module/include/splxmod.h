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

/************************Change History*****************************/
/**
** Modify to support SLES kernel version 2.6.27
** Modify Date: 2009/10/30
** Modify By:   errik_zhang
**/

 /**
 ** Modify to support kernel version 3.0
 ** Modify Date: 2012/06/21
 ** Modify By:	 samir_bai@trendmicro.com.cn
 **/


#ifndef SPLXMOD_H
#define SPLXMOD_H

/* splxmod.h is used by kernel hook module only */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/list.h>
#include <asm/atomic.h>
#include "splxmodinfo.h"
#ifdef X86_64
#define __SPLX_X86_64
#define IA32_HOOK
#endif

#include <splx.h>


#define DEVICE_NAME          "splxdev"
#define CARDNAME	     "SPLXMOD: "

// add  by errik for debulog
#define PROC_NAME        "splx"
#define KHM_ENTRY        "khm_debug_level"
#define KHM_COMMS_ENTRY  "command_exclusion"
#define LOG_CLOSE         0
#define LOG_WARNING       1
#define LOG_COMMON        2
#define LOG_DEBUG         3
// add end

//TT224111 hook status

#define UN_HOOKED 0
#define IN_HOOK   1  //Means is doing hook or unhook
#define HOOKED    2

//End

#if LINUX_VERSION_CODE <= 0x20612
	#define DENTRY dentry
	#define MNT mnt

#else
	#define DENTRY \
		path.dentry
	#define MNT \
		path.mnt
#endif

/* DPRINTK should be coded in one line, otherwise garbage chars will show up */
#define CP_DBG_LVL	int	l_iDbgLevel; \
	spin_lock(&dbg_lock); \
	l_iDbgLevel = g_iDbgLevel; \
	spin_unlock(&dbg_lock)

#define DPRINTK(LOG_LEVEL, format, args...) \
	if (l_iDbgLevel >= LOG_LEVEL) printk(KERN_DEBUG CARDNAME format , ## args)
//end

#define WPRINTK(format, args...) \
	printk(KERN_WARNING CARDNAME format , ## args)

#if LINUX_VERSION_CODE >= 0x20600
#define	MOD_INC_REF_COUNT \
        try_module_get(THIS_MODULE)

#define	MOD_DEC_REF_COUNT \
        module_put(THIS_MODULE)
#else
#define	MOD_INC_REF_COUNT \
        atomic_inc(&ref_cnt)

#define	MOD_DEC_REF_COUNT \
        atomic_dec(&ref_cnt)
#endif

#if LINUX_VERSION_CODE >= 0x20600
#define	MOD_IN_REF \
        (module_refcount(THIS_MODULE) > 0)
#else
#define	MOD_IN_REF \
	(atomic_read(&ref_cnt) > 0)
#endif

#ifndef list_for_each_entry
#define list_for_each_entry(pos, head, member)                          \
        for (pos = list_entry((head)->next, typeof(*pos), member),      \
                     prefetch(pos->member.next);                        \
             &pos->member != (head);                                    \
             pos = list_entry(pos->member.next, typeof(*pos), member),  \
                     prefetch(pos->member.next))
#endif

#ifndef list_for_each_entry_safe
#define list_for_each_entry_safe(pos, n, head, member)                  \
        for (pos = list_entry((head)->next, typeof(*pos), member),      \
                n = list_entry(pos->member.next, typeof(*pos), member); \
             &pos->member != (head);                                    \
             pos = n, n = list_entry(n->member.next, typeof(*n), member))
#endif

/* Bits set in the FLAGS argument to `fnmatch'.  */
#define FNM_PATHNAME    (1 << 0) /* No wildcard can ever match `/'.  */
#define FNM_NOESCAPE    (1 << 1) /* Backslashes don't quote special chars.  */
#define FNM_PERIOD      (1 << 2) /* Leading `.' is matched only explicitly.  */

# define FNM_FILE_NAME   FNM_PATHNAME   /* Preferred GNU name.  */
# define FNM_LEADING_DIR (1 << 3)       /* Ignore `/...' after a match.  */
# define FNM_CASEFOLD    (1 << 4)       /* Compare without regard to case.  */
# define FNM_EXTMATCH    (1 << 5)       /* Use ksh-like extended matching. */

/* Value returned by `fnmatch' if STRING does not match PATTERN.  */
#define FNM_NOMATCH     1
#define FNM_MATCH       0


typedef struct {
        SCAN_ARGS		scan_args;
        Boolean			vsapi_busy;
        Boolean			candid;
        atomic_t		cond;
        struct dentry *         dentry;
        struct vfsmount *       mnt;
} LIST_ITEM_INFO;

typedef struct list_item {
        LIST_ITEM_INFO	info;
        struct list_head	item_list;
} LIST_ITEM;

typedef struct cache_item {
        ino_t           	inode;
        struct list_head        item_list;
} CACHE_ITEM;

typedef struct dentry_path {
	struct dentry *component;
	struct list_head dentry_list;
} dentry_path_t;


/*
 * 2.6.32 support. Currently only consider 2.6.32 but adding codes for 2.6.38 for future
 * support reference
 * The code for 2.6.38 is now disabled
 */
#if (LINUX_VERSION_CODE < 0x2061b)
#define OLD_SUPPORT
#elif (LINUX_VERSION_CODE >= 0x2061b && LINUX_VERSION_CODE < 0x20620)
#define SLES11
#elif (LINUX_VERSION_CODE >= 0x20620 && LINUX_VERSION_CODE < 0x20626)
#define SLES11SP1
#elif (LINUX_VERSION_CODE >= 0x20626)
#define FUTURE_SUPPORT
#endif

#if LINUX_VERSION_CODE >= 0x20620
#define SPLX_UID cred->uid
#else
#define SPLX_UID uid
#endif

//KHM Version Big release Version * 10000 + minor release version* 1000 + maintaince version
//3.0.1.0010
#define KHM_VERSION 30110
//Default commands that to bypass
#define DEF_EXC_COMM "vsapiapp;*syslog*;klogd;entity;splx*;AuPatch;sshd;SetTMDefaultExt"
//Currently, now support excveHook on x86_64
#ifdef SLES11SP1
#ifdef X86_64
#define SLES11SP1_64
#endif
#endif

#if (LINUX_VERSION_CODE >= 0x20620 && defined(X86_64))
#define USE_LSM_HOOK
#endif

#if defined (X86_64) && LINUX_VERSION_CODE >= 0x20610 && LINUX_VERSION_CODE <= 0x20612
#define USE_X86_64_PDA
#endif

#if LINUX_VERSION_CODE >= 0x20612
#define TASK_LIST_SPLX_LOCK rcu_read_lock()
#define TASK_LIST_SPLX_UNLOCK rcu_read_unlock()
#else
#define TASK_LIST_SPLX_LOCK read_lock(&tasklist_lock)
#define TASK_LIST_SPLX_UNLOCK read_unlock(&tasklist_lock)
#endif

//End
#endif
