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
 ** Modify By:	 errik_zhang
 **/
 
 /**
 ** Modify to Add support for command bypass
 ** Proc entry: /proc/splx/comm_exc_list
 ** Modify Date: 2010/01/15
 ** Modify By: errik_zhang@trendmicro.com
 **/
 
 /**
 ** Modify to resolve the confliction with auditd
 ** Function ClearAuditContext() To clear audit flag
 ** Function SetAuditContext() to setback audit flag
 ** Modify Date: 2010/02/01
 **/
 
 /**
 ** Modify to resolve the dead lock issue caused by kini_lock
 ** Modify Date: 2012/02/28
 ** Modify By:	 samir_bai@trendmicro.com.cn
 **/

 /**
 ** Modify to support kernel version 3.0
 ** Modify Date: 2012/06/21
 ** Modify By:	 samir_bai@trendmicro.com.cn
 **/

  /**
 ** Modify to reslove illegal access caused by list
 ** add a reference conut "Del_list" to synchro
 ** Modify Date: 2013/03/15
 ** Modify By:	 rainbow_zhou@trendmicro.com.cn
 **/

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#include <linux/config.h> /* retrieve the CONFIG_* macros */
#if defined(CONFIG_SMP)
#define __SMP__
#endif
#endif

#if LINUX_VERSION_CODE < 0x20600
#if defined(CONFIG_MODVERSIONS) && !defined(MODVERSIONS)
#       define MODVERSIONS /* force it on */
#endif

#ifdef MODVERSIONS
#       include <linux/modversions.h>
#endif
#define __NO_VERSION__ /* don't define kernel_version in module.h */
#endif
#include <linux/module.h>

#include        <linux/kernel.h>
#include        <linux/fs.h>
#include        <linux/fs_struct.h>
#include        <linux/slab.h>

#include	<asm/uaccess.h>
#include	<linux/string.h>
#include        <linux/spinlock.h>
#include        <linux/delay.h>
#include        <linux/sched.h>
#include	<linux/mount.h>
#include	<splxmod.h>

#ifdef USE_X86_64_PDA
#include <asm-x86_64/pda.h>
#endif
#define STRLEN_USER(str) strnlen_user(str, ~0UL >> 1)

extern int	splxmod_debug;
extern int	g_iDbgLevel;
extern long busy_timeout_HZ;
extern long scan_timeout_HZ;
//Add for SLES11 Support
extern struct task_struct * splx_find_task_by_pid(pid_t nr);
//Add end
extern void parseAddDirs(char *);
extern void parseAddExts(char *);
extern void parseAddExcDirs(char *);
extern void parseAddExcFils(char *);
extern void parseAddExcExts(char *);
extern void parseAddExcComms(char *);
extern Boolean findListCandid(pid_t, unsigned int, LIST_ITEM **);
extern void wakeupItemBusy(void);
extern void wakeupItemCandid(void);
extern Boolean initialized(void);
extern wait_queue_head_t vsapi_chldn_wq;
extern void insertAry(pid_t *, pid_t, int *, int);
extern void deleteAry(pid_t *, pid_t, int *);
extern int dir_item_no;
extern int ext_item_no;
extern int exc_dir_item_no;
extern int exc_fil_item_no;
extern int exc_ext_item_no;
extern void removeCacheAll(void);
//extern long INTERRUPTIBLE_SLEEP_ON_TIMEOUT(wait_queue_head_t *, signed long);
#if LINUX_VERSION_CODE < 0x20612
extern void SET_FS_PWD(struct fs_struct *fs, struct vfsmount *mnt, struct dentry *dentry);
#endif
extern spinlock_t dbg_lock;
#ifdef X86_64
extern asmlinkage long (*orig_getpgid)(pid_t);
#else
extern asmlinkage int (*orig_getpgid)(pid_t);
#endif

extern void security_hook(void);
extern void security_unhook(void);
extern Boolean addOneDenyWriteSetting(DENYWRITE_TYPE type, char *item);
extern void parseSetDenyWriteSettings(DENYWRITE_TYPE type, char * settings);
extern long open_file(struct dentry * dentry, struct vfsmount * mnt, int flags);

extern INIT_ARGS kini;
extern rwlock_t kini_lock;
extern struct list_head scanning_item_head;
extern spinlock_t scanning_item_head_lock;
extern int scanning_list_item_no;
extern rwlock_t denywrite_list_head_lock;
extern struct list_head list_item_head;
extern spinlock_t list_item_head_lock;
extern atomic_t candidate;

int 	hook_init = UN_HOOKED;
int	exc_pid_no = 0;
pid_t	*exc_pid_ary = NULL;
pid_t	*vsc_pid_ary = NULL;
Boolean inited = 0;
int	vsapi_chldn_no = 0;
atomic_t Del_list = ATOMIC_INIT(0);




#if LINUX_VERSION_CODE < 0x30000
rwlock_t init_lock __cacheline_aligned = RW_LOCK_UNLOCKED;
rwlock_t hook_init_lock __cacheline_aligned = RW_LOCK_UNLOCKED;
#else
DEFINE_RWLOCK(init_lock);
DEFINE_RWLOCK(hook_init_lock);
#endif

int openMod(struct inode *inode, struct file *file) {
	const char * cpsMethod = "openMod";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	MOD_INC_REF_COUNT;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into openMod\n", cur_pid, cpsMethod);

	DPRINTK(1,"%d: %s: get outta openMod\n", cur_pid, cpsMethod);
	return 0; /* success */
}
#if LINUX_VERSION_CODE >= 0x20610 && defined(X86_64) || LINUX_VERSION_CODE >= 0x20624
long  ioctlMod(struct file * file , unsigned int cmd, unsigned long arg)
#else
int ioctlMod(struct inode *inode, struct file * filp, unsigned int cmd,
			 unsigned long arg) 
#endif
{
	const char * cpsMethod = "ioctlMod";
#ifdef X86_64
        unsigned int u_lip;
        unsigned int d_lip;
#ifdef USE_X86_64_PDA
		struct x8664_pda *pda;
#endif
#endif
	pid_t cur_pid=0;
	SCAN_ARGS	*scan;
	INIT_ARGS	*init;
	KHM_INFO    *info;
	DENYWRITE	*denywrite;
	DENYWRITE_TYPE denywritetype;
    FIRSTITEM   *first_item;
    char fir_addr[32] = {0};
	pid_t	exc_pid;
	pid_t	vsc_pid;
	pid_t	*newp = NULL;
	int	o_max_exc_pid;
	int	o_max_vsc_pid;
	LIST_ITEM	*ip;
	int	found;
	int	count = 0;
	int rewake = 0;
	int scanned = 0;
    int nTaskListLocked = -1;
	char	*str, *tmp_str=NULL;
	SCAN_ARGS       xksca;
	long	timeout;
	struct task_struct      *p;
	LIST_ITEM      *xp, *nxp;

    //Added by Serena Dong -start 2010 9.6
    LIST_ITEM *pos;
    //Added by Serena Dong -end 2010 9.6

    //Add by errik  -start 2010 9.24
    COMMEXCS * commexcs;
    //Add end

	long dummyReturn;
	CP_DBG_LVL;
	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into ioctlMod\n", cur_pid, cpsMethod);

	/* change to put_user/get_user here */
	switch (cmd) 
	{
	case SIOCSETINIFIL:
		DPRINTK(1,"%d: %s: SIOCSETINIFIL\n", cur_pid, cpsMethod);
        write_lock(&init_lock);
		if(inited == 1)
		{	
            write_unlock(&init_lock);
            return 0;
		}
        inited = 1;
        write_unlock(&init_lock);
        
		init = (INIT_ARGS *)arg;
		write_lock(&kini_lock);
		/* deal with incoming, outgoing, and running. */
		get_user(kini.incoming, (Boolean *)&(init->incoming));
		DPRINTK(2,"%d: %s: incoming %d\n", cur_pid, cpsMethod, kini.incoming);
		get_user(kini.outgoing, (Boolean *)&(init->outgoing));
		DPRINTK(2,"%d: %s: outgoing %d\n", cur_pid, cpsMethod, kini.outgoing);
		get_user(kini.running, (Boolean *)&(init->running));
		DPRINTK(2,"%d: %s: running %d\n", cur_pid, cpsMethod, kini.running);
		/* deal with the default maximum numbers. */
		get_user(kini.max_cache_item, (int *)&(init->max_cache_item));
		DPRINTK(2,"%d: %s: max_cache_item %d\n", cur_pid, cpsMethod, kini.max_cache_item);
		get_user(kini.max_list_item, (int *)&(init->max_list_item));
		DPRINTK(2,"%d: %s: max_list_item %d\n", cur_pid, cpsMethod, kini.max_list_item);
		get_user(kini.max_dir_item, (int *)&(init->max_dir_item));
		DPRINTK(2,"%d: %s: max_dir_item %d\n", cur_pid, cpsMethod, kini.max_dir_item);
		get_user(kini.max_ext_item, (int *)&(init->max_ext_item));
		DPRINTK(2,"%d: %s: max_ext_item %d\n", cur_pid, cpsMethod, kini.max_ext_item);
		get_user(kini.max_exc_dir_item, (int *)&(init->max_exc_dir_item));
		DPRINTK(2,"%d: %s: max_exc_dir_item %d\n", cur_pid, cpsMethod, kini.max_exc_dir_item);
		get_user(kini.max_exc_fil_item, (int *)&(init->max_exc_fil_item));
		DPRINTK(2,"%d: %s: max_exc_fil_item %d\n", cur_pid, cpsMethod, kini.max_exc_fil_item);
		get_user(kini.max_exc_ext_item, (int *)&(init->max_exc_ext_item));
		DPRINTK(2,"%d: %s: max_exc_ext_item %d\n", cur_pid, cpsMethod, kini.max_exc_ext_item);
		/* deal with wait queue timeout and vsapi timeout. */
		get_user(kini.waitq_timeout, (int *)&(init->waitq_timeout));
		DPRINTK(2,"%d: %s: waitq_timeout %d\n", cur_pid, cpsMethod, kini.waitq_timeout);
		get_user(kini.vsapi_timeout, (int *)&(init->vsapi_timeout));
		DPRINTK(2,"%d: %s: vsapi_timeout %d\n", cur_pid, cpsMethod, kini.vsapi_timeout);
		busy_timeout_HZ = HZ *(kini.waitq_timeout/1000);
		scan_timeout_HZ = HZ *kini.vsapi_timeout;
		/* deal with include/exclude dirs, exclude files, and include/exclude extensions. */
		get_user(str, (char **)&(init->dirs));
		if (str != NULL) {
			count = STRLEN_USER(str);
			DPRINTK(2,"%d: %s: count %d\n", cur_pid, cpsMethod, count);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: dir is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: dirs %s\n", cur_pid, cpsMethod, tmp_str);
			}
		} else tmp_str = NULL;
		parseAddDirs(tmp_str);

		get_user(str, (char **)&(init->exts));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: exts is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: exts %s\n", cur_pid, cpsMethod, tmp_str);
			}
		} else tmp_str = NULL;
		parseAddExts(tmp_str);

		get_user(str, (char **)&(init->exc_dirs));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: exc_dirs is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: exc_dirs %s\n", cur_pid, cpsMethod, tmp_str);
			}
		} else tmp_str = NULL;
		parseAddExcDirs(tmp_str);

		get_user(str, (char **)&(init->exc_fils));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: exc_fils is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: exc_fils %s\n", cur_pid, cpsMethod, tmp_str);
			}
		} else tmp_str = NULL;
		parseAddExcFils(tmp_str);

		get_user(str, (char **)&(init->exc_exts));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: xkini.exc_exts is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: exc_exts %s\n", cur_pid, cpsMethod, tmp_str);
			}
		} else tmp_str = NULL;
		parseAddExcExts(tmp_str);
		/* debug level */
		get_user(kini.debug_level, (int *)&(init->debug_level));
		DPRINTK(2,"%d: %s: debug_level %d\n", cur_pid, cpsMethod, kini.debug_level);
		if (splxmod_debug == 0)
			g_iDbgLevel = kini.debug_level;
		else
			g_iDbgLevel = splxmod_debug;

		/* get old values */
		o_max_exc_pid = kini.max_exc_pid;
		o_max_vsc_pid = kini.max_vsc_pid;

		/* dynamic arrays */
		get_user(kini.max_exc_pid, (int *)&(init->max_exc_pid));
		DPRINTK(2,"%d: %s: max_exc_pid %d\n", cur_pid, cpsMethod, kini.max_exc_pid);
		get_user(kini.max_vsc_pid, (int *)&(init->max_vsc_pid));
		DPRINTK(2,"%d: %s: max_vsc_pid %d\n", cur_pid, cpsMethod, kini.max_vsc_pid);
		get_user(kini.max_path_len, (int *)&(init->max_path_len));
		DPRINTK(2,"%d: %s: max_path_len %d\n", cur_pid, cpsMethod, kini.max_path_len);
		get_user(kini.max_cmd_len, (int *)&(init->max_cmd_len));
		DPRINTK(2,"%d: %s: max_cmd_len %d\n", cur_pid, cpsMethod, kini.max_cmd_len);

		if (o_max_exc_pid < kini.max_exc_pid) {
			newp = (pid_t *)kmalloc(sizeof(pid_t)*
				kini.max_exc_pid, GFP_ATOMIC);
			if (newp == NULL)
				WPRINTK("SPLXMOD: %d: %s: newp is NULL\n", cur_pid, cpsMethod);
			memcpy(newp, exc_pid_ary, exc_pid_no * sizeof(pid_t));
			if (exc_pid_ary != NULL) kfree(exc_pid_ary);
			exc_pid_ary = newp;
			newp = NULL;
		}
		if (o_max_vsc_pid < kini.max_vsc_pid) {
			newp = (pid_t *)kmalloc(sizeof(pid_t)*
				kini.max_vsc_pid, GFP_ATOMIC);
			if (newp == NULL)
				WPRINTK("SPLXMOD: %d: %s: newp is NULL\n", cur_pid, cpsMethod);
			memcpy(newp, vsc_pid_ary, vsapi_chldn_no * sizeof(pid_t));
			if (vsc_pid_ary != NULL) kfree(vsc_pid_ary);
			vsc_pid_ary = newp;
			newp = NULL;
		}

		/* if disabling realtime scanning, clear cache */
		if (! (kini.incoming || kini.outgoing || kini.running) )
			removeCacheAll();	// cache_item_head_lock
		write_unlock(&kini_lock);

        /* Errik: 2011-3-16 Redo the hook when user change the setting of realtime scan from Web */
        //PDG: SPLX3.0-RHEL6-00002
        read_lock(&hook_init_lock);
        if(hook_init == HOOKED)
        {
            read_unlock(&hook_init_lock);
            security_unhook();
            security_hook();
        }
        else
        {
            read_unlock(&hook_init_lock);
        }
        // End
		/* set inited flag */
		write_lock(&init_lock);
		inited = 2;
		write_unlock(&init_lock);

		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return 0;
        
	case SIOCGETNXTFIL:
	case SIOCPUTLSTRES:
		DPRINTK(1,"%d: %s: SIOCGETNXTFIL || SIOCPUTLSTRES\n", cur_pid, cpsMethod);
		scan = (SCAN_ARGS *)arg;
		get_user(xksca.comm_pid, (pid_t *)&(scan->comm_pid));
		get_user(xksca.fd, (unsigned int *)&(scan->fd));
		if (xksca.comm_pid != 0) { /* has a correspondent other_pid */
#ifndef X86_64
			get_user(ip, (void **)&(scan->lip));
#else
			void * temp_ip;
			get_user(u_lip, (unsigned int *)&(scan->u_lip));
			get_user(d_lip, (unsigned int *)&(scan->d_lip));
			temp_ip = (void *)(unsigned long)u_lip;
			temp_ip=(void *)((((unsigned long)temp_ip)<<32)|(unsigned long)d_lip);
			ip=temp_ip;			
#endif

			get_user(xksca.vsapi_ret,
				(int *)&(scan->vsapi_ret));
			get_user(xksca.action,
				(int *)&(scan->action));
			DPRINTK(2,"%d: %s: wake up openHook()/closeHook()\n", cur_pid, cpsMethod);
			spin_lock(&scanning_item_head_lock);

            TASK_LIST_SPLX_LOCK;
            nTaskListLocked = 1;
            scanned = 0;
			p = splx_find_task_by_pid(xksca.comm_pid);
            DPRINTK(3,"%d: %s: find task's pid:%d by pid: %d\n", cur_pid, cpsMethod, p->pid,xksca.comm_pid);
#if defined (EXIT_ZOMBIE) && defined (EXIT_DEAD)
			if (p && p->exit_state != EXIT_ZOMBIE && p->exit_state != EXIT_DEAD &&
				atomic_read(&(ip->info.cond)) == FALSE) {
#elif defined (TASK_DEAD)
			if (p && p->state != TASK_ZOMBIE && p->state != TASK_DEAD &&
				atomic_read(&(ip->info.cond)) == FALSE) {
#else
			if (p && p->state != TASK_ZOMBIE && atomic_read(&(ip->info.cond)) == FALSE) {
#endif
				if (ip) {
					list_for_each_entry_safe(xp, nxp, &scanning_item_head, item_list) {
						if (ip == xp) {  // item still in scanning list
							ip->info.vsapi_busy = FALSE;
							ip->info.scan_args.vsapi_chld_pid = 0;
							ip->info.scan_args.vsapi_ret = xksca.vsapi_ret;
							ip->info.scan_args.action = xksca.action;
							list_del(&ip->item_list);
							scanning_list_item_no--;
							TASK_LIST_SPLX_UNLOCK;
                            nTaskListLocked = 0;
							spin_unlock(&scanning_item_head_lock);
							scanned = 1;
#ifdef USE_X86_64_PDA
							TASK_LIST_SPLX_LOCK;
                            nTaskListLocked = 1;
                            pda = cpu_pda(p->thread_info->cpu); 
                            if (pda->pcurrent == p)
							{
								if(p->state == TASK_UNINTERRUPTIBLE)
									DPRINTK(1,"%d: %s: task is running, but state is UNINTERRUPTIBLE, pid = %d, command = %s\n", cur_pid, cpsMethod, p->pid, p->comm);
                                TASK_LIST_SPLX_UNLOCK;	
                                nTaskListLocked = 0;
								msleep(1) ;
							}
                            if (1 == nTaskListLocked)
                            {
                                TASK_LIST_SPLX_UNLOCK;
                                nTaskListLocked = 0;
                            }
#endif
                            break;
						}
					}
				}
			}
			
			if(scanned == 1)
			{
				atomic_set(&(ip->info.cond),TRUE);
                TASK_LIST_SPLX_LOCK;
                nTaskListLocked = 1;
				if (p->state != TASK_RUNNING) {
					DPRINTK(2,"%d: %s: wake_up_process(p)\n", cur_pid, cpsMethod);
					rewake = 0;
					while(wake_up_process(p) == 0 && rewake < 10000 )
					{
                        TASK_LIST_SPLX_UNLOCK;
                        nTaskListLocked = 0;
						msleep(1);

						rewake++;
			
                        TASK_LIST_SPLX_LOCK;
                        nTaskListLocked = 1;
						p = splx_find_task_by_pid(xksca.comm_pid);
						if(p == NULL)
						{
							DPRINTK(1,"%d: %s: task_struct point p is NULL\n", cur_pid, cpsMethod);
							break;
						}
					}
					if(rewake != 0 && p)
					{
						DPRINTK(1,"%d: %s: wake_up_process pid = %d, command = %s, rewake = %d\n", cur_pid, cpsMethod, p->pid, p->comm, rewake);
					}	
                    TASK_LIST_SPLX_UNLOCK;
                    nTaskListLocked = 0;
				}
                if (1 == nTaskListLocked)
                {
                    TASK_LIST_SPLX_UNLOCK;
                    nTaskListLocked = 0;
                }
            }
			else
			{
                TASK_LIST_SPLX_UNLOCK;
				spin_unlock(&scanning_item_head_lock);
			}
	
			if (cmd == SIOCPUTLSTRES) return 0;
			xksca.comm_pid = xksca.fd = 0;
		}
		read_lock(&kini_lock);
		timeout = busy_timeout_HZ;
		read_unlock(&kini_lock);
		DPRINTK(2,"%d: %s: enter findListCandid loop\n", cur_pid, cpsMethod);
		do {
			DPRINTK(2,"%d: %s: sleep on vsapi_chldn_wq\n", cur_pid, cpsMethod);
			wait_event_interruptible(vsapi_chldn_wq, atomic_read(&candidate));
			//INTERRUPTIBLE_SLEEP_ON_TIMEOUT(&vsapi_chldn_wq, timeout);
			DPRINTK(2,"%d: %s: waken up from vsapi_chldn_wq\n", cur_pid, cpsMethod);
			if (signal_pending(current)) {
				DPRINTK(2,"%d: %s: signal pending\n", cur_pid, cpsMethod);
				return 1;
			}
			found = findListCandid(xksca.comm_pid, xksca.fd, &ip);
			if (found == 0) {
				atomic_set(&candidate, FALSE);
				DPRINTK(2,"%d: %s: find list failed with PID %d, FD %d\n", cur_pid, cpsMethod, xksca.comm_pid, xksca.fd);
			} else if (found == 1) {
				break;
			}
		} while (found != 1);
		DPRINTK(2,"%d: %s: exit findListCandid loop\n", cur_pid, cpsMethod);
		ip->info.vsapi_busy = TRUE;
		ip->info.scan_args.vsapi_ret = NO_VIRUS;
		xksca.vsapi_ret = NO_VIRUS;
		ip->info.candid = FALSE;
		ip->info.scan_args.vsapi_chld_pid = current->pid;
		xksca.comm_pid = ip->info.scan_args.comm_pid;
		xksca.comm_uid = ip->info.scan_args.comm_uid;
		xksca.size = ip->info.scan_args.size;
		xksca.mode = ip->info.scan_args.mode;
		xksca.flags = ip->info.scan_args.flags;
		xksca.inode = ip->info.scan_args.inode;
#ifndef X86_64
		xksca.lip = ip->info.scan_args.lip;
#else
		xksca.u_lip = ip->info.scan_args.u_lip;
		xksca.d_lip = ip->info.scan_args.d_lip;
#endif
		count = strlen(ip->info.scan_args.full_pn)+1;
		xksca.full_pn = (char *)kmalloc(count, GFP_ATOMIC);
		strncpy(xksca.full_pn, ip->info.scan_args.full_pn,count);
		count = strlen(ip->info.scan_args.comm)+1;
		xksca.comm = (char *)kmalloc(count, GFP_ATOMIC);
		strncpy(xksca.comm, ip->info.scan_args.comm, count);
		/* redundant here? */
		put_user(xksca.vsapi_ret,
			(int *)&(scan->vsapi_ret));
		get_user(str, (char **)&(scan->full_pn));
		dummyReturn = copy_to_user((char *)str,
			(char *)(xksca.full_pn), 
			strlen(xksca.full_pn)+1);
		kfree(xksca.full_pn);
		get_user(str, (char **)&(scan->comm));
		dummyReturn = copy_to_user((char *)str,
			(char *)(xksca.comm),
			strlen(xksca.comm)+1);
		kfree(xksca.comm);
		put_user(xksca.comm_pid,
			(pid_t *)&(scan->comm_pid));
		put_user(xksca.comm_uid,
			(uid_t *)&(scan->comm_uid));
		put_user(xksca.size, (off_t *)&(scan->size));
		put_user(xksca.mode, (mode_t *)&(scan->mode));
		put_user(xksca.flags, (int *)&(scan->flags));
		put_user(xksca.inode, (ino_t *)&(scan->inode));
#ifndef X86_64
		
		put_user(xksca.lip, (void **)&(scan->lip));
#else
		put_user(xksca.u_lip, (unsigned int *)&(scan->u_lip));
		put_user(xksca.d_lip, (unsigned int *)&(scan->d_lip));
//		put_user(xksca.lip, (u64 *)&(scan->lip));
#endif
        // The file fd is not used in application, so not allocate a file struct for it.
        xksca.fd = -1;
		//xksca.fd = (int) open_file(ip->info.dentry, ip->info.mnt, O_RDONLY);
		xksca.dir_fd = (int) open_file(ip->info.dentry->d_parent, ip->info.mnt, O_RDONLY | O_DIRECTORY);
		DPRINTK(2,"%d: %s: fd = [%d]\n", cur_pid, cpsMethod, xksca.fd);
		DPRINTK(2,"%d: %s: dir_fd = [%d]\n", cur_pid, cpsMethod, xksca.dir_fd);
		put_user((int)xksca.fd, (int*)&(scan->fd));
		put_user((int)xksca.dir_fd, (int*)&(scan->dir_fd));
		spin_lock(&scanning_item_head_lock);
		list_add_tail(&ip->item_list, &scanning_item_head);
		scanning_list_item_no++;
		spin_unlock(&scanning_item_head_lock);
		DPRINTK(2,"%d: %s: back to the vsapiapp\n", cur_pid, cpsMethod);
		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);

		return 0;

        //Added by Serena Dong -start 2010 9.6
    case SIOCGETFIRSTITEM:
        spin_lock(&list_item_head_lock);
        pos = list_entry(list_item_head.next, typeof(*pos), item_list);
        if(&pos->item_list == &list_item_head)
        
        {
            /* Waiting List is empty */
            DPRINTK(3,"Waiting List is empty\n");
        }
        else
        {
            /* Get first item address*/
            first_item = (FIRSTITEM *)arg;
            get_user(str, (char **)&(first_item->info));
            memset(fir_addr,'\0', 32);
            snprintf(fir_addr, 32, "%lu", (unsigned long)pos);
            dummyReturn = copy_to_user((char*)str, (char *)fir_addr, 32);
            DPRINTK(2,"SIOCGETFIRSTITEM: Address of first item in Waiting List is 0x%lx\n", (unsigned long)pos);
        }
        spin_unlock(&list_item_head_lock);        
        return 0;
        //Added by Serena Dong -end 2010 9.6

    // Add by errik zhang -start 2010 9.11
    case SIOCGETKHMVERSION:
        put_user(KHM_VERSION, (unsigned int *)arg);
        return 0;
    // Add by errik zhang -end 2010 9.11
    // Add by errik  - start  2010 9.24
    // Provide interface to set command exclusion list
    case SIOCSETCOMMEXCLUSION:
        commexcs = (COMMEXCS *)arg;
		get_user(str, (char**)&(commexcs->info));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: alloc memory for command exclusion list failed\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
			}
		} else tmp_str = NULL;
        DPRINTK(1,"%d: %s: count [%d],exc_comms %s\n", cur_pid, cpsMethod, count, tmp_str);
		parseAddExcComms(tmp_str);      
        return 0;
    // Add by errik end  2010 9.24
    // Add by errik start 2010 9.26
    case SIOCCLEARKHMLIST:
        wakeupItemBusy();
        wakeupItemCandid();
        DPRINTK(1, "%d: %s: SIOCCLEARKHMLIST", cur_pid, cpsMethod);
        return 0;     
    // Add by errik End  2010 9.26
    
	case SIOCPUTEXCPID:
		DPRINTK(1,"%d: %s: SIOCPUTEXCPID\n", cur_pid, cpsMethod);
		get_user(exc_pid, (pid_t *)arg);
		write_lock(&kini_lock);
		insertAry(exc_pid_ary, exc_pid, &exc_pid_no, kini.max_exc_pid);
		write_unlock(&kini_lock);
		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return 0;
	case SIOCPUTVSCPID:
		DPRINTK(1,"%d: %s: SIOCPUTVSCPID\n", cur_pid, cpsMethod);
		get_user(vsc_pid, (pid_t *)arg);
		write_lock(&kini_lock);
		insertAry(vsc_pid_ary, vsc_pid, &vsapi_chldn_no, kini.max_vsc_pid);
		write_unlock(&kini_lock);
		
		read_lock(&kini_lock);
		if (vsapi_chldn_no == 1) 
        {
#ifdef FIND_SYS_CALL_TABLE
			p_sys_call_table = *(*((unsigned long **)(current->thread.esp0) - 16) - 1);
			DPRINTK(1,"%d: %s: got sys_call_table address: %08lx\n", cur_pid, cpsMethod, p_sys_call_table);
#endif
			read_unlock(&kini_lock);

			DPRINTK(1,"%d: %s: into hook_module\n", cur_pid, cpsMethod);

            security_hook();

		    DPRINTK(1,"%d: %s: out hook_module\n", cur_pid, cpsMethod);				
		}
		else
		{
			read_unlock(&kini_lock);
		}

		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return 0;
	case SIOCGETKHMINFO:
		DPRINTK(1,"%d: %s: SIOCGETKHMINFO\n", cur_pid, cpsMethod);
		info = (KHM_INFO *)arg;
		DPRINTK(2, "%d: %s: DIST = %s PLATFORM = %s INTERFACE_VERSION = %d RELEASE = %d\n",	cur_pid, cpsMethod, DIST, PLATFORM, INTERFACE_VERSION, RELEASE);
		get_user(str, (char **)&(info->dist));
		dummyReturn = copy_to_user((char *)str, (char *) DIST, strlen(DIST)+1);
		get_user(str, (char **)&(info->platform));
		dummyReturn = copy_to_user((char *)str, (char *) PLATFORM, strlen(PLATFORM)+1);
		put_user(INTERFACE_VERSION, (int *)&info->interface_version);
		put_user(RELEASE, (int *)&info->release);
		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return 0;
	case SIOCADDONEDENYWRITEFILE:
	case SIOCADDONEDENYWRITEDIR:
		DPRINTK(1,"%d: %s: SIOCADDONEDENYWRITEFILE || SIOCADDONEDENYWRITEDIR\n", cur_pid, cpsMethod);
		denywrite = (DENYWRITE *)arg;
		get_user(str, (char**)&(denywrite->info));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: deny write file/dir is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: deny write file/dir [%s]\n", cur_pid, cpsMethod, tmp_str);
			}
		} else tmp_str = NULL;
		denywritetype = (cmd == SIOCADDONEDENYWRITEFILE) ? DENYWRITE_FILE : DENYWRITE_DIR;
		write_lock(&denywrite_list_head_lock);
		addOneDenyWriteSetting(denywritetype, tmp_str);
		write_unlock(&denywrite_list_head_lock);
		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return 0;
	case SIOCSETDENYACCESSFILELIST:
	case SIOCSETDENYACCESSDIRLIST:
	case SIOCSETFILTEREXTINDENYACCESSDIR:
		DPRINTK(1,"%d: %s: SIOCSETDENYACCESSFILELIST || SIOCSETDENYACCESSDIRLIST || SIOCSETFILTEREXTINDENYACCESSDIR\n", cur_pid, cpsMethod);
		denywrite = (DENYWRITE *)arg;
		get_user(str, (char**)&(denywrite->info));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: deny write dir/ext is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: deny write dir/ext [%s]\n", cur_pid, cpsMethod, tmp_str);
			}
		}
		if (cmd == SIOCSETDENYACCESSFILELIST) denywritetype = DENYWRITE_FILE;
		else if (cmd == SIOCSETDENYACCESSDIRLIST) denywritetype = DENYWRITE_DIR;
		else denywritetype = DENYWRITE_FILTER_EXT;
		write_lock(&denywrite_list_head_lock);
		parseSetDenyWriteSettings(denywritetype, tmp_str);
		write_unlock(&denywrite_list_head_lock);
		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return 0;
	case SIOCSETEXCEPTIONEXTENSION:
		DPRINTK(1,"%d: %s: SIOCSETEXCEPTIONEXTENSION\n", cur_pid, cpsMethod);
		denywrite = (DENYWRITE *)arg;
		get_user(str, (char**)&(denywrite->info));
		if (str != NULL) {
			count = STRLEN_USER(str);
			tmp_str = (char *)kmalloc(count, GFP_ATOMIC);
			if (!tmp_str)
				WPRINTK("SPLXMOD: %d: %s: exc ext is NULL\n", cur_pid, cpsMethod);
			else {
				dummyReturn = strncpy_from_user((char *)(tmp_str),
					(char *)str, count);
				DPRINTK(2,"%d: %s: exc ext %s\n", cur_pid, cpsMethod, tmp_str);
			}
		} else tmp_str = NULL;
		write_lock(&kini_lock);
		parseAddExcExts(tmp_str);
		write_unlock(&kini_lock);
		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return 0;
	default:
		DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
		return -EINVAL;
	}
}

int releaseMod(struct inode *inode, struct file *file) 
{
	const char * cpsMethod = "releaseMod";
	LIST_ITEM *ip, *nip;
	struct task_struct *p;
	pid_t	cur_pid=0;
	pid_t   cur_pgrp=0;

	CP_DBG_LVL;

	cur_pid = current->pid;
#if LINUX_VERSION_CODE <= 0x20612
		cur_pgrp = process_group(current);
#else
		cur_pgrp = task_pgrp_nr(current);
#endif

	DPRINTK(1,"%d: %s: get into releaseMod\n", cur_pid, cpsMethod);

	DPRINTK(3,"%d: %s: pgrp=%ld\n", cur_pid, cpsMethod, (long)cur_pgrp);
        
	spin_lock(&list_item_head_lock);
	list_for_each_entry_safe(ip, nip, &list_item_head, item_list) {
		if (ip) {
            TASK_LIST_SPLX_LOCK;
			p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
			if (p) {
				//DPRINTK(4,"%d :%s task PID :%d",cur_pid,cpsMethod,p->pid);
				DPRINTK(2,"%d: %s: candidate process [%s][%d]\n", cur_pid, cpsMethod, ip->info.scan_args.comm, ip->info.scan_args.comm_pid);
				DPRINTK(2,"%d: %s: state = %ld\n", cur_pid, cpsMethod, p->state);
			}
            TASK_LIST_SPLX_UNLOCK;
		}
	}
	spin_unlock(&list_item_head_lock);

	spin_lock(&scanning_item_head_lock);
	list_for_each_entry_safe(ip, nip, &scanning_item_head, item_list) {
		if (ip) {
            TASK_LIST_SPLX_LOCK;
			p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
			if (p) {
				DPRINTK(2,"%d: %s: busy process [%s][%d]\n", cur_pid, cpsMethod, ip->info.scan_args.comm, ip->info.scan_args.comm_pid);
				DPRINTK(2,"%d: %s: state = %ld\n", cur_pid, cpsMethod, p->state);
			}
            TASK_LIST_SPLX_UNLOCK;
		}
	}
	spin_unlock(&scanning_item_head_lock);

    //TT224111: Remove unhook_module from the spin lock to avoid dead lock.
	/****** TT234414 Samir Bai 20111206 start ******/
	write_lock(&init_lock);
	write_lock(&kini_lock);
	deleteAry(vsc_pid_ary, cur_pgrp, &vsapi_chldn_no);
	if (vsapi_chldn_no == 0) 
    {
		inited = 0;
		write_unlock(&kini_lock);
		write_unlock(&init_lock);
        
        wakeupItemBusy();
		wakeupItemCandid();
		removeCacheAll();

        DPRINTK(1,"%d: %s: try to unhook_module\n", cur_pid, cpsMethod);
        security_unhook();  
	}
    else
    {
        write_unlock(&kini_lock);
		write_unlock(&init_lock);
    }
	/****** TT234414 Samir Bai 20111206 end ******/
    
    write_lock(&kini_lock);
    deleteAry(exc_pid_ary, cur_pgrp, &exc_pid_no);
    write_unlock(&kini_lock);
    
	spin_lock(&list_item_head_lock);
	list_for_each_entry_safe(ip, nip, &list_item_head, item_list) {
		if (ip) {
            TASK_LIST_SPLX_LOCK;
			p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
			if (p) {
				WPRINTK("%d: %s: candidate process found after unhook_module [%s][%d]\n", cur_pid, cpsMethod, ip->info.scan_args.comm, ip->info.scan_args.comm_pid);
				WPRINTK("%d: %s: state = %ld\n", cur_pid, cpsMethod, p->state);
			}
            TASK_LIST_SPLX_UNLOCK;
		}
	}
	spin_unlock(&list_item_head_lock);

	spin_lock(&scanning_item_head_lock);
	list_for_each_entry_safe(ip, nip, &scanning_item_head, item_list) {
		if (ip) {
            TASK_LIST_SPLX_LOCK;
			p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
			if (p) {
				WPRINTK("%d: %s: busy process found after unhook_module [%s][%d]\n", cur_pid, cpsMethod, ip->info.scan_args.comm, ip->info.scan_args.comm_pid);
				WPRINTK("%d: %s: state = %ld\n", cur_pid, cpsMethod, p->state);
			}
            TASK_LIST_SPLX_UNLOCK;
		}
	}
	spin_unlock(&scanning_item_head_lock);

	DPRINTK(3, "%d: %s: releaseMod [%d]\n", cur_pid, cpsMethod, atomic_read(&Del_list));
    while (0 != atomic_read(&Del_list))
    {
        msleep(10);
        DPRINTK(3, "%d: %s: releaseMod in while cycle [%d]\n", cur_pid, cpsMethod, atomic_read(&Del_list));
    }
	DPRINTK(1,"%d: %s: get outta releaseMod\n", cur_pid, cpsMethod);
	MOD_DEC_REF_COUNT;
	return 0;
}
