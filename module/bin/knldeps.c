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
 ** Modify to support kernel version 3.0
 ** Modify Date: 2012/06/21
 ** Modify By:	 samir_bai@trendmicro.com.cn
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

#include	<linux/kernel.h>
#include	<linux/types.h>
#include	<linux/list.h>
#include	<asm/page.h>
#include	<linux/dcache.h>
#include	<linux/fs.h>
#include	<linux/sched.h>
#include        <linux/slab.h>
#if LINUX_VERSION_CODE >= 0x20409
#include    <linux/vmalloc.h>
#endif
#if LINUX_VERSION_CODE < 0x30000
#include	<linux/smp_lock.h>
#endif
#include	<linux/mm.h>
#include	<linux/string.h>
#include	<linux/spinlock.h>

#if LINUX_VERSION_CODE >= 0x020600
#include <linux/mount.h>
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE >= 0x30000
#include <linux/path.h>
#endif

#include	<splxmod.h>

extern int     splxmod_debug;
extern int     g_iDbgLevel;
extern spinlock_t dbg_lock;
extern rwlock_t kini_lock;

#if LINUX_VERSION_CODE <= 0x20612
void SET_FS_PWD(struct fs_struct *fs, struct vfsmount *mnt, struct dentry *dentry)
{
	struct dentry *old_pwd;
	struct vfsmount *old_pwdmnt;

	write_lock(&fs->lock);
	old_pwd = fs->pwd;
	old_pwdmnt = fs->pwdmnt;
	fs->pwdmnt = mntget(mnt);
	fs->pwd = dget(dentry);
	write_unlock(&fs->lock);

	if (old_pwd) {
		dput(old_pwd);
		mntput(old_pwdmnt);
	}
}
#endif
inline int lookup_flags(unsigned int f)
{
	unsigned long retval = LOOKUP_FOLLOW;

	if (f & O_NOFOLLOW)
		retval &= ~LOOKUP_FOLLOW;

	if ((f & (O_CREAT|O_EXCL)) == (O_CREAT|O_EXCL))
		retval &= ~LOOKUP_FOLLOW;

	if (f & O_DIRECTORY)
		retval |= LOOKUP_DIRECTORY;

	return retval;
}

int splx_kill_proc(pid_t pid, int sig, int priv)
{
#if LINUX_VERSION_CODE <= 0x20612
	return kill_proc(sig,priv,pid);
#else
    //TT216751: Merge Patch Form SuSE
    int ret = -ESRCH;
	struct pid * ppid = find_get_pid(pid);
	if(ppid != NULL){
		ret = kill_pid(ppid, sig, priv);
		put_pid(ppid);
	}
	return ret;
#endif
}

//Add to check whether the file is a normal file.
//Date: 2009-11-24
//Some file may belong the other special type of file. Such as eventpoll. Vsapiapp will crash if scanning this type of file

Boolean S_ISNORMAL(mode_t st_mode)
{
	if(S_ISLNK(st_mode) || S_ISREG(st_mode))
	{
		return TRUE;
	}
	else
		return FALSE;
}

//Add to remove the audit_context
//avoid the conflict with auditd

struct audit_context * ClearAuditContext(void)
{
	//Add for avoid conflict with auditd
    struct audit_context * current_audit = current->audit_context;
	task_lock(current);
	current->audit_context = NULL;
	task_unlock(current);
	return current_audit;
	//Add end
}

void SetAuditContext(struct audit_context * current_audit)
{
	task_lock(current);
	current->audit_context = current_audit;
	task_unlock(current);
}

#if LINUX_VERSION_CODE < 0x30000
//Add end
void SPLX_PATH_RELEASE(struct nameidata * nd)
{
#if LINUX_VERSION_CODE <= 0x20612
	return path_release(nd);
#else
	return path_put(&(nd->path));
#endif
}

int PATH_LOOKUP(const char * path, unsigned flags, struct nameidata * nd)
{
#if LINUX_VERSION_CODE >= 0x20600
#if defined (IT_LOOKUP)
	intent_init(&nd->intent, IT_LOOKUP);
#endif
	return path_lookup(path, flags, nd);
#else
	int error = 1;
	if (path_init(path, flags, nd))
		error = path_walk(path, nd);
	return error;
#endif
}
#endif

#if 0
char * CRT_D_PATH(struct dentry *dentry, struct vfsmount *vfsmnt,struct dentry *root, struct vfsmount *rootmnt,	char *buffer, int buflen)
{
	char * end = buffer+buflen;
	char * retval;
	int namelen;

	*--end = '\0';
	buflen--;

	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
#if LINUX_VERSION_CODE >= 0x20600
			mntget(vfsmnt);
			dget(dentry);
			if (follow_up(&vfsmnt, &dentry) == 0) {
				mntput(vfsmnt);
				dput(dentry);
				goto global_root;
			}
#else
			if (vfsmnt->mnt_parent == vfsmnt) {
				goto global_root;
			}
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
#endif
			continue;
		}
		parent = dentry->d_parent;
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			break;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		retval = end;
		dentry = parent;
	}
	return retval;
global_root:
	namelen = dentry->d_name.len;
	buflen -= namelen;
	if (buflen >= 0) {
		retval -= namelen-1;    /* hit the slash */
		memcpy(retval, dentry->d_name.name, namelen);
	}
	return retval;
}
#endif
void DPUT(struct dentry *dentry)
{
	dput(dentry);
}

int REGISTER_CHRDEV(unsigned int major, const char * name, struct file_operations *fops)
{
	int	result;
	result = register_chrdev(major, name, fops);
	return (result);
}

long INTERRUPTIBLE_SLEEP_ON_TIMEOUT(wait_queue_head_t * p, signed long timeout)
{
	long	result;
	result = interruptible_sleep_on_timeout(p, timeout);
	return (result);
}

//void INTERRUPTIBLE_SLEEP_ON(wait_queue_head_t * p)
//{
//	interruptible_sleep_on(p);
//}


/*
* Revalidate the inode. This is required for proper NFS attribute caching.
*/
#if LINUX_VERSION_CODE < 0x020600
__inline__ int
do_revalidate(struct dentry *dentry)
{
	const char * cpsMethod = "do_revalidate";
	pid_t cur_pid=0;
	struct inode * inode = dentry->d_inode;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(3,"%d: %s: get into do_revalidate\n", cur_pid, cpsMethod);
	if (inode->i_op && inode->i_op->revalidate)
		return inode->i_op->revalidate(dentry);
	DPRINTK(3,"%d: %s: get outta do_revalidate\n", cur_pid, cpsMethod);
	return 0;
}
#endif

int cp_new_stat(struct inode * inode, struct stat * statbuf)
{
	const char * cpsMethod = "cp_new_stat";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(3,"%d: %s: get into cp_new_stat\n", cur_pid, cpsMethod);

	/* only need st_ino */
	statbuf->st_ino = inode->i_ino;
	statbuf->st_mode = inode->i_mode;

	DPRINTK(3,"%d: %s: get outta cp_new_stat\n", cur_pid, cpsMethod);
	return 0;
}

#if LINUX_VERSION_CODE <=0x20612
/* from linux/fs/stat.c { */
int userGetStat(char *filename, struct stat *statbuf) 
{
#if LINUX_VERSION_CODE >= 0x20600
	struct nameidata nd;
	struct kstat stat;
	int error;

	error = user_path_walk(filename, &nd);
	if (!error) {
		error = vfs_getattr(nd.MNT, nd.DENTRY, &stat);
		SPLX_PATH_RELEASE(&nd);
	}
	if (!error) {
		statbuf->st_ino = stat.ino;
		statbuf->st_mode = stat.mode;
	}

	return error;
#else
	struct nameidata nd; 
	int error;

	error = user_path_walk(filename, &nd);
	if (!error) {
		error = do_revalidate(nd.DENTRY);
		if (!error)
			error = cp_new_stat(nd.DENTRY->d_inode, statbuf);
		SPLX_PATH_RELEASE(&nd);
	}
	return error;
#endif
}
#endif

/* Split function for SLES11 and keep original function
 * GetStatNewSupport
 * GetStatOldSupport
 * For lookup flags: include/linux/Namei.h
 */
#if LINUX_VERSION_CODE <= 0x20612
int GetStatOldSupport(char *filename, struct stat *statbuf)
{
#if LINUX_VERSION_CODE >= 0x20600
	struct nameidata nd;
	int error = 1;

	error = PATH_LOOKUP(filename, LOOKUP_FOLLOW | LOOKUP_NOALT, &nd);
	if (!error) {
		error = cp_new_stat(nd.DENTRY->d_inode, statbuf);
		SPLX_PATH_RELEASE(&nd);
	}

	return error;
#else
	struct nameidata nd; 
	int error;
	int flags = LOOKUP_FOLLOW|LOOKUP_POSITIVE;

	error = 0;
	if (path_init(filename, flags, &nd))
		error = path_walk(filename, &nd);
	if (!error) {
		error = do_revalidate(nd.DENTRY);
		if (!error)
			error = cp_new_stat(nd.DENTRY->d_inode, statbuf);
		SPLX_PATH_RELEASE(&nd);
	}
	return error;
#endif
}
#endif
/**
 ** SLES11 support
**/
#if LINUX_VERSION_CODE > 0x20612
int GetStatNewSupport(char *filename, struct stat *statbuf)
{
#if LINUX_VERSION_CODE >= 0x30000
	struct path pPath;
	int error = 1;

	error = kern_path(filename, LOOKUP_FOLLOW, &pPath);
	if(!error) {
		error = cp_new_stat(pPath.dentry->d_inode, statbuf);
		path_put(&pPath);
	}
	return error;
#else
	struct nameidata nd;
	int error = 1;
	//Clear it before use it.
	memset(&nd, 0, sizeof(struct nameidata));
	error = PATH_LOOKUP(filename, LOOKUP_FOLLOW, &nd);
	if (!error) {
		error = cp_new_stat(nd.DENTRY->d_inode, statbuf);
		path_put(&(nd.path));
	}
	return error;
#endif
}
#endif

int getStat(char *filename, struct stat *statbuf)
{
#if LINUX_VERSION_CODE <= 0x20612
	return GetStatOldSupport(filename, statbuf);
#else
	return GetStatNewSupport(filename, statbuf);
#endif
}

Boolean inExcForest(pid_t *exc_pid_ary, int exc_pid_no) 
{
	const char * cpsMethod = "inExcForest";
	pid_t current_pid=0;
	pid_t cur_pid=0;
	struct task_struct      *cur;
	Boolean found;
	int     i;
	CP_DBG_LVL;

	current_pid = current->pid;
	DPRINTK(3,"%d: %s: get into inExcForest\n", current_pid, cpsMethod);

	for (i=0; i<exc_pid_no; i++)
		DPRINTK(3,"%d: %s: exc_pid_no[%d]=%d\n", current_pid, cpsMethod, i, exc_pid_ary[i]);

	/* init is always NOT in exc_pid_ary */
	if (current->pid == 1) return FALSE;

	cur = current;
#if LINUX_VERSION_CODE <= 0x20612
	cur_pid = process_group(current);
#else
	cur_pid = task_pgrp_nr(current);
#endif

	found = FALSE;
//	do {
		//read_lock(&kini_lock);
		for (i=0; i<exc_pid_no; i++) {
			if (cur_pid == exc_pid_ary[i]) {
				DPRINTK(2,"%d: %s: found=TRUE\n", current_pid, cpsMethod);
				found = TRUE;
				break;
			}
		}
		//read_unlock(&kini_lock);
//#if LINUX_VERSION_CODE >= 0x020600 ||((defined(RedHat9) || defined(RHEL3)) &&  LINUX_VERSION_CODE >= 0x20414)
//		DPRINTK(2,"%d: %s: get parent using cur->parent\n", current_pid, cpsMethod);
//		cur = cur->parent;
//#else
//		DPRINTK(2,"%d: %s: get parent using cur->p_pptr\n", current_pid, cpsMethod);
//		cur = cur->p_pptr;
//#endif
//		cur_pid = cur->pid;
//	} while (cur_pid != 1 && !found);

	DPRINTK(3,"%d: %s: get outta inExcForest\n", current_pid, cpsMethod);
	return found;
}

