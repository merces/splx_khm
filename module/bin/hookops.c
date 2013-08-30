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
** Modify to support auditd
** Modify Date: 2009/12/30
** Modify By:   errik_zhang
**/

 /**
 ** Modify to support kernel version 3.0
 ** Modify Date: 2012/06/21
 ** Modify By:	 samir_bai@trendmicro.com.cn
 **/

/**
** Modify to fix kernel panic issue when file type is FIFO
** Modify Date: 2013/02/28
** Modify By: fred_chen@trendmicro.com.cn
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
#define MODVERSIONS /* force it on */
#endif

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#define __NO_VERSION__ /* don't define kernel_version in module.h */
#endif
#include <linux/module.h>

#include        <linux/kernel.h>

#include	<linux/sched.h>
#include	<linux/slab.h>
#include	<linux/unistd.h>
#include	<linux/ptrace.h>
#if LINUX_VERSION_CODE < 0x30000
#include	<linux/smp_lock.h>
#endif
#include	<linux/stat.h>
#include	<linux/string.h>
#include        <linux/dcache.h>
#include        <linux/mount.h>
#include        <linux/dcache.h>
#include        <linux/mount.h>
#include        <linux/file.h>
#include	<linux/spinlock.h>
#if LINUX_VERSION_CODE >= 0x20600
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/namei.h>
#endif
#if LINUX_VERSION_CODE >= 0x30000
#include <linux/path.h>
#endif
#include <asm/uaccess.h>

#include        <linux/sys.h>

#include	<splxmod.h>
#include	<asm/atomic.h>

#ifdef	NFSD
#include        <linux/sunrpc/svc.h>
#include        <linux/nfsd/nfsd.h>
#endif
extern asmlinkage int (*orig_open)(const char *, int, int);
extern asmlinkage int (*orig_close)(unsigned int);
extern asmlinkage int (*orig_exit)(int);
extern asmlinkage int (*orig_execve)(struct pt_regs);
extern int getStat(char *, struct stat *);
Boolean needToDenyWrite(struct dentry * dentry, struct vfsmount * mnt, int flags, ino_t inode);
extern Boolean needToScanThisOpen(struct dentry * dentry, struct vfsmount * mnt, int flags, ino_t inode);
extern Boolean needToScanThisClose(struct dentry * dentry, struct vfsmount * mnt, int flags, ino_t inode);
extern Boolean needToScanThisExecve(struct dentry * dentry, struct vfsmount * mnt, ino_t inode);
extern Boolean deleteList(LIST_ITEM *);
extern Boolean deleteListPID(pid_t);
extern void removeCache(ino_t);
extern int lookup_flags(unsigned int f);
extern Boolean insertList(LIST_ITEM *);
extern void addCache(ino_t);
extern Boolean findList(pid_t, unsigned int, LIST_ITEM **);
#if LINUX_VERSION_CODE < 0x30000
extern int PATH_LOOKUP(const char * path, unsigned flags, struct nameidata * nd);
extern void SPLX_PATH_RELEASE(struct nameidata * nd);
#endif
extern void WAKE_UP_INTERRUPTIBLE(wait_queue_head_t *);
extern Boolean inExcForest(pid_t *, int);
extern int splx_kill_proc(pid_t pid, int sig, int priv);
extern Boolean initialized(void);
extern Boolean S_ISNORMAL(mode_t st_mode);
extern struct audit_context * ClearAuditContext(void);
extern void SetAuditContext(struct audit_context * current_audit);
extern Boolean InExcComms(const char * comm);

#ifdef	NFSD
extern int (*orig_nfsd_open)(struct svc_rqst *, struct svc_fh *, int, int, struct file *);
extern void (*orig_nfsd_close)(struct file *);
#endif

extern int     g_iDbgLevel;
extern pid_t  *exc_pid_ary;
extern int    exc_pid_no;
extern INIT_ARGS kini;
extern int    vsapi_chldn_no;
extern rwlock_t kini_lock;
extern spinlock_t dbg_lock;
extern Boolean inited;
extern rwlock_t denywrite_list_head_lock;

long busy_timeout_HZ = 0;
long scan_timeout_HZ = 0;
DECLARE_WAIT_QUEUE_HEAD(vsapi_chldn_wq);
atomic_t	ref_cnt = ATOMIC_INIT(0);
atomic_t	candidate = ATOMIC_INIT(FALSE);

asmlinkage int openHook(const char *filename, int flags, int mode) 
{
	const char * cpsMethod = "openHook";
	ino_t	inode=0;
	mode_t	st_mode=0;
	int	ret;
	LIST_ITEM	*ip=NULL;
	char	*comm=NULL;
	Boolean	found;
	int	vsapi_ret;
	int	action;
	int	clen;
	int	vsapi_chld_pid;
	struct stat	statbuf;
	char	*tmp=NULL;
	int	fd;
	int	error;
#if LINUX_VERSION_CODE >= 0x30000
	struct path pPath;
#else
	struct nameidata nd;
#endif
	int namei_flags;
	struct audit_context * current_audit = NULL;
	Boolean	scan_open = FALSE;
	pid_t   cur_pid=0;
	long timeout;
	DECLARE_WAIT_QUEUE_HEAD(open_wq);
	CP_DBG_LVL;

	MOD_INC_REF_COUNT;
	cur_pid = current->pid;
	//First check whether the command is in the exclusion list
	if(InExcComms(current->comm)){
      MOD_DEC_REF_COUNT;
	  DPRINTK(3,"%d: %s: not to scan because command [%s] in the command exclusion list\n", cur_pid, cpsMethod, current->comm);
	  return orig_open(filename, flags, mode);
	}

    //Add for avoid conflict with auditd
    current_audit = ClearAuditContext();
	//Add end
	
	tmp = getname(filename);
	fd = PTR_ERR(tmp);
	if (IS_ERR(tmp)) {
		MOD_DEC_REF_COUNT;
		SetAuditContext(current_audit);
		return fd;
	}
	DPRINTK(1,"%d: %s: get into openHook filename %s, flags %x, mode %x\n", cur_pid, cpsMethod, tmp, flags, mode);

	DPRINTK(2,"%d: %s: comm=[%s]\n", cur_pid, cpsMethod, current->comm);

	if (!initialized()) {
		DPRINTK(2,"%d: %s: vsapi_chldn_no=0 || !inited, goto jump\n", cur_pid, cpsMethod);
		goto jump;
	}

	read_lock(&kini_lock);
	DPRINTK(2,"%d: %s: vsapi_chldn_no %d\n", cur_pid, cpsMethod, vsapi_chldn_no);
	if (inExcForest(exc_pid_ary, exc_pid_no)) {
		DPRINTK(2,"%d: %s: inExcForest() returned true, goto jump\n", cur_pid, cpsMethod);
		read_unlock(&kini_lock);
		goto jump;
	}
	read_unlock(&kini_lock);

	error = getStat(tmp, &statbuf);
	if (error) {
		memset(&statbuf, 0, sizeof(statbuf));
	}
	inode = statbuf.st_ino;
	DPRINTK(2,"%d: %s: inode %ld\n", cur_pid, cpsMethod, inode);
	st_mode = statbuf.st_mode;
	DPRINTK(2,"%d: %s: st_mode %x\n", cur_pid, cpsMethod, st_mode);
	
	if (!S_ISNORMAL(st_mode)) {
		DPRINTK(3,"%d: %s: %s is not a regular file or link, goto jump\n", cur_pid, cpsMethod, filename);
		goto jump;
	}
	
	namei_flags = flags;
	if ((namei_flags+1) & O_ACCMODE)
		namei_flags++;
	if (namei_flags & O_TRUNC)
		namei_flags |= 2;
#if LINUX_VERSION_CODE >= 0x30000
	error = kern_path(tmp, lookup_flags(namei_flags), &pPath);
#else
	error = PATH_LOOKUP(tmp, lookup_flags(namei_flags), &nd);
#endif
    
	if ((flags & O_ACCMODE) == O_RDWR || (flags & O_ACCMODE) == O_WRONLY) {
		DPRINTK(3,"%d: %s: denywrite: Has write attribute\n", cur_pid, cpsMethod);
		read_lock(&denywrite_list_head_lock);
#if LINUX_VERSION_CODE >= 0x30000
		if (needToDenyWrite(pPath.dentry, pPath.mnt, flags, inode)) {
#else
		if (needToDenyWrite(nd.DENTRY, nd.MNT, flags, inode)) {
#endif
			read_unlock(&denywrite_list_head_lock);
#if LINUX_VERSION_CODE >= 0x30000
			if (!error) path_put(&pPath);
#else
			if (!error) SPLX_PATH_RELEASE(&nd);
#endif
			putname(tmp); tmp=NULL;
			ret = -EACCES;
			MOD_DEC_REF_COUNT;
			DPRINTK(2,"%d: %s: if (!found), return -EACCES\n", cur_pid, cpsMethod);
			SetAuditContext(current_audit);
			return(ret);
		}
		read_unlock(&denywrite_list_head_lock);
	} 
	else 
		DPRINTK(3,"%d: %s: denywrite: No write attribute\n", cur_pid, cpsMethod);

	if (error) {
		DPRINTK(2,"%d: %s: path lookup failed, goto jump\n", cur_pid, cpsMethod);
		goto jump;
	}
		
	putname(tmp);
	tmp = NULL;
	   	
	read_lock(&kini_lock);
#if LINUX_VERSION_CODE >= 0x30000
	scan_open = needToScanThisOpen(pPath.dentry, pPath.mnt, flags, inode);
#else
	scan_open = needToScanThisOpen(nd.DENTRY, nd.MNT, flags, inode);
#endif

	read_unlock(&kini_lock);

	DPRINTK(2,"%d: %s: scan_open: %d\n", cur_pid, cpsMethod, scan_open);

	if (!scan_open) {
		DPRINTK(2,"%d: %s: no need to scan this file open or close, goto jump\n", cur_pid, cpsMethod);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		goto jump;
	}

	ip = (LIST_ITEM *)kmalloc(sizeof(LIST_ITEM), GFP_ATOMIC);
	if (ip == NULL)
	{
		WPRINTK("SPLXMOD: %d: %s: Alloc memory for ip failed, jump\n", cur_pid, cpsMethod);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		goto jump;	
	}
	memset(ip, 0, sizeof(LIST_ITEM));
#if LINUX_VERSION_CODE >= 0x30000
	ip->info.scan_args.full_pn = (char*) pPath.dentry->d_name.name;
#else
	ip->info.scan_args.full_pn = (char*) nd.DENTRY->d_name.name;
#endif
	clen = strlen(current->comm);
	comm = (char *)kmalloc(clen+1, GFP_ATOMIC);
	if (comm == NULL)
	{
		WPRINTK("SPLXMOD: %d: %s: alloc memory for comm is failed, jump\n", cur_pid, cpsMethod);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		kfree(ip);
		ip = NULL;
		goto jump;
	}
	ip->info.scan_args.comm = comm;
	strncpy(ip->info.scan_args.comm, current->comm, clen + 1);
	ip->info.scan_args.comm_pid = current->pid;
	ip->info.scan_args.comm_uid = current->SPLX_UID;
	ip->info.scan_args.flags = flags;
	ip->info.scan_args.lip = ip;
	ip->info.scan_args.inode = inode;
	ip->info.vsapi_busy = FALSE;
	ip->info.candid = TRUE;
	atomic_set(&(ip->info.cond),FALSE);
#if LINUX_VERSION_CODE >= 0x30000	
	ip->info.dentry = pPath.dentry;
	ip->info.mnt = pPath.mnt;
#else	
	ip->info.dentry = nd.DENTRY;
	ip->info.mnt = nd.MNT;
#endif
	INIT_LIST_HEAD(&ip->item_list);
	read_lock(&kini_lock);
	timeout = scan_timeout_HZ;
	read_unlock(&kini_lock);
	if (!initialized()) {
		if (ip->info.scan_args.full_pn != NULL)
			ip->info.scan_args.full_pn = NULL;
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		kfree(ip);
		ip = NULL;
		goto jump;
	}
	DPRINTK(2,"%d: %s: start to scan this open\n", cur_pid, cpsMethod);
	found = insertList(ip);
	if (!found) {
		if (ip->info.scan_args.full_pn != NULL)
			ip->info.scan_args.full_pn = NULL;
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		kfree(ip);
		ip = NULL;
		MOD_DEC_REF_COUNT;
		DPRINTK(2,"%d: %s: if (!found), return -EACCES\n", cur_pid, cpsMethod);
		SetAuditContext(current_audit);
		return(-EACCES);
	}
	atomic_set(&candidate, TRUE);
	wake_up_interruptible(&vsapi_chldn_wq);
	/* scan this open() only when opened in RDONLY/RDWR mode */
	//  if (timeout > 0) {
	//	/* to be implemented */
	//    } else {
	DPRINTK(2,"%d: %s: sleep on open_wq\n", cur_pid, cpsMethod);
	wait_event(open_wq, atomic_read(&(ip->info.cond)));
	//  }
	DPRINTK(3,"%d: %s: other pid %d, fd %d, filename %s\n", cur_pid, cpsMethod, ip->info.scan_args.comm_pid, ip->info.scan_args.fd, ip->info.scan_args.full_pn);

	if (ip->info.vsapi_busy == FALSE) {
		vsapi_ret = ip->info.scan_args.vsapi_ret;
		action = ip->info.scan_args.action;
		if (vsapi_ret == VIRUS_FOUND) {
			/* should be revised here */
			removeCache(inode);
			switch (action) 
			{
			case CLEAN:
				DPRINTK(3,"%d: %s: action CLEAN\n", cur_pid, cpsMethod);
				break;
			case DELETE:
				DPRINTK(3,"%d: %s: action DELETE\n", cur_pid, cpsMethod);
				break;
			case MOVE:
				DPRINTK(3,"%d: %s: action MOVE\n", cur_pid, cpsMethod);
				break;
			case RENAME:
				DPRINTK(3,"%d: %s: action RENAME\n", cur_pid, cpsMethod);
				break;
			case BYPASS:
				DPRINTK(3,"%d: %s: action BYPASS\n", cur_pid, cpsMethod);
				break;
			case DENYACCESS:
				DPRINTK(3,"%d: %s: action DENYACCESS\n", cur_pid, cpsMethod);
				found = deleteList(ip);
				if (!found)
					DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
				ip = NULL;
				/* permission denied */
				ret = -EACCES;
				MOD_DEC_REF_COUNT;
				DPRINTK(2,"%d: %s: return -EACCES\n", cur_pid, cpsMethod);
				SetAuditContext(current_audit);
				return(ret);
			default:
				DPRINTK(3,"%d: %s: action UNKNOWN\n", cur_pid, cpsMethod);
				found = deleteList(ip);
				if (!found)
					DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
				ip = NULL;
				/* permission denied */
				ret = -EACCES;
				MOD_DEC_REF_COUNT;
				DPRINTK(2,"%d: %s: return -EACCES\n", cur_pid, cpsMethod);
				SetAuditContext(current_audit);
				return(ret);
			}
		} else if (vsapi_ret == NO_VIRUS) {
			/* 
			* only perfectly clean files can be
			* added to the cache
			*/
			if ((flags & O_ACCMODE) == O_RDONLY) {
				addCache(inode);
			}
		} else {
			DPRINTK(3,"%d: %s: vsapi_ret UNKNOWN\n", cur_pid, cpsMethod);
			found = deleteList(ip);
			if (!found)
				DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
			ip = NULL;
			/* permission denied */
			ret = -EACCES;
			MOD_DEC_REF_COUNT;
			DPRINTK(2,"%d: %s: if (!found), return -EACCES\n", cur_pid, cpsMethod);
			SetAuditContext(current_audit);
			return(ret);
		}
	} else { /* VSAPI time out */
		vsapi_chld_pid = ip->info.scan_args.vsapi_chld_pid;
		if (vsapi_chld_pid > 0) {
			/* from kernel/signal.c { */
			struct	siginfo info;
			info.si_signo = SIGTERM;
			info.si_errno = 0;
			info.si_code = SI_USER;
			info.si_pid = ip->info.scan_args.vsapi_chld_pid;
			info.si_uid = 0;
			splx_kill_proc(info.si_pid, info.si_signo, (int)&info);
			/* from kernel/signal.c } */
		}
	}


	if (ip != NULL) {
		found = deleteList(ip);
		if (!found)
			DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
		ip = NULL;
	}
jump:
	/* SPNT 5.x scans first and then open here if RDONLY */
	if (tmp != NULL)
	{
		putname(tmp);
	}
	SetAuditContext(current_audit);
	// If the file is a FIFO, it may be blocked in orig_open(), 
	// if KHM is unloaded at this time point. 
	// A kernel panic may happen when the orig_open() return
	// in another word, this change may lead to unload fail of splxmod 
	// when the orig_open() blocked in openning a FIFO file.
	ret = orig_open(filename, flags, mode);
	DPRINTK(1,"%d: %s: get outta openHook\n", cur_pid, cpsMethod);
	MOD_DEC_REF_COUNT;
    return (ret);
}

asmlinkage int closeHook(unsigned int fd) 
{
	const char * cpsMethod = "closeHook";
	unsigned int	flags = 0;
	pid_t	cur_pid = 0;
	unsigned long       inode=0;
	mode_t      st_mode=0;
	LIST_ITEM *     ip=NULL;
	char        *comm=NULL;
	int clen;
	int	ret;
	int	vsapi_ret;
	int	action;
	Boolean	found;
	int vsapi_chld_pid;
	struct file *f = NULL;
	struct dentry *dentry = NULL;
	struct vfsmount *vfsmnt = NULL;
	long timeout;
	Boolean scan_close;
	DECLARE_WAIT_QUEUE_HEAD(close_wq);
	CP_DBG_LVL;
	MOD_INC_REF_COUNT;
    cur_pid = current->pid;
	//First check whether the command is in the exclusion list
	if(InExcComms(current->comm)){
      MOD_DEC_REF_COUNT;
	  DPRINTK(3,"%d: %s: not to scan command [%s] because it in the command exclusion list\n", cur_pid, cpsMethod, current->comm);
	  return orig_close(fd);
	}
	
	DPRINTK(1,"%d: %s: get into closeHook, comm = [%s]\n", cur_pid, cpsMethod, current->comm);
	
	if ((f = fget(fd))) {
		// do dget and mntget here, or else they might be destroyed after invoking the original close.
		dentry = dget(f->f_dentry);
		vfsmnt = mntget(f->f_vfsmnt);
		inode = f->f_dentry->d_inode->i_ino;
		st_mode = f->f_dentry->d_inode->i_mode;
		flags = f->f_flags;
		fput(f);
	}
	DPRINTK(2,"%d: %s: inode=[%ld]\n", cur_pid, cpsMethod, inode);

	ret = orig_close(fd);

	DPRINTK(2,"%d: %s: orig_close() ret %d\n", cur_pid, cpsMethod, ret);
    
    //TT216607: Some special fs have no open function, so vsapiapp will crash when scan the file
	if (!f) {
		DPRINTK(1,"%d: %s: get outta closeHook\n", cur_pid, cpsMethod);
		MOD_DEC_REF_COUNT;
		return ret;
	} else if (ret < 0 || !f->f_op->open) { // it's possible we got file struct (a valid fd), however, other errors occur in original close.
		DPRINTK(1,"%d: %s: get outta closeHook\n", cur_pid, cpsMethod);
		dput(dentry);
		mntput(vfsmnt);
		MOD_DEC_REF_COUNT;
		return ret;
	}
	if (!initialized()) {
		DPRINTK(2,"%d: %s: vsapi_chldn_no=0 || !inited, goto jump\n", cur_pid, cpsMethod);
		dput(dentry);
		mntput(vfsmnt);
		goto jump;
	}

	read_lock(&kini_lock);
	DPRINTK(2,"%d: %s: vsapi_chldn_no %d\n", cur_pid, cpsMethod, vsapi_chldn_no);
	if (inExcForest(exc_pid_ary, exc_pid_no)) {
		DPRINTK(2,"%d: %s: inExcForest() returned true, goto jump\n", cur_pid, cpsMethod);
		read_unlock(&kini_lock);
		dput(dentry);
		mntput(vfsmnt);
		goto jump;
	}
	read_unlock(&kini_lock);

	DPRINTK(2,"%d: %s: st_mode %x\n", cur_pid, cpsMethod, st_mode);
	//Fix a bug when vsapiapp scan a file with st_mode 180, kernel panic.
	//Need to revise: Only scan regular file and link file.	
    if(!S_ISNORMAL(st_mode)){
		DPRINTK(2,"%d: %s: not regular file or link, goto jump\n", cur_pid, cpsMethod);
		dput(dentry);
		mntput(vfsmnt);
		goto jump;
	}

	read_lock(&kini_lock);
	scan_close = needToScanThisClose(dentry, vfsmnt, flags, inode);
	read_unlock(&kini_lock);

	if (((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR))
		removeCache(inode);

	DPRINTK(2,"%d: %s: scan_close: %d\n", cur_pid, cpsMethod, scan_close);

	if (!scan_close) {
		DPRINTK(2,"%d: %s: no need to scan this file close, goto jump\n", cur_pid, cpsMethod);
		dput(dentry);
		mntput(vfsmnt);
		goto jump;
	}

	ip = (LIST_ITEM *)kmalloc(sizeof(LIST_ITEM), GFP_ATOMIC);
	if (ip == NULL)
	{
		WPRINTK("SPLXMOD: %d: %s: ip is NULL\n", cur_pid, cpsMethod);
		dput(dentry);
		mntput(vfsmnt);
		goto jump;
	}
	memset(ip, 0, sizeof(LIST_ITEM));
	ip->info.scan_args.full_pn = (char*)dentry->d_name.name;
	clen = strlen(current->comm);
	comm = (char *)kmalloc(clen+1, GFP_ATOMIC);
	if (comm == NULL)
	{
		WPRINTK("SPLXMOD: %d: %s: comm is NULL\n", cur_pid, cpsMethod);
		kfree(ip);
		ip = NULL;
		dput(dentry);
		mntput(vfsmnt);
		goto jump;
	}
	ip->info.scan_args.comm = comm;
	strncpy(ip->info.scan_args.comm, current->comm, clen+1);
	ip->info.scan_args.comm_pid = current->pid;
	ip->info.scan_args.comm_uid = current->SPLX_UID;
	ip->info.scan_args.flags = flags;
	ip->info.scan_args.lip = ip;
	ip->info.scan_args.inode = inode;
	ip->info.vsapi_busy = FALSE;
	ip->info.candid = TRUE;
	atomic_set(&(ip->info.cond),FALSE);
	ip->info.dentry = dentry;
	ip->info.mnt = vfsmnt;
	INIT_LIST_HEAD(&ip->item_list);
	read_lock(&kini_lock);
	timeout = scan_timeout_HZ;
	read_unlock(&kini_lock);
	if (!initialized()) {
		if (ip->info.scan_args.full_pn != NULL)
			ip->info.scan_args.full_pn = NULL;
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
		kfree(ip);
		ip = NULL;
		dput(dentry);
		mntput(vfsmnt);
		goto jump;
	}
	DPRINTK(2,"%d: %s: start to scan this close\n", cur_pid, cpsMethod);
	found = insertList(ip);
	if (!found) {
		if (ip->info.scan_args.full_pn != NULL)
			ip->info.scan_args.full_pn = NULL;
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
		kfree(ip);
		ip = NULL;
		dput(dentry);
		mntput(vfsmnt);
		MOD_DEC_REF_COUNT;
		DPRINTK(2,"%d: %s: if (!found), return -EACCES\n", cur_pid, cpsMethod);
		return(-EACCES);
	}
	atomic_set(&candidate, TRUE);
	wake_up_interruptible(&vsapi_chldn_wq);
	/* scan this open() only when opened in RDONLY/RDWR mode */
	//  if (timeout > 0) {
	//	/* to be implemented */
	//    } else {
	DPRINTK(2,"%d: %s: sleep on close_wq\n", cur_pid, cpsMethod);
	wait_event(close_wq, atomic_read(&(ip->info.cond)));
	//    }
	DPRINTK(3,"%d: %s: other pid %d, fd %d, filename %s\n", cur_pid, cpsMethod, ip->info.scan_args.comm_pid, ip->info.scan_args.fd, ip->info.scan_args.full_pn);
	if (ip->info.vsapi_busy == FALSE) {
		vsapi_ret = ip->info.scan_args.vsapi_ret;
		action = ip->info.scan_args.action;
		if (vsapi_ret == VIRUS_FOUND) {
			/* should be revised here */
			//removeCache(inode);
			switch (action) 
			{
			case CLEAN:
				DPRINTK(3,"%d: %s: action CLEAN\n", cur_pid, cpsMethod);
				break;
			case DELETE:
				DPRINTK(3,"%d: %s: action DELETE\n", cur_pid, cpsMethod);
				break;
			case MOVE:
				DPRINTK(3,"%d: %s: action MOVE\n", cur_pid, cpsMethod);
				break;
			case RENAME:
				DPRINTK(3,"%d: %s: action RENAME\n", cur_pid, cpsMethod);
				break;
			case DENYACCESS:
				DPRINTK(3,"%d: %s: action DENYACCESS\n", cur_pid, cpsMethod);
				break;
			case BYPASS:
				DPRINTK(3,"%d: %s: action BYPASS\n", cur_pid, cpsMethod);
				break;
			default:
				DPRINTK(3,"%d: %s: action UNKNOWN\n", cur_pid, cpsMethod);
				break;
			}
		} else if (vsapi_ret == NO_VIRUS) {
			/*
			* only perfectly clean files can be
			* added to the cache
			*/
			addCache(inode);
		} else {
			DPRINTK(3,"%d: %s: vsapi_ret UNKNOWN\n", cur_pid, cpsMethod);
		}
	} else {
		vsapi_chld_pid = ip->info.scan_args.vsapi_chld_pid;
		if (vsapi_chld_pid > 0) {
			/* from kernel/signal.c { */
			struct	siginfo info;
			info.si_signo = SIGTERM;
			info.si_errno = 0;
			info.si_code = SI_USER;
			info.si_pid = ip->
				info.scan_args.vsapi_chld_pid;
			info.si_uid = 0;
			splx_kill_proc(info.si_pid, info.si_signo, (int)&info);
			/* from kernel/signal.c } */
		}
	}

	if (ip != NULL) {
		found = deleteList(ip);
		if (!found)
			DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
		ip = NULL;
	}

jump:
	DPRINTK(2,"%d: %s: cur_pid %d, fd %d\n", cur_pid, cpsMethod, cur_pid, fd);

	DPRINTK(1,"%d: %s: get outta closeHook\n", cur_pid, cpsMethod);
	MOD_DEC_REF_COUNT;
	return(ret);
}

asmlinkage int exitHook(int errcode) 
{
	const char * cpsMethod = "exitHook";
	pid_t	cur_pid = 0;
	Boolean	found;
	CP_DBG_LVL;

	MOD_INC_REF_COUNT;
	cur_pid = current->pid;
	DPRINTK(3,"%d: %s: get into exitHook\n", cur_pid, cpsMethod);
	found = deleteListPID(cur_pid);
	if (!found)
		DPRINTK(3,"%d: %s: deleteListPID not found\n", cur_pid, cpsMethod);
	MOD_DEC_REF_COUNT;
	DPRINTK(3,"%d: %s: get out of exitHook\n", cur_pid, cpsMethod);
	return orig_exit(errcode);
}

extern int (*orig_do_execve)(char * ,
	char __user *__user *,
	char __user *__user *,
	struct pt_regs * );

int execveHook(struct pt_regs regs) 
{

	const char * cpsMethod = "execveHook";
	ino_t	inode=0;
	mode_t	st_mode;
	int	ret;
	pid_t   cur_pid = 0;
	Boolean found;
	int error;
	LIST_ITEM	*ip=NULL;
	char	*comm=NULL;
	int	vsapi_ret;
	int	action;
	int	clen;
	int	vsapi_chld_pid;
	struct stat	statbuf;
	char * filename;
	long timeout;
	struct audit_context * current_audit;
	Boolean scan_execve = FALSE;
#if LINUX_VERSION_CODE >= 0x30000
	struct path pPath;
#else
	struct nameidata nd;
#endif

	DECLARE_WAIT_QUEUE_HEAD(execve_wq);
	CP_DBG_LVL;

	MOD_INC_REF_COUNT;

	//Add for avoid conflict with auditd
	current_audit = ClearAuditContext();
	//Add end

	cur_pid = current->pid;
	
	DPRINTK(1,"%d: %s: get into execveHook\n", cur_pid, cpsMethod);
	found = deleteListPID(cur_pid);
	if (!found)
		DPRINTK(3,"%d: %s: deleteListPID not found\n", cur_pid, cpsMethod);
#if LINUX_VERSION_CODE <= 0x20612
#ifdef S390 
	filename = getname((char *) regs.orig_gpr2);
#else
	filename = getname((char *) regs.ebx);
#endif
#else
	filename = getname((char __user *) regs.bx);

#endif
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;
	DPRINTK(3,"%d: %s: get into execveHook filename %s\n", cur_pid, cpsMethod, filename);

	//First check whether the command is in the exclusion list
	if(InExcComms(current->comm)){
	  DPRINTK(2,"%d: %s: not to scan because command [%s] in the command exclusion list\n", cur_pid, cpsMethod, current->comm);
	  goto jump;
	}

	if (!initialized()) {
		DPRINTK(2,"%d: %s: vsapi_chldn_no=0 || !inited, goto jump\n", cur_pid, cpsMethod);
		goto jump;
	}

	read_lock(&kini_lock);
	DPRINTK(2,"%d: %s: vsapi_chldn_no %d\n", cur_pid, cpsMethod, vsapi_chldn_no);
	if (inExcForest(exc_pid_ary, exc_pid_no)) {
		read_unlock(&kini_lock);
		goto jump;
	}
	read_unlock(&kini_lock);

	error = getStat(filename, &statbuf);
	if (error) {
		DPRINTK(2,"%d: %s: stat error %d\n", cur_pid, cpsMethod, error);
		goto jump;
	}
	inode = statbuf.st_ino;
	DPRINTK(2,"%d: %s: inode %ld\n", cur_pid, cpsMethod, inode);
	st_mode = statbuf.st_mode;
	DPRINTK(2,"%d: %s: st_mode %x\n", cur_pid, cpsMethod, st_mode);
	if (!S_ISNORMAL(st_mode)) {
		DPRINTK(2,"%d: %s: not regular file or link\n", cur_pid, cpsMethod);
		goto jump;
	}

#if LINUX_VERSION_CODE < 0x20600
	error = PATH_LOOKUP(filename, LOOKUP_FOLLOW|LOOKUP_POSITIVE, &nd);
#elif LINUX_VERSION_CODE >= 0x30000
	error = kern_path(filename, LOOKUP_FOLLOW, &pPath);
#else
    //TT215640: Crash happens on NFSv4 share directory
	error = PATH_LOOKUP(filename, LOOKUP_FOLLOW, &nd);
#endif
	if (error)
		goto jump;

	read_lock(&kini_lock);
#if LINUX_VERSION_CODE >= 0x30000
	scan_execve = needToScanThisExecve(pPath.dentry, pPath.mnt, inode);
#else
	scan_execve = needToScanThisExecve(nd.DENTRY, nd.MNT, inode);
#endif
	read_unlock(&kini_lock);

	if (!scan_execve) {
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		goto jump;
	}

	ip = (LIST_ITEM *)kmalloc(sizeof(LIST_ITEM), GFP_ATOMIC);
	if (ip == NULL){
		WPRINTK("SPLXMOD: %d: %s: ip is NULL\n", cur_pid, cpsMethod);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		goto jump;
	}
	memset(ip, 0, sizeof(LIST_ITEM));
#if LINUX_VERSION_CODE >= 0x30000
	ip->info.scan_args.full_pn = (char *) pPath.dentry->d_name.name;
#else
	ip->info.scan_args.full_pn = (char *) nd.DENTRY->d_name.name;
#endif
	clen = strlen(current->comm);
	comm = (char *)kmalloc(clen+1, GFP_ATOMIC);
	if (comm == NULL)
	{
		WPRINTK("SPLXMOD: %d: %s: comm is NULL\n", cur_pid, cpsMethod);
		kfree(ip);
		ip = NULL;
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		goto jump;
	}
	ip->info.scan_args.comm = comm;
	strncpy(ip->info.scan_args.comm, current->comm, clen + 1);
	ip->info.scan_args.comm_pid = current->pid;
	ip->info.scan_args.comm_uid = current->SPLX_UID;
	ip->info.scan_args.lip = ip;
	ip->info.scan_args.inode = inode;
	ip->info.vsapi_busy = FALSE;
	ip->info.candid = TRUE;
	atomic_set(&(ip->info.cond),FALSE);
#if LINUX_VERSION_CODE >= 0x30000
	ip->info.dentry = pPath.dentry;
	ip->info.mnt = pPath.mnt;
#else
	ip->info.dentry = nd.DENTRY;
	ip->info.mnt = nd.MNT;
#endif
	INIT_LIST_HEAD(&ip->item_list);
	read_lock(&kini_lock);
	timeout = scan_timeout_HZ;
	read_unlock(&kini_lock);
	if (!initialized()) {
		if (ip->info.scan_args.full_pn != NULL)
			ip->info.scan_args.full_pn = NULL;
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		kfree(ip);
		ip = NULL;
		goto jump;
	}
	DPRINTK(2,"%d: %s: start to scan this execve\n", cur_pid, cpsMethod);
	found = insertList(ip);
	if (!found) {
		if (ip->info.scan_args.full_pn != NULL)
			ip->info.scan_args.full_pn = NULL;
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
#if LINUX_VERSION_CODE >= 0x30000
		path_put(&pPath);
#else
		SPLX_PATH_RELEASE(&nd);
#endif
		kfree(ip);
		putname(filename);
		MOD_DEC_REF_COUNT;
		SetAuditContext(current_audit);
		return(-EACCES);
	}
	atomic_set(&candidate, TRUE);
	wake_up_interruptible(&vsapi_chldn_wq);
	/* scan this execve() */
	//    if (timeout > 0) {
	//	/* to be implemented */
	//    } else {
	DPRINTK(2,"%d: %s: sleep on execve_wq\n", cur_pid, cpsMethod);
	wait_event(execve_wq, atomic_read(&(ip->info.cond)));
	//    }

	DPRINTK(3,"%d: %s: other pid %d, fd %d, filename %s\n", cur_pid, cpsMethod, ip->info.scan_args.comm_pid, ip->info.scan_args.fd, ip->info.scan_args.full_pn);

	if (ip->info.vsapi_busy == FALSE) {
		vsapi_ret = ip->info.scan_args.vsapi_ret;
		action = ip->info.scan_args.action;
		if (vsapi_ret == VIRUS_FOUND) {
			/* should be revised here */
			removeCache(inode);
			switch (action) 
			{
			case CLEAN:
				DPRINTK(3,"%d: %s: action CLEAN\n", cur_pid, cpsMethod);
				break;
			case DELETE:
				DPRINTK(3,"%d: %s: action DELETE\n", cur_pid, cpsMethod);
				break;
			case MOVE:
				DPRINTK(3,"%d: %s: action MOVE\n", cur_pid, cpsMethod);
				break;
			case RENAME:
				DPRINTK(3,"%d: %s: action RENAME\n", cur_pid, cpsMethod);
				break;
			case BYPASS:
				DPRINTK(3,"%d: %s: action BYPASS\n", cur_pid, cpsMethod);
				break;
			case DENYACCESS:
				DPRINTK(3,"%d: %s: action DENYACCESS\n", cur_pid, cpsMethod);
				found = deleteList(ip);
				if (!found)
					DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
				ip = NULL;
				/* permission denied */
				ret = -EACCES;
				putname(filename);
				MOD_DEC_REF_COUNT;
				SetAuditContext(current_audit);
				return(ret);
			default:
				DPRINTK(3,"%d: %s: action UNKNOWN\n", cur_pid, cpsMethod);
				found = deleteList(ip);
				if (!found)
					DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
				ip = NULL;
				/* permission denied */
				ret = -EACCES;
				putname(filename);
				MOD_DEC_REF_COUNT;
				SetAuditContext(current_audit);
				return(ret);
			}
		} else if (vsapi_ret == NO_VIRUS) {
			/* 
			* only perfectly clean files can be
			* added to the cache
			*/
			addCache(inode);
		} else {
			DPRINTK(3,"%d: %s: vsapi_ret UNKNOWN\n", cur_pid, cpsMethod);
			found = deleteList(ip);
			if (!found)
				DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
			ip = NULL;
			/* permission denied */
			ret = -EACCES;
			putname(filename);
			MOD_DEC_REF_COUNT;
			SetAuditContext(current_audit);
			return(ret);
		}
	} else { /* VSAPI time out */
		vsapi_chld_pid = ip->info.scan_args.vsapi_chld_pid;
		if (vsapi_chld_pid > 0) {
			/* from kernel/signal.c { */
			struct	siginfo info;
			info.si_signo = SIGTERM;
			info.si_errno = 0;
			info.si_code = SI_USER;
			info.si_pid = ip->
				info.scan_args.vsapi_chld_pid;
			info.si_uid = 0;
			splx_kill_proc(info.si_pid, info.si_signo, (int)&info);
			/* from kernel/signal.c } */
		}
	}

	if (ip != NULL) {
		found = deleteList(ip);
		if (!found)
			DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
		ip = NULL;
	}
jump:
//First release the filename then set audit flag back. Do that not to impact original execve
#ifndef S390
	if(filename != NULL)
	{
		putname(filename);
		filename = NULL;
	}
#endif
	SetAuditContext(current_audit);
//Re-do: filename
#if LINUX_VERSION_CODE <= 0x20612
#ifdef S390 
	filename = getname((char *) regs.orig_gpr2);
#else
	filename = getname((char *) regs.ebx);
#endif
#else
	filename = getname((char __user *) regs.bx);
#endif

#if LINUX_VERSION_CODE <= 0x20612
#ifdef NAS
	__asm__ volatile ("int $0x80"
		: "=a" (error)
		: "0" (NR_syscalls-1),
		"b" ((long)regs.ebx),
		"c" ((long)regs.ecx),
		"d" ((long)regs.edx));
#else
#ifdef S390
	error = do_execve(filename, (char **) regs.gprs[3], (char **) regs.gprs[4], &regs); 
	if (error == 0) {
		current->ptrace &= ~PT_DTRACE;
	}
#else
	error = orig_do_execve(filename, (char __user * __user *) regs.ecx, (char __user * __user *) regs.edx, &regs);

	if (error == 0)
	{
        #ifndef CONFIG_UTRACE
		task_lock(current);
		current->ptrace &= ~PT_DTRACE;
		task_unlock(current);
        #endif
		/* Make sure we don't return using sysenter.. */
		set_thread_flag(TIF_IRET);
	}
#endif
#endif
#else

error = orig_do_execve(filename,
		(char __user * __user *) regs.cx,
		(char __user * __user *) regs.dx,
		&regs);

if (error == 0)
{
	#ifndef CONFIG_UTRACE
		task_lock(current);
		current->ptrace &= ~PT_DTRACE;
		task_unlock(current);
	#endif

	/* Make sure we don't return using sysenter.. */
	set_thread_flag(TIF_IRET);
}

#endif

#ifndef S390
	if(filename != NULL)
	{
		putname(filename);
		filename = NULL;
	}
#endif

	DPRINTK(2,"%d: %s: error [%d]\n", cur_pid, cpsMethod, error);
	DPRINTK(1,"%d: %s: get outta execveHook\n", cur_pid, cpsMethod);
out:
	MOD_DEC_REF_COUNT;
	return error;
}

#ifdef	NFSD
int nfsdOpenHook(struct svc_rqst *rqstp, struct svc_fh *fhp, int type,
				 int access, struct file *filp) 
{
	const char * cpsMethod = "nfsdOpenHook";
	pid_t cur_pid=0;
	ino_t	inode=0;
	mode_t	st_mode;
	int	ret;
	LIST_ITEM	*ip=NULL;
	char	*cp = NULL;
	Boolean	found;
	int	vsapi_ret;
	int	action;
	int	clen;
	int	vsapi_chld_pid;
	int	error;
	char	*filename;
	int	flags;
	struct dentry   *dentry;
	struct vfsmount *vfsmnt;
	char *page = (char *) __get_free_page(GFP_KERNEL);
	CP_DBG_LVL;

	cur_pid = current->pid;
	error = fh_verify(rqstp, fhp, type, access | MAY_OWNER_OVERRIDE);
	if (error)
		return error;
	dentry = fhp->fh_dentry;
	filename = dentry->d_name.name;
	if (access & MAY_WRITE) {
		flags = O_WRONLY|O_LARGEFILE;
	} else {
		flags = O_RDONLY|O_LARGEFILE;
	}
	DPRINTK(1,"%d: %s: get into nfsdOpenHook filename %s, flags %x\n", cur_pid, cpsMethod, filename, flags);

	spin_lock(&my_lock);
	DPRINTK(2,"%d: %s: vsapi_chldn_no %d\n", cur_pid, cpsMethod, vsapi_chldn_no);
	if (vsapi_chldn_no == 0) goto jump;

	if (inExcForest(exc_pid_ary, exc_pid_no)) goto jump;

	spin_unlock(&my_lock);
	vfsmnt = fhp->fh_export->ex_mnt;
	if (page) {
		unsigned long len;
		char *fpn = d_path(dentry, vfsmnt, page, PAGE_SIZE);
		len = PAGE_SIZE + page - fpn;
		if (len <= MAX_PATH_LEN_DEF) {
			cp = (char *)kmalloc(len+1, GFP_KERNEL);
			if (cp == NULL)
				printk(KERN_WARNING "SPLXMOD: cp is NULL\n", cur_pid, cpsMethod);
			strncpy(cp, fpn, len+1);
			DPRINTK(2,"%d: %s: full pathname %s\n", cur_pid, cpsMethod, cp);
		}
		free_page((unsigned long) page);
	}
	ip = (LIST_ITEM *)kmalloc(sizeof(LIST_ITEM), GFP_KERNEL);
	if (ip == NULL)
		printk(KERN_WARNING "SPLXMOD: ip is NULL\n", cur_pid, cpsMethod);
	memset(ip, 0, sizeof(LIST_ITEM));
	ip->info.scan_args.full_pn = cp;
	clen = strlen(current->comm);
	cp = (char *)kmalloc(clen+1, GFP_KERNEL);
	if (cp == NULL)
		printk(KERN_WARNING "SPLXMOD: cp is NULL\n", cur_pid, cpsMethod);
	ip->info.scan_args.comm = cp;
	strncpy(ip->info.scan_args.comm, current->comm, clen + 1);
	ip->info.scan_args.comm_pid = current->pid;
	ip->info.scan_args.comm_uid = current->SPLX_UID;
	ip->info.scan_args.flags = flags;
	ip->info.scan_args.fd = filp;
	ip->info.scan_args.lip = ip;
	ip->info.vsapi_busy = FALSE;
	ip->info.candid = FALSE;
	init_waitqueue_head(&(ip->info.other_proc_wq));
	ip->next = NULL;
	spin_lock(&my_lock);
	found = insertList(ip);
	spin_unlock(&my_lock);
	if (!found) {
		if (ip->info.scan_args.full_pn != NULL)
			kfree(ip->info.scan_args.full_pn);
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
		kfree(ip);
		return(-EACCES);
	}

	spin_lock(&my_lock);
	inode = dentry->d_inode->i_ino;
	ip->info.scan_args.inode = inode;
	DPRINTK(2,"%d: %s: inode %ld\n", cur_pid, cpsMethod, inode);
	st_mode = dentry->d_inode->i_mode;
	DPRINTK(2,"%d: %s: st_mode %x\n", cur_pid, cpsMethod, st_mode);
	if (S_ISDIR(st_mode) || S_ISCHR(st_mode) || S_ISBLK(st_mode) ||	S_ISFIFO(st_mode) || S_ISSOCK(st_mode)) {
		DPRINTK(2,"%d: %s: not regular file or link\n", cur_pid, cpsMethod);
		found = deleteList(ip);
		if (!found)
			DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
		ip = NULL;
		goto jump;
	}

	/* scan this open() only when opened in RDONLY/RDWR mode */
	if (needToScanThisOpen(ip->info.scan_args.full_pn, flags, inode)) {
		long timeout = scan_timeout_HZ;
		DPRINTK(2,"%d: %s: start to scan this open\n", cur_pid, cpsMethod);
		ip->info.candid = TRUE;
		DPRINTK(2,"%d: %s: wake up vsapi_chldn_wq\n", cur_pid, cpsMethod);
		WAKE_UP_INTERRUPTIBLE(&vsapi_chldn_wq);
		DPRINTK(3,"%d: %s: sleep on ip->info.other_proc_wq with scan_timeout_HZ\n", cur_pid, cpsMethod);
		spin_unlock(&my_lock);
		if (timeout > 0) {
			sleep_on_timeout(
				&(ip->info.other_proc_wq),
				timeout);
		} else {
			sleep_on(
				&(ip->info.other_proc_wq));
		}
		spin_lock(&my_lock);
		DPRINTK(3,"%d: %s: other pid %d, fd %d, filename %s\n", cur_pid, cpsMethod, ip->info.scan_args.comm_pid, ip->info.scan_args.fd, ip->info.scan_args.full_pn);

		if (ip->info.vsapi_busy == FALSE) {
			vsapi_ret = ip->info.scan_args.vsapi_ret;
			action = ip->info.scan_args.action;
			if (vsapi_ret == VIRUS_FOUND) {
				/* should be revised here */
				removeCache(inode);
				switch (action) 
				{
				case CLEAN:
					DPRINTK(3,"%d: %s: action CLEAN\n", cur_pid, cpsMethod);
					if ((flags & O_ACCMODE) == O_RDONLY) {
						found = deleteList(ip);
						if (!found)
							DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
						ip = NULL;
					}
					break;
				case DELETE:
					DPRINTK(3,"%d: %s: action DELETE\n", cur_pid, cpsMethod);
					break;
				case MOVE:
					DPRINTK(3,"%d: %s: action MOVE\n", cur_pid, cpsMethod);
					break;
				case RENAME:
					DPRINTK(3,"%d: %s: action RENAME\n", cur_pid, cpsMethod);
					break;
				case BYPASS:
					DPRINTK(3,"%d: %s: action BYPASS\n", cur_pid, cpsMethod);
					if ((flags & O_ACCMODE) == O_RDONLY) {
						found = deleteList(ip);
						if (!found)
							DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
						ip = NULL;
					}
					break;
				case DENYACCESS:
					DPRINTK(3,"%d: %s: action DENYACCESS\n", cur_pid, cpsMethod);
					found = deleteList(ip);
					if (!found)
						DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
					ip = NULL;
					/* permission denied */
					ret = -EACCES;
					spin_unlock(&my_lock);
					return(ret);
				default:
					DPRINTK(3,"%d: %s: action UNKNOWN\n", cur_pid, cpsMethod);
					found = deleteList(ip);
					if (!found)
						DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
					ip = NULL;
					/* permission denied */
					ret = -EACCES;
					spin_unlock(&my_lock);
					return(ret);
				}
			} else if (vsapi_ret == NO_VIRUS) {
				/* 
				* only perfectly clean files can be
				* added to the cache
				*/
				if ((flags & O_ACCMODE) == O_RDONLY) {
					addCache(inode);
					found = deleteList(ip);
					if (!found)
						DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
					ip = NULL;
				}
			} else {
				DPRINTK(3,"%d: %s: vsapi_ret UNKNOWN\n", cur_pid, cpsMethod);
				found = deleteList(ip);
				if (!found)
					DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
				ip = NULL;
				/* permission denied */
				ret = -EACCES;
				spin_unlock(&my_lock);
				return(ret);
			}
		} else { /* VSAPI time out */
			vsapi_chld_pid = ip->info.scan_args.vsapi_chld_pid;
			if (vsapi_chld_pid > 0) {
				/* from kernel/signal.c { */
				struct	siginfo info;
				info.si_signo = SIGTERM;
				info.si_errno = 0;
				info.si_code = SI_USER;
				info.si_pid = ip->
					info.scan_args.vsapi_chld_pid;
				info.si_uid = 0;
				splx_kill_proc(info.si_pid, info.si_signo, (int)&info);
				/* from kernel/signal.c } */
			}
		}
	}

jump:
	spin_unlock(&my_lock);
	/* SPNT 5.x scans first and then open here if RDONLY */
	ret = orig_nfsd_open(rqstp, fhp, type, access, filp);
	spin_lock(&my_lock);

	DPRINTK(2,"%d: %s: ret %d\n", cur_pid, cpsMethod, ret);
	if (ret != 0) {
		if (ip != NULL) {
			deleteList(ip);
			ip = NULL;
		}
	}

	DPRINTK(1,"%d: %s: get outta nfsdOpenHook\n", cur_pid, cpsMethod);
	spin_unlock(&my_lock);
	return(ret);
}
#if 0
void nfsdCloseHook(struct file *filp) 
{
	const char * cpsMethod = "nfsdCloseHook";
	int	flags;
	ino_t	inode;
	pid_t	cur_pid=0;
	LIST_ITEM *     ip;
	char	full_pn[PATH_MAX];
	int	ret;
	int	vsapi_ret;
	int	action;
	Boolean	found;
	int vsapi_chld_pid;
	struct stat	statbuf;
	int	error;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into nfsdCloseHook\n", cur_pid, cpsMethod);

	/* need to revise here */
	DPRINTK(2,"%d: %s: cur_pid %d, filp %x\n", cur_pid, cpsMethod, cur_pid, filp);
	orig_nfsd_close(filp);

	spin_lock(&my_lock);

	found = findList(cur_pid, filp, &ip);
	if (!found) {
		DPRINTK(2,"%d: %s: find list failed with PID %d, FILP %x\n", cur_pid, cpsMethod, cur_pid, filp);
		goto jump;
	}

	if (vsapi_chldn_no == 0) goto dellst;

	flags = ip->info.scan_args.flags;
	inode = ip->info.scan_args.inode;
	strncpy(full_pn, ip->info.scan_args.full_pn, PATH_MAX);
	if (inode == 0) {
		spin_unlock(&my_lock);
		error = getStat(full_pn, &statbuf);
		spin_lock(&my_lock);
		if (error == 0) 
			inode = ip->info.scan_args.inode = statbuf.st_ino;
	}
	ip->info.vsapi_busy = FALSE;
	ip->info.candid = FALSE;

	/* scan this close() only when opened in WRONLY/RDWR mode */
	if (needToScanThisClose(full_pn, flags)) {
		long timeout = scan_timeout_HZ;
		DPRINTK(2,"%d: %s: start to scan this close\n", cur_pid, cpsMethod);
		ip->info.candid = TRUE;
		WAKE_UP_INTERRUPTIBLE(&vsapi_chldn_wq);
		spin_unlock(&my_lock);
		if (timeout > 0) {
			sleep_on_timeout(
				&(ip->info.other_proc_wq),
				timeout);
		} else {
			sleep_on(
				&(ip->info.other_proc_wq));
		}
		spin_lock(&my_lock);
		DPRINTK(3,"%d: %s: other pid %d, filp %x, filename %s\n", cur_pid, cpsMethod, ip->info.scan_args.comm_pid, ip->info.scan_args.fd, ip->info.scan_args.full_pn);
		if (ip->info.vsapi_busy == FALSE) {
			vsapi_ret = ip->info.scan_args.vsapi_ret;
			action = ip->info.scan_args.action;
			if (vsapi_ret == VIRUS_FOUND) {
				/* should be revised here */
				removeCache(inode);
				switch (action) 
				{
				case CLEAN:
					DPRINTK(3,"%d: %s: action CLEAN\n", cur_pid, cpsMethod);
					break;
				case DELETE:
					DPRINTK(3,"%d: %s: action DELETE\n", cur_pid, cpsMethod);
					/* permission denied */
					ret = -1;
					break;
				case MOVE:
					DPRINTK(3,"%d: %s: action MOVE\n", cur_pid, cpsMethod);
					/* permission denied */
					ret = -1;
					break;
				case RENAME:
					DPRINTK(3,"%d: %s: action RENAME\n", cur_pid, cpsMethod);
					/* permission denied */
					ret = -1;
					break;
				case DENYACCESS:
					DPRINTK(3,"%d: %s: action DENYACCESS\n", cur_pid, cpsMethod);
					break;
				case BYPASS:
					DPRINTK(3,"%d: %s: action BYPASS\n", cur_pid, cpsMethod);
					break;
				default:
					DPRINTK(3,"%d: %s: action UNKNOWN\n", cur_pid, cpsMethod);
					/* permission denied */
					ret = -1;
					break;
				}
			} else if (vsapi_ret == NO_VIRUS) {
				/*
				* only perfectly clean files can be
				* added to the cache
				*/
				addCache(inode);
			} else {
				DPRINTK(3,"%d: %s: vsapi_ret UNKNOWN\n", cur_pid, cpsMethod);
				/* permission denied */
				ret = -1;
			}
		} else {
			vsapi_chld_pid = ip->info.scan_args.vsapi_chld_pid;
			if (vsapi_chld_pid > 0) {
				/* from kernel/signal.c { */
				struct	siginfo info;
				info.si_signo = SIGTERM;
				info.si_errno = 0;
				info.si_code = SI_USER;
				info.si_pid = ip->
					info.scan_args.vsapi_chld_pid;
				info.si_uid = 0;
				splx_kill_proc(info.si_pid, info.si_signo, (int)&info);
				/* from kernel/signal.c } */
			}
		}
	}

dellst:
	found = deleteList(ip);
	if (!found)
		DPRINTK(3,"%d: %s: deleteList not found\n", cur_pid, cpsMethod);
	ip = NULL;
jump:
	DPRINTK(1,"%d: %s: get outta nfsdCloseHook\n", cur_pid, cpsMethod);
	spin_unlock(&my_lock);
	return;
}
#endif
#endif
