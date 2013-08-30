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
 ** Modify to support kernel version 3.0
 ** Modify Date: 2012/06/21
 ** Modify By:	 samir_bai@trendmicro.com.cn
 **/


#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/vermagic.h>
#include <linux/security.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include <linux/security.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE < 0x30000
#include <linux/smp_lock.h>
#endif
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/spinlock.h>

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/fcntl.h>

#include <linux/sys.h>
#include <asm/atomic.h>

#include "splxmod.h"
#include "hook_lsm.h"

#ifdef USE_LSM_HOOK
#define DEFAULT_SECURITY_ADDR_NAME "default_security_ops"
#define SECURITY_ADDR_NAME         "security_ops"
#include <linux/kallsyms.h>

//Address of "security_ops"
static void ** p_security_ops_addr = NULL;
//Address of "default_security_ops"
static void ** p_default_security_ops_addr = NULL;

static struct security_operations * splx_security_ops = NULL;

extern rwlock_t kini_lock;
extern int     g_iDbgLevel;
extern pid_t  *exc_pid_ary;
extern int     exc_pid_no;
extern spinlock_t dbg_lock;
extern atomic_t	candidate;
extern wait_queue_head_t vsapi_chldn_wq;
extern int    vsapi_chldn_no;

extern Boolean initialized(void);
extern Boolean InExcComms(const char* comm);
extern Boolean inExcForest(pid_t *exc_pid_ary, int exc_pid_no);
extern Boolean needToScanThisExecve(struct dentry * dentry, struct vfsmount * mnt, ino_t inode);
extern Boolean insertList(LIST_ITEM *);
extern Boolean deleteList(LIST_ITEM *);
extern Boolean S_ISNORMAL(mode_t st_mode);
extern int splx_kill_proc(pid_t pid, int sig, int priv);
extern void addCache(ino_t);
extern void removeCache(ino_t);

inline void* splx_malloc(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

inline int splx_free(void *ptr)
{
	kfree(ptr);
    ptr = NULL;
	return 0;
}

#if 0
inline int splx_strlen(const char *str)
{
	const char	*p;

	if (str == NULL)
		return -1;

	for (p=str ; *p ; p++)
		continue;

	return (p - str);
}
#endif
/*
 * The hook function for execve Hook
 * file_permission
 */

static int splx_file_permission(struct file *file, int mask)
{
    const char * cpsMethod = "splx_file_permission";
    //Default value is a must for ret
    int ret = 0;
    char	*comm=NULL;
    void * temp_ip;
	int	vsapi_ret;
	int	action;
	int	clen;
    LIST_ITEM	*ip=NULL;
    struct inode *inode = NULL;
    ino_t i_inode = 0;
    mode_t st_mode;
    char * short_name = NULL;
    int	vsapi_chld_pid = 0;
    pid_t cur_pid = current->pid;
    bool scan_execve = true;
    int found = 0;
    DECLARE_WAIT_QUEUE_HEAD(execve_wq);
    CP_DBG_LVL;
    if(file == NULL || !mask)
    {
        return 0;
    }
    
    MOD_INC_REF_COUNT;
    inode = file->f_path.dentry->d_inode;
    st_mode = inode->i_mode;
    i_inode = inode->i_ino;
    
    short_name = (char *)file->f_dentry->d_name.name;

    /*Warning: Not to add log here. Because when debug log is enabled, everytime debug log file is accessed
     *The log item will be recorded. It cause High CPU
     *DPRINTK(3,"%s: get into execveHook. Filename [%s], st_mode [%d], inode [%lu]\n", cpsMethod, short_name, st_mode, i_inode);
     */
    if(!(FMODE_EXEC & file->f_flags))
    {
        goto out;
    }
    
    if (!initialized()) {
		DPRINTK(2,"%d: %s: vsapi_chldn_no=0 || !inited, goto out\n", cur_pid, cpsMethod);
		goto out;
	}
    //Only Scan regular file and link
	if (!S_ISNORMAL(st_mode)) {
        //Not add log here. Because direcotory operation will always goto here
		goto out;
	}

    //Bypass command white-list
    if(InExcComms(current->comm)){
	  DPRINTK(2,"%d: %s: not to scan because command [%s] in the command exclusion list\n", cur_pid, cpsMethod, current->comm);
      goto out;
	}

 	read_lock(&kini_lock);
	if (inExcForest(exc_pid_ary, exc_pid_no)) {
		DPRINTK(3,"%d: %s: inExcForest() returned true, goto out\n", cur_pid, cpsMethod);
		read_unlock(&kini_lock);
		goto out;
	}
	read_unlock(&kini_lock);

	read_lock(&kini_lock);
	scan_execve = needToScanThisExecve(file->f_dentry, file->f_vfsmnt, i_inode);
	read_unlock(&kini_lock);

	if (!scan_execve) {
		goto out;
	}
    DPRINTK(1,"%d: %s: Start to scan file [%s]\n", cur_pid, cpsMethod, short_name);
	ip = (LIST_ITEM *)splx_malloc(sizeof(LIST_ITEM));
	if (ip == NULL){
		WPRINTK("SPLXMOD: %d: %s: Alloc memory for ip failed\n", cur_pid, cpsMethod);
		goto out;
	}
    
	memset(ip, 0, sizeof(LIST_ITEM));
	ip->info.scan_args.full_pn = (char *)short_name;
    
	clen = strlen(current->comm);
	comm = (char *)kmalloc(clen+1, GFP_ATOMIC);
	if (comm == NULL)
	{
		WPRINTK("SPLXMOD: %d: %s: Alloc memory for comm failed\n", cur_pid, cpsMethod);
		splx_free(ip);
		goto out;
	}
    
	ip->info.scan_args.comm = comm;
	strncpy(ip->info.scan_args.comm, current->comm, clen + 1);
	ip->info.scan_args.comm_pid = current->pid;
	ip->info.scan_args.comm_uid = current->SPLX_UID;
#ifdef __SPLX_X86_64
    temp_ip =  ip;
    ip->info.scan_args.u_lip = (((unsigned long)temp_ip)&0xffffffff00000000)>>32;
    temp_ip =  ip;
    ip->info.scan_args.d_lip= ((unsigned long)temp_ip)&0x0000ffffffffffff;
#else
    ip->info.scan_args.lip = ip;
#endif
	ip->info.scan_args.inode = i_inode;
	ip->info.vsapi_busy = FALSE;
	ip->info.candid = TRUE;
	atomic_set(&(ip->info.cond),FALSE);
    
	ip->info.dentry = dget(file->f_dentry);
	ip->info.mnt = mntget(file->f_vfsmnt);
    
	INIT_LIST_HEAD(&ip->item_list);
    
	if (!initialized()) {
		if (ip->info.scan_args.comm != NULL)
		{
			splx_free(ip->info.scan_args.comm);
		}
        dput(ip->info.dentry);
        mntput(ip->info.mnt);
		splx_free(ip);
		goto out;
	}
	DPRINTK(2,"%d: %s: start to scan this execve\n", cur_pid, cpsMethod);
	found = insertList(ip);
	if (!found) {
		if (ip->info.scan_args.comm != NULL)
			splx_free(ip->info.scan_args.comm);
        dput(ip->info.dentry);
        mntput(ip->info.mnt);
		splx_free(ip);
        goto out;
   	}
    
	atomic_set(&candidate, TRUE);
	wake_up_interruptible(&vsapi_chldn_wq);

	DPRINTK(2,"%d: %s: sleep on execve_wq\n", cur_pid, cpsMethod);
	wait_event(execve_wq, atomic_read(&(ip->info.cond)));
	//    }

	//DPRINTK(3,"%d: %s: other pid %d, fd %d, filename %s\n", cur_pid, cpsMethod, ip->info.scan_args.comm_pid, ip->info.scan_args.fd, ip->info.scan_args.full_pn);

	if (ip->info.vsapi_busy == FALSE) 
    {
		vsapi_ret = ip->info.scan_args.vsapi_ret;
		action = ip->info.scan_args.action;
		if (vsapi_ret == VIRUS_FOUND) 
        {
			/* should be revised here */
			removeCache(i_inode);
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
                ret  = -EACCES;
                break;
			default:
				DPRINTK(3,"%d: %s: action UNKNOWN\n", cur_pid, cpsMethod);
                ret  = -EACCES;
                break;
			}
		} 
        else if (vsapi_ret == NO_VIRUS) 
        {
			/* 
			* only perfectly clean files can be
			* added to the cache
			*/
			addCache(i_inode);
		} 
        else 
        {
            ret  = -EACCES;
			DPRINTK(3,"%d: %s: vsapi_ret UNKNOWN\n", cur_pid, cpsMethod);
		}
    } 
    else 
    { /* VSAPI time out */
        /*Never go to here because no timeout handling */
		vsapi_chld_pid = ip->info.scan_args.vsapi_chld_pid;
		if (vsapi_chld_pid > 0) {
			/* from kernel/signal.c { */
			struct	siginfo info;
			info.si_signo = SIGTERM;
			info.si_errno = 0;
			info.si_code = SI_USER;
			info.si_pid = ip->info.scan_args.vsapi_chld_pid;
			info.si_uid = 0;
			splx_kill_proc(info.si_pid, info.si_signo, (long)&info);
			/* from kernel/signal.c } */
		}
	}
    //Free the memory for the scanning items
	if (ip != NULL) 
    {
		found = deleteList(ip);
		if (!found)
		{
			DPRINTK(1,"%d: %s: warning: deleteList not found\n", cur_pid, cpsMethod);
		}
	}
out:
    MOD_DEC_REF_COUNT;
    return ret;
}

/* Function to register the LSM module */
inline void splx_register_security(struct security_operations *ops)
{
    *p_security_ops_addr = (void *)ops;
}

inline void splx_unregister_security(void)
{
    *p_security_ops_addr = (void *)p_default_security_ops_addr;
}
/*
 * Get the len of the str
 * @str: a substring of one line that we found in "find_symbol_addr"
 */

/*
static unsigned int symbol_len(const char * str)
{
    unsigned int i = 0;
    if (*(str-1) != ' ' && *(str-1) != '\t')
        return 0xFFFFFFFF;
 
    while (true)
    {
        if (str[i] == '\0' || str[i] == ' ' || str[i] == '\t' || str[i] == '\n')
            break;
        i++;
    }

    return i;
}
*/

/*
 * Convert the hex_str string to unsigned long
 * Refer to kernel API simple_strtoul
 * ffffffff81f22eb0 b security_ops
 * @hex_str: A line read from /proc/kallsyms
 */

/*
static 
unsigned long simple_hex_strtoul(const char* hex_str)
{
    int i = 0;
    unsigned long result = 0;

    for (i = 0; i < sizeof(unsigned long) * 2; i++) {
        if (hex_str[i] >= '0' && hex_str[i] <= '9') {
            result = result << 4;
            result = result + (hex_str[i] - '0');
        }
        else if (hex_str[i] >= 'a' && hex_str[i] <= 'f') {
            result = result << 4;
            result = result + (hex_str[i] - 'a') + 10;
        }
        else if (hex_str[i] >= 'A' && hex_str[i] <= 'F') {
            result = result << 4;
            result = result + (hex_str[i] - 'A') + 10;
        }
        else break;
    }

    return result;
}
*/

/* 
 * find the symbol address from /proc/kallsyms
 * @sym - symbol string
 */

/*
static
unsigned long find_symbol_addr(const char* sym)
{
    const char * fname = "/proc/kallsyms";
    struct file * fp;
    char buffer[128] = {0};
    char * p = NULL;
    mm_segment_t old_fs;
    bool stop = false;
    int i = 0;
    int ret = 0;
    unsigned long addr = 0;
    
    fp = filp_open(fname, O_RDONLY, 0);
    if(fp == NULL)
        return 0;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    while(!stop)
    {
        //ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
        i = 0;
        memset(buffer, 0, 128);
        do {
            // read one bye one till a line or error or 126
            ret = fp->f_op->read(fp, buffer + i, 1, &fp->f_pos);
            if (ret <= 0) stop = true;
            if (buffer[i] == '\n') break;
            if (i >= 126) break; 

            i++;
        } while (ret > 0);
        p = strstr(buffer, sym);
        if(NULL == p)
            continue;
        //We need to confirm the sym is the same with we find not a substring
        if(strlen(sym) == symbol_len(p))
        {
            addr = simple_hex_strtoul(buffer);
            break;
        }
    }

    set_fs(old_fs);
    fput(fp);
    return addr;
}
*/

// The Interface to do execve Hook
// Patch by fernando@mentebinaria.com.br to hook exevce in x86-64 arch
bool hook_lsm(void)
{
    const char * cpsMethod = "hook_lsm";
    unsigned long func_addr = 0; // address of a exported LSM functions that uses default_security_ops pointer
    unsigned long secops_addr;// = ULONG_MAX; // address of security_ops structure
    //unsigned long secops_addr = 0xffffffffffffffff; // address of security_ops structure
    
    CP_DBG_LVL;

    func_addr = kallsyms_lookup_name("reset_security_ops");

    if (!func_addr) 
    {
        DPRINTK(LOG_CLOSE, "%s: [Fatal] Lookup address for reset_security_ops failed. Can't enable execve Hook\n", cpsMethod);
        return false;
    }

    secops_addr = func_addr; // only to retain the 0xffffffff prefix

    // get security_ops pointer since its used inside reset_security_ops function
    if (memcpy(&secops_addr, (void *) (func_addr + 7), 4) == NULL)
    {
        DPRINTK(LOG_CLOSE, "%s: [Fatal] Lookup address for security ops failed. Can't enable execve Hook\n", cpsMethod);
        return false;
    }

    p_security_ops_addr = (void *)secops_addr;
    p_default_security_ops_addr = (void *)secops_addr;
    DPRINTK(LOG_DEBUG, "%s: Default security ops address [0x%lx], security ops value [0x%lx]\n",
            cpsMethod, (unsigned long)p_default_security_ops_addr, (unsigned long)(*p_security_ops_addr));

    //If another LMS has registerd, not do the hook.
/*
    if(*p_security_ops_addr != (void *)p_default_security_ops_addr)
    {
        //Warning: Not remove the [Fatal] because make test will show the log
        DPRINTK(LOG_CLOSE, "%s: [Fatal] Can't do execve Hook. Linux Security Module [%s] has registerd, not to register SPLX security module\n",
            cpsMethod, ((struct security_operations *)*p_security_ops_addr)->name);
        return false;
    }
*/
    splx_security_ops = (struct security_operations *)splx_malloc(sizeof(struct security_operations));
    if(NULL == splx_security_ops)
    {
        DPRINTK(LOG_CLOSE, "%s: [Fatal] Alloc memory failed for SPLX Security ops\n", cpsMethod);
        return false ;
    }
    
    memcpy(splx_security_ops, (void *)p_default_security_ops_addr, sizeof(struct security_operations));
    memcpy(splx_security_ops->name, "SPLX", SECURITY_NAME_MAX);
    splx_security_ops->name[SECURITY_NAME_MAX] = '\0';
    splx_security_ops->file_permission = splx_file_permission;

    splx_register_security(splx_security_ops);
    //This log is used for "make test" because make test will check if three hook points are hooked
    DPRINTK(LOG_WARNING, "hooked __NR_execve\n");
    return true;
  
}

/*The interface to do unregister execve Hook
 *Only call this function when hook_lsm return true
 */
void unhook_lsm(void)
{
    const char * cpsMethod = "unhook_lsm"; 
    CP_DBG_LVL;
    if(*p_security_ops_addr == splx_security_ops)
    {
        DPRINTK(LOG_WARNING, "%s: Unregister splx security module\n", cpsMethod);
        splx_unregister_security();
        splx_free(splx_security_ops);
    }
    else
    {
        DPRINTK(LOG_DEBUG, "%s: splx security module is not registered\n", cpsMethod);
    }
}
#endif

