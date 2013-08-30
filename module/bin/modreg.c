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
#	define MODVERSIONS /* force it on */
#endif

#ifdef MODVERSIONS
#	include <linux/modversions.h>
#endif
#endif
#include <linux/module.h>

#include	<linux/kernel.h>
#include	<linux/unistd.h>

#include	<linux/fs.h>
#include	<linux/mm.h>
#include	<linux/slab.h>
#include	<linux/ptrace.h>
#include	<linux/string.h>
#include        <linux/spinlock.h>
#include	<asm/atomic.h>
#if LINUX_VERSION_CODE >= 0x20600
#include <linux/init.h>
#include <linux/moduleparam.h>
#endif
#if LINUX_VERSION_CODE < 0x30000
#include	<linux/smp_lock.h>
#endif
#include        <linux/sys.h>
#include        <linux/delay.h>
#include        <linux/sched.h>
#ifdef X86_64
#include <linux/ioctl32.h>
#include <linux/syscalls.h>
#include <linux/ioctl32.h>

#include <linux/compat.h>
#include <linux/cdev.h>
#endif

#include <asm/uaccess.h>
#if LINUX_VERSION_CODE >= 0x20610
#include <asm/page.h>
#include <asm/cacheflush.h>
#endif

#include        <splxmod.h>
#ifdef	NFSD
#include	<linux/sunrpc/svc.h>
#include	<linux/nfsd/nfsd.h>
#define	__NR_nfsd_open	1
#define	__NR_nfsd_close	2
#endif
#ifdef IA32_HOOK
#include <splx_ia32_unistd.h>
#include "hook_ia32.h"
#endif

#include "hook_lsm.h"
// add by errik for /proc
#include <linux/proc_fs.h>
#define PROC_STR_SIZE     8

int khm_read_proc(char *, char **, off_t , int , int *, void *);
int khm_write_proc(struct file *, const char __user *, unsigned long , void *);
void unhook_module(void);
void hook_module(void);
// add end

// Proc entry read/write function.
// 150 for at least 10 command name.
#define PROC_COMMS_LENGTH 150
char g_exc_comms[PROC_COMMS_LENGTH+1]={0};
char exc_comms[PROC_COMMS_LENGTH+1]={0};
int khm_comms_read_proc(char *, char **, off_t, int, int*, void *);
int khm_comms_write_proc(struct file *, const char __user *, unsigned long , void *);
extern void parseAddExcComms(const char *comms);
extern void PrintExcComms(void);

extern rwlock_t hook_init_lock;
// Add end
extern asmlinkage int sys_execve_glue_hook(struct pt_regs);
#ifdef X86_64
#if LINUX_VERSION_CODE >= 0x20610
extern long ioctlMod(struct file *, unsigned int , unsigned long);
extern long splxmod_compat_ioctl(struct file *, unsigned int , unsigned long);
#else
extern long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
extern int ioctlMod(struct inode *, struct file *, unsigned int, unsigned long);
#endif
#elif LINUX_VERSION_CODE < 0x20624
extern int ioctlMod(struct inode *, struct file *, unsigned int, unsigned long);
#else
extern long ioctlMod(struct file *, unsigned int, unsigned long);
#endif

extern int openMod(struct inode *, struct file *);
extern int releaseMod(struct inode *, struct file *);
extern long busy_timeout_HZ;
extern long scan_timeout_HZ;
extern int hook_init;
extern pid_t  *exc_pid_ary;
extern pid_t  *vsc_pid_ary;
#ifdef X86_64
extern asmlinkage long openHook(const char *, int, int);
extern asmlinkage long closeHook(unsigned int);
extern asmlinkage long exitHook(int);
#if LINUX_VERSION_CODE <= 0x20612
extern  long execveHook(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs regs);
#else
#if  (defined(SLES11SP1_64) && defined(CONFIG_XEN)) || !defined(SLES11SP1_64)
extern  long execveHook(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs * regs);
#endif
#endif

#ifdef IA32_HOOK
extern  long stub32_execveHook(char __user *name, char __user *argv,
		char  __user *envp, struct pt_regs regs);

 asmlinkage long (*IA32_orig_open)(const char *,int, int);
 asmlinkage long (*IA32_orig_close)(unsigned int);
 asmlinkage long (*IA32_orig_exit)(int);
 asmlinkage long (*IA32_orig_execve)(char *, char __user * __user *,
									  char __user * __user *, struct pt_regs);
 asmlinkage long (*IA32_orig_syscall)(void);

 long  (*IA32_orig_compat_do_execve)(char __user *name, compat_uptr_t __user *,
			     compat_uptr_t __user *, struct pt_regs *);
#endif
#else
extern int execveHook(struct pt_regs);
extern asmlinkage int openHook(const char *, int, int);
extern asmlinkage int closeHook(unsigned int);
extern asmlinkage int exitHook(int);
#endif
extern void parseAddDirs(char *);
extern void parseAddExts(char *);
extern void parseAddExcDirs(char *);
extern void parseAddExcFils(char *);
extern void parseAddExcExts(char *);
extern int REGISTER_CHRDEV(unsigned int, const char *, struct file_operations *);
extern Boolean deleteListAll(void);
extern void delDirList(void);
extern void delExtList(void);
extern void delExcDirList(void);
extern void delExcFilList(void);
extern void delExcExtList(void);
extern void removeCacheAll(void);
extern void delDenyWriteList(DENYWRITE_TYPE type);
extern void delExcCommList(void);
extern atomic_t ref_cnt;
#ifdef	NFSD
extern void *nfsd_sys_call_table[];
extern int nfsdOpenHook(struct svc_rqst *, struct svc_fh *, int, int,
			struct file *);
extern void nfsdCloseHook(struct file *);
#endif

#ifdef X86_64
asmlinkage long (*orig_open)(const char *,int, int);
asmlinkage long (*orig_close)(unsigned int);
asmlinkage long (*orig_exit)(int);
#if LINUX_VERSION_CODE <= 0x20612
asmlinkage long (*orig_execve)(char *, char __user * __user *,
		char __user * __user *, struct pt_regs);
#else
asmlinkage long (*orig_execve)(char *, char __user * __user *,
		char __user * __user *, struct pt_regs *);
#endif
asmlinkage long (*orig_syscall)(void);
asmlinkage long (*orig_getpgid)(pid_t);
asmlinkage long (*orig_do_execve)(char * ,
	char __user *__user *,
	char __user *__user *,
	struct pt_regs * );

#else
asmlinkage int (*orig_open)(const char *, int, int);
asmlinkage int (*orig_close)(unsigned int);
asmlinkage int (*orig_exit)(int);
asmlinkage int (*orig_execve)(struct pt_regs);
asmlinkage int (*orig_syscall)(void);
asmlinkage int (*orig_getpgid)(pid_t);
asmlinkage int (*orig_do_execve)(char * ,
	char __user *__user *,
	char __user *__user *,
	struct pt_regs * );

#endif
#ifdef	NFSD
int (*orig_nfsd_open)(struct svc_rqst *, struct svc_fh *, int, int,
		      struct file *);
void (*orig_nfsd_close)(struct file *);
#endif

//SLES11 support
unsigned long orig_cr0;
//End
unsigned int major;
int	splxmod_debug = 0;
char	*splxmod_addr = NULL;
int	g_iDbgLevel = 0;

char *splxmod_execve_addr = NULL;

#ifdef IA32_HOOK
char *splxmod_ia32_addr=NULL;
char *splxmod_compat_do_execve_addr = NULL;
#endif
char *splxmod_ret_addr = NULL;
#if LINUX_VERSION_CODE >= 0x20600
module_param(splxmod_debug, int, 0);
module_param(splxmod_addr, charp, 0);
module_param(splxmod_execve_addr, charp, 0);
#ifdef X86_64
module_param(splxmod_compat_do_execve_addr, charp, 0);
module_param(splxmod_ia32_addr, charp, 0);
module_param(splxmod_ret_addr, charp, 0);
#endif
#else
MODULE_PARM(splxmod_debug, "i");
MODULE_PARM(splxmod_addr, "s");
MODULE_PARM(splxmod_execve_addr, "s");
#ifdef X86_64
MODULE_PARM(splxmod_compat_do_execve_addr, "s");
MODULE_PARM(splxmod_ia32_addr, "s");
MODULE_PARM(splxmod_ret_addr, "s");
#endif
#endif
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");



#if LINUX_VERSION_CODE >= 0x20610 && defined(X86_64)
struct file_operations splxmod_fops = {
.owner=         	THIS_MODULE,
.unlocked_ioctl =  	ioctlMod,
.compat_ioctl= 	splxmod_compat_ioctl,
.open=           	openMod,
.release=        	releaseMod,
};
#elif LINUX_VERSION_CODE >= 0x20624
struct file_operations splxmod_fops = {
.owner=			THIS_MODULE,
.unlocked_ioctl=	ioctlMod,
.open=			openMod,
.release=		releaseMod,
};
#else 
struct file_operations splxmod_fops = {
    owner:          	THIS_MODULE,
    ioctl:          	ioctlMod,
    open:           	openMod,
    release:        	releaseMod,
};
#endif

INIT_ARGS kini = {
    incoming: INCOMING_DEF,
    outgoing: OUTGOING_DEF,
    running: RUNNING_DEF,
    dirs: DIRS_DEF,
    exts: EXTS_DEF,
    exc_dirs: EXC_DIRS_DEF,
    exc_fils: EXC_FILS_DEF,
    exc_exts: EXC_EXTS_DEF,
    debug_level: DEBUG_LEVEL_DEF,
    max_cache_item: MAX_CACHE_ITEM_DEF,
    max_list_item: MAX_LIST_ITEM_DEF,
    max_dir_item: MAX_DIR_ITEM_DEF,
    max_ext_item: MAX_EXT_ITEM_DEF,
    max_exc_dir_item: MAX_EXC_DIR_ITEM_DEF,
    max_exc_fil_item: MAX_EXC_FIL_ITEM_DEF,
    max_exc_ext_item: MAX_EXC_EXT_ITEM_DEF,
    waitq_timeout: WAITQ_TIMEOUT_DEF,
    vsapi_timeout: VSAPI_TIMEOUT_DEF,
    max_exc_pid: MAX_EXC_PID_DEF,
    max_vsc_pid: MAX_VSC_PID_DEF,
    max_path_len: MAX_PATH_LEN_DEF,
    max_cmd_len: MAX_CMD_LEN_DEF
};

HOOK_FLAGS hook_flag = {
    open_hooked: 0,
    close_hooked: 0,
    execve_hooked: 0
};

#if LINUX_VERSION_CODE < 0x30000
rwlock_t kini_lock __cacheline_aligned = RW_LOCK_UNLOCKED;
spinlock_t dbg_lock = SPIN_LOCK_UNLOCKED;
//rwlock to protect the command list
rwlock_t comm_list_lock __cacheline_aligned = RW_LOCK_UNLOCKED;
#else
DEFINE_RWLOCK(kini_lock);
DEFINE_SPINLOCK(dbg_lock);
DEFINE_RWLOCK(comm_list_lock);
#endif

void **p_sys_call_table = NULL;
#ifdef IA32_HOOK
void **p_ia32_sys_call_table = NULL;
void ** p_sys32_execve = NULL;
#endif
void ** p_do_execve = NULL;
void ** p_int_ret_from_sys_call = NULL;


#if LINUX_VERSION_CODE >= 0x20612

#ifdef X86_64
asmlinkage long (*splx_change_page_attr_addr)(unsigned long address, int numpages, pgprot_t prot);
void **orig_p_sys_call_table = NULL;
#ifdef IA32_HOOK
void **orig_p_ia32_sys_call_table = NULL;
#endif
#define virt_addr_valid_symbol(kaddr)	pfn_valid(__pa_symbol(kaddr) >> PAGE_SHIFT)
#define virt_to_page_symbol(kaddr)	pfn_to_page(__pa_symbol(kaddr) >> PAGE_SHIFT)
#define PHYS_BASE 0xffffffff803097f8
#define CHANGE_PAGE_ATTR_ADDR 0xffffffff8027d5b7
#endif

/*
* clear WP bit of CR0, and return the original value
* A new way to modify the attribute of memory address
* Only apply on SLES11
*/

unsigned long clear_and_return_cr0(void)
{
    unsigned long cr0 = 0;
    unsigned long ret;
#ifdef X86_64
    __asm__ __volatile("movq %%cr0, %%rax" : "=a"(cr0));
    ret = cr0;
    cr0 &= 0xfffffffffffeffff;
    __asm__ __volatile__("movq %%rax, %%cr0" : : "a"(cr0));
#else
    __asm__ __volatile("mov %%cr0, %%eax" : "=a"(cr0));
    ret = cr0;
    cr0 &= 0xfffeffff;
    __asm__ __volatile__("mov %%eax, %%cr0" : : "a"(cr0));

#endif
    return ret;
}

/** set CR0 with new value
*
* @val : new value to set in cr0

*/
void setback_cr0(unsigned long val)
{
#ifdef X86_64
  __asm__ __volatile__("movq %%rax, %%cr0" : : "a"(val));
#else
  __asm__ __volatile__("mov %%eax, %%cr0" : : "a"(val));
#endif
}
#if LINUX_VERSION_CODE <= 0x20612
void change_page_to_rw(void ** p_addr)
{
#ifdef X86_64
	unsigned long addr;
#ifndef CONFIG_XEN
	unsigned long phys_base;
	unsigned long * p_phys_base ;

	p_phys_base = (unsigned long * ) _AC(PHYS_BASE,UL);

	phys_base = *p_phys_base;
#endif
	splx_change_page_attr_addr = _AC(CHANGE_PAGE_ATTR_ADDR,UL);
	addr = (unsigned long)__va(__pa_symbol(p_addr));
	p_addr=addr;
	splx_change_page_attr_addr(addr, 1, PAGE_KERNEL);
	global_flush_tlb();
#else

	change_page_attr(virt_to_page(p_addr), 1, PAGE_KERNEL);
	global_flush_tlb();
#endif
}

void change_page_to_ro(void ** p_addr)
{
#ifdef X86_64
	unsigned long addr;
#ifndef CONFIG_XEN

	unsigned long phys_base;
	unsigned long * p_phys_base ;

	p_phys_base = _AC(PHYS_BASE,UL);
	phys_base = *p_phys_base;
#endif
	splx_change_page_attr_addr = _AC(CHANGE_PAGE_ATTR_ADDR,UL);
	addr = (unsigned long)__va(__pa_symbol(p_addr));
	splx_change_page_attr_addr(addr, 1, PAGE_KERNEL_RO);
	global_flush_tlb();
	p_addr=addr;
#else
	change_page_attr(virt_to_page(p_addr), 1, PAGE_KERNEL_RO);
	global_flush_tlb();
#endif
}
#endif
//End

//The function only enabled on RHEL6
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32) && !defined(CONFIG_SUSE_KERNEL)
#include <asm/tlbflush.h>
static int splx_set_memory_attr(unsigned long address, bool b_rw)
{
    unsigned int level;
    pte_t *kpte, old_pte, new_pte;
    pgprot_t new_prot;
    unsigned long pfn;
    int i = 0;
    //Set two pages
    for(; i<2; i++)
    {
         address += i * PAGE_SIZE;
         address = (unsigned long)(address) & PAGE_MASK;
         kpte = lookup_address(address, &level);
         
         if(!kpte)
         {
             return 1;
         }
         old_pte = *kpte;
        
         new_prot = pte_pgprot(old_pte);
         pfn = pte_pfn(old_pte);
         if (b_rw)
             pgprot_val(new_prot) |= pgprot_val(__pgprot(_PAGE_RW));
         else
             pgprot_val(new_prot) &= ~pgprot_val(__pgprot(_PAGE_RW));
        
         new_pte = pfn_pte(pfn, canon_pgprot(new_prot));
         set_pte_atomic(kpte, new_pte);
        
    }
    __flush_tlb_all();
    return 0;
}

static int splx_set_syscall_attr_rw(void)
{
    const char * cpsMethod = "splx_set_syscall_attr";
    CP_DBG_LVL;
    if(splx_set_memory_attr((unsigned long)p_sys_call_table, true))
    {
        DPRINTK(0, "%s: Failed to change the attribute of syscall table, please contact TrendMicro\n", cpsMethod);
        return 1;
    }
#ifdef IA32_HOOK
    if(splx_set_memory_attr((unsigned long)p_ia32_sys_call_table, true))
    {
        DPRINTK(0, "%s: Failed to change the attribute of IA32 syscall table, please contact TrendMicro\n", cpsMethod);
        splx_set_memory_attr((unsigned long)p_sys_call_table, false);
        return 1;
    }     
#endif
    return 0;
}

static void splx_set_syscall_attr_ro(void)
{
    const char * cpsMethod = "splx_set_syscall_attr_ro";
    CP_DBG_LVL;
    if(splx_set_memory_attr((unsigned long)p_sys_call_table, false))
    {
        DPRINTK(0, "%s: Failed to change the attribute of syscall table, please contact TrendMicro\n", cpsMethod);
    }
    #ifdef IA32_HOOK
    if(splx_set_memory_attr((unsigned long)p_ia32_sys_call_table, false))
    {
        DPRINTK(0, "%s: Failed to change the attribute of IA32 syscall table, please contact TrendMicro\n", cpsMethod);
    }     
    #endif
}

#endif
//End
/*
** Main entry to change page attribute
** For SLES11, call the kernel API
** SuSE kernel bug 439348
** The API will fail on 2.6.27.19-5
*/
void change_page_to_RW(void ** p_addr)
{
#if LINUX_VERSION_CODE <= 0x20612
	change_page_to_rw(p_addr);
//SuSE 11
#elif defined(CONFIG_SUSE_KERNEL)
    mark_rodata_rw();
//RHEL6
#else
    return;
#endif
}

void change_page_to_RO(void ** p_addr)
{
#if LINUX_VERSION_CODE <= 0x20612
	change_page_to_ro(p_addr);
#elif defined(CONFIG_SUSE_KERNEL)
    mark_rodata_ro();
#else
    return;
#endif
}

#else
//Empty function for kernel below 2.6.18 no need to modify 
//page attributes
inline void change_page_to_RW(void ** p_addr)
{

}
inline void change_page_to_RO(void ** p_addr)
{

}

#endif
// End of #if LINUX_VERSION_CODE >= 0x20612
/**
*** add for dynamically enable debug log
*** khm_read_proc
*** khm_write_proc
*** Date: 2008.10.25
**/

#if LINUX_VERSION_CODE < 0x20624
static DECLARE_MUTEX(mutex);
#else
static DEFINE_SEMAPHORE(mutex);
#endif

int my_snprintf(char *str, size_t size, const char *fmt, ...) {
	int len;

	va_list ap;
	va_start(ap, fmt);
	len = vsnprintf(str, size, fmt, ap);
	va_end(ap);
	return (len <= size)?len:size;
}

int khm_comms_read_proc(char *page, char **start, off_t off, int count,
		int *eof, void *data)
{
	int len;
	const char * cpsMethod = "khm_comms_read_proc";
	char *p = page;
	char *p_tail = page + count;
	CP_DBG_LVL;

	DPRINTK(LOG_COMMON, "%s: Get into read prco:\n", cpsMethod);

	if (down_interruptible(&mutex))
	{
	    DPRINTK(LOG_WARNING, "WARNING:%s: mutex was interrupted\n",cpsMethod);
		return -ERESTARTSYS;
	}

	p += my_snprintf(p, p_tail - p, "%s\n", g_exc_comms);

	up(&mutex);

	len = (p - page) - off;
	if (len < 0)
		len = 0;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
    DPRINTK(LOG_COMMON, "%s: Get out of read prco:\n", cpsMethod);
	return len;
}

int khm_comms_write_proc(struct file *file, const char __user *userbuf,
		unsigned long count, void *data)
{
	const char * cpsMethod = "khm_comms_write_proc";
	char proc_str[PROC_COMMS_LENGTH+1] = {0};
	pid_t cur_pid=current->pid;
	CP_DBG_LVL;

	DPRINTK(LOG_COMMON,"%s: Get into write proc\n",cpsMethod);

	if (count > PROC_COMMS_LENGTH)
	{
		DPRINTK(LOG_WARNING, "WARNING: %d:%s: User's input length exceeds the max length %d\n",cur_pid,cpsMethod,PROC_COMMS_LENGTH);
		return -EINVAL;
	}
    if (count == 0)
    {
    	DPRINTK(LOG_COMMON, "WARNING: %d:%s: Clear the command exclusion list\n",cur_pid,cpsMethod);
    }
	else if(copy_from_user(proc_str, userbuf, count))
	{
	    DPRINTK(LOG_WARNING, "WARNING:%d:%s: Unable to copy date from user\n",cur_pid,cpsMethod);
		return -EPERM;
	}
    proc_str[count] = '\0';
	if (count > 0 && proc_str[count - 1] == '\n')
		proc_str[count -1 ] = '\0';
	DPRINTK(LOG_WARNING,"%d:%s: Write %s to %s\n", cur_pid, cpsMethod, proc_str, file->f_dentry->d_iname);
	if (down_interruptible(&mutex))
	{
	    DPRINTK(LOG_WARNING, "WARNING:%d: %s: mutex was interrupted\n",cur_pid, cpsMethod);
		return -ERESTARTSYS;
	}
	strncpy(g_exc_comms, proc_str, strlen(proc_str));
	g_exc_comms[strlen(proc_str)] = '\0';
    up(&mutex);
	//Initial the command list
	strncpy(exc_comms, proc_str, strlen(proc_str));
	exc_comms[strlen(proc_str)] = '\0';
	parseAddExcComms(exc_comms);
	//PrintExcComms();
	DPRINTK(LOG_COMMON,"%s: Get out of write proc\n",cpsMethod);
	return count;
}

int khm_read_proc(char *page, char **start, off_t off, int count,
		int *eof, void *data)
{
	int len;
	const char * cpsMethod = "khm_read_proc";
	char *p = page;
	char *p_tail = page + count;
	CP_DBG_LVL;

	DPRINTK(LOG_COMMON, "%s: Get into read prco:\n", cpsMethod);

	if (down_interruptible(&mutex))
	{
	    DPRINTK(LOG_WARNING, "WARNING:%s: mutex was interrupted\n",cpsMethod);
		return -ERESTARTSYS;
	}

	p += my_snprintf(p, p_tail - p, "%d\n", g_iDbgLevel);

	up(&mutex);

	len = (p - page) - off;
	if (len < 0)
		len = 0;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
    DPRINTK(LOG_COMMON, "%s: Get out of read prco:\n", cpsMethod);
	return len;
}


int khm_write_proc(struct file *file, const char __user *userbuf,
		unsigned long count, void *data)
{
    const char * cpsMethod = "khm_write_prco";
	char proc_str[PROC_STR_SIZE] = "";
	pid_t cur_pid=current->pid;
	int val;
	CP_DBG_LVL;

	DPRINTK(LOG_COMMON,"%s: Get into write proc\n",cpsMethod);

	if (count > sizeof(proc_str) - 1)
	{
		DPRINTK(LOG_WARNING, "WARNING:%d:%s: User's input length exceeds %d\n",cur_pid,cpsMethod,PROC_STR_SIZE);
		return -EINVAL;
	}

	if (copy_from_user(proc_str, userbuf, count))
	{
	    DPRINTK(LOG_WARNING, "WARNING:%d:%s: Unable to copy date from user\n",cur_pid,cpsMethod);
		return -EPERM;
	}

    proc_str[count] = '\0';
	if (count > 0 && proc_str[count - 1] == '\n')
		proc_str[count -1 ] = '\0';
	DPRINTK(LOG_DEBUG,"%d:%s: Write %s to %s\n", cur_pid, cpsMethod, proc_str, file->f_dentry->d_iname);

	if (sscanf(proc_str, "%d", &val) != 1)
	{
		DPRINTK(LOG_WARNING, "WARNING:%d:%s Invalid value %s for %s\n",cur_pid, cpsMethod, proc_str,file->f_dentry->d_iname);
		return -EINVAL;
	}
	if (down_interruptible(&mutex))
	{
	    DPRINTK(LOG_WARNING, "WARNING:%d: %s: mutex was interrupted\n",cur_pid, cpsMethod);
		return -ERESTARTSYS;
	}
    if(val>3)
		g_iDbgLevel= 3;
	else if(val<0)
		g_iDbgLevel = 0;
	else g_iDbgLevel = val;
	up(&mutex);
	DPRINTK(LOG_COMMON,"%s: Get out of write proc\n",cpsMethod);
	return count;
}
//add end

/* 2010/10/28
** To make code easily read, re-construct the code for hooking
*/

#define HOOK_SYSCALL(index, orig_sys_call, wrapper) \
    do { \
    if(p_sys_call_table[index]) \
    { \
        if (LINUX_VERSION_CODE >= 0x20612)\
           { change_page_to_RW(&(p_sys_call_table[index]));}\
        orig_sys_call = p_sys_call_table[index];\
        p_sys_call_table[index] = wrapper;\
        DPRINTK(1, "hook: hooked %s\n", #index);\
        if (LINUX_VERSION_CODE >= 0x20612)\
	    {change_page_to_RO(&(p_sys_call_table[index]));} \
    } \
    else \
    {\
        DPRINTK(1, "hook: warning: didn't hook %s \n", #index); \
    } \
    }while(0);
    
#ifdef IA32_HOOK

#define HOOK_SYSCALL_IA32(index, orig_sys_call, wrapper) \
    do{ \
    if(p_ia32_sys_call_table[index]) \
    { \
    if (LINUX_VERSION_CODE >= 0x20612) \
        {change_page_to_RW(&(p_ia32_sys_call_table[index]));} \
        orig_sys_call = p_ia32_sys_call_table[index]; \
        p_ia32_sys_call_table[index] = wrapper; \
        DPRINTK(1, "IA32 hook: hooked %s\n", #orig_sys_call); \
    if (LINUX_VERSION_CODE >= 0x20612) \
        {change_page_to_RO(&(p_ia32_sys_call_table[index]));} \
    }\
    else \
    {\
        DPRINTK(1, "IA32 hook: warning: didn't hook %s \n", #orig_sys_call); \
    }\
    }while(0);

#endif

#define UNHOOK_SYSCALL(index, orig_sys_call, wrapper) \
    do{ \
	if (orig_sys_call != NULL) \
    { \
		if (p_sys_call_table[index] != wrapper) \
        { \
		    DPRINTK(1,"unhook_module: warning: Somebody else also played with the %s\n", #orig_sys_call); \
	    } \
        if (LINUX_VERSION_CODE >= 0x20612) \
	    {change_page_to_RW(&(p_sys_call_table[index]));}	\
	    p_sys_call_table[index] = orig_sys_call; \
        if (LINUX_VERSION_CODE >= 0x20612) \
	    {change_page_to_RO(&(p_sys_call_table[index]));} \
	}\
    }while(0);

#ifdef IA32_HOOK
#define UNHOOK_SYSCALL_IA32(index, orig_sys_call, wrapper) \
    do{\
	if (orig_sys_call != NULL) \
    { \
		if (p_ia32_sys_call_table[index] != wrapper) \
        { \
		    DPRINTK(1,"unhook_module: warning: Somebody else also played with the %s\n", #orig_sys_call); \
	    } \
    if (LINUX_VERSION_CODE >= 0x20612) \
	    {change_page_to_RW(&(p_ia32_sys_call_table[index]));} \
        p_ia32_sys_call_table[index] = orig_sys_call; \
    if (LINUX_VERSION_CODE >= 0x20612) \
	    {change_page_to_RO(&(p_ia32_sys_call_table[index]));} \
	}\
    }while(0);
#endif
//2010/10/28 End


//TT224111: Security hook_module

void security_hook(void)
{
    write_lock(&hook_init_lock);
    if(hook_init != UN_HOOKED)
    {
        write_unlock(&hook_init_lock);
        return;
    }
    
    hook_init = IN_HOOK;
    write_unlock(&hook_init_lock);
    
    //Never add spin lock when hook
    hook_module();
    
    write_lock(&hook_init_lock);
    hook_init = HOOKED;
    write_unlock(&hook_init_lock);
}

void hook_module(void) {
    const char * cpsMethod = "hook_module";	
    pid_t cur_pid=0;
    CP_DBG_LVL;

    cur_pid = current->pid;

    memset(&hook_flag, 0, sizeof(HOOK_FLAGS));
    DPRINTK(1, "%d: %s: get into hook_module\n", cur_pid, cpsMethod);

    //2011.3.16   For RHEL6, first change the syscall table attribute
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32) && !defined(CONFIG_SUSE_KERNEL)
    if(splx_set_syscall_attr_rw())
    {
        return;
    }
    #endif
    //End
    if(kini.outgoing)
    {
        HOOK_SYSCALL(__NR_open, orig_open, openHook);
        hook_flag.open_hooked = 1;
    }
    if(kini.incoming)
    {
        HOOK_SYSCALL(__NR_close, orig_close, closeHook);
        hook_flag.close_hooked = 1;
    }

    HOOK_SYSCALL(__NR_exit, orig_exit, exitHook);

/*
 * For 2.6.32 64 bits no_xen kernel, use LSM to do the execve hook
 */
    if(kini.running)
    {
    #ifdef USE_LSM_HOOK
        if(hook_lsm())
        {
            hook_flag.execve_hooked = 1;
        }
    #else
        HOOK_SYSCALL(__NR_execve, orig_execve, execveHook);
        hook_flag.execve_hooked = 1;
    #endif
        
    }

/*get getpid*/
    orig_getpgid = p_sys_call_table[__NR_getpgid];

/*just for hook 32bit systemcall on x86_64*/
#ifdef IA32_HOOK

    if(kini.outgoing)
    {
        HOOK_SYSCALL_IA32(__NR_ia32_open, IA32_orig_open, IA32_openHook);
    }
    if(kini.incoming)
    {
        HOOK_SYSCALL_IA32(__NR_ia32_close, IA32_orig_close, IA32_closeHook);
    }
    HOOK_SYSCALL_IA32(__NR_ia32_exit, IA32_orig_exit, IA32_exitHook);
    if(kini.running)
    {
#ifndef USE_LSM_HOOK
        HOOK_SYSCALL_IA32(__NR_ia32_execve, IA32_orig_execve, stub32_execveHook);
#endif
    }   
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32) && !defined(CONFIG_SUSE_KERNEL)
    splx_set_syscall_attr_ro();
#endif

    DPRINTK(1, "%d: %s: get outta hook_module, hook open [%d], hook close [%d], hook execve [%d]\n", cur_pid, cpsMethod
        , hook_flag.open_hooked, hook_flag.close_hooked, hook_flag.execve_hooked);
}

void security_unhook(void)
{
    write_lock(&hook_init_lock);
    if(hook_init != HOOKED)
    {
        write_unlock(&hook_init_lock);
        return;
    }
    
    hook_init = IN_HOOK;
    write_unlock(&hook_init_lock);
    
    //Never add spin lock when hook/unhook
    unhook_module();
    
    write_lock(&hook_init_lock);
    hook_init = UN_HOOKED;
    write_unlock(&hook_init_lock);
}

void unhook_module(void) 
{
    const char * cpsMethod = "unhook_module";
    pid_t cur_pid=0;
    CP_DBG_LVL;

    cur_pid = current->pid;
    DPRINTK(1, "%d: %s: get into unhook_module\n", cur_pid, cpsMethod);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32) && !defined(CONFIG_SUSE_KERNEL)
    if(splx_set_syscall_attr_rw())
    {
	    DPRINTK(0, "[FATAL]%d: %s: splx_set_syscall_attr_rw failed, can't do unhook\n", cur_pid, cpsMethod);
	    return;  
    }
#endif
    if(hook_flag.open_hooked)
    {
        UNHOOK_SYSCALL(__NR_open, orig_open, openHook);
    }
    if(hook_flag.close_hooked)
    {
        UNHOOK_SYSCALL(__NR_close, orig_close, closeHook);
    }
        
    UNHOOK_SYSCALL(__NR_exit, orig_exit, exitHook);

/*
 * Kernel > 2.6.32 with Arch x86_64, use LSM to do execve Hook
 */
    if(hook_flag.execve_hooked)
    {
    #ifdef USE_LSM_HOOK
        unhook_lsm();
    #else
        UNHOOK_SYSCALL(__NR_execve, orig_execve, execveHook);
    #endif
    }
/*just for unhook 32bit systemcall on x86_64*/
#ifdef IA32_HOOK
    if(hook_flag.open_hooked)
    {
        UNHOOK_SYSCALL_IA32(__NR_ia32_open, IA32_orig_open, IA32_openHook);
    }
    if(hook_flag.close_hooked)
    {
        UNHOOK_SYSCALL_IA32(__NR_ia32_close, IA32_orig_close, IA32_closeHook);
    }
        UNHOOK_SYSCALL_IA32(__NR_ia32_exit, IA32_orig_exit, IA32_exitHook);
    if(hook_flag.execve_hooked)
    {
        #ifndef USE_LSM_HOOK
        UNHOOK_SYSCALL_IA32(__NR_ia32_execve, IA32_orig_execve, stub32_execveHook);
        #endif
    }
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32) && !defined(CONFIG_SUSE_KERNEL)
    splx_set_syscall_attr_ro();
#endif
    DPRINTK(1, "%d: %s: get outta unhook_module\n", cur_pid, cpsMethod);
}

#if LINUX_VERSION_CODE < 0x20600
int can_unload(void)
{
    DECLARE_WAIT_QUEUE_HEAD(cleanup_wq);
    Boolean count;

    count = GET_USE_COUNT(THIS_MODULE) ||
	atomic_read(&ref_cnt);

    return (count?-EBUSY:0);
}
#endif

#ifdef X86_64
#include "ioctl_trans_x86_64.c"
#endif
//Add proc entry for khm debug log
static struct proc_dir_entry * proc_splx_base;

static int __init splxmod_init(void)
{
    	const char * cpsMethod = "init_module";
    	pid_t cur_pid=0;
    	char	*strend;
    	struct proc_dir_entry * entry;

     	char * execve_strend;
	int len = 0;
	char * exc_cmds;
#ifdef X86_64

	char * ret_strend;
#endif
#ifdef IA32_HOOK
	char * ia32_strend;
	char * sys32_execve_strend;
#endif
    CP_DBG_LVL;

    if (splxmod_debug > 0) {
	g_iDbgLevel = splxmod_debug;
	l_iDbgLevel = splxmod_debug;
    }

    cur_pid = current->pid;
    DPRINTK(1,"%d: %s: get into init_module\n", cur_pid, cpsMethod);

    if (!splxmod_addr)
	return -EFAULT;

    p_sys_call_table = (void **) simple_strtoul(splxmod_addr, &strend, 0);
    if (p_sys_call_table == 0)
		return -EFAULT;

#ifdef IA32_HOOK


    if (!splxmod_ia32_addr)
	return -EFAULT;

    p_ia32_sys_call_table = (void **) simple_strtoul(splxmod_ia32_addr, &ia32_strend, 0);
    if (p_ia32_sys_call_table == 0)
		return -EFAULT;
#endif

/*get do_execve address*/
	if(!splxmod_execve_addr)
		return -EFAULT;

	DPRINTK(1,"%d: splxmod_execve_addr = 0x%s:\n", cur_pid, splxmod_execve_addr);
	p_do_execve = (void **) simple_strtoul(splxmod_execve_addr,&execve_strend,0);
#ifndef X86_64
	DPRINTK(1,"%d: p_do_execve = 0x%x:\n", cur_pid, (int) p_do_execve);
#else
	DPRINTK(1,"%d: p_do_execve = 0x%lx:\n", cur_pid,(long unsigned int)p_do_execve);
#endif
	orig_do_execve = (void *) p_do_execve;

#ifndef X86_64
	DPRINTK(1,"%d: orig_do_execve = 0x%x:\n", cur_pid, (int) orig_do_execve);
#else
	DPRINTK(1,"%d: orig_do_execve = 0x%lx:\n", cur_pid, (long unsigned int)orig_do_execve);
#endif

	if (p_do_execve == 0)
	{
		return -EFAULT;
	}
#ifdef IA32_HOOK
/*get compat_do_execve address*/

	if(!splxmod_compat_do_execve_addr)
		return -EFAULT;
	DPRINTK(1,"%d: splxmod_compat_do_execve_addr = 0x%s:\n", cur_pid, splxmod_compat_do_execve_addr);

	p_sys32_execve = (void **) simple_strtoul(splxmod_compat_do_execve_addr,&sys32_execve_strend,0);

	DPRINTK(1,"%d: p_sys32_execve = 0x%lx:\n", cur_pid, (long unsigned int)p_sys32_execve);

	IA32_orig_compat_do_execve = (void *) p_sys32_execve;


	DPRINTK(1,"%d: IA32_orig_compat_do_execve = 0x%lx:\n", cur_pid, (long unsigned int)IA32_orig_compat_do_execve);


	if (p_sys32_execve == 0)
	{
		return -EFAULT;
	}

#endif

#ifdef X86_64
	if (!splxmod_ret_addr)
		return -EFAULT;
	p_int_ret_from_sys_call = (void **) simple_strtoul(splxmod_ret_addr,&ret_strend,0);
	DPRINTK(1,"%d: p_int_ret_from_sys_call = 0x%lx:\n", cur_pid, (long unsigned int)p_int_ret_from_sys_call);
	if (p_int_ret_from_sys_call == 0)
		return -EFAULT;
#endif

#if LINUX_VERSION_CODE < 0x20600
    if (!mod_member_present(&__this_module, can_unload))
		return -EBUSY;

    __this_module.can_unload = &can_unload;
#endif

#if LINUX_VERSION_CODE >= 0x20100 && LINUX_VERSION_CODE < 0x20600
    EXPORT_NO_SYMBOLS;
#endif

    /* setting initializations */
    if (kini.dirs) {
		len = strlen(DIRS_DEF);
		kini.dirs = (char *)kmalloc(len+1, GFP_KERNEL);
		strncpy(kini.dirs, DIRS_DEF, len+1);
		kini.dirs[len] = '\0';
    }
    if (kini.exts) {
        len = strlen(EXTS_DEF);
		kini.exts = (char *)kmalloc(len+1, GFP_KERNEL);
		strncpy(kini.exts, EXTS_DEF, len+1);
		kini.exts[len] = '\0';
    }
    if (kini.exc_dirs) {
        len = strlen(EXC_DIRS_DEF);
		kini.exc_dirs = (char *)kmalloc(len + 1, GFP_KERNEL);
		strncpy(kini.exc_dirs, EXC_DIRS_DEF, len + 1);
		kini.exc_dirs[len] = '\0';
    }
    if (kini.exc_fils) {
	len = strlen(EXC_FILS_DEF);
		kini.exc_fils = (char *)kmalloc(len+1, GFP_KERNEL);
		strncpy(kini.exc_fils, EXC_FILS_DEF, len + 1);
		kini.exc_fils[len] = '\0';
    }
    if (kini.exc_exts) {
        len = strlen(EXC_EXTS_DEF);
		kini.exc_exts = (char *)kmalloc(len + 1, GFP_KERNEL);
		strncpy(kini.exc_exts, EXC_EXTS_DEF, len + 1);
		kini.exc_exts[len] = '\0';
    }

    busy_timeout_HZ = HZ *(kini.waitq_timeout/1000);
    scan_timeout_HZ = HZ *kini.vsapi_timeout;
    exc_pid_ary = (pid_t *)kmalloc(sizeof(pid_t)*MAX_EXC_PID_DEF,
				   GFP_KERNEL);
    vsc_pid_ary = (pid_t *)kmalloc(sizeof(pid_t)*MAX_VSC_PID_DEF,
				   GFP_KERNEL);
    parseAddDirs(kini.dirs);
    parseAddExts(kini.exts);
    parseAddExcDirs(kini.exc_dirs);
    parseAddExcFils(kini.exc_fils);
    parseAddExcExts(kini.exc_exts);

    //Add default exclude command list
    len = strlen(DEF_EXC_COMM);
    exc_cmds = (char *)kmalloc(len + 1, GFP_KERNEL);
    strncpy(exc_cmds, DEF_EXC_COMM, len + 1);
    exc_cmds[len] = '\0';
    parseAddExcComms(exc_cmds);

	/* initialize original pointers */
	orig_open = NULL;
	orig_close = NULL;
	orig_execve = NULL;
	orig_exit = NULL;
	orig_syscall = NULL;
	orig_getpgid = NULL;
#ifdef IA32_HOOK
	IA32_orig_open = NULL;
	IA32_orig_close = NULL;
	IA32_orig_exit =NULL;
	IA32_orig_execve=NULL;
#endif
#ifdef	NFSD
	orig_nfsd_open = NULL;
	orig_nfsd_close = NULL;
#endif

	/* dynamic allocation of major number */
    major = REGISTER_CHRDEV (0, DEVICE_NAME, &splxmod_fops);
    if (major < 0) {
	WPRINTK("%d: %s: can't get major %d\n", cur_pid, cpsMethod, major);
	return(major);
    }
#ifdef X86_64

#if LINUX_VERSION_CODE < 0x20610

	{
		int ret;
		ret = 0;
		/* First compatible ones */
		ret = register_ioctl32_conversion(SIOCSETINIFIL_32,handle_SIOCSETINIFIL);

		ret |= register_ioctl32_conversion(SIOCGETNXTFIL_32,handle_SIOCGETNXTFIL);

		ret |= register_ioctl32_conversion(SIOCPUTEXCPID,(void *)sys_ioctl);

		ret |= register_ioctl32_conversion(SIOCPUTVSCPID,(void *)sys_ioctl);

		ret |= register_ioctl32_conversion(SIOCPUTLSTRES_32,handle_SIOCPUTLSTRES);

		ret |= register_ioctl32_conversion(SIOCGETKHMINFO_32,handle_SIOCGETKHMINFO);

		ret |= register_ioctl32_conversion(SIOCADDONEDENYWRITEFILE_32,handle_SIOCADDONEDENYWRITEFILE);

		ret |= register_ioctl32_conversion(SIOCSETDENYACCESSFILELIST_32,handle_SIOCSETDENYACCESSFILELIST);

		ret |= register_ioctl32_conversion(SIOCADDONEDENYWRITEDIR_32,handle_SIOCADDONEDENYWRITEDIR);

		ret |= register_ioctl32_conversion(SIOCSETDENYACCESSDIRLIST_32,handle_SIOCSETDENYACCESSDIRLIST);

		ret |= register_ioctl32_conversion(SIOCSETFILTEREXTINDENYACCESSDIR_32,handle_SIOCSETFILTEREXTINDENYACCESSDIR);

		ret |= register_ioctl32_conversion(SIOCSETEXCEPTIONEXTENSION_32,handle_SIOCSETEXCEPTIONEXTENSION);

		ret |= register_ioctl32_conversion(SIOCCONTINUECWD,(void *)sys_ioctl);

        //Add by errik 2010-9-29
        ret |= register_ioctl32_conversion(SIOCGETKHMVERSION,(void *)sys_ioctl);
		ret |= register_ioctl32_conversion(SIOCCLEARKHMLIST,(void *)sys_ioctl);
        ret |= register_ioctl32_conversion(SIOCGETFIRSTITEM_32,handle_SIOCGETFIRSTITEM);
        ret |= register_ioctl32_conversion(SIOCSETCOMMEXCLUSION_32,handle_SIOCSETCOMMEXCLUSION);
        //Add end


		/* These need to be handled by translation */
		if (ret)
			printk(KERN_ERR "SPLXMod:  Error registering ioctl32 translations\n");
	}

#endif

#endif

	proc_splx_base = proc_mkdir(PROC_NAME,NULL);
	if(NULL == proc_splx_base)
	{
	  DPRINTK(LOG_WARNING, "%s: can't create  directory /prco/%s for splx kernel module\n", cpsMethod, PROC_NAME);
	  return -EPERM;
	}
	entry = create_proc_entry(KHM_ENTRY, 0600, proc_splx_base);
	if(!entry)
	{
	  remove_proc_entry(PROC_NAME, 0);
	  DPRINTK(LOG_WARNING, "%s: can't create KHM  entry /prco/%s/%s to access khm\n", cpsMethod, PROC_NAME, KHM_ENTRY);
	  return -EPERM;
	}
	entry->read_proc = (read_proc_t *)khm_read_proc;
	entry->write_proc =(write_proc_t *)khm_write_proc;

#if LINUX_VERSION_CODE < 0x2061e
	entry->owner=THIS_MODULE;
#endif
	// add end;

    // Add for commads exclusion list
    // Creat the proc entry for command exclusion list
    entry = create_proc_entry(KHM_COMMS_ENTRY, 0600, proc_splx_base);
	if(!entry)
	{
	  remove_proc_entry(KHM_ENTRY, proc_splx_base);
	  remove_proc_entry(PROC_NAME, 0);
	  DPRINTK(LOG_WARNING, "%s: can't create KHM commands exclusion list entry /prco/%s/%s to access khm\n", cpsMethod, PROC_NAME, KHM_COMMS_ENTRY);
	  return -EPERM;
	}
	entry->read_proc = (read_proc_t *)khm_comms_read_proc;
	entry->write_proc =(write_proc_t *)khm_comms_write_proc;

#if LINUX_VERSION_CODE < 0x2061e
	entry->owner=THIS_MODULE;
#endif
    //Add end
    DPRINTK(LOG_CLOSE, "SPLX 3.0: KHM loaded. Version [%d]\n", KHM_VERSION);
    DPRINTK(1,"%d: %s: get outta init_module\n", cur_pid, cpsMethod);
    return 0; /* success */
}

static void __exit splxmod_exit(void)
{
    const char * cpsMethod = "cleanup_module";
    pid_t cur_pid=0;
    CP_DBG_LVL;

    cur_pid = current->pid;
    DPRINTK(1,"%d: %s: get into cleanup_module\n", cur_pid, cpsMethod);
	// add by errik for debug log
	DPRINTK(LOG_DEBUG,"%d: %s: start to clean proc entry\n", cur_pid, cpsMethod);
	remove_proc_entry(KHM_ENTRY, proc_splx_base);
	remove_proc_entry(KHM_COMMS_ENTRY, proc_splx_base);
	remove_proc_entry(PROC_NAME, 0);
	DPRINTK(LOG_DEBUG,"%d: %s: clean proc entry sucess\n", cur_pid, cpsMethod);
	// add end
    delExcCommList();
    deleteListAll();
    delDirList();
    delExtList();
    delExcDirList();
    delExcFilList();
    delExcExtList();
    delDenyWriteList(DENYWRITE_FILE);
    delDenyWriteList(DENYWRITE_DIR);
    delDenyWriteList(DENYWRITE_FILTER_EXT);
    removeCacheAll();
    if (exc_pid_ary) kfree(exc_pid_ary);
    if (vsc_pid_ary) kfree(vsc_pid_ary);
    if (kini.dirs) kfree(kini.dirs);
    if (kini.exts) kfree(kini.exts);
    if (kini.exc_dirs) kfree(kini.exc_dirs);
    if (kini.exc_fils) kfree(kini.exc_fils);
    if (kini.exc_exts) kfree(kini.exc_exts);

	unregister_chrdev(major, DEVICE_NAME);

	#ifdef X86_64
	{
#if LINUX_VERSION_CODE < 0x20610

		int ret;
		ret = 0;
		/* First compatible ones */
		ret= unregister_ioctl32_conversion(SIOCSETINIFIL_32);

		ret |= unregister_ioctl32_conversion(SIOCGETNXTFIL_32);

		ret |= unregister_ioctl32_conversion(SIOCPUTEXCPID);

		ret |= unregister_ioctl32_conversion(SIOCPUTVSCPID);

		ret |= unregister_ioctl32_conversion(SIOCPUTLSTRES_32);

		ret |= unregister_ioctl32_conversion(SIOCGETKHMINFO_32);

		ret |= unregister_ioctl32_conversion(SIOCADDONEDENYWRITEFILE_32);

		ret |= unregister_ioctl32_conversion(SIOCSETDENYACCESSFILELIST_32);

		ret |= unregister_ioctl32_conversion(SIOCADDONEDENYWRITEDIR_32);

		ret |= unregister_ioctl32_conversion(SIOCSETDENYACCESSDIRLIST_32);

		ret |= unregister_ioctl32_conversion(SIOCSETFILTEREXTINDENYACCESSDIR_32);

		ret |= unregister_ioctl32_conversion(SIOCSETEXCEPTIONEXTENSION_32);

		ret |= unregister_ioctl32_conversion(SIOCCONTINUECWD);

        //Add by errik 2010-9-29
        ret |= unregister_ioctl32_conversion(SIOCGETKHMVERSION);
        ret |= unregister_ioctl32_conversion(SIOCCLEARKHMLIST);
        ret |= unregister_ioctl32_conversion(SIOCGETFIRSTITEM_32);
        ret |= unregister_ioctl32_conversion(SIOCSETCOMMEXCLUSION_32);
        //Add end


		/* These need to be handled by translation */
//		ret |= register_ioctl32_conversion(DV1394_IOC32_GET_STATUS, handle_dv1394_get_status);
		if (ret)
			printk(KERN_ERR "SPLXMod:  Error unregistering ioctl32 translations\n");
#endif
	}
#endif
	DPRINTK(1,"%d: %s: get outta cleanup_module\n", cur_pid, cpsMethod);
    return;
}

module_init(splxmod_init);
module_exit(splxmod_exit);
