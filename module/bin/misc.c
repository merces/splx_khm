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

#include        <linux/sched.h>
#if LINUX_VERSION_CODE < 0x30000
#include	<linux/smp_lock.h>
#endif
#include	<linux/slab.h>
#include	<linux/unistd.h>
#include	<linux/errno.h>
#include	<linux/ctype.h>
#include	<linux/string.h>
#include        <linux/spinlock.h>
#include        <linux/limits.h>
#include	<linux/list.h>
#include	<linux/ctype.h>
#include	<linux/file.h>
#if LINUX_VERSION_CODE >= 0x20600
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#endif
#include <linux/delay.h>
#include <splxmod.h>

#ifdef X86_64
extern asmlinkage long (*orig_getpgid)(pid_t);
#else
extern asmlinkage int (*orig_getpgid)(pid_t);
#endif

#if LINUX_VERSION_CODE < 0x30000
extern int PATH_LOOKUP(const char * path, unsigned flags, struct nameidata * nd);
//Add for SLES11 support
extern void SPLX_PATH_RELEASE(struct nameidata * nd);
//Add end
#endif
extern int     g_iDbgLevel;
extern INIT_ARGS       kini;
extern rwlock_t init_lock;
extern rwlock_t hook_init_lock;
extern int hook_init;
extern int vsapi_chldn_no;
extern Boolean inited;
extern spinlock_t dbg_lock;
extern rwlock_t kini_lock;
extern atomic_t Del_list;


int cache_item_no = 0;
int list_item_no = 0;
int scanning_list_item_no = 0;
int dir_item_no = 0;
int ext_item_no = 0;
int exc_dir_item_no = 0;
int exc_fil_item_no = 0;
int exc_ext_item_no = 0;
int denywrite_file_no;
int denywrite_dir_no;
int denywrite_ext_no;

LIST_HEAD(list_item_head);
LIST_HEAD(scanning_item_head);
LIST_HEAD(dir_list_head);
LIST_HEAD(ext_list_head);
LIST_HEAD(exc_dir_list_abs_head);
LIST_HEAD(exc_dir_list_rel_head);
LIST_HEAD(exc_fil_list_abs_head);
LIST_HEAD(exc_fil_list_rel_head);
LIST_HEAD(exc_ext_list_head);
LIST_HEAD(cache_item_head);
LIST_HEAD(denywrite_file_list_head);
LIST_HEAD(denywrite_dir_list_head);
LIST_HEAD(denywrite_filter_ext_list_head);
//Add for command exclusion list
LIST_HEAD(exc_comm_list_head);

static Boolean has_wildcards(const char *s);
static int fnmatch(const char *pattern, const char *string, int flags);

#if LINUX_VERSION_CODE < 0x30000
spinlock_t list_item_head_lock __cacheline_aligned_in_smp = SPIN_LOCK_UNLOCKED;
spinlock_t scanning_item_head_lock __cacheline_aligned_in_smp = SPIN_LOCK_UNLOCKED;
spinlock_t cache_item_head_lock __cacheline_aligned_in_smp = SPIN_LOCK_UNLOCKED;
rwlock_t denywrite_list_head_lock __cacheline_aligned_in_smp = RW_LOCK_UNLOCKED;
#else
DEFINE_SPINLOCK(list_item_head_lock);
DEFINE_SPINLOCK(scanning_item_head_lock);
DEFINE_SPINLOCK(cache_item_head_lock);
DEFINE_RWLOCK(denywrite_list_head_lock);
#endif

extern rwlock_t comm_list_lock;

#if 0
#ifdef SLES11SP1
#ifdef X86_64
DEFINE_PER_CPU(unsigned long, old_rsp);
#endif
#endif
#endif

/**************************************************/
/** Function related to construct/delete the command list ***
***
***************************************************/

Boolean addExcComm(char *comm) 
{
	const char * cpsMethod = "addExcComm";
	pid_t cur_pid=0;
	EXC_COMM_ITEM *oip, *ip, *nip;
	struct list_head	*plist_head;
	int r;
	CP_DBG_LVL;

	if(comm == NULL)
		return FALSE;
	cur_pid = current->pid;
	DPRINTK(LOG_COMMON,"%d: %s: get into addExcComm\n", cur_pid, cpsMethod);

	plist_head = &exc_comm_list_head;
	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
#ifndef X86_64
		DPRINTK(2,"%d: %s: ip %x, ip->comm %s\n", cur_pid, cpsMethod, (unsigned int)ip, ip->comm);
#else
        DPRINTK(2,"%d: %s: ip 0x%lx, ip->comm %s\n", cur_pid, cpsMethod, (unsigned long)ip, ip->comm);
#endif
		r = strcmp(comm, ip->comm);
		if (r == 0)
			return TRUE;
		else
			continue;
	}

	oip = (EXC_COMM_ITEM *)kmalloc(sizeof(EXC_COMM_ITEM), GFP_ATOMIC);
	if (oip == NULL) {
		WPRINTK("%d: %s: allocate memory for exc comm item failed\n", cur_pid, cpsMethod);
		return FALSE;
	}
	oip->comm = comm;
	list_add_tail(&oip->item_list, &ip->item_list);

	DPRINTK(LOG_COMMON,"%d: %s: get outta addExcComm\n", cur_pid, cpsMethod);
	return TRUE;
}


void delExcCommList(void)
{
	const char * cpsMethod = "delExcCommList";
	EXC_COMM_ITEM	*ip, *nip;
	pid_t cur_pid = current->pid;
	CP_DBG_LVL;

	DPRINTK(LOG_COMMON,"%d: %s: get into delExcCommList\n", cur_pid, cpsMethod);

	list_for_each_entry_safe(ip, nip, &exc_comm_list_head, item_list) {
		list_del(&ip->item_list);
		kfree(ip);
	}
	INIT_LIST_HEAD(&exc_comm_list_head);
	
	DPRINTK(LOG_COMMON,"%d: %s: get outta delExcCommList\n", cur_pid, cpsMethod);
}

// Test function
// Print the exclusion list

void PrintExcComms(void)
{
	const char * cpsMethod = "PrintExcComms";
	EXC_COMM_ITEM	*ip, *nip;
	pid_t cur_pid = current->pid;
	int i = 0;
	CP_DBG_LVL;

	DPRINTK(LOG_COMMON,"%d: %s: get into PrintExcComms\n", cur_pid, cpsMethod);
	list_for_each_entry_safe(ip, nip, &exc_comm_list_head, item_list) {
		DPRINTK(LOG_WARNING, "comm[%d] = %s\n",i, ip->comm);
		i++;
	}
}

// Commands are seperated by ";"
void parseAddExcComms(char *comms)
{
	const char * cpsMethod = "parseAddExcComms";
	pid_t cur_pid=0;
	char	*token;
	char	*parse_comms = comms;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(LOG_COMMON,"%d: %s: get into parseAddExcComms\n", cur_pid, cpsMethod);
	DPRINTK(LOG_COMMON,"%s\n", parse_comms);
	//delExcCommList();

	if (comms == NULL || comms[0] == '\0') return;
    write_lock(&comm_list_lock);
	token = strsep(&parse_comms, (const char *)";");
	do {
		if (!addExcComm(token))
			break;
	} while ((token = strsep(&parse_comms, (const char *)";")));
    write_unlock(&comm_list_lock);
	DPRINTK(LOG_COMMON,"%d: %s: get outta parseAddExcDirs\n", cur_pid, cpsMethod);
}


Boolean InExcComms(const char* comm)
{
	//const char * cpsMethod = "inExcComms";
	EXC_COMM_ITEM *ip, *nip;
    //Bypass syslog suse is 2.6.27 and 2.6.16
    //RedHat is 2.6.9 and 2.6.18
    /*
#if LINUX_VERSION_CODE == 0x2061b || LINUX_VERSION_CODE == 0x20610
	if(0 == strcmp(comm, "syslog-ng"))
		return TRUE;
#elif LINUX_VERSION_CODE == 0x20612 || LINUX_VERSION_CODE == 0x20609
	if(0 == strcmp(comm,"syslogd")|| 0==strcmp(comm,"klogd"))
		return TRUE;
#endif
       */
    read_lock(&comm_list_lock);
    //Support the wildcards * and ?
	list_for_each_entry_safe(ip, nip, &exc_comm_list_head, item_list) 
    {
        if(FALSE == has_wildcards(ip->comm))
        {
		    if(0 == strcmp(comm, ip->comm))
		    {
			    read_unlock(&comm_list_lock);
			    return TRUE;
		    }
        }
        //has wildcards like * and ?
        else
        {
            if(fnmatch(ip->comm, comm, FNM_PATHNAME) == FNM_MATCH)
            {
 			    read_unlock(&comm_list_lock);
			    return TRUE;               
            }
        }
	}
    read_unlock(&comm_list_lock);
	return FALSE;
}

//add end



/*
** splx_find_task_by_pid
** Find task_struct with PID
*/
struct task_struct *splx_find_task_by_pid(pid_t nr)
{
#if LINUX_VERSION_CODE <= 0x20612
	return find_task_by_pid(nr);
#else
    //TT216751: Merge Patch Form SuSE
    struct pid *pid;
    struct task_struct *ts = NULL;
	pid = find_get_pid(nr);
	if(pid) {
		ts = pid_task(pid,PIDTYPE_PID);
		put_pid(pid);
	}
	return ts;
	//return find_task_by_vpid(nr);
#endif
}

static int fnmatch(const char *pattern, const char *string, int flags)
{
	register const char *p = pattern, *n = string;
	register char c;

	while ((c = *p++) != '\0') {
		switch (c) {
		case '?':
			if (*n == '\0')
				return (FNM_NOMATCH);
			else if ((flags & FNM_PATHNAME) && *n == '/')
				return (FNM_NOMATCH);
			else if ((flags & FNM_PERIOD) && *n == '.' &&
				(n == string
				|| ((flags & FNM_PATHNAME) && n[-1] == '/')))
				return (FNM_NOMATCH);
			break;

		case '\\':
			if (!(flags & FNM_NOESCAPE))
				c = *p++;
			if (*n != c)
				return (FNM_NOMATCH);
			break;

		case '*':
			if ((flags & FNM_PERIOD) && *n == '.' &&
				(n == string || ((flags & FNM_PATHNAME) && n[-1] == '/')))
				return (FNM_NOMATCH);

			for (c = *p++; c == '?' || c == '*'; c = *p++, ++n)
				if (((flags & FNM_PATHNAME) && *n == '/') ||
					(c == '?' && *n == '\0'))
					return (FNM_NOMATCH);

			if (c == '\0')
				return 0;

			{
				char c1 = (!(flags & FNM_NOESCAPE) && c == '\\') ? *p : c;
				for (--p; *n != '\0'; ++n)
					if ((c == '[' || *n == c1) &&
						fnmatch(p, n, flags & ~FNM_PERIOD) == 0)
						return 0;
				return (FNM_NOMATCH);
			}

		case '[':
			{
				/* Nonzero if the sense of the character class is
				*         inverted.  */
				register int not;

				if (*n == '\0')
					return (FNM_NOMATCH);

				if ((flags & FNM_PERIOD) && *n == '.' &&
					(n == string
					|| ((flags & FNM_PATHNAME) && n[-1] == '/')))
					return (FNM_NOMATCH);

				/* Make sure there is a closing `]'.  If there isn't,
				*         the `[' is just a character to be matched.  */
				{
					register const char *np;

					for (np = p; np && *np && *np != ']'; np++);

					if (np && !*np) {
						if (*n != '[')
							return (FNM_NOMATCH);
						goto next_char;
					}
				}

				not = (*p == '!' || *p == '^');
				if (not)
					++p;

				c = *p++;
				while (1) {
					register char cstart = c, cend = c;

					if (!(flags & FNM_NOESCAPE) && c == '\\')
						cstart = cend = *p++;

					if (c == '\0')
						/* [ (unterminated) loses.  */
						return (FNM_NOMATCH);

					c = *p++;

					if ((flags & FNM_PATHNAME) && c == '/')
						/* [/] can never match.  */
						return (FNM_NOMATCH);

					if (c == '-' && *p != ']') {
						cend = *p++;
						if (!(flags & FNM_NOESCAPE) && cend == '\\')
							cend = *p++;
						if (cend == '\0')
							return (FNM_NOMATCH);
						c = *p++;
					}

					if (*n >= cstart && *n <= cend)
						goto matched;

					if (c == ']')
						break;
				}
				if (!not)
					return (FNM_NOMATCH);

next_char:
				break;

matched:
				/* Skip the rest of the [...] that already matched.  */
				while (c != ']') {
					if (c == '\0')
						/* [... (unterminated) loses.  */
						return (FNM_NOMATCH);

					c = *p++;
					if (!(flags & FNM_NOESCAPE) && c == '\\')
						/* 1003.2d11 is unclear if this is right.  %%% */
						++p;
				}
				if (not)
					return (FNM_NOMATCH);
			}
			break;

		default:
			if (c != *n)
				return (FNM_NOMATCH);
		}

		++n;
	}

	if (*n == '\0')
		return 0;

	return (FNM_NOMATCH);
}

static Boolean has_wildcards(const char *s)
{
	for (; *s; s++)
		if (*s == '*' || *s == '?' || *s == '[' || *s == ']')
			return TRUE;
	return FALSE;
}

Boolean nonwildcard_match_inDir(const char *path, const struct dentry *dentry, const struct vfsmount *mnt)
{
	const char * cpsMethod = "nonwildcard_match_inDir";
	pid_t cur_pid=0;
#if LINUX_VERSION_CODE >= 0x30000
	struct path pPath;
#else
	struct nameidata nd;
#endif
	struct dentry *ite_dentry; 
	struct dentry *ite_parent;
#if LINUX_VERSION_CODE >= 0x20620
    struct path sPath;
#endif
	struct vfsmount *ite_mnt;
	struct dentry *base;
	int error = 0;
    unsigned int flags;
	CP_DBG_LVL;
#if LINUX_VERSION_CODE <= 0x20612
	flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY | LOOKUP_NOALT;
#else
        //What can replace the flag "LOOKUP_NOALT".
	flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
#endif
	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into nonwildcard_match_inDir\n", cur_pid, cpsMethod);

	DPRINTK(2,"%d: %s: path=[%s] dent[%s] mnt[%s]\n", cur_pid, cpsMethod, path, dentry->d_name.name, mnt->mnt_devname);

	if (path[0] == '/' && path[1] == '\0') {
		DPRINTK(2,"%d: %s: path=/ , return TRUE\n", cur_pid, cpsMethod);
		return TRUE;
	}
	read_unlock(&kini_lock);

#if LINUX_VERSION_CODE >= 0x30000
	error = kern_path(path, flags, &pPath);
	read_lock(&kini_lock);
	if (error) return FALSE;
#elif LINUX_VERSION_CODE >= 0x20600
	error = PATH_LOOKUP(path, flags, &nd);
	read_lock(&kini_lock);
	if (error) return FALSE;
#else
	error = PATH_LOOKUP(path, flags | LOOKUP_POSITIVE, &nd);
	read_lock(&kini_lock);
	if (error) {
		DPRINTK(2,"%d: %s: PATH_LOOKUP error, return FALSE\n", cur_pid, cpsMethod);
		return FALSE;
	} else if (nd.DENTRY->d_inode == NULL) {
		DPRINTK(2,"%d: %s: d_inode is NULL, return FALSE\n", cur_pid, cpsMethod);
		read_unlock(&kini_lock);
		SPLX_PATH_RELEASE(&nd);
		read_lock(&kini_lock);
		return FALSE;
	}
#endif

#if LINUX_VERSION_CODE >= 0x30000
	base = pPath.dentry;
#else
	base = nd.DENTRY;
#endif
	read_unlock(&kini_lock);
	ite_dentry = dget_parent((struct dentry *)dentry);
	ite_mnt    = mntget((struct vfsmount *)mnt);

	while (1) {
#if LINUX_VERSION_CODE >= 0x20620
        sPath.mnt = ite_mnt;
        sPath.dentry = ite_dentry; 
#endif
		if (base == ite_dentry) {
			DPRINTK(2,"%d: %s: match found[%s], return TRUE\n", cur_pid, cpsMethod, ite_dentry->d_name.name);
			mntput(ite_mnt);
			dput(ite_dentry);
#if LINUX_VERSION_CODE >= 0x30000
			path_put(&pPath);
#else
			SPLX_PATH_RELEASE(&nd);
#endif
			read_lock(&kini_lock);
			return TRUE;
		}
		if (ite_dentry == ite_mnt->mnt_root || IS_ROOT(ite_dentry)) {
#if LINUX_VERSION_CODE >= 0x20620
            if (follow_up(&sPath) == 0)
            {
                mntput(sPath.mnt);
				dput(sPath.dentry);
                goto global_root;
            }
            else 
            {
                ite_dentry = sPath.dentry;
                ite_mnt    = sPath.mnt;
			    DPRINTK(3,"%d: %s: followed[%s][%s]\n", cur_pid, cpsMethod, sPath.mnt->mnt_devname, sPath.dentry->d_name.name);
            }
#else
			if (follow_up(&ite_mnt, &ite_dentry) == 0) 
            {
				mntput(ite_mnt);
				dput(ite_dentry);
				goto global_root;
			}
            else
            {
                DPRINTK(3,"%d: %s: followed[%s][%s]\n", cur_pid, cpsMethod, ite_mnt->mnt_devname, ite_dentry->d_name.name);
            }
#endif
          
		} 
        else {
			ite_parent = dget_parent(ite_dentry);
			dput(ite_dentry);
			ite_dentry = ite_parent;
		}
	}

global_root:
#if LINUX_VERSION_CODE >= 0x30000
	path_put(&pPath);
#else
	SPLX_PATH_RELEASE(&nd);
#endif
	read_lock(&kini_lock);
	DPRINTK(1,"%d: %s: get outta nonwildcard_match_inDir\n", cur_pid, cpsMethod);
	return FALSE;
}

#define free_dentry_path(lh)                                        \
		do {                                                        \
			dentry_path_t *ip, *nip;                                \
			list_for_each_entry_safe(ip, nip, &lh, dentry_list) {   \
				kfree(ip);                                          \
			}                                                       \
		} while (0)

Boolean wildcard_match_inDir(const char *path,
	const struct dentry *dentry, const struct vfsmount *mnt)
{
	const char * cpsMethod = "wildcard_match_inDir";
 #if LINUX_VERSION_CODE >= 0x20620
    struct path sPath;
 #endif
	pid_t cur_pid = current->pid;
	struct dentry *ite_dentry = dentry->d_parent;
	struct vfsmount *ite_mnt = (struct vfsmount *)mnt;
	char *tmp_path, *token, *dirs;
	Boolean match = FALSE;
	dentry_path_t *dentry_path, *next_dentry_path;
    int len;
	LIST_HEAD(dentry_path_head);
	CP_DBG_LVL;

	DPRINTK(1,"%d: %s: get into wildcard_match_inDir\n", cur_pid, cpsMethod);

	DPRINTK(2, "%d: %s: path = %s\n", cur_pid, cpsMethod, path);
    len = strlen(path);
	dirs = tmp_path = (char *)kmalloc(len + 1, GFP_ATOMIC);
	if (!dirs) return FALSE;
	strncpy(tmp_path, path, len + 1);

	read_unlock(&kini_lock);
	while (1) {
#if LINUX_VERSION_CODE >= 0x20620
        sPath.mnt = ite_mnt;
        sPath.dentry = ite_dentry;
#endif
		if (ite_dentry == ite_mnt->mnt_root || IS_ROOT(ite_dentry)) {
			mntget(ite_mnt);
			dget(ite_dentry);
#if LINUX_VERSION_CODE >= 0x20620
            if (follow_up(&sPath) == 0) 
            {
				mntput(sPath.mnt);
				dput(sPath.dentry);
				break;
			}
            else
            {
                ite_mnt = sPath.mnt;
                ite_dentry = sPath.dentry;
            }
#else
			if (follow_up(&ite_mnt, &ite_dentry) == 0) 
            {
				mntput(ite_mnt);
				dput(ite_dentry);
				break;
			}
#endif    
		} 
        else {
			dentry_path = (dentry_path_t *)kmalloc(sizeof(dentry_path_t), GFP_ATOMIC);
            if(dentry_path == NULL)
            {
                match = FALSE;
                DPRINTK(1, "%d: %s: Alloc memory for dentry failed\n", cur_pid, cpsMethod);
                goto exit;
            }
			dentry_path->component = ite_dentry;
			list_add(&dentry_path->dentry_list, &dentry_path_head);
			ite_dentry = ite_dentry->d_parent;
		}
	}

	if (*tmp_path == '/') {
		tmp_path++;
		token = strsep(&tmp_path, (const char *)"/");
	} else
		token = strsep(&tmp_path, (const char *)"/");

	do {
		DPRINTK(2, "%d: %s: token = %s\n", cur_pid, cpsMethod, token);
		if (strcmp(token, "*")==0) {
			DPRINTK(2, "%d: %s: last token is *, break\n", cur_pid, cpsMethod);
			break;
		}
		if ((list_empty(&dentry_path_head))) {
			DPRINTK(2, "%d: %s: list is empty, goto EXIT, no match\n", cur_pid, cpsMethod);
			match = FALSE;
			goto exit;
		}
		list_for_each_entry_safe(dentry_path, next_dentry_path, &dentry_path_head, dentry_list) {
			DPRINTK(2, "%d: %s: token = %s, d_name.name=%s\n", cur_pid, cpsMethod, token, dentry_path->component->d_name.name);
			if ((fnmatch(token, dentry_path->component->d_name.name, FNM_PATHNAME)) == FNM_NOMATCH) {
				DPRINTK(2, "%d: %s: fnmatch failed, no match, goto exit\n", cur_pid, cpsMethod);
				match = FALSE;
				goto exit;
			} else {
				DPRINTK(2, "%d: %s: break out loop, match is true\n", cur_pid, cpsMethod);
				list_del(&dentry_path->dentry_list);
				kfree(dentry_path);
				break;
			}
		}
	} while ((token = strsep(&tmp_path, (const char *)"/")));
	DPRINTK(2, "%d: %s: out from loop, match\n", cur_pid, cpsMethod);
	match = TRUE;

exit:
	free_dentry_path(dentry_path_head);
	kfree(dirs);
	read_lock(&kini_lock);
	DPRINTK(1,"%d: %s: get outta wildcard_match_inDir\n", cur_pid, cpsMethod);
	return match;
}


Boolean inDirs(struct dentry * dentry, struct vfsmount * mnt) 
{
	const char * cpsMethod = "inDirs";
	pid_t cur_pid=0;
	DIR_ITEM	*ip, *nip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into inDirs\n", cur_pid, cpsMethod);
    
    atomic_inc(&Del_list);    
	list_for_each_entry_safe(ip, nip, &dir_list_head, item_list) {
#ifndef X86_64
		DPRINTK(2,"%d: %s: ip %x, ip->path %s\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path);
#else
        DPRINTK(2,"%d: %s: ip 0x%lx, ip->path %s\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path);
#endif
		if (has_wildcards(ip->path)) {
			if (wildcard_match_inDir(ip->path, dentry, mnt)) {
				atomic_dec(&Del_list);
				DPRINTK(2,"%d: %s: Del_list = [%d],Return TRUE\n", cur_pid, cpsMethod, atomic_read(&Del_list));
				return TRUE;
			}
		} else {
			if (nonwildcard_match_inDir(ip->path, dentry, mnt)) {
                atomic_dec(&Del_list);
				DPRINTK(2,"%d: %s: Del_list = [%d],Return TRUE\n", cur_pid, cpsMethod, atomic_read(&Del_list));
				return TRUE;
			}
		}
	}
	
    atomic_dec(&Del_list);
	DPRINTK(1,"%d: %s: Del_list = [%d], get outta inDirs\n", cur_pid, cpsMethod, atomic_read(&Del_list));
	return FALSE;
}

Boolean inExcDirs(struct dentry * dentry, struct vfsmount * mnt) 
{
	const char * cpsMethod = "inExcDirs";
	pid_t cur_pid=0;
	EXC_DIR_ITEM	*ip, *nip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into inExcDirs\n", cur_pid, cpsMethod);
	DPRINTK(1,"%d: %s: list for each entry: exc_dir_list_abs_head\n", cur_pid, cpsMethod);
	
    atomic_inc(&Del_list);
	list_for_each_entry_safe(ip, nip, &exc_dir_list_abs_head, item_list) {
#ifndef X86_64
		DPRINTK(1,"%d: %s: ip %x, ip->path %s, ip->item_list.next %x\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path, (unsigned int)ip->item_list.next);
#else
        DPRINTK(1,"%d: %s: ip 0x%lx, ip->path %s, ip->item_list.next 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path, (unsigned long)ip->item_list.next);
#endif
		if (has_wildcards(ip->path)) {
			if (wildcard_match_inDir(ip->path, dentry, mnt)) {
                atomic_dec(&Del_list);
				DPRINTK(2,"%d: %s: Del_list = [%d],Return TRUE\n", cur_pid, cpsMethod, atomic_read(&Del_list));
				return TRUE;
			}
		} else {
			if (nonwildcard_match_inDir(ip->path, dentry, mnt)) {
                atomic_dec(&Del_list);                      
				DPRINTK(2,"%d: %s: Del_list = [%d],Return TRUE\n", cur_pid, cpsMethod, atomic_read(&Del_list));
				return TRUE;
			}	    
		}
	}

	list_for_each_entry_safe(ip, nip, &exc_dir_list_rel_head, item_list) {
		if (has_wildcards(ip->path)) {
			if (wildcard_match_inDir(ip->path, dentry, mnt)) {
                atomic_dec(&Del_list);
				DPRINTK(2,"%d: %s: Del_list = [%d],Return TRUE\n", cur_pid, cpsMethod, atomic_read(&Del_list));
				return TRUE;
			}
		} else {
			if (nonwildcard_match_inDir(ip->path, dentry, mnt)) {
                atomic_dec(&Del_list);
				DPRINTK(2,"%d: %s: Del_list = [%d],Return TRUE\n", cur_pid, cpsMethod, atomic_read(&Del_list));
				return TRUE;
			}	    
		}
	}
	
    atomic_dec(&Del_list);
	DPRINTK(1,"%d: %s: Del_list = [%d], get outta inExcDirs\n", cur_pid, cpsMethod, atomic_read(&Del_list));
	return FALSE;
}

//TT191735: Bug in exclusion file list
Boolean wildcard_match_inExcFil(const char *path,
								const struct dentry *dentry, const struct vfsmount *mnt)
{
	const char * cpsMethod = "wildcard_match_inExcFil";
 #if LINUX_VERSION_CODE >= 0x20620
    struct path sPath;
 #endif
	pid_t cur_pid = current->pid;
	struct dentry *ite_dentry = (struct dentry *)dentry;
	struct vfsmount *ite_mnt = (struct vfsmount *)mnt;
	char *tmp_path, *token, *dirs;
	Boolean match = FALSE;
	dentry_path_t *dentry_path, *next_dentry_path;
	int len;
    LIST_HEAD(dentry_path_head);
	CP_DBG_LVL;
    
	DPRINTK(3,"%d: %s: get into wildcard_match_inExcFil\n", cur_pid, cpsMethod);
    len = strlen(path);
	dirs = tmp_path = (char *)kmalloc(len + 1, GFP_ATOMIC);
	if (!dirs) return FALSE;
    
    //If path is "/home/test/abc"
    //After below is "home/test/abc/"
    //For function strsep
	strncpy(tmp_path, path+1, len-1);
    tmp_path[len-1] = '/';
    tmp_path[len] = '\0';

	read_unlock(&kini_lock);

	while (1) {
#if LINUX_VERSION_CODE >= 0x20620
        sPath.mnt = ite_mnt;
        sPath.dentry = ite_dentry;
#endif
		if (ite_dentry == ite_mnt->mnt_root || IS_ROOT(ite_dentry)) {
			mntget(ite_mnt);
			dget(ite_dentry);
#if LINUX_VERSION_CODE >= 0x20620
            if (follow_up(&sPath) == 0) 
            {
				mntput(sPath.mnt);
				dput(sPath.dentry);
				break;
			}
            else
            {
                ite_mnt = sPath.mnt;
                ite_dentry = sPath.dentry;
            }
#else
			if (follow_up(&ite_mnt, &ite_dentry) == 0) 
            {
				mntput(ite_mnt);
				dput(ite_dentry);
				break;
			}
#endif
		} 
        else
        {
            dentry_path = (dentry_path_t *)kmalloc(sizeof(dentry_path_t), GFP_ATOMIC);
            dentry_path->component = ite_dentry;
		    list_add(&dentry_path->dentry_list, &dentry_path_head);
			ite_dentry = ite_dentry->d_parent;
        }
	}
    
    //Start to match the path
	list_for_each_entry_safe(dentry_path, next_dentry_path, &dentry_path_head, dentry_list) {
		token = strsep(&tmp_path, (const char *)"/");
        /*
        ** example: path is /home/test
        ** file to scan is /home/test/abc
        */
		if(token ==NULL && dentry_path->component->d_name.name != NULL)
		{
			match = FALSE;
			goto exit;
		}
		if (fnmatch(token, dentry_path->component->d_name.name, FNM_PATHNAME)) {
			match = FALSE;
			goto exit;
		} else {
			list_del(&dentry_path->dentry_list);
			kfree(dentry_path);
		}
	}
    /* example
    ** file to scan is /home/test/abc
    ** path is /home/test/abc/abc
    ** go to else
    */ 
	if(tmp_path == NULL || tmp_path[0] == '\0')
		match = TRUE;
	else
		match = FALSE;

exit:
	free_dentry_path(dentry_path_head);
	read_lock(&kini_lock);
	DPRINTK(3,"%d: %s: get outta wildcard_match_inExcFil, result [%d]\n", cur_pid, cpsMethod, match);
	return match;
}

Boolean nonwildcard_match_inExcFil(const char *path,
								   const struct dentry *dentry, const struct vfsmount *mnt)
{
	const char * cpsMethod = "nonwildcard_match_inExcFil";
	pid_t cur_pid=0;
#if LINUX_VERSION_CODE >= 0x30000
	struct path pPath;
#else
	struct nameidata nd;
#endif
	struct dentry *ite_dentry = (struct dentry *)dentry;
	struct dentry *base_dentry;
	struct vfsmount *base_mnt;
#if LINUX_VERSION_CODE <= 0x20612 
	unsigned int flags = LOOKUP_FOLLOW | LOOKUP_NOALT;
#else
    unsigned int flags = LOOKUP_FOLLOW;
#endif
	int error = 0;
	Boolean ret=FALSE;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into nonwildcard_match_inExcFil\n", cur_pid, cpsMethod);

	read_unlock(&kini_lock);

#if LINUX_VERSION_CODE >= 0x30000
	error = kern_path(path, flags, &pPath);
	read_lock(&kini_lock);
	if (error) return FALSE;
#elif LINUX_VERSION_CODE >= 0x20600
	error = PATH_LOOKUP(path, flags, &nd);
	read_lock(&kini_lock);
	if (error) return FALSE;
#else
	error = PATH_LOOKUP(path, flags | LOOKUP_POSITIVE, &nd);
	read_lock(&kini_lock);
	if (error)
		return FALSE;
	else if (nd.DENTRY->d_inode == NULL) {
		ret = FALSE;
		goto out;
	}
#endif

#if LINUX_VERSION_CODE >= 0x30000
	base_dentry = pPath.dentry;
	base_mnt = pPath.mnt;
#else
	base_dentry = nd.DENTRY;
	base_mnt = nd.MNT;
#endif

	if (base_dentry == ite_dentry) {
		ret = TRUE;
		goto out;
	}

out:
	read_unlock(&kini_lock);
#if LINUX_VERSION_CODE >= 0x30000
	path_put(&pPath);
#else
	SPLX_PATH_RELEASE(&nd);
#endif
	read_lock(&kini_lock);
	return ret;
}


Boolean inExcFils(const struct dentry * dentry, const struct vfsmount * mnt) 
{
	const char * cpsMethod = "inExcFils";
	pid_t cur_pid=0;
	EXC_FIL_ITEM	*ip, *nip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into inExcFils\n", cur_pid, cpsMethod);

    atomic_inc(&Del_list);
	list_for_each_entry_safe(ip, nip, &exc_fil_list_abs_head, item_list) {
		if ((has_wildcards(ip->path))) {
			if (wildcard_match_inExcFil(ip->path, dentry, mnt)) {
                atomic_dec(&Del_list);
				return TRUE;
			}
		} else {
			if ((nonwildcard_match_inExcFil(ip->path, dentry, mnt))) {
                atomic_dec(&Del_list);
				return TRUE;
			}
		}
	}

	list_for_each_entry_safe(ip, nip, &exc_fil_list_rel_head, item_list) {
		if ((has_wildcards(ip->path))) {
			if (wildcard_match_inExcFil(ip->path, dentry, mnt)) {
                atomic_dec(&Del_list);
				return TRUE;
			}
		} else {
			if ((nonwildcard_match_inExcFil(ip->path, dentry, mnt))) {
                atomic_dec(&Del_list);
				return TRUE;
			}
		}
	}
    atomic_dec(&Del_list);
	DPRINTK(1,"%d: %s: Del_list=[%d], get outta inExcFils\n", cur_pid, cpsMethod, atomic_read(&Del_list));
	return FALSE;
}

Boolean inCache(ino_t inode) 
{
	const char * cpsMethod = "inCache";
	pid_t cur_pid=0;
	CACHE_ITEM	*ip, *nip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into inCache\n", cur_pid, cpsMethod);

	spin_lock(&cache_item_head_lock);
	list_for_each_entry_safe(ip, nip, &cache_item_head, item_list) {
		if (inode == ip->inode) {
			list_move(&ip->item_list, &cache_item_head);
			spin_unlock(&cache_item_head_lock);
			return TRUE;
		}
	}
	spin_unlock(&cache_item_head_lock);

	DPRINTK(1,"%d: %s: get outta inCache\n", cur_pid, cpsMethod);
	return FALSE;
}

Boolean withExts(char *full_pn) 
{
	const char * cpsMethod = "withExts";
	pid_t cur_pid=0;
	char	*cp;
	EXT_ITEM	*ip, *nip;
	char	*type;
	int r;
	char	*dq = "\"\"";
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into withExts\n", cur_pid, cpsMethod);

	cp = strrchr(full_pn, '.');
	if (cp != NULL) type = cp+1;
	else type = dq;

	list_for_each_entry_safe(ip, nip, &ext_list_head, item_list) {
		r = strnicmp(type, ip->type, (strlen(type) > strlen(ip->type) ?
			strlen(type) : strlen(ip->type)));
		if (r == 0) return TRUE;
		else if (r > 0) continue;
		else break;
	}

	DPRINTK(1,"%d: %s: get outta withExts\n", cur_pid, cpsMethod);
	return FALSE;
}

Boolean withExcExts(char *full_pn) 
{
	const char * cpsMethod = "withExcExts";
	pid_t cur_pid=0;
	char       *cp;
	EXC_EXT_ITEM	*ip, *nip;
	char	*type;
	int r;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into withExcExts\n", cur_pid, cpsMethod);

	cp = strrchr(full_pn, '.');
	if (cp != NULL) type = cp+1;
	else return FALSE;

	list_for_each_entry_safe(ip, nip, &exc_ext_list_head, item_list) {
		r = strnicmp(type, ip->type, (strlen(type) > strlen(ip->type) ?
			strlen(type) : strlen(ip->type)));
		if (r == 0) return TRUE;
		else if (r > 0) continue;
		else break;
	}

	DPRINTK(1,"%d: %s: get outta withExcExts\n", cur_pid, cpsMethod);
	return FALSE;
}

// Before entering, hold kini_lock for read.
Boolean needToScanThisOpen(struct dentry * dentry, struct vfsmount * mnt, int flags, ino_t inode) 
{
	const char * cpsMethod = "needToScanThisOpen";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into needToScanThisOpen\n", cur_pid, cpsMethod);
	if (inode == 0) return FALSE;

	DPRINTK(2,"%d: %s: incoming %d, outgoing %d, flags %x\n", cur_pid, cpsMethod, kini.incoming, kini.outgoing, flags);
	if (!(kini.outgoing && 
		(((flags & O_ACCMODE) == O_RDONLY) || 
		((flags & O_ACCMODE) == O_RDWR)))) 
		return FALSE;

	DPRINTK(2,"%d: %s: test in cache\n", cur_pid, cpsMethod);
	if (inCache(inode)) return FALSE;

	DPRINTK(2,"%d: %s: test in dirs\n", cur_pid, cpsMethod);
	if (!list_empty(&dir_list_head) && !inDirs(dentry, mnt)) return FALSE;

	DPRINTK(2,"%d: %s: test with exts\n", cur_pid, cpsMethod);
	if (!list_empty(&ext_list_head) && !withExts((char*)dentry->d_name.name)) return FALSE;

	DPRINTK(2,"%d: %s: test in exc dirs\n", cur_pid, cpsMethod);
	if ((!list_empty(&exc_dir_list_abs_head) || !list_empty(&exc_dir_list_rel_head)) &&
		inExcDirs(dentry, mnt))
		return FALSE;

	DPRINTK(2,"%d: %s: test in exc fils\n", cur_pid, cpsMethod);
	if ((!list_empty(&exc_fil_list_abs_head) || !list_empty(&exc_fil_list_rel_head)) && 
		inExcFils(dentry, mnt))
		return FALSE;

	DPRINTK(2,"%d: %s: test with exc exts\n", cur_pid, cpsMethod);
	if (!list_empty(&exc_ext_list_head) && withExcExts((char*)dentry->d_name.name)) return FALSE;

	DPRINTK(1,"%d: %s: get outta needToScanThisOpen\n", cur_pid, cpsMethod);
	return TRUE;
}

// Before entering, hold kini_lock for read.
Boolean needToScanThisClose(struct dentry * dentry, struct vfsmount * mnt, int flags, ino_t inode)
{
	const char * cpsMethod = "needToScanThisClose";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into needToScanThisClose\n", cur_pid, cpsMethod);

	DPRINTK(2,"%d: %s: incoming %d, outgoing %d, flags %x\n", cur_pid, cpsMethod, kini.incoming, kini.outgoing, flags);
	if (!((kini.incoming && 
		(((flags & O_ACCMODE) == O_WRONLY) || 
		((flags & O_ACCMODE) == O_RDWR))))) 
		return FALSE;

	//if (inCache(inode)) {
	//	return FALSE;
	//}

	if (!list_empty(&dir_list_head) && !inDirs(dentry, mnt)) return FALSE;

	if (!list_empty(&ext_list_head) && !withExts((char*)dentry->d_name.name)) return FALSE;

	if ((!list_empty(&exc_dir_list_abs_head) || !list_empty(&exc_dir_list_rel_head)) && 
		inExcDirs(dentry,mnt)) 
		return FALSE;

	if ((!list_empty(&exc_fil_list_abs_head) || !list_empty(&exc_fil_list_rel_head)) && 
		inExcFils(dentry, mnt)) 
		return FALSE;

	if (!list_empty(&exc_ext_list_head) && withExcExts((char *)dentry->d_name.name)) return FALSE;

	DPRINTK(1,"%d: %s: get outta needToScanThisClose\n", cur_pid, cpsMethod);
	return TRUE;
}

// Before entering, hold kini_lock for read.
Boolean needToScanThisExecve(struct dentry * dentry, struct vfsmount * mnt, ino_t inode) 
{
	const char * cpsMethod = "needToScanThisExecve";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into needToScanThisExecve\n", cur_pid, cpsMethod);

	DPRINTK(2,"%d: %s: running %d\n", cur_pid, cpsMethod, kini.running);
	if (!kini.running)
		return FALSE;

	DPRINTK(2,"%d: %s: test in cache\n", cur_pid, cpsMethod);
	if (inCache(inode)) return FALSE;

	DPRINTK(2,"%d: %s: test in dirs\n", cur_pid, cpsMethod);
	if (!list_empty(&dir_list_head) && !inDirs(dentry, mnt)) return FALSE;

	DPRINTK(2,"%d: %s: test with exts\n", cur_pid, cpsMethod);
	if (!list_empty(&ext_list_head) && !withExts((char *)dentry->d_name.name)) return FALSE;

	DPRINTK(2,"%d: %s: test in exc dirs\n", cur_pid, cpsMethod);
	if ((!list_empty(&exc_dir_list_abs_head) || !list_empty(&exc_dir_list_rel_head)) && 
		inExcDirs(dentry, mnt)) 
		return FALSE;

	DPRINTK(2,"%d: %s: test in exc fils\n", cur_pid, cpsMethod);
	if ((!list_empty(&exc_fil_list_abs_head) || !list_empty(&exc_fil_list_rel_head)) && 
		inExcFils(dentry, mnt))
		return FALSE;

	DPRINTK(2,"%d: %s: test with exc exts\n", cur_pid, cpsMethod);
	if (!list_empty(&exc_ext_list_head) && withExcExts((char *)dentry->d_name.name)) return FALSE;

	DPRINTK(1,"%d: %s: get outta needToScanThisExecve\n", cur_pid, cpsMethod);
	return TRUE;
}

void addCache(ino_t inode) 
{
	const char * cpsMethod = "addCache";
	pid_t cur_pid=0;
	CACHE_ITEM	*oip, *ip, *nip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into addCache\n", cur_pid, cpsMethod);

	spin_lock(&cache_item_head_lock);
	list_for_each_entry_safe(ip, nip, &cache_item_head, item_list) {
		if (ip->inode == inode) {
			spin_unlock(&cache_item_head_lock);
			return;
		}
	}
	spin_unlock(&cache_item_head_lock);

	read_lock(&kini_lock);
	spin_lock(&cache_item_head_lock);
	if (cache_item_no < kini.max_cache_item) {
		read_unlock(&kini_lock);
		nip = (CACHE_ITEM *)kmalloc(sizeof(CACHE_ITEM), GFP_ATOMIC);
		if (nip == NULL) {
			WPRINTK("%d: %s: nip is NULL\n", cur_pid, cpsMethod);
			spin_unlock(&cache_item_head_lock);
			return;
		}
		nip->inode = inode;
		list_add(&nip->item_list, &cache_item_head);
		cache_item_no++;
	} else {
		read_unlock(&kini_lock);
		oip = list_entry(cache_item_head.prev, CACHE_ITEM, item_list);
		oip->inode = inode;
		list_move(&oip->item_list, &cache_item_head);
	}

	DPRINTK(1,"%d: %s: get outta addCache\n", cur_pid, cpsMethod);
	spin_unlock(&cache_item_head_lock);
}

void removeCache(ino_t inode) 
{
	const char * cpsMethod = "removeCache";
	pid_t cur_pid=0;
	CACHE_ITEM	*nip, *ip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into removeCache\n", cur_pid, cpsMethod);

	spin_lock(&cache_item_head_lock);
	list_for_each_entry_safe(ip, nip, &cache_item_head, item_list) {
		if (ip->inode == inode) {
#ifndef X86_64
			DPRINTK(2, "%d: %s: deleted ip %x\n", cur_pid, cpsMethod, (unsigned int)ip);
#else
			DPRINTK(2, "%d: %s: deleted ip 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip);
#endif
			list_del(&ip->item_list);
			cache_item_no--;
			spin_unlock(&cache_item_head_lock);
			kfree(ip);
			ip = NULL;
			return;
		}
	}
	spin_unlock(&cache_item_head_lock);
	DPRINTK(1,"%d: %s: get outta removeCache\n", cur_pid, cpsMethod);
}

void removeCacheAll(void) {
	const char * cpsMethod = "removeCacheAll";
	pid_t cur_pid=0;
	CACHE_ITEM	*nip, *ip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into removeCacheAll\n", cur_pid, cpsMethod);

	spin_lock(&cache_item_head_lock);
	list_for_each_entry_safe(ip, nip, &cache_item_head, item_list) {
		if (ip) {
			list_del(&ip->item_list);
#ifndef X86_64
			DPRINTK(2, "%d: %s: deleted ip %x\n", cur_pid, cpsMethod, (unsigned int)ip);
#else
    			DPRINTK(2, "%d: %s: deleted ip 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip);
#endif
			kfree(ip);
		}
	}
	INIT_LIST_HEAD(&cache_item_head);
	cache_item_no = 0;
	spin_unlock(&cache_item_head_lock);
	DPRINTK(1,"%d: %s: get outta removeCacheAll\n", cur_pid, cpsMethod);
}

Boolean insertList(LIST_ITEM *lip) 
{
	const char * cpsMethod = "insertList";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into insertList\n", cur_pid, cpsMethod);
#ifndef X86_64
	DPRINTK(2,"%d: %s: insert list lip %x, PID %d, FD %d\n", cur_pid, cpsMethod, (unsigned int)lip, lip->info.scan_args.comm_pid, lip->info.scan_args.fd);
#else
    DPRINTK(2,"%d: %s: insert list lip 0x%lx, PID %d, FD %d\n", cur_pid, cpsMethod, (unsigned long)lip, lip->info.scan_args.comm_pid, lip->info.scan_args.fd); 
#endif
	DPRINTK(2,"%d: %s: list_item_no = %d, kini.max_list_item = %d\n", cur_pid, cpsMethod, list_item_no, kini.max_list_item);

	read_lock(&kini_lock);
	spin_lock(&list_item_head_lock);
	if (list_item_no >= kini.max_list_item || vsapi_chldn_no == 0) {
		spin_unlock(&list_item_head_lock);
		read_unlock(&kini_lock);
		return FALSE;
	}
	read_unlock(&kini_lock);

	list_add_tail(&lip->item_list, &list_item_head);
	list_item_no++;
	spin_unlock(&list_item_head_lock);
	DPRINTK(1,"%d: %s: get outta insertList\n", cur_pid, cpsMethod);
	return TRUE;
}


Boolean deleteList(LIST_ITEM *lip) 
{
	const char * cpsMethod = "deleteList";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into deleteList\n", cur_pid, cpsMethod);
	if (lip != NULL) {
		DPRINTK(2,"%d: %s: delete list PID %d, FD %d\n", cur_pid, cpsMethod,
			lip->info.scan_args.comm_pid, lip->info.scan_args.fd);

		if (lip->info.scan_args.full_pn != NULL)
			lip->info.scan_args.full_pn = NULL;
		if (lip->info.scan_args.comm != NULL)
			kfree(lip->info.scan_args.comm);
		dput(lip->info.dentry);
		mntput(lip->info.mnt);
		kfree(lip);
		lip = NULL;
		return TRUE;
	}
	DPRINTK(1,"%d: %s: get outta deleteList\n", cur_pid, cpsMethod);
	return FALSE;
}

Boolean deleteListPID(pid_t cur_pid) 
{
	const char * cpsMethod = "deleteListPID";
	pid_t current_pid=0;
	LIST_ITEM      *ip, *nip;
	Boolean found = FALSE;
	LIST_HEAD(deletelist_head);
	CP_DBG_LVL;

	current_pid = current->pid;
	DPRINTK(1,"%d: %s: get into deleteListPID\n", current_pid, cpsMethod);
	DPRINTK(2,"%d: %s: delete list all PID %d\n", current_pid, cpsMethod, cur_pid);

	spin_lock(&list_item_head_lock);
	list_for_each_entry_safe(ip, nip, &list_item_head, item_list) {
		if (ip && cur_pid == ip->info.scan_args.comm_pid) {
			found = TRUE;
			list_del_init(&ip->item_list);
			list_item_no--;
			list_add(&ip->item_list, &deletelist_head);
		}
	}
	spin_unlock(&list_item_head_lock);

	spin_lock(&scanning_item_head_lock);
	list_for_each_entry_safe(ip, nip, &scanning_item_head, item_list) {
		if (ip && cur_pid == ip->info.scan_args.comm_pid) {
			found = TRUE;
			list_del_init(&ip->item_list);
			list_item_no--;
			list_add(&ip->item_list, &deletelist_head);
		}
	}
	spin_unlock(&scanning_item_head_lock);

	list_for_each_entry_safe(ip, nip, &deletelist_head, item_list) {
		if (ip->info.scan_args.full_pn != NULL)
			ip->info.scan_args.full_pn = NULL;
		if (ip->info.scan_args.comm != NULL)
			kfree(ip->info.scan_args.comm);
		dput(ip->info.dentry);
		mntput(ip->info.mnt);
		kfree(ip);
		ip = NULL;
	}

	if (found)
#ifndef X86_64
		DPRINTK(2, "%d: %s: deleted ip %x\n", current_pid, cpsMethod, (unsigned int)ip);
#else
		DPRINTK(2, "%d: %s: deleted ip 0x%lx\n", current_pid, cpsMethod, (unsigned long)ip);
#endif
	DPRINTK(1,"%d: %s: get outta deleteListPID\n", current_pid, cpsMethod);
	return found;
}

void deleteListAll(void) 
{
	const char * cpsMethod = "deleteListAll";
	pid_t cur_pid=0;
	LIST_ITEM      *ip, *nip;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into deleteListAll\n", cur_pid, cpsMethod);

	list_for_each_entry_safe(ip, nip, &list_item_head, item_list) {
		if (ip) {
			list_del(&ip->item_list);
			if (ip->info.scan_args.full_pn != NULL)
				ip->info.scan_args.full_pn = NULL;
			if (ip->info.scan_args.comm != NULL)
				kfree(ip->info.scan_args.comm);
			dput(ip->info.dentry);
			mntput(ip->info.mnt);
			kfree(ip);
			ip = NULL;
		}
	}
	INIT_LIST_HEAD(&list_item_head);
	list_item_no = 0;

	list_for_each_entry_safe(ip, nip, &scanning_item_head, item_list) {
		if (ip) {
			list_del(&ip->item_list);
			if (ip->info.scan_args.full_pn != NULL)
				ip->info.scan_args.full_pn = NULL;
			if (ip->info.scan_args.comm != NULL)
				kfree(ip->info.scan_args.comm);
			dput(ip->info.dentry);
			mntput(ip->info.mnt);
			kfree(ip);
			ip = NULL;
		}
	}
	INIT_LIST_HEAD(&scanning_item_head);
	scanning_list_item_no = 0;
	DPRINTK(1,"%d: %s: get outta deleteListAll\n", cur_pid, cpsMethod);
}


Boolean alreadyDead(LIST_ITEM *ip)
{
	const char * cpsMethod = "alreadyDead";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into alreadyDead\n", cur_pid, cpsMethod);

	if (orig_getpgid(ip->info.scan_args.comm_pid) == -ESRCH) {
#ifndef X86_64
		DPRINTK(2,"%d: %s: deleted ip %x\n", cur_pid, cpsMethod, (unsigned int)ip);
#else
DPRINTK(2,"%d: %s: deleted ip lx%lx\n", cur_pid, cpsMethod, (unsigned long)ip);
#endif
		return TRUE;
	}

	DPRINTK(1,"%d: %s: get outta alreadyDead\n", cur_pid, cpsMethod);
	return FALSE;
}

Boolean alreadyBusy(ino_t inode) 
{
	LIST_ITEM      *ip, *nip;

	list_for_each_entry_safe(ip, nip, &scanning_item_head, item_list) {
		if (ip && ip->info.scan_args.inode == inode)
			return TRUE;
	}
	return FALSE;
}

/* 
	ret = 1: has candidate
	ret = 0: no candidate, list is empty
	ret = 2: no candidate, list is not empty
*/
int findListCandid(pid_t cur_pid, unsigned int fd, LIST_ITEM **lipp) 
{
	const char * cpsMethod = "findListCandid";
	pid_t current_pid=0;
	LIST_ITEM      *ip, *nip;
	LIST_ITEM      *dp, *dip;
	int		ret=0;
	LIST_HEAD(deleteList_head);
	CP_DBG_LVL;

	current_pid = current->pid;
	spin_lock(&list_item_head_lock);
	DPRINTK(1,"%d: %s: get into findListCandid\n", current_pid, cpsMethod);
	DPRINTK(2,"%d: %s: find list PID %d, FD %d\n", current_pid, cpsMethod, cur_pid, fd);

	switch(cur_pid) {
	case 0:
		list_for_each_entry_safe(ip, nip, &list_item_head, item_list) {
			spin_lock(&scanning_item_head_lock);
			if (alreadyBusy(ip->info.scan_args.inode)) {
				DPRINTK(2, "%d: %s: *** ip->info.scan_args.comm [%s] ip->info.scan_args.inode [%ld]\n", 
					current_pid, cpsMethod, ip->info.scan_args.comm, ip->info.scan_args.inode);
				//ret = 2;
				//continue;
			}
			spin_unlock(&scanning_item_head_lock);
			if (!alreadyDead(ip)) {
#ifndef X86_64
				DPRINTK(2, "%d: %s: found ip %x\n", current_pid, cpsMethod, (unsigned int)ip);
#else
				DPRINTK(2, "%d: %s: found ip 0x%lx\n", current_pid, cpsMethod, (unsigned long)ip);
#endif
				list_del_init(&ip->item_list);
				list_item_no--;
				*lipp = ip;
				ret = 1;
				goto out;
			} else {
				list_del_init(&ip->item_list);
				list_item_no--;
				list_add(&ip->item_list, &deleteList_head);
			}
		}
		break;
	default:
		list_for_each_entry_safe(ip, nip, &list_item_head, item_list) {
			if ((cur_pid == ip->info.scan_args.comm_pid) && (fd == ip->info.scan_args.fd)) {
				#ifndef X86_64
                DPRINTK(2,"%d: %s: found ip %x\n", current_pid, cpsMethod, (unsigned int)ip);
                #else
                DPRINTK(2,"%d: %s: found ip 0x%lx\n", current_pid, cpsMethod, (unsigned long)ip);
                #endif
				list_del_init(&ip->item_list);
				list_item_no--;
				*lipp = ip;
				ret = 1;
				goto out;
			}
		}
	}

out:
	if (ret != 1) *lipp = NULL;
	DPRINTK(1,"%d: %s: get outta findListCandid, ret = %d\n", current_pid, cpsMethod, ret);
	spin_unlock(&list_item_head_lock);

	list_for_each_entry_safe(dp, dip, &deleteList_head, item_list) {
		if (dp->info.scan_args.full_pn != NULL)
			dp->info.scan_args.full_pn = NULL;
		if (dp->info.scan_args.comm != NULL)
			kfree(dp->info.scan_args.comm);
		dput(dp->info.dentry);
		mntput(dp->info.mnt);
		kfree(dp);
		dp = NULL;
	}

	return ret;
}

void wakeupItemBusy(void)
{
	const char * cpsMethod = "wakeupItemBusy";
	pid_t cur_pid = current->pid;
	LIST_ITEM *ip;
	struct task_struct *p;
    int rewake = 0;
    int nTaskListSplxLocked = -1;
    int nScanningItemHeadLocked = -1;
	CP_DBG_LVL;
	
	DPRINTK(1,"%d: %s: get into wakeupItemBusy\n", cur_pid, cpsMethod);

	spin_lock(&scanning_item_head_lock);
    nScanningItemHeadLocked = 1;
    
	while(!list_empty(&scanning_item_head)) {
		ip = list_entry(scanning_item_head.next, typeof(*ip), item_list);
		if (ip) {
			ip->info.scan_args.vsapi_chld_pid = 0;
			DPRINTK(2,"%d: %s: going to wake up busy process [%s][%d]\n", cur_pid, cpsMethod, ip->info.scan_args.comm, ip->info.scan_args.comm_pid);
            TASK_LIST_SPLX_LOCK;
            nTaskListSplxLocked = 1;
			p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
#if defined (EXIT_ZOMBIE) && defined (EXIT_DEAD)
			if (p && p->exit_state != EXIT_ZOMBIE && p->exit_state != EXIT_DEAD &&
				atomic_read(&(ip->info.cond)) == FALSE) {
#elif defined (TASK_DEAD)
			if (p && p->state != TASK_ZOMBIE && p->state != TASK_DEAD &&
				atomic_read(&(ip->info.cond)) == FALSE) {
#else
			if (p && p->state != TASK_ZOMBIE && atomic_read(&(ip->info.cond)) == FALSE) {
#endif
				atomic_set(&(ip->info.cond), TRUE);
				list_del(&ip->item_list);
				scanning_list_item_no--;
                TASK_LIST_SPLX_UNLOCK;
                nTaskListSplxLocked = 0;
                spin_unlock(&scanning_item_head_lock);
                nScanningItemHeadLocked = 0;

                TASK_LIST_SPLX_LOCK;
                nTaskListSplxLocked = 1;
				if (p->state != TASK_RUNNING) {
					DPRINTK(2,"%d: %s: wake up process\n", cur_pid, cpsMethod);
					rewake = 0;
					while(wake_up_process(p) == 0 && rewake < 10000 )
					{
                        TASK_LIST_SPLX_UNLOCK;
                        nTaskListSplxLocked = 0;
						msleep(1);

						rewake++;
			
                        TASK_LIST_SPLX_LOCK;
                        nTaskListSplxLocked = 1;
						p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
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
				}
                TASK_LIST_SPLX_UNLOCK;
                nTaskListSplxLocked = 0;
			}
            if (1 == nTaskListSplxLocked)
            {
                TASK_LIST_SPLX_UNLOCK;
                nTaskListSplxLocked = 0;
            } 
            if (0 == nScanningItemHeadLocked)
            {
                spin_lock(&scanning_item_head_lock);
                nScanningItemHeadLocked = 1;
            }
		}
        
	}
    if (1 == nScanningItemHeadLocked)
    {
	    spin_unlock(&scanning_item_head_lock);
        nScanningItemHeadLocked = 0;
    }
	DPRINTK(1,"%d: %s: get outta wakeupItemBusy\n", cur_pid, cpsMethod);
}

void wakeupItemCandid(void)
{
	const char * cpsMethod = "wakeupItemCandid";
	pid_t cur_pid = current->pid;
	LIST_ITEM *ip;
	struct task_struct *p;
    int rewake = 0;
    int nTaskListSplxLocked = -1;
    int nListItemHeadLocked = -1;
	CP_DBG_LVL;

	DPRINTK(1,"%d: %s: get into wakeupItemCandid\n", cur_pid, cpsMethod);
	spin_lock(&list_item_head_lock);
    nListItemHeadLocked = 1;
    
	while(!list_empty(&list_item_head)) {
		ip = list_entry(list_item_head.next, typeof(*ip), item_list);
		if (ip) {
			DPRINTK(2,"%d: %s: going to wake up candid process [%s][%d]\n", cur_pid, cpsMethod, ip->info.scan_args.comm, ip->info.scan_args.comm_pid);
            TASK_LIST_SPLX_LOCK;
            nTaskListSplxLocked = 1;
			p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
#if defined (EXIT_ZOMBIE) && defined (EXIT_DEAD)
			if (p && p->exit_state != EXIT_ZOMBIE && p->exit_state != EXIT_DEAD &&
				atomic_read(&(ip->info.cond)) == FALSE) {
#elif defined (TASK_DEAD)
			if (p && p->state != TASK_ZOMBIE && p->state != TASK_DEAD &&
				atomic_read(&(ip->info.cond)) == FALSE) {
#else
			if (p && p-> state != TASK_ZOMBIE && atomic_read(&(ip->info.cond)) == FALSE) {
#endif
				atomic_set(&(ip->info.cond), TRUE);
				list_del(&ip->item_list);
				list_item_no--;
                TASK_LIST_SPLX_UNLOCK;
				nTaskListSplxLocked = 0;
                spin_unlock(&list_item_head_lock);
                nListItemHeadLocked = 0;
                
                TASK_LIST_SPLX_LOCK;
				nTaskListSplxLocked = 1;
				if (p->state != TASK_RUNNING) {
					DPRINTK(2,"%d: %s: wake up process\n", cur_pid, cpsMethod);
					rewake = 0;
					while(wake_up_process(p) == 0 && rewake < 10000 )
					{
                        TASK_LIST_SPLX_UNLOCK;
						nTaskListSplxLocked = 0;
						msleep(1);

						rewake++;
			
                        TASK_LIST_SPLX_LOCK;
						nTaskListSplxLocked = 1;
						p = splx_find_task_by_pid(ip->info.scan_args.comm_pid);
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
				}
                TASK_LIST_SPLX_UNLOCK;
                nTaskListSplxLocked = 0;
			}
            if (1 == nTaskListSplxLocked)
            {
                TASK_LIST_SPLX_UNLOCK;
				nTaskListSplxLocked = 0;
            }
            if (0 == nListItemHeadLocked)
            {
                spin_lock(&list_item_head_lock);
                nListItemHeadLocked = 1;
            }
		}
	}
    if (1 == nListItemHeadLocked)
    {
	    spin_unlock(&list_item_head_lock);
        nListItemHeadLocked = 0;
    }
	DPRINTK(1,"%d: %s: get outta wakeupItemCandid\n", cur_pid, cpsMethod);
}

Boolean addDir(char *path) 
{
	const char * cpsMethod = "addDir";
	pid_t cur_pid=0;
	DIR_ITEM	*oip, *ip, *nip;
	int r;
	char * end;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into addDir, path %s\n", cur_pid, cpsMethod, path);

	DPRINTK(1,"%d: %s: dir_item_no %d, kini.max_dir_item %d\n", cur_pid, cpsMethod, dir_item_no, kini.max_dir_item);
	if (dir_item_no >= kini.max_dir_item) return FALSE;

	if (strcmp(path, "/") != 0) {
		end = path+strlen(path)-1;
		DPRINTK(2, "%d: %s: end=%c\n", cur_pid, cpsMethod,*end);
		while (*end == '/') {
			*end = '\0';
			end--;
		}
	} else {
		DPRINTK(2, "%d: %s: no need to trim path\n", cur_pid, cpsMethod);
	}
	DPRINTK(2, "%d: %s: trimmed path %s\n", cur_pid, cpsMethod, path);

	list_for_each_entry_safe(ip, nip, &dir_list_head, item_list) {
    #ifndef X86_64	
	DPRINTK(2, "%d: %s: ip %x, ip->path %s\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path);
    #else
	DPRINTK(2, "%d: %s: ip 0x%lx, ip->path %s\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path);
    #endif
		r = strcmp(path, ip->path);
		if (r == 0)
			return TRUE;
		else if (r > 0)
			continue;
		else
			break;
	}

	oip = (DIR_ITEM *)kmalloc(sizeof(DIR_ITEM), GFP_ATOMIC);
	if (oip == NULL) {
		WPRINTK("%d: %s: oip is NULL\n", cur_pid, cpsMethod);
		return FALSE;
	}
	oip->path = path;

	list_add_tail(&oip->item_list, &ip->item_list);
	dir_item_no++;
	list_for_each_entry_safe(ip, nip, &dir_list_head, item_list) {
		DPRINTK(2, "%d: %s: directory: %s\n", cur_pid, cpsMethod, ip->path);
	}
	DPRINTK(1,"%d: %s: get outta addDir\n", cur_pid, cpsMethod);
	return TRUE;
}

void delDirList(void)
{
	const char * cpsMethod = "delDirList";
	pid_t cur_pid = current->pid;
	DIR_ITEM    *dip, *nip;
	CP_DBG_LVL;

	DPRINTK(1,"%d: %s: get into delDirList\n", cur_pid, cpsMethod);

	list_for_each_entry_safe(dip, nip, &dir_list_head, item_list) {
		list_del(&dip->item_list);
		kfree(dip);
	}
	if (kini.dirs)
		kfree(kini.dirs);
	kini.dirs = NULL;
	INIT_LIST_HEAD(&dir_list_head);
	dir_item_no = 0;

	DPRINTK(1,"%d: %s: get outta delDirList\n", cur_pid, cpsMethod);
}

void parseAddDirs(char *dirs) 
{
	const char * cpsMethod = "parseAddDirs";
	pid_t cur_pid=0;
	char	*token;
	char	*parse_dirs = dirs;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into parseAddDirs\n", cur_pid, cpsMethod);

	delDirList();

	if (dirs == NULL) return;
	DPRINTK(2,"%d: %s: dirs %s\n", cur_pid, cpsMethod, dirs);

	token = strsep(&parse_dirs, (const char *)":");
	do {
		if (!addDir(token))
			break;
	} while ((token = strsep(&parse_dirs, (const char *)":")));

	DPRINTK(1,"%d: %s: get outta parseAddDirs\n", cur_pid, cpsMethod);
}

Boolean addExt(char *type) 
{
	const char * cpsMethod = "addExt";
	pid_t cur_pid=0;
	EXT_ITEM	*oip, *ip, *nip;
	int r;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into addExt\n", cur_pid, cpsMethod);

	if (ext_item_no >= kini.max_ext_item) return FALSE;

	list_for_each_entry_safe(ip, nip, &ext_list_head, item_list) {
		#ifndef X86_64
        DPRINTK(2, "%d: %s: ip %x, ip->type %s\n", cur_pid, cpsMethod, (unsigned int)ip, ip->type);
        #else
        DPRINTK(2, "%d: %s: ip 0x%lx, ip->type %s\n", cur_pid, cpsMethod, (unsigned long)ip, ip->type);		
        #endif
        r = strnicmp(type, ip->type, (strlen(type) > strlen(ip->type) ?
			strlen(type) : strlen(ip->type)));
		if (r == 0)
			return TRUE;
		else if (r > 0)
			continue;
		else
			break;
	}
	oip = (EXT_ITEM *)kmalloc(sizeof(EXT_ITEM), GFP_ATOMIC);
	if (oip == NULL) {
		WPRINTK("%d: %s: oip is NULL\n", cur_pid, cpsMethod);
		return FALSE;
	}
	oip->type = type;
	list_add_tail(&oip->item_list, &ip->item_list);
	ext_item_no++;
	list_for_each_entry_safe(ip, nip, &ext_list_head, item_list) {
		DPRINTK(2, "%d: %s: extension: %s\n", cur_pid, cpsMethod, ip->type);
	}
	DPRINTK(1,"%d: %s: get outta addExt\n", cur_pid, cpsMethod);
	return TRUE;
}

void delExtList(void)
{
	const char *cpsMethod = "delExtList";
	EXT_ITEM	*ip, *nip;
	pid_t cur_pid = current->pid;
	CP_DBG_LVL;

	DPRINTK(1, "%d: %s: get into delExtList\n", cur_pid, cpsMethod);

	list_for_each_entry_safe(ip, nip, &ext_list_head, item_list) {
		list_del(&ip->item_list);
		kfree(ip);
	}
	if (kini.exts)
		kfree(kini.exts);
	kini.exts = NULL;
	INIT_LIST_HEAD(&ext_list_head);
	ext_item_no = 0;
	DPRINTK(1, "%d: %s: get outta delExtList\n", cur_pid, cpsMethod);
}

void parseAddExts(char *exts) 
{
	const char * cpsMethod = "parseAddExts";
	pid_t cur_pid=0;
	char	*token;
	char	*parse_exts = exts;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into parseAddExts\n", cur_pid, cpsMethod);

	delExtList();

	if (exts == NULL) return;
	DPRINTK(2,"%d: %s: exts = [%s]\n", cur_pid, cpsMethod,exts);

	token = strsep(&parse_exts, (const char *)":");
	do {
		if (!addExt(token))
			break;
	} while ((token=strsep(&parse_exts, (const char *)":")));
	DPRINTK(1,"%d: %s: get outta parseAddExts\n", cur_pid, cpsMethod);
}

Boolean addExcDir(char *path) 
{
	const char * cpsMethod = "addExcDir";
	pid_t cur_pid=0;
	EXC_DIR_ITEM	*oip, *ip, *nip;
	struct list_head	*plist_head;
	int r;
	char * end;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into addExcDir\n", cur_pid, cpsMethod);

	if (exc_dir_item_no >= kini.max_exc_dir_item) return FALSE;

	if (strcmp(path, "/") != 0) {
		end = path+strlen(path)-1;
		DPRINTK(2, "%d: %s: end=%c\n", cur_pid, cpsMethod,*end);
		while (*end == '/') {
			*end = '\0';
			end--;
		}
	} else {
		DPRINTK(2, "%d: %s: no need to trim path\n", cur_pid, cpsMethod);
	}
	DPRINTK(2, "%d: %s: trimmed path=%s\n", cur_pid, cpsMethod, path);   

	plist_head = (*path == '/') ? &exc_dir_list_abs_head : &exc_dir_list_rel_head;

	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
#ifndef X86_64
		DPRINTK(1,"%d: %s: ip %x, ip->path %s, ip->item_list.next %x\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path, (unsigned int)ip->item_list.next);
#else
        DPRINTK(1,"%d: %s: ip 0x%lx, ip->path %s, ip->item_list.next 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path, (unsigned long)ip->item_list.next);
#endif
		r = strcmp(path, ip->path);
		if (r == 0)
			return TRUE;
		else if (r > 0)
			continue;
		else
			break;
	}
	oip = (EXC_DIR_ITEM *)kmalloc(sizeof(EXC_DIR_ITEM), GFP_ATOMIC);
	if (oip == NULL) {
		WPRINTK("%d: %s: oip is NULL\n", cur_pid, cpsMethod);
		return FALSE;
	}
	oip->path = path;
	list_add_tail(&oip->item_list, &ip->item_list);
	exc_dir_item_no++;
	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
		DPRINTK(2, "%d: %s: excluded dir: %s\n", cur_pid, cpsMethod, ip->path);
	}
	DPRINTK(1,"%d: %s: get outta addExcDir\n", cur_pid, cpsMethod);
	return TRUE;
}

void delExcDirList(void)
{
	const char * cpsMethod = "delExcDirList";
	EXC_DIR_ITEM	*ip, *nip;
	pid_t cur_pid = current->pid;
	CP_DBG_LVL;

	DPRINTK(1,"%d: %s: get into delExcDirList\n", cur_pid, cpsMethod);

	DPRINTK(1,"%d: %s: list for each entry: exc_dir_list_abs_head\n", cur_pid, cpsMethod);
	list_for_each_entry_safe(ip, nip, &exc_dir_list_abs_head, item_list) {
#ifndef X86_64
		DPRINTK(1,"%d: %s: ip %x, ip->path %s, ip->item_list.next %x\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path, (unsigned int)ip->item_list.next);
#else
        DPRINTK(1,"%d: %s: ip 0x%lx, ip->path %s, ip->item_list.next 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path, (unsigned long)ip->item_list.next);
#endif
		list_del(&ip->item_list);
		kfree(ip);
	}
	INIT_LIST_HEAD(&exc_dir_list_abs_head);

	DPRINTK(1,"%d: %s: list for each entry: exc_dir_list_rel_head\n", cur_pid, cpsMethod);
	list_for_each_entry_safe(ip, nip, &exc_dir_list_rel_head, item_list) {
#ifndef X86_64
		DPRINTK(1,"%d: %s: ip %x, ip->path %s, ip->item_list.next %x\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path, (unsigned int)ip->item_list.next);
#else
        DPRINTK(1,"%d: %s: ip 0x%lx, ip->path %s, ip->item_list.next 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path, (unsigned long)ip->item_list.next);
#endif
		list_del(&ip->item_list);
		kfree(ip);
	}
	INIT_LIST_HEAD(&exc_dir_list_rel_head);

	if (kini.exc_dirs)
		kfree(kini.exc_dirs);
	kini.exc_dirs = NULL;
	exc_dir_item_no = 0;
	DPRINTK(1,"%d: %s: get outta delExcDirList\n", cur_pid, cpsMethod);
}

void parseAddExcDirs(char *dirs) 
{
	const char * cpsMethod = "parseAddExcDirs";
	pid_t cur_pid=0;
	char	*token;
	char	*parse_dirs = dirs;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into parseAddExcDirs\n", cur_pid, cpsMethod);

	delExcDirList();

	if (dirs == NULL) return;

	token = strsep(&parse_dirs, (const char *)":");
	do {
		if (!addExcDir(token))
			break;
	} while ((token = strsep(&parse_dirs, (const char *)":")));

	DPRINTK(1,"%d: %s: get outta parseAddExcDirs\n", cur_pid, cpsMethod);
}


Boolean addExcFil(char *path) 
{
	const char * cpsMethod = "addExcFil";
	pid_t cur_pid=0;
	EXC_FIL_ITEM	*oip, *ip, *nip;
	struct list_head	*plist_head;
	int r;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into addExcFil\n", cur_pid, cpsMethod);

	if (exc_fil_item_no >= kini.max_exc_fil_item) return FALSE;

	plist_head = (*path == '/') ? &exc_fil_list_abs_head : &exc_fil_list_rel_head;
	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
#ifndef X86_64
		DPRINTK(1,"%d: %s: ip %x, ip->path %s, ip->item_list.next %x\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path, (unsigned int)ip->item_list.next);
#else
        DPRINTK(1,"%d: %s: ip 0x%lx, ip->path %s, ip->item_list.next 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path, (unsigned long)ip->item_list.next);
#endif
		r = strcmp(path, ip->path);
		if (r == 0)
			return TRUE;
		else if (r > 0)
			continue;
		else
			break;
	}

	oip = (EXC_FIL_ITEM *)kmalloc(sizeof(EXC_FIL_ITEM), GFP_ATOMIC);
	if (oip == NULL) {
		WPRINTK("%d: %s: oip is NULL\n", cur_pid, cpsMethod);
		return FALSE;
	}
	oip->path = path;
	list_add_tail(&oip->item_list, &ip->item_list);
	exc_fil_item_no++;
	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
		DPRINTK(2, "%d: %s: excluded file: %s\n", cur_pid, cpsMethod, ip->path);
	}
	DPRINTK(1,"%d: %s: get outta addExcFil\n", cur_pid, cpsMethod);
	return TRUE;
}

void delExcFilList(void)
{
	const char * cpsMethod = "delExcFilList";
	pid_t cur_pid = current->pid;
	EXC_FIL_ITEM        *ip, *nip;
	CP_DBG_LVL;

	DPRINTK(1,"%d: %s: get into delExcFilList\n", cur_pid, cpsMethod);

	DPRINTK(1,"%d: %s: list for each entry: exc_fil_list_abs_head\n", cur_pid, cpsMethod);
	list_for_each_entry_safe(ip, nip, &exc_fil_list_abs_head, item_list) {
#ifndef X86_64
		DPRINTK(1,"%d: %s: ip %x, ip->path %s, ip->item_list.next %x\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path, (unsigned int)ip->item_list.next);
#else
        DPRINTK(1,"%d: %s: ip 0x%lx, ip->path %s, ip->item_list.next 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path, (unsigned long)ip->item_list.next);
#endif
		list_del(&ip->item_list);
		kfree(ip);
	}
	INIT_LIST_HEAD(&exc_fil_list_abs_head);

	DPRINTK(1,"%d: %s: list for each entry: exc_fil_list_rel_head\n", cur_pid, cpsMethod);
	list_for_each_entry_safe(ip, nip, &exc_fil_list_rel_head, item_list) {
#ifndef X86_64
		DPRINTK(1,"%d: %s: ip %x, ip->path %s, ip->item_list.next %x\n", cur_pid, cpsMethod, (unsigned int)ip, ip->path, (unsigned int)ip->item_list.next);
#else
        DPRINTK(1,"%d: %s: ip 0x%lx, ip->path %s, ip->item_list.next 0x%lx\n", cur_pid, cpsMethod, (unsigned long)ip, ip->path, (unsigned long)ip->item_list.next);
#endif
		list_del(&ip->item_list);
		kfree(ip);
	}
	INIT_LIST_HEAD(&exc_fil_list_rel_head);

	if (kini.exc_fils)
		kfree(kini.exc_fils);
	kini.exc_fils = NULL;
	exc_fil_item_no = 0;

	DPRINTK(1,"%d: %s: get outta delExcFilList\n", cur_pid, cpsMethod);
}

void parseAddExcFils(char *fils) 
{
	const char * cpsMethod = "parseAddExcFils";
	pid_t cur_pid=0;
	char	*token;
	char	*parse_fils = fils;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into parseAddExcFils\n", cur_pid, cpsMethod);

	delExcFilList();

	if (fils == NULL) return;

	token = strsep(&parse_fils, (const char *)":");
	do {
		if (!addExcFil(token))
			break;
	} while ((token = strsep(&parse_fils, (const char *)":")));

	DPRINTK(1,"%d: %s: get outta parseAddExcFils\n", cur_pid, cpsMethod);
}

Boolean addExcExt(char *type) 
{
	const char * cpsMethod = "addExcExt";
	pid_t cur_pid=0;
	EXC_EXT_ITEM	*oip, *ip, *nip;
	int r;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into addExcExt\n", cur_pid, cpsMethod);

	if (exc_ext_item_no >= kini.max_exc_ext_item) return FALSE;

	list_for_each_entry_safe(ip, nip, &exc_ext_list_head, item_list) {
#ifndef X86_64
		DPRINTK(2,"%d: %s: ip %x, ip->type %s\n", cur_pid, cpsMethod, (unsigned int)ip, ip->type);
#else
DPRINTK(2,"%d: %s: ip 0x%lx, ip->type %s\n", cur_pid, cpsMethod, (unsigned long)ip, ip->type);
#endif
		r = strnicmp(type, ip->type, (strlen(type) > strlen(ip->type) ?
			strlen(type) : strlen(ip->type)));
		if (r == 0)
			return TRUE;
		else if (r > 0)
			continue;
		else
			break;
	}

	oip = (EXC_EXT_ITEM *)kmalloc(sizeof(EXC_EXT_ITEM), GFP_ATOMIC);
	if (oip == NULL) {
		WPRINTK("%d: %s: oip is NULL\n", cur_pid, cpsMethod);
		return FALSE;
	}
	oip->type = type;
	list_add_tail(&oip->item_list, &ip->item_list);
	exc_ext_item_no++;
	list_for_each_entry_safe(ip, nip, &exc_ext_list_head, item_list) {
		DPRINTK(2, "%d: %s: excluded extension: %s\n", cur_pid, cpsMethod, ip->type);
	}
	DPRINTK(1,"%d: %s: get outta addExcExt\n", cur_pid, cpsMethod);
	return TRUE;
}

void delExcExtList(void)
{
	const char * cpsMethod = "delExcExtList";
	pid_t cur_pid = current->pid;
	EXC_EXT_ITEM        *ip, *nip;
	CP_DBG_LVL;

	DPRINTK(1,"%d: %s: get into delExcExtList\n", cur_pid, cpsMethod);

	list_for_each_entry_safe(ip, nip, &exc_ext_list_head, item_list) {
		
#if LINUX_VERSION_CODE < 0x20612 
		list_del(&ip->item_list);
#endif		
		kfree(ip);
	}
	INIT_LIST_HEAD(&exc_ext_list_head);

	if (kini.exc_exts)
		kfree(kini.exc_exts);
	kini.exc_exts = NULL;
	exc_ext_item_no = 0;
	DPRINTK(1,"%d: %s: get outta delExcExtList\n", cur_pid, cpsMethod);
}

void parseAddExcExts(char *exts) 
{
	const char * cpsMethod = "parseAddExcExts";
	pid_t cur_pid=0;
	char	*token;
	char	*parse_exts = exts;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into parseAddExcExts\n", cur_pid, cpsMethod);

	delExcExtList();

	if (exts == NULL || exts[0] == '\0') return;

	token = strsep(&parse_exts, (const char *)":");
	do {
		if (!addExcExt(token))
			break;
	} while ((token = strsep(&parse_exts, (const char *)":")));

	DPRINTK(1,"%d: %s: get outta parseAddExcExts\n", cur_pid, cpsMethod);
}

void insertAry(pid_t *exc_pid_ary, pid_t exc_pid, int *exc_pid_no, int max_no) 
{
	const char * cpsMethod = "insertAry";
	pid_t cur_pid=0;
	int i=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into insertAry\n", cur_pid, cpsMethod);

	if (*exc_pid_no >= max_no)
		return; 

	for (i=0; i<(*exc_pid_no); i++) {
		if (exc_pid_ary[i] == exc_pid) {
			return;
		}
	}

	exc_pid_ary[*exc_pid_no] = exc_pid;
	(*exc_pid_no)++;
	DPRINTK(1,"%d: %s: inserted %d\n", cur_pid, cpsMethod, exc_pid);
	DPRINTK(1,"%d: %s: get outta insertAry\n", cur_pid, cpsMethod);
}

void deleteAry(pid_t *exc_pid_ary, pid_t cur_pgrp, int *exc_pid_no) 
{
	const char * cpsMethod = "deleteAry";
	pid_t current_pid=0;
	int	i, j;
	CP_DBG_LVL;

	current_pid = current->pid;
	DPRINTK(1,"%d: %s: get into deleteAry\n", current_pid, cpsMethod);

	DPRINTK(1,"%d: %s: try to delete pgrp = [%d]\n", current_pid, cpsMethod, cur_pgrp);
	for (i=0; i<(*exc_pid_no); i++) {
		if (exc_pid_ary[i] == cur_pgrp) {
			for (j=i; j<(*exc_pid_no-1); j++) {
				exc_pid_ary[j] = exc_pid_ary[j+1];
			}
			(*exc_pid_no)--;
			DPRINTK(1,"%d: %s: deleted %d\n", current_pid, cpsMethod, cur_pgrp);
			break;
		}
	}
	DPRINTK(1,"%d: %s: get outta deleteAry\n", current_pid, cpsMethod);
}

Boolean initialized(void)
{
	const char * cpsMethod = "initialized";
	pid_t cur_pid=0;
	CP_DBG_LVL;
	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into initialized\n", cur_pid, cpsMethod);
	
	/****** TT234414 Samir Bai 20111206 start ******/

	read_lock(&init_lock);
	if(inited !=2 ) {
		read_unlock(&init_lock);
		return FALSE;
	}
	read_lock(&kini_lock);
	if(vsapi_chldn_no == 0) {
		read_unlock(&kini_lock);
		read_unlock(&init_lock);
		return FALSE;
	}
	read_unlock(&kini_lock);
	read_unlock(&init_lock);

	/****** TT234414 Samir Bai 20111206 end ******/

	read_lock(&hook_init_lock);
	if (hook_init != HOOKED)
	{
		read_unlock(&hook_init_lock);
		return FALSE;		
	}
	read_unlock(&hook_init_lock);
	
	DPRINTK(1,"%d: %s: get outta initialized\n", cur_pid, cpsMethod);
	return TRUE;
}

Boolean addOneDenyWriteSetting(DENYWRITE_TYPE type, char *item)
{
	const char * cpsMethod = "addOneDenyWriteSetting";
	pid_t cur_pid=0;
	DENYWRITE_ITEM	*oip, *ip, *nip;
	struct list_head	*plist_head;
	int r;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into addDenyWriteSetting\n", cur_pid, cpsMethod);

	if (item == NULL || item[0] == '\0') {
		DPRINTK(2,"%d: %s: empty denywrite item. return FALSE\n", cur_pid, cpsMethod);
		return FALSE;
	}

	switch (type)
	{
	case DENYWRITE_FILE:
		DPRINTK(2,"%d: %s: Add Denywrite File [%s]\n", cur_pid, cpsMethod, item);
		plist_head = &denywrite_file_list_head;
		break;
	case DENYWRITE_DIR:
		DPRINTK(2,"%d: %s: Add Denywrite Dir [%s]\n", cur_pid, cpsMethod, item);
		plist_head = &denywrite_dir_list_head;
		break;
	case DENYWRITE_FILTER_EXT:
		DPRINTK(2,"%d: %s: Add Denywrite Filter Ext [%s]\n", cur_pid, cpsMethod, item);
		plist_head = &denywrite_filter_ext_list_head;
		break;
	default:
		DPRINTK(1,"%d: %s: get outta addDenyWriteSetting. Invalid Type\n", cur_pid, cpsMethod);
		return FALSE;
	}

	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
#ifndef X86_64
		DPRINTK(2,"%d: %s: ip [%x], ip->item [%s]\n", cur_pid, cpsMethod, (unsigned int)ip, ip->item);
#else
	DPRINTK(2,"%d: %s: ip [0x%lx], ip->item [%s]\n", cur_pid, cpsMethod, (unsigned long)ip, ip->item);
#endif
		r = strnicmp(item, ip->item, (strlen(item) > strlen(ip->item) ?
			strlen(item) : strlen(ip->item)));
		if (r == 0) {
			DPRINTK(2, "%d: %s: return TRUE\n", cur_pid, cpsMethod);
			return TRUE;
		} else if (r > 0)
			continue;
		else
			break;
	}

	oip = (DENYWRITE_ITEM *)kmalloc(sizeof(DENYWRITE_ITEM), GFP_ATOMIC);
	if (oip == NULL) {
		WPRINTK("%d: %s: oip is NULL\n", cur_pid, cpsMethod);
		return FALSE;
	}
	DPRINTK(2, "%d: %s: Add denywrite item\n", cur_pid, cpsMethod);
	oip->item = item;
	list_add_tail(&oip->item_list, &ip->item_list);

	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
		DPRINTK(2, "%d: %s: list denywrite item: %s\n", cur_pid, cpsMethod, ip->item);
	}
	DPRINTK(1,"%d: %s: get outta addOneDenyWriteSetting\n", cur_pid, cpsMethod);
	return TRUE;
}

void delDenyWriteList(DENYWRITE_TYPE type)
{
	const char *cpsMethod = "delDenyWriteList";
	DENYWRITE_ITEM	*ip, *nip;
	struct list_head	*plist_head;
	pid_t cur_pid = current->pid;
	CP_DBG_LVL;

	DPRINTK(1, "%d: %s: get into delDenyWriteList\n", cur_pid, cpsMethod);

	switch (type)
	{
	case DENYWRITE_FILE:
		plist_head = &denywrite_file_list_head;
		break;
	case DENYWRITE_DIR:
		plist_head = &denywrite_dir_list_head;
		break;
	case DENYWRITE_FILTER_EXT:
		plist_head = &denywrite_filter_ext_list_head;
		break;
	default:
		DPRINTK(1,"%d: %s: get outta delDenyWriteList. Invalid Type\n", cur_pid, cpsMethod);
		return;
	}


	list_for_each_entry_safe(ip, nip, plist_head, item_list) {
		list_del(&ip->item_list);
		kfree(ip);
	}
	INIT_LIST_HEAD(plist_head);

	DPRINTK(1, "%d: %s: get outta delDenyWriteList\n", cur_pid, cpsMethod);
}

void parseSetDenyWriteSettings(DENYWRITE_TYPE type, char * settings) 
{
	const char * cpsMethod = "parseSetDenyWriteSettings";
	pid_t cur_pid=0;
	char	*token;
	char	*denywrite_settings = settings;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into parseSetDenyWriteSettings\n", cur_pid, cpsMethod);

	delDenyWriteList(type);

	if (settings == NULL || settings[0] == '\0') {
		DPRINTK(2,"%d: %s: empty denywrite settings, return.\n", cur_pid, cpsMethod);
		return;
	}
	DPRINTK(2,"%d: %s: denywrite settings = [%s]\n", cur_pid, cpsMethod, settings);

	token = strsep(&denywrite_settings, (const char *)":");
	do {
		if (!addOneDenyWriteSetting(type, token))
			break;
	} while ((token=strsep(&denywrite_settings, (const char *)":")));
	DPRINTK(1,"%d: %s: get outta parseSetDenyWriteSettings\n", cur_pid, cpsMethod);
}

char * strtoupper(char * str)
{
	char *s;

	for (s = str; *s != '\0'; s++)
		*s = toupper(*s);
	return str;
}

Boolean inDenyWriteFile(struct dentry * dentry, struct vfsmount * mnt)
{
	const char * cpsMethod = "inDenyWriteFile";
	pid_t cur_pid=0;
	DENYWRITE_ITEM	*ip, *nip;
	const unsigned char *basename;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1, "%d: %s: get into inDenyWriteFile\n", cur_pid, cpsMethod);

	basename = dentry->d_name.name;
	DPRINTK(2, "%d: %s: basename=%s\n", cur_pid, cpsMethod, basename);
	list_for_each_entry_safe(ip, nip, &denywrite_file_list_head, item_list) {
		// case insensitive match
		DPRINTK(2, "%d: %s: item=%s\n", cur_pid, cpsMethod, basename);
		if (strnicmp(basename, ip->item, (strlen(basename) > strlen(ip->item) ?
			strlen(basename) : strlen(ip->item))) == 0) {
				DPRINTK(2, "%d: %s: return TRUE\n", cur_pid, cpsMethod);
				return TRUE;
			}
	}

	DPRINTK(1, "%d: %s: get outta inDenyWriteFile\n", cur_pid, cpsMethod);
	return FALSE;    
}

Boolean inDenyWriteDir(struct dentry * dentry, struct vfsmount * mnt)
{
	const char * cpsMethod = "inDenyWriteDir";
	pid_t cur_pid=0;
	int ret = FALSE;
	DENYWRITE_ITEM    *ip, *nip;
	DENYWRITE_ITEM    *dp, *ndp;
	char *tmp=NULL, *extension=NULL;
	const unsigned char *basedir, *basename;
	char	*dq = "\"\"";
#if LINUX_VERSION_CODE >= 0x30000
	struct path pPath;
#else
	struct nameidata nd;
#endif
    unsigned int flags;
	int error=1;
    CP_DBG_LVL;
#if LINUX_VERSION_CODE <= 0x20612
	flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY | LOOKUP_NOALT;
#else
	flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
#endif
	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into inDenyWriteDir\n", cur_pid, cpsMethod);

	basedir = dentry->d_parent->d_name.name;
	basename = dentry->d_name.name;
	tmp = strrchr(basename, '.');
	if (tmp) tmp++;
	if (!tmp || tmp == '\0') {
		DPRINTK(2, "%d: %s: File has no extension. Set to \"\"\n", cur_pid, cpsMethod);
		extension = dq;
	} else {
        int len = strlen(tmp);
		extension = kmalloc(len + 1, GFP_ATOMIC);
		strncpy(extension, tmp, len + 1);
		extension = strtoupper(extension);
	}
	DPRINTK(2, "%d: %s: basedir=%s\n", cur_pid, cpsMethod, basedir);
	DPRINTK(2, "%d: %s: basename=%s\n", cur_pid, cpsMethod, basename);
	DPRINTK(2, "%d: %s: extension=%s\n", cur_pid, cpsMethod, extension);
	list_for_each_entry_safe(ip, nip, &denywrite_dir_list_head, item_list) {
		DPRINTK(2, "%d: %s: ip->item=%s\n", cur_pid, cpsMethod, ip->item);
		if (ip->item[0] == '/') {
			/* absolute */
			read_unlock(&denywrite_list_head_lock);
#if LINUX_VERSION_CODE >= 0x30000
			error = kern_path(ip->item, flags, &pPath);
#elif LINUX_VERSION_CODE >= 0x20600
			error = PATH_LOOKUP(ip->item, flags, &nd);
#else
			error = PATH_LOOKUP(ip->item, flags | LOOKUP_POSITIVE, &nd);
#endif
			read_lock(&denywrite_list_head_lock);
			if (error) {
				DPRINTK(2, "%d: %s: path_lookup error\n", cur_pid, cpsMethod);
				continue;
			}
#if LINUX_VERSION_CODE >= 0x30000
			if (dentry->d_parent == pPath.dentry) {
#else
			if (dentry->d_parent == nd.DENTRY) {
#endif
				DPRINTK(2, "%d: %s: Continue with filter ext comparison.\n", 
					cur_pid, cpsMethod);
				if (list_empty(&denywrite_filter_ext_list_head)) {
					DPRINTK(2, "%d: %s: Filter ext list is empty. Return TRUE.\n", 
						cur_pid, cpsMethod);
					read_unlock(&denywrite_list_head_lock);
#if LINUX_VERSION_CODE >= 0x30000
					path_put(&pPath);
#else
					SPLX_PATH_RELEASE(&nd);
#endif
					read_lock(&denywrite_list_head_lock);
					ret = TRUE;
					goto out;
				} else {
					DPRINTK(2, "%d: %s: Filter ext list not empty\n", cur_pid, cpsMethod);
					list_for_each_entry_safe(dp, ndp, &denywrite_filter_ext_list_head, item_list) {
						DPRINTK(2, "%d: %s: dp->item=%s\n", cur_pid, cpsMethod, dp->item);
						if (fnmatch(dp->item, extension, FNM_PATHNAME) != FNM_NOMATCH) {
							DPRINTK(2, "%d: %s: In Filter ext. Return TRUE\n",
								cur_pid, cpsMethod);
							read_unlock(&denywrite_list_head_lock);
#if LINUX_VERSION_CODE >= 0x30000
							path_put(&pPath);
#else
							SPLX_PATH_RELEASE(&nd);
#endif
							read_lock(&denywrite_list_head_lock);
							ret = TRUE;
							goto out;
						}
					}
				}
			}
			read_unlock(&denywrite_list_head_lock);
#if LINUX_VERSION_CODE >= 0x30000
			path_put(&pPath);
#else
			SPLX_PATH_RELEASE(&nd);
#endif
			read_lock(&denywrite_list_head_lock);
		} else {
			/* relative */
			if (strnicmp(basedir, ip->item, 
				(strlen(basedir) > strlen(ip->item) ? strlen(basedir) : strlen(ip->item))) == 0) 
			{
				if (list_empty(&denywrite_filter_ext_list_head)) {
					DPRINTK(2, "%d: %s: Filter ext is empty. Return TRUE.\n", 
						cur_pid, cpsMethod);
					ret = TRUE;
					goto out;
				} else {
					DPRINTK(2, "%d: %s: Filter ext list not empty\n", cur_pid, cpsMethod);
					list_for_each_entry_safe(dp, ndp, &denywrite_filter_ext_list_head, item_list) {
						DPRINTK(2, "%d: %s: dp->item=%s\n", cur_pid, cpsMethod, dp->item);
						if (fnmatch(dp->item, extension, FNM_PATHNAME) != FNM_NOMATCH) {
							DPRINTK(2, "%d: %s: In Filter ext. Return TRUE\n",
								cur_pid, cpsMethod);
							ret = TRUE;
							goto out;
						}
					}
				}
			}
		}
	}

out:
	DPRINTK(1, "%d: %s: get outta inDenyWriteDir\n", cur_pid, cpsMethod);
	if (strcmp(extension, dq) != 0) kfree(extension);
	return ret;
}

Boolean needToDenyWrite(struct dentry * dentry, struct vfsmount * mnt, 
						int flags, ino_t inode) 
{
	const char * cpsMethod = "needToDenyWrite";
	pid_t cur_pid=0;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into needToDenyWrite\n", cur_pid, cpsMethod);

	if (!list_empty(&denywrite_dir_list_head) && inDenyWriteDir(dentry, mnt)) {
		DPRINTK(2, "%d: %s: In Denywrite dir list. Return TRUE\n", 
			cur_pid, cpsMethod);
		return TRUE;
	}

	if (!list_empty(&denywrite_file_list_head) && inDenyWriteFile(dentry, mnt)) {
		DPRINTK(2, "%d: %s: In Denywrite file list. Return TRUE\n", 
			cur_pid, cpsMethod);
		return TRUE;
	}

	DPRINTK(1, "%d: %s: get outta needToDenyWrite\n", cur_pid, cpsMethod);
	return FALSE;
}

long open_file(struct dentry * dentry, struct vfsmount * mnt, int flags)
{
	const char * cpsMethod = "open_file";
	pid_t cur_pid=0;
	int fd, error;
	struct dentry * ldentry;
	struct vfsmount * lmnt;
	CP_DBG_LVL;

	cur_pid = current->pid;
	DPRINTK(1,"%d: %s: get into open_file\n", cur_pid, cpsMethod);
#if BITS_PER_LONG != 32
	flags |= O_LARGEFILE;
#endif
	fd = get_unused_fd();
	if (fd >= 0) {
		struct file *f;
		lmnt = mntget(mnt);
		ldentry = dget(dentry);
#if LINUX_VERSION_CODE >= 0x20620
		f = dentry_open(ldentry, lmnt, flags, current->cred);
#else
        f = dentry_open(ldentry, lmnt, flags);
#endif
		error = PTR_ERR(f);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = error;
			goto out;
		}
		fd_install(fd, f);
	}
out:
	DPRINTK(1,"%d: %s: get outta open_file\n", cur_pid, cpsMethod);
	return fd;
}

