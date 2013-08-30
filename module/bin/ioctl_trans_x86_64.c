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


#include <linux/compat.h>
#include	<linux/types.h>


typedef struct {
    unsigned int	dist;                 /* RedHat, SuSE, Miracle, etc */
    unsigned int 	platform;             /* AMD/Intel/s390 UP/SMP */
    signed int        interface_version;    
    signed int         release;
} KHM_INFO_32;

typedef struct {
	/* user settings */
        signed int 	incoming;
        signed int  outgoing;
        signed int  running;
        unsigned int dirs;
        unsigned int exts;
        unsigned int exc_dirs;
         unsigned int exc_fils;
         unsigned int exc_exts;
	/* internal settings */
	signed int	 debug_level;
	signed int	 max_cache_item;
	signed int	 max_list_item;
	signed int	 max_dir_item;
	signed int max_ext_item;
	signed int	 max_exc_dir_item;
	signed int	 max_exc_fil_item;
	signed int	 max_exc_ext_item;
	signed int	 waitq_timeout;
	signed int	 vsapi_timeout;
	signed int	 max_exc_pid;
	signed int	 max_vsc_pid;
	signed int	 max_path_len;
	signed int	 max_cmd_len;
} INIT_ARGS_32;

typedef struct {
		unsigned int  full_pn;       /* in: full path name   */
		unsigned int  comm;          /* in: command name     */
		compat_pid_t   comm_pid;       /* in: command PID      */
		compat_uid_t   comm_uid;       /* in: command UID      */
		compat_off_t  size;           /* in: file size        */
		compat_mode_t  mode;           /* in: open mode        */
		signed int	     flags;          /* in: open flags       */
		compat_ino_t   inode;          /* in: file inode       */
		signed int	     fd;             /* in: file descriptor  */
		signed int		dir_fd;		/* in: dir descriptor	*/
		compat_pid_t   vsapi_chld_pid; /* out: VSAPI chld PID  */
		signed int	     vsapi_ret;      /* out: virus scan return	*/
		signed int	     action;         /* out: the last action taken	*/
		 unsigned int u_lip;
        	unsigned int d_lip;	/* kernel module use only */
} SCAN_ARGS_32;


typedef struct {
   unsigned int info;
} DENYWRITE_32;


//2010-9.28  compat_ioctl

typedef struct {
    unsigned int info;
} COMMEXCS_32;

typedef struct {
    unsigned int info;
}FIRSTITEM_32;

#define		SIOCSETINIFIL_32	_IOW(MAGIC, 0, INIT_ARGS_32)
#define		SIOCGETNXTFIL_32	_IOWR(MAGIC, 1, SCAN_ARGS_32)
//#define		SIOCPUTEXCPID	_IOW(MAGIC, 2, pid_t)
//#define		SIOCPUTVSCPID	_IOW(MAGIC, 3, pid_t)
#define		SIOCPUTLSTRES_32	_IOW(MAGIC, 4, SCAN_ARGS_32)
#define		SIOCGETKHMINFO_32	_IOW(MAGIC, 5, KHM_INFO_32)
#define		SIOCADDONEDENYWRITEFILE_32		_IOW(MAGIC, 6, DENYWRITE_32)
#define		SIOCSETDENYACCESSFILELIST_32	_IOW(MAGIC, 7, DENYWRITE_32)
#define		SIOCADDONEDENYWRITEDIR_32		_IOW(MAGIC, 8, DENYWRITE_32)
#define		SIOCSETDENYACCESSDIRLIST_32	_IOW(MAGIC, 9, DENYWRITE_32)
#define		SIOCSETFILTEREXTINDENYACCESSDIR_32 _IOW(MAGIC, 10, DENYWRITE_32)
#define		SIOCSETEXCEPTIONEXTENSION_32	_IOW(MAGIC, 11, DENYWRITE_32)
//Add by errik 2010-9.28

//Set command exclusion list
#define     SIOCSETCOMMEXCLUSION_32 _IOW(MAGIC, 15, COMMEXCS_32) //Add by errik - 2010 9.24
#define     SIOCGETFIRSTITEM_32     _IOW(MAGIC, 13, FIRSTITEM_32)
//Add end
//#define		SIOCCONTINUECWD	_IOW(MAGIC, 12, int)

#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCSETINIFIL(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCSETINIFIL(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	INIT_ARGS_32 args32;
	INIT_ARGS args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif

	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;

	args.debug_level = args32.debug_level;
	args.dirs             = compat_ptr(args32.dirs);
	args.exc_dirs		=compat_ptr(args32.exc_dirs);
	args.exc_exts		= compat_ptr(args32.exc_exts);
	args.exc_fils		= compat_ptr(args32.exc_fils);
	args.exts			= compat_ptr(args32.exts);
	args.incoming		= args32.incoming;
	args.max_cache_item	= args32.max_cache_item;
	args.max_cmd_len		= args32.max_cmd_len;
	args.max_dir_item		= args32.max_dir_item;
	args.max_exc_dir_item	= args32.max_exc_dir_item;
	args.max_exc_ext_item = args32.max_exc_ext_item;
	args.max_exc_fil_item	= args32.max_exc_fil_item;
	args.max_exc_pid	= args32.max_exc_pid;
	args.max_ext_item =args32.max_ext_item;
	args.max_list_item = args32.max_list_item;
	args.max_path_len =  args32.max_path_len;
	args.max_vsc_pid = args32.max_vsc_pid;
	args.outgoing = args32.outgoing;
	args.running = args32.running;
	args.vsapi_timeout = args32.vsapi_timeout;
	args.waitq_timeout = args32.waitq_timeout;


	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCSETINIFIL, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCSETINIFIL, (unsigned long)&args);
#endif
	set_fs(old_fs);

	return ret;
}


#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCGETNXTFIL(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCGETNXTFIL(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif		
{
	SCAN_ARGS_32 args32;
	SCAN_ARGS_32 * p_arg;
	SCAN_ARGS args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;

	 p_arg = (SCAN_ARGS_32 *)arg;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif

	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;

	args.action	= args32.action;
	args.comm	= compat_ptr(args32.comm);
	args.comm_pid = args32.comm_pid;
	args.comm_uid = args32.comm_uid;
	args.dir_fd	= args32.dir_fd;
	args.fd		= args32.fd;
	args.flags	= args32.flags;
	args.full_pn 	= compat_ptr(args32.full_pn);

	args.inode	= args32.inode;
	DPRINTK(3, "before handle_SIOCGETNXTFIL: scan.u_lip = 0x%x\n", args32.u_lip);
	DPRINTK(3, "before handle_SIOCGETNXTFIL: scan.d_lip = 0x%x\n", args32.d_lip);
	args.u_lip = args32.u_lip;
	args.d_lip = args32.d_lip;
	args.mode	= args32.mode;
	args.size		= args32.size;
	args.vsapi_chld_pid	= args32.vsapi_chld_pid;
	args.vsapi_ret			= args32.vsapi_ret;


	
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCGETNXTFIL, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCGETNXTFIL, (unsigned long)&args);
#endif
	set_fs(old_fs);

	if (!ret) {
		
		__put_user(args.vsapi_ret,
			(int *)&(p_arg->vsapi_ret));

		__put_user(args.comm_pid,
			(compat_pid_t *)&(p_arg->comm_pid));
		

		__put_user(args.comm_uid,
			(compat_uid_t *)&(p_arg->comm_uid));
	
		__put_user(args.size, (compat_off_t  *)&(p_arg->size));
	
		__put_user(args.mode, (compat_mode_t  *)&(p_arg->mode));
		__put_user(args.flags, (int *)&(p_arg->flags));
		__put_user(args.inode, (compat_ino_t  *)&(p_arg->inode));
		__put_user(args.u_lip, (unsigned int *)&(p_arg->u_lip));
	        __put_user(args.d_lip, (unsigned int *)&(p_arg->d_lip));
		__put_user((int)args.fd, (int*)&(p_arg->fd));
		__put_user((int)args.dir_fd, (int*)&(p_arg->dir_fd));
	}
	return ret;
}



//#define		SIOCPUTLSTRES_32	_IOW(MAGIC, 4, SCAN_ARGS_32)


#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCPUTLSTRES(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCPUTLSTRES(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	SCAN_ARGS_32 args32;
	SCAN_ARGS args;
	SCAN_ARGS_32 * p_arg;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;

	 p_arg = (SCAN_ARGS_32 *)arg;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif

	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.action	= args32.action;
	args.comm	= compat_ptr(args32.comm);
	args.comm_pid = args32.comm_pid;
	args.comm_uid = args32.comm_uid;
	args.dir_fd	= args32.dir_fd;
	args.fd		= args32.fd;
	args.flags	= args32.flags;
	args.full_pn 	= compat_ptr(args32.full_pn);
	args.inode	= args32.inode;
	args.u_lip = args32.u_lip;
	args.d_lip = args32.d_lip;
	args.mode	= args32.mode;
	args.size		= args32.size;
	args.vsapi_chld_pid	= args32.vsapi_chld_pid;
	args.vsapi_ret			= args32.vsapi_ret;
	

	
	old_fs = get_fs();
	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCPUTLSTRES, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCPUTLSTRES, (unsigned long)&args);
#endif

	set_fs(old_fs);

	if (!ret) {
		
	
		__put_user(args.vsapi_ret,
			(int *)&(p_arg->vsapi_ret));

		__put_user(args.comm_pid,
			(compat_pid_t *)&(p_arg->comm_pid));
		

		__put_user(args.comm_uid,
			(compat_uid_t *)&(p_arg->comm_uid));
	
		__put_user(args.size, (compat_off_t  *)&(p_arg->size));
	
		__put_user(args.mode, (compat_mode_t  *)&(p_arg->mode));
		__put_user(args.flags, (int *)&(p_arg->flags));
		__put_user(args.inode, (compat_ino_t  *)&(p_arg->inode));
		__put_user(args.u_lip, (unsigned int *)&(p_arg->u_lip));
		__put_user(args.d_lip, (unsigned int *)&(p_arg->d_lip));
		__put_user((int)args.fd, (int*)&(p_arg->fd));
		__put_user((int)args.dir_fd, (unsigned long *)&(p_arg->dir_fd));

	}



	return ret;
}




//#define		SIOCGETKHMINFO_32	_IOW(MAGIC, 5, KHM_INFO_32)


#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCGETKHMINFO(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCGETKHMINFO(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	KHM_INFO_32 args32;
	KHM_INFO args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.dist = compat_ptr(args32.dist);
	args.interface_version = args32.interface_version;
	args.platform =compat_ptr(args32.platform);
	args.release = args32.release;


	old_fs = get_fs();
	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCGETKHMINFO, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCGETKHMINFO, (unsigned long)&args);
#endif

	set_fs(old_fs);

	return ret;
}


//#define		SIOCADDONEDENYWRITEFILE_32		_IOW(MAGIC, 6, DENYWRITE_32)

#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCADDONEDENYWRITEFILE(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCADDONEDENYWRITEFILE(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	DENYWRITE_32 args32;
	DENYWRITE args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.info	= compat_ptr(args32.info);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCADDONEDENYWRITEFILE, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCADDONEDENYWRITEFILE, (unsigned long)&args);
#endif	
	set_fs(old_fs);

	return ret;
}



//#define		SIOCSETDENYACCESSFILELIST_32	_IOW(MAGIC, 7, DENYWRITE_32)

#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCSETDENYACCESSFILELIST(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCSETDENYACCESSFILELIST(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	DENYWRITE_32 args32;
	DENYWRITE args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.info	= compat_ptr(args32.info);


	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCSETDENYACCESSFILELIST, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCSETDENYACCESSFILELIST, (unsigned long)&args);
#endif	
	set_fs(old_fs);

	return ret;
}


//#define		SIOCADDONEDENYWRITEDIR_32		_IOW(MAGIC, 8, DENYWRITE_32)
#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCADDONEDENYWRITEDIR(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCADDONEDENYWRITEDIR(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	DENYWRITE_32 args32;
	DENYWRITE args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.info	= compat_ptr(args32.info);


	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCADDONEDENYWRITEDIR, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCADDONEDENYWRITEDIR, (unsigned long)&args);
#endif
	set_fs(old_fs);

	return ret;
}



//#define		SIOCSETDENYACCESSDIRLIST_32	_IOW(MAGIC, 9, DENYWRITE_32)

#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCSETDENYACCESSDIRLIST(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCSETDENYACCESSDIRLIST(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	DENYWRITE_32 args32;
	DENYWRITE args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.info	= compat_ptr(args32.info);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCSETDENYACCESSDIRLIST, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCSETDENYACCESSDIRLIST, (unsigned long)&args);
#endif
	set_fs(old_fs);

	return ret;
}

//#define		SIOCSETFILTEREXTINDENYACCESSDIR_32 _IOW(MAGIC, 10, DENYWRITE_32)
#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCSETFILTEREXTINDENYACCESSDIR(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCSETFILTEREXTINDENYACCESSDIR(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	DENYWRITE_32 args32;
	DENYWRITE args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif

	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.info	= compat_ptr(args32.info);


	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCSETFILTEREXTINDENYACCESSDIR, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCSETFILTEREXTINDENYACCESSDIR, (unsigned long)&args);
#endif

	set_fs(old_fs);

	return ret;
}

//#define		SIOCSETEXCEPTIONEXTENSION_32	_IOW(MAGIC, 11, DENYWRITE_32)
#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCSETEXCEPTIONEXTENSION(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCSETEXCEPTIONEXTENSION(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	DENYWRITE_32 args32;
	DENYWRITE args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;


	args.info	= compat_ptr(args32.info);


	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCSETEXCEPTIONEXTENSION, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCSETEXCEPTIONEXTENSION, (unsigned long)&args);
#endif

	set_fs(old_fs);

	return ret;
}

//Errik Add 2010-9-29
//Compat IOCTL for set command exclusion list

#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCSETCOMMEXCLUSION(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCSETCOMMEXCLUSION(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	COMMEXCS_32 args32;
	COMMEXCS args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;

	args.info	= compat_ptr(args32.info);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCSETCOMMEXCLUSION, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCSETCOMMEXCLUSION, (unsigned long)&args);
#endif	
	set_fs(old_fs);

	return ret;
}


#if LINUX_VERSION_CODE >= 0x20610
static int handle_SIOCGETFIRSTITEM(struct file *file, unsigned int cmd, unsigned long arg)
#else
static int handle_SIOCGETFIRSTITEM(unsigned int fd, unsigned int cmd, unsigned long arg,struct file *file)
#endif
{
	FIRSTITEM_32 args32;
	FIRSTITEM args;
	mm_segment_t old_fs;
	int ret;
	CP_DBG_LVL;
		
#if LINUX_VERSION_CODE >= 0x20610
	if (file->f_op->unlocked_ioctl != ioctlMod)
		return -EFAULT;
#else	
	if (file->f_op->ioctl != ioctlMod)
		return -EFAULT;
#endif


	if (copy_from_user(&args32, (void __user *)arg, sizeof(args32)))
		return -EFAULT;

	args.info	= compat_ptr(args32.info);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= 0x20610
	ret = ioctlMod(file,SIOCGETFIRSTITEM, (unsigned long)&args);
#else
	ret = ioctlMod(file->f_dentry->d_inode, file,SIOCGETFIRSTITEM, (unsigned long)&args);
#endif	
	set_fs(old_fs);

	return ret;
}

//End


#if LINUX_VERSION_CODE >= 0x20610
long splxmod_compat_ioctl(struct file *file, unsigned int cmd,unsigned long arg)
{
		pid_t cur_pid=0;
		const char * cpsMethod = "splxmod_compat_ioctl";
		CP_DBG_LVL;
		cur_pid = current->pid;
		DPRINTK(1,"%d: %s: get into ioctlMod\n", cur_pid, cpsMethod);
	
		switch (cmd) {
		case SIOCSETINIFIL_32:
			return handle_SIOCSETINIFIL(file, cmd, arg);
		case SIOCGETNXTFIL_32:
			return handle_SIOCGETNXTFIL(file, cmd, arg);
		case SIOCPUTEXCPID:
		case SIOCPUTVSCPID:
		case SIOCCONTINUECWD:
        case SIOCGETKHMVERSION:
        case SIOCCLEARKHMLIST:
			return ioctlMod(file, cmd, arg);
        case SIOCGETFIRSTITEM_32:
            return handle_SIOCGETFIRSTITEM(file, cmd, arg);
        case SIOCSETCOMMEXCLUSION_32:
            return handle_SIOCSETCOMMEXCLUSION(file, cmd, arg);
		case SIOCPUTLSTRES_32:		
			return handle_SIOCPUTLSTRES(file, cmd, arg);
		case SIOCGETKHMINFO_32:
			return handle_SIOCGETKHMINFO(file, cmd, arg);
		case SIOCADDONEDENYWRITEFILE_32:
			return handle_SIOCADDONEDENYWRITEFILE(file, cmd, arg);		
		case SIOCSETDENYACCESSFILELIST_32:
			return handle_SIOCSETDENYACCESSFILELIST(file, cmd, arg);
		case SIOCADDONEDENYWRITEDIR_32:
			return handle_SIOCADDONEDENYWRITEDIR(file, cmd, arg);
		case SIOCSETDENYACCESSDIRLIST_32:
			return handle_SIOCSETDENYACCESSDIRLIST(file, cmd, arg);
		case SIOCSETFILTEREXTINDENYACCESSDIR_32:
			return handle_SIOCSETFILTEREXTINDENYACCESSDIR(file, cmd, arg);		
		case SIOCSETEXCEPTIONEXTENSION_32:
			return handle_SIOCSETEXCEPTIONEXTENSION(file, cmd, arg);		
		default:
			DPRINTK(1,"%d: %s: get outta ioctlMod\n", cur_pid, cpsMethod);
			return -EINVAL;
		}

}
#endif

