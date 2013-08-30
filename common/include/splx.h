/* Kernel Hook Module for Trend Micro ServerProtect for Linux  */
/* Copyright (C) 2007 Trend Micro Incorporated.                */

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

#ifndef SPLX_H
#define SPLX_H 1

/* splx.h is used by both VSAPI app and kernel hook module */

#ifdef	__KERNEL__
#include	<linux/types.h>
#include	<linux/list.h>
#else
#include	<sys/types.h>
#endif

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

/* virus scan return */
#define NO_VIRUS	0
#define VIRUS_FOUND	1

/* The last action taken when virus found */
#define	CLEAN		0
#define	DELETE		1
#define	MOVE		2
#define	RENAME		3
#define	DENYACCESS	4
#define	BYPASS		5

/* splxdev ioctl commands */
#define		MAGIC		'S'
#define		SIOCSETINIFIL	_IOW(MAGIC, 0, INIT_ARGS)
#define		SIOCGETNXTFIL	_IOWR(MAGIC, 1, SCAN_ARGS)
#define		SIOCPUTEXCPID	_IOW(MAGIC, 2, pid_t)
#define		SIOCPUTVSCPID	_IOW(MAGIC, 3, pid_t)
#define		SIOCPUTLSTRES	_IOW(MAGIC, 4, SCAN_ARGS)
#define		SIOCGETKHMINFO	_IOW(MAGIC, 5, KHM_INFO)
#define		SIOCADDONEDENYWRITEFILE		_IOW(MAGIC, 6, DENYWRITE)
#define		SIOCSETDENYACCESSFILELIST	_IOW(MAGIC, 7, DENYWRITE)
#define		SIOCADDONEDENYWRITEDIR		_IOW(MAGIC, 8, DENYWRITE)
#define		SIOCSETDENYACCESSDIRLIST	_IOW(MAGIC, 9, DENYWRITE)
#define		SIOCSETFILTEREXTINDENYACCESSDIR _IOW(MAGIC, 10, DENYWRITE)
#define		SIOCSETEXCEPTIONEXTENSION	_IOW(MAGIC, 11, DENYWRITE)
#define		SIOCCONTINUECWD	_IOW(MAGIC, 12, int)
#define     SIOCGETFIRSTITEM    _IOW(MAGIC, 13, FIRSTITEM) //Added by Serena Dong -2010 9.6
#define     SIOCGETKHMVERSION   _IOW(MAGIC, 14, unsigned int)  //Add by errik - 2010 9.11         
#define     SIOCSETCOMMEXCLUSION _IOW(MAGIC, 15, COMMEXCS) //Add by errik - 2010 9.24
//Clear the scanning list and waiting list
#define     SIOCCLEARKHMLIST     _IOW(MAGIC, 16, unsigned int)

typedef struct {
        char    *full_pn;       /* in: full path name   */
        char    *comm;          /* in: command name     */
        pid_t   comm_pid;       /* in: command PID      */
        uid_t   comm_uid;       /* in: command UID      */
        off_t   size;           /* in: file size        */
        mode_t  mode;           /* in: open mode        */
        int     flags;          /* in: open flags       */
        ino_t   inode;          /* in: file inode       */
        int     fd;             /* in: file descriptor  */
	int	dir_fd;		/* in: dir descriptor	*/
        pid_t   vsapi_chld_pid; /* out: VSAPI chld PID  */
        int     vsapi_ret;      /* out: virus scan return	*/
        int     action;         /* out: the last action taken	*/
#ifdef __SPLX_X86_64
        unsigned int u_lip;
        unsigned int d_lip;
#else
	void	*lip;		/* kernel module use only */
#endif
} SCAN_ARGS;


typedef	int	Boolean;


#ifdef __KERNEL__
typedef struct dir_item {
        char            *path;
	struct list_head item_list;
} DIR_ITEM;

typedef struct exc_comm_item {
        char                 *comm;
        struct list_head     item_list;
} EXC_COMM_ITEM;

typedef struct ext_item {
        char            *type;
        struct list_head item_list;
} EXT_ITEM;

typedef struct exc_dir_item {
        char                 *path;
        struct list_head     item_list;
} EXC_DIR_ITEM;

typedef struct exc_fil_item {
        char                 *path;
        struct list_head     item_list;
} EXC_FIL_ITEM;

typedef struct exc_ext_item {
        char                 *type;
        struct list_head     item_list;
} EXC_EXT_ITEM;

typedef enum denywrite_type {DENYWRITE_FILE, DENYWRITE_DIR, DENYWRITE_FILTER_EXT} DENYWRITE_TYPE;

typedef struct denywrite_item {
        char		     *item;
        struct list_head     item_list;
} DENYWRITE_ITEM;

#endif

/* default values for user settings */
//[2010-3]: Only hooked configured sys-ops, so set the default to TRUE, then the make
//test will pass.
#define	INCOMING_DEF	TRUE
#define	OUTGOING_DEF	TRUE
#define	RUNNING_DEF	TRUE
#define	DIRS_DEF	NULL
#define	EXTS_DEF	"BIN:COM:DOC:DOT:DRV:EXE:SYS:XLS:XLA:XLT:VBS:JS:HTML:HTM:CLA:CLASS:SCR:MDB:PPT:POT:DLL:OCX:OVL"
#define	EXC_DIRS_DEF	"/dev:/proc:/var/spool/mail:/var/mail:/var/spool/mqueue:/var/spool/mqueue.iscan:/opt/TrendMicro/SProtectLinux/SPLX.Quarantine:/opt/TrendMicro/SProtectLinux/SPLX.Backup"
#define	EXC_FILS_DEF	NULL
#define	EXC_EXTS_DEF	NULL
/* default values for internal settings */
#define DEBUG_LEVEL_DEF		0
#define MAX_CACHE_ITEM_DEF	96
#define MAX_LIST_ITEM_DEF       2147483647
#define MAX_DIR_ITEM_DEF        30
#define MAX_EXT_ITEM_DEF        200
#define MAX_EXC_DIR_ITEM_DEF    30
#define MAX_EXC_FIL_ITEM_DEF    30
#define MAX_EXC_EXT_ITEM_DEF    30
#define WAITQ_TIMEOUT_DEF	0
#define VSAPI_TIMEOUT_DEF	0
#define MAX_EXC_PID_DEF		60
#define MAX_VSC_PID_DEF		50
#define	MAX_PATH_LEN_DEF	1023
#define	MAX_CMD_LEN_DEF		1024

typedef struct {
	/* user settings */
        Boolean	incoming;
        Boolean outgoing;
        Boolean running;
        char    *dirs;
        char    *exts;
        char    *exc_dirs;
        char    *exc_fils;
        char    *exc_exts;
	/* internal settings */
	int	debug_level;
	int	max_cache_item;
	int	max_list_item;
	int	max_dir_item;
	int	max_ext_item;
	int	max_exc_dir_item;
	int	max_exc_fil_item;
	int	max_exc_ext_item;
	int	waitq_timeout;
	int	vsapi_timeout;
	int	max_exc_pid;
	int	max_vsc_pid;
	int	max_path_len;
	int	max_cmd_len;
} INIT_ARGS;

typedef struct {
    char       *dist;                 /* RedHat, SuSE, Miracle, etc */
    char       *platform;             /* AMD/Intel/s390 UP/SMP */
    int        interface_version;
    int        release;
} KHM_INFO;

typedef struct {
    char * info;
} DENYWRITE;

//Add by errik  -- command exclusion list
typedef struct {
    char * info;
} COMMEXCS;
typedef struct {
    char * info;
}FIRSTITEM;

//TT195706
//In KHM 3.0.0.0005 we add support for realtime scan exclusion commands
//Never modify this value because it's the least version of KHM to support the feature
#define LEAST_VERSION 3005

//Add by errik  -- flags to record if the hook is enabled

typedef struct {
    int open_hooked;
    int close_hooked;
    int execve_hooked;
}HOOK_FLAGS;

#endif
