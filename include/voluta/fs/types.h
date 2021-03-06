/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of voluta.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
 *
 * Voluta is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Voluta is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef VOLUTA_TYPES_H_
#define VOLUTA_TYPES_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <uuid/uuid.h>
#include <gcrypt.h>
#include <iconv.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include <voluta/infra.h>
#include <voluta/defs.h>


/* standard types forward declarations */
struct stat;
struct statx;
struct ucred;
struct timespec;

/* types forward declarations */
struct voluta_list_head;
struct voluta_listq;
struct voluta_avl;
struct voluta_avl_node;
struct voluta_thread;
struct voluta_mutex;
struct voluta_qalloc;
struct voluta_cache;
struct voluta_znode_info;
struct voluta_unode_info;
struct voluta_vnode_info;
struct voluta_inode_info;
struct voluta_fuseq;
struct voluta_fuseq_worker;
struct voluta_fuseq_in;
struct voluta_fuseq_inb;
struct voluta_fuseq_outb;
struct voluta_sb_info;
struct voluta_oper;
struct voluta_dset;
struct voluta_rwiter_ctx;
struct voluta_readdir_ctx;
struct voluta_readdir_info;
struct voluta_listxattr_ctx;


/* file-system control flags */
enum voluta_flags {
	VOLUTA_F_KCOPY          = VOLUTA_BIT(0),
	VOLUTA_F_SYNC           = VOLUTA_BIT(1),
	VOLUTA_F_NOW            = VOLUTA_BIT(2),
	VOLUTA_F_BLKDEV         = VOLUTA_BIT(3),
	VOLUTA_F_MEMFD          = VOLUTA_BIT(4),
	VOLUTA_F_ALLOWOTHER     = VOLUTA_BIT(5),
	VOLUTA_F_NLOOKUP        = VOLUTA_BIT(6),
	VOLUTA_F_BRINGUP        = VOLUTA_BIT(7),
	VOLUTA_F_OPSTART        = VOLUTA_BIT(8),
	VOLUTA_F_TIMEOUT        = VOLUTA_BIT(9),
	VOLUTA_F_SLUGGISH       = VOLUTA_BIT(10),
	VOLUTA_F_IDLE           = VOLUTA_BIT(11),
	VOLUTA_F_SEAL           = VOLUTA_BIT(12),
};


/* inode's attributes masks */
enum voluta_iattr_flags {
	VOLUTA_IATTR_PARENT      = VOLUTA_BIT(0),
	VOLUTA_IATTR_LAZY        = VOLUTA_BIT(1),
	VOLUTA_IATTR_SIZE        = VOLUTA_BIT(2),
	VOLUTA_IATTR_SPAN        = VOLUTA_BIT(3),
	VOLUTA_IATTR_NLINK       = VOLUTA_BIT(4),
	VOLUTA_IATTR_BLOCKS      = VOLUTA_BIT(5),
	VOLUTA_IATTR_MODE        = VOLUTA_BIT(6),
	VOLUTA_IATTR_UID         = VOLUTA_BIT(7),
	VOLUTA_IATTR_GID         = VOLUTA_BIT(8),
	VOLUTA_IATTR_KILL_SUID   = VOLUTA_BIT(9),
	VOLUTA_IATTR_KILL_SGID   = VOLUTA_BIT(10),
	VOLUTA_IATTR_BTIME       = VOLUTA_BIT(11),
	VOLUTA_IATTR_ATIME       = VOLUTA_BIT(12),
	VOLUTA_IATTR_MTIME       = VOLUTA_BIT(13),
	VOLUTA_IATTR_CTIME       = VOLUTA_BIT(14),
	VOLUTA_IATTR_NOW         = VOLUTA_BIT(15),
	VOLUTA_IATTR_MCTIME      = VOLUTA_IATTR_MTIME | VOLUTA_IATTR_CTIME,
	VOLUTA_IATTR_TIMES       = VOLUTA_IATTR_BTIME | VOLUTA_IATTR_ATIME |
	                           VOLUTA_IATTR_MTIME | VOLUTA_IATTR_CTIME
};


/* strings & buffer */
struct voluta_str {
	const char *str;
	size_t len;
};

struct voluta_qstr {
	struct voluta_str str;
	uint64_t hash;
};

struct voluta_namestr {
	struct voluta_str str;
};

/* pair of ino and dir-type */
struct voluta_ino_dt {
	ino_t  ino;
	mode_t dt;
	int    pad;
};

/* name-buffer */
struct voluta_namebuf {
	char name[VOLUTA_NAME_MAX + 1];
};

/* pass-phrase + salt buffers */
struct voluta_passphrase {
	uint8_t pass[VOLUTA_PASSPHRASE_MAX + 1];
	size_t passlen;
};

/* cryptographic interfaces with libgcrypt */
struct voluta_mdigest {
	gcry_md_hd_t md_hd;
};

struct voluta_cipher {
	gcry_cipher_hd_t cipher_hd;
};

struct voluta_crypto {
	struct voluta_mdigest   md;
	struct voluta_cipher    ci;
};


/* cryptographic parameters */
struct voluta_crypt_params {
	struct voluta_kdf_pair kdf;
	uint32_t cipher_algo;
	uint32_t cipher_mode;
};

/* user-credentials */
struct voluta_ucred {
	uid_t  uid;
	gid_t  gid;
	pid_t  pid;
	mode_t umask;
};

/* space-addressing */
typedef loff_t          voluta_lba_t;
typedef uint64_t        voluta_index_t;

struct voluta_index_range {
	voluta_index_t  beg;
	voluta_index_t  end;
};

/* inode's time-stamps (birth, access, modify, change) */
struct voluta_itimes {
	struct timespec btime;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
};

/* inode's attributes */
struct voluta_iattr {
	enum voluta_iattr_flags ia_flags;
	mode_t          ia_mode;
	ino_t           ia_ino;
	ino_t           ia_parent;
	nlink_t         ia_nlink;
	uid_t           ia_uid;
	gid_t           ia_gid;
	dev_t           ia_rdev;
	loff_t          ia_size;
	loff_t          ia_span;
	blkcnt_t        ia_blocks;
	struct voluta_itimes ia_t;
};

/* encryption tuple (key, iv, algo, mode) */
struct voluta_kivam {
	struct voluta_key key;
	struct voluta_iv  iv;
	unsigned int cipher_algo;
	unsigned int cipher_mode;
};

/* uber-space elements addressing */
struct voluta_uaddr {
	loff_t                  off;
	unsigned int            len;
	enum voluta_ztype       ztype;
};

/* file-system elements addressing */
struct voluta_vaddr {
	voluta_index_t          hs_index;
	voluta_index_t          ag_index;
	voluta_lba_t            lba;
	loff_t                  off;
	unsigned int            len;
	enum voluta_ztype       ztype;
};

/* object-address within underlying blobs space */
struct voluta_baddr {
	struct voluta_blobid    bid;
	size_t                  len;
	loff_t                  off;
};

/* uberspace-to-object address mapping */
struct voluta_uba {
	struct voluta_uaddr     uaddr;
	struct voluta_baddr     baddr;
};

/* logical-to-object address mapping */
struct voluta_vba {
	struct voluta_vaddr     vaddr;
	struct voluta_baddr     baddr;
};

/* inode-address */
struct voluta_iaddr {
	struct voluta_vaddr     vaddr;
	ino_t                   ino;
};

/* caching-element's 128-bits key */
struct voluta_ckey {
	uint64_t k[2];
	uint64_t h;
};

/* caching-elements */
struct voluta_cache_elem {
	struct voluta_list_head ce_htb_lh;
	struct voluta_list_head ce_lru_lh;
	struct voluta_ckey ce_ckey;
	int  ce_refcnt;
	bool ce_dirty;
	bool ce_mapped;
	bool ce_forgot;
	char ce_pad;
};

/* cached blocks-section info */
struct voluta_bksec_info {
	struct voluta_cache_elem        bks_ce;
	struct voluta_blocks_sec       *bks;
	uint64_t        bks_mask[VOLUTA_NBK_IN_BKSEC];
	voluta_lba_t    bks_lba;
};

/* dirty-queue of cached-elements */
struct voluta_dirtyq {
	struct voluta_listq      dq_list;
	size_t dq_accum_nbytes;
};

/* LRU + hash-map */
struct voluta_lrumap {
	struct voluta_listq      lru;
	struct voluta_list_head *htbl;
	size_t htbl_nelems;
	size_t htbl_size;
};

/* cache */
struct voluta_cache {
	struct voluta_qalloc   *c_qalloc;
	struct voluta_alloc_if *c_alif;
	struct voluta_block    *c_nil_bk;
	struct voluta_lrumap    c_bsi_lm;
	struct voluta_lrumap    c_ci_lm;
	struct voluta_dirtyq    c_dq;
};

/* space accounting */
struct voluta_space_stat {
	ssize_t         ndata;
	ssize_t         nmeta;
	ssize_t         nfiles;
	ssize_t         zero;
};

struct voluta_space_info {
	struct voluta_space_stat sp_used;
	loff_t          sp_capcity_size;
	size_t          sp_ag_count;
	size_t          sp_hs_count;
	voluta_index_t  sp_hs_active;
	voluta_index_t  sp_hs_index_lo;
};

/* local object-storage device controller (blobs) */
struct voluta_locosd {
	struct voluta_list_head lo_htbl[1024];
	struct voluta_listq     lo_lru;
	struct voluta_alloc_if *lo_alif;
	const char             *lo_basedir;
	size_t  lo_nsubs;
	int     lo_dfd;
};

/* inodes-table in-memory hash-map cache */
struct voluta_itcentry {
	ino_t   ino;
	loff_t  off;
};

struct voluta_itcache {
	struct voluta_alloc_if *itc_alif;
	struct voluta_itcentry *itc_htable;
	size_t itc_nelems;
};

/* inodes-table reference */
struct voluta_itable_info {
	struct voluta_itcache   it_cache;
	struct voluta_vaddr     it_treeroot;
	struct voluta_iaddr     it_rootdir;
	ino_t  it_apex_ino;
	size_t it_ninodes;
	size_t it_ninodes_max;
};

/* operations counters */
struct voluta_oper_stat {
	size_t op_iopen_max;
	size_t op_iopen;
	time_t op_time;
	size_t op_count;
	/* TODO: Have counter per-operation */
};

/* super-block in-memory info */
struct voluta_sb_info {
	struct voluta_super_block      *sb;
	struct voluta_alloc_if         *s_alif;
	struct voluta_qalloc           *s_qalloc;
	struct voluta_cache            *s_cache;
	struct voluta_locosd           *s_locosd;
	struct voluta_vba               s_vba;
	struct voluta_uuid              s_fs_uuid;
	struct voluta_ucred             s_owner;
	struct voluta_space_info        s_spi;
	struct voluta_itable_info       s_itbi;
	struct voluta_oper_stat         s_ops;
	struct voluta_pipe              s_pipe;
	struct voluta_nullfd            s_nullnfd;
	struct voluta_crypto            s_crypto;
	unsigned long                   s_ctl_flags;
	unsigned long                   s_ms_flags;
	iconv_t                         s_iconv;
	time_t                          s_mntime;
} voluta_aligned64;

/* dirty-vnodes set */
typedef void (*voluta_dset_add_fn)(struct voluta_dset *dset,
                                   struct voluta_znode_info *zi);

struct voluta_dset {
	voluta_dset_add_fn              ds_add_fn;
	struct voluta_znode_info       *ds_ziq;
	struct voluta_avl               ds_avl;
};

/* current operation state */
struct voluta_oper {
	struct voluta_ucred ucred;
	struct timespec     xtime;
	long                unique;
	int                 opcode;
};

/* fuse-q machinery */
struct voluta_fuseq_conn_info {
	int     proto_major;
	int     proto_minor;
	int     cap_kern;
	int     cap_want;
	size_t  pagesize;
	size_t  buffsize;
	size_t  max_write;
	size_t  max_read;
	size_t  max_readahead;
	size_t  max_background;
	size_t  congestion_threshold;
	size_t  time_gran;
} voluta_aligned64;

struct voluta_fuseq_worker {
	struct voluta_fuseq            *fq;
	const struct voluta_fuseq_cmd  *cmd;
	struct voluta_sb_info          *sbi;
	struct voluta_fuseq_inb        *inb;
	struct voluta_fuseq_outb       *outb;
	struct voluta_fuseq_rw_iter    *rwi;
	struct voluta_oper             *op;
	struct voluta_oper              oper;
	struct voluta_pipe              pipe;
	struct voluta_nullfd            nfd;
	struct voluta_thread            th;
	int idx;
} voluta_aligned64;

struct voluta_fuseq_workset {
	struct voluta_fuseq_worker      *fws_worker;
	short fws_nlimit;
	short fws_navail;
	short fws_nactive;
};

struct voluta_fuseq {
	struct voluta_fuseq_workset     fq_ws;
	struct voluta_fuseq_conn_info   fq_coni;
	struct voluta_mutex             fq_ch_lock;
	struct voluta_mutex             fq_fs_lock;
	struct voluta_sb_info          *fq_sbi;
	struct voluta_alloc_if         *fq_alif;
	size_t          fq_nopers;
	time_t          fq_times;
	volatile int    fq_active;
	volatile int    fq_fuse_fd;
	bool            fq_got_init;
	bool            fq_got_destroy;
	bool            fq_deny_others;
	bool            fq_mount;
	bool            fq_umount;
	bool            fq_splice_memfd;
} voluta_aligned64;

/* file-system input arguments */
struct voluta_fs_args {
	const char *objsdir;
	const char *mntdir;
	const char *rootid;
	const char *fsname;
	const char *passwd;
	size_t memwant;
	loff_t vsize;
	uid_t  uid;
	gid_t  gid;
	pid_t  pid;
	mode_t umask;
	bool   with_fuseq;
	bool   kcopy_mode;
	bool   pedantic;
	bool   allowother;
	bool   lazytime;
	bool   noexec;
	bool   nosuid;
	bool   nodev;
	bool   rdonly;
};

/* file-system environment context */
struct voluta_fs_env {
	struct voluta_fs_args           args;
	struct voluta_crypt_params      cryp;
	struct voluta_passphrase        passph;
	struct voluta_kivam             kivam;
	struct voluta_qalloc           *qalloc;
	struct voluta_alloc_if         *alif;
	struct voluta_mpool            *mpool;
	struct voluta_cache            *cache;
	struct voluta_locosd           *locosd;
	struct voluta_sb_info          *sbi;
	struct voluta_super_block      *sb;
	struct voluta_fuseq            *fuseq;
	loff_t volume_size;
	int signum;
};

/* call-back types for file-system operations */
typedef int (*voluta_filldir_fn)(struct voluta_readdir_ctx *rd_ctx,
                                 const struct voluta_readdir_info *rdi);

struct voluta_readdir_info {
	struct stat attr;
	const char *name;
	size_t namelen;
	ino_t ino;
	loff_t off;
	mode_t dt;
};

struct voluta_readdir_ctx {
	voluta_filldir_fn actor;
	loff_t pos;
};


typedef int (*voluta_fillxattr_fn)(struct voluta_listxattr_ctx *lxa_ctx,
                                   const char *name, size_t name_len);

struct voluta_listxattr_ctx {
	voluta_fillxattr_fn actor;
};

typedef int (*voluta_rwiter_fn)(struct voluta_rwiter_ctx *rwi_ctx,
                                const struct voluta_fiovec *fiov);

struct voluta_rwiter_ctx {
	voluta_rwiter_fn actor;
	loff_t off;
	size_t len;
};

/* allocation-groups range (beg <= tip <= fin <= end) */
struct voluta_ag_span {
	voluta_index_t beg; /* start ag-index */
	voluta_index_t tip; /* heuristic of current tip ag-index */
	voluta_index_t fin; /* one past last ag-index of current span */
	voluta_index_t end; /* end of hyper-range */
};

#endif /* VOLUTA_TYPES_H_ */
