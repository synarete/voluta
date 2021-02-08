/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * This file is part of libvoluta
 *
 * Copyright (C) 2020-2021 Shachar Sharon
 *
 * Libvoluta is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Libvoluta is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
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
struct voluta_ar_blob_info;


/* file-system control flags */
enum voluta_flags {
	VOLUTA_F_ENCRYPTED      = VOLUTA_BIT(0),
	VOLUTA_F_ENCRYPTWR      = VOLUTA_BIT(1),
	VOLUTA_F_SYNC           = VOLUTA_BIT(1),
	VOLUTA_F_NOW            = VOLUTA_BIT(2),
	VOLUTA_F_BLKDEV         = VOLUTA_BIT(3),
	VOLUTA_F_MEMFD          = VOLUTA_BIT(4),
	VOLUTA_F_NLOOKUP        = VOLUTA_BIT(5),
	VOLUTA_F_TIMEOUT        = VOLUTA_BIT(6),
	VOLUTA_F_IDLE           = VOLUTA_BIT(7),
	VOLUTA_F_BRINGUP        = VOLUTA_BIT(8),
	VOLUTA_F_OPSTART        = VOLUTA_BIT(9),
};


/* inode's attributes masks */
enum voluta_iattr_flags {
	VOLUTA_IATTR_PARENT      = VOLUTA_BIT(0),
	VOLUTA_IATTR_KILL_PRIV   = VOLUTA_BIT(1),
	VOLUTA_IATTR_LAZY        = VOLUTA_BIT(2),
	VOLUTA_IATTR_SIZE        = VOLUTA_BIT(3),
	VOLUTA_IATTR_NLINK       = VOLUTA_BIT(4),
	VOLUTA_IATTR_BLOCKS      = VOLUTA_BIT(5),
	VOLUTA_IATTR_MODE        = VOLUTA_BIT(6),
	VOLUTA_IATTR_UID         = VOLUTA_BIT(7),
	VOLUTA_IATTR_GID         = VOLUTA_BIT(8),
	VOLUTA_IATTR_BTIME       = VOLUTA_BIT(9),
	VOLUTA_IATTR_ATIME       = VOLUTA_BIT(10),
	VOLUTA_IATTR_MTIME       = VOLUTA_BIT(11),
	VOLUTA_IATTR_CTIME       = VOLUTA_BIT(12),
	VOLUTA_IATTR_NOW         = VOLUTA_BIT(13),
	VOLUTA_IATTR_MCTIME      = VOLUTA_IATTR_MTIME | VOLUTA_IATTR_CTIME,
	VOLUTA_IATTR_TIMES       = VOLUTA_IATTR_BTIME | VOLUTA_IATTR_ATIME |
				   VOLUTA_IATTR_MTIME | VOLUTA_IATTR_CTIME
};

/* threading */
typedef int (*voluta_execute_fn)(struct voluta_thread *);

/* wrapper of pthread_t */
struct voluta_thread {
	voluta_execute_fn exec;
	pthread_t       pth;
	char            name[32];
	time_t          start_time;
	time_t          finish_time;
	int             status;
};

/* wrapper of pthread_mutex_t */
struct voluta_mutex {
	pthread_mutex_t mutex;
	int alive;
};

struct voluta_pipe {
	int     fd[2];
	size_t  size;
	size_t  pend;
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

struct voluta_buf {
	void  *buf;
	size_t len;
	size_t bsz;
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

/* pool-based memory-allocator */
struct voluta_mpool {
	struct voluta_qalloc *mp_qal;
	struct voluta_listq mp_bq;
	struct voluta_listq mp_vq;
	struct voluta_listq mp_iq;
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


/* zero-block cryptographic params */
struct voluta_zcrypt_params {
	struct voluta_kdf_pair kdf;
	uint32_t cipher_algo;
	uint32_t cipher_mode;
	uint32_t iv_md_hash; /* TODO: fill & use me */
};

/* user-credentials */
struct voluta_ucred {
	uid_t  uid;
	gid_t  gid;
	pid_t  pid;
	mode_t umask;
};

/* inode's attributes */
struct voluta_itimes {
	struct timespec btime;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
};

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
	blkcnt_t        ia_blocks;
	struct voluta_itimes ia_t;
};

/* logical-address within underlying volume space */
struct voluta_vaddr {
	loff_t          off;
	loff_t          lba;
	uint32_t        len;
	enum voluta_vtype vtype;
};

/* inode-address */
struct voluta_iaddr {
	struct voluta_vaddr vaddr;
	ino_t ino;
};


/* caching-elements */
struct voluta_cache_elem {
	struct voluta_list_head ce_htb_lh;
	struct voluta_list_head ce_lru_lh;
	long ce_key;
	long ce_tick;
	int  ce_refcnt;
	bool ce_mapped;
	bool ce_forgot;
};

/* block caching info */
struct voluta_bk_info {
	struct voluta_cache_elem bki_ce;
	struct voluta_block *bk;
	loff_t   bk_lba;
	uint64_t bk_mask;
};

/* vnode */
union voluta_vnode_u {
	struct voluta_hspace_map        *hsm;
	struct voluta_agroup_map        *agm;
	struct voluta_itable_tnode      *itn;
	struct voluta_inode             *inode;
	struct voluta_radix_tnode       *rtn;
	struct voluta_dir_htnode        *htn;
	struct voluta_xattr_node        *xan;
	struct voluta_lnk_value         *lnv;
	struct voluta_data_block4       *db4;
	struct voluta_data_block        *db;
	void *p;
};

struct voluta_vnode_info {
	union voluta_vnode_u            vu;
	struct voluta_view             *view;
	struct voluta_vaddr             vaddr;
	struct voluta_cache_elem        v_ce;
	struct voluta_list_head         v_dq_mlh;
	struct voluta_list_head         v_dq_blh;
	struct voluta_avl_node          v_ds_an;
	struct voluta_sb_info          *v_sbi;
	struct voluta_bk_info          *v_bki;
	struct voluta_vnode_info       *v_pvi;
	struct voluta_vnode_info       *v_ds_next;
	long v_ds_key;
	int v_dirty;
	int v_verify;
};

/* dirty-queues of cached-elements */
struct voluta_dirtyq {
	struct voluta_listq             dq_list;
	size_t dq_accum_nbytes;
};

struct voluta_dirtyqs {
	struct voluta_qalloc           *dq_qalloc;
	struct voluta_dirtyq           *dq_bins;
	struct voluta_dirtyq            dq_main;
	size_t dq_nbins;
};

/* inode */
struct voluta_inode_info {
	struct voluta_inode            *inode;
	struct voluta_vnode_info        i_vi;
	struct timespec                 i_atime_lazy;
	ino_t  i_ino;
	long   i_nopen;
	long   i_nlookup;
};

/* caching */
struct voluta_lrumap {
	struct voluta_listq      lru;
	struct voluta_list_head *htbl;
	long (*hash_fn)(long);
	size_t htbl_nelems;
	size_t htbl_size;
};

struct voluta_cache {
	struct voluta_mpool    *c_mpool;
	struct voluta_qalloc   *c_qalloc;
	struct voluta_dirtyqs   c_dqs;
	struct voluta_lrumap    c_blm;
	struct voluta_lrumap    c_vlm;
	struct voluta_lrumap    c_ilm;
	struct voluta_block    *c_nil_bk;
	long   c_tick;
};

/* space accounting */
struct voluta_space_stat {
	ssize_t ndata;
	ssize_t nmeta;
	ssize_t nfiles;
	ssize_t zero;
};

struct voluta_space_info {
	loff_t  sp_size;
	size_t  sp_hs_count;
	size_t  sp_hs_active;
	size_t  sp_hs_index_lo;
	size_t  sp_ag_count;
	ssize_t sp_used_meta;
	ssize_t sp_used_data;
	ssize_t sp_nfiles;
};

/* encrypted output buffer */
struct voluta_encbuf {
	uint8_t b[VOLUTA_MEGA];
};

/* persistent-storage I/O-control */
struct voluta_pstore {
	int     ps_dfd;
	int     ps_vfd;
	int     ps_flags;
	loff_t  ps_size;
	loff_t  ps_capacity;
};

/* volume storage controller */
struct voluta_vstore {
	struct voluta_pstore            vs_pstore;
	struct voluta_crypto            vs_crypto;
	struct voluta_qalloc           *vs_qalloc;
	struct voluta_encbuf           *vs_encbuf;
	const char *vs_volpath;
	unsigned long vs_ctl_flags;
};

/* inodes-table in-memory hash-map cache */
struct voluta_itcentry {
	ino_t   ino;
	loff_t  off;
};

struct voluta_itcache {
	struct voluta_qalloc   *itc_qalloc;
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
	struct voluta_qalloc           *sb_qalloc;
	struct voluta_cache            *sb_cache;
	struct voluta_vstore           *sb_vstore;
	struct voluta_uuid              sb_fs_uuid;
	struct voluta_ucred             sb_owner;
	struct voluta_space_info        sb_spi;
	struct voluta_itable_info       sb_iti;
	struct voluta_oper_stat         sb_ops;
	unsigned long                   sb_ctl_flags;
	unsigned long                   sb_ms_flags;
	iconv_t                         sb_iconv;
} voluta_aligned64;

/* de-stage dirty-vnodes set */
typedef void (*voluta_dset_add_fn)(struct voluta_dset *dset,
				   struct voluta_vnode_info *vi);

struct voluta_dset {
	struct voluta_cache            *ds_cache;
	voluta_dset_add_fn              ds_add_fn;
	struct voluta_vnode_info       *ds_viq;
	struct voluta_avl               ds_avl;
	long ds_key;
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
	struct voluta_thread            th;
	int idx;
} voluta_aligned64;

struct voluta_fuseq {
	struct voluta_fuseq_worker      fq_worker[4];
	struct voluta_fuseq_conn_info   fq_coni;
	struct voluta_mutex             fq_ch_lock;
	struct voluta_mutex             fq_fs_lock;
	struct voluta_sb_info          *fq_sbi;
	struct voluta_qalloc           *fq_qal;
	size_t          fq_nopers;
	time_t          fq_times;
	int             fq_nworkers_avail;
	int             fq_nworkers_active;
	volatile int    fq_active;
	volatile int    fq_fuse_fd;
	volatile int    fq_null_fd;
	bool            fq_got_init;
	bool            fq_got_destroy;
	bool            fq_deny_others;
	bool            fq_mount;
	bool            fq_umount;
	bool            fq_splice_memfd;
} voluta_aligned64;

/* file-system arguments */
struct voluta_fs_args {
	const char *volume;
	const char *mountp;
	const char *fsname;
	const char *passwd;
	size_t memwant;
	loff_t vsize;
	uid_t  uid;
	gid_t  gid;
	pid_t  pid;
	mode_t umask;
	bool   with_fuseq;
	bool   pedantic;
	bool   encrypted;
	bool   encryptwr;
	bool   lazytime;
	bool   noexec;
	bool   nosuid;
	bool   nodev;
	bool   rdonly;
};

/* file-system environment context */
struct voluta_fs_env {
	struct voluta_fs_args           args;
	struct voluta_zcrypt_params     zcryp;
	struct voluta_passphrase        passph;
	struct voluta_kivam             kivam;
	struct voluta_qalloc           *qalloc;
	struct voluta_mpool            *mpool;
	struct voluta_cache            *cache;
	struct voluta_vstore           *vstore;
	struct voluta_super_block      *sb;
	struct voluta_sb_info          *sbi;
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
				const struct voluta_xiovec *xiov);

struct voluta_rwiter_ctx {
	voluta_rwiter_fn actor;
	loff_t off;
	size_t len;
};


/* archiving */
struct voluta_ar_args {
	const char *passwd;
	const char *volume;
	const char *blobsdir;
	const char *arcname;
	size_t memwant;
};

struct voluta_archiver {
	struct voluta_ar_args           ar_args;
	struct voluta_kivam             ar_kivam;
	struct voluta_qalloc           *ar_qalloc;
	struct voluta_crypto           *ar_crypto;
	struct voluta_bstore           *ar_bstore;
	struct voluta_ar_blob_info     *ar_bli;
	struct voluta_ar_spec          *ar_spec;
	size_t ar_spec_nents;
	size_t ar_spec_nents_max;
	int try_clone;
};

#endif /* VOLUTA_TYPES_H_ */
