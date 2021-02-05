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
#ifndef VOLUTA_EXTERN_H_
#define VOLUTA_EXTERN_H_

#include <stdlib.h>
#include <stdbool.h>


struct voluta_mntrule {
	char *path;
	uid_t uid;
	bool  recursive;
};

struct voluta_mntrules {
	size_t nrules;
	struct voluta_mntrule rules[VOLUTA_MNTRULE_MAX];
};


struct voluta_fs_stats {
	size_t nalloc_bytes;
	size_t ncache_blocks;
	size_t ncache_inodes;
	size_t ncache_vnodes;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


int voluta_lib_init(void); /* TODO: have fini_lib */

int voluta_resolve_volume_size(const char *path,
			       loff_t size_want, loff_t *out_size);

int voluta_require_volume_path(const char *path, bool rw);

int voluta_check_mntdir_fstype(long vfstype);

int voluta_check_name(const char *name);

/* zero-block */
int voluta_zb_check(const struct voluta_zero_block4 *zb);

int voluta_sb_decipher(struct voluta_super_block *sb, const char *pass);

enum voluta_ztype voluta_zb_type(const struct voluta_zero_block4 *zb);

enum voluta_zbf voluta_zb_flags(const struct voluta_zero_block4 *zb);

/* mount-service */
struct voluta_ms_env;

int voluta_mse_new(struct voluta_ms_env **out_mse);

void voluta_mse_del(struct voluta_ms_env *mse);

int voluta_mse_serve(struct voluta_ms_env *mse,
		     const struct voluta_mntrules *mrules);

void voluta_mse_halt(struct voluta_ms_env *mse, int signum);

/* mount-client */
int voluta_rpc_handshake(uid_t uid, gid_t gid);

int voluta_rpc_mount(const char *mountpoint, uid_t uid, gid_t gid,
		     size_t max_read, unsigned long ms_flags, int *out_fd);

int voluta_rpc_umount(const char *mountpoint,
		      uid_t uid, gid_t gid, int mnt_flags);

long voluta_fuse_super_magic(void);

/* file-system */
int voluta_fse_new(size_t memwant, struct voluta_fs_env **out_fse);

void voluta_fse_del(struct voluta_fs_env *fse);

int voluta_fse_reload(struct voluta_fs_env *fse);

int voluta_fse_format(struct voluta_fs_env *fse);

int voluta_fse_encrypt(struct voluta_fs_env *fse);

int voluta_fse_serve(struct voluta_fs_env *fse);

int voluta_fse_verify(struct voluta_fs_env *fse);

int voluta_fse_term(struct voluta_fs_env *fse);

void voluta_fse_halt(struct voluta_fs_env *fse, int signum);

int voluta_fse_sync_drop(struct voluta_fs_env *fse);

int voluta_fse_setargs(struct voluta_fs_env *fse,
		       const struct voluta_fs_args *args);

void voluta_fse_stats(const struct voluta_fs_env *fse,
		      struct voluta_fs_stats *st);

/* archiver */
int voluta_archiver_new(size_t memwant, struct voluta_archiver **out_arc);

void voluta_archiver_del(struct voluta_archiver *arc);

int voluta_archiver_setargs(struct voluta_archiver *arc,
			    const struct voluta_ar_args *args);

int voluta_archiver_export(struct voluta_archiver *arc);

int voluta_archiver_import(struct voluta_archiver *arc);


#endif /* VOLUTA_EXTERN_H_ */
