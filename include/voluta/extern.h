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


struct voluta_fsinfo {
	long vfstype;
	const char *name;
	bool allowed;
	bool isfuse;
};

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

const struct voluta_fsinfo *voluta_fsinfo_by_vfstype(long vfstype);

int voluta_check_mntdir_fstype(long vfstype);

int voluta_check_name(const char *name);

/* boot */
int voluta_check_boot_record(const struct voluta_super_block *sb);

int voluta_decipher_super_block(struct voluta_super_block *sb,
                                const char *password);

enum voluta_ztype voluta_br_type(const struct voluta_boot_record *br);

enum voluta_brf voluta_br_flags(const struct voluta_boot_record *br);

int voluta_setup_qalloc_with(struct voluta_qalloc *qal, size_t memwant);

/* file-system */
int voluta_fse_new(const struct voluta_fs_args *args,
                   struct voluta_fs_env **out_fse);

void voluta_fse_del(struct voluta_fs_env *fse);

int voluta_fse_reload(struct voluta_fs_env *fse);

int voluta_fse_format(struct voluta_fs_env *fse);

int voluta_fse_traverse(struct voluta_fs_env *fse);

int voluta_fse_serve(struct voluta_fs_env *fse);

int voluta_fse_verify(struct voluta_fs_env *fse);

int voluta_fse_term(struct voluta_fs_env *fse);

void voluta_fse_halt(struct voluta_fs_env *fse, int signum);

int voluta_fse_sync_drop(struct voluta_fs_env *fse);

void voluta_fse_stats(const struct voluta_fs_env *fse,
                      struct voluta_fs_stats *st);

/* archiver */
int voluta_archiver_new(const struct voluta_ar_args *args,
                        struct voluta_archiver **out_arc);

void voluta_archiver_del(struct voluta_archiver *arc);

int voluta_archiver_export(struct voluta_archiver *arc);

int voluta_archiver_import(struct voluta_archiver *arc);

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
                     size_t max_read, unsigned long ms_flags,
                     bool allow_other, int *out_fd);

int voluta_rpc_umount(const char *mountpoint,
                      uid_t uid, gid_t gid, int mnt_flags);

long voluta_fuse_super_magic(void);

#endif /* VOLUTA_EXTERN_H_ */
