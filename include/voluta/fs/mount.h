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
#ifndef VOLUTA_MOUNT_H_
#define VOLUTA_MOUNT_H_

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <voluta/defs.h>

struct voluta_ms_env;

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


int voluta_mse_new(struct voluta_ms_env **out_mse);

void voluta_mse_del(struct voluta_ms_env *mse);

int voluta_mse_serve(struct voluta_ms_env *mse,
                     const struct voluta_mntrules *mrules);

void voluta_mse_halt(struct voluta_ms_env *mse, int signum);


int voluta_rpc_handshake(uid_t uid, gid_t gid);

int voluta_rpc_mount(const char *mountpoint, uid_t uid, gid_t gid,
                     size_t max_read, unsigned long ms_flags,
                     bool allow_other, int *out_fd);

int voluta_rpc_umount(const char *mountpoint,
                      uid_t uid, gid_t gid, int mnt_flags);

bool voluta_is_fuse_fstype(long fstype);

const struct voluta_fsinfo *voluta_fsinfo_by_vfstype(long vfstype);

int voluta_check_mntdir_fstype(long vfstype);

#endif /* VOLUTA_MOUNT_H_ */
