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
#define _GNU_SOURCE 1
#include <voluta/cmd.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *repo_mkpath(const struct voluta_repo_info *repoi, const char *s)
{
	return voluta_joinpath_safe(repoi->base_dir, s);
}

void voluta_repo_acquire_lock(struct voluta_repo_info *repoi)
{
	int err;
	const int o_flags = repoi->rw ? O_RDWR : O_RDONLY;
	struct flock fl = {
		.l_type = repoi->rw ? F_WRLCK : F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	err = voluta_sys_open(repoi->lock_file, o_flags, 0, &repoi->lock_fd);
	if (err) {
		voluta_die(err, "failed to open: %s", repoi->lock_file);
	}
	err = voluta_sys_fcntl_flock(repoi->lock_fd, F_SETLK, &fl);
	if (err) {
		voluta_die(err, "failed to flock: %s", repoi->lock_file);
	}
}

void voluta_repo_release_lock(struct voluta_repo_info *repoi)
{
	int err;
	struct flock fl = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	if (repoi->lock_file && (repoi->lock_fd > 0)) {
		err = voluta_sys_fcntl_flock(repoi->lock_fd, F_SETLK, &fl);
		if (err) {
			voluta_die(err, "no funlock: %s", repoi->lock_file);
		}
		voluta_sys_closefd(&repoi->lock_fd);
	}
}

void voluta_repo_require_lockable(struct voluta_repo_info *repoi)
{
	voluta_repo_acquire_lock(repoi);
	voluta_repo_release_lock(repoi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *repo_base_dir_real(const char *base_dir)
{
	char *path = voluta_realpath_safe(base_dir);

	if (strlen(path) >= VOLUTA_REPO_PATH_MAX) {
		voluta_die(-ENAMETOOLONG, "illegal repository real-path");
	}
	return path;
}

void voluta_repo_setup(struct voluta_repo_info *repoi,
                       const char *base_dir, bool rw)
{
	repoi->base_dir = repo_base_dir_real(base_dir);
	repoi->objs_dir = repo_mkpath(repoi, "objs");
	repoi->lock_file = repo_mkpath(repoi, "voluta.lock");
	repoi->head_file = repo_mkpath(repoi, "HEAD");
	repoi->lock_fd = -1;
	repoi->rw = rw;
}

void voluta_repo_finalize(struct voluta_repo_info *repoi)
{
	voluta_repo_release_lock(repoi);
	voluta_pfree_string(&repoi->base_dir);
	voluta_pfree_string(&repoi->objs_dir);
	voluta_pfree_string(&repoi->lock_file);
	voluta_pfree_string(&repoi->head_file);
}

void voluta_repo_create_skel(const struct voluta_repo_info *repoi)
{
	int err;
	int fd = -1;

	err = voluta_sys_mkdir(repoi->objs_dir, 0700);
	if (err) {
		voluta_die(err, "mkdir failed: %s", repoi->objs_dir);
	}
	err = voluta_sys_open(repoi->lock_file, O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		voluta_die(err, "failed to create: %s", repoi->head_file);
	}
	voluta_sys_closefd(&fd);
}

void voluta_repo_require_skel(struct voluta_repo_info *repoi)
{
	int err;
	struct stat st;

	err = voluta_sys_access(repoi->base_dir, R_OK | W_OK | X_OK);
	if (err) {
		voluta_die(err, "no access: %s", repoi->base_dir);
	}
	err = voluta_sys_stat(repoi->objs_dir, &st);
	if (err) {
		voluta_die(err, "no stat: %s", repoi->objs_dir);
	}
	if (!S_ISDIR(st.st_mode)) {
		voluta_die(-ENOTDIR, "missing objs dir: %s", repoi->objs_dir);
	}
	err = voluta_sys_stat(repoi->lock_file, &st);
	if (err) {
		voluta_die(err, "no stat: %s", repoi->lock_file);
	}
	if (!S_ISREG(st.st_mode)) {
		voluta_die(0, "missing lock file: %s", repoi->lock_file);
	}
}

void voluta_repo_save_head(const struct voluta_repo_info *repoi,
                           const char *rootid)
{
	int err;
	int fd = -1;
	const size_t len = strlen(rootid);

	err = voluta_sys_open(repoi->head_file, O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		voluta_die(err, "failed to create: %s", repoi->head_file);
	}
	err = voluta_sys_pwriten(fd, rootid, len, 0);
	if (err) {
		voluta_die(err, "write error: %s", repoi->head_file);
	}
	err = voluta_sys_pwriten(fd, "\n", 1, (loff_t)len);
	if (err) {
		voluta_die(err, "write error: %s", repoi->head_file);
	}
	voluta_sys_closefd(&fd);
}

static void strip_headref(char *buf, size_t len)
{
	struct voluta_substr ss;

	buf[len] = '\0';
	voluta_substr_init_rw(&ss, buf, len, len);
	voluta_substr_strip_if(&ss, voluta_chr_isspace, &ss);
	voluta_substr_copyto(&ss, buf, len);
}

void voluta_repo_load_head(const struct voluta_repo_info *repoi,
                           char *buf, size_t bsz)
{
	int err;
	int fd = -1;
	size_t nrd = 0;

	err = voluta_sys_open(repoi->head_file, O_RDONLY, 0600, &fd);
	if (err) {
		voluta_die(err, "failed to open: %s", repoi->head_file);
	}
	err = voluta_sys_pread(fd, buf, bsz - 1, 0, &nrd);
	if (err) {
		voluta_die(err, "read error: %s", repoi->head_file);
	}
	voluta_sys_closefd(&fd);
	strip_headref(buf, nrd);
}
