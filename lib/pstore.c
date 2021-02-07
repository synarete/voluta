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
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "libvoluta.h"


struct voluta_vpath_info {
	char path[VOLUTA_VOLUME_PATH_MAX];
	const char *dpath;
	const char *vname;
};


static bool isopen_fd(int fd)
{
	return (fd != -1);
}

static int close_fd(int *pfd)
{
	int err = 0;

	if ((pfd != NULL) && isopen_fd(*pfd)) {
		err = voluta_sys_close(*pfd);
		*pfd = -1;
	}
	return err;
}

static int close_fds(int *pfd1, int *pfd2)
{
	int err1;
	int err2;

	err1 = close_fd(pfd1);
	err2 = close_fd(pfd2);
	return err1 || err2;
}

static int split_path(const char *path, char *buf, size_t bsz,
		      char **head, char **tail)
{
	size_t len;
	char *str;

	len = strnlen(path, bsz);
	if (len >= bsz) {
		return -EINVAL;
	}
	strncpy(buf, path, len);
	str = strrchr(buf, '/');
	if (str == NULL) {
		log_dbg("missing slash in path: '%s'", path);
		return -EINVAL;
	}
	*str = '\0';
	str += 1;
	len = strlen(str);
	if (!len) {
		return -EINVAL;
	}
	*head = buf;
	*tail = str;
	return 0;
}

static int parse_vpath(struct voluta_vpath_info *vpi, const char *path)
{
	int err;
	char *head = NULL;
	char *tail = NULL;

	voluta_memzero(vpi, sizeof(*vpi));
	err = split_path(path, vpi->path, sizeof(vpi->path), &head, &tail);
	if (!err) {
		vpi->dpath = head;
		vpi->vname = tail;
	}
	return err;
}

static int resolve_by_fd(int fd, loff_t *out_size, mode_t *out_mode)
{
	int err;
	size_t sz = 0;
	struct stat st;

	err = voluta_sys_fstat(fd, &st);
	if (err) {
		return err;
	}
	*out_mode = st.st_mode;
	if (S_ISREG(*out_mode)) {
		*out_size = st.st_size;
	} else if (S_ISBLK(*out_mode)) {
		err = voluta_sys_ioctl_blkgetsize64(fd, &sz);
		*out_size = (loff_t)sz;
	} else {
		err = -EINVAL;
	}
	return err;
}

static int resolve_by_path(const char *path, loff_t *out_size)
{
	int err;
	int fd;
	mode_t mode;
	struct stat st;

	*out_size = 0;
	if (path == NULL) {
		return 0;
	}
	err = voluta_sys_stat(path, &st);
	if (err) {
		return err;
	}
	if (S_ISREG(st.st_mode)) {
		*out_size = st.st_size;
		return 0;
	}
	err = voluta_sys_open(path, O_RDONLY, S_IFBLK | S_IRUSR, &fd);
	if (err) {
		return err;
	}
	err = resolve_by_fd(fd, out_size, &mode);
	voluta_sys_close(fd);
	return err;
}

static size_t vol_size_to_nags(loff_t size)
{
	return (size_t)(size / VOLUTA_AG_SIZE);
}

static loff_t vol_size_fixup(loff_t size)
{
	return (loff_t)(vol_size_to_nags(size) * VOLUTA_AG_SIZE);
}

static int vol_size_check(loff_t size)
{
	const loff_t size_min = VOLUTA_VOLUME_SIZE_MIN;
	const loff_t size_max = VOLUTA_VOLUME_SIZE_MAX;

	return ((size < size_min) || (size > size_max)) ? -EINVAL : 0;
}

int voluta_calc_vsize(loff_t size_cur, loff_t size_want, loff_t *out_size)
{
	int err;

	if (size_want == 0) {
		size_want = size_cur;
	}
	err = vol_size_check(size_want);
	if (err) {
		return err;
	}
	*out_size = vol_size_fixup(size_want);
	if (*out_size < 2) {
		return -EINVAL;
	}
	return 0;
}

int voluta_resolve_volume_size(const char *path,
			       loff_t size_want, loff_t *out_size)
{
	int err;
	loff_t size_cur = 0;

	err = resolve_by_path(path, &size_cur);
	if (err && (err != -ENOENT)) {
		return err;
	}
	err = voluta_calc_vsize(size_cur, size_want, out_size);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_require_volume_path(const char *path, bool rw)
{
	int err;
	loff_t size;
	size_t len;
	struct stat st;
	const int access_mode = rw ? (R_OK | W_OK) : R_OK;

	len = strlen(path);
	if (!len) {
		return -EINVAL;
	}
	if (len >= VOLUTA_VOLUME_PATH_MAX) {
		return -ENAMETOOLONG;
	}
	err = voluta_sys_access(path, access_mode);
	if (err) {
		return err;
	}
	err = voluta_sys_stat(path, &st);
	if (err) {
		return err;
	}
	if (S_ISDIR(st.st_mode)) {
		return -EISDIR;
	}
	if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode)) {
		return -EINVAL;
	}
	if ((st.st_mode & S_IRUSR) != S_IRUSR) {
		return -EPERM;
	}
	err = voluta_resolve_volume_size(path, st.st_size, &size);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_pstore_init(struct voluta_pstore *pstore)
{
	pstore->ps_dfd = -1;
	pstore->ps_vfd = -1;
	pstore->ps_flags = 0;
	pstore->ps_size = 0;
	pstore->ps_capacity = 0;
	return 0;
}

void voluta_pstore_fini(struct voluta_pstore *pstore)
{
	voluta_pstore_close(pstore);
	pstore->ps_vfd = -1;
	pstore->ps_flags = 0;
	pstore->ps_size = -1;
	pstore->ps_capacity = -1;
}

static void pstore_setup(struct voluta_pstore *pstore, int dfd, int vfd,
			 loff_t size, loff_t size_max, int xflags)
{
	pstore->ps_dfd = dfd;
	pstore->ps_vfd = vfd;
	pstore->ps_size = size;
	pstore->ps_capacity = size_max;
	pstore->ps_flags |= xflags;
}

static int pstore_create_mem(struct voluta_pstore *pstore, loff_t size)
{
	int err;
	int dfd = -1;
	int vfd = -1;

	err = vol_size_check(size);
	if (err) {
		return err;
	}
	err = voluta_sys_memfd_create("voluta-volume", 0, &vfd);
	if (err) {
		return err;
	}
	err = voluta_sys_ftruncate(vfd, size);
	if (err) {
		close_fd(&vfd);
		return err;
	}
	pstore_setup(pstore, dfd, vfd, size, size, VOLUTA_F_MEMFD);
	return 0;
}

static int pstore_create_reg(struct voluta_pstore *pstore,
			     const char *path, loff_t size_max)
{
	int err;
	int dfd = -1;
	int vfd = -1;
	mode_t mode;
	struct voluta_vpath_info vpi;

	err = parse_vpath(&vpi, path);
	if (err) {
		return err;
	}
	err = voluta_sys_open(vpi.dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		return err;
	}
	mode = S_IFREG | S_IRUSR | S_IWUSR;
	err = voluta_sys_openat(dfd, vpi.vname, O_CREAT | O_RDWR, mode, &vfd);
	if (err) {
		close_fd(&dfd);
		return err;
	}
	pstore_setup(pstore, dfd, vfd, 0, size_max, 0);
	return 0;
}

static int pstore_create_blk(struct voluta_pstore *pstore,
			     const char *path, loff_t size)
{
	int err;
	int vfd = -1;
	loff_t sz;
	mode_t mode = S_IFBLK | S_IRUSR | S_IWUSR;

	err = voluta_sys_open(path, O_CREAT | O_RDWR, mode, &vfd);
	if (err) {
		return err;
	}
	err = resolve_by_fd(vfd, &sz, &mode);
	if (err) {
		close_fd(&vfd);
		return err;
	}
	err = vol_size_check(sz);
	if (err) {
		close_fd(&vfd);
		return err;
	}
	if (size == 0) {
		size = sz;
	}
	pstore_setup(pstore, -1, vfd, size, size, VOLUTA_F_BLKDEV);
	return 0;
}

int voluta_pstore_create(struct voluta_pstore *pstore,
			 const char *path, loff_t size)
{
	int err;
	struct stat st;

	if (path == NULL) {
		err = pstore_create_mem(pstore, size);
	} else {
		err = voluta_sys_stat(path, &st);
		if ((err == -ENOENT) || S_ISREG(st.st_mode)) {
			err = pstore_create_reg(pstore, path, size);
		} else if (!err && S_ISBLK(st.st_mode)) {
			err = pstore_create_blk(pstore, path, size);
		} else if (!err && S_ISDIR(st.st_mode)) {
			err = -EISDIR;
		} else if (!err) {
			err = -EINVAL;
		}
	}
	return err;
}

int voluta_pstore_open(struct voluta_pstore *pstore, const char *path, bool rw)
{
	int err;
	int dfd = -1;
	int vfd = -1;
	int flags;
	mode_t mode;
	loff_t size;
	struct voluta_vpath_info vpi;

	err = parse_vpath(&vpi, path);
	if (err) {
		return err;
	}
	err = voluta_sys_open(vpi.dpath, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		return err;
	}
	flags = rw ? O_RDWR : O_RDONLY;
	err = voluta_sys_openat(dfd, vpi.vname, flags, 0, &vfd);
	if (err) {
		close_fd(&dfd);
		return err;
	}
	err = resolve_by_fd(vfd, &size, &mode);
	if (err) {
		close_fds(&vfd, &dfd);
		return err;
	}
	flags = S_ISBLK(mode) ? VOLUTA_F_BLKDEV : 0;
	pstore_setup(pstore, dfd, vfd, size, size, flags);
	return 0;
}

int voluta_pstore_expand(struct voluta_pstore *pstore, loff_t cap)
{
	int err;

	voluta_assert_ge(pstore->ps_capacity, pstore->ps_size);
	if (pstore->ps_capacity >= cap) {
		return 0;
	}
	if (pstore->ps_flags & VOLUTA_F_BLKDEV) {
		return -ENOTSUP;
	}
	err = voluta_sys_ftruncate(pstore->ps_vfd, cap);
	if (err) {
		return err;
	}
	pstore->ps_capacity = cap;
	return 0;
}


static bool pstore_has_open_vfd(const struct voluta_pstore *pstore)
{
	return isopen_fd(pstore->ps_vfd);
}

static bool pstore_has_open_fds(const struct voluta_pstore *pstore)
{
	return isopen_fd(pstore->ps_dfd) && isopen_fd(pstore->ps_vfd);
}

static void pstore_fsync(struct voluta_pstore *pstore)
{
	voluta_sys_fsync(pstore->ps_vfd);
}

static int pstore_close_fds(struct voluta_pstore *pstore)
{
	return close_fds(&pstore->ps_vfd, &pstore->ps_dfd);
}

int voluta_pstore_close(struct voluta_pstore *pstore)
{
	int err = 0;

	if (pstore_has_open_vfd(pstore)) {
		pstore_fsync(pstore);
		err = pstore_close_fds(pstore);
		pstore_setup(pstore, -1, -1, 0, 0, 0);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_pstore_check_io(const struct voluta_pstore *pstore,
			   loff_t off, size_t len)
{
	loff_t end;

	if (!pstore_has_open_vfd(pstore)) {
		return -EIO;
	}
	if (off >= pstore->ps_capacity) {
		return -EIO;
	}
	end = off_end(off, len);
	if ((end < 0) || (end > pstore->ps_capacity)) {
		return -EINVAL;
	}
	return 0;
}

int voluta_pstore_read(const struct voluta_pstore *pstore,
		       loff_t off, size_t bsz, void *buf)
{
	int err;
	size_t nrd = 0;

	err = voluta_pstore_check_io(pstore, off, bsz);
	if (err) {
		return err;
	}
	err = voluta_sys_pread(pstore->ps_vfd, buf, bsz, off, &nrd);
	if (err) {
		return err;
	}
	if (nrd != bsz) {
		return -EIO;
	}
	return 0;
}

static void pstore_post_write(struct voluta_pstore *pstore,
			      loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);

	if (end > pstore->ps_size) {
		pstore->ps_size = end;
	}
	voluta_assert_ge(pstore->ps_capacity, pstore->ps_size);
}

int voluta_pstore_write(struct voluta_pstore *pstore,
			loff_t off, size_t bsz, const void *buf)
{
	int err;

	err = voluta_pstore_check_io(pstore, off, bsz);
	if (err) {
		return err;
	}
	err = voluta_sys_pwriten(pstore->ps_vfd, buf, bsz, off);
	if (err) {
		return err;
	}
	pstore_post_write(pstore, off, bsz);
	return 0;
}

int voluta_pstore_writev(struct voluta_pstore *pstore, loff_t off,
			 size_t len, const struct iovec *iov, size_t cnt)
{
	int err;
	size_t nwr = 0;

	err = voluta_pstore_check_io(pstore, off, len);
	if (err) {
		return err;
	}
	/* TODO: impl voluta_sys_pwritev (like voluta_sys_pwriten) */
	err = voluta_sys_pwritev(pstore->ps_vfd, iov, (int)cnt, off, &nwr);
	if (err) {
		return err;
	}
	if (nwr != len) {
		return -EIO;
	}
	pstore_post_write(pstore, off, nwr);
	return 0;
}

int voluta_pstore_sync(struct voluta_pstore *pstore, bool all)
{
	int err;

	if (all) {
		err = voluta_sys_fsync(pstore->ps_vfd);
	} else {
		err = voluta_sys_fdatasync(pstore->ps_vfd);
	}
	return err;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int flock_volume(int fd)
{
	struct flock fl;

	voluta_memzero(&fl, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	return voluta_sys_fcntl_flock(fd, F_SETLK, &fl);
}

static int funlock_volume(int fd)
{
	struct flock fl;

	voluta_memzero(&fl, sizeof(fl));
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	return voluta_sys_fcntl_flock(fd, F_SETLK, &fl);
}

int voluta_pstore_flock(const struct voluta_pstore *pstore)
{
	int err = -EPERM;

	if (pstore_has_open_vfd(pstore)) {
		err = flock_volume(pstore->ps_vfd);
	}
	return err;
}

int voluta_pstore_funlock(const struct voluta_pstore *pstore)
{
	int err = 0;

	if (pstore_has_open_vfd(pstore)) {
		err = funlock_volume(pstore->ps_vfd);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pstore_prepare_clone(const struct voluta_pstore *pstore,
				const struct voluta_str *name, int *out_fd)
{
	int err;
	loff_t off_out = 0;
	const int dfd = pstore->ps_dfd;
	const int flags = O_CREAT | O_RDWR | O_EXCL;
	const mode_t mode = S_IRUSR | S_IWUSR;
	const loff_t size = pstore->ps_size;

	err = voluta_sys_openat(dfd, name->str, flags, mode, out_fd);
	if (err) {
		log_warn("create failed: dfd=%d name=%s flags=0x%x "\
			 "mode=0%o err=%d", dfd, name->str, flags, mode, err);
		return err;
	}
	err = voluta_sys_ftruncate(*out_fd, size);
	if (err) {
		log_warn("fruncate failed: size=%ld err=%d", size, err);
		voluta_sys_unlinkat(dfd, name->str, 0);
		return err;
	}
	err = voluta_sys_llseek(*out_fd, 0, SEEK_SET, &off_out);
	if (err) {
		log_warn("llseek failed: err=%d", err);
		voluta_sys_unlinkat(dfd, name->str, 0);
		return err;
	}
	return 0;
}

static int pstore_clone_to_fd(const struct voluta_pstore *pstore, int fd)
{
	int err;

	err = voluta_sys_ioctl_ficlone(fd, pstore->ps_vfd);
	if (err) {
		log_warn("ficlone failed: err=%d", err);
	}
	return err;
}

static int pstore_create_clone(const struct voluta_pstore *pstore,
			       const struct voluta_str *name, int *out_fd)
{
	int err;

	err = pstore_prepare_clone(pstore, name, out_fd);
	if (err) {
		return err;
	}
	err = pstore_clone_to_fd(pstore, *out_fd);
	if (err) {
		return err;
	}
	return 0;
}

static void pstore_unlink_clone(const struct voluta_pstore *pstore,
				const struct voluta_str *name)
{
	int err;
	const int dfd = pstore->ps_dfd;

	err = voluta_sys_unlinkat(dfd, name->str, 0);
	if (err) {
		log_err("unlinkat failed: err=%d", err);
	}
}

static int pstore_check_clone(const struct voluta_pstore *pstore,
			      const struct voluta_str *name)
{
	int err;
	struct stat st;

	if (!pstore_has_open_fds(pstore)) {
		return -EBADF;
	}
	err = voluta_sys_fstatat(pstore->ps_dfd, name->str, &st, 0);
	if (!err) {
		return -EEXIST;
	}
	if (err != -ENOENT) {
		return err;
	}
	return 0;
}

int voluta_pstore_clone(const struct voluta_pstore *pstore,
			const struct voluta_str *name)
{
	int err;
	int fd = -1;

	err = pstore_check_clone(pstore, name);
	if (!err) {
		err = pstore_create_clone(pstore, name, &fd);
		if (err && (fd > 0)) {
			pstore_unlink_clone(pstore, name);
		}
		close_fd(&fd);
	}
	return err;
}
