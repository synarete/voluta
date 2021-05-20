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
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <voluta/infra/syscall.h>

static void *buffer_at(const void *buf, size_t step)
{
	union {
		const void *p;
		void *q;
	} u = {
		.p = (const uint8_t *)buf + step
	};

	return u.q;
}

static loff_t offset_at(loff_t base, size_t step)
{
	return base + (loff_t)step;
}

static int io_status(int err, size_t nexpected, size_t ncomplete)
{
	if (err) {
		return err;
	}
	if (nexpected != ncomplete) {
		return -EIO;
	}
	return 0;
}

int voluta_sys_readn(int fd, void *buf, size_t cnt)
{
	int err = 0;
	size_t nrd_cur;
	size_t nrd = 0;
	uint8_t *ptr;

	while (nrd < cnt) {
		ptr = buffer_at(buf, nrd);
		nrd_cur = 0;
		err = voluta_sys_read(fd, ptr, cnt - nrd, &nrd_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	return io_status(err, nrd, cnt);
}

int voluta_sys_preadn(int fd, void *buf, size_t cnt, loff_t off)
{
	int err = 0;
	loff_t pos;
	size_t nrd_cur;
	size_t nrd = 0;
	uint8_t *ptr;

	while (nrd < cnt) {
		ptr = buffer_at(buf, nrd);
		pos = offset_at(off, nrd);
		nrd_cur = 0;
		err = voluta_sys_pread(fd, ptr, cnt - nrd, pos, &nrd_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nrd_cur) {
			break;
		}
		nrd += nrd_cur;
	}
	return io_status(err, nrd, cnt);
}

int voluta_sys_writen(int fd, const void *buf, size_t cnt)
{
	int err = 0;
	size_t nwr_cur;
	size_t nwr = 0;
	const uint8_t *ptr;

	while (nwr < cnt) {
		ptr = buffer_at(buf, nwr);
		nwr_cur = 0;
		err = voluta_sys_write(fd, ptr, cnt - nwr, &nwr_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nwr_cur) {
			break;
		}
		nwr += nwr_cur;
	}
	return io_status(err, nwr, cnt);
}

int voluta_sys_pwriten(int fd, const void *buf, size_t cnt, loff_t off)
{
	int err = 0;
	loff_t pos;
	size_t nwr_cur;
	size_t nwr = 0;
	const uint8_t *ptr;

	while (nwr < cnt) {
		ptr = buffer_at(buf, nwr);
		pos = offset_at(off, nwr);
		nwr_cur = 0;
		err = voluta_sys_pwrite(fd, ptr, cnt - nwr, pos, &nwr_cur);
		if (err == -EINTR) {
			continue;
		}
		if (err || !nwr_cur) {
			break;
		}
		nwr += nwr_cur;
	}
	return io_status(err, nwr, cnt);
}

int voluta_sys_opendir(const char *path, int *out_fd)
{
	return voluta_sys_open(path, O_DIRECTORY | O_RDONLY, 0, out_fd);
}

int voluta_sys_opendirat(int dfd, const char *path, int *out_fd)
{
	return voluta_sys_openat(dfd, path, O_DIRECTORY | O_RDONLY, 0, out_fd);
}

int voluta_sys_closefd(int *pfd)
{
	int err = 0;

	if ((pfd != NULL) && (*pfd > 0)) {
		err = voluta_sys_close(*pfd);
		*pfd = -1;
	}
	return err;
}

int voluta_sys_llseek_data(int fd, loff_t off, loff_t *out_data_off)
{
	int err;
	loff_t pos = 0;

	err = voluta_sys_llseek(fd, off, SEEK_SET, &pos);
	if (err) {
		return err;
	}
	err = voluta_sys_llseek(fd, pos, SEEK_DATA, out_data_off);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_sys_pselect_rfd(int fd, const struct timespec *ts)
{
	int err;
	int nfds = 0;
	fd_set rfds;

	if (fd >= FD_SETSIZE) {
		return -EBADF;
	}
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	err = voluta_sys_pselect(fd + 1, &rfds, NULL, NULL, ts, NULL, &nfds);
	if (err) {
		return err;
	}
	if (!nfds || !FD_ISSET(fd, &rfds)) {
		return -ETIMEDOUT;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sys_readfile(int dfd, const char *filename,
                        void *buf, size_t bsz, int flags, size_t *nrd)
{
	int err;
	int fd = -1;

	(void)flags;
	err = voluta_sys_openat(dfd, filename, O_RDONLY, 0, &fd);
	if (err) {
		return err;
	}
	err = voluta_sys_read(fd, buf, bsz, nrd);
	if (err) {
		voluta_sys_close(fd);
		return err;
	}
	err = voluta_sys_close(fd);
	if (err) {
		return err;
	}
	return 0;
}

static int sys_readproc(const char *procdir, const char *filename,
                        void *buf, size_t bsz, int flags, size_t *nrd)
{
	int err;
	int dfd = -1;

	err = voluta_sys_open(procdir, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		return err;
	}
	err = sys_readfile(dfd, filename, buf, bsz, flags, nrd);
	if (err) {
		voluta_sys_close(dfd);
		return err;
	}
	err = voluta_sys_close(dfd);
	if (err) {
		return err;
	}
	return 0;
}

static int sys_readproc_long(const char *procdir,
                             const char *filename, long *out_value)
{
	int err;
	size_t nrd = 0;
	char buf[128];
	char *end = NULL;

	memset(buf, 0, sizeof(buf));
	err = sys_readproc(procdir, filename, buf, sizeof(buf) - 1, 0, &nrd);
	if (err) {
		return err;
	}
	if (!nrd || !strlen(buf)) {
		return -ENODATA;
	}
	errno = 0;
	*out_value = strtol(buf, &end, 10);
	err = -errno;
	if (err) {
		return err;
	}
	return 0;
}

int voluta_proc_pipe_max_size(long *out_value)
{
	return sys_readproc_long("/proc/sys/fs", "pipe-max-size", out_value);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long voluta_sc_l1_dcache_linesize(void)
{
	return sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
}

long voluta_sc_page_size(void)
{
	return sysconf(_SC_PAGE_SIZE);
}

long voluta_sc_phys_pages(void)
{
	return sysconf(_SC_PHYS_PAGES);
}

long voluta_sc_avphys_pages(void)
{
	return sysconf(_SC_AVPHYS_PAGES);
}

