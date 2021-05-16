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
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <voluta/logging.h>
#include <voluta/syscall.h>
#include <voluta/minmax.h>
#include <voluta/pipe.h>


static size_t iov_length(const struct iovec *iov, size_t niov)
{
	size_t len = 0;

	for (size_t i = 0; i < niov; ++i) {
		len += iov[i].iov_len;
	}
	return len;
}

static size_t iov_count_ceil(const struct iovec *iov,
                             size_t niov, size_t len_max)
{
	size_t cnt = 0;
	size_t len = 0;

	for (size_t i = 0; i < niov; ++i) {
		if (len >= len_max) {
			break;
		}
		cnt++;
		len += iov[i].iov_len;
	}
	return cnt;
}

void voluta_pipe_init(struct voluta_pipe *pipe)
{
	pipe->fd[0] = -1;
	pipe->fd[1] = -1;
	pipe->size = 0;
	pipe->pend = 0; /* TODO: maybe use 'ioctl(FIONREAD)' ? */
}

int voluta_pipe_open(struct voluta_pipe *pipe)
{
	int err;
	int pipesz = 0;
	const long pagesz = voluta_sc_page_size();

	err = voluta_sys_pipe2(pipe->fd, O_CLOEXEC | O_NONBLOCK);
	if (err) {
		voluta_log_warn("failed to create pipe: err=%d", err);
		return err;
	}
	err = voluta_sys_fcntl_getpipesz(pipe->fd[0], &pipesz);
	if (err) {
		voluta_log_warn("failed to get pipe-size: err=%d", err);
		voluta_pipe_close(pipe);
		return err;
	}
	if (pipesz < pagesz) {
		voluta_log_warn("illegal pipe-size: pipesz=%d pagesz=%lu",
				pipesz, pagesz);
		voluta_pipe_close(pipe);
		return -EINVAL;
	}
	pipe->size = (size_t)pipesz;
	return 0;
}

int voluta_pipe_setsize(struct voluta_pipe *pipe, size_t size)
{
	int err;

	if (size == pipe->size) {
		return 0; /* no-op */
	}
	err = voluta_sys_fcntl_setpipesz(pipe->fd[0], (int)size);
	if (err) {
		voluta_log_warn("failed to set pipe size: size=%lu err=%d",
				size, err);
		return err;
	}
	pipe->size = size;
	return 0;
}

void voluta_pipe_close(struct voluta_pipe *pipe)
{
	if (pipe->fd[0] > 0) {
		voluta_sys_close(pipe->fd[0]);
		pipe->fd[0] = -1;
	}
	if (pipe->fd[1] > 0) {
		voluta_sys_close(pipe->fd[1]);
		pipe->fd[1] = -1;
	}
}

void voluta_pipe_fini(struct voluta_pipe *pipe)
{
	voluta_pipe_close(pipe);
	pipe->size = 0;
	pipe->pend = 0;
}

static size_t pipe_avail(const struct voluta_pipe *pipe)
{
	return (pipe->size - pipe->pend);
}

int voluta_pipe_splice_from_fd(struct voluta_pipe *pipe,
                               int fd, loff_t *off, size_t len)
{
	int err;
	size_t cnt;
	size_t nsp = 0;
	const loff_t off_in = off ? *off : 0;

	cnt = voluta_min(pipe_avail(pipe), len);
	err = voluta_sys_splice(fd, off, pipe->fd[1], NULL, cnt, 0, &nsp);
	if (err) {
		voluta_log_error("splice-error: fd_in=%d off_in=%ld "\
		                 "fd_out=%d cnt=%lu err=%d", fd, off_in,
		                 pipe->fd[1], cnt, err);
		return err;
	}
	if (nsp > cnt) {
		voluta_log_error("bad-splice: fd_in=%d off_in=%ld fd_out=%d "\
		                 "cnt=%lu nsp=%lu", fd, off_in,
		                 pipe->fd[1], cnt, nsp);
		return -EIO;
	}
	pipe->pend += nsp;
	return 0;
}

int voluta_pipe_vmsplice_from_iov(struct voluta_pipe *pipe,
                                  const struct iovec *iov, size_t niov)
{
	int err;
	size_t cnt;
	size_t nsp = 0;
	const unsigned int splice_flags = SPLICE_F_NONBLOCK;

	cnt = iov_count_ceil(iov, niov, pipe_avail(pipe));
	err = voluta_sys_vmsplice(pipe->fd[1], iov, cnt, splice_flags, &nsp);
	if (err) {
		voluta_log_error("vmsplice-error: fd=%d cnt=%lu "\
		                 "splice_flags=%u err=%d",
		                 pipe->fd[1], cnt, splice_flags, err);
		return err;
	}
	pipe->pend += nsp;
	return 0;
}

int voluta_pipe_splice_to_fd(struct voluta_pipe *pipe,
                             int fd, loff_t *off, size_t len)
{
	int err;
	size_t cnt;
	size_t nsp = 0;
	const loff_t off_out = off ? *off : 0;

	cnt = voluta_min(pipe->pend, len);
	err = voluta_sys_splice(pipe->fd[0], NULL, fd, off, cnt, 0, &nsp);
	if (err) {
		voluta_log_error("splice-error: fd_in=%d fd_out=%d "\
		                 "off_out=%ld cnt=%lu err=%d", pipe->fd[0],
		                 fd, off_out, cnt, err);
		return err;
	}
	if (nsp > pipe->pend) {
		voluta_log_error("bad-splice: fd_in=%d fd_out=%d off_out=%ld"\
		                 "cnt=%lu nsp=%lu", pipe->fd[0], fd, off_out,
		                 cnt, nsp);
		return -EIO;
	}
	pipe->pend -= nsp;
	return 0;
}

int voluta_pipe_vmsplice_to_iov(struct voluta_pipe *pipe,
                                const struct iovec *iov, size_t niov)
{
	int err;
	size_t len;
	size_t cnt;
	size_t nsp = 0;

	cnt = iov_count_ceil(iov, niov, pipe->pend);
	len = iov_length(iov, cnt);
	err = voluta_sys_vmsplice(pipe->fd[0], iov, cnt, 0, &nsp);
	if (err) {
		voluta_log_error("vmsplice-error: fd=%d cnt=%lu err=%d",
		                 pipe->fd[1], cnt, err);
		return err;
	}
	if ((nsp != len) || (nsp > pipe->pend)) {
		voluta_log_error("bad-vmsplice: fd=%d cnt=%lu nsp=%lu",
		                 pipe->fd[1], cnt, nsp);
		return -EIO;
	}
	pipe->pend -= nsp;
	return 0;
}

int voluta_pipe_copy_to_buf(struct voluta_pipe *pipe, void *buf, size_t len)
{
	int err;
	size_t cnt;

	cnt = voluta_min(pipe->pend, len);
	err = voluta_sys_readn(pipe->fd[0], buf, cnt);
	if (err) {
		voluta_log_error("readn-from-pipe: fd=%ld cnt=%lu err=%d",
		                 pipe->fd[0], cnt, err);
		return err;
	}
	pipe->pend -= cnt;
	return 0;
}

int voluta_pipe_append_from_buf(struct voluta_pipe *pipe,
                                const void *buf, size_t len)
{
	int err;
	size_t cnt;

	cnt = voluta_min(pipe->size, len);
	err = voluta_sys_writen(pipe->fd[1], buf, cnt);
	if (err) {
		voluta_log_error("writen-to-pipe: fd=%ld cnt=%lu err=%d",
		                 pipe->fd[1], cnt, err);
		return err;
	}
	pipe->pend += cnt;
	return 0;
}

int voluta_pipe_flush_to_fd(struct voluta_pipe *pipe, int fd)
{
	return (pipe->pend > 0) ?
	       voluta_pipe_splice_to_fd(pipe, fd, NULL, pipe->pend) : 0;
}

int voluta_pipe_purge(struct voluta_pipe *pipe,
                      const struct voluta_nullfd *nfd)
{
	return voluta_pipe_flush_to_fd(pipe, nfd->fd);
}

int voluta_pipe_kcopy(struct voluta_pipe *pipe, int fd_in, loff_t *off_in,
                      int fd_out, loff_t *off_out, size_t len)
{
	int err;

	err = voluta_pipe_splice_from_fd(pipe, fd_in, off_in, len);
	if (err) {
		return err;
	}
	err = voluta_pipe_splice_to_fd(pipe, fd_out, off_out, len);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_nullfd_init(struct voluta_nullfd *nfd)
{
	int err;
	const int o_flags = O_WRONLY | O_CREAT | O_TRUNC;
	const char *path = "/dev/null";

	err = voluta_sys_open(path, o_flags, 0666, &nfd->fd);
	if (err) {
		voluta_log_warn("failed to open '%s': o_flags=%o err=%d",
		                path, o_flags, err);
	}
	return err;
}

void voluta_nullfd_fini(struct voluta_nullfd *nfd)
{
	voluta_sys_closefd(&nfd->fd);
}

