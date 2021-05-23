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
#ifndef VOLUTA_PIPE_H_
#define VOLUTA_PIPE_H_

#include <stdlib.h>

struct iovec;

struct voluta_pipe {
	int     fd[2];
	size_t  size;
	size_t  pend;
};

struct voluta_nullfd {
	int     fd;
};

void voluta_pipe_init(struct voluta_pipe *pipe);

int voluta_pipe_open(struct voluta_pipe *pipe);

int voluta_pipe_setsize(struct voluta_pipe *pipe, size_t size);

void voluta_pipe_close(struct voluta_pipe *pipe);

void voluta_pipe_fini(struct voluta_pipe *pipe);

int voluta_pipe_splice_from_fd(struct voluta_pipe *pipe,
                               int fd, loff_t *off, size_t len);

int voluta_pipe_vmsplice_from_iov(struct voluta_pipe *pipe,
                                  const struct iovec *iov, size_t niov);

int voluta_pipe_splice_to_fd(struct voluta_pipe *pipe,
                             int fd, loff_t *off, size_t len);

int voluta_pipe_vmsplice_to_iov(struct voluta_pipe *pipe,
                                const struct iovec *iov, size_t niov);

int voluta_pipe_copy_to_buf(struct voluta_pipe *pipe, void *buf, size_t len);

int voluta_pipe_append_from_buf(struct voluta_pipe *pipe,
                                const void *buf, size_t len);

int voluta_pipe_flush_to_fd(struct voluta_pipe *pipe, int fd);

int voluta_pipe_dispose(struct voluta_pipe *pipe,
                        const struct voluta_nullfd *nfd);


int voluta_nullfd_init(struct voluta_nullfd *nfd);

void voluta_nullfd_fini(struct voluta_nullfd *nfd);


int voluta_kcopy_with_splice(struct voluta_pipe *pipe,
                             struct voluta_nullfd *nfd,
                             int fd_in, loff_t *off_in,
                             int fd_out, loff_t *off_out, size_t len);

#endif /* VOLUTA_PIPE_H_ */
