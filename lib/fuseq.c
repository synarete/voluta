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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/fuse.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include "libvoluta.h"

#if FUSE_KERNEL_VERSION != 7
#error "unsupported FUSE_KERNEL_VERSION"
#endif
#if FUSE_KERNEL_MINOR_VERSION < 31
#error "unsupported FUSE_KERNEL_MINOR_VERSION"
#endif

#define VOLUTA_IO_NBK_MAX \
	(VOLUTA_FILE_HEAD_NLEAVES + (VOLUTA_IO_SIZE_MAX / VOLUTA_BK_SIZE))


#define VOLUTA_CMD_TAIL_MAX \
	(VOLUTA_IO_SIZE_MAX - sizeof(struct fuse_in_header))
#define VOLUTA_CMD_FORGET_ONE_MAX \
	(VOLUTA_CMD_TAIL_MAX / sizeof(struct fuse_forget_one))


/* Local types */
struct voluta_fuseq_hdr_in {
	struct fuse_in_header   hdr;
};

struct voluta_fuseq_cmd_in {
	struct fuse_in_header   hdr;
	char cmd[VOLUTA_IO_SIZE_MAX];
};

struct voluta_fuseq_init_in {
	struct fuse_in_header   hdr;
	struct fuse_init_in     arg;
};

struct voluta_fuseq_setattr_in {
	struct fuse_in_header   hdr;
	struct fuse_setattr_in  arg;
};

struct voluta_fuseq_lookup_in {
	struct fuse_in_header   hdr;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_forget_in {
	struct fuse_in_header   hdr;
	struct fuse_forget_in   arg;
};

struct voluta_fuseq_batch_forget_in {
	struct fuse_in_header   hdr;
	struct fuse_batch_forget_in arg;
	struct fuse_forget_one  one[VOLUTA_CMD_FORGET_ONE_MAX];
};

struct voluta_fuseq_getattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getattr_in  arg;
};

struct voluta_fuseq_symlink_in {
	struct fuse_in_header   hdr;
	char name_target[VOLUTA_NAME_MAX + 1 + VOLUTA_SYMLNK_MAX];
};

struct voluta_fuseq_mknod_in {
	struct fuse_in_header   hdr;
	struct fuse_mknod_in    arg;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_mkdir_in {
	struct fuse_in_header   hdr;
	struct fuse_mkdir_in    arg;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_unlink_in {
	struct fuse_in_header   hdr;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_rmdir_in {
	struct fuse_in_header   hdr;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_rename_in {
	struct fuse_in_header   hdr;
	struct fuse_rename_in   arg;
	char name_newname[2 * (VOLUTA_NAME_MAX + 1)];
};

struct voluta_fuseq_link_in {
	struct fuse_in_header   hdr;
	struct fuse_link_in     arg;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_open_in {
	struct fuse_in_header   hdr;
	struct fuse_open_in     arg;
};

struct voluta_fuseq_release_in {
	struct fuse_in_header   hdr;
	struct fuse_release_in  arg;
};

struct voluta_fuseq_fsync_in {
	struct fuse_in_header   hdr;
	struct fuse_fsync_in    arg;
};

struct voluta_fuseq_setxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_setxattr_in arg;
	char name_value[VOLUTA_NAME_MAX + 1 + VOLUTA_SYMLNK_MAX];
};

struct voluta_fuseq_getxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getxattr_in arg;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_listxattr_in {
	struct fuse_in_header   hdr;
	struct fuse_getxattr_in arg;
};

struct voluta_fuseq_removexattr_in {
	struct fuse_in_header   hdr;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_flush_in {
	struct fuse_in_header   hdr;
	struct fuse_flush_in    arg;
};

struct voluta_fuseq_opendir_in {
	struct fuse_in_header   hdr;
	struct fuse_open_in     arg;
};

struct voluta_fuseq_readdir_in {
	struct fuse_in_header   hdr;
	struct fuse_read_in     arg;
};

struct voluta_fuseq_releasedir_in {
	struct fuse_in_header   hdr;
	struct fuse_release_in  arg;
};

struct voluta_fuseq_fsyncdir_in {
	struct fuse_in_header   hdr;
	struct fuse_fsync_in    arg;
};

struct voluta_fuseq_access_in {
	struct fuse_in_header   hdr;
	struct fuse_access_in   arg;
};

struct voluta_fuseq_create_in {
	struct fuse_in_header   hdr;
	struct fuse_create_in   arg;
	char name[VOLUTA_NAME_MAX + 1];
};

struct voluta_fuseq_ioctl_in {
	struct fuse_in_header   hdr;
	struct fuse_ioctl_in    arg;
	char buf[VOLUTA_PAGE_SIZE];
};

struct voluta_fuseq_fallocate_in {
	struct fuse_in_header   hdr;
	struct fuse_fallocate_in arg;
};

struct voluta_fuseq_rename2_in {
	struct fuse_in_header   hdr;
	struct fuse_rename2_in  arg;
	char name_newname[2 * (VOLUTA_NAME_MAX + 1)];
};

struct voluta_fuseq_lseek_in {
	struct fuse_in_header   hdr;
	struct fuse_lseek_in    arg;
};

struct voluta_fuseq_read_in {
	struct fuse_in_header   hdr;
	struct fuse_read_in     arg;
};

struct voluta_fuseq_write_in {
	struct fuse_in_header   hdr;
	struct fuse_write_in    arg;
	char buf[VOLUTA_BK_SIZE];
};

struct voluta_fuseq_write_iter_in {
	struct fuse_in_header   hdr;
	struct fuse_write_in    arg;
};

struct voluta_fuseq_copy_file_range_in {
	struct fuse_in_header   hdr;
	struct fuse_copy_file_range_in arg;
};


union voluta_fuseq_in_u {
	struct voluta_fuseq_hdr_in              hdr;
	struct voluta_fuseq_cmd_in              cmd;
	struct voluta_fuseq_init_in             init;
	struct voluta_fuseq_setattr_in          setattr;
	struct voluta_fuseq_lookup_in           lookup;
	struct voluta_fuseq_forget_in           forget;
	struct voluta_fuseq_batch_forget_in     batch_forget;
	struct voluta_fuseq_getattr_in          getattr;
	struct voluta_fuseq_symlink_in          symlink;
	struct voluta_fuseq_mknod_in            mknod;
	struct voluta_fuseq_mkdir_in            mkdir;
	struct voluta_fuseq_unlink_in           unlink;
	struct voluta_fuseq_rmdir_in            rmdir;
	struct voluta_fuseq_rename_in           rename;
	struct voluta_fuseq_link_in             link;
	struct voluta_fuseq_open_in             open;
	struct voluta_fuseq_release_in          release;
	struct voluta_fuseq_fsync_in            fsync;
	struct voluta_fuseq_setxattr_in         setxattr;
	struct voluta_fuseq_getxattr_in         getxattr;
	struct voluta_fuseq_listxattr_in        listxattr;
	struct voluta_fuseq_removexattr_in      removexattr;
	struct voluta_fuseq_flush_in            flush;
	struct voluta_fuseq_opendir_in          opendir;
	struct voluta_fuseq_readdir_in          readdir;
	struct voluta_fuseq_releasedir_in       releasedir;
	struct voluta_fuseq_fsyncdir_in         fsyncdir;
	struct voluta_fuseq_access_in           access;
	struct voluta_fuseq_create_in           create;
	struct voluta_fuseq_ioctl_in            ioctl;
	struct voluta_fuseq_fallocate_in        fallocate;
	struct voluta_fuseq_rename2_in          rename2;
	struct voluta_fuseq_lseek_in            lseek;
	struct voluta_fuseq_read_in             read;
	struct voluta_fuseq_write_in            write;
	struct voluta_fuseq_write_iter_in       write_iter;
	struct voluta_fuseq_copy_file_range_in  copy_file_range;
};

struct voluta_fuseq_in {
	union voluta_fuseq_in_u u;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_fuseq_diter {
	char   buf[8 * VOLUTA_UKILO];
	struct voluta_namebuf de_name;
	struct voluta_readdir_ctx rd_ctx;
	size_t bsz;
	size_t len;
	size_t ndes;
	struct stat de_attr;
	loff_t de_off;
	size_t de_nlen;
	ino_t  de_ino;
	mode_t de_dt;
	int    plus;
};

struct voluta_fuseq_xiter {
	struct voluta_listxattr_ctx lxa;
	size_t cnt;
	const char *beg;
	const char *end;
	char *cur;
	char buf[64 * VOLUTA_UKILO];
};

struct voluta_fuseq_wr_iter {
	struct voluta_rwiter_ctx rwi;
	struct voluta_fuseq_ctx *fqc;
	size_t nwr;
	size_t nwr_max;
};

struct voluta_fuseq_rd_iter {
	struct voluta_fiovec fiov[VOLUTA_IO_NBK_MAX];
	struct voluta_rwiter_ctx rwi;
	struct voluta_fuseq_ctx *fqc;
	size_t cnt;
	size_t nrd;
	size_t nrd_max;
};

union voluta_fuseq_inb_u {
	struct voluta_fuseq_in in;
	uint8_t b[VOLUTA_PAGE_SIZE + VOLUTA_IO_SIZE_MAX];
};

struct voluta_fuseq_inb {
	union voluta_fuseq_inb_u u;
};


struct voluta_fuseq_databuf {
	uint8_t buf[VOLUTA_IO_SIZE_MAX];
};

struct voluta_fuseq_pathbuf {
	char path[VOLUTA_PATH_MAX];
};

struct voluta_fuseq_xattrbuf {
	char value[VOLUTA_XATTR_VALUE_MAX];
};

union voluta_fuseq_outb_u {
	uint8_t b[VOLUTA_IO_SIZE_MAX];
	struct voluta_fuseq_databuf  dab;
	struct voluta_fuseq_pathbuf  pab;
	struct voluta_fuseq_xattrbuf xab;
	struct voluta_fuseq_xiter    xit;
	struct voluta_fuseq_diter    dit;
	struct voluta_fuseq_rd_iter  rdi;
};

struct voluta_fuseq_outb {
	union voluta_fuseq_outb_u u;
};


typedef void (*voluta_fuseq_hook)(struct voluta_fuseq_ctx *, ino_t,
				  const struct voluta_fuseq_in *);

struct voluta_fuseq_cmd {
	voluta_fuseq_hook hook;
	const char *name;
	int code;
	int realtime;
};


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

static void pipe_init(struct voluta_pipe *pipe)
{
	pipe->fd[0] = -1;
	pipe->fd[1] = -1;
	pipe->size = 0;
	pipe->pend = 0; /* TODO: maybe use 'ioctl(FIONREAD)' ? */
}

static int pipe_open(struct voluta_pipe *pipe)
{
	int err;
	size_t pgsz;

	err = voluta_sys_pipe2(pipe->fd, O_CLOEXEC | O_NONBLOCK);
	if (err) {
		return err;
	}
	pgsz = voluta_sc_page_size();
	pipe->size = pgsz * 16; /* Linux default ? */
	return 0;
}

static int pipe_setsize(struct voluta_pipe *pipe, size_t size)
{
	int err;

	err = voluta_sys_fcntl_setpipesz(pipe->fd[0], size);
	if (!err) {
		pipe->size = size;
	}
	return err;
}

static void pipe_close(struct voluta_pipe *pipe)
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

static void pipe_fini(struct voluta_pipe *pipe)
{
	pipe_close(pipe);
	pipe->size = 0;
	pipe->pend = 0;
}

static size_t pipe_avail(const struct voluta_pipe *pipe)
{
	voluta_assert_le(pipe->pend, pipe->size);

	return (pipe->size - pipe->pend);
}

static int pipe_splice_from_fd(struct voluta_pipe *pipe,
			       int fd, loff_t *off, size_t len)
{
	int err;
	size_t cnt;
	size_t nsp = 0;
	const loff_t off_in = off ? *off : 0;

	voluta_assert_le(pipe->pend, pipe->size);

	cnt = min(pipe_avail(pipe), len);
	err = voluta_sys_splice(fd, off, pipe->fd[1], NULL, cnt, 0, &nsp);
	if (err) {
		log_err("splice-error: fd_in=%d off_in=%ld fd_out=%d "\
			"cnt=%lu err=%d", fd, off_in, pipe->fd[1], cnt, err);
		return err;
	}
	if (nsp > cnt) {
		log_err("bad-splice: fd_in=%d off_in=%ld fd_out=%d "\
			"cnt=%lu nsp=%lu", fd, off_in, pipe->fd[1], cnt, nsp);
		return -EIO;
	}
	pipe->pend += nsp;
	return 0;
}

static int pipe_vmsplice_from_iov(struct voluta_pipe *pipe,
				  const struct iovec *iov, size_t niov)
{
	int err;
	size_t cnt;
	size_t nsp = 0;

	cnt = iov_count_ceil(iov, niov, pipe_avail(pipe));
	err = voluta_sys_vmsplice(pipe->fd[1], iov, cnt, 0, &nsp);
	if (err) {
		log_err("vmsplice-error: fd=%d cnt=%lu err=%d",
			pipe->fd[1], cnt, err);
		return err;
	}
	pipe->pend += nsp;
	return 0;
}

static int pipe_splice_to_fd(struct voluta_pipe *pipe,
			     int fd, loff_t *off, size_t len)
{
	int err;
	size_t cnt;
	size_t nsp = 0;
	const loff_t off_out = off ? *off : 0;

	cnt = min(pipe->pend, len);
	err = voluta_sys_splice(pipe->fd[0], NULL, fd, off, cnt, 0, &nsp);
	if (err) {
		log_err("splice-error: fd_in=%d fd_out=%d off_out=%ld"\
			"cnt=%lu err=%d", pipe->fd[0], fd, off_out, cnt, err);
		return err;
	}
	if (nsp > pipe->pend) {
		log_err("bad-splice: fd_in=%d fd_out=%d off_out=%ld"\
			"cnt=%lu nsp=%lu", pipe->fd[0], fd, off_out, cnt, nsp);
		return -EIO;
	}
	pipe->pend -= nsp;
	return 0;
}

static int pipe_vmsplice_to_iov(struct voluta_pipe *pipe,
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
		log_err("vmsplice-error: fd=%d cnt=%lu err=%d",
			pipe->fd[1], cnt, err);
		return err;
	}
	if ((nsp != len) || (nsp > pipe->pend)) {
		log_err("bad-vmsplice: fd=%d cnt=%lu nsp=%lu",
			pipe->fd[1], cnt, nsp);
		return -EIO;
	}
	pipe->pend -= nsp;
	return 0;
}

static int pipe_copy_to_buf(struct voluta_pipe *pipe,
			    void *buf, size_t len)
{
	int err;
	size_t cnt;

	cnt = min(pipe->pend, len);
	err = voluta_sys_readn(pipe->fd[0], buf, cnt);
	if (err) {
		log_err("readn-from-pipe: fd=%ld cnt=%lu err=%d",
			pipe->fd[0], cnt, err);
		return err;
	}
	pipe->pend -= cnt;
	return 0;
}

static int pipe_append_from_buf(struct voluta_pipe *pipe,
				const void *buf, size_t len)
{
	int err;
	size_t cnt;

	cnt = min(pipe->size, len);
	err = voluta_sys_writen(pipe->fd[1], buf, cnt);
	if (err) {
		log_err("writen-to-pipe: fd=%ld cnt=%lu err=%d",
			pipe->fd[1], cnt, err);
		return err;
	}
	pipe->pend += cnt;
	return 0;
}

static int pipe_flush_to_fd(struct voluta_pipe *pipe, int fd)
{
	return (pipe->pend > 0) ?
	       pipe_splice_to_fd(pipe, fd, NULL, pipe->pend) : 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const void *after_name(const char *name)
{
	return name + strlen(name) + 1;
}

static void timespec_to_fuse_attr(const struct timespec *ts,
				  uint64_t *sec, uint32_t *nsec)
{
	*sec = (uint64_t)ts->tv_sec;
	*nsec = (uint32_t)ts->tv_nsec;
}

static void fuse_attr_to_timespec(uint64_t sec, uint32_t nsec,
				  struct timespec *ts)
{
	ts->tv_sec = (time_t)sec;
	ts->tv_nsec = (long)nsec;
}

static void stat_to_fuse_attr(const struct stat *st, struct fuse_attr *attr)
{
	memset(attr, 0, sizeof(*attr));
	attr->ino = st->st_ino;
	attr->mode = st->st_mode;
	attr->nlink = (uint32_t)st->st_nlink;
	attr->uid = st->st_uid;
	attr->gid = st->st_gid;
	attr->rdev = (uint32_t)st->st_rdev;
	attr->size = (uint64_t)st->st_size;
	attr->blksize = (uint32_t)st->st_blksize;
	attr->blocks = (uint64_t)st->st_blocks;
	timespec_to_fuse_attr(&st->st_atim, &attr->atime, &attr->atimensec);
	timespec_to_fuse_attr(&st->st_mtim, &attr->mtime, &attr->mtimensec);
	timespec_to_fuse_attr(&st->st_ctim, &attr->ctime, &attr->ctimensec);
}

static void
fuse_setattr_to_stat(const struct fuse_setattr_in *attr, struct stat *st)
{
	memset(st, 0, sizeof(*st));
	st->st_mode = attr->mode;
	st->st_uid = attr->uid;
	st->st_gid = attr->gid;
	st->st_size = (loff_t)attr->size;
	fuse_attr_to_timespec(attr->atime, attr->atimensec, &st->st_atim);
	fuse_attr_to_timespec(attr->mtime, attr->mtimensec, &st->st_mtim);
	fuse_attr_to_timespec(attr->ctime, attr->ctimensec, &st->st_ctim);
}

static void
statfs_to_fuse_kstatfs(const struct statvfs *stv, struct fuse_kstatfs *kstfs)
{
	kstfs->bsize = (uint32_t)stv->f_bsize;
	kstfs->frsize = (uint32_t)stv->f_frsize;
	kstfs->blocks = stv->f_blocks;
	kstfs->bfree = stv->f_bfree;
	kstfs->bavail = stv->f_bavail;
	kstfs->files = stv->f_files;
	kstfs->ffree = stv->f_ffree;
	kstfs->namelen = (uint32_t)stv->f_namemax;
}

static void fill_fuse_entry(struct fuse_entry_out *ent, const struct stat *st)
{
	memset(ent, 0, sizeof(*ent));
	ent->nodeid = st->st_ino;
	ent->generation = 0;
	ent->entry_valid = UINT_MAX;
	ent->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &ent->attr);
}

static void fill_fuse_attr(struct fuse_attr_out *attr, const struct stat *st)
{
	memset(attr, 0, sizeof(*attr));
	attr->attr_valid = UINT_MAX;
	stat_to_fuse_attr(st, &attr->attr);
}

static void fill_fuse_open(struct fuse_open_out *open)
{
	memset(open, 0, sizeof(*open));
	open->open_flags = FOPEN_KEEP_CACHE | FOPEN_CACHE_DIR;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
check_fh(const struct voluta_fuseq_ctx *fqc, ino_t ino, uint64_t fh)
{
	if (fh != 0) {
		log_warn("op=%s ino=%lu fh=0x%lx", fqc->cmd->name, ino, fh);
	}
}

static void fuseq_set_chan_err(struct voluta_fuseq *fq, int chan_err)
{
	fq->fq_chan_err = chan_err;
}

static int fuseq_get_chan_err(const struct voluta_fuseq *fq)
{
	return fq->fq_chan_err;
}

static void fuseq_fill_out_header(struct voluta_fuseq_ctx *fqc,
				  struct fuse_out_header *out_hdr,
				  size_t len, int err)
{
	out_hdr->len = (uint32_t)len;
	out_hdr->error = -abs(err);
	out_hdr->unique = fqc->op.unique;

	voluta_assert_gt(fqc->op.unique, 0);
	voluta_assert_gt(fqc->op.opcode, 0);
}

static void fuseq_send_msg(struct voluta_fuseq_ctx *fqc,
			   const struct iovec *iov, size_t iovcnt)
{
	int err;
	size_t nwr = 0;
	struct voluta_fuseq *fq = fqc->fq;

	voluta_assert(fqc->fq->fq_mount);
	err = voluta_sys_writev(fq->fq_fuse_fd, iov, (int)iovcnt, &nwr);

	/* XXX */
	voluta_assert_ok(err);
	voluta_assert_gt(nwr, 0);

	if (!fqc->fq->fq_umount) {
		/* XXX */
		voluta_assert_ok(err);
		voluta_assert_gt(nwr, 0);
	}

	fuseq_set_chan_err(fq, err);
}

static void fuseq_reply_arg(struct voluta_fuseq_ctx *fqc,
			    const void *arg, size_t argsz)
{
	struct iovec iov[2];
	struct fuse_out_header hdr;
	const size_t hdrsz = sizeof(hdr);
	size_t cnt = 1;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsz;
	if (argsz) {
		iov[1].iov_base = unconst(arg);
		iov[1].iov_len = argsz;
		cnt = 2;
	}
	fuseq_fill_out_header(fqc, &hdr, hdrsz + argsz, 0);
	fuseq_send_msg(fqc, iov, cnt);
}

static void fuseq_reply_arg2(struct voluta_fuseq_ctx *fqc,
			     const void *arg, size_t argsz,
			     const void *buf, size_t bufsz)
{
	struct iovec iov[3];
	struct fuse_out_header hdr;
	const size_t hdrsz = sizeof(hdr);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsz;
	iov[1].iov_base = unconst(arg);
	iov[1].iov_len = argsz;
	iov[2].iov_base = unconst(buf);
	iov[2].iov_len = bufsz;

	fuseq_fill_out_header(fqc, &hdr, hdrsz + argsz + bufsz, 0);
	fuseq_send_msg(fqc, iov, 3);
}

static void fuseq_reply_buf(struct voluta_fuseq_ctx *fqc,
			    const void *buf, size_t bsz)
{
	fuseq_reply_arg(fqc, buf, bsz);
}

static void fuseq_reply_err(struct voluta_fuseq_ctx *fqc, int err)
{
	struct iovec iov[1];
	struct fuse_out_header hdr;
	const size_t hdrsize = sizeof(hdr);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsize;

	fuseq_fill_out_header(fqc, &hdr, hdrsize, err);
	fuseq_send_msg(fqc, iov, 1);
}

static void fuseq_reply_status(struct voluta_fuseq_ctx *fqc, int status)
{
	fuseq_reply_err(fqc, status);
}

static void fuseq_reply_none(struct voluta_fuseq_ctx *fqc)
{
	fqc->op.unique = 0;
}

static void fuseq_reply_entry_ok(struct voluta_fuseq_ctx *fqc,
				 const struct stat *st)
{
	struct fuse_entry_out arg;

	fill_fuse_entry(&arg, st);
	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_create_ok(struct voluta_fuseq_ctx *fqc,
				  const struct stat *st)
{
	struct fuseq_create_out {
		struct fuse_entry_out ent;
		struct fuse_open_out  open;
	} voluta_packed_aligned16 arg;

	fill_fuse_entry(&arg.ent, st);
	fill_fuse_open(&arg.open);
	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_attr_ok(struct voluta_fuseq_ctx *fqc,
				const struct stat *st)
{
	struct fuse_attr_out arg;

	fill_fuse_attr(&arg, st);
	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_statfs_ok(struct voluta_fuseq_ctx *fqc,
				  const struct statvfs *stv)
{
	struct fuse_statfs_out arg;

	statfs_to_fuse_kstatfs(stv, &arg.st);
	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_buf_ok(struct voluta_fuseq_ctx *fqc,
			       const char *buf, size_t bsz)
{
	fuseq_reply_arg(fqc, buf, bsz);
}

static void fuseq_reply_readlink_ok(struct voluta_fuseq_ctx *fqc,
				    const char *lnk, size_t len)
{
	fuseq_reply_buf_ok(fqc, lnk, len);
}

static void fuseq_reply_open_ok(struct voluta_fuseq_ctx *fqc)
{
	struct fuse_open_out arg;

	fill_fuse_open(&arg);
	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_opendir_ok(struct voluta_fuseq_ctx *fqc)
{
	fuseq_reply_open_ok(fqc);
}

static void fuseq_reply_write_ok(struct voluta_fuseq_ctx *fqc, size_t cnt)
{
	struct fuse_write_out arg = {
		.size = (uint32_t)cnt
	};

	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_lseek_ok(struct voluta_fuseq_ctx *fqc, loff_t off)
{
	struct fuse_lseek_out arg = {
		.offset = (uint64_t)off
	};

	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_xattr_len(struct voluta_fuseq_ctx *fqc, size_t len)
{
	struct fuse_getxattr_out arg = {
		.size = (uint32_t)len
	};

	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_xattr_buf(struct voluta_fuseq_ctx *fqc,
				  const void *buf, size_t len)
{
	fuseq_reply_buf(fqc, buf, len);
}

static void fuseq_reply_init_ok(struct voluta_fuseq_ctx *fqc,
				const struct voluta_fuseq_conn_info *coni)
{
	struct fuse_init_out arg = {
		.major = FUSE_KERNEL_VERSION,
		.minor = FUSE_KERNEL_MINOR_VERSION,
		.flags = 0
	};

	if (coni->cap_kern & FUSE_MAX_PAGES) {
		arg.flags |= FUSE_MAX_PAGES;
		arg.max_pages =
			(uint16_t)((coni->max_write - 1) / coni->pagesize + 1);
	}
	arg.flags |= FUSE_BIG_WRITES;
	arg.flags |= (uint32_t)coni->cap_want;
	arg.max_readahead = (uint32_t)coni->max_readahead;
	arg.max_write = (uint32_t)coni->max_write;
	arg.max_background = (uint16_t)coni->max_background;
	arg.congestion_threshold = (uint16_t)coni->congestion_threshold;
	arg.time_gran = (uint32_t)coni->time_gran;

	fuseq_reply_arg(fqc, &arg, sizeof(arg));
}

static void fuseq_reply_ioctl_ok(struct voluta_fuseq_ctx *fqc, int result,
				 const void *buf, size_t size)
{
	struct fuse_ioctl_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;

	if (size) {
		fuseq_reply_arg2(fqc, &arg, sizeof(arg), buf, size);
	} else {
		fuseq_reply_arg(fqc, &arg, sizeof(arg));
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fuseq_reply_attr(struct voluta_fuseq_ctx *fqc,
			     const struct stat *st, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_attr_ok(fqc, st);
	}
}

static void fuseq_reply_entry(struct voluta_fuseq_ctx *fqc,
			      const struct stat *st, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_entry_ok(fqc, st);
	}
}

static void fuseq_reply_create(struct voluta_fuseq_ctx *fqc,
			       const struct stat *st, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_create_ok(fqc, st);
	}
}

static void fuseq_reply_readlink(struct voluta_fuseq_ctx *fqc,
				 const char *lnk, size_t len, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_readlink_ok(fqc, lnk, len);
	}
}

static void fuseq_reply_statfs(struct voluta_fuseq_ctx *fqc,
			       const struct statvfs *stv, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_statfs_ok(fqc, stv);
	}
}

static void fuseq_reply_open(struct voluta_fuseq_ctx *fqc, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_open_ok(fqc);
	}
}

static void fuseq_reply_xattr(struct voluta_fuseq_ctx *fqc,
			      const void *buf, size_t len, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else if (buf == NULL) {
		fuseq_reply_xattr_len(fqc, len);
	} else {
		fuseq_reply_xattr_buf(fqc, buf, len);
	}
}

static void fuseq_reply_opendir(struct voluta_fuseq_ctx *fqc, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_opendir_ok(fqc);
	}
}

static void fuseq_reply_readdir(struct voluta_fuseq_ctx *fqc,
				const struct voluta_fuseq_diter *di, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_buf(fqc, di->buf, di->len);
	}
}

static void fuseq_reply_lseek(struct voluta_fuseq_ctx *fqc,
			      loff_t off, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_lseek_ok(fqc, off);
	}
}

static void fuseq_reply_copy_file_range(struct voluta_fuseq_ctx *fqc,
					size_t cnt, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_write_ok(fqc, cnt);
	}
}

static void fuseq_reply_init(struct voluta_fuseq_ctx *fqc, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_init_ok(fqc, &fqc->fq->fq_coni);
	}
}

static void fuseq_reply_ioctl(struct voluta_fuseq_ctx *fqc, int result,
			      const void *buf, size_t size, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_ioctl_ok(fqc, result, buf, size);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fuseq_reply_write(struct voluta_fuseq_ctx *fqc,
			      size_t cnt, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_write_ok(fqc, cnt);
	}
}

static void fuseq_reply_read_buf(struct voluta_fuseq_ctx *fqc,
				 const void *dat, size_t len, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_buf_ok(fqc, dat, len);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_append_hdr_to_pipe(struct voluta_fuseq_ctx *fqc, size_t len)
{
	struct fuse_out_header hdr;
	struct voluta_pipe *pipe = &fqc->fq->fq_pipe;

	fuseq_fill_out_header(fqc, &hdr,  sizeof(hdr) + len, 0);
	return pipe_append_from_buf(pipe, &hdr, sizeof(hdr));
}


static int fuseq_append_to_pipe_by_fd(struct voluta_fuseq_ctx *fqc,
				      const struct voluta_fiovec *fiov)
{
	struct voluta_pipe *pipe = &fqc->fq->fq_pipe;
	size_t len = fiov->len;
	loff_t off = fiov->off;

	return pipe_splice_from_fd(pipe, fiov->fd, &off, len);
}

static int fuseq_append_to_pipe_by_iov(struct voluta_fuseq_ctx *fqc,
				       const struct voluta_fiovec *fiov)
{
	struct voluta_pipe *pipe = &fqc->fq->fq_pipe;
	struct iovec iov = {
		.iov_base = fiov->mm,
		.iov_len = fiov->len
	};
	return pipe_vmsplice_from_iov(pipe, &iov, 1);
}

static int
fuseq_append_data_to_pipe(struct voluta_fuseq_ctx *fqc,
			  const struct voluta_fiovec *fiov, size_t cnt)
{
	int err = 0;

	for (size_t i = 0; (i < cnt) && !err; ++i) {
		if (fiov[i].mm != NULL) {
			err = fuseq_append_to_pipe_by_iov(fqc, &fiov[i]);
		} else {
			err = fuseq_append_to_pipe_by_fd(fqc, &fiov[i]);
		}
	}
	return err;
}

static int
fuseq_append_response_to_pipe(struct voluta_fuseq_ctx *fqc, size_t nrd,
			      const struct voluta_fiovec *fiov, size_t cnt)
{
	int err;

	err = fuseq_append_hdr_to_pipe(fqc, nrd);
	if (err) {
		return err;
	}
	err = fuseq_append_data_to_pipe(fqc, fiov, cnt);
	if (err) {
		return err;
	}
	return 0;
}

static int fuseq_send_response_out(struct voluta_fuseq_ctx *fqc)
{
	struct voluta_pipe *pipe = &fqc->fq->fq_pipe;

	return pipe_flush_to_fd(pipe, fqc->fq->fq_fuse_fd);
}

static void fuseq_reply_read_pipe(struct voluta_fuseq_ctx *fqc, size_t nrd,
				  const struct voluta_fiovec *fiov, size_t cnt)
{
	int err;

	err = fuseq_append_response_to_pipe(fqc, nrd, fiov, cnt);
	if (err) {
		fuseq_reply_err(fqc, err);
		return;
	}
	err = fuseq_send_response_out(fqc);
	if (err) {
		fuseq_set_chan_err(fqc->fq, err);
	}
}

static void fuseq_reply_read_data(struct voluta_fuseq_ctx *fqc, size_t nrd,
				  const struct voluta_fiovec *fiov)
{
	fuseq_reply_arg(fqc, fiov->mm, nrd);
}

static void fuseq_reply_read_ok(struct voluta_fuseq_ctx *fqc, size_t nrd,
				const struct voluta_fiovec *fiov, size_t cnt)
{
	if ((cnt > 1) || (fiov->mm == NULL)) {
		fuseq_reply_read_pipe(fqc, nrd, fiov, cnt);
	} else {
		fuseq_reply_read_data(fqc, nrd, fiov);
	}
}

static void fuseq_reply_read_iter(struct voluta_fuseq_ctx *fqc, size_t nrd,
				  const struct voluta_fiovec *fiov,
				  size_t cnt, int err)
{
	if (unlikely(err)) {
		fuseq_reply_err(fqc, err);
	} else {
		fuseq_reply_read_ok(fqc, nrd, fiov, cnt);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_fuseq_xiter *xiter_of(struct voluta_listxattr_ctx *p)
{
	return container_of(p, struct voluta_fuseq_xiter, lxa);
}

static size_t xiter_avail(const struct voluta_fuseq_xiter *xi)
{
	return (size_t)(xi->end - xi->cur);
}

static bool xiter_hasroom(const struct voluta_fuseq_xiter *xi, size_t size)
{
	const size_t avail = xiter_avail(xi);

	return (avail >= size);
}

static int fillxent(struct voluta_listxattr_ctx *lsx,
		    const char *name, size_t nlen)
{
	const size_t size = nlen + 1;
	struct voluta_fuseq_xiter *xi = xiter_of(lsx);

	if (xi->cur) {
		if (!xiter_hasroom(xi, size)) {
			return -ERANGE;
		}
		memcpy(xi->cur, name, nlen);
		xi->cur[nlen] = '\0';
		xi->cur += size;
	}
	xi->cnt += size;
	return 0;
}

static void xiter_prep(struct voluta_fuseq_xiter *xi, size_t size)
{
	xi->lxa.actor = fillxent;
	xi->cnt = 0;

	if (size > 0) {
		xi->beg = xi->buf;
		xi->end = xi->beg + min(size, sizeof(xi->buf));
		xi->cur = xi->buf;
	} else {
		xi->beg = NULL;
		xi->end = NULL;
		xi->cur = NULL;
	}
}

static void xiter_done(struct voluta_fuseq_xiter *xi)
{
	xi->lxa.actor = NULL;
	xi->cnt = 0;
	xi->beg = NULL;
	xi->end = NULL;
	xi->cur = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
emit_direntonly(void *buf, size_t bsz, const char *name, size_t nlen,
		ino_t ino, mode_t dt, loff_t off, size_t *out_sz)
{
	size_t entlen;
	size_t entlen_padded;
	struct fuse_dirent *fde = buf;

	entlen = FUSE_NAME_OFFSET + nlen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if (entlen_padded > bsz) {
		return -EINVAL;
	}

	fde->ino = ino;
	fde->off = (uint64_t)off;
	fde->namelen = (uint32_t)nlen;
	fde->type = dt;
	memcpy(fde->name, name, nlen);
	memset(fde->name + nlen, 0, entlen_padded - entlen);

	*out_sz = entlen_padded;
	return 0;
}

static int
emit_direntplus(void *buf, size_t bsz, const char *name, size_t nlen,
		const struct stat *attr, loff_t off, size_t *out_sz)
{
	size_t entlen;
	size_t entlen_padded;
	struct fuse_direntplus *fdp = buf;
	struct fuse_dirent *fde = &fdp->dirent;

	entlen = FUSE_NAME_OFFSET_DIRENTPLUS + nlen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if (entlen_padded > bsz) {
		return -EINVAL;
	}

	memset(&fdp->entry_out, 0, sizeof(fdp->entry_out));
	fill_fuse_entry(&fdp->entry_out, attr);

	fde->ino = attr->st_ino;
	fde->off = (uint64_t)off;
	fde->namelen = (uint32_t)nlen;
	fde->type =  IFTODT(attr->st_mode);
	memcpy(fde->name, name, nlen);
	memset(fde->name + nlen, 0, entlen_padded - entlen);

	*out_sz = entlen_padded;
	return 0;
}

static int emit_dirent(struct voluta_fuseq_diter *di, loff_t off)
{
	int err;
	size_t cnt = 0;
	char *buf = di->buf + di->len;
	const size_t rem = di->bsz - di->len;
	const ino_t ino = di->de_ino;
	const size_t nlen = di->de_nlen;
	const char *name = di->de_name.name;

	voluta_assert_le(di->len, di->bsz);

	if (rem <= di->de_nlen) {
		return -EINVAL;
	}
	err = likely(di->plus) ?
	      emit_direntplus(buf, rem, name, nlen, &di->de_attr, off, &cnt) :
	      emit_direntonly(buf, rem, name, nlen, ino, di->de_dt, off, &cnt);
	if (err) {
		return err;
	}
	voluta_assert_gt(cnt, 0);
	di->ndes++;
	di->len += cnt;
	return 0;
}

static void update_dirent(struct voluta_fuseq_diter *di,
			  const struct voluta_readdir_info *rdi)
{
	const size_t namebuf_sz = sizeof(di->de_name.name);

	di->de_off = rdi->off;
	di->de_ino = rdi->ino;
	di->de_dt = rdi->dt;
	di->de_nlen = min(rdi->namelen, namebuf_sz - 1);
	memcpy(di->de_name.name, rdi->name, di->de_nlen);
	memset(di->de_name.name + di->de_nlen, 0, namebuf_sz - di->de_nlen);
	if (di->plus) {
		memcpy(&di->de_attr, &rdi->attr, sizeof(di->de_attr));
	}
}

static bool has_dirent(const struct voluta_fuseq_diter *di)
{
	return (di->de_ino > 0) && (di->de_nlen > 0);
}

static struct voluta_fuseq_diter *diter_of(struct voluta_readdir_ctx *rd_ctx)
{
	return container_of(rd_ctx, struct voluta_fuseq_diter, rd_ctx);
}

static int filldir(struct voluta_readdir_ctx *rd_ctx,
		   const struct voluta_readdir_info *rdi)
{
	int err = 0;
	struct voluta_fuseq_diter *di;

	di = diter_of(rd_ctx);
	if (has_dirent(di)) {
		err = emit_dirent(di, rdi->off);
	}
	if (!err) {
		update_dirent(di, rdi);
	}
	return err;
}

static void diter_prep(struct voluta_fuseq_diter *di,
		       size_t bsz, loff_t pos, int plus)
{
	di->ndes = 0;
	di->de_off = 0;
	di->de_nlen = 0;
	di->de_ino = 0;
	di->de_dt = 0;
	di->de_name.name[0] = '\0';
	di->bsz = min(bsz, sizeof(di->buf));
	di->len = 0;
	di->rd_ctx.actor = filldir;
	di->rd_ctx.pos = pos;
	di->plus = plus;
	memset(&di->de_attr, 0, sizeof(di->de_attr));
}

static void diter_done(struct voluta_fuseq_diter *di)
{
	di->ndes = 0;
	di->de_off = 0;
	di->de_nlen = 0;
	di->de_ino = 0;
	di->de_dt = 0;
	di->len = 0;
	di->rd_ctx.actor = NULL;
	di->rd_ctx.pos = 0;
	di->plus = 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void setup_cap_want(struct voluta_fuseq_conn_info *coni, int cap)
{
	if (coni->cap_kern & cap) {
		coni->cap_want |= cap;
	}
}

static int check_init(const struct voluta_fuseq_ctx *fqc,
		      const struct fuse_init_in *arg)
{
	int err = 0;
	const unsigned int u_major = FUSE_KERNEL_VERSION;
	const unsigned int u_minor = FUSE_KERNEL_MINOR_VERSION;

	unused(fqc);
	if ((arg->major != u_major) || (arg->minor != u_minor)) {
		log_warn("version mismatch: kernel=%u.%u userspace=%u.%u",
			 arg->major, arg->minor, u_major, u_minor);
	}
	if ((arg->major != 7) || (arg->minor < 31)) {
		log_err("unsupported fuse-protocol version: %u.%u",
			arg->major, arg->minor);
		err = -EPROTO;
	}
	return err;
}

static void do_init(struct voluta_fuseq_ctx *fqc, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err = 0;
	struct voluta_fuseq_conn_info *coni = &fqc->fq->fq_coni;

	unused(ino);

	err = check_init(fqc, &in->u.init.arg);
	if (err) {
		fuseq_reply_init(fqc, err);
		return;
	}

	fqc->fq->fq_got_init = 1;
	coni->proto_major = (int)(in->u.init.arg.major);
	coni->proto_minor = (int)(in->u.init.arg.minor);
	coni->cap_kern = (int)(in->u.init.arg.flags);
	coni->cap_want = 0;

	/*
	 * TODO-0018: Enable more capabilities
	 *
	 * XXX: When enabling FUSE_WRITEBACK_CACHE fstests fails with
	 * metadata (st_ctime,st_blocks) issues. Needs further investigation.
	 *
	 * XXX: Also, bugs in 'test_truncate_zero'
	 */
	/* setup_cap_want(coni, FUSE_WRITEBACK_CACHE); */

	setup_cap_want(coni, FUSE_ATOMIC_O_TRUNC);
	setup_cap_want(coni, FUSE_EXPORT_SUPPORT);
	setup_cap_want(coni, FUSE_HANDLE_KILLPRIV);
	setup_cap_want(coni, FUSE_CACHE_SYMLINKS);
	setup_cap_want(coni, FUSE_DO_READDIRPLUS);
	setup_cap_want(coni, FUSE_SPLICE_READ);
	setup_cap_want(coni, FUSE_SPLICE_WRITE);

	fuseq_reply_init(fqc, 0);
}

static void do_destroy(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	unused(ino);
	unused(in);

	fqc->fq->fq_got_destroy = 1;
	fqc->fq->fq_active = false;
	fuseq_reply_status(fqc, 0);
}

static bool fuseq_has_cap(const struct voluta_fuseq *fq, int cap_mask)
{
	const int cap_want = fq->fq_coni.cap_want;

	return fq->fq_got_init && ((cap_want & cap_mask) == cap_mask);
}

static bool fuseq_may_splice(const struct voluta_fuseq *fq)
{
	return fq->fq_got_init && !fq->fq_got_destroy && (fq->fq_nopers > 10);
}

static bool fuseq_cap_splice_read(const struct voluta_fuseq *fq)
{
	return fuseq_may_splice(fq) && fuseq_has_cap(fq, FUSE_SPLICE_READ);
}

static bool fuseq_cap_splice_write(const struct voluta_fuseq *fq)
{
	return fuseq_may_splice(fq) && fuseq_has_cap(fq, FUSE_SPLICE_WRITE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define FATTR_MASK \
	(FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE | \
	 FATTR_ATIME | FATTR_MTIME | FATTR_FH | FATTR_ATIME_NOW | \
	 FATTR_MTIME_NOW | FATTR_LOCKOWNER | FATTR_CTIME)

#define FATTR_AMTIME_NOW \
	(FATTR_ATIME_NOW | FATTR_MTIME_NOW)

#define FATTR_AMCTIME \
	(FATTR_ATIME | FATTR_MTIME | FATTR_CTIME)

#define FATTR_NONTIME \
	(FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE)


static int
uid_gid_of(const struct stat *attr, int to_set, uid_t *uid, gid_t *gid)
{
	*uid = (to_set & FATTR_UID) ? attr->st_uid : (uid_t)(-1);
	*gid = (to_set & FATTR_GID) ? attr->st_gid : (gid_t)(-1);
	return 0; /* TODO: Check valid ranges */
}

static void utimens_of(const struct stat *st, int to_set, struct stat *times)
{
	bool ctime_now = !(to_set & FATTR_AMTIME_NOW);

	voluta_memzero(times, sizeof(*times));
	times->st_atim.tv_nsec = UTIME_OMIT;
	times->st_mtim.tv_nsec = UTIME_OMIT;
	times->st_ctim.tv_nsec = ctime_now ? UTIME_NOW : UTIME_OMIT;

	if (to_set & FATTR_ATIME) {
		ts_copy(&times->st_atim, &st->st_atim);
	}
	if (to_set & FATTR_MTIME) {
		ts_copy(&times->st_mtim, &st->st_mtim);
	}
	if (to_set & FATTR_CTIME) {
		ts_copy(&times->st_ctim, &st->st_ctim);
	}
}

static void do_setattr(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	int to_set;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	loff_t size;
	struct stat st;
	struct stat times;
	struct stat attr;

	fuse_setattr_to_stat(&in->u.setattr.arg, &attr);

	to_set = (int)(in->u.setattr.arg.valid & FATTR_MASK);
	utimens_of(&attr, to_set, &times);

	err = voluta_fs_getattr(fqc->sbi, &fqc->op, ino, &st);
	if (!err && (to_set & (FATTR_UID | FATTR_GID))) {
		err = uid_gid_of(&attr, to_set, &uid, &gid);
	}
	if (!err && (to_set & FATTR_AMTIME_NOW)) {
		err = voluta_fs_utimens(fqc->sbi, &fqc->op, ino, &times, &st);
	}
	if (!err && (to_set & FATTR_MODE)) {
		mode = attr.st_mode;
		err = voluta_fs_chmod(fqc->sbi, &fqc->op,
				      ino, mode, &times, &st);
	}
	if (!err && (to_set & (FATTR_UID | FATTR_GID))) {
		err = voluta_fs_chown(fqc->sbi, &fqc->op,
				      ino, uid, gid, &times, &st);
	}
	if (!err && (to_set & FATTR_SIZE)) {
		size = attr.st_size;
		err = voluta_fs_truncate(fqc->sbi, &fqc->op, ino, size, &st);
	}
	if (!err && (to_set & FATTR_AMCTIME) && !(to_set & FATTR_NONTIME)) {
		err = voluta_fs_utimens(fqc->sbi, &fqc->op, ino, &times, &st);
	}
	fuseq_reply_attr(fqc, &st, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void do_lookup(struct voluta_fuseq_ctx *fqc, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	const char *name;
	struct stat st = { .st_ino = 0 };

	name = in->u.lookup.name;
	err = voluta_fs_lookup(fqc->sbi, &fqc->op, ino, name, &st);
	fuseq_reply_entry(fqc, &st, err);
}

static void do_forget(struct voluta_fuseq_ctx *fqc, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	unsigned long nlookup;

	nlookup = in->u.forget.arg.nlookup;
	err = voluta_fs_forget(fqc->sbi, &fqc->op, ino, nlookup);
	fuseq_reply_none(fqc);
	unused(err);
}

static void do_batch_forget(struct voluta_fuseq_ctx *fqc, ino_t unused_ino,
			    const struct voluta_fuseq_in *in)
{
	int err;
	ino_t ino;
	size_t nlookup;
	size_t count;

	count = in->u.batch_forget.arg.count;
	for (size_t i = 0; i < count; ++i) {
		ino = (ino_t)(in->u.batch_forget.one[i].nodeid);
		nlookup = (ino_t)(in->u.batch_forget.one[i].nlookup);

		err = voluta_fs_forget(fqc->sbi, &fqc->op, ino, nlookup);
		unused(err);
	}
	fuseq_reply_none(fqc);
	unused(unused_ino);
}

static void do_getattr(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	struct stat st = { .st_ino = 0 };

	check_fh(fqc, ino, in->u.getattr.arg.fh);
	err = voluta_fs_getattr(fqc->sbi, &fqc->op, ino, &st);
	fuseq_reply_attr(fqc, &st, err);
}

static void do_readlink(struct voluta_fuseq_ctx *fqc, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	size_t nrd = 0;
	struct voluta_fuseq_pathbuf *pab;

	pab = &fqc->outb->u.pab;
	err = voluta_fs_readlink(fqc->sbi, &fqc->op, ino,
				 pab->path, sizeof(pab->path), &nrd);
	fuseq_reply_readlink(fqc, pab->path, nrd, err);

	unused(in);
}

static void do_symlink(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	const char *name;
	const char *target;
	struct stat st = { .st_ino = 0 };

	name = in->u.symlink.name_target;
	target = after_name(name);

	err = voluta_fs_symlink(fqc->sbi, &fqc->op, ino, name, target, &st);
	fuseq_reply_entry(fqc, &st, err);
}

static void do_mknod(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	dev_t rdev;
	mode_t umask;
	mode_t mode;
	const char *name;
	struct stat st = { .st_ino = 0 };

	mode = (mode_t)in->u.mknod.arg.mode;
	rdev = (dev_t)in->u.mknod.arg.rdev;
	umask = (mode_t)in->u.mknod.arg.umask;
	name = in->u.mknod.name;

	fqc->op.ucred.umask = umask;
	err = voluta_fs_mknod(fqc->sbi, &fqc->op, ino, name, mode, rdev, &st);
	fuseq_reply_entry(fqc, &st, err);
}

static void do_mkdir(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	mode_t mode;
	mode_t umask;
	const char *name;
	struct stat st = { .st_ino = 0 };

	umask = (mode_t)in->u.mkdir.arg.umask;
	mode = (mode_t)(in->u.mkdir.arg.mode | S_IFDIR);
	name = in->u.mkdir.name;

	fqc->op.ucred.umask = umask;
	err = voluta_fs_mkdir(fqc->sbi, &fqc->op, ino, name, mode, &st);
	fuseq_reply_entry(fqc, &st, err);
}

static void do_unlink(struct voluta_fuseq_ctx *fqc, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	const char *name;

	name = in->u.unlink.name;
	err = voluta_fs_unlink(fqc->sbi, &fqc->op, ino, name);
	fuseq_reply_status(fqc, err);
}

static void do_rmdir(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	const char *name;

	name = in->u.rmdir.name;
	err = voluta_fs_rmdir(fqc->sbi, &fqc->op, ino, name);
	fuseq_reply_status(fqc, err);
}

static void do_rename(struct voluta_fuseq_ctx *fqc, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	ino_t newparent;
	const char *name;
	const char *newname;

	newparent = (ino_t)(in->u.rename.arg.newdir);
	name = in->u.rename.name_newname;
	newname = after_name(name);
	err = voluta_fs_rename(fqc->sbi, &fqc->op, ino, name,
			       newparent, newname, 0);
	fuseq_reply_status(fqc, err);
}

static void do_link(struct voluta_fuseq_ctx *fqc, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	ino_t oldino;
	const char *newname;
	struct stat st = { .st_ino = 0 };

	oldino = (ino_t)(in->u.link.arg.oldnodeid);
	newname = in->u.link.name;
	err = voluta_fs_link(fqc->sbi, &fqc->op, oldino, ino, newname, &st);
	fuseq_reply_entry(fqc, &st, err);
}

static void do_open(struct voluta_fuseq_ctx *fqc, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	int o_flags;

	o_flags = (int)(in->u.open.arg.flags);
	err = voluta_fs_open(fqc->sbi, &fqc->op, ino, o_flags);
	fuseq_reply_open(fqc, err);
}

static void do_statfs(struct voluta_fuseq_ctx *fqc, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	struct statvfs stv = { .f_bsize = 0 };

	err = voluta_fs_statfs(fqc->sbi, &fqc->op, ino, &stv);
	fuseq_reply_statfs(fqc, &stv, err);
	unused(in);
}

static void do_release(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	int o_flags;
	bool flush;

	o_flags = (int)in->u.release.arg.flags;
	flush = (in->u.release.arg.flags & FUSE_RELEASE_FLUSH) != 0;
	check_fh(fqc, ino, in->u.release.arg.fh);

	err = voluta_fs_release(fqc->sbi, &fqc->op, ino, o_flags, flush);
	fuseq_reply_status(fqc, err);
}

static void do_fsync(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	bool datasync;

	datasync = (in->u.fsync.arg.fsync_flags & 1) != 0;
	check_fh(fqc, ino, in->u.fsync.arg.fh);

	err = voluta_fs_fsync(fqc->sbi, &fqc->op, ino, datasync);
	fuseq_reply_status(fqc, err);
}

static void do_setxattr(struct voluta_fuseq_ctx *fqc, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	int xflags;
	size_t value_size;
	const char *name;
	const char *value;

	value_size = in->u.setxattr.arg.size;
	xflags = (int)(in->u.setxattr.arg.flags);
	name = in->u.setxattr.name_value;
	value = after_name(name);

	err = voluta_fs_setxattr(fqc->sbi, &fqc->op, ino,
				 name, value, value_size, xflags);
	fuseq_reply_status(fqc, err);
}

static void do_getxattr(struct voluta_fuseq_ctx *fqc, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	size_t cnt = 0;
	size_t len;
	void *buf;
	const char *name;
	struct voluta_fuseq_xattrbuf *xab;

	xab = &fqc->outb->u.xab;
	len = min(in->u.getxattr.arg.size, sizeof(xab->value));
	buf = len ? xab->value : NULL;
	name = in->u.getxattr.name;

	err = voluta_fs_getxattr(fqc->sbi, &fqc->op, ino,
				 name, buf, len, &cnt);
	fuseq_reply_xattr(fqc, buf, cnt, err);
}

static void do_listxattr(struct voluta_fuseq_ctx *fqc, ino_t ino,
			 const struct voluta_fuseq_in *in)
{
	int err;
	struct voluta_fuseq_xiter *xit;

	xit = &fqc->outb->u.xit;
	xiter_prep(xit, in->u.listxattr.arg.size);
	err = voluta_fs_listxattr(fqc->sbi, &fqc->op, ino, &xit->lxa);
	fuseq_reply_xattr(fqc, xit->beg, xit->cnt, err);
	xiter_done(xit);
}

static void do_removexattr(struct voluta_fuseq_ctx *fqc, ino_t ino,
			   const struct voluta_fuseq_in *in)
{
	int err;
	const char *name;

	name = in->u.removexattr.name;
	err = voluta_fs_removexattr(fqc->sbi, &fqc->op, ino, name);
	fuseq_reply_status(fqc, err);
}

static void do_flush(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;

	check_fh(fqc, ino, in->u.flush.arg.fh);
	err = voluta_fs_flush(fqc->sbi, &fqc->op, ino);
	fuseq_reply_status(fqc, err);
}

static void do_opendir(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	int o_flags;

	o_flags = (int)(in->u.opendir.arg.flags);
	unused(o_flags); /* XXX use me */

	err = voluta_fs_opendir(fqc->sbi, &fqc->op, ino);
	fuseq_reply_opendir(fqc, err);
}

static void do_readdir(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	size_t size;
	loff_t off;
	struct voluta_fuseq_diter *dit;

	size = in->u.readdir.arg.size;
	off = (loff_t)(in->u.readdir.arg.offset);
	check_fh(fqc, ino, in->u.readdir.arg.fh);

	dit = &fqc->outb->u.dit;
	diter_prep(dit, size, off, 0);
	err = voluta_fs_readdir(fqc->sbi, &fqc->op, ino, &dit->rd_ctx);
	fuseq_reply_readdir(fqc, dit, err);
	diter_done(dit);
}

static void do_readdirplus(struct voluta_fuseq_ctx *fqc, ino_t ino,
			   const struct voluta_fuseq_in *in)
{
	int err;
	size_t size;
	loff_t off;
	struct voluta_fuseq_diter *dit;

	size = in->u.readdir.arg.size;
	off = (loff_t)(in->u.readdir.arg.offset);
	check_fh(fqc, ino, in->u.readdir.arg.fh);

	dit = &fqc->outb->u.dit;
	diter_prep(dit, size, off, 1);
	err = voluta_fs_readdirplus(fqc->sbi, &fqc->op, ino, &dit->rd_ctx);
	fuseq_reply_readdir(fqc, dit, err);
	diter_done(dit);
}

static void do_releasedir(struct voluta_fuseq_ctx *fqc, ino_t ino,
			  const struct voluta_fuseq_in *in)
{
	int err;
	int o_flags;

	o_flags = (int)(in->u.releasedir.arg.flags);
	check_fh(fqc, ino, in->u.releasedir.arg.fh);

	err = voluta_fs_releasedir(fqc->sbi, &fqc->op, ino, o_flags);
	fuseq_reply_status(fqc, err);
}

static void do_fsyncdir(struct voluta_fuseq_ctx *fqc, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	bool datasync;

	datasync = (in->u.fsyncdir.arg.fsync_flags & 1) != 0;
	check_fh(fqc, ino, in->u.fsyncdir.arg.fh);

	err = voluta_fs_fsyncdir(fqc->sbi, &fqc->op, ino, datasync);
	fuseq_reply_status(fqc, err);
}

static void do_access(struct voluta_fuseq_ctx *fqc, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	int mask;

	mask = (int)(in->u.access.arg.mask);
	err = voluta_fs_access(fqc->sbi, &fqc->op, ino, mask);
	fuseq_reply_status(fqc, err);
}

static void do_create(struct voluta_fuseq_ctx *fqc, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	int o_flags;
	mode_t mode;
	mode_t umask;
	const char *name;
	struct stat st = { .st_ino = 0 };

	o_flags = (int)(in->u.create.arg.flags);
	mode = (mode_t)(in->u.create.arg.mode);
	umask = (mode_t)(in->u.create.arg.umask);
	name = in->u.create.name;

	fqc->op.ucred.umask = umask;
	err = voluta_fs_create(fqc->sbi, &fqc->op, ino,
			       name, o_flags, mode, &st);
	fuseq_reply_create(fqc, &st, err);
}

static void do_fallocate(struct voluta_fuseq_ctx *fqc, ino_t ino,
			 const struct voluta_fuseq_in *in)
{
	int err;
	int mode;
	loff_t off;
	loff_t len;

	mode = (int)(in->u.fallocate.arg.mode);
	off = (loff_t)(in->u.fallocate.arg.offset);
	len = (loff_t)(in->u.fallocate.arg.length);
	check_fh(fqc, ino, in->u.fallocate.arg.fh);

	err = voluta_fs_fallocate(fqc->sbi, &fqc->op, ino, mode, off, len);
	fuseq_reply_status(fqc, err);
}

static void do_rename2(struct voluta_fuseq_ctx *fqc, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	int flags;
	ino_t newparent;
	const char *name;
	const char *newname;

	newparent = (ino_t)(in->u.rename2.arg.newdir);
	name = in->u.rename2.name_newname;
	newname = after_name(name);
	flags = (int)(in->u.rename2.arg.flags);

	err = voluta_fs_rename(fqc->sbi, &fqc->op, ino,
			       name, newparent, newname, flags);
	fuseq_reply_status(fqc, err);
}

static void do_lseek(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	int whence;
	loff_t off;
	loff_t soff = -1;

	off = (loff_t)(in->u.lseek.arg.offset);
	whence = (int)(in->u.lseek.arg.whence);
	check_fh(fqc, ino, in->u.lseek.arg.fh);

	err = voluta_fs_lseek(fqc->sbi, &fqc->op, ino, off, whence, &soff);
	fuseq_reply_lseek(fqc, soff, err);
}


static void do_copy_file_range(struct voluta_fuseq_ctx *fqc, ino_t ino_in,
			       const struct voluta_fuseq_in *in)
{
	int err;
	int flags;
	loff_t off_in;
	ino_t ino_out;
	loff_t off_out;
	size_t len;
	size_t cnt = 0;

	off_in = (loff_t)in->u.copy_file_range.arg.off_in;
	ino_out = (ino_t)in->u.copy_file_range.arg.nodeid_out;
	off_out = (loff_t)in->u.copy_file_range.arg.off_out;
	len = in->u.copy_file_range.arg.len;
	flags = (int)in->u.copy_file_range.arg.flags;
	check_fh(fqc, ino_in, in->u.copy_file_range.arg.fh_in);
	check_fh(fqc, ino_out, in->u.copy_file_range.arg.fh_out);

	err = voluta_fs_copy_file_range(fqc->sbi, &fqc->op, ino_in, off_in,
					ino_out, off_out, len, flags, &cnt);
	fuseq_reply_copy_file_range(fqc, cnt, err);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fiovec_copy(struct voluta_fiovec *dst,
			const struct voluta_fiovec *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static struct voluta_fuseq_rd_iter *
fuseq_rd_iter_of(const struct voluta_rwiter_ctx *rwi)
{
	const struct voluta_fuseq_rd_iter *fq_rdi =
		container_of2(rwi, struct voluta_fuseq_rd_iter, rwi);

	return unconst(fq_rdi);
}

static int fuseq_rd_iter_actor(struct voluta_rwiter_ctx *rwi,
			       const struct voluta_fiovec *fiov)
{
	struct voluta_fuseq_rd_iter *fq_rdi;

	fq_rdi = fuseq_rd_iter_of(rwi);
	if ((fiov->fd > 0) && (fiov->off < 0)) {
		return -EINVAL;
	}
	if (fq_rdi->cnt >= ARRAY_SIZE(fq_rdi->fiov)) {
		return -EINVAL;
	}
	if ((fq_rdi->nrd + fiov->len) > fq_rdi->nrd_max) {
		return -EINVAL;
	}
	fiovec_copy(&fq_rdi->fiov[fq_rdi->cnt++], fiov);
	fq_rdi->nrd += fiov->len;
	return 0;
}

static void fuseq_setup_rd_iter(struct voluta_fuseq_ctx *fqc,
				struct voluta_fuseq_rd_iter *fq_rdi,
				size_t len, loff_t off)
{
	fq_rdi->fqc = fqc;
	fq_rdi->rwi.actor = fuseq_rd_iter_actor;
	fq_rdi->rwi.len = len;
	fq_rdi->rwi.off = off;
	fq_rdi->cnt = 0;
	fq_rdi->nrd = 0;
	fq_rdi->nrd_max = len;
}

static void do_read_iter(struct voluta_fuseq_ctx *fqc, ino_t ino,
			 const struct voluta_fuseq_in *in)
{
	int err;
	loff_t off;
	size_t len;
	struct voluta_fuseq_rd_iter *fq_rdi;

	off = (loff_t)(in->u.read.arg.offset);
	len = min(in->u.read.arg.size, fqc->fq->fq_coni.max_read);

	fq_rdi = &fqc->outb->u.rdi;
	fuseq_setup_rd_iter(fqc, fq_rdi, len, off);

	err = voluta_fs_read_iter(fqc->sbi, &fqc->op, ino, &fq_rdi->rwi);
	fuseq_reply_read_iter(fqc, fq_rdi->nrd,
			      fq_rdi->fiov, fq_rdi->cnt, err);
}

static void do_read_buf(struct voluta_fuseq_ctx *fqc, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	loff_t off;
	size_t len;
	size_t nrd = 0;
	struct voluta_fuseq_databuf *dab;

	off = (loff_t)(in->u.read.arg.offset);
	len = min(in->u.read.arg.size, fqc->fq->fq_coni.max_read);
	dab = &fqc->outb->u.dab;

	err = voluta_fs_read(fqc->sbi, &fqc->op, ino,
			     dab->buf, len, off, &nrd);
	fuseq_reply_read_buf(fqc, dab->buf, nrd, err);
}

static void do_read(struct voluta_fuseq_ctx *fqc, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	const size_t rd_size = in->u.read.arg.size;

	check_fh(fqc, ino, in->u.read.arg.fh);

	if ((rd_size > 1024) && fuseq_cap_splice_write(fqc->fq)) {
		do_read_iter(fqc, ino, in);
	} else {
		do_read_buf(fqc, ino, in);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_fuseq_wr_iter *
fuseq_wr_iter_of(const struct voluta_rwiter_ctx *rwi)
{
	const struct voluta_fuseq_wr_iter *fq_wri =
		container_of2(rwi, struct voluta_fuseq_wr_iter, rwi);

	return unconst(fq_wri);
}

static int
fuseq_extract_from_pipe_by_fd(struct voluta_fuseq_ctx *fqc,
			      const struct voluta_fiovec *fiov)
{
	loff_t off = fiov->off;
	struct voluta_pipe *pipe = &fqc->fq->fq_pipe;

	return pipe_splice_to_fd(pipe, fiov->fd, &off, fiov->len);
}

static int
fuseq_extract_from_pipe_by_iov(struct voluta_fuseq_ctx *fqc,
			       const struct voluta_fiovec *fiov)
{
	struct iovec iov = {
		.iov_base = fiov->mm,
		.iov_len = fiov->len
	};
	struct voluta_pipe *pipe = &fqc->fq->fq_pipe;

	return pipe_vmsplice_to_iov(pipe, &iov, 1);
}

static int
fuseq_extract_data_from_pipe(struct voluta_fuseq_ctx *fqc,
			     const struct voluta_fiovec *fiov)
{
	int err;

	if (fiov->mm != NULL) {
		err = fuseq_extract_from_pipe_by_iov(fqc, fiov);
	} else {
		err = fuseq_extract_from_pipe_by_fd(fqc, fiov);
	}
	return err;
}

static int fuseq_wr_iter_actor(struct voluta_rwiter_ctx *rwi,
			       const struct voluta_fiovec *fiov)
{
	int err;
	struct voluta_fuseq_wr_iter *fq_wri = fuseq_wr_iter_of(rwi);

	if (!fq_wri->fqc->fq->fq_active) {
		return -EROFS;
	}
	if ((fiov->fd < 0) || (fiov->off < 0)) {
		return -EINVAL;
	}
	if ((fq_wri->nwr + fiov->len) > fq_wri->nwr_max) {
		return -EINVAL;
	}
	err = fuseq_extract_data_from_pipe(fq_wri->fqc, fiov);
	if (err) {
		return err;
	}
	fq_wri->nwr += fiov->len;
	return 0;
}

static void fuseq_setup_wr_iter(struct voluta_fuseq_ctx *fqc,
				struct voluta_fuseq_wr_iter *fq_rwi,
				size_t len, loff_t off)
{
	fq_rwi->fqc = fqc;
	fq_rwi->rwi.actor = fuseq_wr_iter_actor;
	fq_rwi->rwi.len = len;
	fq_rwi->rwi.off = off;
	fq_rwi->nwr = 0;
	fq_rwi->nwr_max = len;
}

static void do_write(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	loff_t off1;
	size_t len1;
	loff_t off2;
	size_t len2;
	size_t nwr = 0;
	const size_t lim = fqc->fq->fq_coni.max_write;
	struct voluta_fuseq_wr_iter fq_rwi;

	off1 = (loff_t)(in->u.write.arg.offset);
	len1 = min3(in->u.write.arg.size, lim, sizeof(in->u.write.buf));
	off2 = off_end(off1, len1);
	len2 = min(in->u.write.arg.size - len1, lim - len1);
	check_fh(fqc, ino, in->u.write.arg.fh);

	err = voluta_fs_write(fqc->sbi, &fqc->op, ino,
			      in->u.write.buf, len1, off1, &nwr);
	if (!err && len2) {
		fuseq_setup_wr_iter(fqc, &fq_rwi, len2, off2);
		err = voluta_fs_write_iter(fqc->sbi, &fqc->op,
					   ino, &fq_rwi.rwi);
		nwr += fq_rwi.nwr;
	}
	fuseq_reply_write(fqc, nwr, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void do_ioc_notimpl(struct voluta_fuseq_ctx *fqc, ino_t ino,
			   const struct voluta_fuseq_in *in)
{
	fuseq_reply_err(fqc, -ENOSYS); /* XXX maybe -ENOTTY */
	unused(ino);
	unused(in);
}

static void do_ioc_getflags(struct voluta_fuseq_ctx *fqc, ino_t ino,
			    const struct voluta_fuseq_in *in)
{
	int err = -EINVAL;
	long ret = 0;
	size_t out_bufsz;
	struct statx stx;

	out_bufsz = in->u.ioctl.arg.out_size;
	if (out_bufsz != sizeof(ret)) {
		fuseq_reply_err(fqc, -EINVAL);
		return;
	}
	err = voluta_fs_statx(fqc->sbi, &fqc->op, ino, &stx);
	ret = (long)stx.stx_attributes;

	fuseq_reply_ioctl(fqc, 0, &ret, sizeof(ret), err);
}

static void do_ioc_query(struct voluta_fuseq_ctx *fqc, ino_t ino,
			 const struct voluta_fuseq_in *in)
{
	int err = -EINVAL;
	int flags;
	size_t bsz_in;
	size_t bsz_out;
	const void *buf_in;
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_NONE
	};

	flags = (int)(in->u.ioctl.arg.flags);
	buf_in = in->u.ioctl.buf;
	bsz_in = in->u.ioctl.arg.in_size;
	bsz_out = in->u.ioctl.arg.out_size;

	if (!bsz_out && (flags | FUSE_IOCTL_RETRY)) {
		fuseq_reply_err(fqc, -ENOSYS);
		return;
	}
	if (bsz_out != sizeof(query)) {
		fuseq_reply_err(fqc, -EINVAL);
		return;
	}
	if (bsz_in < sizeof(query.qtype)) {
		fuseq_reply_err(fqc, -EINVAL);
		return;
	}
	query.qtype = ((const struct voluta_ioc_query *)buf_in)->qtype;
	err = voluta_fs_query(fqc->sbi, &fqc->op, ino, &query);
	fuseq_reply_ioctl(fqc, 0, &query, sizeof(query), err);
}

static void do_ioc_clone(struct voluta_fuseq_ctx *fqc, ino_t ino,
			 const struct voluta_fuseq_in *in)
{
	int err = -EINVAL;
	int flags;
	size_t bsz_in;
	size_t bsz_out;
	const void *buf_in;
	struct voluta_ioc_clone clone = {
		.flags = 0
	};

	flags = (int)(in->u.ioctl.arg.flags);
	buf_in = in->u.ioctl.buf;
	bsz_in = in->u.ioctl.arg.in_size;
	bsz_out = in->u.ioctl.arg.out_size;

	if (!bsz_out && (flags | FUSE_IOCTL_RETRY)) {
		fuseq_reply_err(fqc, -ENOSYS);
		return;
	}
	if (bsz_in < sizeof(clone.flags)) {
		fuseq_reply_err(fqc, -EINVAL);
		return;
	}
	clone.flags = ((const struct voluta_ioc_clone *)buf_in)->flags;
	err = voluta_fs_clone(fqc->sbi, &fqc->op,
			      ino, clone.name, sizeof(clone.name));
	fuseq_reply_ioctl(fqc, 0, &clone, sizeof(clone), err);
}

static void do_ioctl(struct voluta_fuseq_ctx *fqc, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	long cmd;
	int flags;
	size_t in_size;
	const void *in_buf;

	cmd = (long)(in->u.ioctl.arg.cmd);
	flags = (int)(in->u.ioctl.arg.flags);
	in_size = in->u.ioctl.arg.in_size;
	in_buf = in_size ? in->u.ioctl.buf : NULL;
	unused(in_buf); /* XXX */

	if (flags & FUSE_IOCTL_COMPAT) {
		fuseq_reply_err(fqc, -ENOSYS);
		return;
	}
	if ((flags & FUSE_IOCTL_DIR) && (flags & FUSE_IOCTL_UNRESTRICTED)) {
		fuseq_reply_err(fqc, -ENOTTY);
		return;
	}

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		do_ioc_getflags(fqc, ino, in);
		break;
	case VOLUTA_FS_IOC_QUERY:
		do_ioc_query(fqc, ino, in);
		break;
	case VOLUTA_FS_IOC_CLONE:
		do_ioc_clone(fqc, ino, in);
		break;
	default:
		do_ioc_notimpl(fqc, ino, in);
		break;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define FUSEQ_CMDDEF(opcode_, hook_, rtime_) \
	[opcode_] = { hook_, VOLUTA_STR(opcode_), opcode_, rtime_ }

static const struct voluta_fuseq_cmd fuseq_cmd_tbl[] = {
	FUSEQ_CMDDEF(FUSE_LOOKUP, do_lookup, 0),
	FUSEQ_CMDDEF(FUSE_FORGET, do_forget, 0),
	FUSEQ_CMDDEF(FUSE_GETATTR, do_getattr, 0),
	FUSEQ_CMDDEF(FUSE_SETATTR, do_setattr, 1),
	FUSEQ_CMDDEF(FUSE_READLINK, do_readlink, 0),
	FUSEQ_CMDDEF(FUSE_SYMLINK, do_symlink, 1),
	FUSEQ_CMDDEF(FUSE_MKNOD, do_mknod, 1),
	FUSEQ_CMDDEF(FUSE_MKDIR, do_mkdir, 1),
	FUSEQ_CMDDEF(FUSE_UNLINK, do_unlink, 1),
	FUSEQ_CMDDEF(FUSE_RMDIR, do_rmdir, 1),
	FUSEQ_CMDDEF(FUSE_RENAME, do_rename, 1),
	FUSEQ_CMDDEF(FUSE_LINK, do_link, 1),
	FUSEQ_CMDDEF(FUSE_OPEN, do_open, 1),
	FUSEQ_CMDDEF(FUSE_READ, do_read, 0),
	FUSEQ_CMDDEF(FUSE_WRITE, do_write, 1),
	FUSEQ_CMDDEF(FUSE_STATFS, do_statfs, 0),
	FUSEQ_CMDDEF(FUSE_RELEASE, do_release, 0),
	FUSEQ_CMDDEF(FUSE_FSYNC, do_fsync, 0),
	FUSEQ_CMDDEF(FUSE_SETXATTR, do_setxattr, 1),
	FUSEQ_CMDDEF(FUSE_GETXATTR, do_getxattr, 0),
	FUSEQ_CMDDEF(FUSE_LISTXATTR, do_listxattr, 0),
	FUSEQ_CMDDEF(FUSE_REMOVEXATTR, do_removexattr, 1),
	FUSEQ_CMDDEF(FUSE_FLUSH, do_flush, 0),
	FUSEQ_CMDDEF(FUSE_INIT, do_init, 1),
	FUSEQ_CMDDEF(FUSE_OPENDIR, do_opendir, 1),
	FUSEQ_CMDDEF(FUSE_READDIR, do_readdir, 1),
	FUSEQ_CMDDEF(FUSE_RELEASEDIR, do_releasedir, 1),
	FUSEQ_CMDDEF(FUSE_FSYNCDIR, do_fsyncdir, 1),
	FUSEQ_CMDDEF(FUSE_GETLK, NULL, 0),
	FUSEQ_CMDDEF(FUSE_SETLKW, NULL, 0),
	FUSEQ_CMDDEF(FUSE_ACCESS, do_access, 0),
	FUSEQ_CMDDEF(FUSE_CREATE, do_create, 1),
	FUSEQ_CMDDEF(FUSE_INTERRUPT, NULL, 0),
	FUSEQ_CMDDEF(FUSE_BMAP, NULL, 0),
	FUSEQ_CMDDEF(FUSE_DESTROY, do_destroy, 1),
	FUSEQ_CMDDEF(FUSE_IOCTL, do_ioctl, 1),
	FUSEQ_CMDDEF(FUSE_POLL, NULL, 0),
	FUSEQ_CMDDEF(FUSE_NOTIFY_REPLY, NULL, 0),
	FUSEQ_CMDDEF(FUSE_BATCH_FORGET, do_batch_forget, 0),
	FUSEQ_CMDDEF(FUSE_FALLOCATE, do_fallocate, 1),
	FUSEQ_CMDDEF(FUSE_READDIRPLUS, do_readdirplus, 0),
	FUSEQ_CMDDEF(FUSE_RENAME2, do_rename2, 1),
	FUSEQ_CMDDEF(FUSE_LSEEK, do_lseek, 0),
	FUSEQ_CMDDEF(FUSE_COPY_FILE_RANGE, do_copy_file_range, 1),
	FUSEQ_CMDDEF(FUSE_SETUPMAPPING, NULL, 0),
	FUSEQ_CMDDEF(FUSE_REMOVEMAPPING, NULL, 0),
};

static const struct voluta_fuseq_cmd *cmd_of(unsigned int opc)
{
	return (opc <= ARRAY_SIZE(fuseq_cmd_tbl)) ? &fuseq_cmd_tbl[opc] : NULL;
}



static int fuseq_resolve_opdesc(struct voluta_fuseq_ctx *fqc, unsigned int opc)
{
	const struct voluta_fuseq_cmd *cmd = cmd_of(opc);

	if ((cmd == NULL) || (cmd->hook == NULL)) {
		return -ENOSYS;
	}
	if (!fqc->fq->fq_got_init && (cmd->code != FUSE_INIT)) {
		return -EIO;
	}
	if (fqc->fq->fq_got_init && (cmd->code == FUSE_INIT)) {
		return -EIO;
	}
	fqc->cmd = cmd;
	return 0;
}

static int fuseq_check_perm(const struct voluta_fuseq_ctx *fqc, uid_t opuid)
{
	const uid_t owner = fqc->sbi->sb_owner.uid;

	if (!fqc->fq->fq_deny_others) {
		return 0;
	}
	if ((opuid == 0) || (owner == opuid)) {
		return 0;
	}
	switch (fqc->op.opcode) {
	case FUSE_INIT:
	case FUSE_READ:
	case FUSE_WRITE:
	case FUSE_FSYNC:
	case FUSE_RELEASE:
	case FUSE_READDIR:
	case FUSE_FSYNCDIR:
	case FUSE_RELEASEDIR:
	case FUSE_NOTIFY_REPLY:
	case FUSE_READDIRPLUS:
		return 0;
	default:
		break;
	}
	return -EACCES;
}

static void fuseq_assign_curr_oper(struct voluta_fuseq_ctx *fqc,
				   const struct fuse_in_header *hdr)
{
	struct voluta_oper *op = &fqc->op;

	op->ucred.uid = (uid_t)(hdr->uid);
	op->ucred.gid = (gid_t)(hdr->gid);
	op->ucred.pid = (pid_t)(hdr->pid);
	op->ucred.umask = 0;
	op->unique = hdr->unique;
	op->opcode = (int)hdr->opcode;
}

static int fuseq_setup_curr_xtime(struct voluta_fuseq_ctx *fqc)
{
	const bool is_realtime = (fqc->cmd->realtime > 0);

	return voluta_ts_gettime(&fqc->op.xtime, is_realtime);
}

static int fuseq_process_hdr(struct voluta_fuseq_ctx *fqc,
			     const struct voluta_fuseq_in *in)
{
	int err;
	const struct fuse_in_header *hdr = &in->u.hdr.hdr;

	fuseq_assign_curr_oper(fqc, hdr);
	err = fuseq_resolve_opdesc(fqc, hdr->opcode);
	if (err) {
		return err;
	}
	err = fuseq_check_perm(fqc, hdr->uid);
	if (err) {
		return err;
	}
	err = fuseq_setup_curr_xtime(fqc);
	if (err) {
		return err;
	}
	return 0;
}

static void fuseq_call_oper(struct voluta_fuseq_ctx *fqc,
			    const struct voluta_fuseq_in *in)
{
	const unsigned long nodeid = in->u.hdr.hdr.nodeid;

	fqc->cmd->hook(fqc, (ino_t)nodeid, in);
}

static void fuseq_exec_request(struct voluta_fuseq *fq,
			       const struct voluta_fuseq_in *in)
{
	int err;
	struct voluta_fuseq_ctx *fqc = &fq->fq_ctx;

	err = fuseq_process_hdr(fqc, in);
	if (!err) {
		fuseq_call_oper(fqc, in);
	} else {
		fuseq_reply_err(fqc, err);
	}
	fq->fq_nopers++;
}

static void reset_inhdr(struct voluta_fuseq_in *in)
{
	memset(&in->u.hdr, 0, sizeof(in->u.hdr));
}

static int check_inhdr(const struct voluta_fuseq_in *in, size_t nrd)
{
	const int opc = (int)in->u.hdr.hdr.opcode;
	const size_t len = in->u.hdr.hdr.len;

	if (len != nrd) {
		log_err("header length mismatch: "\
			"opc=%d nrd=%lu len=%lu ", opc, nrd, len);
		return -EIO;
	}
	if ((opc != FUSE_WRITE) && (opc != FUSE_BATCH_FORGET)) {
		if (len > sizeof(in->u.write)) {
			log_err("illegal header: opc=%d len=%lu", opc, len);
			return -EPROTO;
		}
	}
	return 0;
}

static int fuseq_read_in(struct voluta_fuseq *fq, struct voluta_fuseq_in *in)
{
	int err;
	size_t len = 0;
	const size_t hdr_len = sizeof(in->u.hdr.hdr);
	struct voluta_pipe *pipe = &fq->fq_pipe;

	voluta_assert_eq(fq->fq_coni.buffsize, pipe->size);

	err = voluta_sys_read(fq->fq_fuse_fd, in, pipe->size, &len);
	if (err) {
		return err;
	}
	if (len < hdr_len) {
		log_err("fuse read-in too-short: "\
			"len=%lu hdr_len=%lu", len, hdr_len);
		return -EIO;
	}
	return check_inhdr(in, len);
}

static void *tail_of(struct voluta_fuseq_in *in, size_t head_len)
{
	void *p = in;

	return (uint8_t *)p + head_len;
}

static int fuseq_splice_in(struct voluta_fuseq *fq, struct voluta_fuseq_in *in)
{
	int err;
	int opc;
	size_t rem;
	size_t len;
	size_t nsp = 0;
	void *tail = NULL;
	const size_t hdr_len = sizeof(in->u.hdr.hdr);
	struct voluta_pipe *pipe = &fq->fq_pipe;

	voluta_assert_eq(fq->fq_coni.buffsize, pipe->size);

	voluta_assert_eq(pipe->pend, 0);
	err = pipe_splice_from_fd(pipe, fq->fq_fuse_fd, NULL, pipe->size);
	if (err) {
		log_err("fuse splice-in failed: err=%d", err);
		return err;
	}
	nsp = pipe->pend;
	if (nsp < hdr_len) {
		log_err("fuse splice-in too-short: "\
			"nsp=%lu hdr_len=%lu", nsp, hdr_len);
		return -EIO;
	}
	len = min(nsp, sizeof(in->u.write));
	err = pipe_copy_to_buf(pipe, in, len);
	if (err) {
		log_err("pipe-copy failed: len=%lu err=%d", len, err);
		return err;
	}
	err = check_inhdr(in, nsp);
	if (err) {
		return err;
	}
	opc = (int)in->u.hdr.hdr.opcode;
	rem = nsp - len;
	if (!rem || (opc == FUSE_WRITE)) {
		return 0;
	}
	tail = tail_of(in, len); /* FUSE_BATCH_FORGET et.al. */
	err = pipe_copy_to_buf(pipe, tail, rem);
	if (err) {
		log_err("pipe-copy-tail failed: "\
			"opc=%d len=%lu err=%d", opc, rem, err);
		return err;
	}
	return 0;
}

static void fuseq_read_or_splice_request(struct voluta_fuseq *fq,
		struct voluta_fuseq_in *in)
{
	int err;

	if (fuseq_cap_splice_read(fq)) {
		err = fuseq_splice_in(fq, in);
	} else {
		err = fuseq_read_in(fq, in);
	}

	if (err == -ENOENT) {
		/* hmmm... ok, but why? */
		reset_inhdr(in);
	} else if ((err == -EINTR) || (err == -EAGAIN)) {
		log_dbg("fuse no-read: err=%d", err);
	} else if (err == -ENODEV) {
		/* Filesystem unmounted, or connection aborted */
		log_info("fuse connection aborted: err=%d", err);
		fuseq_set_chan_err(fq, err);
	} else if (err) {
		log_err("fuse recv-request: err=%d", err);
		fuseq_set_chan_err(fq, err);
	}
}

static int fuseq_prep_request(struct voluta_fuseq *fq,
			      struct voluta_fuseq_in *in)
{
	reset_inhdr(in);
	return pipe_flush_to_fd(&fq->fq_pipe, fq->fq_null_fd);
}

static int fuseq_wait_request(struct voluta_fuseq *fq)
{
	const struct timespec ts = { .tv_sec = 1 };

	return voluta_sys_pselect_rfd(fq->fq_fuse_fd, &ts);
}

static int fuseq_recv_request(struct voluta_fuseq *fq,
			      struct   voluta_fuseq_in *in)
{
	int err;

	err = fuseq_prep_request(fq, in);
	if (err) {
		return err;
	}
	err = fuseq_wait_request(fq);
	if (err) {
		return err;
	}
	fuseq_read_or_splice_request(fq, in);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_fuseq_inb *new_inb(struct voluta_qalloc *qal)
{
	struct voluta_fuseq_inb *inb;

	return voluta_qalloc_zalloc(qal, sizeof(*inb));
}

static void del_inb(struct voluta_qalloc *qal, struct voluta_fuseq_inb *inb)
{
	voluta_qalloc_free(qal, inb, sizeof(*inb));
}

static struct voluta_fuseq_outb *new_outb(struct voluta_qalloc *qal)
{
	struct voluta_fuseq_outb *outb;

	outb = voluta_qalloc_zalloc(qal, sizeof(*outb));
	return outb;
}

static void del_outb(struct voluta_qalloc *qal, struct voluta_fuseq_outb *outb)
{
	voluta_qalloc_free(qal, outb, sizeof(*outb));
}

static int pipe_max_size(size_t *out_size)
{
	int err;
	long pipe_maxsz = 0;

	err = voluta_proc_pipe_max_size(&pipe_maxsz);
	if (!err && (pipe_maxsz > 0)) {
		*out_size = (size_t)pipe_maxsz;
	} else {
		*out_size = 0;
	}
	return err;
}

static int fuseq_init_conn_info(struct voluta_fuseq *fq, size_t bufsize_max)
{
	int err;
	size_t pipe_maxsz;
	size_t page_size;
	size_t pipe_size;
	size_t buff_size;
	size_t rdwr_size;
	const size_t mega = VOLUTA_UMEGA;
	const size_t fuse_min_bsz = FUSE_MIN_READ_BUFFER;

	page_size = voluta_sc_page_size();

	err = pipe_max_size(&pipe_maxsz);
	if (err) {
		return err;
	}
	pipe_size = (pipe_maxsz > mega) ? mega : pipe_maxsz;
	if (pipe_size < (2 * page_size)) {
		log_err("bad system config: page_size=%lu pipe_size=%lu",
			page_size, pipe_size);
		return -EINVAL;
	}
	buff_size = min(pipe_size, bufsize_max);
	if (buff_size < (2 * page_size)) {
		log_err("illegal conn params: page_size=%lu buff_size=%lu",
			page_size, buff_size);
		return -EPROTO;
	}
	if (buff_size < fuse_min_bsz) {
		log_err("buffer too small: buff_size=%lu fuse_min_bsz=%lu",
			buff_size, fuse_min_bsz);
		return -EPROTO;
	}
	rdwr_size = buff_size - page_size;

	fq->fq_coni.pagesize = page_size;
	fq->fq_coni.buffsize = buff_size;
	fq->fq_coni.max_write = rdwr_size;
	fq->fq_coni.max_read = rdwr_size;
	fq->fq_coni.max_readahead = rdwr_size;
	fq->fq_coni.max_background = 16; /* XXX crap */
	fq->fq_coni.congestion_threshold = 12;
	fq->fq_coni.time_gran = 1; /* XXX Is it ? */
	return 0;
}

static int fuseq_init_pipe(struct voluta_fuseq *fq, size_t pipe_size)
{
	int err;
	struct voluta_pipe *pipe = &fq->fq_pipe;

	pipe_init(pipe);
	err = pipe_open(pipe);
	if (err) {
		return err;
	}
	err = pipe_setsize(pipe, pipe_size);
	if (err) {
		return err;
	}
	return 0;
}

static void fuseq_fini_pipe(struct voluta_fuseq *fq)
{
	pipe_fini(&fq->fq_pipe);
}

static int fuseq_init_bufs(struct voluta_fuseq *fq)
{
	struct voluta_fuseq_ctx *fqc = &fq->fq_ctx;

	fqc->inb = NULL;
	fqc->outb = NULL;

	fqc->inb = new_inb(fq->fq_qal);
	if (fqc->inb == NULL) {
		return -ENOMEM;
	}
	fqc->outb = new_outb(fq->fq_qal);
	if (fqc->outb == NULL) {
		del_inb(fq->fq_qal, fqc->inb);
		fqc->inb = NULL;
		return -ENOMEM;
	}
	return 0;
}

static void fuseq_fini_bufs(struct voluta_fuseq *fq)
{
	struct voluta_fuseq_ctx *fqc = &fq->fq_ctx;

	del_outb(fq->fq_qal, fqc->outb);
	del_inb(fq->fq_qal, fqc->inb);
	fqc->inb = NULL;
	fqc->outb = NULL;
}

static int fuseq_init_ctx(struct voluta_fuseq *fq)
{
	struct voluta_fuseq_ctx *fqc = &fq->fq_ctx;

	fqc->cmd = NULL;
	fqc->fq  = fq;
	fqc->sbi = fq->fq_sbi;
	fqc->inb = NULL;
	fqc->outb = NULL;
	return fuseq_init_bufs(fq);
}

static void fuseq_fini_ctx(struct voluta_fuseq *fq)
{
	struct voluta_fuseq_ctx *fqc = &fq->fq_ctx;

	fuseq_fini_bufs(fq);
	fqc->cmd = NULL;
	fqc->fq  = NULL;
	fqc->sbi = NULL;
	fqc->inb = NULL;
	fqc->outb = NULL;
}

static int fuseq_init_null_fd(struct voluta_fuseq *fq)
{
	const int o_flags = O_WRONLY | O_CREAT | O_TRUNC;

	return voluta_sys_open("/dev/null", o_flags, 0666, &fq->fq_null_fd);
}

static void fuseq_fini_null_fd(struct voluta_fuseq *fq)
{
	if (fq->fq_null_fd > 0) {
		voluta_sys_close(fq->fq_null_fd);
		fq->fq_null_fd = -1;
	}
}

int voluta_fuseq_init(struct voluta_fuseq *fq, struct voluta_sb_info *sbi)
{
	int err;
	size_t bsz;

	voluta_memzero(fq, sizeof(*fq));
	pipe_init(&fq->fq_pipe);
	fq->fq_sbi = sbi;
	fq->fq_qal = sbi->sb_qalloc;
	fq->fq_nopers = 0;
	fq->fq_fuse_fd = -1;
	fq->fq_null_fd = -1;
	fq->fq_chan_err = 0;
	fq->fq_got_init = 0;
	fq->fq_got_destroy = 0;
	fq->fq_deny_others = 0;
	fq->fq_active = false;
	fq->fq_umount = false;
	fq->fq_splice_memfd = false;

	bsz = max(sizeof(*fq->fq_ctx.inb), sizeof(*fq->fq_ctx.outb));
	err = fuseq_init_conn_info(fq, bsz);
	if (err) {
		return err;
	}
	err = fuseq_init_ctx(fq);
	if (err) {
		goto out;
	}
	err = fuseq_init_pipe(fq, fq->fq_coni.buffsize);
	if (err) {
		goto out;
	}
	err = fuseq_init_null_fd(fq);
	if (err) {
		goto out;
	}
	sbi->sb_ctl_flags |= VOLUTA_F_NLOOKUP;
out:
	if (err) {
		fuseq_fini_null_fd(fq);
		fuseq_fini_pipe(fq);
		fuseq_fini_ctx(fq);
	}
	return err;
}

static void fuseq_fini_fuse_fd(struct voluta_fuseq *fq)
{
	if (fq->fq_fuse_fd > 0) {
		voluta_sys_close(fq->fq_fuse_fd);
		fq->fq_fuse_fd = -1;
	}
}

void voluta_fuseq_fini(struct voluta_fuseq *fq)
{
	fuseq_fini_fuse_fd(fq);
	fuseq_fini_null_fd(fq);
	fuseq_fini_pipe(fq);
	fuseq_fini_ctx(fq);
	fq->fq_qal = NULL;
	fq->fq_sbi = NULL;
}

int voluta_fuseq_mount(struct voluta_fuseq *fq, const char *path)
{
	int err;
	int fd = -1;
	const uid_t uid = fq->fq_sbi->sb_owner.uid;
	const gid_t gid = fq->fq_sbi->sb_owner.gid;
	const size_t max_read = fq->fq_coni.buffsize;
	const uint64_t ms_flags = fq->fq_sbi->sb_ms_flags;
	const char *sock = VOLUTA_MNTSOCK_NAME;

	err = voluta_rpc_handshake(uid, gid);
	if (err) {
		log_err("no handshake with mountd: "\
			"sock=@%s err=%d", sock, err);
		return err;
	}
	err = voluta_rpc_mount(path, uid, gid, max_read, ms_flags, &fd);
	if (err) {
		log_err("mount failed: path=%s max_read=%lu "\
			"mnt_flags=0x%lx err=%d", path,
			max_read, ms_flags, err);
		return err;
	}
	fq->fq_fuse_fd = fd;
	fq->fq_mount = true;

	/* TODO: Looks like kernel needs time. why? */
	sleep(1);

	return 0;
}

void voluta_fuseq_term(struct voluta_fuseq *fq)
{
	fuseq_fini_fuse_fd(fq);
}

static bool fuseq_has_input(const struct voluta_fuseq *fq)
{
	const struct voluta_fuseq_in *in = &fq->fq_ctx.inb->u.in;

	return in->u.hdr.hdr.len && in->u.hdr.hdr.opcode;
}

static int fuseq_exec_one(struct voluta_fuseq *fq)
{
	int err;
	struct voluta_fuseq_in *in = &fq->fq_ctx.inb->u.in;

	err = fuseq_recv_request(fq, in);
	if (err) {
		return err;
	}
	err = fuseq_get_chan_err(fq);
	if (err) {
		return err;
	}
	if (!fuseq_has_input(fq)) {
		usleep(1);
		return 0;
	}
	fuseq_exec_request(fq, in);
	err = fuseq_get_chan_err(fq);
	if (err) {
		return err;
	}
	return 0;
}

static int fuseq_do_timeout(struct voluta_fuseq *fq)
{
	return voluta_timeout_cycle(fq->fq_sbi);
}

int voluta_fuseq_exec(struct voluta_fuseq *fq)
{
	int err = 0;

	fq->fq_active = true;
	while (fq->fq_active && !err) {
		err = fuseq_exec_one(fq);
		if (err == -ENODEV) {
			err = 0; /* umount case */
			fq->fq_active = false;
		} else if (err == -ETIMEDOUT) {
			err = fuseq_do_timeout(fq);
		}
		/* otherwise: break loop if err */
	}
	fq->fq_active = false;
	return err;
}

