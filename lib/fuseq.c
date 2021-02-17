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
#include <sys/sysinfo.h>
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
	(VOLUTA_FILE_HEAD2_NLEAVES + (VOLUTA_IO_SIZE_MAX / VOLUTA_BK_SIZE))


#define VOLUTA_CMD_TAIL_MAX \
	(VOLUTA_IO_SIZE_MAX - sizeof(struct fuse_in_header))
#define VOLUTA_CMD_FORGET_ONE_MAX \
	(VOLUTA_CMD_TAIL_MAX / sizeof(struct fuse_forget_one))

/* internal special error-codes */
#define FUSEQ_ENORX     (10001)
#define FUSEQ_ENOTX     (10101)

/* local functions */
static void fuseq_lock_ch(const struct voluta_fuseq_worker *fqw);
static void fuseq_unlock_ch(const struct voluta_fuseq_worker *fqw);
static void fuseq_lock_fs(const struct voluta_fuseq_worker *fqw);
static void fuseq_unlock_fs(const struct voluta_fuseq_worker *fqw);


/* local types */
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
	char buf[4 * VOLUTA_KILO];
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
	struct voluta_xiovec xiov[VOLUTA_IO_NBK_MAX];
	struct voluta_rwiter_ctx rwi;
	struct voluta_fuseq_worker *fqw;
	size_t cnt;
	size_t nwr;
	size_t nwr_max;
};

struct voluta_fuseq_rd_iter {
	struct voluta_xiovec xiov[VOLUTA_IO_NBK_MAX];
	struct voluta_rwiter_ctx rwi;
	struct voluta_fuseq_worker *fqw;
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
	struct voluta_fuseq_databuf     dab;
	struct voluta_fuseq_pathbuf     pab;
	struct voluta_fuseq_xattrbuf    xab;
	struct voluta_fuseq_xiter       xit;
	struct voluta_fuseq_diter       dit;
};

struct voluta_fuseq_outb {
	union voluta_fuseq_outb_u u;
};

union voluta_fuseq_rw_iter_u {
	struct voluta_fuseq_wr_iter     wri;
	struct voluta_fuseq_rd_iter     rdi;
};

struct voluta_fuseq_rw_iter {
	union voluta_fuseq_rw_iter_u u;
};

typedef int (*voluta_fuseq_hook)(struct voluta_fuseq_worker *, ino_t,
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
	const unsigned int splice_flags = SPLICE_F_NONBLOCK;

	cnt = iov_count_ceil(iov, niov, pipe_avail(pipe));
	err = voluta_sys_vmsplice(pipe->fd[1], iov, cnt, splice_flags, &nsp);
	if (err) {
		log_err("vmsplice-error: fd=%d cnt=%lu splice_flags=%u err=%d",
			pipe->fd[1], cnt, splice_flags, err);
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

static void fuseq_check_fh(const struct voluta_fuseq_worker *fqw,
			   ino_t ino, uint64_t fh)
{
	if (fh != 0) {
		log_warn("op=%s ino=%lu fh=0x%lx", fqw->cmd->name, ino, fh);
	}
}

static void fuseq_fill_out_header(struct voluta_fuseq_worker *fqw,
				  struct fuse_out_header *out_hdr,
				  size_t len, int err)
{
	out_hdr->len = (uint32_t)len;
	out_hdr->error = -abs(err);
	out_hdr->unique = (uint64_t)fqw->op->unique;

	voluta_assert_gt(fqw->op->unique, 0);
	voluta_assert_gt(fqw->op->opcode, 0);
}

static int fuseq_send_msg(struct voluta_fuseq_worker *fqw,
			  const struct iovec *iov, size_t iovcnt)
{
	int err;
	size_t nwr = 0;
	const int fuse_fd = fqw->fq->fq_fuse_fd;

	err = voluta_sys_writev(fuse_fd, iov, (int)iovcnt, &nwr);
	if (err && (err != -ENOENT)) {
		log_warn("send-to-fuse failed: fuse_fd=%d iovcnt=%lu err=%d",
			 fuse_fd, iovcnt, err);
	}
	return err;
}

static int fuseq_reply_arg(struct voluta_fuseq_worker *fqw,
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
	fuseq_fill_out_header(fqw, &hdr, hdrsz + argsz, 0);
	return fuseq_send_msg(fqw, iov, cnt);
}

static int fuseq_reply_arg2(struct voluta_fuseq_worker *fqw,
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

	fuseq_fill_out_header(fqw, &hdr, hdrsz + argsz + bufsz, 0);
	return fuseq_send_msg(fqw, iov, 3);
}

static int fuseq_reply_buf(struct voluta_fuseq_worker *fqw,
			   const void *buf, size_t bsz)
{
	return fuseq_reply_arg(fqw, buf, bsz);
}

static int fuseq_reply_err(struct voluta_fuseq_worker *fqw, int err)
{
	struct iovec iov[1];
	struct fuse_out_header hdr;
	const size_t hdrsize = sizeof(hdr);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = hdrsize;

	fuseq_fill_out_header(fqw, &hdr, hdrsize, err);
	return fuseq_send_msg(fqw, iov, 1);
}

static int fuseq_reply_status(struct voluta_fuseq_worker *fqw, int status)
{
	return fuseq_reply_err(fqw, status);
}

static int fuseq_reply_none(struct voluta_fuseq_worker *fqw)
{
	fqw->op->unique = 0;
	return 0;
}

static int fuseq_reply_entry_ok(struct voluta_fuseq_worker *fqw,
				const struct stat *st)
{
	struct fuse_entry_out arg;

	fill_fuse_entry(&arg, st);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_create_ok(struct voluta_fuseq_worker *fqw,
				 const struct stat *st)
{
	struct fuseq_create_out {
		struct fuse_entry_out ent;
		struct fuse_open_out  open;
	} voluta_packed_aligned16 arg;

	fill_fuse_entry(&arg.ent, st);
	fill_fuse_open(&arg.open);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_attr_ok(struct voluta_fuseq_worker *fqw,
			       const struct stat *st)
{
	struct fuse_attr_out arg;

	fill_fuse_attr(&arg, st);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_statfs_ok(struct voluta_fuseq_worker *fqw,
				 const struct statvfs *stv)
{
	struct fuse_statfs_out arg;

	statfs_to_fuse_kstatfs(stv, &arg.st);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_buf_ok(struct voluta_fuseq_worker *fqw,
			      const char *buf, size_t bsz)
{
	return fuseq_reply_arg(fqw, buf, bsz);
}

static int fuseq_reply_readlink_ok(struct voluta_fuseq_worker *fqw,
				   const char *lnk, size_t len)
{
	return fuseq_reply_buf_ok(fqw, lnk, len);
}

static int fuseq_reply_open_ok(struct voluta_fuseq_worker *fqw)
{
	struct fuse_open_out arg;

	fill_fuse_open(&arg);
	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_opendir_ok(struct voluta_fuseq_worker *fqw)
{
	return fuseq_reply_open_ok(fqw);
}

static int fuseq_reply_write_ok(struct voluta_fuseq_worker *fqw, size_t cnt)
{
	struct fuse_write_out arg = {
		.size = (uint32_t)cnt
	};

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_lseek_ok(struct voluta_fuseq_worker *fqw, loff_t off)
{
	struct fuse_lseek_out arg = {
		.offset = (uint64_t)off
	};

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_xattr_len(struct voluta_fuseq_worker *fqw, size_t len)
{
	struct fuse_getxattr_out arg = {
		.size = (uint32_t)len
	};

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_xattr_buf(struct voluta_fuseq_worker *fqw,
				 const void *buf, size_t len)
{
	return fuseq_reply_buf(fqw, buf, len);
}

static int fuseq_reply_init_ok(struct voluta_fuseq_worker *fqw,
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

	return fuseq_reply_arg(fqw, &arg, sizeof(arg));
}

static int fuseq_reply_ioctl_ok(struct voluta_fuseq_worker *fqw, int result,
				const void *buf, size_t size)
{
	int ret;
	struct fuse_ioctl_out arg;

	memset(&arg, 0, sizeof(arg));
	arg.result = result;

	if (size) {
		ret = fuseq_reply_arg2(fqw, &arg, sizeof(arg), buf, size);
	} else {
		ret = fuseq_reply_arg(fqw, &arg, sizeof(arg));
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_reply_attr(struct voluta_fuseq_worker *fqw,
			    const struct stat *st, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_attr_ok(fqw, st);
	}
	return ret;
}

static int fuseq_reply_entry(struct voluta_fuseq_worker *fqw,
			     const struct stat *st, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_entry_ok(fqw, st);
	}
	return ret;
}

static int fuseq_reply_create(struct voluta_fuseq_worker *fqw,
			      const struct stat *st, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_create_ok(fqw, st);
	}
	return ret;
}

static int fuseq_reply_readlink(struct voluta_fuseq_worker *fqw,
				const char *lnk, size_t len, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_readlink_ok(fqw, lnk, len);
	}
	return ret;
}

static int fuseq_reply_statfs(struct voluta_fuseq_worker *fqw,
			      const struct statvfs *stv, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_statfs_ok(fqw, stv);
	}
	return ret;
}

static int fuseq_reply_open(struct voluta_fuseq_worker *fqw, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_open_ok(fqw);
	}
	return ret;
}

static int fuseq_reply_xattr(struct voluta_fuseq_worker *fqw,
			     const void *buf, size_t len, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else if (buf == NULL) {
		ret = fuseq_reply_xattr_len(fqw, len);
	} else {
		ret = fuseq_reply_xattr_buf(fqw, buf, len);
	}
	return ret;
}

static int fuseq_reply_opendir(struct voluta_fuseq_worker *fqw, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_opendir_ok(fqw);
	}
	return ret;
}

static int fuseq_reply_readdir(struct voluta_fuseq_worker *fqw,
			       const struct voluta_fuseq_diter *di, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_buf(fqw, di->buf, di->len);
	}
	return ret;
}

static int fuseq_reply_lseek(struct voluta_fuseq_worker *fqw,
			     loff_t off, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_lseek_ok(fqw, off);
	}
	return ret;
}

static int fuseq_reply_copy_file_range(struct voluta_fuseq_worker *fqw,
				       size_t cnt, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_write_ok(fqw, cnt);
	}
	return ret;
}

static int fuseq_reply_init(struct voluta_fuseq_worker *fqw, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_init_ok(fqw, &fqw->fq->fq_coni);
	}
	return ret;
}

static int fuseq_reply_ioctl(struct voluta_fuseq_worker *fqw, int result,
			     const void *buf, size_t size, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_ioctl_ok(fqw, result, buf, size);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_reply_write(struct voluta_fuseq_worker *fqw,
			     size_t cnt, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_write_ok(fqw, cnt);
	}
	return ret;
}

static int fuseq_reply_read_buf(struct voluta_fuseq_worker *fqw,
				const void *dat, size_t len, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_buf_ok(fqw, dat, len);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fuseq_append_hdr_to_pipe(struct voluta_fuseq_worker *fqw,
				    size_t len)
{
	struct fuse_out_header hdr;

	fuseq_fill_out_header(fqw, &hdr,  sizeof(hdr) + len, 0);
	return pipe_append_from_buf(&fqw->pipe, &hdr, sizeof(hdr));
}


static int fuseq_append_to_pipe_by_fd(struct voluta_fuseq_worker *fqw,
				      const struct voluta_xiovec *xiov)
{
	size_t len = xiov->len;
	loff_t off = xiov->off;

	return pipe_splice_from_fd(&fqw->pipe, xiov->fd, &off, len);
}

static int fuseq_append_to_pipe_by_iov(struct voluta_fuseq_worker *fqw,
				       const struct voluta_xiovec *xiov)
{
	struct iovec iov = {
		.iov_base = xiov->base,
		.iov_len = xiov->len
	};

	return pipe_vmsplice_from_iov(&fqw->pipe, &iov, 1);
}

static int
fuseq_append_data_to_pipe(struct voluta_fuseq_worker *fqw,
			  const struct voluta_xiovec *xiov, size_t cnt)
{
	int err = 0;

	for (size_t i = 0; (i < cnt) && !err; ++i) {
		if (xiov[i].base != NULL) {
			err = fuseq_append_to_pipe_by_iov(fqw, &xiov[i]);
		} else {
			err = fuseq_append_to_pipe_by_fd(fqw, &xiov[i]);
		}
	}
	return err;
}

static int
fuseq_append_response_to_pipe(struct voluta_fuseq_worker *fqw, size_t nrd,
			      const struct voluta_xiovec *xiov, size_t cnt)
{
	int err;

	err = fuseq_append_hdr_to_pipe(fqw, nrd);
	if (err) {
		return err;
	}
	err = fuseq_append_data_to_pipe(fqw, xiov, cnt);
	if (err) {
		return err;
	}
	return 0;
}

static int fuseq_send_pipe(struct voluta_fuseq_worker *fqw)
{
	int err;

	err = pipe_flush_to_fd(&fqw->pipe, fqw->fq->fq_fuse_fd);
	return err;
}

static int fuseq_reply_read_pipe(struct voluta_fuseq_worker *fqw, size_t nrd,
				 const struct voluta_xiovec *xiov, size_t cnt)
{
	int err;
	int ret;

	err = fuseq_append_response_to_pipe(fqw, nrd, xiov, cnt);
	if (err) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_send_pipe(fqw);
	}
	return ret ? ret : err;
}

static int fuseq_reply_read_data(struct voluta_fuseq_worker *fqw, size_t nrd,
				 const struct voluta_xiovec *xiov)
{
	return fuseq_reply_arg(fqw, xiov->base, nrd);
}

static int fuseq_reply_read_ok(struct voluta_fuseq_worker *fqw, size_t nrd,
			       const struct voluta_xiovec *xiov, size_t cnt)
{
	int ret;

	if ((cnt > 1) || (xiov->base == NULL)) {
		ret = fuseq_reply_read_pipe(fqw, nrd, xiov, cnt);
	} else {
		ret = fuseq_reply_read_data(fqw, nrd, xiov);
	}
	return ret;
}

static int fuseq_reply_read_iter(struct voluta_fuseq_worker *fqw, size_t nrd,
				 const struct voluta_xiovec *xiov,
				 size_t cnt, int err)
{
	int ret;

	if (unlikely(err)) {
		ret = fuseq_reply_err(fqw, err);
	} else {
		ret = fuseq_reply_read_ok(fqw, nrd, xiov, cnt);
	}
	return ret;
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

static int check_init(const struct voluta_fuseq_worker *fqw,
		      const struct fuse_init_in *arg)
{
	int err = 0;
	const unsigned int u_major = FUSE_KERNEL_VERSION;
	const unsigned int u_minor = FUSE_KERNEL_MINOR_VERSION;

	unused(fqw);
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

static int do_init(struct voluta_fuseq_worker *fqw, ino_t ino,
		   const struct voluta_fuseq_in *in)
{
	int err = 0;
	struct voluta_fuseq_conn_info *coni = &fqw->fq->fq_coni;

	unused(ino);

	err = check_init(fqw, &in->u.init.arg);
	if (err) {
		return fuseq_reply_init(fqw, err);
	}

	fqw->fq->fq_got_init = true;
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

	/* TODO: let super do his private stuff on init */
	fqw->sbi->sb_mntime = voluta_time_now();

	return fuseq_reply_init(fqw, 0);
}

static int do_destroy(struct voluta_fuseq_worker *fqw, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	unused(ino);
	unused(in);

	fuseq_lock_fs(fqw);
	fqw->fq->fq_got_destroy = true;
	fqw->fq->fq_active = 0;
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, 0);
}

static bool fuseq_has_cap(const struct voluta_fuseq *fq, int cap_mask)
{
	const int cap_want = fq->fq_coni.cap_want;

	return fq->fq_got_init && ((cap_want & cap_mask) == cap_mask);
}

static bool fuseq_is_normal(const struct voluta_fuseq *fq)
{
	return fq->fq_got_init && !fq->fq_got_destroy && (fq->fq_nopers > 1);
}

static bool fuseq_may_splice(const struct voluta_fuseq *fq)
{
	return fuseq_is_normal(fq) && (fq->fq_nopers > 4);
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

static int do_setattr(struct voluta_fuseq_worker *fqw, ino_t ino,
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

	fuseq_lock_fs(fqw);
	err = voluta_fs_getattr(fqw->sbi, fqw->op, ino, &st);
	if (!err && (to_set & (FATTR_UID | FATTR_GID))) {
		err = uid_gid_of(&attr, to_set, &uid, &gid);
	}
	if (!err && (to_set & FATTR_AMTIME_NOW)) {
		err = voluta_fs_utimens(fqw->sbi, fqw->op, ino, &times, &st);
	}
	if (!err && (to_set & FATTR_MODE)) {
		mode = attr.st_mode;
		err = voluta_fs_chmod(fqw->sbi, fqw->op,
				      ino, mode, &times, &st);
	}
	if (!err && (to_set & (FATTR_UID | FATTR_GID))) {
		err = voluta_fs_chown(fqw->sbi, fqw->op,
				      ino, uid, gid, &times, &st);
	}
	if (!err && (to_set & FATTR_SIZE)) {
		size = attr.st_size;
		err = voluta_fs_truncate(fqw->sbi, fqw->op, ino, size, &st);
	}
	if (!err && (to_set & FATTR_AMCTIME) && !(to_set & FATTR_NONTIME)) {
		err = voluta_fs_utimens(fqw->sbi, fqw->op, ino, &times, &st);
	}
	fuseq_unlock_fs(fqw);

	return fuseq_reply_attr(fqw, &st, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_lookup(struct voluta_fuseq_worker *fqw, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	const char *name = in->u.lookup.name;
	struct stat st = { .st_ino = 0 };

	fuseq_lock_fs(fqw);
	err = voluta_fs_lookup(fqw->sbi, fqw->op, ino, name, &st);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_entry(fqw, &st, err);
}

static int do_forget(struct voluta_fuseq_worker *fqw, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	const size_t nlookup = in->u.forget.arg.nlookup;

	fuseq_lock_fs(fqw);
	err = voluta_fs_forget(fqw->sbi, fqw->op, ino, nlookup);
	fuseq_unlock_fs(fqw);

	unused(err);
	return fuseq_reply_none(fqw);
}

static int do_batch_forget(struct voluta_fuseq_worker *fqw, ino_t unused_ino,
			   const struct voluta_fuseq_in *in)
{
	int err;
	ino_t ino;
	size_t nlookup;
	const size_t count = in->u.batch_forget.arg.count;

	fuseq_lock_fs(fqw);
	for (size_t i = 0; i < count; ++i) {
		ino = (ino_t)(in->u.batch_forget.one[i].nodeid);
		nlookup = (ino_t)(in->u.batch_forget.one[i].nlookup);

		err = voluta_fs_forget(fqw->sbi, fqw->op, ino, nlookup);
		unused(err);
	}
	fuseq_unlock_fs(fqw);

	unused(unused_ino);
	return fuseq_reply_none(fqw);
}

static int do_getattr(struct voluta_fuseq_worker *fqw, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	struct stat st = { .st_ino = 0 };

	fuseq_check_fh(fqw, ino, in->u.getattr.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_getattr(fqw->sbi, fqw->op, ino, &st);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_attr(fqw, &st, err);
}

static int do_readlink(struct voluta_fuseq_worker *fqw, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	size_t nrd = 0;
	struct voluta_fuseq_pathbuf *pab = &fqw->outb->u.pab;
	const size_t lim = sizeof(pab->path);
	char *lnk = pab->path;

	fuseq_lock_fs(fqw);
	err = voluta_fs_readlink(fqw->sbi, fqw->op, ino, lnk, lim, &nrd);
	fuseq_unlock_fs(fqw);

	unused(in);

	return fuseq_reply_readlink(fqw, lnk, nrd, err);
}

static int do_symlink(struct voluta_fuseq_worker *fqw, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	const char *name = in->u.symlink.name_target;
	const char *target = after_name(name);
	struct stat st = { .st_ino = 0 };

	fuseq_lock_fs(fqw);
	err = voluta_fs_symlink(fqw->sbi, fqw->op, ino, name, target, &st);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_entry(fqw, &st, err);
}

static int do_mknod(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	const dev_t rdev = (dev_t)in->u.mknod.arg.rdev;
	const mode_t mode = (mode_t)in->u.mknod.arg.mode;
	const mode_t umask = (mode_t)in->u.mknod.arg.umask;
	const char *name = in->u.mknod.name;
	struct stat st = { .st_ino = 0 };

	fqw->op->ucred.umask = umask;

	fuseq_lock_fs(fqw);
	err = voluta_fs_mknod(fqw->sbi, fqw->op, ino, name, mode, rdev, &st);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_entry(fqw, &st, err);
}

static int do_mkdir(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	const mode_t mode = (mode_t)(in->u.mkdir.arg.mode | S_IFDIR);
	const mode_t umask = (mode_t)in->u.mkdir.arg.umask;
	const char *name = in->u.mkdir.name;
	struct stat st = { .st_ino = 0 };

	fqw->op->ucred.umask = umask;

	fuseq_lock_fs(fqw);
	err = voluta_fs_mkdir(fqw->sbi, fqw->op, ino, name, mode, &st);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_entry(fqw, &st, err);
}

static int do_unlink(struct voluta_fuseq_worker *fqw, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	const char *name = in->u.unlink.name;

	fuseq_lock_fs(fqw);
	err = voluta_fs_unlink(fqw->sbi, fqw->op, ino, name);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_rmdir(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	const char *name = in->u.rmdir.name;

	fuseq_lock_fs(fqw);
	err = voluta_fs_rmdir(fqw->sbi, fqw->op, ino, name);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_rename(struct voluta_fuseq_worker *fqw, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	const ino_t newparent = (ino_t)(in->u.rename.arg.newdir);
	const char *name = in->u.rename.name_newname;
	const char *newname = after_name(name);

	fuseq_lock_fs(fqw);
	err = voluta_fs_rename(fqw->sbi, fqw->op, ino,
			       name, newparent, newname, 0);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_link(struct voluta_fuseq_worker *fqw, ino_t ino,
		   const struct voluta_fuseq_in *in)
{
	int err;
	const ino_t oldino = (ino_t)(in->u.link.arg.oldnodeid);
	const char *newname = in->u.link.name;
	struct stat st = { .st_ino = 0 };

	fuseq_lock_fs(fqw);
	err = voluta_fs_link(fqw->sbi, fqw->op, oldino, ino, newname, &st);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_entry(fqw, &st, err);
}

static int do_open(struct voluta_fuseq_worker *fqw, ino_t ino,
		   const struct voluta_fuseq_in *in)
{
	int err;
	const int o_flags = (int)(in->u.open.arg.flags);

	fuseq_lock_fs(fqw);
	err = voluta_fs_open(fqw->sbi, fqw->op, ino, o_flags);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_open(fqw, err);
}

static int do_statfs(struct voluta_fuseq_worker *fqw, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	struct statvfs stv = { .f_bsize = 0 };

	fuseq_lock_fs(fqw);
	err = voluta_fs_statfs(fqw->sbi, fqw->op, ino, &stv);
	fuseq_unlock_fs(fqw);

	unused(in);

	return fuseq_reply_statfs(fqw, &stv, err);
}

static int do_release(struct voluta_fuseq_worker *fqw, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	const int o_flags = (int)in->u.release.arg.flags;
	const bool flush = (in->u.release.arg.flags & FUSE_RELEASE_FLUSH) != 0;

	fuseq_check_fh(fqw, ino, in->u.release.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_release(fqw->sbi, fqw->op, ino, o_flags, flush);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_fsync(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	const bool datasync = (in->u.fsync.arg.fsync_flags & 1) != 0;

	fuseq_check_fh(fqw, ino, in->u.fsync.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_fsync(fqw->sbi, fqw->op, ino, datasync);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_setxattr(struct voluta_fuseq_worker *fqw, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	const size_t value_size = in->u.setxattr.arg.size;
	const int xflags = (int)(in->u.setxattr.arg.flags);
	const char *name = in->u.setxattr.name_value;
	const char *value = after_name(name);

	fuseq_lock_fs(fqw);
	err = voluta_fs_setxattr(fqw->sbi, fqw->op, ino,
				 name, value, value_size, xflags);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_getxattr(struct voluta_fuseq_worker *fqw, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	struct voluta_fuseq_xattrbuf *xab = &fqw->outb->u.xab;
	const size_t len = min(in->u.getxattr.arg.size, sizeof(xab->value));
	void *buf = len ? xab->value : NULL;
	const char *name = in->u.getxattr.name;
	size_t cnt = 0;

	fuseq_lock_fs(fqw);
	err = voluta_fs_getxattr(fqw->sbi, fqw->op, ino,
				 name, buf, len, &cnt);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_xattr(fqw, buf, cnt, err);
}

static int do_listxattr(struct voluta_fuseq_worker *fqw, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	int ret;
	struct voluta_fuseq_xiter *xit = &fqw->outb->u.xit;

	xiter_prep(xit, in->u.listxattr.arg.size);

	fuseq_lock_fs(fqw);
	err = voluta_fs_listxattr(fqw->sbi, fqw->op, ino, &xit->lxa);
	fuseq_unlock_fs(fqw);

	ret = fuseq_reply_xattr(fqw, xit->beg, xit->cnt, err);

	xiter_done(xit);

	return ret;
}

static int do_removexattr(struct voluta_fuseq_worker *fqw, ino_t ino,
			  const struct voluta_fuseq_in *in)
{
	int err;
	const char *name = in->u.removexattr.name;

	fuseq_lock_fs(fqw);
	err = voluta_fs_removexattr(fqw->sbi, fqw->op, ino, name);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_flush(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;

	fuseq_check_fh(fqw, ino, in->u.flush.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_flush(fqw->sbi, fqw->op, ino);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_opendir(struct voluta_fuseq_worker *fqw, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	const int o_flags = (int)(in->u.opendir.arg.flags);

	unused(o_flags); /* XXX use me */

	fuseq_lock_fs(fqw);
	err = voluta_fs_opendir(fqw->sbi, fqw->op, ino);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_opendir(fqw, err);
}

static int do_readdir(struct voluta_fuseq_worker *fqw, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	int ret;
	const size_t size = in->u.readdir.arg.size;
	const loff_t off = (loff_t)(in->u.readdir.arg.offset);
	struct voluta_fuseq_diter *dit = &fqw->outb->u.dit;

	fuseq_check_fh(fqw, ino, in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 0);

	fuseq_lock_fs(fqw);
	err = voluta_fs_readdir(fqw->sbi, fqw->op, ino, &dit->rd_ctx);
	fuseq_unlock_fs(fqw);

	ret = fuseq_reply_readdir(fqw, dit, err);
	diter_done(dit);

	return ret;
}

static int do_readdirplus(struct voluta_fuseq_worker *fqw, ino_t ino,
			  const struct voluta_fuseq_in *in)
{
	int err;
	int ret;
	const size_t size = in->u.readdir.arg.size;
	const loff_t off = (loff_t)(in->u.readdir.arg.offset);
	struct voluta_fuseq_diter *dit = &fqw->outb->u.dit;

	fuseq_check_fh(fqw, ino, in->u.readdir.arg.fh);
	diter_prep(dit, size, off, 1);

	fuseq_lock_fs(fqw);
	err = voluta_fs_readdirplus(fqw->sbi, fqw->op, ino, &dit->rd_ctx);
	fuseq_unlock_fs(fqw);

	ret = fuseq_reply_readdir(fqw, dit, err);
	diter_done(dit);

	return ret;
}

static int do_releasedir(struct voluta_fuseq_worker *fqw, ino_t ino,
			 const struct voluta_fuseq_in *in)
{
	int err;
	const int o_flags = (int)(in->u.releasedir.arg.flags);

	fuseq_check_fh(fqw, ino, in->u.releasedir.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_releasedir(fqw->sbi, fqw->op, ino, o_flags);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_fsyncdir(struct voluta_fuseq_worker *fqw, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	const bool datasync = (in->u.fsyncdir.arg.fsync_flags & 1) != 0;

	fuseq_check_fh(fqw, ino, in->u.fsyncdir.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_fsyncdir(fqw->sbi, fqw->op, ino, datasync);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_access(struct voluta_fuseq_worker *fqw, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	const int mask = (int)(in->u.access.arg.mask);

	fuseq_lock_fs(fqw);
	err = voluta_fs_access(fqw->sbi, fqw->op, ino, mask);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_create(struct voluta_fuseq_worker *fqw, ino_t ino,
		     const struct voluta_fuseq_in *in)
{
	int err;
	const int o_flags = (int)(in->u.create.arg.flags);
	const mode_t mode = (mode_t)(in->u.create.arg.mode);
	const mode_t umask = (mode_t)(in->u.create.arg.umask);
	const char *name = in->u.create.name;
	struct stat st = { .st_ino = 0 };

	fqw->op->ucred.umask = umask;

	fuseq_lock_fs(fqw);
	err = voluta_fs_create(fqw->sbi, fqw->op, ino,
			       name, o_flags, mode, &st);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_create(fqw, &st, err);
}

static int do_fallocate(struct voluta_fuseq_worker *fqw, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	const int mode = (int)(in->u.fallocate.arg.mode);
	const loff_t off = (loff_t)(in->u.fallocate.arg.offset);
	const loff_t len = (loff_t)(in->u.fallocate.arg.length);

	fuseq_check_fh(fqw, ino, in->u.fallocate.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_fallocate(fqw->sbi, fqw->op, ino, mode, off, len);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_rename2(struct voluta_fuseq_worker *fqw, ino_t ino,
		      const struct voluta_fuseq_in *in)
{
	int err;
	const ino_t newparent = (ino_t)(in->u.rename2.arg.newdir);
	const char *name = in->u.rename2.name_newname;
	const char *newname = after_name(name);
	const int flags = (int)(in->u.rename2.arg.flags);

	fuseq_lock_fs(fqw);
	err = voluta_fs_rename(fqw->sbi, fqw->op, ino,
			       name, newparent, newname, flags);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_status(fqw, err);
}

static int do_lseek(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	loff_t soff = -1;
	const loff_t off = (loff_t)(in->u.lseek.arg.offset);
	const int whence = (int)(in->u.lseek.arg.whence);

	fuseq_check_fh(fqw, ino, in->u.lseek.arg.fh);

	fuseq_lock_fs(fqw);
	err = voluta_fs_lseek(fqw->sbi, fqw->op, ino, off, whence, &soff);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_lseek(fqw, soff, err);
}


static int do_copy_file_range(struct voluta_fuseq_worker *fqw, ino_t ino_in,
			      const struct voluta_fuseq_in *in)
{
	int err;
	size_t cnt = 0;
	const loff_t off_in = (loff_t)in->u.copy_file_range.arg.off_in;
	const ino_t ino_out = (ino_t)in->u.copy_file_range.arg.nodeid_out;
	const loff_t off_out = (loff_t)in->u.copy_file_range.arg.off_out;
	const size_t len = in->u.copy_file_range.arg.len;
	const int flags = (int)in->u.copy_file_range.arg.flags;

	fuseq_check_fh(fqw, ino_in, in->u.copy_file_range.arg.fh_in);
	fuseq_check_fh(fqw, ino_out, in->u.copy_file_range.arg.fh_out);

	fuseq_lock_fs(fqw);
	err = voluta_fs_copy_file_range(fqw->sbi, fqw->op, ino_in, off_in,
					ino_out, off_out, len, flags, &cnt);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_copy_file_range(fqw, cnt, err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void xiovec_copy(struct voluta_xiovec *dst,
			const struct voluta_xiovec *src)
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
			       const struct voluta_xiovec *xiov)
{
	struct voluta_fuseq_rd_iter *fq_rdi;

	fq_rdi = fuseq_rd_iter_of(rwi);
	if ((xiov->fd > 0) && (xiov->off < 0)) {
		return -EINVAL;
	}
	if (!(fq_rdi->cnt < ARRAY_SIZE(fq_rdi->xiov))) {
		return -EINVAL;
	}
	if ((fq_rdi->nrd + xiov->len) > fq_rdi->nrd_max) {
		return -EINVAL;
	}
	xiovec_copy(&fq_rdi->xiov[fq_rdi->cnt++], xiov);
	fq_rdi->nrd += xiov->len;
	return 0;
}

static void fuseq_setup_rd_iter(struct voluta_fuseq_worker *fqw,
				struct voluta_fuseq_rd_iter *fq_rdi,
				size_t len, loff_t off)
{
	fq_rdi->fqw = fqw;
	fq_rdi->rwi.actor = fuseq_rd_iter_actor;
	fq_rdi->rwi.len = len;
	fq_rdi->rwi.off = off;
	fq_rdi->cnt = 0;
	fq_rdi->nrd = 0;
	fq_rdi->nrd_max = len;
}

static int do_read_iter(struct voluta_fuseq_worker *fqw, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
	int ret;
	const loff_t off = (loff_t)(in->u.read.arg.offset);
	const size_t len = min(in->u.read.arg.size, fqw->fq->fq_coni.max_read);
	struct voluta_fuseq_rd_iter *fq_rdi = &fqw->rwi->u.rdi;

	fuseq_setup_rd_iter(fqw, fq_rdi, len, off);

	fuseq_lock_fs(fqw);
	err = voluta_fs_read_iter(fqw->sbi, fqw->op, ino, &fq_rdi->rwi);
	fuseq_unlock_fs(fqw);

	ret = fuseq_reply_read_iter(fqw, fq_rdi->nrd,
				    fq_rdi->xiov, fq_rdi->cnt, err);

	fuseq_lock_fs(fqw);
	voluta_fs_rdwr_post(fqw->sbi, fqw->op, ino,
			    fq_rdi->xiov, fq_rdi->cnt);
	fuseq_unlock_fs(fqw);
	return ret;
}

static int do_read_buf(struct voluta_fuseq_worker *fqw, ino_t ino,
		       const struct voluta_fuseq_in *in)
{
	int err;
	size_t nrd = 0;
	const loff_t off = (loff_t)(in->u.read.arg.offset);
	const size_t len = min(in->u.read.arg.size, fqw->fq->fq_coni.max_read);
	struct voluta_fuseq_databuf *dab = &fqw->outb->u.dab;

	fuseq_lock_fs(fqw);
	err = voluta_fs_read(fqw->sbi, fqw->op, ino,
			     dab->buf, len, off, &nrd);
	fuseq_unlock_fs(fqw);

	return fuseq_reply_read_buf(fqw, dab->buf, nrd, err);
}

static int do_read(struct voluta_fuseq_worker *fqw, ino_t ino,
		   const struct voluta_fuseq_in *in)
{
	int ret;
	const size_t rd_size = in->u.read.arg.size;

	fuseq_check_fh(fqw, ino, in->u.read.arg.fh);

	if ((rd_size > 1024) && fuseq_cap_splice_write(fqw->fq)) {
		ret = do_read_iter(fqw, ino, in);
	} else {
		ret = do_read_buf(fqw, ino, in);
	}
	return ret;
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
fuseq_extract_from_pipe_by_fd(struct voluta_fuseq_worker *fqw,
			      const struct voluta_xiovec *xiov)
{
	loff_t off = xiov->off;

	return pipe_splice_to_fd(&fqw->pipe, xiov->fd, &off, xiov->len);
}

static int
fuseq_extract_from_pipe_by_iov(struct voluta_fuseq_worker *fqw,
			       const struct voluta_xiovec *xiov)
{
	struct iovec iov = {
		.iov_base = xiov->base,
		.iov_len = xiov->len
	};

	return pipe_vmsplice_to_iov(&fqw->pipe, &iov, 1);
}

static int
fuseq_extract_data_from_pipe(struct voluta_fuseq_worker *fqw,
			     const struct voluta_xiovec *xiov)
{
	int err;

	if (xiov->base != NULL) {
		err = fuseq_extract_from_pipe_by_iov(fqw, xiov);
	} else {
		err = fuseq_extract_from_pipe_by_fd(fqw, xiov);
	}
	return err;
}

static int fuseq_wr_iter_actor(struct voluta_rwiter_ctx *rwi,
			       const struct voluta_xiovec *xiov)
{
	int err;
	struct voluta_fuseq_wr_iter *fq_wri = fuseq_wr_iter_of(rwi);

	if (!fq_wri->fqw->fq->fq_active) {
		return -EROFS;
	}
	if (!(fq_wri->cnt < ARRAY_SIZE(fq_wri->xiov))) {
		return -EINVAL;
	}
	if ((xiov->fd < 0) || (xiov->off < 0)) {
		return -EINVAL;
	}
	if ((fq_wri->nwr + xiov->len) > fq_wri->nwr_max) {
		return -EINVAL;
	}
	err = fuseq_extract_data_from_pipe(fq_wri->fqw, xiov);
	if (err) {
		return err;
	}
	xiovec_copy(&fq_wri->xiov[fq_wri->cnt++], xiov);
	fq_wri->nwr += xiov->len;
	return 0;
}

static void fuseq_setup_wr_iter(struct voluta_fuseq_worker *fqw,
				struct voluta_fuseq_wr_iter *fq_rwi,
				size_t len, loff_t off)
{
	fq_rwi->fqw = fqw;
	fq_rwi->rwi.actor = fuseq_wr_iter_actor;
	fq_rwi->rwi.len = len;
	fq_rwi->rwi.off = off;
	fq_rwi->nwr = 0;
	fq_rwi->cnt = 0;
	fq_rwi->nwr_max = len;
}

static int do_write(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err;
	int ret;
	size_t nwr = 0;
	const loff_t off1 = (loff_t)(in->u.write.arg.offset);
	const size_t lim = fqw->fq->fq_coni.max_write;
	const size_t wsz = in->u.write.arg.size;
	const size_t len1 = min3(wsz, lim, sizeof(in->u.write.buf));
	const loff_t off2 = off_end(off1, len1);
	const size_t len2 = min(wsz - len1, lim - len1);
	struct voluta_fuseq_wr_iter *fq_wri = &fqw->rwi->u.wri;

	fuseq_check_fh(fqw, ino, in->u.write.arg.fh);
	fq_wri->cnt = 0;

	fuseq_lock_fs(fqw);
	err = voluta_fs_write(fqw->sbi, fqw->op, ino,
			      in->u.write.buf, len1, off1, &nwr);
	if (!err && len2) {
		fuseq_setup_wr_iter(fqw, fq_wri, len2, off2);
		err = voluta_fs_write_iter(fqw->sbi, fqw->op,
					   ino, &fq_wri->rwi);
		nwr += fq_wri->nwr;
	}
	fuseq_unlock_fs(fqw);

	ret = fuseq_reply_write(fqw, nwr, err);
	if (!fq_wri->cnt) {
		return ret;
	}

	fuseq_lock_fs(fqw);
	voluta_fs_rdwr_post(fqw->sbi, fqw->op, ino,
			    fq_wri->xiov, fq_wri->cnt);
	fuseq_unlock_fs(fqw);
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_ioc_notimpl(struct voluta_fuseq_worker *fqw, ino_t ino,
			  const struct voluta_fuseq_in *in)
{
	unused(ino);
	unused(in);

	return fuseq_reply_err(fqw, -ENOSYS); /* XXX maybe -ENOTTY */
}

static int do_ioc_getflags(struct voluta_fuseq_worker *fqw, ino_t ino,
			   const struct voluta_fuseq_in *in)
{
	int err;
	long attr = 0;
	size_t out_bufsz;
	struct statx stx;

	out_bufsz = in->u.ioctl.arg.out_size;
	if (out_bufsz != sizeof(attr)) {
		err = -EINVAL;
	} else {
		fuseq_lock_fs(fqw);
		err = voluta_fs_statx(fqw->sbi, fqw->op, ino, &stx);
		fuseq_unlock_fs(fqw);

		attr = (long)stx.stx_attributes;
	}
	return fuseq_reply_ioctl(fqw, 0, &attr, sizeof(attr), err);
}

static int do_ioc_query(struct voluta_fuseq_worker *fqw, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
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
		err = -ENOSYS;
		goto out;
	}
	if (bsz_out != sizeof(query)) {
		err = -EINVAL;
		goto out;
	}
	if (bsz_in < sizeof(query.qtype)) {
		err = -EINVAL;
		goto out;
	}
	query.qtype = ((const struct voluta_ioc_query *)buf_in)->qtype;
	fuseq_lock_fs(fqw);
	err = voluta_fs_query(fqw->sbi, fqw->op, ino, &query);
	fuseq_unlock_fs(fqw);
out:
	return fuseq_reply_ioctl(fqw, 0, &query, sizeof(query), err);
}

static int do_ioc_clone(struct voluta_fuseq_worker *fqw, ino_t ino,
			const struct voluta_fuseq_in *in)
{
	int err;
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
		err = -ENOSYS;
	} else if (bsz_in < sizeof(clone.flags)) {
		err = -EINVAL;
	} else {
		clone.flags = ((const struct voluta_ioc_clone *)buf_in)->flags;

		fuseq_lock_fs(fqw);
		err = voluta_fs_clone(fqw->sbi, fqw->op, ino,
				      clone.name, sizeof(clone.name));
		fuseq_unlock_fs(fqw);
	}
	return fuseq_reply_ioctl(fqw, 0, &clone, sizeof(clone), err);
}

static int check_ioctl_flags(int flags)
{
	if (flags & FUSE_IOCTL_COMPAT) {
		return -ENOSYS;
	}
	if ((flags & FUSE_IOCTL_DIR) && (flags & FUSE_IOCTL_UNRESTRICTED)) {
		return -ENOTTY;
	}
	return 0;
}

static int do_ioctl_bad_flags(struct voluta_fuseq_worker *fqw, int err)
{
	return fuseq_reply_err(fqw, err);
}

static int do_ioctl(struct voluta_fuseq_worker *fqw, ino_t ino,
		    const struct voluta_fuseq_in *in)
{
	int err = 0;
	int ret;
	int flags;
	long cmd;
	size_t in_size;
	const void *in_buf;

	cmd = (long)(in->u.ioctl.arg.cmd);
	flags = (int)(in->u.ioctl.arg.flags);
	in_size = in->u.ioctl.arg.in_size;
	in_buf = in_size ? in->u.ioctl.buf : NULL;
	unused(in_buf); /* XXX */

	err = check_ioctl_flags(flags);
	if (err) {
		ret = do_ioctl_bad_flags(fqw, err);
	} else {
		switch (cmd) {
		case FS_IOC_GETFLAGS:
			ret = do_ioc_getflags(fqw, ino, in);
			break;
		case VOLUTA_FS_IOC_QUERY:
			ret = do_ioc_query(fqw, ino, in);
			break;
		case VOLUTA_FS_IOC_CLONE:
			ret = do_ioc_clone(fqw, ino, in);
			break;
		default:
			ret = do_ioc_notimpl(fqw, ino, in);
			break;
		}
	}
	return ret;
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
#if FUSE_KERNEL_MINOR_VERSION > 31
	FUSEQ_CMDDEF(FUSE_SETUPMAPPING, NULL, 0),
	FUSEQ_CMDDEF(FUSE_REMOVEMAPPING, NULL, 0),
#endif
};

static const struct voluta_fuseq_cmd *cmd_of(unsigned int opc)
{
	return (opc <= ARRAY_SIZE(fuseq_cmd_tbl)) ? &fuseq_cmd_tbl[opc] : NULL;
}



static int fuseq_resolve_opdesc(struct voluta_fuseq_worker *fqw,
				unsigned int opc)
{
	const struct voluta_fuseq_cmd *cmd = cmd_of(opc);

	if ((cmd == NULL) || (cmd->hook == NULL)) {
		return -ENOSYS;
	}
	if (!fqw->fq->fq_got_init && (cmd->code != FUSE_INIT)) {
		return -EIO;
	}
	if (fqw->fq->fq_got_init && (cmd->code == FUSE_INIT)) {
		return -EIO;
	}
	fqw->cmd = cmd;
	return 0;
}

static int fuseq_check_perm(const struct voluta_fuseq_worker *fqw, uid_t opuid)
{
	const uid_t owner = fqw->sbi->sb_owner.uid;

	if (!fqw->fq->fq_deny_others) {
		return 0;
	}
	if ((opuid == 0) || (owner == opuid)) {
		return 0;
	}
	switch (fqw->op->opcode) {
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

static void fuseq_assign_curr_oper(struct voluta_fuseq_worker *fqw,
				   const struct fuse_in_header *hdr)
{
	fqw->op->ucred.uid = (uid_t)(hdr->uid);
	fqw->op->ucred.gid = (gid_t)(hdr->gid);
	fqw->op->ucred.pid = (pid_t)(hdr->pid);
	fqw->op->ucred.umask = 0;
	fqw->op->unique = (long)hdr->unique;
	fqw->op->opcode = (int)hdr->opcode;
}

static int fuseq_setup_curr_xtime(struct voluta_fuseq_worker *fqw)
{
	const bool is_realtime = (fqw->cmd->realtime > 0);

	return voluta_ts_gettime(&fqw->op->xtime, is_realtime);
}

static struct voluta_fuseq_in *
fuseq_in_of(const struct voluta_fuseq_worker *fqw)
{
	const struct voluta_fuseq_in *in = &fqw->inb->u.in;

	return unconst(in);
}

static int fuseq_process_hdr(struct voluta_fuseq_worker *fqw)
{
	int err;
	const struct voluta_fuseq_in *in = fuseq_in_of(fqw);
	const struct fuse_in_header *hdr = &in->u.hdr.hdr;

	fuseq_assign_curr_oper(fqw, hdr);
	err = fuseq_resolve_opdesc(fqw, hdr->opcode);
	if (err) {
		return err;
	}
	err = fuseq_check_perm(fqw, hdr->uid);
	if (err) {
		return err;
	}
	err = fuseq_setup_curr_xtime(fqw);
	if (err) {
		return err;
	}
	return 0;
}

static int fuseq_call_oper(struct voluta_fuseq_worker *fqw)
{
	const struct voluta_fuseq_in *in = fuseq_in_of(fqw);
	const unsigned long nodeid = in->u.hdr.hdr.nodeid;

	return fqw->cmd->hook(fqw, (ino_t)nodeid, in);
}

static int fuseq_exec_request(struct voluta_fuseq_worker *fqw)
{
	int err;

	err = fuseq_process_hdr(fqw);
	if (err) {
		return fuseq_reply_err(fqw, err);
	}
	fqw->fq->fq_nopers++;
	fqw->fq->fq_times = voluta_time_now();
	err = fuseq_call_oper(fqw);
	if (err == -ENOENT) {
		/* probably due to FR_ABORTED on FUSE side */
		return -FUSEQ_ENOTX;
	}
	return err;
}

static void fuseq_reset_inhdr(struct voluta_fuseq_worker *fqw)
{
	struct voluta_fuseq_in *in = fuseq_in_of(fqw);

	memset(&in->u.hdr, 0, sizeof(in->u.hdr));
}

static int fuseq_check_inhdr(const struct voluta_fuseq_worker *fqw, size_t nrd)
{
	const struct voluta_fuseq_in *in = fuseq_in_of(fqw);
	const int opc = (int)in->u.hdr.hdr.opcode;
	const size_t len = in->u.hdr.hdr.len;

	if (len != nrd) {
		log_err("header length mismatch: "\
			"opc=%d nrd=%lu len=%lu ", opc, nrd, len);
		return -EIO;
	}
	if ((len > sizeof(in->u)) && (opc != FUSE_WRITE)) {
		log_err("illegal header: opc=%d len=%lu", opc, len);
		return -EPROTO;
	}
	return 0;
}

static int fuseq_check_pipe_pre(const struct voluta_fuseq_worker *fqw)
{
	const struct voluta_pipe *pipe = &fqw->pipe;
	const size_t buffsize = fqw->fq->fq_coni.buffsize;

	if (buffsize != pipe->size) {
		log_err("pipe-fuse mismatch: pipesize=%lu buffsize=%lu ",
			pipe->size, buffsize);
		return -EIO;
	}
	if (pipe->pend != 0) {
		log_err("pipe not empty: pend=%lu fuse_fd=%d",
			pipe->pend, fqw->fq->fq_fuse_fd);
		return -EIO;
	}
	return 0;
}

static int fuseq_wait_request(const struct voluta_fuseq_worker *fqw)
{
	const int fuse_fd = fqw->fq->fq_fuse_fd;
	const struct timespec ts = { .tv_sec = 1 };

	return voluta_sys_pselect_rfd(fuse_fd, &ts);
}

static int fuseq_do_recv_in(struct voluta_fuseq_worker *fqw, size_t *out_sz)
{
	const int fuse_fd = fqw->fq->fq_fuse_fd;
	struct voluta_fuseq_in *in = fuseq_in_of(fqw);

	return voluta_sys_read(fuse_fd, in, sizeof(*in), out_sz);
}

static int fuseq_recv_in(struct voluta_fuseq_worker *fqw)
{
	int err;
	size_t len = 0;

	err = fuseq_do_recv_in(fqw, &len);
	if (err == -ETIMEDOUT) {
		return err;
	}
	if (err) {
		log_err("read fuse-to-buff failed: fuse_fd=%d err=%d",
			fqw->fq->fq_fuse_fd, err);
		return err;
	}
	if (len < sizeof(struct fuse_in_header)) {
		log_err("fuse read-in too-short: len=%lu", len);
		return -EIO;
	}
	return fuseq_check_inhdr(fqw, len);
}

static void *tail_of(struct voluta_fuseq_in *in, size_t head_len)
{
	void *p = in;

	return (uint8_t *)p + head_len;
}

static int fuseq_do_splice_in(struct voluta_fuseq_worker *fqw)
{
	const int fuse_fd = fqw->fq->fq_fuse_fd;
	struct voluta_pipe *pipe = &fqw->pipe;

	return pipe_splice_from_fd(pipe, fuse_fd, NULL, pipe->size);
}

static int fuseq_splice_in(struct voluta_fuseq_worker *fqw)
{
	int err;
	int opc;
	size_t rem;
	size_t len;
	size_t nsp = 0;
	size_t hdr_len = 0;
	void *tail = NULL;
	struct voluta_fuseq_in *in = NULL;
	struct voluta_pipe *pipe = &fqw->pipe;

	err = fuseq_do_splice_in(fqw);
	if (err == -ETIMEDOUT) {
		return err;
	}
	if (err) {
		log_err("fuse splice-in failed: fuse_fd=%d err=%d",
			fqw->fq->fq_fuse_fd, err);
		return err;
	}
	nsp = pipe->pend;
	hdr_len = sizeof(in->u.hdr.hdr);
	if (nsp < hdr_len) {
		log_err("fuse splice-in too-short: "\
			"nsp=%lu hdr_len=%lu", nsp, hdr_len);
		return -EIO;
	}
	in = fuseq_in_of(fqw);
	len = min(nsp, sizeof(in->u.write));
	err = pipe_copy_to_buf(pipe, in, len);
	if (err) {
		log_err("pipe-copy failed: len=%lu err=%d", len, err);
		return err;
	}
	err = fuseq_check_inhdr(fqw, nsp);
	if (err) {
		return err;
	}
	opc = (int)in->u.hdr.hdr.opcode;
	rem = nsp - len;
	if (!rem || (opc == FUSE_WRITE)) {
		return 0;
	}
	tail = tail_of(in, len); /* FUSE_SETXATTR, FUSE_BATCH_FORGET et.al. */
	err = pipe_copy_to_buf(pipe, tail, rem);
	if (err) {
		log_err("pipe-copy-tail failed: "\
			"opc=%d len=%lu err=%d", opc, rem, err);
		return err;
	}
	return 0;
}

static bool fuseq_is_active(const struct voluta_fuseq *fq)
{
	return fq->fq_active > 0;
}

static bool fuseq_cap_splice_in(const struct voluta_fuseq_worker *fqw)
{
	return fuseq_cap_splice_read(fqw->fq);
}

static int fuseq_recv_in_locked(struct voluta_fuseq_worker *fqw)
{
	int err = -FUSEQ_ENORX;

	fuseq_lock_ch(fqw);
	if (fuseq_is_active(fqw->fq)) {
		err = fuseq_wait_request(fqw);
		if (!err) {
			if (fuseq_cap_splice_in(fqw)) {
				err = fuseq_splice_in(fqw);
			} else {
				err = fuseq_recv_in(fqw);
			}
		}
	}
	fuseq_unlock_ch(fqw);
	return err;
}

static int fuseq_read_or_splice_request(struct voluta_fuseq_worker *fqw)
{
	int err;

	err = fuseq_check_pipe_pre(fqw);
	if (err) {
		return err;
	}
	err = fuseq_recv_in_locked(fqw);
	if ((err == -ETIMEDOUT) || (err == -FUSEQ_ENORX)) {
		return err;
	}
	if (err == -ENOENT) {
		/* hmmm... ok, but why? */
		return -FUSEQ_ENORX;
	}
	if ((err == -EINTR) || (err == -EAGAIN)) {
		log_dbg("fuse no-read: err=%d", err);
		return -FUSEQ_ENORX;
	}
	if (err == -ENODEV) {
		/* Filesystem unmounted, or connection aborted */
		log_info("fuse connection aborted: err=%d", err);
		return err;
	}
	if (err) {
		log_err("fuse recv-request: err=%d", err);
		return err;
	}
	return 0;
}

static int fuseq_prep_request(struct voluta_fuseq_worker *fqw)
{
	const int null_fd = fqw->fq->fq_null_fd;

	fuseq_reset_inhdr(fqw);
	return pipe_flush_to_fd(&fqw->pipe, null_fd);
}

static int fuseq_recv_request(struct voluta_fuseq_worker *fqw)
{
	int err;

	err = fuseq_prep_request(fqw);
	if (err) {
		return err;
	}
	err = fuseq_read_or_splice_request(fqw);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_fuseq_inb *inb_new(struct voluta_qalloc *qal)
{
	struct voluta_fuseq_inb *inb;

	return voluta_qalloc_zmalloc(qal, sizeof(*inb));
}

static void inb_del(struct voluta_fuseq_inb *inb, struct voluta_qalloc *qal)
{
	voluta_qalloc_zfree(qal, inb, sizeof(*inb));
}

static struct voluta_fuseq_outb *outb_new(struct voluta_qalloc *qal)
{
	struct voluta_fuseq_outb *outb;

	outb = voluta_qalloc_zmalloc(qal, sizeof(*outb));
	return outb;
}

static void outb_del(struct voluta_fuseq_outb *outb, struct voluta_qalloc *qal)
{
	voluta_qalloc_zfree(qal, outb, sizeof(*outb));
}


static struct voluta_fuseq_rw_iter *rwi_new(struct voluta_qalloc *qal)
{
	struct voluta_fuseq_rw_iter *rwi;

	rwi = voluta_qalloc_zmalloc(qal, sizeof(*rwi));
	return rwi;
}

static void rwi_del(struct voluta_fuseq_rw_iter *rwi,
		    struct voluta_qalloc *qal)
{
	voluta_qalloc_zfree(qal, rwi, sizeof(*rwi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static size_t fuseq_bufsize_max(const struct voluta_fuseq *fq)
{
	const struct voluta_fuseq_worker *fqw = &fq->fq_worker[0];
	const size_t inbuf_max = sizeof(*fqw->inb);
	const size_t outbuf_max = sizeof(*fqw->outb);

	unused(fqw); /* make clangscan happy */

	return max(inbuf_max, outbuf_max);
}

static int fuseq_init_conn_info(struct voluta_fuseq *fq)
{
	int err;
	size_t pipe_maxsz;
	size_t pipe_size;
	size_t buff_size;
	size_t rdwr_size;
	const size_t mega = VOLUTA_UMEGA;
	const size_t fuse_min_bsz = FUSE_MIN_READ_BUFFER;
	const size_t bufsize_max = fuseq_bufsize_max(fq);
	const size_t page_size = voluta_sc_page_size();

	err = pipe_max_size(&pipe_maxsz);
	if (err) {
		log_err("could not resolve max pipe-size: err=%d", err);
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

static int fuseq_init_pipe(struct voluta_fuseq_worker *fqw, size_t pipe_size)
{
	int err;
	struct voluta_pipe *pipe = &fqw->pipe;

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

static void fuseq_fini_pipe(struct voluta_fuseq_worker *fqw)
{
	pipe_fini(&fqw->pipe);
}

static int fuseq_init_bufs(struct voluta_fuseq_worker *fqw)
{
	struct voluta_qalloc *qal = fqw->fq->fq_qal;

	fqw->inb = inb_new(qal);
	if (fqw->inb == NULL) {
		return -ENOMEM;
	}
	fqw->outb = outb_new(qal);
	if (fqw->outb == NULL) {
		inb_del(fqw->inb, qal);
		fqw->inb = NULL;
		return -ENOMEM;
	}
	return 0;
}

static void fuseq_fini_bufs(struct voluta_fuseq_worker *fqw)
{
	struct voluta_qalloc *qal = fqw->fq->fq_qal;

	outb_del(fqw->outb, qal);
	inb_del(fqw->inb, qal);
	fqw->inb = NULL;
	fqw->outb = NULL;
}

static int fuseq_init_rwi(struct voluta_fuseq_worker *fqw)
{
	fqw->rwi = rwi_new(fqw->fq->fq_qal);
	return (fqw->rwi != NULL) ? 0 : -ENOMEM;
}

static void fuseq_fini_rwi(struct voluta_fuseq_worker *fqw)
{
	if (fqw->rwi != NULL) {
		rwi_del(fqw->rwi, fqw->fq->fq_qal);
		fqw->rwi = NULL;
	}
}

static int fuseq_init_worker(struct voluta_fuseq_worker *fqw,
			     struct voluta_fuseq *fq, int idx)
{
	int err;
	const size_t pipe_size = fq->fq_coni.buffsize;

	STATICASSERT_LE(sizeof(*fqw), 256);

	fqw->cmd = NULL;
	fqw->fq  = fq;
	fqw->sbi = fq->fq_sbi;
	fqw->inb = NULL;
	fqw->outb = NULL;
	fqw->idx = idx;
	fqw->op = &fqw->oper;

	err = fuseq_init_bufs(fqw);
	if (err) {
		goto out;
	}
	err = fuseq_init_rwi(fqw);
	if (err) {
		goto out;
	}
	err = fuseq_init_pipe(fqw, pipe_size);
	if (err) {
		goto out;
	}
out:
	if (err) {
		fuseq_fini_pipe(fqw);
		fuseq_fini_rwi(fqw);
		fuseq_fini_bufs(fqw);
	}
	return err;
}

static void fuseq_fini_worker(struct voluta_fuseq_worker *fqw)
{
	fuseq_fini_pipe(fqw);
	fuseq_fini_rwi(fqw);
	fuseq_fini_bufs(fqw);
	fqw->cmd = NULL;
	fqw->fq  = NULL;
	fqw->sbi = NULL;
	fqw->op = NULL;
}

static int fuseq_init_workers(struct voluta_fuseq *fq)
{
	int err;
	int nprocs;
	int nworkers;
	const int nworkers_max = (int)ARRAY_SIZE(fq->fq_worker);

	nprocs = get_nprocs_conf();
	nworkers = min_int(nprocs, nworkers_max);

	log_dbg("init fuseq workers: nprocs=%d nworkers=%d", nprocs, nworkers);

	fq->fq_nworkers_avail = 0;
	fq->fq_nworkers_active = 0;
	for (int i = 0; i < nworkers; ++i) {
		err = fuseq_init_worker(&fq->fq_worker[i], fq, i);
		if (err) {
			return err;
		}
		fq->fq_nworkers_avail++;
	}
	return 0;
}

static void fuseq_fini_workers(struct voluta_fuseq *fq)
{
	for (int i = 0; i < fq->fq_nworkers_avail; ++i) {
		fuseq_fini_worker(&fq->fq_worker[i]);
	}
}

static int fuseq_init_null_fd(struct voluta_fuseq *fq)
{
	int err;
	int null_fd = -1;
	const int o_flags = O_WRONLY | O_CREAT | O_TRUNC;

	err =  voluta_sys_open("/dev/null", o_flags, 0666, &null_fd);
	if (!err) {
		fq->fq_null_fd = null_fd;
	}
	return err;
}

static void fuseq_fini_null_fd(struct voluta_fuseq *fq)
{
	if (fq->fq_null_fd > 0) {
		voluta_sys_close(fq->fq_null_fd);
		fq->fq_null_fd = -1;
	}
}

static int fuseq_init_locks(struct voluta_fuseq *fq)
{
	int err;

	err = voluta_mutex_init(&fq->fq_ch_lock);
	if (err) {
		return err;
	}
	err = voluta_mutex_init(&fq->fq_fs_lock);
	if (err) {
		voluta_mutex_destroy(&fq->fq_ch_lock);
		return err;
	}
	return 0;
}

static void fuseq_fini_locks(struct voluta_fuseq *fq)
{
	voluta_mutex_destroy(&fq->fq_fs_lock);
	voluta_mutex_destroy(&fq->fq_ch_lock);
}

static void fuseq_init_common(struct voluta_fuseq *fq,
			      struct voluta_sb_info *sbi)
{
	fq->fq_times = 0;
	fq->fq_sbi = sbi;
	fq->fq_qal = sbi->sb_qalloc;
	fq->fq_nopers = 0;
	fq->fq_nworkers_avail = 0;
	fq->fq_nworkers_active = 0;
	fq->fq_fuse_fd = -1;
	fq->fq_null_fd = -1;
	fq->fq_got_init = false;
	fq->fq_got_destroy = false;
	fq->fq_deny_others = false;
	fq->fq_active = 0;
	fq->fq_umount = false;
	fq->fq_splice_memfd = false;
}

int voluta_fuseq_init(struct voluta_fuseq *fq, struct voluta_sb_info *sbi)
{
	int err;

	voluta_memzero(fq, sizeof(*fq));
	fuseq_init_common(fq, sbi);

	err = fuseq_init_conn_info(fq);
	if (err) {
		return err;
	}
	err = fuseq_init_locks(fq);
	if (err) {
		goto out;
	}
	err = fuseq_init_workers(fq);
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
		fuseq_fini_workers(fq);
		fuseq_fini_locks(fq);
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
	fuseq_fini_workers(fq);
	fuseq_fini_locks(fq);

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

static int fuseq_check_input(const struct voluta_fuseq_worker *fqw)
{
	int err = 0;
	const struct voluta_fuseq_in *in = fuseq_in_of(fqw);
	const uint32_t in_len = in->u.hdr.hdr.len;
	const uint32_t opcode = in->u.hdr.hdr.opcode;

	if (!in_len || !opcode) {
		log_warn("bad fuse input: in_len=%u opcode=%u",
			 in_len, opcode);
		err = -FUSEQ_ENORX;
	}
	return err;
}

static int fuseq_exec_one(struct voluta_fuseq_worker *fqw)
{
	int err;

	if (!fuseq_is_active(fqw->fq)) {
		return -FUSEQ_ENORX;
	}
	err = fuseq_recv_request(fqw);
	if (err) {
		return err;
	}
	err = fuseq_check_input(fqw);
	if (err) {
		return err;
	}
	err = fuseq_exec_request(fqw);
	if (err) {
		return err;
	}
	return 0;
}

static int fuseq_do_timeout(struct voluta_fuseq_worker *fqw)
{
	int flags;
	int err = 0;
	const time_t now = voluta_time_now();
	const time_t dif = labs(now - fqw->fq->fq_times);

	if (fuseq_is_normal(fqw->fq) && (dif > 2)) {
		flags = (dif > 10) ? VOLUTA_F_IDLE : 0;

		fuseq_lock_fs(fqw);
		err = voluta_fs_timedout(fqw->fq->fq_sbi, flags);
		fuseq_unlock_fs(fqw);
	}
	return err;
}

static int fuseq_sub_exec_loop(struct voluta_fuseq_worker *fqw)
{
	int err = 0;

	while (!err && fuseq_is_active(fqw->fq)) {
		/* bootstrap case: only worker-0 may operate */
		if (fqw->idx && !fuseq_is_normal(fqw->fq)) {
			sleep(1);
			continue;
		}

		/* serve single in-comming request */
		err = fuseq_exec_one(fqw);

		/* timeout case */
		if (err == -ETIMEDOUT) {
			err = fuseq_do_timeout(fqw);
			voluta_assert_ok(err);
			continue;
		}
		/* umount case */
		if (err == -ENODEV) {
			fqw->fq->fq_active = 0; /* umount case */
			break;
		}
		/* no-lock & interrupt cases */
		if ((err == -FUSEQ_ENORX) || (err == -FUSEQ_ENOTX)) {
			usleep(1);
			err = 0;
		}

		/* XXX FIXME */
		if (err == -ENOENT) {
			log_err("unexpected: err=%d", err);
			sleep(1);
			err = 0;
		}
	}
	return err;
}

static struct voluta_fuseq_worker *
thread_to_fuseq_worker(struct voluta_thread *th)
{
	return container_of(th, struct voluta_fuseq_worker, th);
}

static int fuseq_start(struct voluta_thread *th)
{
	int err;
	struct voluta_fuseq_worker *fqw = thread_to_fuseq_worker(th);

	log_info("exec fuseq-worker: %s", th->name);
	err = fuseq_sub_exec_loop(fqw);
	log_info("done fuseq-worker: %s err=%d", th->name, err);
	return err;
}

static int fuseq_exec_thread(struct voluta_fuseq_worker *fqw)
{
	int err;
	char name[32] = "";

	snprintf(name, sizeof(name) - 1, "voluta-%d", fqw->idx + 1);
	err = voluta_thread_create(&fqw->th, fuseq_start, name);
	if (err) {
		log_err("failed to create fuse worker: %s err=%d", name, err);
	}
	return err;
}

static int fuseq_join_thread(struct voluta_fuseq_worker *fqw)
{
	return voluta_thread_join(&fqw->th);
}

static void fuseq_suspend_while_active(const struct voluta_fuseq *fq)
{
	while (fuseq_is_active(fq)) {
		sleep(1);
	}
}

static int fuseq_start_workers(struct voluta_fuseq *fq)
{
	int err;

	fq->fq_active = 1;
	fq->fq_nworkers_active = 0;
	for (int i = 0; i < fq->fq_nworkers_avail; ++i) {
		err = fuseq_exec_thread(&fq->fq_worker[i]);
		if (err) {
			return err;
		}
		fq->fq_nworkers_active++;
	}
	return 0;
}

static void fuseq_finish_workers(struct voluta_fuseq *fq)
{
	fq->fq_active = 0;
	for (int i = 0; i < fq->fq_nworkers_active; ++i) {
		fuseq_join_thread(&fq->fq_worker[i]);
	}
}

int voluta_fuseq_exec(struct voluta_fuseq *fq)
{
	int err;

	err = fuseq_start_workers(fq);
	if (!err) {
		fuseq_suspend_while_active(fq);
	}
	fuseq_finish_workers(fq);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fuseq_lock_ch(const struct voluta_fuseq_worker *fqw)
{
	voluta_mutex_lock(&fqw->fq->fq_ch_lock);
}

static void fuseq_unlock_ch(const struct voluta_fuseq_worker *fqw)
{
	voluta_mutex_unlock(&fqw->fq->fq_ch_lock);
}

static void fuseq_lock_fs(const struct voluta_fuseq_worker *fqw)
{
	voluta_mutex_lock(&fqw->fq->fq_fs_lock);
}

static void fuseq_unlock_fs(const struct voluta_fuseq_worker *fqw)
{
	voluta_mutex_unlock(&fqw->fq->fq_fs_lock);
}
