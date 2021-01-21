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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <linux/falloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <limits.h>
#include "unitest.h"

static struct voluta_sb_info *sbi(struct ut_env *ute)
{
	return ute->fse->sbi;
}

static const struct voluta_oper *op(struct ut_env *ute)
{
	struct voluta_oper *oper = &ute->oper;

	oper->ucred.uid = getuid();
	oper->ucred.gid = getgid();
	oper->ucred.pid = getpid();
	oper->ucred.umask = 0002;
	oper->unique = ute->unique_count++;
	voluta_ts_gettime(&oper->xtime, true);

	return oper;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ut_statfs(struct ut_env *ute,
		     ino_t ino, struct statvfs *st)
{
	return voluta_fs_statfs(sbi(ute), op(ute), ino, st);
}

static int ut_statx(struct ut_env *ute, ino_t ino, struct statx *stx)
{
	return voluta_fs_statx(sbi(ute), op(ute), ino, stx);
}

static int ut_access(struct ut_env *ute, ino_t ino, int mode)
{
	return voluta_fs_access(sbi(ute), op(ute), ino, mode);
}

static int ut_getattr(struct ut_env *ute, ino_t ino, struct stat *st)
{
	return voluta_fs_getattr(sbi(ute), op(ute), ino, st);
}

static int ut_lookup(struct ut_env *ute, ino_t parent,
		     const char *name, struct stat *st)
{
	return voluta_fs_lookup(sbi(ute), op(ute), parent, name, st);
}

static int ut_utimens(struct ut_env *ute, ino_t ino,
		      const struct stat *utimes, struct stat *st)
{
	return voluta_fs_utimens(sbi(ute), op(ute), ino, utimes, st);
}

static int ut_mkdir(struct ut_env *ute, ino_t parent,
		    const char *name, mode_t mode, struct stat *out_st)
{
	return voluta_fs_mkdir(sbi(ute), op(ute),
			       parent, name, mode | S_IFDIR, out_st);
}

static int ut_rmdir(struct ut_env *ute, ino_t parent, const char *name)
{
	return voluta_fs_rmdir(sbi(ute), op(ute), parent, name);
}

static int ut_opendir(struct ut_env *ute, ino_t ino)
{
	return voluta_fs_opendir(sbi(ute), op(ute), ino);
}

static int ut_releasedir(struct ut_env *ute, ino_t ino)
{
	return voluta_fs_releasedir(sbi(ute), op(ute), ino, 0);
}

static int ut_fsyncdir(struct ut_env *ute, ino_t ino, bool datasync)
{
	return voluta_fs_fsyncdir(sbi(ute), op(ute), ino, datasync);
}


static int ut_symlink(struct ut_env *ute, ino_t parent,
		      const char *name, const char *val, struct stat *out_st)
{
	return voluta_fs_symlink(sbi(ute), op(ute),
				 parent, name, val, out_st);
}

static int ut_readlink(struct ut_env *ute,
		       ino_t ino, char *buf, size_t len, size_t *out_len)
{
	return voluta_fs_readlink(sbi(ute), op(ute),
				  ino, buf, len, out_len);
}

static int ut_link(struct ut_env *ute, ino_t ino, ino_t parent,
		   const char *name, struct stat *out_st)
{
	return voluta_fs_link(sbi(ute), op(ute),
			      ino, parent, name, out_st);
}

static int ut_unlink(struct ut_env *ute, ino_t parent, const char *name)
{
	return voluta_fs_unlink(sbi(ute), op(ute), parent, name);
}

static int ut_create(struct ut_env *ute, ino_t parent,
		     const char *name, mode_t mode, struct stat *out_st)
{
	return voluta_fs_create(sbi(ute), op(ute),
				parent, name, 0, mode, out_st);
}

static int ut_open(struct ut_env *ute, ino_t ino, int flags)
{
	return voluta_fs_open(sbi(ute), op(ute), ino, flags);
}

static int ut_release(struct ut_env *ute, ino_t ino)
{
	return voluta_fs_release(sbi(ute), op(ute), ino, 0, false);
}

static int ut_truncate(struct ut_env *ute, ino_t ino,
		       loff_t length, struct stat *out_st)
{
	return voluta_fs_truncate(sbi(ute), op(ute),
				  ino, length, out_st);
}

static int ut_fsync(struct ut_env *ute, ino_t ino, bool datasync)
{
	return voluta_fs_fsync(sbi(ute), op(ute), ino, datasync);
}

static int ut_rename(struct ut_env *ute, ino_t parent,
		     const char *name, ino_t newparent,
		     const char *newname, int flags)
{
	return voluta_fs_rename(sbi(ute), op(ute), parent, name,
				newparent, newname, flags);
}

static int ut_fiemap(struct ut_env *ute, ino_t ino, struct fiemap *fm)
{
	return voluta_fs_fiemap(sbi(ute), op(ute), ino, fm);
}

static int ut_lseek(struct ut_env *ute, ino_t ino,
		    loff_t off, int whence, loff_t *out)
{
	return voluta_fs_lseek(sbi(ute), op(ute), ino, off, whence, out);
}

static int ut_query(struct ut_env *ute, ino_t ino,
		    struct voluta_ioc_query *out_qry)
{
	return voluta_fs_query(sbi(ute), op(ute), ino, out_qry);
}

static int ut_read(struct ut_env *ute, ino_t ino, void *buf,
		   size_t len, loff_t off, size_t *out_len)
{
	return voluta_fs_read(sbi(ute), op(ute),
			      ino, buf, len, off, out_len);
}

static int ut_write(struct ut_env *ute, ino_t ino, const void *buf,
		    size_t len, off_t off, size_t *out_len)
{
	return voluta_fs_write(sbi(ute), op(ute),
			       ino, buf, len, off, out_len);
}

static int ut_fallocate(struct ut_env *ute, ino_t ino,
			int mode, loff_t offset, loff_t len)
{
	return voluta_fs_fallocate(sbi(ute), op(ute),
				   ino, mode, offset, len);
}

static struct ut_readdir_ctx *ut_readdir_ctx_of(struct voluta_readdir_ctx *ptr)
{
	return ut_container_of(ptr, struct ut_readdir_ctx, rd_ctx);
}

static int filldir(struct voluta_readdir_ctx *rd_ctx,
		   const struct voluta_readdir_info *rdi)
{
	size_t ndents_max;
	struct ut_dirent_info *dei;
	struct ut_readdir_ctx *ut_rd_ctx;

	ut_rd_ctx = ut_readdir_ctx_of(rd_ctx);
	ndents_max = UT_ARRAY_SIZE(ut_rd_ctx->dei);

	if ((rdi->off < 0) || !rdi->namelen) {
		return -EINVAL;
	}
	if (ut_rd_ctx->nde >= ndents_max) {
		return -EINVAL;
	}
	dei = &ut_rd_ctx->dei[ut_rd_ctx->nde++];

	ut_expect(rdi->namelen < sizeof(dei->de.d_name));
	memcpy(dei->de.d_name, rdi->name, rdi->namelen);
	dei->de.d_name[rdi->namelen] = '\0';
	dei->de.d_reclen = (uint16_t)rdi->namelen;
	dei->de.d_ino = rdi->ino;
	dei->de.d_type = (uint8_t)rdi->dt;
	dei->de.d_off = rdi->off;
	if (ut_rd_ctx->plus) {
		memcpy(&dei->attr, &rdi->attr, sizeof(dei->attr));
	}
	return 0;
}

static int ut_readdir(struct ut_env *ute, ino_t ino, loff_t doff,
		      struct ut_readdir_ctx *ut_rd_ctx)
{
	struct voluta_readdir_ctx *rd_ctx = &ut_rd_ctx->rd_ctx;

	ut_rd_ctx->nde = 0;
	ut_rd_ctx->plus = 0;
	rd_ctx->pos = doff;
	rd_ctx->actor = filldir;
	return voluta_fs_readdir(sbi(ute), op(ute), ino, rd_ctx);
}

static int ut_readdirplus(struct ut_env *ute, ino_t ino, loff_t doff,
			  struct ut_readdir_ctx *ut_rd_ctx)
{
	struct voluta_readdir_ctx *rd_ctx = &ut_rd_ctx->rd_ctx;

	ut_rd_ctx->nde = 0;
	ut_rd_ctx->plus = 1;
	rd_ctx->pos = doff;
	rd_ctx->actor = filldir;
	return voluta_fs_readdirplus(sbi(ute), op(ute), ino, rd_ctx);
}

static int ut_setxattr(struct ut_env *ute, ino_t ino,
		       const char *name, const void *value,
		       size_t size, int flags)
{
	return voluta_fs_setxattr(sbi(ute), op(ute),
				  ino, name, value, size, flags);
}

static int ut_getxattr(struct ut_env *ute, ino_t ino,
		       const char *name, void *buf,
		       size_t size, size_t *out_size)
{
	return voluta_fs_getxattr(sbi(ute), op(ute),
				  ino, name, buf, size, out_size);
}

static int ut_removexattr(struct ut_env *ute, ino_t ino, const char *name)
{
	return voluta_fs_removexattr(sbi(ute), op(ute), ino, name);
}

static struct ut_listxattr_ctx *
ut_listxattr_ctx_of(struct voluta_listxattr_ctx *ptr)
{
	return ut_container_of(ptr, struct ut_listxattr_ctx,
			       lxa_ctx);
}

static int fillxent(struct voluta_listxattr_ctx *lxa_ctx,
		    const char *name, size_t nlen)
{
	char *xname;
	size_t limit;
	struct ut_listxattr_ctx *ut_lxa_ctx;

	ut_lxa_ctx = ut_listxattr_ctx_of(lxa_ctx);

	limit = sizeof(ut_lxa_ctx->names);
	if (ut_lxa_ctx->count == limit) {
		return -ERANGE;
	}
	xname = ut_strndup(ut_lxa_ctx->ute, name, nlen);
	ut_lxa_ctx->names[ut_lxa_ctx->count++] = xname;
	return 0;
}

static int ut_listxattr(struct ut_env *ute, ino_t ino,
			struct ut_listxattr_ctx *ut_lxa_ctx)
{
	struct voluta_listxattr_ctx *lxa_ctx = &ut_lxa_ctx->lxa_ctx;

	memset(ut_lxa_ctx, 0, sizeof(*ut_lxa_ctx));
	ut_lxa_ctx->ute = ute;
	ut_lxa_ctx->lxa_ctx.actor = fillxent;

	return voluta_fs_listxattr(sbi(ute), op(ute), ino, lxa_ctx);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define ut_expect_status(err_, status_) \
	ut_expect_eq(err_, -abs(status_))

void ut_access_ok(struct ut_env *ute, ino_t ino, int mode)
{
	int err;

	err = ut_access(ute, ino, mode);
	ut_expect_ok(err);
}

void ut_statfs_ok(struct ut_env *ute, ino_t ino, struct statvfs *st)
{
	int err;

	err = ut_statfs(ute, ino, st);
	ut_expect_ok(err);
}

void ut_statfs_rootd(struct ut_env *ute, struct statvfs *st)
{
	ut_statfs_ok(ute, VOLUTA_INO_ROOT, st);
}

static void ut_expect_sane_statx(const struct statx *stx)
{
	ut_expect_gt(stx->stx_blksize, 0);
	ut_expect_gt(stx->stx_btime.tv_sec, 0);
	ut_expect_le(stx->stx_btime.tv_sec, stx->stx_ctime.tv_sec);
	ut_expect_le(stx->stx_btime.tv_sec, stx->stx_mtime.tv_sec);
}

void ut_statx_exists(struct ut_env *ute, ino_t ino, struct statx *stx)
{
	int err;

	err = ut_statx(ute, ino, stx);
	ut_expect_ok(err);
	ut_expect_sane_statx(stx);
}

void ut_getattr_ok(struct ut_env *ute, ino_t ino, struct stat *st)
{
	int err;

	err = ut_getattr(ute, ino, st);
	ut_expect_ok(err);
	ut_expect_eq(ino, st->st_ino);
}

void ut_getattr_noent(struct ut_env *ute, ino_t ino)
{
	int err;
	struct stat st;

	err = ut_getattr(ute, ino, &st);
	ut_expect_err(err, -ENOENT);
}

void ut_getattr_file(struct ut_env *ute, ino_t ino, struct stat *st)
{
	ut_getattr_ok(ute, ino, st);
	ut_expect(S_ISREG(st->st_mode));
}

void ut_getattr_lnk(struct ut_env *ute, ino_t ino, struct stat *st)
{
	ut_getattr_ok(ute, ino, st);
	ut_expect(S_ISLNK(st->st_mode));
}

void ut_getattr_dir(struct ut_env *ute, ino_t ino, struct stat *st)
{
	ut_getattr_ok(ute, ino, st);
	ut_expect(S_ISDIR(st->st_mode));
}

void ut_getattr_dirsize(struct ut_env *ute, ino_t ino, loff_t size)
{
	struct stat st;

	ut_getattr_dir(ute, ino, &st);
	ut_expect_ge(st.st_size, size);
	if (!size) {
		ut_expect_eq(st.st_size, VOLUTA_DIR_EMPTY_SIZE);
	}
}

void ut_utimens_atime(struct ut_env *ute, ino_t ino,
		      const struct timespec *atime)
{
	int err;
	struct stat st;
	struct stat uts = { .st_ino = 0 };

	uts.st_atim.tv_sec = atime->tv_sec;
	uts.st_atim.tv_nsec = atime->tv_nsec;
	uts.st_mtim.tv_nsec = UTIME_OMIT;
	uts.st_ctim.tv_sec = atime->tv_sec;
	uts.st_ctim.tv_nsec = atime->tv_nsec;

	err = ut_utimens(ute, ino, &uts, &st);
	ut_expect_ok(err);
	ut_expect_eq(ino, st.st_ino);
	ut_expect_eq(st.st_atim.tv_sec, atime->tv_sec);
	ut_expect_eq(st.st_atim.tv_nsec, atime->tv_nsec);
}

void ut_utimens_mtime(struct ut_env *ute, ino_t ino,
		      const struct timespec *mtime)
{
	int err;
	struct stat st;
	struct stat uts;

	memset(&uts, 0, sizeof(uts));
	uts.st_mtim.tv_sec = mtime->tv_sec;
	uts.st_mtim.tv_nsec = mtime->tv_nsec;
	uts.st_atim.tv_nsec = UTIME_OMIT;
	uts.st_ctim.tv_sec = mtime->tv_sec;
	uts.st_ctim.tv_nsec = mtime->tv_nsec;

	err = ut_utimens(ute, ino, &uts, &st);
	ut_expect_ok(err);
	ut_expect_eq(ino, st.st_ino);
	ut_expect_eq(st.st_mtim.tv_sec, mtime->tv_sec);
	ut_expect_eq(st.st_mtim.tv_nsec, mtime->tv_nsec);
}

static void ut_lookup_status(struct ut_env *ute, ino_t parent,
			     const char *name, struct stat *out_st, int status)
{
	int err;

	err = ut_lookup(ute, parent, name, out_st);
	ut_expect_status(err, status);
}

void ut_lookup_ok(struct ut_env *ute, ino_t parent,
		  const char *name, struct stat *out_st)
{
	ut_lookup_status(ute, parent, name, out_st, 0);
}

void ut_lookup_ino(struct ut_env *ute, ino_t parent,
		   const char *name, ino_t *out_ino)
{
	struct stat st;

	ut_lookup_ok(ute, parent, name, &st);
	*out_ino = st.st_ino;
}

void ut_lookup_noent(struct ut_env *ute, ino_t ino, const char *name)
{
	ut_lookup_status(ute, ino, name, NULL, -ENOENT);
}

void ut_lookup_exists(struct ut_env *ute, ino_t parent,
		      const char *name, ino_t ino, mode_t mode)
{
	struct stat st;

	ut_lookup_ok(ute, parent, name, &st);
	ut_expect_eq(ino, st.st_ino);
	ut_expect_eq(mode, st.st_mode & mode);
}

void ut_lookup_dir(struct ut_env *ute, ino_t parent,
		   const char *name, ino_t dino)
{
	ut_lookup_exists(ute, parent, name, dino, S_IFDIR);
}

void ut_lookup_file(struct ut_env *ute, ino_t parent,
		    const char *name, ino_t ino)
{
	ut_lookup_exists(ute, parent, name, ino, S_IFREG);
}

void ut_lookup_lnk(struct ut_env *ute, ino_t parent,
		   const char *name, ino_t ino)
{
	ut_lookup_exists(ute, parent, name, ino, S_IFLNK);
}


static void ut_mkdir_status(struct ut_env *ute, ino_t parent,
			    const char *name, struct stat *out_st, int status)
{
	int err;

	err = ut_mkdir(ute, parent, name, 0700, out_st);
	ut_expect_status(err, status);
}

void ut_mkdir_ok(struct ut_env *ute, ino_t parent,
		 const char *name, struct stat *out_st)
{
	int err;
	ino_t dino;
	struct stat st;

	ut_mkdir_status(ute, parent, name, out_st, 0);

	dino = out_st->st_ino;
	ut_expect_ne(dino, parent);
	ut_expect_ne(dino, VOLUTA_INO_NULL);

	err = ut_getattr(ute, dino, &st);
	ut_expect_ok(err);
	ut_expect_eq(st.st_ino, dino);
	ut_expect_eq(st.st_nlink, 2);

	err = ut_lookup(ute, parent, name, &st);
	ut_expect_ok(err);
	ut_expect_eq(st.st_ino, dino);

	err = ut_getattr(ute, parent, &st);
	ut_expect_ok(err);
	ut_expect_eq(st.st_ino, parent);
	ut_expect_gt(st.st_nlink, 2);
	ut_expect_gt(st.st_size, 0);
}

void ut_mkdir_oki(struct ut_env *ute, ino_t parent,
		  const char *name, ino_t *out_ino)
{
	struct stat st;

	ut_mkdir_ok(ute, parent, name, &st);
	*out_ino = st.st_ino;
}

void ut_mkdir_err(struct ut_env *ute, ino_t parent,
		  const char *name, int err)
{
	ut_mkdir_status(ute, parent, name, NULL, err);
}

void ut_mkdir_at_root(struct ut_env *ute,
		      const char *name, ino_t *out_ino)
{
	ut_mkdir_oki(ute, VOLUTA_INO_ROOT, name, out_ino);
}


static void ut_rmdir_status(struct ut_env *ute,
			    ino_t parent, const char *name, int status)
{
	int err;

	err = ut_rmdir(ute, parent, name);
	ut_expect_status(err, status);
}

void ut_rmdir_ok(struct ut_env *ute, ino_t parent, const char *name)
{
	struct stat st;

	ut_lookup_ok(ute, parent, name, &st);
	ut_rmdir_status(ute, parent, name, 0);
	ut_lookup_noent(ute, parent, name);
	ut_getattr_ok(ute, parent, &st);
}

void ut_rmdir_err(struct ut_env *ute, ino_t parent,
		  const char *name, int err)
{
	ut_rmdir_status(ute, parent, name, err);
}

void ut_rmdir_at_root(struct ut_env *ute, const char *name)
{
	ut_rmdir_ok(ute, VOLUTA_INO_ROOT, name);
}


static void ut_require_dir(struct ut_env *ute, ino_t dino)
{
	int err;
	struct stat st;

	err = ut_getattr(ute, dino, &st);
	ut_expect_ok(err);
	ut_expect(S_ISDIR(st.st_mode));
}

static void ut_opendir_status(struct ut_env *ute, ino_t ino, int status)
{
	int err;

	err = ut_opendir(ute, ino);
	ut_expect_status(err, status);
}

void ut_opendir_ok(struct ut_env *ute, ino_t ino)
{
	ut_require_dir(ute, ino);
	ut_opendir_status(ute, ino, 0);
}

void ut_opendir_err(struct ut_env *ute, ino_t ino, int err)
{
	ut_opendir_status(ute, ino, err);
}

static void ut_releasedir_status(struct ut_env *ute, ino_t ino, int status)
{
	int err;

	err = ut_releasedir(ute, ino);
	ut_expect_status(err, status);
}

void ut_releasedir_ok(struct ut_env *ute, ino_t ino)
{
	ut_require_dir(ute, ino);
	ut_releasedir_status(ute, ino, 0);
}

void ut_releasedir_err(struct ut_env *ute, ino_t ino, int err)
{
	ut_releasedir_status(ute, ino, err);
}

void ut_fsyncdir_ok(struct ut_env *ute, ino_t ino)
{
	int err;

	err = ut_fsyncdir(ute, ino, true);
	ut_expect_ok(err);
}

void ut_readdir_ok(struct ut_env *ute, ino_t ino, loff_t doff,
		   struct ut_readdir_ctx *ut_rd_ctx)
{
	int err;

	err = ut_readdir(ute, ino, doff, ut_rd_ctx);
	ut_expect_ok(err);
}

void ut_readdirplus_ok(struct ut_env *ute, ino_t ino, loff_t doff,
		       struct ut_readdir_ctx *ut_rd_ctx)
{
	int err;

	err = ut_readdirplus(ute, ino, doff, ut_rd_ctx);
	ut_expect_ok(err);
}

static void ut_link_status(struct ut_env *ute, ino_t ino,
			   ino_t parent, const char *name,
			   struct stat *out_st, int status)
{
	int err;

	err = ut_link(ute, ino, parent, name, out_st);
	ut_expect_status(err, status);
}

void ut_link_ok(struct ut_env *ute, ino_t ino,
		ino_t parent, const char *name, struct stat *out_st)
{
	nlink_t nlink1;
	nlink_t nlink2;
	struct stat st;

	ut_lookup_noent(ute, parent, name);
	ut_getattr_ok(ute, ino, &st);
	nlink1 = st.st_nlink;

	ut_link_status(ute, ino, parent, name, out_st, 0);
	ut_expect_eq(out_st->st_ino, ino);
	ut_expect_gt(out_st->st_nlink, 1);

	ut_lookup_ok(ute, parent, name, &st);
	ut_getattr_ok(ute, ino, &st);
	nlink2 = st.st_nlink;
	ut_expect_eq(nlink1 + 1, nlink2);
}

void ut_link_err(struct ut_env *ute, ino_t ino,
		 ino_t parent, const char *name, int err)
{
	ut_link_status(ute, ino, parent, name, NULL, err);
}


static void ut_unlink_status(struct ut_env *ute,
			     ino_t parent, const char *name, int status)
{
	int err;

	err = ut_unlink(ute, parent, name);
	ut_expect_status(err, status);
}

void ut_unlink_ok(struct ut_env *ute, ino_t parent, const char *name)
{
	ut_unlink_status(ute, parent, name, 0);
	ut_lookup_noent(ute, parent, name);
}

void ut_unlink_err(struct ut_env *ute,
		   ino_t parent, const char *name, int err)
{
	ut_unlink_status(ute, parent, name, err);
}

void ut_unlink_file(struct ut_env *ute,
		    ino_t parent, const char *name)
{
	ino_t ino;
	struct stat st;

	ut_lookup_ino(ute, parent, name, &ino);
	ut_getattr_file(ute, ino, &st);
	ut_unlink_ok(ute, parent, name);
}

static void ut_rename_ok(struct ut_env *ute, ino_t parent,
			 const char *name, ino_t newparent,
			 const char *newname, int flags)
{
	int err;

	err = ut_rename(ute, parent, name, newparent, newname, flags);
	ut_expect_ok(err);
}

void ut_rename_move(struct ut_env *ute, ino_t parent, const char *name,
		    ino_t newparent, const char *newname)
{
	struct stat st;

	ut_lookup_ok(ute, parent, name, &st);
	ut_lookup_noent(ute, newparent, newname);
	ut_rename_ok(ute, parent, name, newparent, newname, 0);
	ut_lookup_noent(ute, parent, name);
	ut_lookup_ok(ute, newparent, newname, &st);
}

void ut_rename_replace(struct ut_env *ute, ino_t parent, const char *name,
		       ino_t newparent, const char *newname)
{
	struct stat st;

	ut_lookup_ok(ute, parent, name, &st);
	ut_lookup_ok(ute, newparent, newname, &st);
	ut_rename_ok(ute, parent, name, newparent, newname, 0);
	ut_lookup_noent(ute, parent, name);
	ut_lookup_ok(ute, newparent, newname, &st);
}

void ut_rename_exchange(struct ut_env *ute, ino_t parent, const char *name,
			ino_t newparent, const char *newname)
{
	struct stat st1;
	struct stat st2;
	struct stat st3;
	struct stat st4;
	const int flags = RENAME_EXCHANGE;

	ut_lookup_ok(ute, parent, name, &st1);
	ut_expect_gt(st1.st_nlink, 0);
	ut_lookup_ok(ute, newparent, newname, &st2);
	ut_expect_gt(st2.st_nlink, 0);
	ut_rename_ok(ute, parent, name, newparent, newname, flags);
	ut_lookup_ok(ute, parent, name, &st3);
	ut_lookup_ok(ute, newparent, newname, &st4);
	ut_expect_eq(st1.st_ino, st4.st_ino);
	ut_expect_eq(st1.st_mode, st4.st_mode);
	ut_expect_eq(st1.st_nlink, st4.st_nlink);
	ut_expect_eq(st2.st_ino, st3.st_ino);
	ut_expect_eq(st2.st_mode, st3.st_mode);
	ut_expect_eq(st2.st_nlink, st3.st_nlink);
}

void ut_symlink_ok(struct ut_env *ute, ino_t parent,
		   const char *name, const char *value, ino_t *out_ino)
{
	int err;
	struct stat st;

	err = ut_lookup(ute, parent, name, &st);
	ut_expect_err(err, -ENOENT);

	err = ut_symlink(ute, parent, name, value, &st);
	ut_expect_ok(err);
	ut_expect_ne(st.st_ino, parent);

	ut_readlink_expect(ute, st.st_ino, value);

	*out_ino = st.st_ino;
}

void ut_readlink_expect(struct ut_env *ute, ino_t ino, const char *value)
{
	int err;
	char *lnk;
	size_t nrd = 0;
	const size_t lsz = VOLUTA_PATH_MAX;

	lnk = ut_zalloc(ute, lsz);
	err = ut_readlink(ute, ino, lnk, lsz, &nrd);
	ut_expect_ok(err);
	ut_expect_eq(strlen(value), nrd);
	ut_expect_eqs(value, lnk);
}

static void ut_create_status(struct ut_env *ute, ino_t parent,
			     const char *name, mode_t mode,
			     struct stat *out_st, int status)
{
	int err;

	err = ut_create(ute, parent, name, mode, out_st);
	ut_expect_status(err, status);
}

void ut_create_ok(struct ut_env *ute, ino_t parent,
		  const char *name, mode_t mode, struct stat *out_st)
{
	ut_create_status(ute, parent, name, mode, out_st, 0);
}

static void ut_create_new(struct ut_env *ute, ino_t parent,
			  const char *name, mode_t mode, ino_t *out_ino)
{
	ino_t ino;
	struct stat st;
	struct statvfs stv[2];

	ut_statfs_ok(ute, parent, &stv[0]);
	ut_create_ok(ute, parent, name, mode, &st);

	ino = st.st_ino;
	ut_expect_ne(ino, parent);
	ut_expect_ne(ino, VOLUTA_INO_NULL);
	ut_expect_eq(st.st_nlink, 1);
	ut_expect_eq(st.st_mode & S_IFMT, mode & S_IFMT);

	ut_getattr_ok(ute, parent, &st);
	ut_expect_eq(st.st_ino, parent);
	ut_expect_gt(st.st_size, 0);

	ut_statfs_ok(ute, ino, &stv[1]);
	ut_expect_eq(stv[1].f_ffree + 1, stv[0].f_ffree);
	ut_expect_le(stv[1].f_bfree, stv[0].f_bfree);

	*out_ino = ino;
}

void ut_create_file(struct ut_env *ute, ino_t parent,
		    const char *name, ino_t *out_ino)
{
	ut_create_new(ute, parent, name, S_IFREG | 0600, out_ino);
}

void ut_create_special(struct ut_env *ute, ino_t parent,
		       const char *name, mode_t mode, ino_t *out_ino)
{
	ut_expect(S_ISFIFO(mode) || S_ISSOCK(mode));
	ut_create_new(ute, parent, name, mode, out_ino);
}

void ut_create_noent(struct ut_env *ute, ino_t parent, const char *name)
{
	ut_create_status(ute, parent, name, S_IFREG | 0600, NULL, -ENOENT);
}

void ut_release_ok(struct ut_env *ute, ino_t ino)
{
	int err;

	err = ut_release(ute, ino);
	ut_expect_ok(err);
}

void ut_release_file(struct ut_env *ute, ino_t ino)
{
	struct stat st;

	ut_getattr_file(ute, ino, &st);
	ut_release_ok(ute, ino);
}

void ut_fsync_ok(struct ut_env *ute, ino_t ino, bool datasync)
{
	int err;

	err = ut_fsync(ute, ino, datasync);
	ut_expect_ok(err);
}

void ut_create_only(struct ut_env *ute, ino_t parent,
		    const char *name, ino_t *out_ino)
{
	ino_t ino;
	struct stat st;

	ut_create_ok(ute, parent, name, S_IFREG | 0600, &st);
	ino = st.st_ino;
	ut_expect_ne(ino, parent);
	ut_expect_ne(ino, VOLUTA_INO_NULL);

	ut_release_ok(ute, ino);
	ut_lookup_ok(ute, parent, name, &st);
	ut_expect_eq(ino, st.st_ino);

	*out_ino = ino;
}

void ut_open_rdonly(struct ut_env *ute, ino_t ino)
{
	int err;

	err = ut_open(ute, ino, O_RDONLY);
	ut_expect_ok(err);
}

void ut_open_rdwr(struct ut_env *ute, ino_t ino)
{
	int err;

	err = ut_open(ute, ino, O_RDWR);
	ut_expect_ok(err);
}

void ut_remove_file(struct ut_env *ute, ino_t parent,
		    const char *name, ino_t ino)
{
	struct statvfs stv[2];

	ut_statfs_ok(ute, ino, &stv[0]);
	ut_release_ok(ute, ino);
	ut_unlink_ok(ute, parent, name);
	ut_unlink_err(ute, parent, name, -ENOENT);
	ut_statfs_ok(ute, parent, &stv[1]);
	ut_expect_eq(stv[0].f_ffree + 1, stv[1].f_ffree);
}

void ut_remove_link(struct ut_env *ute,
		    ino_t parent, const char *name)
{
	struct stat st;

	ut_lookup_ok(ute, parent, name, &st);
	ut_unlink_ok(ute, parent, name);
	ut_unlink_err(ute, parent, name, -ENOENT);
}

void ut_write_ok(struct ut_env *ute, ino_t ino,
		 const void *buf, size_t bsz, loff_t off)
{
	int err;
	size_t nwr;

	err = ut_write(ute, ino, buf, bsz, off, &nwr);
	ut_expect_ok(err);
	ut_expect_eq(nwr, bsz);
}

void ut_write_nospc(struct ut_env *ute, ino_t ino,
		    const void *buf, size_t bsz,
		    loff_t off, size_t *out_nwr)
{
	int err;

	*out_nwr = 0;
	err = ut_write(ute, ino, buf, bsz, off, out_nwr);
	if (err) {
		ut_expect_status(err, -ENOSPC);
	}
}

void ut_write_read(struct ut_env *ute, ino_t ino,
		   const void *buf, size_t bsz, loff_t off)
{
	ut_write_ok(ute, ino, buf, bsz, off);
	ut_read_verify(ute, ino, buf, bsz, off);
}

void ut_write_read1(struct ut_env *ute, ino_t ino, loff_t off)
{
	const uint8_t dat[] = { 1 };

	ut_write_read(ute, ino, dat, 1, off);
}

void ut_write_read_str(struct ut_env *ute, ino_t ino,
		       const char *str, loff_t off)
{
	ut_write_read(ute, ino, str, strlen(str), off);
}

void ut_read_verify(struct ut_env *ute, ino_t ino,
		    const void *buf, size_t bsz, loff_t off)
{
	void *dat;
	char tmp[1024];

	dat = (bsz > sizeof(tmp)) ? ut_randbuf(ute, bsz) : tmp;
	ut_read_ok(ute, ino, dat, bsz, off);
	ut_expect_eqm(buf, dat, bsz);
}

void ut_read_verify_str(struct ut_env *ute, ino_t ino,
			const char *str, loff_t off)
{
	ut_read_verify(ute, ino, str, strlen(str), off);
}


void ut_read_ok(struct ut_env *ute, ino_t ino,
		void *buf, size_t bsz, loff_t off)
{
	int err;
	size_t nrd;

	err = ut_read(ute, ino, buf, bsz, off, &nrd);
	ut_expect_ok(err);
	ut_expect_eq(nrd, bsz);
}

void ut_read_zero(struct ut_env *ute, ino_t ino, loff_t off)
{
	uint8_t zero[] = { 0 };

	if (off >= 0) {
		ut_read_verify(ute, ino, zero, 1, off);
	}
}

void ut_read_zeros(struct ut_env *ute,
		   ino_t ino, loff_t off, size_t len)
{
	const void *zeros = ut_zerobuf(ute, len);

	ut_read_verify(ute, ino, zeros, len, off);
}

void ut_trunacate_file(struct ut_env *ute, ino_t ino, loff_t off)
{
	int err;
	size_t nrd;
	uint8_t buf[1] = { 0 };
	struct stat st;

	err = ut_truncate(ute, ino, off, &st);
	ut_expect_ok(err);
	ut_expect_eq(off, st.st_size);

	err = ut_read(ute, ino, buf, 1, off, &nrd);
	ut_expect_ok(err);
	ut_expect_eq(nrd, 0);
	ut_expect_eq(buf[0], 0);
}

void ut_fallocate_reserve(struct ut_env *ute, ino_t ino,
			  loff_t offset, loff_t len)
{
	int err;
	struct stat st;

	err = ut_fallocate(ute, ino, 0, offset, len);
	ut_expect_ok(err);

	err = ut_getattr(ute, ino, &st);
	ut_expect_ok(err);
	ut_expect_ge(st.st_size, offset + len);
}

void ut_fallocate_punch_hole(struct ut_env *ute, ino_t ino,
			     loff_t offset, loff_t len)
{
	int err;
	loff_t isize;
	struct stat st;
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	err = ut_getattr(ute, ino, &st);
	ut_expect_ok(err);
	isize = st.st_size;

	err = ut_fallocate(ute, ino, mode, offset, len);
	ut_expect_ok(err);

	err = ut_getattr(ute, ino, &st);
	ut_expect_ok(err);
	ut_expect_eq(st.st_size, isize);
}

static void ut_setgetxattr(struct ut_env *ute, ino_t ino,
			   const struct ut_keyval *kv, int flags)
{
	int err;

	err = ut_setxattr(ute, ino, kv->name, kv->value, kv->size, flags);
	ut_expect_ok(err);

	ut_getxattr_value(ute, ino, kv);
}

void ut_setxattr_create(struct ut_env *ute, ino_t ino,
			const struct ut_keyval *kv)
{
	ut_setgetxattr(ute, ino, kv, XATTR_CREATE);
}

void ut_setxattr_replace(struct ut_env *ute, ino_t ino,
			 const struct ut_keyval *kv)
{
	ut_setgetxattr(ute, ino, kv, XATTR_REPLACE);
}

void ut_setxattr_rereplace(struct ut_env *ute, ino_t ino,
			   const struct ut_keyval *kv)
{
	ut_setgetxattr(ute, ino, kv, 0);
}

void ut_setxattr_all(struct ut_env *ute, ino_t ino,
		     const struct ut_kvl *kvl)
{
	const struct ut_keyval *kv;

	for (size_t i = 0; i < kvl->count; ++i) {
		kv = kvl->list[i];
		ut_setxattr_create(ute, ino, kv);
		ut_getxattr_value(ute, ino, kv);
	}
}


void ut_getxattr_value(struct ut_env *ute, ino_t ino,
		       const struct ut_keyval *kv)
{
	int err;
	size_t vsz;
	void *val;

	vsz = 0;
	err = ut_getxattr(ute, ino, kv->name, NULL, 0, &vsz);
	ut_expect_ok(err);
	ut_expect_eq(vsz, kv->size);

	val = ut_randbuf(ute, vsz);
	err = ut_getxattr(ute, ino, kv->name, val, vsz, &vsz);
	ut_expect_ok(err);
	ut_expect_eqm(val, kv->value, kv->size);
}

void ut_getxattr_nodata(struct ut_env *ute, ino_t ino,
			const struct ut_keyval *kv)

{
	int err;
	size_t bsz = 0;
	char buf[256] = "";

	err = ut_getxattr(ute, ino, kv->name,
			  buf, sizeof(buf), &bsz);
	ut_expect_err(err, -ENODATA);
	ut_expect_eq(bsz, 0);
}

void ut_removexattr_ok(struct ut_env *ute, ino_t ino,
		       const struct ut_keyval *kv)
{
	int err;

	err = ut_removexattr(ute, ino, kv->name);
	ut_expect_ok(err);

	err = ut_removexattr(ute, ino, kv->name);
	ut_expect_err(err, -ENODATA);
}


static struct ut_keyval *
kvl_search(const struct ut_kvl *kvl, const char *name)
{
	struct ut_keyval *kv;

	for (size_t i = 0; i < kvl->count; ++i) {
		kv = kvl->list[i];
		if (!strcmp(name, kv->name)) {
			return kv;
		}
	}
	return NULL;
}

void ut_listxattr_ok(struct ut_env *ute, ino_t ino,
		     const struct ut_kvl *kvl)
{
	int err;
	const char *name;
	const struct ut_keyval *kv;
	struct ut_listxattr_ctx ut_lxa_ctx;

	err = ut_listxattr(ute, ino, &ut_lxa_ctx);
	ut_expect_ok(err);
	ut_expect_eq(ut_lxa_ctx.count, kvl->count);

	for (size_t i = 0; i < ut_lxa_ctx.count; ++i) {
		name = ut_lxa_ctx.names[i];
		ut_expect_not_null(name);
		kv = kvl_search(kvl, name);
		ut_expect_not_null(kv);
	}
}

void ut_removexattr_all(struct ut_env *ute, ino_t ino,
			const struct ut_kvl *kvl)
{
	const struct ut_keyval *kv;

	for (size_t i = 0; i < kvl->count; ++i) {
		kv = kvl->list[i];
		ut_removexattr_ok(ute, ino, kv);
	}
}

void ut_query_ok(struct ut_env *ute, ino_t ino,
		 struct voluta_ioc_query *out_qry)
{
	int err;

	err = ut_query(ute, ino, out_qry);
	ut_expect_ok(err);
}

void ut_fiemap_ok(struct ut_env *ute, ino_t ino, struct fiemap *fm)
{
	int err;

	err = ut_fiemap(ute, ino, fm);
	ut_expect_ok(err);
	ut_expect_lt(fm->fm_mapped_extents, UINT_MAX / 2);
	if (fm->fm_extent_count) {
		ut_expect_le(fm->fm_mapped_extents, fm->fm_extent_count);
	}
}

static void ut_lseek_ok(struct ut_env *ute, ino_t ino,
			loff_t off, int whence, loff_t *out_off)
{
	int err;
	struct stat st;

	ut_getattr_ok(ute, ino, &st);

	*out_off = -1;
	err = ut_lseek(ute, ino, off, whence, out_off);
	ut_expect_ok(err);
	ut_expect_ge(*out_off, 0);
	ut_expect_le(*out_off, st.st_size);
}

void ut_lseek_data(struct ut_env *ute,
		   ino_t ino, loff_t off, loff_t *out_off)
{
	ut_lseek_ok(ute, ino, off, SEEK_DATA, out_off);
}

void ut_lseek_hole(struct ut_env *ute,
		   ino_t ino, loff_t off, loff_t *out_off)
{
	ut_lseek_ok(ute, ino, off, SEEK_HOLE, out_off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ut_write_dvec(struct ut_env *ute, ino_t ino,
		   const struct ut_dvec *dvec)
{
	ut_write_read(ute, ino, dvec->dat,
		      dvec->len, dvec->off);
}

void ut_read_dvec(struct ut_env *ute, ino_t ino,
		  const struct ut_dvec *dvec)
{
	void *dat = ut_zerobuf(ute, dvec->len);

	ut_read_ok(ute, ino, dat, dvec->len, dvec->off);
	ut_expect_eqm(dat, dvec->dat, dvec->len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ut_sync_drop(struct ut_env *ute)
{
	int err;

	err = voluta_fse_sync_drop(ute->fse);
	ut_expect_ok(err);
}

void ut_drop_caches_fully(struct ut_env *ute)
{
	struct voluta_fs_stats st;

	ut_sync_drop(ute);

	/* Expects only super-block */
	voluta_fse_stats(ute->fse, &st);
	ut_expect_eq(st.ncache_blocks, 1);
	ut_expect_eq(st.ncache_vnodes, 1);
	ut_expect_eq(st.ncache_inodes, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ut_expect_eq_ts(const struct timespec *ts1, const struct timespec *ts2)
{
	ut_expect_eq(ts1->tv_sec, ts2->tv_sec);
	ut_expect_eq(ts1->tv_nsec, ts2->tv_nsec);
}

void ut_expect_eq_stat(const struct stat *st1, const struct stat *st2)
{
	ut_expect_eq(st1->st_ino, st2->st_ino);
	ut_expect_eq(st1->st_nlink, st2->st_nlink);
	ut_expect_eq(st1->st_uid, st2->st_uid);
	ut_expect_eq(st1->st_gid, st2->st_gid);
	ut_expect_eq(st1->st_mode, st2->st_mode);
	ut_expect_eq(st1->st_size, st2->st_size);
	ut_expect_eq(st1->st_blocks, st2->st_blocks);
	ut_expect_eq(st1->st_blksize, st2->st_blksize);
	ut_expect_eq_ts(&st1->st_mtim, &st2->st_mtim);
	ut_expect_eq_ts(&st1->st_ctim, &st2->st_ctim);
}

void ut_expect_statvfs(const struct statvfs *stv1, const struct statvfs *stv2)
{
	fsblkcnt_t bfree_dif;

	ut_expect_eq(stv1->f_bsize, stv2->f_bsize);
	ut_expect_eq(stv1->f_frsize, stv2->f_frsize);
	ut_expect_eq(stv1->f_files, stv2->f_files);
	ut_expect_eq(stv1->f_ffree, stv2->f_ffree);
	ut_expect_eq(stv1->f_favail, stv2->f_favail);
	ut_expect_eq(stv1->f_blocks, stv2->f_blocks);
	ut_expect_ge(stv1->f_bfree, stv2->f_bfree);
	ut_expect_ge(stv1->f_bavail, stv2->f_bavail);

	/* XXX calc expected diff based on volume size */
	bfree_dif = stv1->f_bfree - stv2->f_bfree;
	ut_expect_lt(bfree_dif, 4000);
}

static void ut_reload_fs_ok(struct ut_env *ute)
{
	int err;

	err = voluta_fse_sync_drop(ute->fse);
	ut_expect_ok(err);

	err = voluta_fse_term(ute->fse);
	ut_expect_ok(err);

	err = voluta_fse_load(ute->fse);
	ut_expect_ok(err);
}

void ut_reload_ok(struct ut_env *ute, ino_t ino)
{
	struct stat st[2];
	struct statvfs fsst[2];

	ut_statfs_ok(ute, ino, &fsst[0]);
	ut_getattr_ok(ute, ino, &st[0]);
	ut_reload_fs_ok(ute);
	ut_statfs_ok(ute, ino, &fsst[1]);
	ut_getattr_ok(ute, ino, &st[1]);

	ut_expect_statvfs(&fsst[0], &fsst[1]);
	ut_expect_eq_stat(&st[0], &st[1]);
}
