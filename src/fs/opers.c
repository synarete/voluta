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
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <voluta/fs/types.h>
#include <voluta/fs/address.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/super.h>
#include <voluta/fs/namei.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/dir.h>
#include <voluta/fs/file.h>
#include <voluta/fs/symlink.h>
#include <voluta/fs/xattr.h>
#include <voluta/fs/opers.h>
#include <voluta/fs/private.h>


#define ok_or_goto_out(err_) \
	do { if ((err_) != 0) goto out; } while (0)

#define ok_or_goto_out_ok(err_) \
	do { if ((err_) != 0) goto out_ok; } while (0)

static int op_start(struct voluta_sb_info *sbi, const struct voluta_oper *op)
{
	int err;

	sbi->sb_ops.op_time = op->xtime.tv_sec;
	sbi->sb_ops.op_count++;

	err = voluta_flush_dirty(sbi, 0);
	if (!err) {
		voluta_cache_relax(sbi->sb_cache, VOLUTA_F_OPSTART);
	}
	return err;
}

static int op_finish(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, int err)
{
	const time_t now = time(NULL);
	const time_t beg = op->xtime.tv_sec;
	const time_t dif = now - beg;

	if ((beg < now) && (dif > 30)) {
		log_warn("slow-oper: id=%ld code=%d duration=%ld status=%d",
		         sbi->sb_ops.op_count, op->opcode, dif, err);
	}
	/* TODO: maybe extra flush-relax? */
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stat_to_itimes(const struct stat *times,
                           struct voluta_itimes *itimes)
{
	ts_copy(&itimes->atime, &times->st_atim);
	ts_copy(&itimes->mtime, &times->st_mtim);
	ts_copy(&itimes->ctime, &times->st_ctim);
	/* Birth _must_not_ be set from outside */
}

static int symval_to_str(const char *symval, struct voluta_str *str)
{
	size_t symlen;

	symlen = strnlen(symval, VOLUTA_SYMLNK_MAX + 1);
	if (symlen == 0) {
		return -EINVAL;
	}
	if (symlen > VOLUTA_SYMLNK_MAX) {
		return -ENAMETOOLONG;
	}
	str->str = symval;
	str->len = symlen;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_fs_forget(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op,
                     ino_t ino, size_t nlookup)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_cached_inode(sbi, ino, &ii);
	ok_or_goto_out_ok(err);

	err = voluta_do_forget(op, ii, nlookup);
	ok_or_goto_out(err);
out_ok:
	err = 0;
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_statfs(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op,
                     ino_t ino, struct statvfs *stvfs)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_statvfs(op, ii, stvfs);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_lookup(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, struct stat *out_stat)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_lookup(op, dir_ii, &nstr, &ii);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_getattr(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op,
                      ino_t ino, struct stat *out_stat)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_access(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino, int mode)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_access(op, ii, mode);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_mkdir(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t parent,
                    const char *name, mode_t mode, struct stat *out_stat)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_mkdir(op, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_rmdir(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op,
                    ino_t parent, const char *name)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_rmdir(op, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_symlink(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t parent,
                      const char *name, const char *symval,
                      struct stat *out_stat)
{
	int err;
	struct voluta_str value;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = symval_to_str(symval, &value);
	ok_or_goto_out(err);

	err = voluta_do_symlink(op, dir_ii, &nstr, &value, &ii);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_readlink(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op,
                       ino_t ino, char *ptr, size_t lim, size_t *out_len)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_readlink(op, ii, ptr, lim, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_unlink(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op,
                     ino_t parent, const char *name)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_unlink(op, dir_ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_link(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, ino_t parent,
                   const char *name, struct stat *out_stat)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_link(op, dir_ii, &nstr, ii);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_opendir(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino)
{
	int err;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_do_opendir(op, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_releasedir(struct voluta_sb_info *sbi,
                         const struct voluta_oper *op, ino_t ino, int o_flags)
{
	int err;
	struct voluta_inode_info *dir_ii = NULL;

	unused(o_flags); /* TODO: useme */

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_do_releasedir(op, dir_ii);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_readdir(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino,
                      struct voluta_readdir_ctx *rd_ctx)
{
	int err;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_do_readdir(op, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_readdirplus(struct voluta_sb_info *sbi,
                          const struct voluta_oper *op, ino_t ino,
                          struct voluta_readdir_ctx *rd_ctx)
{
	int err;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_do_readdirplus(op, dir_ii, rd_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_fsyncdir(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino, bool datasync)
{
	int err;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_do_fsyncdir(op, dir_ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_chmod(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat)
{
	int err;
	struct voluta_itimes itimes;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = voluta_do_chmod(op, ii, mode, &itimes);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_chown(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat)
{
	int err;
	struct voluta_itimes itimes;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(st, &itimes);
	err = voluta_do_chown(op, ii, uid, gid, &itimes);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_utimens(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino,
                      const struct stat *times, struct stat *out_stat)
{
	int err;
	struct voluta_itimes itimes;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	stat_to_itimes(times, &itimes);
	err = voluta_do_utimens(op, ii, &itimes);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_truncate(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino, loff_t len,
                       struct stat *out_stat)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_truncate(op, ii, len);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_create(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct stat *out_stat)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;
	struct voluta_inode_info *dir_ii = NULL;

	unused(o_flags); /* XXX use me */

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_create(op, dir_ii, &nstr, mode, &ii);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_open(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, int o_flags)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_open(op, ii, o_flags);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_mknod(struct voluta_sb_info *sbi, const struct voluta_oper *op,
                    ino_t parent, const char *name, mode_t mode, dev_t rdev,
                    struct stat *out_stat)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;
	struct voluta_inode_info *dir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_mknod(op, dir_ii, &nstr, mode, rdev, &ii);
	ok_or_goto_out(err);

	err = voluta_do_getattr(op, ii, out_stat);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_release(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op,
                      ino_t ino, int o_flags, bool flush)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	/* TODO: useme */
	unused(flush);
	unused(o_flags);

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_release(op, ii);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_flush(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_flush(op, ii);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_fsync(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op,
                    ino_t ino, bool datasync)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_fsync(op, ii, datasync);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_rename(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_namestr newnstr;
	struct voluta_inode_info *dir_ii = NULL;
	struct voluta_inode_info *newdir_ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, parent, &dir_ii);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, newparent, &newdir_ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_make_namestr(dir_ii, newname, &newnstr);
	ok_or_goto_out(err);

	err = voluta_do_rename(op, dir_ii, &nstr, newdir_ii, &newnstr, flags);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_read(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_read(op, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_read_iter(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        struct voluta_rwiter_ctx *rwi_ctx)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_read_iter(op, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_write(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    const void *buf, size_t len, off_t off, size_t *out_len)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_write(op, ii, buf, len, off, out_len);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_write_iter(struct voluta_sb_info *sbi,
                         const struct voluta_oper *op, ino_t ino,
                         struct voluta_rwiter_ctx *rwi_ctx)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_write_iter(op, ii, rwi_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_rdwr_post(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        const struct voluta_fiovec *fiov, size_t cnt)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_rdwr_post(op, ii, fiov, cnt);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_fallocate(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        int mode, loff_t offset, loff_t length)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_fallocate(op, ii, mode, offset, length);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_lseek(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    loff_t off, int whence, loff_t *out_off)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_lseek(op, ii, off, whence, out_off);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_copy_file_range(struct voluta_sb_info *sbi,
                              const struct voluta_oper *op, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp)
{
	int err;
	struct voluta_inode_info *ii_in = NULL;
	struct voluta_inode_info *ii_out = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino_in, &ii_in);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino_out, &ii_out);
	ok_or_goto_out(err);

	err = voluta_do_copy_file_range(op, ii_in, ii_out, off_in,
	                                off_out, len, flags, out_ncp);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_setxattr(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_setxattr(op, ii, &nstr, value, size, flags);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_getxattr(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_getxattr(op, ii, &nstr, buf, size, out_size);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_listxattr(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        struct voluta_listxattr_ctx *lxa_ctx)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_listxattr(op, ii, lxa_ctx);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_removexattr(struct voluta_sb_info *sbi,
                          const struct voluta_oper *op,
                          ino_t ino, const char *name)
{
	int err;
	struct voluta_namestr nstr;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_stage_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_make_namestr(ii, name, &nstr);
	ok_or_goto_out(err);

	err = voluta_do_removexattr(op, ii, &nstr);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_statx(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_statx(op, ii, request_mask, out_stx);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_fiemap(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op,
                     ino_t ino, struct fiemap *fm)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_fiemap(op, ii, fm);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_query(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    struct voluta_ioc_query *out_qry)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_query(op, ii, out_qry);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_snap(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op,
                   ino_t ino, char *str, size_t lim)
{
	int err;
	struct voluta_inode_info *ii = NULL;

	err = op_start(sbi, op);
	ok_or_goto_out(err);

	err = voluta_authorize(sbi, op);
	ok_or_goto_out(err);

	err = voluta_fetch_inode(sbi, ino, &ii);
	ok_or_goto_out(err);

	err = voluta_do_snap(op, ii, str, lim);
	ok_or_goto_out(err);
out:
	return op_finish(sbi, op, err);
}

int voluta_fs_timedout(struct voluta_sb_info *sbi, int flags)
{
	int err;

	err = voluta_flush_dirty(sbi, flags);
	if (err) {
		return err;
	}
	voluta_cache_relax(sbi->sb_cache, flags);
	return 0;
}
