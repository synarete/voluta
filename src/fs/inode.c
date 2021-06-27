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
#include <sys/sysmacros.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <voluta/fs/types.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/address.h>
#include <voluta/fs/super.h>
#include <voluta/fs/namei.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/dir.h>
#include <voluta/fs/file.h>
#include <voluta/fs/symlink.h>
#include <voluta/fs/xattr.h>
#include <voluta/fs/private.h>

/*
 * TODO-0001: Support setxflags/getxflags ioctls
 *
 * Have support for xflags attributes per inode. Follow XFS' extended flags
 * per inode. At minimum, have support for S_IMMUTABLE of inode. That is, an
 * inode which can not be modified or removed.
 *
 * See kernel's 'xfs_ioc_getxflags/xfs_ioc_setxflags'
 */

/*
 * TODO-0002: Track meta-blocks per inode
 *
 * For each inode (+ entire file-system) track number on meta-blocks.
 * Especially important for deep/sparse dir/file inodes.
 */

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ts_to_cpu(const struct voluta_timespec *vts, struct timespec *ts)
{
	if (ts != NULL) {
		ts->tv_sec = (time_t)voluta_le64_to_cpu(vts->t_sec);
		ts->tv_nsec = (long)voluta_le64_to_cpu(vts->t_nsec);
	}
}

static void cpu_to_ts(const struct timespec *ts, struct voluta_timespec *vts)
{
	if (ts != NULL) {
		vts->t_sec = voluta_cpu_to_le64((uint64_t)ts->tv_sec);
		vts->t_nsec = voluta_cpu_to_le64((uint64_t)ts->tv_nsec);
	}
}

static void assign_ts(struct timespec *ts, const struct timespec *other)
{
	ts->tv_sec = other->tv_sec;
	ts->tv_nsec = other->tv_nsec;
}

static void assign_xts(struct statx_timestamp *xts, const struct timespec *ts)
{
	xts->tv_sec = ts->tv_sec;
	xts->tv_nsec = (uint32_t)(ts->tv_nsec);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t inode_ino(const struct voluta_inode *inode)
{
	return voluta_cpu_to_ino(inode->i_ino);
}

static void inode_set_ino(struct voluta_inode *inode, ino_t ino)
{
	inode->i_ino = voluta_ino_to_cpu(ino);
}

static ino_t inode_parent(const struct voluta_inode *inode)
{
	return voluta_cpu_to_ino(inode->i_parent);
}

static void inode_set_parent(struct voluta_inode *inode, ino_t ino)
{
	inode->i_parent = voluta_cpu_to_ino(ino);
}

static uid_t inode_uid(const struct voluta_inode *inode)
{
	return voluta_le32_to_cpu(inode->i_uid);
}

static void inode_set_uid(struct voluta_inode *inode, uid_t uid)
{
	inode->i_uid = voluta_cpu_to_le32(uid);
}

static gid_t inode_gid(const struct voluta_inode *inode)
{
	return voluta_le32_to_cpu(inode->i_gid);
}

static void inode_set_gid(struct voluta_inode *inode, uid_t gid)
{
	inode->i_gid = voluta_cpu_to_le32(gid);
}

static mode_t inode_mode(const struct voluta_inode *inode)
{
	return voluta_le32_to_cpu(inode->i_mode);
}

static void inode_set_mode(struct voluta_inode *inode, mode_t mode)
{
	inode->i_mode = voluta_cpu_to_le32(mode);
}

static loff_t inode_size(const struct voluta_inode *inode)
{
	return voluta_off_to_cpu(inode->i_size);
}

static void inode_set_size(struct voluta_inode *inode, loff_t off)
{
	inode->i_size = voluta_cpu_to_off(off);
}

static loff_t inode_span(const struct voluta_inode *inode)
{
	return voluta_off_to_cpu(inode->i_span);
}

static void inode_set_span(struct voluta_inode *inode, loff_t off)
{
	inode->i_span = voluta_cpu_to_off(off);
}

static blkcnt_t inode_blocks(const struct voluta_inode *inode)
{
	return (blkcnt_t)voluta_le64_to_cpu(inode->i_blocks);
}

static void inode_set_blocks(struct voluta_inode *inode, blkcnt_t blocks)
{
	inode->i_blocks = voluta_cpu_to_le64((uint64_t)blocks);
}

static nlink_t inode_nlink(const struct voluta_inode *inode)
{
	return voluta_le64_to_cpu(inode->i_nlink);
}

static void inode_set_nlink(struct voluta_inode *inode, nlink_t nlink)
{
	inode->i_nlink = voluta_cpu_to_le64(nlink);
}

static long inode_revision(const struct voluta_inode *inode)
{
	return (long)voluta_le64_to_cpu(inode->i_revision);
}

static void inode_set_revision(struct voluta_inode *inode, long r)
{
	inode->i_revision = voluta_cpu_to_le64((uint64_t)r);
}

static void inode_inc_revision(struct voluta_inode *inode)
{
	inode_set_revision(inode, inode_revision(inode) + 1);
}

static enum voluta_inodef inode_flags(const struct voluta_inode *inode)
{
	return voluta_le32_to_cpu(inode->i_flags);
}

static void inode_set_flags(struct voluta_inode *inode,
                            enum voluta_inodef flags)
{
	inode->i_flags = voluta_cpu_to_le32(flags);
}

static bool inode_has_flags(struct voluta_inode *inode,
                            enum voluta_inodef mask)
{
	return (inode_flags(inode) & mask) == mask;
}

static unsigned int inode_rdev_major(const struct voluta_inode *inode)
{
	return voluta_le32_to_cpu(inode->i_rdev_major);
}

static unsigned int inode_rdev_minor(const struct voluta_inode *inode)
{
	return voluta_le32_to_cpu(inode->i_rdev_minor);
}

static void inode_set_rdev(struct voluta_inode *inode,
                           unsigned int maj, unsigned int min)
{
	inode->i_rdev_major = voluta_cpu_to_le32(maj);
	inode->i_rdev_minor = voluta_cpu_to_le32(min);
}

static void inode_btime(const struct voluta_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_t.btime, ts);
}

static void inode_set_btime(struct voluta_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_t.btime);
}

static void inode_atime(const struct voluta_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_t.atime, ts);
}

static void inode_set_atime(struct voluta_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_t.atime);
}

static void inode_mtime(const struct voluta_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_t.mtime, ts);
}

static void inode_set_mtime(struct voluta_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_t.mtime);
}

static void inode_ctime(const struct voluta_inode *inode, struct timespec *ts)
{
	ts_to_cpu(&inode->i_t.ctime, ts);
}

static void inode_set_ctime(struct voluta_inode *inode,
                            const struct timespec *ts)
{
	cpu_to_ts(ts, &inode->i_t.ctime);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

ino_t voluta_ii_xino(const struct voluta_inode_info *ii)
{
	return ii_isrootd(ii) ? VOLUTA_INO_ROOT : ii_ino(ii);
}

ino_t voluta_ii_parent(const struct voluta_inode_info *ii)
{
	return inode_parent(ii->inode);
}

uid_t voluta_ii_uid(const struct voluta_inode_info *ii)
{
	return inode_uid(ii->inode);
}

gid_t voluta_ii_gid(const struct voluta_inode_info *ii)
{
	return inode_gid(ii->inode);
}

mode_t voluta_ii_mode(const struct voluta_inode_info *ii)
{
	return inode_mode(ii->inode);
}

nlink_t voluta_ii_nlink(const struct voluta_inode_info *ii)
{
	return inode_nlink(ii->inode);
}

loff_t voluta_ii_size(const struct voluta_inode_info *ii)
{
	return inode_size(ii->inode);
}

loff_t voluta_ii_span(const struct voluta_inode_info *ii)
{
	return inode_span(ii->inode);
}

blkcnt_t voluta_ii_blocks(const struct voluta_inode_info *ii)
{
	return inode_blocks(ii->inode);
}

static dev_t ii_rdev(const struct voluta_inode_info *ii)
{
	const struct voluta_inode *inode = ii->inode;

	return makedev(inode_rdev_major(inode), inode_rdev_minor(inode));
}

static unsigned int i_rdev_major_of(const struct voluta_inode_info *ii)
{
	return inode_rdev_major(ii->inode);
}

static unsigned int i_rdev_minor_of(const struct voluta_inode_info *ii)
{
	return inode_rdev_minor(ii->inode);
}

bool voluta_ii_isdir(const struct voluta_inode_info *ii)
{
	return S_ISDIR(ii_mode(ii));
}

bool voluta_ii_isreg(const struct voluta_inode_info *ii)
{
	return S_ISREG(ii_mode(ii));
}

bool voluta_ii_islnk(const struct voluta_inode_info *ii)
{
	return S_ISLNK(ii_mode(ii));
}

bool voluta_ii_isfifo(const struct voluta_inode_info *ii)
{
	return S_ISFIFO(ii_mode(ii));
}

bool voluta_ii_issock(const struct voluta_inode_info *ii)
{
	return S_ISSOCK(ii_mode(ii));
}

static ino_t rootd_ino(const struct voluta_sb_info *sbi)
{
	return sbi->sb_itbi.it_rootdir.ino;
}

bool voluta_ii_isrootd(const struct voluta_inode_info *ii)
{
	const struct voluta_sb_info *sbi = ii_sbi(ii);

	return ii_isdir(ii) && (ii_ino(ii) == rootd_ino(sbi));
}

void voluta_fixup_rootdir(struct voluta_inode_info *ii)
{
	struct voluta_inode *inode = ii->inode;

	inode_set_parent(inode, ii_ino(ii));
	inode_set_nlink(inode, 2);
	inode_set_flags(inode, VOLUTA_INODEF_ROOTD);
}

bool voluta_is_rootdir(const struct voluta_inode_info *ii)
{
	return ii_isdir(ii) && inode_has_flags(ii->inode, VOLUTA_INODEF_ROOTD);
}

enum voluta_inodef voluta_ii_flags(const struct voluta_inode_info *ii)
{
	return inode_flags(ii->inode);
}

static void voluta_ii_times(const struct voluta_inode_info *ii,
                            struct voluta_itimes *tms)
{
	const struct voluta_inode *inode = ii->inode;

	inode_btime(inode, &tms->btime);
	inode_atime(inode, &tms->atime);
	inode_mtime(inode, &tms->mtime);
	inode_ctime(inode, &tms->ctime);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void voluta_setup_ispecial(struct voluta_inode_info *ii, dev_t rdev)
{
	const unsigned int rdev_major = major(rdev);
	const unsigned int rdev_minor = minor(rdev);

	inode_set_rdev(ii->inode, rdev_major, rdev_minor);
	ii_dirtify(ii);
}

/*
 * TODO-0008: Per-inode extra accounting
 *
 * Track number of meta-data bytes allocated per inode.
 *
 *
 * TODO-0010: Store timezone in inode
 */
static void setup_inode_common(struct voluta_inode *inode,
                               const struct voluta_ucred *ucred,
                               ino_t ino, ino_t parent, mode_t mode)
{
	inode_set_ino(inode, ino);
	inode_set_parent(inode, parent);
	inode_set_uid(inode, ucred->uid);
	inode_set_gid(inode, ucred->gid);
	inode_set_mode(inode, mode & ~ucred->umask);
	inode_set_flags(inode, 0);
	inode_set_size(inode, 0);
	inode_set_span(inode, 0);
	inode_set_blocks(inode, 0);
	inode_set_nlink(inode, 0);
	inode_set_revision(inode, 0);
}

void voluta_setup_inode(struct voluta_inode_info *ii,
                        const struct voluta_ucred *ucred,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev)
{
	setup_inode_common(ii->inode, ucred, ii_ino(ii), parent_ino, mode);
	voluta_ii_setup_xattr(ii);
	if (ii_isdir(ii)) {
		voluta_setup_dir(ii, parent_mode, 1);
	} else if (ii_isreg(ii)) {
		voluta_setup_reg(ii);
	} else if (ii_islnk(ii)) {
		voluta_setup_symlnk(ii);
	} else {
		voluta_setup_ispecial(ii, rdev);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ts_setup_now(struct timespec *ts)
{
	ts->tv_sec = 0;
	ts->tv_nsec = UTIME_NOW;
}

static void itimes_setup(struct voluta_itimes *itimes)
{
	ts_setup_now(&itimes->atime);
	ts_setup_now(&itimes->ctime);
	ts_setup_now(&itimes->mtime);
	ts_setup_now(&itimes->btime);
}

static void itimes_copy(struct voluta_itimes *itimes,
                        const struct voluta_itimes *other)
{
	ts_copy(&itimes->atime, &other->atime);
	ts_copy(&itimes->ctime, &other->ctime);
	ts_copy(&itimes->mtime, &other->mtime);
	ts_copy(&itimes->btime, &other->btime);
}

static void iattr_set_times(struct voluta_iattr *iattr,
                            const struct voluta_itimes *itimes)
{
	itimes_copy(&iattr->ia_t, itimes);
}

void voluta_iattr_setup(struct voluta_iattr *iattr, ino_t ino)
{
	voluta_memzero(iattr, sizeof(*iattr));
	itimes_setup(&iattr->ia_t);
	iattr->ia_ino = ino;
}

static void iattr_setup3(struct voluta_iattr *iattr, ino_t ino,
                         const struct voluta_itimes *itimes)
{
	iattr_setup(iattr, ino);
	iattr_set_times(iattr, itimes);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static mode_t itype_of(mode_t mode)
{
	return S_IFMT & mode;
}

static bool uid_isnull(uid_t uid)
{
	const uid_t uid_none = (uid_t)(-1);

	return uid_eq(uid, uid_none);
}

static bool gid_isnull(gid_t gid)
{
	const gid_t gid_none = (gid_t)(-1);

	return gid_eq(gid, gid_none);
}

static bool isowner(const struct voluta_ucred *ucred,
                    const struct voluta_inode_info *ii)
{
	return uid_eq(ucred->uid, ii_uid(ii));
}

static bool has_itype(const struct voluta_inode_info *ii, mode_t mode)
{
	const mode_t imode = ii_mode(ii);

	return (itype_of(imode) == itype_of(mode));
}

static int check_waccess(const struct voluta_oper *op,
                         struct voluta_inode_info *ii)
{
	return voluta_do_access(op, ii, W_OK);
}

static int check_xaccess_parent(const struct voluta_oper *op,
                                const struct voluta_inode_info *ii)
{
	int err;
	ino_t parent;
	struct voluta_inode_info *parent_ii = NULL;

	if (!ii_isdir(ii) || ii_isrootd(ii)) {
		return 0;
	}
	parent = ii_parent(ii);
	err = voluta_fetch_inode(ii_sbi(ii), parent, &parent_ii);
	if (err) {
		return err;
	}
	if (!ii_isdir(parent_ii)) {
		return -EFSCORRUPTED; /* XXX */
	}
	err = voluta_do_access(op, parent_ii, X_OK);
	if (err) {
		return err;
	}
	return 0;
}

static void kill_suid_sgid(struct voluta_inode_info *ii, long flags)
{
	mode_t mask = 0;
	const mode_t mode = ii_mode(ii);

	if ((flags & VOLUTA_IATTR_KILL_SUID) && (mode & S_ISUID)) {
		mask |= S_ISUID;
	}
	if ((flags & VOLUTA_IATTR_KILL_SGID) &&
	    ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))) {
		mask |= S_ISGID;
	}
	if (mask) {
		inode_set_mode(ii->inode, mode & ~mask);
		ii_dirtify(ii);
	}
}

static mode_t new_mode_of(const struct voluta_inode_info *ii, mode_t mask)
{
	const mode_t fmt_mask = S_IFMT;

	return (ii_mode(ii) & fmt_mask) | (mask & ~fmt_mask);
}

static int check_chmod(const struct voluta_oper *op,
                       struct voluta_inode_info *ii, mode_t mode)
{
	const struct voluta_ucred *ucred = &op->ucred;

	/* TODO: Check chmod allowed and allow root (or CAP_FOWNER) */
	if (!capable_fowner(ucred) && !isowner(ucred, ii)) {
		return -EPERM;
	}
	/* Must not change inode type */
	if (itype_of(mode) && !has_itype(ii, mode)) {
		return -EPERM;
	}
	return 0;
}

static void update_times_attr(const struct voluta_oper *op,
                              struct voluta_inode_info *ii,
                              enum voluta_iattr_flags attr_flags,
                              const struct voluta_itimes *itimes)
{
	struct voluta_iattr iattr;

	iattr_setup(&iattr, ii_ino(ii));
	memcpy(&iattr.ia_t, itimes, sizeof(iattr.ia_t));
	iattr.ia_flags = attr_flags;
	update_iattrs(op, ii, &iattr);
}

/*
 * TODO-0013: Allow file-sealing
 *
 * Support special mode for file as read-only permanently (immutable).
 */

static void update_post_chmod(const struct voluta_oper *op,
                              struct voluta_inode_info *ii,
                              struct voluta_iattr *iattr)
{
	const gid_t gid = ii_gid(ii);
	const struct voluta_ucred *ucred = &op->ucred;

	iattr->ia_flags |= VOLUTA_IATTR_MODE | VOLUTA_IATTR_CTIME;
	if (!gid_eq(gid, ucred->gid) && !capable_fsetid(ucred)) {
		iattr->ia_flags |= VOLUTA_IATTR_KILL_SGID;
	}
	update_iattrs(op, ii, iattr);
}

static int do_chmod(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, mode_t mode,
                    const struct voluta_itimes *itimes)
{
	int err;
	struct voluta_iattr iattr = { .ia_flags = 0 };

	err = check_chmod(op, ii, mode);
	if (err) {
		return err;
	}
	err = check_xaccess_parent(op, ii);
	if (err) {
		return err;
	}

	iattr_setup3(&iattr, ii_ino(ii), itimes);
	iattr.ia_mode = new_mode_of(ii, mode);
	update_post_chmod(op, ii, &iattr);
	return 0;
}

int voluta_do_chmod(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, mode_t mode,
                    const struct voluta_itimes *itimes)
{
	int err;

	ii_incref(ii);
	err = do_chmod(op, ii, mode, itimes);
	ii_decref(ii);
	return err;
}

static int check_chown_uid(const struct voluta_oper *op,
                           const struct voluta_inode_info *ii, uid_t uid)
{
	const struct voluta_ucred *ucred = &op->ucred;

	if (uid_eq(uid, ii_uid(ii))) {
		return 0;
	}
	if (capable_chown(ucred)) {
		return 0;
	}
	return -EPERM;
}

static int check_chown_gid(const struct voluta_oper *op,
                           const struct voluta_inode_info *ii, gid_t gid)
{
	const struct voluta_ucred *ucred = &op->ucred;

	if (gid_eq(gid, ii_gid(ii))) {
		return 0;
	}
	if (isowner(ucred, ii)) {
		return 0;
	}
	if (capable_chown(ucred)) {
		return 0;
	}
	return -EPERM;
}

static int check_chown(const struct voluta_oper *op,
                       const struct voluta_inode_info *ii,
                       uid_t uid, gid_t gid)
{
	int err = 0;

	if (!uid_isnull(uid)) {
		err = check_chown_uid(op, ii, uid);
	}
	if (!gid_isnull(gid) && !err) {
		err = check_chown_gid(op, ii, gid);
	}
	return err;
}

static void update_post_chown(const struct voluta_oper *op,
                              struct voluta_inode_info *ii,
                              struct voluta_iattr *iattr)
{
	const mode_t mode = ii_mode(ii);
	const mode_t mask = S_IXUSR | S_IXGRP | S_IXOTH;

	iattr->ia_flags |= VOLUTA_IATTR_CTIME;
	if (mode & mask) {
		iattr->ia_flags |= VOLUTA_IATTR_KILL_SUID;
		iattr->ia_flags |= VOLUTA_IATTR_KILL_SGID;
	}
	update_iattrs(op, ii, iattr);
}

static int do_chown(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, uid_t uid, gid_t gid,
                    const struct voluta_itimes *itimes)
{
	int err;
	bool chown_uid = !uid_isnull(uid);
	bool chown_gid = !gid_isnull(gid);
	struct voluta_iattr iattr = { .ia_flags = 0 };

	if (!chown_uid && !chown_gid) {
		return 0; /* no-op */
	}
	err = check_chown(op, ii, uid, gid);
	if (err) {
		return err;
	}
	iattr_setup3(&iattr, ii_ino(ii), itimes);
	if (chown_uid) {
		iattr.ia_uid = uid;
		iattr.ia_flags |= VOLUTA_IATTR_UID;
	}
	if (chown_gid) {
		iattr.ia_gid = gid;
		iattr.ia_flags |= VOLUTA_IATTR_GID;
	}
	update_post_chown(op, ii, &iattr);
	return 0;
}

int voluta_do_chown(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, uid_t uid, gid_t gid,
                    const struct voluta_itimes *itimes)
{
	int err;

	ii_incref(ii);
	err = do_chown(op, ii, uid, gid, itimes);
	ii_decref(ii);
	return err;
}

static bool is_utime_now(const struct timespec *tv)
{
	return (tv->tv_nsec == UTIME_NOW);
}

static bool is_utime_omit(const struct timespec *tv)
{
	return (tv->tv_nsec == UTIME_OMIT);
}

static int check_utimens(const struct voluta_oper *op,
                         struct voluta_inode_info *ii)
{
	int err;

	if (isowner(&op->ucred, ii)) {
		return 0;
	}
	/* TODO: check VOLUTA_CAPF_FOWNER */
	/* TODO: Follow "Permissions requirements" in UTIMENSAT(2) */
	err = check_waccess(op, ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_utimens(const struct voluta_oper *op,
                      struct voluta_inode_info *ii,
                      const struct voluta_itimes *itimes)
{
	int err;
	const struct timespec *ctime = &itimes->ctime;
	const struct timespec *atime = &itimes->atime;
	const struct timespec *mtime = &itimes->mtime;

	err = check_utimens(op, ii);
	if (err) {
		return err;
	}
	if (is_utime_now(atime)) {
		update_itimes(op, ii, VOLUTA_IATTR_ATIME);
	} else if (!is_utime_omit(atime)) {
		update_times_attr(op, ii, VOLUTA_IATTR_ATIME, itimes);
	}
	if (is_utime_now(mtime)) {
		update_itimes(op, ii, VOLUTA_IATTR_MTIME);
	} else if (!is_utime_omit(mtime)) {
		update_times_attr(op, ii, VOLUTA_IATTR_MTIME, itimes);
	}
	if (!is_utime_omit(ctime)) {
		update_times_attr(op, ii, VOLUTA_IATTR_CTIME, itimes);
	}
	return 0;
}


int voluta_do_utimens(const struct voluta_oper *op,
                      struct voluta_inode_info *ii,
                      const struct voluta_itimes *itimes)
{
	int err;

	ii_incref(ii);
	err = do_utimens(op, ii, itimes);
	ii_decref(ii);
	return err;
}

static int check_parent_dir_ii(const struct voluta_inode_info *ii)
{
	int err;
	ino_t parent;
	struct voluta_inode_info *parent_ii = NULL;

	if (!ii_isdir(ii) || ii_isrootd(ii)) {
		return 0;
	}
	parent = ii_parent(ii);
	if (ino_isnull(parent)) {
		return ii->i_nopen ? 0 : -ENOENT;
	}
	err = voluta_fetch_inode(ii_sbi(ii), parent, &parent_ii);
	if (err) {
		return err;
	}
	if (!ii_isdir(parent_ii)) {
		return -EFSCORRUPTED; /* XXX */
	}
	return 0;
}

/*
 * TODO-0004: Submit a patch to Linux kernel which support readdir of
 * multiple pages, possible using 'st_blksize' as hint.
 *
 * As of glibc-2.28 'opendir' uses 'st_blksize' as a hint to for size
 * of internal allocated buffer of 'DIR', which in turn passed to
 * 'getdents' system call. Unfortunately, currently FUSE chops readdir
 * into single page iterations.
 */
static blksize_t stat_blksize_of(const struct voluta_inode_info *ii)
{
	blksize_t bsz = VOLUTA_BK_SIZE;

	if (ii_isreg(ii) && (ii_size(ii) < bsz)) {
		bsz = VOLUTA_FILE_HEAD2_LEAF_SIZE;
	}
	return bsz;
}

static blkcnt_t stat_blocks_of(const struct voluta_inode_info *ii)
{
	const size_t frg_size = 512;
	const ssize_t kb_size = VOLUTA_KB_SIZE;
	const blkcnt_t blocks = ii_blocks(ii);
	const size_t nbytes = (size_t)(blocks * kb_size);

	return (blkcnt_t)div_round_up(nbytes, frg_size);
}

void voluta_stat_of(const struct voluta_inode_info *ii, struct stat *st)
{
	struct voluta_itimes tms;

	voluta_memzero(st, sizeof(*st));
	st->st_ino = ii_xino(ii);
	st->st_mode = ii_mode(ii);
	st->st_nlink = ii_nlink(ii);
	st->st_uid = ii_uid(ii);
	st->st_gid = ii_gid(ii);
	st->st_rdev = ii_rdev(ii);
	st->st_size = ii_size(ii);
	st->st_blocks = stat_blocks_of(ii);
	st->st_blksize = stat_blksize_of(ii);

	voluta_ii_times(ii, &tms);
	assign_ts(&st->st_atim, &ii->i_atime_lazy);
	assign_ts(&st->st_ctim, &tms.ctime);
	assign_ts(&st->st_mtim, &tms.mtime);
}

static void voluta_statx_of(const struct voluta_inode_info *ii,
                            unsigned int request_mask, struct statx *stx)
{
	struct voluta_itimes tms;
	const mode_t ifmt = S_IFMT;
	const unsigned int statx_times =
	        STATX_ATIME | STATX_BTIME | STATX_CTIME | STATX_MTIME;

	voluta_memzero(stx, sizeof(*stx));
	if (request_mask & STATX_NLINK) {
		stx->stx_nlink = (uint32_t)ii_nlink(ii);
		stx->stx_mask |= STATX_NLINK;
	}
	if (request_mask & STATX_UID) {
		stx->stx_uid = ii_uid(ii);
		stx->stx_mask |= STATX_UID;
	}
	if (request_mask & STATX_GID) {
		stx->stx_gid = ii_gid(ii);
		stx->stx_mask |= STATX_GID;
	}
	if (request_mask & STATX_TYPE) {
		stx->stx_mode |= (uint16_t)(ii_mode(ii) & ifmt);
		stx->stx_mask |= STATX_TYPE;
	}
	if (request_mask & STATX_MODE) {
		stx->stx_mode |= (uint16_t)(ii_mode(ii) & ~ifmt);
		stx->stx_mask |= STATX_MODE;
	}
	if (request_mask & STATX_INO) {
		stx->stx_ino = ii_xino(ii);
		stx->stx_mask |= STATX_INO;
	}
	if (request_mask & STATX_SIZE) {
		stx->stx_size = (uint64_t)ii_size(ii);
		stx->stx_mask |= STATX_SIZE;
	}
	if (request_mask & STATX_BLOCKS) {
		stx->stx_blocks = (uint64_t)stat_blocks_of(ii);
		stx->stx_mask |= STATX_BLOCKS;
	}

	stx->stx_blksize = (uint32_t)stat_blksize_of(ii);
	stx->stx_rdev_minor =  i_rdev_minor_of(ii);
	stx->stx_rdev_major =  i_rdev_major_of(ii);

	stx->stx_attributes_mask = STATX_ATTR_ENCRYPTED;
	stx->stx_attributes = STATX_ATTR_ENCRYPTED;

	if (request_mask & statx_times) {
		voluta_ii_times(ii, &tms);
		assign_xts(&stx->stx_atime, &ii->i_atime_lazy);
		assign_xts(&stx->stx_btime, &tms.btime);
		assign_xts(&stx->stx_ctime, &tms.ctime);
		assign_xts(&stx->stx_mtime, &tms.mtime);
		stx->stx_mask |= statx_times;
	}
}

/*
 * TODO-0016: Support strict-access mode
 *
 * Have special mode where only root & self may read inode's attributes.
 */
static int check_getattr(const struct voluta_oper *op,
                         const struct voluta_inode_info *ii)
{
	int err;

	unused(op);
	err = check_parent_dir_ii(ii);
	if (err) {
		return err;
	}
	return 0;
}

static int do_getattr(const struct voluta_oper *op,
                      const struct voluta_inode_info *ii,
                      struct stat *out_st)
{
	int err;

	err = check_getattr(op, ii);
	if (err) {
		return err;
	}
	voluta_stat_of(ii, out_st);
	return 0;
}

int voluta_do_getattr(const struct voluta_oper *op,
                      struct voluta_inode_info *ii, struct stat *out_st)
{
	int err;

	ii_incref(ii);
	err = do_getattr(op, ii, out_st);
	ii_decref(ii);
	return err;
}

static int do_statx(const struct voluta_oper *op,
                    const struct voluta_inode_info *ii,
                    unsigned int request_mask, struct statx *out_stx)
{
	int err;

	err = check_getattr(op, ii);
	if (err) {
		return err;
	}
	voluta_statx_of(ii, request_mask, out_stx);
	return 0;
}

int voluta_do_statx(const struct voluta_oper *op,
                    struct voluta_inode_info *ii,
                    unsigned int request_mask, struct statx *out_stx)
{
	int err;

	ii_incref(ii);
	err = do_statx(op, ii, request_mask, out_stx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct timespec *
timespec_of(const struct voluta_oper *op, const struct timespec *ts_in)
{
	const struct timespec *ts = ts_in;

	voluta_assert_not_null(ts_in);
	if (ts_in->tv_nsec == UTIME_NOW) {
		ts = &op->xtime;
	} else if (ts_in->tv_nsec == UTIME_OMIT) {
		ts = NULL;
	}
	return ts;
}

static void i_update_atime(struct voluta_inode_info *ii,
                           const struct timespec *atime)
{
	if (atime != NULL) {
		memcpy(&ii->i_atime_lazy, atime, sizeof(ii->i_atime_lazy));
	}
}

static void update_inode_attr(struct voluta_inode_info *ii,
                              const struct voluta_oper *op,
                              enum voluta_iattr_flags attr_flags,
                              const struct voluta_iattr *iattr)
{
	long flags = (long)attr_flags;
	struct voluta_inode *inode;
	const struct timespec *ts;

	if (ii == NULL) {
		return; /* e.g., rename */
	}
	if (flags & (VOLUTA_IATTR_LAZY | VOLUTA_IATTR_ATIME)) {
		ts = timespec_of(op, &iattr->ia_t.atime);
		i_update_atime(ii, ts);
		flags &= ~VOLUTA_IATTR_ATIME;
	}
	flags &= ~VOLUTA_IATTR_LAZY;
	if (!flags) {
		return;
	}
	inode = ii->inode;
	if (flags & VOLUTA_IATTR_PARENT) {
		inode_set_parent(inode, iattr->ia_parent);
	}
	if (flags & VOLUTA_IATTR_SIZE) {
		inode_set_size(inode, iattr->ia_size);
	}
	if (flags & VOLUTA_IATTR_SPAN) {
		inode_set_span(inode, iattr->ia_span);
	}
	if (flags & VOLUTA_IATTR_BLOCKS) {
		inode_set_blocks(inode, iattr->ia_blocks);
	}
	if (flags & VOLUTA_IATTR_NLINK) {
		voluta_assert_lt(iattr->ia_nlink, UINT_MAX);
		inode_set_nlink(inode, iattr->ia_nlink);
	}
	if (flags & VOLUTA_IATTR_MODE) {
		inode_set_mode(inode, iattr->ia_mode);
	}
	if (flags & VOLUTA_IATTR_UID) {
		inode_set_uid(inode, iattr->ia_uid);
	}
	if (flags & VOLUTA_IATTR_GID) {
		inode_set_gid(inode, iattr->ia_gid);
	}
	if (flags & VOLUTA_IATTR_BTIME) {
		ts = timespec_of(op, &iattr->ia_t.btime);
		inode_set_btime(inode, ts);
	}
	if (flags & VOLUTA_IATTR_MTIME) {
		ts = timespec_of(op, &iattr->ia_t.mtime);
		inode_set_mtime(inode, ts);
	}
	if (flags & VOLUTA_IATTR_CTIME) {
		ts = timespec_of(op, &iattr->ia_t.ctime);
		inode_set_ctime(inode, ts);
	}
	if (flags & VOLUTA_IATTR_ATIME) {
		ts = timespec_of(op, &iattr->ia_t.atime);
		inode_set_atime(inode, ts);
		voluta_refresh_atime(ii, true);
	} else if (flags & VOLUTA_IATTR_TIMES) {
		voluta_refresh_atime(ii, false);
	}
	if (flags & (VOLUTA_IATTR_KILL_SUID | VOLUTA_IATTR_KILL_SGID)) {
		kill_suid_sgid(ii, flags);
	}
	inode_inc_revision(inode);
	ii_dirtify(ii);
}

void voluta_update_iattrs(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          const struct voluta_iattr *iattr)
{
	struct voluta_oper dummy_op = {
		.unique = 0,
	};

	update_inode_attr(ii, op ? op : &dummy_op, iattr->ia_flags, iattr);
}

void voluta_update_itimes(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          enum voluta_iattr_flags attr_flags)
{
	struct voluta_iattr iattr;
	const enum voluta_iattr_flags mask = VOLUTA_IATTR_TIMES;

	iattr_setup(&iattr, ii_ino(ii));
	update_inode_attr(ii, op, attr_flags & mask, &iattr);
}

void voluta_refresh_atime(struct voluta_inode_info *ii, bool to_volatile)
{
	if (to_volatile) {
		inode_atime(ii->inode, &ii->i_atime_lazy);
	} else {
		inode_set_atime(ii->inode, &ii->i_atime_lazy);
	}
}

static blkcnt_t recalc_iblocks(const struct voluta_inode_info *ii,
                               enum voluta_vtype vtype, long dif)
{
	blkcnt_t cnt;
	const size_t nkbs = vtype_nkbs(vtype);
	const blkcnt_t blocks = ii_blocks(ii);

	if (dif > 0) {
		cnt = blocks + (blkcnt_t)(nkbs * (size_t)dif);
	} else {
		cnt = blocks - (blkcnt_t)(nkbs * (size_t)labs(dif));
	}
	voluta_assert_ge(cnt, 0);

	return cnt;
}

void voluta_update_iblocks(const struct voluta_oper *op,
                           struct voluta_inode_info *ii,
                           enum voluta_vtype vtype, long dif)
{
	struct voluta_iattr iattr;

	iattr_setup(&iattr, ii_ino(ii));
	iattr.ia_blocks = recalc_iblocks(ii, vtype, dif);
	iattr.ia_flags = VOLUTA_IATTR_BLOCKS;

	update_iattrs(op, ii, &iattr);
}

void voluta_update_isize(const struct voluta_oper *op,
                         struct voluta_inode_info *ii, loff_t size)
{
	struct voluta_iattr iattr;

	iattr_setup(&iattr, ii_ino(ii));
	iattr.ia_size = size;
	iattr.ia_flags = VOLUTA_IATTR_SIZE;

	update_iattrs(op, ii, &iattr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_inode_specific(const struct voluta_inode *inode)
{
	int err;
	const mode_t mode = inode_mode(inode);

	if (S_ISDIR(mode)) {
		err = voluta_verify_dir_inode(inode);
	} else {
		/* TODO: ALL type */
		err = 0;
	}
	return err;
}

int voluta_verify_inode(const struct voluta_inode *inode)
{
	int err;

	err = voluta_verify_ino(inode_ino(inode));
	if (err) {
		return err;
	}
	err = voluta_verify_inode_xattr(inode);
	if (err) {
		return err;
	}
	err = verify_inode_specific(inode);
	if (err) {
		return err;
	}
	return err;
}

