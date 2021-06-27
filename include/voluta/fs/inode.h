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
#ifndef VOLUTA_INODE_H_
#define VOLUTA_INODE_H_

#include <unistd.h>
#include <voluta/fs/types.h>


ino_t voluta_ii_parent(const struct voluta_inode_info *ii);

ino_t voluta_ii_xino(const struct voluta_inode_info *ii);

uid_t voluta_ii_uid(const struct voluta_inode_info *ii);

gid_t voluta_ii_gid(const struct voluta_inode_info *ii);

mode_t voluta_ii_mode(const struct voluta_inode_info *ii);

nlink_t voluta_ii_nlink(const struct voluta_inode_info *ii);

loff_t voluta_ii_size(const struct voluta_inode_info *ii);

loff_t voluta_ii_span(const struct voluta_inode_info *ii);

blkcnt_t voluta_ii_blocks(const struct voluta_inode_info *ii);

bool voluta_ii_isdir(const struct voluta_inode_info *ii);

bool voluta_ii_isreg(const struct voluta_inode_info *ii);

bool voluta_ii_isfifo(const struct voluta_inode_info *ii);

bool voluta_ii_issock(const struct voluta_inode_info *ii);

bool voluta_ii_islnk(const struct voluta_inode_info *ii);

bool voluta_ii_isrootd(const struct voluta_inode_info *ii);

bool voluta_is_rootdir(const struct voluta_inode_info *ii);

void voluta_fixup_rootdir(struct voluta_inode_info *ii);

enum voluta_inodef voluta_ii_flags(const struct voluta_inode_info *ii);

int voluta_do_getattr(const struct voluta_oper *op,
                      struct voluta_inode_info *ii, struct stat *out_st);

int voluta_do_statx(const struct voluta_oper *op,
                    struct voluta_inode_info *ii,
                    unsigned int request_mask, struct statx *out_stx);

int voluta_do_chmod(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, mode_t mode,
                    const struct voluta_itimes *itimes);

int voluta_do_chown(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, uid_t uid, gid_t gid,
                    const struct voluta_itimes *itimes);

int voluta_do_utimens(const struct voluta_oper *op,
                      struct voluta_inode_info *ii,
                      const struct voluta_itimes *itimes);

int voluta_verify_inode(const struct voluta_inode *inode);

void voluta_update_itimes(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          enum voluta_iattr_flags attr_flags);

void voluta_update_iblocks(const struct voluta_oper *op,
                           struct voluta_inode_info *ii,
                           enum voluta_vtype vtype, long dif);

void voluta_update_isize(const struct voluta_oper *op,
                         struct voluta_inode_info *ii, loff_t size);

void voluta_update_iattrs(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          const struct voluta_iattr *attr);

void voluta_iattr_setup(struct voluta_iattr *iattr, ino_t ino);

void voluta_refresh_atime(struct voluta_inode_info *ii, bool to_volatile);

void voluta_setup_inode(struct voluta_inode_info *ii,
                        const struct voluta_ucred *ucred,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev);

void voluta_snap_inode(struct voluta_inode_info *ii,
                       const struct voluta_inode_info *ii_other);

void voluta_stat_of(const struct voluta_inode_info *ii, struct stat *st);

#endif /* VOLUTA_INODE_H_ */
