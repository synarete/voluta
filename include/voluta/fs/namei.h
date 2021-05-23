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
#ifndef VOLUTA_NAMEI_H_
#define VOLUTA_NAMEI_H_

#include <unistd.h>

struct voluta_sb_info;
struct voluta_oper;
struct voluta_ioc_query;

int voluta_authorize(const struct voluta_sb_info *sbi,
                     const struct voluta_oper *op);

int voluta_make_namestr(const struct voluta_inode_info *ii,
                        const char *name, struct voluta_namestr *str);

int voluta_do_forget(const struct voluta_oper *op,
                     struct voluta_inode_info *ii, size_t nlookup);

int voluta_do_statvfs(const struct voluta_oper *op,
                      struct voluta_inode_info *ii,
                      struct statvfs *out_stvfs);

int voluta_do_access(const struct voluta_oper *op,
                     struct voluta_inode_info *ii, int mode);

int voluta_do_open(const struct voluta_oper *op,
                   struct voluta_inode_info *ii, int flags);

int voluta_do_release(const struct voluta_oper *op,
                      struct voluta_inode_info *ii);

int voluta_do_mkdir(const struct voluta_oper *op,
                    struct voluta_inode_info *dir_ii,
                    const struct voluta_namestr *name, mode_t mode,
                    struct voluta_inode_info **out_ii);

int voluta_do_rmdir(const struct voluta_oper *op,
                    struct voluta_inode_info *dir_ii,
                    const struct voluta_namestr *name);

int voluta_do_rename(const struct voluta_oper *op,
                     struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name,
                     struct voluta_inode_info *newdir_ii,
                     const struct voluta_namestr *newname, int flags);

int voluta_do_symlink(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      const struct voluta_namestr *name,
                      const struct voluta_str *symval,
                      struct voluta_inode_info **out_ii);

int voluta_do_link(const struct voluta_oper *op,
                   struct voluta_inode_info *dir_ii,
                   const struct voluta_namestr *name,
                   struct voluta_inode_info *ii);

int voluta_do_unlink(const struct voluta_oper *op,
                     struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name);

int voluta_do_create(const struct voluta_oper *op,
                     struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name, mode_t mode,
                     struct voluta_inode_info **out_ii);

int voluta_do_mknod(const struct voluta_oper *op,
                    struct voluta_inode_info *dir_ii,
                    const struct voluta_namestr *name, mode_t mode, dev_t dev,
                    struct voluta_inode_info **out_ii);

int voluta_do_lookup(const struct voluta_oper *op,
                     struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name,
                     struct voluta_inode_info **out_ii);

int voluta_do_opendir(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii);

int voluta_do_releasedir(const struct voluta_oper *op,
                         struct voluta_inode_info *dir_ii);

int voluta_do_fsyncdir(const struct voluta_oper *op,
                       struct voluta_inode_info *dir_ii, bool dsync);

int voluta_do_fsync(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, bool datasync);

int voluta_do_flush(const struct voluta_oper *op,
                    struct voluta_inode_info *ii);

int voluta_do_query(const struct voluta_oper *op,
                    struct voluta_inode_info *ii,
                    struct voluta_ioc_query *out_qry);

int voluta_do_clone(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, char *str, size_t lim);

int voluta_check_name(const char *name);

#endif /* VOLUTA_NAMEI_H_ */
