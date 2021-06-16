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
#ifndef VOLUTA_OPERS_H_
#define VOLUTA_OPERS_H_

#include <unistd.h>
#include <stdlib.h>

struct voluta_sb_info;
struct voluta_oper;
struct voluta_ioc_query;

int voluta_fs_forget(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino, size_t nlookup);

int voluta_fs_statfs(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino,
                     struct statvfs *stvfs);

int voluta_fs_lookup(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, struct stat *out_stat);

int voluta_fs_getattr(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op,
                      ino_t ino, struct stat *out_stat);

int voluta_fs_mkdir(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t parent,
                    const char *name, mode_t mode, struct stat *out_stat);

int voluta_fs_rmdir(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op,
                    ino_t parent, const char *name);

int voluta_fs_access(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino, int mode);

int voluta_fs_chmod(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat);

int voluta_fs_chown(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat);

int voluta_fs_truncate(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino, loff_t len,
                       struct stat *out_stat);

int voluta_fs_utimens(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino,
                      const struct stat *times, struct stat *out_stat);

int voluta_fs_symlink(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t parent,
                      const char *name, const char *symval,
                      struct stat *out_stat);

int voluta_fs_readlink(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op,
                       ino_t ino, char *ptr, size_t lim, size_t *out_len);

int voluta_fs_unlink(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op,
                     ino_t parent, const char *name);

int voluta_fs_link(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, ino_t parent,
                   const char *name, struct stat *out_stat);

int voluta_fs_rename(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags);

int voluta_fs_opendir(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino);

int voluta_fs_releasedir(struct voluta_sb_info *sbi,
                         const struct voluta_oper *op, ino_t ino, int o_flags);

int voluta_fs_readdir(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino,
                      struct voluta_readdir_ctx *rd_ctx);

int voluta_fs_readdirplus(struct voluta_sb_info *sbi,
                          const struct voluta_oper *op, ino_t ino,
                          struct voluta_readdir_ctx *rd_ctx);

int voluta_fs_fsyncdir(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino, bool datasync);

int voluta_fs_create(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct stat *out_stat);

int voluta_fs_open(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, int o_flags);

int voluta_fs_mknod(struct voluta_sb_info *sbi, const struct voluta_oper *op,
                    ino_t parent, const char *name, mode_t mode, dev_t rdev,
                    struct stat *out_stat);

int voluta_fs_release(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op,
                      ino_t ino, int o_flags, bool flush);

int voluta_fs_flush(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino);

int voluta_fs_fsync(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op,
                    ino_t ino, bool datasync);

int voluta_fs_getxattr(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size);

int voluta_fs_setxattr(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags);

int voluta_fs_listxattr(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        struct voluta_listxattr_ctx *lxa_ctx);

int voluta_fs_removexattr(struct voluta_sb_info *sbi,
                          const struct voluta_oper *op,
                          ino_t ino, const char *name);

int voluta_fs_fallocate(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        int mode, loff_t offset, loff_t length);

int voluta_fs_lseek(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    loff_t off, int whence, loff_t *out_off);

int voluta_fs_copy_file_range(struct voluta_sb_info *sbi,
                              const struct voluta_oper *op, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp);

int voluta_fs_read(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len);

int voluta_fs_read_iter(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        struct voluta_rwiter_ctx *rwi_ctx);

int voluta_fs_write(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    const void *buf, size_t len, off_t off, size_t *out_len);

int voluta_fs_write_iter(struct voluta_sb_info *sbi,
                         const struct voluta_oper *op, ino_t ino,
                         struct voluta_rwiter_ctx *rwi_ctx);

int voluta_fs_rdwr_post(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        const struct voluta_fiovec *fiov, size_t cnt);

int voluta_fs_statx(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    unsigned int request_mask, struct statx *out_stx);

int voluta_fs_fiemap(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino,
                     struct fiemap *fm);

int voluta_fs_query(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    struct voluta_ioc_query *out_qry);

int voluta_fs_snap(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op,
                   ino_t ino, char *str, size_t lim);

int voluta_fs_timedout(struct voluta_sb_info *sbi, int flags);

#endif /* VOLUTA_OPERS_H_ */
