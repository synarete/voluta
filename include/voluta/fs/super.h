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
#ifndef VOLUTA_SUPER_H_
#define VOLUTA_SUPER_H_

#include <unistd.h>
#include <stdlib.h>
#include <voluta/fs/types.h>


int voluta_sbi_init(struct voluta_sb_info *sbi,
                    struct voluta_super_block *sb,
                    struct voluta_cache *cache, struct voluta_vstore *vstore);

void voluta_sbi_fini(struct voluta_sb_info *sbi);

void voluta_sbi_setowner(struct voluta_sb_info *sbi,
                         const struct voluta_ucred *cred);

int voluta_sbi_setspace(struct voluta_sb_info *sbi, loff_t volume_capacity);

void voluta_sbi_add_ctlflags(struct voluta_sb_info *sbi, enum voluta_flags f);




int voluta_adjust_super(struct voluta_sb_info *sbi);

int voluta_format_spmaps(struct voluta_sb_info *sbi);

int voluta_reload_super(struct voluta_sb_info *sbi);

int voluta_reload_spmaps(struct voluta_sb_info *sbi);

int voluta_traverse_space(struct voluta_sb_info *sbi);

void voluta_statvfs_of(const struct voluta_sb_info *sbi,
                       struct statvfs *out_stvfs);

int voluta_flush_dirty(struct voluta_sb_info *sbi, int flags);

int voluta_flush_dirty_of(const struct voluta_inode_info *ii, int flags);

int voluta_shut_super(struct voluta_sb_info *sbi);


int voluta_fetch_inode(struct voluta_sb_info *sbi, ino_t xino,
                       struct voluta_inode_info **out_ii);

int voluta_fetch_cached_inode(struct voluta_sb_info *sbi, ino_t xino,
                              struct voluta_inode_info **out_ii);

int voluta_stage_inode(struct voluta_sb_info *sbi, ino_t xino,
                       struct voluta_inode_info **out_ii);

int voluta_stage_vnode(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       const struct voluta_inode_info *pii,
                       struct voluta_vnode_info **out_vi);

int voluta_stage_data(struct voluta_sb_info *sbi,
                      const struct voluta_vaddr *vaddr,
                      const struct voluta_inode_info *pii,
                      struct voluta_vnode_info **out_vi);

int voluta_create_inode(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev,
                        struct voluta_inode_info **out_ii);

int voluta_create_vnode(struct voluta_sb_info *sbi,
                        struct voluta_inode_info *pii,
                        enum voluta_vtype vtype,
                        struct voluta_vnode_info **out_vi);

int voluta_allocate_space(struct voluta_sb_info *sbi,
                          enum voluta_vtype vtype,
                          struct voluta_vaddr *out_vaddr);

int voluta_remove_inode(struct voluta_sb_info *sbi,
                        struct voluta_inode_info *ii);

int voluta_remove_vnode(struct voluta_sb_info *sbi,
                        struct voluta_vnode_info *vi);

int voluta_remove_vnode_at(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr);

int voluta_probe_unwritten(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr, bool *out_res);

int voluta_clear_unwritten(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr);

int voluta_mark_unwritten(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr);

int voluta_refcnt_islast_at(struct voluta_sb_info *sbi,
                            const struct voluta_vaddr *vaddr, bool *out_res);

int voluta_kivam_of(const struct voluta_vnode_info *vi,
                    struct voluta_kivam *out_kivam);


#endif /* VOLUTA_SUPER_H_ */