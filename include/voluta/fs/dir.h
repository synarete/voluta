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
#ifndef VOLUTA_DIR_H_
#define VOLUTA_DIR_H_

#include <voluta/fs/types.h>

size_t voluta_dir_ndentries(const struct voluta_inode_info *dir_ii);

enum voluta_dirf voluta_dir_flags(const struct voluta_inode_info *dir_ii);

int voluta_verify_dir_inode(const struct voluta_inode *inode);

int voluta_verify_dir_htree_node(const struct voluta_dir_tnode *htn);

void voluta_setup_dir(struct voluta_inode_info *dir_ii,
                      mode_t parent_mode, nlink_t nlink);

int voluta_lookup_dentry(const struct voluta_oper *op,
                         struct voluta_inode_info *dir_ii,
                         const struct voluta_qstr *name,
                         struct voluta_ino_dt *out_idt);

int voluta_add_dentry(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      const struct voluta_qstr *name,
                      struct voluta_inode_info *ii);

int voluta_remove_dentry(const struct voluta_oper *op,
                         struct voluta_inode_info *dir_ii,
                         const struct voluta_qstr *name);

int voluta_do_readdir(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      struct voluta_readdir_ctx *rd_ctx);

int voluta_do_readdirplus(const struct voluta_oper *op,
                          struct voluta_inode_info *dir_ii,
                          struct voluta_readdir_ctx *rd_ctx);

int voluta_drop_dir(struct voluta_inode_info *dir_ii);


#endif /* VOLUTA_DIR_H_ */
