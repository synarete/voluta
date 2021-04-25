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
#ifndef VOLUTA_XATTR_H_
#define VOLUTA_XATTR_H_

void voluta_setup_xattr(struct voluta_inode_info *ii);

int voluta_do_getxattr(const struct voluta_oper *op,
                       struct voluta_inode_info *ii,
                       const struct voluta_namestr *name,
                       void *buf, size_t size, size_t *out_size);

int voluta_do_setxattr(const struct voluta_oper *op,
                       struct voluta_inode_info *ii,
                       const struct voluta_namestr *name,
                       const void *value, size_t size, int flags);

int voluta_do_removexattr(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          const struct voluta_namestr *name);

int voluta_do_listxattr(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        struct voluta_listxattr_ctx *lxa_ctx);

int voluta_drop_xattr(struct voluta_inode_info *ii);

int voluta_verify_inode_xattr(const struct voluta_inode *inode);

int voluta_verify_xattr_node(const struct voluta_xattr_node *xan);


#endif /* VOLUTA_XATTR_H_ */
