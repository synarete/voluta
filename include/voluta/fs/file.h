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
#ifndef VOLUTA_FILE_H_
#define VOLUTA_FILE_H_

#include <unistd.h>
#include <stdlib.h>

void voluta_setup_reg(struct voluta_inode_info *ii);

int voluta_drop_reg(struct voluta_inode_info *ii);

int voluta_do_write(const struct voluta_oper *op,
                    struct voluta_inode_info *ii,
                    const void *buf, size_t len,
                    loff_t off, size_t *out_len);

int voluta_do_write_iter(const struct voluta_oper *op,
                         struct voluta_inode_info *ii,
                         struct voluta_rwiter_ctx *rwi_ctx);

int voluta_do_rdwr_post(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        const struct voluta_fiovec *fiov, size_t cnt);

int voluta_do_read_iter(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        struct voluta_rwiter_ctx *rwi_ctx);

int voluta_do_read(const struct voluta_oper *op,
                   struct voluta_inode_info *ii,
                   void *buf, size_t len, loff_t off, size_t *out_len);

int voluta_do_lseek(const struct voluta_oper *op,
                    struct voluta_inode_info *ii,
                    loff_t off, int whence, loff_t *out_off);

int voluta_do_fallocate(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        int mode, loff_t off, loff_t length);

int voluta_do_truncate(const struct voluta_oper *op,
                       struct voluta_inode_info *ii, loff_t off);

int voluta_do_fiemap(const struct voluta_oper *op,
                     struct voluta_inode_info *ii, struct fiemap *fm);

int voluta_do_copy_file_range(const struct voluta_oper *op,
                              struct voluta_inode_info *ii_in,
                              struct voluta_inode_info *ii_out,
                              loff_t off_in, loff_t off_out, size_t len,
                              int flags, size_t *out_ncp);

int voluta_verify_radix_tnode(const struct voluta_radix_tnode *rtn);


#endif /* VOLUTA_FILE_H_ */
