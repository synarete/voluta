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
#ifndef VOLUTA_SYMLINK_H_
#define VOLUTA_SYMLINK_H_

#include <stdlib.h>

void voluta_setup_symlnk(struct voluta_inode_info *lnk_ii);

int voluta_drop_symlink(struct voluta_inode_info *lnk_ii);

int voluta_do_readlink(const struct voluta_oper *op,
                       struct voluta_inode_info *lnk_ii,
                       void *ptr, size_t lim, size_t *out_len);

int voluta_setup_symlink(const struct voluta_oper *op,
                         struct voluta_inode_info *lnk_ii,
                         const struct voluta_str *symval);

int voluta_verify_lnk_value(const struct voluta_symlnk_value *lnv);

#endif /* VOLUTA_SYMLINK_H_ */
