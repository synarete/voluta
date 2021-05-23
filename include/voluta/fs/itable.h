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
#ifndef VOLUTA_ITABLE_H_
#define VOLUTA_ITABLE_H_

#include <unistd.h>

int voluta_itbi_init(struct voluta_itable_info *iti,
                     struct voluta_alloc_if *alif);

void voluta_itbi_reinit(struct voluta_itable_info *iti);

void voluta_itbi_fini(struct voluta_itable_info *iti);

int voluta_acquire_ino(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_iaddr *out_iaddr);

int voluta_update_ino(struct voluta_sb_info *sbi,
                      const struct voluta_iaddr *iaddr);

int voluta_discard_ino(struct voluta_sb_info *sbi, ino_t ino);

int voluta_resolve_ino(struct voluta_sb_info *sbi,
                       ino_t xino, struct voluta_iaddr *out_iaddr);

int voluta_real_ino(const struct voluta_sb_info *sbi,
                    ino_t ino, ino_t *out_ino);

const struct voluta_vaddr *
voluta_root_of_itable(const struct voluta_sb_info *sbi);

int voluta_bind_rootdir(struct voluta_sb_info *sbi,
                        const struct voluta_inode_info *ii);

int voluta_format_itable(struct voluta_sb_info *sbi);

int voluta_reload_itable(struct voluta_sb_info *sbi);

int voluta_verify_itnode(const struct voluta_itable_tnode *itn);



#endif /* VOLUTA_ITABLE_H_ */
