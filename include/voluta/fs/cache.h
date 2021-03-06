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
#ifndef VOLUTA_CACHE_H_
#define VOLUTA_CACHE_H_

#include <stdlib.h>
#include <voluta/fs/types.h>


int voluta_ckey_compare(const struct voluta_ckey *ckey1,
                        const struct voluta_ckey *ckey2);

void voluta_ce_init(struct voluta_cache_elem *ce);

void voluta_ce_fini(struct voluta_cache_elem *ce);


int voluta_cache_init(struct voluta_cache *cache,
                      struct voluta_qalloc *qalloc,
                      struct voluta_alloc_if *alif);

void voluta_cache_fini(struct voluta_cache *cache);

void voluta_cache_relax(struct voluta_cache *cache, int flags);

void voluta_cache_drop(struct voluta_cache *cache);

void voluta_cache_shrink_once(struct voluta_cache *cache);

bool voluta_cache_need_flush(const struct voluta_cache *cache, int flags);

void voluta_cache_fill_into_dset(const struct voluta_cache *cache,
                                 struct voluta_dset *dset);

void voluta_cache_undirtify_by_dset(struct voluta_cache *cache,
                                    const struct voluta_dset *dset);

struct voluta_bksec_info *
voluta_cache_lookup_bsi(struct voluta_cache *cache,
                        const struct voluta_vba *vba);

struct voluta_bksec_info *
voluta_cache_spawn_bsi(struct voluta_cache *cache,
                       const struct voluta_vba *vba);

void voluta_cache_forget_bsi(struct voluta_cache *cache,
                             struct voluta_bksec_info *bsi);


void voluta_bsi_mark_visible_at(struct voluta_bksec_info *bsi,
                                const struct voluta_vaddr *vaddr);

void voluta_bsi_mark_opaque_at(struct voluta_bksec_info *bsi,
                               const struct voluta_vaddr *vaddr);

bool voluta_bsi_is_visible_at(struct voluta_bksec_info *bsi,
                              const struct voluta_vaddr *vaddr);

void voluta_bsi_mark_visible(struct voluta_bksec_info *bsi);


struct voluta_vnode_info *
voluta_cache_lookup_vi(struct voluta_cache *cache,
                       const struct voluta_vaddr *vaddr);

struct voluta_vnode_info *
voluta_cache_spawn_vi(struct voluta_cache *cache,
                      const struct voluta_vba *vba);

void voulta_cache_forget_vi(struct voluta_cache *cache,
                            struct voluta_vnode_info *vi);


void voluta_vi_dirtify(struct voluta_vnode_info *vi);

void voluta_vi_undirtify(struct voluta_vnode_info *vi);

void voluta_vi_attach_to(struct voluta_vnode_info *vi,
                         struct voluta_bksec_info *bsi);

void voluta_vi_incref(struct voluta_vnode_info *vi);

void voluta_vi_decref(struct voluta_vnode_info *vi);

size_t voluta_vi_refcnt(const struct voluta_vnode_info *vi);

size_t voluta_ii_refcnt(const struct voluta_inode_info *ii);

void voluta_ii_incref(struct voluta_inode_info *ii);

void voluta_ii_decref(struct voluta_inode_info *ii);

void voluta_ii_dirtify(struct voluta_inode_info *ii);

void voluta_ii_undirtify(struct voluta_inode_info *ii);


struct voluta_unode_info *
voluta_cache_spawn_ui(struct voluta_cache *cache,
                      const struct voluta_uba *uba);

void voulta_cache_forget_ui(struct voluta_cache *cache,
                            struct voluta_unode_info *ui);

struct voluta_unode_info *
voluta_cache_lookup_ui(struct voluta_cache *cache,
                       const struct voluta_uaddr *uaddr);

void voluta_ui_attach_to(struct voluta_unode_info *ui,
                         struct voluta_bksec_info *bsi);


void voluta_ui_incref(struct voluta_unode_info *ui);

void voluta_ui_decref(struct voluta_unode_info *ui);

void voluta_ui_dirtify(struct voluta_unode_info *ui);

void voluta_ui_undirtify(struct voluta_unode_info *ui);

bool voluta_zi_isevictable(const struct voluta_znode_info *zi);


#endif /* VOLUTA_CACHE_H_ */
