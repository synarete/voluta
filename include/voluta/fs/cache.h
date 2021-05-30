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
#ifndef VOLUTA_CACHE_H_
#define VOLUTA_CACHE_H_

#include <stdlib.h>
#include <voluta/fs/types.h>


void voluta_ce_init(struct voluta_cache_elem *ce);

void voluta_ce_fini(struct voluta_cache_elem *ce);


int voluta_cache_init(struct voluta_cache *cache, struct voluta_mpool *mpool);

void voluta_cache_fini(struct voluta_cache *cache);

void voluta_cache_relax(struct voluta_cache *cache, int flags);

void voluta_cache_drop(struct voluta_cache *cache);

void voluta_cache_shrink_once(struct voluta_cache *cache);

bool voluta_cache_need_flush(const struct voluta_cache *cache, int flags);

bool voluta_cache_need_flush_of(const struct voluta_cache *cache,
                                const struct voluta_inode_info *ii, int flags);

void voluta_cache_inhabit_dset(const struct voluta_cache *cache,
                               struct voluta_dset *dset);

struct voluta_bksec_info *
voluta_cache_lookup_bsi(struct voluta_cache *cache, voluta_lba_t lba);

struct voluta_bksec_info *
voluta_cache_spawn_bsi(struct voluta_cache *cache, voluta_lba_t lba);

void voluta_cache_forget_bsi(struct voluta_cache *cache,
                             struct voluta_bksec_info *bsi);

struct voluta_inode_info *
voluta_cache_spawn_ii(struct voluta_cache *cache,
                      const struct voluta_vaddr *vaddr, ino_t ino);

void voulta_cache_forget_ii(struct voluta_cache *cache,
                            struct voluta_inode_info *ii);

struct voluta_inode_info *
voluta_cache_lookup_ii(struct voluta_cache *cache,
                       const struct voluta_vaddr *vaddr);

struct voluta_vnode_info *
voluta_cache_lookup_vi(struct voluta_cache *cache,
                       const struct voluta_vaddr *vaddr);

struct voluta_vnode_info *
voluta_cache_spawn_vi(struct voluta_cache *cache,
                      const struct voluta_vaddr *vaddr);

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

bool voluta_ii_isrdonly(const struct voluta_inode_info *ii);

bool voluta_ii_isevictable(const struct voluta_inode_info *ii);


void voluta_mark_visible(const struct voluta_vnode_info *vi);

void voluta_mark_opaque_at(struct voluta_bksec_info *bsi,
                           const struct voluta_vaddr *vaddr);

bool voluta_is_visible(const struct voluta_vnode_info *vi);



struct voluta_agroup_info *
voluta_agi_from_vi(const struct voluta_vnode_info *vi);

#endif /* VOLUTA_CACHE_H_ */
