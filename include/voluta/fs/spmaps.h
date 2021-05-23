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
#ifndef VOLUTA_SPMAPS_H_
#define VOLUTA_SPMAPS_H_


#include <voluta/fs/types.h>

void voluta_usm_init(struct voluta_uspace_map *usm);

void voluta_usm_vaddr(const struct voluta_uspace_map *usm,
                      voluta_index_t hs_index, struct voluta_vaddr *out_vaddr);

void voluta_usm_set_vaddr(struct voluta_uspace_map *usm,
                          voluta_index_t hs_index,
                          const struct voluta_vaddr *vaddr);

void voluta_accum_space_stat(struct voluta_space_stat *sp_st,
                             const struct voluta_space_stat *other);

void voluta_setup_hsmap(struct voluta_hspace_info *hsi,
                        voluta_index_t hs_index, size_t nags_span);

voluta_index_t voluta_hs_index_of(const struct voluta_hspace_info *hsi);

void voluta_update_space(struct voluta_hspace_info *hsi,
                         voluta_index_t ag_index,
                         const struct voluta_space_stat *sp_st);

void voluta_space_stat_at(const struct voluta_hspace_info *hsi,
                          voluta_index_t ag_index,
                          struct voluta_space_stat *sp_st);

void voluta_space_stat_of(const struct voluta_hspace_info *hsi,
                          struct voluta_space_stat *sp_st);

void voluta_set_formatted_ag(struct voluta_hspace_info *hsi,
                             const struct voluta_vaddr *agm_vaddr,
                             const struct voluta_vaddr *bks_vaddr);

bool voluta_has_formatted_ag(const struct voluta_hspace_info *hsi,
                             voluta_index_t ag_index);

void voluta_ag_range_of(const struct voluta_hspace_info *hsi,
                        struct voluta_ag_range *ag_range);

void voluta_mark_fragmented(struct voluta_hspace_info *hsi,
                            voluta_index_t ag_index);

void voluta_clear_fragmented_at(struct voluta_hspace_info *hsi,
                                const struct voluta_vaddr *vaddr);

void voluta_mark_with_next(struct voluta_hspace_info *hsi);

bool voluta_has_next_hspace(const struct voluta_hspace_info *hsi);

void voluta_bind_to_kindof(struct voluta_hspace_info *hsi,
                           const struct voluta_vaddr *vaddr);

int voluta_check_cap_alloc(const struct voluta_hspace_info *hsi,
                           const enum voluta_vtype vtype);

void voluta_resolve_vaddrs_of_ag(const struct voluta_hspace_info *hsi,
                                 voluta_index_t ag_index,
                                 struct voluta_vaddr *out_agm_vaddr,
                                 struct voluta_vaddr *out_bks_vaddr);

void voluta_setup_agmap(struct voluta_agroup_info *agi,
                        voluta_index_t ag_index);

size_t voluta_ag_index_of(const struct voluta_agroup_info *agi);


int voluta_search_avail_ag(const struct voluta_hspace_info *hsi,
                           voluta_index_t ag_index_first,
                           voluta_index_t ag_index_last,
                           enum voluta_vtype vtype, size_t *out_ag_index);

int voluta_search_free_space(const struct voluta_hspace_info *hsi,
                             const struct voluta_agroup_info *agi,
                             enum voluta_vtype vtype,
                             struct voluta_vaddr *out_vaddr);

void voluta_mark_allocated_space(struct voluta_agroup_info *agi,
                                 const struct voluta_vaddr *vaddr);

void voluta_clear_allocated_space(struct voluta_agroup_info *agi,
                                  const struct voluta_vaddr *vaddr);

size_t voluta_block_refcnt_at(const struct voluta_agroup_info *agi,
                              const struct voluta_vaddr *vaddr);

bool voluta_has_lone_refcnt(const struct voluta_agroup_info *agi,
                            const struct voluta_vaddr *vaddr);

void voluta_calc_space_stat_of(const struct voluta_agroup_info *agi,
                               struct voluta_space_stat *out_sp_st);

bool voluta_has_unwritten_at(const struct voluta_agroup_info *agi,
                             const struct voluta_vaddr *vaddr);

void voluta_clear_unwritten_at(struct voluta_agroup_info *agi,
                               const struct voluta_vaddr *vaddr);

void voluta_mark_unwritten_at(struct voluta_agroup_info *agi,
                              const struct voluta_vaddr *vaddr);

bool voluta_is_allocated_with(const struct voluta_agroup_info *agi,
                              const struct voluta_vaddr *vaddr);


int voluta_verify_hspace_map(const struct voluta_hspace_map *hsm);

int voluta_verify_agroup_map(const struct voluta_agroup_map *agm);



#endif /* VOLUTA_SPMAPS_H_ */
