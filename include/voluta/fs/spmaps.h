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
#ifndef VOLUTA_SPMAPS_H_
#define VOLUTA_SPMAPS_H_


#include <voluta/fs/types.h>

void voluta_bls_initn(struct voluta_blobspec *bls, size_t n);

void voluta_bls_vba(const struct voluta_blobspec *bls,
                    struct voluta_vba *out_vba);

void voluta_bls_set_vba(struct voluta_blobspec *bls,
                        const struct voluta_vba *vba);


void voluta_accum_space_stat(struct voluta_space_stat *sp_st,
                             const struct voluta_space_stat *other);

void voluta_hsi_setup(struct voluta_hspace_info *hsi, size_t nags_span);

void voluta_hsi_vba(const struct voluta_hspace_info *hsi,
                    struct voluta_vba *out_vba);

void voluta_hsi_update_space(struct voluta_hspace_info *hsi,
                             voluta_index_t ag_index,
                             const struct voluta_space_stat *sp_st);

void voluta_hsi_space_stat_at(const struct voluta_hspace_info *hsi,
                              voluta_index_t ag_index,
                              struct voluta_space_stat *sp_st);

void voluta_hsi_space_stat_of(const struct voluta_hspace_info *hsi,
                              struct voluta_space_stat *sp_st);

void voluta_hsi_resolve_agm(const struct voluta_hspace_info *hsi,
                            voluta_index_t ag_index,
                            struct voluta_vba *out_agm_vba);

void voluta_hsi_bind_agm(struct voluta_hspace_info *hsi,
                         voluta_index_t ag_index,
                         const struct voluta_vba *agm_vba);

bool voluta_hsi_has_agm(const struct voluta_hspace_info *hsi,
                        voluta_index_t ag_index);

void voluta_hsi_ag_span(const struct voluta_hspace_info *hsi,
                        struct voluta_ag_span *ag_span);

void voluta_hsi_mark_fragmented(struct voluta_hspace_info *hsi,
                                voluta_index_t ag_index);

void voluta_hsi_clear_fragmented(struct voluta_hspace_info *hsi,
                                 voluta_index_t ag_index);

bool voluta_hsi_is_fragmented(const struct voluta_hspace_info *hsi,
                              voluta_index_t ag_index);


void voluta_hsi_bind_to_kindof(struct voluta_hspace_info *hsi,
                               const struct voluta_vaddr *vaddr);

int voluta_hsi_check_cap_alloc(const struct voluta_hspace_info *hsi,
                               const enum voluta_vtype vtype);

int voluta_hsi_search_avail_ag(const struct voluta_hspace_info *hsi,
                               const struct voluta_index_range *range,
                               enum voluta_vtype vtype,
                               voluta_index_t *out_ag_index,
                               size_t *out_bn_within_ag);


void voluta_agi_dirtify(struct voluta_agroup_info *agi);


void voluta_agi_setup(struct voluta_agroup_info *agi);

void voluta_agi_vba(const struct voluta_agroup_info *agi,
                    struct voluta_vba *out_vba);

void voluta_agi_set_bks_blobid(struct voluta_agroup_info *agi,
                               const struct voluta_blobid *bid);

void voluta_agi_resolve_bks(const struct voluta_agroup_info *agi,
                            const struct voluta_vaddr *vaddr,
                            struct voluta_vba *out_vba);

int voluta_agi_find_free_space(const struct voluta_agroup_info *agi,
                               enum voluta_vtype vtype, size_t bn_start_hint,
                               struct voluta_vba *out_vba);

void voluta_agi_mark_allocated_space(struct voluta_agroup_info *agi,
                                     const struct voluta_vaddr *vaddr);

void voluta_agi_clear_allocated_space(struct voluta_agroup_info *agi,
                                      const struct voluta_vaddr *vaddr);

size_t voluta_block_refcnt_at(const struct voluta_agroup_info *agi,
                              const struct voluta_vaddr *vaddr);

bool voluta_has_lone_refcnt(const struct voluta_agroup_info *agi,
                            const struct voluta_vaddr *vaddr);

void voluta_calc_space_stat_of(const struct voluta_agroup_info *agi,
                               struct voluta_space_stat *out_sp_st);

bool voluta_agi_has_unwritten_at(const struct voluta_agroup_info *agi,
                                 const struct voluta_vaddr *vaddr);

void voluta_agi_clear_unwritten_at(struct voluta_agroup_info *agi,
                                   const struct voluta_vaddr *vaddr);

void voluta_agi_mark_unwritten_at(struct voluta_agroup_info *agi,
                                  const struct voluta_vaddr *vaddr);

bool voluta_agi_is_allocated_with(const struct voluta_agroup_info *agi,
                                  const struct voluta_vaddr *vaddr);


int voluta_verify_hspace_map(const struct voluta_hspace_map *hsm);

int voluta_verify_agroup_map(const struct voluta_agroup_map *agm);



#endif /* VOLUTA_SPMAPS_H_ */
