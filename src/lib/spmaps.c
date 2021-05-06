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
 */
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include "libvoluta.h"


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static voluta_index_t index_to_cpu(uint64_t index)
{
	return le64_to_cpu(index);
}

static uint64_t cpu_to_index(voluta_index_t index)
{
	return cpu_to_le64(index);
}

static bool vtype_ismeta(enum voluta_vtype vtype)
{
	return !vtype_isdata(vtype) && !vtype_isnone(vtype);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ag_index_isnull(voluta_index_t ag_index)
{
	return (ag_index == VOLUTA_AG_INDEX_NULL);
}

static size_t nkb_of(const struct voluta_vaddr *vaddr)
{
	return vtype_nkbs(vaddr->vtype);
}

static size_t kbn_of(const struct voluta_vaddr *vaddr)
{
	const loff_t kb_size = VOLUTA_KB_SIZE;
	const loff_t nkb_in_bk = VOLUTA_NKB_IN_BK;
	const loff_t off = vaddr->off;

	return (size_t)((off / kb_size) % nkb_in_bk);
}

static ssize_t calc_used_bytes(const struct voluta_space_stat *sp_st)
{
	return sp_st->ndata + sp_st->nmeta;
}

static void sum_space_stat(struct voluta_space_stat *res,
                           const struct voluta_space_stat *st1,
                           const struct voluta_space_stat *st2)

{
	res->nmeta = st1->nmeta + st2->nmeta;
	res->ndata = st1->ndata + st2->ndata;
	res->nfiles = st1->nfiles + st2->nfiles;
}

void voluta_accum_space_stat(struct voluta_space_stat *sp_st,
                             const struct voluta_space_stat *other)
{
	sum_space_stat(sp_st, sp_st, other);
}

static size_t safe_sum(size_t cur, ssize_t dif)
{
	size_t val = cur;

	if (dif > 0) {
		val += (size_t)dif;
		voluta_assert_gt(val, cur);
	} else if (dif < 0) {
		val -= (size_t)(-dif);
		voluta_assert_lt(val, cur);
	}
	return val;
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static void agr_spmap_vaddr(const struct voluta_ag_rec *agr,
                            struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&agr->ag_spmap_vaddr, out_vaddr);
}

static void agr_set_spmap_vaddr(struct voluta_ag_rec *agr,
                                const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&agr->ag_spmap_vaddr, vaddr);
}

static uint64_t agr_seed(const struct voluta_ag_rec *agr)
{
	return le64_to_cpu(agr->ag_seed);
}

static void agr_set_seed(struct voluta_ag_rec *agr, uint64_t s)
{
	agr->ag_seed = cpu_to_le64(s);
}

static size_t agr_used_meta(const struct voluta_ag_rec *agr)
{
	return le32_to_cpu(agr->ag_used_meta);
}

static void agr_set_used_meta(struct voluta_ag_rec *agr, size_t used_meta)
{
	agr->ag_used_meta = cpu_to_le32((uint32_t)used_meta);
}

static size_t agr_used_data(const struct voluta_ag_rec *agr)
{
	return le32_to_cpu(agr->ag_used_data);
}

static void agr_set_used_data(struct voluta_ag_rec *agr, size_t used_data)
{
	agr->ag_used_data = cpu_to_le32((uint32_t)used_data);
}

static size_t agr_nfiles(const struct voluta_ag_rec *agr)
{
	return le32_to_cpu(agr->ag_nfiles);
}

static void agr_set_nfiles(struct voluta_ag_rec *agr, size_t nfiles)
{
	voluta_assert_lt(nfiles, UINT32_MAX / 2);

	agr->ag_nfiles = cpu_to_le32((uint32_t)nfiles);
}

static enum voluta_agf agr_flags(const struct voluta_ag_rec *agr)
{
	return le32_to_cpu(agr->ag_flags);
}

static void agr_set_flags(struct voluta_ag_rec *agr, enum voluta_agf f)
{
	agr->ag_flags = cpu_to_le32((uint32_t)f);
}

static bool agr_has_flags(const struct voluta_ag_rec *agr,
                          const enum voluta_agf mask)
{
	return ((agr_flags(agr) & mask) == mask);
}

static void agr_add_flags(struct voluta_ag_rec *agr, enum voluta_agf mask)
{
	agr_set_flags(agr, agr_flags(agr) | mask);
}

static void agr_del_flags(struct voluta_ag_rec *agr, enum voluta_agf mask)
{
	agr_set_flags(agr, agr_flags(agr) & ~mask);
}

static bool agr_is_formatted(const struct voluta_ag_rec *agr)
{
	return agr_has_flags(agr, VOLUTA_AGF_FORMATTED);
}

static void agr_set_formatted(struct voluta_ag_rec *agr)
{
	agr_add_flags(agr, VOLUTA_AGF_FORMATTED);
}

static bool agr_is_fragmented(const struct voluta_ag_rec *agr)
{
	return agr_has_flags(agr, VOLUTA_AGF_FRAGMENTED);
}

static void agr_set_fragmented(struct voluta_ag_rec *agr)
{
	agr_add_flags(agr, VOLUTA_AGF_FRAGMENTED);
}

static void agr_unset_fragmented(struct voluta_ag_rec *agr)
{
	agr_del_flags(agr, VOLUTA_AGF_FRAGMENTED);
}

static bool agr_is_metadata(const struct voluta_ag_rec *agr)
{
	return agr_has_flags(agr, VOLUTA_AGF_METADATA);
}

static bool agr_is_userdata(const struct voluta_ag_rec *agr)
{
	return agr_has_flags(agr, VOLUTA_AGF_USERDATA);
}

static void agr_bind_to_kind(struct voluta_ag_rec *agr,
                             enum voluta_vtype vtype)
{
	if (vtype_ismeta(vtype)) {
		agr_add_flags(agr, VOLUTA_AGF_METADATA);
	} else if (vtype_isdata(vtype)) {
		agr_add_flags(agr, VOLUTA_AGF_USERDATA);
	}
}

static bool agr_kind_fits_vtype(const struct voluta_ag_rec *agr,
                                enum voluta_vtype vtype)
{
	bool ret = true;

	if (agr_is_metadata(agr)) {
		ret = vtype_ismeta(vtype);
	} else if (agr_is_userdata(agr)) {
		ret = vtype_isdata(vtype);
	}
	return ret;
}

static void agr_init(struct voluta_ag_rec *agr)
{
	agr_set_spmap_vaddr(agr, vaddr_none());
	agr_set_used_meta(agr, 0);
	agr_set_used_data(agr, 0);
	agr_set_nfiles(agr, 0);
	agr_set_flags(agr, 0);
	agr_set_seed(agr, voluta_getentropy64());
}

static void agr_initn(struct voluta_ag_rec *agr, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		agr_init(&agr[i]);
	}
}

static void agr_stat(const struct voluta_ag_rec *agr,
                     struct voluta_space_stat *sp_st)
{
	sp_st->nmeta = (ssize_t)agr_used_meta(agr);
	sp_st->ndata = (ssize_t)agr_used_data(agr);
	sp_st->nfiles = (ssize_t)agr_nfiles(agr);
}

static void agr_accum_stats(struct voluta_ag_rec *agr,
                            const struct voluta_space_stat *sp_st)
{
	agr_set_used_data(agr, safe_sum(agr_used_data(agr), sp_st->ndata));
	agr_set_used_meta(agr, safe_sum(agr_used_meta(agr), sp_st->nmeta));
	agr_set_nfiles(agr, safe_sum(agr_nfiles(agr), sp_st->nfiles));
}

static size_t agr_used_space(const struct voluta_ag_rec *agr)
{
	return agr_used_meta(agr) + agr_used_data(agr);
}

static bool agr_has_nfree(const struct voluta_ag_rec *agr, size_t nbytes)
{
	const size_t nbytes_max = VOLUTA_AG_SIZE;
	const size_t nbytes_cur = agr_used_space(agr);

	voluta_assert_le(nbytes_cur, nbytes_max);

	return ((nbytes_cur + nbytes) <= nbytes_max);
}

static bool agr_may_alloc(const struct voluta_ag_rec *agr,
                          enum voluta_vtype vtype)
{
	const size_t bk_size = VOLUTA_BK_SIZE;
	const size_t nbytes = vtype_size(vtype);

	if (!agr_is_formatted(agr)) {
		return false;
	}
	if (!agr_has_nfree(agr, nbytes)) {
		return false;
	}
	if (agr_is_fragmented(agr)) {
		return (nbytes < bk_size);
	}
	return true;
}

static bool agr_may_alloc_vtype(const struct voluta_ag_rec *agr,
                                enum voluta_vtype vtype)
{
	return agr_kind_fits_vtype(agr, vtype) && agr_may_alloc(agr, vtype);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static voluta_index_t hsm_index(const struct voluta_hspace_map *hsm)
{
	return index_to_cpu(hsm->hs_index);
}

static void hsm_set_index(struct voluta_hspace_map *hsm,
                          voluta_index_t hs_index)
{
	hsm->hs_index = cpu_to_index(hs_index);
}

static enum voluta_hsf hsm_flags(const struct voluta_hspace_map *hsm)
{
	return le32_to_cpu(hsm->hs_flags);
}

static void hsm_set_flags(struct voluta_hspace_map *hsm,
                          enum voluta_hsf flags)
{
	hsm->hs_flags = cpu_to_le32((uint32_t)flags);
}

static void hsm_add_flag(struct voluta_hspace_map *hsm, enum voluta_hsf f)
{
	hsm_set_flags(hsm, f | hsm_flags(hsm));
}

static void hsm_add_hasnext(struct voluta_hspace_map *hsm)
{
	hsm_add_flag(hsm, VOLUTA_HSF_HASNEXT);
}

static bool hsm_test_hasnext(const struct voluta_hspace_map *hsm)
{
	const enum voluta_hsf f = VOLUTA_HSF_HASNEXT;

	return ((hsm_flags(hsm) & f) == f);
}

static size_t hsm_nags_span(const struct voluta_hspace_map *hsm)
{
	return le32_to_cpu(hsm->hs_nags_span);
}

static void hsm_set_nags_span(struct voluta_hspace_map *hsm, size_t nags)
{
	voluta_assert_le(nags, ARRAY_SIZE(hsm->hs_agr));

	hsm->hs_nags_span = cpu_to_le32((uint32_t)nags);
}

static size_t hsm_nags_form(const struct voluta_hspace_map *hsm)
{
	return le32_to_cpu(hsm->hs_nags_form);
}

static void hsm_set_nags_form(struct voluta_hspace_map *hsm, size_t nags_form)
{
	voluta_assert_le(nags_form, ARRAY_SIZE(hsm->hs_agr));

	hsm->hs_nags_form = cpu_to_le32((uint32_t)nags_form);
}

static void hsm_inc_nags_form(struct voluta_hspace_map *hsm)
{
	hsm_set_nags_form(hsm, hsm_nags_form(hsm) + 1);
}

static size_t hsm_nused(const struct voluta_hspace_map *hsm)
{
	return le64_to_cpu(hsm->hs_nused);
}

static void hsm_set_nused(struct voluta_hspace_map *hsm, size_t nused)
{
	voluta_assert_le(nused, VOLUTA_HS_SIZE);
	hsm->hs_nused = cpu_to_le64(nused);
}

static voluta_index_t hsm_ag_index_beg(const struct voluta_hspace_map *hsm)
{
	return voluta_ag_index_by_hs(hsm_index(hsm), 0);
}

static voluta_index_t hsm_ag_index_fin(const struct voluta_hspace_map *hsm)
{
	return voluta_ag_index_by_hs(hsm_index(hsm), hsm_nags_form(hsm));
}

static voluta_index_t hsm_ag_index_end(const struct voluta_hspace_map *hsm)
{
	return voluta_ag_index_by_hs(hsm_index(hsm), hsm_nags_span(hsm));
}

static void hsm_setup_keys(struct voluta_hspace_map *hsm)
{
	voluta_kivam_setup_n(hsm->hs_keys.k, ARRAY_SIZE(hsm->hs_keys.k));
}

static void hsm_init(struct voluta_hspace_map *hsm,
                     voluta_index_t hs_index, size_t nags_span)
{
	hsm_set_index(hsm, hs_index);
	hsm_set_flags(hsm, 0);
	hsm_set_nags_span(hsm, nags_span);
	hsm_set_nags_form(hsm, 0);
	hsm_set_nused(hsm, 0);
	hsm_setup_keys(hsm);
	agr_initn(hsm->hs_agr, ARRAY_SIZE(hsm->hs_agr));
}

static struct voluta_ag_rec *
hsm_record_at(const struct voluta_hspace_map *hsm, size_t slot)
{
	const struct voluta_ag_rec *agr = &hsm->hs_agr[slot];

	voluta_assert_lt(slot, ARRAY_SIZE(hsm->hs_agr));
	return unconst(agr);
}

static struct voluta_ag_rec *
hsm_record_of(const struct voluta_hspace_map *hsm, voluta_index_t ag_index)
{
	const size_t slot = voluta_ag_index_to_hs_slot(ag_index);

	return hsm_record_at(hsm, slot);
}

static void hsm_agm_vaddr_of(const struct voluta_hspace_map *hsm,
                             voluta_index_t ag_index,
                             struct voluta_vaddr *out_vaddr)
{
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	agr_spmap_vaddr(agr, out_vaddr);
}

static void hsm_set_agm_vaddr_of(struct voluta_hspace_map *hsm,
                                 voluta_index_t ag_index,
                                 const struct voluta_vaddr *vaddr)
{
	struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	agr_set_spmap_vaddr(agr, vaddr);
}

static voluta_index_t
hsm_resolve_ag_index(const struct voluta_hspace_map *hsm,
                     const struct voluta_ag_rec *agr)
{
	const size_t ag_slot = (size_t)(agr - hsm->hs_agr);
	const voluta_index_t hs_index = hsm_index(hsm);

	voluta_assert(agr >= hsm->hs_agr);
	voluta_assert_lt(ag_slot, ARRAY_SIZE(hsm->hs_agr));

	return voluta_ag_index_by_hs(hs_index, ag_slot);
}

static void hsm_accum_stats_of(struct voluta_hspace_map *hsm,
                               struct voluta_ag_rec *agr,
                               const struct voluta_space_stat *sp_st)
{
	const ssize_t diff = calc_used_bytes(sp_st);

	agr_accum_stats(agr, sp_st);
	hsm_set_nused(hsm, safe_sum(hsm_nused(hsm), diff));

	voluta_assert_le(hsm->hs_nused, VOLUTA_HS_SIZE);
	voluta_assert_le(agr_used_space(agr), VOLUTA_AG_SIZE);
}

static void hsm_accum_stats(struct voluta_hspace_map *hsm,
                            voluta_index_t ag_index,
                            const struct voluta_space_stat *sp_st)
{
	struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	hsm_accum_stats_of(hsm, agr, sp_st);
}

static void hsm_space_stat_of(const struct voluta_hspace_map *hsm,
                              voluta_index_t ag_index,
                              struct voluta_space_stat *sp_st)
{
	const struct voluta_ag_rec *agr;

	agr = hsm_record_of(hsm, ag_index);
	agr_stat(agr, sp_st);
}

static void hsm_space_stat(const struct voluta_hspace_map *hsm,
                           struct voluta_space_stat *sp_st_total)
{
	voluta_index_t ag_index;
	const struct voluta_ag_rec *agr;
	const voluta_index_t ag_index_fin = hsm_ag_index_fin(hsm);
	struct voluta_space_stat sp_st = { .zero = 0 };

	ag_index = hsm_ag_index_beg(hsm);
	while (ag_index < ag_index_fin) {
		agr = hsm_record_of(hsm, ag_index);
		agr_stat(agr, &sp_st);
		voluta_accum_space_stat(sp_st_total, &sp_st);
		ag_index++;
	}
}

static void hsm_set_formatted(struct voluta_hspace_map *hsm,
                              voluta_index_t ag_index)
{
	struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	agr_set_formatted(agr);
}

static bool hsm_is_formatted(const struct voluta_hspace_map *hsm,
                             voluta_index_t ag_index)
{
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	return agr_is_formatted(agr);
}

static bool hsm_is_fragmented(struct voluta_hspace_map *hsm,
                              voluta_index_t ag_index)
{
	return agr_is_fragmented(hsm_record_of(hsm, ag_index));
}

static bool hsm_may_alloc(const struct voluta_hspace_map *hsm, size_t nbytes)
{
	const size_t nbytes_max = VOLUTA_HS_SIZE;
	const size_t nbytes_cur = hsm_nused(hsm);

	voluta_assert_le(nbytes_cur, nbytes_max);

	return ((nbytes_cur + nbytes) <= nbytes_max);
}

static void hsm_mark_fragmented(struct voluta_hspace_map *hsm,
                                voluta_index_t ag_index)
{
	agr_set_fragmented(hsm_record_of(hsm, ag_index));
}

static void hsm_clear_fragmented(struct voluta_hspace_map *hsm,
                                 voluta_index_t ag_index)
{
	agr_unset_fragmented(hsm_record_of(hsm, ag_index));
}

static void hsm_bind_to_kind(struct voluta_hspace_map *hsm,
                             voluta_index_t ag_index, enum voluta_vtype vtype)
{
	agr_bind_to_kind(hsm_record_of(hsm, ag_index), vtype);
}

static size_t hsm_ag_index_tip(const struct voluta_hspace_map *hsm)
{
	const size_t ag_size = VOLUTA_AG_SIZE;
	const size_t nused = hsm_nused(hsm);
	const voluta_index_t ag_index_beg = hsm_ag_index_beg(hsm);

	return ag_index_beg + div_round_up(nused, ag_size);
}

static size_t
hsm_used_space_of(const struct voluta_hspace_map *hsm, voluta_index_t ag_index)
{
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	return agr_used_space(agr);
}

static const struct voluta_kivam *
hsm_kivam_of(const struct voluta_hspace_map *hsm, voluta_index_t ag_index)
{
	const size_t k_slot = ag_index % ARRAY_SIZE(hsm->hs_keys.k);

	return &hsm->hs_keys.k[k_slot];
}

static uint64_t
hsm_seed_of(const struct voluta_hspace_map *hsm, voluta_index_t ag_index)
{
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	return agr_seed(agr);
}

static void hsm_mark_itroot_at(struct voluta_hspace_map *hsm,
                               voluta_index_t ag_index)
{
	struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	agr_add_flags(agr, VOLUTA_AGF_ITABLEROOT);
}

static size_t hsm_find_itroot_ag(const struct voluta_hspace_map *hsm)
{
	voluta_index_t ag_index;
	const struct voluta_ag_rec *agr = NULL;
	const size_t nags = hsm_nags_span(hsm);

	ag_index = VOLUTA_AG_INDEX_NULL;
	for (size_t slot = 0; slot < nags; ++slot) {
		agr = hsm_record_at(hsm, slot);
		if (agr_has_flags(agr, VOLUTA_AGF_ITABLEROOT)) {
			ag_index = hsm_resolve_ag_index(hsm, agr);
			break;
		}
	}
	return ag_index;
}

static voluta_index_t
hsm_find_avail(const struct voluta_hspace_map *hsm,
               voluta_index_t ag_index_from,
               voluta_index_t ag_index_last,
               enum voluta_vtype vtype)
{
	size_t nags_iter;
	voluta_index_t ag_index;
	const struct voluta_ag_rec *agr = NULL;
	const size_t nags_span = hsm_nags_span(hsm);

	ag_index = ag_index_from;
	nags_iter = min(nags_span, ag_index_last - ag_index_from);
	while ((ag_index < ag_index_last) && nags_iter--) {
		agr = hsm_record_of(hsm, ag_index);
		if (!agr_is_formatted(agr)) {
			break;
		}
		if (agr_may_alloc_vtype(agr, vtype)) {
			return ag_index;
		}
		ag_index++;
	}
	return VOLUTA_AG_INDEX_NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t mask_of(size_t kbn, size_t nkb)
{
	uint64_t mask;
	const size_t nkb_in_bk = VOLUTA_NKB_IN_BK;

	voluta_assert_lt(kbn, nkb_in_bk);
	voluta_assert_le(nkb, nkb_in_bk);
	voluta_assert_le(kbn + nkb, nkb_in_bk);

	mask = (nkb < nkb_in_bk) ? (((1UL << nkb) - 1UL) << kbn) : ~0UL;
	voluta_assert_ne(mask, 0);

	return mask;
}

static enum voluta_vtype bkr_vtype(const struct voluta_bk_rec *bkr)
{
	return (enum voluta_vtype)(bkr->bk_vtype);
}

static void bkr_set_vtype(struct voluta_bk_rec *bkr, enum voluta_vtype vtype)
{
	bkr->bk_vtype = (uint8_t)vtype;
}

static bool bkr_has_vtype_or_none(const struct voluta_bk_rec *bkr,
                                  enum voluta_vtype vtype)
{
	const enum voluta_vtype vt = bkr_vtype(bkr);

	return vtype_isnone(vt) || vtype_isequal(vt, vtype);
}

static uint64_t bkr_seed(const struct voluta_bk_rec *bkr)
{
	return le64_to_cpu(bkr->bk_seed);
}

static void bkr_set_seed(struct voluta_bk_rec *bkr, uint64_t s)
{
	bkr->bk_seed = cpu_to_le64(s);
}

static void bkr_set_flags(struct voluta_bk_rec *bkr, uint32_t f)
{
	bkr->bk_flags = cpu_to_le32(f);
}

static size_t bkr_refcnt(const struct voluta_bk_rec *bkr)
{
	return le64_to_cpu(bkr->bk_refcnt);
}

static void bkr_set_refcnt(struct voluta_bk_rec *bkr, size_t refcnt)
{
	voluta_assert_le(refcnt, VOLUTA_NKB_IN_BK);

	bkr->bk_refcnt = cpu_to_le64(refcnt);
}

static void bkr_inc_refcnt(struct voluta_bk_rec *bkr, size_t n)
{
	bkr_set_refcnt(bkr, bkr_refcnt(bkr) + n);
}

static void bkr_dec_refcnt(struct voluta_bk_rec *bkr, size_t n)
{
	voluta_assert_ge(bkr_refcnt(bkr), n);

	bkr_set_refcnt(bkr, bkr_refcnt(bkr) - n);
}

static uint64_t bkr_allocated(const struct voluta_bk_rec *bkr)
{
	return le64_to_cpu(bkr->bk_allocated);
}

static void bkr_set_allocated(struct voluta_bk_rec *bkr, uint64_t allocated)
{
	bkr->bk_allocated = cpu_to_le64(allocated);
}

static bool bkr_test_allocated_at(const struct voluta_bk_rec *bkr,
                                  size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);

	return ((bkr_allocated(bkr) & mask) == mask);
}

static bool bkr_test_allocated_bk(const struct voluta_bk_rec *bkr)
{
	return bkr_test_allocated_at(bkr, 0, VOLUTA_NKB_IN_BK);
}

static void bkr_set_allocated_at(struct voluta_bk_rec *bkr,
                                 size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t allocated = bkr_allocated(bkr);

	voluta_assert_eq(allocated & mask, 0);
	bkr_set_allocated(bkr, allocated | mask);
	voluta_assert_ne(bkr_allocated(bkr), 0);
}

static void bkr_clear_allocated_at(struct voluta_bk_rec *bkr,
                                   size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t allocated = bkr_allocated(bkr);

	voluta_assert_eq(allocated & mask, mask);
	bkr_set_allocated(bkr, allocated & ~mask);
}

static size_t bkr_usecnt(const struct voluta_bk_rec *bkr)
{
	const uint64_t allocated = bkr_allocated(bkr);

	return voluta_popcount64(allocated);
}

static size_t bkr_freecnt(const struct voluta_bk_rec *bkr)
{
	return VOLUTA_NKB_IN_BK - bkr_usecnt(bkr);
}

static bool bkr_isfull(const struct voluta_bk_rec *bkr)
{
	return bkr_test_allocated_bk(bkr);
}

static bool bkr_isunused(const struct voluta_bk_rec *bkr)
{
	return (bkr_usecnt(bkr) == 0);
}

static uint64_t bkr_unwritten(const struct voluta_bk_rec *bkr)
{
	return le64_to_cpu(bkr->bk_unwritten);
}

static void bkr_set_unwritten(struct voluta_bk_rec *bkr, uint64_t unwritten)
{
	bkr->bk_unwritten = cpu_to_le64(unwritten);
}

static bool bkr_test_unwritten_at(const struct voluta_bk_rec *bkr,
                                  size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t unwritten = bkr_unwritten(bkr);

	voluta_assert(((unwritten & mask) == mask) ||
	              ((unwritten & mask) == 0));

	return (unwritten & mask) == mask;
}

static void bkr_set_unwritten_at(struct voluta_bk_rec *bkr,
                                 size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t unwritten = bkr_unwritten(bkr);

	voluta_assert(!bkr_test_unwritten_at(bkr, kbn, nkb));

	bkr_set_unwritten(bkr, unwritten | mask);
}

static void bkr_clear_unwritten_at(struct voluta_bk_rec *bkr,
                                   size_t kbn, size_t nkb)
{
	const uint64_t mask = mask_of(kbn, nkb);
	const uint64_t unwritten = bkr_unwritten(bkr);

	voluta_assert(bkr_test_unwritten_at(bkr, kbn, nkb));

	bkr_set_unwritten(bkr, unwritten & ~mask);
}

static void bkr_init(struct voluta_bk_rec *bkr)
{
	bkr_set_vtype(bkr, VOLUTA_VTYPE_NONE);
	bkr_set_seed(bkr, voluta_getentropy64());
	bkr_set_refcnt(bkr, 0);
	bkr_set_flags(bkr, 0);
	bkr_set_allocated(bkr, 0);
	bkr_set_unwritten(bkr, 0);
	bkr->bk_flags = 0;
}

static void bkr_init_arr(struct voluta_bk_rec *arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		bkr_init(&arr[i]);
	}
}

static void bkr_renew(struct voluta_bk_rec *bkr)
{
	bkr_init(bkr);
}

static bool bkr_may_alloc(const struct voluta_bk_rec *bkr,
                          enum voluta_vtype vtype, size_t nkb)
{
	bool ret = false;

	if (!bkr_isfull(bkr) && (bkr_freecnt(bkr) >= nkb)) {
		ret = bkr_has_vtype_or_none(bkr, vtype);
	}
	return ret;
}

static int bkr_find_free(const struct voluta_bk_rec *bkr,
                         size_t nkb, size_t *out_kbn)
{
	uint64_t mask;
	const size_t nkb_in_bk = VOLUTA_NKB_IN_BK;
	const uint64_t allocated = bkr_allocated(bkr);

	for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
		mask = mask_of(kbn, nkb);
		if ((allocated & mask) == 0) {
			*out_kbn = kbn;
			return 0;
		}
	}
	return -ENOSPC;
}

static void bkr_alloc_info(const struct voluta_bk_rec *bkr,
                           struct voluta_balloc_info *bai)
{
	size_t nkb;
	uint64_t mask;
	const uint64_t allocated = bkr_allocated(bkr);
	const size_t nkb_in_bk = VOLUTA_NKB_IN_BK;

	bai->cnt = 0;
	bai->vtype = bkr_vtype(bkr);
	if (!vtype_isnone(bai->vtype)) {
		nkb = vtype_nkbs(bai->vtype);
		for (size_t kbn = 0; (kbn + nkb) <= nkb_in_bk; kbn += nkb) {
			mask = mask_of(kbn, nkb);
			if ((allocated & mask) == mask) {
				bai->kbn[bai->cnt++] = kbn;
			}
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static voluta_index_t agm_index(const struct voluta_agroup_map *agm)
{
	return index_to_cpu(agm->ag_index);
}

static void agm_set_index(struct voluta_agroup_map *agm,
                          voluta_index_t ag_index)
{
	agm->ag_index = cpu_to_index(ag_index);
}

static void agm_it_root(const struct voluta_agroup_map *agm,
                        struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&agm->ag_it_root, out_vaddr);
}

static void agm_set_it_root(struct voluta_agroup_map *agm,
                            const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&agm->ag_it_root, vaddr);
}

static void agm_setup_keys(struct voluta_agroup_map *agm)
{
	voluta_kivam_setup_n(agm->ag_keys.k, ARRAY_SIZE(agm->ag_keys.k));
}

static void agm_init(struct voluta_agroup_map *agm, voluta_index_t ag_index)
{
	STATICASSERT_EQ(sizeof(agm->ag_bkr[0]), 56);
	STATICASSERT_EQ(sizeof(*agm), VOLUTA_BK_SIZE);

	agm_set_index(agm, ag_index);
	agm_set_it_root(agm, vaddr_none());
	agm_setup_keys(agm);
	bkr_init_arr(agm->ag_bkr, ARRAY_SIZE(agm->ag_bkr));
}

static struct voluta_bk_rec *
agm_bkr_at(const struct voluta_agroup_map *agm, size_t slot)
{
	const struct voluta_bk_rec *bkr = &(agm->ag_bkr[slot]);

	voluta_assert_lt(slot, ARRAY_SIZE(agm->ag_bkr));
	return unconst(bkr);
}

static void agm_balloc_info_at(const struct voluta_agroup_map *agm,
                               size_t slot, struct voluta_balloc_info *bai)
{
	const voluta_index_t ag_index = agm_index(agm);
	const struct voluta_bk_rec *bkr = agm_bkr_at(agm, slot);

	bkr_alloc_info(bkr, bai);
	bai->bn = slot;
	bai->lba = voluta_lba_by_ag(ag_index, bai->bn);
}

static size_t agm_nslots(const struct voluta_agroup_map *agm)
{
	return ARRAY_SIZE(agm->ag_bkr);
}

static size_t agm_lba_slot(const struct voluta_agroup_map *agm,
                           voluta_lba_t lba)
{
	return (size_t)lba % agm_nslots(agm);
}

static struct voluta_bk_rec *
agm_bkr_by_lba(const struct voluta_agroup_map *agm, voluta_lba_t lba)
{
	return agm_bkr_at(agm, agm_lba_slot(agm, lba));
}

static struct voluta_bk_rec *
agm_bkr_by_vaddr(const struct voluta_agroup_map *agm,
                 const struct voluta_vaddr *vaddr)
{
	return agm_bkr_by_lba(agm, vaddr->lba);
}

static enum voluta_vtype agm_vtype_at(const struct voluta_agroup_map *agm,
                                      const struct voluta_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	const struct voluta_bk_rec *bkr = agm_bkr_by_lba(agm, vaddr->lba);

	return bkr_test_allocated_at(bkr, kbn, nkb) ?
	       bkr_vtype(bkr) : VOLUTA_VTYPE_NONE;
}

static bool agm_test_unwritten_at(const struct voluta_agroup_map *agm,
                                  const struct voluta_vaddr *vaddr)
{
	const struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	return bkr_test_unwritten_at(bkr, kbn_of(vaddr), nkb_of(vaddr));
}

static void agm_set_unwritten_at(struct voluta_agroup_map *agm,
                                 const struct voluta_vaddr *vaddr)
{
	struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	bkr_set_unwritten_at(bkr, kbn_of(vaddr), nkb_of(vaddr));
}

static void agm_clear_unwritten_at(struct voluta_agroup_map *agm,
                                   const struct voluta_vaddr *vaddr)
{
	struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	bkr_clear_unwritten_at(bkr, kbn_of(vaddr), nkb_of(vaddr));
}

static size_t agm_refcnt_at(const struct voluta_agroup_map *agm,
                            const struct voluta_vaddr *vaddr)
{
	const struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	return bkr_refcnt(bkr);
}

static bool agm_last_refcnt_at(const struct voluta_agroup_map *agm,
                               const struct voluta_vaddr *vaddr)
{
	const size_t nkb = nkb_of(vaddr);

	return (nkb == agm_refcnt_at(agm, vaddr));
}

static void agm_set_allocated_at(struct voluta_agroup_map *agm,
                                 const struct voluta_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	bkr_inc_refcnt(bkr, nkb);
	bkr_set_allocated_at(bkr, kbn, nkb);
	bkr_set_vtype(bkr, vaddr->vtype);
}

static void agm_clear_allocated_at(struct voluta_agroup_map *agm,
                                   const struct voluta_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	const size_t nkb_in_bk = VOLUTA_NKB_IN_BK;
	struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	bkr_dec_refcnt(bkr, nkb);
	if (!bkr_refcnt(bkr) || (nkb < nkb_in_bk)) {
		bkr_clear_allocated_at(bkr, kbn, nkb);
	}
	if (!bkr_allocated(bkr)) {
		voluta_assert_eq(bkr_refcnt(bkr), 0);
		bkr_set_vtype(bkr, VOLUTA_VTYPE_NONE);
	}
}

static void agm_renew_if_unused(struct voluta_agroup_map *agm,
                                const struct voluta_vaddr *vaddr)
{
	struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	if (bkr_isunused(bkr)) {
		bkr_renew(bkr);
	}
}

static int agm_find_nfree_at(const struct voluta_agroup_map *agm,
                             enum voluta_vtype vtype, size_t bn,
                             size_t *out_kbn)
{
	int err = -ENOSPC;
	const size_t nkb = vtype_nkbs(vtype);
	const struct voluta_bk_rec *bkr = agm_bkr_at(agm, bn);

	if (bkr_may_alloc(bkr, vtype, nkb)) {
		err = bkr_find_free(bkr, nkb, out_kbn);
	}
	return err;
}

static int agm_find_free(const struct voluta_agroup_map *agm,
                         enum voluta_vtype vtype, size_t start_bn,
                         size_t *out_bn, size_t *out_kbn)
{
	int err;
	const size_t nbkrs = ARRAY_SIZE(agm->ag_bkr);

	for (size_t i = 0; i < nbkrs; ++i) {
		*out_bn = (start_bn + i) % nbkrs;
		err = agm_find_nfree_at(agm, vtype, *out_bn, out_kbn);
		if (!err) {
			return 0;
		}
	}
	return -ENOSPC;
}

static int agm_find_free_space(const struct voluta_agroup_map *agm,
                               enum voluta_vtype vtype, size_t start_bn,
                               struct voluta_vaddr *out_vaddr)
{
	int err;
	size_t bn;
	size_t kbn;
	voluta_index_t ag_index;

	err = agm_find_free(agm, vtype, start_bn, &bn, &kbn);
	if (err) {
		return err;
	}
	ag_index = agm_index(agm);
	vaddr_by_ag(out_vaddr, vtype, ag_index, bn, kbn);
	return 0;
}

static void agm_calc_space_stat(const struct voluta_agroup_map *agm,
                                struct voluta_space_stat *sp_st)
{
	ssize_t usecnt;
	enum voluta_vtype vtype;
	const struct voluta_bk_rec *bkr;
	const size_t nslots = agm_nslots(agm);
	const ssize_t kb_size = (ssize_t)(VOLUTA_KB_SIZE);

	voluta_memzero(sp_st, sizeof(*sp_st));
	for (size_t slot = 0; slot < nslots; ++slot) {
		bkr = agm_bkr_at(agm, slot);

		vtype = bkr_vtype(bkr);
		if (vtype_isnone(vtype)) {
			continue;
		}
		usecnt = (ssize_t)bkr_usecnt(bkr);
		voluta_assert_gt(usecnt, 0);
		if (vtype_isdata(vtype)) {
			sp_st->ndata += (usecnt * kb_size);
		} else {
			sp_st->nmeta += (usecnt * kb_size);
			if (vtype_isinode(vtype)) {
				sp_st->nfiles += usecnt;
			}
		}
	}
}

static const struct voluta_kivam *
agm_kivam_of(const struct voluta_agroup_map *agm, voluta_lba_t lba)
{
	const size_t k_slot = (size_t)lba % ARRAY_SIZE(agm->ag_keys.k);

	return &agm->ag_keys.k[k_slot];
}

static uint64_t agm_seed_of(const struct voluta_agroup_map *agm,
                            voluta_lba_t lba)
{
	const struct voluta_bk_rec *bkr = agm_bkr_by_lba(agm, lba);

	return bkr_seed(bkr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* spmaps */

static struct voluta_hspace_map *
hspace_map_of(const struct voluta_vnode_info *hsm_vi)
{
	voluta_assert_not_null(hsm_vi);
	voluta_assert_eq(hsm_vi->vaddr.vtype, VOLUTA_VTYPE_HSMAP);

	return hsm_vi->vu.hsm;
}

void voluta_setup_hsmap(struct voluta_vnode_info *hsm_vi,
                        voluta_index_t hs_index, size_t nags_span)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_init(hsm, hs_index, nags_span);
}

voluta_index_t voluta_hs_index_of(const struct voluta_vnode_info *hsm_vi)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	return hsm_index(hsm);
}

static size_t
nused_bytes_at(const struct voluta_vnode_info *hsm_vi, voluta_index_t ag_index)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	return hsm_used_space_of(hsm, ag_index);
}

static size_t
nused_bks_at(const struct voluta_vnode_info *hsm_vi, size_t ag_index)
{
	const size_t nused_bytes = nused_bytes_at(hsm_vi, ag_index);

	return nused_bytes / VOLUTA_BK_SIZE;
}

int voluta_search_avail_ag(const struct voluta_vnode_info *hsm_vi,
                           voluta_index_t ag_index_first,
                           voluta_index_t ag_index_last,
                           enum voluta_vtype vtype,
                           voluta_index_t *out_ag_index)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	*out_ag_index =
	        hsm_find_avail(hsm, ag_index_first, ag_index_last, vtype);

	return ag_index_isnull(*out_ag_index) ? -ENOSPC : 0;
}


int voluta_find_itroot_ag(const struct voluta_vnode_info *hsm_vi,
                          voluta_index_t *out_ag_index)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	*out_ag_index = hsm_find_itroot_ag(hsm);
	return ag_index_isnull(*out_ag_index) ? -ENOENT : 0;
}

void voluta_mark_itroot_at(struct voluta_vnode_info *hsm_vi,
                           voluta_index_t ag_index)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_mark_itroot_at(hsm, ag_index);
	vi_dirtify(hsm_vi);
}

void voluta_mark_with_next(struct voluta_vnode_info *hsm_vi)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	if (!hsm_test_hasnext(hsm)) {
		hsm_add_hasnext(hsm);
		vi_dirtify(hsm_vi);
	}
}

bool voluta_has_next_hspace(const struct voluta_vnode_info *hsm_vi)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	return hsm_test_hasnext(hsm);
}

void voluta_update_space(struct voluta_vnode_info *hsm_vi,
                         voluta_index_t ag_index,
                         const struct voluta_space_stat *sp_st)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_accum_stats(hsm, ag_index, sp_st);
	vi_dirtify(hsm_vi);
}

void voluta_space_stat_at(const struct voluta_vnode_info *hsm_vi,
                          voluta_index_t ag_index,
                          struct voluta_space_stat *sp_st)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_space_stat_of(hsm, ag_index, sp_st);
}

void voluta_space_stat_of(const struct voluta_vnode_info *hsm_vi,
                          struct voluta_space_stat *sp_st)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_space_stat(hsm, sp_st);
}

void voluta_set_formatted_ag(struct voluta_vnode_info *hsm_vi,
                             const struct voluta_vaddr *agm_vaddr,
                             voluta_index_t ag_index)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	voluta_assert(!hsm_is_formatted(hsm, ag_index));

	hsm_set_agm_vaddr_of(hsm, ag_index, agm_vaddr);
	hsm_set_formatted(hsm, ag_index);
	hsm_inc_nags_form(hsm);
	vi_dirtify(hsm_vi);
}

bool voluta_has_formatted_ag(const struct voluta_vnode_info *hsm_vi,
                             voluta_index_t ag_index)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	return hsm_is_formatted(hsm, ag_index);
}

void voluta_ag_range_of(const struct voluta_vnode_info *hsm_vi,
                        struct voluta_ag_range *ag_range)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	ag_range->beg = hsm_ag_index_beg(hsm);
	ag_range->tip = hsm_ag_index_tip(hsm);
	ag_range->fin = hsm_ag_index_fin(hsm);
	ag_range->end = hsm_ag_index_end(hsm);
}

void voluta_mark_fragmented(struct voluta_vnode_info *hsm_vi,
                            voluta_index_t ag_index)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_mark_fragmented(hsm, ag_index);
	vi_dirtify(hsm_vi);
}

void voluta_clear_fragmented_at(struct voluta_vnode_info *hsm_vi,
                                const struct voluta_vaddr *vaddr)
{
	const voluta_index_t ag_index = vaddr->ag_index;
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	if (hsm_is_fragmented(hsm, ag_index) && (nkb_of(vaddr) > 1)) {
		hsm_clear_fragmented(hsm, ag_index);
		vi_dirtify(hsm_vi);
	}
}

void voluta_bind_to_kindof(struct voluta_vnode_info *hsm_vi,
                           const struct voluta_vaddr *vaddr)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_bind_to_kind(hsm, vaddr->ag_index, vaddr->vtype);
	vi_dirtify(hsm_vi);
}

int voluta_check_cap_alloc(const struct voluta_vnode_info *hsm_vi,
                           const enum voluta_vtype vtype)
{
	const size_t nbytes = vtype_size(vtype);
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	return hsm_may_alloc(hsm, nbytes) ? 0 : -ENOSPC;
}

void voluta_kivam_of_agmap(const struct voluta_vnode_info *hsm_vi,
                           voluta_index_t ag_index,
                           struct voluta_kivam *out_kivam)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	voluta_kivam_copyto(hsm_kivam_of(hsm, ag_index), out_kivam);
	voluta_kivam_xor_iv(out_kivam, hsm_seed_of(hsm, ag_index));
}

void voluta_resolve_agmap_vaddr(const struct voluta_vnode_info *hsm_vi,
                                voluta_index_t ag_index,
                                struct voluta_vaddr *out_vaddr)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsm_vi);

	hsm_agm_vaddr_of(hsm, ag_index, out_vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_agroup_map *
agroup_map_of(const struct voluta_vnode_info *agm_vi)
{
	voluta_assert_not_null(agm_vi);
	voluta_assert_eq(agm_vi->vaddr.vtype, VOLUTA_VTYPE_AGMAP);

	return agm_vi->vu.agm;
}

void voluta_setup_agmap(struct voluta_vnode_info *agm_vi,
                        voluta_index_t ag_index)
{
	struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	agm_init(agm, ag_index);
}

size_t voluta_ag_index_of(const struct voluta_vnode_info *agm_vi)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	return agm_index(agm);
}

static voluta_index_t ag_index_of(const struct voluta_vnode_info *agm_vi)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	return agm_index(agm);
}

static bool vtype_isdatabk(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_DATABK);
}

static size_t start_bn_of(const struct voluta_vnode_info *hsm_vi,
                          const struct voluta_vnode_info *agm_vi,
                          enum voluta_vtype vtype)
{
	size_t bn;
	const size_t nbk_in_ag = VOLUTA_NBK_IN_AG;
	const voluta_index_t ag_index = ag_index_of(agm_vi);

	/* Heuristic for mostly append pattern */
	bn = nused_bks_at(hsm_vi, ag_index);

	/* In case of full data-block align to higher */
	if (bn && vtype_isdatabk(vtype)) {
		bn = voluta_min(bn + 1, nbk_in_ag - 1);
	}
	return bn;
}

int voluta_search_free_space(const struct voluta_vnode_info *hsm_vi,
                             const struct voluta_vnode_info *agm_vi,
                             enum voluta_vtype vtype,
                             struct voluta_vaddr *out_vaddr)
{
	const size_t start_bn = start_bn_of(hsm_vi, agm_vi, vtype);
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	voluta_assert_le(start_bn, VOLUTA_NBK_IN_AG);
	voluta_assert(hsm_is_formatted(hspace_map_of(hsm_vi), agm_index(agm)));

	return agm_find_free_space(agm, vtype, start_bn, out_vaddr);
}

void voluta_mark_allocated_space(struct voluta_vnode_info *agm_vi,
                                 const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	agm_set_allocated_at(agm, vaddr);
	if (vaddr_isdata(vaddr)) {
		agm_set_unwritten_at(agm, vaddr);
	}
	vi_dirtify(agm_vi);
}

void voluta_clear_allocated_space(struct voluta_vnode_info *agm_vi,
                                  const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	voluta_assert_eq(agm_index(agm), vaddr->ag_index);

	agm_clear_allocated_at(agm, vaddr);
	agm_renew_if_unused(agm, vaddr);
	vi_dirtify(agm_vi);
}

size_t voluta_block_refcnt_at(const struct voluta_vnode_info *agm_vi,
                              const struct voluta_vaddr *vaddr)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	return agm_refcnt_at(agm, vaddr);
}

bool voluta_has_lone_refcnt(const struct voluta_vnode_info *agm_vi,
                            const struct voluta_vaddr *vaddr)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	return agm_last_refcnt_at(agm, vaddr);
}

void voluta_calc_space_stat_of(const struct voluta_vnode_info *agm_vi,
                               struct voluta_space_stat *out_sp_st)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	agm_calc_space_stat(agm, out_sp_st);
}

bool voluta_is_allocated_with(const struct voluta_vnode_info *agm_vi,
                              const struct voluta_vaddr *vaddr)
{
	enum voluta_vtype vtype;
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	vtype = agm_vtype_at(agm, vaddr);
	return vtype_isequal(vtype, vaddr->vtype);
}

bool voluta_has_unwritten_at(const struct voluta_vnode_info *agm_vi,
                             const struct voluta_vaddr *vaddr)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	return agm_test_unwritten_at(agm, vaddr);
}

void voluta_clear_unwritten_at(struct voluta_vnode_info *agm_vi,
                               const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	if (agm_test_unwritten_at(agm, vaddr)) {
		agm_clear_unwritten_at(agm, vaddr);
		vi_dirtify(agm_vi);
	}
}

void voluta_mark_unwritten_at(struct voluta_vnode_info *agm_vi,
                              const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	if (!agm_test_unwritten_at(agm, vaddr)) {
		agm_set_unwritten_at(agm, vaddr);
		vi_dirtify(agm_vi);
	}
}

void voluta_assign_itroot(struct voluta_vnode_info *hsm_vi,
                          struct voluta_vnode_info *agm_vi,
                          const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	voluta_assert_eq(agm_index(agm), vaddr->ag_index);

	agm_set_it_root(agm, vaddr);
	vi_dirtify(agm_vi);

	voluta_mark_itroot_at(hsm_vi, agm_index(agm));
}

void voluta_parse_itroot(const struct voluta_vnode_info *agm_vi,
                         struct voluta_vaddr *out_vaddr)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	agm_it_root(agm, out_vaddr);
}


void voluta_kivam_of_vnode_at(const struct voluta_vnode_info *agm_vi,
                              const struct voluta_vaddr *vaddr,
                              struct voluta_kivam *out_kivam)
{
	uint64_t seed;
	const voluta_lba_t lba = vaddr->lba;
	const struct voluta_kivam *kivam = NULL;
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	kivam = agm_kivam_of(agm, lba);
	voluta_kivam_copyto(kivam, out_kivam);

	seed = agm_seed_of(agm, lba);
	voluta_kivam_xor_iv(out_kivam, seed);
}

void voluta_balloc_info_at(const struct voluta_vnode_info *agm_vi,
                           size_t slot, struct voluta_balloc_info *bai)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agm_vi);

	agm_balloc_info_at(agm, slot, bai);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_vtype(enum voluta_vtype vtype)
{
	switch (vtype) {
	case VOLUTA_VTYPE_NONE:
	case VOLUTA_VTYPE_HSMAP:
	case VOLUTA_VTYPE_AGMAP:
	case VOLUTA_VTYPE_ITNODE:
	case VOLUTA_VTYPE_INODE:
	case VOLUTA_VTYPE_XANODE:
	case VOLUTA_VTYPE_HTNODE:
	case VOLUTA_VTYPE_RTNODE:
	case VOLUTA_VTYPE_SYMVAL:
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		return 0;
	default:
		break;
	}
	return -EFSCORRUPTED;
}

static int verify_bkr(const struct voluta_bk_rec *bkr)
{
	int err;

	err = verify_vtype(bkr_vtype(bkr));
	if (err) {
		return err;
	}
	return 0;
}

static int verify_agmap(const struct voluta_agroup_map *agm)
{
	int err;
	const struct voluta_bk_rec *bkr;

	for (size_t i = 0; i < ARRAY_SIZE(agm->ag_bkr); ++i) {
		bkr = agm_bkr_at(agm, i);
		err = verify_bkr(bkr);
		if (err) {
			return err;
		}
	}
	return 0;
}

int voluta_verify_agroup_map(const struct voluta_agroup_map *agm)
{
	int err;

	if (agm_index(agm) > 0xFFFFFFFUL) { /* XXX */
		return -EFSCORRUPTED;
	}
	err = verify_agmap(agm);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_verify_hspace_map(const struct voluta_hspace_map *hsm)
{
	const size_t hs_size = VOLUTA_HS_SIZE;
	const size_t vol_size_max = VOLUTA_VOLUME_SIZE_MAX;
	const voluta_index_t hs_index = hsm_index(hsm);

	if ((hs_index * hs_size) >= vol_size_max) {
		return -EFSCORRUPTED;
	}
	return 0;
}

