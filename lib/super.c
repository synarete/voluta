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
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include "libvoluta.h"


/* non-valid ("NIL") allocation-group index */
#define VOLUTA_AG_INDEX_NULL            (0UL - 1)


struct voluta_ag_range {
	size_t beg; /* start ag-index */
	size_t tip; /* heuristic of current tip ag-index */
	size_t fin; /* one past last ag-index of current span */
	size_t end; /* end of hyper-range */
	/* beg <= tip <= fin <= end */
};

struct voluta_kbn_vtype {
	size_t kbn;
	enum voluta_vtype vtype;
};

struct voluta_balloc_info {
	loff_t lba;
	size_t bn;
	size_t kbn[VOLUTA_NKB_IN_BK];
	size_t cnt;
	enum voluta_vtype vtype;
};

struct voluta_super_ctx {
	struct voluta_sb_info    *sbi;
	struct voluta_bk_info    *bki;
	struct voluta_vnode_info *hsm_vi;
	struct voluta_vnode_info *agm_vi;
	struct voluta_inode_info *pii;
	struct voluta_inode_info *ii;
	struct voluta_vnode_info *vi;
};


static int stage_hsmap(struct voluta_sb_info *sbi, size_t hs_index,
		       struct voluta_vnode_info **out_vi);
static int stage_agmap(struct voluta_sb_info *sbi, size_t ag_index,
		       struct voluta_vnode_info **out_vi);
static int format_spmaps_at(struct voluta_sb_info *sbi,
			    size_t hs_index, size_t nags);
static int fetch_parents_of(struct voluta_super_ctx *s_ctx,
			    const struct voluta_vaddr *vaddr);
static int format_next_agmaps(struct voluta_sb_info *sbi,
			      struct voluta_vnode_info *hsm_vi,
			      size_t nags_want, size_t *out_nags_fmt);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_cache *cache_of(const struct voluta_super_ctx *s_ctx)
{
	return s_ctx->sbi->sb_cache;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ag_index_isnull(size_t ag_index)
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

static void agr_update_stats(struct voluta_ag_rec *agr,
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t hsm_index(const struct voluta_hspace_map *hsm)
{
	return le32_to_cpu(hsm->hs_index);
}

static void hsm_set_index(struct voluta_hspace_map *hsm, size_t hs_index)
{
	hsm->hs_index = cpu_to_le32((uint32_t)hs_index);
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

static size_t hsm_ag_index_beg(const struct voluta_hspace_map *hsm)
{
	return voluta_ag_index_by_hs(hsm_index(hsm), 0);
}

static size_t hsm_ag_index_fin(const struct voluta_hspace_map *hsm)
{
	return hsm_ag_index_beg(hsm) + hsm_nags_form(hsm);
}

static size_t hsm_ag_index_end(const struct voluta_hspace_map *hsm)
{
	return hsm_ag_index_beg(hsm) + hsm_nags_span(hsm);
}

static void hsm_setup_keys(struct voluta_hspace_map *hsm)
{
	voluta_kivam_setup_n(hsm->hs_keys.k, ARRAY_SIZE(hsm->hs_keys.k));
}

static void hsm_init(struct voluta_hspace_map *hsm,
		     size_t hs_index, size_t nags_span)
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
hsm_record_of(const struct voluta_hspace_map *hsm, size_t ag_index)
{
	const size_t slot = voluta_ag_index_to_hs_slot(ag_index);

	return hsm_record_at(hsm, slot);
}

static size_t hsm_resolve_ag_index(const struct voluta_hspace_map *hsm,
				   const struct voluta_ag_rec *agr)
{
	const size_t ag_slot = (size_t)(agr - hsm->hs_agr);
	const size_t hs_index = hsm_index(hsm);

	voluta_assert(agr >= hsm->hs_agr);
	voluta_assert_lt(ag_slot, ARRAY_SIZE(hsm->hs_agr));

	return voluta_ag_index_by_hs(hs_index, ag_slot);
}

static void hsm_update_stats_of(struct voluta_hspace_map *hsm,
				struct voluta_ag_rec *agr,
				const struct voluta_space_stat *sp_st)
{
	const ssize_t diff = calc_used_bytes(sp_st);

	agr_update_stats(agr, sp_st);
	hsm_set_nused(hsm, safe_sum(hsm_nused(hsm), diff));

	voluta_assert_le(hsm->hs_nused, VOLUTA_HS_SIZE);
	voluta_assert_le(agr_used_space(agr), VOLUTA_AG_SIZE);
}

static void hsm_update_stats(struct voluta_hspace_map *hsm, size_t ag_index,
			     const struct voluta_space_stat *sp_st)
{
	struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	hsm_update_stats_of(hsm, agr, sp_st);
}

static void hsm_space_stat_of(const struct voluta_hspace_map *hsm,
			      size_t ag_index, struct voluta_space_stat *sp_st)
{
	const struct voluta_ag_rec *agr;

	agr = hsm_record_of(hsm, ag_index);
	agr_stat(agr, sp_st);
}

static void hsm_space_stat(const struct voluta_hspace_map *hsm,
			   struct voluta_space_stat *sp_st_total)
{
	struct voluta_space_stat ag_sp_st;
	const struct voluta_ag_rec *agr;
	const size_t nags = hsm_nags_span(hsm);

	for (size_t i = 0; i < nags; ++i) {
		agr = hsm_record_at(hsm, i);
		agr_stat(agr, &ag_sp_st);
		sum_space_stat(sp_st_total, &ag_sp_st, sp_st_total);
	}
}

static void hsm_set_formatted(struct voluta_hspace_map *hsm, size_t ag_index)
{
	struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	agr_set_formatted(agr);
}

static bool hsm_is_formatted(const struct voluta_hspace_map *hsm,
			     size_t ag_index)
{
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	return agr_is_formatted(agr);
}

static bool hsm_is_fragmented(struct voluta_hspace_map *hsm, size_t ag_index)
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

static bool hsm_may_alloc_from(const struct voluta_hspace_map *hsm,
			       size_t ag_index, enum voluta_vtype vtype)
{
	bool ret = false;
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	if (agr_kind_fits_vtype(agr, vtype)) {
		ret = agr_may_alloc(agr, vtype);
	}
	return ret;
}

static void hsm_mark_fragmented(struct voluta_hspace_map *hsm, size_t ag_index)
{
	agr_set_fragmented(hsm_record_of(hsm, ag_index));
}

static void hsm_clear_fragmented(struct voluta_hspace_map *hsm,
				 size_t ag_index)
{
	agr_unset_fragmented(hsm_record_of(hsm, ag_index));
}

static void hsm_bind_to_vtype(struct voluta_hspace_map *hsm,
			      size_t ag_index, enum voluta_vtype vtype)
{
	agr_bind_to_kind(hsm_record_of(hsm, ag_index), vtype);
}

static size_t hsm_record_slot(const struct voluta_hspace_map *hsm,
			      const struct voluta_ag_rec *agr)
{
	voluta_assert(agr >= hsm->hs_agr);

	return (size_t)(agr - hsm->hs_agr);
}

static size_t hsm_ag_index_tip(const struct voluta_hspace_map *hsm)
{
	const size_t ag_size = VOLUTA_AG_SIZE;
	const size_t nused = hsm_nused(hsm);
	const size_t ag_index_beg = hsm_ag_index_beg(hsm);

	return ag_index_beg + (nused / ag_size);
}

static size_t hsm_find_avail(const struct voluta_hspace_map *hsm,
			     size_t ag_index_from, enum voluta_vtype vtype)
{
	size_t beg;
	const size_t nags = hsm_nags_span(hsm);
	const struct voluta_ag_rec *agr;

	agr = hsm_record_of(hsm, ag_index_from);
	beg = hsm_record_slot(hsm, agr);
	for (size_t i = beg; i < nags; ++i) {
		agr = hsm_record_at(hsm, i);
		if (!agr_is_formatted(agr)) {
			break;
		}
		if (agr_may_alloc(agr, vtype)) {
			return hsm_resolve_ag_index(hsm, agr);
		}
	}
	return VOLUTA_AG_INDEX_NULL;
}

static void
hsm_update_formatted_ag(struct voluta_hspace_map *hsm, size_t ag_index)
{
	struct voluta_space_stat sp_st = {
		.nmeta = vtype_ssize(VOLUTA_VTYPE_AGMAP)
	};

	hsm_set_formatted(hsm, ag_index);
	hsm_update_stats(hsm, ag_index, &sp_st);
}

static size_t
hsm_used_space_of(const struct voluta_hspace_map *hsm, size_t ag_index)
{
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	return agr_used_space(agr);
}

static const struct voluta_kivam *
hsm_kivam_of(const struct voluta_hspace_map *hsm, size_t ag_index)
{
	const size_t k_slot = ag_index % ARRAY_SIZE(hsm->hs_keys.k);

	return &hsm->hs_keys.k[k_slot];
}

static uint64_t
hsm_seed_of(const struct voluta_hspace_map *hsm, size_t ag_index)
{
	const struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	return agr_seed(agr);
}

static void hsm_mark_itroot_at(struct voluta_hspace_map *hsm, size_t ag_index)
{
	struct voluta_ag_rec *agr = hsm_record_of(hsm, ag_index);

	agr_add_flags(agr, VOLUTA_AGF_ITABLEROOT);
}

static size_t hsm_find_itroot_ag(const struct voluta_hspace_map *hsm)
{
	size_t ag_index;
	const size_t nags = hsm_nags_span(hsm);
	const struct voluta_ag_rec *agr;

	ag_index = VOLUTA_AG_INDEX_NULL;
	for (size_t i = 0; i < nags; ++i) {
		agr = hsm_record_at(hsm, i);
		if (agr_has_flags(agr, VOLUTA_AGF_ITABLEROOT)) {
			ag_index = hsm_resolve_ag_index(hsm, agr);
			break;
		}
	}
	return ag_index;
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

static uint32_t bkr_refcnt(const struct voluta_bk_rec *bkr)
{
	return le32_to_cpu(bkr->bk_refcnt);
}

static void bkr_set_refcnt(struct voluta_bk_rec *bkr, uint32_t refcnt)
{
	bkr->bk_refcnt = cpu_to_le32(refcnt);
}

static void bkr_inc_refcnt(struct voluta_bk_rec *bkr)
{
	bkr_set_refcnt(bkr, bkr_refcnt(bkr) + 1);
}

static void bkr_dec_refcnt(struct voluta_bk_rec *bkr)
{
	voluta_assert_gt(bkr_refcnt(bkr), 0);

	bkr_set_refcnt(bkr, bkr_refcnt(bkr) - 1);
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

static size_t agm_index(const struct voluta_agroup_map *agm)
{
	return le64_to_cpu(agm->ag_index);
}

static void agm_set_index(struct voluta_agroup_map *agm, size_t ag_index)
{
	agm->ag_index = cpu_to_le64(ag_index);
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

static void agm_init(struct voluta_agroup_map *agm, size_t ag_index)
{
	agm_set_index(agm, ag_index);
	agm_set_it_root(agm, &voluta_vaddr_none);
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
	const size_t ag_index = agm_index(agm);
	const struct voluta_bk_rec *bkr = agm_bkr_at(agm, slot);

	bkr_alloc_info(bkr, bai);
	bai->bn = slot;
	bai->lba = voluta_lba_by_ag(ag_index, bai->bn);
}

static size_t agm_nslots(const struct voluta_agroup_map *agm)
{
	return ARRAY_SIZE(agm->ag_bkr);
}

static size_t agm_lba_slot(const struct voluta_agroup_map *agm, loff_t lba)
{
	return (size_t)lba % agm_nslots(agm);
}

static struct voluta_bk_rec *
agm_bkr_by_lba(const struct voluta_agroup_map *agm, loff_t lba)
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

static void agm_set_allocated_at(struct voluta_agroup_map *agm,
				 const struct voluta_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	bkr_set_allocated_at(bkr, kbn, nkb);
	bkr_inc_refcnt(bkr);
	bkr_set_vtype(bkr, vaddr->vtype);
}

static void agm_clear_allocated_at(struct voluta_agroup_map *agm,
				   const struct voluta_vaddr *vaddr)
{
	const size_t kbn = kbn_of(vaddr);
	const size_t nkb = nkb_of(vaddr);
	struct voluta_bk_rec *bkr = agm_bkr_by_vaddr(agm, vaddr);

	bkr_clear_allocated_at(bkr, kbn, nkb);
	bkr_dec_refcnt(bkr);
	if (!bkr_allocated(bkr)) {
		voluta_assert_eq(bkr_refcnt(bkr), 0);
		bkr_set_vtype(bkr, VOLUTA_VTYPE_NONE);
	}
}

static void agm_set_allocated_self(const struct voluta_agroup_map *agm)
{
	const size_t bn_self = 0;
	const size_t nkb_in_bk = VOLUTA_NKB_IN_BK;
	struct voluta_bk_rec *bkr = agm_bkr_at(agm, bn_self);

	STATICASSERT_EQ(sizeof(*bkr), 56);
	STATICASSERT_EQ(sizeof(*agm), VOLUTA_BK_SIZE);

	bkr_set_allocated_at(bkr, 0, nkb_in_bk);
	bkr_inc_refcnt(bkr);
	bkr_set_vtype(bkr, VOLUTA_VTYPE_AGMAP);
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
	size_t ag_index;

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
agm_kivam_of(const struct voluta_agroup_map *agm, loff_t lba)
{
	const size_t k_slot = (size_t)lba % ARRAY_SIZE(agm->ag_keys.k);

	return &agm->ag_keys.k[k_slot];
}

static uint64_t agm_seed_of(const struct voluta_agroup_map *agm, loff_t lba)
{
	const struct voluta_bk_rec *bkr = agm_bkr_by_lba(agm, lba);

	return bkr_seed(bkr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vi_isagmap(const struct voluta_vnode_info *vi)
{
	return vtype_isagmap(vi_vtype(vi));
}

static size_t vi_ag_index(const struct voluta_vnode_info *vi)
{
	voluta_assert(vi_isagmap(vi));

	return agm_index(vi->vu.agm);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static void spi_init(struct voluta_space_info *spi)
{
	spi->sp_size = -1;
	spi->sp_hs_count = 0;
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 0;
	spi->sp_ag_count = 0;
	spi->sp_used_meta = 0;
	spi->sp_used_data = 0;
	spi->sp_nfiles = 0;
}

static void spi_fini(struct voluta_space_info *spi)
{
	spi->sp_size = -1;
	spi->sp_hs_count = 0;
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 0;
	spi->sp_ag_count = 0;
	spi->sp_used_meta = INT_MIN;
	spi->sp_used_data = INT_MIN;
	spi->sp_nfiles = INT_MIN;
}

static void spi_setup(struct voluta_space_info *spi, loff_t space_size)
{
	size_t ag_count;
	size_t hs_count;
	const size_t nag_in_hs = VOLUTA_NAG_IN_HS;
	const size_t nag_prefix = VOLUTA_NAG_IN_HS_PREFIX;

	ag_count = voluta_size_to_ag_count((size_t)space_size);
	hs_count = div_round_up(ag_count - nag_prefix, nag_in_hs);

	spi->sp_size = space_size;
	spi->sp_ag_count = ag_count;
	spi->sp_hs_count = hs_count;
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 1;
}

static void spi_mark_hs_active(struct voluta_space_info *spi, size_t hs_index)
{
	spi->sp_hs_active = max(hs_index, spi->sp_hs_active);
}

static void spi_accum_stat(struct voluta_space_info *spi,
			   const struct voluta_space_stat *sp_st)
{
	spi->sp_used_data += sp_st->ndata;
	spi->sp_used_meta += sp_st->nmeta;
	spi->sp_nfiles += sp_st->nfiles;

	voluta_assert_ge(spi->sp_used_data, 0);
	voluta_assert_ge(spi->sp_used_meta, 0);
	voluta_assert_ge(spi->sp_nfiles, 0);
}

static ssize_t spi_used_bytes(const struct voluta_space_info *spi)
{
	return spi->sp_used_meta + spi->sp_used_data;
}

static ssize_t spi_space_limit(const struct voluta_space_info *spi)
{
	const size_t ag_size = VOLUTA_AG_SIZE;

	return (ssize_t)(ag_size * spi->sp_ag_count);
}

static ssize_t spi_calc_inodes_limit(const struct voluta_space_info *spi)
{
	const ssize_t inode_size = VOLUTA_INODE_SIZE;
	const ssize_t bytes_limit = spi_space_limit(spi);
	const ssize_t inodes_limit = (bytes_limit / inode_size) >> 2;

	return inodes_limit;
}

static bool spi_may_alloc_data(const struct voluta_space_info *spi, size_t nb)
{
	const ssize_t user_limit = (31 * spi_space_limit(spi)) / 32;
	const ssize_t used_bytes = spi_used_bytes(spi);

	return ((used_bytes + (ssize_t)nb) <= user_limit);
}

static bool spi_may_alloc_meta(const struct voluta_space_info *spi,
			       size_t nb, bool new_file)
{
	bool ret = true;
	ssize_t files_max;
	const ssize_t limit = spi_space_limit(spi);
	const ssize_t unsed = spi_used_bytes(spi);

	if ((unsed + (ssize_t)nb) > limit) {
		ret = false;
	} else if (new_file) {
		files_max = spi_calc_inodes_limit(spi);
		ret = (spi->sp_nfiles < files_max);
	}
	return ret;
}

static void spi_update_stats(struct voluta_space_info *spi, size_t hs_index,
			     const struct voluta_space_stat *sp_st)
{
	ssize_t nbytes_dif;
	ssize_t nbytes_max;
	ssize_t nbytes_use;

	spi->sp_used_data += sp_st->ndata;
	spi->sp_used_meta += sp_st->nmeta;
	spi->sp_nfiles += sp_st->nfiles;

	nbytes_max = spi_space_limit(spi);
	nbytes_use = spi_used_bytes(spi);
	nbytes_dif = nbytes_max - nbytes_use;
	voluta_assert_ge(nbytes_dif, 0);

	spi->sp_hs_index_lo = min(hs_index, spi->sp_hs_index_lo);
}

static void spi_update_meta(struct voluta_space_info *spi, ssize_t nmeta)
{
	const struct voluta_space_stat sp_st = {
		.nmeta = nmeta
	};
	spi_update_stats(spi, spi->sp_hs_index_lo, &sp_st);
}

static void spi_mark_used_prefix_ags(struct voluta_space_info *spi)
{
	const loff_t off = ag_index_to_off(VOLUTA_NAG_IN_HS_PREFIX);

	if (off > spi->sp_used_meta) {
		spi->sp_used_meta = off;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vi_isvisible(const struct voluta_vnode_info *vi)
{
	return voluta_is_visible(vi);
}

static void vi_mark_visible(const struct voluta_vnode_info *vi)
{
	voluta_mark_visible(vi);
}

static void vi_stamp_view(struct voluta_vnode_info *vi)
{
	struct voluta_view *view = vi->view;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if (!vaddr_isdata(vaddr)) {
		voluta_stamp_view(view, vaddr);
		vi_dirtify(vi);
	}
	vi_mark_visible(vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum voluta_vtype vtype_at(const struct voluta_vnode_info *agm_vi,
				  const struct voluta_vaddr *vaddr)
{
	return agm_vtype_at(agm_vi->vu.agm, vaddr);
}

static void setup_agmap(struct voluta_vnode_info *agm_vi, size_t ag_index)
{
	struct voluta_agroup_map *agm = agm_vi->vu.agm;

	vi_stamp_view(agm_vi);
	agm_init(agm, ag_index);
	agm_set_allocated_self(agm);

	vi_dirtify(agm_vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void calc_stat_change(const struct voluta_vaddr *vaddr, int take,
			     struct voluta_space_stat *sp_st)
{
	const ssize_t nbytes = (ssize_t)vaddr->len;
	const enum voluta_vtype vtype = vaddr->vtype;

	sp_st->ndata = 0;
	sp_st->nmeta = 0;
	sp_st->nfiles = 0;
	if (take > 0) {
		if (vtype_isdata(vtype)) {
			sp_st->ndata = nbytes;
		} else {
			sp_st->nmeta = nbytes;
		}
		if (vtype_isinode(vtype)) {
			sp_st->nfiles = 1;
		}
	} else if (take < 0) {
		if (vtype_isdata(vtype)) {
			sp_st->ndata = -nbytes;
		} else {
			sp_st->nmeta = -nbytes;
		}
		if (vtype_isinode(vtype)) {
			sp_st->nfiles = -1;
		}
	}
}

static void update_space_stat(struct voluta_sb_info *sbi, int take,
			      const struct voluta_vaddr *vaddr)
{
	const size_t hs_index = vaddr_hs_index(vaddr);
	const size_t ag_index = vaddr_ag_index(vaddr);
	struct voluta_space_stat sp_st = { .zero = 0 };

	if (hs_index && ag_index) {
		calc_stat_change(vaddr, take, &sp_st);
		spi_update_stats(&sbi->sb_spi, hs_index, &sp_st);
	}
}

static fsblkcnt_t bytes_to_fsblkcnt(ssize_t nbytes)
{
	return (fsblkcnt_t)nbytes / VOLUTA_KB_SIZE;
}

void voluta_statvfs_of(const struct voluta_sb_info *sbi,
		       struct statvfs *out_stvfs)
{
	const struct voluta_space_info *spi = &sbi->sb_spi;
	const ssize_t nbytes_max = spi_space_limit(spi);
	const ssize_t nbytes_use = spi_used_bytes(spi);
	const ssize_t nfiles_max = spi_calc_inodes_limit(spi);

	voluta_assert_ge(nbytes_max, nbytes_use);
	voluta_assert_ge(nfiles_max, spi->sp_nfiles);

	voluta_memzero(out_stvfs, sizeof(*out_stvfs));
	out_stvfs->f_bsize = VOLUTA_BK_SIZE;
	out_stvfs->f_frsize = VOLUTA_KB_SIZE;
	out_stvfs->f_blocks = bytes_to_fsblkcnt(nbytes_max);
	out_stvfs->f_bfree = bytes_to_fsblkcnt(nbytes_max - nbytes_use);
	out_stvfs->f_bavail = out_stvfs->f_bfree;
	out_stvfs->f_files = (fsfilcnt_t)nfiles_max;
	out_stvfs->f_ffree = (fsfilcnt_t)(nfiles_max - spi->sp_nfiles);
	out_stvfs->f_favail = out_stvfs->f_ffree;
	out_stvfs->f_namemax = VOLUTA_NAME_MAX;
	out_stvfs->f_fsid = VOLUTA_SUPER_MAGIC;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void resolve_bk_xiovec(const struct voluta_sb_info *sbi,
			      const struct voluta_bk_info *bki,
			      struct voluta_xiovec *out_xiov)
{
	out_xiov->base = NULL;
	out_xiov->off = lba_to_off(bki->bk_lba);
	out_xiov->len = sizeof(*bki->bk);
	out_xiov->fd = sbi->sb_vstore->vs_pstore.ps_vfd;
}

static bool has_unwritten_at(const struct voluta_vnode_info *agm_vi,
			     const struct voluta_vaddr *vaddr)
{
	voluta_assert_eq(agm_vi->vaddr.vtype, VOLUTA_VTYPE_AGMAP);

	return agm_test_unwritten_at(agm_vi->vu.agm, vaddr);
}

static void clear_unwritten_at(const struct voluta_vnode_info *agm_vi,
			       const struct voluta_vaddr *vaddr)
{
	voluta_assert_eq(agm_vi->vaddr.vtype, VOLUTA_VTYPE_AGMAP);

	agm_clear_unwritten_at(agm_vi->vu.agm, vaddr);
}

static int find_cached_bki(struct voluta_sb_info *sbi, loff_t lba,
			   struct voluta_bk_info **out_bki)
{
	*out_bki = voluta_cache_lookup_bki(sbi->sb_cache, lba);
	return (*out_bki != NULL) ? 0 : -ENOENT;
}

static int find_cached_bki_of(struct voluta_super_ctx *s_ctx,
			      const struct voluta_vaddr *vaddr)
{
	return find_cached_bki(s_ctx->sbi, vaddr->lba, &s_ctx->bki);
}

static size_t total_dirty_size(const struct voluta_sb_info *sbi)
{
	return sbi->sb_cache->c_dqs.dq_main.dq_accum_nbytes;
}

static int commit_dirty_now(const struct voluta_super_ctx *s_ctx)
{
	int err;

	err = voluta_flush_dirty(s_ctx->sbi, VOLUTA_F_NOW);
	if (err) {
		log_dbg("commit dirty failure: dirty=%lu err=%d",
			total_dirty_size(s_ctx->sbi), err);
	}
	return err;
}

static int spawn_bki_of(struct voluta_super_ctx *s_ctx,
			const struct voluta_vaddr *vaddr)
{
	int err;
	const loff_t lba = vaddr->lba;
	struct voluta_cache *cache = s_ctx->sbi->sb_cache;

	for (size_t retry = 0; retry < 4; ++retry) {
		s_ctx->bki = voluta_cache_spawn_bki(cache, lba);
		if (s_ctx->bki != NULL) {
			return 0;
		}
		err = commit_dirty_now(s_ctx);
		if (err) {
			return err;
		}
	}
	return -ENOMEM;
}

static const struct voluta_vstore *
vstore_of(const struct voluta_super_ctx *s_ctx)
{
	return s_ctx->sbi->sb_vstore;
}

static int load_bki(struct voluta_super_ctx *s_ctx)
{
	struct voluta_xiovec xiov;
	struct voluta_bk_info *bki = s_ctx->bki;
	const struct voluta_vstore *vstore = vstore_of(s_ctx);

	resolve_bk_xiovec(s_ctx->sbi, bki, &xiov);
	return voluta_vstore_read(vstore, xiov.off, xiov.len, bki->bk);
}

static void forget_bki(struct voluta_super_ctx *s_ctx)
{
	voluta_cache_forget_bki(s_ctx->sbi->sb_cache, s_ctx->bki);
	s_ctx->bki = NULL;
}

static int fetch_bki_of(struct voluta_super_ctx *s_ctx,
			const struct voluta_vaddr *vaddr)
{
	int err;

	err = find_cached_bki_of(s_ctx, vaddr);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bki_of(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = load_bki(s_ctx);
	if (err) {
		forget_bki(s_ctx);
		return err;
	}
	return 0;
}

static struct voluta_view *view_of(const void *p)
{
	return unconst(p);
}

static struct voluta_view *
view_at(const struct voluta_bk_info *bki, loff_t off)
{
	long pos;
	long kbn;
	const long kb_size = VOLUTA_KB_SIZE;
	const long nkb_in_bk = VOLUTA_NKB_IN_BK;
	const struct voluta_block *bk = bki->bk;

	kbn = ((off / kb_size) % nkb_in_bk);
	pos = kbn * kb_size;
	voluta_assert_le(pos + kb_size, sizeof(bk->u.bk));

	return view_of(&bk->u.bk[pos]);
}

static int verify_vnode_view(struct voluta_vnode_info *vi)
{
	int err;

	if (vi_isdata(vi)) {
		return 0;
	}
	err = voluta_verify_meta(vi);
	if (err) {
		return err;
	}
	vi->v_verify++;
	return 0;
}

static bool encrypted_mode(const struct voluta_sb_info *sbi)
{
	const unsigned long mask = VOLUTA_F_ENCRYPTED;

	return (sbi->sb_ctl_flags & mask) == mask;
}

static int decrypt_vnode(struct voluta_super_ctx *s_ctx)
{
	int err;
	const struct voluta_vnode_info *vi = s_ctx->vi;

	if (vi_isvisible(vi)) {
		return 0;
	}
	if (!encrypted_mode(s_ctx->sbi)) {
		return 0;
	}
	err = voluta_decrypt_vnode(vi, vi->view);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nused_nbks_at(const struct voluta_vnode_info *agm_vi)
{
	size_t nused_bytes;
	const size_t bk_size = VOLUTA_BK_SIZE;
	const size_t ag_index = vi_ag_index(agm_vi);
	const struct voluta_vnode_info *hsm_vi = agm_vi->v_pvi;

	nused_bytes = hsm_used_space_of(hsm_vi->vu.hsm, ag_index);
	return nused_bytes / bk_size;
}

static bool vtype_isdatabk(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_DATABK);
}

static size_t start_bn_of(struct voluta_vnode_info *agm_vi,
			  enum voluta_vtype vtype)
{
	size_t bn;
	const size_t nbk_in_ag = VOLUTA_NBK_IN_AG;

	/* Heuristic for mostly append pattern */
	bn = nused_nbks_at(agm_vi);

	/* In case of full data-block align to higher */
	if (bn && vtype_isdatabk(vtype)) {
		bn = voluta_min(bn + 1, nbk_in_ag - 1);
	}
	return bn;
}

static int allocate_and_mark(struct voluta_vnode_info *agm_vi,
			     enum voluta_vtype vtype, size_t start_bn,
			     struct voluta_vaddr *out_vaddr)
{
	int err;
	struct voluta_agroup_map *agm = agm_vi->vu.agm;

	voluta_assert_le(start_bn, VOLUTA_NBK_IN_AG);

	err = agm_find_free_space(agm, vtype, start_bn, out_vaddr);
	if (err) {
		return err;
	}
	agm_set_allocated_at(agm, out_vaddr);
	if (vaddr_isdata(out_vaddr)) {
		agm_set_unwritten_at(agm, out_vaddr);
	}
	vi_dirtify(agm_vi);
	return 0;
}

static int allocate_at(struct voluta_sb_info *sbi, size_t ag_index,
		       enum voluta_vtype vtype, struct voluta_vaddr *out_vaddr)
{
	int err;
	size_t start_bn;
	struct voluta_vnode_info *agm_vi = NULL;
	struct voluta_vnode_info *hsm_vi = NULL;
	struct voluta_space_stat sp_st = { .zero = 0 };

	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	start_bn = start_bn_of(agm_vi, vtype);
	err = allocate_and_mark(agm_vi, vtype, start_bn, out_vaddr);
	if (err) {
		return err;
	}

	calc_stat_change(out_vaddr, 1, &sp_st);
	hsm_vi = agm_vi->v_pvi;
	hsm_update_stats(hsm_vi->vu.hsm, ag_index, &sp_st);
	vi_dirtify(hsm_vi);
	return 0;
}

static bool can_allocate_from(const struct voluta_vnode_info *hsm_vi,
			      size_t ag_index, enum voluta_vtype vtype)
{
	return hsm_may_alloc_from(hsm_vi->vu.hsm, ag_index, vtype);
}

static void ag_range_of(const struct voluta_vnode_info *hsm_vi,
			struct voluta_ag_range *ag_range)
{
	const struct voluta_hspace_map *hsm = hsm_vi->vu.hsm;

	ag_range->beg = hsm_ag_index_beg(hsm);
	ag_range->tip = hsm_ag_index_tip(hsm);
	ag_range->fin = hsm_ag_index_fin(hsm);
	ag_range->end = hsm_ag_index_end(hsm);

	voluta_assert_ge(ag_range->tip, ag_range->beg);
	voluta_assert_ge(ag_range->fin, ag_range->tip);
	voluta_assert_ge(ag_range->end, ag_range->fin);
}

static int try_allocate_at(struct voluta_vnode_info *hsm_vi,
			   size_t ag_index, enum voluta_vtype vtype,
			   struct voluta_vaddr *out_vaddr)
{
	int err;
	const size_t nbytes = vtype_size(vtype);
	const size_t bk_size = VOLUTA_BK_SIZE;
	struct voluta_sb_info *sbi = vi_sbi(hsm_vi);

	err = allocate_at(sbi, ag_index, vtype, out_vaddr);
	if ((err == -ENOSPC) && (nbytes < bk_size)) {
		hsm_mark_fragmented(hsm_vi->vu.hsm, ag_index);
		vi_dirtify(hsm_vi);
	}
	return err;
}

static void rebind_to_vtype(struct voluta_vnode_info *hsm_vi,
			    size_t ag_index, enum voluta_vtype vtype)
{
	hsm_bind_to_vtype(hsm_vi->vu.hsm, ag_index, vtype);
	vi_dirtify(hsm_vi);
}

static int try_allocate_within(struct voluta_vnode_info *hsm_vi,
			       size_t ag_index_first, size_t ag_index_last,
			       enum voluta_vtype vtype,
			       struct voluta_vaddr *out_vaddr)
{
	int err;
	size_t ag_index;

	for (ag_index = ag_index_first; ag_index < ag_index_last; ++ag_index) {
		ag_index = hsm_find_avail(hsm_vi->vu.hsm, ag_index, vtype);
		if (ag_index_isnull(ag_index)) {
			break;
		}
		if (!can_allocate_from(hsm_vi, ag_index, vtype)) {
			continue;
		}
		err = try_allocate_at(hsm_vi, ag_index, vtype, out_vaddr);
		if (!err) {
			rebind_to_vtype(hsm_vi, ag_index, vtype);
			return 0;
		}
		if (err != -ENOSPC) {
			return err;
		}
	}
	return -ENOSPC;
}

static int try_allocate_within_range(struct voluta_vnode_info *hsm_vi,
				     const struct voluta_ag_range *ag_range,
				     enum voluta_vtype vtype,
				     struct voluta_vaddr *out_vaddr)
{
	int err;

	/* fast search */
	err = try_allocate_within(hsm_vi, ag_range->tip, ag_range->fin,
				  vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	/* slow search */
	err = try_allocate_within(hsm_vi, ag_range->beg, ag_range->tip,
				  vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int check_cap_alloc(const struct voluta_vnode_info *hsm_vi, size_t nb)
{
	return hsm_may_alloc(hsm_vi->vu.hsm, nb) ? 0 : -ENOSPC;
}

static int do_allocate_from(struct voluta_sb_info *sbi,
			    struct voluta_vnode_info *hsm_vi,
			    enum voluta_vtype vtype,
			    struct voluta_vaddr *out_vaddr)
{
	int err;
	size_t nags_fmt = 0;
	struct voluta_ag_range ag_range;
	const size_t nbytes = vtype_size(vtype);

	err = check_cap_alloc(hsm_vi, nbytes);
	if (err) {
		return err;
	}
	ag_range_of(hsm_vi, &ag_range);
	err = try_allocate_within_range(hsm_vi, &ag_range, vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	err = format_next_agmaps(sbi, hsm_vi, 1, &nags_fmt);
	if (err) {
		return err;
	}
	if (nags_fmt == 0) {
		return -ENOSPC;
	}
	ag_range_of(hsm_vi, &ag_range);
	err = try_allocate_within_range(hsm_vi, &ag_range, vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int try_allocate_from(struct voluta_sb_info *sbi,
			     struct voluta_vnode_info *hsm_vi,
			     enum voluta_vtype vtype,
			     struct voluta_vaddr *out_vaddr)
{
	int err;

	vi_incref(hsm_vi);
	err = do_allocate_from(sbi, hsm_vi, vtype, out_vaddr);
	vi_decref(hsm_vi);

	return err;
}

static int try_allocate_space(struct voluta_sb_info *sbi,
			      enum voluta_vtype vtype,
			      struct voluta_vaddr *out_vaddr)
{
	int err;
	size_t hs_index;
	struct voluta_vnode_info *hsm_vi;
	struct voluta_space_info *spi = &sbi->sb_spi;
	const size_t bk_size = VOLUTA_BK_SIZE;

	hs_index = spi->sp_hs_index_lo;
	while (hs_index <= spi->sp_hs_active) {
		err = stage_hsmap(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		err = try_allocate_from(sbi, hsm_vi, vtype, out_vaddr);
		if (!err || (err != -ENOSPC)) {
			return err;
		}
		hs_index++;
		err = check_cap_alloc(hsm_vi, 2 * bk_size);
		if (err) {
			spi->sp_hs_index_lo = hs_index;
		}
	}
	return -ENOSPC;
}

static int expand_space(struct voluta_sb_info *sbi)
{
	int err = -ENOSPC;
	const struct voluta_space_info *spi = &sbi->sb_spi;

	if (spi->sp_hs_active < spi->sp_hs_count) {
		err = format_spmaps_at(sbi, spi->sp_hs_active + 1, 1);
	}
	if (err) {
		log_dbg("can not expand space: "\
			"hs_active=%lu hs_count=%lu err=%d",
			spi->sp_hs_active, spi->sp_hs_count, err);
	}
	return err;
}

static int allocate_space(struct voluta_super_ctx *s_ctx,
			  enum voluta_vtype vtype,
			  struct voluta_vaddr *out_vaddr)
{
	int err = -ENOSPC;
	size_t niter = 2;

	while (niter--) {
		err = try_allocate_space(s_ctx->sbi, vtype, out_vaddr);
		if (!err || (err != -ENOSPC)) {
			break;
		}
		err = expand_space(s_ctx->sbi);
		if (err) {
			break;
		}
	}
	return err;
}

static void deallocate_space_at(struct voluta_vnode_info *agm_vi,
				const struct voluta_vaddr *vaddr)
{
	const size_t nkb = nkb_of(vaddr);
	const size_t ag_index = vaddr_ag_index(vaddr);
	struct voluta_vnode_info *hsm_vi = agm_vi->v_pvi;

	voluta_assert_not_null(hsm_vi);
	voluta_assert_eq(hsm_vi->vaddr.vtype, VOLUTA_VTYPE_HSMAP);

	agm_clear_allocated_at(agm_vi->vu.agm, vaddr);
	agm_renew_if_unused(agm_vi->vu.agm, vaddr);
	vi_dirtify(agm_vi);

	if ((nkb > 1) && hsm_is_fragmented(hsm_vi->vu.hsm, ag_index)) {
		hsm_clear_fragmented(hsm_vi->vu.hsm, ag_index);
		vi_dirtify(hsm_vi);
	}
}

static int deallocate_at(struct voluta_sb_info *sbi,
			 const struct voluta_vaddr *vaddr)
{
	int err;
	const size_t hs_index = vaddr_hs_index(vaddr);
	const size_t ag_index = vaddr_ag_index(vaddr);
	struct voluta_vnode_info *agm_vi = NULL;
	struct voluta_vnode_info *hsm_vi = NULL;
	struct voluta_space_stat sp_st = { .zero = 0 };

	voluta_assert_gt(hs_index, 0);
	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	deallocate_space_at(agm_vi, vaddr);

	calc_stat_change(vaddr, -1, &sp_st);
	hsm_vi = agm_vi->v_pvi;
	hsm_update_stats(hsm_vi->vu.hsm, ag_index, &sp_st);
	vi_dirtify(hsm_vi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bind_view(struct voluta_vnode_info *vi, struct voluta_view *view)
{
	vi->view = view;

	switch (vi->vaddr.vtype) {
	case VOLUTA_VTYPE_HSMAP:
		vi->vu.hsm = &view->u.hsm;
		break;
	case VOLUTA_VTYPE_AGMAP:
		vi->vu.agm = &view->u.agm;
		break;
	case VOLUTA_VTYPE_ITNODE:
		vi->vu.itn = &view->u.itn;
		break;
	case VOLUTA_VTYPE_INODE:
		vi->vu.inode = &view->u.inode;
		break;
	case VOLUTA_VTYPE_XANODE:
		vi->vu.xan = &view->u.xan;
		break;
	case VOLUTA_VTYPE_HTNODE:
		vi->vu.htn = &view->u.htn;
		break;
	case VOLUTA_VTYPE_RTNODE:
		vi->vu.rtn = &view->u.rtn;
		break;
	case VOLUTA_VTYPE_SYMVAL:
		vi->vu.lnv = &view->u.lnv;
		break;
	case VOLUTA_VTYPE_DATA4K:
		vi->vu.db4 = &view->u.db4;
		break;
	case VOLUTA_VTYPE_DATABK:
		vi->vu.db = &view->u.db;
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		break;
	}
}

static void vi_assign_ds_key(struct voluta_vnode_info *vi,
			     const struct voluta_inode_info *parent_ii)
{
	if (parent_ii != NULL) {
		vi->v_ds_key = (long)ii_ino(parent_ii);
	} else {
		vi->v_ds_key = 0;
	}
}

static void attach_vnode(const struct voluta_super_ctx *s_ctx)
{
	struct voluta_vnode_info *vi = s_ctx->vi;
	struct voluta_inode_info *ii = s_ctx->ii;
	struct voluta_inode_info *parent_ii = s_ctx->pii;
	struct voluta_vnode_info *parent_vi =
			s_ctx->agm_vi ? s_ctx->agm_vi : s_ctx->hsm_vi;

	s_ctx->vi->v_sbi = s_ctx->sbi;
	voluta_vi_attach_to(vi, s_ctx->bki, parent_vi);
	vi_assign_ds_key(vi, ii ? ii : parent_ii);
}

static int bind_vnode(struct voluta_super_ctx *s_ctx)
{
	struct voluta_view *view;
	struct voluta_vnode_info *vi = s_ctx->vi;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	attach_vnode(s_ctx);

	view = view_at(s_ctx->bki, vaddr->off);
	bind_view(vi, view);

	return 0;
}

static int bind_inode(struct voluta_super_ctx *s_ctx)
{
	int err;
	struct voluta_inode_info *ii = s_ctx->ii;

	s_ctx->vi = ii_vi(ii);
	err = bind_vnode(s_ctx);
	if (err) {
		return err;
	}
	ii->inode = ii->i_vi.vu.inode;
	return 0;
}

static int find_cached_vi(struct voluta_super_ctx *s_ctx,
			  const struct voluta_vaddr *vaddr)
{
	s_ctx->vi = voluta_cache_lookup_vi(cache_of(s_ctx), vaddr);
	return (s_ctx->vi != NULL) ? 0 : -ENOENT;
}

static int spawn_vi_now(struct voluta_super_ctx *s_ctx,
			const struct voluta_vaddr *vaddr, bool expect_ok)
{
	struct voluta_cache *cache = cache_of(s_ctx);

	s_ctx->vi = voluta_cache_spawn_vi(cache, vaddr);
	if (s_ctx->vi != NULL) {
		return 0;
	}
	if (expect_ok) {
		log_dbg("can not spawn vi: nvi=%lu dirty=%lu",
			cache->c_vlm.htbl_size, total_dirty_size(s_ctx->sbi));
	}
	return -ENOMEM;
}

static int spawn_vi(struct voluta_super_ctx *s_ctx,
		    const struct voluta_vaddr *vaddr)
{
	int err;

	err = spawn_vi_now(s_ctx, vaddr, false);
	if (!err) {
		return 0;
	}
	err = commit_dirty_now(s_ctx);
	if (err) {
		return err;
	}
	err = spawn_vi_now(s_ctx, vaddr, true);
	if (err) {
		return err;
	}
	return 0;
}

static int spawn_bind_vi(struct voluta_super_ctx *s_ctx,
			 const struct voluta_vaddr *vaddr)
{
	int err;

	err = fetch_parents_of(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = spawn_vi(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = bind_vnode(s_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static void forget_cached_vi(struct voluta_vnode_info *vi)
{
	voulta_cache_forget_vi(vi_cache(vi), vi);
}

static int spawn_ii_now(struct voluta_super_ctx *s_ctx,
			const struct voluta_iaddr *iaddr, bool expect_ok)
{
	struct voluta_cache *cache = cache_of(s_ctx);

	s_ctx->ii = voluta_cache_spawn_ii(cache, iaddr);
	if ((s_ctx->ii == NULL) && expect_ok) {
		log_dbg("can not spawn ii: nii=%lu dirty=%lu",
			cache->c_ilm.htbl_size, total_dirty_size(s_ctx->sbi));
	}
	return (s_ctx->ii == NULL) ? -ENOMEM : 0;
}

static int spawn_ii(struct voluta_super_ctx *s_ctx,
		    const struct voluta_iaddr *iaddr)
{
	int err;

	err = spawn_ii_now(s_ctx, iaddr, false);
	if (!err) {
		return 0;
	}
	err = commit_dirty_now(s_ctx);
	if (err) {
		return err;
	}
	err = spawn_ii_now(s_ctx, iaddr, true);
	if (err) {
		return err;
	}
	s_ctx->vi = ii_vi(s_ctx->ii);
	return 0;
}

static int spawn_bind_ii(struct voluta_super_ctx *s_ctx,
			 const struct voluta_iaddr *iaddr)
{
	int err;

	err = fetch_parents_of(s_ctx, &iaddr->vaddr);
	if (err) {
		return err;
	}
	err = spawn_ii(s_ctx, iaddr);
	if (err) {
		return err;
	}
	err = bind_inode(s_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static void forget_cached_ii(struct voluta_super_ctx *s_ctx)
{
	voulta_cache_forget_ii(cache_of(s_ctx), s_ctx->ii);
}

static int find_cached_or_spawn_bki(struct voluta_super_ctx *s_ctx,
				    const struct voluta_vaddr *vaddr)
{
	int err;

	err = find_cached_bki_of(s_ctx, vaddr);
	if (err) {
		err = spawn_bki_of(s_ctx, vaddr);
	}
	return err;
}

static int spawn_vmeta(struct voluta_super_ctx *s_ctx,
		       const struct voluta_vaddr *vaddr)
{
	int err;

	err = find_cached_or_spawn_bki(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = spawn_bind_vi(s_ctx, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int spawn_meta(struct voluta_super_ctx *s_ctx,
		      const struct voluta_vaddr *vaddr,
		      struct voluta_vnode_info **out_vi)
{
	int err;

	err = spawn_vmeta(s_ctx, vaddr);
	if (!err) {
		*out_vi = s_ctx->vi;
	}
	return err;
}

static int review_vnode(struct voluta_super_ctx *s_ctx)
{
	int err;
	struct voluta_vnode_info *vi = s_ctx->vi;

	if (vi_isvisible(vi)) {
		return 0;
	}
	err = verify_vnode_view(vi);
	if (err) {
		return err;
	}
	vi_mark_visible(vi);
	return 0;
}

static int stage_vnode(struct voluta_super_ctx *s_ctx,
		       const struct voluta_vaddr *vaddr)
{
	int err;

	err = find_cached_vi(s_ctx, vaddr);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = fetch_bki_of(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = spawn_bind_vi(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = decrypt_vnode(s_ctx);
	if (err) {
		return err;
	}
	err = review_vnode(s_ctx);
	if (err) {
		forget_cached_vi(s_ctx->vi);
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vaddr_isitnode(const struct voluta_vaddr *vaddr)
{
	return !vaddr_isnull(vaddr) &&
	       vtype_isequal(vaddr->vtype, VOLUTA_VTYPE_ITNODE);
}


static int sbi_resolve_itroot_ag(struct voluta_sb_info *sbi,
				 size_t *out_ag_index)
{
	int err;
	size_t ag_index;
	struct voluta_vnode_info *hsm_vi = NULL;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	for (size_t hs_index = 1; (hs_index <= hs_count); ++hs_index) {
		err = stage_hsmap(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		ag_index = hsm_find_itroot_ag(hsm_vi->vu.hsm);
		if (!ag_index_isnull(ag_index)) {
			*out_ag_index = ag_index;
			return 0;
		}
	}
	log_err("failed to find it-root ag: hs_count=%lu", hs_count);
	return -EFSCORRUPTED;
}

static int sbi_resolve_itroot(struct voluta_sb_info *sbi,
			      struct voluta_vaddr *out_vaddr)
{
	int err;
	size_t ag_index;
	struct voluta_vnode_info *agm_vi = NULL;

	err = sbi_resolve_itroot_ag(sbi, &ag_index);
	if (err) {
		return err;
	}
	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	agm_it_root(agm_vi->vu.agm, out_vaddr);
	if (!vaddr_isitnode(out_vaddr)) {
		log_err("non valid it-root vaddr: off=0x%lx vtype=%d",
			out_vaddr->off, out_vaddr->vtype);
		return -EFSCORRUPTED;
	}
	return 0;
}

int voluta_reload_itable(struct voluta_sb_info *sbi)
{
	int err;
	struct voluta_vaddr vaddr;

	vaddr_reset(&vaddr);
	err = sbi_resolve_itroot(sbi, &vaddr);
	if (err) {
		return err;
	}
	err = voluta_reload_itable_at(sbi, &vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_adjust_super(struct voluta_sb_info *sbi)
{
	spi_mark_used_prefix_ags(&sbi->sb_spi);
	return 0;
}

int voluta_shut_super(struct voluta_sb_info *sbi)
{
	log_dbg("shut-super: op_count=%lu", sbi->sb_ops.op_count);
	spi_init(&sbi->sb_spi);
	voluta_iti_reinit(&sbi->sb_iti);
	return 0;
}

static int stamp_itable_at(struct voluta_sb_info *sbi,
			   const struct voluta_vaddr *vaddr)
{
	int err;
	size_t hs_index;
	size_t ag_index;
	struct voluta_vnode_info *hsm_vi;
	struct voluta_vnode_info *agm_vi;

	hs_index = vaddr_hs_index(vaddr);
	err = stage_hsmap(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	ag_index = vaddr_ag_index(vaddr);
	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	agm_set_it_root(agm_vi->vu.agm, vaddr);
	vi_dirtify(agm_vi);
	hsm_mark_itroot_at(hsm_vi->vu.hsm, ag_index);
	vi_dirtify(hsm_vi);
	return 0;
}

int voluta_format_itable(struct voluta_sb_info *sbi)
{
	int err;
	const struct voluta_vaddr *vaddr = NULL;

	err = voluta_create_itable(sbi);
	if (err) {
		return err;
	}
	vaddr = voluta_root_of_itable(sbi);
	err = stamp_itable_at(sbi, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void relax_bringup_cache(struct voluta_sb_info *sbi)
{
	voluta_cache_relax(sbi->sb_cache, VOLUTA_F_BRINGUP);
}

static int flush_dirty_cache(struct voluta_sb_info *sbi, bool all)
{
	return voluta_flush_dirty(sbi, all ? VOLUTA_F_NOW : 0);
}

static int flush_and_relax(struct voluta_sb_info *sbi, int flags)
{
	int err;

	err = voluta_flush_dirty(sbi, flags);
	if (!err) {
		voluta_cache_relax(sbi->sb_cache, flags);
	}
	return err;
}

static void update_spi_by_hsm(struct voluta_sb_info *sbi,
			      const struct voluta_vnode_info *hsm_vi)
{
	struct voluta_space_info *spi = &sbi->sb_spi;
	const struct voluta_hspace_map *hsm = hsm_vi->vu.hsm;
	struct voluta_space_stat sp_st = { .zero = 0 };

	hsm_space_stat(hsm, &sp_st);
	spi_accum_stat(spi, &sp_st);
	spi_mark_hs_active(spi, hsm_index(hsm));
}

static void update_spi_on_hsp(struct voluta_sb_info *sbi)
{
	spi_update_meta(&sbi->sb_spi, VOLUTA_AG_SIZE);
}

static void update_spi_on_agm(struct voluta_sb_info *sbi)
{
	STATICASSERT_EQ(sizeof(struct voluta_bk_rec), 56);
	STATICASSERT_EQ(sizeof(struct voluta_agroup_map), VOLUTA_BK_SIZE);

	spi_update_meta(&sbi->sb_spi, VOLUTA_BK_SIZE);
}

static int spawn_hsmap(struct voluta_sb_info *sbi, size_t hs_index,
		       struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr vaddr;
	struct voluta_super_ctx s_ctx = { .sbi = sbi, };

	voluta_vaddr_of_hsmap(&vaddr, hs_index);
	return spawn_meta(&s_ctx, &vaddr, out_vi);
}

static void setup_hsmap(struct voluta_vnode_info *hsm_vi,
			size_t hs_index, size_t nags_span)
{
	struct voluta_hspace_map *hsm = hsm_vi->vu.hsm;

	voluta_assert_gt(nags_span, 0);
	voluta_assert_le(nags_span, ARRAY_SIZE(hsm->hs_agr));

	vi_stamp_view(hsm_vi);
	hsm_init(hsm, hs_index, nags_span);

	vi_dirtify(hsm_vi);
}

static int format_hsmap(struct voluta_sb_info *sbi,
			size_t hs_index, size_t nags_span,
			struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *hsm_vi;

	err = spawn_hsmap(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	setup_hsmap(hsm_vi, hs_index, nags_span);
	update_spi_on_hsp(sbi);

	*out_vi = hsm_vi;
	return 0;
}

static int mark_prev_hsmap_with_next(struct voluta_sb_info *sbi,
				     size_t hs_index_prev)
{
	int err;
	struct voluta_vnode_info *hsm_vi = NULL;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	if ((hs_index_prev < 1) || (hs_index_prev >= hs_count)) {
		return 0;
	}
	err = stage_hsmap(sbi, hs_index_prev, &hsm_vi);
	if (err) {
		return err;
	}
	if (!hsm_test_hasnext(hsm_vi->vu.hsm)) {
		hsm_add_hasnext(hsm_vi->vu.hsm);
		vi_dirtify(hsm_vi);
	}
	return 0;
}

static size_t nags_in_hs(const struct voluta_sb_info *sbi, size_t hs_index)
{
	size_t nags;
	size_t ag_index_base;
	size_t ag_index_next;
	const size_t ag_count = sbi->sb_spi.sp_ag_count;

	ag_index_base = voluta_ag_index_by_hs(hs_index, 0);
	ag_index_next = voluta_ag_index_by_hs(hs_index + 1, 0);
	nags = min(ag_index_next - ag_index_base, ag_count - ag_index_base);

	return nags;
}

static int format_hsmap_at(struct voluta_sb_info *sbi, size_t hs_index,
			   struct voluta_vnode_info **out_hsm_vi)
{
	int err;
	const size_t nags_span = nags_in_hs(sbi, hs_index);

	err = format_hsmap(sbi, hs_index, nags_span, out_hsm_vi);
	if (err) {
		return err;
	}
	err = mark_prev_hsmap_with_next(sbi, hs_index - 1);
	if (err) {
		return err;
	}
	spi_mark_hs_active(&sbi->sb_spi, hs_index);
	return 0;
}

static int format_spmaps_at(struct voluta_sb_info *sbi,
			    size_t hs_index, size_t nags)
{
	int err;
	size_t nags_fmt = 0;
	struct voluta_vnode_info *hsm_vi = NULL;

	err = format_hsmap_at(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	err = format_next_agmaps(sbi, hsm_vi, nags, &nags_fmt);
	if (err) {
		return err;
	}
	if (nags_fmt == 0) {
		log_err("failed to format new ags: hs_index=%lu", hs_index);
		return -EFSCORRUPTED;
	}
	return 0;
}

int voluta_format_spmaps(struct voluta_sb_info *sbi)
{
	int err;
	const size_t hs_count = 1; /* TODO: format more then one? */
	const size_t ag_count = VOLUTA_VOLUME_NAG_MIN - 1;

	voluta_assert_gt(hs_count, 0);
	voluta_assert_gt(sbi->sb_spi.sp_ag_count, VOLUTA_NAG_IN_HS_PREFIX);

	for (size_t hs_index = 1; hs_index <= hs_count; ++hs_index) {
		err = format_spmaps_at(sbi, hs_index, ag_count);
		if (err) {
			return err;
		}
		err = flush_dirty_cache(sbi, true);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int spawn_agmap(struct voluta_sb_info *sbi, size_t ag_index,
		       struct voluta_vnode_info *hsm_vi,
		       struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr vaddr;
	struct voluta_super_ctx s_ctx = {
		.sbi = sbi,
		.hsm_vi = hsm_vi,
	};

	voluta_vaddr_of_agmap(&vaddr, ag_index);
	return spawn_meta(&s_ctx, &vaddr, out_vi);
}

static int unlimit_agmap_on_pstore(struct voluta_sb_info *sbi, size_t ag_index)
{
	loff_t cap;
	struct voluta_vaddr vaddr;
	struct voluta_vstore *vstore = sbi->sb_vstore;
	const loff_t ag_size = VOLUTA_AG_SIZE;

	voluta_vaddr_of_agmap(&vaddr, ag_index);
	cap = ((vaddr.off + ag_size) / ag_size) * ag_size;
	return voluta_vstore_expand(vstore, cap);
}

static int do_format_agmap(struct voluta_sb_info *sbi,
			   struct voluta_vnode_info *hsm_vi, size_t ag_index)
{
	int err;
	struct voluta_vnode_info *agm_vi;
	struct voluta_hspace_map *hsm = hsm_vi->vu.hsm;

	err = unlimit_agmap_on_pstore(sbi, ag_index);
	if (err) {
		return err;
	}
	err = spawn_agmap(sbi, ag_index, hsm_vi, &agm_vi);
	if (err) {
		return err;
	}
	setup_agmap(agm_vi, ag_index);

	hsm_update_formatted_ag(hsm, ag_index);
	hsm_inc_nags_form(hsm);
	vi_dirtify(hsm_vi);

	update_spi_on_agm(sbi);

	return 0;
}

static int format_nagmaps(struct voluta_sb_info *sbi,
			  struct voluta_vnode_info *hsm_vi,
			  size_t ag_index_start, size_t nags)
{
	int err = 0;
	size_t ag_index = ag_index_start;

	vi_incref(hsm_vi);
	while (nags-- && !err) {
		err = do_format_agmap(sbi, hsm_vi, ag_index++);
	}
	vi_decref(hsm_vi);

	return err;
}

static int format_next_agmaps(struct voluta_sb_info *sbi,
			      struct voluta_vnode_info *hsm_vi,
			      size_t nags_want, size_t *out_nags_fmt)
{
	int err;
	size_t nags;
	struct voluta_ag_range ag_range;

	ag_range_of(hsm_vi, &ag_range);
	nags = min(nags_want, ag_range.end - ag_range.fin);
	err = format_nagmaps(sbi, hsm_vi, ag_range.fin, nags);
	if (err) {
		return err;
	}
	*out_nags_fmt = nags;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int load_hsmap_at(struct voluta_sb_info *sbi, size_t hs_index,
			 struct voluta_vnode_info **out_hsm_vi)
{
	int err;
	struct voluta_vnode_info *hsm_vi;

	err = stage_hsmap(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	update_spi_by_hsm(sbi, hsm_vi);
	update_spi_on_hsp(sbi);

	*out_hsm_vi = hsm_vi;
	return 0;
}

static int load_agmap(struct voluta_sb_info *sbi, size_t ag_index)
{
	int err;
	struct voluta_vnode_info *agm_vi;
	struct voluta_vnode_info *hsm_vi;

	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	hsm_vi = agm_vi->v_pvi;
	voluta_assert_not_null(hsm_vi);
	voluta_assert_eq(hsm_vi->vaddr.vtype, VOLUTA_VTYPE_HSMAP);

	if (!hsm_is_formatted(hsm_vi->vu.hsm, ag_index)) {
		return -EFSCORRUPTED;
	}
	return 0;
}

static int load_first_agmap_of(struct voluta_sb_info *sbi,
			       struct voluta_vnode_info *hsm_vi)
{
	int err;
	const size_t hs_index = hsm_index(hsm_vi->vu.hsm);
	const size_t ag_index = voluta_ag_index_by_hs(hs_index, 0);

	vi_incref(hsm_vi);
	err = load_agmap(sbi, ag_index);
	vi_decref(hsm_vi);
	return err;
}

int voluta_reload_spmaps(struct voluta_sb_info *sbi)
{
	int err;
	bool has_next;
	struct voluta_vnode_info *hsm_vi;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	for (size_t hs_index = 1; (hs_index <= hs_count); ++hs_index) {
		err = load_hsmap_at(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		err = load_first_agmap_of(sbi, hsm_vi);
		if (err) {
			return err;
		}
		has_next = hsm_test_hasnext(hsm_vi->vu.hsm);
		if (!has_next) {
			break;
		}
		relax_bringup_cache(sbi);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vaddr_by_bai(struct voluta_vaddr *vaddr,
			 const struct voluta_vnode_info *agm_vi,
			 const struct voluta_balloc_info *bai, size_t idx)
{
	const size_t ag_index = agm_index(agm_vi->vu.agm);

	vaddr_by_ag(vaddr, bai->vtype, ag_index, bai->bn, bai->kbn[idx]);
}

static int traverse_by_balloc_info(struct voluta_super_ctx *s_ctx,
				   const struct voluta_balloc_info *bai)
{
	int err;
	size_t nvis = 0;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi;
	struct voluta_vnode_info *vis[VOLUTA_NKB_IN_BK];

	STATICASSERT_EQ(ARRAY_SIZE(vis), ARRAY_SIZE(bai->kbn));

	for (size_t i = 0; i < bai->cnt; ++i) {
		vaddr_by_bai(&vaddr, s_ctx->agm_vi, bai, i);
		err = voluta_fetch_vnode(s_ctx->sbi, &vaddr, NULL, &vi);
		if (err) {
			goto out;
		}
		vis[nvis++] = vi;
		vi_incref(vi);
	}
	for (size_t i = 0; i < nvis; ++i) {
		vi = vis[i];
		vi_dirtify(vi);
	}
	err = voluta_vstore_punch_bk(vstore_of(s_ctx), bai->lba);
out:
	for (size_t i = 0; i < nvis; ++i) {
		vi = vis[i];
		vi_decref(vi);
	}
	return err;
}

static int do_traverse_by_agmap(struct voluta_super_ctx *s_ctx)
{
	int err;
	struct voluta_vnode_info *agm_vi = s_ctx->agm_vi;
	const size_t nslots = agm_nslots(agm_vi->vu.agm);
	struct voluta_balloc_info bai = { .cnt = 0 };

	for (size_t slot = 0; slot < nslots; ++slot) {
		agm_balloc_info_at(agm_vi->vu.agm, slot, &bai);
		if (vtype_isumap(bai.vtype)) {
			continue;
		}
		err = traverse_by_balloc_info(s_ctx, &bai);
		if (err) {
			return err;
		}
		err = flush_and_relax(s_ctx->sbi, VOLUTA_F_OPSTART);
		if (err) {
			return err;
		}
	}
	vi_dirtify(agm_vi);
	return 0;
}

static int traverse_by_agmap(struct voluta_sb_info *sbi,
			     struct voluta_vnode_info *agm_vi)
{
	int err;
	struct voluta_super_ctx s_ctx = {
		.sbi = sbi,
		.hsm_vi = agm_vi->v_pvi,
		.agm_vi = agm_vi,
	};

	vi_incref(agm_vi);
	err = do_traverse_by_agmap(&s_ctx);
	vi_decref(agm_vi);
	return err;
}

static int do_traverse_by_hsmap(struct voluta_super_ctx *s_ctx)
{
	int err;
	size_t ag_index;
	struct voluta_ag_range ag_range;
	struct voluta_vnode_info *hsm_vi = s_ctx->hsm_vi;

	ag_range_of(hsm_vi, &ag_range);
	for (ag_index = ag_range.beg; ag_index < ag_range.fin; ++ag_index) {
		err = stage_agmap(s_ctx->sbi, ag_index, &s_ctx->agm_vi);
		if (err) {
			return err;
		}
		err = traverse_by_agmap(s_ctx->sbi, s_ctx->agm_vi);
		if (err) {
			return err;
		}
		err = flush_and_relax(s_ctx->sbi, VOLUTA_F_OPSTART);
		if (err) {
			return err;
		}
	}
	vi_dirtify(hsm_vi);
	return 0;
}

static int traverse_by_hsmap(struct voluta_sb_info *sbi,
			     struct voluta_vnode_info *hsm_vi)
{
	int err;
	struct voluta_super_ctx s_ctx = {
		.sbi = sbi,
		.hsm_vi = hsm_vi
	};

	vi_incref(hsm_vi);
	err = do_traverse_by_hsmap(&s_ctx);
	vi_decref(hsm_vi);
	return err;
}

int voluta_traverse_space(struct voluta_sb_info *sbi)
{
	int err;
	bool has_next;
	struct voluta_vnode_info *hsm_vi;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	voluta_assert_gt(hs_count, 0);

	for (size_t hs_index = 1; hs_index <= hs_count; ++hs_index) {
		err = load_hsmap_at(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		err = traverse_by_hsmap(sbi, hsm_vi);
		if (err) {
			return err;
		}
		has_next = hsm_test_hasnext(hsm_vi->vu.hsm);
		if (!has_next) {
			break;
		}
		err = flush_dirty_cache(sbi, false);
		if (err) {
			return err;
		}
	}
	return 0;
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

int voluta_verify_uspace_map(const struct voluta_hspace_map *hsm)
{
	size_t hs_index;
	const size_t hs_size = VOLUTA_HS_SIZE;
	const size_t vol_size_max = VOLUTA_VOLUME_SIZE_MAX;

	hs_index = hsm_index(hsm);
	if ((hs_index * hs_size) >= vol_size_max) {
		return -EFSCORRUPTED;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t calc_iopen_limit(const struct voluta_cache *cache)
{
	return (cache->c_qalloc->st.memsz_data / (2 * VOLUTA_BK_SIZE));
}

static int sbi_init_commons(struct voluta_sb_info *sbi)
{
	voluta_uuid_generate(&sbi->sb_fs_uuid);
	spi_init(&sbi->sb_spi);
	sbi->sb_owner.uid = getuid();
	sbi->sb_owner.gid = getgid();
	sbi->sb_owner.pid = getpid();
	sbi->sb_owner.umask = 0002;
	sbi->sb_iconv = (iconv_t)(-1);
	sbi->sb_qalloc = sbi->sb_cache->c_qalloc;
	sbi->sb_ops.op_iopen_max = calc_iopen_limit(sbi->sb_cache);
	sbi->sb_ops.op_iopen = 0;
	sbi->sb_ops.op_time = voluta_time_now();
	sbi->sb_ops.op_count = 0;
	sbi->sb_ctl_flags = 0;
	sbi->sb_ms_flags = 0;
	sbi->sb_mntime = 0;
	return 0;
}

static void sbi_fini_commons(struct voluta_sb_info *sbi)
{
	spi_fini(&sbi->sb_spi);
	sbi->sb = NULL;
	sbi->sb_cache = NULL;
	sbi->sb_qalloc = NULL;
	sbi->sb_vstore = NULL;
	sbi->sb_ctl_flags = 0;
	sbi->sb_ms_flags = 0;
}

static int sbi_init_iti(struct voluta_sb_info *sbi)
{
	return voluta_iti_init(&sbi->sb_iti, sbi->sb_qalloc);
}

static void sbi_fini_iti(struct voluta_sb_info *sbi)
{
	voluta_iti_fini(&sbi->sb_iti);
}

static int sbi_init_iconv(struct voluta_sb_info *sbi)
{
	int err = 0;

	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	sbi->sb_iconv = iconv_open("UTF32LE", "UTF8");
	if (sbi->sb_iconv == (iconv_t)(-1)) {
		err = errno ? -errno : -ENOTSUP;
	}
	return err;
}

static void sbi_fini_iconv(struct voluta_sb_info *sbi)
{
	if (sbi->sb_iconv == (iconv_t)(-1)) {
		iconv_close(sbi->sb_iconv);
		sbi->sb_iconv = (iconv_t)(-1);
	}
}

static int sbi_init_subs(struct voluta_sb_info *sbi)
{
	int err;

	err = sbi_init_iti(sbi);
	if (err) {
		return err;
	}
	err = sbi_init_iconv(sbi);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_sbi_init(struct voluta_sb_info *sbi,
		    struct voluta_super_block *sb,
		    struct voluta_cache *cache, struct voluta_vstore *vstore)
{
	int err;

	sbi->sb = sb;
	sbi->sb_cache = cache;
	sbi->sb_vstore = vstore;

	err = sbi_init_commons(sbi);
	if (err) {
		return err;
	}
	err = sbi_init_subs(sbi);
	if (err) {
		voluta_sbi_fini(sbi);
		return err;
	}
	return 0;
}

void voluta_sbi_fini(struct voluta_sb_info *sbi)
{
	sbi_fini_iconv(sbi);
	sbi_fini_iti(sbi);
	sbi_fini_commons(sbi);
}

void voluta_sbi_setowner(struct voluta_sb_info *sbi,
			 const struct voluta_ucred *cred)
{
	sbi->sb_owner.uid = cred->uid;
	sbi->sb_owner.gid = cred->gid;
	sbi->sb_owner.pid = cred->pid;
	sbi->sb_owner.umask = cred->umask;
}

void voluta_sbi_setspace(struct voluta_sb_info *sbi, loff_t sp_size)
{
	spi_setup(&sbi->sb_spi, sp_size);
}

void voluta_sbi_add_ctlflags(struct voluta_sb_info *sbi, enum voluta_flags f)
{
	sbi->sb_ctl_flags |= f;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stage_agmap_of(struct voluta_sb_info *sbi,
			  const struct voluta_vaddr *vaddr,
			  struct voluta_vnode_info **out_vi)
{
	return stage_agmap(sbi, vaddr_ag_index(vaddr), out_vi);
}

static int fetch_agmap_of(struct voluta_super_ctx *s_ctx,
			  const struct voluta_vaddr *vaddr)
{
	return stage_agmap_of(s_ctx->sbi, vaddr, &s_ctx->agm_vi);
}

static int require_stable_at(const struct voluta_super_ctx *s_ctx,
			     const struct voluta_vaddr *vaddr)
{
	const enum voluta_vtype vtype = vtype_at(s_ctx->agm_vi, vaddr);

	return vtype_isequal(vtype, vaddr->vtype) ? 0 : -EFSCORRUPTED;
}

static int fetch_parents_of(struct voluta_super_ctx *s_ctx,
			    const struct voluta_vaddr *vaddr)
{
	int err;

	err = fetch_bki_of(s_ctx, vaddr);
	if (err) {
		return err;
	}
	if (vtype_isumap(vaddr->vtype)) {
		return 0;
	}
	err = fetch_agmap_of(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = require_stable_at(s_ctx, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int commit_last(const struct voluta_sb_info *sbi, int flags)
{
	int err = 0;

	if (flags & VOLUTA_F_NOW) {
		err = voluta_vstore_sync(sbi->sb_vstore);
	}
	return err;
}

int voluta_flush_dirty(struct voluta_sb_info *sbi, int flags)
{
	int err;
	bool need_flush;

	need_flush = voluta_cache_need_flush(sbi->sb_cache, flags);
	if (!need_flush) {
		return 0;
	}
	err = voluta_vstore_flush(sbi->sb_vstore, sbi->sb_cache, 0);
	if (err) {
		return err;
	}
	err = commit_last(sbi, flags);
	if (err) {
		return err;
	}
	return err;
}

int voluta_flush_dirty_of(const struct voluta_inode_info *ii, int flags)
{
	int err;
	bool need_flush;
	struct voluta_sb_info *sbi = ii_sbi(ii);
	const long ds_key = ii->i_vi.v_ds_key;

	need_flush = voluta_cache_need_flush_of(sbi->sb_cache, ii, flags);
	if (!need_flush) {
		return 0;
	}
	err = voluta_vstore_flush(sbi->sb_vstore, sbi->sb_cache, ds_key);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stage_meta(struct voluta_super_ctx *s_ctx,
		      const struct voluta_vaddr *vaddr,
		      struct voluta_vnode_info **out_vi)
{
	int err;

	err = stage_vnode(s_ctx, vaddr);
	*out_vi = s_ctx->vi;
	return err;
}

static int stage_hsmap(struct voluta_sb_info *sbi, size_t hs_index,
		       struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr vaddr;
	struct voluta_super_ctx s_ctx = { .sbi = sbi, };

	voluta_vaddr_of_hsmap(&vaddr, hs_index);
	return stage_meta(&s_ctx, &vaddr, out_vi);
}

static int stage_hsmap_of(struct voluta_sb_info *sbi,
			  const struct voluta_vaddr *vaddr,
			  struct voluta_vnode_info **out_vi)
{
	return stage_hsmap(sbi, vaddr_hs_index(vaddr), out_vi);
}

static bool equal_space_stat(const struct voluta_space_stat *sp_st1,
			     const struct voluta_space_stat *sp_st2)
{
	voluta_assert_eq(sp_st1->ndata, sp_st2->ndata);
	voluta_assert_eq(sp_st1->nmeta, sp_st2->nmeta);
	voluta_assert_eq(sp_st1->nfiles, sp_st2->nfiles);

	return (sp_st1->ndata == sp_st2->ndata) &&
	       (sp_st1->nmeta == sp_st2->nmeta) &&
	       (sp_st1->nfiles == sp_st2->nfiles);
}

static int verify_agm_stat(struct voluta_vnode_info *agm_vi)
{
	const size_t ag_index = vi_ag_index(agm_vi);
	const struct voluta_vnode_info *hsm_vi = agm_vi->v_pvi;
	struct voluta_space_stat hsm_sp_st = { .zero = 0 };
	struct voluta_space_stat agm_sp_st = { .zero = 0 };

	if (agm_vi->v_verify > 1) {
		return 0;
	}
	hsm_space_stat_of(hsm_vi->vu.hsm, ag_index, &hsm_sp_st);
	agm_calc_space_stat(agm_vi->vu.agm, &agm_sp_st);

	if (!equal_space_stat(&hsm_sp_st, &agm_sp_st)) {
		return -EFSCORRUPTED;
	}
	agm_vi->v_verify++;
	return 0;
}

static int stage_agmap(struct voluta_sb_info *sbi, size_t ag_index,
		       struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *agm_vi = NULL;
	struct voluta_super_ctx s_ctx = { .sbi = sbi };

	voluta_vaddr_of_agmap(&vaddr, ag_index);
	err = unlimit_agmap_on_pstore(sbi, ag_index);
	if (err) {
		return err;
	}
	err = stage_hsmap_of(sbi, &vaddr, &s_ctx.hsm_vi);
	if (err) {
		return err;
	}
	err = stage_meta(&s_ctx, &vaddr, &agm_vi);
	if (err) {
		return err;
	}
	err = verify_agm_stat(agm_vi);
	if (err) {
		/* TODO: cleanups */
		return err;
	}
	*out_vi = agm_vi;
	return 0;
}

static int spawn_vnode(struct voluta_super_ctx *s_ctx,
		       const struct voluta_vaddr *vaddr)
{
	int err;

	err = fetch_parents_of(s_ctx, vaddr);
	if (err) {
		return err;
	}
	err = spawn_bind_vi(s_ctx, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int find_cached_ii(struct voluta_super_ctx *s_ctx,
			  const struct voluta_iaddr *iaddr)
{
	s_ctx->ii = voluta_cache_lookup_ii(cache_of(s_ctx), iaddr);
	return (s_ctx->ii != NULL) ? 0 : -ENOENT;
}

static int resolve_iaddr(struct voluta_super_ctx *s_ctx, ino_t ino,
			 struct voluta_iaddr *out_iattr)
{
	return voluta_resolve_ino(s_ctx->sbi, ino, out_iattr);
}

static int fetch_inode_at(struct voluta_super_ctx *s_ctx,
			  const struct voluta_iaddr *iaddr)
{
	int err;

	err = find_cached_ii(s_ctx, iaddr);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bind_ii(s_ctx, iaddr);
	if (err) {
		return err;
	}
	err = decrypt_vnode(s_ctx);
	if (err) {
		return err;
	}
	err = review_vnode(s_ctx);
	if (err) {
		forget_cached_ii(s_ctx);
		return err;
	}
	voluta_refresh_atime(s_ctx->ii, true);
	return 0;
}

static int fetch_inode(struct voluta_super_ctx *s_ctx, ino_t ino)
{
	int err;
	struct voluta_iaddr iaddr;

	err = resolve_iaddr(s_ctx, ino, &iaddr);
	if (err) {
		return err;
	}
	err = fetch_inode_at(s_ctx, &iaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int check_writable_fs(const struct voluta_super_ctx *s_ctx)
{
	const unsigned long mask = MS_RDONLY;
	const struct voluta_sb_info *sbi = s_ctx->sbi;

	return ((sbi->sb_ms_flags & mask) == mask) ? -EROFS : 0;
}

static int stage_inode(struct voluta_super_ctx *s_ctx, ino_t ino)
{
	int err;

	err = check_writable_fs(s_ctx);
	if (err) {
		return err;
	}
	err = fetch_inode(s_ctx, ino);
	if (err) {
		return err;
	}
	if (ii_isrdonly(s_ctx->ii)) {
		return -EROFS;
	}
	return 0;
}

static int resolve_real_ino(struct voluta_super_ctx *s_ctx,
			    ino_t xino, ino_t *out_ino)
{
	return voluta_real_ino(s_ctx->sbi, xino, out_ino);
}

int voluta_fetch_inode(struct voluta_sb_info *sbi, ino_t xino,
		       struct voluta_inode_info **out_ii)
{
	int err;
	ino_t ino;
	struct voluta_super_ctx s_ctx = { .sbi = sbi };

	err = resolve_real_ino(&s_ctx, xino, &ino);
	if (err) {
		return err;
	}
	err = fetch_inode(&s_ctx, ino);
	if (err) {
		return err;
	}
	*out_ii = s_ctx.ii;
	return 0;
}

int voluta_stage_inode(struct voluta_sb_info *sbi, ino_t xino,
		       struct voluta_inode_info **out_ii)
{
	int err;
	ino_t ino;
	struct voluta_super_ctx s_ctx = { .sbi = sbi };

	err = resolve_real_ino(&s_ctx, xino, &ino);
	if (err) {
		return err;
	}
	err = stage_inode(&s_ctx, ino);
	if (err) {
		return err;
	}
	*out_ii = s_ctx.ii;
	return 0;
}

int voluta_fetch_vnode(struct voluta_sb_info *sbi,
		       const struct voluta_vaddr *vaddr,
		       struct voluta_inode_info *pii,
		       struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_super_ctx s_ctx = {
		.sbi = sbi,
		.pii = pii,
	};

	err = stage_vnode(&s_ctx, vaddr);
	if (err) {
		return err;
	}
	*out_vi = s_ctx.vi;
	return 0;
}

int voluta_stage_data(struct voluta_sb_info *sbi,
		      const struct voluta_vaddr *vaddr,
		      struct voluta_inode_info *pii,
		      struct voluta_vnode_info **out_vi)
{
	voluta_assert(vaddr_isdata(vaddr));
	voluta_assert_not_null(pii);

	return voluta_fetch_vnode(sbi, vaddr, pii, out_vi);
}

static int check_avail_space(struct voluta_sb_info *sbi,
			     enum voluta_vtype vtype)
{
	bool ok;
	const bool new_file = vtype_isinode(vtype);
	const size_t nbytes = vtype_size(vtype);

	if (vtype_isdata(vtype)) {
		ok = spi_may_alloc_data(&sbi->sb_spi, nbytes);
	} else {
		ok = spi_may_alloc_meta(&sbi->sb_spi, nbytes, new_file);
	}
	return ok ? 0 : -ENOSPC;
}

static int allocate_vnode_space(struct voluta_super_ctx *s_ctx,
				enum voluta_vtype vtype,
				struct voluta_vaddr *out_vaddr)
{
	int err;

	err = check_avail_space(s_ctx->sbi, vtype);
	if (err) {
		return err;
	}
	err = allocate_space(s_ctx, vtype, out_vaddr);
	if (err) {
		/* TODO: cleanup */
		return err;
	}
	if (!vaddr_isdata(out_vaddr)) {
		voluta_clear_unwritten(s_ctx->sbi, out_vaddr);
	}
	update_space_stat(s_ctx->sbi, 1, out_vaddr);
	return 0;
}

static int alloc_ispace(struct voluta_super_ctx *s_ctx,
			struct voluta_vaddr *out_vaddr)
{
	return allocate_vnode_space(s_ctx, VOLUTA_VTYPE_INODE, out_vaddr);
}

int voluta_create_vspace(struct voluta_sb_info *sbi,
			 enum voluta_vtype vtype,
			 struct voluta_vaddr *out_vaddr)
{
	struct voluta_super_ctx s_ctx = { .sbi = sbi };

	return allocate_vnode_space(&s_ctx, vtype, out_vaddr);
}

static int require_supported_itype(mode_t mode)
{
	const mode_t sup = S_IFDIR | S_IFREG | S_IFLNK |
			   S_IFSOCK | S_IFIFO | S_IFCHR | S_IFBLK;

	return (((mode & S_IFMT) | sup) == sup) ? 0 : -ENOTSUP;
}

static int acquire_ino(struct voluta_super_ctx *s_ctx,
		       const struct voluta_vaddr *vaddr,
		       struct voluta_iaddr *out_iaddr)
{
	int err;
	struct voluta_vnode_info *hsm_vi = NULL;
	struct voluta_vnode_info *agm_vi = NULL;
	struct voluta_sb_info *sbi = s_ctx->sbi;

	err = voluta_acquire_ino(sbi, vaddr, out_iaddr);
	if (err) {
		return err;
	}
	err = stage_hsmap_of(sbi, vaddr, &hsm_vi);
	if (err) {
		return err;
	}
	err = stage_agmap_of(sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	return 0;
}

static void setup_new_inode(struct voluta_super_ctx *s_ctx,
			    const struct voluta_oper *op,
			    mode_t mode, ino_t parent, dev_t rdev)
{
	vi_stamp_view(s_ctx->vi);
	voluta_setup_inode(s_ctx->ii, &op->ucred, mode, parent, rdev);
	update_itimes(op, s_ctx->ii, VOLUTA_IATTR_TIMES);
}

static int create_inode(struct voluta_super_ctx *s_ctx,
			const struct voluta_oper *op,
			mode_t mode, ino_t parent, dev_t rdev)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_iaddr iaddr;

	vaddr_reset(&vaddr);
	err = alloc_ispace(s_ctx, &vaddr);
	if (err) {
		return err;
	}
	err = acquire_ino(s_ctx, &vaddr, &iaddr);
	if (err) {
		return err;
	}
	err = spawn_bind_ii(s_ctx, &iaddr);
	if (err) {
		/* TODO: spfree inode from ag */
		return err;
	}
	setup_new_inode(s_ctx, op, mode, parent, rdev);
	return 0;
}

int voluta_create_inode(struct voluta_sb_info *sbi,
			const struct voluta_oper *op,
			mode_t mode, ino_t parent, dev_t rdev,
			struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_super_ctx s_ctx = { .sbi = sbi, };

	err = require_supported_itype(mode);
	if (err) {
		return err;
	}
	err = create_inode(&s_ctx, op, mode, parent, rdev);
	if (err) {
		return err;
	}
	*out_ii = s_ctx.ii;
	return 0;
}

/* TODO: cleanups and resource reclaim upon failure in every path */
static int create_vnode(struct voluta_super_ctx *s_ctx,
			enum voluta_vtype vtype)
{
	int err;
	struct voluta_vaddr vaddr;

	vaddr_reset(&vaddr);
	err = allocate_vnode_space(s_ctx, vtype, &vaddr);
	if (err) {
		return err;
	}
	err = spawn_vnode(s_ctx, &vaddr);
	if (err) {
		/* TODO: spfree inode from ag */
		return err;
	}
	vi_stamp_view(s_ctx->vi);
	return 0;
}

int voluta_create_vnode(struct voluta_sb_info *sbi,
			struct voluta_inode_info *pii,
			enum voluta_vtype vtype,
			struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_super_ctx s_ctx = {
		.sbi = sbi,
		.pii = pii,
	};

	err = create_vnode(&s_ctx, vtype);
	if (err) {
		return err;
	}
	*out_vi = s_ctx.vi;
	return 0;
}

static int deallocate_vnode_space(struct voluta_sb_info *sbi,
				  const struct voluta_vaddr *vaddr)
{
	int err;

	err = deallocate_at(sbi, vaddr);
	if (err) {
		return err;
	}
	update_space_stat(sbi, -1, vaddr);
	return 0;
}

static int forgat_and_discard_inode(struct voluta_super_ctx *s_ctx,
				    const struct voluta_iaddr *iaddr)
{
	int err;

	err = voluta_discard_ino(s_ctx->sbi, iaddr->ino);
	if (err) {
		return err;
	}
	err = deallocate_vnode_space(s_ctx->sbi, &iaddr->vaddr);
	if (err) {
		return err;
	}
	forget_cached_ii(s_ctx);
	return 0;
}

static void iaddr_of(const struct voluta_inode_info *ii,
		     struct voluta_iaddr *iaddr)
{
	vaddr_copyto(ii_vaddr(ii), &iaddr->vaddr);
	iaddr->ino = ii_ino(ii);
}

int voluta_remove_inode(struct voluta_sb_info *sbi,
			struct voluta_inode_info *ii)
{
	struct voluta_iaddr iaddr;
	struct voluta_super_ctx s_ctx = {
		.sbi = sbi,
		.ii = ii,
	};

	iaddr_of(ii, &iaddr);
	return forgat_and_discard_inode(&s_ctx, &iaddr);
}

static void mark_opaque_at(struct voluta_sb_info *sbi,
			   const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_bk_info *bki = NULL;

	err = find_cached_bki(sbi, vaddr->lba, &bki);
	if (!err) {
		voluta_mark_opaque_at(bki, vaddr);
	}
}

static int free_vspace_at(struct voluta_sb_info *sbi,
			  const struct voluta_vaddr *vaddr)
{
	int err;

	err = deallocate_vnode_space(sbi, vaddr);
	if (err) {
		return err;
	}
	mark_opaque_at(sbi, vaddr);
	return 0;
}

int voluta_remove_vnode(struct voluta_sb_info *sbi,
			struct voluta_vnode_info *vi)
{
	int err;

	err = deallocate_vnode_space(sbi, vi_vaddr(vi));
	if (err) {
		return err;
	}
	voluta_mark_opaque(vi);
	forget_cached_vi(vi);
	return 0;
}

int voluta_remove_vnode_at(struct voluta_sb_info *sbi,
			   const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_super_ctx s_ctx = { .sbi = sbi };

	err = find_cached_vi(&s_ctx, vaddr);
	if (!err) {
		err = voluta_remove_vnode(s_ctx.sbi, s_ctx.vi);
	} else if (err == -ENOENT) {
		err = free_vspace_at(s_ctx.sbi, vaddr);
	}
	return err;
}

int voluta_probe_unwritten(struct voluta_sb_info *sbi,
			   const struct voluta_vaddr *vaddr, bool *out_res)
{
	int err;
	struct voluta_super_ctx s_ctx = { .sbi = sbi };

	err = fetch_agmap_of(&s_ctx, vaddr);
	if (err) {
		return err;
	}
	*out_res = has_unwritten_at(s_ctx.agm_vi, vaddr);
	return 0;
}

int voluta_clear_unwritten(struct voluta_sb_info *sbi,
			   const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *agm_vi = NULL;

	err = stage_agmap_of(sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	if (has_unwritten_at(agm_vi, vaddr)) {
		clear_unwritten_at(agm_vi, vaddr);
		vi_dirtify(agm_vi);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void kivam_of_hsmap(const struct voluta_vnode_info *vi,
			   struct voluta_kivam *out_kivam)
{
	size_t hs_index;
	const struct voluta_kivam *kivam;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);
	const struct voluta_super_block *sb = vi->v_sbi->sb;

	hs_index = vaddr_hs_index(vaddr);
	kivam = voluta_sb_kivam_of(sb, hs_index);
	voluta_kivam_copyto(kivam, out_kivam);

	voluta_kivam_xor_iv(out_kivam, vaddr->off, 0);
}

static void kivam_of_agmap(const struct voluta_vnode_info *vi,
			   struct voluta_kivam *out_kivam)
{
	size_t ag_index;
	uint64_t ag_seed;
	const struct voluta_kivam *kivam;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);
	const struct voluta_hspace_map *hsm = vi->v_pvi->vu.hsm;

	ag_index = vaddr_ag_index(vaddr);
	kivam = hsm_kivam_of(hsm, ag_index);
	voluta_kivam_copyto(kivam, out_kivam);

	ag_seed = hsm_seed_of(hsm, ag_index);
	voluta_kivam_xor_iv(out_kivam, vaddr->off, ag_seed);
}

static void kivam_of_normal(const struct voluta_vnode_info *vi,
			    struct voluta_kivam *out_kivam)
{
	loff_t lba;
	uint64_t bk_seed;
	const struct voluta_kivam *kivam;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);
	const struct voluta_agroup_map *agm = vi->v_pvi->vu.agm;

	lba = vaddr->lba;
	kivam = agm_kivam_of(agm, lba);
	voluta_kivam_copyto(kivam, out_kivam);

	bk_seed = agm_seed_of(agm, lba);
	voluta_kivam_xor_iv(out_kivam, vaddr->off, bk_seed);
}

void voluta_kivam_of(const struct voluta_vnode_info *vi,
		     struct voluta_kivam *out_kivam)
{
	const enum voluta_vtype vtype = vi_vtype(vi);

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		kivam_of_hsmap(vi, out_kivam);
		break;
	case VOLUTA_VTYPE_AGMAP:
		kivam_of_agmap(vi, out_kivam);
		break;
	case VOLUTA_VTYPE_ITNODE:
	case VOLUTA_VTYPE_INODE:
	case VOLUTA_VTYPE_XANODE:
	case VOLUTA_VTYPE_HTNODE:
	case VOLUTA_VTYPE_RTNODE:
	case VOLUTA_VTYPE_SYMVAL:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		kivam_of_normal(vi, out_kivam);
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		voluta_kivam_setup(out_kivam);
		break;
	}
}
