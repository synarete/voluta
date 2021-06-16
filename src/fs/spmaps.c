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
#include <limits.h>
#include <voluta/fs/types.h>
#include <voluta/fs/address.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/losdc.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/private.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static voluta_index_t index_to_cpu(uint64_t index)
{
	return voluta_le64_to_cpu(index);
}

static uint64_t cpu_to_index(voluta_index_t index)
{
	return voluta_cpu_to_le64(index);
}

static bool vtype_isdatabk(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_DATABK);
}

static enum voluta_agkind vtype_to_agkind(enum voluta_vtype vtype)
{
	return voluta_vtype_to_agkind(vtype);
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

static void bls_init(struct voluta_blobspec *bls)
{
	memset(bls, 0, sizeof(*bls));
}

static void bls_initn(struct voluta_blobspec *bls, size_t n)
{
	memset(bls, 0, n * sizeof(*bls));
}

static void bls_vaddr(const struct voluta_blobspec *bls,
                      struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&bls->vaddr, out_vaddr);
}

static void bls_set_vaddr(struct voluta_blobspec *bls,
                          const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&bls->vaddr, vaddr);
}

static void bls_set_blobid(struct voluta_blobspec *bls,
                           const struct voluta_blobid *bid)
{
	blobid_copyto(bid, &bls->blobid);
}

static void bls_to_baddr(const struct voluta_blobspec *bls,
                         struct voluta_baddr *out_baddr)
{
	voluta_baddr_assign(out_baddr, &bls->blobid);
}

static void bls_set_from_baddr(struct voluta_blobspec *bls,
                               const struct voluta_baddr *baddr)
{
	bls_set_blobid(bls, &baddr->bid);
}

static void bls_vba(const struct voluta_blobspec *bls,
                    struct voluta_vba *out_vba)
{
	bls_vaddr(bls, &out_vba->vaddr);
	bls_to_baddr(bls, &out_vba->baddr);
}

static void bls_set_vba(struct voluta_blobspec *bls,
                        const struct voluta_vba *vba)
{
	bls_set_vaddr(bls, &vba->vaddr);
	bls_set_from_baddr(bls, &vba->baddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_usm_init(struct voluta_sb_uspace *usm)
{
	bls_initn(usm->us_hsm_bls, ARRAY_SIZE(usm->us_hsm_bls));
}

static size_t hs_index_to_us_slot(voluta_index_t hs_index)
{
	return hs_index % VOLUTA_NHS_IN_US;
}

static struct voluta_blobspec *
usm_blobspec_at(const struct voluta_sb_uspace *usm, size_t slot)
{
	const struct voluta_blobspec *bls = &usm->us_hsm_bls[slot];

	voluta_assert_lt(slot, ARRAY_SIZE(usm->us_hsm_bls));
	return unconst(bls);
}

static struct voluta_blobspec *
usm_blobspec_of(const struct voluta_sb_uspace *usm, voluta_index_t hs_index)
{
	const size_t slot = hs_index_to_us_slot(hs_index);

	return usm_blobspec_at(usm, slot);
}

void voluta_usm_vba(const struct voluta_sb_uspace *usm,
                    voluta_index_t hs_index, struct voluta_vba *out_vba)
{
	const struct voluta_blobspec *bls = usm_blobspec_of(usm, hs_index);

	bls_vba(bls, out_vba);
}

void voluta_usm_set_vba(struct voluta_sb_uspace *usm,
                        voluta_index_t hs_index,
                        const struct voluta_vba *vba)
{
	struct voluta_blobspec *bls = usm_blobspec_of(usm, hs_index);

	bls_set_vba(bls, vba);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t agr_used_meta(const struct voluta_ag_rec *agr)
{
	return voluta_le32_to_cpu(agr->ag_used_meta);
}

static void agr_set_used_meta(struct voluta_ag_rec *agr, size_t used_meta)
{
	agr->ag_used_meta = voluta_cpu_to_le32((uint32_t)used_meta);
}

static size_t agr_used_data(const struct voluta_ag_rec *agr)
{
	return voluta_le32_to_cpu(agr->ag_used_data);
}

static void agr_set_used_data(struct voluta_ag_rec *agr, size_t used_data)
{
	agr->ag_used_data = voluta_cpu_to_le32((uint32_t)used_data);
}

static size_t agr_nfiles(const struct voluta_ag_rec *agr)
{
	return voluta_le32_to_cpu(agr->ag_nfiles);
}

static void agr_set_nfiles(struct voluta_ag_rec *agr, size_t nfiles)
{
	voluta_assert_lt(nfiles, UINT32_MAX / 2);

	agr->ag_nfiles = voluta_cpu_to_le32((uint32_t)nfiles);
}

static enum voluta_agkind agr_kind(const struct voluta_ag_rec *agr)
{
	return voluta_le16_to_cpu(agr->ag_kind);
}

static void agr_set_kind(struct voluta_ag_rec *agr, enum voluta_agkind kind)
{
	agr->ag_kind = voluta_cpu_to_le16((uint16_t)kind);
}

static enum voluta_agf agr_flags(const struct voluta_ag_rec *agr)
{
	return voluta_le16_to_cpu(agr->ag_flags);
}

static void agr_set_flags(struct voluta_ag_rec *agr, enum voluta_agf f)
{
	agr->ag_flags = voluta_cpu_to_le16((uint16_t)f);
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

static void agr_bind_to_kind(struct voluta_ag_rec *agr,
                             enum voluta_vtype vtype)
{
	agr_set_kind(agr, vtype_to_agkind(vtype));
}

static bool agr_kind_fits_vtype(const struct voluta_ag_rec *agr,
                                enum voluta_vtype vtype)
{
	const enum voluta_agkind agkind = agr_kind(agr);

	return (agkind == VOLUTA_AGKIND_NONE) ||
	       (agkind == vtype_to_agkind(vtype));
}

static void agr_init(struct voluta_ag_rec *agr)
{
	agr_set_used_meta(agr, 0);
	agr_set_used_data(agr, 0);
	agr_set_nfiles(agr, 0);
	agr_set_kind(agr, VOLUTA_AGKIND_NONE);
	agr_set_flags(agr, 0);
	bls_init(&agr->ag_agm_bls);
	memset(agr->ag_reserved, 0, sizeof(agr->ag_reserved));
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

static void agr_agm_vba(const struct voluta_ag_rec *agr,
                        struct voluta_vba *out_vba)
{
	bls_vba(&agr->ag_agm_bls, out_vba);
}

static void agr_set_agm_vba(struct voluta_ag_rec *agr,
                            const struct voluta_vba *vba)
{
	bls_set_vba(&agr->ag_agm_bls, vba);
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
	return voluta_le32_to_cpu(hsm->hs_flags);
}

static void hsm_set_flags(struct voluta_hspace_map *hsm,
                          enum voluta_hsf flags)
{
	hsm->hs_flags = voluta_cpu_to_le32((uint32_t)flags);
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
	return voluta_le32_to_cpu(hsm->hs_nags_span);
}

static void hsm_set_nags_span(struct voluta_hspace_map *hsm, size_t nags)
{
	voluta_assert_le(nags, ARRAY_SIZE(hsm->hs_agr));

	hsm->hs_nags_span = voluta_cpu_to_le32((uint32_t)nags);
}

static size_t hsm_nags_form(const struct voluta_hspace_map *hsm)
{
	return voluta_le32_to_cpu(hsm->hs_nags_form);
}

static void hsm_set_nags_form(struct voluta_hspace_map *hsm, size_t nags_form)
{
	voluta_assert_le(nags_form, ARRAY_SIZE(hsm->hs_agr));

	hsm->hs_nags_form = voluta_cpu_to_le32((uint32_t)nags_form);
}

static void hsm_inc_nags_form(struct voluta_hspace_map *hsm)
{
	hsm_set_nags_form(hsm, hsm_nags_form(hsm) + 1);
}

static size_t hsm_nused(const struct voluta_hspace_map *hsm)
{
	return voluta_le64_to_cpu(hsm->hs_nused);
}

static void hsm_set_nused(struct voluta_hspace_map *hsm, size_t nused)
{
	voluta_assert_le(nused, VOLUTA_HS_SIZE);
	hsm->hs_nused = voluta_cpu_to_le64(nused);
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

static void hsm_init(struct voluta_hspace_map *hsm,
                     voluta_index_t hs_index, size_t nags_span)
{
	hsm_set_index(hsm, hs_index);
	hsm_set_flags(hsm, 0);
	hsm_set_nags_span(hsm, nags_span);
	hsm_set_nags_form(hsm, 0);
	hsm_set_nused(hsm, 0);
	agr_initn(hsm->hs_agr, ARRAY_SIZE(hsm->hs_agr));
}

static struct voluta_ag_rec *
hsm_ag_rec_at(const struct voluta_hspace_map *hsm, size_t slot)
{
	const struct voluta_ag_rec *agr = &hsm->hs_agr[slot];

	voluta_assert_lt(slot, ARRAY_SIZE(hsm->hs_agr));
	return unconst(agr);
}

static size_t ag_index_to_hs_slot(voluta_index_t ag_index)
{
	return ag_index % VOLUTA_NAG_IN_HS;
}

static struct voluta_ag_rec *
hsm_ag_rec_of(const struct voluta_hspace_map *hsm, voluta_index_t ag_index)
{
	const size_t slot = ag_index_to_hs_slot(ag_index);

	return hsm_ag_rec_at(hsm, slot);
}

static void hsm_agm_vba_of(const struct voluta_hspace_map *hsm,
                           voluta_index_t ag_index, struct voluta_vba *out_vba)
{
	const struct voluta_ag_rec *agr = hsm_ag_rec_of(hsm, ag_index);

	agr_agm_vba(agr, out_vba);
}

static void hsm_set_agm_vba_of(struct voluta_hspace_map *hsm,
                               voluta_index_t ag_index,
                               const struct voluta_vba *vba)
{
	struct voluta_ag_rec *agr = hsm_ag_rec_of(hsm, ag_index);

	agr_set_agm_vba(agr, vba);
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
	struct voluta_ag_rec *agr = hsm_ag_rec_of(hsm, ag_index);

	hsm_accum_stats_of(hsm, agr, sp_st);
}

static void hsm_space_stat_of(const struct voluta_hspace_map *hsm,
                              voluta_index_t ag_index,
                              struct voluta_space_stat *sp_st)
{
	const struct voluta_ag_rec *agr;

	agr = hsm_ag_rec_of(hsm, ag_index);
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
		agr = hsm_ag_rec_of(hsm, ag_index);
		agr_stat(agr, &sp_st);
		voluta_accum_space_stat(sp_st_total, &sp_st);
		ag_index++;
	}
}

static void hsm_set_formatted(struct voluta_hspace_map *hsm,
                              voluta_index_t ag_index)
{
	struct voluta_ag_rec *agr = hsm_ag_rec_of(hsm, ag_index);

	agr_set_formatted(agr);
}

static bool hsm_is_formatted(const struct voluta_hspace_map *hsm,
                             voluta_index_t ag_index)
{
	const struct voluta_ag_rec *agr = hsm_ag_rec_of(hsm, ag_index);

	return agr_is_formatted(agr);
}

static bool hsm_is_fragmented(struct voluta_hspace_map *hsm,
                              voluta_index_t ag_index)
{
	return agr_is_fragmented(hsm_ag_rec_of(hsm, ag_index));
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
	agr_set_fragmented(hsm_ag_rec_of(hsm, ag_index));
}

static void hsm_clear_fragmented(struct voluta_hspace_map *hsm,
                                 voluta_index_t ag_index)
{
	agr_unset_fragmented(hsm_ag_rec_of(hsm, ag_index));
}

static void hsm_bind_to_kind(struct voluta_hspace_map *hsm,
                             voluta_index_t ag_index, enum voluta_vtype vtype)
{
	agr_bind_to_kind(hsm_ag_rec_of(hsm, ag_index), vtype);
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
	const struct voluta_ag_rec *agr = hsm_ag_rec_of(hsm, ag_index);

	return agr_used_space(agr);
}

static voluta_index_t
hsm_find_avail(const struct voluta_hspace_map *hsm,
               const struct voluta_index_range *range,
               enum voluta_vtype vtype)
{
	size_t nags_iter;
	voluta_index_t ag_index;
	const struct voluta_ag_rec *agr = NULL;
	const size_t nags_span = hsm_nags_span(hsm);

	ag_index = range->beg;
	nags_iter = min(nags_span, range->end - range->beg);
	while ((ag_index < range->end) && nags_iter--) {
		agr = hsm_ag_rec_of(hsm, ag_index);
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

static void bkr_set_flags(struct voluta_bk_rec *bkr, uint32_t f)
{
	bkr->bk_flags = voluta_cpu_to_le32(f);
}

static size_t bkr_refcnt(const struct voluta_bk_rec *bkr)
{
	return voluta_le64_to_cpu(bkr->bk_refcnt);
}

static void bkr_set_refcnt(struct voluta_bk_rec *bkr, size_t refcnt)
{
	voluta_assert_le(refcnt, VOLUTA_NKB_IN_BK);

	bkr->bk_refcnt = voluta_cpu_to_le64(refcnt);
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
	return voluta_le64_to_cpu(bkr->bk_allocated);
}

static void bkr_set_allocated(struct voluta_bk_rec *bkr, uint64_t allocated)
{
	bkr->bk_allocated = voluta_cpu_to_le64(allocated);
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
	return voluta_le64_to_cpu(bkr->bk_unwritten);
}

static void bkr_set_unwritten(struct voluta_bk_rec *bkr, uint64_t unwritten)
{
	bkr->bk_unwritten = voluta_cpu_to_le64(unwritten);
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

static void agm_init(struct voluta_agroup_map *agm, voluta_index_t ag_index)
{
	STATICASSERT_EQ(sizeof(agm->ag_bkr[0]), 56);
	STATICASSERT_EQ(sizeof(*agm), VOLUTA_BK_SIZE);

	agm_set_index(agm, ag_index);
	voluta_blobid_reset(&agm->ag_bks_blobid);
	bkr_init_arr(agm->ag_bkr, ARRAY_SIZE(agm->ag_bkr));
}

static void agm_bks_blobid(const struct voluta_agroup_map *agm,
                           struct voluta_blobid *out_blobid)
{
	blobid_copyto(&agm->ag_bks_blobid, out_blobid);
}

static void agm_set_bks_blobid(struct voluta_agroup_map *agm,
                               const struct voluta_blobid *bid)
{
	blobid_copyto(bid, &agm->ag_bks_blobid);
}

static struct voluta_bk_rec *
agm_bkr_at(const struct voluta_agroup_map *agm, size_t slot)
{
	const struct voluta_bk_rec *bkr = &(agm->ag_bkr[slot]);

	voluta_assert_lt(slot, ARRAY_SIZE(agm->ag_bkr));
	return unconst(bkr);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct voluta_hspace_map *
hspace_map_of(const struct voluta_hspace_info *hsi)
{
	voluta_assert_not_null(hsi->hs_vi.vu.hsm);

	return hsi->hs_vi.vu.hsm;
}

static void hsi_dirtify(struct voluta_hspace_info *hsi)
{
	vi_dirtify(hsi_vi(hsi));
}

void voluta_hsi_set_index(struct voluta_hspace_info *hsi,
                          voluta_index_t hs_index)
{
	voluta_assert_gt(hs_index, 0);
	hsi->hs_index = hs_index;
}

void voluta_hsi_setup(struct voluta_hspace_info *hsi,
                      voluta_index_t hs_index, size_t nags_span)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	voluta_hsi_set_index(hsi, hs_index);
	hsm_init(hsm, hs_index, nags_span);
}

void voluta_hsi_vba(const struct voluta_hspace_info *hsi,
                    struct voluta_vba *out_vba)
{
	voluta_vba_setup(out_vba, hsi_vaddr(hsi), hsi_baddr(hsi));
}

static size_t
nused_bytes_at(const struct voluta_hspace_info *hsi, voluta_index_t ag_index)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	return hsm_used_space_of(hsm, ag_index);
}

static size_t
nused_bks_at(const struct voluta_hspace_info *hsi, size_t ag_index)
{
	const size_t nused_bytes = nused_bytes_at(hsi, ag_index);

	return nused_bytes / VOLUTA_BK_SIZE;
}

static size_t start_bn_of(const struct voluta_hspace_info *hsi,
                          voluta_index_t ag_index, enum voluta_vtype vtype)
{
	size_t bn;
	const size_t nbk_in_ag = VOLUTA_NBK_IN_AG;

	/* Heuristic for mostly append pattern */
	bn = nused_bks_at(hsi, ag_index);

	/* In case of full data-block align to higher */
	if (bn && vtype_isdatabk(vtype)) {
		bn = voluta_min(bn + 1, nbk_in_ag - 1);
	}
	return bn;
}

int voluta_hsi_search_avail_ag(const struct voluta_hspace_info *hsi,
                               const struct voluta_index_range *range,
                               enum voluta_vtype vtype,
                               voluta_index_t *out_ag_index,
                               size_t *out_bn_within_ag)
{
	size_t ag_index;
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	ag_index = hsm_find_avail(hsm, range, vtype);
	if (ag_index_isnull(ag_index)) {
		return -ENOSPC;
	}
	*out_ag_index = ag_index;
	*out_bn_within_ag = start_bn_of(hsi, ag_index, vtype);
	return 0;
}

void voluta_mark_with_next(struct voluta_hspace_info *hsi)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	if (!hsm_test_hasnext(hsm)) {
		hsm_add_hasnext(hsm);
		hsi_dirtify(hsi);
	}
}

bool voluta_has_next_hspace(const struct voluta_hspace_info *hsi)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	return hsm_test_hasnext(hsm);
}

void voluta_hsi_update_space(struct voluta_hspace_info *hsi,
                             voluta_index_t ag_index,
                             const struct voluta_space_stat *sp_st)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	hsm_accum_stats(hsm, ag_index, sp_st);
	hsi_dirtify(hsi);
}

void voluta_hsi_space_stat_at(const struct voluta_hspace_info *hsi,
                              voluta_index_t ag_index,
                              struct voluta_space_stat *sp_st)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	hsm_space_stat_of(hsm, ag_index, sp_st);
}

void voluta_hsi_space_stat_of(const struct voluta_hspace_info *hsi,
                              struct voluta_space_stat *sp_st)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	hsm_space_stat(hsm, sp_st);
}

void voluta_hsi_set_formatted_ag(struct voluta_hspace_info *hsi,
                                 voluta_index_t ag_index,
                                 const struct voluta_vba *agm_vba)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	voluta_assert_lt(agm_vba->vaddr.ag_index, ag_index);
	voluta_assert(!hsm_is_formatted(hsm, ag_index));

	hsm_set_agm_vba_of(hsm, ag_index, agm_vba);
	hsm_set_formatted(hsm, ag_index);
	hsm_inc_nags_form(hsm);
	hsi_dirtify(hsi);
}

bool voluta_hsi_has_formatted_ag(const struct voluta_hspace_info *hsi,
                                 voluta_index_t ag_index)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	return hsm_is_formatted(hsm, ag_index);
}

void voluta_hsi_ag_span_of(const struct voluta_hspace_info *hsi,
                           struct voluta_ag_span *ag_span)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	ag_span->beg = hsm_ag_index_beg(hsm);
	ag_span->tip = hsm_ag_index_tip(hsm);
	ag_span->fin = hsm_ag_index_fin(hsm);
	ag_span->end = hsm_ag_index_end(hsm);
}

void voluta_hsi_mark_fragmented_at(struct voluta_hspace_info *hsi,
                                   voluta_index_t ag_index)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	hsm_mark_fragmented(hsm, ag_index);
	hsi_dirtify(hsi);
}

void voluta_hsi_clear_fragmented_at(struct voluta_hspace_info *hsi,
                                    voluta_index_t ag_index)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	hsm_clear_fragmented(hsm, ag_index);
	hsi_dirtify(hsi);
}

bool voluta_hsi_fragmented_by(const struct voluta_hspace_info *hsi,
                              const struct voluta_vaddr *vaddr)
{
	const voluta_index_t ag_index = vaddr->ag_index;
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	return (hsm_is_fragmented(hsm, ag_index) && (nkb_of(vaddr) > 1));
}

void voluta_hsi_bind_to_kindof(struct voluta_hspace_info *hsi,
                               const struct voluta_vaddr *vaddr)
{
	struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	hsm_bind_to_kind(hsm, vaddr->ag_index, vaddr->vtype);
	hsi_dirtify(hsi);
}

int voluta_hsi_check_cap_alloc(const struct voluta_hspace_info *hsi,
                               const enum voluta_vtype vtype)
{
	const size_t nbytes = vtype_size(vtype);
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	return hsm_may_alloc(hsm, nbytes) ? 0 : -ENOSPC;
}

void voluta_resolve_ag(const struct voluta_hspace_info *hsi,
                       voluta_index_t ag_index, struct voluta_vba *out_agm_vba)
{
	const struct voluta_hspace_map *hsm = hspace_map_of(hsi);

	hsm_agm_vba_of(hsm, ag_index, out_agm_vba);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_agroup_map *
agroup_map_of(const struct voluta_agroup_info *agi)
{
	return agi->ag_vi.vu.agm;
}

void voluta_agi_dirtify(struct voluta_agroup_info *agi)
{
	vi_dirtify(agi_vi(agi));
}

void voluta_agi_set_index(struct voluta_agroup_info *agi,
                          voluta_index_t ag_index)
{
	voluta_assert_gt(ag_index, 0);
	agi->ag_index = ag_index;
}

void voluta_agi_setup(struct voluta_agroup_info *agi,
                      voluta_index_t ag_index)
{
	struct voluta_agroup_map *agm = agroup_map_of(agi);

	voluta_agi_set_index(agi, ag_index);
	agm_init(agm, ag_index);
}

void voluta_agi_vba(const struct voluta_agroup_info *agi,
                    struct voluta_vba *out_vba)
{
	voluta_vba_setup(out_vba, agi_vaddr(agi), agi_baddr(agi));
}

void voluta_agi_set_bks_blobid(struct voluta_agroup_info *agi,
                               const struct voluta_blobid *bid)
{
	struct voluta_agroup_map *agm = agroup_map_of(agi);

	agm_set_bks_blobid(agm, bid);
}

void voluta_agi_resolve_vba(const struct voluta_agroup_info *agi,
                            const struct voluta_vaddr *vaddr,
                            struct voluta_vba *out_vba)
{
	struct voluta_blobid bid;
	const struct voluta_agroup_map *agm = agroup_map_of(agi);

	agm_bks_blobid(agm, &bid);
	voluta_vba_setup_by(out_vba, vaddr, &bid);
}

int voluta_agi_find_free_space(const struct voluta_agroup_info *agi,
                               enum voluta_vtype vtype, size_t bn_start_hint,
                               struct voluta_vba *out_vba)
{
	int err;
	struct voluta_vaddr vaddr;
	const struct voluta_agroup_map *agm = agroup_map_of(agi);

	err = agm_find_free_space(agm, vtype, bn_start_hint, &vaddr);
	if (err) {
		return err;
	}
	voluta_agi_resolve_vba(agi, &vaddr, out_vba);
	return 0;
}

void voluta_agi_mark_allocated_space(struct voluta_agroup_info *agi,
                                     const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agi);

	agm_set_allocated_at(agm, vaddr);
	if (vaddr_isdata(vaddr)) {
		agm_set_unwritten_at(agm, vaddr);
	}
	agi_dirtify(agi);
}

void voluta_agi_clear_allocated_space(struct voluta_agroup_info *agi,
                                      const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agi);

	voluta_assert_eq(agm_index(agm), vaddr->ag_index);

	agm_clear_allocated_at(agm, vaddr);
	agm_renew_if_unused(agm, vaddr);
	agi_dirtify(agi);
}

size_t voluta_block_refcnt_at(const struct voluta_agroup_info *agi,
                              const struct voluta_vaddr *vaddr)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agi);

	return agm_refcnt_at(agm, vaddr);
}

bool voluta_has_lone_refcnt(const struct voluta_agroup_info *agi,
                            const struct voluta_vaddr *vaddr)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agi);

	return agm_last_refcnt_at(agm, vaddr);
}

void voluta_calc_space_stat_of(const struct voluta_agroup_info *agi,
                               struct voluta_space_stat *out_sp_st)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agi);

	agm_calc_space_stat(agm, out_sp_st);
}

bool voluta_agi_is_allocated_with(const struct voluta_agroup_info *agi,
                                  const struct voluta_vaddr *vaddr)
{
	enum voluta_vtype vtype;
	const struct voluta_agroup_map *agm = agroup_map_of(agi);

	vtype = agm_vtype_at(agm, vaddr);
	return vtype_isequal(vtype, vaddr->vtype);
}

bool voluta_agi_has_unwritten_at(const struct voluta_agroup_info *agi,
                                 const struct voluta_vaddr *vaddr)
{
	const struct voluta_agroup_map *agm = agroup_map_of(agi);

	return agm_test_unwritten_at(agm, vaddr);
}

void voluta_agi_clear_unwritten_at(struct voluta_agroup_info *agi,
                                   const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agi);

	if (agm_test_unwritten_at(agm, vaddr)) {
		agm_clear_unwritten_at(agm, vaddr);
		agi_dirtify(agi);
	}
}

void voluta_agi_mark_unwritten_at(struct voluta_agroup_info *agi,
                                  const struct voluta_vaddr *vaddr)
{
	struct voluta_agroup_map *agm = agroup_map_of(agi);

	if (!agm_test_unwritten_at(agm, vaddr)) {
		agm_set_unwritten_at(agm, vaddr);
		agi_dirtify(agi);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_vtype(enum voluta_vtype vtype)
{
	switch (vtype) {
	case VOLUTA_VTYPE_NONE:
	case VOLUTA_VTYPE_SUPER:
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
	case VOLUTA_VTYPE_AGBKS:
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

