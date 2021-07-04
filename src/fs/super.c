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
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <limits.h>
#include <voluta/fs/types.h>
#include <voluta/fs/address.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/crypto.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/locosd.h>
#include <voluta/fs/super.h>
#include <voluta/fs/superb.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/itable.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/private.h>

struct voluta_spalloc_ctx {
	struct voluta_hspace_info *hsi;
	struct voluta_agroup_info *agi;
	struct voluta_vba vba;
	enum voluta_vtype vtype;
	bool first_alloc;
};


static int format_head_spmaps_of(struct voluta_sb_info *sbi,
                                 voluta_index_t hs_index);
static int format_next_agmap(struct voluta_sb_info *sbi,
                             struct voluta_hspace_info *hsi);
static int stage_hsmap(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                       struct voluta_hspace_info **out_vi);
static int stage_agmap(struct voluta_sb_info *sbi, voluta_index_t ag_index,
                       struct voluta_agroup_info **out_agi);
static int stage_agmap_of(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_agroup_info **out_agi);
static int stage_parents_of(struct voluta_sb_info *sbi,
                            const struct voluta_vba *vba,
                            struct voluta_agroup_info **out_agi,
                            struct voluta_bksec_info **out_bsi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_cache *cache_of(const struct voluta_sb_info *sbi)
{
	return sbi->sb_cache;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spi_init(struct voluta_space_info *spi)
{
	spi->sp_capcity_size = -1;
	spi->sp_hs_count = 0;
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 0;
	spi->sp_ag_count = 0;
	spi->sp_used.nmeta = 0;
	spi->sp_used.ndata = 0;
	spi->sp_used.nfiles = 0;
}

static void spi_fini(struct voluta_space_info *spi)
{
	spi->sp_capcity_size = -1;
	spi->sp_hs_count = 0;
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 0;
	spi->sp_ag_count = 0;
	spi->sp_used.nmeta = INT_MIN;
	spi->sp_used.ndata = INT_MIN;
	spi->sp_used.nfiles = INT_MIN;
}

static void spi_setup(struct voluta_space_info *spi, loff_t capacity_size)
{
	const loff_t address_space = capacity_size + VOLUTA_HS_SIZE;

	spi->sp_capcity_size = capacity_size;
	spi->sp_ag_count = nbytes_to_ag_count(address_space);
	spi->sp_hs_count = div_round_up(spi->sp_ag_count, VOLUTA_NAG_IN_HS);
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 1;
	spi->sp_used.nmeta = VOLUTA_SB_SIZE;
}

static void spi_mark_hs_active(struct voluta_space_info *spi,
                               voluta_index_t hs_index)
{
	spi->sp_hs_active = max(hs_index, spi->sp_hs_active);
}

static void spi_accum_stat(struct voluta_space_info *spi,
                           const struct voluta_space_stat *sp_st)
{
	voluta_accum_space_stat(&spi->sp_used, sp_st);

	voluta_assert_ge(spi->sp_used.ndata, 0);
	voluta_assert_ge(spi->sp_used.nmeta, 0);
	voluta_assert_ge(spi->sp_used.nfiles, 0);
}

static ssize_t spi_used_bytes(const struct voluta_space_info *spi)
{
	return spi->sp_used.nmeta + spi->sp_used.ndata;
}

static ssize_t spi_space_limit(const struct voluta_space_info *spi)
{
	return spi->sp_capcity_size;
}

static ssize_t spi_inodes_limit(const struct voluta_space_info *spi)
{
	const ssize_t inode_size = VOLUTA_INODE_SIZE;

	return (spi_space_limit(spi) / inode_size) >> 2;
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
		files_max = spi_inodes_limit(spi);
		ret = (spi->sp_used.nfiles < files_max);
	}
	return ret;
}

static void spi_update_stats(struct voluta_space_info *spi,
                             voluta_index_t hs_index,
                             const struct voluta_space_stat *sp_st)
{
	ssize_t nbytes_dif;
	ssize_t nbytes_max;
	ssize_t nbytes_use;

	voluta_accum_space_stat(&spi->sp_used, sp_st);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vi_isvisible(const struct voluta_vnode_info *vi)
{
	return voluta_bsi_is_visible_at(vi->v_bsi, vi_vaddr(vi));
}

static void vi_mark_visible(const struct voluta_vnode_info *vi)
{
	voluta_bsi_mark_visible_at(vi->v_bsi, vi_vaddr(vi));
}

static void vi_stamp_mark_visible(struct voluta_vnode_info *vi)
{
	voluta_vi_stamp_view(vi);
	vi_mark_visible(vi);
	vi_dirtify(vi);
}


static void hsi_incref(struct voluta_hspace_info *hsi)
{
	vi_incref(hsi_vi(hsi));
}

static void hsi_decref(struct voluta_hspace_info *hsi)
{
	vi_decref(hsi_vi(hsi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	const ssize_t nfiles_max = spi_inodes_limit(spi);

	voluta_assert_ge(nbytes_max, nbytes_use);
	voluta_assert_ge(nfiles_max, spi->sp_used.nfiles);

	voluta_memzero(out_stvfs, sizeof(*out_stvfs));
	out_stvfs->f_bsize = VOLUTA_BK_SIZE;
	out_stvfs->f_frsize = VOLUTA_KB_SIZE;
	out_stvfs->f_blocks = bytes_to_fsblkcnt(nbytes_max);
	out_stvfs->f_bfree = bytes_to_fsblkcnt(nbytes_max - nbytes_use);
	out_stvfs->f_bavail = out_stvfs->f_bfree;
	out_stvfs->f_files = (fsfilcnt_t)nfiles_max;
	out_stvfs->f_ffree = (fsfilcnt_t)(nfiles_max - spi->sp_used.nfiles);
	out_stvfs->f_favail = out_stvfs->f_ffree;
	out_stvfs->f_namemax = VOLUTA_NAME_MAX;
	out_stvfs->f_fsid = VOLUTA_SUPER_MAGIC;
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

static void update_space_change(struct voluta_sb_info *sbi,
                                struct voluta_hspace_info *hsi, int take,
                                const struct voluta_vaddr *vaddr)
{
	struct voluta_space_stat sp_st = { .zero = 0 };

	calc_stat_change(vaddr, take, &sp_st);
	voluta_hsi_update_space(hsi, vaddr->ag_index, &sp_st);

	if (vaddr->hs_index && vaddr->ag_index) {
		spi_update_stats(&sbi->sb_spi, vaddr->hs_index, &sp_st);
	}
}

static void mark_allocated_at(struct voluta_sb_info *sbi,
                              struct voluta_hspace_info *hsi,
                              struct voluta_agroup_info *agi,
                              const struct voluta_vaddr *vaddr)
{
	voluta_agi_mark_allocated_space(agi, vaddr);
	voluta_hsi_bind_to_kindof(hsi, vaddr);
	update_space_change(sbi, hsi, 1, vaddr);
}

static void mark_unallocate_at(struct voluta_sb_info *sbi,
                               struct voluta_hspace_info *hsi,
                               struct voluta_agroup_info *agi,
                               const struct voluta_vaddr *vaddr)
{
	const size_t nkbs = vtype_nkbs(vaddr->vtype);
	const voluta_index_t ag_index = vaddr->ag_index;

	voluta_agi_clear_allocated_space(agi, vaddr);
	if ((nkbs > 1) && voluta_hsi_is_fragmented(hsi, ag_index)) {
		voluta_hsi_clear_fragmented(hsi, ag_index);
	}
	update_space_change(sbi, hsi, -1, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_block *
block_of(const struct voluta_bksec_info *bsi, loff_t off)
{
	const loff_t lba = off_to_lba(off);
	struct voluta_blocks_sec *bks = bsi->bks;
	const size_t slot = (size_t)lba % ARRAY_SIZE(bks->bk);

	return &bks->bk[slot];
}

static int find_cached_bksec(struct voluta_sb_info *sbi,
                             const struct voluta_vba *vba,
                             struct voluta_bksec_info **out_bsi)
{
	*out_bsi = voluta_cache_lookup_bsi(sbi->sb_cache, vba);
	return (*out_bsi != NULL) ? 0 : -ENOENT;
}

static size_t total_dirty_size(const struct voluta_sb_info *sbi)
{
	const struct voluta_cache *cache = cache_of(sbi);

	return cache->c_dqs.dq_vis_all.dq_accum_nbytes;
}

static int commit_dirty_now(struct voluta_sb_info *sbi)
{
	int err;

	err = voluta_flush_dirty(sbi, VOLUTA_F_NOW);
	if (err) {
		log_dbg("commit dirty failure: dirty=%lu err=%d",
		        total_dirty_size(sbi), err);
	}
	return err;
}


static int try_spawn_bsi(struct voluta_sb_info *sbi,
                         const struct voluta_vba *vba,
                         struct voluta_bksec_info **out_bsi)
{
	*out_bsi = voluta_cache_spawn_bsi(cache_of(sbi), vba);
	return (*out_bsi != NULL) ? 0 : -ENOMEM;
}

static int spawn_bsi(struct voluta_sb_info *sbi, const struct voluta_vba *vba,
                     struct voluta_bksec_info **out_bsi)
{
	int err = -ENOMEM;
	int retry = 4;

	while (retry-- > 0) {
		err = try_spawn_bsi(sbi, vba, out_bsi);
		if (!err) {
			break;
		}
		err = commit_dirty_now(sbi);
		if (err) {
			break;
		}
	}
	return err;
}

static void zero_blocks_sec(struct voluta_bksec_info *bsi)
{
	struct voluta_blocks_sec *bks;

	if (likely(bsi != NULL)) { /* make clang-scan happy */
		bks = bsi->bks;
		voluta_memzero(bks, sizeof(*bks));
	}
}

static int load_bksec(const struct voluta_sb_info *sbi,
                      const struct voluta_vba *vba,
                      struct voluta_bksec_info *bsi)
{
	int err;
	struct voluta_baddr baddr;
	struct voluta_blocks_sec *bks = bsi->bks;

	voluta_vba_to_bksec_baddr(vba, &baddr);
	voluta_assert_le(vba->vaddr.len, VOLUTA_BKSEC_SIZE);
	voluta_assert_ge(baddr.bid.size, VOLUTA_BK_SIZE);
	voluta_assert_eq(baddr.len, sizeof(*bks));
	voluta_assert_eq(baddr.off % VOLUTA_BKSEC_SIZE, 0);

	err = voluta_locosd_load(sbi->sb_locosd, &baddr, bks);
	if (err) {
		voluta_assert_ok(err);
		return err;
	}
	return 0;
}

static void forget_bksec(const struct voluta_sb_info *sbi,
                         struct voluta_bksec_info *bsi)
{
	if (bsi != NULL) {
		voluta_cache_forget_bsi(cache_of(sbi), bsi);
	}
}

static int spawn_bksec(struct voluta_sb_info *sbi,
                       const struct voluta_vba *vba,
                       struct voluta_bksec_info **out_bsi)
{
	int err;

	err = find_cached_bksec(sbi, vba, out_bsi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bsi(sbi, vba, out_bsi);
	if (err) {
		return err;
	}
	zero_blocks_sec(*out_bsi);
	return 0;
}

static int stage_bksec(struct voluta_sb_info *sbi,
                       const struct voluta_vba *vba,
                       struct voluta_bksec_info **out_bsi)
{
	int err;

	err = find_cached_bksec(sbi, vba, out_bsi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bsi(sbi, vba, out_bsi);
	if (err) {
		return err;
	}
	err = load_bksec(sbi, vba, *out_bsi);
	if (err) {
		forget_bksec(sbi, *out_bsi);
		return err;
	}
	return 0;
}

static union voluta_view *make_view(const void *opaque_view)
{
	union {
		const union voluta_view *vp;
		union voluta_view *vq;
	} u = {
		.vp = opaque_view
	};
	return u.vq;
}

static const void *opaque_view_of(const struct voluta_bksec_info *bsi,
                                  const struct voluta_vaddr *vaddr)
{
	long pos;
	long kbn;
	const long kb_size = VOLUTA_KB_SIZE;
	const long nkb_in_bk = VOLUTA_NKB_IN_BK;
	const loff_t off = vaddr->off;
	const struct voluta_block *bk = block_of(bsi, off);

	kbn = ((off / kb_size) % nkb_in_bk);
	pos = kbn * kb_size;
	voluta_assert_le(pos + kb_size, sizeof(bk->u.bk));

	return &bk->u.bk[pos];
}

static int verify_vnode_view(struct voluta_vnode_info *vi)
{
	int err;

	if (vi_isdata(vi) || vi->v_verify) {
		return 0;
	}
	err = voluta_vi_verify_meta(vi);
	if (err) {
		return err;
	}
	vi->v_verify++;
	return 0;
}

static bool is_first_alloc(const struct voluta_agroup_info *agi,
                           const struct voluta_vaddr *vaddr)
{
	return (voluta_block_refcnt_at(agi, vaddr) == 0);
}

static int find_free_space_at(struct voluta_sb_info *sbi,
                              struct voluta_spalloc_ctx *spa,
                              voluta_index_t ag_index, size_t bn_start)
{
	int err;
	struct voluta_agroup_info *agi = NULL;
	const enum voluta_vtype vtype = spa->vtype;

	err = stage_agmap(sbi, ag_index, &agi);
	if (err) {
		return err;
	}
	err = voluta_agi_find_free_space(agi, vtype, bn_start, &spa->vba);
	if (err) {
		return err;
	}
	spa->agi = agi;
	spa->first_alloc = is_first_alloc(agi, &spa->vba.vaddr);
	return 0;
}

static bool is_sub_bk(enum voluta_vtype vtype)
{
	return (vtype_size(vtype) < VOLUTA_BK_SIZE);
}

static bool range_is_empty(const struct voluta_index_range *range)
{
	return (range->beg >= range->end);
}

static int find_free_space_within(struct voluta_sb_info *sbi,
                                  struct voluta_spalloc_ctx *spa,
                                  struct voluta_index_range *ag_range)
{
	int err;
	size_t bn_start;
	voluta_index_t ag_index;
	const enum voluta_vtype vtype = spa->vtype;

	while (!range_is_empty(ag_range)) {
		err = voluta_hsi_search_avail_ag(spa->hsi, ag_range,
		                                 vtype, &ag_index, &bn_start);
		if (err) {
			return err;
		}
		err = find_free_space_at(sbi, spa, ag_index, bn_start);
		if (err != -ENOSPC) {
			return err;
		}
		if ((err == -ENOSPC) && is_sub_bk(spa->vtype)) {
			voluta_hsi_mark_fragmented(spa->hsi, ag_index);
		}
		ag_range->beg = ag_index + 1;
	}
	return -ENOSPC;
}


static int find_free_space_for(struct voluta_sb_info *sbi,
                               struct voluta_spalloc_ctx *spa)
{
	int err;
	struct voluta_ag_span ag_span;
	struct voluta_index_range ag_range;

	voluta_hsi_ag_span(spa->hsi, &ag_span);

	/* fast search */
	ag_range.beg = ag_span.tip;
	ag_range.end = ag_span.fin;
	err = find_free_space_within(sbi, spa, &ag_range);
	if (err != -ENOSPC) {
		return err;
	}
	/* slow search */
	ag_range.beg = ag_span.beg;
	ag_range.end = ag_span.tip;
	err = find_free_space_within(sbi, spa, &ag_range);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int try_find_free_space(struct voluta_sb_info *sbi,
                               struct voluta_spalloc_ctx *spa)
{
	int err;

	err = voluta_hsi_check_cap_alloc(spa->hsi, spa->vtype);
	if (err) {
		return err;
	}
	err = find_free_space_for(sbi, spa);
	if (err) {
		return err;
	}
	return 0;
}

static int do_find_free_or_extend(struct voluta_sb_info *sbi,
                                  struct voluta_spalloc_ctx *spa)
{
	int err;

	err = try_find_free_space(sbi, spa);
	if (err != -ENOSPC) {
		return err;
	}
	err = format_next_agmap(sbi, spa->hsi);
	if (err) {
		return err;
	}
	err = try_find_free_space(sbi, spa);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int find_free_or_extend(struct voluta_sb_info *sbi,
                               struct voluta_spalloc_ctx *spa)
{
	int err;

	hsi_incref(spa->hsi);
	err = do_find_free_or_extend(sbi, spa);
	hsi_decref(spa->hsi);
	return err;
}

static int find_free_space(struct voluta_sb_info *sbi,
                           struct voluta_spalloc_ctx *spa)
{
	int err;
	voluta_index_t hs_index;
	struct voluta_hspace_info *hsi;
	struct voluta_space_info *spi = &sbi->sb_spi;
	const size_t bk_size = VOLUTA_BK_SIZE;

	hs_index = spi->sp_hs_index_lo;
	while (hs_index <= spi->sp_hs_active) {
		err = stage_hsmap(sbi, hs_index, &hsi);
		if (err) {
			return err;
		}
		spa->hsi = hsi;
		err = find_free_or_extend(sbi, spa);
		if (!err || (err != -ENOSPC)) {
			return err;
		}
		spa->hsi = NULL;

		hs_index++;
		err = voluta_hsi_check_cap_alloc(hsi, 2 * bk_size);
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

	if ((spi->sp_hs_active + 1) < spi->sp_hs_count) {
		err = format_head_spmaps_of(sbi, spi->sp_hs_active + 1);
	}
	if (err) {
		log_dbg("can not expand space: "\
		        "hs_active=%lu hs_count=%lu err=%d",
		        spi->sp_hs_active, spi->sp_hs_count, err);
	}
	return err;
}

static int find_unallocated_space(struct voluta_sb_info *sbi,
                                  struct voluta_spalloc_ctx *spa)
{
	int err = -ENOSPC;
	size_t niter = 2;

	while (niter--) {
		err = find_free_space(sbi, spa);
		if (!err || (err != -ENOSPC)) {
			break;
		}
		err = expand_space(sbi);
		if (err) {
			break;
		}
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void update_dskey(struct voluta_vnode_info *vi,
                         const struct voluta_inode_info *parent_ii)
{
	if (parent_ii != NULL) {
		vi->v_ds_key = (long)ii_ino(parent_ii);
	} else {
		vi->v_ds_key = 0;
	}
}

static void attach_vnode(struct voluta_sb_info *sbi,
                         struct voluta_vnode_info *vi,
                         struct voluta_bksec_info *bsi)
{
	voluta_assert_not_null(vi);

	if (likely(vi != NULL)) { /* make clang-scan happy */
		vi->v_sbi = sbi;
		voluta_vi_attach_to(vi, bsi);
	}
}

static void bind_vnode(struct voluta_sb_info *sbi,
                       struct voluta_vnode_info *vi,
                       struct voluta_bksec_info *bsi)
{
	attach_vnode(sbi, vi, bsi);
	vi->view = make_view(opaque_view_of(bsi, vi_vaddr(vi)));
}

int voluta_stage_cached_vnode(struct voluta_sb_info *sbi,
                              const struct voluta_vaddr *vaddr,
                              struct voluta_vnode_info **out_vi)
{
	struct voluta_cache *cache = cache_of(sbi);

	*out_vi = voluta_cache_lookup_vi(cache, vaddr);
	return (*out_vi != NULL) ? 0 : -ENOENT;
}

static int try_spawn_vi(struct voluta_sb_info *sbi,
                        const struct voluta_vba *vba,
                        struct voluta_vnode_info **out_vi)
{
	*out_vi = voluta_cache_spawn_vi(cache_of(sbi), vba);
	return (*out_vi == NULL) ? -ENOMEM : 0;
}

static int spawn_vi(struct voluta_sb_info *sbi,
                    const struct voluta_vba *vba,
                    struct voluta_vnode_info **out_vi)
{
	int err = -ENOMEM;
	int retry = 2;
	struct voluta_cache *cache = cache_of(sbi);

	while (retry-- > 0) {
		err = try_spawn_vi(sbi, vba, out_vi);
		if (!err) {
			return 0;
		}
		err = commit_dirty_now(sbi);
		if (err) {
			break;
		}
	}
	log_dbg("can not spawn vi: nvi=%lu dirty=%lu",
	        cache->c_vlm.htbl_size, total_dirty_size(sbi));
	return err;
}

static int spawn_bind_vnode(struct voluta_sb_info *sbi,
                            const struct voluta_vba *vba,
                            struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_bksec_info *bsi = NULL;
	struct voluta_agroup_info *agi = NULL;

	voluta_assert_eq(vba->vaddr.len, vba->baddr.len);

	err = stage_parents_of(sbi, vba, &agi, &bsi);
	if (err) {
		return err;
	}
	err = spawn_vi(sbi, vba, out_vi);
	if (err) {
		return err;
	}
	bind_vnode(sbi, *out_vi, bsi);
	return 0;
}

static void forget_cached_vi(struct voluta_sb_info *sbi,
                             struct voluta_vnode_info *vi)
{
	if (vi != NULL) {
		voulta_cache_forget_vi(cache_of(sbi), vi);
	}
}

static int spawn_bind_inode(struct voluta_sb_info *sbi,
                            const struct voluta_iaddr *iaddr,
                            struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_vba vba;
	struct voluta_vnode_info *vi = NULL;

	err = voluta_resolve_vba(sbi, &iaddr->vaddr, &vba);
	if (err) {
		return err;
	}
	err = spawn_bind_vnode(sbi, &vba, &vi);
	if (err) {
		return err;
	}
	*out_ii = voluta_ii_from_vi_rebind(vi, iaddr->ino);
	return 0;
}

static void forget_cached_ii(struct voluta_sb_info *sbi,
                             struct voluta_inode_info *ii)
{
	forget_cached_vi(sbi, ii_to_vi(ii));
}

static int spawn_spmap(struct voluta_sb_info *sbi,
                       const struct voluta_vba *vba,
                       struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_bksec_info *bsi = NULL;

	err = spawn_bksec(sbi, vba, &bsi);
	if (err) {
		return err;
	}
	err = spawn_vi(sbi, vba, out_vi);
	if (err) {
		return err;
	}
	bind_vnode(sbi, *out_vi, bsi);
	vi_stamp_mark_visible(*out_vi);
	return 0;
}

static int review_vnode(struct voluta_vnode_info *vi)
{
	int err;

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

static int stage_vnode(struct voluta_sb_info *sbi,
                       const struct voluta_vba *vba,
                       struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	err = voluta_stage_cached_vnode(sbi, &vba->vaddr, out_vi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bind_vnode(sbi, vba, &vi);
	if (err) {
		goto out_err;
	}
	err = review_vnode(vi);
	if (err) {
		goto out_err;
	}
	*out_vi = vi;
	return 0;
out_err:
	forget_cached_vi(sbi, vi);
	*out_vi = NULL;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_format_super(struct voluta_sb_info *sbi)
{
	/* XXX */
	voluta_unused(sbi);
	return 0;
}

int voluta_shut_super(struct voluta_sb_info *sbi)
{
	log_dbg("shut-super: op_count=%lu", sbi->sb_ops.op_count);
	spi_init(&sbi->sb_spi);
	voluta_itbi_reinit(&sbi->sb_itbi);
	return 0;
}

int voluta_sbi_save_sb(struct voluta_sb_info *sbi)
{
	const struct voluta_vba *vba = &sbi->sb_vba;

	voluta_assert_eq(vba->vaddr.len, vba->baddr.len);
	return voluta_locosd_store(sbi->sb_locosd, &vba->baddr, sbi->sb);
}

int voluta_sbi_load_sb(struct voluta_sb_info *sbi)
{
	const struct voluta_vba *vba = &sbi->sb_vba;

	return voluta_locosd_load(sbi->sb_locosd, &vba->baddr, sbi->sb);
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

static void update_spi_by_hsm(struct voluta_sb_info *sbi,
                              const struct voluta_hspace_info *hsi)
{
	struct voluta_space_info *spi = &sbi->sb_spi;
	struct voluta_space_stat sp_st = { .zero = 0 };

	voluta_hsi_space_stat_of(hsi, &sp_st);

	spi_accum_stat(spi, &sp_st);
	spi_mark_hs_active(spi, hsi->hs_index);
}

static void update_spi_on_hsm(struct voluta_sb_info *sbi)
{
	const ssize_t hsm_size = vtype_ssize(VOLUTA_VTYPE_HSMAP);

	spi_update_meta(&sbi->sb_spi, hsm_size);
}

static void update_spi_on_agm(struct voluta_sb_info *sbi, size_t nags)
{
	const ssize_t agm_size = vtype_ssize(VOLUTA_VTYPE_AGMAP);

	STATICASSERT_EQ(sizeof(struct voluta_bk_rec), 56);
	STATICASSERT_EQ(sizeof(struct voluta_agroup_map), VOLUTA_BK_SIZE);

	spi_update_meta(&sbi->sb_spi, (ssize_t)nags * agm_size);
}

static void setup_hsmap(struct voluta_hspace_info *hsi, size_t nags_span)
{
	voluta_hsi_setup(hsi, nags_span);
}

static int spawn_hsmap_of(struct voluta_sb_info *sbi,
                          const struct voluta_vba *vba,
                          voluta_index_t hs_index, size_t nags_span,
                          struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	err = spawn_spmap(sbi, vba, &vi);
	if (err) {
		return err;
	}
	*out_hsi = voluta_hsi_from_vi_rebind(vi, hs_index);
	setup_hsmap(*out_hsi, nags_span);
	return 0;
}

static void sbi_bind_hsmap(struct voluta_sb_info *sbi,
                           struct voluta_hspace_info *hsi)
{
	struct voluta_vba vba;

	voluta_hsi_vba(hsi, &vba);
	voluta_sb_bind_hsm(sbi->sb, hsi->hs_index, &vba);
}

static int format_hsmap(struct voluta_sb_info *sbi,
                        voluta_index_t hs_index, size_t nags_span,
                        struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_vba vba;
	struct voluta_hspace_info *hsi = NULL;

	voluta_vba_for_hsmap(&vba, hs_index);
	err = spawn_hsmap_of(sbi, &vba, hs_index, nags_span, &hsi);
	if (err) {
		return err;
	}
	sbi_bind_hsmap(sbi, hsi);
	update_spi_on_hsm(sbi);

	*out_hsi = hsi;
	return 0;
}

static size_t
nags_limit_of(const struct voluta_sb_info *sbi, voluta_index_t hs_index)
{
	size_t nags;
	voluta_index_t ag_index_base;
	voluta_index_t ag_index_next;
	const struct voluta_space_info *spi = &sbi->sb_spi;

	voluta_assert_gt(spi->sp_ag_count, VOLUTA_NAG_IN_HS);

	ag_index_base = voluta_ag_index_by_hs(hs_index, 0);
	ag_index_next = voluta_ag_index_by_hs(hs_index + 1, 0);
	voluta_assert_ge(ag_index_base, VOLUTA_NAG_IN_HS);

	nags = min(ag_index_next - ag_index_base,
	           spi->sp_ag_count - ag_index_base);

	voluta_assert_lt(nags, spi->sp_ag_count);

	return nags;
}

static int format_hsmap_of(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                           struct voluta_hspace_info **out_hsi)
{
	int err;
	const size_t nags_span = nags_limit_of(sbi, hs_index);

	err = format_hsmap(sbi, hs_index, nags_span, out_hsi);
	if (err) {
		return err;
	}
	spi_mark_hs_active(&sbi->sb_spi, hs_index);
	return 0;
}

static int format_head_spmaps_of(struct voluta_sb_info *sbi,
                                 voluta_index_t hs_index)
{
	int err;
	struct voluta_hspace_info *hsi = NULL;

	err = format_hsmap_of(sbi, hs_index, &hsi);
	if (err) {
		return err;
	}
	err = format_next_agmap(sbi, hsi);
	if (err) {
		log_err("failed to format next ags: hs_index=%lu", hs_index);
		return err;
	}
	return 0;
}

int voluta_format_spmaps(struct voluta_sb_info *sbi)
{
	int err;
	voluta_index_t hs_index;
	const size_t hs_count = 1; /* TODO: format more then one? */

	voluta_assert_gt(hs_count, 0);

	for (hs_index = 1; hs_index <= hs_count; ++hs_index) {
		err = format_head_spmaps_of(sbi, hs_index);
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

static int spawn_agmap_of(struct voluta_sb_info *sbi,
                          const struct voluta_vba *vba,
                          voluta_index_t ag_index,
                          struct voluta_agroup_info **out_agi)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	err = spawn_spmap(sbi, vba, &vi);
	if (err) {
		return err;
	}
	*out_agi = voluta_agi_from_vi_rebind(vi, ag_index);
	voluta_agi_setup(*out_agi);
	return 0;
}

static int format_agbks_of(struct voluta_sb_info *sbi,
                           struct voluta_agroup_info *agi)
{
	int err;
	struct voluta_blobid blobid;

	voluta_blobid_for_agbks(&blobid);
	err = voluta_locosd_create(sbi->sb_locosd, &blobid);
	if (err) {
		return err;
	}
	voluta_agi_set_bks_blobid(agi, &blobid);
	agi_dirtify(agi);
	return 0;
}

static void bind_agmap(struct voluta_hspace_info *hsi,
                       struct voluta_agroup_info *agi)
{
	struct voluta_vba agm_vba;

	voluta_assert_gt(agi->ag_index, 0);

	voluta_agi_vba(agi, &agm_vba);
	voluta_hsi_bind_agm(hsi, agi->ag_index, &agm_vba);
}

static int do_format_agmap(struct voluta_sb_info *sbi,
                           struct voluta_hspace_info *hsi,
                           voluta_index_t ag_index)
{
	int err;
	struct voluta_vba vba;
	struct voluta_agroup_info *agi;

	voluta_vba_for_agmap(&vba, ag_index);
	err = spawn_agmap_of(sbi, &vba, ag_index, &agi);
	if (err) {
		return err;
	}
	err = format_agbks_of(sbi, agi);
	if (err) {
		return err;
	}
	bind_agmap(hsi, agi);
	update_spi_on_agm(sbi, 1);
	return 0;
}

static int format_agmap(struct voluta_sb_info *sbi,
                        struct voluta_hspace_info *hsi,
                        voluta_index_t ag_index)
{
	int err;

	hsi_incref(hsi);
	err = do_format_agmap(sbi, hsi, ag_index);
	hsi_decref(hsi);
	return err;
}

static int next_unformatted_ag(const struct voluta_hspace_info *hsi,
                               voluta_index_t *out_ag_index)
{
	struct voluta_ag_span ag_span;

	voluta_hsi_ag_span(hsi, &ag_span);
	*out_ag_index = ag_span.fin;

	return (*out_ag_index < ag_span.end) ? 0 : -ENOSPC;
}

static int format_next_agmap(struct voluta_sb_info *sbi,
                             struct voluta_hspace_info *hsi)
{
	int err;
	voluta_index_t ag_index;

	err = next_unformatted_ag(hsi, &ag_index);
	if (err) {
		return err;
	}
	err = format_agmap(sbi, hsi, ag_index);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t hsi_nags_active(const struct voluta_hspace_info *hsi)
{
	struct voluta_ag_span ag_span;

	voluta_hsi_ag_span(hsi, &ag_span);
	voluta_assert_gt(ag_span.fin, ag_span.beg);

	return ag_span.fin - ag_span.beg;
}

static int load_hsmap_at(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                         struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_hspace_info *hsi = NULL;

	err = stage_hsmap(sbi, hs_index, &hsi);
	if (err) {
		return err;
	}
	update_spi_by_hsm(sbi, hsi);
	update_spi_on_hsm(sbi);
	update_spi_on_agm(sbi, hsi_nags_active(hsi));
	*out_hsi = hsi;
	return 0;
}

static int load_agmap_of(struct voluta_sb_info *sbi,
                         struct voluta_hspace_info *hsi,
                         voluta_index_t ag_index)
{
	int err;
	struct voluta_agroup_info *agi;

	if (!voluta_hsi_has_agm(hsi, ag_index)) {
		return -EFSCORRUPTED;
	}
	err = stage_agmap(sbi, ag_index, &agi);
	if (err) {
		return err;
	}
	return 0;
}

static int load_first_agmap_of(struct voluta_sb_info *sbi,
                               struct voluta_hspace_info *hsi)
{
	int err;
	struct voluta_ag_span ag_span = { .beg = 0 };

	voluta_hsi_ag_span(hsi, &ag_span);
	hsi_incref(hsi);
	err = load_agmap_of(sbi, hsi, ag_span.beg);
	hsi_decref(hsi);
	return err;
}

static bool sbi_has_hsmap(const struct voluta_sb_info *sbi,
                          voluta_index_t hs_index)
{
	return voluta_sb_has_hsm(sbi->sb, hs_index);
}

int voluta_reload_spmaps(struct voluta_sb_info *sbi)
{
	int err;
	voluta_index_t hs_index;
	struct voluta_hspace_info *hsi = NULL;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	for (hs_index = 1; (hs_index <= hs_count); ++hs_index) {
		if (!sbi_has_hsmap(sbi, hs_index)) {
			break;
		}
		err = load_hsmap_at(sbi, hs_index, &hsi);
		if (err) {
			return err;
		}
		err = load_first_agmap_of(sbi, hsi);
		if (err) {
			return err;
		}
		relax_bringup_cache(sbi);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t calc_iopen_limit(const struct voluta_cache *cache)
{
	struct voluta_alloc_stat st;

	voluta_allocstat(cache->c_alif, &st);
	return (st.memsz_data / (2 * VOLUTA_BK_SIZE));
}

static void sbi_init_commons(struct voluta_sb_info *sbi)
{
	voluta_vba_reset(&sbi->sb_vba);
	voluta_uuid_generate(&sbi->sb_fs_uuid);
	spi_init(&sbi->sb_spi);
	sbi->sb_owner.uid = getuid();
	sbi->sb_owner.gid = getgid();
	sbi->sb_owner.pid = getpid();
	sbi->sb_owner.umask = 0002;
	sbi->sb_iconv = (iconv_t)(-1);
	sbi->sb_ops.op_iopen_max = 0;
	sbi->sb_ops.op_iopen = 0;
	sbi->sb_ops.op_time = voluta_time_now();
	sbi->sb_ops.op_count = 0;
	sbi->sb_ctl_flags = 0;
	sbi->sb_ms_flags = 0;
	sbi->sb_mntime = 0;
	sbi->sb_cache = NULL;
	sbi->sb_qalloc = NULL;
	sbi->sb_locosd = NULL;
}

static void sbi_fini_commons(struct voluta_sb_info *sbi)
{
	voluta_vba_reset(&sbi->sb_vba);
	spi_fini(&sbi->sb_spi);
	sbi->sb_ctl_flags = 0;
	sbi->sb_ms_flags = 0;
	sbi->sb_cache = NULL;
	sbi->sb_qalloc = NULL;
	sbi->sb_locosd = NULL;
	sbi->sb = NULL;
}

static int sbi_init_piper(struct voluta_sb_info *sbi)
{
	int err;
	struct voluta_pipe *pipe = &sbi->sb_pipe;
	struct voluta_nullfd *nullfd = &sbi->sb_nullnfd;
	const size_t pipe_size_want = VOLUTA_BK_SIZE;

	voluta_pipe_init(pipe);
	err = voluta_pipe_open(pipe);
	if (err) {
		return err;
	}
	err = voluta_pipe_setsize(pipe, pipe_size_want);
	if (err) {
		voluta_pipe_fini(pipe);
		return err;
	}
	err = voluta_nullfd_init(nullfd);
	if (err) {
		voluta_pipe_fini(pipe);
		return err;
	}
	return 0;
}

static void sbi_fini_piper(struct voluta_sb_info *sbi)
{
	struct voluta_pipe *pipe = &sbi->sb_pipe;
	struct voluta_nullfd *nullfd = &sbi->sb_nullnfd;

	voluta_nullfd_fini(nullfd);
	voluta_pipe_fini(pipe);
}


static int sbi_init_crypto(struct voluta_sb_info *sbi)
{
	return voluta_crypto_init(&sbi->sb_crypto);
}

static void sbi_fini_crypto(struct voluta_sb_info *sbi)
{
	voluta_crypto_fini(&sbi->sb_crypto);
}

static int sbi_init_iti(struct voluta_sb_info *sbi)
{
	return voluta_itbi_init(&sbi->sb_itbi, &sbi->sb_qalloc->alif);
}

static void sbi_fini_iti(struct voluta_sb_info *sbi)
{
	voluta_itbi_fini(&sbi->sb_itbi);
}

static int sbi_init_iconv(struct voluta_sb_info *sbi)
{
	int err = 0;

	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	sbi->sb_iconv = iconv_open("UTF32LE", "UTF8");
	if (sbi->sb_iconv == (iconv_t)(-1)) {
		err = errno ? -errno : -EOPNOTSUPP;
	}
	return err;
}

static void sbi_fini_iconv(struct voluta_sb_info *sbi)
{
	if (sbi->sb_iconv != (iconv_t)(-1)) {
		iconv_close(sbi->sb_iconv);
		sbi->sb_iconv = (iconv_t)(-1);
	}
}

static int sbi_init_subs(struct voluta_sb_info *sbi)
{
	int err;

	err = sbi_init_iconv(sbi);
	if (err) {
		return err;
	}
	err = sbi_init_piper(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_init_crypto(sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_init_iti(sbi);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	sbi_fini_crypto(sbi);
	sbi_fini_piper(sbi);
	sbi_fini_iconv(sbi);
	return err;
}

static void sbi_attach_to(struct voluta_sb_info *sbi,
                          struct voluta_cache *cache,
                          struct voluta_locosd *locosd)
{
	sbi->sb_cache = cache;
	sbi->sb_locosd = locosd;
	sbi->sb_alif = cache->c_alif;
	sbi->sb_qalloc = cache->c_qalloc;
	sbi->sb_ops.op_iopen_max = calc_iopen_limit(cache);
}

int voluta_sbi_init(struct voluta_sb_info *sbi,
                    struct voluta_cache *cache, struct voluta_locosd *locosd)
{
	sbi_init_commons(sbi);
	sbi_attach_to(sbi, cache, locosd);
	return sbi_init_subs(sbi);
}

void voluta_sbi_fini(struct voluta_sb_info *sbi)
{
	sbi_fini_iti(sbi);
	sbi_fini_crypto(sbi);
	sbi_fini_piper(sbi);
	sbi_fini_iconv(sbi);
	sbi_fini_commons(sbi);
}

void voluta_sbi_bind_sb(struct voluta_sb_info *sbi,
                        struct voluta_super_block *sb,
                        const struct voluta_vba *vba)
{
	voluta_vba_copyto(vba, &sbi->sb_vba);
	voluta_sb_set_self_vaddr(sb, &vba->vaddr);
	sbi->sb = sb;
}

void voluta_sbi_setowner(struct voluta_sb_info *sbi,
                         const struct voluta_ucred *cred)
{
	sbi->sb_owner.uid = cred->uid;
	sbi->sb_owner.gid = cred->gid;
	sbi->sb_owner.pid = cred->pid;
	sbi->sb_owner.umask = cred->umask;
}

int voluta_sbi_setspace(struct voluta_sb_info *sbi, loff_t volume_size)
{
	int err;
	loff_t capacity_size = 0;

	err = voluta_calc_volume_space(volume_size, &capacity_size);
	if (err) {
		return err;
	}
	spi_setup(&sbi->sb_spi, capacity_size);
	return 0;
}

void voluta_sbi_add_ctlflags(struct voluta_sb_info *sbi, enum voluta_flags f)
{
	sbi->sb_ctl_flags |= f;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stage_agmap_of(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_agroup_info **out_agi)
{
	return stage_agmap(sbi, vaddr->ag_index, out_agi);
}

static int require_stable_at(const struct voluta_agroup_info *agi,
                             const struct voluta_vaddr *vaddr)
{
	return voluta_agi_is_allocated_with(agi, vaddr) ? 0 : -EFSCORRUPTED;
}

static int stage_parents_of(struct voluta_sb_info *sbi,
                            const struct voluta_vba *vba,
                            struct voluta_agroup_info **out_agi,
                            struct voluta_bksec_info **out_bsi)
{
	int err;
	const struct voluta_vaddr *vaddr = &vba->vaddr;

	voluta_assert(!vaddr_isspmap(vaddr));

	err = stage_agmap_of(sbi, vaddr, out_agi);
	if (err) {
		return err;
	}
	err = require_stable_at(*out_agi, vaddr);
	if (err) {
		return err;
	}
	err = stage_bksec(sbi, vba, out_bsi);
	if (err) {
		return err;
	}
	return 0;
}

static int commit_last(const struct voluta_sb_info *sbi, int flags)
{
	return (flags & VOLUTA_F_NOW) ? voluta_locosd_sync(sbi->sb_locosd) : 0;
}

int voluta_flush_dirty(struct voluta_sb_info *sbi, int flags)
{
	int err;
	bool need_flush;

	need_flush = voluta_cache_need_flush(sbi->sb_cache, flags);
	if (!need_flush) {
		return 0;
	}
	err = voluta_flush_dirty_vnodes(sbi->sb_cache, sbi->sb_locosd, 0);
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
	err = voluta_flush_dirty_vnodes(sbi->sb_cache, sbi->sb_locosd, ds_key);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_resolve_hsmap(const struct voluta_sb_info *sbi,
                             voluta_index_t hs_index,
                             struct voluta_vba *out_hsm_vba)
{
	voluta_sb_resolve_hsm(sbi->sb, hs_index, out_hsm_vba);
	return vaddr_isnull(&out_hsm_vba->vaddr) ? -ENOENT : 0;
}

static int try_stage_cached_hsmap(struct voluta_sb_info *sbi,
                                  const struct voluta_vba *vba,
                                  struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	voluta_assert_eq(vba->vaddr.vtype, VOLUTA_VTYPE_HSMAP);

	err = voluta_stage_cached_vnode(sbi, &vba->vaddr, &vi);
	if (err) {
		return err;
	}
	*out_hsi = voluta_hsi_from_vi(vi);
	return 0;
}

static int stage_bind_spmap(struct voluta_sb_info *sbi,
                            const struct voluta_vba *vba,
                            struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_bksec_info *bsi = NULL;

	err = stage_bksec(sbi, vba, &bsi);
	if (err) {
		return err;
	}
	err = spawn_vi(sbi, vba, out_vi);
	if (err) {
		return err;
	}
	bind_vnode(sbi, *out_vi, bsi);
	return 0;
}

static int stage_hsmap(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                       struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_vba vba;
	struct voluta_vnode_info *vi = NULL;

	err = sbi_resolve_hsmap(sbi, hs_index, &vba);
	if (err) {
		return err;
	}
	err = try_stage_cached_hsmap(sbi, &vba, out_hsi);
	if (!err) {
		return 0; /* cache hit */
	}
	err = stage_bind_spmap(sbi, &vba, &vi);
	if (err) {
		return err;
	}
	*out_hsi = voluta_hsi_from_vi_rebind(vi, hs_index);
	return 0;
}

static int stage_hsmap_of(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_hspace_info **out_hsi)
{
	return stage_hsmap(sbi, vaddr->hs_index, out_hsi);
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

static int resolve_agmap(struct voluta_sb_info *sbi, voluta_index_t ag_index,
                         struct voluta_vba *out_agm_vba)
{
	int err;
	voluta_index_t hs_index;
	struct voluta_hspace_info *hsi = NULL;

	hs_index = voluta_hs_index_of_ag(ag_index);
	err = stage_hsmap(sbi, hs_index, &hsi);
	if (err) {
		return err;
	}
	voluta_hsi_resolve_agm(hsi, ag_index, out_agm_vba);
	if (vaddr_isnull(&out_agm_vba->vaddr)) {
		return -ENOENT;
	}
	return 0;
}

static int try_stage_cached_agmap(struct voluta_sb_info *sbi,
                                  const struct voluta_vba *vba,
                                  struct voluta_agroup_info **out_agi)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	voluta_assert_eq(vba->vaddr.vtype, VOLUTA_VTYPE_AGMAP);

	err = voluta_stage_cached_vnode(sbi, &vba->vaddr, &vi);
	if (err) {
		return err;
	}
	*out_agi = voluta_agi_from_vi(vi);
	return 0;
}

static voluta_index_t hs_index_by_agm(const struct voluta_agroup_info *agi)
{
	voluta_assert_gt(agi->ag_index, 0);

	return voluta_hs_index_of_ag(agi->ag_index);
}

static int verify_agmap_stat(struct voluta_sb_info *sbi,
                             struct voluta_agroup_info *agi)
{
	int err;
	voluta_index_t hs_index;
	struct voluta_hspace_info *hsi = NULL;
	struct voluta_space_stat sp_st[2];

	if (agi->ag_vi.v_verify > 1) {
		return 0;
	}
	hs_index = hs_index_by_agm(agi);
	err = stage_hsmap(sbi, hs_index, &hsi);
	if (err) {
		return err;
	}
	voluta_hsi_space_stat_at(hsi, agi->ag_index, &sp_st[0]);
	voluta_calc_space_stat_of(agi, &sp_st[1]);
	if (!equal_space_stat(&sp_st[0], &sp_st[1])) {
		return -EFSCORRUPTED;
	}
	agi->ag_vi.v_verify++;
	return 0;
}

static int stage_agmap(struct voluta_sb_info *sbi, voluta_index_t ag_index,
                       struct voluta_agroup_info **out_agi)
{
	int err;
	struct voluta_vba vba;
	struct voluta_vnode_info *vi = NULL;

	err = resolve_agmap(sbi, ag_index, &vba);
	if (err) {
		return err;
	}
	err = try_stage_cached_agmap(sbi, &vba, out_agi);
	if (!err) {
		return 0; /* cache hit */
	}
	err = stage_bind_spmap(sbi, &vba, &vi);
	if (err) {
		return err;
	}
	*out_agi = voluta_agi_from_vi_rebind(vi, ag_index);

	err = verify_agmap_stat(sbi, *out_agi);
	if (err) {
		/* TODO: cleanups */
		return err;
	}
	return 0;
}

static int find_cached_ii(const struct voluta_sb_info *sbi,
                          const struct voluta_iaddr *iaddr,
                          struct voluta_inode_info **out_ii)
{
	struct voluta_vnode_info *vi = NULL;

	vi = voluta_cache_lookup_vi(cache_of(sbi), &iaddr->vaddr);
	if (vi == NULL) {
		return -ENOENT;
	}
	*out_ii = voluta_ii_from_vi(vi);
	return 0;
}

static int review_inode(struct voluta_inode_info *ii)
{
	return review_vnode(ii_to_vi(ii));
}

static int fetch_inode_at(struct voluta_sb_info *sbi,
                          const struct voluta_iaddr *iaddr,
                          struct voluta_inode_info **out_ii)
{
	int err;

	err = find_cached_ii(sbi, iaddr, out_ii);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bind_inode(sbi, iaddr, out_ii);
	if (err) {
		return err;
	}
	err = review_inode(*out_ii);
	if (err) {
		forget_cached_ii(sbi, *out_ii);
		return err;
	}
	voluta_refresh_atime(*out_ii, true);
	return 0;
}

static int fetch_inode(struct voluta_sb_info *sbi, ino_t ino,
                       struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_vba vba;
	struct voluta_iaddr iaddr;

	err = voluta_resolve_ino(sbi, ino, &iaddr);
	if (err) {
		return err;
	}
	err = voluta_resolve_vba(sbi, &iaddr.vaddr, &vba);
	if (err) {
		return err;
	}
	err = fetch_inode_at(sbi, &iaddr, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int check_writable_fs(const struct voluta_sb_info *sbi)
{
	const unsigned long mask = MS_RDONLY;

	return ((sbi->sb_ms_flags & mask) == mask) ? -EROFS : 0;
}

/* TODO: repeated logic; add inode-specific flags check */
static bool ii_isrdonly(const struct voluta_inode_info *ii)
{
	return (check_writable_fs(ii_sbi(ii)) != 0);
}

static int stage_inode(struct voluta_sb_info *sbi, ino_t ino,
                       struct voluta_inode_info **out_ii)
{
	int err;

	err = check_writable_fs(sbi);
	if (err) {
		return err;
	}
	err = fetch_inode(sbi, ino, out_ii);
	if (err) {
		return err;
	}
	if (ii_isrdonly(*out_ii)) {
		return -EROFS;
	}
	return 0;
}

int voluta_fetch_inode(struct voluta_sb_info *sbi, ino_t xino,
                       struct voluta_inode_info **out_ii)
{
	int err;
	ino_t ino;

	err = voluta_real_ino(sbi, xino, &ino);
	if (err) {
		return err;
	}
	err = fetch_inode(sbi, ino, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_fetch_cached_inode(struct voluta_sb_info *sbi, ino_t ino,
                              struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_iaddr iaddr;

	err = voluta_resolve_ino(sbi, ino, &iaddr);
	if (err) {
		return err;
	}
	err = find_cached_ii(sbi, &iaddr, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_stage_inode(struct voluta_sb_info *sbi, ino_t xino,
                       struct voluta_inode_info **out_ii)
{
	int err;
	ino_t ino;

	err = voluta_real_ino(sbi, xino, &ino);
	if (err) {
		return err;
	}
	err = stage_inode(sbi, ino, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int stage_vnode_at(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          const struct voluta_inode_info *pii,
                          struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vba vba;

	err = voluta_resolve_vba(sbi, vaddr, &vba);
	if (err) {
		return err;
	}
	err = stage_vnode(sbi, &vba, out_vi);
	if (err) {
		return err;
	}
	update_dskey(*out_vi, pii);
	return 0;
}

int voluta_stage_vnode(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_inode_info *pii,
                       struct voluta_vnode_info **out_vi)
{
	int err;

	ii_incref(pii);
	err = stage_vnode_at(sbi, vaddr, pii, out_vi);
	ii_decref(pii);
	return err;
}

static int check_avail_space(const struct voluta_sb_info *sbi,
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

static int claim_space(struct voluta_sb_info *sbi,
                       struct voluta_spalloc_ctx *spa)
{
	int err;

	err = check_avail_space(sbi, spa->vtype);
	if (err) {
		return err;
	}
	err = find_unallocated_space(sbi, spa);
	if (err) {
		/* TODO: cleanup */
		return err;
	}
	mark_allocated_at(sbi, spa->hsi, spa->agi, &spa->vba.vaddr);
	return 0;
}

int voluta_claim_space(struct voluta_sb_info *sbi,
                       enum voluta_vtype vtype,
                       struct voluta_vaddr *out_vaddr)
{
	int err;
	struct voluta_spalloc_ctx spa = {
		.vtype = vtype,
		.first_alloc = false
	};

	err = claim_space(sbi, &spa);
	if (err) {
		return err;
	}
	vaddr_copyto(&spa.vba.vaddr, out_vaddr);
	return 0;
}

static int require_supported_itype(mode_t mode)
{
	const mode_t sup = S_IFDIR | S_IFREG | S_IFLNK |
	                   S_IFSOCK | S_IFIFO | S_IFCHR | S_IFBLK;

	return (((mode & S_IFMT) | sup) == sup) ? 0 : -EOPNOTSUPP;
}

static int acquire_ino_at(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_iaddr *out_iaddr)
{
	int err;
	struct voluta_hspace_info *hsi = NULL;
	struct voluta_agroup_info *agi = NULL;

	err = voluta_acquire_ino(sbi, vaddr, out_iaddr);
	if (err) {
		return err;
	}
	err = stage_hsmap_of(sbi, vaddr, &hsi);
	if (err) {
		return err;
	}
	err = stage_agmap_of(sbi, vaddr, &agi);
	if (err) {
		return err;
	}
	return 0;
}

static void setup_vnode(struct voluta_vnode_info *vi,
                        const struct voluta_inode_info *parent_ii)
{
	update_dskey(vi, parent_ii);
	vi_stamp_mark_visible(vi);
}

static void setup_inode(struct voluta_inode_info *ii,
                        const struct voluta_oper *op,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev)
{
	const struct voluta_ucred *ucred = &op->ucred;

	setup_vnode(ii_to_vi(ii), ii);
	voluta_setup_inode(ii, ucred, parent_ino, parent_mode, mode, rdev);
	update_itimes(op, ii, VOLUTA_IATTR_TIMES);
}

static int spawn_inode(struct voluta_sb_info *sbi,
                       struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_iaddr iaddr;
	struct voluta_spalloc_ctx spa = {
		.vtype = VOLUTA_VTYPE_INODE,
		.first_alloc = false
	};

	err = claim_space(sbi, &spa);
	if (err) {
		return err;
	}
	err = acquire_ino_at(sbi, &spa.vba.vaddr, &iaddr);
	if (err) {
		return err;
	}
	err = spawn_bind_inode(sbi, &iaddr, out_ii);
	if (err) {
		/* TODO: spfree inode from ag */
		return err;
	}
	return 0;
}

int voluta_spawn_inode(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op,
                       ino_t parent_ino, mode_t parent_mode,
                       mode_t mode, dev_t rdev,
                       struct voluta_inode_info **out_ii)
{
	int err;

	err = require_supported_itype(mode);
	if (err) {
		return err;
	}
	err = spawn_inode(sbi, out_ii);
	if (err) {
		return err;
	}
	setup_inode(*out_ii, op, parent_ino, parent_mode, mode, rdev);
	return 0;
}

/* TODO: cleanups and resource reclaim upon failure in every path */
static int spawn_vnode(struct voluta_sb_info *sbi,
                       struct voluta_inode_info *pii,
                       enum voluta_vtype vtype,
                       struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_spalloc_ctx spa = {
		.vtype = vtype,
		.first_alloc = false
	};

	err = claim_space(sbi, &spa);
	if (err) {
		return err;
	}
	err = spawn_bind_vnode(sbi, &spa.vba, out_vi);
	if (err) {
		/* TODO: spfree inode from ag */
		return err;
	}
	setup_vnode(*out_vi, pii);
	return 0;
}

int voluta_spawn_vnode(struct voluta_sb_info *sbi,
                       struct voluta_inode_info *pii,
                       enum voluta_vtype vtype,
                       struct voluta_vnode_info **out_vi)
{
	int err;

	ii_incref(pii);
	err = spawn_vnode(sbi, pii, vtype, out_vi);
	ii_decref(pii);
	return err;
}

static int reclaim_space(struct voluta_sb_info *sbi,
                         const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_hspace_info *hsi = NULL;
	struct voluta_agroup_info *agi = NULL;

	voluta_assert_gt(vaddr->hs_index, 0);
	err = stage_hsmap(sbi, vaddr->hs_index, &hsi);
	if (err) {
		return err;
	}
	err = stage_agmap(sbi, vaddr->ag_index, &agi);
	if (err) {
		return err;
	}
	mark_unallocate_at(sbi, hsi, agi, vaddr);
	return 0;
}

static int discard_inode_at(struct voluta_sb_info *sbi,
                            const struct voluta_iaddr *iaddr)
{
	int err;

	err = voluta_discard_ino(sbi, iaddr->ino);
	if (err) {
		return err;
	}
	err = reclaim_space(sbi, &iaddr->vaddr);
	if (err) {
		return err;
	}
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
	int err;
	struct voluta_iaddr iaddr;

	iaddr_of(ii, &iaddr);
	err = discard_inode_at(sbi, &iaddr);
	if (err) {
		return err;
	}
	forget_cached_ii(sbi, ii);
	return 0;
}

static void mark_opaque_at(struct voluta_sb_info *sbi,
                           const struct voluta_vba *vba)
{
	int err;
	struct voluta_bksec_info *bsi = NULL;

	err = find_cached_bksec(sbi, vba, &bsi);
	if (!err) {
		voluta_bsi_mark_opaque_at(bsi, &vba->vaddr);
	}
}

static int reclaim_space_at(struct voluta_sb_info *sbi,
                            const struct voluta_vba *vba)
{
	int err;

	err = reclaim_space(sbi, &vba->vaddr);
	if (err) {
		return err;
	}
	mark_opaque_at(sbi, vba);
	return 0;
}

int voluta_remove_vnode(struct voluta_sb_info *sbi,
                        struct voluta_vnode_info *vi)
{
	int err;
	struct voluta_vba vba;

	voluta_assert(!vaddr_isspmap(vi_vaddr(vi)));

	err = voluta_resolve_vba(sbi, vi_vaddr(vi), &vba);
	if (err) {
		return err;
	}
	err = reclaim_space_at(sbi, &vba);
	if (err) {
		return err;
	}
	forget_cached_vi(sbi, vi);
	return 0;
}

int voluta_remove_vnode_at(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vba vba;
	struct voluta_vnode_info *vi = NULL;

	err = voluta_resolve_vba(sbi, vaddr, &vba);
	if (err) {
		return err;
	}
	err = voluta_stage_cached_vnode(sbi, &vba.vaddr, &vi);
	if (!err) {
		return voluta_remove_vnode(sbi, vi);
	}
	err = reclaim_space_at(sbi, &vba);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_probe_unwritten(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr, bool *out_res)
{
	int err;
	struct voluta_agroup_info *agi = NULL;

	err = stage_agmap_of(sbi, vaddr, &agi);
	if (err) {
		return err;
	}
	*out_res = voluta_agi_has_unwritten_at(agi, vaddr);
	return 0;
}

int voluta_clear_unwritten(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_agroup_info *agi = NULL;

	err = stage_agmap_of(sbi, vaddr, &agi);
	if (err) {
		return err;
	}
	voluta_agi_clear_unwritten_at(agi, vaddr);
	return 0;
}

int voluta_mark_unwritten(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_agroup_info *agi = NULL;

	err = stage_agmap_of(sbi, vaddr, &agi);
	if (err) {
		return err;
	}
	voluta_agi_mark_unwritten_at(agi, vaddr);
	return 0;
}

int voluta_refcnt_islast_at(struct voluta_sb_info *sbi,
                            const struct voluta_vaddr *vaddr, bool *out_res)
{
	int err;
	struct voluta_agroup_info *agi = NULL;

	err = stage_agmap_of(sbi, vaddr, &agi);
	if (err) {
		return err;
	}
	*out_res = voluta_has_lone_refcnt(agi, vaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_resolve_vba(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_vba *out_vba)
{
	int err;
	struct voluta_agroup_info *agi = NULL;

	voluta_assert(!vaddr_isspmap(vaddr));

	err = stage_agmap_of(sbi, vaddr, &agi);
	if (err) {
		return err;
	}
	voluta_agi_resolve_bks(agi, vaddr, out_vba);
	return 0;
}

static void voluta_sbi_vba(const struct voluta_sb_info *sbi,
                           struct voluta_vba *out_vba)
{
	voluta_vba_copyto(&sbi->sb_vba, out_vba);
}

int voluta_resolve_baddr_of(struct voluta_sb_info *sbi,
                            const struct voluta_vnode_info *vi,
                            struct voluta_baddr *out_baddr)
{
	int err = 0;
	struct voluta_vba vba = { .baddr.len = 0 };
	const enum voluta_vtype vtype = vi_vtype(vi);

	switch (vtype) {
	case VOLUTA_VTYPE_SUPER:
		voluta_sbi_vba(sbi, &vba);
		break;
	case VOLUTA_VTYPE_HSMAP:
		voluta_hsi_vba(voluta_hsi_from_vi(vi), &vba);
		break;
	case VOLUTA_VTYPE_AGMAP:
		voluta_agi_vba(voluta_agi_from_vi(vi), &vba);
		break;
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_ITNODE:
	case VOLUTA_VTYPE_INODE:
	case VOLUTA_VTYPE_XANODE:
	case VOLUTA_VTYPE_DTNODE:
	case VOLUTA_VTYPE_RTNODE:
	case VOLUTA_VTYPE_SYMVAL:
	case VOLUTA_VTYPE_DATABK:
		err = voluta_resolve_vba(sbi, vi_vaddr(vi), &vba);
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		err = -EINVAL;
		break;
	}

	if (!err) {
		voluta_baddr_copyto(&vba.baddr, out_baddr);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_kivam_of(const struct voluta_vnode_info *vi,
                    struct voluta_kivam *out_kivam)
{
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);
	const struct voluta_super_block *sb = vi->v_sbi->sb;

	voluta_sb_kivam_of(sb, vaddr, out_kivam);
	return 0;
}
