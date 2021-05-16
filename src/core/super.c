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
#include <string.h>
#include <limits.h>
#include "libvoluta.h"

struct voluta_spalloc_ctx {
	struct voluta_hspace_info *hsi;
	struct voluta_agroup_info *agi;
	struct voluta_vaddr vaddr;
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
static int stage_parents_of(struct voluta_sb_info *sbi,
                            const struct voluta_vaddr *vaddr, bool dont_reload,
                            struct voluta_bk_info **out_bki);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_cache *cache_of(const struct voluta_sb_info *sbi)
{
	return sbi->sb_cache;
}

static struct voluta_vstore *vstore_of(const struct voluta_sb_info *sbi)
{
	return sbi->sb_vstore;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void spi_init(struct voluta_space_info *spi)
{
	spi->sp_capcity_size = -1;
	spi->sp_address_space = -1;
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
	spi->sp_address_space = -1;
	spi->sp_hs_count = 0;
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 0;
	spi->sp_ag_count = 0;
	spi->sp_used.nmeta = INT_MIN;
	spi->sp_used.ndata = INT_MIN;
	spi->sp_used.nfiles = INT_MIN;
}

static void spi_setup(struct voluta_space_info *spi,
                      loff_t capacity_size, loff_t address_space)
{
	size_t ag_count;
	size_t hs_count;
	const size_t nag_in_hs = VOLUTA_NAG_IN_HS;

	voluta_assert_ge(address_space, capacity_size);

	ag_count = nbytes_to_ag_count(address_space);
	hs_count = div_round_up(ag_count, nag_in_hs);

	spi->sp_capcity_size = capacity_size;
	spi->sp_address_space = address_space;
	spi->sp_ag_count = ag_count;
	spi->sp_hs_count = hs_count;
	spi->sp_hs_active = 0;
	spi->sp_hs_index_lo = 1;
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

static void spi_mark_used_super(struct voluta_space_info *spi)
{
	/* FIXME bad logic XXX */
	const loff_t off = 2 * VOLUTA_AG_SIZE;

	if (off > spi->sp_used.nmeta) {
		spi->sp_used.nmeta = off;
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


static void hsi_incref(struct voluta_hspace_info *hsi)
{
	vi_incref(hsi_vi(hsi));
}

static void hsi_decref(struct voluta_hspace_info *hsi)
{
	vi_decref(hsi_vi(hsi));
}

static void hsi_dirtify(struct voluta_hspace_info *hsi)
{
	vi_dirtify(hsi_vi(hsi));
}

static const struct voluta_vaddr *
hsi_vaddr(const struct voluta_hspace_info *hsi)
{
	return vi_vaddr(hsi_vi(hsi));
}


static void agi_incref(struct voluta_agroup_info *agi)
{
	vi_incref(agi_vi(agi));
}

static void agi_decref(struct voluta_agroup_info *agi)
{
	vi_decref(agi_vi(agi));
}

static void agi_dirtify(struct voluta_agroup_info *agi)
{
	vi_dirtify(agi_vi(agi));
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
	voluta_update_space(hsi, vaddr->ag_index, &sp_st);

	if (vaddr->hs_index && vaddr->ag_index) {
		spi_update_stats(&sbi->sb_spi, vaddr->hs_index, &sp_st);
	}
}

static void mark_allocated_at(struct voluta_sb_info *sbi,
                              struct voluta_hspace_info *hsi,
                              struct voluta_agroup_info *agi,
                              const struct voluta_vaddr *vaddr)
{
	voluta_mark_allocated_space(agi, vaddr);
	voluta_bind_to_kindof(hsi, vaddr);
	update_space_change(sbi, hsi, 1, vaddr);
}

static void mark_unallocate_at(struct voluta_sb_info *sbi,
                               struct voluta_hspace_info *hsi,
                               struct voluta_agroup_info *agi,
                               const struct voluta_vaddr *vaddr)
{
	voluta_clear_allocated_space(agi, vaddr);
	voluta_clear_fragmented_at(hsi, vaddr);
	update_space_change(sbi, hsi, -1, vaddr);
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

static int find_cached_bk(struct voluta_sb_info *sbi, voluta_lba_t lba,
                          struct voluta_bk_info **out_bki)
{
	*out_bki = voluta_cache_lookup_bki(sbi->sb_cache, lba);
	return (*out_bki != NULL) ? 0 : -ENOENT;
}

static size_t total_dirty_size(const struct voluta_sb_info *sbi)
{
	const struct voluta_cache *cache = cache_of(sbi);

	return cache->c_dqs.dq_main.dq_accum_nbytes;
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

static int spawn_bk(struct voluta_sb_info *sbi, voluta_lba_t lba,
                    struct voluta_bk_info **out_bki)
{
	int err;
	struct voluta_cache *cache = cache_of(sbi);

	for (size_t retry = 0; retry < 4; ++retry) {
		*out_bki = voluta_cache_spawn_bki(cache, lba);
		if (*out_bki != NULL) {
			return 0;
		}
		err = commit_dirty_now(sbi);
		if (err) {
			return err;
		}
	}
	return -ENOMEM;
}

static void zero_bk(struct voluta_bk_info *bki)
{
	struct voluta_block *bk = bki->bk;

	voluta_memzero(bk, sizeof(*bk));
}

static int load_bk(const struct voluta_sb_info *sbi,
                   struct voluta_bk_info *bki)
{
	struct voluta_xiovec xiov;
	const struct voluta_vstore *vstore = vstore_of(sbi);

	resolve_bk_xiovec(sbi, bki, &xiov);
	return voluta_vstore_read(vstore, xiov.off, xiov.len, bki->bk);
}

static void forget_bk(const struct voluta_sb_info *sbi,
                      struct voluta_bk_info *bki)
{
	if (bki != NULL) {
		voluta_cache_forget_bki(cache_of(sbi), bki);
	}
}

static int stage_bk(struct voluta_sb_info *sbi, const voluta_lba_t lba,
                    bool dont_reload, struct voluta_bk_info **out_bki)
{
	int err;
	struct voluta_bk_info *bki = NULL;

	err = find_cached_bk(sbi, lba, out_bki);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bk(sbi, lba, &bki);
	if (err) {
		goto out_err;
	}
	if (dont_reload) {
		zero_bk(bki);
		goto out_ok;
	}
	err = load_bk(sbi, bki);
	if (err) {
		goto out_err;
	}
out_ok:
	*out_bki = bki;
	return 0;
out_err:
	forget_bk(sbi, bki);
	*out_bki = NULL;
	return err;
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

	if (vi_isdata(vi) || vi->v_verify) {
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

static int decrypt_vnode(const struct voluta_sb_info *sbi,
                         const struct voluta_vnode_info *vi)
{
	int err;

	if (vi_isvisible(vi)) {
		return 0;
	}
	if (!encrypted_mode(sbi)) {
		return 0;
	}
	err = voluta_decrypt_vnode(vi, vi->view);
	if (err) {
		return err;
	}
	return 0;
}

static bool is_first_alloc(const struct voluta_agroup_info *agi,
                           const struct voluta_vaddr *vaddr)
{
	return (voluta_block_refcnt_at(agi, vaddr) == 0);
}

static int find_free_space_at(struct voluta_sb_info *sbi,
                              struct voluta_spalloc_ctx *spa,
                              voluta_index_t ag_index)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_agroup_info *agi = NULL;
	const enum voluta_vtype vtype = spa->vtype;

	err = stage_agmap(sbi, ag_index, &agi);
	if (err) {
		return err;
	}
	err = voluta_search_free_space(spa->hsi, agi, vtype, &vaddr);
	if (err) {
		return err;
	}
	vaddr_copyto(&vaddr, &spa->vaddr);
	spa->agi = agi;
	spa->first_alloc = is_first_alloc(agi, &vaddr);

	return 0;
}

static bool is_sub_bk(enum voluta_vtype vtype)
{
	return (vtype_size(vtype) < VOLUTA_BK_SIZE);
}

static int find_free_space_within(struct voluta_sb_info *sbi,
                                  struct voluta_spalloc_ctx *spa,
                                  voluta_index_t ag_index_first,
                                  voluta_index_t ag_index_last)
{
	int err;
	voluta_index_t ag_index;

	ag_index = ag_index_first;
	while (ag_index < ag_index_last) {
		err = voluta_search_avail_ag(spa->hsi, ag_index,
		                             ag_index_last, spa->vtype,
		                             &ag_index);
		if (err) {
			return err;
		}
		err = find_free_space_at(sbi, spa, ag_index);
		if (err != -ENOSPC) {
			return err;
		}
		if ((err == -ENOSPC) && is_sub_bk(spa->vtype)) {
			voluta_mark_fragmented(spa->hsi, ag_index);
		}
		ag_index++;
	}
	return -ENOSPC;
}


static int find_free_space_for(struct voluta_sb_info *sbi,
                               struct voluta_spalloc_ctx *spa)
{
	int err;
	struct voluta_ag_range ag_range = { .beg = 0, .end = 0 };

	voluta_ag_range_of(spa->hsi, &ag_range);

	/* fast search */
	err = find_free_space_within(sbi, spa, ag_range.tip, ag_range.fin);
	if (err != -ENOSPC) {
		return err;
	}
	/* slow search */
	err = find_free_space_within(sbi, spa, ag_range.beg, ag_range.tip);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int try_find_free_space(struct voluta_sb_info *sbi,
                               struct voluta_spalloc_ctx *spa)
{
	int err;

	err = voluta_check_cap_alloc(spa->hsi, spa->vtype);
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
		err = voluta_check_cap_alloc(hsi, 2 * bk_size);
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
	case VOLUTA_VTYPE_DATA1K:
		vi->vu.db1 = &view->u.db1;
		break;
	case VOLUTA_VTYPE_DATA4K:
		vi->vu.db4 = &view->u.db4;
		break;
	case VOLUTA_VTYPE_DATABK:
	case VOLUTA_VTYPE_BLOB:
		vi->vu.db = &view->u.db;
		break;
	case VOLUTA_VTYPE_SUPER:
	case VOLUTA_VTYPE_NONE:
	default:
		break;
	}
}

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
                         struct voluta_bk_info *bki)
{
	vi->v_sbi = sbi;
	voluta_vi_attach_to(vi, bki);
}

static int bind_vnode(struct voluta_sb_info *sbi,
                      struct voluta_vnode_info *vi,
                      struct voluta_bk_info *bki)
{
	struct voluta_view *view;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	attach_vnode(sbi, vi, bki);
	view = view_at(bki, vaddr->off);
	bind_view(vi, view);
	return 0;
}

static int bind_inode(struct voluta_sb_info *sbi,
                      struct voluta_inode_info *ii,
                      struct voluta_bk_info *bki)
{
	int err;

	err = bind_vnode(sbi, ii_vi(ii), bki);
	if (err) {
		return err;
	}
	ii->inode = ii->i_vi.vu.inode;
	return 0;
}

static int find_cached_vi(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_vnode_info **out_vi)
{
	struct voluta_cache *cache = cache_of(sbi);

	*out_vi = voluta_cache_lookup_vi(cache, vaddr);
	return (*out_vi != NULL) ? 0 : -ENOENT;
}

static int spawn_vi_at(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_vnode_info **out_vi)
{
	*out_vi = voluta_cache_spawn_vi(cache_of(sbi), vaddr);
	return (*out_vi == NULL) ? -ENOMEM : 0;
}

static int spawn_vi(struct voluta_sb_info *sbi,
                    const struct voluta_vaddr *vaddr,
                    struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_cache *cache = cache_of(sbi);

	err = spawn_vi_at(sbi, vaddr, out_vi);
	if (!err) {
		return 0;
	}
	err = commit_dirty_now(sbi);
	if (err) {
		return err;
	}
	err = spawn_vi_at(sbi, vaddr, out_vi);
	if (err) {
		log_dbg("can not spawn vi: nvi=%lu dirty=%lu",
		        cache->c_vlm.htbl_size, total_dirty_size(sbi));
		return err;
	}
	return 0;
}

static int spawn_bind_vi(struct voluta_sb_info *sbi,
                         const struct voluta_vaddr *vaddr, bool dont_reload,
                         struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_bk_info *bki = NULL;

	err = stage_parents_of(sbi, vaddr, dont_reload, &bki);
	if (err) {
		return err;
	}
	err = spawn_vi(sbi, vaddr, out_vi);
	if (err) {
		return err;
	}
	err = bind_vnode(sbi, *out_vi, bki);
	if (err) {
		return err;
	}
	return 0;
}

static void forget_cached_vi(struct voluta_vnode_info *vi)
{
	if (vi != NULL) {
		voulta_cache_forget_vi(vi_cache(vi), vi);
	}
}

static int spawn_ii_now(struct voluta_sb_info *sbi,
                        const struct voluta_iaddr *iaddr,
                        struct voluta_inode_info **out_ii)
{
	struct voluta_cache *cache = cache_of(sbi);

	*out_ii = voluta_cache_spawn_ii(cache, iaddr);
	return (*out_ii == NULL) ? -ENOMEM : 0;
}

static int spawn_ii(struct voluta_sb_info *sbi,
                    const struct voluta_iaddr *iaddr,
                    struct voluta_inode_info **out_ii)
{
	int err;
	const struct voluta_cache *cache = cache_of(sbi);

	err = spawn_ii_now(sbi, iaddr, out_ii);
	if (!err) {
		return 0;
	}
	err = commit_dirty_now(sbi);
	if (err) {
		return err;
	}
	err = spawn_ii_now(sbi, iaddr, out_ii);
	if (err) {
		log_dbg("can not spawn ii: nii=%lu dirty=%lu",
		        cache->c_ilm.htbl_size, total_dirty_size(sbi));
		return err;
	}
	return 0;
}

static int spawn_bind_ii(struct voluta_sb_info *sbi,
                         const struct voluta_iaddr *iaddr, bool dont_reload,
                         struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_bk_info *bki = NULL;

	err = stage_parents_of(sbi, &iaddr->vaddr, dont_reload, &bki);
	if (err) {
		return err;
	}
	err = spawn_ii(sbi, iaddr, out_ii);
	if (err) {
		return err;
	}
	err = bind_inode(sbi, *out_ii, bki);
	if (err) {
		return err;
	}
	return 0;
}

static void forget_cached_ii(struct voluta_sb_info *sbi,
                             struct voluta_inode_info *ii)
{
	voulta_cache_forget_ii(cache_of(sbi), ii);
}

static int lookup_or_spawn_bki(struct voluta_sb_info *sbi, voluta_lba_t lba,
                               struct voluta_bk_info **out_bki)
{
	int err;

	err = find_cached_bk(sbi, lba, out_bki);
	if (err) {
		err = spawn_bk(sbi, lba, out_bki);
	}
	return err;
}

static int spawn_spmap(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_bk_info *bki = NULL;

	err = lookup_or_spawn_bki(sbi, vaddr->lba, &bki);
	if (err) {
		return err;
	}
	err = spawn_bind_vi(sbi, vaddr, false, out_vi);
	if (err) {
		return err;
	}
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

static int decrypt_review_vnode(struct voluta_sb_info *sbi,
                                struct voluta_vnode_info *vi)
{
	int err;

	err = decrypt_vnode(sbi, vi);
	if (err) {
		return err;
	}
	err = review_vnode(vi);
	if (err) {
		return err;
	}
	return 0;
}

static int stage_vnode(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	err = find_cached_vi(sbi, vaddr, out_vi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bind_vi(sbi, vaddr, false, &vi);
	if (err) {
		goto out_err;
	}
	err = decrypt_review_vnode(sbi, vi);
	if (err) {
		goto out_err;
	}
	*out_vi = vi;
	return 0;
out_err:
	forget_cached_vi(vi);
	*out_vi = NULL;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_adjust_super(struct voluta_sb_info *sbi)
{
	spi_mark_used_super(&sbi->sb_spi);
	return 0;
}

int voluta_shut_super(struct voluta_sb_info *sbi)
{
	log_dbg("shut-super: op_count=%lu", sbi->sb_ops.op_count);
	spi_init(&sbi->sb_spi);
	voluta_iti_reinit(&sbi->sb_iti);
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
                              const struct voluta_hspace_info *hsi)
{
	voluta_index_t hs_index;
	struct voluta_space_info *spi = &sbi->sb_spi;
	struct voluta_space_stat sp_st = { .zero = 0 };

	hs_index = voluta_hs_index_of(hsi);
	voluta_space_stat_of(hsi, &sp_st);

	spi_accum_stat(spi, &sp_st);
	spi_mark_hs_active(spi, hs_index);
}

static void update_spi_on_hsm(struct voluta_sb_info *sbi)
{
	/* XXX */
	return;

	spi_update_meta(&sbi->sb_spi, vtype_ssize(VOLUTA_VTYPE_HSMAP));
}

static void update_spi_on_agm(struct voluta_sb_info *sbi)
{
	STATICASSERT_EQ(sizeof(struct voluta_bk_rec), 56);
	STATICASSERT_EQ(sizeof(struct voluta_agroup_map), VOLUTA_BK_SIZE);

	/* XXX */
	return;

	spi_update_meta(&sbi->sb_spi, vtype_ssize(VOLUTA_VTYPE_AGMAP));
}

static int spawn_hsmap_of(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                          struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi = NULL;

	voluta_vaddr_of_hsmap(&vaddr, hs_index);
	err = spawn_spmap(sbi, &vaddr, &vi);
	if (err) {
		return err;
	}
	*out_hsi = voluta_hsi_from_vi(vi);
	(*out_hsi)->hs_index = hs_index;
	return 0;
}

static void setup_hsmap(struct voluta_hspace_info *hsi,
                        voluta_index_t hs_index, size_t nags_span)
{
	struct voluta_vnode_info *vi = hsi_vi(hsi);

	vi_stamp_view(vi);
	voluta_setup_hsmap(hsi, hs_index, nags_span);
	vi_dirtify(vi);
}

static void bind_hsmap(struct voluta_sb_info *sbi,
                       struct voluta_hspace_info *hsi)
{
	struct voluta_super_block *sb = sbi->sb;

	voluta_usm_set_vaddr(&sb->sb_usm, hsi->hs_index, hsi_vaddr(hsi));
}

static int format_hsmap(struct voluta_sb_info *sbi,
                        voluta_index_t hs_index, size_t nags_span,
                        struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_hspace_info *hsi = NULL;

	err = spawn_hsmap_of(sbi, hs_index, &hsi);
	if (err) {
		return err;
	}
	setup_hsmap(hsi, hs_index, nags_span);
	bind_hsmap(sbi, hsi);
	update_spi_on_hsm(sbi);

	*out_hsi = hsi;
	return 0;
}

static int mark_prev_hsmap_with_next(struct voluta_sb_info *sbi,
                                     voluta_index_t hs_index)
{
	int err;
	voluta_index_t hs_index_prev;
	struct voluta_hspace_info *hsi;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	if ((hs_index <= 1) || (hs_index >= hs_count)) {
		return 0;
	}
	hs_index_prev = hs_index - 1;
	err = stage_hsmap(sbi, hs_index_prev, &hsi);
	if (err) {
		return err;
	}
	voluta_mark_with_next(hsi);
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
	err = mark_prev_hsmap_with_next(sbi, hs_index);
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

static int spawn_agmap_of(struct voluta_sb_info *sbi, voluta_index_t ag_index,
                          struct voluta_agroup_info **out_agi)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi = NULL;

	voluta_vaddr_of_agmap(&vaddr, ag_index);
	err = spawn_spmap(sbi, &vaddr, &vi);
	if (err) {
		return err;
	}
	*out_agi = voluta_agi_from_vi(vi);
	(*out_agi)->ag_index = ag_index;
	return 0;
}

static int unlimit_agmap_on_pstore(struct voluta_sb_info *sbi,
                                   voluta_index_t ag_index)
{
	loff_t cap;
	struct voluta_vaddr vaddr;
	struct voluta_vstore *vstore = sbi->sb_vstore;
	const loff_t ag_size = VOLUTA_AG_SIZE;

	voluta_vaddr_of_agmap(&vaddr, ag_index);
	cap = ((vaddr.off + ag_size) / ag_size) * ag_size;
	return voluta_vstore_expand(vstore, cap);
}

static void setup_agmap(struct voluta_agroup_info *agi,
                        voluta_index_t ag_index)
{
	struct voluta_vnode_info *vi = agi_vi(agi);

	vi_stamp_view(vi);
	voluta_setup_agmap(agi, ag_index);
	vi_dirtify(vi);
}

static int do_format_agmap_of(struct voluta_sb_info *sbi,
                              struct voluta_hspace_info *hsi,
                              voluta_index_t ag_index)
{
	int err;
	struct voluta_agroup_info *agi;
	struct voluta_vaddr bks_vaddr;

	err = unlimit_agmap_on_pstore(sbi, ag_index);
	if (err) {
		return err;
	}
	err = spawn_agmap_of(sbi, ag_index, &agi);
	if (err) {
		return err;
	}
	setup_agmap(agi, ag_index);

	voluta_vaddr_of_blob(&bks_vaddr, ag_index);
	voluta_set_formatted_ag(hsi, vi_vaddr(agi_vi(agi)), &bks_vaddr);
	update_spi_on_agm(sbi);
	return 0;
}

static int format_agmap_of(struct voluta_sb_info *sbi,
                           struct voluta_hspace_info *hsi,
                           voluta_index_t ag_index)
{
	int err;

	hsi_incref(hsi);
	err = do_format_agmap_of(sbi, hsi, ag_index);
	hsi_decref(hsi);
	return err;
}

static int next_unformatted_ag(const struct voluta_hspace_info *hsi,
                               voluta_index_t *out_ag_index)
{
	struct voluta_ag_range ag_range;

	voluta_ag_range_of(hsi, &ag_range);
	*out_ag_index = ag_range.fin;

	return (*out_ag_index < ag_range.end) ? 0 : -ENOSPC;
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
	err = format_agmap_of(sbi, hsi, ag_index);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

	*out_hsi = hsi;
	return 0;
}

static int load_agmap_of(struct voluta_sb_info *sbi,
                         struct voluta_hspace_info *hsi,
                         voluta_index_t ag_index)
{
	int err;
	struct voluta_agroup_info *agi;

	if (!voluta_has_formatted_ag(hsi, ag_index)) {
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
	struct voluta_ag_range ag_range = { .beg = 0 };

	voluta_ag_range_of(hsi, &ag_range);
	hsi_incref(hsi);
	err = load_agmap_of(sbi, hsi, ag_range.beg);
	hsi_decref(hsi);
	return err;
}

int voluta_reload_spmaps(struct voluta_sb_info *sbi)
{
	int err;
	bool has_next;
	voluta_index_t hs_index;
	struct voluta_hspace_info *hsi = NULL;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	for (hs_index = 1; (hs_index <= hs_count); ++hs_index) {
		err = load_hsmap_at(sbi, hs_index, &hsi);
		if (err) {
			return err;
		}
		err = load_first_agmap_of(sbi, hsi);
		if (err) {
			return err;
		}
		has_next = voluta_has_next_hspace(hsi);
		if (!has_next) {
			break;
		}
		relax_bringup_cache(sbi);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vaddr_by_bai(struct voluta_vaddr *vaddr,
                         const struct voluta_agroup_info *agi,
                         const struct voluta_balloc_info *bai, size_t idx)
{
	const voluta_index_t ag_index = voluta_ag_index_of(agi);

	vaddr_by_ag(vaddr, bai->vtype, ag_index, bai->bn, bai->kbn[idx]);
}

static int traverse_by_balloc_info(struct voluta_sb_info *sbi,
                                   const struct voluta_agroup_info *agi,
                                   const struct voluta_balloc_info *bai)
{
	int err;
	size_t nvis = 0;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi;
	struct voluta_vnode_info *vis[VOLUTA_NKB_IN_BK];

	STATICASSERT_EQ(ARRAY_SIZE(vis), ARRAY_SIZE(bai->kbn));

	for (size_t i = 0; i < bai->cnt; ++i) {
		vaddr_by_bai(&vaddr, agi, bai, i);
		err = voluta_stage_vnode(sbi, &vaddr, NULL, &vi);
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
	err = voluta_vstore_clear_bk(vstore_of(sbi), bai->lba);
out:
	for (size_t i = 0; i < nvis; ++i) {
		vi = vis[i];
		vi_decref(vi);
	}
	return err;
}

static int do_traverse_by_agmap(struct voluta_sb_info *sbi,
                                struct voluta_agroup_info *agi)
{
	int err;
	struct voluta_balloc_info bai = { .cnt = 0 };

	for (size_t bk_idx = 0; bk_idx < VOLUTA_NBK_IN_AG; ++bk_idx) {
		voluta_balloc_info_at(agi, bk_idx, &bai);
		if (voluta_vtype_isspmap(bai.vtype)) {
			continue;
		}
		err = traverse_by_balloc_info(sbi, agi, &bai);
		if (err) {
			return err;
		}
		err = flush_and_relax(sbi, VOLUTA_F_OPSTART);
		if (err) {
			return err;
		}
	}
	agi_dirtify(agi);
	return 0;
}

static int traverse_by_agmap(struct voluta_sb_info *sbi,
                             struct voluta_hspace_info *hsi,
                             struct voluta_agroup_info *agi)
{
	int err;

	hsi_incref(hsi);
	agi_incref(agi);
	err = do_traverse_by_agmap(sbi, agi);
	agi_decref(agi);
	hsi_decref(hsi);
	return err;
}

static int do_traverse_by_hsmap(struct voluta_sb_info *sbi,
                                struct voluta_hspace_info *hsi)
{
	int err;
	voluta_index_t ag_index;
	struct voluta_ag_range ag_range;
	struct voluta_agroup_info *agi = NULL;

	voluta_ag_range_of(hsi, &ag_range);
	for (ag_index = ag_range.beg; ag_index < ag_range.fin; ++ag_index) {
		err = stage_agmap(sbi, ag_index, &agi);
		if (err) {
			return err;
		}
		err = traverse_by_agmap(sbi, hsi, agi);
		if (err) {
			return err;
		}
		err = flush_and_relax(sbi, VOLUTA_F_OPSTART);
		if (err) {
			return err;
		}
		agi = NULL;
	}
	hsi_dirtify(hsi);
	return 0;
}

static int traverse_by_hsmap(struct voluta_sb_info *sbi,
                             struct voluta_hspace_info *hsi)
{
	int err;

	hsi_incref(hsi);
	err = do_traverse_by_hsmap(sbi, hsi);
	hsi_decref(hsi);
	return err;
}

int voluta_traverse_space(struct voluta_sb_info *sbi)
{
	int err;
	bool has_next;
	voluta_index_t hs_index;
	struct voluta_hspace_info *hsi;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	voluta_assert_gt(hs_count, 0);

	for (hs_index = 1; hs_index <= hs_count; ++hs_index) {
		err = load_hsmap_at(sbi, hs_index, &hsi);
		if (err) {
			return err;
		}
		err = traverse_by_hsmap(sbi, hsi);
		if (err) {
			return err;
		}
		has_next = voluta_has_next_hspace(hsi);
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
		err = errno ? -errno : -EOPNOTSUPP;
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

int voluta_sbi_setspace(struct voluta_sb_info *sbi, loff_t volume_capacity)
{
	int err;
	loff_t capacity_size = 0;
	loff_t address_space = 0;

	err = voluta_calc_volume_space(volume_capacity,
	                               &capacity_size,
	                               &address_space);
	if (!err) {
		spi_setup(&sbi->sb_spi, capacity_size, address_space);
	}
	return err;
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
	return voluta_is_allocated_with(agi, vaddr) ? 0 : -EFSCORRUPTED;
}

static int stage_parents_of_spmap(struct voluta_sb_info *sbi,
                                  const struct voluta_vaddr *vaddr,
                                  struct voluta_bk_info **out_bki)
{
	return stage_bk(sbi, vaddr->lba, false, out_bki);
}

static int stage_parents_of_normal(struct voluta_sb_info *sbi,
                                   const struct voluta_vaddr *vaddr,
                                   bool dont_reload,
                                   struct voluta_bk_info **out_bki)
{
	int err;
	struct voluta_agroup_info *agi = NULL;

	err = stage_agmap_of(sbi, vaddr, &agi);
	if (err) {
		return err;
	}
	err = require_stable_at(agi, vaddr);
	if (err) {
		return err;
	}
	err = stage_bk(sbi, vaddr->lba, dont_reload, out_bki);
	if (err) {
		return err;
	}
	return 0;
}

static int stage_parents_of(struct voluta_sb_info *sbi,
                            const struct voluta_vaddr *vaddr, bool dont_reload,
                            struct voluta_bk_info **out_bki)
{
	return vaddr_isspmap(vaddr) ?
	       stage_parents_of_spmap(sbi, vaddr, out_bki) :
	       stage_parents_of_normal(sbi, vaddr, dont_reload, out_bki);
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

static int resolve_hsmap(const struct voluta_sb_info *sbi,
                         voluta_index_t hs_index,
                         struct voluta_vaddr *out_vaddr)
{
	struct voluta_super_block *sb = sbi->sb;

	voluta_usm_vaddr(&sb->sb_usm, hs_index, out_vaddr);
	return vaddr_isnull(out_vaddr) ? -ENOENT : 0;
}

static int stage_hsmap(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                       struct voluta_hspace_info **out_hsi)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi = NULL;

	err = resolve_hsmap(sbi, hs_index, &vaddr);
	if (err) {
		return err;
	}
	err = stage_vnode(sbi, &vaddr, &vi);
	if (err) {
		return err;
	}
	*out_hsi = voluta_hsi_from_vi(vi);
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

static int verify_agm_stat(struct voluta_hspace_info *hsi,
                           struct voluta_agroup_info *agi)
{
	voluta_index_t ag_index;
	struct voluta_space_stat sp_st[2];

	if (agi->ag_vi.v_verify > 1) {
		return 0;
	}
	ag_index = voluta_ag_index_of(agi);
	voluta_space_stat_at(hsi, ag_index, &sp_st[0]);
	voluta_calc_space_stat_of(agi, &sp_st[1]);
	if (!equal_space_stat(&sp_st[0], &sp_st[1])) {
		return -EFSCORRUPTED;
	}
	agi->ag_vi.v_verify++;
	return 0;
}

static int resolve_agmap(struct voluta_sb_info *sbi, voluta_index_t ag_index,
                         struct voluta_vaddr *out_agm_vaddr)
{
	int err;
	voluta_index_t hs_index;
	struct voluta_vaddr agm_vaddr = { .off = -1 };
	struct voluta_vaddr bks_vaddr = { .off = -1 };
	struct voluta_hspace_info *hsi = NULL;

	hs_index = voluta_hs_index_of_ag(ag_index);
	err = stage_hsmap(sbi, hs_index, &hsi);
	if (err) {
		return err;
	}
	voluta_resolve_vaddrs_of_ag(hsi, ag_index, &agm_vaddr, &bks_vaddr);
	if (vaddr_isnull(&agm_vaddr)) {
		return -ENOENT;
	}
	vaddr_copyto(&agm_vaddr, out_agm_vaddr);
	return 0;
}

static voluta_index_t hs_index_by_agm(const struct voluta_agroup_info *agi)
{
	const voluta_index_t ag_index = voluta_ag_index_of(agi);

	return voluta_hs_index_of_ag(ag_index);
}

static int verify_agmap(struct voluta_sb_info *sbi,
                        struct voluta_agroup_info *agi)
{
	int err;
	struct voluta_hspace_info *hsi = NULL;
	const voluta_index_t hs_index = hs_index_by_agm(agi);

	err = stage_hsmap(sbi, hs_index, &hsi);
	if (err) {
		return err;
	}
	err = verify_agm_stat(hsi, agi);
	if (err) {
		return err;
	}
	return 0;
}

static int stage_agmap(struct voluta_sb_info *sbi, voluta_index_t ag_index,
                       struct voluta_agroup_info **out_agi)
{
	int err;
	struct voluta_vaddr vaddr = { .off = -1 };
	struct voluta_vnode_info *vi = NULL;
	struct voluta_agroup_info *agi = NULL;

	err = unlimit_agmap_on_pstore(sbi, ag_index);
	if (err) {
		return err;
	}
	err = resolve_agmap(sbi, ag_index, &vaddr);
	if (err) {
		return err;
	}
	err = stage_vnode(sbi, &vaddr, &vi);
	if (err) {
		return err;
	}
	agi = voluta_agi_from_vi(vi);
	err = verify_agmap(sbi, agi);
	if (err) {
		/* TODO: cleanups */
		return err;
	}
	*out_agi = agi;
	return 0;
}

static int find_cached_ii(const struct voluta_sb_info *sbi,
                          const struct voluta_iaddr *iaddr,
                          struct voluta_inode_info **out_ii)
{
	struct voluta_cache *cache = cache_of(sbi);

	*out_ii = voluta_cache_lookup_ii(cache, iaddr);
	return (*out_ii != NULL) ? 0 : -ENOENT;
}

static int fetch_inode_at(struct voluta_sb_info *sbi,
                          const struct voluta_iaddr *iaddr,
                          struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_vnode_info *vi;

	err = find_cached_ii(sbi, iaddr, out_ii);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = spawn_bind_ii(sbi, iaddr, false, out_ii);
	if (err) {
		return err;
	}
	vi = ii_vi(*out_ii);
	err = decrypt_vnode(sbi, vi);
	if (err) {
		return err;
	}
	err = review_vnode(vi);
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
	struct voluta_iaddr iaddr;

	err = voluta_resolve_ino(sbi, ino, &iaddr);
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

static int stage_normal(struct voluta_sb_info *sbi,
                        const struct voluta_vaddr *vaddr,
                        const struct voluta_inode_info *pii,
                        struct voluta_vnode_info **out_vi)
{
	int err;

	err = stage_vnode(sbi, vaddr, out_vi);
	if (err) {
		return err;
	}
	update_dskey(*out_vi, pii);
	return 0;
}

int voluta_stage_vnode(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       const struct voluta_inode_info *pii,
                       struct voluta_vnode_info **out_vi)
{
	int err;

	ii_incref(pii);
	err = stage_normal(sbi, vaddr, pii, out_vi);
	ii_decref(pii);
	return err;
}

int voluta_stage_data(struct voluta_sb_info *sbi,
                      const struct voluta_vaddr *vaddr,
                      const struct voluta_inode_info *pii,
                      struct voluta_vnode_info **out_vi)
{
	voluta_assert(vaddr_isdata(vaddr));
	voluta_assert_not_null(pii);

	return voluta_stage_vnode(sbi, vaddr, pii, out_vi);
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

static int allocate_space(struct voluta_sb_info *sbi,
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
	mark_allocated_at(sbi, spa->hsi, spa->agi, &spa->vaddr);
	return 0;
}

int voluta_allocate_space(struct voluta_sb_info *sbi,
                          enum voluta_vtype vtype,
                          struct voluta_vaddr *out_vaddr)
{
	int err;
	struct voluta_spalloc_ctx spa = {
		.vtype = vtype,
		.first_alloc = false
	};

	err = allocate_space(sbi, &spa);
	if (err) {
		return err;
	}
	vaddr_copyto(&spa.vaddr, out_vaddr);
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
	vi_stamp_view(vi);
}

static void setup_inode(struct voluta_inode_info *ii,
                        const struct voluta_oper *op,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev)
{
	const struct voluta_ucred *ucred = &op->ucred;

	setup_vnode(ii_vi(ii), ii);
	voluta_setup_inode(ii, ucred, parent_ino, parent_mode, mode, rdev);
	update_itimes(op, ii, VOLUTA_IATTR_TIMES);
}

static int create_inode(struct voluta_sb_info *sbi,
                        struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_iaddr iaddr;
	struct voluta_spalloc_ctx spa = {
		.vtype = VOLUTA_VTYPE_INODE,
		.first_alloc = false
	};

	err = allocate_space(sbi, &spa);
	if (err) {
		return err;
	}
	err = acquire_ino_at(sbi, &spa.vaddr, &iaddr);
	if (err) {
		return err;
	}
	err = spawn_bind_ii(sbi, &iaddr, spa.first_alloc, out_ii);
	if (err) {
		/* TODO: spfree inode from ag */
		return err;
	}
	return 0;
}

int voluta_create_inode(struct voluta_sb_info *sbi,
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
	err = create_inode(sbi, out_ii);
	if (err) {
		return err;
	}
	setup_inode(*out_ii, op, parent_ino, parent_mode, mode, rdev);
	return 0;
}

/* TODO: cleanups and resource reclaim upon failure in every path */
static int create_vnode(struct voluta_sb_info *sbi,
                        struct voluta_inode_info *pii,
                        enum voluta_vtype vtype,
                        struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_spalloc_ctx spa = {
		.vtype = vtype,
		.first_alloc = false
	};

	err = allocate_space(sbi, &spa);
	if (err) {
		return err;
	}
	err = spawn_bind_vi(sbi, &spa.vaddr, spa.first_alloc, out_vi);
	if (err) {
		/* TODO: spfree inode from ag */
		return err;
	}
	setup_vnode(*out_vi, pii);
	return 0;
}

int voluta_create_vnode(struct voluta_sb_info *sbi,
                        struct voluta_inode_info *pii,
                        enum voluta_vtype vtype,
                        struct voluta_vnode_info **out_vi)
{
	int err;

	ii_incref(pii);
	err = create_vnode(sbi, pii, vtype, out_vi);
	ii_decref(pii);
	return err;
}

static int deallocate_space(struct voluta_sb_info *sbi,
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
	err = deallocate_space(sbi, &iaddr->vaddr);
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
                           const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_bk_info *bki = NULL;

	err = find_cached_bk(sbi, vaddr->lba, &bki);
	if (!err) {
		voluta_mark_opaque_at(bki, vaddr);
	}
}

static int free_vspace_at(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr)
{
	int err;

	err = deallocate_space(sbi, vaddr);
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

	err = free_vspace_at(sbi, vi_vaddr(vi));
	if (err) {
		return err;
	}
	forget_cached_vi(vi);
	return 0;
}

int voluta_remove_vnode_at(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	err = find_cached_vi(sbi, vaddr, &vi);
	if (!err) {
		err = voluta_remove_vnode(sbi, vi);
	} else if (err == -ENOENT) {
		err = free_vspace_at(sbi, vaddr);
	}
	return err;
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
	*out_res = voluta_has_unwritten_at(agi, vaddr);
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
	voluta_clear_unwritten_at(agi, vaddr);
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
	voluta_mark_unwritten_at(agi, vaddr);
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

int voluta_kivam_of(const struct voluta_vnode_info *vi,
                    struct voluta_kivam *out_kivam)
{
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);
	const struct voluta_super_block *sb = vi->v_sbi->sb;

	voluta_sb_kivam_of(sb, vaddr, out_kivam);
	return 0;
}
