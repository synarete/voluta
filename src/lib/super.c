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


struct voluta_super_ctx {
	struct voluta_sb_info    *sbi;
	struct voluta_bk_info    *bki;
	struct voluta_vnode_info *hsm_vi;
	struct voluta_vnode_info *agm_vi;
	struct voluta_inode_info *pii;
	struct voluta_inode_info *ii;
	struct voluta_vnode_info *vi;
};


static int stage_hsmap(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                       struct voluta_vnode_info **out_vi);
static int stage_agmap(struct voluta_sb_info *sbi, voluta_index_t ag_index,
                       struct voluta_vnode_info **out_vi);
static int fetch_parents_of(struct voluta_super_ctx *s_ctx,
                            const struct voluta_vaddr *vaddr);
static int format_head_spmaps_of(struct voluta_sb_info *sbi,
                                 voluta_index_t hs_index);
static int format_next_agmap(struct voluta_sb_info *sbi,
                             struct voluta_vnode_info *hsm_vi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_cache *cache_of(const struct voluta_super_ctx *s_ctx)
{
	return s_ctx->sbi->sb_cache;
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
	const loff_t off = VOLUTA_AG_SIZE;

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void setup_agmap(struct voluta_vnode_info *agm_vi,
                        voluta_index_t ag_index)
{
	vi_stamp_view(agm_vi);
	voluta_setup_agmap(agm_vi, ag_index);
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
	const voluta_index_t hs_index = vaddr_hs_index(vaddr);
	const voluta_index_t ag_index = vaddr_ag_index(vaddr);
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

static void resolve_bk_xiovec(const struct voluta_sb_info *sbi,
                              const struct voluta_bk_info *bki,
                              struct voluta_xiovec *out_xiov)
{
	out_xiov->base = NULL;
	out_xiov->off = lba_to_off(bki->bk_lba);
	out_xiov->len = sizeof(*bki->bk);
	out_xiov->fd = sbi->sb_vstore->vs_pstore.ps_vfd;
}

static int find_cached_bki(struct voluta_sb_info *sbi, voluta_lba_t lba,
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
	const voluta_lba_t lba = vaddr->lba;
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

static struct voluta_vstore *vstore_of(const struct voluta_super_ctx *s_ctx)
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

static int allocate_at(struct voluta_sb_info *sbi,
                       struct voluta_vnode_info *hsm_vi,
                       voluta_index_t ag_index,
                       enum voluta_vtype vtype,
                       struct voluta_vaddr *out_vaddr)
{
	int err;
	struct voluta_vnode_info *agm_vi = NULL;
	struct voluta_space_stat sp_st = { .zero = 0 };

	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	err = voluta_allocate_space(hsm_vi, agm_vi, vtype, out_vaddr);
	if (err) {
		return err;
	}
	calc_stat_change(out_vaddr, 1, &sp_st);
	voluta_update_space(hsm_vi, ag_index, &sp_st);
	return 0;
}

static int try_allocate_at(struct voluta_vnode_info *hsm_vi,
                           voluta_index_t ag_index, enum voluta_vtype vtype,
                           struct voluta_vaddr *out_vaddr)
{
	int err;
	const size_t nbytes = vtype_size(vtype);
	const size_t bk_size = VOLUTA_BK_SIZE;
	struct voluta_sb_info *sbi = vi_sbi(hsm_vi);

	err = allocate_at(sbi, hsm_vi, ag_index, vtype, out_vaddr);
	if ((err == -ENOSPC) && (nbytes < bk_size)) {
		voluta_mark_fragmented(hsm_vi, ag_index);
	}
	return err;
}

static int try_allocate_within(struct voluta_vnode_info *hsm_vi,
                               voluta_index_t ag_index_first,
                               voluta_index_t ag_index_last,
                               enum voluta_vtype vtype,
                               struct voluta_vaddr *out_vaddr)
{
	int err;
	voluta_index_t ag_index;

	ag_index = ag_index_first;
	while (ag_index < ag_index_last) {
		err = voluta_find_free_vspace(hsm_vi, ag_index,
		                              ag_index_last, vtype, &ag_index);
		if (err) {
			return err;
		}
		err = try_allocate_at(hsm_vi, ag_index, vtype, out_vaddr);
		if (!err) {
			voluta_bind_to_vtype(hsm_vi, ag_index, vtype);
			return 0;
		}
		if (err != -ENOSPC) {
			return err;
		}
		ag_index++;
	}
	return -ENOSPC;
}

static int try_allocate_by_vtype(struct voluta_vnode_info *hsm_vi,
                                 enum voluta_vtype vtype,
                                 struct voluta_vaddr *out_vaddr)
{
	int err;
	struct voluta_ag_range ag_range = { .beg = 0, .end = 0 };

	voluta_ag_range_of(hsm_vi, &ag_range);

	/* fast search */
	err = try_allocate_within(hsm_vi, ag_range.tip, ag_range.fin,
	                          vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	/* slow search */
	err = try_allocate_within(hsm_vi, ag_range.beg, ag_range.tip,
	                          vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int try_allocate_space_at(struct voluta_vnode_info *hsm_vi,
                                 enum voluta_vtype vtype,
                                 struct voluta_vaddr *out_vaddr)
{
	int err;

	err = voluta_check_cap_alloc(hsm_vi, vtype);
	if (err) {
		return err;
	}
	err = try_allocate_by_vtype(hsm_vi, vtype, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int do_allocate_from(struct voluta_vnode_info *hsm_vi,
                            enum voluta_vtype vtype,
                            struct voluta_vaddr *out_vaddr)
{
	int err;

	err = try_allocate_space_at(hsm_vi, vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	err = format_next_agmap(hsm_vi->v_sbi, hsm_vi);
	if (err) {
		return err;
	}
	err = try_allocate_space_at(hsm_vi, vtype, out_vaddr);
	if (err != -ENOSPC) {
		return err;
	}
	return -ENOSPC;
}

static int try_allocate_from(struct voluta_vnode_info *hsm_vi,
                             enum voluta_vtype vtype,
                             struct voluta_vaddr *out_vaddr)
{
	int err;

	vi_incref(hsm_vi);
	err = do_allocate_from(hsm_vi, vtype, out_vaddr);
	vi_decref(hsm_vi);
	return err;
}

static int try_allocate_space(struct voluta_sb_info *sbi,
                              enum voluta_vtype vtype,
                              struct voluta_vaddr *out_vaddr)
{
	int err;
	voluta_index_t hs_index;
	struct voluta_vnode_info *hsm_vi;
	struct voluta_space_info *spi = &sbi->sb_spi;
	const size_t bk_size = VOLUTA_BK_SIZE;

	hs_index = spi->sp_hs_index_lo;
	while (hs_index <= spi->sp_hs_active) {
		err = stage_hsmap(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		err = try_allocate_from(hsm_vi, vtype, out_vaddr);
		if (!err || (err != -ENOSPC)) {
			return err;
		}
		hs_index++;
		err = voluta_check_cap_alloc(hsm_vi, 2 * bk_size);
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

static int deallocate_at(struct voluta_sb_info *sbi,
                         const struct voluta_vaddr *vaddr)
{
	int err;
	const voluta_index_t hs_index = vaddr_hs_index(vaddr);
	const voluta_index_t ag_index = vaddr_ag_index(vaddr);
	struct voluta_vnode_info *hsm_vi = NULL;
	struct voluta_vnode_info *agm_vi = NULL;
	struct voluta_space_stat sp_st = { .zero = 0 };

	voluta_assert_gt(hs_index, 0);
	err = stage_hsmap(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	voluta_deallocate_space_at(hsm_vi, agm_vi, vaddr);

	calc_stat_change(vaddr, -1, &sp_st);
	voluta_update_space(hsm_vi, ag_index, &sp_st);
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
	case VOLUTA_VTYPE_DATA1K:
		vi->vu.db1 = &view->u.db1;
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

	s_ctx->vi->v_sbi = s_ctx->sbi;
	voluta_vi_attach_to(vi, s_ctx->bki);
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
	voluta_index_t hs_index;
	struct voluta_vnode_info *hsm_vi = NULL;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	for (hs_index = 1; (hs_index <= hs_count); ++hs_index) {
		err = stage_hsmap(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		err = voluta_find_itroot_ag(hsm_vi, out_ag_index);
		if (!err) {
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
	voluta_index_t ag_index;
	struct voluta_vnode_info *agm_vi = NULL;

	err = sbi_resolve_itroot_ag(sbi, &ag_index);
	if (err) {
		return err;
	}
	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	voluta_parse_itroot(agm_vi, out_vaddr);
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

static int stamp_itable_at(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *hsm_vi = NULL;
	struct voluta_vnode_info *agm_vi = NULL;

	err = stage_hsmap(sbi, vaddr->hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	err = stage_agmap(sbi, vaddr->ag_index, &agm_vi);
	if (err) {
		return err;
	}
	voluta_assign_itroot(hsm_vi, agm_vi, vaddr);
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
	voluta_index_t hs_index;
	struct voluta_space_info *spi = &sbi->sb_spi;
	struct voluta_space_stat sp_st = { .zero = 0 };

	hs_index = voluta_hs_index_of(hsm_vi);
	voluta_space_stat_of(hsm_vi, &sp_st);

	spi_accum_stat(spi, &sp_st);
	spi_mark_hs_active(spi, hs_index);
}

static void update_spi_on_hsm(struct voluta_sb_info *sbi)
{
	spi_update_meta(&sbi->sb_spi, vtype_ssize(VOLUTA_VTYPE_HSMAP));
}

static void update_spi_on_agm(struct voluta_sb_info *sbi)
{
	STATICASSERT_EQ(sizeof(struct voluta_bk_rec), 56);
	STATICASSERT_EQ(sizeof(struct voluta_agroup_map), VOLUTA_BK_SIZE);

	spi_update_meta(&sbi->sb_spi, vtype_ssize(VOLUTA_VTYPE_AGMAP));
}

static int spawn_hsmap_of(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                          struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr vaddr;
	struct voluta_super_ctx s_ctx = { .sbi = sbi, };

	voluta_vaddr_of_hsmap(&vaddr, hs_index);
	return spawn_meta(&s_ctx, &vaddr, out_vi);
}

static void setup_hsmap(struct voluta_vnode_info *hsm_vi,
                        voluta_index_t hs_index, size_t nags_span)
{
	vi_stamp_view(hsm_vi);
	voluta_setup_hsmap(hsm_vi, hs_index, nags_span);
	vi_dirtify(hsm_vi);
}

static int format_hsmap(struct voluta_sb_info *sbi,
                        voluta_index_t hs_index, size_t nags_span,
                        struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *hsm_vi;

	err = spawn_hsmap_of(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	setup_hsmap(hsm_vi, hs_index, nags_span);
	update_spi_on_hsm(sbi);

	*out_vi = hsm_vi;
	return 0;
}

static int mark_prev_hsmap_with_next(struct voluta_sb_info *sbi,
                                     voluta_index_t hs_index)
{
	int err;
	voluta_index_t hs_index_prev;
	struct voluta_vnode_info *hsm_vi = NULL;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	if ((hs_index <= 1) || (hs_index >= hs_count)) {
		return 0;
	}
	hs_index_prev = hs_index - 1;
	err = stage_hsmap(sbi, hs_index_prev, &hsm_vi);
	if (err) {
		return err;
	}
	voluta_mark_with_next(hsm_vi);
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
                           struct voluta_vnode_info **out_hsm_vi)
{
	int err;
	const size_t nags_span = nags_limit_of(sbi, hs_index);

	err = format_hsmap(sbi, hs_index, nags_span, out_hsm_vi);
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
	struct voluta_vnode_info *hsm_vi = NULL;

	err = format_hsmap_of(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	err = format_next_agmap(sbi, hsm_vi);
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

static int do_format_agmap_of(struct voluta_sb_info *sbi,
                              struct voluta_vnode_info *hsm_vi,
                              voluta_index_t ag_index)
{
	int err;
	struct voluta_vnode_info *agm_vi;

	err = unlimit_agmap_on_pstore(sbi, ag_index);
	if (err) {
		return err;
	}
	err = spawn_agmap_of(sbi, ag_index, hsm_vi, &agm_vi);
	if (err) {
		return err;
	}
	setup_agmap(agm_vi, ag_index);

	voluta_set_formatted_ag(hsm_vi, ag_index);
	update_spi_on_agm(sbi);
	return 0;
}

static int format_agmap_of(struct voluta_sb_info *sbi,
                           struct voluta_vnode_info *hsm_vi,
                           voluta_index_t ag_index)
{
	int err;

	vi_incref(hsm_vi);
	err = do_format_agmap_of(sbi, hsm_vi, ag_index);
	vi_decref(hsm_vi);
	return err;
}

static bool isumap_ag_index(voluta_index_t ag_index)
{
	return voluta_ag_index_isumap(ag_index);
}

static int next_unformatted_ag(const struct voluta_vnode_info *hsm_vi,
                               voluta_index_t *out_ag_index)
{
	voluta_index_t ag_index;
	struct voluta_ag_range ag_range;

	voluta_ag_range_of(hsm_vi, &ag_range);
	ag_index = ag_range.fin;
	if (isumap_ag_index(ag_index)) {
		ag_index++;
	}
	if (ag_index >= ag_range.end) {
		return -ENOSPC;
	}
	*out_ag_index = ag_index;
	return 0;
}

static int format_next_agmap(struct voluta_sb_info *sbi,
                             struct voluta_vnode_info *hsm_vi)
{
	int err;
	voluta_index_t ag_index;

	err = next_unformatted_ag(hsm_vi, &ag_index);
	if (err) {
		return err;
	}
	err = format_agmap_of(sbi, hsm_vi, ag_index);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int load_hsmap_at(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                         struct voluta_vnode_info **out_hsm_vi)
{
	int err;
	struct voluta_vnode_info *hsm_vi;

	err = stage_hsmap(sbi, hs_index, &hsm_vi);
	if (err) {
		return err;
	}
	update_spi_by_hsm(sbi, hsm_vi);
	update_spi_on_hsm(sbi);

	*out_hsm_vi = hsm_vi;
	return 0;
}

static int load_agmap_of(struct voluta_sb_info *sbi,
                         struct voluta_vnode_info *hsm_vi,
                         voluta_index_t ag_index)
{
	int err;
	struct voluta_vnode_info *agm_vi;

	voluta_assert_not_null(hsm_vi);
	voluta_assert_eq(hsm_vi->vaddr.vtype, VOLUTA_VTYPE_HSMAP);

	if (!voluta_has_formatted_ag(hsm_vi, ag_index)) {
		return -EFSCORRUPTED;
	}

	err = stage_agmap(sbi, ag_index, &agm_vi);
	if (err) {
		return err;
	}
	return 0;
}

static int load_first_agmap_of(struct voluta_sb_info *sbi,
                               struct voluta_vnode_info *hsm_vi)
{
	int err;
	const voluta_index_t hs_index = voluta_hs_index_of(hsm_vi);
	const voluta_index_t ag_index = voluta_ag_index_by_hs(hs_index, 1);

	vi_incref(hsm_vi);
	err = load_agmap_of(sbi, hsm_vi, ag_index);
	vi_decref(hsm_vi);
	return err;
}

int voluta_reload_spmaps(struct voluta_sb_info *sbi)
{
	int err;
	bool has_next;
	voluta_index_t hs_index;
	struct voluta_vnode_info *hsm_vi;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	for (hs_index = 1; (hs_index <= hs_count); ++hs_index) {
		err = load_hsmap_at(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		err = load_first_agmap_of(sbi, hsm_vi);
		if (err) {
			return err;
		}
		has_next = voluta_has_next_hspace(hsm_vi);
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
	const voluta_index_t ag_index = voluta_ag_index_of(agm_vi);

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
	err = voluta_vstore_clear_bk(vstore_of(s_ctx), bai->lba);
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
	struct voluta_balloc_info bai = { .cnt = 0 };

	for (size_t bk_idx = 0; bk_idx < VOLUTA_NBK_IN_AG; ++bk_idx) {
		voluta_balloc_info_at(agm_vi, bk_idx, &bai);
		if (voluta_vtype_isumap(bai.vtype)) {
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
                             struct voluta_vnode_info *hsm_vi,
                             struct voluta_vnode_info *agm_vi)
{
	int err;
	struct voluta_super_ctx s_ctx = {
		.sbi = sbi,
		.hsm_vi = hsm_vi,
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
	voluta_index_t ag_index;
	struct voluta_ag_range ag_range;
	struct voluta_vnode_info *hsm_vi = s_ctx->hsm_vi;

	voluta_ag_range_of(hsm_vi, &ag_range);
	for (ag_index = ag_range.beg; ag_index < ag_range.fin; ++ag_index) {
		if (isumap_ag_index(ag_index)) {
			continue;
		}
		err = stage_agmap(s_ctx->sbi, ag_index, &s_ctx->agm_vi);
		if (err) {
			return err;
		}
		err = traverse_by_agmap(s_ctx->sbi, hsm_vi, s_ctx->agm_vi);
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
	voluta_index_t hs_index;
	struct voluta_vnode_info *hsm_vi;
	const size_t hs_count = sbi->sb_spi.sp_hs_count;

	voluta_assert_gt(hs_count, 0);

	for (hs_index = 1; hs_index <= hs_count; ++hs_index) {
		err = load_hsmap_at(sbi, hs_index, &hsm_vi);
		if (err) {
			return err;
		}
		err = traverse_by_hsmap(sbi, hsm_vi);
		if (err) {
			return err;
		}
		has_next = voluta_has_next_hspace(hsm_vi);
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

int voluta_stage_agmap_of(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_vnode_info **out_agm_vi)
{
	return stage_agmap(sbi, vaddr->ag_index, out_agm_vi);
}

static int fetch_agmap_of(struct voluta_super_ctx *s_ctx,
                          const struct voluta_vaddr *vaddr)
{
	return voluta_stage_agmap_of(s_ctx->sbi, vaddr, &s_ctx->agm_vi);
}

static int require_stable_at(const struct voluta_super_ctx *s_ctx,
                             const struct voluta_vaddr *vaddr)
{
	return voluta_allocated_with(s_ctx->agm_vi, vaddr) ? 0 : -EFSCORRUPTED;
}

static int fetch_parents_of(struct voluta_super_ctx *s_ctx,
                            const struct voluta_vaddr *vaddr)
{
	int err;

	err = fetch_bki_of(s_ctx, vaddr);
	if (err) {
		return err;
	}
	if (voluta_vtype_isumap(vaddr->vtype)) {
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

static int stage_hsmap(struct voluta_sb_info *sbi, voluta_index_t hs_index,
                       struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr vaddr;
	struct voluta_super_ctx s_ctx = { .sbi = sbi, };

	voluta_vaddr_of_hsmap(&vaddr, hs_index);
	return stage_meta(&s_ctx, &vaddr, out_vi);
}

int voluta_stage_hsmap_of(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_vnode_info **out_hsm_vi)
{
	return stage_hsmap(sbi, vaddr_hs_index(vaddr), out_hsm_vi);
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

static int verify_agm_stat(struct voluta_vnode_info *hsm_vi,
                           struct voluta_vnode_info *agm_vi)
{
	voluta_index_t ag_index;
	struct voluta_space_stat sp_st[2];

	if (agm_vi->v_verify > 1) {
		return 0;
	}
	ag_index = voluta_ag_index_of(agm_vi);
	voluta_space_stat_at(hsm_vi, ag_index, &sp_st[0]);
	voluta_calc_space_stat_of(agm_vi, &sp_st[1]);
	if (!equal_space_stat(&sp_st[0], &sp_st[1])) {
		return -EFSCORRUPTED;
	}
	agm_vi->v_verify++;
	return 0;
}

static int stage_agmap(struct voluta_sb_info *sbi, voluta_index_t ag_index,
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
	err = voluta_stage_hsmap_of(sbi, &vaddr, &s_ctx.hsm_vi);
	if (err) {
		return err;
	}
	err = stage_meta(&s_ctx, &vaddr, &agm_vi);
	if (err) {
		return err;
	}
	err = verify_agm_stat(s_ctx.hsm_vi, agm_vi);
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

int voluta_fetch_cached_inode(struct voluta_sb_info *sbi, ino_t xino,
                              struct voluta_inode_info **out_ii)
{
	int err;
	ino_t ino;
	struct voluta_iaddr iaddr;
	struct voluta_super_ctx s_ctx = { .sbi = sbi };

	err = resolve_real_ino(&s_ctx, xino, &ino);
	if (err) {
		return err;
	}
	err = resolve_iaddr(&s_ctx, ino, &iaddr);
	if (err) {
		return err;
	}
	err = find_cached_ii(&s_ctx, &iaddr);
	if (err) {
		return err;
	}
	voluta_assert_not_null(s_ctx.ii);
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

	return (((mode & S_IFMT) | sup) == sup) ? 0 : -EOPNOTSUPP;
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
	err = voluta_stage_hsmap_of(sbi, vaddr, &hsm_vi);
	if (err) {
		return err;
	}
	err = voluta_stage_agmap_of(sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	return 0;
}

static void setup_vnode(struct voluta_super_ctx *s_ctx)
{
	vi_stamp_view(s_ctx->vi);
}

static void setup_inode(struct voluta_super_ctx *s_ctx,
                        const struct voluta_oper *op,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev)
{
	struct voluta_inode_info *ii = s_ctx->ii;
	const struct voluta_ucred *ucred = &op->ucred;

	setup_vnode(s_ctx);
	voluta_setup_inode(ii, ucred, parent_ino, parent_mode, mode, rdev);
	update_itimes(op, ii, VOLUTA_IATTR_TIMES);
}

static int create_inode(struct voluta_super_ctx *s_ctx,
                        const struct voluta_oper *op,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev)
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
	setup_inode(s_ctx, op, parent_ino, parent_mode, mode, rdev);
	return 0;
}

int voluta_create_inode(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op,
                        ino_t parent_ino, mode_t parent_mode,
                        mode_t mode, dev_t rdev,
                        struct voluta_inode_info **out_ii)
{
	int err;
	struct voluta_super_ctx s_ctx = { .sbi = sbi, };

	err = require_supported_itype(mode);
	if (err) {
		return err;
	}
	err = create_inode(&s_ctx, op, parent_ino, parent_mode, mode, rdev);
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
	setup_vnode(s_ctx);
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

static int forget_and_discard_inode(struct voluta_super_ctx *s_ctx,
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
	return forget_and_discard_inode(&s_ctx, &iaddr);
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
	*out_res = voluta_has_unwritten_at(s_ctx.agm_vi, vaddr);
	return 0;
}

int voluta_clear_unwritten(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *agm_vi = NULL;

	err = voluta_stage_agmap_of(sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	voluta_clear_unwritten_at(agm_vi, vaddr);
	return 0;
}

int voluta_mark_unwritten(struct voluta_sb_info *sbi,
                          const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *agm_vi = NULL;

	err = voluta_stage_agmap_of(sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	voluta_mark_unwritten_at(agm_vi, vaddr);
	return 0;
}

int voluta_refcnt_at(struct voluta_sb_info *sbi,
                     const struct voluta_vaddr *vaddr, size_t *out_refcnt)
{
	int err;
	struct voluta_vnode_info *agm_vi = NULL;

	err = voluta_stage_agmap_of(sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	*out_refcnt = voluta_refcnt_of_vnode(agm_vi, vaddr);
	return 0;
}

int voluta_decref_at(struct voluta_sb_info *sbi,
                     const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *agm_vi = NULL;

	err = voluta_stage_agmap_of(sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	voluta_decref_of_vnode(agm_vi, vaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int kivam_of_hsmap(const struct voluta_vnode_info *vi,
                          struct voluta_kivam *out_kivam)
{
	voluta_index_t hs_index;
	const struct voluta_kivam *kivam;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);
	const struct voluta_super_block *sb = vi->v_sbi->sb;

	hs_index = vaddr_hs_index(vaddr);
	kivam = voluta_sb_kivam_of(sb, hs_index);
	voluta_kivam_copyto(kivam, out_kivam);

	voluta_kivam_xor_iv(out_kivam, 0);
	return 0;
}

static int kivam_of_agmap(const struct voluta_vnode_info *agm_vi,
                          struct voluta_kivam *out_kivam)
{
	int err;
	struct voluta_vnode_info *hsm_vi;
	const struct voluta_vaddr *vaddr = vi_vaddr(agm_vi);

	err = voluta_stage_hsmap_of(agm_vi->v_sbi, vaddr, &hsm_vi);
	if (err) {
		return err;
	}
	voluta_kivam_of_agmap(hsm_vi, vaddr->ag_index, out_kivam);
	return 0;
}

static int kivam_of_vnode(const struct voluta_vnode_info *vi,
                          struct voluta_kivam *out_kivam)
{
	int err;
	struct voluta_vnode_info *agm_vi;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	err = voluta_stage_agmap_of(vi->v_sbi, vaddr, &agm_vi);
	if (err) {
		return err;
	}
	voluta_kivam_of_vnode_at(agm_vi, vi_vaddr(vi), out_kivam);
	return 0;
}

int voluta_kivam_of(const struct voluta_vnode_info *vi,
                    struct voluta_kivam *out_kivam)
{
	int err = 0;
	const enum voluta_vtype vtype = vi_vtype(vi);

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		err = kivam_of_hsmap(vi, out_kivam);
		break;
	case VOLUTA_VTYPE_AGMAP:
		err = kivam_of_agmap(vi, out_kivam);
		break;
	case VOLUTA_VTYPE_ITNODE:
	case VOLUTA_VTYPE_INODE:
	case VOLUTA_VTYPE_XANODE:
	case VOLUTA_VTYPE_HTNODE:
	case VOLUTA_VTYPE_RTNODE:
	case VOLUTA_VTYPE_SYMVAL:
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		err = kivam_of_vnode(vi, out_kivam);
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		voluta_kivam_setup(out_kivam);
		break;
	}
	return err;
}
