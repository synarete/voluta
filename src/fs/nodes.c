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
#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <voluta/fs/address.h>
#include <voluta/fs/types.h>
#include <voluta/fs/mpool.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/private.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lh_init(struct voluta_list_head *lh)
{
	voluta_list_head_init(lh);
}

static void lh_fini(struct voluta_list_head *lh)
{
	voluta_list_head_fini(lh);
}

static void an_init(struct voluta_avl_node *an)
{
	voluta_avl_node_init(an);
}

static void an_fini(struct voluta_avl_node *an)
{
	voluta_avl_node_fini(an);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bi_init(struct voluta_bnode_info *bi)
{
	baddr_reset(&bi->baddr);
	bi->bp = NULL;
}

static void bi_fini(struct voluta_bnode_info *bi)
{
	baddr_reset(&bi->baddr);
	bi->bp = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vi_init(struct voluta_vnode_info *vi,
                    voluta_vi_delete_fn del_hook)
{
	bi_init(&vi->v_bi);
	voluta_ce_init(&vi->v_ce);
	lh_init(&vi->v_dq_blh);
	lh_init(&vi->v_dq_mlh);
	an_init(&vi->v_ds_an);
	vaddr_reset(&vi->vaddr);
	vi->view = NULL;
	vi->v_sbi = NULL;
	vi->v_bsi = NULL;
	vi->v_ds_next = NULL;
	vi->vu.p = NULL;
	vi->v_ds_key = 0;
	vi->v_dirty = 0;
	vi->v_verify = 0;
	vi->v_del_hook = del_hook;
}

static void vi_fini(struct voluta_vnode_info *vi)
{
	bi_fini(&vi->v_bi);
	voluta_ce_fini(&vi->v_ce);
	lh_fini(&vi->v_dq_blh);
	lh_fini(&vi->v_dq_mlh);
	an_fini(&vi->v_ds_an);
	vaddr_reset(&vi->vaddr);
	vi->view = NULL;
	vi->v_sbi = NULL;
	vi->v_bsi = NULL;
	vi->v_ds_next = NULL;
	vi->vu.p = NULL;
	vi->v_dirty = -11;
	vi->v_verify = 0;
	vi->v_del_hook = NULL;
}

static struct voluta_vnode_info *vi_malloc(struct voluta_mpool *mpool)
{
	return voluta_malloc_vi(mpool);
}

static void vi_free(struct voluta_mpool *mpool, struct voluta_vnode_info *vi)
{
	voluta_free_vi(mpool, vi);
}

static void vi_delete(struct voluta_vnode_info *vi, struct voluta_mpool *mpool)
{
	vi_fini(vi);
	vi_free(mpool, vi);
}

struct voluta_vnode_info *voluta_vi_new(struct voluta_mpool *mpool)
{
	struct voluta_vnode_info *vi;

	vi = vi_malloc(mpool);
	if (vi != NULL) {
		vi_init(vi, vi_delete);
	}
	return vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_hspace_info *
voluta_hsi_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_hspace_info *hsi = NULL;

	if (likely(vi != NULL)) {
		hsi = container_of2(vi, struct voluta_hspace_info, hs_vi);
	}
	return unconst(hsi);
}

static void hsi_init(struct voluta_hspace_info *hsi,
                     voluta_vi_delete_fn del_hook)
{
	vi_init(&hsi->hs_vi, del_hook);
	baddr_reset(&hsi->hs_baddr);
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
}

static void hsi_fini(struct voluta_hspace_info *hsi)
{
	vi_fini(&hsi->hs_vi);
	baddr_reset(&hsi->hs_baddr);
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
}

static struct voluta_hspace_info *hsi_malloc(struct voluta_qalloc *qal)
{
	struct voluta_hspace_info *hsi;

	hsi = voluta_qalloc_malloc(qal, sizeof(*hsi));
	return hsi;
}

static void hsi_free(struct voluta_qalloc *qal, struct voluta_hspace_info *hsi)
{
	voluta_qalloc_free(qal, hsi, sizeof(*hsi));
}

static void hsi_delete(struct voluta_hspace_info *hsi,
                       struct voluta_mpool *mpool)
{
	hsi_fini(hsi);
	hsi_free(mpool->mp_qal, hsi);
}

static void hsi_delete_by(struct voluta_vnode_info *vi,
                          struct voluta_mpool *mpool)
{
	hsi_delete(voluta_hsi_from_vi(vi), mpool);
}

struct voluta_hspace_info *voluta_hsi_new(struct voluta_mpool *mpool)
{
	struct voluta_hspace_info *hsi;

	hsi = hsi_malloc(mpool->mp_qal);
	if (hsi != NULL) {
		hsi_init(hsi, hsi_delete_by);
	}
	return hsi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_agroup_info *
voluta_agi_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_agroup_info *agi = NULL;

	if (likely(vi != NULL)) {
		agi = container_of2(vi, struct voluta_agroup_info, ag_vi);
	}
	return unconst(agi);
}

static void agi_init(struct voluta_agroup_info *agi,
                     voluta_vi_delete_fn del_hook)
{
	vi_init(&agi->ag_vi, del_hook);
	baddr_reset(&agi->ag_baddr);
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
}

static void agi_fini(struct voluta_agroup_info *agi)
{
	vi_fini(&agi->ag_vi);
	baddr_reset(&agi->ag_baddr);
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
}

static struct voluta_agroup_info *agi_malloc(struct voluta_qalloc *qal)
{
	struct voluta_agroup_info *agi;

	agi = voluta_qalloc_malloc(qal, sizeof(*agi));
	return agi;
}

static void agi_free(struct voluta_qalloc *qal, struct voluta_agroup_info *agi)
{
	voluta_qalloc_free(qal, agi, sizeof(*agi));
}

static void agi_delete(struct voluta_agroup_info *agi,
                       struct voluta_mpool *mpool)
{
	agi_fini(agi);
	agi_free(mpool->mp_qal, agi);
}

static void agi_delete_by(struct voluta_vnode_info *vi,
                          struct voluta_mpool *mpool)
{
	agi_delete(voluta_agi_from_vi(vi), mpool);
}

struct voluta_agroup_info *voluta_agi_new(struct voluta_mpool *mpool)
{
	struct voluta_agroup_info *agi;

	agi = agi_malloc(mpool->mp_qal);
	if (agi != NULL) {
		agi_init(agi, agi_delete_by);
	}
	return agi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_inode_info *voluta_ii_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_inode_info *ii = NULL;

	if (likely(vi != NULL)) {
		ii = container_of2(vi, struct voluta_inode_info, i_vi);
	}
	return unconst(ii);
}

static void ii_init(struct voluta_inode_info *ii,
                    voluta_vi_delete_fn del_hook)
{
	vi_init(&ii->i_vi, del_hook);
	ii->inode = NULL;
	ii->i_ino = VOLUTA_INO_NULL;
	ii->i_nopen = 0;
	ii->i_nlookup = 0;
	ii->i_pinned = false;
}

static void ii_fini(struct voluta_inode_info *ii)
{
	voluta_assert_ge(ii->i_nopen, 0);

	vi_fini(&ii->i_vi);
	ii->inode = NULL;
	ii->i_ino = VOLUTA_INO_NULL;
	ii->i_nopen = INT_MIN;
}

static struct voluta_inode_info *ii_malloc(struct voluta_mpool *mpool)
{
	return voluta_malloc_ii(mpool);
}

static void ii_free(struct voluta_mpool *mpool, struct voluta_inode_info *ii)
{
	voluta_free_ii(mpool, ii);
}

static void ii_delete(struct voluta_inode_info *ii, struct voluta_mpool *mpool)
{
	ii_fini(ii);
	ii_free(mpool, ii);
}

static void ii_delete_by(struct voluta_vnode_info *vi,
                         struct voluta_mpool *mpool)
{
	ii_delete(voluta_ii_from_vi(vi), mpool);
}

struct voluta_inode_info *voluta_ii_new(struct voluta_mpool *mpool)
{
	struct voluta_inode_info *ii;

	ii = ii_malloc(mpool);
	if (ii != NULL) {
		ii_init(ii, ii_delete_by);
	}
	return ii;
}
