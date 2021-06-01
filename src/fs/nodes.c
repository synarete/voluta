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

static void bi_init(struct voluta_bnode_info *bi,
                    const struct voluta_baddr *baddr)
{
	baddr_copyto(baddr, &bi->baddr);
	bi->bp = NULL;
}

static void bi_fini(struct voluta_bnode_info *bi)
{
	baddr_reset(&bi->baddr);
	bi->bp = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vi_init(struct voluta_vnode_info *vi,
                    const struct voluta_vba *vba,
                    voluta_vi_delete_fn del_hook)
{
	bi_init(&vi->v_bi, &vba->baddr);
	voluta_ce_init(&vi->v_ce);
	lh_init(&vi->v_dq_blh);
	lh_init(&vi->v_dq_mlh);
	an_init(&vi->v_ds_an);
	vaddr_copyto(&vba->vaddr, &vi->vaddr);
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

static struct voluta_vnode_info *vi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_vnode_info *vi;

	vi = voluta_allocate(alif, sizeof(*vi));
	return vi;
}

static void vi_free(struct voluta_vnode_info *vi, struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, vi, sizeof(*vi));
}

static void vi_delete(struct voluta_vnode_info *vi,
                      struct voluta_alloc_if *alif)
{
	vi_fini(vi);
	vi_free(vi, alif);
}

struct voluta_vnode_info *voluta_vi_new(struct voluta_alloc_if *alif,
                                        const struct voluta_vba *vba)
{
	struct voluta_vnode_info *vi;

	vi = vi_malloc(alif);
	if (vi != NULL) {
		vi_init(vi, vba, vi_delete);
	}
	return vi;
}

void voluta_vi_vba(const struct voluta_vnode_info *vi,
                   struct voluta_vba *out_vba)
{
	voluta_vba_setup(out_vba, vi_vaddr(vi), bi_baddr(&vi->v_bi));
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
                     const struct voluta_vba *vba,
                     voluta_vi_delete_fn del_hook)
{
	vi_init(&hsi->hs_vi, vba, del_hook);
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
}

static void hsi_fini(struct voluta_hspace_info *hsi)
{
	vi_fini(&hsi->hs_vi);
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
}

static struct voluta_hspace_info *hsi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_hspace_info *hsi;

	hsi = voluta_allocate(alif, sizeof(*hsi));
	return hsi;
}

static void hsi_free(struct voluta_hspace_info *hsi,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, hsi, sizeof(*hsi));
}

static void hsi_delete(struct voluta_hspace_info *hsi,
                       struct voluta_alloc_if *alif)
{
	hsi_fini(hsi);
	hsi_free(hsi, alif);
}

static void hsi_delete_by(struct voluta_vnode_info *vi,
                          struct voluta_alloc_if *alif)
{
	hsi_delete(voluta_hsi_from_vi(vi), alif);
}

struct voluta_hspace_info *
voluta_hsi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_hspace_info *hsi;

	hsi = hsi_malloc(alif);
	if (hsi != NULL) {
		hsi_init(hsi, vba, hsi_delete_by);
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
                     const struct voluta_vba *vba,
                     voluta_vi_delete_fn del_hook)
{
	vi_init(&agi->ag_vi, vba, del_hook);
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
}

static void agi_fini(struct voluta_agroup_info *agi)
{
	vi_fini(&agi->ag_vi);
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
}

static struct voluta_agroup_info *agi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_agroup_info *agi;

	agi = voluta_allocate(alif, sizeof(*agi));
	return agi;
}

static void agi_free(struct voluta_agroup_info *agi,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, agi, sizeof(*agi));
}

static void agi_delete(struct voluta_agroup_info *agi,
                       struct voluta_alloc_if *alif)
{
	agi_fini(agi);
	agi_free(agi, alif);
}

static void agi_delete_by(struct voluta_vnode_info *vi,
                          struct voluta_alloc_if *alif)
{
	agi_delete(voluta_agi_from_vi(vi), alif);
}

struct voluta_agroup_info *
voluta_agi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_agroup_info *agi;

	agi = agi_malloc(alif);
	if (agi != NULL) {
		agi_init(agi, vba, agi_delete_by);
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
                    const struct voluta_vba *vba, ino_t ino,
                    voluta_vi_delete_fn del_hook)
{
	vi_init(&ii->i_vi, vba, del_hook);
	ii->inode = NULL;
	ii->i_ino = ino;
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

static struct voluta_inode_info *ii_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_inode_info *ii;

	ii = voluta_allocate(alif, sizeof(*ii));
	return ii;
}

static void ii_free(struct voluta_inode_info *ii,
                    struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, ii, sizeof(*ii));
}

static void ii_delete(struct voluta_inode_info *ii,
                      struct voluta_alloc_if *alif)
{
	ii_fini(ii);
	ii_free(ii, alif);
}

static void ii_delete_by(struct voluta_vnode_info *vi,
                         struct voluta_alloc_if *alif)
{
	ii_delete(voluta_ii_from_vi(vi), alif);
}

struct voluta_inode_info *
voluta_ii_new(struct voluta_alloc_if *alif,
              const struct voluta_vba *vba, ino_t ino)
{
	struct voluta_inode_info *ii;

	ii = ii_malloc(alif);
	if (ii != NULL) {
		ii_init(ii, vba, ino, ii_delete_by);
	}
	return ii;
}
