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
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <voluta/fs/address.h>
#include <voluta/fs/types.h>
#include <voluta/fs/mpool.h>
#include <voluta/fs/crypto.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/itable.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/dir.h>
#include <voluta/fs/file.h>
#include <voluta/fs/symlink.h>
#include <voluta/fs/xattr.h>
#include <voluta/fs/private.h>


/* local functions forward declarations */
static const struct voluta_vnode_vtbl *vi_vtbl(void);
static const struct voluta_vnode_vtbl *hsi_vtbl(void);
static const struct voluta_vnode_vtbl *agi_vtbl(void);
static const struct voluta_vnode_vtbl *itni_vtbl(void);
static const struct voluta_vnode_vtbl *ii_vtbl(void);
static const struct voluta_vnode_vtbl *xani_vtbl(void);
static const struct voluta_vnode_vtbl *symi_vtbl(void);
static const struct voluta_vnode_vtbl *htni_vtbl(void);

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

static void ui_init(struct voluta_unode_info *ui,
                    const struct voluta_baddr *baddr)
{
	baddr_copyto(baddr, &ui->u_baddr);
}

static void ui_fini(struct voluta_unode_info *ui)
{
	baddr_reset(&ui->u_baddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *vi_unconst(const struct voluta_vnode_info *vi)
{
	union {
		const struct voluta_vnode_info *p;
		struct voluta_vnode_info *q;
	} u = {
		.p = vi
	};
	return u.q;
}

static struct voluta_vnode_info *
vi_from_fiovref(const struct voluta_fiovref *fir)
{
	const struct voluta_vnode_info *vi = NULL;

	vi = container_of2(fir, struct voluta_vnode_info, v_fir);
	return vi_unconst(vi);
}


static void vi_fiov_pre(struct voluta_fiovref *fir)
{
	struct voluta_vnode_info *vi = vi_from_fiovref(fir);

	voluta_vi_incref(vi);
}

static void vi_fiov_post(struct voluta_fiovref *fir)
{
	struct voluta_vnode_info *vi = vi_from_fiovref(fir);

	voluta_vi_decref(vi);
}

static void vi_init(struct voluta_vnode_info *vi,
                    const struct voluta_vba *vba,
                    const struct voluta_vnode_vtbl *vtbl)
{
	voluta_ce_init(&vi->v_ce);
	lh_init(&vi->v_dq_blh);
	lh_init(&vi->v_dq_mlh);
	an_init(&vi->v_ds_an);
	vaddr_copyto(&vba->vaddr, &vi->vaddr);
	voluta_fiovref_init(&vi->v_fir, vi_fiov_pre, vi_fiov_post);
	vi->view = NULL;
	vi->v_sbi = NULL;
	vi->v_bsi = NULL;
	vi->v_ds_next = NULL;
	vi->vu.p = NULL;
	vi->v_ds_key = 0;
	vi->v_dirty = 0;
	vi->v_verify = 0;
	vi->v_vtbl = vtbl;
}

static void vi_fini(struct voluta_vnode_info *vi)
{
	voluta_ce_fini(&vi->v_ce);
	lh_fini(&vi->v_dq_blh);
	lh_fini(&vi->v_dq_mlh);
	an_fini(&vi->v_ds_an);
	vaddr_reset(&vi->vaddr);
	voluta_fiovref_fini(&vi->v_fir);
	vi->view = NULL;
	vi->v_sbi = NULL;
	vi->v_bsi = NULL;
	vi->v_ds_next = NULL;
	vi->vu.p = NULL;
	vi->v_dirty = -11111;
	vi->v_verify = 0;
	vi->v_vtbl = NULL;
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

static struct voluta_vnode_info *
vi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_vnode_info *vi;

	vi = vi_malloc(alif);
	if (vi != NULL) {
		vi_init(vi, vba, vi_vtbl());
	}
	return vi;
}

bool voluta_vi_isdata(const struct voluta_vnode_info *vi)
{
	return voluta_vtype_isdata(vi_vtype(vi));
}

void *voluta_vi_dat_of(const struct voluta_vnode_info *vi)
{
	void *dat;
	const enum voluta_vtype vtype = vi_vtype(vi);

	switch (vtype) {
	case VOLUTA_VTYPE_DATA1K:
		dat = vi->vu.db1->dat;
		break;
	case VOLUTA_VTYPE_DATA4K:
		dat = vi->vu.db4->dat;
		break;
	case VOLUTA_VTYPE_DATABK:
		dat = vi->vu.db->dat;
		break;
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
	case VOLUTA_VTYPE_AGBKS:
	default:
		dat = NULL;
		break;
	}
	return dat;
}

static const struct voluta_vnode_vtbl vtbl_vi = {
	.evictable = voluta_vi_isevictable,
	.del = vi_delete
};

static const struct voluta_vnode_vtbl *vi_vtbl(void)
{
	return &vtbl_vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
hsi_to_vi(const struct voluta_hspace_info *hsi)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(hsi != NULL)) {
		vi = &hsi->hs_vi;
	}
	return vi_unconst(vi);
}

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
                     const struct voluta_vnode_vtbl *vtbl)
{
	ui_init(&hsi->hs_ui, &vba->baddr);
	vi_init(&hsi->hs_vi, vba, vtbl);
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
	hsi->hsm = NULL;
}

static void hsi_fini(struct voluta_hspace_info *hsi)
{
	ui_fini(&hsi->hs_ui);
	vi_fini(&hsi->hs_vi);
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
	hsi->hsm = NULL;
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

static struct voluta_hspace_info *
hsi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_hspace_info *hsi;

	hsi = hsi_malloc(alif);
	if (hsi != NULL) {
		hsi_init(hsi, vba, hsi_vtbl());
	}
	return hsi;
}

static const struct voluta_vnode_vtbl vtbl_hsi = {
	.evictable = voluta_vi_isevictable,
	.del = hsi_delete_by
};

static const struct voluta_vnode_vtbl *hsi_vtbl(void)
{
	return &vtbl_hsi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
agi_to_vi(const struct voluta_agroup_info *agi)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(agi != NULL)) {
		vi = &agi->ag_vi;
	}
	return vi_unconst(vi);
}

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
                     const struct voluta_vnode_vtbl *vtbl)
{
	ui_init(&agi->ag_ui, &vba->baddr);
	vi_init(&agi->ag_vi, vba, vtbl);
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
	agi->agm = NULL;
}

static void agi_fini(struct voluta_agroup_info *agi)
{
	ui_fini(&agi->ag_ui);
	vi_fini(&agi->ag_vi);
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
	agi->agm = NULL;
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

static struct voluta_agroup_info *
agi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_agroup_info *agi;

	agi = agi_malloc(alif);
	if (agi != NULL) {
		agi_init(agi, vba, agi_vtbl());
	}
	return agi;
}

struct voluta_agroup_info *
voluta_agi_from_vi_rebind(struct voluta_vnode_info *vi,
                          voluta_index_t ag_index)
{
	struct voluta_agroup_info *agi = voluta_agi_from_vi(vi);

	voluta_assert_gt(ag_index, 0);
	agi->ag_index = ag_index;
	agi->agm = &vi->view->u.agm;

	return agi;
}

static const struct voluta_vnode_vtbl vtbl_agi = {
	.evictable = voluta_vi_isevictable,
	.del = agi_delete_by
};

static const struct voluta_vnode_vtbl *agi_vtbl(void)
{
	return &vtbl_agi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
itni_to_vi(const struct voluta_itnode_info *itni)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(itni != NULL)) {
		vi = &itni->itn_vi;
	}
	return vi_unconst(vi);
}

struct voluta_itnode_info *
voluta_itni_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_itnode_info *itni = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_ITNODE);
		itni = container_of2(vi, struct voluta_itnode_info, itn_vi);
	}
	return unconst(itni);
}

struct voluta_itnode_info *
voluta_itni_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_itnode_info *itni = voluta_itni_from_vi(vi);

	if (likely(itni != NULL)) {
		itni->itn = &vi->view->u.itn;
	}
	return itni;
}

static void itni_init(struct voluta_itnode_info *itni,
                      const struct voluta_vba *vba,
                      const struct voluta_vnode_vtbl *vtbl)
{
	vi_init(&itni->itn_vi, vba, vtbl);
	itni->itn = NULL;
}

static void itni_fini(struct voluta_itnode_info *itni)
{
	vi_fini(&itni->itn_vi);
	itni->itn = NULL;
}

static struct voluta_itnode_info *itni_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_itnode_info *itni;

	itni = voluta_allocate(alif, sizeof(*itni));
	return itni;
}

static void itni_free(struct voluta_itnode_info *itni,
                      struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, itni, sizeof(*itni));
}

static void itni_delete(struct voluta_itnode_info *itni,
                        struct voluta_alloc_if *alif)
{
	itni_fini(itni);
	itni_free(itni, alif);
}

static void itni_delete_by(struct voluta_vnode_info *vi,
                           struct voluta_alloc_if *alif)
{
	itni_delete(voluta_itni_from_vi(vi), alif);
}

static struct voluta_itnode_info *
itni_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_itnode_info *itni;

	itni = itni_malloc(alif);
	if (itni != NULL) {
		itni_init(itni, vba, itni_vtbl());
	}
	return itni;
}

static const struct voluta_vnode_vtbl vtbl_itni = {
	.evictable = voluta_vi_isevictable,
	.del = itni_delete_by
};

static const struct voluta_vnode_vtbl *itni_vtbl(void)
{
	return &vtbl_itni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_inode_info *voluta_ii_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_inode_info *ii = NULL;

	if (likely(vi != NULL)) {
		ii = container_of2(vi, struct voluta_inode_info, i_vi);
	}
	return ii_unconst(ii);
}

static void ii_init(struct voluta_inode_info *ii,
                    const struct voluta_vba *vba,
                    const struct voluta_vnode_vtbl *vtbl)
{
	vi_init(&ii->i_vi, vba, vtbl);
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

static struct voluta_inode_info *
ii_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_inode_info *ii;

	ii = ii_malloc(alif);
	if (ii != NULL) {
		ii_init(ii, vba, ii_vtbl());
	}
	return ii;
}

static bool ii_isevictable_by(const struct voluta_vnode_info *vi)
{
	const struct voluta_inode_info *ii = voluta_ii_from_vi(vi);

	return voluta_ii_isevictable(ii);
}


void voluta_ii_rebind(struct voluta_inode_info *ii, ino_t ino)
{
	ii->inode = &ii->i_vi.view->u.inode;
	ii->i_ino = ino;
}

static const struct voluta_vnode_vtbl vtbl_ii = {
	.evictable = ii_isevictable_by,
	.del = ii_delete_by
};

static const struct voluta_vnode_vtbl *ii_vtbl(void)
{
	return &vtbl_ii;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
xani_to_vi(const struct voluta_xanode_info *xani)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(xani != NULL)) {
		vi = &xani->xan_vi;
	}
	return vi_unconst(vi);
}

struct voluta_xanode_info *
voluta_xani_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_xanode_info *xani = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_XANODE);
		xani = container_of2(vi, struct voluta_xanode_info, xan_vi);
	}
	return unconst(xani);
}

struct voluta_xanode_info *
voluta_xani_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_xanode_info *xani = voluta_xani_from_vi(vi);

	xani->xan = &vi->view->u.xan;
	return xani;
}

static void xani_init(struct voluta_xanode_info *xani,
                      const struct voluta_vba *vba,
                      const struct voluta_vnode_vtbl *vtbl)
{
	vi_init(&xani->xan_vi, vba, vtbl);
	xani->xan = NULL;
}

static void xani_fini(struct voluta_xanode_info *xani)
{
	vi_fini(&xani->xan_vi);
	xani->xan = NULL;
}

static struct voluta_xanode_info *xani_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_xanode_info *xani;

	xani = voluta_allocate(alif, sizeof(*xani));
	return xani;
}

static void xani_free(struct voluta_xanode_info *xani,
                      struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, xani, sizeof(*xani));
}

static void xani_delete(struct voluta_xanode_info *xani,
                        struct voluta_alloc_if *alif)
{
	xani_fini(xani);
	xani_free(xani, alif);
}

static void xani_delete_by(struct voluta_vnode_info *vi,
                           struct voluta_alloc_if *alif)
{
	xani_delete(voluta_xani_from_vi(vi), alif);
}

static struct voluta_xanode_info *
xani_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_xanode_info *xani;

	xani = xani_malloc(alif);
	if (xani != NULL) {
		xani_init(xani, vba, xani_vtbl());
	}
	return xani;
}

static const struct voluta_vnode_vtbl vtbl_xani = {
	.evictable = voluta_vi_isevictable,
	.del = xani_delete_by
};

static const struct voluta_vnode_vtbl *xani_vtbl(void)
{
	return &vtbl_xani;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
symi_to_vi(const struct voluta_symval_info *symi)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(symi != NULL)) {
		vi = &symi->sym_vi;
	}
	return vi_unconst(vi);
}

struct voluta_symval_info *
voluta_symi_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_symval_info *symi = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_SYMVAL);
		symi = container_of2(vi, struct voluta_symval_info, sym_vi);
	}
	return unconst(symi);
}

struct voluta_symval_info *
voluta_symi_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_symval_info *symi = voluta_symi_from_vi(vi);

	if (likely(symi != NULL)) {
		symi->sym = &symi->sym_vi.view->u.sym;
	}
	return symi;
}

static void symi_init(struct voluta_symval_info *symi,
                      const struct voluta_vba *vba,
                      const struct voluta_vnode_vtbl *vtbl)
{
	vi_init(&symi->sym_vi, vba, vtbl);
	symi->sym = NULL;
}

static void symi_fini(struct voluta_symval_info *symi)
{
	vi_fini(&symi->sym_vi);
	symi->sym = NULL;
}

static struct voluta_symval_info *symi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_symval_info *symi;

	symi = voluta_allocate(alif, sizeof(*symi));
	return symi;
}

static void symi_free(struct voluta_symval_info *symi,
                      struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, symi, sizeof(*symi));
}

static void symi_delete(struct voluta_symval_info *symi,
                        struct voluta_alloc_if *alif)
{
	symi_fini(symi);
	symi_free(symi, alif);
}

static void symi_delete_by(struct voluta_vnode_info *vi,
                           struct voluta_alloc_if *alif)
{
	symi_delete(voluta_symi_from_vi(vi), alif);
}

static struct voluta_symval_info *
symi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_symval_info *symi;

	symi = symi_malloc(alif);
	if (symi != NULL) {
		symi_init(symi, vba, symi_vtbl());
	}
	return symi;
}

static const struct voluta_vnode_vtbl vtbl_symi = {
	.evictable = voluta_vi_isevictable,
	.del = symi_delete_by
};

static const struct voluta_vnode_vtbl *symi_vtbl(void)
{
	return &vtbl_symi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
htni_to_vi(const struct voluta_htnode_info *htni)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(htni != NULL)) {
		vi = &htni->htn_vi;
	}
	return vi_unconst(vi);
}

struct voluta_htnode_info *
voluta_htni_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_htnode_info *htni = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_HTNODE);
		htni = container_of2(vi, struct voluta_htnode_info, htn_vi);
	}
	return unconst(htni);
}

struct voluta_htnode_info *
voluta_htni_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_htnode_info *htni = voluta_htni_from_vi(vi);

	if (likely(htni != NULL)) {
		htni->htn = &htni->htn_vi.view->u.htn;
	}
	return htni;
}

static void htni_init(struct voluta_htnode_info *htni,
                      const struct voluta_vba *vba,
                      const struct voluta_vnode_vtbl *vtbl)
{
	vi_init(&htni->htn_vi, vba, vtbl);
	htni->htn = NULL;
}

static void htni_fini(struct voluta_htnode_info *htni)
{
	vi_fini(&htni->htn_vi);
	htni->htn = NULL;
}

static struct voluta_htnode_info *htni_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_htnode_info *htni;

	htni = voluta_allocate(alif, sizeof(*htni));
	return htni;
}

static void htni_free(struct voluta_htnode_info *htni,
                      struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, htni, sizeof(*htni));
}

static void htni_delete(struct voluta_htnode_info *htni,
                        struct voluta_alloc_if *alif)
{
	htni_fini(htni);
	htni_free(htni, alif);
}

static void htni_delete_by(struct voluta_vnode_info *vi,
                           struct voluta_alloc_if *alif)
{
	htni_delete(voluta_htni_from_vi(vi), alif);
}

static struct voluta_htnode_info *
htni_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_htnode_info *htni;

	htni = htni_malloc(alif);
	if (htni != NULL) {
		htni_init(htni, vba, htni_vtbl());
	}
	return htni;
}

static const struct voluta_vnode_vtbl vtbl_htni = {
	.evictable = voluta_vi_isevictable,
	.del = htni_delete_by
};

static const struct voluta_vnode_vtbl *htni_vtbl(void)
{
	return &vtbl_htni;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_unode_info *
voluta_new_ui(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	/* XXX */
	voluta_unused(alif);
	voluta_unused(vba);
	return NULL;
}

struct voluta_vnode_info *
voluta_new_vi(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_vnode_info *vi;
	const enum voluta_vtype vtype = vba->vaddr.vtype;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		vi = hsi_to_vi(hsi_new(alif, vba));
		break;
	case VOLUTA_VTYPE_AGMAP:
		vi = agi_to_vi(agi_new(alif, vba));
		break;
	case VOLUTA_VTYPE_ITNODE:
		vi = itni_to_vi(itni_new(alif, vba));
		break;
	case VOLUTA_VTYPE_INODE:
		vi = ii_to_vi(ii_new(alif, vba));
		break;
	case VOLUTA_VTYPE_XANODE:
		vi = xani_to_vi(xani_new(alif, vba));
		break;
	case VOLUTA_VTYPE_SYMVAL:
		vi = symi_to_vi(symi_new(alif, vba));
		break;
	case VOLUTA_VTYPE_HTNODE:
		vi = htni_to_vi(htni_new(alif, vba));
		break;
	case VOLUTA_VTYPE_RTNODE:
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		vi = vi_new(alif, vba);
		break;
	case VOLUTA_VTYPE_NONE:
	case VOLUTA_VTYPE_SUPER:
	case VOLUTA_VTYPE_AGBKS:
	default:
		vi = NULL;
	}
	return vi;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint32_t hdr_magic(const struct voluta_header *hdr)
{
	return voluta_le32_to_cpu(hdr->h_magic);
}

static void hdr_set_magic(struct voluta_header *hdr, uint32_t magic)
{
	hdr->h_magic = voluta_cpu_to_le32(magic);
}

static size_t hdr_size(const struct voluta_header *hdr)
{
	return voluta_le32_to_cpu(hdr->h_size);
}

static size_t hdr_payload_size(const struct voluta_header *hdr)
{
	return hdr_size(hdr) - sizeof(*hdr);
}

static void hdr_set_size(struct voluta_header *hdr, size_t size)
{
	hdr->h_size = voluta_cpu_to_le32((uint32_t)size);
}

static enum voluta_vtype hdr_vtype(const struct voluta_header *hdr)
{
	return (enum voluta_vtype)(hdr->h_vtype);
}

static void hdr_set_vtype(struct voluta_header *hdr, enum voluta_vtype vtype)
{
	hdr->h_vtype = (uint8_t)vtype;
}

static uint32_t hdr_csum(const struct voluta_header *hdr)
{
	return voluta_le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct voluta_header *hdr, uint32_t csum)
{
	hdr->h_csum = voluta_cpu_to_le32(csum);
}

static const void *hdr_payload(const struct voluta_header *hdr)
{
	return hdr + 1;
}

static struct voluta_header *hdr_of(const struct voluta_view *view)
{
	const struct voluta_header *hdr = &view->u.hdr;

	return unconst(hdr);
}

static void hdr_stamp(struct voluta_header *hdr,
                      enum voluta_vtype vtype, size_t size)
{
	hdr_set_magic(hdr, VOLUTA_VTYPE_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_vtype(hdr, vtype);
	hdr_set_csum(hdr, 0);
	hdr->h_flags = 0;
	hdr->h_reserved = 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_header *
vi_hdr_of(const struct voluta_vnode_info *vi)
{
	return hdr_of(vi->view);
}


static uint32_t calc_meta_chekcsum(const struct voluta_header *hdr,
                                   const struct voluta_mdigest *md)
{
	uint32_t csum = 0;
	const void *payload = hdr_payload(hdr);
	const size_t pl_size = hdr_payload_size(hdr);

	voluta_assert_le(pl_size, VOLUTA_BK_SIZE - VOLUTA_HEADER_SIZE);

	voluta_crc32_of(md, payload, pl_size, &csum);
	return csum;
}

static uint32_t calc_data_checksum(const void *dat, size_t len,
                                   const struct voluta_mdigest *md)
{
	uint32_t csum = 0;

	voluta_crc32_of(md, dat, len, &csum);
	return csum;
}

static uint32_t calc_chekcsum_of(const struct voluta_vnode_info *vi)
{
	uint32_t csum;
	const struct voluta_mdigest *md = vi_mdigest(vi);
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if (vaddr_isdata(vaddr)) {
		csum = calc_data_checksum(vi_dat_of(vi), vaddr->len, md);
	} else {
		csum = calc_meta_chekcsum(vi_hdr_of(vi), md);
	}
	return csum;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_hdr(const struct voluta_view *view, enum voluta_vtype vtype)
{
	const struct voluta_header *hdr = hdr_of(view);
	const size_t hsz = hdr_size(hdr);
	const size_t psz = vtype_size(vtype);

	if (vtype_isdata(vtype)) {
		return 0;
	}
	if (hdr_magic(hdr) != VOLUTA_VTYPE_MAGIC) {
		return -EFSCORRUPTED;
	}
	if (hdr_vtype(hdr) != vtype) {
		return -EFSCORRUPTED;
	}
	if (hsz != psz) {
		return -EFSCORRUPTED;
	}

	return 0;
}

static int verify_checksum(const struct voluta_view *view,
                           const struct voluta_mdigest *md)
{
	uint32_t csum;
	const struct voluta_header *hdr = hdr_of(view);

	csum = calc_meta_chekcsum(hdr, md);
	return (csum == hdr_csum(hdr)) ? 0 : -EFSCORRUPTED;
}

static int verify_sub(const struct voluta_view *view, enum voluta_vtype vtype)
{
	int err;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		err = voluta_verify_hspace_map(&view->u.hsm);
		break;
	case VOLUTA_VTYPE_AGMAP:
		err = voluta_verify_agroup_map(&view->u.agm);
		break;
	case VOLUTA_VTYPE_ITNODE:
		err = voluta_verify_itnode(&view->u.itn);
		break;
	case VOLUTA_VTYPE_INODE:
		err = voluta_verify_inode(&view->u.inode);
		break;
	case VOLUTA_VTYPE_XANODE:
		err = voluta_verify_xattr_node(&view->u.xan);
		break;
	case VOLUTA_VTYPE_HTNODE:
		err = voluta_verify_dir_htree_node(&view->u.htn);
		break;
	case VOLUTA_VTYPE_RTNODE:
		err = voluta_verify_radix_tnode(&view->u.rtn);
		break;
	case VOLUTA_VTYPE_SYMVAL:
		err = voluta_verify_lnk_value(&view->u.sym);
		break;
	case VOLUTA_VTYPE_SUPER:
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
	case VOLUTA_VTYPE_AGBKS:
		err = 0;
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		err = -EFSCORRUPTED;
		break;
	}
	return err;
}

static int verify_view(const struct voluta_view *view,
                       enum voluta_vtype vtype,
                       const struct voluta_mdigest *md)
{
	int err;

	if (vtype_isdata(vtype)) {
		return 0;
	}
	err = verify_hdr(view, vtype);
	if (err) {
		return err;
	}
	err = verify_checksum(view, md);
	if (err) {
		return err;
	}
	err = verify_sub(view, vtype);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_vi_verify_meta(const struct voluta_vnode_info *vi)
{
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	return verify_view(vi->view, vaddr->vtype, vi_mdigest(vi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void stamp_view(struct voluta_view *view,
                       const struct voluta_vaddr *vaddr)
{
	struct voluta_header *hdr = hdr_of(view);

	voluta_memzero(view, vaddr->len);
	hdr_stamp(hdr, vaddr->vtype, vaddr->len);
}

void voluta_vi_stamp_view(const struct voluta_vnode_info *vi)
{
	if (!vi_isdata(vi)) {
		stamp_view(vi->view, vi_vaddr(vi));
	}
}

void voluta_vi_seal_meta(const struct voluta_vnode_info *vi)
{
	uint32_t csum;

	if (!vi_isdata(vi)) {
		csum = calc_chekcsum_of(vi);
		hdr_set_csum(hdr_of(vi->view), csum);
	}
}


