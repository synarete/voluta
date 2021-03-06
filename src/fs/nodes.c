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
#include <voluta/fs/super.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/itable.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/dir.h>
#include <voluta/fs/file.h>
#include <voluta/fs/symlink.h>
#include <voluta/fs/xattr.h>
#include <voluta/fs/private.h>


/* local functions forward declarations */
static const struct voluta_znode_vtbl *hsi_vtbl(void);
static const struct voluta_znode_vtbl *agi_vtbl(void);
static const struct voluta_znode_vtbl *itni_vtbl(void);
static const struct voluta_znode_vtbl *ii_vtbl(void);
static const struct voluta_znode_vtbl *xai_vtbl(void);
static const struct voluta_znode_vtbl *syi_vtbl(void);
static const struct voluta_znode_vtbl *dti_vtbl(void);
static const struct voluta_znode_vtbl *rti_vtbl(void);
static const struct voluta_znode_vtbl *fli_vtbl(void);

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

static void zi_init(struct voluta_znode_info *zi,
                    const struct voluta_znode_vtbl *vtbl)
{
	voluta_ce_init(&zi->z_ce);
	lh_init(&zi->z_dq_lh);
	an_init(&zi->z_ds_an);
	zi->z_ds_next = NULL;
	zi->z_sbi = NULL;
	zi->z_bsi = NULL;
	zi->z_view = NULL;
	zi->z_view_len = 0;
	zi->z_vtbl = vtbl;
}

static void zi_fini(struct voluta_znode_info *zi)
{
	voluta_ce_fini(&zi->z_ce);
	lh_fini(&zi->z_dq_lh);
	an_fini(&zi->z_ds_an);
	zi->z_ds_next = NULL;
	zi->z_sbi = NULL;
	zi->z_bsi = NULL;
	zi->z_view = NULL;
	zi->z_vtbl = NULL;
}

static void zi_seal_noop(struct voluta_znode_info *zi)
{
	voluta_unused(zi);
}

static bool zi_evictable(const struct voluta_znode_info *zi)
{
	return voluta_zi_isevictable(zi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_unode_info *ui_unconst(const struct voluta_unode_info *ui)
{
	union {
		const struct voluta_unode_info *p;
		struct voluta_unode_info *q;
	} u = {
		.p = ui
	};
	return u.q;
}

static void ui_init(struct voluta_unode_info *ui,
                    const struct voluta_uba *uba,
                    const struct voluta_znode_vtbl *vtbl)
{
	zi_init(&ui->u_zi, vtbl);
	voluta_uba_copyto(uba, &ui->uba);
}

static void ui_fini(struct voluta_unode_info *ui)
{
	voluta_uba_reset(&ui->uba);
	zi_fini(&ui->u_zi);
}

struct voluta_unode_info *voluta_ui_from_zi(const struct voluta_znode_info *zi)
{
	const struct voluta_unode_info *ui = NULL;

	if (likely(zi != NULL)) {
		ui = container_of2(zi, struct voluta_unode_info, u_zi);
	}
	return ui_unconst(ui);
}

static int ui_resolve(const struct voluta_unode_info *ui,
                      struct voluta_baddr *out_baddr)
{
	baddr_copyto(&ui->uba.baddr, out_baddr);
	return 0;
}

static int ui_resolve_as_zi(const struct voluta_znode_info *zi,
                            struct voluta_baddr *out_baddr)
{
	return ui_resolve(voluta_ui_from_zi(zi), out_baddr);
}

static void ui_seal_as_zi(struct voluta_znode_info *zi)
{
	struct voluta_unode_info *ui = voluta_ui_from_zi(zi);

	voluta_unused(ui);
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
                    const struct voluta_znode_vtbl *ci_vtbl)
{
	zi_init(&vi->v_zi, ci_vtbl);
	vaddr_copyto(&vba->vaddr, &vi->vaddr);
	voluta_fiovref_init(&vi->v_fir, vi_fiov_pre, vi_fiov_post);
	vi->v_iowner = VOLUTA_INO_NULL;
	vi->v_verify = 0;
}

static void vi_fini(struct voluta_vnode_info *vi)
{
	zi_fini(&vi->v_zi);
	vaddr_reset(&vi->vaddr);
	voluta_fiovref_fini(&vi->v_fir);
	vi->v_verify = 0;
}

struct voluta_vnode_info *voluta_vi_from_zi(const struct voluta_znode_info *zi)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(zi != NULL)) {
		vi = container_of2(zi, struct voluta_vnode_info, v_zi);
	}
	return vi_unconst(vi);
}

bool voluta_vi_isdata(const struct voluta_vnode_info *vi)
{
	return voluta_ztype_isdata(vi_ztype(vi));
}

static int vi_resolve(const struct voluta_vnode_info *vi,
                      struct voluta_baddr *out_baddr)
{
	return voluta_resolve_baddr_of(vi_sbi(vi), vi, out_baddr);
}

static int vi_resolve_as_zi(const struct voluta_znode_info *zi,
                            struct voluta_baddr *out_baddr)
{
	const struct voluta_vnode_info *vi = voluta_vi_from_zi(zi);

	return (likely(vi != NULL)) ? vi_resolve(vi, out_baddr) : -ENOENT;
}

static void vi_seal_as_zi(struct voluta_znode_info *zi)
{
	struct voluta_vnode_info *vi = voluta_vi_from_zi(zi);

	voluta_vi_seal_meta(vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* XXX: this code seg must die */

void voluta_uba_to_vba(const struct voluta_uba *uba, struct voluta_vba *vba)
{
	const enum voluta_ztype ztype = uba->uaddr.ztype;

	voluta_baddr_copyto(&uba->baddr, &vba->baddr);
	voluta_vaddr_setup(&vba->vaddr, ztype, uba->uaddr.off);
}

void voluta_vba_to_uba(const struct voluta_vba *vba, struct voluta_uba *uba)
{
	const enum voluta_ztype ztype = vba->vaddr.ztype;

	voluta_baddr_copyto(&vba->baddr, &uba->baddr);
	voluta_uaddr_setup(&uba->uaddr, ztype, vba->vaddr.off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_unode_info *
hsi_to_ui(const struct voluta_hsmap_info *hsi)
{
	const struct voluta_unode_info *ui = NULL;

	if (likely(hsi != NULL)) {
		ui = &hsi->hs_ui;
	}
	return ui_unconst(ui);
}

struct voluta_hsmap_info *
voluta_hsi_from_ui(const struct voluta_unode_info *ui)
{
	const struct voluta_hsmap_info *hsi = NULL;

	if (likely(ui != NULL)) {
		hsi = container_of2(ui, struct voluta_hsmap_info, hs_ui);
	}
	return unconst(hsi);
}

struct voluta_hsmap_info *
voluta_hsi_from_ui_rebind(const struct voluta_unode_info *ui,
                          voluta_index_t hs_index)
{
	struct voluta_hsmap_info *hsi = voluta_hsi_from_ui(ui);

	if (likely(hsi != NULL)) {
		hsi->hs_index = hs_index;
		hsi->hsm = &ui->u_zi.z_view->hsm;
	}
	return hsi;
}

static void hsi_init(struct voluta_hsmap_info *hsi,
                     const struct voluta_uba *uba)
{
	ui_init(&hsi->hs_ui, uba, hsi_vtbl());
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
	hsi->hsm = NULL;
}

static void hsi_fini(struct voluta_hsmap_info *hsi)
{
	ui_fini(&hsi->hs_ui);
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
	hsi->hsm = NULL;
}

static struct voluta_hsmap_info *hsi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_hsmap_info *hsi;

	hsi = voluta_allocate(alif, sizeof(*hsi));
	return hsi;
}

static void hsi_free(struct voluta_hsmap_info *hsi,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, hsi, sizeof(*hsi));
}

static void hsi_delete(struct voluta_hsmap_info *hsi,
                       struct voluta_alloc_if *alif)
{
	hsi_fini(hsi);
	hsi_free(hsi, alif);
}

static void hsi_delete_as_ui(struct voluta_unode_info *ui,
                             struct voluta_alloc_if *alif)
{
	hsi_delete(voluta_hsi_from_ui(ui), alif);
}

static void hsi_delete_as_zi(struct voluta_znode_info *zi,
                             struct voluta_alloc_if *alif)
{
	hsi_delete_as_ui(voluta_ui_from_zi(zi), alif);
}

static struct voluta_hsmap_info *
hsi_new(struct voluta_alloc_if *alif, const struct voluta_uba *uba)
{
	struct voluta_hsmap_info *hsi;

	hsi = hsi_malloc(alif);
	if (hsi != NULL) {
		hsi_init(hsi, uba);
	}
	return hsi;
}

static const struct voluta_znode_vtbl *hsi_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = hsi_delete_as_zi,
		.evictable = zi_evictable,
		.seal = ui_seal_as_zi,
		.resolve = ui_resolve_as_zi,
	};

	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_unode_info *
agi_to_ui(const struct voluta_agmap_info *agi)
{
	const struct voluta_unode_info *ui = NULL;

	if (likely(agi != NULL)) {
		ui = &agi->ag_ui;
	}
	return ui_unconst(ui);
}

struct voluta_agmap_info *
voluta_agi_from_ui(const struct voluta_unode_info *ui)
{
	const struct voluta_agmap_info *agi = NULL;

	if (likely(ui != NULL)) {
		agi = container_of2(ui, struct voluta_agmap_info, ag_ui);
	}
	return unconst(agi);
}

static void agi_init(struct voluta_agmap_info *agi,
                     const struct voluta_uba *uba)
{
	struct voluta_vba vba;

	voluta_uba_to_vba(uba, &vba);
	ui_init(&agi->ag_ui, uba, agi_vtbl());
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
	agi->agm = NULL;
	agi->ag_verify = 0;
}

static void agi_fini(struct voluta_agmap_info *agi)
{
	ui_fini(&agi->ag_ui);
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
	agi->agm = NULL;
}

static struct voluta_agmap_info *agi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_agmap_info *agi;

	agi = voluta_allocate(alif, sizeof(*agi));
	return agi;
}

static void agi_free(struct voluta_agmap_info *agi,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, agi, sizeof(*agi));
}

static void agi_delete(struct voluta_agmap_info *agi,
                       struct voluta_alloc_if *alif)
{
	agi_fini(agi);
	agi_free(agi, alif);
}

static void agi_delete_as_ui(struct voluta_unode_info *ui,
                             struct voluta_alloc_if *alif)
{
	agi_delete(voluta_agi_from_ui(ui), alif);
}

static void agi_delete_as_zi(struct voluta_znode_info *zi,
                             struct voluta_alloc_if *alif)
{
	agi_delete_as_ui(voluta_ui_from_zi(zi), alif);
}

static struct voluta_agmap_info *
agi_new(struct voluta_alloc_if *alif, const struct voluta_uba *uba)
{
	struct voluta_agmap_info *agi;

	agi = agi_malloc(alif);
	if (agi != NULL) {
		agi_init(agi, uba);
	}
	return agi;
}

struct voluta_agmap_info *
voluta_agi_from_ui_rebind(struct voluta_unode_info *ui,
                          voluta_index_t ag_index)
{
	struct voluta_agmap_info *agi = voluta_agi_from_ui(ui);

	voluta_assert_gt(ag_index, 0);
	if (likely(agi != NULL)) {
		agi->ag_index = ag_index;
		agi->agm = &ui->u_zi.z_view->agm;
	}
	return agi;
}

static const struct voluta_znode_vtbl *agi_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = agi_delete_as_zi,
		.evictable = zi_evictable,
		.seal = ui_seal_as_zi,
		.resolve = ui_resolve_as_zi,
	};
	return &vtbl;
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
		voluta_assert_eq(vi->vaddr.ztype, VOLUTA_ZTYPE_ITNODE);
		itni = container_of2(vi, struct voluta_itnode_info, itn_vi);
	}
	return unconst(itni);
}

struct voluta_itnode_info *
voluta_itni_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_itnode_info *itni = voluta_itni_from_vi(vi);

	if (likely(itni != NULL)) {
		itni->itn = &vi->v_zi.z_view->itn;
	}
	return itni;
}

static void itni_init(struct voluta_itnode_info *itni,
                      const struct voluta_vba *vba)
{
	vi_init(&itni->itn_vi, vba, itni_vtbl());
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

static void itni_delete_as_vi(struct voluta_vnode_info *vi,
                              struct voluta_alloc_if *alif)
{
	itni_delete(voluta_itni_from_vi(vi), alif);
}

static void itni_delete_as_zi(struct voluta_znode_info *zi,
                              struct voluta_alloc_if *alif)
{
	itni_delete_as_vi(voluta_vi_from_zi(zi), alif);
}

static struct voluta_itnode_info *
itni_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_itnode_info *itni;

	itni = itni_malloc(alif);
	if (itni != NULL) {
		itni_init(itni, vba);
	}
	return itni;
}

static const struct voluta_znode_vtbl *itni_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = itni_delete_as_zi,
		.evictable = zi_evictable,
		.seal = vi_seal_as_zi,
		.resolve = vi_resolve_as_zi,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_inode_info *ii_from_zi(const struct voluta_znode_info *zi)
{
	return voluta_ii_from_vi(voluta_vi_from_zi(zi));
}

struct voluta_inode_info *voluta_ii_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_inode_info *ii = NULL;

	if (likely(vi != NULL)) {
		ii = container_of2(vi, struct voluta_inode_info, i_vi);
	}
	return ii_unconst(ii);
}

struct voluta_inode_info *
voluta_ii_from_vi_rebind(struct voluta_vnode_info *vi, ino_t ino)
{
	struct voluta_inode_info *ii = voluta_ii_from_vi(vi);

	if (likely(ii != NULL)) {
		ii->inode = &ii->i_vi.v_zi.z_view->inode;
		ii->i_ino = ino;
	}
	return ii_unconst(ii);
}

static void ii_init(struct voluta_inode_info *ii, const struct voluta_vba *vba)
{
	vi_init(&ii->i_vi, vba, ii_vtbl());
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

static void ii_delete_as_vi(struct voluta_vnode_info *vi,
                            struct voluta_alloc_if *alif)
{
	ii_delete(voluta_ii_from_vi(vi), alif);
}

static void ii_delete_as_zi(struct voluta_znode_info *zi,
                            struct voluta_alloc_if *alif)
{
	ii_delete_as_vi(voluta_vi_from_zi(zi), alif);
}

static struct voluta_inode_info *
ii_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_inode_info *ii;

	ii = ii_malloc(alif);
	if (ii != NULL) {
		ii_init(ii, vba);
	}
	return ii;
}

static bool ii_evictable_as_zi(const struct voluta_znode_info *zi)
{
	const struct voluta_inode_info *ii = ii_from_zi(zi);

	return voluta_ii_isevictable(ii);
}

static const struct voluta_znode_vtbl *ii_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = ii_delete_as_zi,
		.evictable = ii_evictable_as_zi,
		.seal = vi_seal_as_zi,
		.resolve = vi_resolve_as_zi,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
xai_to_vi(const struct voluta_xanode_info *xai)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(xai != NULL)) {
		vi = &xai->xa_vi;
	}
	return vi_unconst(vi);
}

struct voluta_xanode_info *
voluta_xai_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_xanode_info *xai = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.ztype, VOLUTA_ZTYPE_XANODE);
		xai = container_of2(vi, struct voluta_xanode_info, xa_vi);
	}
	return unconst(xai);
}

struct voluta_xanode_info *
voluta_xai_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_xanode_info *xai = voluta_xai_from_vi(vi);

	xai->xan = &vi->v_zi.z_view->xan;
	return xai;
}

static void xai_init(struct voluta_xanode_info *xai,
                     const struct voluta_vba *vba)
{
	vi_init(&xai->xa_vi, vba, xai_vtbl());
	xai->xan = NULL;
}

static void xai_fini(struct voluta_xanode_info *xai)
{
	vi_fini(&xai->xa_vi);
	xai->xan = NULL;
}

static struct voluta_xanode_info *xai_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_xanode_info *xai;

	xai = voluta_allocate(alif, sizeof(*xai));
	return xai;
}

static void xai_free(struct voluta_xanode_info *xai,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, xai, sizeof(*xai));
}

static void xai_delete(struct voluta_xanode_info *xai,
                       struct voluta_alloc_if *alif)
{
	xai_fini(xai);
	xai_free(xai, alif);
}

static void xai_delete_as_vi(struct voluta_vnode_info *vi,
                             struct voluta_alloc_if *alif)
{
	xai_delete(voluta_xai_from_vi(vi), alif);
}

static void xai_delete_as_zi(struct voluta_znode_info *zi,
                             struct voluta_alloc_if *alif)
{
	xai_delete_as_vi(voluta_vi_from_zi(zi), alif);
}

static struct voluta_xanode_info *
xai_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_xanode_info *xai;

	xai = xai_malloc(alif);
	if (xai != NULL) {
		xai_init(xai, vba);
	}
	return xai;
}

static const struct voluta_znode_vtbl *xai_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = xai_delete_as_zi,
		.evictable = zi_evictable,
		.seal = vi_seal_as_zi,
		.resolve = vi_resolve_as_zi,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
syi_to_vi(const struct voluta_symval_info *syi)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(syi != NULL)) {
		vi = &syi->sy_vi;
	}
	return vi_unconst(vi);
}

struct voluta_symval_info *
voluta_syi_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_symval_info *syi = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.ztype, VOLUTA_ZTYPE_SYMVAL);
		syi = container_of2(vi, struct voluta_symval_info, sy_vi);
	}
	return unconst(syi);
}

struct voluta_symval_info *
voluta_syi_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_symval_info *syi = voluta_syi_from_vi(vi);

	if (likely(syi != NULL)) {
		syi->syv = &syi->sy_vi.v_zi.z_view->sym;
	}
	return syi;
}

static void syi_init(struct voluta_symval_info *syi,
                     const struct voluta_vba *vba)
{
	vi_init(&syi->sy_vi, vba, syi_vtbl());
	syi->syv = NULL;
}

static void syi_fini(struct voluta_symval_info *syi)
{
	vi_fini(&syi->sy_vi);
	syi->syv = NULL;
}

static struct voluta_symval_info *syi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_symval_info *syi;

	syi = voluta_allocate(alif, sizeof(*syi));
	return syi;
}

static void syi_free(struct voluta_symval_info *syi,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, syi, sizeof(*syi));
}

static void syi_delete(struct voluta_symval_info *syi,
                       struct voluta_alloc_if *alif)
{
	syi_fini(syi);
	syi_free(syi, alif);
}

static void syi_delete_as_vi(struct voluta_vnode_info *vi,
                             struct voluta_alloc_if *alif)
{
	syi_delete(voluta_syi_from_vi(vi), alif);
}

static void syi_delete_as_zi(struct voluta_znode_info *zi,
                             struct voluta_alloc_if *alif)
{
	syi_delete_as_vi(voluta_vi_from_zi(zi), alif);
}

static struct voluta_symval_info *
syi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_symval_info *syi;

	syi = syi_malloc(alif);
	if (syi != NULL) {
		syi_init(syi, vba);
	}
	return syi;
}

static const struct voluta_znode_vtbl *syi_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = syi_delete_as_zi,
		.evictable = zi_evictable,
		.seal = vi_seal_as_zi,
		.resolve = vi_resolve_as_zi,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
dti_to_vi(const struct voluta_dtnode_info *dti)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(dti != NULL)) {
		vi = &dti->dt_vi;
	}
	return vi_unconst(vi);
}

struct voluta_dtnode_info *
voluta_dti_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_dtnode_info *dti = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.ztype, VOLUTA_ZTYPE_DTNODE);
		dti = container_of2(vi, struct voluta_dtnode_info, dt_vi);
	}
	return unconst(dti);
}

struct voluta_dtnode_info *
voluta_dti_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_dtnode_info *dti = voluta_dti_from_vi(vi);

	if (likely(dti != NULL)) {
		dti->dtn = &dti->dt_vi.v_zi.z_view->htn;
	}
	return dti;
}

static void dti_init(struct voluta_dtnode_info *dti,
                     const struct voluta_vba *vba)
{
	vi_init(&dti->dt_vi, vba, dti_vtbl());
	dti->dtn = NULL;
}

static void dti_fini(struct voluta_dtnode_info *dti)
{
	vi_fini(&dti->dt_vi);
	dti->dtn = NULL;
}

static struct voluta_dtnode_info *dti_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_dtnode_info *dti;

	dti = voluta_allocate(alif, sizeof(*dti));
	return dti;
}

static void dti_free(struct voluta_dtnode_info *dti,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, dti, sizeof(*dti));
}

static void dti_delete(struct voluta_dtnode_info *dti,
                       struct voluta_alloc_if *alif)
{
	dti_fini(dti);
	dti_free(dti, alif);
}

static void dti_delete_as_vi(struct voluta_vnode_info *vi,
                             struct voluta_alloc_if *alif)
{
	dti_delete(voluta_dti_from_vi(vi), alif);
}

static void dti_delete_as_zi(struct voluta_znode_info *zi,
                             struct voluta_alloc_if *alif)
{
	dti_delete_as_vi(voluta_vi_from_zi(zi), alif);
}

static struct voluta_dtnode_info *
dti_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_dtnode_info *dti;

	dti = dti_malloc(alif);
	if (dti != NULL) {
		dti_init(dti, vba);
	}
	return dti;
}

static const struct voluta_znode_vtbl *dti_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = dti_delete_as_zi,
		.evictable = zi_evictable,
		.seal = vi_seal_as_zi,
		.resolve = vi_resolve_as_zi,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
rti_to_vi(const struct voluta_rtnode_info *rti)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(rti != NULL)) {
		vi = &rti->rt_vi;
	}
	return vi_unconst(vi);
}

struct voluta_rtnode_info *
voluta_rti_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_rtnode_info *rti = NULL;

	if (likely(vi != NULL)) {
		voluta_assert_eq(vi->vaddr.ztype, VOLUTA_ZTYPE_RTNODE);
		rti = container_of2(vi, struct voluta_rtnode_info, rt_vi);
	}
	return unconst(rti);
}

struct voluta_rtnode_info *
voluta_rti_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_rtnode_info *rti = voluta_rti_from_vi(vi);

	if (likely(rti != NULL)) {
		rti->rtn = &rti->rt_vi.v_zi.z_view->rtn;
	}
	return rti;
}

static void rti_init(struct voluta_rtnode_info *rti,
                     const struct voluta_vba *vba)
{
	vi_init(&rti->rt_vi, vba, rti_vtbl());
	rti->rtn = NULL;
}

static void rti_fini(struct voluta_rtnode_info *rti)
{
	vi_fini(&rti->rt_vi);
	rti->rtn = NULL;
}

static struct voluta_rtnode_info *rti_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_rtnode_info *rti;

	rti = voluta_allocate(alif, sizeof(*rti));
	return rti;
}

static void rti_free(struct voluta_rtnode_info *rti,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, rti, sizeof(*rti));
}

static void rti_delete(struct voluta_rtnode_info *rti,
                       struct voluta_alloc_if *alif)
{
	rti_fini(rti);
	rti_free(rti, alif);
}

static void rti_delete_as_vi(struct voluta_vnode_info *vi,
                             struct voluta_alloc_if *alif)
{
	rti_delete(voluta_rti_from_vi(vi), alif);
}

static void rti_delete_as_zi(struct voluta_znode_info *zi,
                             struct voluta_alloc_if *alif)
{
	rti_delete_as_vi(voluta_vi_from_zi(zi), alif);
}

static struct voluta_rtnode_info *
rti_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_rtnode_info *rti;

	rti = rti_malloc(alif);
	if (rti != NULL) {
		rti_init(rti, vba);
	}
	return rti;
}

static const struct voluta_znode_vtbl *rti_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = rti_delete_as_zi,
		.evictable = zi_evictable,
		.seal = vi_seal_as_zi,
		.resolve = vi_resolve_as_zi,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
fli_to_vi(const struct voluta_fleaf_info *fli)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(fli != NULL)) {
		vi = &fli->fl_vi;
	}
	return vi_unconst(vi);
}

struct voluta_fleaf_info *
voluta_fli_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_fleaf_info *fli = NULL;

	if (likely(vi != NULL)) {
		fli = container_of2(vi, struct voluta_fleaf_info, fl_vi);
	}
	return unconst(fli);
}

struct voluta_fleaf_info *
voluta_fli_from_vi_rebind(struct voluta_vnode_info *vi)
{
	enum voluta_ztype ztype;
	struct voluta_fleaf_info *fli = voluta_fli_from_vi(vi);

	if (likely(fli != NULL)) {
		ztype = vi_ztype(vi);
		if (ztype == VOLUTA_ZTYPE_DATA1K) {
			fli->flu.db1 = &fli->fl_vi.v_zi.z_view->db1;
		} else if (ztype == VOLUTA_ZTYPE_DATA4K) {
			fli->flu.db4 = &fli->fl_vi.v_zi.z_view->db4;
		} else {
			voluta_assert_eq(ztype, VOLUTA_ZTYPE_DATABK);
			fli->flu.db = &fli->fl_vi.v_zi.z_view->db;
		}
	}
	return fli;
}

static void fli_init(struct voluta_fleaf_info *fli,
                     const struct voluta_vba *vba)
{
	vi_init(&fli->fl_vi, vba, fli_vtbl());
	fli->flu.db = NULL;
}

static void fli_fini(struct voluta_fleaf_info *fli)
{
	vi_fini(&fli->fl_vi);
	fli->flu.db = NULL;
}

static struct voluta_fleaf_info *fli_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_fleaf_info *fli;

	fli = voluta_allocate(alif, sizeof(*fli));
	return fli;
}

static void fli_free(struct voluta_fleaf_info *fli,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, fli, sizeof(*fli));
}

static void fli_delete(struct voluta_fleaf_info *fli,
                       struct voluta_alloc_if *alif)
{
	fli_fini(fli);
	fli_free(fli, alif);
}

static void fli_delete_as_vi(struct voluta_vnode_info *vi,
                             struct voluta_alloc_if *alif)
{
	fli_delete(voluta_fli_from_vi(vi), alif);
}

static void fli_delete_as_zi(struct voluta_znode_info *zi,
                             struct voluta_alloc_if *alif)
{
	fli_delete_as_vi(voluta_vi_from_zi(zi), alif);
}

static struct voluta_fleaf_info *
fli_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_fleaf_info *fli;

	fli = fli_malloc(alif);
	if (fli != NULL) {
		fli_init(fli, vba);
	}
	return fli;
}

static const struct voluta_znode_vtbl *fli_vtbl(void)
{
	static const struct voluta_znode_vtbl vtbl = {
		.del = fli_delete_as_zi,
		.evictable = zi_evictable,
		.seal = zi_seal_noop,
		.resolve = vi_resolve_as_zi,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_unode_info *
voluta_new_ui(struct voluta_alloc_if *alif, const struct voluta_uba *uba)
{
	struct voluta_unode_info *ui;
	const enum voluta_ztype ztype = uba->uaddr.ztype;

	switch (ztype) {
	case VOLUTA_ZTYPE_HSMAP:
		ui = hsi_to_ui(hsi_new(alif, uba));
		break;
	case VOLUTA_ZTYPE_AGMAP:
		ui = agi_to_ui(agi_new(alif, uba));
		break;
	case VOLUTA_ZTYPE_ITNODE:
	case VOLUTA_ZTYPE_INODE:
	case VOLUTA_ZTYPE_XANODE:
	case VOLUTA_ZTYPE_SYMVAL:
	case VOLUTA_ZTYPE_DTNODE:
	case VOLUTA_ZTYPE_RTNODE:
	case VOLUTA_ZTYPE_DATA1K:
	case VOLUTA_ZTYPE_DATA4K:
	case VOLUTA_ZTYPE_DATABK:
	case VOLUTA_ZTYPE_SUPER:
	case VOLUTA_ZTYPE_NONE:
	default:
		ui = NULL;
		break;
	}
	return ui;
}

struct voluta_vnode_info *
voluta_new_vi(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_vnode_info *vi;
	const enum voluta_ztype ztype = vba->vaddr.ztype;

	switch (ztype) {
	case VOLUTA_ZTYPE_ITNODE:
		vi = itni_to_vi(itni_new(alif, vba));
		break;
	case VOLUTA_ZTYPE_INODE:
		vi = ii_to_vi(ii_new(alif, vba));
		break;
	case VOLUTA_ZTYPE_XANODE:
		vi = xai_to_vi(xai_new(alif, vba));
		break;
	case VOLUTA_ZTYPE_SYMVAL:
		vi = syi_to_vi(syi_new(alif, vba));
		break;
	case VOLUTA_ZTYPE_DTNODE:
		vi = dti_to_vi(dti_new(alif, vba));
		break;
	case VOLUTA_ZTYPE_RTNODE:
		vi = rti_to_vi(rti_new(alif, vba));
		break;
	case VOLUTA_ZTYPE_DATA1K:
	case VOLUTA_ZTYPE_DATA4K:
	case VOLUTA_ZTYPE_DATABK:
		vi = fli_to_vi(fli_new(alif, vba));
		break;
	case VOLUTA_ZTYPE_SUPER:
	case VOLUTA_ZTYPE_HSMAP:
	case VOLUTA_ZTYPE_AGMAP:
	case VOLUTA_ZTYPE_NONE:
	default:
		vi = NULL;
		voluta_assert_not_null(vi);
		break;
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

static enum voluta_ztype hdr_ztype(const struct voluta_header *hdr)
{
	return (enum voluta_ztype)(hdr->h_ztype);
}

static void hdr_set_ztype(struct voluta_header *hdr, enum voluta_ztype ztype)
{
	hdr->h_ztype = (uint8_t)ztype;
}

static uint32_t hdr_csum(const struct voluta_header *hdr)
{
	return voluta_le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct voluta_header *hdr, uint32_t csum)
{
	hdr->h_csum = voluta_cpu_to_le32(csum);
	hdr->h_flags |= VOLUTA_HDRF_CSUM;
}

static bool hdr_has_csum(const struct voluta_header *hdr)
{
	return (hdr->h_flags & VOLUTA_HDRF_CSUM) > 0;
}

static const void *hdr_payload(const struct voluta_header *hdr)
{
	return hdr + 1;
}

static void hdr_stamp(struct voluta_header *hdr,
                      enum voluta_ztype ztype, size_t size)
{
	hdr_set_magic(hdr, VOLUTA_ZTYPE_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_ztype(hdr, ztype);
	hdr->h_csum = 0;
	hdr->h_flags = 0;
	hdr->h_reserved = 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
		csum = calc_data_checksum(vi->v_zi.z_view, vaddr->len, md);
	} else {
		csum = calc_meta_chekcsum(&vi->v_zi.z_view->hdr, md);
	}
	return csum;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_hdr(const union voluta_view *view, enum voluta_ztype ztype)
{
	const struct voluta_header *hdr = &view->hdr;
	const size_t hsz = hdr_size(hdr);
	const size_t psz = ztype_size(ztype);

	if (ztype_isdata(ztype)) {
		return 0;
	}
	if (hdr_magic(hdr) != VOLUTA_ZTYPE_MAGIC) {
		return -EFSCORRUPTED;
	}
	if (hdr_ztype(hdr) != ztype) {
		return -EFSCORRUPTED;
	}
	if (hsz != psz) {
		return -EFSCORRUPTED;
	}

	return 0;
}

static int verify_checksum(const union voluta_view *view,
                           const struct voluta_mdigest *md)
{
	uint32_t csum;
	const struct voluta_header *hdr = &view->hdr;

	if (hdr_has_csum(hdr)) {
		csum = calc_meta_chekcsum(hdr, md);
		if (csum != hdr_csum(hdr)) {
			return -EFSCORRUPTED;
		}
	}
	return 0;
}

static int verify_sub(const union voluta_view *view, enum voluta_ztype ztype)
{
	int err;

	switch (ztype) {
	case VOLUTA_ZTYPE_HSMAP:
		err = voluta_verify_hspace_map(&view->hsm);
		break;
	case VOLUTA_ZTYPE_AGMAP:
		err = voluta_verify_agroup_map(&view->agm);
		break;
	case VOLUTA_ZTYPE_ITNODE:
		err = voluta_verify_itnode(&view->itn);
		break;
	case VOLUTA_ZTYPE_INODE:
		err = voluta_verify_inode(&view->inode);
		break;
	case VOLUTA_ZTYPE_XANODE:
		err = voluta_verify_xattr_node(&view->xan);
		break;
	case VOLUTA_ZTYPE_DTNODE:
		err = voluta_verify_dir_htree_node(&view->htn);
		break;
	case VOLUTA_ZTYPE_RTNODE:
		err = voluta_verify_radix_tnode(&view->rtn);
		break;
	case VOLUTA_ZTYPE_SYMVAL:
		err = voluta_verify_lnk_value(&view->sym);
		break;
	case VOLUTA_ZTYPE_SUPER:
	case VOLUTA_ZTYPE_DATA1K:
	case VOLUTA_ZTYPE_DATA4K:
	case VOLUTA_ZTYPE_DATABK:
		err = 0;
		break;
	case VOLUTA_ZTYPE_NONE:
	default:
		err = -EFSCORRUPTED;
		break;
	}
	return err;
}

static int verify_view(const union voluta_view *view,
                       enum voluta_ztype ztype,
                       const struct voluta_mdigest *md)
{
	int err;

	if (ztype_isdata(ztype)) {
		return 0;
	}
	err = verify_hdr(view, ztype);
	if (err) {
		return err;
	}
	err = verify_checksum(view, md);
	if (err) {
		return err;
	}
	err = verify_sub(view, ztype);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_vi_verify_meta(const struct voluta_vnode_info *vi)
{
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	return verify_view(vi->v_zi.z_view, vaddr->ztype, vi_mdigest(vi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vi_seal_meta(const struct voluta_vnode_info *vi)
{
	const struct voluta_sb_info *sbi = vi_sbi(vi);

	if ((sbi->s_ctl_flags & VOLUTA_F_SEAL) && !vi_isdata(vi)) {
		hdr_set_csum(&vi->v_zi.z_view->hdr, calc_chekcsum_of(vi));
	}
}

void voluta_zero_stamp_view(union voluta_view *view, enum voluta_ztype ztype)
{
	const size_t len = ztype_size(ztype);

	voluta_memzero(view, len);
	hdr_stamp(&view->hdr, ztype, len);
}

