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
static const struct voluta_cnode_vtbl *hsi_vtbl(void);
static const struct voluta_cnode_vtbl *agi_vtbl(void);
static const struct voluta_cnode_vtbl *itni_vtbl(void);
static const struct voluta_cnode_vtbl *ii_vtbl(void);
static const struct voluta_cnode_vtbl *xai_vtbl(void);
static const struct voluta_cnode_vtbl *syi_vtbl(void);
static const struct voluta_cnode_vtbl *dti_vtbl(void);
static const struct voluta_cnode_vtbl *rti_vtbl(void);
static const struct voluta_cnode_vtbl *fli_vtbl(void);

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

static void ci_init(struct voluta_cnode_info *ci,
                    const struct voluta_cnode_vtbl *vtbl)
{
	voluta_ce_init(&ci->ce);
	lh_init(&ci->c_dq_lh);
	an_init(&ci->c_ds_an);
	ci->c_ds_next = NULL;
	ci->c_sbi = NULL;
	ci->c_xref = NULL;
	ci->c_vtbl = vtbl;
}

static void ci_fini(struct voluta_cnode_info *ci)
{
	voluta_ce_fini(&ci->ce);
	lh_fini(&ci->c_dq_lh);
	an_fini(&ci->c_ds_an);
	ci->c_ds_next = NULL;
	ci->c_sbi = NULL;
	ci->c_xref = NULL;
	ci->c_vtbl = NULL;
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
                    const struct voluta_baddr *baddr,
                    const struct voluta_cnode_vtbl *vtbl)
{
	voluta_uba_reset(&ui->uba);
	baddr_copyto(baddr, &ui->uba.baddr);
	ci_init(&ui->u_ci, vtbl);
	lh_init(&ui->u_dq_lh);
	ui->u_bsi = NULL;
}

static void ui_init2(struct voluta_unode_info *ui,
                     const struct voluta_uba *uba,
                     const struct voluta_cnode_vtbl *vtbl)
{
	ui_init(ui, &uba->baddr, vtbl);
	voluta_uba_copyto(uba, &ui->uba);
}

static void ui_fini(struct voluta_unode_info *ui)
{
	voluta_uba_reset(&ui->uba);
	ci_fini(&ui->u_ci);
	lh_fini(&ui->u_dq_lh);
	ui->u_bsi = NULL;
}

struct voluta_unode_info *voluta_ui_from_ci(const struct voluta_cnode_info *ci)
{
	const struct voluta_unode_info *ui = NULL;

	if (likely(ci != NULL)) {
		ui = container_of2(ci, struct voluta_unode_info, u_ci);
	}
	return ui_unconst(ui);
}

static int ui_resolve(const struct voluta_unode_info *ui,
                      struct voluta_baddr *out_baddr)
{
	baddr_copyto(&ui->uba.baddr, out_baddr);
	return 0;
}

/* XXX TODO
 * start using when the time comes
 */
static inline int ui_resolve_as_ci(const struct voluta_cnode_info *ci,
                                   struct voluta_baddr *out_baddr)
{
	return ui_resolve(voluta_ui_from_ci(ci), out_baddr);
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
                    const struct voluta_cnode_vtbl *ci_vtbl)
{
	ci_init(&vi->v_ci, ci_vtbl);

	lh_init(&vi->v_dq_lh);
	an_init(&vi->v_ds_an);
	vi->v_ds_next = NULL;

	vaddr_copyto(&vba->vaddr, &vi->vaddr);
	voluta_fiovref_init(&vi->v_fir, vi_fiov_pre, vi_fiov_post);
	vi->view = NULL;
	vi->v_bsi = NULL;
	vi->v_iowner = VOLUTA_INO_NULL;
	vi->v_verify = 0;
}

static void vi_fini(struct voluta_vnode_info *vi)
{
	ci_fini(&vi->v_ci);
	lh_fini(&vi->v_dq_lh);
	an_fini(&vi->v_ds_an);
	vaddr_reset(&vi->vaddr);
	voluta_fiovref_fini(&vi->v_fir);
	vi->view = NULL;
	vi->v_bsi = NULL;
	vi->v_ds_next = NULL;
	vi->v_verify = 0;
}

struct voluta_vnode_info *voluta_vi_from_ci(const struct voluta_cnode_info *ci)
{
	const struct voluta_vnode_info *vi = NULL;

	if (likely(ci != NULL)) {
		vi = container_of2(ci, struct voluta_vnode_info, v_ci);
	}
	return vi_unconst(vi);
}

bool voluta_vi_isdata(const struct voluta_vnode_info *vi)
{
	return voluta_vtype_isdata(vi_vtype(vi));
}

static int vi_resolve(const struct voluta_vnode_info *vi,
                      struct voluta_baddr *out_baddr)
{
	return voluta_resolve_baddr_of(vi_sbi(vi), vi, out_baddr);
}

static int vi_resolve_as_ci(const struct voluta_cnode_info *ci,
                            struct voluta_baddr *out_baddr)
{
	const struct voluta_vnode_info *vi = voluta_vi_from_ci(ci);

	return (likely(vi != NULL)) ? vi_resolve(vi, out_baddr) : -ENOENT;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* XXX: this code seg must die */
static enum voluta_vtype uba_to_vtype(const struct voluta_uba *uba)
{
	enum voluta_vtype vtype;
	const enum voluta_utype utype = uba->uaddr.utype;

	switch (utype) {
	case VOLUTA_UTYPE_SUPER:
		vtype = VOLUTA_VTYPE_SUPER;
		break;
	case VOLUTA_UTYPE_HSMAP:
		vtype = VOLUTA_VTYPE_HSMAP;
		break;
	case VOLUTA_UTYPE_AGMAP:
		vtype = VOLUTA_VTYPE_AGMAP;
		break;
	case VOLUTA_UTYPE_NONE:
	default:
		vtype = VOLUTA_VTYPE_NONE;
		break;
	}
	voluta_assert_ne(vtype, VOLUTA_VTYPE_NONE);
	return vtype;
}

static void uba_to_vba(const struct voluta_uba *uba, struct voluta_vba *vba)
{
	voluta_baddr_copyto(&uba->baddr, &vba->baddr);
	voluta_vaddr_setup(&vba->vaddr, uba_to_vtype(uba), uba->uaddr.off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_unode_info *
hsi_to_ui(const struct voluta_hspace_info *hsi)
{
	const struct voluta_unode_info *ui = NULL;

	if (likely(hsi != NULL)) {
		ui = &hsi->hs_ui;
	}
	return ui_unconst(ui);
}

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
voluta_hsi_from_ui(const struct voluta_unode_info *ui)
{
	const struct voluta_hspace_info *hsi = NULL;

	if (likely(ui != NULL)) {
		hsi = container_of2(ui, struct voluta_hspace_info, hs_ui);
	}
	return unconst(hsi);
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

struct voluta_hspace_info *
voluta_hsi_from_vi_rebind(const struct voluta_vnode_info *vi,
                          voluta_index_t hs_index)
{
	struct voluta_hspace_info *hsi = voluta_hsi_from_vi(vi);

	if (likely(hsi != NULL)) {
		hsi->hs_index = hs_index;
		hsi->hsm = &vi->view->hsm;
	}
	return hsi;
}

static void hsi_init(struct voluta_hspace_info *hsi,
                     const struct voluta_vba *vba)
{
	ui_init(&hsi->hs_ui, &vba->baddr, hsi_vtbl());
	vi_init(&hsi->hs_vi, vba, hsi_vtbl());
	hsi->hs_index = VOLUTA_HS_INDEX_NULL;
	hsi->hsm = NULL;
}

static void hsi_init2(struct voluta_hspace_info *hsi,
                      const struct voluta_uba *uba)
{
	struct voluta_vba vba;

	uba_to_vba(uba, &vba);
	ui_init2(&hsi->hs_ui, uba, hsi_vtbl());
	vi_init(&hsi->hs_vi, &vba, hsi_vtbl());
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

static void hsi_delete_as_vi(struct voluta_vnode_info *vi,
                             struct voluta_alloc_if *alif)
{
	hsi_delete(voluta_hsi_from_vi(vi), alif);
}

/* XXX TODO use when the time comde */
static inline void hsi_delete_as_ui(struct voluta_unode_info *ui,
                                    struct voluta_alloc_if *alif)
{
	hsi_delete(voluta_hsi_from_ui(ui), alif);
}

static void hsi_delete_as_ci(struct voluta_cnode_info *ci,
                             struct voluta_alloc_if *alif)
{
	/* XXX TODO
	 * change voluta_vi_from_ci --> voluta_ui_from_ci when time comes
	 */
	hsi_delete_as_vi(voluta_vi_from_ci(ci), alif);
}

static struct voluta_hspace_info *
hsi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_hspace_info *hsi;

	hsi = hsi_malloc(alif);
	if (hsi != NULL) {
		hsi_init(hsi, vba);
	}
	return hsi;
}

static struct voluta_hspace_info *
hsi_new2(struct voluta_alloc_if *alif, const struct voluta_uba *uba)
{
	struct voluta_hspace_info *hsi;

	hsi = hsi_malloc(alif);
	if (hsi != NULL) {
		hsi_init2(hsi, uba);
	}
	return hsi;
}

static const struct voluta_cnode_vtbl *hsi_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = hsi_delete_as_ci,
		.resolve = vi_resolve_as_ci,
	};

	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_unode_info *
agi_to_ui(const struct voluta_agroup_info *agi)
{
	const struct voluta_unode_info *ui = NULL;

	if (likely(agi != NULL)) {
		ui = &agi->ag_ui;
	}
	return ui_unconst(ui);
}

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

struct voluta_agroup_info *
voluta_agi_from_ui(const struct voluta_unode_info *ui)
{
	const struct voluta_agroup_info *agi = NULL;

	if (likely(ui != NULL)) {
		agi = container_of2(ui, struct voluta_agroup_info, ag_ui);
	}
	return unconst(agi);
}

static void agi_init(struct voluta_agroup_info *agi,
                     const struct voluta_vba *vba)
{
	ui_init(&agi->ag_ui, &vba->baddr, agi_vtbl());
	vi_init(&agi->ag_vi, vba, agi_vtbl());
	agi->ag_index = VOLUTA_AG_INDEX_NULL;
	agi->agm = NULL;
}

static void agi_init2(struct voluta_agroup_info *agi,
                      const struct voluta_uba *uba)
{
	struct voluta_vba vba;

	uba_to_vba(uba, &vba);
	ui_init2(&agi->ag_ui, uba, agi_vtbl());
	vi_init(&agi->ag_vi, &vba, agi_vtbl());
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

static void agi_delete_as_vi(struct voluta_vnode_info *vi,
                             struct voluta_alloc_if *alif)
{
	agi_delete(voluta_agi_from_vi(vi), alif);
}

static inline void agi_delete_as_ui(struct voluta_unode_info *ui,
                                    struct voluta_alloc_if *alif)
{
	agi_delete(voluta_agi_from_ui(ui), alif);
}

static void agi_delete_as_ci(struct voluta_cnode_info *ci,
                             struct voluta_alloc_if *alif)
{
	/* XXX TODO
	 * change voluta_vi_from_ci --> voluta_ui_from_ci when time comes
	 */
	agi_delete_as_vi(voluta_vi_from_ci(ci), alif);
}

static struct voluta_agroup_info *
agi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba)
{
	struct voluta_agroup_info *agi;

	agi = agi_malloc(alif);
	if (agi != NULL) {
		agi_init(agi, vba);
	}
	return agi;
}

static struct voluta_agroup_info *
agi_new2(struct voluta_alloc_if *alif, const struct voluta_uba *uba)
{
	struct voluta_agroup_info *agi;

	agi = agi_malloc(alif);
	if (agi != NULL) {
		agi_init2(agi, uba);
	}
	return agi;
}

struct voluta_agroup_info *
voluta_agi_from_vi_rebind(struct voluta_vnode_info *vi,
                          voluta_index_t ag_index)
{
	struct voluta_agroup_info *agi = voluta_agi_from_vi(vi);

	voluta_assert_gt(ag_index, 0);
	if (likely(agi != NULL)) {
		agi->ag_index = ag_index;
		agi->agm = &vi->view->agm;
	}
	return agi;
}

static const struct voluta_cnode_vtbl *agi_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = agi_delete_as_ci,
		.resolve = vi_resolve_as_ci,
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
		itni->itn = &vi->view->itn;
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

static void itni_delete_as_ci(struct voluta_cnode_info *ci,
                              struct voluta_alloc_if *alif)
{
	itni_delete_as_vi(voluta_vi_from_ci(ci), alif);
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

static const struct voluta_cnode_vtbl *itni_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = itni_delete_as_ci,
		.resolve = vi_resolve_as_ci,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_inode_info *ii_from_ci(const struct voluta_cnode_info *ci)
{
	return voluta_ii_from_vi(voluta_vi_from_ci(ci));
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
		ii->inode = &ii->i_vi.view->inode;
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

static void ii_delete_as_ci(struct voluta_cnode_info *ci,
                            struct voluta_alloc_if *alif)
{
	ii_delete_as_vi(voluta_vi_from_ci(ci), alif);
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

static bool ii_evictable_as_ci(const struct voluta_cnode_info *ci)
{
	const struct voluta_inode_info *ii = ii_from_ci(ci);

	return voluta_ii_isevictable(ii);
}

static const struct voluta_cnode_vtbl *ii_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = ii_evictable_as_ci,
		.del = ii_delete_as_ci,
		.resolve = vi_resolve_as_ci,
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
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_XANODE);
		xai = container_of2(vi, struct voluta_xanode_info, xa_vi);
	}
	return unconst(xai);
}

struct voluta_xanode_info *
voluta_xai_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_xanode_info *xai = voluta_xai_from_vi(vi);

	xai->xan = &vi->view->xan;
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

static void xai_delete_as_ci(struct voluta_cnode_info *ci,
                             struct voluta_alloc_if *alif)
{
	xai_delete_as_vi(voluta_vi_from_ci(ci), alif);
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

static const struct voluta_cnode_vtbl *xai_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = xai_delete_as_ci,
		.resolve = vi_resolve_as_ci,
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
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_SYMVAL);
		syi = container_of2(vi, struct voluta_symval_info, sy_vi);
	}
	return unconst(syi);
}

struct voluta_symval_info *
voluta_syi_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_symval_info *syi = voluta_syi_from_vi(vi);

	if (likely(syi != NULL)) {
		syi->syv = &syi->sy_vi.view->sym;
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

static void syi_delete_as_ci(struct voluta_cnode_info *ci,
                             struct voluta_alloc_if *alif)
{
	syi_delete_as_vi(voluta_vi_from_ci(ci), alif);
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

static const struct voluta_cnode_vtbl *syi_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = syi_delete_as_ci,
		.resolve = vi_resolve_as_ci,
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
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_DTNODE);
		dti = container_of2(vi, struct voluta_dtnode_info, dt_vi);
	}
	return unconst(dti);
}

struct voluta_dtnode_info *
voluta_dti_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_dtnode_info *dti = voluta_dti_from_vi(vi);

	if (likely(dti != NULL)) {
		dti->dtn = &dti->dt_vi.view->htn;
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

static void dti_delete_as_ci(struct voluta_cnode_info *ci,
                             struct voluta_alloc_if *alif)
{
	dti_delete_as_vi(voluta_vi_from_ci(ci), alif);
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

static const struct voluta_cnode_vtbl *dti_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = dti_delete_as_ci,
		.resolve = vi_resolve_as_ci,
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
		voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_RTNODE);
		rti = container_of2(vi, struct voluta_rtnode_info, rt_vi);
	}
	return unconst(rti);
}

struct voluta_rtnode_info *
voluta_rti_from_vi_rebind(struct voluta_vnode_info *vi)
{
	struct voluta_rtnode_info *rti = voluta_rti_from_vi(vi);

	if (likely(rti != NULL)) {
		rti->rtn = &rti->rt_vi.view->rtn;
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

static void rti_delete_as_ci(struct voluta_cnode_info *ci,
                             struct voluta_alloc_if *alif)
{
	rti_delete_as_vi(voluta_vi_from_ci(ci), alif);
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

static const struct voluta_cnode_vtbl *rti_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = rti_delete_as_ci,
		.resolve = vi_resolve_as_ci,
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
	enum voluta_vtype vtype;
	struct voluta_fleaf_info *fli = voluta_fli_from_vi(vi);

	if (likely(fli != NULL)) {
		vtype = vi_vtype(vi);
		if (vtype == VOLUTA_VTYPE_DATA1K) {
			fli->flu.db1 = &fli->fl_vi.view->db1;
		} else if (vtype == VOLUTA_VTYPE_DATA4K) {
			fli->flu.db4 = &fli->fl_vi.view->db4;
		} else {
			voluta_assert_eq(vtype, VOLUTA_VTYPE_DATABK);
			fli->flu.db = &fli->fl_vi.view->db;
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

static void fli_delete_as_ci(struct voluta_cnode_info *ci,
                             struct voluta_alloc_if *alif)
{
	fli_delete_as_vi(voluta_vi_from_ci(ci), alif);
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

static const struct voluta_cnode_vtbl *fli_vtbl(void)
{
	static const struct voluta_cnode_vtbl vtbl = {
		.evictable = voluta_ci_isevictable,
		.del = fli_delete_as_ci,
		.resolve = vi_resolve_as_ci,
	};
	return &vtbl;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_unode_info *
voluta_new_ui(struct voluta_alloc_if *alif, const struct voluta_uba *uba)
{
	struct voluta_unode_info *ui;
	const enum voluta_utype utype = uba->uaddr.utype;

	switch (utype) {
	case VOLUTA_UTYPE_HSMAP:
		ui = hsi_to_ui(hsi_new2(alif, uba));
		break;
	case VOLUTA_UTYPE_AGMAP:
		ui = agi_to_ui(agi_new2(alif, uba));
		break;
	case VOLUTA_UTYPE_NONE:
	case VOLUTA_UTYPE_SUPER:
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
		vi = xai_to_vi(xai_new(alif, vba));
		break;
	case VOLUTA_VTYPE_SYMVAL:
		vi = syi_to_vi(syi_new(alif, vba));
		break;
	case VOLUTA_VTYPE_DTNODE:
		vi = dti_to_vi(dti_new(alif, vba));
		break;
	case VOLUTA_VTYPE_RTNODE:
		vi = rti_to_vi(rti_new(alif, vba));
		break;
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		vi = fli_to_vi(fli_new(alif, vba));
		break;
	case VOLUTA_VTYPE_NONE:
	case VOLUTA_VTYPE_SUPER:
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

static struct voluta_header *hdr_of(const union voluta_view *view)
{
	const struct voluta_header *hdr = &view->hdr;

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
		csum = calc_data_checksum(vi->view, vaddr->len, md);
	} else {
		csum = calc_meta_chekcsum(vi_hdr_of(vi), md);
	}
	return csum;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_hdr(const union voluta_view *view, enum voluta_vtype vtype)
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

static int verify_checksum(const union voluta_view *view,
                           const struct voluta_mdigest *md)
{
	uint32_t csum;
	const struct voluta_header *hdr = hdr_of(view);

	csum = calc_meta_chekcsum(hdr, md);
	return (csum == hdr_csum(hdr)) ? 0 : -EFSCORRUPTED;
}

static int verify_sub(const union voluta_view *view, enum voluta_vtype vtype)
{
	int err;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		err = voluta_verify_hspace_map(&view->hsm);
		break;
	case VOLUTA_VTYPE_AGMAP:
		err = voluta_verify_agroup_map(&view->agm);
		break;
	case VOLUTA_VTYPE_ITNODE:
		err = voluta_verify_itnode(&view->itn);
		break;
	case VOLUTA_VTYPE_INODE:
		err = voluta_verify_inode(&view->inode);
		break;
	case VOLUTA_VTYPE_XANODE:
		err = voluta_verify_xattr_node(&view->xan);
		break;
	case VOLUTA_VTYPE_DTNODE:
		err = voluta_verify_dir_htree_node(&view->htn);
		break;
	case VOLUTA_VTYPE_RTNODE:
		err = voluta_verify_radix_tnode(&view->rtn);
		break;
	case VOLUTA_VTYPE_SYMVAL:
		err = voluta_verify_lnk_value(&view->sym);
		break;
	case VOLUTA_VTYPE_SUPER:
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		err = 0;
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		err = -EFSCORRUPTED;
		break;
	}
	return err;
}

static int verify_view(const union voluta_view *view,
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

static void stamp_view(union voluta_view *view,
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


