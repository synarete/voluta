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
                    voluta_vi_delete_fn del_hook)
{
	bi_init(&vi->v_bi, &vba->baddr);
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
	voluta_fiovref_fini(&vi->v_fir);
	vi->view = NULL;
	vi->v_sbi = NULL;
	vi->v_bsi = NULL;
	vi->v_ds_next = NULL;
	vi->vu.p = NULL;
	vi->v_dirty = -11111;
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
		err = voluta_verify_lnk_value(&view->u.lnv);
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

int voluta_verify_meta(const struct voluta_vnode_info *vi)
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


