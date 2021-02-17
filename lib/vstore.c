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
#include "libvoluta.h"


bool voluta_vtype_isubermap(enum voluta_vtype vtype)
{
	bool ret;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
	case VOLUTA_VTYPE_AGMAP:
		ret = true;
		break;
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
	case VOLUTA_VTYPE_ITNODE:
	case VOLUTA_VTYPE_INODE:
	case VOLUTA_VTYPE_XANODE:
	case VOLUTA_VTYPE_HTNODE:
	case VOLUTA_VTYPE_RTNODE:
	case VOLUTA_VTYPE_SYMVAL:
	case VOLUTA_VTYPE_NONE:
	default:
		ret = false;
		break;
	}
	return ret;
}

bool voluta_vtype_isdata(enum voluta_vtype vtype)
{
	bool ret;

	switch (vtype) {
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		ret = true;
		break;
	case VOLUTA_VTYPE_HSMAP:
	case VOLUTA_VTYPE_AGMAP:
	case VOLUTA_VTYPE_ITNODE:
	case VOLUTA_VTYPE_INODE:
	case VOLUTA_VTYPE_XANODE:
	case VOLUTA_VTYPE_HTNODE:
	case VOLUTA_VTYPE_RTNODE:
	case VOLUTA_VTYPE_SYMVAL:
	case VOLUTA_VTYPE_NONE:
	default:
		ret = false;
		break;
	}
	return ret;
}

size_t voluta_vtype_size(enum voluta_vtype vtype)
{
	size_t sz;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		sz = sizeof(struct voluta_hspace_map);
		break;
	case VOLUTA_VTYPE_AGMAP:
		sz = sizeof(struct voluta_agroup_map);
		break;
	case VOLUTA_VTYPE_ITNODE:
		sz = sizeof(struct voluta_itable_tnode);
		break;
	case VOLUTA_VTYPE_INODE:
		sz = sizeof(struct voluta_inode);
		break;
	case VOLUTA_VTYPE_XANODE:
		sz = sizeof(struct voluta_xattr_node);
		break;
	case VOLUTA_VTYPE_HTNODE:
		sz = sizeof(struct voluta_dir_htnode);
		break;
	case VOLUTA_VTYPE_RTNODE:
		sz = sizeof(struct voluta_radix_tnode);
		break;
	case VOLUTA_VTYPE_SYMVAL:
		sz = sizeof(struct voluta_lnk_value);
		break;
	case VOLUTA_VTYPE_DATA1K:
		sz = sizeof(struct voluta_data_block1);
		break;
	case VOLUTA_VTYPE_DATA4K:
		sz = sizeof(struct voluta_data_block4);
		break;
	case VOLUTA_VTYPE_DATABK:
		sz = sizeof(struct voluta_data_block);
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		sz = 0;
		break;
	}
	return sz;
}

ssize_t voluta_vtype_ssize(enum voluta_vtype vtype)
{
	return (ssize_t)voluta_vtype_size(vtype);
}

size_t voluta_vtype_nkbs(enum voluta_vtype vtype)
{
	const size_t size = voluta_vtype_size(vtype);

	return div_round_up(size, VOLUTA_KB_SIZE);
}

bool voluta_vtype_ismeta(enum voluta_vtype vtype)
{
	return !vtype_isdata(vtype) && !vtype_isnone(vtype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static size_t lba_to_ag_index(loff_t lba)
{
	return (size_t)(lba / VOLUTA_NBK_IN_AG);
}

static loff_t lba_kbn_to_off(loff_t lba, size_t kbn)
{
	return lba_to_off(lba) + (loff_t)(kbn * VOLUTA_KB_SIZE);
}

static loff_t lba_by_ag(size_t ag_index, size_t bn)
{
	const loff_t nbk_in_ag = VOLUTA_NBK_IN_AG;

	voluta_assert_lt(bn, VOLUTA_NBK_IN_AG);

	return nbk_in_ag * (loff_t)ag_index + (loff_t)bn;
}

loff_t voluta_lba_by_ag(size_t ag_index, size_t bn)
{
	return lba_by_ag(ag_index, bn);
}

static loff_t hsmap_lba_by_index(size_t hs_index)
{
	const loff_t hsm_lba = (loff_t)(VOLUTA_LBA_SB + hs_index);

	voluta_assert_gt(hs_index, 0);
	voluta_assert_lt(hsm_lba, VOLUTA_NBK_IN_AG);

	return hsm_lba;
}

size_t voluta_hs_index_of_ag(size_t ag_index)
{
	const size_t nag_in_hs = VOLUTA_NAG_IN_HS;
	const size_t nag_prefix = VOLUTA_NAG_IN_HS_PREFIX;

	return (ag_index / (nag_prefix + nag_in_hs)) + 1;
}

size_t voluta_ag_index_by_hs(size_t hs_index, size_t ag_slot)
{
	const size_t nag_in_hs = VOLUTA_NAG_IN_HS;
	const size_t nag_prefix = VOLUTA_NAG_IN_HS_PREFIX;

	voluta_assert_gt(hs_index, 0);

	return nag_prefix + ((hs_index - 1) * nag_in_hs) + ag_slot;
}

size_t voluta_ag_index_to_hs_slot(size_t ag_index)
{
	const size_t nag_in_hs = VOLUTA_NAG_IN_HS;
	const size_t nag_prefix = VOLUTA_NAG_IN_HS_PREFIX;

	voluta_assert_ge(ag_index, nag_prefix);
	return (ag_index - nag_prefix) % nag_in_hs;
}

size_t voluta_size_to_ag_count(size_t nbytes)
{
	return nbytes / VOLUTA_AG_SIZE;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct voluta_vaddr voluta_vaddr_none = {
	.off = VOLUTA_OFF_NULL,
	.lba = VOLUTA_LBA_NULL,
	.vtype = VOLUTA_VTYPE_NONE,
	.len = 0
};

size_t voluta_vaddr_ag_index(const struct voluta_vaddr *vaddr)
{
	return lba_to_ag_index(vaddr->lba);
}

size_t voluta_vaddr_hs_index(const struct voluta_vaddr *vaddr)
{
	return voluta_hs_index_of_ag(vaddr_ag_index(vaddr));
}

void voluta_vaddr_setup(struct voluta_vaddr *vaddr,
			enum voluta_vtype vtype, loff_t off)
{
	vaddr->vtype = vtype;
	vaddr->len = (uint32_t)vtype_size(vtype);
	if (!off_isnull(off)) {
		vaddr->lba = off_to_lba(off);
		vaddr->off = off;
	} else {
		vaddr->lba = VOLUTA_LBA_NULL;
		vaddr->off = VOLUTA_OFF_NULL;
	}
}

void voluta_vaddr_copyto(const struct voluta_vaddr *vaddr,
			 struct voluta_vaddr *other)
{
	other->off = vaddr->off;
	other->lba = vaddr->lba;
	other->vtype = vaddr->vtype;
	other->len = vaddr->len;
}

void voluta_vaddr_reset(struct voluta_vaddr *vaddr)
{
	vaddr->off = VOLUTA_OFF_NULL;
	vaddr->lba = VOLUTA_LBA_NULL;
	vaddr->vtype = VOLUTA_VTYPE_NONE;
	vaddr->len = 0;
}

bool voluta_vaddr_isnull(const struct voluta_vaddr *vaddr)
{
	return off_isnull(vaddr->off) || vtype_isnone(vaddr->vtype);
}

bool voluta_vaddr_isdata(const struct voluta_vaddr *vaddr)
{
	return vtype_isdata(vaddr->vtype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vaddr_of_hsmap(struct voluta_vaddr *vaddr, size_t hs_index)
{
	const loff_t lba = hsmap_lba_by_index(hs_index);
	const loff_t off = lba_to_off(lba);

	vaddr_setup(vaddr, VOLUTA_VTYPE_HSMAP, off);
}

void voluta_vaddr_of_agmap(struct voluta_vaddr *vaddr, size_t ag_index)
{
	const loff_t off = ag_index_to_off(ag_index);

	vaddr_setup(vaddr, VOLUTA_VTYPE_AGMAP, off);
}

void voluta_vaddr_of_itnode(struct voluta_vaddr *vaddr, loff_t off)
{
	vaddr_setup(vaddr, VOLUTA_VTYPE_ITNODE, off);
}

void voluta_vaddr_by_ag(struct voluta_vaddr *vaddr, enum voluta_vtype vtype,
			size_t ag_index, size_t bn, size_t kbn)
{
	const loff_t lba = lba_by_ag(ag_index, bn);
	const loff_t off = lba_kbn_to_off(lba, kbn);

	vaddr_setup(vaddr, vtype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vaddr56_set(struct voluta_vaddr56 *va, loff_t off)
{
	const uint64_t uoff = (uint64_t)off;

	if (!off_isnull(off)) {
		voluta_assert_eq(uoff & 0xFFL, 0);
		va->lo = cpu_to_le32((uint32_t)(uoff >> 8));
		va->me = cpu_to_le16((uint16_t)(uoff >> 40));
		va->hi = (uint8_t)(uoff >> 56);
	} else {
		va->lo = cpu_to_le32(UINT32_MAX);
		va->me = cpu_to_le16(UINT16_MAX);
		va->hi = UINT8_MAX;
	}
}

loff_t voluta_vaddr56_parse(const struct voluta_vaddr56 *va)
{
	loff_t off;
	const uint64_t lo = le32_to_cpu(va->lo);
	const uint64_t me = le16_to_cpu(va->me);
	const uint64_t hi = va->hi;

	if ((lo == UINT32_MAX) && (me == UINT16_MAX) && (hi == UINT8_MAX)) {
		off = VOLUTA_OFF_NULL;
	} else {
		off = (loff_t)((lo << 8) | (me << 40) | (hi << 56));
	}
	return off;
}

void voluta_vaddr64_set(struct voluta_vaddr64 *va,
			const struct voluta_vaddr *vaddr)
{
	const uint64_t off = (uint64_t)vaddr->off;
	const uint64_t vtype = (uint64_t)vaddr->vtype;

	if (!vaddr_isnull(vaddr)) {
		va->off_vtype = cpu_to_le64((off << 8) | (vtype & 0xFF));
	} else {
		va->off_vtype = 0;
	}
}

void voluta_vaddr64_parse(const struct voluta_vaddr64 *va,
			  struct voluta_vaddr *vaddr)
{
	const uint64_t off_vtype = le64_to_cpu(va->off_vtype);

	if (off_vtype != 0) {
		vaddr_setup(vaddr, off_vtype & 0xFF, (loff_t)(off_vtype >> 8));
	} else {
		vaddr_reset(vaddr);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint32_t hdr_magic(const struct voluta_header *hdr)
{
	return le32_to_cpu(hdr->h_magic);
}

static void hdr_set_magic(struct voluta_header *hdr, uint32_t magic)
{
	hdr->h_magic = cpu_to_le32(magic);
}

static size_t hdr_size(const struct voluta_header *hdr)
{
	return le32_to_cpu(hdr->h_size);
}

static size_t hdr_payload_size(const struct voluta_header *hdr)
{
	return hdr_size(hdr) - sizeof(*hdr);
}

static void hdr_set_size(struct voluta_header *hdr, size_t size)
{
	hdr->h_size = cpu_to_le32((uint32_t)size);
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
	return le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct voluta_header *hdr, uint32_t csum)
{
	hdr->h_csum = cpu_to_le32(csum);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_header *
vi_hdr_of(const struct voluta_vnode_info *vi)
{
	return hdr_of(vi->view);
}

static bool vi_isdatabk(const struct voluta_vnode_info *vi)
{
	return vtype_isequal(vi_vtype(vi), VOLUTA_VTYPE_DATABK);
}

void *voluta_vi_dat_of(const struct voluta_vnode_info *vi)
{
	return vi_isdatabk(vi) ? vi->vu.db->dat : vi->vu.db4->dat;
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

int voluta_verify_ino(ino_t ino)
{
	return !ino_isnull(ino) ? 0 : -EFSCORRUPTED;
}

int voluta_verify_off(loff_t off)
{
	return (off_isnull(off) || (off >= 0)) ? 0 : -EFSCORRUPTED;
}

static int verify_sub(const struct voluta_view *view, enum voluta_vtype vtype)
{
	int err;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		err = voluta_verify_uspace_map(&view->u.hsm);
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

static void stamp_hdr(struct voluta_header *hdr,
		      enum voluta_vtype vtype, size_t size)
{
	hdr_set_magic(hdr, VOLUTA_VTYPE_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_vtype(hdr, vtype);
	hdr_set_csum(hdr, 0);
	hdr->h_flags = 0;
	hdr->h_reserved = 0;
}

void voluta_stamp_view(struct voluta_view *view,
		       const struct voluta_vaddr *vaddr)
{
	struct voluta_header *hdr = hdr_of(view);

	voluta_memzero(view, vaddr->len);
	stamp_hdr(hdr, vaddr->vtype, vaddr->len);
}

static void seal_meta_vnode(const struct voluta_vnode_info *vi)
{
	uint32_t csum;
	struct voluta_header *hdr = hdr_of(vi->view);

	csum = calc_chekcsum_of(vi);
	hdr_set_csum(hdr, csum);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool voluta_vi_isdata(const struct voluta_vnode_info *vi)
{
	return voluta_vtype_isdata(vi_vtype(vi));
}


static const struct voluta_cipher *
vi_cipher(const struct voluta_vnode_info *vi)
{
	return &vi->v_sbi->sb_vstore->vs_crypto.ci;
}

static int encrypt_vnode(const struct voluta_vnode_info *vi,
			 const struct voluta_cipher *cipher, void *buf)
{
	struct voluta_kivam kivam = { .reserved = 0 };
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	voluta_kivam_of(vi, &kivam);
	return voluta_encrypt_buf(cipher, &kivam,
				  vi->view, buf, vaddr->len);
}

int voluta_decrypt_vnode(const struct voluta_vnode_info *vi, const void *buf)
{
	struct voluta_kivam kivam;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	voluta_kivam_of(vi, &kivam);
	return voluta_decrypt_buf(vi_cipher(vi), &kivam,
				  buf, vi->view, vaddr->len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstore_init_crypto(struct voluta_vstore *vstore)
{
	return voluta_crypto_init(&vstore->vs_crypto);
}

static void vstore_fini_crypto(struct voluta_vstore *vstore)
{
	voluta_crypto_fini(&vstore->vs_crypto);
}

static int vstore_init_encbuf(struct voluta_vstore *vstore)
{
	vstore->vs_encbuf = voluta_qalloc_zmalloc(vstore->vs_qalloc,
			    sizeof(*vstore->vs_encbuf));

	return (vstore->vs_encbuf == NULL) ? -ENOMEM : 0;
}

static void vstore_fini_encbuf(struct voluta_vstore *vstore)
{
	if (vstore->vs_encbuf != NULL) {
		voluta_qalloc_zfree(vstore->vs_qalloc, vstore->vs_encbuf,
				    sizeof(*vstore->vs_encbuf));
		vstore->vs_encbuf = NULL;
	}
}

static int vstore_init_pstore(struct voluta_vstore *vstore)
{
	return voluta_pstore_init(&vstore->vs_pstore);
}

static void vstore_fini_pstore(struct voluta_vstore *vstore)
{
	voluta_pstore_fini(&vstore->vs_pstore);
}

int voluta_vstore_init(struct voluta_vstore *vstore,
		       struct voluta_qalloc *qalloc)
{
	int err;

	voluta_memzero(vstore, sizeof(*vstore));
	vstore->vs_qalloc = qalloc;
	vstore->vs_volpath = NULL;
	vstore->vs_ctl_flags = 0;

	err = vstore_init_crypto(vstore);
	if (err) {
		return err;
	}
	err = vstore_init_encbuf(vstore);
	if (err) {
		goto out;
	}
	err = vstore_init_pstore(vstore);
	if (err) {
		goto out;
	}
out:
	if (err) {
		vstore_fini_pstore(vstore);
		vstore_fini_encbuf(vstore);
		vstore_fini_crypto(vstore);
	}
	return err;
}

void voluta_vstore_fini(struct voluta_vstore *vstore)
{
	vstore_fini_pstore(vstore);
	vstore_fini_encbuf(vstore);
	vstore_fini_crypto(vstore);
	vstore->vs_qalloc = NULL;
	vstore->vs_volpath = NULL;
	vstore->vs_ctl_flags = 0;
}

void voluta_vstore_add_ctlflags(struct voluta_vstore *vstore,
				enum voluta_flags flags)
{
	vstore->vs_ctl_flags |= flags;
}

int voluta_vstore_check_size(const struct voluta_vstore *vstore)
{
	const loff_t size_min = VOLUTA_VOLUME_SIZE_MIN;
	const loff_t size_max = VOLUTA_VOLUME_SIZE_MAX;
	const loff_t size_cur = vstore->vs_pstore.ps_size;

	return ((size_cur < size_min) || (size_cur > size_max)) ? -EINVAL : 0;
}

int voluta_vstore_open(struct voluta_vstore *vstore, const char *path, bool rw)
{
	int err;

	err = voluta_pstore_open(&vstore->vs_pstore, path, rw);
	if (err) {
		return err;
	}
	vstore->vs_volpath = path;
	return 0;
}

int voluta_vstore_create(struct voluta_vstore *vstore,
			 const char *path, loff_t size)
{
	int err;
	const loff_t vol_size_min = VOLUTA_VOLUME_SIZE_MIN;

	err = voluta_pstore_create(&vstore->vs_pstore, path, size);
	if (err) {
		return err;
	}
	err = voluta_vstore_expand(vstore, vol_size_min);
	if (err) {
		return err;
	}
	vstore->vs_volpath = path;
	return 0;
}

int voluta_vstore_close(struct voluta_vstore *vstore)
{
	return voluta_pstore_close(&vstore->vs_pstore);
}

int voluta_vstore_expand(struct voluta_vstore *vstore, loff_t cap)
{
	return voluta_pstore_expand(&vstore->vs_pstore, cap);
}

int voluta_vstore_flock(const struct voluta_vstore *vstore)
{
	return voluta_pstore_flock(&vstore->vs_pstore);
}

int voluta_vstore_funlock(const struct voluta_vstore *vstore)
{
	return voluta_pstore_funlock(&vstore->vs_pstore);
}

int voluta_vstore_write(struct voluta_vstore *vstore,
			loff_t off, size_t bsz, const void *buf)
{
	return voluta_pstore_write(&vstore->vs_pstore, off, bsz, buf);
}

int voluta_vstore_writev(struct voluta_vstore *vstore, loff_t off,
			 size_t len, const struct iovec *iov, size_t cnt)
{
	return voluta_pstore_writev(&vstore->vs_pstore, off, len, iov, cnt);
}

int voluta_vstore_read(const struct voluta_vstore *vstore,
		       loff_t off, size_t bsz, void *buf)
{
	return voluta_pstore_read(&vstore->vs_pstore, off, bsz, buf);
}

int voluta_vstore_clone(const struct voluta_vstore *vstore,
			const struct voluta_str *name)
{
	return voluta_pstore_clone(&vstore->vs_pstore, name);
}

int voluta_vstore_sync(struct voluta_vstore *vstore)
{
	return voluta_pstore_sync(&vstore->vs_pstore, false);
}

int voluta_vstore_xiovec(const struct voluta_vstore *vstore,
			 loff_t off, size_t len, struct voluta_xiovec *xiov)
{
	int err;
	const struct voluta_pstore *pstore = &vstore->vs_pstore;

	err = voluta_pstore_check_io(pstore, off, len);
	if (!err) {
		xiov->off = off;
		xiov->len = len;
		xiov->base = NULL;
		xiov->fd = pstore->ps_vfd;
	}
	return err;
}

static const struct voluta_cipher *
vstore_cipher(const struct voluta_vstore *vstore)
{
	return &vstore->vs_crypto.ci;
}

static bool vstore_encryptwr(const struct voluta_vstore *vstore)
{
	const unsigned long mask = VOLUTA_F_ENCRYPTWR;

	return ((vstore->vs_ctl_flags & mask) == mask);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct voluta_sgvec {
	struct iovec iov[VOLUTA_NKB_IN_BK];
	loff_t off;
	size_t len;
	size_t cnt;
	size_t lim;
};

static void sgv_setup(struct voluta_sgvec *sgv)
{
	memset(sgv, 0, sizeof(*sgv));
	sgv->off = -1;
	sgv->lim = 2 * VOLUTA_MEGA;
}

static bool sgv_isappendable(const struct voluta_sgvec *sgv,
			     const struct voluta_vnode_info *vi)
{
	loff_t off;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if ((sgv->cnt == 0) && (vaddr->len < sgv->lim)) {
		return true;
	}
	if (sgv->cnt == ARRAY_SIZE(sgv->iov)) {
		return false;
	}
	off = off_end(sgv->off, sgv->len);
	if (vaddr->off != off) {
		return false;
	}
	if ((sgv->len + vaddr->len) > sgv->lim) {
		return false;
	}
	return true;
}

static int sgv_append(struct voluta_sgvec *sgv,
		      const struct voluta_vnode_info *vi)
{
	const size_t idx = sgv->cnt;
	const size_t len = vi_length(vi);

	if (idx == 0) {
		sgv->off = vi_offset(vi);
	}
	sgv->iov[idx].iov_base = vi->view;
	sgv->iov[idx].iov_len = len;
	sgv->len += len;
	sgv->cnt += 1;
	return 0;
}

static int sgv_populate(struct voluta_sgvec *sgv,
			struct voluta_vnode_info **viq)
{
	int err;
	struct voluta_vnode_info *vi;

	while (*viq != NULL) {
		vi = *viq;
		if (!sgv_isappendable(sgv, vi)) {
			break;
		}
		err = sgv_append(sgv, vi);
		if (err) {
			return err;
		}
		*viq = vi->v_ds_next;
	}
	return 0;
}

static int sgv_destage(const struct voluta_sgvec *sgv,
		       struct voluta_vstore *vstore)
{
	return voluta_vstore_writev(vstore, sgv->off,
				    sgv->len, sgv->iov, sgv->cnt);
}

static int sgv_flush_dset(struct voluta_sgvec *sgv,
			  const struct voluta_dset *dset,
			  struct voluta_vstore *vstore)
{
	int err;
	struct voluta_vnode_info *viq = dset->ds_viq;

	while (viq != NULL) {
		sgv_setup(sgv);
		err = sgv_populate(sgv, &viq);
		if (err) {
			return err;
		}
		err = sgv_destage(sgv, vstore);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_iobuf {
	struct voluta_buf buf;
	loff_t off;
};

static void iob_setup(struct voluta_iobuf *iob, struct voluta_encbuf *eb)
{
	iob->buf.len = 0;
	iob->buf.buf = eb->b;
	iob->buf.bsz = sizeof(eb->b);
	iob->off = -1;
}

static bool iob_isappendable(const struct voluta_iobuf *iob,
			     const struct voluta_vnode_info *vi)
{
	loff_t off;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if ((iob->buf.len == 0) && (vaddr->len < iob->buf.bsz)) {
		return true;
	}
	off = off_end(iob->off, iob->buf.len);
	if (vaddr->off != off) {
		return false;
	}
	if ((iob->buf.len + vaddr->len) > iob->buf.bsz) {
		return false;
	}
	return true;
}

static int iob_append(struct voluta_iobuf *iob,
		      const struct voluta_cipher *ci,
		      const struct voluta_vnode_info *vi)
{
	int err;
	void *ptr;
	const size_t len = vi_length(vi);

	if (iob->off == -1) {
		iob->off = vi_offset(vi);
	}
	voluta_assert_ge(buf_rem(&iob->buf), len);

	ptr = buf_end(&iob->buf);
	err = encrypt_vnode(vi, ci, ptr);
	if (err) {
		return err;
	}
	iob->buf.len += len;
	return 0;
}

static int iob_populate(struct voluta_iobuf *iob,
			struct voluta_vnode_info **viq,
			const struct voluta_cipher *ci)
{
	int err;
	struct voluta_vnode_info *vi;

	while (*viq != NULL) {
		vi = *viq;
		if (!iob_isappendable(iob, vi)) {
			break;
		}
		err = iob_append(iob, ci, vi);
		if (err) {
			return err;
		}
		*viq = vi->v_ds_next;
	}
	return 0;
}

static int iob_destage(const struct voluta_iobuf *iob,
		       struct voluta_vstore *vstore)
{
	const loff_t lba = off_to_lba(iob->off);

	voluta_assert(!off_isnull(iob->off));
	voluta_assert(!lba_isnull(lba));
	voluta_assert_gt(lba, VOLUTA_LBA_SB);

	return voluta_vstore_write(vstore, iob->off,
				   iob->buf.len, iob->buf.buf);
}

static int iob_flush_dset(struct voluta_iobuf *iob,
			  const struct voluta_dset *dset,
			  struct voluta_vstore *vstore)
{
	int err;
	struct voluta_vnode_info *viq = dset->ds_viq;
	const struct voluta_cipher *cipher = vstore_cipher(vstore);

	while (viq != NULL) {
		iob_setup(iob, vstore->vs_encbuf);
		err = iob_populate(iob, &viq, cipher);
		if (err) {
			return err;
		}
		err = iob_destage(iob, vstore);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long off_compare(const void *x, const void *y)
{
	const loff_t x_off = *((const loff_t *)x);
	const loff_t y_off = *((const loff_t *)y);

	return y_off - x_off;
}

static struct voluta_vnode_info *
avl_node_to_vi(const struct voluta_avl_node *an)
{
	const struct voluta_vnode_info *vi;

	vi = container_of2(an, struct voluta_vnode_info, v_ds_an);
	return unconst(vi);
}

static const void *vi_getkey(const struct voluta_avl_node *an)
{
	const struct voluta_vnode_info *vi = avl_node_to_vi(an);

	return &vi->vaddr.off;
}

static void vi_visit_reinit(struct voluta_avl_node *an, void *p)
{
	struct voluta_vnode_info *vi = avl_node_to_vi(an);

	voluta_avl_node_init(&vi->v_ds_an);
	unused(p);
}

static void dset_clear_map(struct voluta_dset *dset)
{
	voluta_avl_clear(&dset->ds_avl, vi_visit_reinit, NULL);
}

static void dset_add_dirty_vi(struct voluta_dset *dset,
			      struct voluta_vnode_info *vi)
{
	voluta_avl_insert(&dset->ds_avl, &vi->v_ds_an);
}

static void dset_init(struct voluta_dset *dset, long key)
{
	voluta_avl_init(&dset->ds_avl, vi_getkey, off_compare, dset);
	dset->ds_viq = NULL;
	dset->ds_key = key;
	dset->ds_add_fn = dset_add_dirty_vi;
}

static void dset_fini(struct voluta_dset *dset)
{
	voluta_avl_fini(&dset->ds_avl);
	dset->ds_viq = NULL;
	dset->ds_add_fn = NULL;
}

static void dset_purge(const struct voluta_dset *dset)
{
	struct voluta_vnode_info *vi;
	struct voluta_vnode_info *next;

	vi = dset->ds_viq;
	while (vi != NULL) {
		next = vi->v_ds_next;

		vi_undirtify(vi);
		vi->v_ds_next = NULL;

		vi = next;
	}
}

static void dset_push_front_viq(struct voluta_dset *dset,
				struct voluta_vnode_info *vi)
{
	vi->v_ds_next = dset->ds_viq;
	dset->ds_viq = vi;
}

static void dset_make_fifo(struct voluta_dset *dset)
{
	struct voluta_vnode_info *vi;
	const struct voluta_avl_node *end;
	const struct voluta_avl_node *itr;
	const struct voluta_avl *avl = &dset->ds_avl;

	dset->ds_viq = NULL;
	end = voluta_avl_end(avl);
	itr = voluta_avl_rbegin(avl);
	while (itr != end) {
		vi = avl_node_to_vi(itr);
		dset_push_front_viq(dset, vi);
		itr = voluta_avl_prev(avl, itr);
	}
}

static void dset_inhabit(struct voluta_dset *dset,
			 const struct voluta_cache *cache)
{
	voluta_cache_inhabit_dset(cache, dset);
}

static void dset_seal_meta(const struct voluta_dset *dset)
{
	const struct voluta_vnode_info *vi = dset->ds_viq;

	while (vi != NULL) {
		if (!vi_isdata(vi)) {
			seal_meta_vnode(vi);
		}
		vi = vi->v_ds_next;
	}
}

static void dset_cleanup(struct voluta_dset *dset)
{
	dset_clear_map(dset);
	dset_purge(dset);
}

static int dset_flush(const struct voluta_dset *dset,
		      struct voluta_vstore *vstore)
{
	struct voluta_sgvec sgv;
	struct voluta_iobuf iob;

	return vstore_encryptwr(vstore) ?
	       iob_flush_dset(&iob, dset, vstore) :
	       sgv_flush_dset(&sgv, dset, vstore);
}

static int dset_collect_flush(struct voluta_dset *dset,
			      const struct voluta_cache *cache,
			      struct voluta_vstore *vstore)
{
	int err;

	dset_inhabit(dset, cache);
	dset_make_fifo(dset);
	dset_seal_meta(dset);
	err = dset_flush(dset, vstore);
	dset_cleanup(dset);
	return err;
}

int voluta_vstore_flush(struct voluta_vstore *vstore,
			const struct voluta_cache *cache, long ds_key)
{
	int err;
	struct voluta_dset dset;

	dset_init(&dset, ds_key);
	err = dset_collect_flush(&dset, cache, vstore);
	dset_fini(&dset);
	return err;
}

int voluta_vstore_punch_bk(const struct voluta_vstore *vstore, loff_t lba)
{
	const loff_t off = lba_to_off(lba);
	const size_t len = VOLUTA_BK_SIZE;

	voluta_assert_eq(off % (long)len, 0);

	return voluta_pstore_punch_hole(&vstore->vs_pstore, off, len);
}

