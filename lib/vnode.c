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


bool voluta_vtype_isnormal(enum voluta_vtype vtype)
{
	bool ret;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
	case VOLUTA_VTYPE_AGMAP:
		ret = false;
		break;
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
		ret = true;
		break;
	}
	return ret;
}

bool voluta_vtype_isdata(enum voluta_vtype vtype)
{
	bool ret;

	switch (vtype) {
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
	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		return sizeof(struct voluta_hspace_map);
	case VOLUTA_VTYPE_AGMAP:
		return sizeof(struct voluta_agroup_map);
	case VOLUTA_VTYPE_ITNODE:
		return sizeof(struct voluta_itable_tnode);
	case VOLUTA_VTYPE_INODE:
		return sizeof(struct voluta_inode);
	case VOLUTA_VTYPE_XANODE:
		return sizeof(struct voluta_xattr_node);
	case VOLUTA_VTYPE_HTNODE:
		return sizeof(struct voluta_dir_htnode);
	case VOLUTA_VTYPE_RTNODE:
		return sizeof(struct voluta_radix_tnode);
	case VOLUTA_VTYPE_SYMVAL:
		return sizeof(struct voluta_lnk_value);
	case VOLUTA_VTYPE_DATA4K:
		return sizeof(struct voluta_data_block4);
	case VOLUTA_VTYPE_DATABK:
		return sizeof(struct voluta_data_block);
	case VOLUTA_VTYPE_NONE:
	default:
		break;
	}
	return 0;
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

void voluta_vaddr_of_vnode(struct voluta_vaddr *vaddr, enum voluta_vtype vtype,
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
	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		return voluta_verify_uspace_map(&view->u.hsm);
	case VOLUTA_VTYPE_AGMAP:
		return voluta_verify_agroup_map(&view->u.agm);
	case VOLUTA_VTYPE_ITNODE:
		return voluta_verify_itnode(&view->u.itn);
	case VOLUTA_VTYPE_INODE:
		return voluta_verify_inode(&view->u.inode);
	case VOLUTA_VTYPE_XANODE:
		return voluta_verify_xattr_node(&view->u.xan);
	case VOLUTA_VTYPE_HTNODE:
		return voluta_verify_dir_htree_node(&view->u.htn);
	case VOLUTA_VTYPE_RTNODE:
		return voluta_verify_radix_tnode(&view->u.rtn);
	case VOLUTA_VTYPE_SYMVAL:
		return voluta_verify_lnk_value(&view->u.lnv);
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
		return 0;
	case VOLUTA_VTYPE_NONE:
	default:
		break;
	}
	return -EFSCORRUPTED;
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

void voluta_seal_meta(const struct voluta_vnode_info *vi)
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
	return &vi->v_sbi->sb_crypto.ci;
}

int voluta_encrypt_vnode(const struct voluta_vnode_info *vi, void *buf)
{
	struct voluta_iv_key iv_key;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	voluta_iv_key_of(vi, &iv_key);
	return voluta_encrypt_buf(vi_cipher(vi), &iv_key,
				  vi->view, buf, vaddr->len);
}

int voluta_decrypt_vnode(const struct voluta_vnode_info *vi, const void *buf)
{
	struct voluta_iv_key iv_key;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	voluta_iv_key_of(vi, &iv_key);
	return voluta_decrypt_buf(vi_cipher(vi), &iv_key,
				  buf, vi->view, vaddr->len);
}



