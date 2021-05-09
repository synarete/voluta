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


static voluta_lba_t lba_plus(voluta_lba_t lba, size_t nbk)
{
	return lba + (voluta_lba_t)nbk;
}

static voluta_lba_t lba_kbn_to_off(voluta_lba_t lba, size_t kbn)
{
	return lba_to_off(lba) + (voluta_lba_t)(kbn * VOLUTA_KB_SIZE);
}

static voluta_index_t lba_to_ag_index(voluta_lba_t lba)
{
	return (voluta_index_t)(lba / VOLUTA_NBK_IN_AG);
}

static voluta_lba_t ag_index_to_lba(voluta_index_t ag_index)
{
	return (voluta_lba_t)(ag_index * VOLUTA_NBK_IN_AG);
}

static voluta_lba_t lba_within_ag(voluta_index_t ag_index, size_t slot)
{
	voluta_assert_lt(slot, VOLUTA_NBK_IN_AG);

	return lba_plus(ag_index_to_lba(ag_index), slot);
}

static voluta_index_t ag_to_hs_index(voluta_index_t ag_index)
{
	return ag_index / VOLUTA_NAG_IN_HS;
}

static voluta_lba_t agm_lba_by_index(voluta_index_t ag_index)
{
	const size_t nbk_in_ag = VOLUTA_NBK_IN_AG;
	const voluta_lba_t agm_lba = (voluta_lba_t)(nbk_in_ag + ag_index);

	voluta_assert_ge(ag_index, VOLUTA_NAG_IN_HS);
	voluta_assert_lt(agm_lba, VOLUTA_NBK_IN_HS);

	return agm_lba;
}

voluta_lba_t voluta_lba_by_ag(voluta_index_t ag_index, size_t bn)
{
	return lba_within_ag(ag_index, bn);
}

static voluta_lba_t hsm_lba_by_index(voluta_index_t hs_index)
{
	const voluta_lba_t hsm_lba = (voluta_lba_t)(VOLUTA_LBA_SB + hs_index);

	voluta_assert_lt(hsm_lba, VOLUTA_NBK_IN_HS);

	return hsm_lba;
}

voluta_index_t voluta_hs_index_of_ag(voluta_index_t ag_index)
{
	return ag_to_hs_index(ag_index);
}

voluta_index_t voluta_ag_index_by_hs(voluta_index_t hs_index, size_t ag_slot)
{
	return (hs_index * VOLUTA_NAG_IN_HS) + ag_slot;
}

size_t voluta_ag_index_to_hs_slot(voluta_index_t ag_index)
{
	return ag_index % VOLUTA_NAG_IN_HS;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool voluta_vtype_isspmap(enum voluta_vtype vtype)
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
	case VOLUTA_VTYPE_BLOB:
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
	case VOLUTA_VTYPE_BLOB:
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
	case VOLUTA_VTYPE_BLOB:
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_vaddr s_vaddr_none = {
	.hs_index = VOLUTA_HS_INDEX_NULL,
	.ag_index = VOLUTA_AG_INDEX_NULL,
	.off = VOLUTA_OFF_NULL,
	.lba = VOLUTA_LBA_NULL,
	.vtype = VOLUTA_VTYPE_NONE,
	.len = 0
};

const struct voluta_vaddr *voluta_vaddr_none(void)
{
	return &s_vaddr_none;
}

void voluta_vaddr_setup(struct voluta_vaddr *vaddr,
                        enum voluta_vtype vtype, loff_t off)
{
	vaddr->vtype = vtype;
	vaddr->len = (uint32_t)vtype_size(vtype);
	if (!off_isnull(off)) {
		vaddr->off = off;
		vaddr->lba = off_to_lba(off);
		vaddr->ag_index = lba_to_ag_index(vaddr->lba);
		vaddr->hs_index = ag_to_hs_index(vaddr->ag_index);
	} else {
		vaddr->off = VOLUTA_OFF_NULL;
		vaddr->lba = VOLUTA_LBA_NULL;
		vaddr->ag_index = VOLUTA_AG_INDEX_NULL;
		vaddr->hs_index = VOLUTA_HS_INDEX_NULL;
	}
}

void voluta_vaddr_copyto(const struct voluta_vaddr *vaddr,
                         struct voluta_vaddr *other)
{
	other->hs_index = vaddr->hs_index;
	other->ag_index = vaddr->ag_index;
	other->off = vaddr->off;
	other->lba = vaddr->lba;
	other->vtype = vaddr->vtype;
	other->len = vaddr->len;
}

void voluta_vaddr_reset(struct voluta_vaddr *vaddr)
{
	vaddr->hs_index = VOLUTA_HS_INDEX_NULL;
	vaddr->ag_index = VOLUTA_AG_INDEX_NULL;
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

bool voluta_vaddr_isspmap(const struct voluta_vaddr *vaddr)
{
	return voluta_vtype_isspmap(vaddr->vtype);
}


void voluta_vaddr_of_hsmap(struct voluta_vaddr *vaddr, voluta_index_t hs_index)
{
	const voluta_lba_t lba = hsm_lba_by_index(hs_index);

	vaddr_setup(vaddr, VOLUTA_VTYPE_HSMAP, lba_to_off(lba));
}

void voluta_vaddr_of_agmap(struct voluta_vaddr *vaddr, voluta_index_t ag_index)
{
	const voluta_lba_t lba = agm_lba_by_index(ag_index);

	vaddr_setup(vaddr, VOLUTA_VTYPE_AGMAP, lba_to_off(lba));
}

void voluta_vaddr_of_itnode(struct voluta_vaddr *vaddr, loff_t off)
{
	vaddr_setup(vaddr, VOLUTA_VTYPE_ITNODE, off);
}

void voluta_vaddr_by_ag(struct voluta_vaddr *vaddr, enum voluta_vtype vtype,
                        voluta_index_t ag_index, size_t bn, size_t kbn)
{
	const voluta_lba_t lba = lba_within_ag(ag_index, bn);
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

static const struct voluta_baddr s_baddr_none = {
	.id[0] = 0,
};

const struct voluta_baddr *voluta_baddr_none(void)
{
	return &s_baddr_none;
}

void voluta_baddr_create(struct voluta_baddr *baddr)
{
	voluta_getentropy(baddr->id, sizeof(baddr->id));
}

void voluta_baddr_copyto(const struct voluta_baddr *baddr,
                         struct voluta_baddr *other)
{
	memcpy(other->id, baddr->id, sizeof(other->id));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_baddr256_set(struct voluta_baddr256 *ba,
                         const struct voluta_baddr *baddr)
{
	STATICASSERT_EQ(sizeof(ba->id), sizeof(baddr->id));

	memcpy(ba->id, baddr->id, sizeof(ba->id));
}

void voluta_baddr256_parse(const struct voluta_baddr256 *ba,
                           struct voluta_baddr *baddr)
{
	STATICASSERT_EQ(sizeof(ba->id), sizeof(baddr->id));

	memcpy(baddr->id, ba->id, sizeof(baddr->id));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool value_within(long value, long lower_bound, long upper_bound)
{
	return (value >= lower_bound) && (value <= upper_bound) ;
}

static long nbytes_to_nags(long nbytes)
{
	return (long)nbytes_to_ag_count(nbytes);
}

static long nags_to_nbytes(long nags)
{
	return ag_count_to_nbytes((size_t)nags);
}

int voluta_check_volume_size(loff_t size)
{
	const long nags = nbytes_to_nags(size);
	const long nag_min = VOLUTA_VOLUME_NAG_MIN;
	const long nag_max = VOLUTA_VOLUME_NAG_MAX;

	return value_within(nags, nag_min, nag_max) ? 0 : -EINVAL;
}

int voluta_check_address_space(loff_t size)
{
	const long nags = nbytes_to_nags(size);
	const long nag_min = VOLUTA_NAG_IN_HS;
	const long nag_max = VOLUTA_VOLUME_NAG_MAX;

	return value_within(nags, nag_min, nag_max) ? 0 : -EINVAL;
}

int voluta_calc_volume_space(loff_t volume_capacity,
                             loff_t *out_capacity_size,
                             loff_t *out_address_space)
{
	int err;
	long nags;

	err = voluta_check_volume_size(volume_capacity);
	if (err) {
		return err;
	}
	nags = nbytes_to_nags(volume_capacity);

	*out_address_space = nags_to_nbytes(nags + VOLUTA_NAG_IN_HS);
	*out_capacity_size = nags_to_nbytes(nags);

	return 0;
}


