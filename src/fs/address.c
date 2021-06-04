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
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <ctype.h>
#include <voluta/fs/types.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/address.h>
#include <voluta/fs/private.h>

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

static voluta_lba_t hsm_lba_by_index(voluta_index_t hs_index)
{
	const size_t nbk_in_bu = VOLUTA_NBK_IN_BKSEC;
	const voluta_lba_t hsm_lba = (voluta_lba_t)(nbk_in_bu + hs_index);

	voluta_assert_gt(VOLUTA_NBK_IN_BKSEC, VOLUTA_LBA_SB);

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

loff_t voluta_off_in_blob(loff_t off, size_t blob_size)
{
	const size_t uoff = (size_t)off;

	voluta_assert_gt(blob_size, 0);
	voluta_assert_ge(off, 0);
	voluta_assert(!off_isnull(off));

	return (loff_t)(uoff % blob_size);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool voluta_vtype_isspmap(enum voluta_vtype vtype)
{
	bool ret;

	switch (vtype) {
	case VOLUTA_VTYPE_SUPER:
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
	case VOLUTA_VTYPE_AGBKS:
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
	case VOLUTA_VTYPE_SUPER:
		sz = sizeof(struct voluta_super_block);
		break;
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
	case VOLUTA_VTYPE_AGBKS:
		sz = VOLUTA_AG_SIZE;
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

static void vaddr_of_agbks(struct voluta_vaddr *vaddr, voluta_index_t ag_index)
{
	const loff_t off = ag_index_to_off(ag_index);

	vaddr_setup(vaddr, VOLUTA_VTYPE_AGBKS, off);
}

void voluta_vaddr_by_ag(struct voluta_vaddr *vaddr, enum voluta_vtype vtype,
                        voluta_index_t ag_index, size_t bn, size_t kbn)
{
	const voluta_lba_t lba = lba_within_ag(ag_index, bn);
	const loff_t off = lba_kbn_to_off(lba, kbn);

	vaddr_setup(vaddr, vtype, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vaddr56_set(struct voluta_vaddr56 *vadr, loff_t off)
{
	const uint64_t uoff = (uint64_t)off;

	if (!off_isnull(off)) {
		voluta_assert_eq(uoff & 0xFFL, 0);
		vadr->lo = voluta_cpu_to_le32((uint32_t)(uoff >> 8));
		vadr->me = voluta_cpu_to_le16((uint16_t)(uoff >> 40));
		vadr->hi = (uint8_t)(uoff >> 56);
	} else {
		vadr->lo = voluta_cpu_to_le32(UINT32_MAX);
		vadr->me = voluta_cpu_to_le16(UINT16_MAX);
		vadr->hi = UINT8_MAX;
	}
}

loff_t voluta_vaddr56_parse(const struct voluta_vaddr56 *vadr)
{
	loff_t off;
	const uint64_t lo = voluta_le32_to_cpu(vadr->lo);
	const uint64_t me = voluta_le16_to_cpu(vadr->me);
	const uint64_t hi = vadr->hi;

	if ((lo == UINT32_MAX) && (me == UINT16_MAX) && (hi == UINT8_MAX)) {
		off = VOLUTA_OFF_NULL;
	} else {
		off = (loff_t)((lo << 8) | (me << 40) | (hi << 56));
	}
	return off;
}

void voluta_vaddr64_set(struct voluta_vaddr64 *vadr,
                        const struct voluta_vaddr *vaddr)
{
	const uint64_t off = (uint64_t)vaddr->off;
	const uint64_t vtype = (uint64_t)vaddr->vtype;

	if (!vaddr_isnull(vaddr)) {
		vadr->off_vtype =
		        voluta_cpu_to_le64((off << 8) | (vtype & 0xFF));
	} else {
		vadr->off_vtype = 0;
	}
}

void voluta_vaddr64_parse(const struct voluta_vaddr64 *vadr,
                          struct voluta_vaddr *vaddr)
{
	const uint64_t off_vtype = voluta_le64_to_cpu(vadr->off_vtype);

	if (off_vtype != 0) {
		vaddr_setup(vaddr, off_vtype & 0xFF, (loff_t)(off_vtype >> 8));
	} else {
		vaddr_reset(vaddr);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t uint64_at(const void *p)
{
	return *(const uint64_t *)p;
}

size_t voluta_blobid_size(const struct voluta_blobid *blobid)
{
	return voluta_le32_to_cpu(blobid->size);
}

static void blobid_set_size(struct voluta_blobid *blobid, size_t size)
{
	blobid->size = voluta_cpu_to_le32((uint32_t)size);
}

static loff_t blobid_off_within(const struct voluta_blobid *blobid, loff_t off)
{
	const size_t blob_size = voluta_blobid_size(blobid);

	return blob_size ? voluta_off_in_blob(off, blob_size) : 0;
}

void voluta_blobid_reset(struct voluta_blobid *blobid)
{
	memset(blobid->oid, 0, sizeof(blobid->oid));
	blobid_set_size(blobid, 0);
}

static void blobid_generate_oid(struct voluta_blobid *blobid)
{
	voluta_getentropy(blobid->oid, sizeof(blobid->oid));
}

static void blodid_make(struct voluta_blobid *blobid, size_t size)
{
	blobid_generate_oid(blobid);
	blobid_set_size(blobid, size);
}

void voluta_blobid_copyto(const struct voluta_blobid *blobid,
                          struct voluta_blobid *other)
{
	memcpy(other->oid, blobid->oid, sizeof(other->oid));
	blobid_set_size(other, voluta_blobid_size(blobid));
	other->reserved = 0;
}

bool voluta_blobid_isequal(const struct voluta_blobid *blobid,
                           const struct voluta_blobid *other)
{
	return (voluta_blobid_size(blobid) == voluta_blobid_size(other)) &&
	       (memcmp(blobid->oid, other->oid, sizeof(blobid->oid)) == 0);
}

uint64_t voluta_blobid_hkey(const struct voluta_blobid *blobid)
{
	const uint8_t *oid = blobid->oid;
	const uint64_t size = voluta_blobid_size(blobid);

	STATICASSERT_SIZEOF(blobid->oid, 32);

	return size ^ uint64_at(oid) ^ uint64_at(oid + 8) ^
	       uint64_at(oid + 16) ^ uint64_at(oid + 24);
}

static void byte_to_ascii(unsigned int byte, char *a1, char *a2)
{
	*a1 = voluta_nibble_to_ascii((int)(byte >> 4));
	*a2 = voluta_nibble_to_ascii((int)byte);
}

int voluta_blobid_to_name(const struct voluta_blobid *blobid,
                          char *name, size_t nmax, size_t *out_len)
{
	unsigned int byte;
	size_t len = 0;
	const size_t oid_size = ARRAY_SIZE(blobid->oid);

	if (nmax < (2 * oid_size)) {
		return -EINVAL;
	}
	for (size_t i = 0; i < oid_size; ++i) {
		byte = (int)(blobid->oid[i]);
		byte_to_ascii(byte, &name[len], &name[len + 1]);
		len += 2;
	}
	*out_len = len;
	return 0;
}

static int ascii_to_nibble(char a, unsigned int *out_nib)
{
	int ret;

	ret = voluta_ascii_to_nibble(a);
	if (ret < 0) {
		return ret;
	}
	*out_nib = (uint8_t)ret;
	return 0;
}

static int ascii_to_byte(char a1, char a2, uint8_t *out_byte)
{
	int err;
	unsigned int nib[2];

	err = ascii_to_nibble(a1, &nib[0]);
	if (err) {
		return err;
	}
	err = ascii_to_nibble(a2, &nib[1]);
	if (err) {
		return err;
	}
	*out_byte = (uint8_t)(nib[0] << 4 | nib[1]);
	return 0;
}

int voluta_blobid_from_name(struct voluta_blobid *blobid,
                            const char *name, size_t len)
{
	int err = 0;
	uint8_t *byte;
	const size_t oid_size = ARRAY_SIZE(blobid->oid);

	if (len < (2 * oid_size)) {
		return -EINVAL;
	}
	for (size_t i = 0; i < oid_size; ++i) {
		byte = &blobid->oid[i];
		err = ascii_to_byte(name[2 * i], name[(2 * i) + 1], byte);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_baddr s_baddr_none = {
	.len = 0,
	.off = 0,
};

const struct voluta_baddr *voluta_baddr_none(void)
{
	return &s_baddr_none;
}

void voluta_baddr_setup(struct voluta_baddr *baddr,
                        const struct voluta_blobid *bid,
                        size_t size, loff_t off)
{
	voluta_blobid_copyto(bid, &baddr->bid);
	baddr->len = size;
	baddr->off = blobid_off_within(bid, off);
}

void voluta_baddr_assign(struct voluta_baddr *baddr,
                         const struct voluta_blobid *bid)
{
	voluta_baddr_setup(baddr, bid, voluta_blobid_size(bid), 0);
}

void voluta_baddr_reset(struct voluta_baddr *baddr)
{
	memset(baddr->bid.oid, 0, sizeof(baddr->bid.oid));
	baddr->len = 0;
	baddr->off = 0;
}

void voluta_baddr_copyto(const struct voluta_baddr *baddr,
                         struct voluta_baddr *other)
{
	voluta_blobid_copyto(&baddr->bid, &other->bid);
	other->len = baddr->len;
	other->off = baddr->off;
}

bool voluta_baddr_isequal(const struct voluta_baddr *baddr,
                          const struct voluta_baddr *other)
{
	return (baddr->len == other->len) && (baddr->off == other->off) &&
	       voluta_blobid_isequal(&baddr->bid, &other->bid);
}

static void baddr_make(struct voluta_baddr *baddr, size_t size)
{
	blodid_make(&baddr->bid, size);
	baddr->len = size;
	baddr->off = 0;
}

static void baddr_make_for(struct voluta_baddr *baddr, enum voluta_vtype vtype)
{
	baddr_make(baddr, vtype_size(vtype));
}

void voluta_baddr_for_super(struct voluta_baddr *baddr)
{
	baddr_make_for(baddr, VOLUTA_VTYPE_SUPER);
}

static void baddr_for_hsmap(struct voluta_baddr *baddr)
{
	baddr_make_for(baddr, VOLUTA_VTYPE_HSMAP);
}

static void baddr_for_agmap(struct voluta_baddr *baddr)
{
	baddr_make_for(baddr, VOLUTA_VTYPE_HSMAP);
}

static void baddr_for_agbks(struct voluta_baddr *baddr)
{
	baddr_make(baddr, VOLUTA_AG_SIZE);
}

int voluta_baddr_parse_super(struct voluta_baddr *baddr, const char *name)
{
	int err;
	const size_t sb_size = VOLUTA_SB_SIZE;
	struct voluta_blobid *blobid = &baddr->bid;

	err = voluta_blobid_from_name(blobid, name, strlen(name));
	if (err) {
		return err;
	}
	blobid_set_size(blobid, sb_size);
	baddr->len = sb_size;
	baddr->off = 0;
	return 0;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vba_setup(struct voluta_vba *vba,
                      const struct voluta_vaddr *vaddr,
                      const struct voluta_baddr *baddr)
{
	voluta_vaddr_copyto(vaddr, &vba->vaddr);
	voluta_baddr_copyto(baddr, &vba->baddr);
}

void voluta_vba_reset(struct voluta_vba *vba)
{
	voluta_vaddr_reset(&vba->vaddr);
	voluta_baddr_reset(&vba->baddr);
}

void voluta_vba_copyto(const struct voluta_vba *vba, struct voluta_vba *other)
{
	voluta_vaddr_copyto(&vba->vaddr, &other->vaddr);
	voluta_baddr_copyto(&vba->baddr, &other->baddr);
}

void voluta_vba_for_hsmap(struct voluta_vba *vba, voluta_index_t hs_index)
{
	voluta_vaddr_of_hsmap(&vba->vaddr, hs_index);
	baddr_for_hsmap(&vba->baddr);
}

void voluta_vba_for_agmap(struct voluta_vba *vba, voluta_index_t ag_index)
{
	voluta_vaddr_of_agmap(&vba->vaddr, ag_index);
	baddr_for_agmap(&vba->baddr);
}

void voluta_vba_for_agbks(struct voluta_vba *vba, voluta_index_t ag_index)
{
	vaddr_of_agbks(&vba->vaddr, ag_index);
	baddr_for_agbks(&vba->baddr);
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_uuid_generate(struct voluta_uuid *uu)
{
	uuid_generate_random(uu->uu);
}

void voluta_uuid_copyto(const struct voluta_uuid *uu1, struct voluta_uuid *uu2)
{
	uuid_copy(uu2->uu, uu1->uu);
}

void voluta_uuid_name(const struct voluta_uuid *uu, struct voluta_namebuf *nb)
{
	char buf[40] = "";
	const char *s = buf;
	char *t = nb->name;

	uuid_unparse_lower(uu->uu, buf);
	while (*s != '\0') {
		if (isxdigit(*s)) {
			*t = *s;
		}
		t++;
		s++;
	}
	*t = '\0';
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_verify_ino(ino_t ino)
{
	return !ino_isnull(ino) ? 0 : -EFSCORRUPTED;
}

int voluta_verify_off(loff_t off)
{
	return (off_isnull(off) || (off >= 0)) ? 0 : -EFSCORRUPTED;
}

