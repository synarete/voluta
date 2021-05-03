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

static voluta_index_t hs_to_ag_index(voluta_index_t hs_index)
{
	return hs_index * VOLUTA_NAG_IN_HS;
}

static size_t ag_index_mapping_slot(voluta_index_t ag_index)
{
	return ag_index % VOLUTA_NAG_IN_HS;
}

static voluta_index_t ag_index_to_agm_ag_index(voluta_index_t ag_index)
{
	const voluta_index_t hs_index = ag_to_hs_index(ag_index);
	const voluta_index_t agm_ag_index = hs_to_ag_index(hs_index);

	return agm_ag_index;
}

static voluta_lba_t ag_index_to_agm_lba(voluta_index_t ag_index)
{
	const size_t ag_index_slot = ag_index_mapping_slot(ag_index);
	const voluta_index_t agm_ag_index = ag_index_to_agm_ag_index(ag_index);

	return lba_within_ag(agm_ag_index, ag_index_slot);
}

voluta_lba_t voluta_lba_by_ag(voluta_index_t ag_index, size_t bn)
{
	return lba_within_ag(ag_index, bn);
}

static voluta_lba_t hsm_lba_by_index(voluta_index_t hs_index)
{
	const voluta_lba_t hsm_lba = (voluta_lba_t)(VOLUTA_LBA_SB + hs_index);

	voluta_assert_gt(hs_index, 0);
	voluta_assert_lt(hsm_lba, VOLUTA_NBK_IN_HS);

	return hsm_lba;
}

voluta_index_t voluta_hs_index_of_ag(voluta_index_t ag_index)
{
	return ag_to_hs_index(ag_index);
}

voluta_index_t voluta_ag_index_by_hs(voluta_index_t hs_index, size_t ag_slot)
{
	return hs_to_ag_index(hs_index) + ag_slot;
}

size_t voluta_ag_index_to_hs_slot(voluta_index_t ag_index)
{
	return ag_index_mapping_slot(ag_index);
}

voluta_index_t voluta_agm_index_of_ag(voluta_index_t ag_index)
{
	return ag_index_to_agm_ag_index(ag_index);
}

bool voluta_ag_index_isumap(voluta_index_t ag_index)
{
	voluta_index_t hs_index;
	voluta_index_t agm_ag_index;

	hs_index = ag_to_hs_index(ag_index);
	if (hs_index < 1) {
		return true;
	}
	agm_ag_index = hs_to_ag_index(hs_index);
	if (ag_index == agm_ag_index) {
		return true;
	}
	return false;
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

voluta_index_t voluta_vaddr_ag_index(const struct voluta_vaddr *vaddr)
{
	return vaddr->ag_index;
}

voluta_index_t voluta_vaddr_hs_index(const struct voluta_vaddr *vaddr)
{
	return vaddr->hs_index;
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
	return voluta_vtype_isumap(vaddr->vtype);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vaddr_of_hsmap(struct voluta_vaddr *vaddr, voluta_index_t hs_index)
{
	const voluta_lba_t lba = hsm_lba_by_index(hs_index);

	voluta_assert_gt(hs_index, 0);

	vaddr_setup(vaddr, VOLUTA_VTYPE_HSMAP, lba_to_off(lba));
}

void voluta_vaddr_of_agmap(struct voluta_vaddr *vaddr, voluta_index_t ag_index)
{
	const voluta_lba_t lba = ag_index_to_agm_lba(ag_index);

	voluta_assert_gt(ag_index, VOLUTA_NAG_IN_HS);
	voluta_assert_ne(ag_index % VOLUTA_NAG_IN_HS, 0);

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


