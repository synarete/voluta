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
#ifndef VOLUTA_ADDRESS_H_
#define VOLUTA_ADDRESS_H_

#include <stdint.h>
#include <endian.h>
#include <voluta/fs/types.h>

/* non-valid ("NIL") allocation-group index */
#define VOLUTA_AG_INDEX_NULL            (0UL - 1)
#define VOLUTA_HS_INDEX_NULL            (0UL - 1)


/* address */
voluta_index_t voluta_hs_index_of_ag(voluta_index_t ag_index);

voluta_index_t voluta_ag_index_by_hs(voluta_index_t hs_index, size_t ag_slot);

loff_t voluta_off_in_blob(loff_t off, size_t blob_size);


bool voluta_vtype_isspmap(enum voluta_vtype vtype);

bool voluta_vtype_isdata(enum voluta_vtype vtype);

bool voluta_vtype_ismeta(enum voluta_vtype vtype);

size_t voluta_vtype_size(enum voluta_vtype vtype);

ssize_t voluta_vtype_ssize(enum voluta_vtype vtype);

size_t voluta_vtype_nkbs(enum voluta_vtype vtype);

enum voluta_agkind voluta_vtype_to_agkind(enum voluta_vtype vtype);


const struct voluta_vaddr *voluta_vaddr_none(void);

void voluta_vaddr_copyto(const struct voluta_vaddr *vaddr,
                         struct voluta_vaddr *other);

void voluta_vaddr_setup(struct voluta_vaddr *vaddr,
                        enum voluta_vtype vtype, loff_t off);

void voluta_vaddr_reset(struct voluta_vaddr *vaddr);

bool voluta_vaddr_isnull(const struct voluta_vaddr *vaddr);

bool voluta_vaddr_isdata(const struct voluta_vaddr *vaddr);

bool voluta_vaddr_isspmap(const struct voluta_vaddr *vaddr);


void voluta_vaddr_by_ag(struct voluta_vaddr *vaddr, enum voluta_vtype vtype,
                        voluta_index_t ag_index, size_t bn, size_t kbn);


void voluta_vaddr56_set(struct voluta_vaddr56 *va, loff_t off);

loff_t voluta_vaddr56_parse(const struct voluta_vaddr56 *va);

void voluta_vaddr64_set(struct voluta_vaddr64 *va,
                        const struct voluta_vaddr *vaddr);

void voluta_vaddr64_parse(const struct voluta_vaddr64 *va,
                          struct voluta_vaddr *vaddr);


size_t voluta_blobid_size(const struct voluta_blobid *blobid);

void voluta_blobid_reset(struct voluta_blobid *blobid);

void voluta_blobid_copyto(const struct voluta_blobid *blobid,
                          struct voluta_blobid *other);

bool voluta_blobid_isequal(const struct voluta_blobid *blobid,
                           const struct voluta_blobid *other);

uint64_t voluta_blobid_hkey(const struct voluta_blobid *blobid);

int voluta_blobid_to_name(const struct voluta_blobid *blobid,
                          char *name, size_t nmax, size_t *out_len);

int voluta_blobid_from_name(struct voluta_blobid *blobid,
                            const char *name, size_t len);

void voluta_blobid_for_agbks(struct voluta_blobid *blobid);


const struct voluta_baddr *voluta_baddr_none(void);

void voluta_baddr_setup(struct voluta_baddr *baddr,
                        const struct voluta_blobid *bid,
                        size_t len, loff_t off);

void voluta_baddr_assign(struct voluta_baddr *baddr,
                         const struct voluta_blobid *bid);

void voluta_baddr_reset(struct voluta_baddr *baddr);

void voluta_baddr_copyto(const struct voluta_baddr *baddr,
                         struct voluta_baddr *other);

bool voluta_baddr_isequal(const struct voluta_baddr *baddr,
                          const struct voluta_baddr *other);


int voluta_baddr_parse_super(struct voluta_baddr *baddr, const char *name);



void voluta_vba_setup(struct voluta_vba *vba,
                      const struct voluta_vaddr *vaddr,
                      const struct voluta_baddr *baddr);

void voluta_vba_setup_by(struct voluta_vba *vba,
                         const struct voluta_vaddr *vaddr,
                         const struct voluta_blobid *bid);

void voluta_vba_reset(struct voluta_vba *vba);

void voluta_vba_copyto(const struct voluta_vba *vba, struct voluta_vba *other);

void voluta_vba_for_super(struct voluta_vba *vba);

void voluta_vba_for_hsmap(struct voluta_vba *vba, voluta_index_t hs_index);

void voluta_vba_for_agmap(struct voluta_vba *vba, voluta_index_t ag_index);

void voluta_vba_to_bksec_baddr(const struct voluta_vba *vba,
                               struct voluta_baddr *baddr);


const struct voluta_uaddr *voluta_uaddr_none(void);

void voluta_uaddr_setup(struct voluta_uaddr *uaddr,
                        enum voluta_utype utype, loff_t off);

void voluta_uaddr_copyto(const struct voluta_uaddr *uaddr,
                         struct voluta_uaddr *other);

void voluta_uaddr_reset(struct voluta_uaddr *uaddr);

bool voluta_uaddr_isnull(const struct voluta_uaddr *uaddr);


void voluta_uba_setup(struct voluta_uba *uba,
                      const struct voluta_uaddr *uaddr,
                      const struct voluta_baddr *baddr);

void voluta_uba_setup_by(struct voluta_uba *uba,
                         const struct voluta_uaddr *uaddr,
                         const struct voluta_blobid *bid);

void voluta_uba_reset(struct voluta_uba *uba);

void voluta_uba_copyto(const struct voluta_uba *uba, struct voluta_uba *other);


void voluta_uuid_generate(struct voluta_uuid *uu);

void voluta_uuid_copyto(const struct voluta_uuid *u1, struct voluta_uuid *u2);

void voluta_uuid_name(const struct voluta_uuid *uu, struct voluta_namebuf *nb);


int voluta_check_volume_size(loff_t size);

int voluta_check_address_space(loff_t size);

int voluta_calc_volume_space(loff_t volume_size, loff_t *out_capacity_size);


int voluta_verify_ino(ino_t ino);

int voluta_verify_off(loff_t off);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline uint16_t voluta_cpu_to_le16(uint16_t n)
{
	return htole16(n);
}

static inline uint16_t voluta_le16_to_cpu(uint16_t n)
{
	return le16toh(n);
}

static inline uint32_t voluta_cpu_to_le32(uint32_t n)
{
	return htole32(n);
}

static inline uint32_t voluta_le32_to_cpu(uint32_t n)
{
	return le32toh(n);
}

static inline uint64_t voluta_cpu_to_le64(uint64_t n)
{
	return htole64(n);
}

static inline uint64_t voluta_le64_to_cpu(uint64_t n)
{
	return le64toh(n);
}

static inline uint64_t voluta_cpu_to_ino(ino_t ino)
{
	return voluta_cpu_to_le64(ino);
}

static inline ino_t voluta_ino_to_cpu(uint64_t ino)
{
	return (ino_t)voluta_le64_to_cpu(ino);
}

static inline int64_t voluta_cpu_to_off(loff_t off)
{
	return (int64_t)voluta_cpu_to_le64((uint64_t)off);
}

static inline loff_t voluta_off_to_cpu(int64_t off)
{
	return (loff_t)voluta_le64_to_cpu((uint64_t)off);
}

#endif /* VOLUTA_ADDRESS_H_ */
