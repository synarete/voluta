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
#ifndef VOLUTA_INLINES_H_
#define VOLUTA_INLINES_H_

#ifndef VOLUTA_LIBPRIVATE
#error "internal library header -- do not include!"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <voluta/defs.h>
#include <voluta/infra.h>
#include <voluta/types.h>


static inline int min_int(int x, int y)
{
	return (x < y) ? x : y;
}

static inline size_t min(size_t x, size_t y)
{
	return (x < y) ? x : y;
}

static inline size_t min3(size_t x, size_t y, size_t z)
{
	return min(min(x, y), z);
}

static inline size_t max(size_t x, size_t y)
{
	return (x > y) ? x : y;
}

static inline long lmax(long x, long y)
{
	return (x > y) ? x : y;
}

static inline size_t clamp(size_t v, size_t lo, size_t hi)
{
	return min(max(v, lo), hi);
}

static inline size_t div_round_up(size_t n, size_t d)
{
	return (n + d - 1) / d;
}


static inline bool ino_isnull(ino_t ino)
{
	return (ino == VOLUTA_INO_NULL);
}


static inline bool off_isnull(loff_t off)
{
	return (off >= VOLUTA_OFF_NULL) || (off < 0);
}

static inline loff_t off_min(loff_t off1, loff_t off2)
{
	return (off1 < off2) ? off1 : off2;
}

static inline loff_t off_max(loff_t off1, loff_t off2)
{
	return (off1 > off2) ? off1 : off2;
}

static inline loff_t off_max_min(loff_t off1, loff_t off2, loff_t off3)
{
	return off_min(off_max(off1, off2), off3);
}

static inline loff_t off_end(loff_t off, size_t len)
{
	return off + (loff_t)len;
}

static inline loff_t off_align(loff_t off, ssize_t align)
{
	return (off / align) * align;
}

static inline loff_t off_next(loff_t off, ssize_t len)
{
	return off_align(off + len, len);
}

static inline loff_t off_to_lba(loff_t off)
{
	return off / VOLUTA_BK_SIZE;
}

static inline ssize_t off_diff(loff_t beg, loff_t end)
{
	return end - beg;
}

static inline ssize_t off_len(loff_t beg, loff_t end)
{
	return off_diff(beg, end);
}

static inline size_t off_ulen(loff_t beg, loff_t end)
{
	return (size_t)off_len(beg, end);
}


static inline bool lba_isequal(voluta_lba_t lba1, voluta_lba_t lba2)
{
	return (lba1 == lba2);
}

static inline bool lba_isnull(voluta_lba_t lba)
{
	return lba_isequal(lba, VOLUTA_LBA_NULL);
}

static inline voluta_lba_t lba_to_off(voluta_lba_t lba)
{
	return lba * (voluta_lba_t)VOLUTA_BK_SIZE;
}


static inline loff_t ag_index_to_off(voluta_index_t ag_index)
{
	return (loff_t)(ag_index * VOLUTA_AG_SIZE);
}

static inline size_t nbytes_to_ag_count(loff_t nbytes)
{
	return (size_t)nbytes / VOLUTA_AG_SIZE;
}

static inline loff_t ag_count_to_nbytes(size_t nags)
{
	return (loff_t)nags * VOLUTA_AG_SIZE;
}


static inline bool uid_eq(uid_t uid1, uid_t uid2)
{
	return (uid1 == uid2);
}

static inline bool gid_eq(gid_t gid1, gid_t gid2)
{
	return (gid1 == gid2);
}

static inline bool uid_isroot(uid_t uid)
{
	return uid_eq(uid, 0);
}


static inline bool capable_fsetid(const struct voluta_ucred *ucred)
{
	/* TODO: CAP_SYS_ADMIN */
	return uid_isroot(ucred->uid);
}

static inline bool capable_chown(const struct voluta_ucred *ucred)
{
	/* TODO: CAP_CHOWN */
	return uid_isroot(ucred->uid);
}

static inline bool capable_fowner(const struct voluta_ucred *ucred)
{
	/* TODO: CAP_FOWNER */
	return uid_isroot(ucred->uid);
}

static inline bool capable_sys_admin(const struct voluta_ucred *ucred)
{
	/* TODO: CAP_SYS_ADMIN */
	return uid_isroot(ucred->uid);
}


static inline bool vtype_isequal(enum voluta_vtype vt1, enum voluta_vtype vt2)
{
	return (vt1 == vt2);
}

static inline bool vtype_isnone(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_NONE);
}

static inline bool vtype_ishsmap(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_HSMAP);
}

static inline bool vtype_isagmap(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_AGMAP);
}

static inline bool vtype_isinode(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_INODE);
}


static inline
const struct voluta_vaddr *vi_vaddr(const struct voluta_vnode_info *vi)
{
	return &vi->vaddr;
}

static inline enum voluta_vtype vi_vtype(const struct voluta_vnode_info *vi)
{
	return (vi != NULL) ? vi_vaddr(vi)->vtype : VOLUTA_VTYPE_NONE;
}

static inline size_t vi_length(const struct voluta_vnode_info *vi)
{
	return vi_vaddr(vi)->len;
}

static inline loff_t vi_offset(const struct voluta_vnode_info *vi)
{
	return vi_vaddr(vi)->off;
}

static inline
struct voluta_sb_info *vi_sbi(const struct voluta_vnode_info *vi)
{
	return vi->v_sbi;
}

static inline
struct voluta_cache *vi_cache(const struct voluta_vnode_info *vi)
{
	return vi_sbi(vi)->sb_cache;
}

static inline
const struct voluta_mdigest *vi_mdigest(const struct voluta_vnode_info *vi)
{
	return &vi->v_sbi->sb_vstore->vs_crypto.md;
}

static inline
struct voluta_vnode_info *ii_vi(const struct voluta_inode_info *ii)
{
	return (ii != NULL) ? unconst(&ii->i_vi) : NULL;
}

static inline ino_t ii_ino(const struct voluta_inode_info *ii)
{
	return ii->i_ino;
}

static inline
const struct voluta_vaddr *ii_vaddr(const struct voluta_inode_info *ii)
{
	return vi_vaddr(ii_vi(ii));
}

static inline
struct voluta_bk_info *ii_bki(const struct voluta_inode_info *ii)
{
	return ii_vi(ii)->v_bki;
}

static inline
struct voluta_sb_info *ii_sbi(const struct voluta_inode_info *ii)
{
	return vi_sbi(ii_vi(ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static inline uint16_t cpu_to_le16(uint16_t n)
{
	return htole16(n);
}

static inline uint16_t le16_to_cpu(uint16_t n)
{
	return le16toh(n);
}

static inline uint32_t cpu_to_le32(uint32_t n)
{
	return htole32(n);
}

static inline uint32_t le32_to_cpu(uint32_t n)
{
	return le32toh(n);
}

static inline uint64_t cpu_to_le64(uint64_t n)
{
	return htole64(n);
}

static inline uint64_t le64_to_cpu(uint64_t n)
{
	return le64toh(n);
}

static inline uint64_t cpu_to_ino(ino_t ino)
{
	return cpu_to_le64(ino);
}

static inline ino_t ino_to_cpu(uint64_t ino)
{
	return (ino_t)le64_to_cpu(ino);
}

static inline int64_t cpu_to_off(loff_t off)
{
	return (int64_t)cpu_to_le64((uint64_t)off);
}

static inline loff_t off_to_cpu(int64_t off)
{
	return (loff_t)le64_to_cpu((uint64_t)off);
}


#endif /* VOLUTA_INLINES_H_ */

