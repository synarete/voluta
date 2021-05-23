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
#ifndef VOLUTA_PRIVATE_H_
#define VOLUTA_PRIVATE_H_

#ifndef VOLUTA_LIBPRIVATE
#error "internal library header -- do not include!"
#endif

#include <voluta/infra.h>
#include <voluta/defs.h>
#include <voluta/fs/types.h>


/* error-codes borrowed from XFS */
#ifndef ENOATTR
#define ENOATTR         ENODATA /* Attribute not found */
#endif
#ifndef EFSCORRUPTED
#define EFSCORRUPTED    EUCLEAN /* File-system is corrupted */
#endif
#ifndef EFSBADCRC
#define EFSBADCRC       EBADMSG /* Bad CRC detected */
#endif

/* common macros */
#define likely(x_)                      voluta_likely(x_)
#define unlikely(x_)                    voluta_unlikely(x_)

#define STATICASSERT(expr_)             VOLUTA_STATICASSERT(expr_)
#define STATICASSERT_EQ(a_, b_)         VOLUTA_STATICASSERT_EQ(a_, b_)
#define STATICASSERT_LT(a_, b_)         VOLUTA_STATICASSERT_LT(a_, b_)
#define STATICASSERT_LE(a_, b_)         VOLUTA_STATICASSERT_LE(a_, b_)
#define STATICASSERT_GT(a_, b_)         VOLUTA_STATICASSERT_GT(a_, b_)
#define STATICASSERT_SIZEOF(t_, s_)     VOLUTA_STATICASSERT_EQ(sizeof(t_), s_)

/* aliases */
#define ARRAY_SIZE(x)                   VOLUTA_ARRAY_SIZE(x)
#define container_of(p, t, m)           voluta_container_of(p, t, m)
#define container_of2(p, t, m)          voluta_container_of2(p, t, m)
#define unconst(p)                      voluta_unconst(p)
#define unused(x)                       voluta_unused(x)

#define min(x, y)                       voluta_min(x, y)
#define min3(x, y, z)                   voluta_min3(x, y, z)
#define max(x, y)                       voluta_max(x, y)
#define clamp(x, y, z)                  voluta_clamp(x, y, z)
#define div_round_up(n, d)              voluta_div_round_up(n, d)

#define log_dbg(fmt, ...)               voluta_log_debug(fmt, __VA_ARGS__)
#define log_info(fmt, ...)              voluta_log_info(fmt, __VA_ARGS__)
#define log_warn(fmt, ...)              voluta_log_warn(fmt, __VA_ARGS__)
#define log_err(fmt, ...)               voluta_log_error(fmt, __VA_ARGS__)
#define log_crit(fmt, ...)              voluta_log_crit(fmt, __VA_ARGS__)

#define vtype_nkbs(vt)                  voluta_vtype_nkbs(vt)
#define vtype_size(vt)                  voluta_vtype_size(vt)
#define vtype_ssize(vt)                 voluta_vtype_ssize(vt)
#define vtype_isdata(vt)                voluta_vtype_isdata(vt)

#define vaddr_none()                    voluta_vaddr_none()
#define vaddr_isnull(va)                voluta_vaddr_isnull(va)
#define vaddr_isdata(va)                voluta_vaddr_isdata(va)
#define vaddr_isspmap(va)               voluta_vaddr_isspmap(va)
#define vaddr_reset(va)                 voluta_vaddr_reset(va)
#define vaddr_copyto(va1, va2)          voluta_vaddr_copyto(va1, va2)
#define vaddr_ag_index(va)              voluta_vaddr_ag_index(va)
#define vaddr_hs_index(va)              voluta_vaddr_hs_index(va)
#define vaddr_setup(va, t, o)           voluta_vaddr_setup(va, t, o)
#define vaddr_by_ag(va, t, ag, bn, k)   voluta_vaddr_by_ag(va, t, ag, bn, k)

#define baddr_reset(ba)                 voluta_baddr_reset(ba)
#define baddr_create(ba, sz)            voluta_baddr_create(ba, sz)
#define baddr_copyto(ba1, ba2)          voluta_baddr_copyto(ba1, ba2)

#define vi_refcnt(vi)                   voluta_vi_refcnt(vi)
#define vi_incref(vi)                   voluta_vi_incref(vi)
#define vi_decref(vi)                   voluta_vi_decref(vi)
#define vi_dirtify(vi)                  voluta_vi_dirtify(vi)
#define vi_undirtify(vi)                voluta_vi_undirtify(vi)
#define vi_isdata(vi)                   voluta_vi_isdata(vi)
#define vi_dat_of(vi)                   voluta_vi_dat_of(vi)
#define ii_refcnt(ii)                   voluta_ii_refcnt(ii)
#define ii_incref(ii)                   voluta_ii_incref(ii)
#define ii_decref(ii)                   voluta_ii_decref(ii)
#define ii_dirtify(ii)                  voluta_ii_dirtify(ii)
#define ii_undirtify(ii)                voluta_ii_undirtify(ii)
#define ii_isrdonly(ii)                 voluta_ii_isrdonly(ii)
#define ii_xino(ii)                     voluta_ii_xino(ii)
#define ii_parent(ii)                   voluta_ii_parent(ii)
#define ii_uid(ii)                      voluta_ii_uid(ii)
#define ii_gid(ii)                      voluta_ii_gid(ii)
#define ii_mode(ii)                     voluta_ii_mode(ii)
#define ii_nlink(ii)                    voluta_ii_nlink(ii)
#define ii_size(ii)                     voluta_ii_size(ii)
#define ii_span(ii)                     voluta_ii_span(ii)
#define ii_blocks(ii)                   voluta_ii_blocks(ii)
#define ii_isrootd(ii)                  voluta_ii_isrootd(ii)
#define ii_isdir(ii)                    voluta_ii_isdir(ii)
#define ii_isreg(ii)                    voluta_ii_isreg(ii)
#define ii_islnk(ii)                    voluta_ii_islnk(ii)
#define ii_isfifo(ii)                   voluta_ii_isfifo(ii)
#define ii_issock(ii)                   voluta_ii_issock(ii)
#define ii_isevictable(ii)              voluta_ii_isevictable(ii)
#define bli_incref(bli)                 voluta_bli_incref(bli)
#define bli_decref(bli)                 voluta_bli_decref(bli)

#define ts_copy(dst, src)               voluta_ts_copy(dst, src)
#define iattr_setup(ia, ino)            voluta_iattr_setup(ia, ino)
#define update_itimes(op, ii, f)        voluta_update_itimes(op, ii, f)
#define update_iattrs(op, ii, a)        voluta_update_iattrs(op, ii, a)
#define update_isize(op, ii, sz)        voluta_update_isize(op, ii, sz)
#define update_iblocks(op, ii, vt, d)   voluta_update_iblocks(op, ii, vt, d)

#define list_head_init(lh)              voluta_list_head_init(lh)
#define list_head_initn(lh, n)          voluta_list_head_initn(lh, n)
#define list_head_fini(lh)              voluta_list_head_fini(lh)
#define list_head_finin(lh, n)          voluta_list_head_finin(lh, n)
#define list_head_remove(lh)            voluta_list_head_remove(lh)
#define list_head_insert_after(p, q)    voluta_list_head_insert_after(p, q)
#define list_head_insert_before(p, q)   voluta_list_head_insert_before(p, q)

#define list_init(ls)                   voluta_list_init(ls)
#define list_fini(ls)                   voluta_list_fini(ls)
#define list_isempty(ls)                voluta_list_isempty(ls)
#define list_push_back(ls, lh)          voluta_list_push_back(ls, lh)
#define list_push_front(ls, lh)         voluta_list_push_front(ls, lh)
#define list_pop_front(ls)              voluta_list_pop_front(ls)
#define list_front(ls)                  voluta_list_front(ls)

#define listq_init(lq)                  voluta_listq_init(lq)
#define listq_initn(lq, n)              voluta_listq_initn(lq, n)
#define listq_fini(lq)                  voluta_listq_fini(lq)
#define listq_finin(lq, n)              voluta_listq_finin(lq, n)
#define listq_isempty(lq)               voluta_listq_isempty(lq)
#define listq_push_back(lq, lh)         voluta_listq_push_back(lq, lh)
#define listq_push_front(lq, lh)        voluta_listq_push_front(lq, lh)
#define listq_pop_front(lq)             voluta_listq_pop_front(lq)
#define listq_remove(lq, lh)            voluta_listq_remove(lq, lh)
#define listq_front(lq)                 voluta_listq_front(lq)
#define listq_back(lq)                  voluta_listq_back(lq)
#define listq_next(lq, lh)              voluta_listq_next(lq, lh)
#define listq_prev(lq, lh)              voluta_listq_prev(lq, lh)

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/


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

static inline struct voluta_sb_info *
vi_sbi(const struct voluta_vnode_info *vi)
{
	return vi->v_sbi;
}

static inline struct voluta_cache *
vi_cache(const struct voluta_vnode_info *vi)
{
	return vi_sbi(vi)->sb_cache;
}

static inline const struct voluta_mdigest *
vi_mdigest(const struct voluta_vnode_info *vi)
{
	return &vi->v_sbi->sb_vstore->vs_crypto.md;
}


static inline struct voluta_vnode_info *
hsi_vi(const struct voluta_hspace_info *hsi)
{
	return voluta_likely(hsi != NULL) ?
	       voluta_unconst(&hsi->hs_vi) : NULL;
}

static inline struct voluta_vnode_info *
agi_vi(const struct voluta_agroup_info *agi)
{
	return voluta_likely(agi != NULL) ?
	       voluta_unconst(&agi->ag_vi) : NULL;
}

static inline struct voluta_vnode_info *
ii_vi(const struct voluta_inode_info *ii)
{
	return voluta_likely(ii != NULL) ?
	       voluta_unconst(&ii->i_vi) : NULL;
}

static inline ino_t ii_ino(const struct voluta_inode_info *ii)
{
	return ii->i_ino;
}

static inline const struct voluta_vaddr *
ii_vaddr(const struct voluta_inode_info *ii)
{
	return vi_vaddr(ii_vi(ii));
}

static inline struct voluta_bksec_info *
ii_bsi(const struct voluta_inode_info *ii)
{
	return ii_vi(ii)->v_bsi;
}

static inline struct voluta_sb_info *
ii_sbi(const struct voluta_inode_info *ii)
{
	return vi_sbi(ii_vi(ii));
}

#endif /* VOLUTA_PRIVATE_H_ */
