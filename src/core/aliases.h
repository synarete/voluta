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
#ifndef VOLUTA_ALIASES_H_
#define VOLUTA_ALIASES_H_

#ifndef VOLUTA_LIBPRIVATE
#error "internal library header -- do not include!"
#endif

#include <unistd.h>
#include <errno.h>


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
#define baddr_copyto(ba1, ba2)          voluta_baddr_copyto(ba1, ba2)

#define vi_refcnt(vi)                   voluta_vi_refcnt(vi)
#define vi_incref(vi)                   voluta_vi_incref(vi)
#define vi_decref(vi)                   voluta_vi_decref(vi)
#define vi_dirtify(vi)                  voluta_vi_dirtify(vi)
#define vi_undirtify(vi)                voluta_vi_undirtify(vi)
#define vi_isdata(vi)                   voluta_vi_isdata(vi)
#define vi_dat_of(vi)                   voluta_vi_dat_of(vi)
#define ii_refcnt(ii)                   vi_refcnt(ii_vi(ii))
#define ii_incref(ii)                   vi_incref(ii_vi(ii))
#define ii_decref(ii)                   vi_decref(ii_vi(ii))
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

#endif /* VOLUTA_ALIASES_H_ */

