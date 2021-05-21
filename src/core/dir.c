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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <voluta/core/cache.h>
#include <voluta/core/private.h>

#include "libvoluta.h"


#define HTREE_FANOUT            VOLUTA_DIR_HTNODE_NCHILDS
#define HTREE_DEPTH_MAX         VOLUTA_DIR_HTREE_DEPTH_MAX
#define HTREE_INDEX_MAX         VOLUTA_DIR_HTREE_INDEX_MAX
#define HTREE_INDEX_NULL        VOLUTA_DIR_HTREE_INDEX_NULL
#define HTREE_INDEX_ROOT        0


/*
 * TODO-0006: Support VOLUTA_NAME_MAX=1023
 *
 * While 255 is de-facto standard for modern file-systems, long term vision
 * should allow more (think non-ascii with long UTF8 encoding).
 */
struct voluta_dir_entry_view {
	struct voluta_dir_entry de;
	uint8_t de_name[VOLUTA_NAME_MAX + 1];
} voluta_packed_aligned8;

struct voluta_dir_entry_info {
	struct voluta_vnode_info *vi;
	struct voluta_dir_entry  *de;
	struct voluta_ino_dt  ino_dt;
};

struct voluta_dir_ctx {
	struct voluta_sb_info     *sbi;
	const struct voluta_oper *op;
	struct voluta_inode_info  *dir_ii;
	struct voluta_inode_info  *parent_ii;
	struct voluta_inode_info  *child_ii;
	struct voluta_readdir_ctx *rd_ctx;
	const struct voluta_qstr  *name;
	int keep_iter;
	int readdir_plus;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ino_isvalid(ino_t ino)
{
	/* TODO: Check ino max */
	return (ino > VOLUTA_INO_NULL);
}

static mode_t dttoif(mode_t dt)
{
	mode_t mode;

	switch (dt) {
	case DT_UNKNOWN:
	case DT_FIFO:
	case DT_CHR:
	case DT_DIR:
	case DT_BLK:
	case DT_REG:
	case DT_LNK:
	case DT_SOCK:
	case DT_WHT:
		mode = DTTOIF(dt);
		break;
	default:
		mode = 0;
		break;
	}
	return mode;
}

static void vaddr_of_htnode(struct voluta_vaddr *vaddr, loff_t off)
{
	vaddr_setup(vaddr, VOLUTA_VTYPE_HTNODE, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static bool index_isnull(size_t index)
{
	return (index == HTREE_INDEX_NULL);
}

static bool index_isvalid(size_t index)
{
	VOLUTA_STATICASSERT_GT(HTREE_INDEX_NULL, VOLUTA_DIR_HTREE_INDEX_MAX);

	return (index < HTREE_INDEX_MAX);
}

static size_t index_to_parent(size_t index)
{
	return (index - 1) / HTREE_FANOUT;
}

static size_t index_to_child_ord(size_t index)
{
	const size_t parent_index = index_to_parent(index);

	return (index - (parent_index * HTREE_FANOUT) - 1);
}

static size_t parent_to_child_index(size_t parent_index, size_t child_ord)
{
	return (parent_index * HTREE_FANOUT) + child_ord + 1;
}

static size_t index_to_depth(size_t index)
{
	size_t depth = 0;

	/* TODO: use shift operations */
	while (index > 0) {
		depth++;
		index = index_to_parent(index);
	}
	return depth;
}

static bool depth_isvalid(size_t depth)
{
	return (depth <= HTREE_DEPTH_MAX);
}

static bool index_valid_depth(size_t index)
{
	return index_isvalid(index) && depth_isvalid(index_to_depth(index));
}

static size_t hash_to_child_ord(uint64_t hash, size_t depth)
{
	voluta_assert_gt(depth, 0);
	voluta_assert_lt(depth, sizeof(hash));
	voluta_assert_le(depth, HTREE_DEPTH_MAX);

	return (hash >> (8 * (depth - 1))) % HTREE_FANOUT;
}

static size_t hash_to_child_index(uint64_t hash, size_t parent_index)
{
	const size_t depth = index_to_depth(parent_index);
	const size_t child_ord = hash_to_child_ord(hash, depth + 1);

	return parent_to_child_index(parent_index, child_ord);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define DOFF_SHIFT 13

static loff_t make_doffset(size_t node_index, size_t sloti)
{
	STATICASSERT_LT(VOLUTA_DIR_HTNODE_NENTS, 1 << 10);
	STATICASSERT_EQ(VOLUTA_DIR_HTNODE_SIZE, 1 << DOFF_SHIFT);

	return (loff_t)((node_index << DOFF_SHIFT) | (sloti << 2) | 3);
}

static size_t doffset_to_index(loff_t doff)
{
	const loff_t doff_mask = (1L << DOFF_SHIFT) - 1;

	STATICASSERT_EQ(HTREE_INDEX_ROOT, 0);

	return (size_t)((doff >> DOFF_SHIFT) & doff_mask);
}

static loff_t calc_d_isize(size_t last_index)
{
	loff_t dir_isize;

	if (index_isnull(last_index)) {
		dir_isize = VOLUTA_DIR_EMPTY_SIZE;
	} else {
		dir_isize = make_doffset(last_index + 1, 0) & ~3;
	}
	return dir_isize;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_dir_entry_view *
de_view_of(const struct voluta_dir_entry *de)
{
	const struct voluta_dir_entry_view *de_view;

	de_view = container_of2(de, struct voluta_dir_entry_view, de);
	return unconst(de_view);
}

static struct voluta_dir_entry *de_unconst(const struct voluta_dir_entry *de)
{
	union {
		const struct voluta_dir_entry *p;
		struct voluta_dir_entry *q;
	} u = {
		.p = de
	};
	return u.q;
}

static mode_t de_dt(const struct voluta_dir_entry *de)
{
	return de->de_dt;
}

static void de_set_dt(struct voluta_dir_entry *de, mode_t dt)
{
	de->de_dt = (uint8_t)dt;
}

static bool de_isvalid(const struct voluta_dir_entry *de)
{
	return (dttoif(de_dt(de)) != 0);
}

static ino_t de_ino(const struct voluta_dir_entry *de)
{
	return voluta_ino_to_cpu(de->de_ino);
}

static void de_set_ino(struct voluta_dir_entry *de, ino_t ino)
{
	de->de_ino = voluta_cpu_to_ino(ino);
}

static void de_set_ino_dt(struct voluta_dir_entry *de, ino_t ino, mode_t dt)
{
	de_set_ino(de, ino);
	de_set_dt(de, dt);
}

static size_t de_name_len(const struct voluta_dir_entry *de)
{
	return voluta_le16_to_cpu(de->de_name_len);
}

static void de_set_name_len(struct voluta_dir_entry *de, size_t nlen)
{
	de->de_name_len = voluta_cpu_to_le16((uint16_t)nlen);
}

static bool de_isactive(const struct voluta_dir_entry *de)
{
	return (de_name_len(de) > 0) && ino_isvalid(de_ino(de));
}

static const char *de_name(const struct voluta_dir_entry *de)
{
	const struct voluta_dir_entry_view *de_view = de_view_of(de);

	return (const char *)(de_view->de_name);
}

static bool de_has_name_len(const struct voluta_dir_entry *de, size_t nlen)
{
	return (de_name_len(de) == nlen);
}

static bool de_has_name(const struct voluta_dir_entry *de,
                        const struct voluta_str *name)
{
	bool ret = false;

	if (de_isactive(de) && de_has_name_len(de, name->len)) {
		ret = !memcmp(de_name(de), name->str, name->len);
	}
	return ret;
}

static size_t de_nents_for_name(const struct voluta_dir_entry *de, size_t nlen)
{
	const size_t de_size = sizeof(*de);
	const size_t name_ndes = (nlen + de_size - 1) / de_size;

	return 1 + name_ndes;
}

static size_t de_nents(const struct voluta_dir_entry *de)
{
	return voluta_le16_to_cpu(de->de_nents);
}

static void de_set_nents(struct voluta_dir_entry *de, size_t nents)
{
	de->de_nents = voluta_cpu_to_le16((uint16_t)nents);
}

static size_t de_nprev(const struct voluta_dir_entry *de)
{
	return voluta_le16_to_cpu(de->de_nprev);
}

static void de_set_nprev(struct voluta_dir_entry *de, size_t nprev)
{
	de->de_nprev = voluta_cpu_to_le16((uint16_t)nprev);
}

static struct voluta_dir_entry *de_next(const struct voluta_dir_entry *de)
{
	const size_t step = de_nents(de);

	return de_unconst(de + step);
}

static struct voluta_dir_entry *
de_next_safe(const struct voluta_dir_entry *de,
             const struct voluta_dir_entry *end)
{
	const struct voluta_dir_entry *next = de_next(de);

	return (next < end) ? de_unconst(next) : NULL;
}

static struct voluta_dir_entry *
de_prev_safe(const struct voluta_dir_entry *de)
{
	const size_t step = de_nprev(de);

	return step ? de_unconst(de - step) : NULL;
}

static void de_assign(struct voluta_dir_entry *de, size_t nents,
                      const struct voluta_str *name, ino_t ino, mode_t dt)
{
	struct voluta_dir_entry_view *de_view  = de_view_of(de);

	de_set_ino_dt(de, ino, dt);
	de_set_name_len(de, name->len);
	de_set_nents(de, nents);
	memcpy(de_view->de_name, name->str, name->len);
}

static void de_reset(struct voluta_dir_entry *de, size_t nents, size_t nprev)
{
	voluta_memzero(de + 1, (nents - 1) * sizeof(*de));
	de_set_ino_dt(de, VOLUTA_INO_NULL, 0);
	de_set_name_len(de, 0);
	de_set_nents(de, nents);
	de_set_nprev(de, nprev);
}

static void de_reset_arr(struct voluta_dir_entry *de, size_t nents)
{
	de_reset(de, nents, 0);
}

static size_t de_slot(const struct voluta_dir_entry *de,
                      const struct voluta_dir_entry *beg)
{
	const ptrdiff_t slot = (de - beg);

	return (size_t)slot;
}

static loff_t de_doffset(const struct voluta_dir_entry *de,
                         const struct voluta_dir_entry *beg, size_t node_index)
{
	return make_doffset(node_index, de_slot(de, beg));
}

static const struct voluta_dir_entry *
de_search(const struct voluta_dir_entry *de,
          const struct voluta_dir_entry *end,
          const struct voluta_str *name)
{
	const struct voluta_dir_entry *itr = de;

	while (itr < end) {
		if (de_has_name(itr, name)) {
			return itr;
		}
		itr = de_next(itr);
	}
	return NULL;
}

static int de_verify(const struct voluta_dir_entry *beg,
                     const struct voluta_dir_entry *end)
{
	const struct voluta_dir_entry *itr = beg;

	while (itr < end) {
		if (de_isactive(itr) && !de_isvalid(itr)) {
			return -EFSCORRUPTED;
		}
		itr = de_next(itr);
	}
	return 0;
}

static const struct voluta_dir_entry *
de_scan(const struct voluta_dir_entry *de, const struct voluta_dir_entry *beg,
        const struct voluta_dir_entry *end, size_t node_index, loff_t pos)
{
	loff_t doff;
	const struct voluta_dir_entry *itr = de;

	while (itr < end) {
		if (de_isactive(itr)) {
			doff = de_doffset(itr, beg, node_index);
			if (doff >= pos) {
				return itr;
			}
		}
		itr = de_next(itr);
	}
	return NULL;
}

static const struct voluta_dir_entry *
de_insert_at(struct voluta_dir_entry *de, const struct voluta_dir_entry *end,
             size_t nents, const struct voluta_str *name, ino_t ino, mode_t dt)
{
	size_t nents_new;
	struct voluta_dir_entry *next_new;
	struct voluta_dir_entry *next_old;
	const size_t ncurr = de_nents(de);

	next_old = de_next_safe(de, end);
	de_assign(de, nents, name, ino, dt);
	if (nents < ncurr) {
		nents_new = ncurr - nents;
		next_new = de_next(de);
		de_reset(next_new, nents_new, nents);
		if (next_old != NULL) {
			de_set_nprev(next_old, nents_new);
		}
	}
	return de;
}

static bool de_may_insert(const struct voluta_dir_entry *de, size_t nwant)
{
	size_t nents;

	if (de_isactive(de)) {
		return false;
	}
	nents = de_nents(de);
	if (nwant > nents) {
		return false;
	}
	/* avoid single-dentry holes, as it is useless */
	if ((nents - nwant) == 1) {
		return false;
	}
	return true;
}

static const struct voluta_dir_entry *
de_insert(struct voluta_dir_entry *beg, const struct voluta_dir_entry *end,
          const struct voluta_str *name, ino_t ino, mode_t dt)
{
	struct voluta_dir_entry *itr = beg;
	const size_t nwant = de_nents_for_name(itr, name->len);

	while (itr < end) {
		if (de_may_insert(itr, nwant)) {
			return de_insert_at(itr, end, nwant, name, ino, dt);
		}
		itr = de_next(itr);
	}
	return NULL;
}

static void de_remove(struct voluta_dir_entry *de,
                      const struct voluta_dir_entry *end)
{
	size_t nents = de_nents(de);
	size_t nents_prev = de_nprev(de);
	struct voluta_dir_entry *next;
	struct voluta_dir_entry *prev;
	struct voluta_dir_entry *dent = de;

	next = de_next_safe(de, end);
	if (next != NULL) {
		if (!de_isactive(next)) {
			nents += de_nents(next);
			next = de_next_safe(next, end);
		}
	}
	prev = de_prev_safe(de);
	if (prev != NULL) {
		if (!de_isactive(prev)) {
			nents += de_nents(prev);
			nents_prev = de_nprev(prev);
			dent = prev;
		}
	}

	de_reset(dent, nents, nents_prev);
	if (next != NULL) {
		de_set_nprev(next, nents);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t htn_ino(const struct voluta_dir_htnode *htn)
{
	return voluta_ino_to_cpu(htn->dh_ino);
}

static void htn_set_ino(struct voluta_dir_htnode *htn, ino_t ino)
{
	htn->dh_ino = voluta_cpu_to_ino(ino);
}

static loff_t htn_parent(const struct voluta_dir_htnode *htn)
{
	return voluta_off_to_cpu(htn->dh_parent);
}

static void htn_set_parent(struct voluta_dir_htnode *htn, loff_t parent)
{
	htn->dh_parent = voluta_cpu_to_off(parent);
}

static size_t htn_node_index(const struct voluta_dir_htnode *htn)
{
	return voluta_le32_to_cpu(htn->dh_node_index);
}

static void htn_set_node_index(struct voluta_dir_htnode *htn, size_t index)
{
	htn->dh_node_index = voluta_cpu_to_le32((uint32_t)index);
}

static void htn_child(const struct voluta_dir_htnode *htn,
                      size_t ord, struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&htn->dh_child[ord], out_vaddr);
}

static void htn_set_child(struct voluta_dir_htnode *htn,
                          size_t ord, const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&htn->dh_child[ord], vaddr);
}

static void htn_reset_childs(struct voluta_dir_htnode *htn)
{
	for (size_t ord = 0; ord < ARRAY_SIZE(htn->dh_child); ++ord) {
		htn_set_child(htn, ord, vaddr_none());
	}
}

static void htn_setup(struct voluta_dir_htnode *htn,
                      ino_t ino, size_t node_index, loff_t parent_off)
{
	voluta_assert_le(node_index, HTREE_INDEX_MAX);

	htn_set_ino(htn, ino);
	htn_set_parent(htn, parent_off);
	htn_set_node_index(htn, node_index);
	htn_reset_childs(htn);
	de_reset_arr(htn->de, ARRAY_SIZE(htn->de));
	htn->dh_flags = 0;
}

static size_t htn_child_ord(const struct voluta_dir_htnode *htn)
{
	return index_to_child_ord(htn_node_index(htn));
}

static size_t htn_depth(const struct voluta_dir_htnode *htn)
{
	const size_t index = htn_node_index(htn);

	return index_to_depth(index);
}

static struct voluta_dir_entry *
htn_begin(const struct voluta_dir_htnode *htn)
{
	return de_unconst(htn->de);
}

static const struct voluta_dir_entry *
htn_end(const struct voluta_dir_htnode *htn)
{
	return htn->de + ARRAY_SIZE(htn->de);
}

static void htn_reset_des(struct voluta_dir_htnode *htn)
{
	de_reset(htn->de, ARRAY_SIZE(htn->de), 0);
}

static const struct voluta_dir_entry *
htn_search(const struct voluta_dir_htnode *htn,
           const struct voluta_qstr *name)
{
	return de_search(htn_begin(htn), htn_end(htn), &name->str);
}

static const struct voluta_dir_entry *
htn_scan(const struct voluta_dir_htnode *htn,
         const struct voluta_dir_entry *hint, loff_t pos)
{
	const struct voluta_dir_entry *beg = htn_begin(htn);
	const struct voluta_dir_entry *end = htn_end(htn);
	const size_t node_index = htn_node_index(htn);

	return de_scan(hint ? hint : beg, beg, end, node_index, pos);
}

static const struct voluta_dir_entry *
htn_insert(struct voluta_dir_htnode *htn,
           const struct voluta_qstr *name, ino_t ino, mode_t dt)
{
	return de_insert(htn_begin(htn), htn_end(htn), &name->str, ino, dt);
}

static loff_t htn_next_doffset(const struct voluta_dir_htnode *htn)
{
	const size_t node_index = htn_node_index(htn);

	return make_doffset(node_index + 1, 0);
}

static loff_t htn_resolve_doffset(const struct voluta_dir_htnode *htn,
                                  const struct voluta_dir_entry *de)
{
	const size_t index = htn_node_index(htn);
	const size_t sloti = de_slot(de, htn_begin(htn));

	return make_doffset(index, sloti);
}

static void htn_child_by_ord(const struct voluta_dir_htnode *htn,
                             size_t ord, struct voluta_vaddr *out_vaddr)
{
	htn_child(htn, ord, out_vaddr);
}

static void htn_child_by_hash(const struct voluta_dir_htnode *htn,
                              uint64_t hash, struct voluta_vaddr *out_vaddr)
{
	const size_t ord = hash_to_child_ord(hash, htn_depth(htn) + 1);

	htn_child_by_ord(htn, ord, out_vaddr);
}

static void htn_parent_addr(const struct voluta_dir_htnode *htn,
                            struct voluta_vaddr *out_vaddr)
{
	vaddr_of_htnode(out_vaddr, htn_parent(htn));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t dir_ino_of(const struct voluta_vnode_info *vi)
{
	return htn_ino(vi->vu.htn);
}

static mode_t dtype_of(const struct voluta_inode_info *ii)
{
	return IFTODT(ii_mode(ii));
}

static int check_dir_io(const struct voluta_inode_info *ii)
{
	if (!ii_isdir(ii)) {
		return -ENOTDIR;
	}
	if (!ii->i_nopen) {
		return -EBADF;
	}
	return 0;
}

static struct voluta_inode *unconst_inode(const struct voluta_inode *inode)
{
	return unconst(inode);
}

static struct voluta_inode_info *unconst_ii(const struct voluta_inode_info *ii)
{
	return unconst(ii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_dir_ispec *dis_of(const struct voluta_inode *inode)
{
	struct voluta_inode *dir_inode = unconst_inode(inode);

	return &dir_inode->i_s.d;
}

static uint64_t dis_ndents(const struct voluta_dir_ispec *dis)
{
	return voluta_le64_to_cpu(dis->d_ndents);
}

static void dis_set_ndents(struct voluta_dir_ispec *dis, size_t n)
{
	dis->d_ndents = voluta_cpu_to_le64(n);
}

static void dis_inc_ndents(struct voluta_dir_ispec *dis)
{
	dis_set_ndents(dis, dis_ndents(dis) + 1);
}

static void dis_dec_ndents(struct voluta_dir_ispec *dis)
{
	dis_set_ndents(dis, dis_ndents(dis) - 1);
}

static size_t dis_last_index(const struct voluta_dir_ispec *dis)
{
	return voluta_le32_to_cpu(dis->d_last_index);
}

static void dis_set_last_index(struct voluta_dir_ispec *dis, size_t index)
{
	dis->d_last_index = voluta_cpu_to_le32((uint32_t)index);
}

static void dis_update_last_index(struct voluta_dir_ispec *dis,
                                  size_t alt_index, bool add)
{
	size_t new_index;
	const size_t cur_index = dis_last_index(dis);
	const size_t nil_index = HTREE_INDEX_NULL;

	new_index = cur_index;
	if (add) {
		if ((cur_index < alt_index) || index_isnull(cur_index)) {
			new_index = alt_index;
		}
	} else {
		if (cur_index == alt_index) {
			new_index = !cur_index ? nil_index : cur_index - 1;
		}
	}
	dis_set_last_index(dis, new_index);
}

static loff_t dis_htree_root(const struct voluta_dir_ispec *dis)
{
	return voluta_off_to_cpu(dis->d_root);
}

static void dis_set_htree_root(struct voluta_dir_ispec *dis, loff_t off)
{
	dis->d_root = voluta_cpu_to_off(off);
}

static enum voluta_dirf dis_flags(const struct voluta_dir_ispec *dis)
{
	return voluta_le32_to_cpu(dis->d_flags);
}

static void dis_set_flags(struct voluta_dir_ispec *dis,
                          enum voluta_dirf f)
{
	dis->d_flags = voluta_cpu_to_le32((uint32_t)f);
}

static void dis_setup(struct voluta_dir_ispec *dis)
{
	dis_set_htree_root(dis, VOLUTA_OFF_NULL);
	dis_set_last_index(dis, HTREE_INDEX_NULL);
	dis_set_ndents(dis, 0);
	dis_set_flags(dis, VOLUTA_DIRF_HASH_SHA256 | VOLUTA_DIRF_NAME_UTF8);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_dir_ispec *
dir_ispec_of(const struct voluta_inode_info *dir_ii)
{
	return dis_of(dir_ii->inode);
}

static uint64_t dir_ndents(const struct voluta_inode_info *dir_ii)
{
	return dis_ndents(dir_ispec_of(dir_ii));
}

static void dir_inc_ndents(struct voluta_inode_info *dir_ii)
{
	dis_inc_ndents(dir_ispec_of(dir_ii));
	ii_dirtify(dir_ii);
}

static void dir_dec_ndents(struct voluta_inode_info *dir_ii)
{
	dis_dec_ndents(dir_ispec_of(dir_ii));
	ii_dirtify(dir_ii);
}

static loff_t dir_htree_root(const struct voluta_inode_info *dir_ii)
{
	return dis_htree_root(dir_ispec_of(dir_ii));
}

static void dir_htree_root_addr(const struct voluta_inode_info *dir_ii,
                                struct voluta_vaddr *out_vaddr)
{
	vaddr_of_htnode(out_vaddr, dir_htree_root(dir_ii));
}

static bool dir_has_htree(const struct voluta_inode_info *dir_ii)
{
	return !off_isnull(dir_htree_root(dir_ii));
}

static void dir_set_htree_root(struct voluta_inode_info *dir_ii,
                               const struct voluta_vaddr *vaddr)
{
	struct voluta_dir_ispec *dis = dir_ispec_of(dir_ii);

	dis_set_htree_root(dis, vaddr->off);
	dis_set_last_index(dis, HTREE_INDEX_ROOT);
}

static size_t dir_last_index(const struct voluta_inode_info *dir_ii)
{
	return dis_last_index(dir_ispec_of(dir_ii));
}

static void dir_update_last_index(struct voluta_inode_info *dir_ii,
                                  size_t alt_index, bool add)
{
	dis_update_last_index(dir_ispec_of(dir_ii), alt_index, add);
}

size_t voluta_dir_ndentries(const struct voluta_inode_info *dir_ii)
{
	return dir_ndents(dir_ii);
}

enum voluta_dirf voluta_dir_flags(const struct voluta_inode_info *dir_ii)
{
	return dis_flags(dir_ispec_of(dir_ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_setup_dir(struct voluta_inode_info *dir_ii,
                      mode_t parent_mode, nlink_t nlink)
{
	struct voluta_iattr iattr = {
		.ia_size = VOLUTA_DIR_EMPTY_SIZE,
		.ia_nlink = nlink,
		.ia_blocks = 0,
		.ia_mode = ii_mode(dir_ii) | (parent_mode & S_ISGID),
		.ia_flags =
		VOLUTA_IATTR_SIZE | VOLUTA_IATTR_BLOCKS |
		VOLUTA_IATTR_NLINK | VOLUTA_IATTR_MODE
	};

	dis_setup(dis_of(dir_ii->inode));
	update_iattrs(NULL, dir_ii, &iattr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *unconst_vi(const struct voluta_vnode_info *vi)
{
	return unconst(vi);
}

static struct voluta_dir_entry *unconst_de(const struct voluta_dir_entry *de)
{
	return unconst(de);
}

static void dei_setup(struct voluta_dir_entry_info *dei,
                      const struct voluta_vnode_info *vi,
                      const struct voluta_dir_entry *de)
{
	dei->vi = unconst_vi(vi);
	dei->de = unconst_de(de);
	dei->ino_dt.ino = de_ino(de);
	dei->ino_dt.dt = de_dt(de);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void child_addr_by_hash(const struct voluta_vnode_info *parent_vi,
                               uint64_t hash, struct voluta_vaddr *out_vaddr)
{
	htn_child_by_hash(parent_vi->vu.htn, hash, out_vaddr);
}

static void child_addr_by_ord(const struct voluta_vnode_info *parent_vi,
                              size_t ord, struct voluta_vaddr *out_vaddr)
{
	htn_child_by_ord(parent_vi->vu.htn, ord, out_vaddr);
}

static int search_htnode(const struct voluta_vnode_info *vi,
                         const struct voluta_qstr *name,
                         struct voluta_dir_entry_info *out_dei)
{
	const struct voluta_dir_entry *de;

	de = htn_search(vi->vu.htn, name);
	if (de == NULL) {
		return -ENOENT;
	}
	dei_setup(out_dei, vi, de);
	return 0;
}

static int stage_htnode(const struct voluta_dir_ctx *d_ctx,
                        const struct voluta_vaddr *vaddr,
                        struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi;

	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	err = voluta_stage_vnode(d_ctx->sbi, vaddr, d_ctx->dir_ii, &vi);
	if (err) {
		return err;
	}
	if (dir_ino_of(vi) != ii_ino(d_ctx->dir_ii)) {
		return -EFSCORRUPTED;
	}
	*out_vi = vi;
	return 0;
}

static int do_stage_child(const struct voluta_dir_ctx *d_ctx,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_vnode_info **out_vi)
{
	/* TODO: check depth */
	return stage_htnode(d_ctx, vaddr, out_vi);
}

static int stage_child(const struct voluta_dir_ctx *d_ctx,
                       struct voluta_vnode_info *parent_vi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_vnode_info **out_vi)
{
	int err;

	vi_incref(parent_vi);
	err = do_stage_child(d_ctx, vaddr, out_vi);
	vi_decref(parent_vi);

	return err;
}

static int stage_child_by_name(const struct voluta_dir_ctx *d_ctx,
                               struct voluta_vnode_info *parent_vi,
                               struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr vaddr;

	child_addr_by_hash(parent_vi, d_ctx->name->hash, &vaddr);
	return stage_child(d_ctx, parent_vi, &vaddr, out_vi);
}

static int new_htnode(const struct voluta_dir_ctx *d_ctx,
                      struct voluta_vnode_info **out_vi)
{
	return voluta_create_vnode(d_ctx->sbi, d_ctx->dir_ii,
	                           VOLUTA_VTYPE_HTNODE, out_vi);
}

static int del_htnode(const struct voluta_dir_ctx *d_ctx,
                      struct voluta_vnode_info *vi)
{
	return voluta_remove_vnode(d_ctx->sbi, vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t last_node_index_of(const struct voluta_dir_ctx *d_ctx)
{
	return dir_last_index(d_ctx->dir_ii);
}

static size_t curr_node_index_of(const struct voluta_dir_ctx *d_ctx)
{
	return doffset_to_index(d_ctx->rd_ctx->pos);
}

static void update_isizeblocks(const struct voluta_dir_ctx *d_ctx,
                               size_t node_index, bool new_node)
{
	size_t last_index;
	const long dif = new_node ? 1 : -1;
	struct voluta_inode_info *dir_ii = d_ctx->dir_ii;

	dir_update_last_index(dir_ii, node_index, new_node);
	last_index = dir_last_index(dir_ii);

	update_isize(d_ctx->op, dir_ii, calc_d_isize(last_index));
	update_iblocks(d_ctx->op, dir_ii, VOLUTA_VTYPE_HTNODE, dif);
}

static int create_htnode(const struct voluta_dir_ctx *d_ctx,
                         const struct voluta_vaddr *parent, size_t node_index,
                         struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi;
	struct voluta_inode_info *dir_ii = d_ctx->dir_ii;

	err = new_htnode(d_ctx, &vi);
	if (err) {
		return err;
	}
	htn_setup(vi->vu.htn, ii_ino(dir_ii), node_index, parent->off);
	update_isizeblocks(d_ctx, node_index, true);
	vi_dirtify(vi);
	*out_vi = vi;
	return 0;
}

static int stage_htree_root(const struct voluta_dir_ctx *d_ctx,
                            struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr vaddr;

	dir_htree_root_addr(d_ctx->dir_ii, &vaddr);
	return stage_htnode(d_ctx, &vaddr, out_vi);
}

static int create_htree_root(const struct voluta_dir_ctx *d_ctx,
                             struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi;

	vaddr_of_htnode(&vaddr, VOLUTA_OFF_NULL);
	err = create_htnode(d_ctx, &vaddr, HTREE_INDEX_ROOT, &vi);
	if (err) {
		return err;
	}
	dir_set_htree_root(d_ctx->dir_ii, vi_vaddr(vi));
	ii_dirtify(d_ctx->dir_ii);

	*out_vi = vi;
	return 0;
}

static int stage_or_create_root(const struct voluta_dir_ctx *d_ctx,
                                struct voluta_vnode_info **out_vi)
{
	int err;

	if (dir_has_htree(d_ctx->dir_ii)) {
		err = stage_htree_root(d_ctx, out_vi);
	} else {
		err = create_htree_root(d_ctx, out_vi);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_child_depth(const struct voluta_vnode_info *vi,
                             size_t parent_depth)
{
	int err = 0;
	const size_t child_depth = htn_depth(vi->vu.htn);
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if ((parent_depth + 1) != child_depth) {
		log_err("illegal-tree-depth: voff=0x%lx "
		        "parent_depth=%lu child_depth=%lu ",
		        vaddr->off, parent_depth, child_depth);
		err = -EFSCORRUPTED;
	}
	return err;
}

static int do_lookup_by_tree(const struct voluta_dir_ctx *d_ctx,
                             struct voluta_vnode_info *root_vi,
                             struct voluta_dir_entry_info *dei)
{
	int err;
	size_t depth;
	struct voluta_vnode_info *child_vi;
	struct voluta_vnode_info *vi = root_vi;
	const struct voluta_qstr *name = d_ctx->name;

	depth = htn_depth(vi->vu.htn);
	while (depth_isvalid(depth)) {
		err = search_htnode(vi, name, dei);
		if (!err) {
			return 0;
		}
		if (err != -ENOENT) {
			return err;
		}
		err = stage_child_by_name(d_ctx, vi, &child_vi);
		if (err) {
			return err;
		}
		vi = child_vi;
		err = check_child_depth(vi, depth);
		if (err) {
			return err;
		}
		depth++;
	}
	return -ENOENT;
}

static int lookup_by_tree(const struct voluta_dir_ctx *d_ctx,
                          struct voluta_vnode_info *root_vi,
                          struct voluta_dir_entry_info *dei)
{
	int err;

	vi_incref(root_vi);
	err = do_lookup_by_tree(d_ctx, root_vi, dei);
	vi_decref(root_vi);

	return err;
}

static int lookup_by_name(const struct voluta_dir_ctx *d_ctx,
                          struct voluta_dir_entry_info *dei)
{
	int err = -ENOENT;
	struct voluta_vnode_info *root_vi;

	if (!dir_has_htree(d_ctx->dir_ii)) {
		return -ENOENT;
	}
	err = stage_htree_root(d_ctx, &root_vi);
	if (err) {
		return err;
	}
	err = lookup_by_tree(d_ctx, root_vi, dei);
	if (err) {
		return err;
	}
	return 0;
}

static int check_dir_and_name(const struct voluta_dir_ctx *d_ctx)
{
	if (!ii_isdir(d_ctx->dir_ii)) {
		return -ENOTDIR;
	}
	if (d_ctx->name->str.len == 0) {
		return -EINVAL;
	}
	if (d_ctx->name->str.len > VOLUTA_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	return 0;
}

static void fill_ino_dt(struct voluta_ino_dt *ino_dt,
                        const struct voluta_dir_entry_info *dei)
{
	ino_dt->ino = dei->ino_dt.ino;
	ino_dt->dt = dei->ino_dt.dt;
}

static int do_lookup_dentry(struct voluta_dir_ctx *d_ctx,
                            struct voluta_ino_dt *ino_dt)
{
	int err;
	struct voluta_dir_entry_info dei;

	err = check_dir_and_name(d_ctx);
	if (err) {
		return err;
	}
	err = lookup_by_name(d_ctx, &dei);
	if (err) {
		return err;
	}
	fill_ino_dt(ino_dt, &dei);
	return 0;
}

int voluta_lookup_dentry(const struct voluta_oper *op,
                         const struct voluta_inode_info *dir_ii,
                         const struct voluta_qstr *name,
                         struct voluta_ino_dt *out_idt)
{
	int err;
	struct voluta_dir_ctx d_ctx = {
		.sbi = ii_sbi(dir_ii),
		.op = op,
		.dir_ii = unconst_ii(dir_ii),
		.name = name
	};

	ii_incref(dir_ii);
	err = do_lookup_dentry(&d_ctx, out_idt);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int create_child(const struct voluta_dir_ctx *d_ctx,
                        const struct voluta_vaddr *parent, size_t index,
                        struct voluta_vnode_info **out_vi)
{
	int err;

	if (!index_valid_depth(index)) {
		return -ENOSPC;
	}
	err = create_htnode(d_ctx, parent, index, out_vi);
	if (err) {
		return err;
	}
	vi_dirtify(*out_vi);
	return 0;
}

static void set_parent_link(struct voluta_vnode_info *parent_vi,
                            const struct voluta_vaddr *vaddr, size_t index)
{
	const size_t child_ord = index_to_child_ord(index);

	htn_set_child(parent_vi->vu.htn, child_ord, vaddr);
	vi_dirtify(parent_vi);
}

static int do_create_link_child(const struct voluta_dir_ctx *d_ctx,
                                struct voluta_vnode_info *parent_vi,
                                struct voluta_vnode_info **out_vi)
{
	int err;
	size_t parent_index;
	size_t child_index;
	struct voluta_vnode_info *vi;
	const struct voluta_qstr *name = d_ctx->name;

	parent_index = htn_node_index(parent_vi->vu.htn);
	child_index = hash_to_child_index(name->hash, parent_index);
	err = create_child(d_ctx, vi_vaddr(parent_vi), child_index, &vi);
	if (err) {
		return err;
	}
	set_parent_link(parent_vi, vi_vaddr(vi), child_index);
	*out_vi = vi;
	return 0;
}

static int create_link_child(const struct voluta_dir_ctx *d_ctx,
                             struct voluta_vnode_info *parent_vi,
                             struct voluta_vnode_info **out_vi)
{
	int err;

	vi_incref(parent_vi);
	err = do_create_link_child(d_ctx, parent_vi, out_vi);
	vi_decref(parent_vi);

	return err;
}

static int stage_or_create_child(const struct voluta_dir_ctx *d_ctx,
                                 struct voluta_vnode_info *parent_vi,
                                 struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vaddr vaddr;
	const struct voluta_qstr *name = d_ctx->name;

	child_addr_by_hash(parent_vi, name->hash, &vaddr);
	if (!vaddr_isnull(&vaddr)) {
		err = stage_child(d_ctx, parent_vi, &vaddr, out_vi);
	} else {
		err = create_link_child(d_ctx, parent_vi, out_vi);
	}
	return err;
}

static int discard_htnode(const struct voluta_dir_ctx *d_ctx,
                          struct voluta_vnode_info *vi)
{
	int err;
	const size_t node_index = htn_node_index(vi->vu.htn);

	htn_reset_des(vi->vu.htn);
	err = del_htnode(d_ctx, vi);
	if (err) {
		return err;
	}
	update_isizeblocks(d_ctx, node_index, false);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static nlink_t i_nlink_new(const struct voluta_inode_info *ii, long dif)
{
	return (nlink_t)((long)ii_nlink(ii) + dif);
}

static void update_nlink(const struct voluta_dir_ctx *d_ctx, long dif)
{
	struct voluta_iattr iattr;
	struct voluta_inode_info *child_ii = d_ctx->child_ii;
	struct voluta_inode_info *dir_ii = d_ctx->dir_ii;

	iattr_setup(&iattr, ii_ino(child_ii));
	iattr.ia_nlink = i_nlink_new(child_ii, dif);
	iattr.ia_flags |= VOLUTA_IATTR_NLINK;
	if (dif > 0) {
		iattr.ia_parent = ii_ino(dir_ii);
		iattr.ia_flags |= VOLUTA_IATTR_PARENT;
	} else if (ii_parent(child_ii) == ii_ino(dir_ii)) {
		iattr.ia_parent = VOLUTA_INO_NULL;
		iattr.ia_flags |= VOLUTA_IATTR_PARENT;
	}
	update_iattrs(d_ctx->op, child_ii, &iattr);

	iattr_setup(&iattr, ii_ino(dir_ii));
	if (ii_isdir(child_ii)) {
		iattr.ia_nlink = i_nlink_new(dir_ii, dif);
		iattr.ia_flags |= VOLUTA_IATTR_NLINK;
	}
	update_iattrs(d_ctx->op, dir_ii, &iattr);
}

static int add_to_htnode(const struct voluta_dir_ctx *d_ctx,
                         struct voluta_vnode_info *vi)
{
	const struct voluta_dir_entry *de;
	const struct voluta_inode_info *ii = d_ctx->child_ii;

	de = htn_insert(vi->vu.htn, d_ctx->name, ii_ino(ii), dtype_of(ii));
	if (de == NULL) {
		return -ENOSPC;
	}
	dir_inc_ndents(d_ctx->dir_ii);
	vi_dirtify(vi);
	return 0;
}

static int do_add_to_tree(const struct voluta_dir_ctx *d_ctx,
                          struct voluta_vnode_info *root_vi)
{
	int err;
	size_t depth;
	struct voluta_vnode_info *vi = root_vi;

	depth = htn_depth(vi->vu.htn);
	while (depth_isvalid(depth)) {
		err = add_to_htnode(d_ctx, vi);
		if (!err) {
			return 0;
		}
		err = stage_or_create_child(d_ctx, vi, &vi);
		if (err) {
			return err;
		}
		err = check_child_depth(vi, depth);
		if (err) {
			return err;
		}
		depth++;
	}
	return -ENOSPC;
}

static int add_to_tree(const struct voluta_dir_ctx *d_ctx,
                       struct voluta_vnode_info *root_vi)
{
	int err;

	vi_incref(root_vi);
	err = do_add_to_tree(d_ctx, root_vi);
	vi_decref(root_vi);

	return err;
}

static int insert_dentry(struct voluta_dir_ctx *d_ctx,
                         struct voluta_vnode_info *root_vi)
{
	int err;

	err = add_to_tree(d_ctx, root_vi);
	if (err) {
		return err;
	}
	update_nlink(d_ctx, 1);
	return 0;
}

static int do_add_dentry(struct voluta_dir_ctx *d_ctx)
{
	int err;
	struct voluta_vnode_info *root_vi;

	err = stage_or_create_root(d_ctx, &root_vi);
	if (err) {
		return err;
	}
	err = insert_dentry(d_ctx, root_vi);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_add_dentry(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      const struct voluta_qstr *name,
                      struct voluta_inode_info *ii)
{
	int err;
	struct voluta_dir_ctx d_ctx = {
		.sbi = ii_sbi(dir_ii),
		.op = op,
		.dir_ii = dir_ii,
		.child_ii = ii,
		.name = name,
	};

	ii_incref(dir_ii);
	ii_incref(ii);
	err = do_add_dentry(&d_ctx);
	ii_decref(ii);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fetch_inode(const struct voluta_dir_ctx *d_ctx, ino_t ino,
                       struct voluta_inode_info **out_ii)
{
	return voluta_fetch_inode(d_ctx->sbi, ino, out_ii);
}

static int check_stage_parent(struct voluta_dir_ctx *d_ctx)
{
	int err;
	ino_t parent;

	parent = ii_parent(d_ctx->dir_ii);
	if (ino_isnull(parent)) {
		/* special case: unlinked-but-open dir */
		return -ENOENT;
	}
	if (!ino_isvalid(parent)) {
		return -EFSCORRUPTED;
	}
	err = fetch_inode(d_ctx, parent, &d_ctx->parent_ii);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool index_inrange(const struct voluta_dir_ctx *d_ctx, size_t index)
{
	const size_t last = last_node_index_of(d_ctx);

	return (last != HTREE_INDEX_NULL) ? (index <= last) : false;
}

static bool inrange(const struct voluta_dir_ctx *d_ctx)
{
	const loff_t doff = d_ctx->rd_ctx->pos;

	return (doff >= 0) && index_inrange(d_ctx, doffset_to_index(doff));
}

static bool stopped(const struct voluta_dir_ctx *d_ctx)
{
	return !d_ctx->keep_iter;
}

static bool emit(struct voluta_dir_ctx *d_ctx, const char *name,
                 size_t nlen, ino_t ino, mode_t dt, const struct stat *attr)
{
	int err;
	struct voluta_readdir_ctx *rd_ctx = d_ctx->rd_ctx;
	struct voluta_readdir_info rdi = {
		.attr.st_ino = ino,
		.name = name,
		.namelen = nlen,
		.ino = ino,
		.dt = dt,
		.off = rd_ctx->pos
	};

	if (attr != NULL) {
		memcpy(&rdi.attr, attr, sizeof(rdi.attr));
	}

	err = rd_ctx->actor(rd_ctx, &rdi);
	d_ctx->keep_iter = (err == 0);
	return d_ctx->keep_iter;
}

static bool emit_dirent(struct voluta_dir_ctx *d_ctx,
                        const struct voluta_dir_entry *de, loff_t doff,
                        const struct voluta_inode_info *ii)
{
	const ino_t ino = de_ino(de);
	const mode_t dt = de_dt(de);
	const size_t len = de_name_len(de);
	const char *name = de_name(de);
	const struct stat *attr = NULL;
	struct stat st;

	if (ii != NULL) {
		voluta_stat_of(ii, &st);
		attr = &st;
	}

	d_ctx->rd_ctx->pos = doff;
	return emit(d_ctx, name, len, ino, dt, attr);
}

static bool emit_ii(struct voluta_dir_ctx *d_ctx, const char *name,
                    size_t nlen, const struct voluta_inode_info *ii)
{
	const ino_t xino = ii_xino(ii);
	const mode_t mode = ii_mode(ii);
	struct stat attr;

	voluta_stat_of(ii, &attr);
	return emit(d_ctx, name, nlen, xino, IFTODT(mode), &attr);
}

static int fetch_inode_of_de(const struct voluta_dir_ctx *d_ctx,
                             const struct voluta_dir_entry *de,
                             struct voluta_inode_info **out_ii)
{
	int err = 0;

	*out_ii = NULL;
	if (d_ctx->readdir_plus) {
		err = fetch_inode(d_ctx, de_ino(de), out_ii);
	}
	return err;
}

static int iterate_htnode(struct voluta_dir_ctx *d_ctx,
                          const struct voluta_vnode_info *vi)
{
	int err;
	loff_t off;
	struct voluta_inode_info *ii = NULL;
	const struct voluta_dir_entry *de = NULL;
	bool ok;

	while (!stopped(d_ctx)) {
		de = htn_scan(vi->vu.htn, de, d_ctx->rd_ctx->pos);
		if (!de) {
			off = htn_next_doffset(vi->vu.htn);
			d_ctx->rd_ctx->pos = off;
			break;
		}
		off = htn_resolve_doffset(vi->vu.htn, de);
		err = fetch_inode_of_de(d_ctx, de, &ii);
		if (err) {
			return err;
		}
		ok = emit_dirent(d_ctx, de, off, ii);
		if (!ok) {
			break;
		}
		d_ctx->rd_ctx->pos += 1;
	}
	return 0;
}

static int readdir_eos(struct voluta_dir_ctx *d_ctx)
{
	d_ctx->rd_ctx->pos = -1;
	emit(d_ctx, "", 0, VOLUTA_INO_NULL, 0, NULL);

	d_ctx->keep_iter = false;
	return 0;
}

static int do_stage_child_by_ord(struct voluta_dir_ctx *d_ctx,
                                 const struct voluta_vnode_info *vi,
                                 size_t ord, struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vaddr vaddr;

	if (ord >= HTREE_FANOUT) {
		return -ENOENT;
	}
	child_addr_by_ord(vi, ord, &vaddr);
	err = stage_htnode(d_ctx, &vaddr, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

static int stage_child_by_ord(struct voluta_dir_ctx *d_ctx,
                              struct voluta_vnode_info *vi, size_t ord,
                              struct voluta_vnode_info **out_vi)
{
	int err;

	vi_incref(vi);
	err = do_stage_child_by_ord(d_ctx, vi, ord, out_vi);
	vi_decref(vi);

	return err;
}

static int stage_htnode_by_index(struct voluta_dir_ctx *d_ctx,
                                 const struct voluta_vnode_info *root_vi,
                                 size_t idx, struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi;
	const size_t depth = index_to_depth(idx);
	size_t child_ord[HTREE_DEPTH_MAX];

	if (depth >= ARRAY_SIZE(child_ord)) {
		return -ENOENT;
	}
	for (size_t d = depth; d > 0; --d) {
		child_ord[d - 1] = index_to_child_ord(idx);
		idx = index_to_parent(idx);
	}
	vi = unconst_vi(root_vi);
	for (size_t i = 0; i < depth; ++i) {
		err = stage_child_by_ord(d_ctx, vi, child_ord[i], &vi);
		if (err) {
			return err;
		}
	}
	*out_vi = vi;
	return 0;
}

static int next_htnode(struct voluta_dir_ctx *d_ctx,
                       const struct voluta_vnode_info *vi, size_t *out_index)
{
	int err;
	size_t ord;
	size_t next_index;
	size_t curr_index;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *parent_vi;

	curr_index = htn_node_index(vi->vu.htn);
	next_index = curr_index + 1;

	htn_parent_addr(vi->vu.htn, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		*out_index = next_index;
		return 0;
	}
	err = stage_htnode(d_ctx, &vaddr, &parent_vi);
	if (err) {
		return err;
	}
	ord = htn_child_ord(vi->vu.htn);
	while (++ord < HTREE_FANOUT) {
		child_addr_by_ord(parent_vi, ord, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			break;
		}
		next_index += 1;
	}
	*out_index = next_index;
	return 0;
}

static int do_iterate_htnodes(struct voluta_dir_ctx *d_ctx,
                              const struct voluta_vnode_info *root_vi)
{
	int err = 0;
	size_t index;
	struct voluta_vnode_info *vi = NULL;

	index = curr_node_index_of(d_ctx);
	while (!err && !stopped(d_ctx)) {
		if (!index_inrange(d_ctx, index)) {
			return readdir_eos(d_ctx);
		}
		err = stage_htnode_by_index(d_ctx, root_vi, index, &vi);
		if (err == -ENOENT) {
			index++;
			err = 0;
			continue;
		}
		if (err) {
			break;
		}
		err = iterate_htnode(d_ctx, vi);
		if (err) {
			break;
		}
		err = next_htnode(d_ctx, vi, &index);
	}
	return err;
}


static int iterate_htnodes(struct voluta_dir_ctx *d_ctx,
                           struct voluta_vnode_info *root_vi)
{
	int err;

	vi_incref(root_vi);
	err = do_iterate_htnodes(d_ctx, root_vi);
	vi_decref(root_vi);

	return err;
}

static int iterate_htree(struct voluta_dir_ctx *d_ctx)
{
	int err;
	struct voluta_vnode_info *root_vi;
	const size_t start_index = curr_node_index_of(d_ctx);

	if (!index_inrange(d_ctx, start_index)) {
		return readdir_eos(d_ctx);
	}
	err = stage_htree_root(d_ctx, &root_vi);
	if (err) {
		return err;
	}
	err = iterate_htnodes(d_ctx, root_vi);
	if (err) {
		return err;
	}
	return 0;
}

static int iterate_dir(struct voluta_dir_ctx *d_ctx)
{
	int err;

	if (!dir_has_htree(d_ctx->dir_ii)) {
		return readdir_eos(d_ctx);
	}
	err = iterate_htree(d_ctx);
	if (err || stopped(d_ctx)) {
		return err;
	}
	return readdir_eos(d_ctx);
}

static int readdir_emit(struct voluta_dir_ctx *d_ctx)
{
	int err = 0;
	bool ok = true;
	struct voluta_iattr iattr;

	if (d_ctx->rd_ctx->pos == 0) {
		ok = emit_ii(d_ctx, ".", 1, d_ctx->dir_ii);
		d_ctx->rd_ctx->pos = 1;
	}
	if (ok && (d_ctx->rd_ctx->pos == 1)) {
		ok = emit_ii(d_ctx, "..", 2, d_ctx->parent_ii);
		d_ctx->rd_ctx->pos = 2;
	}
	if (ok && !inrange(d_ctx)) {
		err = readdir_eos(d_ctx);
	}
	if (ok && !stopped(d_ctx)) {
		err = iterate_dir(d_ctx);
	}

	iattr_setup(&iattr, ii_ino(d_ctx->dir_ii));
	iattr.ia_flags |= VOLUTA_IATTR_ATIME | VOLUTA_IATTR_LAZY;
	update_iattrs(d_ctx->op, d_ctx->dir_ii, &iattr);

	return err;
}

static int check_raccess(const struct voluta_dir_ctx *d_ctx)
{
	return voluta_do_access(d_ctx->op, d_ctx->dir_ii, R_OK);
}

static int do_readdir(struct voluta_dir_ctx *d_ctx)
{
	int err;

	err = check_dir_io(d_ctx->dir_ii);
	if (err) {
		return err;
	}
	err = check_raccess(d_ctx);
	if (err) {
		return err;
	}
	err = check_stage_parent(d_ctx);
	if (err) {
		return err;
	}
	err = readdir_emit(d_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_do_readdir(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      struct voluta_readdir_ctx *rd_ctx)
{
	int err;
	struct voluta_dir_ctx d_ctx = {
		.op = op,
		.sbi = ii_sbi(dir_ii),
		.rd_ctx = rd_ctx,
		.dir_ii = dir_ii,
		.keep_iter = true,
		.readdir_plus = 0
	};

	ii_incref(dir_ii);
	err = do_readdir(&d_ctx);
	ii_decref(dir_ii);
	return err;
}

int voluta_do_readdirplus(const struct voluta_oper *op,
                          struct voluta_inode_info *dir_ii,
                          struct voluta_readdir_ctx *rd_ctx)
{
	int err;
	struct voluta_dir_ctx d_ctx = {
		.op = op,
		.sbi = ii_sbi(dir_ii),
		.rd_ctx = rd_ctx,
		.dir_ii = dir_ii,
		.keep_iter = true,
		.readdir_plus = 1
	};

	ii_incref(dir_ii);
	err = do_readdir(&d_ctx);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int discard_recursively(struct voluta_dir_ctx *d_ctx,
                               const struct voluta_vaddr *vaddr);

static int do_discard_childs_of(struct voluta_dir_ctx *d_ctx,
                                struct voluta_vnode_info *vi)
{
	int err = 0;
	struct voluta_vaddr child_vaddr;

	for (size_t ord = 0; (ord < HTREE_FANOUT) && !err; ++ord) {
		htn_child_by_ord(vi->vu.htn, ord, &child_vaddr);
		err = discard_recursively(d_ctx, &child_vaddr);
	}
	return err;
}

static int discard_childs_of(struct voluta_dir_ctx *d_ctx,
                             struct voluta_vnode_info *vi)
{
	int err;

	vi_incref(vi);
	err = do_discard_childs_of(d_ctx, vi);
	vi_decref(vi);

	return err;
}

static int discard_htree_at(struct voluta_dir_ctx *d_ctx,
                            struct voluta_vnode_info *vi)
{
	int err;

	err = discard_childs_of(d_ctx, vi);
	if (err) {
		return err;
	}
	err = discard_htnode(d_ctx, vi);
	if (err) {
		return err;
	}
	return 0;
}

static int discard_recursively(struct voluta_dir_ctx *d_ctx,
                               const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *vi;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = stage_htnode(d_ctx, vaddr, &vi);
	if (err) {
		return err;
	}
	err = discard_htree_at(d_ctx, vi);
	if (err) {
		return err;
	}
	return 0;
}

static int finalize_htree(struct voluta_dir_ctx *d_ctx)
{
	int err;
	struct voluta_vnode_info *root_vi;
	struct voluta_inode_info *dir_ii = d_ctx->dir_ii;

	if (!dir_has_htree(dir_ii)) {
		return 0;
	}
	err = stage_htree_root(d_ctx, &root_vi);
	if (err) {
		return err;
	}
	err = discard_htree_at(d_ctx, root_vi);
	if (err) {
		return err;
	}
	voluta_setup_dir(dir_ii, 0, ii_nlink(dir_ii));
	ii_dirtify(dir_ii);
	return 0;
}

int voluta_drop_dir(struct voluta_inode_info *dir_ii)
{
	int err;
	struct voluta_dir_ctx d_ctx = {
		.sbi = ii_sbi(dir_ii),
		.dir_ii = dir_ii,
	};

	ii_incref(dir_ii);
	err = finalize_htree(&d_ctx);
	ii_decref(dir_ii);
	return err;
}


/*
 * TODO-0005: Squeeze htree
 *
 * Currently, we drop htree only when its empty. Try to squeeze it up and
 * remove empty leaf nodes.
 */
static int do_erase_dentry(struct voluta_dir_ctx *d_ctx,
                           const struct voluta_dir_entry_info *dei)
{
	struct voluta_inode_info *dir_ii = d_ctx->dir_ii;

	de_remove(dei->de, htn_end(dei->vi->vu.htn));
	vi_dirtify(dei->vi);

	dir_dec_ndents(dir_ii);
	update_nlink(d_ctx, -1);

	return !dir_ndents(dir_ii) ? finalize_htree(d_ctx) : 0;
}

static int erase_dentry(struct voluta_dir_ctx *d_ctx,
                        const struct voluta_dir_entry_info *dei)
{
	int err;

	ii_incref(d_ctx->child_ii);
	err = do_erase_dentry(d_ctx, dei);
	ii_decref(d_ctx->child_ii);
	return err;
}

static int check_and_lookup_by_name(struct voluta_dir_ctx *d_ctx,
                                    struct voluta_dir_entry_info *dei)
{
	int err;

	err = check_dir_and_name(d_ctx);
	if (err) {
		return err;
	}
	err = lookup_by_name(d_ctx, dei);
	if (err) {
		return err;
	}
	return 0;
}
static int stage_child_by_de(struct voluta_dir_ctx *d_ctx,
                             const struct voluta_dir_entry_info *dei)
{
	int err;
	const ino_t ino = dei->ino_dt.ino;

	vi_incref(dei->vi);
	err = fetch_inode(d_ctx, ino, &d_ctx->child_ii);
	vi_decref(dei->vi);

	return err;
}

static int do_remove_dentry(struct voluta_dir_ctx *d_ctx)
{
	int err;
	struct voluta_dir_entry_info dei;

	err = check_and_lookup_by_name(d_ctx, &dei);
	if (err) {
		return err;
	}
	err = stage_child_by_de(d_ctx, &dei);
	if (err) {
		return err;
	}
	err = erase_dentry(d_ctx, &dei);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_remove_dentry(const struct voluta_oper *op,
                         struct voluta_inode_info *dir_ii,
                         const struct voluta_qstr *name)
{
	int err;
	struct voluta_dir_ctx d_ctx = {
		.sbi = ii_sbi(dir_ii),
		.op = op,
		.dir_ii = unconst_ii(dir_ii),
		.name = name
	};

	ii_incref(dir_ii);
	err = do_remove_dentry(&d_ctx);
	ii_decref(dir_ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_node_index(size_t node_index, bool has_tree)
{
	int err;

	if (has_tree) {
		err = index_isvalid(node_index) ? 0 : -EFSCORRUPTED;
	} else {
		err = index_isnull(node_index) ? 0 : -EFSCORRUPTED;
	}
	return err;
}

static int verify_dir_root(const struct voluta_inode *inode)
{
	int err;
	loff_t root_off;
	const struct voluta_dir_ispec *dis = dis_of(inode);

	root_off = dis_htree_root(dis);
	err = voluta_verify_off(root_off);
	if (err) {
		return err;
	}
	err = verify_node_index(dis_last_index(dis), !off_isnull(root_off));
	if (err) {
		return err;
	}
	return 0;
}

int voluta_verify_dir_inode(const struct voluta_inode *inode)
{
	int err;

	/* TODO: Check more */
	err = verify_dir_root(inode);
	if (err) {
		return err;
	}
	return 0;
}

static int verify_childs_of(const struct voluta_dir_htnode *htn)
{
	int err;
	struct voluta_vaddr vaddr;

	for (size_t i = 0; i < ARRAY_SIZE(htn->dh_child); ++i) {
		htn_child(htn, i, &vaddr);
		if (vaddr_isnull(&vaddr)) {
			continue;
		}
		err = voluta_verify_off(vaddr.off);
		if (err) {
			return err;
		}
		if (!vtype_isequal(vaddr.vtype, VOLUTA_VTYPE_HTNODE)) {
			return -EFSCORRUPTED;
		}
	}
	return 0;
}

static int verify_dirents_of(const struct voluta_dir_htnode *htn)
{
	return de_verify(htn_begin(htn), htn_end(htn));
}

int voluta_verify_dir_htree_node(const struct voluta_dir_htnode *htn)
{
	int err;

	err = voluta_verify_ino(htn_ino(htn));
	if (err) {
		return err;
	}
	err = voluta_verify_off(htn_parent(htn));
	if (err) {
		return err;
	}
	err = verify_node_index(htn_node_index(htn), true);
	if (err) {
		return err;
	}
	err = verify_childs_of(htn);
	if (err) {
		return err;
	}
	err = verify_dirents_of(htn);
	if (err) {
		return err;
	}
	return 0;
}
