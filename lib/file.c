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
#include <linux/falloc.h>
#include <linux/fiemap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include "libvoluta.h"

#define STATICASSERT_NELEMS(x, y) \
	VOLUTA_STATICASSERT_EQ(VOLUTA_ARRAY_SIZE(x), y)

#define OP_READ         (1 << 0)
#define OP_WRITE        (1 << 1)
#define OP_TRUNC        (1 << 2)
#define OP_FALLOC       (1 << 3)
#define OP_FIEMAP       (1 << 4)
#define OP_LSEEK        (1 << 5)
#define OP_COPY_RANGE   (1 << 6)


struct voluta_filenode_ref {
	struct voluta_vnode_info *parent;
	struct voluta_vaddr vaddr;
	size_t slot;
	loff_t file_pos;
};

struct voluta_file_ctx {
	const struct voluta_oper *op;
	struct voluta_sb_info    *sbi;
	struct voluta_inode_info *ii;
	struct voluta_rwiter_ctx *rwi_ctx;
	struct fiemap *fm;
	size_t  len;
	loff_t  beg;
	loff_t  off;
	loff_t  end;
	int     op_mask;
	int     fl_mode;
	int     fm_flags;
	int     fm_stop;
	int     cp_flags;
	int     whence;
};

static bool fl_keep_size(const struct voluta_file_ctx *f_ctx);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_vaddr *vaddr_none(void)
{
	return &voluta_vaddr_none;
}

static ssize_t data_size_of(enum voluta_vtype vtype)
{
	return vtype_ssize(vtype);
}

static loff_t off_to_bk(loff_t off)
{
	return off_align(off, VOLUTA_BK_SIZE);
}

static loff_t off_in_data(loff_t off, enum voluta_vtype vtype)
{
	const ssize_t len = data_size_of(vtype);

	return off % len;
}

static loff_t off_max3(loff_t off1, loff_t off2, loff_t off3)
{
	return off_max(off_max(off1, off2), off3);
}

static size_t len_to_next(loff_t off, enum voluta_vtype vtype)
{
	const ssize_t len = data_size_of(vtype);
	const loff_t next = off_next(off, len);

	return off_ulen(off, next);
}

static size_t len_of_data(loff_t off, loff_t end, enum voluta_vtype vtype)
{
	const ssize_t len = data_size_of(vtype);
	const loff_t next = off_next(off, len);

	return (next < end) ? off_ulen(off, next) : off_ulen(off, end);
}

static bool off_is_inrange(loff_t off, loff_t beg, loff_t end)
{
	return (beg <= off) && (off < end);
}

static bool off_is_partial(loff_t off, loff_t end, enum voluta_vtype vtype)
{
	const ssize_t len = data_size_of(vtype);
	const ssize_t io_len = off_len(off, end);
	const loff_t off_start = off_align(off, len);

	return (off != off_start) || (io_len < len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vtype_isrtnode(enum voluta_vtype vtype)
{
	return vtype_isequal(vtype, VOLUTA_VTYPE_RTNODE);
}

static bool vaddr_isrtnode(const struct voluta_vaddr *vaddr)
{
	return vtype_isrtnode(vaddr->vtype);
}

static void vaddr_of_rtnode(struct voluta_vaddr *vaddr, loff_t off)
{
	vaddr_setup(vaddr, VOLUTA_VTYPE_RTNODE, off);
}

static void vaddr_of_databk_leaf(struct voluta_vaddr *vaddr, loff_t off)
{
	vaddr_setup(vaddr, VOLUTA_VTYPE_DATABK, off);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *nil_bk_buf_of(const struct voluta_file_ctx *f_ctx)
{
	struct voluta_block *nil_bk = f_ctx->sbi->sb_cache->c_nil_bk;

	return nil_bk->u.bk;
}

static int xiovec_by_qalloc(const struct voluta_file_ctx *f_ctx,
			    void *bk_start, loff_t off_in_bk, size_t len,
			    struct voluta_xiovec *out_xiov)
{
	uint8_t *qamem = (uint8_t *)bk_start + off_in_bk;
	const struct voluta_qalloc *qalloc = f_ctx->sbi->sb_qalloc;

	return voluta_qalloc_xiovec(qalloc, qamem, len, out_xiov);
}

static int xiovec_by_pstore(const struct voluta_file_ctx *f_ctx,
			    loff_t bk_start, loff_t off_in_bk, size_t len,
			    struct voluta_xiovec *out_xiov)
{
	const loff_t ps_off = bk_start + off_in_bk;
	const struct voluta_pstore *pstore = f_ctx->sbi->sb_pstore;

	return voluta_pstore_xiovec(pstore, ps_off, len, out_xiov);
}

static int xiovec_of_vnode(const struct voluta_file_ctx *f_ctx,
			   struct voluta_vnode_info *vi,
			   struct voluta_xiovec *out_xiov)
{
	int err;
	void *dat = vi_dat_of(vi);
	const enum voluta_vtype vtype = vi_vtype(vi);
	const loff_t oib = off_in_data(f_ctx->off, vtype);
	const size_t len = len_of_data(f_ctx->off, f_ctx->end, vtype);

	err = xiovec_by_qalloc(f_ctx, dat, oib, len, out_xiov);
	if (!err) {
		vi_incref(vi);
		out_xiov->cookie = unconst(vi);
	}
	return err;
}

static int xiovec_of_data(const struct voluta_file_ctx *f_ctx,
			  loff_t bk_start, loff_t off_in_bk, size_t len,
			  struct voluta_xiovec *out_xiov)
{
	return xiovec_by_pstore(f_ctx, bk_start, off_in_bk, len, out_xiov);
}

static int xiovec_of_vaddr(const struct voluta_file_ctx *f_ctx,
			   const struct voluta_vaddr *vaddr,
			   struct voluta_xiovec *out_xiov)
{
	const enum voluta_vtype vtype = vaddr->vtype;
	const loff_t oid = off_in_data(f_ctx->off, vtype);
	const size_t len = len_of_data(f_ctx->off, f_ctx->end, vtype);

	return xiovec_of_data(f_ctx, vaddr->off, oid, len, out_xiov);
}

static int xiovec_of_zeros(const struct voluta_file_ctx *f_ctx,
			   const enum voluta_vtype vtype,
			   struct voluta_xiovec *out_xiov)
{
	void *buf = nil_bk_buf_of(f_ctx);
	const size_t len = len_of_data(f_ctx->off, f_ctx->end, vtype);

	voluta_assert_le(len, VOLUTA_BK_SIZE);
	return xiovec_by_qalloc(f_ctx, buf, 0, len, out_xiov);
}

static int xiovec_copy_into(const struct voluta_xiovec *xiov, void *buf)
{
	int err = 0;

	if (xiov->base != NULL) {
		memcpy(buf, xiov->base, xiov->len);
	} else {
		err = voluta_sys_preadn(xiov->fd, buf, xiov->len, xiov->off);
	}
	return err;
}

static int xiovec_copy_from(const struct voluta_xiovec *xiov, const void *buf)
{
	int err = 0;

	voluta_assert_le(xiov->len, VOLUTA_BK_SIZE);
	if (xiov->base != NULL) {
		memcpy(xiov->base, buf, xiov->len);
	} else {
		err = voluta_sys_pwriten(xiov->fd, buf, xiov->len, xiov->off);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t rtn_ino(const struct voluta_radix_tnode *rtn)
{
	return ino_to_cpu(rtn->r_ino);
}

static void rtn_set_ino(struct voluta_radix_tnode *rtn, ino_t ino)
{
	rtn->r_ino = cpu_to_ino(ino);
}

static loff_t rtn_beg(const struct voluta_radix_tnode *rtn)
{
	return off_to_cpu(rtn->r_beg);
}

static void rtn_set_beg(struct voluta_radix_tnode *rtn, loff_t beg)
{
	rtn->r_beg = cpu_to_off(beg);
}

static loff_t rtn_end(const struct voluta_radix_tnode *rtn)
{
	return off_to_cpu(rtn->r_end);
}

static void rtn_set_end(struct voluta_radix_tnode *rtn, loff_t end)
{
	rtn->r_end = cpu_to_off(end);
}

static size_t rtn_nchilds_max(const struct voluta_radix_tnode *rtn)
{
	return ARRAY_SIZE(rtn->r_child);
}

static ssize_t rtn_span(const struct voluta_radix_tnode *rtn)
{
	return off_len(rtn_beg(rtn), rtn_end(rtn));
}

static size_t rtn_height(const struct voluta_radix_tnode *rtn)
{
	return rtn->r_height;
}

static void rtn_set_height(struct voluta_radix_tnode *rtn, size_t height)
{
	voluta_assert_le(height, VOLUTA_FILE_HEIGHT_MAX);
	rtn->r_height = (uint8_t)height;
}

static bool rtn_isbottom(const struct voluta_radix_tnode *rtn)
{
	const size_t height = rtn_height(rtn);

	voluta_assert_gt(height, 1);
	voluta_assert_le(height, VOLUTA_FILE_HEIGHT_MAX);

	return (height == 2);
}

static size_t rtn_nbytes_per_slot(const struct voluta_radix_tnode *rtn)
{
	return (size_t)rtn_span(rtn) / rtn_nchilds_max(rtn);
}

static size_t
rtn_slot_by_file_pos(const struct voluta_radix_tnode *rtn, loff_t file_pos)
{
	loff_t roff;
	size_t slot;
	const loff_t span = rtn_span(rtn);
	const size_t nslots = rtn_nchilds_max(rtn);

	roff = off_diff(rtn_beg(rtn), file_pos);
	slot = (size_t)((roff * (long)nslots) / span);

	return slot;
}

static size_t
rtn_height_by_file_pos(const struct voluta_radix_tnode *rtn, loff_t off)
{
	size_t height = 1;
	loff_t xlba = off / VOLUTA_FILE_TREE_LEAF_SIZE;
	const size_t fm_shift = VOLUTA_FILE_MAP_SHIFT;

	STATICASSERT_NELEMS(rtn->r_child, VOLUTA_FILE_TREE_NCHILDS);

	/* TODO: count bits */
	while (xlba > 0) {
		height += 1;
		xlba = (xlba >> fm_shift);
	}
	return height;
}

static loff_t rtn_child(const struct voluta_radix_tnode *rtn, size_t slot)
{
	const struct voluta_vaddr56 *va = &rtn->r_child[slot];

	return voluta_vaddr56_parse(va);
}

static void rtn_set_child(struct voluta_radix_tnode *rtn,
			  size_t slot, loff_t off)
{
	struct voluta_vaddr56 *va = &rtn->r_child[slot];

	voluta_vaddr56_set(va, off);
}

static void rtn_reset_child(struct voluta_radix_tnode *rtn, size_t slot)
{
	rtn_set_child(rtn, slot, VOLUTA_OFF_NULL);
}

static bool rtn_isinrange(const struct voluta_radix_tnode *rtn, loff_t pos)
{
	return off_is_inrange(pos, rtn_beg(rtn), rtn_end(rtn));
}

static loff_t
rtn_span_by_height(const struct voluta_radix_tnode *rtn, size_t height)
{
	loff_t span = 0;
	const loff_t bk_size = VOLUTA_FILE_TREE_LEAF_SIZE;
	const size_t fm_shift = VOLUTA_FILE_MAP_SHIFT;
	const size_t height_max = VOLUTA_FILE_HEIGHT_MAX;

	voluta_assert_eq(1L << fm_shift, rtn_nchilds_max(rtn));

	if (likely((height > 1) && (height <= height_max))) {
		span = (bk_size << ((height - 1) * fm_shift));
	}
	return likely(span) ? span : LONG_MAX; /* make clang-scan happy */
}

static void rtn_calc_range(const struct voluta_radix_tnode *rtn,
			   loff_t off, size_t height, loff_t *beg, loff_t *end)
{
	const loff_t span = rtn_span_by_height(rtn, height);

	*beg = off_align(off, span);
	*end = *beg + span;
}

static loff_t rtn_file_pos(const struct voluta_radix_tnode *rtn, size_t slot)
{
	loff_t next_off;
	const size_t nbps = rtn_nbytes_per_slot(rtn);

	next_off = off_end(rtn_beg(rtn), slot * nbps);
	return off_to_bk(next_off);
}

static loff_t
rtn_next_file_pos(const struct voluta_radix_tnode *rtn, size_t slot)
{
	loff_t file_pos;
	const size_t nbps = rtn_nbytes_per_slot(rtn);

	file_pos = rtn_file_pos(rtn, slot);
	return off_end(file_pos, nbps);
}

static void rtn_clear_childs(struct voluta_radix_tnode *rtn)
{
	const size_t nslots_max = rtn_nchilds_max(rtn);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		rtn_reset_child(rtn, slot);
	}
}

static void rtn_init(struct voluta_radix_tnode *rtn,
		     ino_t ino, loff_t off, size_t height)
{
	loff_t beg = 0;
	loff_t end = 0;

	rtn_calc_range(rtn, off, height, &beg, &end);
	rtn_set_ino(rtn, ino);
	rtn_set_beg(rtn, beg);
	rtn_set_end(rtn, end);
	rtn_set_height(rtn, height);
	rtn_clear_childs(rtn);
	voluta_memzero(rtn->r_zeros, sizeof(rtn->r_zeros));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_reg_ispec *ris_of(const struct voluta_inode *inode)
{
	const struct voluta_reg_ispec *ris = &inode->i_s.r;

	return unconst(ris);
}

static void ris_head_leaf(const struct voluta_reg_ispec *ris, size_t slot,
			  struct voluta_vaddr *vaddr)
{
	voluta_assert_lt(slot, ARRAY_SIZE(ris->r_head_leaf));

	voluta_vaddr64_parse(&ris->r_head_leaf[slot], vaddr);
}

static void ris_set_head_leaf(struct voluta_reg_ispec *ris, size_t slot,
			      const struct voluta_vaddr *vaddr)
{
	voluta_assert_lt(slot, ARRAY_SIZE(ris->r_head_leaf));

	voluta_vaddr64_set(&ris->r_head_leaf[slot], vaddr);
}

static size_t ris_num_head_leaves(const struct voluta_reg_ispec *ris)
{
	return ARRAY_SIZE(ris->r_head_leaf);
}

static void ris_tree_root(const struct voluta_reg_ispec *ris,
			  struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_parse(&ris->r_tree_root, vaddr);
}

static void ris_set_tree_root(struct voluta_reg_ispec *ris,
			      const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&ris->r_tree_root, vaddr);
}

static void ris_setup(struct voluta_reg_ispec *ris)
{
	size_t nhead_leaves;

	nhead_leaves = ris_num_head_leaves(ris);
	for (size_t i = 0; i < nhead_leaves; ++i) {
		ris_set_head_leaf(ris, i, vaddr_none());
	}
	ris_set_tree_root(ris, vaddr_none());
}

static struct voluta_reg_ispec *ii_ris_of(const struct voluta_inode_info *ii)
{
	return ris_of(ii->inode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fnref_init(struct voluta_filenode_ref *fnr, loff_t file_pos)
{
	vaddr_reset(&fnr->vaddr);
	fnr->parent = NULL;
	fnr->slot = UINT_MAX;
	fnr->file_pos = file_pos;
}

static void fnref_setup(struct voluta_filenode_ref *fnr,
			const struct voluta_vaddr *vaddr,
			struct voluta_vnode_info *parent,
			size_t slot, loff_t file_pos)
{
	loff_t leaf_off = 0;

	if (parent != NULL) {
		leaf_off = rtn_file_pos(parent->vu.rtn, slot);
	}
	if (vaddr != NULL) {
		vaddr_copyto(vaddr, &fnr->vaddr);
	} else {
		vaddr_reset(&fnr->vaddr);
	}
	fnr->parent = parent;
	fnr->slot = slot;
	fnr->file_pos = off_max(leaf_off, file_pos);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool isinrange(const struct voluta_vnode_info *vi, loff_t file_pos)
{
	return rtn_isinrange(vi->vu.rtn, file_pos);
}

static bool isbottom(const struct voluta_vnode_info *vi)
{
	return rtn_isbottom(vi->vu.rtn);
}

static size_t height_of(const struct voluta_vnode_info *vi)
{
	return rtn_height(vi->vu.rtn);
}

static size_t nchilds_max(const struct voluta_vnode_info *vi)
{
	return rtn_nchilds_max(vi->vu.rtn);
}

static size_t child_slot_of(const struct voluta_vnode_info *vi, loff_t off)
{
	return rtn_slot_by_file_pos(vi->vu.rtn, off);
}

static void resolve_child_by_slot(const struct voluta_vnode_info *vi,
				  size_t slot, struct voluta_vaddr *vaddr)
{
	loff_t child_off;

	child_off = rtn_child(vi->vu.rtn, slot);
	if (isbottom(vi)) {
		vaddr_of_databk_leaf(vaddr, child_off);
	} else {
		vaddr_of_rtnode(vaddr, child_off);
	}
}

static void assign_child_by_pos(struct voluta_vnode_info *vi, loff_t file_pos,
				const struct voluta_vaddr *vaddr)
{
	size_t child_slot;

	child_slot = child_slot_of(vi, file_pos);
	rtn_set_child(vi->vu.rtn, child_slot, vaddr->off);
}

static void resolve_child_at(struct voluta_vnode_info *vi,
			     loff_t file_pos, size_t slot,
			     struct voluta_filenode_ref *fnr)
{
	struct voluta_vaddr vaddr;

	resolve_child_by_slot(vi, slot, &vaddr);
	fnref_setup(fnr, &vaddr, vi, slot, file_pos);
}

static void resolve_child(struct voluta_vnode_info *vi, loff_t file_pos,
			  struct voluta_filenode_ref *fnr)
{
	size_t child_slot;

	if (vi != NULL) {
		child_slot = child_slot_of(vi, file_pos);
		resolve_child_at(vi, file_pos, child_slot, fnr);
	} else {
		fnref_init(fnr, file_pos);
	}
}

static void bind_child(struct voluta_vnode_info *parent_vi, loff_t file_pos,
		       const struct voluta_vaddr *vaddr)
{
	assign_child_by_pos(parent_vi, file_pos, vaddr);
	vi_dirtify(parent_vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void file_tree_setup(struct voluta_inode_info *ii)
{
	ris_setup(ii_ris_of(ii));
}

static void file_head_leaf(const struct voluta_inode_info *ii, size_t slot,
			   struct voluta_vaddr *out_vaddr)
{
	const struct voluta_reg_ispec *ris = ii_ris_of(ii);

	ris_head_leaf(ris, slot, out_vaddr);
}

static void file_set_head_leaf(struct voluta_inode_info *ii, size_t slot,
			       const struct voluta_vaddr *vaddr)
{
	struct voluta_reg_ispec *ris = ii_ris_of(ii);

	ris_set_head_leaf(ris, slot, vaddr);
}

static size_t head_leaf_slot_of(const struct voluta_file_ctx *f_ctx)
{
	size_t slot;
	const loff_t off = f_ctx->off;
	const size_t slot_size = VOLUTA_FILE_HEAD_LEAF_SIZE;

	voluta_assert_lt(off, VOLUTA_BK_SIZE);
	slot = (size_t)off / slot_size;

	voluta_assert_lt(slot, VOLUTA_FILE_HEAD_NLEAVES);
	return slot;
}

static void head_leaf_at(const struct voluta_file_ctx *f_ctx, size_t slot,
			 struct voluta_vaddr *out_vaddr)
{
	file_head_leaf(f_ctx->ii, slot, out_vaddr);
}

static void
resolve_head_leaf(const struct voluta_file_ctx *f_ctx,
		  size_t *out_slot, struct voluta_vaddr *out_vaddr)
{
	*out_slot = head_leaf_slot_of(f_ctx);
	head_leaf_at(f_ctx, *out_slot, out_vaddr);
}

static void set_head_leaf_at(const struct voluta_file_ctx *f_ctx,
			     size_t slot, const struct voluta_vaddr *vaddr)
{
	file_set_head_leaf(f_ctx->ii, slot, vaddr);
}

static void set_head_leaf_of(const struct voluta_file_ctx *f_ctx,
			     const struct voluta_vaddr *vaddr)
{
	set_head_leaf_at(f_ctx, head_leaf_slot_of(f_ctx), vaddr);
}

static void file_tree_root(const struct voluta_inode_info *ii,
			   struct voluta_vaddr *out_vaddr)
{
	ris_tree_root(ii_ris_of(ii), out_vaddr);
}

static void tree_root_of(const struct voluta_file_ctx *f_ctx,
			 struct voluta_vaddr *out_vaddr)
{
	file_tree_root(f_ctx->ii, out_vaddr);
}

static bool has_tree_root(const struct voluta_file_ctx *f_ctx)
{
	struct voluta_vaddr vaddr;

	tree_root_of(f_ctx, &vaddr);
	return vaddr_isrtnode(&vaddr);
}

static void file_tree_update(struct voluta_inode_info *ii,
			     const struct voluta_vaddr *vaddr)
{
	ris_set_tree_root(ii_ris_of(ii), vaddr);
}

static void set_tree_root_of(const struct voluta_file_ctx *f_ctx,
			     const struct voluta_vaddr *vaddr)
{
	file_tree_update(f_ctx->ii, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void advance_to(struct voluta_file_ctx *f_ctx, loff_t off)
{
	f_ctx->off = off_max_min(f_ctx->off, off, f_ctx->end);
}

static void advance_by_nbytes(struct voluta_file_ctx *f_ctx, size_t len)
{
	advance_to(f_ctx, off_end(f_ctx->off, len));
}

static void advance_to_next_head_leaf(struct voluta_file_ctx *f_ctx)
{
	advance_by_nbytes(f_ctx, len_to_next(f_ctx->off, VOLUTA_VTYPE_DATA4K));
}

static void advance_to_next_tree_leaf(struct voluta_file_ctx *f_ctx)
{
	advance_by_nbytes(f_ctx, len_to_next(f_ctx->off, VOLUTA_VTYPE_DATABK));
}

static void
advance_to_tree_slot(struct voluta_file_ctx *f_ctx,
		     const struct voluta_vnode_info *vi, size_t slot)
{
	advance_to(f_ctx, rtn_file_pos(vi->vu.rtn, slot));
}

static void
advance_to_next_tree_slot(struct voluta_file_ctx *f_ctx,
			  const struct voluta_vnode_info *vi, size_t slot)
{
	advance_to(f_ctx, rtn_next_file_pos(vi->vu.rtn, slot));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t io_length(const struct voluta_file_ctx *f_ctx)
{
	return off_ulen(f_ctx->beg, f_ctx->off);
}

static bool has_more_io(const struct voluta_file_ctx *f_ctx)
{
	return (f_ctx->off < f_ctx->end) && !f_ctx->fm_stop;
}

static loff_t head_off_end(size_t slot)
{
	const size_t leaf_size = VOLUTA_FILE_HEAD_LEAF_SIZE;

	return off_end(0, (slot + 1) * leaf_size);
}

static loff_t head_off_max(void)
{
	return head_off_end(VOLUTA_FILE_HEAD_NLEAVES - 1);
}

static bool off_is_head(loff_t off)
{
	return off_is_inrange(off, 0, head_off_max());
}

static bool has_head_leaves_io(const struct voluta_file_ctx *f_ctx)
{
	return has_more_io(f_ctx) && off_is_head(f_ctx->off);
}

static bool has_partial_write_at(const struct voluta_file_ctx *f_ctx,
				 const struct voluta_vaddr *vaddr)
{
	return off_is_partial(f_ctx->off, f_ctx->end, vaddr->vtype);
}

static enum voluta_vtype off_to_data_vtype(loff_t off)
{
	return (off < head_off_max()) ?
	       VOLUTA_VTYPE_DATA4K : VOLUTA_VTYPE_DATABK;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_reg(const struct voluta_inode_info *ii)
{
	if (ii_isdir(ii)) {
		return -EISDIR;
	}
	if (!ii_isreg(ii)) {
		return -EINVAL;
	}
	return 0;
}

static int check_isopen(const struct voluta_inode_info *ii)
{
	return ii->i_nopen ? 0 : -EBADF;
}

static int check_range(loff_t off, size_t len)
{
	const loff_t llen = (loff_t)len;
	const loff_t fsz_max = VOLUTA_FILE_SIZE_MAX;

	if (off < 0) {
		return -EINVAL;
	}
	if (off > fsz_max) {
		return -EFBIG;
	}
	if (llen > fsz_max) {
		return -EINVAL;
	}
	return 0;
}

static int check_seek_pos(loff_t pos, loff_t isz, int whence)
{
	if ((whence == SEEK_DATA) || (whence == SEEK_HOLE)) {
		if (pos >= isz) {
			return -ENXIO;
		}
	}
	return 0;
}

static int check_file_io(const struct voluta_file_ctx *f_ctx)
{
	int err;
	loff_t isz;
	const size_t iosize_max = VOLUTA_IO_SIZE_MAX;

	err = check_reg(f_ctx->ii);
	if (err) {
		return err;
	}
	err = check_isopen(f_ctx->ii);
	if (err && (f_ctx->op_mask & ~OP_TRUNC)) {
		return err;
	}
	err = check_range(f_ctx->beg, f_ctx->len);
	if (err) {
		return err;
	}
	if (f_ctx->op_mask & (OP_WRITE | OP_FALLOC)) {
		err = check_range(f_ctx->end, 0);
		if (err) {
			return err;
		}
	}
	if (f_ctx->op_mask & (OP_READ | OP_WRITE)) {
		if (f_ctx->len > iosize_max) {
			return -EINVAL;
		}
		if (!f_ctx->rwi_ctx) {
			return -EINVAL;
		}
	}
	if (f_ctx->op_mask & OP_LSEEK) {
		isz = ii_size(f_ctx->ii);
		err = check_seek_pos(f_ctx->off, isz, f_ctx->whence);
		if (err) {
			return err;
		}
	}
	if (f_ctx->op_mask & OP_COPY_RANGE) {
		if (f_ctx->cp_flags != 0) {
			return -EINVAL;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int seek_tree_recursive(struct voluta_file_ctx *f_ctx,
			       struct voluta_vnode_info *parent_vi,
			       struct voluta_filenode_ref *fnr);

static bool kcopy_mode(const struct voluta_file_ctx *f_ctx)
{
	const long unsigned flags = f_ctx->sbi->sb_ctl_flags;
	const long unsigned mask = VOLUTA_F_ENCRYPT | VOLUTA_F_SPLICED;

	return ((flags & mask) == VOLUTA_F_SPLICED);
}

static bool is_mapping_boundaries(const struct voluta_file_ctx *f_ctx)
{
	const loff_t mapping_size =
		(VOLUTA_FILE_TREE_LEAF_SIZE * VOLUTA_FILE_TREE_NCHILDS);

	return ((f_ctx->off % mapping_size) == 0);
}

static void post_io_update(const struct voluta_file_ctx *f_ctx, bool killprv)
{
	struct voluta_iattr iattr;
	struct voluta_inode_info *ii = f_ctx->ii;
	const loff_t isz = ii_size(ii);
	const loff_t off = f_ctx->off;
	const size_t len = io_length(f_ctx);

	iattr_setup(&iattr, ii_ino(ii));
	if (f_ctx->op_mask & OP_READ) {
		iattr.ia_flags |= VOLUTA_IATTR_ATIME | VOLUTA_IATTR_LAZY;
	} else if (f_ctx->op_mask & OP_FALLOC) {
		iattr.ia_flags |= VOLUTA_IATTR_MCTIME;
		if (!fl_keep_size(f_ctx)) {
			iattr.ia_flags |= VOLUTA_IATTR_SIZE;
			iattr.ia_size = off_max(off, isz);
		}
	} else if (f_ctx->op_mask & OP_WRITE) {
		iattr.ia_flags |= VOLUTA_IATTR_SIZE;
		iattr.ia_size = off_max(off, isz);
		if (len > 0) {
			iattr.ia_flags |= VOLUTA_IATTR_MCTIME;
			if (killprv) {
				iattr.ia_flags |= VOLUTA_IATTR_KILL_PRIV;
			}
		}
	} else if (f_ctx->op_mask & OP_TRUNC) {
		iattr.ia_flags |= VOLUTA_IATTR_SIZE;
		iattr.ia_size = f_ctx->beg;
		if (isz != f_ctx->beg) {
			iattr.ia_flags |= VOLUTA_IATTR_MCTIME;
			if (killprv) {
				iattr.ia_flags |= VOLUTA_IATTR_KILL_PRIV;
			}
		}
	}
	update_iattrs(f_ctx->op, ii, &iattr);
}

static int probe_unwritten_at(const struct voluta_file_ctx *f_ctx,
			      const struct voluta_vaddr *vaddr, bool *out_res)
{
	int err = 0;

	*out_res = false;
	if (!vaddr_isnull(vaddr)) {
		err = voluta_probe_unwritten(f_ctx->sbi, vaddr, out_res);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dirtify_data_leaf(const struct voluta_file_ctx *f_ctx,
			      struct voluta_vnode_info *leaf_vi)
{
	struct voluta_vnode_info *agm_vi = leaf_vi->v_pvi;

	voluta_assert_not_null(agm_vi);
	voluta_assert_eq(agm_vi->vaddr.vtype, VOLUTA_VTYPE_AGMAP);
	voluta_assert(vaddr_isdata(vi_vaddr(leaf_vi)));

	vi_dirtify(leaf_vi);
	if (!kcopy_mode(f_ctx)) {
		vi_dirtify(agm_vi); /* for data checksum */
	}
}

static void zero_data_leaf_sub(const struct voluta_file_ctx *f_ctx,
			       struct voluta_vnode_info *vi,
			       loff_t off_in_db, size_t len)
{
	struct voluta_data_block *db = vi->vu.db;

	voluta_assert_ge(off_in_db, 0);
	voluta_assert_lt(off_in_db, sizeof(db->dat));
	voluta_assert_le(off_in_db + (long)len, sizeof(db->dat));

	voluta_memzero(&db->dat[off_in_db], len);
	dirtify_data_leaf(f_ctx, vi);
}

static int zero_tree_leaf_range(const struct voluta_file_ctx *f_ctx,
				const struct voluta_vaddr *vaddr,
				loff_t off_in_bk, size_t len)
{
	int err;
	struct voluta_vnode_info *vi;
	struct voluta_xiovec xiov = { .base = NULL };

	if (kcopy_mode(f_ctx)) {
		err = xiovec_of_data(f_ctx, vaddr->off, off_in_bk, len, &xiov);
		if (err) {
			return err;
		}
		err = xiovec_copy_from(&xiov, nil_bk_buf_of(f_ctx));
		if (err) {
			return err;
		}
	} else {
		err = voluta_stage_data(f_ctx->sbi, vaddr, f_ctx->ii, &vi);
		if (err) {
			return err;
		}
		zero_data_leaf_sub(f_ctx, vi, off_in_bk, len);
	}
	return 0;
}

static int zero_tree_leaf_at(const struct voluta_file_ctx *f_ctx,
			     const struct voluta_vaddr *vaddr)
{
	const ssize_t len = data_size_of(vaddr->vtype);

	return zero_tree_leaf_range(f_ctx, vaddr, 0, (size_t)len);
}

static int stage_data_leaf(const struct voluta_file_ctx *f_ctx,
			   const struct voluta_vaddr *vaddr,
			   struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	voluta_assert(!kcopy_mode(f_ctx));

	*out_vi = NULL;
	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	err = voluta_stage_data(f_ctx->sbi, vaddr, f_ctx->ii, &vi);
	if (err) {
		return err;
	}
	*out_vi = vi;
	return 0;
}

static int stage_radix_tnode(const struct voluta_file_ctx *f_ctx,
			     const struct voluta_vaddr *vaddr,
			     struct voluta_vnode_info **out_vi)
{
	int err;

	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	err = voluta_fetch_vnode(f_ctx->sbi, vaddr, f_ctx->ii, out_vi);
	if (err) {
		return err;
	}
	voluta_assert_ge(rtn_height((*out_vi)->vu.rtn), 2);
	return 0;
}

static int stage_tree_root(const struct voluta_file_ctx *f_ctx,
			   struct voluta_vnode_info **out_vi)
{
	struct voluta_vaddr root_vaddr;

	tree_root_of(f_ctx, &root_vaddr);
	return stage_radix_tnode(f_ctx, &root_vaddr, out_vi);
}

static size_t iter_start_slot(const struct voluta_file_ctx *f_ctx,
			      const struct voluta_vnode_info *parent_vi)
{
	return child_slot_of(parent_vi, f_ctx->off);
}

static bool is_seek_data(const struct voluta_file_ctx *f_ctx)
{
	return (f_ctx->whence == SEEK_DATA);
}

static bool is_seek_hole(const struct voluta_file_ctx *f_ctx)
{
	return (f_ctx->whence == SEEK_HOLE);
}

static int seek_data_by_tree_leaves(struct voluta_file_ctx *f_ctx,
				    struct voluta_vnode_info *parent_vi,
				    struct voluta_filenode_ref *fnr)
{
	size_t start_slot;
	const size_t nslots_max = nchilds_max(parent_vi);

	start_slot = iter_start_slot(f_ctx, parent_vi);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		advance_to_tree_slot(f_ctx, parent_vi, slot);

		resolve_child_at(parent_vi, f_ctx->off, slot, fnr);
		if (!vaddr_isnull(&fnr->vaddr)) {
			return 0;
		}
	}
	return -ENOENT;
}

static int seek_hole_by_tree_leaves(struct voluta_file_ctx *f_ctx,
				    struct voluta_vnode_info *parent_vi,
				    struct voluta_filenode_ref *fnr)
{
	size_t start_slot;
	const size_t nslots_max = nchilds_max(parent_vi);

	start_slot = iter_start_slot(f_ctx, parent_vi);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		advance_to_tree_slot(f_ctx, parent_vi, slot);

		resolve_child_at(parent_vi, f_ctx->off, slot, fnr);
		if (vaddr_isnull(&fnr->vaddr)) {
			return 0;
		}
	}
	return -ENOENT;
}

static int seek_tree_bottom(struct voluta_file_ctx *f_ctx,
			    struct voluta_vnode_info *parent_vi,
			    struct voluta_filenode_ref *fnr)
{
	return is_seek_hole(f_ctx) ?
	       seek_hole_by_tree_leaves(f_ctx, parent_vi, fnr) :
	       seek_data_by_tree_leaves(f_ctx, parent_vi, fnr);
}

static int seek_tree_recursive_at(struct voluta_file_ctx *f_ctx,
				  struct voluta_vnode_info *parent_vi,
				  size_t slot, struct voluta_filenode_ref *fnr)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi;

	resolve_child_by_slot(parent_vi, slot, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return -ENOENT;
	}
	err = stage_radix_tnode(f_ctx, &vaddr, &vi);
	if (err) {
		return err;
	}
	err = seek_tree_recursive(f_ctx, vi, fnr);
	if (err) {
		return err;
	}
	return 0;
}

static int do_seek_tree_recursive(struct voluta_file_ctx *f_ctx,
				  struct voluta_vnode_info *parent_vi,
				  struct voluta_filenode_ref *fnr)
{
	int err;
	size_t start_slot;
	const size_t nslots_max = nchilds_max(parent_vi);

	if (!isinrange(parent_vi, f_ctx->off)) {
		return -ENOENT;
	}
	if (isbottom(parent_vi)) {
		return seek_tree_bottom(f_ctx, parent_vi, fnr);
	}
	err = is_seek_hole(f_ctx) ? 0 : -ENOENT;
	start_slot = child_slot_of(parent_vi, f_ctx->off);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		err = seek_tree_recursive_at(f_ctx, parent_vi, slot, fnr);
		if (err != -ENOENT) {
			break;
		}
		advance_to_next_tree_slot(f_ctx, parent_vi, slot);
	}
	return err;
}

static int seek_tree_recursive(struct voluta_file_ctx *f_ctx,
			       struct voluta_vnode_info *parent_vi,
			       struct voluta_filenode_ref *fnr)
{
	int err;

	vi_incref(parent_vi);
	err = do_seek_tree_recursive(f_ctx, parent_vi, fnr);
	vi_decref(parent_vi);

	return err;
}

static int seek_by_tree_map(struct voluta_file_ctx *f_ctx,
			    struct voluta_filenode_ref *fnr)
{
	int err;
	struct voluta_vnode_info *root_vi;

	if (!has_tree_root(f_ctx)) {
		return -ENOENT;
	}
	err = stage_tree_root(f_ctx, &root_vi);
	if (err) {
		return err;
	}
	fnref_init(fnr, f_ctx->off);
	err = seek_tree_recursive(f_ctx, root_vi, fnr);
	if (err) {
		return err;
	}
	return 0;
}

static int seek_data_by_head_leaves(struct voluta_file_ctx *f_ctx,
				    struct voluta_filenode_ref *fnr)
{
	size_t slot;
	struct voluta_vaddr vaddr;

	while (has_head_leaves_io(f_ctx)) {
		resolve_head_leaf(f_ctx, &slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			fnref_setup(fnr, &vaddr, NULL, slot, f_ctx->off);
			return 0;
		}
		advance_to_next_head_leaf(f_ctx);
	}
	return -ENOENT;
}

static int seek_hole_by_head_leaves(struct voluta_file_ctx *f_ctx,
				    struct voluta_filenode_ref *fnr)
{
	size_t slot;
	struct voluta_vaddr vaddr;

	while (has_head_leaves_io(f_ctx)) {
		resolve_head_leaf(f_ctx, &slot, &vaddr);
		if (vaddr_isnull(&vaddr)) {
			fnref_setup(fnr, NULL, NULL, slot, f_ctx->off);
			return 0;
		}
		advance_to_next_head_leaf(f_ctx);
	}
	return -ENOENT;
}

static int resolve_xiovec(const struct voluta_file_ctx *f_ctx,
			  struct voluta_vnode_info *vi,
			  const struct voluta_vaddr *vaddr,
			  struct voluta_xiovec *out_xiov)
{
	int err;
	enum voluta_vtype vtype;

	if (vi != NULL) {
		err = xiovec_of_vnode(f_ctx, vi, out_xiov);
	} else if ((vaddr != NULL) && !vaddr_isnull(vaddr)) {
		err = xiovec_of_vaddr(f_ctx, vaddr, out_xiov);
	} else {
		vtype = off_to_data_vtype(f_ctx->off);
		err = xiovec_of_zeros(f_ctx, vtype, out_xiov);
	}
	return err;
}

static int call_rw_actor(const struct voluta_file_ctx *f_ctx,
			 struct voluta_vnode_info *vi,
			 const struct voluta_vaddr *vaddr,
			 size_t *out_len)
{
	int err;
	struct voluta_xiovec xiov = {
		.off = -1,
		.len = 0,
		.base = NULL,
		.fd = -1,
		.cookie = NULL
	};

	err = resolve_xiovec(f_ctx, vi, vaddr, &xiov);
	if (err) {
		return err;
	}
	err = f_ctx->rwi_ctx->actor(f_ctx->rwi_ctx, &xiov);
	if (err) {
		return err;
	}
	*out_len = xiov.len;
	return 0;
}

static const struct voluta_vaddr *vi_vaddr2(const struct voluta_vnode_info *vi)
{
	return (vi != NULL) ? vi_vaddr(vi) : NULL;
}

static int export_data_by_vnode(const struct voluta_file_ctx *f_ctx,
				struct voluta_vnode_info *vi,
				size_t *out_size)
{
	return call_rw_actor(f_ctx, vi, vi_vaddr2(vi), out_size);
}

static int export_data_by_vaddr(struct voluta_file_ctx *f_ctx,
				const struct voluta_vaddr *vaddr,
				size_t *out_size)
{
	return call_rw_actor(f_ctx, NULL, vaddr, out_size);
}

static int import_data_by_vnode(const struct voluta_file_ctx *f_ctx,
				struct voluta_vnode_info *vi,
				size_t *out_size)
{
	return call_rw_actor(f_ctx, vi, vi_vaddr2(vi), out_size);
}

static int import_data_by_vaddr(const struct voluta_file_ctx *f_ctx,
				const struct voluta_vaddr *vaddr,
				size_t *out_size)
{
	return call_rw_actor(f_ctx, NULL, vaddr, out_size);
}

static void child_of_current_pos(const struct voluta_file_ctx *f_ctx,
				 struct voluta_vnode_info *parent_vi,
				 struct voluta_filenode_ref *fnr)
{
	resolve_child(parent_vi, f_ctx->off, fnr);
}

static void resolve_tree_leaf(const struct voluta_file_ctx *f_ctx,
			      struct voluta_vnode_info *parent_vi,
			      struct voluta_vaddr *out_vaddr)
{
	struct voluta_filenode_ref fnr;

	child_of_current_pos(f_ctx, parent_vi, &fnr);
	vaddr_copyto(&fnr.vaddr, out_vaddr);
}

static void resolve_curr_node(const struct voluta_file_ctx *f_ctx,
			      struct voluta_vnode_info *parent_vi,
			      struct voluta_vaddr *out_vaddr)
{
	struct voluta_filenode_ref fnr;

	child_of_current_pos(f_ctx, parent_vi, &fnr);
	vaddr_copyto(&fnr.vaddr, out_vaddr);
}

static int stage_by_tree_map(const struct voluta_file_ctx *f_ctx,
			     struct voluta_vnode_info **out_vi)
{
	int err;
	size_t height;
	struct voluta_vnode_info *vi;
	struct voluta_vaddr vaddr = { .off = -1 };

	if (!has_tree_root(f_ctx)) {
		return -ENOENT;
	}
	err = stage_tree_root(f_ctx, &vi);
	if (err) {
		return err;
	}
	if (!isinrange(vi, f_ctx->off)) {
		return -ENOENT;
	}
	height = height_of(vi);
	while (height--) {
		if (isbottom(vi)) {
			*out_vi = vi;
			return 0;
		}
		resolve_curr_node(f_ctx, vi, &vaddr);
		err = stage_radix_tnode(f_ctx, &vaddr, &vi);
		if (err) {
			return err;
		}
	}
	return -EFSCORRUPTED;
}

static int do_read_by_copy_from_leaf(struct voluta_file_ctx *f_ctx,
				     struct voluta_vnode_info *leaf_vi,
				     size_t *out_sz)
{
	return export_data_by_vnode(f_ctx, leaf_vi, out_sz);
}

static int read_leaf_by_copy(struct voluta_file_ctx *f_ctx,
			     struct voluta_vnode_info *leaf_vi,
			     size_t *out_sz)
{
	int err;

	vi_incref(leaf_vi);
	err = do_read_by_copy_from_leaf(f_ctx, leaf_vi, out_sz);
	vi_decref(leaf_vi);

	return err;
}

static int read_leaf_by_vaddr(struct voluta_file_ctx *f_ctx,
			      const struct voluta_vaddr *vaddr,
			      size_t *out_sz)
{
	return export_data_by_vaddr(f_ctx, vaddr, out_sz);
}

static int read_leaf_as_zeros(struct voluta_file_ctx *f_ctx, size_t *out_sz)
{
	return export_data_by_vaddr(f_ctx, NULL, out_sz);
}

static int read_from_leaf(struct voluta_file_ctx *f_ctx,
			  const struct voluta_vaddr *vaddr, size_t *out_len)
{
	int err;
	bool unwritten = false;
	struct voluta_vnode_info *vi = NULL;

	*out_len = 0;
	err = probe_unwritten_at(f_ctx, vaddr, &unwritten);
	if (err) {
		return err;
	}
	if (unwritten) {
		err = read_leaf_as_zeros(f_ctx, out_len);
		if (err) {
			return err;
		}
	} else if (kcopy_mode(f_ctx)) {
		err = read_leaf_by_vaddr(f_ctx, vaddr, out_len);
		if (err) {
			return err;
		}
	} else {
		err = stage_data_leaf(f_ctx, vaddr, &vi);
		if (err && (err != -ENOENT)) {
			return err;
		}
		err = read_leaf_by_copy(f_ctx, vi, out_len);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int do_read_tree_leaves(struct voluta_file_ctx *f_ctx,
			       struct voluta_vnode_info *parent_vi)
{
	int err;
	size_t len;
	struct voluta_vaddr vaddr = { .off = -1 };

	while (has_more_io(f_ctx)) {
		resolve_tree_leaf(f_ctx, parent_vi, &vaddr);
		err = read_from_leaf(f_ctx, &vaddr, &len);
		if (err) {
			return err;
		}
		advance_by_nbytes(f_ctx, len);
		if (is_mapping_boundaries(f_ctx)) {
			break;
		}
	}
	return 0;
}

static int read_tree_leaves(struct voluta_file_ctx *f_ctx,
			    struct voluta_vnode_info *parent_vi)
{
	int err;

	vi_incref(parent_vi);
	err = do_read_tree_leaves(f_ctx, parent_vi);
	vi_decref(parent_vi);

	return err;
}

static int read_by_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_vnode_info *parent_vi;

	while (has_more_io(f_ctx)) {
		parent_vi = NULL;
		err = stage_by_tree_map(f_ctx, &parent_vi);
		if (err && (err != -ENOENT)) {
			return err;
		}
		err = read_tree_leaves(f_ctx, parent_vi);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int read_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	size_t len;
	size_t slot;
	struct voluta_vaddr vaddr;

	while (has_head_leaves_io(f_ctx)) {
		resolve_head_leaf(f_ctx, &slot, &vaddr);
		err = read_from_leaf(f_ctx, &vaddr, &len);
		if (err) {
			return err;
		}
		advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int read_data(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = read_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = read_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

struct voluta_read_iter {
	struct voluta_rwiter_ctx rwi;
	uint8_t *dat;
	size_t dat_len;
	size_t dat_max;
};

static struct voluta_read_iter *
read_iter_of(const struct voluta_rwiter_ctx *rwi)
{
	const struct voluta_read_iter *rdi =
		container_of2(rwi, struct voluta_read_iter, rwi);

	return unconst(rdi);
}

static int read_iter_actor(struct voluta_rwiter_ctx *rwi,
			   const struct voluta_xiovec *xiov)
{
	int err;
	struct voluta_read_iter *rdi = read_iter_of(rwi);

	if ((xiov->fd > 0) && (xiov->off < 0)) {
		return -EINVAL;
	}
	if ((rdi->dat_len + xiov->len) > rdi->dat_max) {
		return -EINVAL;
	}
	err = xiovec_copy_into(xiov, rdi->dat + rdi->dat_len);
	if (err) {
		return err;
	}
	rdi->dat_len += xiov->len;
	return 0;
}

static loff_t rw_iter_end(const struct voluta_rwiter_ctx *rwi)
{
	return off_end(rwi->off, rwi->len);
}

static void update_with_rw_iter(struct voluta_file_ctx *f_ctx,
				struct voluta_rwiter_ctx *rwi_ctx)
{
	const loff_t end = rw_iter_end(rwi_ctx);
	const loff_t isz = ii_size(f_ctx->ii);

	f_ctx->rwi_ctx = rwi_ctx;
	f_ctx->len = rwi_ctx->len;
	f_ctx->beg = rwi_ctx->off;
	f_ctx->off = rwi_ctx->off;
	if (f_ctx->op_mask & OP_READ) {
		f_ctx->end = off_min(end, isz);
	} else {
		f_ctx->end = end;
	}
}

static int do_read_iter(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = read_data(f_ctx);
	post_io_update(f_ctx, false);
	return err;
}

int voluta_do_read_iter(const struct voluta_oper *op,
			struct voluta_inode_info *ii,
			struct voluta_rwiter_ctx *rwi)
{
	int err;
	struct voluta_file_ctx f_ctx = {
		.op = op,
		.sbi = ii_sbi(ii),
		.ii = ii,
		.op_mask = OP_READ
	};

	update_with_rw_iter(&f_ctx, rwi);

	ii_incref(ii);
	err = do_read_iter(&f_ctx);
	ii_decref(ii);

	return err;
}

int voluta_do_read(const struct voluta_oper *op,
		   struct voluta_inode_info *ii,
		   void *buf, size_t len, loff_t off, size_t *out_len)
{
	int err;
	struct voluta_read_iter rdi = {
		.dat_len = 0,
		.rwi.actor = read_iter_actor,
		.rwi.len = len,
		.rwi.off = off,
		.dat = buf,
		.dat_max = len
	};

	err = voluta_do_read_iter(op, ii, &rdi.rwi);
	*out_len = rdi.dat_len;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int new_data_vspace(const struct voluta_file_ctx *f_ctx,
			   enum voluta_vtype vtype, struct voluta_vaddr *out)
{
	return voluta_create_vspace(f_ctx->sbi, vtype, out);
}

static int del_data_vspace(const struct voluta_file_ctx *f_ctx,
			   const struct voluta_vaddr *vaddr)
{
	int err;

	voluta_assert(vaddr_isdata(vaddr));

	err = voluta_clear_unwritten(f_ctx->sbi, vaddr);
	if (err) {
		return err;
	}
	err = voluta_remove_vnode_at(f_ctx->sbi, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int new_rtnode(const struct voluta_file_ctx *f_ctx,
		      struct voluta_vnode_info **out_vi)
{
	return voluta_create_vnode(f_ctx->sbi, f_ctx->ii,
				   VOLUTA_VTYPE_RTNODE, out_vi);
}

static int del_rtnode(const struct voluta_file_ctx *f_ctx,
		      struct voluta_vnode_info *vi)
{
	voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_RTNODE);

	return voluta_remove_vnode(f_ctx->sbi, vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void update_head_leaf(const struct voluta_file_ctx *f_ctx,
			     const struct voluta_vaddr *vaddr)
{
	set_head_leaf_of(f_ctx, vaddr);
	ii_dirtify(f_ctx->ii);
}

static void update_tree_root(const struct voluta_file_ctx *f_ctx,
			     const struct voluta_vaddr *vaddr)
{
	set_tree_root_of(f_ctx, vaddr);
	ii_dirtify(f_ctx->ii);
}

static void update_iattr_blocks(const struct voluta_file_ctx *f_ctx,
				const struct voluta_vaddr *vaddr, long dif)
{
	update_iblocks(f_ctx->op, f_ctx->ii, vaddr->vtype, dif);
}

static int create_radix_tnode(const struct voluta_file_ctx *f_ctx,
			      loff_t off, size_t height,
			      struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi;

	err = new_rtnode(f_ctx, &vi);
	if (err) {
		return err;
	}
	rtn_init(vi->vu.rtn, ii_ino(f_ctx->ii), off, height);
	vi_dirtify(vi);
	*out_vi = vi;
	return 0;
}

static int create_root_node(const struct voluta_file_ctx *f_ctx,
			    size_t height, struct voluta_vnode_info **out_vi)
{
	voluta_assert_gt(height, 0);

	return create_radix_tnode(f_ctx, 0, height, out_vi);
}

static int create_bind_node(const struct voluta_file_ctx *f_ctx,
			    struct voluta_vnode_info *parent_vi,
			    struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vnode_info *vi;
	const loff_t file_pos = f_ctx->off;
	const size_t height = height_of(parent_vi);

	err = create_radix_tnode(f_ctx, file_pos, height - 1, &vi);
	if (err) {
		return err;
	}
	bind_child(parent_vi, file_pos, vi_vaddr(vi));

	*out_vi = vi;
	return 0;
}

static int create_data_leaf(const struct voluta_file_ctx *f_ctx,
			    enum voluta_vtype vtype,
			    struct voluta_vaddr *out_vaddr)
{
	int err;

	err = new_data_vspace(f_ctx, vtype, out_vaddr);
	if (err) {
		return err;
	}
	update_iattr_blocks(f_ctx, out_vaddr, 1);
	return 0;
}

static int create_head_leaf_space(const struct voluta_file_ctx *f_ctx,
				  struct voluta_vaddr *out_vaddr)
{
	int err;

	err = create_data_leaf(f_ctx, VOLUTA_VTYPE_DATA4K, out_vaddr);
	if (err) {
		return err;
	}
	update_head_leaf(f_ctx, out_vaddr);
	return 0;
}

static int create_tree_leaf_space(const struct voluta_file_ctx *f_ctx,
				  struct voluta_vnode_info *parent_vi,
				  struct voluta_vaddr *out_vaddr)
{
	int err;

	err = create_data_leaf(f_ctx, VOLUTA_VTYPE_DATABK, out_vaddr);
	if (err) {
		return err;
	}
	bind_child(parent_vi, f_ctx->off, out_vaddr);
	return 0;
}

static void bind_sub_tree(struct voluta_file_ctx *f_ctx,
			  struct voluta_vnode_info *vi)
{
	struct voluta_vaddr vaddr;

	tree_root_of(f_ctx, &vaddr);
	rtn_set_child(vi->vu.rtn, 0, vaddr.off);
	vi_dirtify(vi);

	update_tree_root(f_ctx, vi_vaddr(vi));
}

static size_t off_to_height(loff_t off)
{
	return rtn_height_by_file_pos(NULL, off);
}

static int create_tree_spine(struct voluta_file_ctx *f_ctx)
{
	int err;
	size_t new_height;
	size_t cur_height = 0;
	struct voluta_vnode_info *vi = NULL;

	err = stage_tree_root(f_ctx, &vi);
	if (!err) {
		cur_height = height_of(vi);
	} else if (err == -ENOENT) {
		cur_height = 1;
	} else {
		return err;
	}
	new_height = off_to_height(f_ctx->off);
	while (new_height > cur_height) {
		err = create_root_node(f_ctx, ++cur_height, &vi);
		if (err) {
			return err;
		}
		bind_sub_tree(f_ctx, vi);
	}
	return 0;
}

static int do_stage_or_create_node(const struct voluta_file_ctx *f_ctx,
				   struct voluta_vnode_info *parent_vi,
				   struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_vaddr vaddr;

	resolve_curr_node(f_ctx, parent_vi, &vaddr);
	if (!vaddr_isnull(&vaddr)) {
		err = stage_radix_tnode(f_ctx, &vaddr, out_vi);
	} else {
		err = create_bind_node(f_ctx, parent_vi, out_vi);
	}
	return err;
}

static int stage_or_create_node(const struct voluta_file_ctx *f_ctx,
				struct voluta_vnode_info *parent_vi,
				struct voluta_vnode_info **out_vi)
{
	int err;

	vi_incref(parent_vi);
	err = do_stage_or_create_node(f_ctx, parent_vi, out_vi);
	vi_decref(parent_vi);

	return err;
}

static int stage_or_create_tree_path(struct voluta_file_ctx *f_ctx,
				     struct voluta_vnode_info **out_vi)
{
	int err;
	size_t height;
	struct voluta_vnode_info *vi;

	*out_vi = NULL;
	err = stage_tree_root(f_ctx, &vi);
	if (err) {
		return err;
	}
	height = height_of(vi);
	for (size_t level = height; level > 0; --level) {
		if (isbottom(vi)) {
			*out_vi = vi;
			break;
		}
		err = stage_or_create_node(f_ctx, vi, &vi);
		if (err) {
			return err;
		}
	}
	return unlikely(*out_vi == NULL) ? -EFSCORRUPTED : 0;
}

static int stage_or_create_tree_map(struct voluta_file_ctx *f_ctx,
				    struct voluta_vnode_info **out_vi)
{
	int err;

	err = create_tree_spine(f_ctx);
	if (err) {
		return err;
	}
	err = stage_or_create_tree_path(f_ctx, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

static int do_write_leaf_by_copy(struct voluta_file_ctx *f_ctx,
				 struct voluta_vnode_info *leaf_vi,
				 size_t *out_sz)
{
	int err;
	const struct voluta_vaddr *vaddr = vi_vaddr(leaf_vi);

	err = import_data_by_vnode(f_ctx, leaf_vi, out_sz);
	if (err) {
		return err;
	}
	err = voluta_clear_unwritten(f_ctx->sbi, vaddr);
	if (err) {
		return err;
	}
	dirtify_data_leaf(f_ctx, leaf_vi);
	return 0;
}

static int write_leaf_by_copy(struct voluta_file_ctx *f_ctx,
			      struct voluta_vnode_info *leaf_vi,
			      size_t *out_sz)
{
	int err;

	vi_incref(leaf_vi);
	err = do_write_leaf_by_copy(f_ctx, leaf_vi, out_sz);
	vi_decref(leaf_vi);

	return err;
}

static int write_leaf_by_vaddr(struct voluta_file_ctx *f_ctx,
			       const struct voluta_vaddr *vaddr,
			       size_t *out_sz)
{
	int err;

	err = import_data_by_vaddr(f_ctx, vaddr, out_sz);
	if (err) {
		return err;
	}
	err = voluta_clear_unwritten(f_ctx->sbi, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int prepare_unwritten_leaf(struct voluta_file_ctx *f_ctx,
				  const struct voluta_vaddr *vaddr)
{
	int err;
	bool partial;
	bool unwritten;

	partial = has_partial_write_at(f_ctx, vaddr);
	if (!partial) {
		return 0;
	}
	err = probe_unwritten_at(f_ctx, vaddr, &unwritten);
	if (err) {
		return err;
	}
	if (!unwritten) {
		return 0;
	}
	err = zero_tree_leaf_at(f_ctx, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int require_tree_leaf(struct voluta_file_ctx *f_ctx,
			     struct voluta_vnode_info *parent_vi,
			     struct voluta_vaddr *out_vaddr)
{
	int err;

	resolve_tree_leaf(f_ctx, parent_vi, out_vaddr);
	if (!vaddr_isnull(out_vaddr)) {
		voluta_assert(vaddr_isdata(out_vaddr));
		return 0;
	}
	err = create_tree_leaf_space(f_ctx, parent_vi, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int write_to_leaf(struct voluta_file_ctx *f_ctx,
			 const struct voluta_vaddr *vaddr, size_t *out_len)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	*out_len = 0;
	err = prepare_unwritten_leaf(f_ctx, vaddr);
	if (err) {
		return err;
	}
	if (kcopy_mode(f_ctx)) {
		err = write_leaf_by_vaddr(f_ctx, vaddr, out_len);
		if (err) {
			return err;
		}
	} else {
		err = stage_data_leaf(f_ctx, vaddr, &vi);
		if (err) {
			return err;
		}
		err = write_leaf_by_copy(f_ctx, vi, out_len);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int do_write_tree_leaves(struct voluta_file_ctx *f_ctx,
				struct voluta_vnode_info *parent_vi)
{
	int err;
	size_t len;
	struct voluta_vaddr vaddr;

	while (has_more_io(f_ctx)) {
		err = require_tree_leaf(f_ctx, parent_vi, &vaddr);
		if (err) {
			return err;
		}
		err = write_to_leaf(f_ctx, &vaddr, &len);
		if (err) {
			return err;
		}
		advance_by_nbytes(f_ctx, len);
		if (is_mapping_boundaries(f_ctx)) {
			break;
		}
	}
	return 0;
}

static int write_to_leaves(struct voluta_file_ctx *f_ctx,
			   struct voluta_vnode_info *vi)
{
	int err;

	vi_incref(vi);
	err = do_write_tree_leaves(f_ctx, vi);
	vi_decref(vi);

	return err;
}

static int write_by_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_vnode_info *vi;

	while (has_more_io(f_ctx)) {
		err = stage_or_create_tree_map(f_ctx, &vi);
		if (err) {
			return err;
		}
		err = write_to_leaves(f_ctx, vi);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int require_head_leaf(struct voluta_file_ctx *f_ctx,
			     struct voluta_vaddr *out_vaddr)
{
	int err;
	size_t slot;

	resolve_head_leaf(f_ctx, &slot, out_vaddr);
	if (!vaddr_isnull(out_vaddr)) {
		return 0;
	}
	err = create_head_leaf_space(f_ctx, out_vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int write_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	size_t len = 0;
	struct voluta_vaddr vaddr;

	while (has_head_leaves_io(f_ctx)) {
		err = require_head_leaf(f_ctx, &vaddr);
		if (err) {
			return err;
		}
		err = write_to_leaf(f_ctx, &vaddr, &len);
		if (err) {
			return err;
		}
		advance_by_nbytes(f_ctx, len);
	}
	return 0;
}

static int write_data(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = write_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = write_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

struct voluta_write_iter {
	struct voluta_rwiter_ctx rwi;
	const uint8_t *dat;
	size_t dat_len;
	size_t dat_max;
};


static struct voluta_write_iter *
write_iter_of(const struct voluta_rwiter_ctx *rwi)
{
	const struct voluta_write_iter *wri =
		container_of2(rwi, struct voluta_write_iter, rwi);

	return unconst(wri);
}

static int write_iter_actor(struct voluta_rwiter_ctx *rwi,
			    const struct voluta_xiovec *xiov)
{
	int err;
	struct voluta_write_iter *wri = write_iter_of(rwi);

	if ((xiov->fd > 0) && (xiov->off < 0)) {
		return -EINVAL;
	}
	if ((wri->dat_len + xiov->len) > wri->dat_max) {
		return -EINVAL;
	}
	err = xiovec_copy_from(xiov, wri->dat + wri->dat_len);
	if (err) {
		return err;
	}
	wri->dat_len += xiov->len;
	return 0;
}

static int do_write_iter(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = write_data(f_ctx);
	post_io_update(f_ctx, err == 0);

	return err;
}

static int write_iter(struct voluta_file_ctx *f_ctx)
{
	int err;

	ii_incref(f_ctx->ii);
	err = do_write_iter(f_ctx);
	ii_decref(f_ctx->ii);

	return err;
}

int voluta_do_write_iter(const struct voluta_oper *op,
			 struct voluta_inode_info *ii,
			 struct voluta_rwiter_ctx *rwi)
{
	struct voluta_file_ctx f_ctx = {
		.sbi = ii_sbi(ii),
		.op = op,
		.ii = ii,
		.op_mask = OP_WRITE,
	};

	update_with_rw_iter(&f_ctx, rwi);
	return write_iter(&f_ctx);
}

int voluta_do_write(const struct voluta_oper *op,
		    struct voluta_inode_info *ii,
		    const void *buf, size_t len,
		    loff_t off, size_t *out_len)
{
	int err;
	struct voluta_write_iter wri = {
		.rwi.actor = write_iter_actor,
		.rwi.len = len,
		.rwi.off = off,
		.dat = buf,
		.dat_len = 0,
		.dat_max = len
	};
	struct voluta_file_ctx f_ctx = {
		.sbi = ii_sbi(ii),
		.op = op,
		.ii = ii,
		.op_mask = OP_WRITE,
	};

	update_with_rw_iter(&f_ctx, &wri.rwi);
	err = write_iter(&f_ctx);
	*out_len = wri.dat_len;
	return err;
}

int voluta_do_rdwr_post(const struct voluta_oper *op,
			const struct voluta_inode_info *ii,
			const struct voluta_xiovec *xiov, size_t cnt)
{
	struct voluta_vnode_info *vi;

	ii_incref(ii);
	for (size_t i = 0; i < cnt; ++i) {
		vi = xiov[i].cookie;
		vi_decref(vi);
	}
	ii_decref(ii);
	unused(op);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int drop_del_subtree(struct voluta_file_ctx *f_ctx,
			    struct voluta_vnode_info *vi);

static int discard_data_leaf(const struct voluta_file_ctx *f_ctx,
			     const struct voluta_vaddr *vaddr)
{
	int err;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = del_data_vspace(f_ctx, vaddr);
	if (err) {
		return err;
	}
	update_iattr_blocks(f_ctx, vaddr, -1);
	return 0;
}

static int drop_subtree(struct voluta_file_ctx *f_ctx,
			const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_vnode_info *vi;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = stage_radix_tnode(f_ctx, vaddr, &vi);
	if (err) {
		return err;
	}
	err = drop_del_subtree(f_ctx, vi);
	if (err) {
		return err;
	}
	return 0;
}

static int
drop_subtree_at(struct voluta_file_ctx *f_ctx,
		const struct voluta_vnode_info *parent_vi, size_t slot)
{
	int err;
	struct voluta_vaddr vaddr;

	resolve_child_by_slot(parent_vi, slot, &vaddr);
	if (isbottom(parent_vi)) {
		err = discard_data_leaf(f_ctx, &vaddr);
	} else {
		err = drop_subtree(f_ctx, &vaddr);
	}
	return err;
}

static int do_drop_recursive(struct voluta_file_ctx *f_ctx,
			     struct voluta_vnode_info *vi)
{
	int err;
	const size_t nslots_max = rtn_nchilds_max(vi->vu.rtn);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		err = drop_subtree_at(f_ctx, vi, slot);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int drop_recursive(struct voluta_file_ctx *f_ctx,
			  struct voluta_vnode_info *vi)
{
	int err;

	vi_incref(vi);
	err = do_drop_recursive(f_ctx, vi);
	vi_decref(vi);

	return err;
}

static int drop_del_subtree(struct voluta_file_ctx *f_ctx,
			    struct voluta_vnode_info *vi)
{
	int err;

	err = drop_recursive(f_ctx, vi);
	if (err) {
		return err;
	}
	err = del_rtnode(f_ctx, vi);
	if (err) {
		return err;
	}
	return 0;
}

static void reset_tree_root(struct voluta_file_ctx *f_ctx)
{
	set_tree_root_of(f_ctx, vaddr_none());
	ii_dirtify(f_ctx->ii);
}

static int drop_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_vnode_info *vi;

	if (!has_tree_root(f_ctx)) {
		return 0;
	}
	err = stage_tree_root(f_ctx, &vi);
	if (err) {
		return err;
	}
	err = drop_del_subtree(f_ctx, vi);
	if (err) {
		return err;
	}
	reset_tree_root(f_ctx);
	return 0;
}

static int drop_head_leaf_at(struct voluta_file_ctx *f_ctx, size_t slot)
{
	struct voluta_vaddr vaddr;

	head_leaf_at(f_ctx, slot, &vaddr);
	return discard_data_leaf(f_ctx, &vaddr);
}

static void reset_head_leaf_at(struct voluta_file_ctx *f_ctx, size_t slot)
{
	set_head_leaf_at(f_ctx, slot, vaddr_none());
	ii_dirtify(f_ctx->ii);
}

static int drop_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	const size_t nslots = ris_num_head_leaves(ii_ris_of(f_ctx->ii));

	for (size_t slot = 0; slot < nslots; ++slot) {
		err = drop_head_leaf_at(f_ctx, slot);
		if (err) {
			return err;
		}
		reset_head_leaf_at(f_ctx, slot);
	}
	return 0;
}

static int drop_meta_and_data(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = drop_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = drop_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_drop_reg(struct voluta_inode_info *ii)
{
	int err;
	struct voluta_file_ctx f_ctx = {
		.sbi = ii_sbi(ii),
		.ii = ii
	};

	ii_incref(ii);
	err = drop_meta_and_data(&f_ctx);
	ii_decref(ii);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_discard_partial(const struct voluta_file_ctx *f_ctx,
			      const struct voluta_filenode_ref *fnr)
{
	const struct voluta_vaddr *vaddr = &fnr->vaddr;
	const loff_t off = fnr->file_pos;
	const loff_t oid = off_in_data(off, vaddr->vtype);
	const size_t len = len_of_data(off, f_ctx->end, vaddr->vtype);

	return zero_tree_leaf_range(f_ctx, vaddr, oid, len);
}

static int discard_partial(const struct voluta_file_ctx *f_ctx,
			   const struct voluta_filenode_ref *fnr)
{
	int err;

	vi_incref(fnr->parent);
	err = do_discard_partial(f_ctx, fnr);
	vi_decref(fnr->parent);

	return err;
}

static void clear_subtree_mappings(struct voluta_vnode_info *vi, size_t slot)
{
	rtn_reset_child(vi->vu.rtn, slot);
	vi_dirtify(vi);
}

static int discard_data_leaf_at(struct voluta_file_ctx *f_ctx,
				const struct voluta_filenode_ref *fnr)
{
	int err;

	vi_incref(fnr->parent);
	err = discard_data_leaf(f_ctx, &fnr->vaddr);
	vi_decref(fnr->parent);

	return err;
}

static int discard_entire(struct voluta_file_ctx *f_ctx,
			  const struct voluta_filenode_ref *fnr)
{
	int err;

	err = discard_data_leaf_at(f_ctx, fnr);
	if (err) {
		return err;
	}
	if (off_is_head(fnr->file_pos)) {
		voluta_assert_null(fnr->parent);
		reset_head_leaf_at(f_ctx, fnr->slot);
	} else {
		voluta_assert_not_null(fnr->parent);
		clear_subtree_mappings(fnr->parent, fnr->slot);
	}
	return 0;
}

static int discard_data_at(struct voluta_file_ctx *f_ctx,
			   const struct voluta_filenode_ref *fnr)
{
	int err;
	bool partial;

	if (vaddr_isnull(&fnr->vaddr)) {
		return 0;
	}
	partial = off_is_partial(fnr->file_pos, f_ctx->end, fnr->vaddr.vtype);
	if (partial) {
		err = discard_partial(f_ctx, fnr);
	} else {
		err = discard_entire(f_ctx, fnr);
	}
	return err;
}

static int discard_by_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_filenode_ref fnr;

	if (!has_tree_root(f_ctx)) {
		return 0;
	}
	while (has_more_io(f_ctx)) {
		err = seek_by_tree_map(f_ctx, &fnr);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = discard_data_at(f_ctx, &fnr);
		if (err) {
			return err;
		}
		advance_to_next_tree_leaf(f_ctx);
	}
	return 0;
}

static int discard_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_filenode_ref fnr;

	while (has_head_leaves_io(f_ctx)) {
		fnref_init(&fnr, f_ctx->off);
		resolve_head_leaf(f_ctx, &fnr.slot, &fnr.vaddr);
		err = discard_data_at(f_ctx, &fnr);
		if (err) {
			return err;
		}
		advance_to_next_head_leaf(f_ctx);
	}
	return 0;
}

static int discard_data(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = discard_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = discard_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int discard_unused_meta(struct voluta_file_ctx *f_ctx)
{
	return (f_ctx->beg == 0) ? drop_meta_and_data(f_ctx) : 0;
}

static void
head_leaves_end(const struct voluta_file_ctx *f_ctx, loff_t *out_end)
{
	struct voluta_vaddr vaddr;
	const size_t nslots = ris_num_head_leaves(ii_ris_of(f_ctx->ii));

	*out_end = 0;
	for (size_t slot = 0; slot < nslots; ++slot) {
		head_leaf_at(f_ctx, slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			*out_end = head_off_end(slot);
		}
	}
}

static int
tree_leaves_end(const struct voluta_file_ctx *f_ctx, loff_t *out_end)
{
	int err;
	struct voluta_vnode_info *vi;

	*out_end = 0;
	if (!has_tree_root(f_ctx)) {
		return 0;
	}
	err = stage_tree_root(f_ctx, &vi);
	if (err) {
		return err;
	}
	*out_end = rtn_end(vi->vu.rtn);
	return 0;
}

static int resolve_truncate_end(struct voluta_file_ctx *f_ctx)
{
	int err;
	loff_t end_head;
	loff_t end_tree;

	head_leaves_end(f_ctx, &end_head);
	err = tree_leaves_end(f_ctx, &end_tree);
	if (err) {
		return err;
	}
	f_ctx->end = off_max3(f_ctx->off, end_head, end_tree);
	return 0;
}

static int do_truncate(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = resolve_truncate_end(f_ctx);
	if (err) {
		return err;
	}
	err = discard_data(f_ctx);
	if (err) {
		return err;
	}
	err = discard_unused_meta(f_ctx);
	if (err) {
		return err;
	}
	post_io_update(f_ctx, err == 0);
	return err;
}

int voluta_do_truncate(const struct voluta_oper *op,
		       struct voluta_inode_info *ii, loff_t off)
{
	int err;
	const loff_t isz = ii_size(ii);
	const size_t len = (off < isz) ? off_ulen(off, isz) : 0;
	struct voluta_file_ctx f_ctx = {
		.op = op,
		.sbi = ii_sbi(ii),
		.ii = ii,
		.len = len,
		.beg = off,
		.off = off,
		.end = off_end(off, len),
		.op_mask = OP_TRUNC,
	};

	ii_incref(ii);
	err = do_truncate(&f_ctx);
	ii_decref(ii);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lseek_data_leaf(struct voluta_file_ctx *f_ctx,
			   struct voluta_filenode_ref *fnr)
{
	int err;

	voluta_assert_eq(f_ctx->whence, SEEK_DATA);

	err = seek_data_by_head_leaves(f_ctx, fnr);
	if (!err || (err != -ENOENT)) {
		return err;
	}
	err = seek_by_tree_map(f_ctx, fnr);
	if (err) {
		return err;
	}
	return 0;
}

static int lseek_data(struct voluta_file_ctx *f_ctx)
{
	int err;
	const loff_t isz = ii_size(f_ctx->ii);
	struct voluta_filenode_ref fnr = {
		.parent = NULL,
	};

	err = lseek_data_leaf(f_ctx, &fnr);
	if (err == 0) {
		f_ctx->off = off_max_min(fnr.file_pos, f_ctx->off, isz);
	} else if (err == -ENOENT) {
		f_ctx->off = isz;
		err = 0;
	}
	return err;
}

static int lseek_hole_noleaf(struct voluta_file_ctx *f_ctx,
			     struct voluta_filenode_ref *fnr)
{
	int err;

	err = seek_hole_by_head_leaves(f_ctx, fnr);
	if (!err || (err != -ENOENT)) {
		return err;
	}
	err = seek_by_tree_map(f_ctx, fnr);
	if (err) {
		return err;
	}
	return 0;
}

static int lseek_hole(struct voluta_file_ctx *f_ctx)
{
	int err;
	const loff_t isz = ii_size(f_ctx->ii);
	struct voluta_filenode_ref fnr = {
		.parent = NULL,
	};

	err = lseek_hole_noleaf(f_ctx, &fnr);
	if (err == 0) {
		f_ctx->off = off_max_min(fnr.file_pos, f_ctx->off, isz);
	} else if (err == -ENOENT) {
		f_ctx->off = isz;
		err = 0;
	}
	return err;
}

static int lseek_notsupp(struct voluta_file_ctx *f_ctx)
{
	f_ctx->off = f_ctx->end;
	return -ENOTSUP;
}

static int do_lseek(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = check_file_io(f_ctx);
	if (err) {
		return err;
	}
	if (is_seek_data(f_ctx)) {
		err = lseek_data(f_ctx);
	} else if (is_seek_hole(f_ctx)) {
		err =  lseek_hole(f_ctx);
	} else {
		err = lseek_notsupp(f_ctx);
	}
	return err;
}

int voluta_do_lseek(const struct voluta_oper *op,
		    struct voluta_inode_info *ii,
		    loff_t off, int whence, loff_t *out_off)
{
	int err;
	struct voluta_file_ctx f_ctx = {
		.op = op,
		.sbi = ii_sbi(ii),
		.ii = ii,
		.len = 0,
		.beg = off,
		.off = off,
		.end = ii_size(ii),
		.op_mask = OP_LSEEK,
		.whence = whence
	};

	ii_incref(ii);
	err = do_lseek(&f_ctx);
	ii_decref(ii);

	*out_off = f_ctx.off;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool fl_reserve_range(const struct voluta_file_ctx *f_ctx)
{
	const int fl_mask = FALLOC_FL_KEEP_SIZE;

	return (f_ctx->fl_mode & ~fl_mask) == 0;
}

static bool fl_keep_size(const struct voluta_file_ctx *f_ctx)
{
	const int fl_mask = FALLOC_FL_KEEP_SIZE;

	return (f_ctx->fl_mode & fl_mask) == fl_mask;
}

static bool fl_punch_hole(const struct voluta_file_ctx *f_ctx)
{
	const int fl_mask = FALLOC_FL_PUNCH_HOLE;

	return (f_ctx->fl_mode & fl_mask) == fl_mask;
}

/*
 * TODO-0012: Proper handling for FALLOC_FL_KEEP_SIZE beyond file size
 *
 * See 'man 2 fallocate' for semantics details of FALLOC_FL_KEEP_SIZE
 * beyond end-of-file.
 */
static int check_fl_mode(const struct voluta_file_ctx *f_ctx)
{
	const int fl_mode = f_ctx->fl_mode;
	const int fl_supported =
		FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;

	if ((fl_mode & FALLOC_FL_PUNCH_HOLE) &&
	    !(fl_mode & FALLOC_FL_KEEP_SIZE)) {
		return -EINVAL;
	}
	if (fl_mode & ~fl_supported) {
		return -ENOTSUP;
	}
	return 0;
}

static int create_bind_tree_leaf(const struct voluta_file_ctx *f_ctx,
				 struct voluta_vnode_info *parent_vi)
{
	int err;
	struct voluta_vaddr vaddr;

	resolve_tree_leaf(f_ctx, parent_vi, &vaddr);
	if (!vaddr_isnull(&vaddr)) {
		return 0;
	}
	err = create_data_leaf(f_ctx, VOLUTA_VTYPE_DATABK, &vaddr);
	if (err) {
		return err;
	}
	bind_child(parent_vi, f_ctx->off, &vaddr);
	return 0;
}

static int do_reserve_tree_leaves(struct voluta_file_ctx *f_ctx,
				  struct voluta_vnode_info *parent_vi)
{
	int err;
	bool next_mapping = false;

	while (has_more_io(f_ctx) && !next_mapping) {
		err = create_bind_tree_leaf(f_ctx, parent_vi);
		if (err) {
			return err;
		}
		advance_to_next_tree_leaf(f_ctx);
		next_mapping = is_mapping_boundaries(f_ctx);
	}
	return 0;
}

static int reserve_tree_leaves(struct voluta_file_ctx *f_ctx,
			       struct voluta_vnode_info *parent_vi)
{
	int err;

	vi_incref(parent_vi);
	err = do_reserve_tree_leaves(f_ctx, parent_vi);
	vi_decref(parent_vi);

	return err;
}

static int reserve_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	size_t height;
	struct voluta_vnode_info *vi;

	err = stage_tree_root(f_ctx, &vi);
	if (err) {
		return err;
	}
	height = height_of(vi);
	for (size_t level = height; level > 0; --level) {
		if (isbottom(vi)) {
			return reserve_tree_leaves(f_ctx, vi);
		}
		err = stage_or_create_node(f_ctx, vi, &vi);
		if (err) {
			return err;
		}
	}
	return -EFSCORRUPTED;
}

static int reserve_by_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = create_tree_spine(f_ctx);
	if (err) {
		return err;
	}
	err = reserve_leaves(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int fallocate_reserve_by_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err = 0;

	while (has_more_io(f_ctx) && !err) {
		err = reserve_by_tree_map(f_ctx);
	}
	return err;
}

static int fallocate_reserve_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_vaddr vaddr;

	while (has_head_leaves_io(f_ctx)) {
		err = require_head_leaf(f_ctx, &vaddr);
		if (err) {
			return err;
		}
		advance_to_next_head_leaf(f_ctx);
	}
	return 0;
}

static int fallocate_reserve(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = fallocate_reserve_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = fallocate_reserve_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int fallocate_punch_hole(struct voluta_file_ctx *f_ctx)
{
	return discard_data(f_ctx);
}

static int do_fallocate_op(struct voluta_file_ctx *f_ctx)
{
	int err;

	if (fl_reserve_range(f_ctx)) {
		err = fallocate_reserve(f_ctx);
	} else if (fl_punch_hole(f_ctx)) {
		err = fallocate_punch_hole(f_ctx);
	} else {
		err = -ENOTSUP;
	}
	return err;
}

static int do_fallocate(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = check_fl_mode(f_ctx);
	if (err) {
		return err;
	}
	err = do_fallocate_op(f_ctx);
	if (err) {
		return err;
	}
	post_io_update(f_ctx, false);
	return err;
}

int voluta_do_fallocate(const struct voluta_oper *op,
			struct voluta_inode_info *ii,
			int mode, loff_t off, loff_t length)
{
	int err;
	const size_t len = (size_t)length;
	struct voluta_file_ctx f_ctx = {
		.op = op,
		.sbi = ii_sbi(ii),
		.ii = ii,
		.len = len,
		.beg = off,
		.off = off,
		.end = off_end(off, len),
		.op_mask = OP_FALLOC,
		.fl_mode = mode,
	};

	ii_incref(ii);
	err = do_fallocate(&f_ctx);
	ii_decref(ii);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool emit_fiemap_ext(struct voluta_file_ctx *f_ctx,
			    const struct voluta_vaddr *vaddr, size_t *out_len)
{
	loff_t end;
	struct fiemap_extent *fm_ext;
	struct fiemap *fm = f_ctx->fm;
	const size_t len = vaddr->len;

	end = off_min(off_end(f_ctx->off, len), f_ctx->end);
	*out_len = len_of_data(f_ctx->off, end, vaddr->vtype);
	if (*out_len == 0) {
		return true;
	}
	if (vaddr_isnull(vaddr)) {
		return false;
	}
	fm_ext = &fm->fm_extents[fm->fm_mapped_extents++];
	if (fm->fm_mapped_extents <= fm->fm_extent_count) {
		fm_ext->fe_flags = FIEMAP_EXTENT_DATA_ENCRYPTED;
		fm_ext->fe_logical = (uint64_t)(f_ctx->off);
		fm_ext->fe_physical = (uint64_t)(vaddr->off);
		fm_ext->fe_length = *out_len;
	}
	return (fm->fm_mapped_extents == fm->fm_extent_count);
}

static void emit_fiemap(struct voluta_file_ctx *f_ctx,
			const struct voluta_vaddr *vaddr, size_t *out_len)
{
	*out_len = 0;
	if (!vaddr_isnull(vaddr)) {
		f_ctx->fm_stop = emit_fiemap_ext(f_ctx, vaddr, out_len);
	}
}

static int do_fiemap_by_tree_leaves(struct voluta_file_ctx *f_ctx,
				    struct voluta_vnode_info *parent_vi)
{
	size_t len;
	struct voluta_vaddr vaddr;

	while (has_more_io(f_ctx)) {
		resolve_tree_leaf(f_ctx, parent_vi, &vaddr);
		emit_fiemap(f_ctx, &vaddr, &len);
		if (len > 0) {
			advance_by_nbytes(f_ctx, len);
		} else {
			advance_to_next_tree_leaf(f_ctx);
		}
		if (is_mapping_boundaries(f_ctx)) {
			break;
		}
	}
	return 0;
}

static int fiemap_by_tree_leaves(struct voluta_file_ctx *f_ctx,
				 struct voluta_vnode_info *parent_vi)
{
	int err;

	vi_incref(parent_vi);
	err = do_fiemap_by_tree_leaves(f_ctx, parent_vi);
	vi_decref(parent_vi);

	return err;
}

static int fiemap_by_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_filenode_ref fnr = { .file_pos = -1 };

	while (has_more_io(f_ctx)) {
		err = seek_by_tree_map(f_ctx, &fnr);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = fiemap_by_tree_leaves(f_ctx, fnr.parent);
		if (err) {
			return err;
		}
		/* TODO: need to skip large holes */
	}
	return 0;
}

static int fiemap_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	size_t len;
	size_t slot;
	struct voluta_vaddr vaddr;

	while (has_head_leaves_io(f_ctx)) {
		resolve_head_leaf(f_ctx, &slot, &vaddr);
		emit_fiemap(f_ctx, &vaddr, &len);
		if (len > 0) {
			advance_by_nbytes(f_ctx, len);
		} else {
			advance_to_next_head_leaf(f_ctx);
		}
	}
	return 0;
}

static int fiemap_data(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = fiemap_by_head_leaves(f_ctx);
	if (err) {
		return err;
	}
	err = fiemap_by_tree_map(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int check_fm_flags(const struct voluta_file_ctx *f_ctx)
{
	const int fm_allowed =
		FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR | FIEMAP_FLAG_CACHE;

	if (f_ctx->fm_flags & ~fm_allowed) {
		return -ENOTSUP;
	}
	if (f_ctx->fm_flags & fm_allowed) {
		return -ENOTSUP;
	}
	return 0;
}

static int do_fiemap(struct voluta_file_ctx *f_ctx)
{
	int err;

	err = check_file_io(f_ctx);
	if (err) {
		return err;
	}
	err = check_fm_flags(f_ctx);
	if (err) {
		return err;
	}
	err = fiemap_data(f_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static loff_t i_off_end(const struct voluta_inode_info *ii,
			loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t isz = ii_size(ii);

	return off_min(end, isz);
}

int voluta_do_fiemap(const struct voluta_oper *op,
		     struct voluta_inode_info *ii, struct fiemap *fm)
{
	int err;
	const loff_t off = (loff_t)fm->fm_start;
	const size_t len = (size_t)fm->fm_length;
	struct voluta_file_ctx f_ctx = {
		.op = op,
		.sbi = ii_sbi(ii),
		.ii = ii,
		.len = len,
		.beg = off,
		.off = off,
		.end = i_off_end(ii, off, len),
		.op_mask = OP_FIEMAP,
		.fm = fm,
		.fm_flags = (int)(fm->fm_flags),
		.fm_stop = 0,
		.whence = SEEK_DATA
	};

	fm->fm_mapped_extents = 0;

	ii_incref(ii);
	err = do_fiemap(&f_ctx);
	ii_decref(ii);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_copy_file_range(struct voluta_file_ctx *f_ctx_src,
			      struct voluta_file_ctx *f_ctx_dst,
			      size_t *out_ncp)
{
	int err;

	*out_ncp = 0;
	err = check_file_io(f_ctx_src);
	if (err) {
		return err;
	}
	err = check_file_io(f_ctx_dst);
	if (err) {
		return err;
	}
	return -ENOSYS;
}

int voluta_do_copy_file_range(const struct voluta_oper *op,
			      struct voluta_inode_info *ii_in,
			      struct voluta_inode_info *ii_out,
			      loff_t off_in, loff_t off_out, size_t len,
			      int flags, size_t *out_ncp)
{
	int err;
	struct voluta_file_ctx f_ctx_in = {
		.op = op,
		.sbi = ii_sbi(ii_in),
		.ii = ii_in,
		.len = len,
		.beg = off_in,
		.off = off_in,
		.end = i_off_end(ii_in, off_in, len),
		.op_mask = OP_COPY_RANGE,
		.cp_flags = flags,
	};
	struct voluta_file_ctx f_ctx_out = {
		.op = op,
		.sbi = ii_sbi(ii_in),
		.ii = ii_out,
		.len = len,
		.beg = off_out,
		.off = off_out,
		.end = i_off_end(ii_out, off_out, len),
		.op_mask = OP_COPY_RANGE,
		.cp_flags = flags,
	};

	if (flags) {
		return -EINVAL;
	}

	ii_incref(ii_in);
	ii_incref(ii_out);
	err = do_copy_file_range(&f_ctx_in, &f_ctx_out, out_ncp);
	ii_decref(ii_out);
	ii_decref(ii_in);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_setup_reg(struct voluta_inode_info *ii)
{
	file_tree_setup(ii);
	ii_dirtify(ii);
}

int voluta_verify_radix_tnode(const struct voluta_radix_tnode *rtn)
{
	int err;
	loff_t spbh;
	const loff_t span = rtn_span(rtn);
	const size_t height = rtn_height(rtn);

	err = voluta_verify_ino(rtn_ino(rtn));
	if (err) {
		return err;
	}
	if ((rtn_beg(rtn) < 0) || (rtn_end(rtn) < 0)) {
		return -EFSCORRUPTED;
	}
	if (rtn_beg(rtn) >= rtn_end(rtn)) {
		return -EFSCORRUPTED;
	}
	if ((height <= 1) || (height > 7)) {
		return -EFSCORRUPTED;
	}
	spbh = rtn_span_by_height(rtn, height);
	if (span != spbh) {
		return -EFSCORRUPTED;
	}
	return 0;
}
