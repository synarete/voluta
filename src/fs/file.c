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
#include <errno.h>
#include <limits.h>
#include <voluta/fs/types.h>
#include <voluta/fs/address.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/osdc.h>
#include <voluta/fs/super.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/file.h>
#include <voluta/fs/private.h>


#define STATICASSERT_NELEMS(x, y) \
	VOLUTA_STATICASSERT_EQ(VOLUTA_ARRAY_SIZE(x), y)

#define OP_READ         (1 << 0)
#define OP_WRITE        (1 << 1)
#define OP_TRUNC        (1 << 2)
#define OP_FALLOC       (1 << 3)
#define OP_FIEMAP       (1 << 4)
#define OP_LSEEK        (1 << 5)
#define OP_COPY_RANGE   (1 << 6)


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
	int     with_backref;
};

struct voluta_fmap_ctx {
	const struct voluta_file_ctx *f_ctx;
	struct voluta_vnode_info *parent;
	struct voluta_vaddr vaddr;
	size_t  slot_idx;
	size_t  slot_len;
	loff_t  file_pos;
	bool    head1;
	bool    head2;
	bool    tree;
	bool    leaf;
	bool    has_data;
	bool    has_hole;
	bool    has_target;
};

static bool off_is_head1(loff_t off);
static bool off_is_head2(loff_t off);
static size_t off_to_data_size(loff_t off);
static bool fl_keep_size(const struct voluta_file_ctx *f_ctx);
static bool fl_zero_range(const struct voluta_file_ctx *f_ctx);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ssize_t data_size_of(enum voluta_vtype vtype)
{
	return vtype_ssize(vtype);
}

static loff_t off_to_bk(loff_t off)
{
	return off_align(off, VOLUTA_BK_SIZE);
}

static bool off_isaligned(loff_t off)
{
	return (off % VOLUTA_BK_SIZE) == 0;
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

static int fiovec_by_qalloc(const struct voluta_file_ctx *f_ctx,
                            void *bk_start, loff_t off_in_bk, size_t len,
                            struct voluta_fiovec *out_fiov)
{
	uint8_t *qamem = (uint8_t *)bk_start + off_in_bk;
	const struct voluta_qalloc *qalloc = f_ctx->sbi->sb_qalloc;

	return voluta_qalloc_fiovec(qalloc, qamem, len, out_fiov);
}

static int fiovec_by_blob(const struct voluta_file_ctx *f_ctx,
                          const struct voluta_vaddr *vaddr,
                          loff_t off_within, size_t len,
                          struct voluta_fiovec *out_fiov)
{
	int err;
	struct voluta_vba vba;

	err = voluta_resolve_vba(f_ctx->sbi, vaddr, &vba);
	if (err) {
		return err;
	}
	err = voluta_osdc_resolve(f_ctx->sbi->sb_osdc, &vba.baddr,
	                          off_within, len, out_fiov);
	if (err) {
		return err;
	}
	return 0;
}

static int fiovec_of_vnode(const struct voluta_file_ctx *f_ctx,
                           struct voluta_vnode_info *vi,
                           struct voluta_fiovec *out_fiov)
{
	int err;
	void *dat = vi_dat_of(vi);
	const enum voluta_vtype vtype = vi_vtype(vi);
	const loff_t off_in_dat = off_in_data(f_ctx->off, vtype);
	const size_t len = len_of_data(f_ctx->off, f_ctx->end, vtype);

	err = fiovec_by_qalloc(f_ctx, dat, off_in_dat, len, out_fiov);
	if (err) {
		return err;
	}
	if (f_ctx->with_backref) {
		out_fiov->fv_ref = &vi->v_fir;
		voluta_fiovref_do_pre(out_fiov->fv_ref);
	}
	return 0;
}

static int fiovec_of_data(const struct voluta_file_ctx *f_ctx,
                          const struct voluta_vaddr *vaddr,
                          loff_t off_in_bk, size_t len,
                          struct voluta_fiovec *out_fiov)
{
	return fiovec_by_blob(f_ctx, vaddr, off_in_bk, len, out_fiov);
}

static int fiovec_of_vaddr(const struct voluta_file_ctx *f_ctx,
                           const struct voluta_vaddr *vaddr,
                           struct voluta_fiovec *out_fiov)
{
	int err;
	const enum voluta_vtype vtype = vaddr->vtype;
	const loff_t off_within = off_in_data(f_ctx->off, vtype);
	const size_t len = len_of_data(f_ctx->off, f_ctx->end, vtype);

	err = fiovec_of_data(f_ctx, vaddr, off_within, len, out_fiov);
	if (err) {
		return err;
	}
	if (f_ctx->with_backref) {
		voluta_fiovref_do_pre(out_fiov->fv_ref);
	}
	return 0;
}

static int fiovec_of_zeros(const struct voluta_file_ctx *f_ctx,
                           const enum voluta_vtype vtype,
                           struct voluta_fiovec *out_fiov)
{
	void *buf = nil_bk_buf_of(f_ctx);
	const size_t len = len_of_data(f_ctx->off, f_ctx->end, vtype);

	voluta_assert_le(len, VOLUTA_BK_SIZE);
	return fiovec_by_qalloc(f_ctx, buf, 0, len, out_fiov);
}

static int fiovec_copy_into(const struct voluta_fiovec *fiov, void *buf)
{
	int err = 0;

	if (fiov->fv_base != NULL) {
		memcpy(buf, fiov->fv_base, fiov->fv_len);
	} else {
		err = voluta_sys_preadn(fiov->fv_fd, buf,
		                        fiov->fv_len, fiov->fv_off);
	}
	return err;
}

static int fiovec_copy_from(const struct voluta_fiovec *fiov, const void *buf)
{
	int err = 0;

	voluta_assert_le(fiov->fv_len, VOLUTA_BK_SIZE);
	if (fiov->fv_base != NULL) {
		memcpy(fiov->fv_base, buf, fiov->fv_len);
	} else {
		err = voluta_sys_pwriten(fiov->fv_fd, buf,
		                         fiov->fv_len, fiov->fv_off);
	}
	return err;
}

static int fiovec_copy_mem(const struct voluta_fiovec *fiov_src,
                           const struct voluta_fiovec *fiov_dst, size_t len)
{
	voluta_assert_ge(fiov_src->fv_len, len);
	voluta_assert_ge(fiov_dst->fv_len, len);
	voluta_assert_not_null(fiov_src->fv_base);
	voluta_assert_not_null(fiov_dst->fv_base);

	memcpy(fiov_dst->fv_base, fiov_src->fv_base, len);
	return 0;
}

static int fiovec_copy_splice(const struct voluta_fiovec *fiov_src,
                              const struct voluta_fiovec *fiov_dst,
                              struct voluta_pipe *pipe,
                              struct voluta_nullfd *nullfd, size_t len)
{
	loff_t off_src = fiov_src->fv_off;
	loff_t off_dst = fiov_dst->fv_off;
	const int fd_src = fiov_src->fv_fd;
	const int fd_dst = fiov_dst->fv_fd;

	return voluta_kcopy_with_splice(pipe, nullfd, fd_src, &off_src,
	                                fd_dst, &off_dst, len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t rtn_refcnt(const struct voluta_radix_tnode *rtn)
{
	return voluta_le64_to_cpu(rtn->r_refcnt);
}

static void rtn_set_refcnt(struct voluta_radix_tnode *rtn, size_t refcnt)
{
	rtn->r_refcnt = voluta_cpu_to_le64(refcnt);
}

static void rtn_inc_refcnt(struct voluta_radix_tnode *rtn)
{
	rtn_set_refcnt(rtn, rtn_refcnt(rtn) + 1);
}

static void rtn_dec_refcnt(struct voluta_radix_tnode *rtn)
{
	voluta_assert_gt(rtn_refcnt(rtn), 0);

	rtn_set_refcnt(rtn, rtn_refcnt(rtn) - 1);
}

static ino_t rtn_ino(const struct voluta_radix_tnode *rtn)
{
	return voluta_ino_to_cpu(rtn->r_ino);
}

static void rtn_set_ino(struct voluta_radix_tnode *rtn, ino_t ino)
{
	rtn->r_ino = voluta_cpu_to_ino(ino);
}

static loff_t rtn_beg(const struct voluta_radix_tnode *rtn)
{
	return voluta_off_to_cpu(rtn->r_beg);
}

static void rtn_set_beg(struct voluta_radix_tnode *rtn, loff_t beg)
{
	rtn->r_beg = voluta_cpu_to_off(beg);
}

static loff_t rtn_end(const struct voluta_radix_tnode *rtn)
{
	return voluta_off_to_cpu(rtn->r_end);
}

static void rtn_set_end(struct voluta_radix_tnode *rtn, loff_t end)
{
	rtn->r_end = voluta_cpu_to_off(end);
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
                     ino_t ino, loff_t beg, loff_t end, size_t height)
{
	rtn_set_refcnt(rtn, 0);
	rtn_set_ino(rtn, ino);
	rtn_set_beg(rtn, beg);
	rtn_set_end(rtn, end);
	rtn_set_height(rtn, height);
	rtn_clear_childs(rtn);
	voluta_memzero(rtn->r_zeros, sizeof(rtn->r_zeros));
}

static void rtn_init_by(struct voluta_radix_tnode *rtn,
                        ino_t ino, loff_t off, size_t height)
{
	loff_t beg = 0;
	loff_t end = 0;

	rtn_calc_range(rtn, off, height, &beg, &end);
	rtn_init(rtn, ino, beg, end, height);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_reg_ispec *ris_of(const struct voluta_inode *inode)
{
	const struct voluta_reg_ispec *ris = &inode->i_s.r;

	return unconst(ris);
}

static void ris_head1_leaf(const struct voluta_reg_ispec *ris, size_t slot,
                           struct voluta_vaddr *vaddr)
{
	voluta_assert_lt(slot, ARRAY_SIZE(ris->r_head1_leaf));

	voluta_vaddr64_parse(&ris->r_head1_leaf[slot], vaddr);
}

static void ris_set_head1_leaf(struct voluta_reg_ispec *ris, size_t slot,
                               const struct voluta_vaddr *vaddr)
{
	voluta_assert_lt(slot, ARRAY_SIZE(ris->r_head1_leaf));

	voluta_vaddr64_set(&ris->r_head1_leaf[slot], vaddr);
}

static void ris_head2_leaf(const struct voluta_reg_ispec *ris, size_t slot,
                           struct voluta_vaddr *vaddr)
{
	voluta_assert_lt(slot, ARRAY_SIZE(ris->r_head2_leaf));

	voluta_vaddr64_parse(&ris->r_head2_leaf[slot], vaddr);
}

static void ris_set_head2_leaf(struct voluta_reg_ispec *ris, size_t slot,
                               const struct voluta_vaddr *vaddr)
{
	voluta_assert_lt(slot, ARRAY_SIZE(ris->r_head2_leaf));

	voluta_vaddr64_set(&ris->r_head2_leaf[slot], vaddr);
}

static size_t ris_num_head1_leaves(const struct voluta_reg_ispec *ris)
{
	return ARRAY_SIZE(ris->r_head1_leaf);
}

static size_t ris_num_head2_leaves(const struct voluta_reg_ispec *ris)
{
	return ARRAY_SIZE(ris->r_head2_leaf);
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
	size_t nslots;
	const struct voluta_vaddr *vaddr = vaddr_none();

	nslots = ris_num_head1_leaves(ris);
	for (size_t slot = 0; slot < nslots; ++slot) {
		ris_set_head1_leaf(ris, slot, vaddr);
	}
	nslots = ris_num_head2_leaves(ris);
	for (size_t slot = 0; slot < nslots; ++slot) {
		ris_set_head2_leaf(ris, slot, vaddr);
	}
	ris_set_tree_root(ris, vaddr);
}

static struct voluta_reg_ispec *ii_ris_of(const struct voluta_inode_info *ii)
{
	return ris_of(ii->inode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool isbottom(const struct voluta_vnode_info *vi);

static void vaddr_assign(struct voluta_vaddr *vaddr,
                         const struct voluta_vaddr *from)
{
	if (from != NULL) {
		vaddr_copyto(from, vaddr);
	} else {
		vaddr_reset(vaddr);
	}
}

static void fm_ctx_init(struct voluta_fmap_ctx *fm_ctx,
                        const struct voluta_file_ctx *f_ctx,
                        const struct voluta_vaddr *vaddr, loff_t file_pos)
{
	vaddr_assign(&fm_ctx->vaddr, vaddr);
	fm_ctx->f_ctx = f_ctx;
	fm_ctx->parent = NULL;
	fm_ctx->slot_idx = UINT_MAX;
	fm_ctx->slot_len = off_to_data_size(file_pos);
	fm_ctx->file_pos = file_pos;
	fm_ctx->head1 = off_is_head1(file_pos);
	fm_ctx->head2 = off_is_head2(file_pos);
	fm_ctx->tree = !fm_ctx->head1 && !fm_ctx->head2;
	fm_ctx->leaf = false;
	fm_ctx->has_data = false;
	fm_ctx->has_hole = false;
	fm_ctx->has_target = !vaddr_isnull(vaddr);
}

static void fm_ctx_setup(struct voluta_fmap_ctx *fm_ctx,
                         const struct voluta_file_ctx *f_ctx,
                         const struct voluta_vaddr *vaddr,
                         struct voluta_vnode_info *parent_vi,
                         size_t slot, loff_t file_pos)
{
	fm_ctx_init(fm_ctx, f_ctx, vaddr, file_pos);
	fm_ctx->parent = parent_vi;
	fm_ctx->slot_idx = slot;
	if (fm_ctx->head1 || fm_ctx->head2) {
		fm_ctx->leaf = true;
	} else if (vaddr_isdata(vaddr)) {
		fm_ctx->leaf = true;
	} else if (parent_vi && isbottom(parent_vi)) {
		fm_ctx->leaf = true;
	}
	if (fm_ctx->leaf) {
		fm_ctx->has_data = fm_ctx->has_target;
		fm_ctx->has_hole = !fm_ctx->has_data;
	}
}

static void fm_ctx_nomap(struct voluta_fmap_ctx *fm_ctx,
                         const struct voluta_file_ctx *f_ctx,
                         struct voluta_vnode_info *parent, loff_t file_pos)
{
	fm_ctx_setup(fm_ctx, f_ctx, vaddr_none(), parent, UINT_MAX, file_pos);
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

static void resolve_child_at(const struct voluta_file_ctx *f_ctx,
                             struct voluta_vnode_info *vi,
                             loff_t file_pos, size_t slot,
                             struct voluta_fmap_ctx *out_fm_ctx)
{
	struct voluta_vaddr vaddr;

	resolve_child_by_slot(vi, slot, &vaddr);
	fm_ctx_setup(out_fm_ctx, f_ctx, &vaddr, vi, slot, file_pos);
}

static void resolve_child(const struct voluta_file_ctx *f_ctx,
                          struct voluta_vnode_info *vi, loff_t file_pos,
                          struct voluta_fmap_ctx *out_fm_ctx)
{
	size_t child_slot;

	if (vi != NULL) {
		child_slot = child_slot_of(vi, file_pos);
		resolve_child_at(f_ctx, vi, file_pos, child_slot, out_fm_ctx);
	} else {
		fm_ctx_init(out_fm_ctx, f_ctx, vaddr_none(), file_pos);
	}
}

static void bind_child(struct voluta_vnode_info *parent_vi, loff_t file_pos,
                       const struct voluta_vaddr *vaddr)
{
	if (parent_vi != NULL) {
		assign_child_by_pos(parent_vi, file_pos, vaddr);
		vi_dirtify(parent_vi);
	}
}

static void bind_rtnode(struct voluta_vnode_info *parent_vi,
                        loff_t file_pos, struct voluta_vnode_info *vi)
{
	bind_child(parent_vi, file_pos, vi_vaddr(vi));
	rtn_inc_refcnt(vi->vu.rtn);
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

static loff_t head1_off_end(size_t slot)
{
	const size_t leaf_size = VOLUTA_FILE_HEAD1_LEAF_SIZE;

	voluta_assert_lt(slot, VOLUTA_FILE_HEAD1_NLEAVES);

	return off_end(0, (slot + 1) * leaf_size);
}

static loff_t head1_off_max(void)
{
	return head1_off_end(VOLUTA_FILE_HEAD1_NLEAVES - 1);
}

static loff_t head2_off_end(size_t slot)
{
	const size_t leaf_size = VOLUTA_FILE_HEAD2_LEAF_SIZE;

	voluta_assert_lt(slot, VOLUTA_FILE_HEAD2_NLEAVES);

	return head1_off_max() + off_end(0, (slot + 1) * leaf_size);
}

static loff_t head2_off_max(void)
{
	return head2_off_end(VOLUTA_FILE_HEAD2_NLEAVES - 1);
}

static bool off_is_head1(loff_t off)
{
	return off_is_inrange(off, 0, head1_off_max());
}

static bool off_is_head2(loff_t off)
{
	return off_is_inrange(off, head1_off_max(), head2_off_max());
}

static bool has_head1_leaves_io(const struct voluta_file_ctx *f_ctx)
{
	return has_more_io(f_ctx) && off_is_head1(f_ctx->off);
}

static bool has_head2_leaves_io(const struct voluta_file_ctx *f_ctx)
{
	return has_more_io(f_ctx) && off_is_head2(f_ctx->off);
}

static bool has_partial_write_at(const struct voluta_file_ctx *f_ctx,
                                 const struct voluta_vaddr *vaddr)
{
	return off_is_partial(f_ctx->off, f_ctx->end, vaddr->vtype);
}

static bool has_partial_write(const struct voluta_fmap_ctx *fm_ctx)
{
	return has_partial_write_at(fm_ctx->f_ctx, &fm_ctx->vaddr);
}

static enum voluta_vtype off_to_data_vtype(loff_t off)
{
	enum voluta_vtype vtype;

	if (off < head1_off_max()) {
		vtype = VOLUTA_VTYPE_DATA1K;
	} else if (off < head2_off_max()) {
		vtype = VOLUTA_VTYPE_DATA4K;
	} else {
		vtype = VOLUTA_VTYPE_DATABK;
	}
	return vtype;
}

static size_t off_to_data_size(loff_t off)
{
	return (size_t)data_size_of(off_to_data_vtype(off));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void file_tree_setup(struct voluta_inode_info *ii)
{
	ris_setup(ii_ris_of(ii));
}

static void file_head1_leaf(const struct voluta_inode_info *ii, size_t slot,
                            struct voluta_vaddr *out_vaddr)
{
	ris_head1_leaf(ii_ris_of(ii), slot, out_vaddr);
}

static void file_set_head1_leaf(struct voluta_inode_info *ii, size_t slot,
                                const struct voluta_vaddr *vaddr)
{
	ris_set_head1_leaf(ii_ris_of(ii), slot, vaddr);
}

static size_t head1_leaf_slot_of(const struct voluta_file_ctx *f_ctx)
{
	size_t slot;
	const loff_t off = f_ctx->off;
	const size_t slot_size = VOLUTA_FILE_HEAD1_LEAF_SIZE;

	voluta_assert_lt(off, 4 * VOLUTA_KILO);
	slot = (size_t)off / slot_size;

	voluta_assert_lt(slot, VOLUTA_FILE_HEAD1_NLEAVES);
	return slot;
}

static void head1_leaf_at(const struct voluta_file_ctx *f_ctx, size_t slot,
                          struct voluta_vaddr *out_vaddr)
{
	file_head1_leaf(f_ctx->ii, slot, out_vaddr);
}

static void resolve_head1_leaf(const struct voluta_file_ctx *f_ctx,
                               struct voluta_fmap_ctx *out_fm_ctx)
{
	struct voluta_vaddr vaddr;
	const size_t slot = head1_leaf_slot_of(f_ctx);

	head1_leaf_at(f_ctx, slot, &vaddr);
	fm_ctx_setup(out_fm_ctx, f_ctx, &vaddr, NULL, slot, f_ctx->off);
}

static void set_head1_leaf_at(const struct voluta_file_ctx *f_ctx,
                              size_t slot, const struct voluta_vaddr *vaddr)
{
	file_set_head1_leaf(f_ctx->ii, slot, vaddr);
}

static void file_head2_leaf(const struct voluta_inode_info *ii, size_t slot,
                            struct voluta_vaddr *out_vaddr)
{
	ris_head2_leaf(ii_ris_of(ii), slot, out_vaddr);
}

static void file_set_head2_leaf(struct voluta_inode_info *ii, size_t slot,
                                const struct voluta_vaddr *vaddr)
{
	ris_set_head2_leaf(ii_ris_of(ii), slot, vaddr);
}

static size_t head2_leaf_slot_of(const struct voluta_file_ctx *f_ctx)
{
	size_t slot;
	const loff_t off = f_ctx->off;
	const size_t slot_size = VOLUTA_FILE_HEAD2_LEAF_SIZE;

	voluta_assert_lt(off, VOLUTA_BK_SIZE);
	voluta_assert_ge(off, head1_off_max());
	slot = (size_t)(off - head1_off_max()) / slot_size;

	voluta_assert_lt(slot, VOLUTA_FILE_HEAD2_NLEAVES);
	return slot;
}

static void head2_leaf_at(const struct voluta_file_ctx *f_ctx, size_t slot,
                          struct voluta_vaddr *out_vaddr)
{
	file_head2_leaf(f_ctx->ii, slot, out_vaddr);
}

static void resolve_head2_leaf(const struct voluta_file_ctx *f_ctx,
                               struct voluta_fmap_ctx *out_fm_ctx)
{
	struct voluta_vaddr vaddr;
	const size_t slot = head2_leaf_slot_of(f_ctx);

	head2_leaf_at(f_ctx, slot, &vaddr);
	fm_ctx_setup(out_fm_ctx, f_ctx, &vaddr, NULL, slot, f_ctx->off);
}

static void set_head2_leaf_at(const struct voluta_file_ctx *f_ctx,
                              size_t slot, const struct voluta_vaddr *vaddr)
{
	file_set_head2_leaf(f_ctx->ii, slot, vaddr);
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

static size_t distance_to_next(const struct voluta_file_ctx *f_ctx)
{
	const enum voluta_vtype vtype = off_to_data_vtype(f_ctx->off);

	return len_to_next(f_ctx->off, vtype);
}

static void advance_to(struct voluta_file_ctx *f_ctx, loff_t off)
{
	f_ctx->off = off_max_min(f_ctx->off, off, f_ctx->end);
}

static void advance_by_nbytes(struct voluta_file_ctx *f_ctx, size_t len)
{
	voluta_assert_gt(len, 0);
	advance_to(f_ctx, off_end(f_ctx->off, len));
}

static void advance_to_next(struct voluta_file_ctx *f_ctx)
{
	advance_by_nbytes(f_ctx, distance_to_next(f_ctx));
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
	if ((off + llen) < off) {
		return -EOVERFLOW;
	}
	return 0;
}

static int check_seek_pos(loff_t pos, loff_t isz, int whence)
{
	if ((whence == SEEK_DATA) || (whence == SEEK_HOLE)) {
		if ((pos >= isz) || (pos < 0)) {
			return -ENXIO;
		}
	}
	return 0;
}

static int check_file_io(const struct voluta_file_ctx *f_ctx)
{
	int err;
	loff_t isz;
	const size_t len_max = VOLUTA_IO_SIZE_MAX;

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
		if (f_ctx->len > len_max) {
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
		if (!off_isaligned(f_ctx->beg) && (f_ctx->len > len_max)) {
			return -EINVAL;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int seek_tree_recursive(struct voluta_file_ctx *f_ctx,
                               struct voluta_vnode_info *parent_vi,
                               struct voluta_fmap_ctx *out_fm_ctx);

static bool kcopy_mode(const struct voluta_file_ctx *f_ctx)
{
	const long unsigned flags = f_ctx->sbi->sb_ctl_flags;
	const long unsigned mask = VOLUTA_F_ENCRYPTED | VOLUTA_F_ENCRYPTWR;

	return ((flags & mask) == 0);
}

static bool is_mapping_boundaries(const struct voluta_file_ctx *f_ctx)
{
	const loff_t mapping_size =
	        (VOLUTA_FILE_TREE_LEAF_SIZE * VOLUTA_FILE_TREE_NCHILDS);

	return ((f_ctx->off % mapping_size) == 0);
}

static void update_post_io(const struct voluta_file_ctx *f_ctx,
                           bool kill_suid_sgid)
{
	struct voluta_iattr iattr;
	struct voluta_inode_info *ii = f_ctx->ii;
	const loff_t isz = ii_size(ii);
	const loff_t isp = ii_span(ii);
	const loff_t off = f_ctx->off;
	const loff_t end = f_ctx->end;
	const size_t len = io_length(f_ctx);

	iattr_setup(&iattr, ii_ino(ii));
	if (f_ctx->op_mask & OP_READ) {
		iattr.ia_flags |= VOLUTA_IATTR_ATIME | VOLUTA_IATTR_LAZY;
	} else if (f_ctx->op_mask & (OP_WRITE | OP_COPY_RANGE)) {
		iattr.ia_flags |= VOLUTA_IATTR_SIZE | VOLUTA_IATTR_SPAN;
		iattr.ia_size = off_max(off, isz);
		iattr.ia_span = off_max(off, isp);
		if (len > 0) {
			iattr.ia_flags |= VOLUTA_IATTR_MCTIME;
			if (kill_suid_sgid) {
				iattr.ia_flags |= VOLUTA_IATTR_KILL_SUID;
				iattr.ia_flags |= VOLUTA_IATTR_KILL_SGID;
			}
		}
	} else if (f_ctx->op_mask & OP_FALLOC) {
		iattr.ia_flags |= VOLUTA_IATTR_MCTIME | VOLUTA_IATTR_SPAN;
		iattr.ia_span = off_max(end, isp);
		if (!fl_keep_size(f_ctx)) {
			iattr.ia_flags |= VOLUTA_IATTR_SIZE;
			iattr.ia_size = off_max(end, isz);
		}
	} else if (f_ctx->op_mask & OP_TRUNC) {
		iattr.ia_flags |= VOLUTA_IATTR_SIZE | VOLUTA_IATTR_SPAN;
		iattr.ia_size = f_ctx->beg;
		iattr.ia_span = f_ctx->beg;
		if (isz != f_ctx->beg) {
			iattr.ia_flags |= VOLUTA_IATTR_MCTIME;
			if (kill_suid_sgid) {
				iattr.ia_flags |= VOLUTA_IATTR_KILL_SUID;
				iattr.ia_flags |= VOLUTA_IATTR_KILL_SGID;
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

static int probe_unwritten(const struct voluta_fmap_ctx *fm_ctx, bool *out_res)
{
	return probe_unwritten_at(fm_ctx->f_ctx, &fm_ctx->vaddr, out_res);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dirtify_data_leaf(const struct voluta_file_ctx *f_ctx,
                              struct voluta_vnode_info *leaf_vi)
{
	voluta_assert(vaddr_isdata(vi_vaddr(leaf_vi)));

	vi_dirtify(leaf_vi);
	if (!kcopy_mode(f_ctx)) {
		/* for data checksum, need to do:  */
		/* vi_dirtify(agi); */
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

static int zero_data_leaf_range(const struct voluta_file_ctx *f_ctx,
                                const struct voluta_vaddr *vaddr,
                                loff_t off_in_bk, size_t len)
{
	int err;
	struct voluta_vnode_info *vi;
	struct voluta_fiovec fiov = { .fv_base = NULL };

	if (kcopy_mode(f_ctx)) {
		err = fiovec_of_data(f_ctx, vaddr, off_in_bk, len, &fiov);
		if (err) {
			return err;
		}
		err = fiovec_copy_from(&fiov, nil_bk_buf_of(f_ctx));
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

static int zero_data_leaf_at(const struct voluta_file_ctx *f_ctx,
                             const struct voluta_vaddr *vaddr)
{
	const ssize_t len = data_size_of(vaddr->vtype);

	return zero_data_leaf_range(f_ctx, vaddr, 0, (size_t)len);
}

static int stage_data_leaf_at(const struct voluta_fmap_ctx *fm_ctx,
                              struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_sb_info *sbi = fm_ctx->f_ctx->sbi;
	struct voluta_inode_info *ii = fm_ctx->f_ctx->ii;

	voluta_assert(!kcopy_mode(fm_ctx->f_ctx));

	*out_vi = NULL;
	if (!fm_ctx->has_data) {
		return -ENOENT;
	}
	err = voluta_stage_data(sbi, &fm_ctx->vaddr, ii, out_vi);
	if (err) {
		return err;
	}
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
	err = voluta_stage_vnode(f_ctx->sbi, vaddr, f_ctx->ii, out_vi);
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

static int seek_tree_at_leaves(struct voluta_file_ctx *f_ctx,
                               struct voluta_vnode_info *parent_vi,
                               struct voluta_fmap_ctx *out_fm_ctx)
{
	size_t start_slot;
	const size_t nslots_max = nchilds_max(parent_vi);
	const bool seek_hole = is_seek_hole(f_ctx);

	start_slot = iter_start_slot(f_ctx, parent_vi);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		advance_to_tree_slot(f_ctx, parent_vi, slot);
		if (!has_more_io(f_ctx)) {
			break;
		}
		resolve_child_at(f_ctx, parent_vi, f_ctx->off,
		                 slot, out_fm_ctx);
		if (seek_hole == out_fm_ctx->has_hole) {
			return 0;
		}
	}
	return -ENOENT;
}

static int
seek_tree_recursive_at(struct voluta_file_ctx *f_ctx,
                       struct voluta_vnode_info *parent_vi, size_t slot,
                       struct voluta_fmap_ctx *out_fm_ctx)
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
	err = seek_tree_recursive(f_ctx, vi, out_fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int do_seek_tree_recursive(struct voluta_file_ctx *f_ctx,
                                  struct voluta_vnode_info *parent_vi,
                                  struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;
	size_t start_slot;
	const size_t nslots_max = nchilds_max(parent_vi);

	if (!isinrange(parent_vi, f_ctx->off)) {
		return -ENOENT;
	}
	if (isbottom(parent_vi)) {
		return seek_tree_at_leaves(f_ctx, parent_vi, out_fm_ctx);
	}
	err = is_seek_hole(f_ctx) ? 0 : -ENOENT;
	start_slot = child_slot_of(parent_vi, f_ctx->off);
	for (size_t slot = start_slot; slot < nslots_max; ++slot) {
		err = seek_tree_recursive_at(f_ctx, parent_vi,
		                             slot, out_fm_ctx);
		if (err != -ENOENT) {
			break;
		}
		advance_to_next_tree_slot(f_ctx, parent_vi, slot);
	}
	return err;
}

static int seek_tree_recursive(struct voluta_file_ctx *f_ctx,
                               struct voluta_vnode_info *parent_vi,
                               struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;

	vi_incref(parent_vi);
	err = do_seek_tree_recursive(f_ctx, parent_vi, out_fm_ctx);
	vi_decref(parent_vi);
	return err;
}

static int seek_by_tree_map(struct voluta_file_ctx *f_ctx,
                            struct voluta_fmap_ctx *out_fm_ctx)
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
	err = seek_tree_recursive(f_ctx, root_vi, out_fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int seek_data_by_head_leaves(struct voluta_file_ctx *f_ctx,
                                    struct voluta_fmap_ctx *out_fm_ctx)
{
	while (has_head1_leaves_io(f_ctx)) {
		resolve_head1_leaf(f_ctx, out_fm_ctx);
		if (out_fm_ctx->has_data) {
			return 0;
		}
		advance_to_next(f_ctx);
	}
	while (has_head2_leaves_io(f_ctx)) {
		resolve_head2_leaf(f_ctx, out_fm_ctx);
		if (out_fm_ctx->has_data) {
			return 0;
		}
		advance_to_next(f_ctx);
	}
	return -ENOENT;
}

static int seek_hole_by_head_leaves(struct voluta_file_ctx *f_ctx,
                                    struct voluta_fmap_ctx *out_fm_ctx)
{
	while (has_head1_leaves_io(f_ctx)) {
		resolve_head1_leaf(f_ctx, out_fm_ctx);
		if (out_fm_ctx->has_hole) {
			return 0;
		}
		advance_to_next(f_ctx);
	}
	while (has_head2_leaves_io(f_ctx)) {
		resolve_head2_leaf(f_ctx, out_fm_ctx);
		if (out_fm_ctx->has_hole) {
			return 0;
		}
		advance_to_next(f_ctx);
	}
	return -ENOENT;
}

static int resolve_fiovec(const struct voluta_file_ctx *f_ctx,
                          struct voluta_vnode_info *vi,
                          const struct voluta_vaddr *vaddr,
                          struct voluta_fiovec *out_fiov)
{
	int err;
	enum voluta_vtype vtype;

	if (vi != NULL) {
		err = fiovec_of_vnode(f_ctx, vi, out_fiov);
	} else if ((vaddr != NULL) && !vaddr_isnull(vaddr)) {
		err = fiovec_of_vaddr(f_ctx, vaddr, out_fiov);
	} else {
		vtype = off_to_data_vtype(f_ctx->off);
		err = fiovec_of_zeros(f_ctx, vtype, out_fiov);
	}
	return err;
}

static int call_rw_actor(const struct voluta_file_ctx *f_ctx,
                         struct voluta_vnode_info *vi,
                         const struct voluta_vaddr *vaddr,
                         size_t *out_len)
{
	int err;
	struct voluta_fiovec fiov = {
		.fv_base = NULL,
		.fv_off = -1,
		.fv_len = 0,
		.fv_fd = -1,
	};

	err = resolve_fiovec(f_ctx, vi, vaddr, &fiov);
	if (err) {
		return err;
	}
	err = f_ctx->rwi_ctx->actor(f_ctx->rwi_ctx, &fiov);
	if (err) {
		return err;
	}
	*out_len = fiov.fv_len;
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
                                 struct voluta_fmap_ctx *out_fm_ctx)
{
	resolve_child(f_ctx, parent_vi, f_ctx->off, out_fm_ctx);
}

static void resolve_tree_leaf(const struct voluta_file_ctx *f_ctx,
                              struct voluta_vnode_info *parent_vi,
                              struct voluta_fmap_ctx *out_fm_ctx)
{
	child_of_current_pos(f_ctx, parent_vi, out_fm_ctx);
}

static void resolve_curr_node(const struct voluta_file_ctx *f_ctx,
                              struct voluta_vnode_info *parent_vi,
                              struct voluta_fmap_ctx *out_fm_ctx)
{
	child_of_current_pos(f_ctx, parent_vi, out_fm_ctx);
}

static int stage_by_tree_map(const struct voluta_file_ctx *f_ctx,
                             struct voluta_vnode_info **out_vi)
{
	int err;
	size_t height;
	struct voluta_vnode_info *vi;
	struct voluta_fmap_ctx fm_ctx = { .file_pos = -1 };

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
		resolve_curr_node(f_ctx, vi, &fm_ctx);
		err = stage_radix_tnode(f_ctx, &fm_ctx.vaddr, &vi);
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

static int read_leaf_at(struct voluta_file_ctx *f_ctx,
                        const struct voluta_fmap_ctx *fm_ctx, size_t *out_sz)
{
	return export_data_by_vaddr(f_ctx, &fm_ctx->vaddr, out_sz);
}

static int read_leaf_as_zeros(struct voluta_file_ctx *f_ctx, size_t *out_sz)
{
	return export_data_by_vaddr(f_ctx, NULL, out_sz);
}

static int read_from_leaf(struct voluta_file_ctx *f_ctx,
                          const struct voluta_fmap_ctx *fm_ctx,
                          size_t *out_len)
{
	int err;
	bool unwritten = false;
	struct voluta_vnode_info *vi = NULL;

	*out_len = 0;
	err = probe_unwritten(fm_ctx, &unwritten);
	if (err) {
		return err;
	}
	if (unwritten) {
		err = read_leaf_as_zeros(f_ctx, out_len);
		if (err) {
			return err;
		}
	} else if (kcopy_mode(f_ctx)) {
		err = read_leaf_at(f_ctx, fm_ctx, out_len);
		if (err) {
			return err;
		}
	} else {
		err = stage_data_leaf_at(fm_ctx, &vi);
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
	struct voluta_fmap_ctx fm_ctx;

	while (has_more_io(f_ctx)) {
		resolve_tree_leaf(f_ctx, parent_vi, &fm_ctx);
		err = read_from_leaf(f_ctx, &fm_ctx, &len);
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
	struct voluta_fmap_ctx fm_ctx;

	while (has_head1_leaves_io(f_ctx)) {
		resolve_head1_leaf(f_ctx, &fm_ctx);
		err = read_from_leaf(f_ctx, &fm_ctx, &len);
		if (err) {
			return err;
		}
		advance_by_nbytes(f_ctx, len);
	}
	while (has_head2_leaves_io(f_ctx)) {
		resolve_head2_leaf(f_ctx, &fm_ctx);
		err = read_from_leaf(f_ctx, &fm_ctx, &len);
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
                           const struct voluta_fiovec *fiov)
{
	int err;
	struct voluta_read_iter *rdi = read_iter_of(rwi);

	if ((fiov->fv_fd > 0) && (fiov->fv_off < 0)) {
		return -EINVAL;
	}
	if ((rdi->dat_len + fiov->fv_len) > rdi->dat_max) {
		return -EINVAL;
	}
	err = fiovec_copy_into(fiov, rdi->dat + rdi->dat_len);
	if (err) {
		return err;
	}
	rdi->dat_len += fiov->fv_len;
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
	update_post_io(f_ctx, false);
	return err;
}

static int read_iter(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_inode_info *ii = f_ctx->ii;

	ii_incref(ii);
	err = do_read_iter(f_ctx);
	ii_decref(ii);
	return err;
}

int voluta_do_read_iter(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        struct voluta_rwiter_ctx *rwi)
{
	struct voluta_file_ctx f_ctx = {
		.op = op,
		.sbi = ii_sbi(ii),
		.ii = ii,
		.op_mask = OP_READ,
		.with_backref = 1,
	};

	update_with_rw_iter(&f_ctx, rwi);
	return read_iter(&f_ctx);
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
		.dat_max = len,
	};
	struct voluta_file_ctx f_ctx = {
		.op = op,
		.sbi = ii_sbi(ii),
		.ii = ii,
		.op_mask = OP_READ,
		.with_backref = 0,
	};

	update_with_rw_iter(&f_ctx, &rdi.rwi);
	err = read_iter(&f_ctx);
	*out_len = rdi.dat_len;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int clear_unwritten_at(const struct voluta_file_ctx *f_ctx,
                              const struct voluta_vaddr *vaddr)
{
	voluta_assert(vaddr_isdata(vaddr));

	return voluta_clear_unwritten(f_ctx->sbi, vaddr);
}

static int clear_unwritten_of(const struct voluta_file_ctx *f_ctx,
                              struct voluta_vnode_info *vi)
{
	int err;

	err = clear_unwritten_at(f_ctx, vi_vaddr(vi));
	if (err) {
		return err;
	}
	dirtify_data_leaf(f_ctx, vi);
	return 0;
}

static int clear_unwritten_by(const struct voluta_fmap_ctx *fm_ctx)
{
	return clear_unwritten_at(fm_ctx->f_ctx, &fm_ctx->vaddr);
}

static int new_data_vspace(const struct voluta_file_ctx *f_ctx,
                           enum voluta_vtype vtype, struct voluta_vaddr *out)
{
	return voluta_allocate_space(f_ctx->sbi, vtype, out);
}

static bool vaddr_isdatabk(const struct voluta_vaddr *vaddr)
{
	return vtype_isequal(vaddr->vtype, VOLUTA_VTYPE_DATABK);
}

static int del_data_vspace(const struct voluta_file_ctx *f_ctx,
                           const struct voluta_vaddr *vaddr)
{
	int err;
	bool last = false;

	voluta_assert(vaddr_isdata(vaddr));

	err = voluta_refcnt_islast_at(f_ctx->sbi, vaddr, &last);
	if (err) {
		return err;
	}
	if (last || !vaddr_isdatabk(vaddr)) {
		err = clear_unwritten_at(f_ctx, vaddr);
		if (err) {
			return err;
		}
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
	return voluta_spawn_vnode(f_ctx->sbi, f_ctx->ii,
	                          VOLUTA_VTYPE_RTNODE, out_vi);
}

static int del_rtnode(const struct voluta_file_ctx *f_ctx,
                      struct voluta_vnode_info *vi)
{
	voluta_assert_eq(vi->vaddr.vtype, VOLUTA_VTYPE_RTNODE);

	return voluta_remove_vnode(f_ctx->sbi, vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void update_head1_leaf(const struct voluta_fmap_ctx *fm_ctx)
{
	set_head1_leaf_at(fm_ctx->f_ctx, fm_ctx->slot_idx, &fm_ctx->vaddr);
	ii_dirtify(fm_ctx->f_ctx->ii);
}

static void update_head2_leaf(const struct voluta_fmap_ctx *fm_ctx)
{
	set_head2_leaf_at(fm_ctx->f_ctx, fm_ctx->slot_idx, &fm_ctx->vaddr);
	ii_dirtify(fm_ctx->f_ctx->ii);
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
	rtn_init_by(vi->vu.rtn, ii_ino(f_ctx->ii), off, height);
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

static int create_bind_rtnode(const struct voluta_file_ctx *f_ctx,
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
	bind_rtnode(parent_vi, file_pos, vi);

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

static int create_head1_leaf_space(const struct voluta_file_ctx *f_ctx,
                                   struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;
	struct voluta_vaddr vaddr;
	const size_t slot = head1_leaf_slot_of(f_ctx);

	err = create_data_leaf(f_ctx, VOLUTA_VTYPE_DATA1K, &vaddr);
	if (err) {
		return err;
	}
	fm_ctx_setup(out_fm_ctx, f_ctx, &vaddr, NULL, slot, f_ctx->off);
	update_head1_leaf(out_fm_ctx);
	return 0;
}

static int create_head2_leaf_space(const struct voluta_file_ctx *f_ctx,
                                   struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;
	struct voluta_vaddr vaddr;
	const size_t slot = head2_leaf_slot_of(f_ctx);

	err = create_data_leaf(f_ctx, VOLUTA_VTYPE_DATA4K, &vaddr);
	if (err) {
		return err;
	}
	fm_ctx_setup(out_fm_ctx, f_ctx, &vaddr, NULL, slot, f_ctx->off);
	update_head2_leaf(out_fm_ctx);
	return 0;
}

static int create_tree_leaf_space(const struct voluta_file_ctx *f_ctx,
                                  struct voluta_vnode_info *parent_vi,
                                  struct voluta_vaddr *out_vaddr)
{
	int err;

	vi_incref(parent_vi);
	err = create_data_leaf(f_ctx, VOLUTA_VTYPE_DATABK, out_vaddr);
	if (!err) {
		bind_child(parent_vi, f_ctx->off, out_vaddr);
	}
	vi_decref(parent_vi);
	return err;
}

static void bind_sub_tree(const struct voluta_file_ctx *f_ctx,
                          struct voluta_vnode_info *vi)
{
	struct voluta_vaddr vaddr;

	tree_root_of(f_ctx, &vaddr);
	rtn_set_child(vi->vu.rtn, 0, vaddr.off);
	vi_dirtify(vi);

	update_tree_root(f_ctx, vi_vaddr(vi));
	bind_rtnode(NULL, 0, vi);
}

static size_t off_to_height(loff_t off)
{
	return rtn_height_by_file_pos(NULL, off);
}

static int create_tree_spine(const struct voluta_file_ctx *f_ctx)
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

static int do_stage_or_create_rtnode(const struct voluta_file_ctx *f_ctx,
                                     struct voluta_vnode_info *parent_vi,
                                     struct voluta_vnode_info **out_vi)
{
	int err;
	struct voluta_fmap_ctx fm_ctx;

	resolve_curr_node(f_ctx, parent_vi, &fm_ctx);
	if (fm_ctx.has_target) {
		err = stage_radix_tnode(f_ctx, &fm_ctx.vaddr, out_vi);
	} else {
		err = create_bind_rtnode(f_ctx, parent_vi, out_vi);
	}
	return err;
}

static int stage_or_create_rtnode(const struct voluta_file_ctx *f_ctx,
                                  struct voluta_vnode_info *parent_vi,
                                  struct voluta_vnode_info **out_vi)
{
	int err;

	vi_incref(parent_vi);
	err = do_stage_or_create_rtnode(f_ctx, parent_vi, out_vi);
	vi_decref(parent_vi);
	return err;
}

static int stage_or_create_tree_path(const struct voluta_file_ctx *f_ctx,
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
		err = stage_or_create_rtnode(f_ctx, vi, &vi);
		if (err) {
			return err;
		}
	}
	return unlikely(*out_vi == NULL) ? -EFSCORRUPTED : 0;
}

static int stage_or_create_tree_map(const struct voluta_file_ctx *f_ctx,
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

static int do_write_leaf_by_copy(const struct voluta_file_ctx *f_ctx,
                                 struct voluta_vnode_info *leaf_vi,
                                 size_t *out_sz)
{
	int err;

	err = import_data_by_vnode(f_ctx, leaf_vi, out_sz);
	if (err) {
		return err;
	}
	err = clear_unwritten_of(f_ctx, leaf_vi);
	if (err) {
		return err;
	}
	return 0;
}

static int write_leaf_by_copy(const struct voluta_file_ctx *f_ctx,
                              struct voluta_vnode_info *leaf_vi,
                              size_t *out_sz)
{
	int err;

	vi_incref(leaf_vi);
	err = do_write_leaf_by_copy(f_ctx, leaf_vi, out_sz);
	vi_decref(leaf_vi);
	return err;
}

static int write_leaf_at(const struct voluta_file_ctx *f_ctx,
                         const struct voluta_fmap_ctx *fm_ctx, size_t *out_sz)
{
	int err;

	err = import_data_by_vaddr(f_ctx, &fm_ctx->vaddr, out_sz);
	if (err) {
		return err;
	}
	err = clear_unwritten_at(f_ctx, &fm_ctx->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int prepare_unwritten_leaf(const struct voluta_fmap_ctx *fm_ctx)
{
	int err;
	bool partial;
	bool unwritten;

	partial = has_partial_write(fm_ctx);
	if (!partial) {
		return 0;
	}
	err = probe_unwritten(fm_ctx, &unwritten);
	if (err) {
		return err;
	}
	if (!unwritten) {
		return 0;
	}
	err = zero_data_leaf_at(fm_ctx->f_ctx, &fm_ctx->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int require_tree_leaf(const struct voluta_file_ctx *f_ctx,
                             struct voluta_vnode_info *parent_vi,
                             struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;

	resolve_tree_leaf(f_ctx, parent_vi, out_fm_ctx);
	if (out_fm_ctx->has_data) {
		voluta_assert(out_fm_ctx->has_target);
		return 0;
	}
	err = create_tree_leaf_space(f_ctx, parent_vi, &out_fm_ctx->vaddr);
	if (err) {
		return err;
	}
	out_fm_ctx->has_target = true;
	out_fm_ctx->has_data = true;
	out_fm_ctx->has_hole = false;

	return 0;
}

static int write_to_leaf(const struct voluta_fmap_ctx *fm_ctx, size_t *out_len)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	*out_len = 0;
	err = prepare_unwritten_leaf(fm_ctx);
	if (err) {
		return err;
	}
	if (kcopy_mode(fm_ctx->f_ctx)) {
		err = write_leaf_at(fm_ctx->f_ctx, fm_ctx, out_len);
		if (err) {
			return err;
		}
	} else {
		err = stage_data_leaf_at(fm_ctx, &vi);
		if (err) {
			return err;
		}
		err = write_leaf_by_copy(fm_ctx->f_ctx, vi, out_len);
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
	struct voluta_fmap_ctx fm_ctx;

	while (has_more_io(f_ctx)) {
		err = require_tree_leaf(f_ctx, parent_vi, &fm_ctx);
		if (err) {
			return err;
		}
		err = write_to_leaf(&fm_ctx, &len);
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

static int require_head1_leaf(const struct voluta_file_ctx *f_ctx,
                              struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;

	resolve_head1_leaf(f_ctx, out_fm_ctx);
	if (out_fm_ctx->has_data) {
		return 0;
	}
	err = create_head1_leaf_space(f_ctx, out_fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int require_head2_leaf(const struct voluta_file_ctx *f_ctx,
                              struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;

	resolve_head2_leaf(f_ctx, out_fm_ctx);
	if (out_fm_ctx->has_data) {
		return 0;
	}
	err = create_head2_leaf_space(f_ctx, out_fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int write_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	size_t len = 0;
	struct voluta_fmap_ctx fm_ctx;

	while (has_head1_leaves_io(f_ctx)) {
		err = require_head1_leaf(f_ctx, &fm_ctx);
		if (err) {
			return err;
		}
		err = write_to_leaf(&fm_ctx, &len);
		if (err) {
			return err;
		}
		advance_by_nbytes(f_ctx, len);
	}
	while (has_head2_leaves_io(f_ctx)) {
		err = require_head2_leaf(f_ctx, &fm_ctx);
		if (err) {
			return err;
		}
		err = write_to_leaf(&fm_ctx, &len);
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
                            const struct voluta_fiovec *fiov)
{
	int err;
	struct voluta_write_iter *wri = write_iter_of(rwi);

	if ((fiov->fv_fd > 0) && (fiov->fv_off < 0)) {
		return -EINVAL;
	}
	if ((wri->dat_len + fiov->fv_len) > wri->dat_max) {
		return -EINVAL;
	}
	err = fiovec_copy_from(fiov, wri->dat + wri->dat_len);
	if (err) {
		return err;
	}
	wri->dat_len += fiov->fv_len;
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
	update_post_io(f_ctx, !err && (f_ctx->off > f_ctx->beg));
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
		.with_backref = 1,
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
		.with_backref = 0,
	};

	update_with_rw_iter(&f_ctx, &wri.rwi);
	err = write_iter(&f_ctx);
	*out_len = wri.dat_len;
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_do_rdwr_post(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        const struct voluta_fiovec *fiov, size_t cnt)
{
	ii_incref(ii);
	for (size_t i = 0; i < cnt; ++i) {
		voluta_fiovref_do_post(fiov[i].fv_ref);
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

static int drop_rtnode(struct voluta_file_ctx *f_ctx,
                       struct voluta_vnode_info *vi)
{
	int err = 0;
	struct voluta_radix_tnode *rtn = vi->vu.rtn;

	rtn_dec_refcnt(vi->vu.rtn);
	if (!rtn_refcnt(rtn)) {
		err = del_rtnode(f_ctx, vi);
	}
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
	err = drop_rtnode(f_ctx, vi);
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

static int drop_head1_leaf_at(struct voluta_file_ctx *f_ctx, size_t slot)
{
	struct voluta_vaddr vaddr;

	head1_leaf_at(f_ctx, slot, &vaddr);
	return discard_data_leaf(f_ctx, &vaddr);
}

static int drop_head2_leaf_at(struct voluta_file_ctx *f_ctx, size_t slot)
{
	struct voluta_vaddr vaddr;

	head2_leaf_at(f_ctx, slot, &vaddr);
	return discard_data_leaf(f_ctx, &vaddr);
}

static void
reset_head1_leaf_at(const struct voluta_file_ctx *f_ctx, size_t slot)
{
	set_head1_leaf_at(f_ctx, slot, vaddr_none());
	ii_dirtify(f_ctx->ii);
}

static void
reset_head2_leaf_at(const struct voluta_file_ctx *f_ctx, size_t slot)
{
	set_head2_leaf_at(f_ctx, slot, vaddr_none());
	ii_dirtify(f_ctx->ii);
}

static size_t num_head1_leaf_slots(const struct voluta_file_ctx *f_ctx)
{
	return ris_num_head1_leaves(ii_ris_of(f_ctx->ii));
}

static size_t num_head2_leaf_slots(const struct voluta_file_ctx *f_ctx)
{
	return ris_num_head2_leaves(ii_ris_of(f_ctx->ii));
}

static int drop_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	size_t nslots;

	nslots = num_head1_leaf_slots(f_ctx);
	for (size_t slot = 0; slot < nslots; ++slot) {
		err = drop_head1_leaf_at(f_ctx, slot);
		if (err) {
			return err;
		}
		reset_head1_leaf_at(f_ctx, slot);
	}
	nslots = num_head2_leaf_slots(f_ctx);
	for (size_t slot = 0; slot < nslots; ++slot) {
		err = drop_head2_leaf_at(f_ctx, slot);
		if (err) {
			return err;
		}
		reset_head2_leaf_at(f_ctx, slot);
	}
	return 0;
}

static int drop_data_and_meta(struct voluta_file_ctx *f_ctx)
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

	voluta_assert_ge(ii_span(ii), ii_size(ii));

	ii_incref(ii);
	err = drop_data_and_meta(&f_ctx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int do_discard_partial(const struct voluta_fmap_ctx *fm_ctx)
{
	const struct voluta_vaddr *vaddr = &fm_ctx->vaddr;
	const loff_t off = fm_ctx->file_pos;
	const loff_t oid = off_in_data(off, vaddr->vtype);
	const size_t len = len_of_data(off, fm_ctx->f_ctx->end, vaddr->vtype);

	return zero_data_leaf_range(fm_ctx->f_ctx, vaddr, oid, len);
}

static int discard_partial(const struct voluta_fmap_ctx *fm_ctx)
{
	int err;

	vi_incref(fm_ctx->parent);
	err = do_discard_partial(fm_ctx);
	vi_decref(fm_ctx->parent);

	return err;
}

static int discard_data_leaf_at(const struct voluta_fmap_ctx *fm_ctx)
{
	int err;

	vi_incref(fm_ctx->parent);
	err = discard_data_leaf(fm_ctx->f_ctx, &fm_ctx->vaddr);
	vi_decref(fm_ctx->parent);

	return err;
}

static void clear_subtree_mappings(struct voluta_vnode_info *vi, size_t slot)
{
	if (likely(vi != NULL)) { /* make clang-scan happy */
		rtn_reset_child(vi->vu.rtn, slot);
		vi_dirtify(vi);
	}
}

static int discard_entire(const struct voluta_fmap_ctx *fm_ctx)
{
	int err;

	err = discard_data_leaf_at(fm_ctx);
	if (err) {
		return err;
	}
	if (off_is_head1(fm_ctx->file_pos)) {
		voluta_assert_null(fm_ctx->parent);
		reset_head1_leaf_at(fm_ctx->f_ctx, fm_ctx->slot_idx);
	} else if (off_is_head2(fm_ctx->file_pos)) {
		voluta_assert_null(fm_ctx->parent);
		reset_head2_leaf_at(fm_ctx->f_ctx, fm_ctx->slot_idx);
	} else {
		voluta_assert_not_null(fm_ctx->parent);
		clear_subtree_mappings(fm_ctx->parent, fm_ctx->slot_idx);
	}
	return 0;
}

static int discard_by_set_unwritten(const struct voluta_fmap_ctx *fm_ctx)
{
	return voluta_mark_unwritten(fm_ctx->f_ctx->sbi, &fm_ctx->vaddr);
}

static int discard_data_at(const struct voluta_fmap_ctx *fm_ctx)
{
	int err = 0;
	bool partial;
	const loff_t end = fm_ctx->f_ctx->end;
	const enum voluta_vtype vtype = fm_ctx->vaddr.vtype;

	voluta_assert_lt(fm_ctx->file_pos, end);
	if (fm_ctx->has_data) {
		partial = off_is_partial(fm_ctx->file_pos, end, vtype);
		if (partial) {
			err = discard_partial(fm_ctx);
		} else if (fl_zero_range(fm_ctx->f_ctx)) {
			err = discard_by_set_unwritten(fm_ctx);
		} else {
			err = discard_entire(fm_ctx);
		}
	}
	return err;
}

static int discard_by_tree_map(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_fmap_ctx fm_ctx;

	if (!has_tree_root(f_ctx)) {
		return 0;
	}
	while (has_more_io(f_ctx)) {
		err = seek_by_tree_map(f_ctx, &fm_ctx);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = discard_data_at(&fm_ctx);
		if (err) {
			return err;
		}
		advance_to_next(f_ctx);
	}
	return 0;
}

static int discard_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	int err;
	struct voluta_fmap_ctx fm_ctx;

	while (has_head1_leaves_io(f_ctx)) {
		resolve_head1_leaf(f_ctx, &fm_ctx);
		err = discard_data_at(&fm_ctx);
		if (err) {
			return err;
		}
		advance_to_next(f_ctx);
	}
	while (has_head2_leaves_io(f_ctx)) {
		resolve_head2_leaf(f_ctx, &fm_ctx);
		err = discard_data_at(&fm_ctx);
		if (err) {
			return err;
		}
		advance_to_next(f_ctx);
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
	return (f_ctx->beg == 0) ? drop_data_and_meta(f_ctx) : 0;
}

static loff_t head_leaves_end(const struct voluta_file_ctx *f_ctx)
{
	size_t slot;
	struct voluta_vaddr vaddr;

	slot = num_head2_leaf_slots(f_ctx);
	while (slot-- > 0) {
		head2_leaf_at(f_ctx, slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			return head2_off_end(slot);
		}
	}
	slot = num_head1_leaf_slots(f_ctx);
	while (slot-- > 0) {
		head1_leaf_at(f_ctx, slot, &vaddr);
		if (!vaddr_isnull(&vaddr)) {
			return head1_off_end(slot);
		}
	}
	return 0;
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
	loff_t end_tree;

	err = tree_leaves_end(f_ctx, &end_tree);
	if (err) {
		return err;
	}
	f_ctx->end = off_max3(f_ctx->off, head_leaves_end(f_ctx), end_tree);
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
	update_post_io(f_ctx, err == 0);
	return err;
}

int voluta_do_truncate(const struct voluta_oper *op,
                       struct voluta_inode_info *ii, loff_t off)
{
	int err;
	const loff_t isp = ii_span(ii);
	const size_t len = (off < isp) ? off_ulen(off, isp) : 0;
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

	voluta_assert_ge(ii_span(ii), ii_size(ii));

	ii_incref(ii);
	err = do_truncate(&f_ctx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lseek_data_leaf(struct voluta_file_ctx *f_ctx,
                           struct voluta_fmap_ctx *fm_ctx)
{
	int err;

	voluta_assert_eq(f_ctx->whence, SEEK_DATA);

	err = seek_data_by_head_leaves(f_ctx, fm_ctx);
	if (!err || (err != -ENOENT)) {
		return err;
	}
	err = seek_by_tree_map(f_ctx, fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int lseek_data(struct voluta_file_ctx *f_ctx)
{
	int err;
	const loff_t isz = ii_size(f_ctx->ii);
	struct voluta_fmap_ctx fm = {
		.parent = NULL,
	};

	err = lseek_data_leaf(f_ctx, &fm);
	if (err == 0) {
		f_ctx->off = off_max_min(fm.file_pos, f_ctx->off, isz);
	} else if (err == -ENOENT) {
		f_ctx->off = isz;
		err = -ENXIO;
	}
	return err;
}

static int lseek_hole_noleaf(struct voluta_file_ctx *f_ctx,
                             struct voluta_fmap_ctx *fm_ctx)
{
	int err;

	err = seek_hole_by_head_leaves(f_ctx, fm_ctx);
	if (!err || (err != -ENOENT)) {
		return err;
	}
	err = seek_by_tree_map(f_ctx, fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int lseek_hole(struct voluta_file_ctx *f_ctx)
{
	int err;
	const loff_t isz = ii_size(f_ctx->ii);
	struct voluta_fmap_ctx fm_ctx = {
		.parent = NULL,
	};

	err = lseek_hole_noleaf(f_ctx, &fm_ctx);
	if (err == 0) {
		f_ctx->off = off_max_min(fm_ctx.file_pos, f_ctx->off, isz);
	} else if (err == -ENOENT) {
		f_ctx->off = isz;
		err = 0;
	}
	return err;
}

static int lseek_notsupp(struct voluta_file_ctx *f_ctx)
{
	f_ctx->off = f_ctx->end;
	return -EOPNOTSUPP;
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

static bool fl_has_mode(const struct voluta_file_ctx *f_ctx, int fl_mask)
{
	return (f_ctx->fl_mode & fl_mask) == fl_mask;
}

static bool fl_keep_size(const struct voluta_file_ctx *f_ctx)
{
	return fl_has_mode(f_ctx, FALLOC_FL_KEEP_SIZE);
}

static bool fl_punch_hole(const struct voluta_file_ctx *f_ctx)
{
	return fl_has_mode(f_ctx, FALLOC_FL_PUNCH_HOLE);
}

static bool fl_zero_range(const struct voluta_file_ctx *f_ctx)
{
	return fl_has_mode(f_ctx, FALLOC_FL_ZERO_RANGE);
}

/*
 * TODO-0012: Proper handling for FALLOC_FL_KEEP_SIZE beyond file size
 *
 * See 'man 2 fallocate' for semantics details of FALLOC_FL_KEEP_SIZE
 * beyond end-of-file.
 */
static int check_fl_mode(const struct voluta_file_ctx *f_ctx)
{
	int mask;
	const int mode = f_ctx->fl_mode;

	/* punch hole and zero range are mutually exclusive */
	mask = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE;
	if ((mode & mask) == mask) {
		return -EOPNOTSUPP;
	}
	/* currently supported modes */
	mask = FALLOC_FL_KEEP_SIZE |
	       FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE;
	if (mode & ~mask) {
		return -EOPNOTSUPP;
	}
	return 0;
}

static int create_bind_tree_leaf(const struct voluta_file_ctx *f_ctx,
                                 struct voluta_vnode_info *parent_vi)
{
	int err;
	struct voluta_fmap_ctx fm_ctx;

	resolve_tree_leaf(f_ctx, parent_vi, &fm_ctx);
	if (fm_ctx.has_data) {
		return 0;
	}
	err = create_data_leaf(f_ctx, VOLUTA_VTYPE_DATABK, &fm_ctx.vaddr);
	if (err) {
		return err;
	}
	bind_child(parent_vi, f_ctx->off, &fm_ctx.vaddr);
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
		advance_to_next(f_ctx);
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
		err = stage_or_create_rtnode(f_ctx, vi, &vi);
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
	struct voluta_fmap_ctx fm_ctx;

	while (has_head1_leaves_io(f_ctx)) {
		err = require_head1_leaf(f_ctx, &fm_ctx);
		if (err) {
			return err;
		}
		advance_to_next(f_ctx);
	}
	while (has_head2_leaves_io(f_ctx)) {
		err = require_head2_leaf(f_ctx, &fm_ctx);
		if (err) {
			return err;
		}
		advance_to_next(f_ctx);
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

static int fallocate_zero_range(struct voluta_file_ctx *f_ctx)
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
	} else if (fl_zero_range(f_ctx)) {
		err = fallocate_zero_range(f_ctx);
	} else {
		err = -EOPNOTSUPP;
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
	update_post_io(f_ctx, false);
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
                            const struct voluta_vaddr *vaddr)
{
	loff_t end;
	size_t len;
	struct fiemap_extent *fm_ext;
	struct fiemap *fm = f_ctx->fm;

	end = off_min(off_end(f_ctx->off, vaddr->len), f_ctx->end);
	len = len_of_data(f_ctx->off, end, vaddr->vtype);
	if (len == 0) {
		return false;
	}
	if (fm->fm_extent_count == 0) {
		fm->fm_mapped_extents++;
		return true;
	}
	if (fm->fm_mapped_extents >= fm->fm_extent_count) {
		return false;
	}
	fm_ext = &fm->fm_extents[fm->fm_mapped_extents++];
	fm_ext->fe_flags = FIEMAP_EXTENT_DATA_ENCRYPTED;
	fm_ext->fe_logical = (uint64_t)(f_ctx->off);
	fm_ext->fe_physical = (uint64_t)(vaddr->off);
	fm_ext->fe_length = len;
	return true;
}

static bool emit_fiemap(struct voluta_file_ctx *f_ctx,
                        const struct voluta_fmap_ctx *fm_ctx)
{
	bool ok = true;

	if (fm_ctx->has_data) {
		ok = emit_fiemap_ext(f_ctx, &fm_ctx->vaddr);
		if (!ok) {
			f_ctx->fm_stop = true;
		}
	}
	return ok;
}

static int do_fiemap_by_tree_leaves(struct voluta_file_ctx *f_ctx,
                                    struct voluta_vnode_info *parent_vi)
{
	struct voluta_fmap_ctx fm_ctx;

	while (has_more_io(f_ctx)) {
		resolve_tree_leaf(f_ctx, parent_vi, &fm_ctx);
		if (!emit_fiemap(f_ctx, &fm_ctx)) {
			break;
		}
		advance_to_next(f_ctx);
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
	struct voluta_fmap_ctx fm_ctx = { .file_pos = -1 };

	while (has_more_io(f_ctx)) {
		err = seek_by_tree_map(f_ctx, &fm_ctx);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		err = fiemap_by_tree_leaves(f_ctx, fm_ctx.parent);
		if (err) {
			return err;
		}
		/* TODO: need to skip large holes */
	}
	return 0;
}

static int fiemap_by_head_leaves(struct voluta_file_ctx *f_ctx)
{
	struct voluta_fmap_ctx fm;

	while (has_head1_leaves_io(f_ctx)) {
		resolve_head1_leaf(f_ctx, &fm);
		if (!emit_fiemap(f_ctx, &fm)) {
			break;
		}
		advance_to_next(f_ctx);
	}
	while (has_head2_leaves_io(f_ctx)) {
		resolve_head2_leaf(f_ctx, &fm);
		if (!emit_fiemap(f_ctx, &fm)) {
			break;
		}
		advance_to_next(f_ctx);
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
		return -EOPNOTSUPP;
	}
	if (f_ctx->fm_flags & fm_allowed) {
		return -EOPNOTSUPP;
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

static int resolve_fmap_by_tree_recursive(struct voluta_file_ctx *f_ctx,
                struct voluta_vnode_info *parent_vi,
                struct voluta_fmap_ctx *out_fm_ctx);

static int resolve_fmap_by_head_leaves(struct voluta_file_ctx *f_ctx,
                                       struct voluta_fmap_ctx *out_fm_ctx)
{
	int err = 0;

	if (has_head1_leaves_io(f_ctx)) {
		resolve_head1_leaf(f_ctx, out_fm_ctx);
	} else if (has_head2_leaves_io(f_ctx)) {
		resolve_head2_leaf(f_ctx, out_fm_ctx);
	} else {
		fm_ctx_nomap(out_fm_ctx, f_ctx, NULL, f_ctx->off);
		err = -ENOENT;
	}
	return err;
}

static int
resolve_fmap_recursive_at(struct voluta_file_ctx *f_ctx,
                          struct voluta_vnode_info *parent_vi, size_t slot,
                          struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_vnode_info *vi;

	resolve_child_by_slot(parent_vi, slot, &vaddr);
	fm_ctx_nomap(out_fm_ctx, f_ctx, parent_vi, f_ctx->off);

	if (vaddr_isnull(&vaddr)) {
		return -ENOENT;
	}
	err = stage_radix_tnode(f_ctx, &vaddr, &vi);
	if (err) {
		return err;
	}
	err = resolve_fmap_by_tree_recursive(f_ctx, vi, out_fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int
do_resolve_fmap_by_tree_recursive(struct voluta_file_ctx *f_ctx,
                                  struct voluta_vnode_info *parent_vi,
                                  struct voluta_fmap_ctx *out_fm_ctx)
{
	size_t slot;

	if (!isinrange(parent_vi, f_ctx->off)) {
		return -ENOENT;
	}
	slot = child_slot_of(parent_vi, f_ctx->off);
	if (!isbottom(parent_vi)) {
		return resolve_fmap_recursive_at(f_ctx, parent_vi,
		                                 slot, out_fm_ctx);
	}
	resolve_child_at(f_ctx, parent_vi, f_ctx->off, slot, out_fm_ctx);
	return 0;
}

static int
resolve_fmap_by_tree_recursive(struct voluta_file_ctx *f_ctx,
                               struct voluta_vnode_info *parent_vi,
                               struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;

	vi_incref(parent_vi);
	err = do_resolve_fmap_by_tree_recursive(f_ctx, parent_vi, out_fm_ctx);
	vi_decref(parent_vi);
	return err;
}

static int resolve_fmap_by_tree_map(struct voluta_file_ctx *f_ctx,
                                    struct voluta_fmap_ctx *out_fm_ctx)
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
	err = resolve_fmap_by_tree_recursive(f_ctx, root_vi, out_fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int resolve_fmap_at(struct voluta_file_ctx *f_ctx,
                           struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;

	err = resolve_fmap_by_head_leaves(f_ctx, out_fm_ctx);
	if (err == -ENOENT) {
		err = resolve_fmap_by_tree_map(f_ctx, out_fm_ctx);
	}
	return err;
}

static size_t copy_length_of(const struct voluta_file_ctx *f_ctx)
{
	const size_t len_to_end = off_ulen(f_ctx->off, f_ctx->end);
	const size_t len_to_next = distance_to_next(f_ctx);

	return min(len_to_end, len_to_next);
}

static size_t copy_range_length(const struct voluta_fmap_ctx *fm_ctx_src,
                                const struct voluta_fmap_ctx *fm_ctx_dst)
{
	const size_t len_src = copy_length_of(fm_ctx_src->f_ctx);
	const size_t len_dst = copy_length_of(fm_ctx_dst->f_ctx);

	return min(len_src, len_dst);
}

static int resolve_leaf_vnode(const struct voluta_fmap_ctx *fm_ctx,
                              struct voluta_vnode_info **out_vi,
                              struct voluta_fiovec *out_fiov)
{
	int err;

	err = stage_data_leaf_at(fm_ctx, out_vi);
	if (err) {
		return err;
	}
	err = fiovec_of_vnode(fm_ctx->f_ctx, *out_vi, out_fiov);
	if (err) {
		return err;
	}
	return 0;
}

static int resolve_leaf_vaddr(const struct voluta_fmap_ctx *fm_ctx,
                              struct voluta_fiovec *out_fiov)
{
	voluta_assert(!vaddr_isnull(&fm_ctx->vaddr));

	return fiovec_of_vaddr(fm_ctx->f_ctx, &fm_ctx->vaddr, out_fiov);
}

static struct voluta_pipe *pipe_of(const struct voluta_fmap_ctx *fm_ctx)
{
	return & fm_ctx->f_ctx->sbi->sb_pipe;
}

static struct voluta_nullfd *nullfd_of(const struct voluta_fmap_ctx *fm_ctx)
{
	return & fm_ctx->f_ctx->sbi->sb_nullnfd;
}

static int copy_leaf(const struct voluta_fmap_ctx *fm_ctx_src,
                     const struct voluta_fmap_ctx *fm_ctx_dst, size_t len)
{
	int err;
	struct voluta_vnode_info *vi_src = NULL;
	struct voluta_vnode_info *vi_dst = NULL;
	struct voluta_fiovec fiov_src = { .fv_off = -1, .fv_fd = -1 };
	struct voluta_fiovec fiov_dst = { .fv_off = -1, .fv_fd = -1 };

	err = prepare_unwritten_leaf(fm_ctx_dst);
	if (err) {
		return err;
	}
	err = prepare_unwritten_leaf(fm_ctx_src);
	if (err) {
		return err;
	}
	if (kcopy_mode(fm_ctx_dst->f_ctx)) {
		err = resolve_leaf_vaddr(fm_ctx_src, &fiov_src);
		if (err) {
			return err;
		}
		err = resolve_leaf_vaddr(fm_ctx_dst, &fiov_dst);
		if (err) {
			return err;
		}
		err = fiovec_copy_splice(&fiov_src, &fiov_dst,
		                         pipe_of(fm_ctx_dst),
		                         nullfd_of(fm_ctx_dst), len);
		if (err) {
			return err;
		}
		err = clear_unwritten_by(fm_ctx_dst);
		if (err) {
			return err;
		}
	} else {
		err = resolve_leaf_vnode(fm_ctx_src, &vi_src, &fiov_src);
		if (err) {
			return err;
		}
		err = resolve_leaf_vnode(fm_ctx_dst, &vi_dst, &fiov_dst);
		if (err) {
			return err;
		}
		err = fiovec_copy_mem(&fiov_src, &fiov_dst, len);
		if (err) {
			return err;
		}
		err = clear_unwritten_of(fm_ctx_dst->f_ctx, vi_dst);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int require_tree_leaf2(const struct voluta_file_ctx *f_ctx,
                              struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;
	struct voluta_vnode_info *parent_vi = NULL;

	err = stage_or_create_tree_map(f_ctx, &parent_vi);
	if (err) {
		return err;
	}
	err = require_tree_leaf(f_ctx, parent_vi, out_fm_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int require_leaf(const struct voluta_file_ctx *f_ctx,
                        struct voluta_fmap_ctx *out_fm_ctx)
{
	int err;

	if (off_is_head1(f_ctx->off)) {
		err = require_head1_leaf(f_ctx, out_fm_ctx);
	} else if (off_is_head2(f_ctx->off)) {
		err = require_head2_leaf(f_ctx, out_fm_ctx);
	} else {
		err = require_tree_leaf2(f_ctx, out_fm_ctx);
	}
	return err;
}

static int
copy_range_at_leaf(const struct voluta_fmap_ctx *fm_ctx_src,
                   struct voluta_fmap_ctx *fm_ctx_dst, size_t *out_len)
{
	int err = 0;
	size_t len = 0;
	const struct voluta_file_ctx *f_ctx_dst = fm_ctx_dst->f_ctx;

	len = copy_range_length(fm_ctx_src, fm_ctx_dst);
	if (!fm_ctx_src->has_data) {
		if (fm_ctx_dst->has_data) {
			err = discard_data_at(fm_ctx_dst);
			if (err) {
				return err;
			}
		}
	} else {
		if (!fm_ctx_dst->has_data) {
			err = require_leaf(f_ctx_dst, fm_ctx_dst);
			if (err) {
				return err;
			}
		}
		err = copy_leaf(fm_ctx_src, fm_ctx_dst, len);
		if (err) {
			return err;
		}
	}
	*out_len = len;
	return 0;
}

static int copy_range_iter(struct voluta_file_ctx *f_ctx_src,
                           struct voluta_file_ctx *f_ctx_dst)
{
	int err;
	size_t len;
	struct voluta_fmap_ctx fm_ctx_src;
	struct voluta_fmap_ctx fm_ctx_dst;

	while (has_more_io(f_ctx_src) && has_more_io(f_ctx_dst)) {
		err = resolve_fmap_at(f_ctx_src, &fm_ctx_src);
		if (err && (err != -ENOENT)) {
			return err;
		}
		err = resolve_fmap_at(f_ctx_dst, &fm_ctx_dst);
		if (err && (err != -ENOENT)) {
			return err;
		}
		err = copy_range_at_leaf(&fm_ctx_src, &fm_ctx_dst, &len);
		if (err) {
			return err;
		}
		advance_by_nbytes(f_ctx_dst, len);
		advance_by_nbytes(f_ctx_src, len);
	}
	return 0;
}

static int check_copy_range(const struct voluta_file_ctx *f_ctx_src,
                            const struct voluta_file_ctx *f_ctx_dst)
{
	int err;
	const long len = (long)(f_ctx_dst->len);
	const loff_t off_src = f_ctx_src->off;
	const loff_t off_dst = f_ctx_dst->off;

	err = check_file_io(f_ctx_src);
	if (err) {
		return err;
	}
	err = check_file_io(f_ctx_dst);
	if (err) {
		return err;
	}
	/* don't allow overlapped copying within the same file. */
	if ((f_ctx_src->ii == f_ctx_dst->ii) &&
	    ((off_dst + len) > off_src) && (off_dst < (off_src + len))) {
		return -EINVAL;
	}
	return 0;
}

static int do_copy_range(struct voluta_file_ctx *f_ctx_src,
                         struct voluta_file_ctx *f_ctx_dst, size_t *out_ncp)
{
	int err;

	err = check_copy_range(f_ctx_src, f_ctx_dst);
	if (err) {
		return err;
	}
	err = copy_range_iter(f_ctx_src, f_ctx_dst);
	if (err) {
		return err;
	}
	update_post_io(f_ctx_dst, false);
	*out_ncp = io_length(f_ctx_dst);
	return 0;
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
		.with_backref = 0,
	};
	struct voluta_file_ctx f_ctx_out = {
		.op = op,
		.sbi = ii_sbi(ii_out),
		.ii = ii_out,
		.len = len,
		.beg = off_out,
		.off = off_out,
		.end = i_off_end(ii_out, off_out, len),
		.op_mask = OP_COPY_RANGE,
		.cp_flags = flags,
		.with_backref = 0,
	};

	ii_incref(ii_in);
	ii_incref(ii_out);
	err = do_copy_range(&f_ctx_in, &f_ctx_out, out_ncp);
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
