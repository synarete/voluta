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
#include <string.h>
#include <errno.h>
#include "libvoluta.h"

#define MPC_MAGIC               0xA119CE6D2BL
#define MPC_SIZE                VOLUTA_BK_SIZE
#define NOBJ_IN_MPC(t_)         (MPC_SIZE / sizeof(t_))
#define NBKI_IN_MPC             NOBJ_IN_MPC(struct voluta_mobj_bki)
#define NVI_IN_MPC              NOBJ_IN_MPC(struct voluta_mobj_vi)
#define NII_IN_MPC              NOBJ_IN_MPC(struct voluta_mobj_ii)


union voluta_mobj_bki_u {
	struct voluta_list_head lh;
	struct voluta_bk_info   bki;
};

struct voluta_mobj_bki {
	union voluta_mobj_bki_u   u;
	struct voluta_mpool_chnk *p;
} voluta_aligned64;

union voluta_mobj_vi_u {
	struct voluta_list_head  lh;
	struct voluta_vnode_info vi;
};

struct voluta_mobj_vi {
	union voluta_mobj_vi_u    u;
	struct voluta_mpool_chnk *p;
} voluta_aligned64;

union voluta_mobj_ii_u {
	struct voluta_list_head  lh;
	struct voluta_inode_info ii;
};

struct voluta_mobj_ii {
	union voluta_mobj_ii_u    u;
	struct voluta_mpool_chnk *p;
} voluta_aligned64;


struct voluta_mpc_tail {
	long   magic;
	size_t nused;
};

union voluta_mpc_objs {
	uint8_t d[MPC_SIZE - sizeof(struct voluta_mpc_tail)];
	struct voluta_mobj_bki b[NBKI_IN_MPC];
	struct voluta_mobj_vi  v[NVI_IN_MPC];
	struct voluta_mobj_ii  i[NII_IN_MPC];
};

struct voluta_mpool_chnk {
	union voluta_mpc_objs  objs;
	struct voluta_mpc_tail tail;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mpc_init(struct voluta_mpool_chnk *mpc)
{
	mpc->tail.nused = 0;
	mpc->tail.magic = MPC_MAGIC;
}

static void mpc_fini(struct voluta_mpool_chnk *mpc)
{
	voluta_assert_eq(mpc->tail.nused, 0);
	mpc->tail.nused = ~0UL;
	mpc->tail.magic = ~MPC_MAGIC;
}

static void mpc_inc_nused(struct voluta_mpool_chnk *mpc)
{
	voluta_assert_eq(mpc->tail.magic, MPC_MAGIC);
	mpc->tail.nused++;
}

static void mpc_dec_nused(struct voluta_mpool_chnk *mpc)
{
	voluta_assert_eq(mpc->tail.magic, MPC_MAGIC);
	voluta_assert_gt(mpc->tail.nused, 0);
	mpc->tail.nused--;
}

static bool mpc_is_unused(const struct voluta_mpool_chnk *mpc)
{
	return (mpc->tail.nused == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_mpool_init(struct voluta_mpool *mpool, struct voluta_qalloc *qal)
{
	mpool->mp_qal = qal;
	listq_init(&mpool->mp_bq);
	listq_init(&mpool->mp_vq);
	listq_init(&mpool->mp_iq);
}

void voluta_mpool_fini(struct voluta_mpool *mpool)
{
	listq_fini(&mpool->mp_iq);
	listq_fini(&mpool->mp_vq);
	listq_fini(&mpool->mp_bq);
	mpool->mp_qal = NULL;
}

static struct voluta_mpool_chnk *mpool_new_mpc(struct voluta_mpool *mpool)
{
	struct voluta_mpool_chnk *mpc;

	mpc = voluta_qalloc_malloc(mpool->mp_qal, sizeof(*mpc));
	if (mpc != NULL) {
		mpc_init(mpc);
	}
	return mpc;
}

static void mpool_del_mpc(struct voluta_mpool *mpool,
                          struct voluta_mpool_chnk *mpc)
{
	mpc_fini(mpc);
	voluta_qalloc_free(mpool->mp_qal, mpc, sizeof(*mpc));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_bk_info *lh_to_bki(struct voluta_list_head *lh)
{
	union voluta_mobj_bki_u *u;
	struct voluta_mobj_bki  *m;

	u = container_of(lh, union voluta_mobj_bki_u, lh);
	m = container_of(u, struct voluta_mobj_bki, u);

	return &m->u.bki;
}

static struct voluta_list_head *bki_to_lh(struct voluta_bk_info *bki)
{
	union voluta_mobj_bki_u *u;
	struct voluta_mobj_bki  *m;

	u = container_of(bki, union voluta_mobj_bki_u, bki);
	m = container_of(u, struct voluta_mobj_bki, u);

	return &m->u.lh;
}

static struct voluta_mpool_chnk *bki_to_mpc(const struct voluta_bk_info *bki)
{
	struct voluta_mpool_chnk *mpc;
	const union voluta_mobj_bki_u *u;
	const struct voluta_mobj_bki  *m;

	u = container_of2(bki, union voluta_mobj_bki_u, bki);
	m = container_of2(u, struct voluta_mobj_bki, u);

	mpc = m->p;
	voluta_assert_not_null(mpc);
	voluta_assert_le(mpc->tail.nused, ARRAY_SIZE(mpc->objs.b));
	voluta_assert_eq(mpc->tail.magic, MPC_MAGIC);

	return mpc;
}

static struct voluta_bk_info *mpool_pop_bki(struct voluta_mpool *mpool)
{
	struct voluta_list_head *lh;
	struct voluta_bk_info *bki = NULL;

	lh = listq_pop_front(&mpool->mp_bq);
	if (lh != NULL) {
		bki = lh_to_bki(lh);
	}
	return bki;
}

static void mpool_push_bki(struct voluta_mpool *mpool,
                           struct voluta_bk_info *bki)
{
	listq_push_back(&mpool->mp_bq, bki_to_lh(bki));
}

static void mpool_remove_bki(struct voluta_mpool *mpool,
                             struct voluta_bk_info *bki)
{
	listq_remove(&mpool->mp_bq, bki_to_lh(bki));
}

static void mpool_add_bfree_page(struct voluta_mpool *mpool,
                                 struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_bki *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.b); ++i) {
		m = &mpc->objs.b[i];
		m->p = mpc;
		mpool_push_bki(mpool, &m->u.bki);
	}
}

static void mpool_remove_bfree_page(struct voluta_mpool *mpool,
                                    struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_bki *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.b); ++i) {
		m = &mpc->objs.b[i];
		mpool_remove_bki(mpool, &m->u.bki);
		m->p = NULL;
	}
}

static int mpool_more_bfree(struct voluta_mpool *mpool)
{
	struct voluta_mpool_chnk *mpc;

	mpc = mpool_new_mpc(mpool);
	if (mpc == NULL) {
		return -ENOMEM;
	}
	mpool_add_bfree_page(mpool, mpc);
	return 0;
}

static void mpool_less_bfree(struct voluta_mpool *mpool,
                             struct voluta_mpool_chnk *mpc)
{
	mpool_remove_bfree_page(mpool, mpc);
	mpool_del_mpc(mpool, mpc);
}


static struct voluta_bk_info *mpool_alloc_bki(struct voluta_mpool *mpool)
{
	struct voluta_bk_info *bki;
	struct voluta_mpool_chnk *mpc;

	bki = mpool_pop_bki(mpool);
	if (bki != NULL) {
		mpc = bki_to_mpc(bki);
		mpc_inc_nused(mpc);
	}
	return bki;
}

static void mpool_free_bki(struct voluta_mpool *mpool,
                           struct voluta_bk_info *bki)
{
	struct voluta_mpool_chnk *mpc = bki_to_mpc(bki);

	mpc_dec_nused(mpc);
	mpool_push_bki(mpool, bki);

	if (mpc_is_unused(mpc)) {
		mpool_less_bfree(mpool, mpc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *lh_to_vi(struct voluta_list_head *lh)
{
	union voluta_mobj_vi_u *u;
	struct voluta_mobj_vi  *m;

	u = container_of(lh, union voluta_mobj_vi_u, lh);
	m = container_of(u, struct voluta_mobj_vi, u);

	return &m->u.vi;
}

static struct voluta_list_head *vi_to_lh(struct voluta_vnode_info *vi)
{
	union voluta_mobj_vi_u *u;
	struct voluta_mobj_vi  *m;

	u = container_of(vi, union voluta_mobj_vi_u, vi);
	m = container_of(u, struct voluta_mobj_vi, u);

	return &m->u.lh;
}

static struct voluta_mpool_chnk *vi_to_mpc(const struct voluta_vnode_info *vi)
{
	struct voluta_mpool_chnk *mpc;
	const union voluta_mobj_vi_u *u;
	const struct voluta_mobj_vi  *m;

	u = container_of2(vi, union voluta_mobj_vi_u, vi);
	m = container_of2(u, struct voluta_mobj_vi, u);

	mpc = m->p;
	voluta_assert_not_null(mpc);
	voluta_assert_le(mpc->tail.nused, ARRAY_SIZE(mpc->objs.v));
	voluta_assert_eq(mpc->tail.magic, MPC_MAGIC);

	return mpc;
}

static struct voluta_vnode_info *mpool_pop_vi(struct voluta_mpool *mpool)
{
	struct voluta_list_head *lh;
	struct voluta_vnode_info *vi = NULL;

	lh = listq_pop_front(&mpool->mp_vq);
	if (lh != NULL) {
		vi = lh_to_vi(lh);
	}
	return vi;
}

static void mpool_push_vi(struct voluta_mpool *mpool,
                          struct voluta_vnode_info *vi)
{
	listq_push_back(&mpool->mp_vq, vi_to_lh(vi));
}

static void mpool_remove_vi(struct voluta_mpool *mpool,
                            struct voluta_vnode_info *vi)
{
	listq_remove(&mpool->mp_vq, vi_to_lh(vi));
}

static void mpool_add_vfree_page(struct voluta_mpool *mpool,
                                 struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_vi *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.v); ++i) {
		m = &mpc->objs.v[i];
		m->p = mpc;
		mpool_push_vi(mpool, &m->u.vi);
	}
}

static void mpool_remove_vfree_page(struct voluta_mpool *mpool,
                                    struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_vi *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.v); ++i) {
		m = &mpc->objs.v[i];
		mpool_remove_vi(mpool, &m->u.vi);
		m->p = NULL;
	}
}

static int mpool_more_vfree(struct voluta_mpool *mpool)
{
	struct voluta_mpool_chnk *mpc;

	mpc = mpool_new_mpc(mpool);
	if (mpc == NULL) {
		return -ENOMEM;
	}
	mpool_add_vfree_page(mpool, mpc);
	return 0;
}

static void mpool_less_vfree(struct voluta_mpool *mpool,
                             struct voluta_mpool_chnk *mpc)
{
	mpool_remove_vfree_page(mpool, mpc);
	mpool_del_mpc(mpool, mpc);
}

static struct voluta_vnode_info *mpool_alloc_vi(struct voluta_mpool *mpool)
{
	struct voluta_vnode_info *vi;
	struct voluta_mpool_chnk *mpc;

	vi = mpool_pop_vi(mpool);
	if (vi != NULL) {
		mpc = vi_to_mpc(vi);
		mpc_inc_nused(mpc);
	}
	return vi;
}

static void mpool_free_vi(struct voluta_mpool *mpool,
                          struct voluta_vnode_info *vi)
{
	struct voluta_mpool_chnk *mpc = vi_to_mpc(vi);

	mpc_dec_nused(mpc);
	mpool_push_vi(mpool, vi);

	if (mpc_is_unused(mpc)) {
		mpool_less_vfree(mpool, mpc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_inode_info *lh_to_ii(struct voluta_list_head *lh)
{
	union voluta_mobj_ii_u *u;
	struct voluta_mobj_ii  *m;

	u = container_of(lh, union voluta_mobj_ii_u, lh);
	m = container_of(u, struct voluta_mobj_ii, u);

	return &m->u.ii;
}

static struct voluta_list_head *ii_to_lh(struct voluta_inode_info *ii)
{
	union voluta_mobj_ii_u *u;
	struct voluta_mobj_ii  *m;

	u = container_of(ii, union voluta_mobj_ii_u, ii);
	m = container_of(u, struct voluta_mobj_ii, u);

	return &m->u.lh;
}

static struct voluta_mpool_chnk *ii_to_mpc(const struct voluta_inode_info *ii)
{
	struct voluta_mpool_chnk *mpc;
	const union voluta_mobj_ii_u *u;
	const struct voluta_mobj_ii  *m;

	u = container_of2(ii, union voluta_mobj_ii_u, ii);
	m = container_of2(u, struct voluta_mobj_ii, u);

	mpc = m->p;
	voluta_assert_not_null(mpc);
	voluta_assert_le(mpc->tail.nused, ARRAY_SIZE(mpc->objs.i));
	voluta_assert_eq(mpc->tail.magic, MPC_MAGIC);

	return mpc;
}

static struct voluta_inode_info *mpool_pop_ii(struct voluta_mpool *mpool)
{
	struct voluta_list_head *lh;
	struct voluta_inode_info *ii = NULL;

	lh = listq_pop_front(&mpool->mp_iq);
	if (lh != NULL) {
		ii = lh_to_ii(lh);
	}
	return ii;
}

static void mpool_push_ii(struct voluta_mpool *mpool,
                          struct voluta_inode_info *ii)
{
	listq_push_back(&mpool->mp_iq, ii_to_lh(ii));
}

static void mpool_remove_ii(struct voluta_mpool *mpool,
                            struct voluta_inode_info *ii)
{
	listq_remove(&mpool->mp_iq, ii_to_lh(ii));
}

static void mpool_add_ifree_page(struct voluta_mpool *mpool,
                                 struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_ii *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.i); ++i) {
		m = &mpc->objs.i[i];
		m->p = mpc;
		mpool_push_ii(mpool, &m->u.ii);
	}
}

static void mpool_remove_ifree_page(struct voluta_mpool *mpool,
                                    struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_ii *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.i); ++i) {
		m = &mpc->objs.i[i];
		mpool_remove_ii(mpool, &m->u.ii);
		m->p = NULL;
	}
}

static int mpool_more_ifree(struct voluta_mpool *mpool)
{
	struct voluta_mpool_chnk *mpc;

	mpc = mpool_new_mpc(mpool);
	if (mpc == NULL) {
		return -ENOMEM;
	}
	mpool_add_ifree_page(mpool, mpc);
	return 0;
}

static void mpool_less_ifree(struct voluta_mpool *mpool,
                             struct voluta_mpool_chnk *mpc)
{
	mpool_remove_ifree_page(mpool, mpc);
	mpool_del_mpc(mpool, mpc);
}

static struct voluta_inode_info *mpool_alloc_ii(struct voluta_mpool *mpool)
{
	struct voluta_inode_info *ii;
	struct voluta_mpool_chnk *mpc;

	ii = mpool_pop_ii(mpool);
	if (ii != NULL) {
		mpc = ii_to_mpc(ii);
		mpc_inc_nused(mpc);
	}
	return ii;
}

static void mpool_free_ii(struct voluta_mpool *mpool,
                          struct voluta_inode_info *ii)
{
	struct voluta_mpool_chnk *mpc = ii_to_mpc(ii);

	mpc_dec_nused(mpc);
	mpool_push_ii(mpool, ii);

	if (mpc_is_unused(mpc)) {
		mpool_less_ifree(mpool, mpc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_bk_info *voluta_malloc_bki(struct voluta_mpool *mpool)
{
	int err;
	struct voluta_bk_info *bki;

	bki = mpool_alloc_bki(mpool);
	if (bki != NULL) {
		return bki;
	}
	err = mpool_more_bfree(mpool);
	if (err) {
		return NULL;
	}
	bki = mpool_alloc_bki(mpool);
	if (bki == NULL) {
		return NULL;
	}
	return bki;
}

void voluta_free_bki(struct voluta_mpool *mpool, struct voluta_bk_info *bki)
{
	mpool_free_bki(mpool, bki);
}


struct voluta_vnode_info *voluta_malloc_vi(struct voluta_mpool *mpool)
{
	int err;
	struct voluta_vnode_info *vi;

	vi = mpool_alloc_vi(mpool);
	if (vi != NULL) {
		return vi;
	}
	err = mpool_more_vfree(mpool);
	if (err) {
		return NULL;
	}
	vi = mpool_alloc_vi(mpool);
	if (vi == NULL) {
		return NULL;
	}
	return vi;
}

void voluta_free_vi(struct voluta_mpool *mpool, struct voluta_vnode_info *vi)
{
	mpool_free_vi(mpool, vi);
}


struct voluta_inode_info *voluta_malloc_ii(struct voluta_mpool *mpool)
{
	int err;
	struct voluta_inode_info *ii;

	ii = mpool_alloc_ii(mpool);
	if (ii != NULL) {
		return ii;
	}
	err = mpool_more_ifree(mpool);
	if (err) {
		return NULL;
	}
	ii = mpool_alloc_ii(mpool);
	if (ii == NULL) {
		return NULL;
	}
	return ii;
}

void voluta_free_ii(struct voluta_mpool *mpool, struct voluta_inode_info *ii)
{
	mpool_free_ii(mpool, ii);
}

