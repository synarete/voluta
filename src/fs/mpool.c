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
#define _GNU_SOURCE 1
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <voluta/infra.h>
#include <voluta/fs/mpool.h>
#include <voluta/fs/private.h>


#define MPC_MAGIC               0xA119CE6D2BL
#define MPC_SIZE                VOLUTA_BK_SIZE
#define MPC_TAIL_SIZE           (64)
#define NOBJ_IN_MPC(t_)         ((MPC_SIZE - MPC_TAIL_SIZE) / sizeof(t_))
#define NBKI_IN_MPC             NOBJ_IN_MPC(struct voluta_mobj_bsi)
#define NVI_IN_MPC              NOBJ_IN_MPC(struct voluta_mobj_xxi)
#define NII_IN_MPC              NOBJ_IN_MPC(struct voluta_mobj_ii)


union voluta_mobj_bsi_u {
	struct voluta_list_head  lh;
	struct voluta_bksec_info bsi;
};

struct voluta_mobj_bsi {
	union voluta_mobj_bsi_u   u;
	struct voluta_mpool_chnk *p;
} voluta_aligned64;


union voluta_xxnode_info_u {
	struct voluta_vnode_info        vi;
	struct voluta_hspace_info       hsi;
	struct voluta_agroup_info       agi;
	struct voluta_itnode_info       itni;
	struct voluta_xanode_info       xani;
	struct voluta_htnode_info       htni;
	struct voluta_symval_info       symi;
	struct voluta_rtnode_info       rtni;
};

struct voluta_xxnode_info {
	union voluta_xxnode_info_u u;
};

union voluta_mobj_xxi_u {
	struct voluta_list_head  lh;
	struct voluta_xxnode_info xxi;
};

struct voluta_mobj_xxi {
	union voluta_mobj_xxi_u   u;
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
	int8_t pad[48];
} voluta_aligned64;

union voluta_mpc_objs {
	uint8_t d[MPC_SIZE - sizeof(struct voluta_mpc_tail)];
	struct voluta_mobj_bsi bsi[NBKI_IN_MPC];
	struct voluta_mobj_xxi  xxi[NVI_IN_MPC];
	struct voluta_mobj_ii  ii[NII_IN_MPC];
};

struct voluta_mpool_chnk {
	union voluta_mpc_objs  objs;
	struct voluta_mpc_tail tail;
};


static void mpool_init_alloc_if(struct voluta_mpool *mpool);
static void mpool_fini_alloc_if(struct voluta_mpool *mpool);


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
	mpool_init_alloc_if(mpool);
}

void voluta_mpool_fini(struct voluta_mpool *mpool)
{
	mpool_fini_alloc_if(mpool);
	listq_fini(&mpool->mp_iq);
	listq_fini(&mpool->mp_vq);
	listq_fini(&mpool->mp_bq);
	mpool->mp_qal = NULL;
}

static struct voluta_mpool_chnk *mpool_new_mpc(struct voluta_mpool *mpool)
{
	struct voluta_mpool_chnk *mpc;

	STATICASSERT_EQ(sizeof(mpc->tail), MPC_TAIL_SIZE);
	STATICASSERT_LE(sizeof(*mpc), MPC_SIZE);

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

static struct voluta_bksec_info *lh_to_bsi(struct voluta_list_head *lh)
{
	union voluta_mobj_bsi_u *u;
	struct voluta_mobj_bsi  *m;

	u = container_of(lh, union voluta_mobj_bsi_u, lh);
	m = container_of(u, struct voluta_mobj_bsi, u);

	return &m->u.bsi;
}

static struct voluta_list_head *bsi_to_lh(struct voluta_bksec_info *bsi)
{
	union voluta_mobj_bsi_u *u;
	struct voluta_mobj_bsi  *m;

	u = container_of(bsi, union voluta_mobj_bsi_u, bsi);
	m = container_of(u, struct voluta_mobj_bsi, u);

	return &m->u.lh;
}

static struct voluta_mpool_chnk *
bsi_to_mpc(const struct voluta_bksec_info *bsi)
{
	struct voluta_mpool_chnk *mpc;
	const union voluta_mobj_bsi_u *u;
	const struct voluta_mobj_bsi  *m;

	u = container_of2(bsi, union voluta_mobj_bsi_u, bsi);
	m = container_of2(u, struct voluta_mobj_bsi, u);

	mpc = m->p;
	voluta_assert_not_null(mpc);
	voluta_assert_le(mpc->tail.nused, ARRAY_SIZE(mpc->objs.bsi));
	voluta_assert_eq(mpc->tail.magic, MPC_MAGIC);

	return mpc;
}

static struct voluta_bksec_info *mpool_pop_bsi(struct voluta_mpool *mpool)
{
	struct voluta_list_head *lh;
	struct voluta_bksec_info *bsi = NULL;

	lh = listq_pop_front(&mpool->mp_bq);
	if (lh != NULL) {
		bsi = lh_to_bsi(lh);
	}
	return bsi;
}

static void mpool_push_bsi(struct voluta_mpool *mpool,
                           struct voluta_bksec_info *bsi)
{
	listq_push_back(&mpool->mp_bq, bsi_to_lh(bsi));
}

static void mpool_remove_bsi(struct voluta_mpool *mpool,
                             struct voluta_bksec_info *bsi)
{
	listq_remove(&mpool->mp_bq, bsi_to_lh(bsi));
}

static void mpool_add_bfree_chnk(struct voluta_mpool *mpool,
                                 struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_bsi *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.bsi); ++i) {
		m = &mpc->objs.bsi[i];
		m->p = mpc;
		mpool_push_bsi(mpool, &m->u.bsi);
	}
}

static void mpool_remove_bfree_chnk(struct voluta_mpool *mpool,
                                    struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_bsi *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.bsi); ++i) {
		m = &mpc->objs.bsi[i];
		mpool_remove_bsi(mpool, &m->u.bsi);
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
	mpool_add_bfree_chnk(mpool, mpc);
	return 0;
}

static void mpool_less_bfree(struct voluta_mpool *mpool,
                             struct voluta_mpool_chnk *mpc)
{
	mpool_remove_bfree_chnk(mpool, mpc);
	mpool_del_mpc(mpool, mpc);
}


static struct voluta_bksec_info *mpool_alloc_bsi(struct voluta_mpool *mpool)
{
	struct voluta_bksec_info *bsi;
	struct voluta_mpool_chnk *mpc;

	bsi = mpool_pop_bsi(mpool);
	if (bsi != NULL) {
		mpc = bsi_to_mpc(bsi);
		mpc_inc_nused(mpc);
	}
	return bsi;
}

static void mpool_free_bsi(struct voluta_mpool *mpool,
                           struct voluta_bksec_info *bsi)
{
	struct voluta_mpool_chnk *mpc = bsi_to_mpc(bsi);

	mpc_dec_nused(mpc);
	mpool_push_bsi(mpool, bsi);

	if (mpc_is_unused(mpc)) {
		mpool_less_bfree(mpool, mpc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_xxnode_info *lh_to_xxi(struct voluta_list_head *lh)
{
	union voluta_mobj_xxi_u *u;
	struct voluta_mobj_xxi  *m;

	u = container_of(lh, union voluta_mobj_xxi_u, lh);
	m = container_of(u, struct voluta_mobj_xxi, u);

	return &m->u.xxi;
}

static struct voluta_list_head *xxi_to_lh(struct voluta_xxnode_info *xxi)
{
	union voluta_mobj_xxi_u *u;
	struct voluta_mobj_xxi  *m;

	u = container_of(xxi, union voluta_mobj_xxi_u, xxi);
	m = container_of(u, struct voluta_mobj_xxi, u);

	return &m->u.lh;
}

static struct voluta_mpool_chnk *xxi_to_mpc(const struct voluta_xxnode_info
                *xxi)
{
	struct voluta_mpool_chnk *mpc;
	const union voluta_mobj_xxi_u *u;
	const struct voluta_mobj_xxi  *m;

	u = container_of2(xxi, union voluta_mobj_xxi_u, xxi);
	m = container_of2(u, struct voluta_mobj_xxi, u);

	mpc = m->p;
	voluta_assert_not_null(mpc);
	voluta_assert_le(mpc->tail.nused, ARRAY_SIZE(mpc->objs.xxi));
	voluta_assert_eq(mpc->tail.magic, MPC_MAGIC);

	return mpc;
}

static struct voluta_xxnode_info *mpool_pop_xxi(struct voluta_mpool *mpool)
{
	struct voluta_list_head *lh;
	struct voluta_xxnode_info *xxi = NULL;

	lh = listq_pop_front(&mpool->mp_vq);
	if (lh != NULL) {
		xxi = lh_to_xxi(lh);
	}
	return xxi;
}

static void mpool_push_xxi(struct voluta_mpool *mpool,
                           struct voluta_xxnode_info *xxi)
{
	listq_push_back(&mpool->mp_vq, xxi_to_lh(xxi));
}

static void mpool_remove_xxi(struct voluta_mpool *mpool,
                             struct voluta_xxnode_info *xxi)
{
	listq_remove(&mpool->mp_vq, xxi_to_lh(xxi));
}

static void mpool_add_vfree_chnk(struct voluta_mpool *mpool,
                                 struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_xxi *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.xxi); ++i) {
		m = &mpc->objs.xxi[i];
		m->p = mpc;
		mpool_push_xxi(mpool, &m->u.xxi);
	}
}

static void mpool_remove_vfree_chnk(struct voluta_mpool *mpool,
                                    struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_xxi *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.xxi); ++i) {
		m = &mpc->objs.xxi[i];
		mpool_remove_xxi(mpool, &m->u.xxi);
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
	mpool_add_vfree_chnk(mpool, mpc);
	return 0;
}

static void mpool_less_vfree(struct voluta_mpool *mpool,
                             struct voluta_mpool_chnk *mpc)
{
	mpool_remove_vfree_chnk(mpool, mpc);
	mpool_del_mpc(mpool, mpc);
}

static struct voluta_xxnode_info *mpool_alloc_xxi(struct voluta_mpool *mpool)
{
	struct voluta_xxnode_info *xxi;
	struct voluta_mpool_chnk *mpc;

	xxi = mpool_pop_xxi(mpool);
	if (xxi != NULL) {
		mpc = xxi_to_mpc(xxi);
		mpc_inc_nused(mpc);
	}
	return xxi;
}

static void mpool_free_xxi(struct voluta_mpool *mpool,
                           struct voluta_xxnode_info *xxi)
{
	struct voluta_mpool_chnk *mpc = xxi_to_mpc(xxi);

	mpc_dec_nused(mpc);
	mpool_push_xxi(mpool, xxi);

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
	voluta_assert_le(mpc->tail.nused, ARRAY_SIZE(mpc->objs.ii));
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

static void mpool_add_ifree_chnk(struct voluta_mpool *mpool,
                                 struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_ii *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.ii); ++i) {
		m = &mpc->objs.ii[i];
		m->p = mpc;
		mpool_push_ii(mpool, &m->u.ii);
	}
}

static void mpool_remove_ifree_chnk(struct voluta_mpool *mpool,
                                    struct voluta_mpool_chnk *mpc)
{
	struct voluta_mobj_ii *m;

	for (size_t i = 0; i < ARRAY_SIZE(mpc->objs.ii); ++i) {
		m = &mpc->objs.ii[i];
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
	mpool_add_ifree_chnk(mpool, mpc);
	return 0;
}

static void mpool_less_ifree(struct voluta_mpool *mpool,
                             struct voluta_mpool_chnk *mpc)
{
	mpool_remove_ifree_chnk(mpool, mpc);
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

static struct voluta_bksec_info *mpool_malloc_bsi(struct voluta_mpool *mpool)
{
	int err;
	struct voluta_bksec_info *bsi;

	bsi = mpool_alloc_bsi(mpool);
	if (bsi != NULL) {
		return bsi;
	}
	err = mpool_more_bfree(mpool);
	if (err) {
		return NULL;
	}
	bsi = mpool_alloc_bsi(mpool);
	if (bsi == NULL) {
		return NULL;
	}
	return bsi;
}

static struct voluta_xxnode_info *mpool_malloc_xxi(struct voluta_mpool *mpool)
{
	int err;
	struct voluta_xxnode_info *xxi;

	xxi = mpool_alloc_xxi(mpool);
	if (xxi != NULL) {
		return xxi;
	}
	err = mpool_more_vfree(mpool);
	if (err) {
		return NULL;
	}
	xxi = mpool_alloc_xxi(mpool);
	if (xxi == NULL) {
		return NULL;
	}
	return xxi;
}

static struct voluta_inode_info *mpool_malloc_ii(struct voluta_mpool *mpool)
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_mpool *aif_to_mpool(const struct voluta_alloc_if *aif)
{
	const struct voluta_mpool *mpool;

	mpool = voluta_container_of2(aif, struct voluta_mpool, mp_alif);
	return voluta_unconst(mpool);
}

static bool is_bsi_size(size_t nbytes)
{
	return (nbytes == sizeof(struct voluta_bksec_info));
}

static bool is_ii_size(size_t nbytes)
{
	return (nbytes == sizeof(struct voluta_inode_info));
}

static bool is_xxi_size(size_t nbytes)
{
	STATICASSERT_GT(sizeof(struct voluta_xxnode_info),
	                sizeof(struct voluta_vnode_info));

	STATICASSERT_LT(sizeof(struct voluta_xxnode_info),
	                (2 * sizeof(struct voluta_vnode_info)));

	return (nbytes <= sizeof(struct voluta_xxnode_info)) &&
	       (nbytes >= sizeof(struct voluta_vnode_info));
}

static void *mpool_malloc(struct voluta_alloc_if *alif, size_t nbytes)
{
	void *ptr;
	struct voluta_mpool *mpool = aif_to_mpool(alif);

	if (is_bsi_size(nbytes)) {
		ptr = mpool_malloc_bsi(mpool);
	} else if (is_ii_size(nbytes)) {
		ptr = mpool_malloc_ii(mpool);
	} else if (is_xxi_size(nbytes)) {
		ptr = mpool_malloc_xxi(mpool);
	} else {
		ptr = voluta_qalloc_malloc(mpool->mp_qal, nbytes);
	}
	return ptr;
}

static void mpool_free(struct voluta_alloc_if *alif, void *ptr, size_t nbytes)
{
	struct voluta_mpool *mpool = aif_to_mpool(alif);

	if (is_bsi_size(nbytes)) {
		mpool_free_bsi(mpool, ptr);
	} else if (is_ii_size(nbytes)) {
		mpool_free_ii(mpool, ptr);
	} else if (is_xxi_size(nbytes)) {
		mpool_free_xxi(mpool, ptr);
	} else {
		voluta_qalloc_free(mpool->mp_qal, ptr, nbytes);
	}
}

static void mpool_stat(const struct voluta_alloc_if *alif,
                       struct voluta_alloc_stat *out_stat)
{
	const struct voluta_mpool *mpool = aif_to_mpool(alif);

	voluta_qalloc_stat(mpool->mp_qal, out_stat);
}

static void mpool_init_alloc_if(struct voluta_mpool *mpool)
{
	mpool->mp_alif.malloc_fn = mpool_malloc;
	mpool->mp_alif.free_fn = mpool_free;
	mpool->mp_alif.stat_fn = mpool_stat;
}

static void mpool_fini_alloc_if(struct voluta_mpool *mpool)
{
	mpool->mp_alif.malloc_fn = NULL;
	mpool->mp_alif.free_fn = NULL;
	mpool->mp_alif.stat_fn = NULL;
}

