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
#include <sys/types.h>
#include <sys/mount.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include "libvoluta.h"

static void bki_init(struct voluta_bk_info *bki, struct voluta_block *bk);
static void bki_fini(struct voluta_bk_info *bki);
static void bki_incref(struct voluta_bk_info *bki);
static void bki_decref(struct voluta_bk_info *bki);
static void vi_init(struct voluta_vnode_info *vi);
static void vi_fini(struct voluta_vnode_info *vi);
static void vi_undirtify(struct voluta_vnode_info *vi);
static void ii_init(struct voluta_inode_info *ii);
static void ii_fini(struct voluta_inode_info *ii);
static void cache_evict_some(struct voluta_cache *cache);
static struct voluta_inode_info *
ii_from_vi(const struct voluta_vnode_info *vi);

typedef int (*voluta_cache_elem_fn)(struct voluta_cache_elem *, void *);

struct voluta_cache_ctx {
	struct voluta_cache *cache;
	struct voluta_bk_info *bki;
	struct voluta_vnode_info *vi;
	struct voluta_inode_info *ii;
	size_t limit;
	size_t count;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lh_init(struct voluta_list_head *lh)
{
	voluta_list_head_init(lh);
}

static void lh_fini(struct voluta_list_head *lh)
{
	voluta_list_head_fini(lh);
}

static void an_init(struct voluta_avl_node *an)
{
	voluta_avl_node_init(an);
}

static void an_fini(struct voluta_avl_node *an)
{
	voluta_avl_node_fini(an);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* LBA/offset re-hashing functions */
static uint64_t twang_mix64(uint64_t key)
{
	key = ~key + (key << 21);
	key = key ^ (key >> 24);
	key = key + (key << 3) + (key << 8);
	key = key ^ (key >> 14);
	key = key + (key << 2) + (key << 4);
	key = key ^ (key >> 28);
	key = key + (key << 31);

	return key;
}

static long twang_mix(long v)
{
	return (long)twang_mix64((uint64_t)v);
}

static long rotate(long x, unsigned int b)
{
	return (x << b) | (x >> (64 - b));
}

static long lba_hash(long lba)
{
	return twang_mix(lba);
}

static long off_hash(long off)
{
	return rotate(off, (unsigned int)((off >> 10) % 31));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *malloc_nelems(struct voluta_qalloc *qal,
			   size_t elemsz, size_t nelems)
{
	return voluta_qalloc_malloc(qal, elemsz * nelems);
}


static void free_nelems(struct voluta_qalloc *qal,
			void *ptr, size_t elemsz, size_t nelems)
{
	voluta_qalloc_free(qal, ptr, elemsz * nelems);
}

static struct voluta_list_head *
new_htbl(struct voluta_qalloc *qal, size_t nelems)
{
	struct voluta_list_head *htbl;

	htbl = malloc_nelems(qal, sizeof(*htbl), nelems);
	if (htbl != NULL) {
		list_head_initn(htbl, nelems);
	}
	return htbl;
}

static void del_htbl(struct voluta_qalloc *qal,
		     struct voluta_list_head *htbl, size_t nelems)
{
	list_head_finin(htbl, nelems);
	free_nelems(qal, htbl, sizeof(*htbl), nelems);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_block *malloc_bk(struct voluta_qalloc *qal)
{
	struct voluta_block *bk;

	bk = voluta_qalloc_malloc(qal, sizeof(*bk));
	return bk;
}

static void free_bk(struct voluta_qalloc *qal, struct voluta_block *bk)
{
	voluta_qalloc_free(qal, bk, sizeof(*bk));
}

static struct voluta_bk_info *malloc_bki(struct voluta_mpool *mpool)
{
	return voluta_malloc_bki(mpool);
}

static void free_bki(struct voluta_mpool *mpool, struct voluta_bk_info *bki)
{
	voluta_free_bki(mpool, bki);
}

static struct voluta_vnode_info *malloc_vi(struct voluta_mpool *mpool)
{
	return voluta_malloc_vi(mpool);
}

static void free_vi(struct voluta_mpool *mpool, struct voluta_vnode_info *vi)
{
	voluta_free_vi(mpool, vi);
}

static struct voluta_inode_info *malloc_ii(struct voluta_mpool *mpool)
{
	return voluta_malloc_ii(mpool);
}

static void free_ii(struct voluta_mpool *mpool, struct voluta_inode_info *ii)
{
	voluta_free_ii(mpool, ii);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_cache_elem *
ce_from_htb_link(const struct voluta_list_head *lh)
{
	const struct voluta_cache_elem *ce;

	ce = container_of2(lh, struct voluta_cache_elem, ce_htb_lh);
	return unconst(ce);
}

static struct voluta_cache_elem *
ce_from_lru_link(const struct voluta_list_head *lh)
{
	const struct voluta_cache_elem *ce;

	ce = container_of2(lh, struct voluta_cache_elem, ce_lru_lh);
	return unconst(ce);
}

static void ce_init(struct voluta_cache_elem *ce)
{
	lh_init(&ce->ce_htb_lh);
	lh_init(&ce->ce_lru_lh);
	ce->ce_refcnt = 0;
	ce->ce_tick = 0;
}

static void ce_fini(struct voluta_cache_elem *ce)
{
	lh_fini(&ce->ce_htb_lh);
	lh_fini(&ce->ce_lru_lh);
	ce->ce_refcnt = 0;
	ce->ce_tick = -1;
}

static void ce_hmap(struct voluta_cache_elem *ce,
		    struct voluta_list_head *hlst)
{
	list_push_front(hlst, &ce->ce_htb_lh);
}

static void ce_hunmap(struct voluta_cache_elem *ce)
{
	list_head_remove(&ce->ce_htb_lh);
}

static struct voluta_list_head *ce_lru_link(struct voluta_cache_elem *ce)
{
	return &ce->ce_lru_lh;
}

static void ce_lru(struct voluta_cache_elem *ce, struct voluta_list_head *lru)
{
	list_push_front(lru, ce_lru_link(ce));
}

static void ce_unlru(struct voluta_cache_elem *ce)
{
	list_head_remove(ce_lru_link(ce));
}

static bool ce_islru_front(struct voluta_cache_elem *ce,
			   struct voluta_list_head *lru)
{
	return (list_front(lru) == ce_lru_link(ce));
}

static void ce_relru(struct voluta_cache_elem *ce,
		     struct voluta_list_head *lru)
{
	if (!ce_islru_front(ce, lru)) {
		ce_unlru(ce);
		ce_lru(ce, lru);
	}
}

static size_t ce_refcnt(const struct voluta_cache_elem *ce)
{
	return (size_t)ce->ce_refcnt;
}

static void ce_incref(struct voluta_cache_elem *ce)
{
	voluta_assert_lt(ce->ce_refcnt, INT_MAX / 2);
	voluta_assert_ge(ce->ce_refcnt, 0);
	ce->ce_refcnt++;
}

static void ce_decref(struct voluta_cache_elem *ce)
{
	voluta_assert_gt(ce->ce_refcnt, 0);
	ce->ce_refcnt--;
}

static bool ce_is_evictable(const struct voluta_cache_elem *ce)
{
	return !ce->ce_refcnt;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *vi_from_ce(const struct voluta_cache_elem *ce)
{
	const struct voluta_vnode_info *vi = NULL;

	if (ce != NULL) {
		vi = container_of2(ce, struct voluta_vnode_info, v_ce);
	}
	return unconst(vi);
}

static struct voluta_cache_elem *vi_ce(const struct voluta_vnode_info *vi)
{
	const struct voluta_cache_elem *ce = &vi->v_ce;

	return unconst(ce);
}

static void vi_init(struct voluta_vnode_info *vi)
{
	vaddr_reset(&vi->vaddr);
	ce_init(vi_ce(vi));
	lh_init(&vi->v_dq_blh);
	lh_init(&vi->v_dq_mlh);
	an_init(&vi->v_ds_an);
	vi->view = NULL;
	vi->v_sbi = NULL;
	vi->v_bki = NULL;
	vi->v_pvi = NULL;
	vi->v_ds_next = NULL;
	vi->vu.p = NULL;
	vi->v_ds_key = 0;
	vi->v_dirty = 0;
	vi->v_verify = 0;
}

static void vi_fini(struct voluta_vnode_info *vi)
{
	vaddr_reset(&vi->vaddr);
	ce_fini(vi_ce(vi));
	lh_fini(&vi->v_dq_blh);
	lh_fini(&vi->v_dq_mlh);
	an_fini(&vi->v_ds_an);
	vi->view = NULL;
	vi->v_sbi = NULL;
	vi->v_bki = NULL;
	vi->v_pvi = NULL;
	vi->v_ds_next = NULL;
	vi->vu.p = NULL;
	vi->v_dirty = -11;
	vi->v_verify = 0;
}

static void vi_assign(struct voluta_vnode_info *vi,
		      const struct voluta_vaddr *vaddr)
{
	vaddr_copyto(vaddr, &vi->vaddr);
}

size_t voluta_vi_refcnt(const struct voluta_vnode_info *vi)
{
	size_t refcnt = 0;

	if (likely(vi != NULL)) {
		refcnt = ce_refcnt(vi_ce(vi));
	}
	return refcnt;
}

void voluta_vi_incref(struct voluta_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		ce_incref(vi_ce(vi));
	}
}

void voluta_vi_decref(struct voluta_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		ce_decref(vi_ce(vi));
	}
}

static void vi_attach_bk(struct voluta_vnode_info *vi,
			 struct voluta_bk_info *bki)
{
	voluta_assert_null(vi->v_bki);

	bki_incref(bki);
	vi->v_bki = bki;
}

static void vi_detach_bk(struct voluta_vnode_info *vi)
{
	if (vi->v_bki != NULL) {
		bki_decref(vi->v_bki);
		vi->v_bki = NULL;
		vi->view = NULL;
		vi->vu.p = NULL;
	}
}

static void vi_attach_pvi(struct voluta_vnode_info *vi,
			  struct voluta_vnode_info *pvi)
{
	voluta_assert_null(vi->v_pvi);

	if (pvi != NULL) {
		vi->v_pvi = pvi;
		vi_incref(pvi);
	}
}

static void vi_detach_pvi(struct voluta_vnode_info *vi)
{

	if (vi->v_pvi != NULL) {
		vi_decref(vi->v_pvi);
		vi->v_pvi = NULL;
	}
}

static void vi_setup_ds_key(struct voluta_vnode_info *vi,
			    const struct voluta_inode_info *pii)
{
	const enum voluta_vtype vtype = vi_vtype(vi);

	if (pii != NULL) {
		vi->v_ds_key = (long)ii_ino(pii);
	} else if (vtype_isinode(vtype)) {
		vi->v_ds_key = (long)ii_ino(ii_from_vi(vi));
		voluta_assert_gt(vi->v_ds_key, 0);
	} else {
		voluta_assert(vtype_isumap(vtype) ||
			      (vtype == VOLUTA_VTYPE_ITNODE));
		vi->v_ds_key = 0;
	}
}

static void vi_detach_all(struct voluta_vnode_info *vi)
{
	vi_detach_pvi(vi);
	vi_detach_bk(vi);
}

static bool vi_is_evictable(const struct voluta_vnode_info *vi)
{
	return !vi->v_dirty && ce_is_evictable(vi_ce(vi));
}

static bool vi_has_tick(const struct voluta_vnode_info *vi, long ctick)
{
	return (vi->v_ce.ce_tick == ctick);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_inode_info *ii_from_vi(const struct voluta_vnode_info *vi)
{
	const struct voluta_inode_info *ii = NULL;

	if (vi != NULL) {
		ii = container_of2(vi, struct voluta_inode_info, i_vi);
	}
	return unconst(ii);
}

static struct voluta_inode_info *ii_from_ce(const struct voluta_cache_elem *ce)
{
	return ii_from_vi(vi_from_ce(ce));
}

static struct voluta_cache_elem *ii_ce(const struct voluta_inode_info *ii)
{
	return vi_ce(ii_vi(ii));
}

static void ii_init(struct voluta_inode_info *ii)
{
	vi_init(&ii->i_vi);
	ii->inode = NULL;
	ii->i_ino = VOLUTA_INO_NULL;
	ii->i_nopen = 0;
	ii->i_nlookup = 0;
}

static void ii_fini(struct voluta_inode_info *ii)
{
	voluta_assert_ge(ii->i_nopen, 0);

	vi_fini(&ii->i_vi);
	ii->inode = NULL;
	ii->i_ino = VOLUTA_INO_NULL;
	ii->i_nopen = INT_MIN;
}

static void ii_assign(struct voluta_inode_info *ii,
		      const struct voluta_iaddr *iaddr)
{
	vi_assign(&ii->i_vi, &iaddr->vaddr);
	ii->i_ino = iaddr->ino;
}

bool voluta_ii_isevictable(const struct voluta_inode_info *ii)
{
	return !ii->i_nopen && vi_is_evictable(ii_vi(ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_bk_info *bki_from_ce(const struct voluta_cache_elem *ce)
{
	const struct voluta_bk_info *bki = NULL;

	if (ce != NULL) {
		bki = container_of2(ce, struct voluta_bk_info, bki_ce);
	}
	return unconst(bki);
}

static struct voluta_cache_elem *bki_ce(const struct voluta_bk_info *bki)
{
	const struct voluta_cache_elem *ce = &bki->bki_ce;

	return unconst(ce);
}

static void bki_set_lba(struct voluta_bk_info *bki, loff_t lba)
{
	bki->bk_lba = lba;
}

static void bki_init(struct voluta_bk_info *bki, struct voluta_block *bk)
{
	ce_init(&bki->bki_ce);
	bki_set_lba(bki, VOLUTA_LBA_NULL);
	bki->bk_mask = 0;
	bki->bk = bk;
}

static void bki_fini(struct voluta_bk_info *bki)
{
	ce_fini(&bki->bki_ce);
	bki_set_lba(bki, VOLUTA_LBA_NULL);
	bki->bk = NULL;
}

static void bki_incref(struct voluta_bk_info *bki)
{
	ce_incref(bki_ce(bki));
}

static void bki_decref(struct voluta_bk_info *bki)
{
	ce_decref(bki_ce(bki));
}

static bool bki_is_evictable(const struct voluta_bk_info *bki)
{
	return ce_is_evictable(bki_ce(bki));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t vaddr_nkbs(const struct voluta_vaddr *vaddr)
{
	return voluta_vtype_nkbs(vaddr->vtype);
}

static size_t vaddr_kb_index(const struct voluta_vaddr *vaddr)
{
	const loff_t kb_size = VOLUTA_KB_SIZE;
	const size_t nkb_in_bk = VOLUTA_NKB_IN_BK;

	return (size_t)(vaddr->off / kb_size) % nkb_in_bk;
}

static uint64_t view_mask_of(const struct voluta_vaddr *vaddr)
{
	uint64_t mask;
	uint64_t kb_mask;
	const uint64_t kb_none = 0;
	const size_t nkbs = vaddr_nkbs(vaddr);
	const size_t kidx = vaddr_kb_index(vaddr);

	kb_mask = (nkbs < 64) ? ((1UL << nkbs) - 1) : ~kb_none;
	mask = kb_mask << kidx;
	voluta_assert_ne(mask, 0);

	return mask;
}

static void bki_mark_visible(struct voluta_bk_info *bki,
			     const struct voluta_vaddr *vaddr)
{
	bki->bk_mask |= view_mask_of(vaddr);
}

static void bki_mark_opaque(struct voluta_bk_info *bki,
			    const struct voluta_vaddr *vaddr)
{
	bki->bk_mask &= ~view_mask_of(vaddr);
}

static bool bki_is_visible(struct voluta_bk_info *bki,
			   const struct voluta_vaddr *vaddr)
{
	const uint64_t mask = view_mask_of(vaddr);
	const uint64_t bk_mask = bki->bk_mask;

	return ((bk_mask & mask) == mask);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lrumap_init(struct voluta_lrumap *lm, struct voluta_qalloc *qal,
		       size_t htbl_size, long (*hash_fn)(long))
{
	struct voluta_list_head *htbl;

	htbl = new_htbl(qal, htbl_size);
	if (htbl == NULL) {
		return -ENOMEM;
	}
	list_init(&lm->lru);
	lm->htbl = htbl;
	lm->hash_fn = hash_fn;
	lm->hsize = htbl_size;
	lm->count = 0;
	return 0;
}

static void lrumap_fini(struct voluta_lrumap *lm, struct voluta_qalloc *qal)
{
	if (lm->htbl != NULL) {
		del_htbl(qal, lm->htbl, lm->hsize);
		list_fini(&lm->lru);
		lm->htbl = NULL;
		lm->hash_fn = NULL;
		lm->hsize = 0;
	}
}

static size_t lrumap_usage(const struct voluta_lrumap *lm)
{
	return lm->count;
}

static size_t lrumap_key_to_bin(const struct voluta_lrumap *lm, long ckey)
{
	return (size_t)(lm->hash_fn(ckey)) % lm->hsize;
}

static void lrumap_store(struct voluta_lrumap *lm,
			 struct voluta_cache_elem *ce, long ckey)
{
	const size_t bin = lrumap_key_to_bin(lm, ckey);

	ce->ce_key = ckey;
	ce_hmap(ce, &lm->htbl[bin]);
	ce_lru(ce, &lm->lru);
	lm->count += 1;
}

static struct voluta_cache_elem *
lrumap_find(const struct voluta_lrumap *lm, long ckey)
{
	size_t bin;
	const struct voluta_list_head *lst;
	const struct voluta_list_head *itr;
	const struct voluta_cache_elem *ce;

	bin = lrumap_key_to_bin(lm, ckey);
	lst = &lm->htbl[bin];
	itr = lst->next;
	while (itr != lst) {
		ce = ce_from_htb_link(itr);
		if (ce->ce_key == ckey) {
			return unconst(ce);
		}
		itr = itr->next;
	}
	return NULL;
}

static void lrumap_remove(struct voluta_lrumap *lm,
			  struct voluta_cache_elem *ce)
{
	ce_hunmap(ce);
	ce_unlru(ce);
	lm->count -= 1;
}

static void lrumap_promote_lru(struct voluta_lrumap *lm,
			       struct voluta_cache_elem *ce)
{
	ce_relru(ce, &lm->lru);
}

static struct voluta_cache_elem *
lrumap_get_lru(const struct voluta_lrumap *cq)
{
	struct voluta_cache_elem *ce = NULL;

	if (cq->count > 0) {
		ce = ce_from_lru_link(cq->lru.prev);
	}
	return ce;
}

static void lrumap_foreach_backward(struct voluta_lrumap *lm,
				    voluta_cache_elem_fn cb, void *arg)
{
	int ret = 0;
	size_t count;
	struct voluta_cache_elem *ce;
	struct voluta_list_head *lru = &lm->lru;
	struct voluta_list_head *itr = lru->prev;

	count = lm->count;
	while (!ret && count-- && (itr != lru)) {
		ce = ce_from_lru_link(itr);
		itr = itr->prev;
		ret = cb(ce, arg);
	}
}

static size_t lrumap_overpop(const struct voluta_lrumap *lm)
{
	return (lm->count > lm->hsize) ? (lm->count - lm->hsize) : 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dq_init(struct voluta_dirtyq *dq)
{
	listq_init(&dq->dq_list);
	dq->dq_accum_nbytes = 0;
}

static void dq_initn(struct voluta_dirtyq *dq, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		dq_init(&dq[i]);
	}
}

static void dq_fini(struct voluta_dirtyq *dq)
{
	listq_fini(&dq->dq_list);
	dq->dq_accum_nbytes = 0;
}

static void dq_finin(struct voluta_dirtyq *dq, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		dq_fini(&dq[i]);
	}
}

static void dq_append(struct voluta_dirtyq *dq,
		      struct voluta_list_head *lh, size_t len)
{
	listq_push_back(&dq->dq_list, lh);
	dq->dq_accum_nbytes += len;
}

static void dq_remove(struct voluta_dirtyq *dq,
		      struct voluta_list_head *lh, size_t len)
{
	voluta_assert_ge(dq->dq_accum_nbytes, len);

	listq_remove(&dq->dq_list, lh);
	dq->dq_accum_nbytes -= len;
}

static struct voluta_list_head *dq_front(const struct voluta_dirtyq *dq)
{
	return listq_front(&dq->dq_list);
}

static struct voluta_list_head *
dq_next_of(const struct voluta_dirtyq *dq,
	   const struct voluta_list_head *lh)
{
	return listq_next(&dq->dq_list, lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *dq_blh_to_vi(struct voluta_list_head *dq_blh)
{
	const struct voluta_vnode_info *vi = NULL;

	if (dq_blh != NULL) {
		vi = container_of(dq_blh, struct voluta_vnode_info, v_dq_blh);
	}
	return unconst(vi);
}

static struct voluta_vnode_info *dq_mlh_to_vi(struct voluta_list_head *dq_mlh)
{
	const struct voluta_vnode_info *vi = NULL;

	if (dq_mlh != NULL) {
		vi = container_of(dq_mlh, struct voluta_vnode_info, v_dq_mlh);
	}
	return unconst(vi);
}

static size_t dirtyqs_key_to_slot(const struct voluta_dirtyqs *dqs, long key)
{
	size_t bin = 0;

	if (key > 0) {
		bin = ((size_t)key % (dqs->dq_nbins - 1)) + 1;
	}
	return bin;
}

static int dirtyqs_init(struct voluta_dirtyqs *dqs, struct voluta_qalloc *qal)
{
	const size_t nbins = 2729 + 1; /* prime plus 1 */
	const size_t msize = nbins * sizeof(*dqs->dq_bins);

	dqs->dq_qalloc = qal;
	dqs->dq_nbins = 0;

	dqs->dq_bins = voluta_qalloc_zmalloc(qal, msize);
	if (dqs->dq_bins == NULL) {
		return -ENOMEM;
	}
	dq_initn(dqs->dq_bins, nbins);
	dq_init(&dqs->dq_main);
	dqs->dq_nbins = nbins;
	return 0;
}

static void dirtyqs_fini(struct voluta_dirtyqs *dqs)
{
	const size_t msize = dqs->dq_nbins * sizeof(*dqs->dq_bins);

	dq_fini(&dqs->dq_main);
	dq_finin(dqs->dq_bins, dqs->dq_nbins);
	voluta_qalloc_free(dqs->dq_qalloc, dqs->dq_bins, msize);
	dqs->dq_qalloc = NULL;
	dqs->dq_nbins = 0;
	dqs->dq_bins = 0;
}

static struct voluta_dirtyq *
dirtyqs_queue_at(const struct voluta_dirtyqs *dqs, size_t slot)
{
	const struct voluta_dirtyq *dq = &dqs->dq_bins[slot];

	voluta_assert_lt(slot, dqs->dq_nbins);
	return unconst(dq);
}

static size_t dirtyqs_slot_of_vi(const struct voluta_dirtyqs *dqs,
				 const struct voluta_vnode_info *vi)
{
	return dirtyqs_key_to_slot(dqs, vi->v_ds_key);
}

static struct voluta_dirtyq *
dirtyqs_queue_of_vi(const struct voluta_dirtyqs *dqs,
		    const struct voluta_vnode_info *vi)
{
	const size_t slot = dirtyqs_slot_of_vi(dqs, vi);

	return dirtyqs_queue_at(dqs, slot);
}

static struct voluta_dirtyq *
dirtyqs_queue_of_ii(const struct voluta_dirtyqs *dqs,
		    const struct voluta_inode_info *ii)
{
	return dirtyqs_queue_of_vi(dqs, ii_vi(ii));
}

static void dirtyqs_enq_vi(struct voluta_dirtyqs *dqs,
			   struct voluta_vnode_info *vi)
{
	struct voluta_dirtyq *dq;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if (!vi->v_dirty) {
		dq = dirtyqs_queue_of_vi(dqs, vi);
		dq_append(dq, &vi->v_dq_blh, vaddr->len);

		dq = &dqs->dq_main;
		dq_append(dq, &vi->v_dq_mlh, vaddr->len);

		vi->v_dirty = 1;
	}
}

static void dirtyqs_dec_vi(struct voluta_dirtyqs *dqs,
			   struct voluta_vnode_info *vi)
{
	struct voluta_dirtyq *dq;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if (vi->v_dirty) {
		dq = dirtyqs_queue_of_vi(dqs, vi);
		dq_remove(dq, &vi->v_dq_blh, vaddr->len);

		dq = &dqs->dq_main;
		dq_remove(dq, &vi->v_dq_mlh, vaddr->len);

		vi->v_dirty = 0;
	}
}

static struct voluta_vnode_info *
dirtyqs_front(const struct voluta_dirtyqs *dqs)
{
	const struct voluta_dirtyq *dq = &dqs->dq_main;

	return dq_mlh_to_vi(dq_front(dq));
}

static struct voluta_vnode_info *
dirtyqs_nextof(const struct voluta_dirtyqs *dqs,
	       const struct voluta_vnode_info *vi)
{
	const struct voluta_dirtyq *dq = &dqs->dq_main;

	return dq_mlh_to_vi(dq_next_of(dq, &vi->v_dq_mlh));
}

static struct voluta_vnode_info *
dirtyqs_front_at(const struct voluta_dirtyqs *dqs, size_t slot)
{
	const struct voluta_dirtyq *dq = dirtyqs_queue_at(dqs, slot);

	return dq_blh_to_vi(dq_front(dq));
}

static struct voluta_vnode_info *
dirtyqs_nextof_at(const struct voluta_dirtyqs *dqs,
		  const struct voluta_vnode_info *vi, size_t slot)
{
	const struct voluta_dirtyq *dq = dirtyqs_queue_at(dqs, slot);

	return dq_blh_to_vi(dq_next_of(dq, &vi->v_dq_blh));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cache_tick_once(struct voluta_cache *cache)
{
	cache->c_tick += 1;
}

static void cache_dirtify_vi(struct voluta_cache *cache,
			     struct voluta_vnode_info *vi)
{
	dirtyqs_enq_vi(&cache->c_dqs, vi);
}

static void cache_undirtify_vi(struct voluta_cache *cache,
			       struct voluta_vnode_info *vi)
{
	dirtyqs_dec_vi(&cache->c_dqs, vi);
}

static struct voluta_bk_info *cache_new_bki(const struct voluta_cache *cache)
{
	struct voluta_block *bk;
	struct voluta_bk_info *bki;

	bk = malloc_bk(cache->c_qalloc);
	if (bk == NULL) {
		return NULL;
	}
	bki = malloc_bki(cache->c_mpool);
	if (bki == NULL) {
		free_bk(cache->c_qalloc, bk);
		return NULL;
	}
	bki_init(bki, bk);
	return bki;
}

static void cache_del_bki(const struct voluta_cache *cache,
			  struct voluta_bk_info *bki)
{
	struct voluta_block *bk = bki->bk;

	bki_fini(bki);
	free_bk(cache->c_qalloc, bk);
	free_bki(cache->c_mpool, bki);
}

static int cache_init_dirtyqs(struct voluta_cache *cache)
{
	return dirtyqs_init(&cache->c_dqs, cache->c_qalloc);
}

static void cache_fini_dirtyqs(struct voluta_cache *cache)
{
	dirtyqs_fini(&cache->c_dqs);
}

static int cache_init_blm(struct voluta_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_blm, cache->c_qalloc,
			   htbl_size, lba_hash);
}

static void cache_fini_blm(struct voluta_cache *cache)
{
	lrumap_fini(&cache->c_blm, cache->c_qalloc);
}

static struct voluta_bk_info *
cache_find_bki(const struct voluta_cache *cache, loff_t lba)
{
	struct voluta_cache_elem *ce;

	ce = lrumap_find(&cache->c_blm, lba);
	return bki_from_ce(ce);
}

static void cache_store_bki(struct voluta_cache *cache,
			    struct voluta_bk_info *bki, loff_t lba)
{
	bki_set_lba(bki, lba);
	lrumap_store(&cache->c_blm, &bki->bki_ce, lba);
}

static void cache_promote_lru_bki(struct voluta_cache *cache,
				  struct voluta_bk_info *bki)
{
	struct voluta_cache_elem *ce = &bki->bki_ce;

	lrumap_promote_lru(&cache->c_blm, ce);
	ce->ce_tick = cache->c_tick;
}

static void cache_evict_bki(struct voluta_cache *cache,
			    struct voluta_bk_info *bki)
{
	voluta_assert(ce_is_evictable(bki_ce(bki)));

	lrumap_remove(&cache->c_blm, &bki->bki_ce);
	cache_del_bki(cache, bki);
}

void voluta_cache_forget_bki(struct voluta_cache *cache,
			     struct voluta_bk_info *bki)
{
	voluta_assert_eq(bki->bki_ce.ce_refcnt, 0);

	cache_evict_bki(cache, bki);
}

static struct voluta_bk_info *
cache_spawn_bki(struct voluta_cache *cache, loff_t lba)
{
	struct voluta_bk_info *bki;

	bki = cache_new_bki(cache);
	if (bki == NULL) {
		return NULL;
	}
	cache_store_bki(cache, bki, lba);
	return bki;
}

static struct voluta_bk_info *
cache_find_relru_bki(struct voluta_cache *cache, loff_t lba)
{
	struct voluta_bk_info *bki;

	bki = cache_find_bki(cache, lba);
	if (bki != NULL) {
		cache_promote_lru_bki(cache, bki);
	}
	return bki;
}

struct voluta_bk_info *
voluta_cache_lookup_bki(struct voluta_cache *cache, loff_t lba)
{
	struct voluta_bk_info *bki = NULL;

	if (lba != VOLUTA_LBA_NULL) {
		bki = cache_find_relru_bki(cache, lba);
	}
	return bki;
}

static struct voluta_bk_info *
cache_find_or_spawn_bki(struct voluta_cache *cache, loff_t lba)
{
	struct voluta_bk_info *bki;

	bki = cache_find_relru_bki(cache, lba);
	if (bki != NULL) {
		return bki;
	}
	bki = cache_spawn_bki(cache, lba);
	if (bki == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return bki;
}

static int visit_evictable_bki(struct voluta_cache_elem *ce, void *arg)
{
	int ret = 0;
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_bk_info *bki = bki_from_ce(ce);

	if (c_ctx->count++ >= c_ctx->limit) {
		ret = 1;
	} else if (bki_is_evictable(bki)) {
		c_ctx->bki = bki;
		ret = 1;
	}
	return ret;
}

static size_t calc_search_evictable_max(const struct voluta_lrumap *lm)
{
	return clamp(lm->count / 4, 1, 256);
}

static struct voluta_bk_info *
cache_find_evictable_bki(struct voluta_cache *cache)
{
	struct voluta_cache_ctx c_ctx = {
		.cache = cache,
		.bki = NULL,
		.limit = calc_search_evictable_max(&cache->c_blm)
	};

	lrumap_foreach_backward(&cache->c_blm, visit_evictable_bki, &c_ctx);
	return c_ctx.bki;
}

static struct voluta_bk_info *
cache_require_bki(struct voluta_cache *cache, loff_t lba)
{
	struct voluta_bk_info *bki = NULL;

	bki = cache_find_or_spawn_bki(cache, lba);
	if (bki == NULL) {
		cache_evict_some(cache);
		bki = cache_find_or_spawn_bki(cache, lba);
	}
	return bki;
}

struct voluta_bk_info *
voluta_cache_spawn_bki(struct voluta_cache *cache, loff_t lba)
{
	return cache_require_bki(cache, lba);
}

static struct voluta_bk_info *cache_get_lru_bki(struct voluta_cache *cache)
{
	struct voluta_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_blm);
	return bki_from_ce(ce);
}

static void cache_try_evict_bki(struct voluta_cache *cache,
				struct voluta_bk_info *bki)
{
	voluta_assert_not_null(bki);

	if (bki_is_evictable(bki)) {
		cache_evict_bki(cache, bki);
	}
}

static int try_evict_bki(struct voluta_cache_elem *ce, void *arg)
{
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_bk_info *bki = bki_from_ce(ce);

	cache_try_evict_bki(c_ctx->cache, bki);
	return 0;
}

static void cache_drop_evictable_bkis(struct voluta_cache *cache)
{
	struct voluta_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_blm, try_evict_bki, &c_ctx);
}

static bool cache_evict_or_relru_bki(struct voluta_cache *cache,
				     struct voluta_bk_info *bki)
{
	bool evicted;

	if (bki_is_evictable(bki)) {
		cache_evict_bki(cache, bki);
		evicted = true;
	} else {
		cache_promote_lru_bki(cache, bki);
		evicted = false;
	}
	return evicted;
}

static void cache_shrink_or_relru_bkis(struct voluta_cache *cache, size_t cnt)
{
	bool ok = true;
	struct voluta_bk_info *bki;
	const size_t n = min(cnt, cache->c_blm.count);

	for (size_t i = 0; (i < n) && ok; ++i) {
		bki = cache_get_lru_bki(cache);
		if (bki == NULL) {
			break;
		}
		ok = cache_evict_or_relru_bki(cache, bki);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *cache_new_vi(const struct voluta_cache *cache)
{
	struct voluta_vnode_info *vi;

	vi = malloc_vi(cache->c_mpool);
	if (vi != NULL) {
		vi_init(vi);
	}
	return vi;
}

static void cache_del_vi(const struct voluta_cache *cache,
			 struct voluta_vnode_info *vi)
{
	vi_fini(vi);
	free_vi(cache->c_mpool, vi);
}

static int cache_init_vlm(struct voluta_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_vlm, cache->c_qalloc,
			   htbl_size, off_hash);
}

static void cache_fini_vlm(struct voluta_cache *cache)
{
	lrumap_fini(&cache->c_vlm, cache->c_qalloc);
}

static struct voluta_vnode_info *
cache_find_vi(struct voluta_cache *cache, const struct voluta_vaddr *vaddr)
{
	struct voluta_cache_elem *ce;

	ce = lrumap_find(&cache->c_vlm, vaddr->off);
	return vi_from_ce(ce);
}

static void cache_evict_vi(struct voluta_cache *cache,
			   struct voluta_vnode_info *vi)
{
	voluta_assert(!vi->v_dirty);

	lrumap_remove(&cache->c_vlm, vi_ce(vi));
	vi_detach_all(vi);
	cache_del_vi(cache, vi);
}

static void cache_promote_lru_vi(struct voluta_cache *cache,
				 struct voluta_vnode_info *vi)
{
	struct voluta_cache_elem *ce = vi_ce(vi);

	lrumap_promote_lru(&cache->c_vlm, ce);
	ce->ce_tick = cache->c_tick;
}

static struct voluta_vnode_info *
cache_lookup_vi(struct voluta_cache *cache, const struct voluta_vaddr *vaddr)
{
	struct voluta_vnode_info *vi;

	vi = cache_find_vi(cache, vaddr);
	if (vi != NULL) {
		cache_promote_lru_vi(cache, vi);
		cache_promote_lru_bki(cache, vi->v_bki);
	}
	return vi;
}

struct voluta_vnode_info *
voluta_cache_lookup_vi(struct voluta_cache *cache,
		       const struct voluta_vaddr *vaddr)
{
	return cache_lookup_vi(cache, vaddr);
}

static void cache_store_vi(struct voluta_cache *cache,
			   struct voluta_vnode_info *vi,
			   const struct voluta_vaddr *vaddr)
{
	vi_assign(vi, vaddr);
	lrumap_store(&cache->c_vlm, &vi->v_ce, vaddr->off);
}

static int visit_evictable_vi(struct voluta_cache_elem *ce, void *arg)
{
	int ret = 0;
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_vnode_info *vi = vi_from_ce(ce);

	if (c_ctx->count++ >= c_ctx->limit) {
		ret = 1;
	} else if (vi_is_evictable(vi)) {
		c_ctx->vi = vi;
		ret = 1;
	}
	return ret;
}

static struct voluta_vnode_info *
cache_find_evictable_vi(struct voluta_cache *cache)
{
	struct voluta_cache_ctx c_ctx = {
		.cache = cache,
		.vi = NULL,
		.limit = calc_search_evictable_max(&cache->c_vlm)
	};

	lrumap_foreach_backward(&cache->c_vlm, visit_evictable_vi, &c_ctx);
	return c_ctx.vi;
}

static struct voluta_vnode_info *
cache_spawn_vi(struct voluta_cache *cache, const struct voluta_vaddr *vaddr)
{
	struct voluta_vnode_info *vi;

	vi = cache_new_vi(cache);
	if (vi == NULL) {
		return NULL;
	}
	cache_store_vi(cache, vi, vaddr);
	return vi;
}

static struct voluta_vnode_info *
cache_require_vi(struct voluta_cache *cache, const struct voluta_vaddr *vaddr)
{
	struct voluta_vnode_info *vi = NULL;

	vi = cache_spawn_vi(cache, vaddr);
	if (vi == NULL) {
		cache_evict_some(cache);
		vi = cache_spawn_vi(cache, vaddr);
	}
	return vi;
}

struct voluta_vnode_info *
voluta_cache_spawn_vi(struct voluta_cache *cache,
		      const struct voluta_vaddr *vaddr)
{
	return cache_require_vi(cache, vaddr);
}

void voulta_cache_forget_vi(struct voluta_cache *cache,
			    struct voluta_vnode_info *vi)
{
	voluta_assert_eq(vi_refcnt(vi), 0);

	vi_undirtify(vi);
	cache_evict_vi(cache, vi);
}

void voluta_attach_to(struct voluta_vnode_info *vi,
		      struct voluta_bk_info *bki,
		      struct voluta_vnode_info *pvi,
		      struct voluta_inode_info *pii)
{
	voluta_assert_null(vi->v_bki);

	vi_attach_bk(vi, bki);
	vi_attach_pvi(vi, pvi);
	vi_setup_ds_key(vi, pii);
}

static struct voluta_vnode_info *cache_get_lru_vi(struct voluta_cache *cache)
{
	struct voluta_vnode_info *vi = NULL;
	const struct voluta_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_vlm);
	if (ce != NULL) {
		vi = vi_from_ce(ce);
	}
	return vi;
}

static bool cache_is_evictable_vi(const struct voluta_cache *cache,
				  const struct voluta_vnode_info *vi)
{
	/*
	 * Special case: do not evict data used in current read_iter cycle,
	 * or bad things will happen while pages are spliced to user.
	 */
	if (vi_isdata(vi) && vi_has_tick(vi, cache->c_tick)) {
		return false;
	}
	return vi_is_evictable(vi);
}

static bool cache_evict_or_relru_vi(struct voluta_cache *cache,
				    struct voluta_vnode_info *vi)
{
	bool evicted;

	if (cache_is_evictable_vi(cache, vi)) {
		cache_evict_vi(cache, vi);
		evicted = true;
	} else {
		cache_promote_lru_vi(cache, vi);
		evicted = false;
	}
	return evicted;
}

static int try_evict_vi(struct voluta_cache_elem *ce, void *arg)
{
	struct voluta_cache *cache = arg;
	struct voluta_vnode_info *vi = vi_from_ce(ce);

	voluta_assert_ne(vi->vaddr.vtype, VOLUTA_VTYPE_NONE);

	cache_evict_or_relru_vi(cache, vi);
	return 0;
}

static void cache_drop_evictable_vis(struct voluta_cache *cache)
{
	lrumap_foreach_backward(&cache->c_vlm, try_evict_vi, cache);
}

static void cache_shrink_or_relru_vis(struct voluta_cache *cache, size_t cnt)
{
	bool ok = true;
	struct voluta_vnode_info *vi;
	const size_t n = min(cnt, cache->c_vlm.count);

	for (size_t i = 0; (i < n) && ok; ++i) {
		vi = cache_get_lru_vi(cache);
		if (vi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_vi(cache, vi);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_inode_info *cache_new_ii(const struct voluta_cache *cache)
{
	struct voluta_inode_info *ii;

	ii = malloc_ii(cache->c_mpool);
	if (ii != NULL) {
		ii_init(ii);
	}
	return ii;
}

static void cache_del_ii(const struct voluta_cache *cache,
			 struct voluta_inode_info *ii)
{
	ii_fini(ii);
	free_ii(cache->c_mpool, ii);
}

static int cache_init_ilm(struct voluta_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_ilm, cache->c_qalloc,
			   htbl_size, off_hash);
}

static void cache_fini_ilm(struct voluta_cache *cache)
{
	lrumap_fini(&cache->c_ilm, cache->c_qalloc);
}

static struct voluta_inode_info *
cache_find_ii(struct voluta_cache *cache, const struct voluta_iaddr *iaddr)
{
	struct voluta_cache_elem *ce;
	struct voluta_inode_info *ii = NULL;

	ce = lrumap_find(&cache->c_ilm, (long)(iaddr->vaddr.off));
	if (ce != NULL) {
		ii = ii_from_ce(ce);
	}
	return ii;
}

static void cache_evict_ii(struct voluta_cache *cache,
			   struct voluta_inode_info *ii)
{
	struct voluta_vnode_info *vi = ii_vi(ii);

	lrumap_remove(&cache->c_ilm, ii_ce(ii));
	vi_detach_all(vi);
	cache_del_ii(cache, ii);
}

static void cache_promote_lru_ii(struct voluta_cache *cache,
				 struct voluta_inode_info *ii)
{
	struct voluta_cache_elem *ce = ii_ce(ii);

	lrumap_promote_lru(&cache->c_ilm, ce);
	ce->ce_tick = cache->c_tick;
}

static struct voluta_inode_info *
cache_lookup_ii(struct voluta_cache *cache, const struct voluta_iaddr *iaddr)
{
	struct voluta_inode_info *ii;

	ii = cache_find_ii(cache, iaddr);
	if (ii != NULL) {
		cache_promote_lru_ii(cache, ii);
		cache_promote_lru_bki(cache, ii->i_vi.v_bki);
	}
	return ii;
}

struct voluta_inode_info *
voluta_cache_lookup_ii(struct voluta_cache *cache,
		       const struct voluta_iaddr *iaddr)
{
	return cache_lookup_ii(cache, iaddr);
}

static void cache_store_ii(struct voluta_cache *cache,
			   struct voluta_inode_info *ii,
			   const struct voluta_iaddr *iaddr)
{
	ii_assign(ii, iaddr);
	lrumap_store(&cache->c_ilm, ii_ce(ii), (long)(iaddr->vaddr.off));
}

static int visit_evictable_ii(struct voluta_cache_elem *ce, void *arg)
{
	int ret = 0;
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_inode_info *ii = ii_from_ce(ce);

	if (c_ctx->count++ >= c_ctx->limit) {
		ret = 1;
	} else if (ii_isevictable(ii)) {
		c_ctx->ii = ii;
		ret = 1;
	}
	return ret;
}

static struct voluta_inode_info *
cache_find_evictable_ii(struct voluta_cache *cache)
{
	struct voluta_cache_ctx c_ctx = {
		.cache = cache,
		.ii = NULL,
		.limit = calc_search_evictable_max(&cache->c_ilm)
	};

	lrumap_foreach_backward(&cache->c_ilm, visit_evictable_ii, &c_ctx);
	return c_ctx.ii;
}

static struct voluta_inode_info *
cache_spawn_ii(struct voluta_cache *cache, const struct voluta_iaddr *iaddr)
{
	struct voluta_inode_info *ii;

	ii = cache_new_ii(cache);
	if (ii == NULL) {
		return NULL;
	}
	cache_store_ii(cache, ii, iaddr);
	return ii;
}

static struct voluta_inode_info *
cache_require_ii(struct voluta_cache *cache, const struct voluta_iaddr *iaddr)
{
	struct voluta_inode_info *ii = NULL;

	ii = cache_spawn_ii(cache, iaddr);
	if (ii == NULL) {
		cache_evict_some(cache);
		ii = cache_spawn_ii(cache, iaddr);
	}
	return ii;
}

struct voluta_inode_info *
voluta_cache_spawn_ii(struct voluta_cache *cache,
		      const struct voluta_iaddr *iaddr)
{
	return cache_require_ii(cache, iaddr);
}

void voulta_cache_forget_ii(struct voluta_cache *cache,
			    struct voluta_inode_info *ii)
{
	vi_undirtify(ii_vi(ii));
	cache_evict_ii(cache, ii);
}

static struct voluta_inode_info *cache_get_lru_ii(struct voluta_cache *cache)
{
	struct voluta_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_ilm);
	return (ce != NULL) ? ii_from_ce(ce) : NULL;
}

static bool cache_evict_or_relru_ii(struct voluta_cache *cache,
				    struct voluta_inode_info *ii)
{
	bool evicted;
	const bool recently_used = vi_has_tick(ii_vi(ii), cache->c_tick);

	if (!recently_used && ii_isevictable(ii)) {
		cache_evict_ii(cache, ii);
		evicted = true;
	} else {
		cache_promote_lru_ii(cache, ii);
		evicted = false;
	}
	return evicted;
}

static int try_evict_ii(struct voluta_cache_elem *ce, void *arg)
{
	struct voluta_cache *cache = arg;
	struct voluta_inode_info *ii = ii_from_ce(ce);

	cache_evict_or_relru_ii(cache, ii);
	return 0;
}

static void cache_drop_evictable_iis(struct voluta_cache *cache)
{
	lrumap_foreach_backward(&cache->c_ilm, try_evict_ii, cache);
}

static void cache_shrink_or_relru_iis(struct voluta_cache *cache, size_t cnt)
{
	bool ok = true;
	struct voluta_inode_info *ii;
	const size_t n = min(cnt, cache->c_ilm.count);

	for (size_t i = 0; (i < n) && ok; ++i) {
		ii = cache_get_lru_ii(cache);
		if (ii == NULL) {
			break;
		}
		ok = cache_evict_or_relru_ii(cache, ii);
	}
}

static void cache_shrink_some(struct voluta_cache *cache, size_t factor)
{
	size_t count;
	size_t nshrink;

	count = lrumap_overpop(&cache->c_vlm) + 1;
	nshrink = min(count * factor, VOLUTA_NKB_IN_BK);
	cache_shrink_or_relru_vis(cache, nshrink);

	count = lrumap_overpop(&cache->c_ilm) + 1;
	nshrink = min(count * factor, VOLUTA_NKB_IN_BK);
	cache_shrink_or_relru_iis(cache, nshrink);

	count = lrumap_overpop(&cache->c_blm) + 1;
	nshrink = min(count * factor, VOLUTA_MEGA / VOLUTA_BK_SIZE);
	cache_shrink_or_relru_bkis(cache, nshrink);
}

static unsigned int cache_memory_pressure(const struct voluta_cache *cache)
{
	const size_t npages_used = cache->c_qalloc->st.npages_used;
	const size_t npages_tota = cache->c_qalloc->st.npages;

	/* percentage ration */
	return (unsigned int)((100 * npages_used) / npages_tota);
}

static bool cache_has_overpop(const struct voluta_cache *cache)
{
	return lrumap_overpop(&cache->c_blm) ||
	       lrumap_overpop(&cache->c_vlm) ||
	       lrumap_overpop(&cache->c_ilm);
}

static size_t cache_calc_niter(const struct voluta_cache *cache, int flags)
{
	size_t niter = 0;
	const uint32_t mem_press = cache_memory_pressure(cache);

	if (mem_press > 16) {
		niter = 8;
	} else if (mem_press > 8) {
		niter = 4;
	} else if (mem_press > 4) {
		niter = 2;
	} else if (mem_press > 2) {
		niter = 1;
	}
	if (flags & VOLUTA_F_TIMEOUT) {
		niter = max(niter, 1);
	}
	if (cache_has_overpop(cache)) {
		niter += 1;
	}
	return niter;
}

static size_t cache_calc_factor(const struct voluta_cache *cache, int flags)
{
	size_t factor = 1;
	const size_t mem_press = cache_memory_pressure(cache);

	if (flags & VOLUTA_F_TIMEOUT) {
		factor = (flags & VOLUTA_F_IDLE) ? 8 : 2;
	}
	if (flags & VOLUTA_F_BRINGUP) {
		factor += 1;
	}
	if (flags & VOLUTA_F_OPSTART) {
		factor += 1;
	}
	if (mem_press > 50) {
		factor *= 2;
	}
	return factor;
}

void voluta_cache_relax(struct voluta_cache *cache, int flags)
{
	const size_t factor = cache_calc_factor(cache, flags);
	const size_t niter = factor * cache_calc_niter(cache, flags);

	for (size_t i = 0; i < niter; ++i) {
		cache_tick_once(cache);
		cache_shrink_some(cache, factor);
	}
}

void voluta_cache_shrink_once(struct voluta_cache *cache)
{
	const size_t bk_size = VOLUTA_BK_SIZE;
	const size_t memsz_bkis = bk_size * cache->c_blm.count;
	const size_t memsz_data = cache->c_qalloc->st.memsz_data;

	if ((8 * memsz_bkis) > memsz_data) {
		cache_shrink_some(cache, 1);
	}
}

static size_t cache_lrumap_usage_sum(const struct voluta_cache *cache)
{
	return lrumap_usage(&cache->c_blm) +
	       lrumap_usage(&cache->c_ilm) +
	       lrumap_usage(&cache->c_vlm);
}

static void cache_drop_evictables(struct voluta_cache *cache)
{
	cache_drop_evictable_vis(cache);
	cache_drop_evictable_iis(cache);
	cache_drop_evictable_bkis(cache);
}

void voluta_cache_drop(struct voluta_cache *cache)
{
	size_t usage_now;
	size_t usage_pre = 0;
	size_t iter_count = 0;

	usage_now = cache_lrumap_usage_sum(cache);
	while ((iter_count++ < 10) && (usage_now != usage_pre)) {
		usage_pre = usage_now;
		cache_tick_once(cache);
		cache_drop_evictables(cache);
		usage_now = cache_lrumap_usage_sum(cache);
	}
}

static size_t flush_threshold_of(int flags)
{
	size_t threshold;
	const size_t mega = VOLUTA_UMEGA;

	if (flags & VOLUTA_F_NOW) {
		threshold = 0;
	} else if (flags & VOLUTA_F_IDLE) {
		threshold = mega / 2;
	} else if (flags & VOLUTA_F_SYNC) {
		threshold = mega;
	} else {
		threshold = 2 * mega;
	}
	return threshold;
}

static bool cache_dq_need_flush(const struct voluta_cache *cache,
				const struct voluta_dirtyq *dq, int flags)
{
	unsigned int mem_press;
	const size_t threshold = flush_threshold_of(flags);

	if (dq->dq_accum_nbytes > threshold) {
		return true;
	}
	mem_press = cache_memory_pressure(cache);
	if (mem_press > 50) {
		return true;
	}
	return false;
}

bool voluta_cache_need_flush(const struct voluta_cache *cache, int flags)
{
	const struct voluta_dirtyq *dq = &cache->c_dqs.dq_main;

	return cache_dq_need_flush(cache, dq, flags);
}

bool voluta_cache_need_flush_of(const struct voluta_cache *cache,
				const struct voluta_inode_info *ii, int flags)
{
	const struct voluta_dirtyq *dq =
		dirtyqs_queue_of_ii(&cache->c_dqs, ii);

	return cache_dq_need_flush(cache, dq, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cache_evict_by_bki(struct voluta_cache *cache,
			       struct voluta_bk_info *bki)
{
	bool ret = false;

	if ((bki != NULL) && bki_is_evictable(bki)) {
		cache_evict_bki(cache, bki);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_vi(struct voluta_cache *cache,
			      struct voluta_vnode_info *vi)
{
	struct voluta_bk_info *bki = NULL;
	struct voluta_vnode_info *pvi = NULL;

	if ((vi != NULL) && vi_is_evictable(vi)) {
		pvi = vi->v_pvi;
		bki = vi->v_bki;
		cache_evict_vi(cache, vi);
		cache_evict_by_vi(cache, pvi);
	}
	return cache_evict_by_bki(cache, bki);
}

static bool cache_evict_by_ii(struct voluta_cache *cache,
			      struct voluta_inode_info *ii)
{
	struct voluta_bk_info *bki = NULL;
	struct voluta_vnode_info *pvi = NULL;

	if ((ii != NULL) && ii_isevictable(ii)) {
		pvi = ii->i_vi.v_pvi;
		bki = ii->i_vi.v_bki;
		cache_evict_ii(cache, ii);
		cache_evict_by_vi(cache, pvi);
	}
	return cache_evict_by_bki(cache, bki);
}

static void cache_evict_some(struct voluta_cache *cache)
{
	bool ok = false;
	struct voluta_bk_info *bki;
	struct voluta_vnode_info *vi;
	struct voluta_inode_info *ii;

	vi = cache_find_evictable_vi(cache);
	if (cache_evict_by_vi(cache, vi)) {
		ok = true;
	}
	ii = cache_find_evictable_ii(cache);
	if (cache_evict_by_ii(cache, ii)) {
		ok = true;
	}
	bki = cache_find_evictable_bki(cache);
	if (cache_evict_by_bki(cache, bki)) {
		ok = true;
	}
	if (!ok) {
		cache_shrink_some(cache, 1);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_nil_bk(struct voluta_cache *cache)
{
	struct voluta_qalloc *qal = cache->c_qalloc;
	const size_t bk_size = sizeof(*cache->c_nil_bk);

	cache->c_nil_bk = voluta_qalloc_zmalloc(qal, bk_size);
	return (cache->c_nil_bk != NULL) ? 0 : -ENOMEM;
}

static void cache_fini_nil_bk(struct voluta_cache *cache)
{
	struct voluta_qalloc *qal = cache->c_qalloc;
	const size_t bk_size = sizeof(*cache->c_nil_bk);

	if (cache->c_nil_bk != NULL) {
		voluta_qalloc_free(qal, cache->c_nil_bk, bk_size);
		cache->c_nil_bk = NULL;
	}
}

static size_t cache_htbl_size(const struct voluta_cache *cache, size_t div)
{
	const struct voluta_qalloc *qal = cache->c_qalloc;
	const size_t hwant = qal->st.memsz_data / div;
	const size_t limit = clamp(hwant, 1U << 14, 1U << 20);

	return voluta_hash_prime(limit);
}

static void cache_fini_lrumaps(struct voluta_cache *cache)
{
	cache_fini_vlm(cache);
	cache_fini_ilm(cache);
	cache_fini_blm(cache);
}

static int cache_init_lrumaps(struct voluta_cache *cache)
{
	int err;
	size_t hsize;

	hsize = cache_htbl_size(cache, sizeof(struct voluta_block));
	err = cache_init_blm(cache, hsize);
	if (err) {
		goto out;
	}
	hsize = cache_htbl_size(cache, 2 * sizeof(struct voluta_inode));
	err = cache_init_ilm(cache, hsize);
	if (err) {
		goto out;
	}
	hsize = cache_htbl_size(cache, sizeof(struct voluta_data_block4));
	err = cache_init_vlm(cache, hsize);
	if (err) {
		goto out;
	}
out:
	if (err) {
		cache_fini_lrumaps(cache);
	}
	return 0;
}

int voluta_cache_init(struct voluta_cache *cache, struct voluta_mpool *mpool)
{
	int err;

	voluta_memzero(cache, sizeof(*cache));
	cache->c_tick = 1;
	cache->c_mpool = mpool;
	cache->c_qalloc = mpool->mp_qal;

	err = cache_init_nil_bk(cache);
	if (err) {
		goto out;
	}
	err = cache_init_dirtyqs(cache);
	if (err) {
		goto out;
	}
	err = cache_init_lrumaps(cache);
	if (err) {
		goto out;
	}
out:
	if (err) {
		cache_fini_lrumaps(cache);
		cache_fini_dirtyqs(cache);
		cache_fini_nil_bk(cache);
	}
	return err;
}

void voluta_cache_fini(struct voluta_cache *cache)
{
	cache_fini_lrumaps(cache);
	cache_fini_dirtyqs(cache);
	cache_fini_nil_bk(cache);
	cache->c_qalloc = NULL;
	cache->c_mpool = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vi_dirtify(struct voluta_vnode_info *vi)
{
	cache_dirtify_vi(vi_cache(vi), vi);
}

static void vi_undirtify(struct voluta_vnode_info *vi)
{
	cache_undirtify_vi(vi_cache(vi), vi);
}

void voluta_ii_dirtify(struct voluta_inode_info *ii)
{
	voluta_vi_dirtify(ii_vi(ii));
}

bool voluta_ii_isrdonly(const struct voluta_inode_info *ii)
{
	const unsigned long ms_mask = MS_RDONLY;
	const struct voluta_sb_info *sbi = ii_sbi(ii);

	return ((sbi->sb_ms_flags & ms_mask) == ms_mask);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool voluta_is_visible(const struct voluta_vnode_info *vi)
{
	return bki_is_visible(vi->v_bki, vi_vaddr(vi));
}

void voluta_mark_visible(const struct voluta_vnode_info *vi)
{
	bki_mark_visible(vi->v_bki, vi_vaddr(vi));
}

void voluta_mark_opaque_at(struct voluta_bk_info *bki,
			   const struct voluta_vaddr *vaddr)
{
	bki_mark_opaque(bki, vaddr);
}

void voluta_mark_opaque(const struct voluta_vnode_info *vi)
{
	voluta_mark_opaque_at(vi->v_bki, vi_vaddr(vi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long off_compare(const void *x, const void *y)
{
	const loff_t x_off = *((const loff_t *)x);
	const loff_t y_off = *((const loff_t *)y);

	return y_off - x_off;
}

static struct voluta_vnode_info *
avl_node_to_vi(const struct voluta_avl_node *an)
{
	const struct voluta_vnode_info *vi;

	vi = container_of2(an, struct voluta_vnode_info, v_ds_an);
	return unconst(vi);
}

static const void *vi_getkey(const struct voluta_avl_node *an)
{
	const struct voluta_vnode_info *vi = avl_node_to_vi(an);

	return &vi->vaddr.off;
}

static void vi_visit_reinit(struct voluta_avl_node *an, void *p)
{
	struct voluta_vnode_info *vi = avl_node_to_vi(an);

	voluta_avl_node_init(&vi->v_ds_an);
	unused(p);
}

static void dset_init(struct voluta_dset *dset,
		      struct voluta_cache *cache, long key)
{
	voluta_avl_init(&dset->ds_avl, vi_getkey, off_compare, dset);
	dset->ds_cache = cache;
	dset->ds_viq = NULL;
	dset->ds_key = key;
}

static void dset_fini(struct voluta_dset *dset)
{
	voluta_avl_fini(&dset->ds_avl);
	dset->ds_cache = NULL;
	dset->ds_viq = NULL;
}

static void dset_clear_map(struct voluta_dset *dset)
{
	voluta_avl_clear(&dset->ds_avl, vi_visit_reinit, NULL);
}

static void dset_add_dirty_vi(struct voluta_dset *dset,
			      struct voluta_vnode_info *vi)
{
	voluta_avl_insert(&dset->ds_avl, &vi->v_ds_an);
}

static const struct voluta_dirtyqs *
dset_dirtyqs(const struct voluta_dset *dset)
{
	return &dset->ds_cache->c_dqs;
}

static void dset_iter_dirty_by_key(struct voluta_dset *dset)
{
	size_t slot;
	struct voluta_vnode_info *vi = NULL;
	const struct voluta_dirtyqs *dqs = dset_dirtyqs(dset);

	slot = dirtyqs_key_to_slot(dqs, dset->ds_key);
	vi = dirtyqs_front_at(dqs, slot);
	while (vi != NULL) {
		dset_add_dirty_vi(dset, vi);
		vi = dirtyqs_nextof_at(dqs, vi, slot);
	}
}

static void dset_iter_dirty_all(struct voluta_dset *dset)
{
	struct voluta_vnode_info *vi = NULL;
	const struct voluta_dirtyqs *dqs = dset_dirtyqs(dset);

	vi = dirtyqs_front(dqs);
	while (vi != NULL) {
		dset_add_dirty_vi(dset, vi);
		vi = dirtyqs_nextof(dqs, vi);
	}
}

static void dset_inhabit(struct voluta_dset *dset)
{
	if (dset->ds_key > 0) {
		dset_iter_dirty_by_key(dset);
	} else {
		dset_iter_dirty_all(dset);
	}
}

static void dset_purge(const struct voluta_dset *dset)
{
	struct voluta_vnode_info *vi;
	struct voluta_vnode_info *next;

	vi = dset->ds_viq;
	while (vi != NULL) {
		next = vi->v_ds_next;

		vi_undirtify(vi);
		vi->v_ds_next = NULL;

		vi = next;
	}
}

static void dset_push_front_viq(struct voluta_dset *dset,
				struct voluta_vnode_info *vi)
{
	vi->v_ds_next = dset->ds_viq;
	dset->ds_viq = vi;
}

static void dset_make_fifo(struct voluta_dset *dset)
{
	struct voluta_vnode_info *vi;
	const struct voluta_avl_node *end;
	const struct voluta_avl_node *itr;
	const struct voluta_avl *avl = &dset->ds_avl;

	dset->ds_viq = NULL;
	end = voluta_avl_end(avl);
	itr = voluta_avl_rbegin(avl);
	while (itr != end) {
		vi = avl_node_to_vi(itr);
		dset_push_front_viq(dset, vi);
		itr = voluta_avl_prev(avl, itr);
	}
}

void voluta_dset_build(struct voluta_dset *dset,
		       struct voluta_cache *cache, long key)
{
	dset_init(dset, cache, key);
	dset_inhabit(dset);
	dset_make_fifo(dset);
}

void voluta_dset_cleanup(struct voluta_dset *dset)
{
	dset_clear_map(dset);
	dset_purge(dset);
	dset_fini(dset);
}


