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
#include <sys/types.h>
#include <sys/mount.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <voluta/fs/address.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/mpool.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/private.h>

#define CACHE_RETRY 2


static void cache_evict_some(struct voluta_cache *cache);
static void cache_dirtify_ui(struct voluta_cache *cache,
                             struct voluta_unode_info *ui);
static void cache_undirtify_ui(struct voluta_cache *cache,
                               struct voluta_unode_info *ui);

typedef int (*voluta_cache_elem_fn)(struct voluta_cache_elem *, void *);

struct voluta_cache_ctx {
	struct voluta_cache *cache;
	struct voluta_bksec_info *bsi;
	struct voluta_unode_info *ui;
	struct voluta_vnode_info *vi;
	size_t limit;
	size_t count;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* prime-value for hash-table of n-elements */
static const unsigned int voluta_primes[] = {
	13, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157,
	98317, 147377, 196613, 294979, 393241, 589933, 786433, 1572869,
	3145739, 6291469, 12582917, 25165843, 50331653, 100663319, 201326611,
	402653189, 805306457, 1610612741, 3221225473, 4294967291
};

static size_t htbl_prime_size(size_t lim)
{
	size_t p = 11;

	for (size_t i = 0; i < ARRAY_SIZE(voluta_primes); ++i) {
		if (voluta_primes[i] > lim) {
			break;
		}
		p = voluta_primes[i];
	}
	return p;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static uint64_t rotate64(uint64_t x, unsigned int b)
{
	return (x << b) | (x >> (64 - b));
}

static int compare64(uint64_t x, uint64_t y)
{
	return (x < y) ? -1 : (x > y ? 1 : 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void *malloc_nelems(struct voluta_alloc_if *alif,
                           size_t elemsz, size_t nelems)
{
	return voluta_allocate(alif, elemsz * nelems);
}


static void free_nelems(struct voluta_alloc_if *alif,
                        void *ptr, size_t elemsz, size_t nelems)
{
	voluta_deallocate(alif, ptr, elemsz * nelems);
}

static struct voluta_list_head *
new_htbl(struct voluta_alloc_if *alif, size_t nelems)
{
	struct voluta_list_head *htbl;

	htbl = malloc_nelems(alif, sizeof(*htbl), nelems);
	if (htbl != NULL) {
		list_head_initn(htbl, nelems);
	}
	return htbl;
}

static void del_htbl(struct voluta_alloc_if *alif,
                     struct voluta_list_head *htbl, size_t nelems)
{
	list_head_finin(htbl, nelems);
	free_nelems(alif, htbl, sizeof(*htbl), nelems);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_blocks_sec *bks_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_blocks_sec *bs;

	bs = voluta_allocate(alif, sizeof(*bs));
	return bs;
}

static void bks_free(struct voluta_blocks_sec *bs,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, bs, sizeof(*bs));
}

static struct voluta_bksec_info *bsi_malloc(struct voluta_alloc_if *alif)
{
	struct voluta_bksec_info *bsi;

	bsi = voluta_allocate(alif, sizeof(*bsi));
	return bsi;
}

static void bsi_free(struct voluta_bksec_info *bsi,
                     struct voluta_alloc_if *alif)
{
	voluta_deallocate(alif, bsi, sizeof(*bsi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t ckey_make_hash(const struct voluta_ckey *ckey)
{
	const uint64_t h1 = twang_mix64(ckey->k[0]);
	const uint64_t h2 = rotate64(ckey->k[1], (uint32_t)(h1 % 61));

	return h1 ^ h2;
}

static void ckey_setup(struct voluta_ckey *ckey, uint64_t k1, uint64_t k2)
{
	ckey->k[0] = k1;
	ckey->k[1] = k2;
	ckey->h = ckey_make_hash(ckey);
}

static void ckey_setup3(struct voluta_ckey *ckey,
                        uint64_t k1, uint32_t k2, uint32_t k3)
{
	ckey_setup(ckey, k1, ((uint64_t)k2 << 32) | (uint64_t)k3);
}

static void ckey_by_lba(struct voluta_ckey *ckey, voluta_lba_t lba)
{
	ckey_setup(ckey, (uint64_t)lba, 0);
}

static void ckey_by_uaddr(struct voluta_ckey *ckey,
                          const struct voluta_uaddr *uaddr)
{
	ckey_setup3(ckey, (uint64_t)uaddr->off | (1UL << 63),
	            (uint32_t)uaddr->utype, (uint32_t)uaddr->len);
}

static void ckey_by_vaddr(struct voluta_ckey *ckey,
                          const struct voluta_vaddr *vaddr)
{
	ckey_setup3(ckey, (uint64_t)vaddr->off,
	            (uint32_t)vaddr->vtype, (uint32_t)vaddr->len);
}

static void ckey_reset(struct voluta_ckey *ckey)
{
	ckey_setup(ckey, 0, 0);
}

static bool ckey_isequal(const struct voluta_ckey *ckey,
                         const struct voluta_ckey *other)
{
	return (ckey->k[0] == other->k[0]) && (ckey->k[1] == other->k[1]);
}

int voluta_ckey_compare(const struct voluta_ckey *ckey1,
                        const struct voluta_ckey *ckey2)
{
	int cmp;

	cmp = compare64(ckey1->k[0], ckey2->k[0]);
	if (cmp == 0) {
		cmp = compare64(ckey1->k[1], ckey2->k[1]);
	}
	return cmp;
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

void voluta_ce_init(struct voluta_cache_elem *ce)
{
	ckey_reset(&ce->ce_ckey);
	list_head_init(&ce->ce_htb_lh);
	list_head_init(&ce->ce_lru_lh);
	ce->ce_refcnt = 0;
	ce->ce_mapped = false;
	ce->ce_forgot = false;
	ce->ce_dirty = false;
}

void voluta_ce_fini(struct voluta_cache_elem *ce)
{
	voluta_assert(!ce->ce_mapped);
	voluta_assert(!ce->ce_dirty);

	ckey_reset(&ce->ce_ckey);
	list_head_fini(&ce->ce_htb_lh);
	list_head_fini(&ce->ce_lru_lh);
	ce->ce_refcnt = 0;
}

static void ce_hmap(struct voluta_cache_elem *ce,
                    struct voluta_list_head *hlst)
{
	voluta_assert(!ce->ce_mapped);

	list_push_front(hlst, &ce->ce_htb_lh);
	ce->ce_mapped = true;
}

static void ce_hunmap(struct voluta_cache_elem *ce)
{
	voluta_assert(ce->ce_mapped);

	list_head_remove(&ce->ce_htb_lh);
	ce->ce_mapped = false;
}

static struct voluta_list_head *ce_lru_link(struct voluta_cache_elem *ce)
{
	return &ce->ce_lru_lh;
}

static void ce_lru(struct voluta_cache_elem *ce, struct voluta_listq *lru)
{
	listq_push_front(lru, ce_lru_link(ce));
}

static void ce_unlru(struct voluta_cache_elem *ce, struct voluta_listq *lru)
{
	listq_remove(lru, ce_lru_link(ce));
}

static bool ce_islru_front(struct voluta_cache_elem *ce,
                           struct voluta_listq *lru)
{
	return (listq_front(lru) == ce_lru_link(ce));
}

static void ce_relru(struct voluta_cache_elem *ce, struct voluta_listq *lru)
{
	if (!ce_islru_front(ce, lru)) {
		ce_unlru(ce, lru);
		ce_lru(ce, lru);
	}
}

static size_t ce_refcnt(const struct voluta_cache_elem *ce)
{
	return (size_t)ce->ce_refcnt;
}

static size_t ce_incref(struct voluta_cache_elem *ce)
{
	voluta_assert_lt(ce->ce_refcnt, INT_MAX / 2);
	voluta_assert_ge(ce->ce_refcnt, 0);
	ce->ce_refcnt++;

	return ce_refcnt(ce);
}

static size_t ce_decref(struct voluta_cache_elem *ce)
{
	voluta_assert_gt(ce->ce_refcnt, 0);
	ce->ce_refcnt--;

	return ce_refcnt(ce);
}

static bool ce_is_evictable(const struct voluta_cache_elem *ce)
{
	return !ce->ce_refcnt && !ce->ce_dirty;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_bksec_info *
bsi_from_ce(const struct voluta_cache_elem *ce)
{
	const struct voluta_bksec_info *bsi = NULL;

	if (ce != NULL) {
		bsi = container_of2(ce, struct voluta_bksec_info, bks_ce);
	}
	return unconst(bsi);
}

static struct voluta_cache_elem *bsi_ce(const struct voluta_bksec_info *bsi)
{
	const struct voluta_cache_elem *ce = &bsi->bks_ce;

	return unconst(ce);
}

static void bsi_set_lba(struct voluta_bksec_info *bsi, voluta_lba_t lba)
{
	struct voluta_cache_elem *ce = bsi_ce(bsi);

	bsi->bks_lba = lba_of_bks(lba);
	ckey_by_lba(&ce->ce_ckey, bsi->bks_lba);
}

static void bsi_init(struct voluta_bksec_info *bsi,
                     struct voluta_blocks_sec *bs)
{
	voluta_ce_init(&bsi->bks_ce);
	memset(bsi->bks_mask, 0, sizeof(bsi->bks_mask));
	bsi->bks = bs;
	bsi->bks_lba = VOLUTA_LBA_NULL;
}

static void bsi_fini(struct voluta_bksec_info *bsi)
{
	voluta_ce_fini(&bsi->bks_ce);
	bsi->bks = NULL;
	bsi->bks_lba = VOLUTA_LBA_NULL;
}

static void bsi_incref(struct voluta_bksec_info *bsi)
{
	ce_incref(bsi_ce(bsi));
}

static void bsi_decref(struct voluta_bksec_info *bsi)
{
	ce_decref(bsi_ce(bsi));
}

static bool bsi_is_evictable(const struct voluta_bksec_info *bsi)
{
	return ce_is_evictable(bsi_ce(bsi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_cnode_info *ci_from_ce(const struct voluta_cache_elem *ce)
{
	const struct voluta_cnode_info *ci = NULL;

	if (likely(ce != NULL)) {
		ci = container_of2(ce, struct voluta_cnode_info, ce);
	}
	return unconst(ci);
}

static struct voluta_cache_elem *ci_to_ce(const struct voluta_cnode_info *ci)
{
	const struct voluta_cache_elem *ce = &ci->ce;

	return unconst(ce);
}

static struct voluta_cache *ci_cache(const struct voluta_cnode_info *ci)
{
	return ci->c_sbi->s_cache;
}

bool voluta_ci_isevictable(const struct voluta_cnode_info *ci)
{
	return ce_is_evictable(ci_to_ce(ci));
}

static void ci_attach_bk(struct voluta_cnode_info *ci,
                         struct voluta_bksec_info *bsi)
{
	voluta_assert_null(ci->c_bsi);

	bsi_incref(bsi);
	ci->c_bsi = bsi;
}

static void ci_detach_bk(struct voluta_cnode_info *ci)
{
	if (ci->c_bsi != NULL) {
		bsi_decref(ci->c_bsi);
		ci->c_bsi = NULL;
	}
}

static size_t ci_incref(struct voluta_cnode_info *ci)
{
	return ce_incref(&ci->ce);
}

static size_t ci_decref(struct voluta_cnode_info *ci)
{
	return ce_decref(&ci->ce);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_unode_info *ui_from_ce(const struct voluta_cache_elem *ce)
{
	const struct voluta_unode_info *ui = NULL;

	if (likely(ce != NULL)) {
		ui = voluta_ui_from_ci(ci_from_ce(ce));
	}
	return unconst(ui);
}

static struct voluta_cache_elem *ui_to_ce(const struct voluta_unode_info *ui)
{
	return ci_to_ce(&ui->u_ci);
}

static struct voluta_cache *ui_cache(const struct voluta_unode_info *ui)
{
	return ci_cache(&ui->u_ci);
}

void voluta_ui_incref(struct voluta_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ci_incref(&ui->u_ci);
	}
}

void voluta_ui_decref(struct voluta_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ci_decref(&ui->u_ci);
	}
}

void voluta_ui_dirtify(struct voluta_unode_info *ui)
{
	cache_dirtify_ui(ui_cache(ui), ui);
}

void voluta_ui_undirtify(struct voluta_unode_info *ui)
{
	cache_undirtify_ui(ui_cache(ui), ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_cache *vi_cache(const struct voluta_vnode_info *vi)
{
	return vi_sbi(vi)->s_cache;
}

static struct voluta_vnode_info *vi_from_ce(const struct voluta_cache_elem *ce)
{
	const struct voluta_vnode_info *vi = NULL;
	const struct voluta_cnode_info *ci = ci_from_ce(ce);

	if (likely(ci != NULL)) {
		vi = container_of2(ci, struct voluta_vnode_info, v_ci);
	}
	return unconst(vi);
}

static struct voluta_cache_elem *vi_to_ce(const struct voluta_vnode_info *vi)
{
	const struct voluta_cache_elem *ce = &vi->v_ci.ce;

	return unconst(ce);
}

static struct voluta_cnode_info *vi_to_ci(const struct voluta_vnode_info *vi)
{
	const struct voluta_cnode_info *ci = NULL;

	if (likely(vi != NULL)) {
		ci = &vi->v_ci;
	}
	return unconst(ci);
}

size_t voluta_vi_refcnt(const struct voluta_vnode_info *vi)
{
	size_t refcnt = 0;

	if (likely(vi != NULL)) {
		refcnt = ce_refcnt(vi_to_ce(vi));
	}
	return refcnt;
}

void voluta_vi_incref(struct voluta_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		ce_incref(vi_to_ce(vi));
	}
}

static void vi_decref_fixup(struct voluta_vnode_info *vi)
{
	size_t refcnt_post;
	struct voluta_cache_elem *ce = vi_to_ce(vi);

	refcnt_post = ce_decref(ce);

	/*
	 * Special case where data-node has been unmapped due to forget, yet
	 * it still had a live ref-count due to on-going I/O operation.
	 */
	if (!refcnt_post && ce->ce_forgot) {
		voulta_cache_forget_vi(vi_cache(vi), vi);
	}
}

void voluta_vi_decref(struct voluta_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		vi_decref_fixup(vi);
	}
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

static size_t bsi_mask_slot_of(const struct voluta_bksec_info *bsi,
                               const struct voluta_vaddr *vaddr)
{
	return (size_t)(vaddr->lba) % ARRAY_SIZE(bsi->bks_mask);
}

void voluta_bsi_mark_visible_at(struct voluta_bksec_info *bsi,
                                const struct voluta_vaddr *vaddr)
{
	const size_t slot = bsi_mask_slot_of(bsi, vaddr);

	bsi->bks_mask[slot] |= view_mask_of(vaddr);
}

void voluta_bsi_mark_opaque_at(struct voluta_bksec_info *bsi,
                               const struct voluta_vaddr *vaddr)
{
	const size_t slot = bsi_mask_slot_of(bsi, vaddr);

	bsi->bks_mask[slot] &= ~view_mask_of(vaddr);
}

bool voluta_bsi_is_visible_at(struct voluta_bksec_info *bsi,
                              const struct voluta_vaddr *vaddr)
{
	const size_t slot = bsi_mask_slot_of(bsi, vaddr);
	const uint64_t bk_mask = bsi->bks_mask[slot];
	const uint64_t mask = view_mask_of(vaddr);

	return ((bk_mask & mask) == mask);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lrumap_init(struct voluta_lrumap *lm,
                       struct voluta_alloc_if *alif, size_t htbl_size)
{
	struct voluta_list_head *htbl;

	htbl = new_htbl(alif, htbl_size);
	if (htbl == NULL) {
		return -ENOMEM;
	}
	listq_init(&lm->lru);
	lm->htbl = htbl;
	lm->htbl_nelems = htbl_size;
	lm->htbl_size = 0;
	return 0;
}

static void lrumap_fini(struct voluta_lrumap *lm, struct voluta_alloc_if *alif)
{
	if (lm->htbl != NULL) {
		del_htbl(alif, lm->htbl, lm->htbl_nelems);
		listq_fini(&lm->lru);
		lm->htbl = NULL;
		lm->htbl_nelems = 0;
	}
}

static size_t lrumap_usage(const struct voluta_lrumap *lm)
{
	return lm->htbl_size;
}

static size_t lrumap_key_to_bin(const struct voluta_lrumap *lm,
                                const struct voluta_ckey *ckey)
{
	return ckey->h % lm->htbl_nelems;
}

static void lrumap_store(struct voluta_lrumap *lm,
                         struct voluta_cache_elem *ce)
{
	const size_t bin = lrumap_key_to_bin(lm, &ce->ce_ckey);

	ce_hmap(ce, &lm->htbl[bin]);
	ce_lru(ce, &lm->lru);
	lm->htbl_size += 1;
}

static struct voluta_cache_elem *
lrumap_find(const struct voluta_lrumap *lm, const struct voluta_ckey *ckey)
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
		if (ckey_isequal(&ce->ce_ckey, ckey)) {
			return unconst(ce);
		}
		itr = itr->next;
	}
	return NULL;
}

static void lrumap_unmap(struct voluta_lrumap *lm,
                         struct voluta_cache_elem *ce)
{
	ce_hunmap(ce);
	lm->htbl_size -= 1;
}

static void lrumap_unlru(struct voluta_lrumap *lm,
                         struct voluta_cache_elem *ce)
{
	voluta_assert_gt(lm->lru.sz, 0);

	ce_unlru(ce, &lm->lru);
}

static void lrumap_remove(struct voluta_lrumap *lm,
                          struct voluta_cache_elem *ce)
{
	lrumap_unmap(lm, ce);
	lrumap_unlru(lm, ce);
}

static void lrumap_promote_lru(struct voluta_lrumap *lm,
                               struct voluta_cache_elem *ce)
{
	ce_relru(ce, &lm->lru);
}

static struct voluta_cache_elem *lrumap_get_lru(const struct voluta_lrumap *lm)
{
	struct voluta_cache_elem *ce = NULL;

	if (lm->lru.sz > 0) {
		ce = ce_from_lru_link(lm->lru.ls.prev);
	}
	return ce;
}

static void lrumap_foreach_backward(struct voluta_lrumap *lm,
                                    voluta_cache_elem_fn cb, void *arg)
{
	int ret = 0;
	size_t count;
	struct voluta_cache_elem *ce;
	struct voluta_listq *lru = &lm->lru;
	struct voluta_list_head *itr = lru->ls.prev;

	count = lru->sz;
	while (!ret && count-- && (itr != &lru->ls)) {
		ce = ce_from_lru_link(itr);
		itr = itr->prev;
		ret = cb(ce, arg);
	}
}

static size_t lrumap_overpop(const struct voluta_lrumap *lm)
{
	if (lm->htbl_size > lm->htbl_nelems) {
		return (lm->htbl_size - lm->htbl_nelems);
	}
	if (lm->lru.sz > lm->htbl_size) {
		return (lm->lru.sz - lm->htbl_size);
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dq_init(struct voluta_dirtyq *dq)
{
	listq_init(&dq->dq_list);
	dq->dq_accum_nbytes = 0;
}

static void dq_fini(struct voluta_dirtyq *dq)
{
	listq_fini(&dq->dq_list);
	dq->dq_accum_nbytes = 0;
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

static struct voluta_cnode_info *dq_lh_to_ci(struct voluta_list_head *dq_lh)
{
	const struct voluta_cnode_info *ci = NULL;

	if (dq_lh != NULL) {
		ci = container_of(dq_lh, struct voluta_cnode_info, c_dq_lh);
	}
	return unconst(ci);
}

static void cache_dq_enq_ci(struct voluta_cache *cache,
                            struct voluta_cnode_info *ci)
{
	struct voluta_dirtyq *dq = &cache->c_dq;

	if (!ci->ce.ce_dirty) {
		dq_append(dq, &ci->c_dq_lh, ci->c_xref_len);
		ci->ce.ce_dirty = true;
	}
}

static void cache_dq_dec_ci(struct voluta_cache *cache,
                            struct voluta_cnode_info *ci)
{
	struct voluta_dirtyq *dq = &cache->c_dq;

	if (ci->ce.ce_dirty) {
		dq_remove(dq, &ci->c_dq_lh, ci->c_xref_len);
		ci->ce.ce_dirty = false;
	}
}

static struct voluta_cnode_info *
cache_dq_front_ci(const struct voluta_cache *cache)
{
	const struct voluta_dirtyq *dq = &cache->c_dq;

	return dq_lh_to_ci(dq_front(dq));
}

static struct voluta_cnode_info *
cache_dq_next_ci(const struct voluta_cache *cache,
                 const struct voluta_cnode_info *ci)
{
	const struct voluta_dirtyq *dq = &cache->c_dq;

	return dq_lh_to_ci(dq_next_of(dq, &ci->c_dq_lh));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void cache_dirtify_ui(struct voluta_cache *cache,
                             struct voluta_unode_info *ui)
{
	cache_dq_enq_ci(cache, &ui->u_ci);
}

static void cache_undirtify_ui(struct voluta_cache *cache,
                               struct voluta_unode_info *ui)
{
	cache_dq_dec_ci(cache, &ui->u_ci);
}

static void cache_dirtify_vi(struct voluta_cache *cache,
                             struct voluta_vnode_info *vi)
{
	cache_dq_enq_ci(cache, &vi->v_ci);
}

static void cache_undirtify_vi(struct voluta_cache *cache,
                               struct voluta_vnode_info *vi)
{
	cache_dq_dec_ci(cache, &vi->v_ci);
}

static struct voluta_bksec_info *
cache_new_bsi(const struct voluta_cache *cache)
{
	struct voluta_blocks_sec *bs;
	struct voluta_bksec_info *bsi;

	bs = bks_malloc(cache->c_alif);
	if (bs == NULL) {
		return NULL;
	}
	bsi = bsi_malloc(cache->c_alif);
	if (bsi == NULL) {
		bks_free(bs, cache->c_alif);
		return NULL;
	}
	bsi_init(bsi, bs);
	return bsi;
}

static void cache_del_bsi(const struct voluta_cache *cache,
                          struct voluta_bksec_info *bsi)
{
	struct voluta_blocks_sec *bks = bsi->bks;

	bsi_fini(bsi);
	bks_free(bks, cache->c_alif);
	bsi_free(bsi, cache->c_alif);
}

static int cache_init_blm(struct voluta_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_blm, cache->c_alif, htbl_size);
}

static void cache_fini_blm(struct voluta_cache *cache)
{
	lrumap_fini(&cache->c_blm, cache->c_alif);
}

static struct voluta_bksec_info *
cache_find_bsi(const struct voluta_cache *cache, voluta_lba_t lba)
{
	struct voluta_cache_elem *ce;
	struct voluta_ckey ckey;

	ckey_by_lba(&ckey, lba_of_bks(lba));
	ce = lrumap_find(&cache->c_blm, &ckey);
	return bsi_from_ce(ce);
}

static void cache_store_bsi(struct voluta_cache *cache,
                            struct voluta_bksec_info *bsi, voluta_lba_t lba)
{
	struct voluta_cache_elem *ce = &bsi->bks_ce;

	bsi_set_lba(bsi, lba);
	lrumap_store(&cache->c_blm, ce);
}

static void cache_promote_lru_bsi(struct voluta_cache *cache,
                                  struct voluta_bksec_info *bsi)
{
	lrumap_promote_lru(&cache->c_blm, &bsi->bks_ce);
}

static void cache_evict_bsi(struct voluta_cache *cache,
                            struct voluta_bksec_info *bsi)
{
	voluta_assert(ce_is_evictable(bsi_ce(bsi)));

	lrumap_remove(&cache->c_blm, &bsi->bks_ce);
	cache_del_bsi(cache, bsi);
}

void voluta_cache_forget_bsi(struct voluta_cache *cache,
                             struct voluta_bksec_info *bsi)
{
	voluta_assert_eq(bsi->bks_ce.ce_refcnt, 0);

	cache_evict_bsi(cache, bsi);
}

static struct voluta_bksec_info *
cache_spawn_bsi(struct voluta_cache *cache, voluta_lba_t lba)
{
	struct voluta_bksec_info *bsi;

	bsi = cache_new_bsi(cache);
	if (bsi == NULL) {
		return NULL;
	}
	cache_store_bsi(cache, bsi, lba);
	return bsi;
}

static struct voluta_bksec_info *
cache_find_relru_bsi(struct voluta_cache *cache, voluta_lba_t lba)
{
	struct voluta_bksec_info *bsi;

	bsi = cache_find_bsi(cache, lba);
	if (bsi != NULL) {
		cache_promote_lru_bsi(cache, bsi);
	}
	return bsi;
}

struct voluta_bksec_info *
voluta_cache_lookup_bsi(struct voluta_cache *cache,
                        const struct voluta_vba *vba)
{
	const voluta_lba_t lba = lba_of_bks(vba->vaddr.lba);

	return cache_find_relru_bsi(cache, lba);
}

static struct voluta_bksec_info *
cache_find_or_spawn_bsi(struct voluta_cache *cache, voluta_lba_t lba)
{
	struct voluta_bksec_info *bsi;

	bsi = cache_find_relru_bsi(cache, lba);
	if (bsi != NULL) {
		return bsi;
	}
	bsi = cache_spawn_bsi(cache, lba);
	if (bsi == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return bsi;
}

static int visit_evictable_bsi(struct voluta_cache_elem *ce, void *arg)
{
	int ret = 0;
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_bksec_info *bsi = bsi_from_ce(ce);

	if (c_ctx->count++ >= c_ctx->limit) {
		ret = 1;
	} else if (bsi_is_evictable(bsi)) {
		c_ctx->bsi = bsi;
		ret = 1;
	}
	return ret;
}

static size_t calc_search_evictable_max(const struct voluta_lrumap *lm)
{
	return clamp(lm->htbl_size / 4, 1, 16);
}

static struct voluta_bksec_info *
cache_find_evictable_bsi(struct voluta_cache *cache)
{
	struct voluta_cache_ctx c_ctx = {
		.cache = cache,
		.bsi = NULL,
		.limit = calc_search_evictable_max(&cache->c_blm)
	};

	lrumap_foreach_backward(&cache->c_blm, visit_evictable_bsi, &c_ctx);
	return c_ctx.bsi;
}

static struct voluta_bksec_info *
cache_require_bsi(struct voluta_cache *cache, voluta_lba_t lba)
{
	int retry = CACHE_RETRY;
	struct voluta_bksec_info *bsi = NULL;

	while (retry-- > 0) {
		bsi = cache_find_or_spawn_bsi(cache, lba);
		if (bsi != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return bsi;
}

struct voluta_bksec_info *
voluta_cache_spawn_bsi(struct voluta_cache *cache,
                       const struct voluta_vba *vba)
{
	return cache_require_bsi(cache, vba->vaddr.lba);
}

static struct voluta_bksec_info *cache_get_lru_bsi(struct voluta_cache *cache)
{
	struct voluta_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_blm);
	return bsi_from_ce(ce);
}

static void cache_try_evict_bsi(struct voluta_cache *cache,
                                struct voluta_bksec_info *bsi)
{
	voluta_assert_not_null(bsi);

	if (bsi_is_evictable(bsi)) {
		cache_evict_bsi(cache, bsi);
	}
}

static int try_evict_bsi(struct voluta_cache_elem *ce, void *arg)
{
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_bksec_info *bsi = bsi_from_ce(ce);

	cache_try_evict_bsi(c_ctx->cache, bsi);
	return 0;
}

static void cache_drop_evictable_bsis(struct voluta_cache *cache)
{
	struct voluta_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_blm, try_evict_bsi, &c_ctx);
}

static bool cache_evict_or_relru_bsi(struct voluta_cache *cache,
                                     struct voluta_bksec_info *bsi)
{
	bool evicted;

	if (bsi_is_evictable(bsi)) {
		cache_evict_bsi(cache, bsi);
		evicted = true;
	} else {
		cache_promote_lru_bsi(cache, bsi);
		evicted = false;
	}
	return evicted;
}

static size_t cache_shrink_or_relru_bks(struct voluta_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct voluta_bksec_info *bsi;
	const size_t n = min(cnt, cache->c_blm.lru.sz);

	for (size_t i = 0; i < n; ++i) {
		bsi = cache_get_lru_bsi(cache);
		if (bsi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_bsi(cache, bsi);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_vnode_info *
cache_new_vi(const struct voluta_cache *cache, const struct voluta_vba *vba)
{
	return voluta_new_vi(cache->c_alif, vba);
}

static int cache_init_vlm(struct voluta_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_vlm, cache->c_alif, htbl_size);
}

static void cache_fini_vlm(struct voluta_cache *cache)
{
	lrumap_fini(&cache->c_vlm, cache->c_alif);
}

static struct voluta_vnode_info *
cache_find_vi(struct voluta_cache *cache, const struct voluta_vaddr *vaddr)
{
	struct voluta_ckey ckey;
	struct voluta_cache_elem *ce;

	ckey_by_vaddr(&ckey, vaddr);
	ce = lrumap_find(&cache->c_vlm, &ckey);
	return vi_from_ce(ce);
}

static void cache_unmap_vi(struct voluta_cache *cache,
                           struct voluta_vnode_info *vi)
{
	if (vi->v_ci.ce.ce_mapped) {
		lrumap_remove(&cache->c_vlm, vi_to_ce(vi));
	}
}

static void cache_remove_vi(struct voluta_cache *cache,
                            struct voluta_vnode_info *vi)
{
	struct voluta_lrumap *lm = &cache->c_vlm;
	struct voluta_cache_elem *ce = vi_to_ce(vi);

	if (ce->ce_mapped) {
		lrumap_remove(lm, ce);
	} else {
		lrumap_unlru(lm, ce);
	}
}

static void cache_evict_vi(struct voluta_cache *cache,
                           struct voluta_vnode_info *vi)
{
	struct voluta_cnode_info *ci = &vi->v_ci;

	voluta_assert(!ci->ce.ce_dirty);

	cache_remove_vi(cache, vi);
	ci_detach_bk(ci);
	ci->c_vtbl->del(ci, cache->c_alif);
}

static void cache_promote_lru_vi(struct voluta_cache *cache,
                                 struct voluta_vnode_info *vi)
{
	lrumap_promote_lru(&cache->c_vlm, vi_to_ce(vi));
}

static struct voluta_vnode_info *
cache_find_relru_vi(struct voluta_cache *cache,
                    const struct voluta_vaddr *vaddr)
{
	struct voluta_vnode_info *vi;

	vi = cache_find_vi(cache, vaddr);
	if (vi != NULL) {
		cache_promote_lru_vi(cache, vi);
		cache_promote_lru_bsi(cache, vi->v_ci.c_bsi);
	}
	return vi;
}

struct voluta_vnode_info *
voluta_cache_lookup_vi(struct voluta_cache *cache,
                       const struct voluta_vaddr *vaddr)
{
	return cache_find_relru_vi(cache, vaddr);
}

static void cache_store_vi(struct voluta_cache *cache,
                           struct voluta_vnode_info *vi)
{
	struct voluta_cnode_info *ci = &vi->v_ci;

	ckey_by_vaddr(&ci->ce.ce_ckey, &vi->vaddr);
	lrumap_store(&cache->c_vlm, &ci->ce);
}

static int visit_evictable_vi(struct voluta_cache_elem *ce, void *arg)
{
	int ret = 0;
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_vnode_info *vi = vi_from_ce(ce);
	struct voluta_cnode_info *ci = ci_from_ce(ce);

	if (c_ctx->count++ >= c_ctx->limit) {
		ret = 1;
	} else if (ci->c_vtbl->evictable(ci)) {
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
cache_require_vi(struct voluta_cache *cache, const struct voluta_vba *vba)
{
	int retry = CACHE_RETRY;
	struct voluta_vnode_info *vi = NULL;

	while (retry-- > 0) {
		vi = cache_new_vi(cache, vba);
		if (vi != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return vi;
}

void voulta_cache_forget_vi(struct voluta_cache *cache,
                            struct voluta_vnode_info *vi)
{
	vi_undirtify(vi);
	if (vi_refcnt(vi) > 0) {
		cache_unmap_vi(cache, vi);
		vi->v_ci.ce.ce_forgot = true;
	} else {
		cache_evict_vi(cache, vi);
	}
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

static bool cache_evict_or_relru_vi(struct voluta_cache *cache,
                                    struct voluta_vnode_info *vi)
{
	bool evicted;
	struct voluta_cnode_info *ci = vi_to_ci(vi);

	if (ci->c_vtbl->evictable(ci)) {
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

static size_t cache_shrink_or_relru_vis(struct voluta_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct voluta_vnode_info *vi;
	const size_t n = min(cnt, cache->c_vlm.lru.sz);

	for (size_t i = 0; i < n; ++i) {
		vi = cache_get_lru_vi(cache);
		if (vi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_vi(cache, vi);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

void voluta_vi_attach_to(struct voluta_vnode_info *vi,
                         struct voluta_bksec_info *bsi)
{
	ci_attach_bk(&vi->v_ci, bsi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_vnode_info *
voluta_cache_spawn_vi(struct voluta_cache *cache,
                      const struct voluta_vba *vba)
{
	struct voluta_vnode_info *vi;

	vi = cache_require_vi(cache, vba);
	if (vi != NULL) {
		cache_store_vi(cache, vi);
	}
	return vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_ulm(struct voluta_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_ulm, cache->c_alif, htbl_size);
}

static void cache_fini_ilm(struct voluta_cache *cache)
{
	lrumap_fini(&cache->c_ulm, cache->c_alif);
}

static struct voluta_unode_info *
cache_find_ui(struct voluta_cache *cache, const struct voluta_uaddr *uaddr)
{
	struct voluta_ckey ckey;
	struct voluta_cache_elem *ce;
	struct voluta_unode_info *ui = NULL;

	ckey_by_uaddr(&ckey, uaddr);
	ce = lrumap_find(&cache->c_ulm, &ckey);
	if (ce != NULL) {
		ui = ui_from_ce(ce);
	}
	return ui;
}

static void cache_evict_ui(struct voluta_cache *cache,
                           struct voluta_unode_info *ui)
{
	struct voluta_cnode_info *ci = &ui->u_ci;

	lrumap_remove(&cache->c_ulm, ci_to_ce(ci));
	ci_detach_bk(ci);
	ci->c_vtbl->del(ci, cache->c_alif);
}

static void cache_promote_lru_ui(struct voluta_cache *cache,
                                 struct voluta_unode_info *ui)
{
	lrumap_promote_lru(&cache->c_ulm, ui_to_ce(ui));
}

static struct voluta_unode_info *
cache_find_relru_ui(struct voluta_cache *cache,
                    const struct voluta_uaddr *uaddr)
{
	struct voluta_unode_info *ui;

	ui = cache_find_ui(cache, uaddr);
	if (ui != NULL) {
		cache_promote_lru_ui(cache, ui);
		cache_promote_lru_bsi(cache, ui->u_ci.c_bsi);
	}
	return ui;
}

struct voluta_unode_info *
voluta_cache_lookup_ui(struct voluta_cache *cache,
                       const struct voluta_uaddr *uaddr)
{
	return cache_find_relru_ui(cache, uaddr);
}

static void cache_store_ui(struct voluta_cache *cache,
                           struct voluta_unode_info *ui)
{
	struct voluta_cnode_info *ci = &ui->u_ci;

	ckey_by_uaddr(&ci->ce.ce_ckey, &ui->uba.uaddr);
	lrumap_store(&cache->c_ulm, &ci->ce);
}

static int visit_evictable_ui(struct voluta_cache_elem *ce, void *arg)
{
	int ret = 0;
	struct voluta_cache_ctx *c_ctx = arg;
	struct voluta_cnode_info *ci = ci_from_ce(ce);

	if (c_ctx->count++ >= c_ctx->limit) {
		ret = 1;
	} else if (ci->c_vtbl->evictable(ci)) {
		c_ctx->ui = voluta_ui_from_ci(ci);
		ret = 1;
	}
	return ret;
}

static struct voluta_unode_info *
cache_find_evictable_ui(struct voluta_cache *cache)
{
	struct voluta_cache_ctx c_ctx = {
		.cache = cache,
		.ui = NULL,
		.limit = calc_search_evictable_max(&cache->c_ulm)
	};

	lrumap_foreach_backward(&cache->c_ulm, visit_evictable_ui, &c_ctx);
	return c_ctx.ui;
}

static struct voluta_unode_info *
cache_new_ui(const struct voluta_cache *cache, const struct voluta_uba *uba)
{
	return voluta_new_ui(cache->c_alif, uba);
}

static struct voluta_unode_info *
cache_require_ui(struct voluta_cache *cache, const struct voluta_uba *uba)
{
	int retry = CACHE_RETRY;
	struct voluta_unode_info *ui = NULL;

	while (retry-- > 0) {
		ui = cache_new_ui(cache, uba);
		if (ui != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return ui;
}

struct voluta_unode_info *
voluta_cache_spawn_ui(struct voluta_cache *cache,
                      const struct voluta_uba *uba)
{
	struct voluta_unode_info *ui;

	ui = cache_require_ui(cache, uba);
	if (ui != NULL) {
		cache_store_ui(cache, ui);
	}
	return ui;
}

void voulta_cache_forget_ui(struct voluta_cache *cache,
                            struct voluta_unode_info *ui)
{
	ui_undirtify(ui);
	cache_evict_ui(cache, ui);
}

static struct voluta_unode_info *cache_get_lru_ui(struct voluta_cache *cache)
{
	struct voluta_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_ulm);
	return (ce != NULL) ? ui_from_ce(ce) : NULL;
}

static bool cache_evict_or_relru_ui(struct voluta_cache *cache,
                                    struct voluta_unode_info *ui)
{
	bool evicted;
	struct voluta_cnode_info *ci = &ui->u_ci;

	if (ci->c_vtbl->evictable(ci)) {
		cache_evict_ui(cache, ui);
		evicted = true;
	} else {
		cache_promote_lru_ui(cache, ui);
		evicted = false;
	}
	return evicted;
}

static int try_evict_ui(struct voluta_cache_elem *ce, void *arg)
{
	struct voluta_cache *cache = arg;
	struct voluta_unode_info *ui = ui_from_ce(ce);

	cache_evict_or_relru_ui(cache, ui);
	return 0;
}

static void cache_drop_evictable_uis(struct voluta_cache *cache)
{
	lrumap_foreach_backward(&cache->c_ulm, try_evict_ui, cache);
}

static size_t cache_shrink_or_relru_uis(struct voluta_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct voluta_unode_info *ui;
	const size_t n = min(cnt, cache->c_ulm.lru.sz);

	for (size_t i = 0; i < n; ++i) {
		ui = cache_get_lru_ui(cache);
		if (ui == NULL) {
			break;
		}
		ok = cache_evict_or_relru_ui(cache, ui);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

void voluta_ui_attach_to(struct voluta_unode_info *ui,
                         struct voluta_bksec_info *bsi)
{
	struct voluta_cnode_info *ci = &ui->u_ci;

	ci_attach_bk(ci, bsi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cache_shrink_some(struct voluta_cache *cache, size_t factor)
{
	size_t count;
	size_t shrink;
	size_t actual = 0;

	count = lrumap_overpop(&cache->c_vlm) + 1;
	shrink = min(count * factor, VOLUTA_NKB_IN_BK);
	actual += cache_shrink_or_relru_vis(cache, shrink);

	count = lrumap_overpop(&cache->c_ulm) + 1;
	shrink = min(count * factor, VOLUTA_NKB_IN_BK);
	actual += cache_shrink_or_relru_uis(cache, shrink);

	count = lrumap_overpop(&cache->c_blm) + 1;
	shrink = min(count * factor, VOLUTA_MEGA / VOLUTA_BK_SIZE);
	actual += cache_shrink_or_relru_bks(cache, shrink);

	return (actual > 0);
}

static bool cache_has_overpop(const struct voluta_cache *cache)
{
	return lrumap_overpop(&cache->c_blm) ||
	       lrumap_overpop(&cache->c_vlm) ||
	       lrumap_overpop(&cache->c_ulm);
}

static uint64_t cache_memory_pressure(const struct voluta_cache *cache)
{
	uint64_t nbits;
	struct voluta_alloc_stat st;

	voluta_allocstat(cache->c_alif, &st);
	nbits = ((61UL * st.npages_used) / st.npages_tota);

	/* returns memory-pressure represented as bit-mask */
	return ((1UL << nbits) - 1);
}

static size_t cache_calc_niter(const struct voluta_cache *cache, int flags)
{
	size_t niter = 0;
	const uint64_t mem_press = cache_memory_pressure(cache);

	if (flags & VOLUTA_F_BRINGUP) {
		niter += voluta_popcount64(mem_press >> 3);
	}
	if (flags & VOLUTA_F_TIMEOUT) {
		niter += voluta_popcount64(mem_press >> 5);
	}
	if (flags & VOLUTA_F_OPSTART) {
		niter += voluta_popcount64(mem_press >> 11);
	}
	if ((flags & VOLUTA_F_SLUGGISH) && (mem_press & ~3UL)) {
		niter += 1;
	}
	if ((flags & VOLUTA_F_IDLE) && (mem_press & ~1UL)) {
		niter += 2;
	}
	if (cache_has_overpop(cache)) {
		niter += 2;
	}
	return niter;
}

void voluta_cache_relax(struct voluta_cache *cache, int flags)
{
	bool evicted = true;
	const size_t factor = 1;
	const size_t niter = cache_calc_niter(cache, flags);

	for (size_t i = 0; (i < niter) && evicted; ++i) {
		evicted = cache_shrink_some(cache, factor);
	}
}

void voluta_cache_shrink_once(struct voluta_cache *cache)
{
	const size_t bk_size = VOLUTA_BK_SIZE;
	const size_t memsz_bsis = bk_size * cache->c_blm.htbl_size;
	const size_t memsz_data = cache->c_qalloc->st.memsz_data;

	if ((8 * memsz_bsis) > memsz_data) {
		cache_shrink_some(cache, 1);
	}
}

static size_t cache_lrumap_usage_sum(const struct voluta_cache *cache)
{
	return lrumap_usage(&cache->c_blm) +
	       lrumap_usage(&cache->c_ulm) +
	       lrumap_usage(&cache->c_vlm);
}

static void cache_drop_evictables(struct voluta_cache *cache)
{
	cache_drop_evictable_vis(cache);
	cache_drop_evictable_uis(cache);
	cache_drop_evictable_bsis(cache);
}

void voluta_cache_drop(struct voluta_cache *cache)
{
	size_t usage_now;
	size_t usage_pre = 0;
	size_t iter_count = 0;

	usage_now = cache_lrumap_usage_sum(cache);
	while ((iter_count++ < 10) && (usage_now != usage_pre)) {
		usage_pre = usage_now;
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
	} else if (flags & (VOLUTA_F_SLUGGISH | VOLUTA_F_IDLE)) {
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
	const size_t threshold = flush_threshold_of(flags);

	voluta_unused(cache);
	return (dq->dq_accum_nbytes > threshold);
}

static bool cache_mem_press_need_flush(const struct voluta_cache *cache)
{
	const uint64_t mem_press = cache_memory_pressure(cache);

	return voluta_popcount64(mem_press) > 12;
}

bool voluta_cache_need_flush(const struct voluta_cache *cache, int flags)
{
	return cache_dq_need_flush(cache, &cache->c_dq, flags) ||
	       cache_mem_press_need_flush(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cache_evict_by_bsi(struct voluta_cache *cache,
                               struct voluta_bksec_info *bsi)
{
	bool ret = false;

	if ((bsi != NULL) && bsi_is_evictable(bsi)) {
		cache_evict_bsi(cache, bsi);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_vi(struct voluta_cache *cache,
                              struct voluta_vnode_info *vi)
{
	struct voluta_bksec_info *bsi = NULL;
	struct voluta_cnode_info *ci = vi_to_ci(vi);

	if ((ci != NULL) && (ci->c_vtbl->evictable(ci))) {
		bsi = ci->c_bsi;
		cache_evict_vi(cache, vi);
	}
	return cache_evict_by_bsi(cache, bsi);
}

static bool cache_evict_by_ui(struct voluta_cache *cache,
                              struct voluta_unode_info *ui)
{
	struct voluta_bksec_info *bsi = NULL;
	struct voluta_cnode_info *ci = NULL;

	if (ui == NULL) {
		return false;
	}
	ci = &ui->u_ci;
	if (ci->c_vtbl->evictable(ci)) {
		bsi = ci->c_bsi;
		cache_evict_ui(cache, ui);
	}
	return cache_evict_by_bsi(cache, bsi);
}

static void cache_evict_some(struct voluta_cache *cache)
{
	bool ok = false;
	struct voluta_vnode_info *vi;
	struct voluta_unode_info *ui;
	struct voluta_bksec_info *bsi;

	vi = cache_find_evictable_vi(cache);
	if (cache_evict_by_vi(cache, vi)) {
		ok = true;
	}
	ui = cache_find_evictable_ui(cache);
	if (cache_evict_by_ui(cache, ui)) {
		ok = true;
	}
	bsi = cache_find_evictable_bsi(cache);
	if (cache_evict_by_bsi(cache, bsi)) {
		ok = true;
	}
	if (!ok) {
		cache_shrink_some(cache, 1);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_nil_bk(struct voluta_cache *cache)
{
	struct voluta_block *nil_bk;

	nil_bk = voluta_allocate(cache->c_alif, sizeof(*nil_bk));
	if (nil_bk == NULL) {
		return -ENOMEM;
	}
	voluta_memzero(nil_bk, sizeof(*nil_bk));
	cache->c_nil_bk = nil_bk;
	return 0;
}

static void cache_fini_nil_bk(struct voluta_cache *cache)
{
	struct voluta_block *nil_bk = cache->c_nil_bk;

	if (nil_bk != NULL) {
		voluta_deallocate(cache->c_alif, nil_bk, sizeof(*nil_bk));
		cache->c_nil_bk = NULL;
	}
}

static size_t cache_htbl_size(const struct voluta_cache *cache, size_t div)
{
	const struct voluta_qalloc *qal = cache->c_qalloc;
	const size_t hwant = qal->st.memsz_data / div;
	const size_t limit = clamp(hwant, 1U << 14, 1U << 20);

	return htbl_prime_size(limit);
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
	err = cache_init_ulm(cache, hsize);
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

int voluta_cache_init(struct voluta_cache *cache,
                      struct voluta_qalloc *qalloc,
                      struct voluta_alloc_if *alif)
{
	int err;

	dq_init(&cache->c_dq);
	cache->c_qalloc = qalloc;
	cache->c_alif = alif;

	err = cache_init_nil_bk(cache);
	if (err) {
		return err;
	}
	err = cache_init_lrumaps(cache);
	if (err) {
		cache_fini_nil_bk(cache);
		return err;
	}
	return 0;
}

void voluta_cache_fini(struct voluta_cache *cache)
{
	dq_fini(&cache->c_dq);
	cache_fini_lrumaps(cache);
	cache_fini_nil_bk(cache);
	cache->c_qalloc = NULL;
	cache->c_alif = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_vi_dirtify(struct voluta_vnode_info *vi)
{
	cache_dirtify_vi(vi_cache(vi), vi);
}

void voluta_vi_undirtify(struct voluta_vnode_info *vi)
{
	cache_undirtify_vi(vi_cache(vi), vi);
}

void voluta_ii_dirtify(struct voluta_inode_info *ii)
{
	voluta_vi_dirtify(ii_to_vi(ii));
}

void voluta_ii_undirtify(struct voluta_inode_info *ii)
{
	voluta_vi_undirtify(ii_to_vi(ii));
}

size_t voluta_ii_refcnt(const struct voluta_inode_info *ii)
{
	return voluta_vi_refcnt(ii_to_vi(ii));
}

void voluta_ii_incref(struct voluta_inode_info *ii)
{
	voluta_vi_incref(ii_to_vi(ii));
}

void voluta_ii_decref(struct voluta_inode_info *ii)
{
	voluta_vi_decref(ii_to_vi(ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_cache_fill_into_dset(const struct voluta_cache *cache,
                                 struct voluta_dset *dset)
{
	struct voluta_cnode_info *ci = NULL;

	ci = cache_dq_front_ci(cache);
	while (ci != NULL) {
		dset->ds_add_fn(dset, ci);
		ci = cache_dq_next_ci(cache, ci);
	}
}

void voluta_cache_undirtify_by_dset(struct voluta_cache *cache,
                                    const struct voluta_dset *dset)
{
	struct voluta_cnode_info *next = NULL;
	struct voluta_cnode_info *ci = dset->ds_ciq;

	while (ci != NULL) {
		next = ci->c_ds_next;

		/* XXX CRAP */
		cache_undirtify_vi(cache, voluta_vi_from_ci(ci));

		ci->c_ds_next = NULL;
		ci = next;
	}
}
