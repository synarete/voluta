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
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#include "libvoluta.h"


#define MPAGE_SHIFT             VOLUTA_PAGE_SHIFT
#define MPAGE_SIZE              VOLUTA_PAGE_SIZE
#define MPAGE_SIZE_MAX          VOLUTA_PAGE_SIZE_MAX
#define MPAGE_NSEGS             (MPAGE_SIZE / MSLAB_SEG_SIZE)
#define MPAGES_IN_HOLE          (2 * (MPAGE_SIZE_MAX / MPAGE_SIZE))
#define MSLAB_SHIFT_MIN         (4)
#define MSLAB_SHIFT_MAX         (MPAGE_SHIFT - 1)
#define MSLAB_SIZE_MIN          (1U << MSLAB_SHIFT_MIN)
#define MSLAB_SIZE_MAX          (1U << MSLAB_SHIFT_MAX)
#define MSLAB_SEG_SIZE          MSLAB_SIZE_MIN
#define MSLAB_INDEX_NONE        (-1)
#define MALLOC_SIZE_MAX         (64 * VOLUTA_UMEGA)
#define CACHELINE_SIZE_MIN      VOLUTA_CACHELINE_SIZE
#define QALLOC_NSLABS           (MPAGE_SHIFT - MSLAB_SHIFT_MIN)

#define STATICASSERT_SIZEOF_GE(t_, s_) \
	VOLUTA_STATICASSERT_GE(sizeof(t_), s_)

#define STATICASSERT_SIZEOF_LE(t_, s_) \
	VOLUTA_STATICASSERT_LE(sizeof(t_), s_)

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* TODO: Use AVL instead of linked-list for free-chunks? */

struct voluta_slab_seg {
	struct voluta_list_head link;
} voluta_aligned;


union voluta_page {
	struct voluta_slab_seg seg[MPAGE_NSEGS];
	uint8_t data[MPAGE_SIZE];
} voluta_packed_aligned64;


struct voluta_page_info {
	struct voluta_page_info *prev;
	union voluta_page *pg;
	struct voluta_list_head link;
	size_t pg_index;
	size_t pg_count; /* num pages free/used */
	int pg_free;
	int slab_index;
	int slab_nused;
	int slab_nelems;
} voluta_aligned64;


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void static_assert_alloc_sizes(void)
{
	const struct voluta_qalloc *qal = NULL;

	STATICASSERT_SIZEOF(struct voluta_slab_seg, 16);
	STATICASSERT_SIZEOF(struct voluta_slab_seg, MSLAB_SEG_SIZE);
	STATICASSERT_SIZEOF(union voluta_page, MPAGE_SIZE);
	STATICASSERT_SIZEOF(struct voluta_page_info, 64);
	STATICASSERT_SIZEOF_LE(struct voluta_slab_seg, CACHELINE_SIZE_MIN);
	STATICASSERT_SIZEOF_GE(struct voluta_page_info, CACHELINE_SIZE_MIN);
	STATICASSERT_EQ(ARRAY_SIZE(qal->slabs), QALLOC_NSLABS);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_page_info *
link_to_page_info(const struct voluta_list_head *link)
{
	const struct voluta_page_info *pgi =
		container_of2(link, struct voluta_page_info, link);

	return unconst(pgi);
}

static void page_info_update(struct voluta_page_info *pgi,
			     struct voluta_page_info *prev, size_t count)
{
	pgi->prev = prev;
	pgi->pg_count = count;
	pgi->pg_free = 1;
}

static void page_info_mute(struct voluta_page_info *pgi)
{
	page_info_update(pgi, NULL, 0);
}

static void page_info_init(struct voluta_page_info *pgi,
			   union voluta_page *pg, size_t pg_index)
{
	list_head_init(&pgi->link);
	page_info_mute(pgi);
	pgi->pg = pg;
	pgi->pg_index = pg_index;
	pgi->slab_nused = 0;
	pgi->slab_index = MSLAB_INDEX_NONE;
}

static void page_info_push_head(struct voluta_page_info *pgi,
				struct voluta_list_head *ls)
{
	list_push_front(ls, &pgi->link);
}

static void page_info_push_tail(struct voluta_page_info *pgi,
				struct voluta_list_head *ls)
{
	list_push_back(ls, &pgi->link);
}

static void page_info_unlink(struct voluta_page_info *pgi)
{
	list_head_remove(&pgi->link);
}

static void page_info_unlink_mute(struct voluta_page_info *pgi)
{
	page_info_unlink(pgi);
	page_info_mute(pgi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_slab_seg *
link_to_slab_seg(const struct voluta_list_head *link)
{
	const struct voluta_slab_seg *seg =
		container_of2(link, struct voluta_slab_seg, link);

	return unconst(seg);
}

static struct voluta_list_head *slab_seg_to_link(struct voluta_slab_seg *seg)
{
	return &seg->link;
}

static bool slab_issize(size_t size)
{
	return ((size > 0) && (size <= MSLAB_SIZE_MAX));
}

static size_t slab_size_to_nlz(size_t size)
{
	const size_t shift = MSLAB_SHIFT_MIN;

	return voluta_clz(((unsigned int)size - 1) >> shift);
}

static int slab_size_to_index(size_t size, size_t *out_index)
{
	size_t idx;
	size_t nlz;

	if (!slab_issize(size)) {
		return -EINVAL;
	}
	nlz = slab_size_to_nlz(size);
	if (!nlz || (nlz > 32)) {
		return -EINVAL;
	}
	idx = 32 - nlz;
	if (idx >= QALLOC_NSLABS) {
		return -EINVAL;
	}
	*out_index = idx;
	return 0;
}

static void slab_init(struct voluta_slab *slab, size_t sindex, size_t elemsz)
{
	int err;
	size_t index_by_elemsz = 0;

	err = slab_size_to_index(elemsz, &index_by_elemsz);
	if (err || (sindex != index_by_elemsz)) {
		voluta_panic("slab: index=%lu elemsz=%lu", sindex, elemsz);
	}
	list_init(&slab->free_list);
	slab->elemsz = elemsz;
	slab->nfree = 0;
	slab->nused = 0;
	slab->sindex = sindex;
}

static void slab_fini(struct voluta_slab *slab)
{
	list_init(&slab->free_list);
	slab->elemsz = 0;
	slab->nfree = 0;
	slab->nused = 0;
	slab->sindex = UINT_MAX;
}

static void slab_expand(struct voluta_slab *slab, struct voluta_page_info *pgi)
{
	struct voluta_slab_seg *seg;
	union voluta_page *pg = pgi->pg;
	const size_t step = slab->elemsz / sizeof(*seg);

	pgi->slab_index = (int)slab->sindex;
	pgi->slab_nelems = (int)(sizeof(*pg) / slab->elemsz);
	pgi->slab_nused = 0;
	for (size_t i = 0; i < ARRAY_SIZE(pg->seg); i += step) {
		seg = &pg->seg[i];
		list_push_back(&slab->free_list, &seg->link);
		slab->nfree++;
	}
}

static void slab_shrink(struct voluta_slab *slab, struct voluta_page_info *pgi)
{
	struct voluta_slab_seg *seg;
	union voluta_page *pg = pgi->pg;
	const size_t step = slab->elemsz / sizeof(*seg);

	voluta_assert_eq(pgi->slab_index, slab->sindex);
	voluta_assert_eq(pgi->slab_nused, 0);

	for (size_t i = 0; i < ARRAY_SIZE(pg->seg); i += step) {
		voluta_assert_gt(slab->nfree, 0);

		seg = &pg->seg[i];
		list_head_remove(&seg->link);
		slab->nfree--;
	}
	pgi->slab_index = -1;
	pgi->slab_nelems = 0;
}

static struct voluta_slab_seg *slab_alloc(struct voluta_slab *slab)
{
	struct voluta_list_head *lh;
	struct voluta_slab_seg *seg = NULL;

	lh = list_pop_front(&slab->free_list);
	if (lh == NULL) {
		return NULL;
	}
	list_head_init(lh);

	voluta_assert_gt(slab->nfree, 0);
	slab->nfree--;
	slab->nused++;

	seg = link_to_slab_seg(lh);
	return seg;
}

static void slab_free(struct voluta_slab *slab, struct voluta_slab_seg *seg)
{
	struct voluta_list_head *lh;

	lh = slab_seg_to_link(seg);
	list_push_front(&slab->free_list, lh);
	voluta_assert_gt(slab->nused, 0);
	slab->nused--;
	slab->nfree++;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int resolve_mem_sizes(size_t npgs, size_t *msz_data, size_t *msz_meta)
{
	const size_t npgs_max = UINT_MAX; /* TODO: proper upper limit */

	if ((npgs == 0) || (npgs > npgs_max)) {
		return -EINVAL;
	}
	*msz_data = npgs * sizeof(union voluta_page);
	*msz_meta = npgs * sizeof(struct voluta_page_info);
	return 0;
}

static int memfd_setup(const char *name, size_t size,
		       int *out_fd, void **out_mem)
{
	int err;
	int fd = -1;
	void *mem = NULL;
	const int prot = PROT_READ | PROT_WRITE;
	const int flags = MAP_SHARED;

	err = voluta_sys_memfd_create(name, 0, &fd);
	if (err) {
		return err;
	}
	err = voluta_sys_ftruncate(fd, (loff_t)size);
	if (err) {
		voluta_sys_close(fd);
		return err;
	}
	err = voluta_sys_mmap(NULL, size, prot, flags, fd, 0, &mem);
	if (err) {
		voluta_sys_close(fd);
		return err;
	}
	*out_fd = fd;
	*out_mem = mem;
	return 0;
}

static int memfd_close(int fd, void *mem, size_t memsz)
{
	int err;

	err = voluta_sys_munmap(mem, memsz);
	if (err) {
		return err;
	}
	err = voluta_sys_close(fd);
	if (err) {
		return err;
	}
	return 0;
}

static int qalloc_init_memfd(struct voluta_qalloc *qal, size_t npgs)
{
	int err;
	char name[256] = "";

	err = resolve_mem_sizes(npgs, &qal->st.memsz_data,
				&qal->st.memsz_meta);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "voluta-mem-data%d", qal->memfd_indx);
	err = memfd_setup(name, qal->st.memsz_data,
			  &qal->memfd_data, &qal->mem_data);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "voluta-mem-meta%d", qal->memfd_indx);
	err = memfd_setup(name, qal->st.memsz_meta,
			  &qal->memfd_meta, &qal->mem_meta);
	if (err) {
		memfd_close(qal->memfd_data,
			    qal->mem_data, qal->st.memsz_data);
		return err;
	}
	qal->st.nbytes_used = 0;
	qal->st.npages = npgs;
	return 0;
}

static int qalloc_fini_memfd(struct voluta_qalloc *qal)
{
	int err;

	if (!qal->st.npages) {
		return 0;
	}
	err = memfd_close(qal->memfd_data, qal->mem_data,
			  qal->st.memsz_data);
	if (err) {
		return err;
	}
	err = memfd_close(qal->memfd_meta, qal->mem_meta,
			  qal->st.memsz_meta);
	if (err) {
		return err;
	}
	qal->memfd_data = -1;
	qal->memfd_meta = -1;
	qal->mem_data = NULL;
	qal->mem_meta = NULL;
	qal->st.memsz_data = 0;
	qal->st.memsz_meta = 0;
	return 0;
}

static void qalloc_init_slabs(struct voluta_qalloc *qal)
{
	size_t elemsz;
	struct voluta_slab *slab;
	const size_t shift_base = MSLAB_SHIFT_MIN;

	for (size_t i = 0; i < ARRAY_SIZE(qal->slabs); ++i) {
		elemsz = 1U << (shift_base + i);
		slab = &qal->slabs[i];
		slab_init(slab, i, elemsz);
	}
}

static void qalloc_fini_slabs(struct voluta_qalloc *qal)
{
	for (size_t i = 0; i < ARRAY_SIZE(qal->slabs); ++i) {
		slab_fini(&qal->slabs[i]);
	}
}

static void *qalloc_page_at(const struct voluta_qalloc *qal, size_t idx)
{
	union voluta_page *pg_arr = qal->mem_data;

	voluta_assert_lt(idx, qal->st.npages);

	return pg_arr + idx;
}

static struct voluta_page_info *
qalloc_page_info_at(const struct voluta_qalloc *qal, size_t idx)
{
	struct voluta_page_info *pgi_arr = qal->mem_meta;

	voluta_assert_lt(idx, qal->st.npages);

	return pgi_arr + idx;
}

static struct voluta_page_info *
qalloc_next(const struct voluta_qalloc *qal,
	    const struct voluta_page_info *pgi, size_t npgs)
{
	const size_t idx_next = pgi->pg_index + npgs;
	struct voluta_page_info *pgi_next = NULL;

	if (idx_next < qal->st.npages) {
		pgi_next = qalloc_page_info_at(qal, idx_next);
	}
	return pgi_next;
}

static void qalloc_update(const struct voluta_qalloc *qal,
			  struct voluta_page_info *pgi, size_t npgs)
{
	struct voluta_page_info *pgi_next;

	pgi_next = qalloc_next(qal, pgi, npgs);
	if (pgi_next != NULL) {
		pgi_next->prev = pgi;
	}
}

static void qalloc_add_free(struct voluta_qalloc *qal,
			    struct voluta_page_info *pgi,
			    struct voluta_page_info *prev, size_t npgs)
{
	const size_t threshold = MPAGES_IN_HOLE;
	struct voluta_list_head *free_list = &qal->free_list;

	page_info_update(pgi, prev, npgs);
	qalloc_update(qal, pgi, npgs);
	if (npgs >= threshold) {
		page_info_push_head(pgi, free_list);
	} else {
		page_info_push_tail(pgi, free_list);
	}
}

static void qalloc_init_pages(struct voluta_qalloc *qal)
{
	union voluta_page *pg;
	struct voluta_page_info *pgi;

	for (size_t i = 0; i < qal->st.npages; ++i) {
		pg = qalloc_page_at(qal, i);
		pgi = qalloc_page_info_at(qal, i);
		page_info_init(pgi, pg, i);
	}

	list_init(&qal->free_list);
	pgi = qalloc_page_info_at(qal, 0);
	qalloc_add_free(qal, pgi, NULL, qal->st.npages);
}

static int check_memsize(size_t memsize)
{
	static_assert_alloc_sizes();

	if (memsize < (8 * VOLUTA_UMEGA)) {
		return -EINVAL;
	}
	if (memsize > (64 * VOLUTA_UGIGA)) {
		return -EINVAL;
	}
	return 0;
}

int voluta_qalloc_init(struct voluta_qalloc *qal, size_t memsize)
{
	int err;
	size_t npgs;
	static int g_memfd_indx;

	err = check_memsize(memsize);
	if (err) {
		return err;
	}
	qal->st.npages_used = 0;
	qal->st.nbytes_used = 0;
	qal->mode = false;
	qal->memfd_indx = ++g_memfd_indx;

	npgs = memsize / MPAGE_SIZE;
	err = qalloc_init_memfd(qal, npgs);
	if (err) {
		return err;
	}
	qalloc_init_pages(qal);
	qalloc_init_slabs(qal);
	return 0;
}

int voluta_qalloc_init2(struct voluta_qalloc *qal, size_t memwant)
{
	int err;
	size_t memsize = 0;

	err = voluta_resolve_memsize(memwant, &memsize);
	if (!err) {
		err = voluta_qalloc_init(qal, memsize);
	}
	return err;
}


int voluta_qalloc_fini(struct voluta_qalloc *qal)
{
	/* TODO: release all pending memory-elements in slabs */
	qalloc_fini_slabs(qal);
	return qalloc_fini_memfd(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nbytes_to_npgs(size_t nbytes)
{
	return (nbytes + MPAGE_SIZE - 1) / MPAGE_SIZE;
}

static size_t npgs_to_nbytes(size_t npgs)
{
	return npgs * MPAGE_SIZE;
}

static loff_t qalloc_ptr_to_off(const struct voluta_qalloc *qal,
				const void *ptr)
{
	return (const char *)ptr - (const char *)qal->mem_data;
}

static size_t qalloc_ptr_to_pgn(const struct voluta_qalloc *qal,
				const void *ptr)
{
	const loff_t off = qalloc_ptr_to_off(qal, ptr);

	return (size_t)off / MPAGE_SIZE;
}

static bool qalloc_isinrange(const struct voluta_qalloc *qal,
			     const void *ptr, size_t nb)
{
	const loff_t off = qalloc_ptr_to_off(qal, ptr);
	const loff_t end = off + (loff_t)nb;

	return (off >= 0) && (end <= (loff_t)qal->st.memsz_data);
}

static struct voluta_page_info *
qalloc_page_info_of(const struct voluta_qalloc *qal, const void *ptr)
{
	const size_t pgn = qalloc_ptr_to_pgn(qal, ptr);

	voluta_assert_lt(pgn, qal->st.npages);
	return qalloc_page_info_at(qal, pgn);
}

static struct voluta_slab_seg *
qalloc_slab_seg_of(const struct voluta_qalloc *qal, const void *ptr)
{
	loff_t off;
	size_t idx;
	struct voluta_slab_seg *seg = qal->mem_data;

	off = qalloc_ptr_to_off(qal, ptr);
	idx = (size_t)off / sizeof(*seg);

	return &seg[idx];
}

static struct voluta_page_info *
qalloc_search_free_from_tail(struct voluta_qalloc *qal, size_t npgs)
{
	struct voluta_page_info *pgi;
	struct voluta_list_head *itr;
	struct voluta_list_head *free_list = &qal->free_list;

	itr = free_list->prev;
	while (itr != free_list) {
		pgi = link_to_page_info(itr);
		if (pgi->pg_count >= npgs) {
			return pgi;
		}
		itr = itr->prev;
	}
	return NULL;
}

static struct voluta_page_info *
qalloc_search_free_from_head(struct voluta_qalloc *qal, size_t npgs)
{
	struct voluta_page_info *pgi;
	struct voluta_list_head *itr;
	struct voluta_list_head *free_list = &qal->free_list;

	itr = free_list->next;
	while (itr != free_list) {
		pgi = link_to_page_info(itr);
		if (pgi->pg_count >= npgs) {
			return pgi;
		}
		itr = itr->next;
	}
	return NULL;
}

static struct voluta_page_info *
qalloc_search_free_list(struct voluta_qalloc *qal, size_t npgs)
{
	struct voluta_page_info *pgi = NULL;
	const size_t threshold = MPAGES_IN_HOLE;

	if ((qal->st.npages_used + npgs) <= qal->st.npages) {
		if (npgs >= threshold) {
			pgi = qalloc_search_free_from_head(qal, npgs);
		} else {
			pgi = qalloc_search_free_from_tail(qal, npgs);
		}
	}
	return pgi;
}

static struct voluta_page_info *
qalloc_alloc_npgs(struct voluta_qalloc *qal, size_t npgs)
{
	struct voluta_page_info *pgi;
	struct voluta_page_info *pgi_next = NULL;

	pgi = qalloc_search_free_list(qal, npgs);
	if (pgi == NULL) {
		return NULL;
	}
	voluta_assert_eq(pgi->slab_index, MSLAB_INDEX_NONE);
	voluta_assert_ge(pgi->pg_count, npgs);

	page_info_unlink(pgi);
	pgi->pg_free = 0;
	if (pgi->pg_count == npgs) {
		return pgi;
	}
	pgi_next = qalloc_next(qal, pgi, npgs);
	voluta_assert_not_null(pgi_next);
	voluta_assert_eq(pgi_next->slab_index, MSLAB_INDEX_NONE);
	voluta_assert_eq(pgi_next->pg_count, 0);
	voluta_assert_eq(pgi_next->pg_free, 1);
	qalloc_add_free(qal, pgi_next, pgi, pgi->pg_count - npgs);

	pgi->pg_count = npgs;
	return pgi;
}

static struct voluta_slab *
qalloc_slab_of(const struct voluta_qalloc *qal, size_t nbytes)
{
	int err;
	size_t sindex;
	const struct voluta_slab *slab = NULL;

	err = slab_size_to_index(nbytes, &sindex);
	if (!err && (sindex < ARRAY_SIZE(qal->slabs))) {
		slab = &qal->slabs[sindex];
	}
	return unconst(slab);
}

static int qalloc_require_slab_space(struct voluta_qalloc *qal,
				     struct voluta_slab *slab)
{
	struct voluta_page_info *pgi;

	if (slab->nfree > 0) {
		return 0;
	}
	pgi = qalloc_alloc_npgs(qal, 1);
	if (pgi == NULL) {
		return -ENOMEM;
	}
	slab_expand(slab, pgi);
	return 0;
}

static struct voluta_slab_seg *
qalloc_alloc_from_slab(struct voluta_qalloc *qal, struct voluta_slab *slab)
{
	struct voluta_slab_seg *seg;
	struct voluta_page_info *pgi;

	seg = slab_alloc(slab);
	if (seg == NULL) {
		return NULL;
	}
	pgi = qalloc_page_info_of(qal, seg);

	voluta_assert_lt(pgi->slab_nused, pgi->slab_nelems);
	pgi->slab_nused += 1;

	return seg;
}

static int qalloc_alloc_slab(struct voluta_qalloc *qal, size_t nbytes,
			     struct voluta_slab_seg **out_seg)
{
	int err;
	struct voluta_slab *slab;
	struct voluta_slab_seg *seg;

	slab = qalloc_slab_of(qal, nbytes);
	if (slab == NULL) {
		return -ENOMEM;
	}
	err = qalloc_require_slab_space(qal, slab);
	if (err) {
		return err;
	}
	seg = qalloc_alloc_from_slab(qal, slab);
	if (seg == NULL) {
		return -ENOMEM;
	}
	*out_seg = seg;
	return 0;
}

static int qalloc_check_alloc(const struct voluta_qalloc *qal, size_t nbytes)
{
	const size_t nbytes_max = MALLOC_SIZE_MAX;

	if (qal->mem_data == NULL) {
		return -ENOMEM;
	}
	if (nbytes > nbytes_max) {
		return -ENOMEM;
	}
	if (!nbytes) {
		return -EINVAL;
	}
	return 0;
}

static int qalloc_alloc_sub_pg(struct voluta_qalloc *qal,
			       size_t nbytes, void **out_ptr)
{
	int err;
	struct voluta_slab_seg *seg;

	err = qalloc_alloc_slab(qal, nbytes, &seg);
	if (err) {
		return err;
	}
	*out_ptr = seg;
	return 0;
}

static int qalloc_alloc_multi_pg(struct voluta_qalloc *qal,
				 size_t nbytes, void **out_ptr)
{
	size_t npgs;
	struct voluta_page_info *pgi;

	npgs = nbytes_to_npgs(nbytes);
	pgi = qalloc_alloc_npgs(qal, npgs);
	if (pgi == NULL) {
		return -ENOMEM;
	}
	*out_ptr = pgi->pg->data;
	qal->st.npages_used += npgs;
	voluta_assert_ge(qal->st.npages, qal->st.npages_used);
	return 0;
}

static int qalloc_malloc(struct voluta_qalloc *qal,
			 size_t nbytes, void **out_ptr)
{
	int err;

	err = qalloc_check_alloc(qal, nbytes);
	if (err) {
		return err;
	}
	if (slab_issize(nbytes)) {
		err = qalloc_alloc_sub_pg(qal, nbytes, out_ptr);
	} else {
		err = qalloc_alloc_multi_pg(qal, nbytes, out_ptr);
	}
	if (err) {
		return err;
	}
	qal->st.nbytes_used += nbytes;
	return 0;
}

void *voluta_qalloc_malloc(struct voluta_qalloc *qal, size_t nbytes)
{
	int err;
	void *ptr = NULL;

	err = qalloc_malloc(qal, nbytes, &ptr);
	if (err) {
		log_dbg("malloc failed: nbytes=%lu err=%d", nbytes, err);
	}
	return ptr;
}

void *voluta_qalloc_zmalloc(struct voluta_qalloc *qal, size_t nbytes)
{
	void *ptr;

	ptr = voluta_qalloc_malloc(qal, nbytes);
	if (ptr != NULL) {
		voluta_memzero(ptr, nbytes);
	}
	return ptr;
}

static int qalloc_check_free(const struct voluta_qalloc *qal,
			     const void *ptr, size_t nbytes)
{
	if ((qal->mem_data == NULL) || (ptr == NULL)) {
		return -EINVAL;
	}
	if (!nbytes || (nbytes > MALLOC_SIZE_MAX)) {
		return -EINVAL;
	}
	if (!qalloc_isinrange(qal, ptr, nbytes)) {
		return -EINVAL;
	}
	return 0;
}

static void
qalloc_punch_hole_at(const struct voluta_qalloc *qal,
		     const struct voluta_page_info *pgi, size_t npgs)
{
	int err;
	size_t off;
	size_t len;
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	off = npgs_to_nbytes(pgi->pg_index);
	len = npgs_to_nbytes(npgs);
	err = voluta_sys_fallocate(qal->memfd_data, mode,
				   (loff_t)off, (loff_t)len);
	voluta_assert_ok(err);
}

static void
qalloc_release_npgs(const struct voluta_qalloc *qal,
		    const struct voluta_page_info *pgi, size_t npgs)
{
	const size_t threshold = MPAGES_IN_HOLE;

	if (npgs >= threshold) {
		qalloc_punch_hole_at(qal, pgi, npgs);
	}
}

static int qalloc_free_npgs(struct voluta_qalloc *qal,
			    struct voluta_page_info *pgi, size_t npgs)
{
	struct voluta_page_info *pgi_next;
	struct voluta_page_info *pgi_prev;

	pgi_next = qalloc_next(qal, pgi, npgs);
	if (pgi_next && pgi_next->pg_free) {
		voluta_assert_gt(pgi_next->pg_count, 0);
		npgs += pgi_next->pg_count;
		page_info_unlink_mute(pgi_next);
	}
	pgi_prev = pgi->prev;
	if (pgi_prev && pgi_prev->pg_free) {
		voluta_assert_gt(pgi_prev->pg_count, 0);
		npgs += pgi_prev->pg_count;
		page_info_mute(pgi);
		pgi = pgi_prev;
		pgi_prev = pgi_prev->prev;
		page_info_unlink_mute(pgi);
	}

	qalloc_release_npgs(qal, pgi, npgs);
	qalloc_add_free(qal, pgi, pgi_prev, npgs);
	return 0;
}

static void qalloc_free_to_slab(struct voluta_qalloc *qal,
				struct voluta_slab *slab,
				struct voluta_slab_seg *seg)
{
	struct voluta_page_info *pgi = qalloc_page_info_of(qal, seg);

	voluta_assert_eq(pgi->slab_index, slab->sindex);
	slab_free(slab, seg);

	voluta_assert_le(pgi->slab_nused, pgi->slab_nelems);
	voluta_assert_gt(pgi->slab_nused, 0);
	pgi->slab_nused -= 1;
	if (!pgi->slab_nused) {
		slab_shrink(slab, pgi);
		qalloc_free_npgs(qal, pgi, 1);
	}
}

static int qalloc_check_at_slab(const struct voluta_qalloc *qal,
				const struct voluta_slab_seg *seg, size_t nb)
{
	const struct voluta_slab *slab;
	const struct voluta_page_info *pgi;

	slab = qalloc_slab_of(qal, nb);
	if (slab == NULL) {
		return -EINVAL;
	}
	if (!slab->nused) {
		return -EINVAL;
	}
	if (nb > slab->elemsz) {
		return -EINVAL;
	}
	if (slab->sindex && (nb <= (slab->elemsz / 2))) {
		return -EINVAL;
	}
	pgi = qalloc_page_info_of(qal, seg);
	if (pgi->slab_index != ((int)slab->sindex)) {
		return -EINVAL;
	}
	if (pgi->slab_nused == 0) {
		return -EINVAL;
	}
	return 0;
}

static int qalloc_free_slab(struct voluta_qalloc *qal,
			    struct voluta_slab_seg *seg, size_t nbytes)
{
	int err;
	struct voluta_slab *slab;

	slab = qalloc_slab_of(qal, nbytes);
	if (slab == NULL) {
		return -EINVAL;
	}
	err = qalloc_check_at_slab(qal, seg, nbytes);
	if (err) {
		return err;
	}
	qalloc_free_to_slab(qal, slab, seg);
	return 0;
}

static int qalloc_free_sub_pg(struct voluta_qalloc *qal,
			      void *ptr, size_t nbytes)
{
	struct voluta_slab_seg *seg;

	seg = qalloc_slab_seg_of(qal, ptr);
	return qalloc_free_slab(qal, seg, nbytes);
}

static int qalloc_check_by_page(const struct voluta_qalloc *qal,
				const void *ptr, size_t nbytes)
{
	size_t npgs;
	const struct voluta_page_info *pgi;

	npgs = nbytes_to_npgs(nbytes);
	if (qal->st.npages_used < npgs) {
		return -EINVAL;
	}
	pgi = qalloc_page_info_of(qal, ptr);
	if (pgi == NULL) {
		return -EINVAL;
	}
	if (pgi->pg_count != npgs) {
		return -EINVAL;
	}
	return 0;
}

static int qalloc_free_multi_pg(struct voluta_qalloc *qal,
				void *ptr, size_t nbytes)
{
	int err;
	size_t npgs;
	struct voluta_page_info *pgi;

	err = qalloc_check_by_page(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	npgs = nbytes_to_npgs(nbytes);
	pgi = qalloc_page_info_of(qal, ptr);
	qalloc_free_npgs(qal, pgi, npgs);
	qal->st.npages_used -= npgs;
	return 0;
}

static void *
qalloc_base_of(const struct voluta_qalloc *qal, void *ptr, size_t len)
{
	void *base = NULL;
	struct voluta_slab_seg *seg;
	struct voluta_page_info *pgi;

	if (!qalloc_isinrange(qal, ptr, len)) {
		return NULL;
	}
	if (slab_issize(len)) {
		seg = qalloc_slab_seg_of(qal, ptr);
		if (seg != NULL) {
			base = seg;
		}
	} else {
		pgi = qalloc_page_info_of(qal, ptr);
		if (pgi != NULL) {
			base = pgi->pg;
		}
	}
	return base;
}

static void
qalloc_wreck_data(const struct voluta_qalloc *qal, void *ptr, size_t nbytes)
{
	voluta_assert_ge(qal->st.nbytes_used, nbytes);

	if (qal->mode && ptr) {
		memset(ptr, 0xF3, voluta_min(512, nbytes));
	}
}

static int qalloc_free(struct voluta_qalloc *qal, void *ptr, size_t nbytes)
{
	int err;

	if ((ptr == NULL) || (nbytes == 0)) {
		return 0;
	}
	err = qalloc_check_free(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	qalloc_wreck_data(qal, ptr, nbytes);
	if (slab_issize(nbytes)) {
		err = qalloc_free_sub_pg(qal, ptr, nbytes);
	} else {
		err = qalloc_free_multi_pg(qal, ptr, nbytes);
	}
	if (err) {
		return err;
	}
	qal->st.nbytes_used -= nbytes;
	return err;
}

void voluta_qalloc_free(struct voluta_qalloc *qal, void *ptr, size_t nbytes)
{
	int err;

	err = qalloc_free(qal, ptr, nbytes);
	if (err) {
		voluta_panic("free error: ptr=%p nbytes=%lu err=%d",
			     ptr, nbytes, err);
	}
}

void voluta_qalloc_zfree(struct voluta_qalloc *qal, void *ptr, size_t nbytes)
{
	if (ptr != NULL) {
		voluta_memzero(ptr, nbytes);
		voluta_qalloc_free(qal, ptr, nbytes);
	}
}

static int qalloc_check_by_slab(const struct voluta_qalloc *qal,
				const void *ptr, size_t nbytes)
{
	int err = -EINVAL;
	const struct voluta_slab_seg *seg;

	seg = qalloc_slab_seg_of(qal, ptr);
	if (seg != NULL) {
		err = qalloc_check_at_slab(qal, seg, nbytes);
	}
	return err;
}

int voluta_qalloc_mcheck(const struct voluta_qalloc *qal,
			 const void *ptr, size_t nbytes)
{
	int err;

	if ((ptr == NULL) || (nbytes == 0)) {
		return 0;
	}
	err = qalloc_check_free(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	if (slab_issize(nbytes)) {
		err = qalloc_check_by_slab(qal, ptr, nbytes);
	} else {
		err = qalloc_check_by_page(qal, ptr, nbytes);
	}
	return err;
}

int voluta_qalloc_xiovec(const struct voluta_qalloc *qal,
			 void *ptr, size_t len, struct voluta_xiovec *xiov)
{
	const void *base;

	base = qalloc_base_of(qal, ptr, len);
	if ((base == NULL) || (base > ptr)) {
		return -ERANGE;
	}
	xiov->off = qalloc_ptr_to_off(qal, ptr);
	xiov->len = len;
	xiov->base = ptr;
	xiov->fd = qal->memfd_data;
	xiov->cookie = NULL;
	return 0;
}

void voluta_qalloc_stat(const struct voluta_qalloc *qal,
			struct voluta_qastat *qast)
{
	memcpy(qast, &qal->st, sizeof(*qast));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t align_down(size_t sz, size_t align)
{
	return (sz / align) * align;
}

static int getmemlimit(size_t *out_lim)
{
	int err;
	struct rlimit rlim = {
		.rlim_cur = 0
	};

	err = voluta_sys_getrlimit(RLIMIT_AS, &rlim);
	if (!err) {
		*out_lim = rlim.rlim_cur;
	}
	return err;
}

int voluta_resolve_memsize(size_t mem_want, size_t *out_mem_size)
{
	int err;
	size_t mem_floor;
	size_t mem_ceil;
	size_t mem_rlim;
	size_t mem_glim;
	size_t page_size;
	size_t phys_pages;
	size_t mem_total;
	size_t mem_uget;

	page_size = voluta_sc_page_size();
	phys_pages = voluta_sc_phys_pages();
	mem_total = (page_size * phys_pages);
	mem_floor = VOLUTA_UGIGA / 8;
	if (mem_total < mem_floor) {
		return -ENOMEM;
	}
	err = getmemlimit(&mem_rlim);
	if (err) {
		return err;
	}
	if (mem_rlim < mem_floor) {
		return -ENOMEM;
	}
	mem_glim = 64 * VOLUTA_UGIGA;
	mem_ceil = min3(mem_glim, mem_rlim, mem_total / 4);

	if (mem_want == 0) {
		mem_want = 2 * VOLUTA_GIGA;
	}
	mem_uget = clamp(mem_want, mem_floor, mem_ceil);

	*out_mem_size = align_down(mem_uget, VOLUTA_UMEGA);
	return 0;
}

