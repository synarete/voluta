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
#include "unitest.h"

#define MAGIC   0xDEADBEEF

struct ut_mrecord {
	long    magic;
	struct voluta_qalloc *qal;
	struct voluta_list_head link;
	void  *mem;
	size_t len;
	size_t dat_len;
	char   dat[8];
};


static void mrecord_setup(struct ut_mrecord *mr, void *mem, size_t len)
{
	STATICASSERT_SIZEOF(*mr, 64);

	ut_expect_ge(len, sizeof(*mr));
	voluta_list_head_init(&mr->link);
	mr->magic = MAGIC;
	mr->mem = mem;
	mr->len = len;
	mr->dat_len = len - offsetof(struct ut_mrecord, dat);
}

static struct ut_mrecord *mrecord_of(void *mem, size_t len)
{
	struct ut_mrecord *mr = mem;

	mrecord_setup(mr, mem, len);
	return mr;
}

static void mrecord_check(const struct ut_mrecord *mr)
{
	ut_expect_eq(mr->magic, MAGIC);
	ut_expect_ge(mr->len, sizeof(*mr));
	ut_expect_not_null(mr->mem);
}

static struct ut_mrecord *
link_to_mrecord(const struct voluta_list_head *link)
{
	const struct ut_mrecord *mr =
	        ut_container_of2(link, struct ut_mrecord, link);

	mrecord_check(mr);
	return voluta_unconst(mr);
}

static struct ut_mrecord *
mrecord_new(struct voluta_qalloc *qal, size_t msz)
{
	int err;
	void *mem;
	struct ut_mrecord *mr;
	struct voluta_fiovec fiov = {
		.fv_base = NULL,
		.fv_fd = -1
	};

	mem = voluta_qalloc_malloc(qal, msz);
	ut_expect_not_null(mem);

	err = voluta_qalloc_mcheck(qal, mem, msz);
	ut_expect_ok(err);

	err = voluta_qalloc_fiovec(qal, mem, msz, &fiov);
	ut_expect_ok(err);
	ut_expect_eq(mem, fiov.fv_base);

	mr = mrecord_of(mem, msz);
	mr->qal = qal;

	return mr;
}

static void mrecord_del(struct ut_mrecord *mr)
{
	int err;
	struct voluta_qalloc *qal = mr->qal;

	mrecord_check(mr);
	err = voluta_qalloc_mcheck(qal, mr->mem, mr->len);
	ut_expect_ok(err);
	voluta_qalloc_free(qal, mr->mem, mr->len);
}

static void link_mrecord_del(struct voluta_list_head *link)
{
	struct ut_mrecord *mr;

	mr = link_to_mrecord(link);
	voluta_list_head_remove(link);
	mrecord_del(mr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_qalloc *
ut_new_qalloc(struct ut_env *ute, size_t sz)
{
	int err;
	struct voluta_qalloc *qal = NULL;

	qal = ut_zalloc(ute, sizeof(*qal));
	err = voluta_qalloc_init(qal, sz);
	ut_expect_ok(err);

	return qal;
}

static void ut_del_qalloc(struct voluta_qalloc *qal)
{
	int err;

	err = voluta_qalloc_fini(qal);
	ut_expect_ok(err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_qalloc_nbks_simple(struct ut_env *ute)
{
	struct voluta_list_head lst;
	struct voluta_qalloc *qal;
	struct ut_mrecord *mr;
	struct voluta_list_head *lnk = NULL;
	const size_t sizes[] = {
		UT_BK_SIZE - 1, UT_BK_SIZE, UT_BK_SIZE + 1,
		2 * UT_BK_SIZE, 8 * UT_BK_SIZE - 1
	};

	voluta_list_init(&lst);
	qal = ut_new_qalloc(ute, 32 * UT_UMEGA);
	for (size_t i = 0; i < UT_ARRAY_SIZE(sizes); ++i) {
		mr = mrecord_new(qal, sizes[i]);
		memset(mr->dat, (int)i, mr->dat_len);
		voluta_list_push_back(&lst, &mr->link);
	}
	lnk = lst.next;
	while (lnk != &lst) {
		link_mrecord_del(lnk);
		lnk = lst.next;
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t align_up(size_t nn, size_t align)
{
	return ((nn + align - 1) / align) * align;
}

static void ut_qalloc_free_nbks(struct ut_env *ute)
{
	size_t msz = 0;
	size_t rem = 0;
	size_t total = 0;
	struct voluta_qalloc *qal;
	struct ut_mrecord *mr;
	struct voluta_list_head lst;
	struct voluta_list_head *lnk;
	const size_t bk_size =  UT_BK_SIZE;
	struct voluta_alloc_stat qast;

	voluta_list_init(&lst);
	qal = ut_new_qalloc(ute, 32 * UT_UMEGA);
	voluta_qalloc_stat(qal, &qast);
	while (total < qast.memsz_data) {
		rem = qast.memsz_data - total;
		msz = sizeof(*mr) + (bk_size / 2) + (total % 10000);
		msz = voluta_clamp(msz, (bk_size / 2) + 1, rem);

		mr = mrecord_new(qal, msz);
		voluta_list_push_back(&lst, &mr->link);

		total += align_up(msz, bk_size);
		voluta_qalloc_stat(qal, &qast);
	}
	lnk = lst.next;
	while (lnk != &lst) {
		link_mrecord_del(lnk);
		lnk = lst.next;
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_qalloc_slab_elems(struct ut_env *ute)
{
	size_t val = 0;
	size_t msz = 0;
	struct voluta_qalloc *qal;
	struct ut_mrecord *mr;
	struct voluta_list_head *lnk;
	struct voluta_list_head lst;
	const size_t pg_size = VOLUTA_PAGE_SIZE;

	voluta_list_init(&lst);
	qal = ut_new_qalloc(ute, 64 * UT_UMEGA);
	for (size_t i = 0; i < 10000; ++i) {
		val = (pg_size + i) % (pg_size / 2);
		msz = voluta_clamp(val, sizeof(*mr), (pg_size / 2));
		mr = mrecord_new(qal, msz);
		memset(mr->dat, (int)i, mr->dat_len);
		voluta_list_push_back(&lst, &mr->link);

		if ((i % 7) == 1) {
			link_mrecord_del(lst.next);
		}
	}
	lnk = lst.next;
	while (lnk != &lst) {
		link_mrecord_del(lnk);
		lnk = lst.next->next;
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_qalloc_mixed(struct ut_env *ute)
{
	size_t msz = 0;
	size_t val = 0;
	size_t val2 = 0;
	size_t val_max = 100000;
	struct voluta_qalloc *qal = NULL;
	const size_t bk_size = UT_BK_SIZE;
	struct ut_mrecord *ai = NULL;
	struct voluta_list_head *lnk = NULL;
	struct voluta_list_head lst;

	voluta_list_init(&lst);
	qal = ut_new_qalloc(ute, 256 * UT_UMEGA);
	for (val = 0; val < val_max; val += 100) {
		msz = voluta_clamp(val, sizeof(*ai), 11 * bk_size);
		ai = mrecord_new(qal, msz);
		voluta_list_push_back(&lst, &ai->link);

		if ((val % 11) == 1) {
			link_mrecord_del(lst.next);
		}

		val2 = (val_max - val) / 2;
		msz = voluta_clamp(val2, sizeof(*ai), 11 * bk_size);
		ai = mrecord_new(qal, msz);
		voluta_list_push_back(&lst, &ai->link);
	}
	lnk = lst.next;
	while (lnk != &lst) {
		link_mrecord_del(lnk);
		lnk = lst.next->next;
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define NALLOC_SMALL 128

static size_t small_alloc_size(size_t i)
{
	return (i * 17) + 1;
}

static void ut_qalloc_small_sizes(struct ut_env *ute)
{
	size_t idx;
	size_t msz;
	void *mem = NULL;
	void *ptr[NALLOC_SMALL];
	long idx_arr[NALLOC_SMALL];
	struct voluta_qalloc *qal;

	qal = ut_new_qalloc(ute, 32 * UT_UMEGA);
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		msz = small_alloc_size(i);
		mem = voluta_qalloc_malloc(qal, msz);
		ut_expect_not_null(mem);
		memset(mem, (int)i, msz);
		ptr[i] = mem;
	}
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		msz = small_alloc_size(i);
		mem = ptr[i];
		voluta_qalloc_free(qal, mem, msz);
		ptr[i] = NULL;
	}

	ut_prandom_seq(idx_arr, UT_ARRAY_SIZE(idx_arr), 0);
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		idx = (size_t)idx_arr[i];
		msz = small_alloc_size(idx);
		mem = voluta_qalloc_malloc(qal, msz);
		ut_expect_not_null(mem);
		memset(mem, (int)i, msz);
		ptr[idx] = mem;
	}
	ut_prandom_seq(idx_arr, UT_ARRAY_SIZE(idx_arr), 0);
	for (size_t i = 0; i < UT_ARRAY_SIZE(ptr); ++i) {
		idx = (size_t)idx_arr[i];
		msz = small_alloc_size(idx);
		mem = ptr[idx];
		voluta_qalloc_free(qal, mem, msz);
		ptr[idx] = NULL;
	}
	ut_del_qalloc(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct iovec *random_iovecs(struct ut_env *ute,
                                   size_t cnt, size_t len_min, size_t len_max)
{
	struct iovec *iov = NULL;
	const size_t msz = sizeof(*iov) * cnt;
	const size_t len_dif = len_max - len_min;

	iov = ut_malloc(ute, msz);
	ut_randfill(ute, iov, msz);

	for (size_t i = 0; i < cnt; ++i) {
		iov[i].iov_len = (iov[i].iov_len % len_dif) + len_min;
		iov[i].iov_base = NULL;
	}
	return iov;
}

static void ut_qalloc_random_(struct ut_env *ute, size_t cnt)
{
	int err;
	size_t msz;
	void *mem = NULL;
	struct iovec *iov;
	struct voluta_qalloc *qal;
	const size_t pg_size = VOLUTA_PAGE_SIZE;

	qal = ut_new_qalloc(ute, cnt * 2 * pg_size);
	iov = random_iovecs(ute, cnt, 1, 2 * pg_size);
	for (size_t i = 0; i < cnt; ++i) {
		msz = iov[i].iov_len;
		mem = voluta_qalloc_malloc(qal, msz);
		ut_expect_not_null(mem);
		memset(mem, (int)i, msz);
		err = voluta_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		iov[i].iov_base = mem;
	}
	for (size_t i = 0; i < cnt; i += 3) {
		msz = iov[i].iov_len;
		mem = iov[i].iov_base;
		err = voluta_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		voluta_qalloc_free(qal, mem, msz);
		iov[i].iov_base = NULL;
	}
	for (size_t i = 1; i < cnt; i += 3) {
		msz = iov[i].iov_len;
		mem = iov[i].iov_base;
		err = voluta_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		voluta_qalloc_free(qal, mem, msz);
		iov[i].iov_len = 0;
		iov[i].iov_base = NULL;
	}
	for (size_t i = 0; i < cnt; i += 3) {
		msz = iov[i].iov_len;
		mem = voluta_qalloc_malloc(qal, msz);
		ut_expect_ok(err);
		ut_expect_not_null(mem);
		iov[i].iov_base = mem;
	}
	for (size_t i = 0; i < cnt; i++) {
		msz = iov[i].iov_len;
		mem = iov[i].iov_base;
		err = voluta_qalloc_mcheck(qal, mem, msz);
		ut_expect_ok(err);
		voluta_qalloc_free(qal, mem, msz);
		iov[i].iov_len = 0;
		iov[i].iov_base = NULL;
	}
	ut_del_qalloc(qal);
}

static void ut_qalloc_random(struct ut_env *ute)
{
	ut_qalloc_random_(ute, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_mpool *ut_new_mpool(struct ut_env *ute)
{
	struct voluta_qalloc *qal;
	struct voluta_mpool *mpool;

	qal = ut_new_qalloc(ute, 8 * UT_UMEGA);
	mpool = ut_malloc(ute, sizeof(*mpool));
	voluta_mpool_init(mpool, qal);
	return mpool;
}

static void ut_del_mpool(struct voluta_mpool *mpool)
{
	struct voluta_qalloc *qal = mpool->mp_qal;

	voluta_mpool_fini(mpool);
	ut_del_qalloc(qal);
}

static void ut_mpool_simple_(struct ut_env *ute, size_t nbks)
{
	size_t nbytes;
	struct voluta_mpool *mpool = NULL;
	struct voluta_alloc_if *alif = NULL;
	struct voluta_bksec_info *bsi = NULL;
	struct voluta_bksec_info **bsi_arr = NULL;

	mpool = ut_new_mpool(ute);
	alif = &mpool->mp_alif;

	nbytes = nbks * sizeof(struct voluta_bksec_info *);
	bsi_arr = voluta_allocate(alif, nbytes);
	ut_expect_not_null(bsi_arr);

	for (size_t i = 0; i < nbks; ++i) {
		bsi = voluta_allocate(alif, sizeof(*bsi));
		ut_expect_not_null(bsi);
		bsi_arr[i] = bsi;
	}
	for (size_t i = 1; i < nbks; i += 2) {
		bsi = bsi_arr[i];
		voluta_deallocate(alif, bsi, sizeof(*bsi));
		bsi_arr[i] = NULL;
	}
	for (size_t i = 0; i < nbks; i += 2) {
		bsi = bsi_arr[i];
		voluta_deallocate(alif, bsi, sizeof(*bsi));
		bsi_arr[i] = NULL;
	}

	voluta_deallocate(alif, bsi_arr, nbytes);
	ut_del_mpool(mpool);
}

static void ut_mpool_simple(struct ut_env *ute)
{
	ut_mpool_simple_(ute, 64);
	ut_mpool_simple_(ute, 271);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_qalloc_nbks_simple),
	UT_DEFTEST(ut_qalloc_free_nbks),
	UT_DEFTEST(ut_qalloc_slab_elems),
	UT_DEFTEST(ut_qalloc_mixed),
	UT_DEFTEST(ut_qalloc_small_sizes),
	UT_DEFTEST(ut_qalloc_random),
	UT_DEFTEST(ut_mpool_simple),
};

const struct ut_tests ut_test_qalloc = UT_MKTESTS(ut_local_tests);


