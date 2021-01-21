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

#define UT_VOLUME_SIZE (2L * VOLUTA_GIGA)

#define UT_DEFTGRP(t_) \
	{ .tests = &(t_), .name = VOLUTA_STR(t_) }

static struct ut_tgroup const g_ut_tgroups[] = {
	UT_DEFTGRP(ut_test_strings),
	UT_DEFTGRP(ut_test_avl),
	UT_DEFTGRP(ut_test_qalloc),
	UT_DEFTGRP(ut_test_super),
	UT_DEFTGRP(ut_test_dir),
	UT_DEFTGRP(ut_test_dir_iter),
	UT_DEFTGRP(ut_test_dir_list),
	UT_DEFTGRP(ut_test_namei),
	UT_DEFTGRP(ut_test_rename),
	UT_DEFTGRP(ut_test_symlink),
	UT_DEFTGRP(ut_test_xattr),
	UT_DEFTGRP(ut_test_ioctl),
	UT_DEFTGRP(ut_test_file_basic),
	UT_DEFTGRP(ut_test_file_stat),
	UT_DEFTGRP(ut_test_file_ranges),
	UT_DEFTGRP(ut_test_file_records),
	UT_DEFTGRP(ut_test_file_random),
	UT_DEFTGRP(ut_test_file_edges),
	UT_DEFTGRP(ut_test_file_truncate),
	UT_DEFTGRP(ut_test_file_fallocate),
	UT_DEFTGRP(ut_test_file_lseek),
	UT_DEFTGRP(ut_test_file_fiemap),
	UT_DEFTGRP(ut_test_reload),
	UT_DEFTGRP(ut_test_fillfs),
	UT_DEFTGRP(ut_test_archive),
};

/* Local functions forward declarations */
static struct ut_env *ute_new(void);
static void ute_del(struct ut_env *ute);
static void ute_setup(struct ut_env *ute);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_track_test(struct ut_env *ute,
			  const struct ut_testdef *td, bool pre_execute)
{
	FILE *fp = stdout;
	struct timespec dur;

	if (ute->silent) {
		return;
	}
	if (pre_execute) {
		fprintf(fp, "  %-32s", td->name);
		voluta_mclock_now(&ute->ts_start);
	} else {
		voluta_mclock_dur(&ute->ts_start, &dur);
		fprintf(fp, "OK (%ld.%03lds)\n",
			dur.tv_sec, dur.tv_nsec / 1000000L);
	}
	fflush(fp);
}

static void ut_check_valid_statvfs(const struct statvfs *stv)
{
	ut_expect_le(stv->f_bfree, stv->f_blocks);
	ut_expect_le(stv->f_bavail, stv->f_blocks);
	ut_expect_le(stv->f_ffree, stv->f_files);
	ut_expect_le(stv->f_favail, stv->f_files);
}

static void ut_check_statvfs(const struct statvfs *stv1,
			     const struct statvfs *stv2)
{
	ut_check_valid_statvfs(stv1);
	ut_check_valid_statvfs(stv2);
	ut_expect_statvfs(stv1, stv2);
}

static size_t ualloc_nbytes_now(const struct ut_env *ute)
{
	struct voluta_fs_stats st;

	voluta_fse_stats(ute->fse, &st);
	return st.nalloc_bytes;
}

static void ut_probe_stats(struct ut_env *ute, bool pre_execute)
{
	size_t ualloc_now;
	struct statvfs stvfs_now;
	const size_t bk_sz = UT_BK_SIZE;

	if (pre_execute) {
		ut_statfs_rootd(ute, &ute->stvfs_start);
		ut_drop_caches_fully(ute);
		ute->ualloc_start = ualloc_nbytes_now(ute);
	} else {
		ut_statfs_rootd(ute, &stvfs_now);
		ut_check_statvfs(&ute->stvfs_start, &stvfs_now);
		ut_drop_caches_fully(ute);
		ualloc_now = ualloc_nbytes_now(ute);
		/* XXX ut_expect_eq(ute->ualloc_start, ualloc_now); */
		ut_expect_ge(ute->ualloc_start + (2 * bk_sz), ualloc_now);
	}
}

static bool ut_is_runnable(const struct ut_env *ute,
			   const struct ut_testdef *td)
{
	return (!ute->tname || strstr(td->name, ute->tname));
}

static void ut_run_tgroup(struct ut_env *ute,
			  const struct ut_tgroup *tgroup)
{
	const struct ut_testdef *td;

	for (size_t i = 0; i < tgroup->tests->len; ++i) {
		td = &tgroup->tests->arr[i];
		if (ut_is_runnable(ute, td)) {
			ut_track_test(ute, td, true);
			ut_probe_stats(ute, true);
			td->hook(ute);
			ut_probe_stats(ute, false);
			ut_track_test(ute, td, false);
			ut_freeall(ute);
		}
	}
}

static void ut_exec_tests(struct ut_env *ute)
{
	for (size_t i = 0; i < UT_ARRAY_SIZE(g_ut_tgroups); ++i) {
		ut_run_tgroup(ute, &g_ut_tgroups[i]);
	}
}

static void ut_prep_tests(struct ut_env *ute)
{
	int err;

	err = voluta_fse_format(ute->fse);
	voluta_assert_ok(err);

	err = voluta_fse_term(ute->fse);
	voluta_assert_ok(err);

	err = voluta_fse_reload(ute->fse);
	voluta_assert_ok(err);
}

static void ut_done_tests(struct ut_env *ute)
{
	int err;

	err = voluta_fse_term(ute->fse);
	voluta_assert_ok(err);
}

static char *ut_joinpath(const char *path, const char *base)
{
	char *rpath;
	const size_t plen = strlen(path);
	const size_t blen = strlen(base);

	rpath = calloc(plen + blen + 2, 1);
	voluta_assert_not_null(rpath);

	strncpy(rpath, path, plen + 1);
	rpath[plen] = '/';
	strncpy(rpath + plen + 1, base, blen + 1);
	rpath[plen + 1 + blen] = '\0';

	return rpath;
}

static void ut_unlinkpath(char *path)
{
	voluta_sys_unlink(path);
}

void ut_execute_tests(void)
{
	char *volpath;
	struct ut_env *ute;

	ute = ute_new();

	volpath = ut_joinpath(ut_globals.test_dir_real, "ut.voluta");
	ute->fs_args.volume = volpath;
	ute->fs_args.encrypted = (ut_globals.encrypt_mode > 0);
	ute->fs_args.spliced = (ut_globals.spliced_mode > 0);
	ute->ar_args.volume = volpath;
	ute->ar_args.blobsdir = ut_globals.test_dir_real;
	ute->ar_args.arcname = "ut_archive.voluta";
	ute->tname = ut_globals.test_name;

	ut_unlinkpath(volpath);
	ute_setup(ute);

	ut_prep_tests(ute);
	ut_exec_tests(ute);
	ut_done_tests(ute);

	ute_del(ute);

	ut_unlinkpath(volpath);
	free(volpath);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/


static size_t aligned_size(size_t sz, size_t a)
{
	return ((sz + a - 1) / a) * a;
}

static size_t malloc_total_size(size_t nbytes)
{
	size_t total_size;
	struct ut_malloc_chunk *mchunk = NULL;
	const size_t mchunk_size = sizeof(*mchunk);
	const size_t data_size = sizeof(mchunk->data);

	total_size = mchunk_size;
	if (nbytes > data_size) {
		total_size += aligned_size(nbytes - data_size, mchunk_size);
	}
	return total_size;
}

static struct ut_malloc_chunk *
ut_malloc_chunk(struct ut_env *ute, size_t nbytes)
{
	size_t total_size;
	struct ut_malloc_chunk *mchunk;

	total_size = malloc_total_size(nbytes);
	mchunk = (struct ut_malloc_chunk *)malloc(total_size);
	voluta_assert_not_null(mchunk);

	mchunk->size = total_size;
	mchunk->next = ute->malloc_list;
	ute->malloc_list = mchunk;
	ute->nbytes_alloc += total_size;

	return mchunk;
}

static void ut_free(struct ut_env *ute,
		    struct ut_malloc_chunk *mchunk)
{
	voluta_assert_ge(ute->nbytes_alloc, mchunk->size);

	ute->nbytes_alloc -= mchunk->size;
	memset(mchunk, 0xFC, mchunk->size);
	free(mchunk);
}

void *ut_malloc(struct ut_env *ute, size_t nbytes)
{
	struct ut_malloc_chunk *mchunk;

	mchunk = ut_malloc_chunk(ute, nbytes);
	return mchunk->data;
}

void *ut_zalloc(struct ut_env *ute, size_t nbytes)
{
	void *ptr;

	ptr = ut_malloc(ute, nbytes);
	memset(ptr, 0, nbytes);

	return ptr;
}

char *ut_strdup(struct ut_env *ute, const char *str)
{
	return ut_strndup(ute, str, strlen(str));
}

char *ut_strndup(struct ut_env *ute, const char *str,
		 size_t len)
{
	char *str2;

	str2 = ut_zalloc(ute, len + 1);
	memcpy(str2, str, len);

	return str2;
}

void ut_freeall(struct ut_env *ute)
{
	struct ut_malloc_chunk *mnext;
	struct ut_malloc_chunk *mchunk = ute->malloc_list;

	while (mchunk != NULL) {
		mnext = mchunk->next;
		ut_free(ute, mchunk);
		mchunk = mnext;
	}
	voluta_assert_eq(ute->nbytes_alloc, 0);

	ute->nbytes_alloc = 0;
	ute->malloc_list = NULL;
}

const char *ut_make_name(struct ut_env *ute, const char *pre, size_t idx)
{
	const char *name;

	if (pre && strlen(pre)) {
		name = ut_strfmt(ute, "%s-%lx", pre, idx + 1);
	} else {
		name = ut_strfmt(ute, "%lx", idx + 1);
	}
	return name;
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *ut_make_passphrase(struct ut_env *ute)
{
	struct voluta_passphrase *pp = &ute->pass;
	const size_t nn = ((size_t)time(NULL) % sizeof(pp->pass));

	voluta_memzero(pp, sizeof(*pp));

	pp->passlen = voluta_min(nn + 1, sizeof(pp->pass) - 1);
	voluta_fill_random_ascii((char *)pp->pass, pp->passlen);

	return (const char *)(pp->pass);
}

static void ute_init_passphrase(struct ut_env *ute)
{
	const char *pass = ut_make_passphrase(ute);

	ute->ar_args.passph = pass;
	ute->fs_args.passwd = pass;
}

static void ute_init(struct ut_env *ute)
{
	memset(ute, 0, sizeof(*ute));
	ute->fs_args.uid = getuid();
	ute->fs_args.gid = getgid();
	ute->fs_args.pid = getpid();
	ute->fs_args.umask = 0002;
	ute->fs_args.mountp = "/";
	ute->fs_args.volume = NULL;
	ute->fs_args.fsname = "voluta-ut";
	ute->fs_args.vsize = UT_VOLUME_SIZE;
	ute->fs_args.pedantic = false; /* TODO: make me a nob (true) */
	ute->ar_args.arcname = "unitest.voluta";

	ute->silent = false;
	ute->malloc_list = NULL;
	ute->nbytes_alloc = 0;
	ute->unique_count = 1;

	ute_init_passphrase(ute);
}

static void ute_fini(struct ut_env *ute)
{
	struct voluta_archiver *arc = ute->arc;
	struct voluta_fs_env *fse = ute->fse;

	if (arc != NULL) {
		voluta_archiver_del(arc);
	}
	if (fse != NULL) {
		voluta_fse_term(fse);
		voluta_fse_del(fse);
	}
	memset(ute, 0, sizeof(*ute));
}

static void ute_setup(struct ut_env *ute)
{
	int err;
	size_t mem_want = VOLUTA_GIGA;
	struct voluta_fs_env *fse = NULL;
	struct voluta_archiver *arc = NULL;

	err = voluta_fse_new(mem_want, &fse);
	voluta_assert_ok(err);

	err = voluta_fse_setargs(fse, &ute->fs_args);
	voluta_assert_ok(err);

	err = voluta_archiver_new(mem_want, &arc);
	voluta_assert_ok(err);

	err = voluta_archiver_setargs(arc, &ute->ar_args);
	voluta_assert_ok(err);

	ute->fse = fse;
	ute->arc = arc;
}

static struct ut_env *ute_new(void)
{
	struct ut_env *ute;

	ute = (struct ut_env *)malloc(sizeof(*ute));
	voluta_assert_not_null(ute);

	ute_init(ute);
	return ute;
}

static void ute_del(struct ut_env *ute)
{
	ut_freeall(ute);
	ute_fini(ute);
	memset(ute, 0, sizeof(*ute));
	free(ute);
}

void *ut_zerobuf(struct ut_env *ute, size_t bsz)
{
	return ut_zalloc(ute, bsz);
}

void ut_randfill(struct ut_env *ute, void *buf, size_t bsz)
{
	voluta_getentropy(buf, bsz);
	voluta_unused(ute);
}

void *ut_randbuf(struct ut_env *ute, size_t bsz)
{
	uint8_t *buf = NULL;

	if (bsz > 0) {
		buf = ut_malloc(ute, bsz);
		ut_randfill(ute, buf, bsz);
	}
	return buf;
}

static void swap(long *arr, size_t p1, size_t p2)
{
	long tmp = arr[p1];

	arr[p1] = arr[p2];
	arr[p2] = tmp;
}

long *ut_randseq(struct ut_env *ute, size_t len, long base)
{
	long *arr;
	size_t *pos;

	arr = ut_zerobuf(ute, len * sizeof(*arr));
	for (size_t i = 0; i < len; ++i) {
		arr[i] = base++;
	}

	pos = ut_randbuf(ute, len * sizeof(*pos));
	for (size_t i = 0; i < len; ++i) {
		swap(arr, i, pos[i] % len);
	}
	return arr;
}

static void force_alnum(char *str, size_t len)
{
	int ch;
	size_t idx;
	const char *alt = "_0123456789abcdefghijklmnopqrstuvwxyz";

	for (size_t i = 0; i < len; ++i) {
		ch = (int)(str[i]);
		if (!isalnum(ch)) {
			idx = (size_t)abs(ch);
			str[i] = alt[idx % strlen(alt)];
		}
	}
}

char *ut_randstr(struct ut_env *ute, size_t len)
{
	char *str;

	str = ut_randbuf(ute, len + 1);
	force_alnum(str, len);
	str[len] = '\0';
	return str;
}

char *ut_strfmt(struct ut_env *ute, const char *fmt, ...)
{
	int nb;
	size_t bsz = 255;
	char *buf;
	va_list ap;

	va_start(ap, fmt);
	nb = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if ((size_t)nb > bsz) {
		bsz = (size_t)nb;
	}

	va_start(ap, fmt);
	buf = ut_zerobuf(ute, bsz + 1);
	nb = vsnprintf(buf, bsz, fmt, ap);
	va_end(ap);

	voluta_unused(nb);
	return buf;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct ut_dvec *ut_new_dvec(struct ut_env *ute,
			    loff_t off, size_t len)
{
	size_t size;
	struct ut_dvec *dvec;

	size = (sizeof(*dvec) + len - sizeof(dvec->dat)) | 0x7;
	dvec = ut_zerobuf(ute, size);
	dvec->off = off;
	dvec->len = len;
	ut_randfill(ute, dvec->dat, len);
	return dvec;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void swap_long(long *a, long *b)
{
	const long c = *a;

	*a = *b;
	*b = c;
}

/*
 * Pseudo-random shuffle, using hash function.
 * See: http://benpfaff.org/writings/clc/shuffle.html
 */
struct voluta_prandoms {
	uint64_t dat[16];
	size_t nr;
};

static uint64_t next_prandom(struct voluta_prandoms *pr)
{
	if (pr->nr == 0) {
		voluta_getentropy(pr->dat, sizeof(pr->dat));
		pr->nr = UT_ARRAY_SIZE(pr->dat);
	}
	pr->nr -= 1;
	return pr->dat[pr->nr];
}

static void prandom_shuffle(long *arr, size_t len)
{
	size_t j;
	uint64_t rnd;
	struct voluta_prandoms pr = { .nr = 0 };

	if (len < 2) {
		return;
	}
	for (size_t i = 0; i < len - 1; i++) {
		rnd = next_prandom(&pr);
		j = i + (rnd / (ULONG_MAX / (len - i) + 1));
		swap_long(arr + i, arr + j);
	}
}

static void create_seq(long *arr, size_t len, long base)
{
	for (size_t i = 0; i < len; ++i) {
		arr[i] = base++;
	}
}

/* Generates sequence of integers [base..base+n) and then random shuffle */
void ut_prandom_seq(long *arr, size_t len, long base)
{
	create_seq(arr, len, base);
	prandom_shuffle(arr, len);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ut_equal_strings(const char *s1, const char *s2)
{
	return (strcmp(s1, s2) == 0);
}

bool ut_dot_or_dotdot(const char *s)
{
	return ut_equal_strings(s, ".") || ut_equal_strings(s, "..");
}

bool ut_not_dot_or_dotdot(const char *s)
{
	return !ut_dot_or_dotdot(s);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint64_t ut_fnv1a(const void *buf, size_t len, uint64_t hval_base)
{
	uint64_t hval;
	const uint8_t *itr = (const uint8_t *)buf;
	const uint8_t *end = itr + len;
	const uint64_t fnv_prime = 0x100000001b3UL;

	hval = hval_base;
	while (itr < end) {
		hval *= fnv_prime;

		hval ^= (uint64_t)(*itr++);
	}
	return hval;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void ut_expect_true_(bool cond, const char *fl, int ln)
{
	if (!cond) {
		voluta_panicf(fl, ln, "failure: cond=%d", cond);
	}
}

void ut_expect_lt_(long a, long b, const char *fl, int ln)
{
	if (!(a < b)) {
		voluta_panicf(fl, ln, "unexpected: (%ld < %ld)", a, b);
	}
}

void ut_expect_le_(long a, long b, const char *fl, int ln)
{
	if (!(a <= b)) {
		voluta_panicf(fl, ln, "unexpected: (%ld <= %ld)", a, b);
	}
}

void ut_expect_gt_(long a, long b, const char *fl, int ln)
{
	if (!(a > b)) {
		voluta_panicf(fl, ln, "unexpected: (%ld > %ld)", a, b);
	}
}

void ut_expect_ge_(long a, long b, const char *fl, int ln)
{
	if (!(a >= b)) {
		voluta_panicf(fl, ln, "unexpected: (%ld >= %ld)", a, b);
	}
}

void ut_expect_eq_(long a, long b, const char *fl, int ln)
{
	if (!(a == b)) {
		voluta_panicf(fl, ln, "unexpected: (%ld == %ld)", a, b);
	}
}

void ut_expect_ne_(long a, long b, const char *fl, int ln)
{
	if (!(a != b)) {
		voluta_panicf(fl, ln, "unexpected: (%ld != %ld)", a, b);
	}
}

void ut_expect_eqs_(const char *s1, const char *s2, const char *fl, int ln)
{
	if (strcmp(s1, s2) != 0) {
		voluta_panicf(fl, ln, "not equal: '%s' != '%s'", s1, s2);
	}
}

void ut_expect_eqm_(const void *p, const void *q,
		    size_t n, const char *fl, int ln)
{
	if (memcmp(p, q, n) != 0) {
		voluta_panicf(fl, ln, "not equal at: %p %p", p, q);
	}
}

void ut_expect_ok_(int err, const char *fl, int ln)
{
	if (err) {
		voluta_panicf(fl, ln, "err=%d", err);
	}
}

void ut_expect_err_(int err, int exp, const char *fl, int ln)
{
	if (err != exp) {
		voluta_panicf(fl, ln, "err=%d exp=%d", err, exp);
	}
}

void ut_expect_null_(const void *ptr, const char *fl, int ln)
{
	if (ptr != NULL) {
		voluta_panicf(fl, ln, "not null: %p", ptr);
	}
}

void ut_expect_not_null_(const void *ptr, const char *fl, int ln)
{
	if (ptr == NULL) {
		voluta_panicf(fl, ln, "null pointer: %p", ptr);
	}
}

