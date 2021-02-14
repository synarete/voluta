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


static void ut_create_open_release(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_release_ok(ute, ino);
	ut_drop_caches_fully(ute);
	ut_lookup_file(ute, dino, name, ino);
	ut_drop_caches_fully(ute);
	ut_open_rdonly(ute, ino);
	ut_release_ok(ute, ino);
	ut_unlink_ok(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static void ut_create_unlink_simple(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	struct stat st;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_lookup_ok(ute, dino, name, &st);
	ut_expect(S_ISREG(st.st_mode));
	ut_expect_eq(ino, st.st_ino);
	ut_release_ok(ute, ino);
	ut_drop_caches_fully(ute);
	ut_lookup_ok(ute, dino, name, &st);
	ut_drop_caches_fully(ute);
	ut_unlink_ok(ute, dino, name);
	ut_lookup_noent(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

static const char *ut_link_name(struct ut_env *ute,
                                const char *prefix, unsigned long i)
{
	return ut_strfmt(ute, "%s%lu", prefix, i);
}

static void ut_link_unlink_many(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	struct stat st;
	const char *lname;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	const size_t nlinks_max = 10000;

	ut_expect_le(nlinks_max, VOLUTA_LINK_MAX);
	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_file(ute, dino, fname, &ino);
	for (size_t i = 0; i < nlinks_max; ++i) {
		ut_getattr_ok(ute, ino, &st);
		ut_expect_eq(st.st_nlink, i + 1);

		lname = ut_link_name(ute, fname, i + 1);
		ut_link_ok(ute, ino, dino, lname, &st);

		ut_getattr_ok(ute, ino, &st);
		ut_expect_eq(st.st_nlink, i + 2);
	}
	for (size_t i = 0; i < nlinks_max; i += 2) {
		lname = ut_link_name(ute, fname, i + 1);
		ut_unlink_ok(ute, dino, lname);
	}
	for (size_t i = 1; i < nlinks_max; i += 2) {
		lname = ut_link_name(ute, fname, i + 1);
		ut_unlink_ok(ute, dino, lname);
	}

	ut_remove_file(ute, dino, fname, ino);
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_link_max(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	struct stat st;
	struct statvfs stv;
	const char *lname;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	const size_t nlink_max = VOLUTA_LINK_MAX;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_statfs_ok(ute, dino, &stv);
	ut_expect_gt(stv.f_favail, nlink_max);

	ut_create_file(ute, dino, fname, &ino);
	ut_getattr_ok(ute, ino, &st);
	ut_expect_eq(st.st_nlink, 1);

	for (size_t i = 1; i < nlink_max; ++i) {
		lname = ut_link_name(ute, fname, i);
		ut_link_ok(ute, ino, dino, lname, &st);
	}
	lname = ut_link_name(ute, fname, 1000 * nlink_max);
	ut_link_err(ute, ino, dino, lname, -EMLINK);

	for (size_t j = 1; j < nlink_max; ++j) {
		lname = ut_link_name(ute, fname, j);
		ut_unlink_ok(ute, dino, lname);
	}
	ut_getattr_ok(ute, ino, &st);
	ut_expect_eq(st.st_nlink, 1);
	ut_remove_file(ute, dino, fname, ino);
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *
make_repeated_name(struct ut_env *ute, char c, size_t len)
{
	size_t nlen;
	char name[UT_NAME_MAX + 1] = "";

	nlen = (len < sizeof(name)) ? len : (sizeof(name) - 1);
	memset(name, c, nlen);
	return ut_strdup(ute, name);
}

static void ut_link_similar_names(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	struct stat st;
	const char *name = UT_NAME;
	const char *lname;
	const char *abc = "abcdefghijklmnopqrstuvwxyz" \
	                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const size_t abc_len = strlen(abc);
	const size_t name_max = UT_NAME_MAX;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);

	for (size_t i = 0; i < abc_len; ++i) {
		for (size_t j = 1; j <= name_max; ++j) {
			lname = make_repeated_name(ute, abc[i], j);
			ut_link_ok(ute, ino, dino, lname, &st);
		}
	}
	for (size_t i = 0; i < abc_len; ++i) {
		for (size_t j = 1; j <= name_max; ++j) {
			lname = make_repeated_name(ute, abc[i], j);
			ut_unlink_ok(ute, dino, lname);
		}
	}
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_link_rand_names(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	size_t name_len;
	struct stat st;
	const char *name = UT_NAME;
	const size_t nlinks = 8 * 1024; /* XXX check with large */
	const size_t name_max = UT_NAME_MAX;
	char *lname = NULL;
	char **links = NULL;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_only(ute, dino, name, &ino);
	links = ut_zerobuf(ute, nlinks * sizeof(*links));
	for (size_t i = 0; i < nlinks; ++i) {
		name_len = (i % name_max) | 0xA1;
		lname = ut_randstr(ute, name_len);
		ut_link_ok(ute, ino, dino, lname, &st);
		links[i] = lname;
	}
	ut_drop_caches_fully(ute);
	for (size_t i = 0; i < nlinks; ++i) {
		lname = links[i];
		ut_unlink_ok(ute, dino, lname);
	}
	ut_remove_link(ute, dino, name);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_inode_utimes(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	struct timespec mtime = { 111, 2222 };
	struct timespec atime = { 33333, 444444 };

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_utimens_atime(ute, ino, &atime);
	ut_utimens_mtime(ute, ino, &mtime);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_inode_special(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	const mode_t rmode = S_IRUSR | S_IRGRP;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_special(ute, dino, name, S_IFIFO | rmode, &ino);
	ut_remove_file(ute, dino, name, ino);
	ut_create_special(ute, dino, name, S_IFSOCK | rmode, &ino);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_expect_eq_tsx(const struct statx_timestamp *stx_ts,
                             const struct timespec *st_ts)
{
	ut_expect_eq(stx_ts->tv_sec, st_ts->tv_sec);
	ut_expect_eq(stx_ts->tv_nsec, st_ts->tv_nsec);
}

static void ut_expect_eq_statx(const struct statx *stx, const struct stat *st)
{
	ut_expect_eq(st->st_nlink, stx->stx_nlink);
	ut_expect_eq(st->st_uid, stx->stx_uid);
	ut_expect_eq(st->st_gid, stx->stx_gid);
	ut_expect_eq(st->st_mode, stx->stx_mode);
	ut_expect_eq(st->st_ino, stx->stx_ino);
	ut_expect_eq(st->st_size, stx->stx_size);
	ut_expect_eq(st->st_blocks, stx->stx_blocks);
	ut_expect_eq(st->st_blksize, stx->stx_blksize);
	ut_expect_eq_tsx(&stx->stx_mtime, &st->st_mtim);
	ut_expect_eq_tsx(&stx->stx_ctime, &st->st_ctim);
}

static void ut_inode_statx(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	struct stat st;
	struct statx stx;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_getattr_ok(ute, ino, &st);
	ut_statx_exists(ute, ino, &stx);
	ut_expect_eq_statx(&stx, &st);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_create_open_release),
	UT_DEFTEST(ut_create_unlink_simple),
	UT_DEFTEST(ut_link_unlink_many),
	UT_DEFTEST(ut_link_similar_names),
	UT_DEFTEST(ut_link_rand_names),
	UT_DEFTEST(ut_link_max),
	UT_DEFTEST(ut_inode_utimes),
	UT_DEFTEST(ut_inode_special),
	UT_DEFTEST(ut_inode_statx),
};

const struct ut_tests ut_test_namei = UT_MKTESTS(ut_local_tests);

