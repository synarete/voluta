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

struct ut_namesarr {
	size_t cnt;
	const char *arr[1];
};

static const char *make_name(struct ut_env *ute,
                             long idx, size_t len)
{
	char name[UT_NAME_MAX + 1] = "";
	const size_t name_max = sizeof(name) - 1;

	ut_expect_lt(len, sizeof(name));
	memset(name, 'x', name_max);
	snprintf(name, name_max, "%lu", idx);
	if (len) {
		name[strlen(name)] = '_';
		name[len] = '\0';
	}
	return ut_strdup(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct ut_namesarr *
new_namesarr(struct ut_env *ute, size_t cnt)
{
	size_t sz;
	struct ut_namesarr *na;

	sz = sizeof(*na) + ((cnt - 1) * sizeof(na->arr));
	na = ut_zalloc(ute, sz);
	na->cnt = cnt;

	return na;
}

static struct ut_namesarr *
make_names_(struct ut_env *ute, size_t cnt, size_t len)
{
	struct ut_namesarr *na;

	na = new_namesarr(ute, cnt);
	for (size_t i = 0; i < na->cnt; ++i) {
		na->arr[i] = make_name(ute, (long)i + 1, len);
	}
	return na;
}

static struct ut_namesarr *
make_names(struct ut_env *ute, size_t cnt)
{
	return make_names_(ute, cnt, 0);
}

static struct ut_namesarr *
make_long_names(struct ut_env *ute, size_t cnt)
{
	return make_names_(ute, cnt, UT_NAME_MAX);
}

static struct ut_namesarr *
make_names_any_len(struct ut_env *ute, size_t cnt)
{
	struct ut_namesarr *na = new_namesarr(ute, cnt);

	for (size_t i = 0; i < na->cnt; ++i) {
		size_t len = voluta_clamp(i % UT_NAME_MAX, 17, UT_NAME_MAX);

		na->arr[i] = make_name(ute, (long)i + 1, len);
	}
	return na;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_mkdir_simple(struct ut_env *ute)
{
	ino_t ino;
	const char *name = UT_NAME;
	const ino_t parent = UT_ROOT_INO;
	struct stat st;
	struct statvfs stv[2];

	ut_statfs_rootd(ute, &stv[0]);
	ut_mkdir_ok(ute, parent, name, &st);
	ino = st.st_ino;
	ut_expect(S_ISDIR(st.st_mode));
	ut_expect_eq(st.st_nlink, 2);
	ut_expect_ne(ino, parent);
	ut_lookup_ok(ute, parent, name, &st);
	ut_expect(S_ISDIR(st.st_mode));
	ut_expect_eq(ino, st.st_ino);
	ut_lookup_noent(ute, parent, "abc");
	ut_mkdir_err(ute, parent, name, -EEXIST);
	ut_rmdir_ok(ute, parent, name);
	ut_lookup_noent(ute, parent, name);
	ut_statfs_rootd(ute, &stv[1]);
	ut_expect_eq(stv[0].f_bfree, stv[1].f_bfree);
	ut_expect_eq(stv[0].f_ffree, stv[1].f_ffree);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_mkdir_subdirs_(struct ut_env *ute, size_t cnt)
{
	ino_t sino;
	ino_t dino;
	const char *name = UT_NAME;
	const struct ut_namesarr *na = make_names(ute, cnt);

	ut_mkdir_at_root(ute, name, &dino);
	for (size_t i = 0; i < cnt; ++i) {
		ut_mkdir_oki(ute, dino, na->arr[i], &sino);
		ut_mkdir_err(ute, dino, na->arr[i], -EEXIST);
	}
	for (size_t j = 0; j < cnt; ++j) {
		ut_mkdir_err(ute, dino, na->arr[j], -EEXIST);
		ut_rmdir_ok(ute, dino, na->arr[j]);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_mkdir_subdirs(struct ut_env *ute)
{
	ut_mkdir_subdirs_(ute, 1);
	ut_mkdir_subdirs_(ute, 10);
	ut_mkdir_subdirs_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_mkdir_reloaded(struct ut_env *ute)
{
	ino_t ino;
	struct stat st;
	const char *name = UT_NAME;
	const ino_t parent = UT_ROOT_INO;

	ut_drop_caches_fully(ute);
	ut_getattr_ok(ute, parent, &st);
	ut_expect(S_ISDIR(st.st_mode));
	ut_expect_eq(st.st_nlink, 2);

	ut_drop_caches_fully(ute);
	ut_mkdir_oki(ute, parent, name, &ino);
	ut_expect_ne(ino, parent);
	ut_getattr_ok(ute, ino, &st);

	ut_drop_caches_fully(ute);
	ut_getattr_ok(ute, ino, &st);
	ut_expect(S_ISDIR(st.st_mode));
	ut_expect_eq(st.st_nlink, 2);

	ut_drop_caches_fully(ute);
	ut_lookup_dir(ute, parent, name, ino);

	ut_drop_caches_fully(ute);
	ut_mkdir_err(ute, parent, name, -EEXIST);

	ut_drop_caches_fully(ute);
	ut_rmdir_ok(ute, parent, name);

	ut_drop_caches_fully(ute);
	ut_lookup_noent(ute, parent, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_mkdir_multi_(struct ut_env *ute, size_t cnt)
{
	ino_t dino;
	ino_t child_ino;
	loff_t size = 0;
	blkcnt_t blkcnt = 0;
	struct stat st;
	struct statvfs stv;
	const char *dname = UT_NAME;
	const ino_t root_ino = UT_ROOT_INO;
	struct ut_namesarr *na = make_names(ute, cnt + 1);

	ut_mkdir_oki(ute, root_ino, dname, &dino);
	ut_statfs_ok(ute, dino, &stv);
	ut_expect_gt(stv.f_favail, cnt);

	for (size_t i = 0; i < cnt; ++i) {
		ut_mkdir_oki(ute, dino, na->arr[i], &child_ino);
		ut_lookup_noent(ute, dino, na->arr[i + 1]);
		ut_getattr_ok(ute, dino, &st);

		ut_expect_gt(st.st_size, 0);
		ut_expect_ge(st.st_size, size);
		size = st.st_size;
		ut_expect_gt(st.st_blocks, 0);
		ut_expect_ge(st.st_blocks, blkcnt);
		blkcnt = st.st_blocks;
	}
	ut_drop_caches_fully(ute);
	ut_getattr_ok(ute, dino, &st);
	ut_expect_eq(st.st_size, size);
	ut_expect_eq(st.st_blocks, blkcnt);

	for (size_t j = 0; j < cnt; ++j) {
		ut_getattr_ok(ute, dino, &st);
		ut_expect_gt(st.st_size, 0);
		ut_expect_gt(st.st_blocks, 0);
		ut_rmdir_ok(ute, dino, na->arr[j]);
	}
	ut_rmdir_ok(ute, root_ino, dname);
}

static void ut_mkdir_multi(struct ut_env *ute)
{
	ut_mkdir_multi_(ute, 10);
	ut_mkdir_multi_(ute, 1000);
}

static void ut_mkdir_multi_link_max(struct ut_env *ute)
{
	ut_mkdir_multi_(ute, VOLUTA_LINK_MAX - 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_mkdir_link_max(struct ut_env *ute)
{
	ino_t child_ino;
	ino_t dino;
	struct stat st;
	struct statvfs stv;
	const char *dname = UT_NAME;
	const size_t nlink_max = VOLUTA_LINK_MAX;
	struct ut_namesarr *na = make_names(ute, nlink_max);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_statfs_ok(ute, dino, &stv);
	ut_expect_gt(stv.f_favail, nlink_max);
	ut_getattr_ok(ute, dino, &st);
	ut_expect_eq(st.st_nlink, 2);

	for (size_t i = 2; i < nlink_max; ++i) {
		ut_mkdir_oki(ute, dino, na->arr[i], &child_ino);
		ut_getattr_ok(ute, dino, &st);
		ut_expect_eq(st.st_nlink, i + 1);
	}
	ut_drop_caches_fully(ute);
	ut_mkdir_err(ute, dino, dname, -EMLINK);

	for (size_t j = 2; j < nlink_max; ++j) {
		ut_rmdir_ok(ute, dino, na->arr[j]);
	}
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_link_any_names_(struct ut_env *ute, size_t cnt)
{
	ino_t ino;
	ino_t dino;
	const char *name = UT_NAME;
	const long *idx = ut_randseq(ute, cnt, 0);
	struct ut_namesarr *na = make_names_any_len(ute, cnt);

	ut_mkdir_at_root(ute, name, &dino);
	for (size_t i = 0; i < cnt; ++i) {
		ut_create_only(ute, dino, na->arr[idx[i]], &ino);
	}
	for (size_t j = 0; j < cnt; ++j) {
		ut_unlink_ok(ute, dino, na->arr[idx[j]]);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_dir_link_any_names(struct ut_env *ute)
{
	ut_dir_link_any_names_(ute, 10);
	ut_dir_link_any_names_(ute, 100);
	ut_dir_link_any_names_(ute, 1000);
	ut_dir_link_any_names_(ute, 50000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_link_long_names_(struct ut_env *ute, size_t cnt)
{
	ino_t ino;
	ino_t dino;
	long *idx = NULL;
	const char *name = UT_NAME;
	const struct ut_namesarr *na = make_long_names(ute, cnt);

	ut_mkdir_at_root(ute, name, &dino);
	idx = ut_randseq(ute, cnt, 0);
	for (size_t i = 0; i < cnt; ++i) {
		ut_create_only(ute, dino, na->arr[idx[i]], &ino);
	}
	idx = ut_randseq(ute, cnt, 0);
	for (size_t j = 0; j < cnt; ++j) {
		ut_unlink_ok(ute, dino, na->arr[idx[j]]);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_dir_link_long_names(struct ut_env *ute)
{
	ut_dir_link_long_names_(ute, 10);
	ut_dir_link_long_names_(ute, 100);
	ut_dir_link_long_names_(ute, 1000);
	ut_dir_link_long_names_(ute, 50000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *make_lname(struct ut_env *ute, size_t len, int tag)
{
	char name[UT_NAME_MAX + 1] = "";
	const size_t name_max = sizeof(name) - 1;
	const char ch = tag ? 'A' : 'B';

	ut_expect_le(len, name_max);
	memset(name, ch, len);
	name[len] = '\0';

	return ut_strdup(ute, name);
}

static void ut_dir_link_unlink_mixed_(struct ut_env *ute, size_t nfiles)
{
	size_t len;
	ino_t ino;
	ino_t dino;
	struct stat st;
	const char *dname = UT_NAME;
	const char *fname = UT_NAME;
	const char *lname = NULL;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_create_ok(ute, dino, fname, S_IFREG | S_IRWXU, &st);
	ino = st.st_ino;

	ut_release_ok(ute, ino);
	for (size_t i = 0; i < nfiles; i += 2) {
		len = i + 1;
		lname = make_lname(ute, len, 0);
		ut_link_ok(ute, ino, dino, lname, &st);
		lname = make_lname(ute, len, 1);
		ut_link_ok(ute, ino, dino, lname, &st);
		lname = make_lname(ute, len, 0);
		ut_unlink_ok(ute, dino, lname);
	}
	for (size_t i = 1; i < nfiles; i += 2) {
		len = i + 1;
		lname = make_lname(ute, len, 0);
		ut_link_ok(ute, ino, dino, lname, &st);
		lname = make_lname(ute, len, 1);
		ut_link_ok(ute, ino, dino, lname, &st);
		lname = make_lname(ute, len, 0);
		ut_unlink_ok(ute, dino, lname);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		len = i + 1;
		lname = make_lname(ute, len, 0);
		ut_unlink_err(ute, dino, lname, -ENOENT);
		lname = make_lname(ute, len, 1);
		ut_unlink_ok(ute, dino, lname);
	}
	ut_unlink_ok(ute, dino, fname);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_link_unlink_mixed(struct ut_env *ute)
{
	ut_dir_link_unlink_mixed_(ute, 11);
	ut_dir_link_unlink_mixed_(ute, UT_NAME_MAX);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *make_xname(struct ut_env *ute, size_t x)
{
	return ut_strfmt(ute, "%lx", x);
}

static void ut_dir_stat_(struct ut_env *ute, size_t cnt)
{
	ino_t ino;
	ino_t dino;
	loff_t dsize;
	blkcnt_t blocks = 0;
	blkcnt_t nfrg = UT_BK_SIZE / 512;
	const char *dname = UT_NAME;
	const char *xname = NULL;
	const loff_t empty_size = VOLUTA_DIR_EMPTY_SIZE;
	struct stat st;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_getattr_ok(ute, dino, &st);
	ut_expect_eq(st.st_size, empty_size);

	dsize = empty_size;
	for (size_t i = 0; i < cnt; ++i) {
		xname = make_xname(ute, i);
		ut_create_only(ute, dino, xname, &ino);
		ut_getattr_ok(ute, dino, &st);
		ut_expect_ge(st.st_size, (loff_t)i + 1);
		ut_expect_gt(st.st_size, empty_size);
		ut_expect_ge(st.st_size, dsize);
		ut_expect_ge(st.st_blocks, blocks);
		ut_expect_le(st.st_blocks, blocks + nfrg);
		blocks = st.st_blocks;
		dsize = st.st_size;
	}
	ut_drop_caches_fully(ute);

	ut_getattr_ok(ute, dino, &st);
	ut_expect_ge(st.st_size, cnt);
	ut_expect_eq(st.st_size, dsize);
	ut_expect_gt(st.st_blocks, 0);
	for (size_t i = 0; i < cnt; ++i) {
		xname = make_xname(ute, i);
		ut_remove_link(ute, dino, xname);
		ut_getattr_ok(ute, dino, &st);
		ut_expect_ge(st.st_size, (loff_t)(cnt - i) - 1);
		ut_expect_le(st.st_size, dsize);
		dsize = st.st_size;
	}

	ut_getattr_ok(ute, dino, &st);
	ut_expect_eq(st.st_size, empty_size);
	ut_expect_eq(st.st_blocks, 0);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_stat_simple(struct ut_env *ute)
{
	ut_dir_stat_(ute, 16);
	ut_dir_stat_(ute, 256);
}

static void ut_dir_stat_large(struct ut_env *ute)
{
	ut_dir_stat_(ute, VOLUTA_LINK_MAX); /* TODO: VOLUTA_DIROFF_MAX */
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_rmdir_when_open(struct ut_env *ute)
{
	ino_t ino;
	ino_t dino;
	ino_t parentd;
	struct stat st;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &parentd);
	ut_mkdir_oki(ute, parentd, name, &dino);
	ut_opendir_ok(ute, dino);
	ut_getattr_dir(ute, dino, &st);
	ut_expect_eq(st.st_nlink, 2);
	ut_create_file(ute, dino, name, &ino);
	ut_getattr_reg(ute, ino, &st);
	ut_expect_eq(st.st_nlink, 1);
	ut_unlink_ok(ute, dino, name);
	ut_rmdir_ok(ute, parentd, name);
	ut_getattr_dir(ute, dino, &st);
	ut_expect_eq(st.st_nlink, 1);
	ut_create_noent(ute, dino, name);
	ut_releasedir_ok(ute, dino);
	ut_getattr_noent(ute, dino);
	ut_release_ok(ute, ino);
	ut_getattr_noent(ute, ino);
	ut_rmdir_at_root(ute, name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_mkdir_simple),
	UT_DEFTEST(ut_mkdir_subdirs),
	UT_DEFTEST(ut_mkdir_reloaded),
	UT_DEFTEST(ut_mkdir_multi),
	UT_DEFTEST(ut_mkdir_multi_link_max),
	UT_DEFTEST(ut_mkdir_link_max),
	UT_DEFTEST(ut_rmdir_when_open),
	UT_DEFTEST(ut_dir_link_any_names),
	UT_DEFTEST(ut_dir_link_long_names),
	UT_DEFTEST(ut_dir_link_unlink_mixed),
	UT_DEFTEST(ut_dir_stat_simple),
	UT_DEFTEST(ut_dir_stat_large),
};

const struct ut_tests ut_test_dir = UT_MKTESTS(ut_local_tests);

