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


struct ut_readdir_ctx *ut_new_readdir_ctx(struct ut_env *ute)
{
	struct ut_readdir_ctx *readdir_ctx;

	readdir_ctx = ut_zerobuf(ute, sizeof(*readdir_ctx));
	return readdir_ctx;
}


static const struct ut_dirent_info *
ut_find_not_dot(const struct ut_dirent_info *deis, size_t n, size_t start_pos)
{
	size_t pos = start_pos;
	const struct ut_dirent_info *dei = NULL;

	for (size_t i = 0; i < n; ++i) {
		if (pos >= n) {
			pos = 0;
		}
		dei = deis + pos;
		if (ut_not_dot_or_dotdot(dei->de.d_name)) {
			break;
		}
		++pos;
		dei = NULL;
	}
	ut_expect_not_null(dei);
	return dei;
}

static const struct ut_dirent_info *
ut_find_first_not_dot(const struct ut_dirent_info *dei, size_t n)
{
	return ut_find_not_dot(dei, n, 0);
}

static const struct ut_dirent_info *
ut_find_any_not_dot(const struct ut_dirent_info *dei, size_t n)
{
	return ut_find_not_dot(dei, n, n / 2);
}

static void ut_expect_name_exists(const struct ut_dirent_info *dei,
                                  size_t n, const char *name)
{
	bool name_exists = false;

	while ((n-- > 0) && !name_exists) {
		name_exists = (strcmp(dei->de.d_name, name) == 0);
		++dei;
	}
	ut_expect(name_exists);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_open_release(struct ut_env *ute)
{
	ino_t ino;
	struct stat st;
	const char *name = UT_NAME;
	const ino_t parent = UT_ROOT_INO;

	ut_mkdir_ok(ute, parent, name, &st);
	ut_lookup_ok(ute, parent, name, &st);
	ino = st.st_ino;
	ut_opendir_ok(ute, ino);
	ut_releasedir_ok(ute, ino);
	ut_rmdir_ok(ute, parent, name);
	ut_opendir_err(ute, ino, -ENOENT);
	ut_releasedir_err(ute, ino, -ENOENT);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_verify_iter_simple(struct ut_env *ute, const char *pre,
                                  const struct ut_readdir_ctx *rd_ctx)
{
	const char *name;
	const struct ut_dirent_info *dei = rd_ctx->dei;

	ut_expect_ge(rd_ctx->nde, 2);
	ut_expect_eqs(dei[0].de.d_name, ".");
	ut_expect_eqs(dei[1].de.d_name, "..");

	for (size_t i = 0; i < rd_ctx->nde - 2; ++i) {
		name = ut_make_name(ute, pre, i);
		ut_expect_name_exists(dei, rd_ctx->nde, name);
	}
}

static void ut_dir_iter_simple(struct ut_env *ute)
{
	ino_t dino;
	struct stat st;
	const char *name = NULL;
	const char *dname = UT_NAME;
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);
	const size_t count = UT_ARRAY_SIZE(rd_ctx->dei) - 2;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir_ok(ute, dino);
	for (size_t i = 0; i < count; ++i) {
		ut_readdir_ok(ute, dino, 0, rd_ctx);
		ut_expect_eq(rd_ctx->nde, i + 2);

		name = ut_make_name(ute, dname, i);
		ut_mkdir_ok(ute, dino, name, &st);
		ut_readdir_ok(ute, dino, 0, rd_ctx);
		ut_expect_eq(rd_ctx->nde, i + 3);

		ut_fsyncdir_ok(ute, dino);
		ut_verify_iter_simple(ute, dname, rd_ctx);
	}
	for (size_t j = count; j > 0; --j) {
		name = ut_make_name(ute, dname, j - 1);
		ut_rmdir_ok(ute, dino, name);
		ut_readdir_ok(ute, dino, 0, rd_ctx);
		ut_verify_iter_simple(ute, dname, rd_ctx);
	}
	ut_releasedir_ok(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_iter_links_(struct ut_env *ute, size_t count)
{
	loff_t doff;
	ino_t ino;
	ino_t dino;
	ino_t dino2;
	const char *lname = NULL;
	const char *fname = UT_NAME;
	const char *dname = UT_NAME;
	const char *dname2 = "AAA";
	const struct ut_dirent_info *dei;
	struct ut_readdir_ctx *rd_ctx;
	struct stat st;

	/* TODO: Use comp wrappers */
	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir_ok(ute, dino);
	ut_mkdir_at_root(ute, dname2, &dino2);
	ut_opendir_ok(ute, dino2);
	ut_create_only(ute, dino2, fname, &ino);

	rd_ctx = ut_new_readdir_ctx(ute);
	for (size_t i = 0; i < count; ++i) {
		lname = ut_make_name(ute, dname, i);
		ut_link_ok(ute, ino, dino, lname, &st);
		ut_expect_eq(ino, st.st_ino);
		ut_expect_eq(i + 2, st.st_nlink);
		ut_fsyncdir_ok(ute, dino);
	}

	doff = 0;
	for (size_t i = 0; i < count; ++i) {
		ut_readdir_ok(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);

		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_lookup_ok(ute, dino, dei->de.d_name, &st);
		ut_expect_eq(ino, st.st_ino);

		doff = dei->de.d_off + 1;
	}

	doff = 0;
	for (size_t i = 0; i < count; ++i) {
		ut_readdir_ok(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);

		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_unlink_ok(ute, dino, dei->de.d_name);
		ut_lookup_noent(ute, dino, dei->de.d_name);

		doff = dei->de.d_off;
	}

	ut_unlink_ok(ute, dino2, fname);
	ut_releasedir_ok(ute, dino2);
	ut_releasedir_ok(ute, dino);
	ut_rmdir_at_root(ute, dname2);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_iter_links(struct ut_env *ute)
{
	ut_dir_iter_links_(ute, 10);
	ut_dir_iter_links_(ute, 100);
	ut_dir_iter_links_(ute, 1000);
	ut_dir_iter_links_(ute, 10000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_iter_unlink_(struct ut_env *ute, size_t count)
{
	loff_t doff = 0;
	size_t ndents;
	ino_t ino;
	ino_t dino;
	const char *fname = NULL;
	const char *dname = UT_NAME;
	struct stat st;
	const struct ut_dirent_info *dei = NULL;
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);

	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir_ok(ute, dino);

	for (size_t i = 0; i < count; ++i) {
		fname = ut_make_name(ute, dname, i);
		ut_create_only(ute, dino, fname, &ino);
	}
	for (size_t i = 0; i < count; ++i) {
		ut_readdir_ok(ute, dino, doff, rd_ctx);
		ndents = rd_ctx->nde;
		ut_expect_gt(ndents, 0);

		dei = ut_find_any_not_dot(rd_ctx->dei, ndents);
		ut_lookup_ok(ute, dino, dei->de.d_name, &st);
		ut_unlink_ok(ute, dino, dei->de.d_name);

		dei = ut_find_first_not_dot(rd_ctx->dei, ndents);
		doff = dei->de.d_off;
	}

	ut_releasedir_ok(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_iter_unlink(struct ut_env *ute)
{
	ut_dir_iter_unlink_(ute, 10000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_dir_iter_plus_(struct ut_env *ute, size_t count)
{
	ino_t ino;
	ino_t dino;
	uint8_t x = 1;
	loff_t doff = 0;
	struct stat st;
	const char *name = NULL;
	const char *dname = UT_NAME;
	const struct ut_dirent_info *dei;
	struct ut_readdir_ctx *rd_ctx = ut_new_readdir_ctx(ute);

	/* TODO: Use comp wrappers */
	ut_mkdir_at_root(ute, dname, &dino);
	ut_opendir_ok(ute, dino);

	for (size_t i = 0; i < count; ++i) {
		name = ut_make_name(ute, dname, i);
		ut_create_file(ute, dino, name, &ino);
		ut_write_read(ute, ino, &x, 1, (loff_t)i);
		ut_release_file(ute, ino);
	}
	doff = 0;
	for (size_t i = 0; i < count; ++i) {
		ut_readdirplus_ok(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);

		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_lookup_ok(ute, dino, dei->de.d_name, &st);
		ut_expect_gt(dei->attr.st_size, 0);
		ut_expect_eq(dei->attr.st_size, st.st_size);
		ut_expect_eq(dei->attr.st_mode, st.st_mode);
		doff = dei->de.d_off + 1;
	}
	doff = 0;
	for (size_t i = 0; i < count; ++i) {
		ut_readdirplus_ok(ute, dino, doff, rd_ctx);
		ut_expect_gt(rd_ctx->nde, 0);

		dei = ut_find_first_not_dot(rd_ctx->dei, rd_ctx->nde);
		ut_unlink_ok(ute, dino, dei->de.d_name);
		doff = dei->de.d_off;
	}
	ut_releasedir_ok(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_dir_iter_plus(struct ut_env *ute)
{
	ut_dir_iter_plus_(ute, 10);
	ut_dir_iter_plus_(ute, 100);
	ut_dir_iter_plus_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_dir_open_release),
	UT_DEFTEST(ut_dir_iter_simple),
	UT_DEFTEST(ut_dir_iter_links),
	UT_DEFTEST(ut_dir_iter_unlink),
	UT_DEFTEST(ut_dir_iter_plus),
};

const struct ut_tests ut_test_dir_iter = UT_MKTESTS(ut_local_tests);
