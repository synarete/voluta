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


static void ut_rootd_getattr(struct ut_env *ute)
{
	struct stat st;

	ut_getattr_ok(ute, UT_ROOT_INO, &st);
	ut_expect(S_ISDIR(st.st_mode));
	ut_expect_eq(st.st_size, VOLUTA_DIR_EMPTY_SIZE);
	ut_expect_eq(st.st_nlink, 2);
}

static void ut_rootd_access(struct ut_env *ute)
{
	ut_access_ok(ute, UT_ROOT_INO, R_OK);
	ut_access_ok(ute, UT_ROOT_INO, X_OK);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_empty(struct ut_env *ute)
{
	size_t fs_size;
	size_t used_bytes;
	size_t used_files;
	const size_t vol_size = (size_t)(ute->args.fs_args.vsize);
	const size_t ag_size = VOLUTA_AG_SIZE;
	struct statvfs stv;

	ut_statfs_ok(ute, UT_ROOT_INO, &stv);
	ut_expect_eq(stv.f_frsize, UT_1K);
	ut_expect_gt(stv.f_blocks, 0);
	ut_expect_gt(stv.f_blocks, stv.f_bfree);
	ut_expect_gt(stv.f_files, stv.f_ffree);

	fs_size = stv.f_frsize * stv.f_blocks;
	ut_expect_eq(fs_size, vol_size);

	used_bytes = (stv.f_blocks - stv.f_bfree) * stv.f_frsize;
	ut_expect_gt(used_bytes, ag_size);
	ut_expect_lt(used_bytes, vol_size);

	used_files = stv.f_files - stv.f_ffree;
	ut_expect_eq(used_files, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_statfs_files_(struct ut_env *ute, size_t cnt)
{
	ino_t ino;
	ino_t dino;
	fsfilcnt_t ffree;
	const char *dname = UT_NAME;
	const char *fname = NULL;
	struct statvfs stv;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_statfs_ok(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, cnt);
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, dname, i);
		ut_create_only(ute, dino, fname, &ino);
		ut_statfs_ok(ute, dino, &stv);
		ut_expect_eq(ffree, stv.f_ffree + 1);
		ffree = stv.f_ffree;
	}
	ut_statfs_ok(ute, dino, &stv);
	ffree = stv.f_ffree;
	ut_expect_gt(ffree, 0);
	for (size_t i = 0; i < cnt; ++i) {
		fname = ut_make_name(ute, dname, i);
		ut_unlink_file(ute, dino, fname);
		ut_statfs_ok(ute, dino, &stv);
		ut_expect_eq(ffree + 1, stv.f_ffree);
		ffree = stv.f_ffree;
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_statfs_files(struct ut_env *ute)
{
	ut_statfs_files_(ute, 100);
	ut_statfs_files_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_rootd_getattr),
	UT_DEFTEST(ut_rootd_access),
	UT_DEFTEST(ut_statfs_empty),
	UT_DEFTEST(ut_statfs_files),
};

const struct ut_tests ut_test_super = UT_MKTESTS(ut_local_tests);

