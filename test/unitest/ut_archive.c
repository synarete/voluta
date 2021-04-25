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


static void ut_export_import_ok(struct ut_env *ute)
{
	int err;
	struct voluta_fs_env *fse = ute->fse;
	struct voluta_archiver *arc = ute->arc;

	err = voluta_fse_sync_drop(fse);
	ut_expect_ok(err);

	err = voluta_fse_term(fse);
	ut_expect_ok(err);

	err = voluta_archiver_export(arc);
	ut_expect_ok(err);

	err = voluta_archiver_import(arc);
	ut_expect_ok(err);

	err = voluta_fse_reload(fse);
	ut_expect_ok(err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_archive_simple(struct ut_env *ute)
{
	ino_t ino;
	ino_t parent = UT_ROOT_INO;
	const char *name = UT_NAME;
	struct stat st;

	ut_mkdir_ok(ute, parent, name, &st);
	ino = st.st_ino;
	ut_export_import_ok(ute);
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
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_archive_nfiles_(struct ut_env *ute, size_t nfiles)
{
	ino_t ino;
	ino_t dino;
	const char *fname;
	const char *dname = UT_NAME;

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, dname, i);
		ut_create_only(ute, dino, fname, &ino);
	}
	ut_export_import_ok(ute);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, dname, i);
		ut_remove_link(ute, dino, fname);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_archive_nfiles(struct ut_env *ute)
{
	ut_archive_nfiles_(ute, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_archive_simple),
	UT_DEFTEST(ut_archive_nfiles),
};

const struct ut_tests ut_test_archive = UT_MKTESTS(ut_local_tests);


