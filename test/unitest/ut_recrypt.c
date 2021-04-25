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


static void ut_recrypt_nfiles_(struct ut_env *ute, size_t nfiles)
{
	ino_t ino;
	ino_t dino;
	const char *fname;
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_create_only(ute, dino, fname, &ino);
	}
	ut_recrypt_flip_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_lookup_ino(ute, dino, fname, &ino);
	}
	ut_recrypt_flip_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, name, i);
		ut_remove_link(ute, dino, fname);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_recrypt_nfiles(struct ut_env *ute)
{
	ut_recrypt_nfiles_(ute, 64);
	ut_recrypt_nfiles_(ute, 1024);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_recrypt_with_data_(struct ut_env *ute, size_t nfiles)
{
	ino_t ino;
	ino_t dino;
	size_t uoff;
	const char *fname = NULL;
	const char *name = UT_NAME;
	const size_t mega = VOLUTA_UMEGA;

	ut_mkdir_at_root(ute, name, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		uoff = ((mega * i) + i);
		fname = ut_make_name(ute, name, uoff);
		ut_create_file(ute, dino, fname, &ino);
		ut_write_read(ute, ino, fname, strlen(fname), (loff_t)uoff);
		ut_release_file(ute, ino);
	}
	ut_recrypt_flip_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		uoff = ((mega * i) + i);
		fname = ut_make_name(ute, name, uoff);
		ut_lookup_ino(ute, dino, fname, &ino);
		ut_open_rdonly(ute, ino);
		ut_read_verify(ute, ino, fname, strlen(fname), (loff_t)uoff);
		ut_release_file(ute, ino);
	}
	ut_recrypt_flip_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		uoff = ((mega * i) + i);
		fname = ut_make_name(ute, name, uoff);
		ut_lookup_ino(ute, dino, fname, &ino);
		ut_open_rdonly(ute, ino);
		ut_read_verify(ute, ino, fname, strlen(fname), (loff_t)uoff);
		ut_release_file(ute, ino);
		ut_remove_link(ute, dino, fname);
	}
	ut_rmdir_at_root(ute, name);
}

static void ut_recrypt_with_data(struct ut_env *ute)
{
	ut_recrypt_with_data_(ute, 10);
	ut_recrypt_with_data_(ute, 1000);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_recrypt_nfiles),
	UT_DEFTEST(ut_recrypt_with_data),
};

const struct ut_tests ut_test_recrypt = UT_MKTESTS(ut_local_tests);
