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
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include "unitest.h"


static void ut_reload_nfiles_(struct ut_env *ute, size_t nfiles)
{
	ino_t ino;
	ino_t dino;
	const char *fname;
	const char *dname = UT_NAME;

	ut_mkdir_at_root(ute, dname, &dino);
	ut_reload_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_create_only(ute, dino, fname, &ino);
	}
	ut_reload_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_remove_link(ute, dino, fname);
	}
	ut_reload_ok(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_reload_simple(struct ut_env *ute)
{
	ut_reload_nfiles_(ute, 0);
}

static void ut_reload_nfiles(struct ut_env *ute)
{
	ut_reload_nfiles_(ute, 1);
	ut_reload_nfiles_(ute, 11);
	ut_reload_nfiles_(ute, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_reload_mixed_(struct ut_env *ute, size_t nfiles)
{
	ino_t fino;
	ino_t sino;
	ino_t dino;
	ino_t tino;
	const char *name;
	const char *tname = UT_NAME;
	struct stat st;

	ut_mkdir_at_root(ute, tname, &tino);
	ut_reload_ok(ute, tino);
	for (size_t i = 0; i < nfiles; ++i) {
		name = ut_make_name(ute, "d", i);
		ut_mkdir_oki(ute, tino, name, &dino);
		name = ut_make_name(ute, "f", i);
		ut_create_only(ute, dino, name, &fino);
		name = ut_make_name(ute, "s", i);
		ut_symlink_ok(ute, dino, name, tname, &sino);
		ut_reload_ok(ute, dino);
		ut_getattr_reg(ute, fino, &st);
		ut_lookup_lnk(ute, dino, name, sino);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		name = ut_make_name(ute, "d", i);
		ut_lookup_ino(ute, tino, name, &dino);
		ut_getattr_dir(ute, dino, &st);
		name = ut_make_name(ute, "f", i);
		ut_lookup_ino(ute, dino, name, &fino);
		ut_getattr_reg(ute, fino, &st);
		ut_reload_ok(ute, dino);
		ut_remove_link(ute, dino, name);
		name = ut_make_name(ute, "s", i);
		ut_lookup_ino(ute, dino, name, &sino);
		ut_getattr_lnk(ute, sino, &st);
		ut_remove_link(ute, dino, name);
		name = ut_make_name(ute, "d", i);
		ut_rmdir_ok(ute, tino, name);
	}
	ut_reload_ok(ute, tino);
	ut_rmdir_at_root(ute, tname);
}

static void ut_reload_mixed(struct ut_env *ute)
{
	ut_reload_mixed_(ute, 1);
	ut_reload_mixed_(ute, 10);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t make_offset(size_t idx, size_t step)
{
	return (loff_t)((idx * step) + idx);
}

static void ut_reload_io_(struct ut_env *ute, size_t nfiles, size_t step)
{
	ino_t fino;
	ino_t dino;
	loff_t off;
	size_t len;
	const char *fname;
	const char *dname = UT_NAME;
	struct stat st;

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_create_file(ute, dino, fname, &fino);
		len = strlen(fname);
		off = make_offset(i, step);
		ut_write_read(ute, fino, fname, len, off);
		ut_release_file(ute, fino);
	}
	ut_reload_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_lookup_ino(ute, dino, fname, &fino);
		ut_open_rdonly(ute, fino);
		len = strlen(fname);
		off = make_offset(i, step);
		ut_read_verify(ute, fino, fname, len, off);
		ut_trunacate_file(ute, fino, off);
		ut_release_file(ute, fino);
	}
	ut_reload_ok(ute, dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_lookup_ino(ute, dino, fname, &fino);
		off = make_offset(i, step);
		ut_getattr_reg(ute, fino, &st);
		ut_expect_eq(st.st_size, off);
		ut_unlink_ok(ute, dino, fname);
	}
	ut_rmdir_at_root(ute, dname);
}

static void ut_reload_io(struct ut_env *ute)
{
	ut_reload_io_(ute, 1, VOLUTA_BK_SIZE);
	ut_reload_io_(ute, 10, VOLUTA_GIGA);
	ut_reload_io_(ute, 100, VOLUTA_MEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_reload_unlinked_(struct ut_env *ute,
                                size_t nfiles, size_t step)
{
	ino_t fino;
	ino_t dino;
	loff_t off;
	size_t len;
	const char *fname;
	const char *dname = UT_NAME;
	ino_t *fino_arr = ut_zalloc(ute, nfiles * sizeof(ino_t));

	ut_mkdir_at_root(ute, dname, &dino);
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		ut_create_file(ute, dino, fname, &fino);
		fino_arr[i] = fino;
		len = strlen(fname);
		off = make_offset(i, step);
		ut_write_read(ute, fino, fname, len, off);
		ut_unlink_file(ute, dino, fname);
	}
	for (size_t i = 0; i < nfiles; ++i) {
		fname = ut_make_name(ute, "f", i);
		fino = fino_arr[i];
		len = strlen(fname);
		off = make_offset(i, step);
		ut_read_verify(ute, fino, fname, len, off);
		ut_release_file(ute, fino);
	}
	ut_reload_ok(ute, dino);
	ut_rmdir_at_root(ute, dname);
}

static void ut_reload_unlinked(struct ut_env *ute)
{
	ut_reload_unlinked_(ute, 10, VOLUTA_GIGA - 1);
	ut_reload_unlinked_(ute, 1000, VOLUTA_MEGA - 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_reload_simple),
	UT_DEFTEST(ut_reload_nfiles),
	UT_DEFTEST(ut_reload_mixed),
	UT_DEFTEST(ut_reload_io),
	UT_DEFTEST(ut_reload_unlinked),
};

const struct ut_tests ut_test_reload = UT_MKTESTS(ut_local_tests);
