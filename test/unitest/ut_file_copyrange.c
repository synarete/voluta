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


static void ut_file_copy_range_simple_(struct ut_env *ute,
                                       loff_t off, size_t bsz)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf = ut_randbuf(ute, bsz);

	return; /*XXX*/

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, bsz, off);
	ut_trunacate_file(ute, ino_dst, off + (long)bsz);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, bsz);
	ut_read_verify(ute, ino_dst, buf, bsz, off);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_simple(struct ut_env *ute)
{
	ut_file_copy_range_simple_(ute, 0, UT_1K_SIZE);
}
/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_copy_range_simple),
};

const struct ut_tests ut_test_file_copy_range = UT_MKTESTS(ut_local_tests);
