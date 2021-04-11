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


struct ut_copy_args {
	loff_t off_src;
	size_t len_src;
	loff_t off_dst;
	size_t len_dst;
};

#define COPYARGS1(a_, b_) \
	COPYARGS2(a_, b_, 0, 0)
#define COPYARGS2(a_, b_, c_, d_) \
	{ .off_src = a_, .len_src = b_, .off_dst = c_, .len_dst = d_ }

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_copy_range1_(struct ut_env *ute, loff_t off, size_t len)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf = ut_randbuf(ute, len);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_write_read(ute, ino_src, buf, len, off);
	ut_trunacate_file(ute, ino_dst, off + (long)len);
	ut_copy_file_range_ok(ute, ino_src, off, ino_dst, off, len);
	ut_read_verify(ute, ino_dst, buf, len, off);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_aligned(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		COPYARGS1(0, UT_1K),
		COPYARGS1(UT_1K, 2 * UT_1K),
		COPYARGS1(0, UT_4K),
		COPYARGS1(UT_4K, 8 * UT_4K),
		COPYARGS1(0, UT_64K),
		COPYARGS1(UT_64K, UT_64K),
		COPYARGS1(2 * UT_64K, UT_64K),
		COPYARGS1(UT_MEGA, 2 * UT_64K),
		COPYARGS1(UT_GIGA, UT_MEGA),
		COPYARGS1(UT_TERA, UT_MEGA + UT_64K),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(args); ++i) {
		ut_file_copy_range1_(ute, args[i].off_src, args[i].len_src);
	}
}

static void ut_file_copy_range_unaligned(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		COPYARGS1(1, UT_1K - 1),
		COPYARGS1(2, UT_1K + 2),
		COPYARGS1(3, 3 * UT_1K + 3),
		COPYARGS1(4, UT_4K + 4),
		COPYARGS1(UT_4K - 5, UT_4K + 7),
		COPYARGS1(2 * UT_4K - 5, 3 * UT_4K),
		COPYARGS1(UT_64K - 11, UT_64K + 111),
		COPYARGS1(UT_64K - 111, UT_MEGA + 1111),
		COPYARGS1(UT_MEGA - 1, 11 * UT_64K + 11),
		COPYARGS1(UT_GIGA - 11, UT_MEGA + 111),
		COPYARGS1(UT_TERA - 111, 11 * UT_64K + 111),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(args); ++i) {
		ut_file_copy_range1_(ute, args[i].off_src, args[i].len_src);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_copy_range2_(struct ut_env *ute,
                                 loff_t off_src, size_t len_src,
                                 loff_t off_dst, size_t len_dst)
{
	ino_t dino;
	ino_t ino_src;
	ino_t ino_dst;
	const size_t len_max = max(len_src, len_dst);
	const size_t len_min = min(len_src, len_dst);
	const char *name = UT_NAME;
	const char *name_src = UT_NAME_AT;
	const char *name_dst = UT_NAME_AT;
	void *buf_src = ut_randbuf(ute, len_max);
	void *buf_dst = ut_randbuf(ute, len_max);

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name_src, &ino_src);
	ut_create_file(ute, dino, name_dst, &ino_dst);
	ut_trunacate_file(ute, ino_src, off_src + (int)len_max);
	ut_trunacate_file(ute, ino_dst, off_dst + (int)len_max);
	ut_write_read(ute, ino_src, buf_src, len_src, off_src);
	ut_copy_file_range_ok(ute, ino_src, off_src,
	                      ino_dst, off_dst, len_dst);
	ut_read_verify(ute, ino_dst, buf_src, len_min, off_dst);
	ut_read_zeros(ute, ino_dst, off_dst + (int)len_min, len_dst - len_min);
	ut_write_read(ute, ino_dst, buf_dst, len_dst, off_dst);
	ut_trunacate_file(ute, ino_src, off_src);
	ut_trunacate_file(ute, ino_src, off_src + (int)len_max);
	ut_copy_file_range_ok(ute, ino_src, off_src,
	                      ino_dst, off_dst, len_dst);
	ut_read_zeros(ute, ino_dst, off_dst, len_min);
	ut_remove_file(ute, dino, name_dst, ino_dst);
	ut_remove_file(ute, dino, name_src, ino_src);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_between(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		/* aligned */
		COPYARGS2(0, UT_1K, 0, UT_1K),
		COPYARGS2(0, UT_1K, UT_1K, UT_1K),
		COPYARGS2(UT_1K, UT_1K, 0, UT_1K),
		COPYARGS2(UT_1K, UT_1K, UT_1K, UT_1K),
		COPYARGS2(0, UT_1K, 2 * UT_1K, 2 * UT_1K),
		COPYARGS2(0, UT_4K, 0, UT_4K),
		COPYARGS2(UT_4K, UT_4K, UT_4K, UT_4K),
		COPYARGS2(UT_4K, UT_4K, 2 * UT_4K, 2 * UT_4K),
		COPYARGS2(2 * UT_4K, 4 * UT_4K, UT_4K, 2 * UT_4K),
		COPYARGS2(0, UT_4K, UT_1K, UT_4K),
		COPYARGS2(UT_1K, 2 * UT_4K, UT_4K, 3 * UT_4K),
		COPYARGS2(0, UT_64K, 0, UT_64K),
		COPYARGS2(UT_64K, UT_64K, UT_64K, UT_64K),
		COPYARGS2(UT_MEGA, UT_64K, 0, UT_64K),
		COPYARGS2(UT_MEGA, UT_64K, UT_GIGA, 2 * UT_64K),
		COPYARGS2(UT_TERA, 3 * UT_64K, UT_MEGA, UT_64K),
		COPYARGS2(UT_TERA, 3 * UT_64K, 0, UT_MEGA),
		/* unaligned */
		COPYARGS2(1, UT_1K - 1, 1, UT_1K - 1),
		COPYARGS2(1, UT_1K - 1, 1, UT_1K - 1),
		COPYARGS2(1, UT_1K + 1, UT_1K + 2, UT_1K + 2),
		COPYARGS2(UT_1K + 3, 3 * UT_1K + 1, 3, 3 * UT_1K),
		COPYARGS2(UT_1K + 11, UT_1K + 1, UT_1K - 1, UT_1K),
		COPYARGS2(7, UT_1K + 17, 7 * UT_1K + 1, 17 * UT_1K),
		COPYARGS2(1, UT_4K - 1, 2, UT_4K - 2),
		COPYARGS2(UT_4K + 1, UT_4K + 1, UT_4K + 1, UT_4K + 1),
		COPYARGS2(UT_4K, UT_4K, 2 * UT_4K - 1, 2 * UT_4K + 3),
		COPYARGS2(2 * UT_4K + 2, 4 * UT_4K, UT_4K + 1, UT_4K),
		COPYARGS2(1, UT_4K, UT_1K + 1, UT_4K + 11),
		COPYARGS2(1, UT_64K + 11, 11, UT_64K + 1),
		COPYARGS2(UT_64K + 11, 11 * UT_64K, UT_64K + 1, UT_64K - 11),
		COPYARGS2(UT_MEGA - 1, UT_64K - 2, 1, UT_64K - 3),
		COPYARGS2(UT_MEGA + 11, UT_MEGA, UT_GIGA + 11, UT_MEGA + 1111),
		COPYARGS2(UT_TERA + 111, UT_MEGA + 333, UT_MEGA - 111, 11111),
		COPYARGS2(UT_TERA - 1111, 111111, 1, UT_MEGA + 1111),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(args); ++i) {
		ut_file_copy_range2_(ute, args[i].off_src, args[i].len_src,
		                     args[i].off_dst, args[i].len_dst);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ut_file_copy_range_self_(struct ut_env *ute,
                                     loff_t off_src, size_t len_src,
                                     loff_t off_dst, size_t len_dst)
{
	ino_t dino;
	ino_t ino;
	const size_t len_max = max(len_src, len_dst);
	const size_t len_min = min(len_src, len_dst);
	const loff_t off_max = lmax(off_src, off_dst) + (long)len_max;
	void *buf_src = ut_randbuf(ute, len_src);
	void *buf_dst = ut_randbuf(ute, len_dst);
	const char *name = UT_NAME;

	ut_mkdir_at_root(ute, name, &dino);
	ut_create_file(ute, dino, name, &ino);
	ut_trunacate_file(ute, ino, off_max);
	ut_write_read(ute, ino, buf_src, len_src, off_src);
	ut_copy_file_range_ok(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_verify(ute, ino, buf_src, len_min, off_dst);
	ut_read_zeros(ute, ino, off_dst + (int)len_min, len_dst - len_min);
	ut_write_read(ute, ino, buf_dst, len_dst, off_dst);
	ut_trunacate_file(ute, ino, 0);
	ut_trunacate_file(ute, ino, off_max);
	ut_copy_file_range_ok(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_zeros(ute, ino, off_dst, len_min);
	ut_write_read(ute, ino, buf_src, len_src, off_src);
	ut_copy_file_range_ok(ute, ino, off_src, ino, off_dst, len_dst);
	ut_read_verify(ute, ino, buf_src, len_min, off_dst);
	ut_remove_file(ute, dino, name, ino);
	ut_rmdir_at_root(ute, name);
}

static void ut_file_copy_range_self(struct ut_env *ute)
{
	const struct ut_copy_args args[] = {
		/* aligned */
		COPYARGS2(0, UT_1K, UT_1K, UT_1K),
		COPYARGS2(0, UT_1K, UT_64K, UT_1K),
		COPYARGS2(0, UT_1K, UT_4K, UT_4K),
		COPYARGS2(UT_1K, UT_4K, UT_64K, UT_4K),
		COPYARGS2(UT_64K, UT_64K, 4 * UT_64K, UT_4K),
		COPYARGS2(UT_MEGA, UT_64K, UT_GIGA, UT_MEGA),
		COPYARGS2(UT_GIGA, UT_MEGA, 0, UT_4K),
		COPYARGS2(UT_GIGA, UT_MEGA, UT_TERA, UT_MEGA / 2),
		/* unaligned */
		COPYARGS2(1, UT_1K - 1, 2 * UT_1K + 1, UT_1K + 1),
		COPYARGS2(UT_4K + 1, UT_4K - 1, UT_64K - 1, UT_4K + 1),
		COPYARGS2(2 * UT_64K + 11, UT_64K - 111, UT_MEGA - 1, 11111),
		COPYARGS2(UT_MEGA - 1, 11111, 333, 33333),
		COPYARGS2(UT_GIGA - 111, 11111, UT_64K - 11, UT_64K + 111),
		COPYARGS2(UT_TERA - 1111, 11111, UT_64K - 111, UT_64K + 1111),
	};

	for (size_t i = 0; i < UT_ARRAY_SIZE(args); ++i) {
		ut_file_copy_range_self_(ute, args[i].off_src, args[i].len_src,
		                         args[i].off_dst, args[i].len_dst);
		ut_file_copy_range_self_(ute, args[i].off_dst, args[i].len_dst,
		                         args[i].off_src, args[i].len_src);

	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct ut_testdef ut_local_tests[] = {
	UT_DEFTEST(ut_file_copy_range_aligned),
	UT_DEFTEST(ut_file_copy_range_unaligned),
	UT_DEFTEST(ut_file_copy_range_between),
	UT_DEFTEST(ut_file_copy_range_self),
};

const struct ut_tests ut_test_file_copy_range = UT_MKTESTS(ut_local_tests);
