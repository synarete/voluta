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
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "fstests.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects read-write data-consistency upon n-gigbytes write in chunks of 1M
 */
static void test_ngiga_rdwr_(struct vt_env *vte,
                             loff_t off_base, size_t nskip)
{
	int fd;
	loff_t off;
	size_t num;
	const size_t bsz = VT_MEGA;
	const size_t cnt = VT_GIGA / bsz;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	for (size_t i = 0; i < cnt; ++i) {
		num = i + 1;
		off = off_base + (loff_t)(i * (bsz + nskip));

		vt_pwriten(fd, buf, bsz, off);
		vt_pwriten(fd, &num, sizeof(num), off);
	}
	for (size_t i = 0; i < cnt; ++i) {
		num = 0;
		off = off_base + (loff_t)(i * (bsz + nskip));

		vt_preadn(fd, &num, sizeof(num), off);
		vt_expect_eq(num, i + 1);
		vt_preadn(fd, buf, bsz, off);
	}
	vt_close(fd);
	vt_unlink(path);
}

static void test_large_simple(struct vt_env *vte)
{
	test_ngiga_rdwr_(vte, 0, 0);
	test_ngiga_rdwr_(vte, 0, VT_MEGA);
	test_ngiga_rdwr_(vte, VT_TERA, VT_GIGA);
}

static void test_large_unaligned(struct vt_env *vte)
{
	test_ngiga_rdwr_(vte, 1, 1);
	test_ngiga_rdwr_(vte, VT_MEGA - 5, 7 * VT_MEGA + 7);
	test_ngiga_rdwr_(vte, VT_TERA - 11, 11 * VT_MEGA + 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_large_simple),
	VT_DEFTEST(test_large_unaligned),
};

const struct vt_tests vt_test_rw_large = VT_DEFTESTS(vt_local_tests);
