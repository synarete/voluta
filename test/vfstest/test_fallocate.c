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
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include "vfstest.h"


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to successfully allocate space, and return EBADF if
 * fd is not opened for writing.
 */
static void test_fallocate_basic(struct vt_env *vte)
{
	int fd = -1;
	loff_t len = VT_BK_SIZE;
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	vt_fallocate(fd, 0, 0, len);
	vt_close(fd);
	vt_open(path, O_RDONLY, 0, &fd);
	vt_fallocate_err(fd, 0, len, 2 * len, -EBADF);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to successfully allocate space for file's sub-ranges.
 */
static void test_fallocate_(struct vt_env *vte, loff_t off, ssize_t len)
{
	int fd = -1;
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_creat(path, 0600, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);
	vt_fallocate(fd, 0, off, len);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + len);
	vt_expect_gt(st.st_blocks, 0);
	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_aligned(struct vt_env *vte)
{
	test_fallocate_(vte, 0, VT_BK_SIZE);
	test_fallocate_(vte, 0, VT_UMEGA);
	test_fallocate_(vte, VT_UMEGA, VT_BK_SIZE);
	test_fallocate_(vte, VT_UGIGA, VT_UMEGA);
	test_fallocate_(vte, VT_UTERA, VT_UMEGA);
}

static void test_fallocate_unaligned(struct vt_env *vte)
{
	test_fallocate_(vte, 0, 1);
	test_fallocate_(vte, 0, VT_BK_SIZE - 1);
	test_fallocate_(vte, 0, VT_UMEGA - 1);
	test_fallocate_(vte, VT_BK_SIZE, VT_BK_SIZE - 1);
	test_fallocate_(vte, 1, VT_BK_SIZE + 3);
	test_fallocate_(vte, VT_BK_SIZE - 1, VT_BK_SIZE + 3);
	test_fallocate_(vte, 1, VT_UMEGA + 3);
	test_fallocate_(vte, VT_UMEGA - 1, VT_UMEGA + 3);
	test_fallocate_(vte, VT_UGIGA - 11, VT_UMEGA + 11);
	test_fallocate_(vte, VT_UTERA - 111, VT_UMEGA + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) to report allocated space as zero
 */
static void test_fallocate_zeros_(struct vt_env *vte,
				  loff_t off, ssize_t len)
{
	int fd = -1;
	uint8_t byte = 1;
	uint8_t zero = 0;
	uint8_t ab = 0xAB;
	struct stat st;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, len);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off + len);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, off + len - 1);
	vt_expect_eq(byte, zero);
	vt_pwriten(fd, &ab, 1, off);
	vt_preadn(fd, &byte, 1, off + 1);
	vt_expect_eq(byte, zero);
	vt_pwriten(fd, &ab, 1, off + len - 1);
	vt_preadn(fd, &byte, 1, off + len - 2);
	vt_expect_eq(byte, zero);
	vt_unlink(path);
	vt_close(fd);
}

static void test_fallocate_zeros(struct vt_env *vte)
{
	test_fallocate_zeros_(vte, 0, VT_BK_SIZE / 2);
	test_fallocate_zeros_(vte, 0, VT_BK_SIZE);
	test_fallocate_zeros_(vte, 0, VT_UMEGA);
	test_fallocate_zeros_(vte, VT_UMEGA, VT_BK_SIZE);
	test_fallocate_zeros_(vte, VT_UGIGA, VT_UMEGA);
	test_fallocate_zeros_(vte, VT_UTERA, VT_UMEGA);
	test_fallocate_zeros_(vte, 1, VT_UMEGA + 3);
	test_fallocate_zeros_(vte, VT_UMEGA - 1, VT_UMEGA + 11);
	test_fallocate_zeros_(vte, VT_UGIGA - 11, VT_UMEGA + 111);
	test_fallocate_zeros_(vte, VT_UTERA - 111, VT_UMEGA + 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) and ftruncate(2) to be synchronized.
 */
static void test_fallocate_truncate_(struct vt_env *vte,
				     loff_t off, ssize_t len)
{
	int fd = -1;
	uint8_t byte = 1;
	uint8_t zero = 0;
	uint16_t abcd = 0xABCD;
	const loff_t mid = off + (len / 2);
	const loff_t end = off + len;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, len);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, end - 1);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, mid);
	vt_expect_eq(byte, zero);
	vt_ftruncate(fd, mid);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, mid - 1);
	vt_expect_eq(byte, zero);
	vt_ftruncate(fd, end);
	vt_preadn(fd, &byte, 1, end - 1);
	vt_expect_eq(byte, zero);
	vt_pwriten(fd, &abcd, 2, mid);
	vt_preadn(fd, &byte, 1, off);
	vt_expect_eq(byte, zero);
	vt_preadn(fd, &byte, 1, end - 1);
	vt_expect_eq(byte, zero);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_truncate(struct vt_env *ut_env)
{
	test_fallocate_truncate_(ut_env, 0, VT_BK_SIZE / 4);
	test_fallocate_truncate_(ut_env, 3, VT_BK_SIZE / 3);
	test_fallocate_truncate_(ut_env, VT_BK_SIZE / 2, VT_BK_SIZE);
	test_fallocate_truncate_(ut_env, 0, VT_BK_SIZE);
	test_fallocate_truncate_(ut_env, 11, VT_BK_SIZE);
	test_fallocate_truncate_(ut_env, 11, VT_UMEGA + 111);
	test_fallocate_truncate_(ut_env, 0, VOLUTA_AG_SIZE);
	test_fallocate_truncate_(ut_env, VT_MEGA - 1, VOLUTA_AG_SIZE + 2);
	test_fallocate_truncate_(ut_env, VT_GIGA, VT_UMEGA);
	test_fallocate_truncate_(ut_env, VT_TERA - 2, VOLUTA_AG_SIZE + 3);
	test_fallocate_truncate_(ut_env, VT_TERA - 1111, VT_UMEGA + 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) with FALLOC_FL_PUNCH_HOLE to return zeros on hole
 */
static void test_fallocate_punch_hole_(struct vt_env *vte,
				       loff_t data_off, size_t data_len,
				       loff_t hole_off, size_t hole_len)
{
	int fd = -1;
	loff_t pos;
	size_t nwr;
	size_t nrd;
	uint8_t byte;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	const void *buf =  vt_new_buf_rands(vte, data_len);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwrite(fd, buf, data_len, data_off, &nwr);
	vt_expect_eq(nwr, data_len);
	vt_fallocate(fd, mode, hole_off, (loff_t)hole_len);
	vt_pread(fd, &byte, 1, hole_off, &nrd);
	vt_expect_eq(nrd, 1);
	vt_expect_eq(byte, 0);
	pos = hole_off + (loff_t)(hole_len - 1);
	vt_pread(fd, &byte, 1, pos, &nrd);
	vt_expect_eq(nrd, 1);
	vt_expect_eq(byte, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_punch_hole(struct vt_env *vte)
{
	test_fallocate_punch_hole_(vte, 0, 1024, 0, 512);
	test_fallocate_punch_hole_(vte, 0, VT_BK_SIZE, 0, 32);
	test_fallocate_punch_hole_(vte, 0, VT_BK_SIZE, 1, 17);
	test_fallocate_punch_hole_(vte, VT_BK_SIZE, VT_BK_SIZE,
				   VT_BK_SIZE + 1, VT_BK_SIZE - 2);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests fallocate(2) with FALLOC_FL_PUNCH_HOLE on various corner cases
 */
static void
test_fallocate_punch_into_hole_(struct vt_env *vte, loff_t base_off)
{
	int fd;
	size_t nrd;
	struct stat st[2];
	const size_t size = VT_UMEGA;
	const loff_t zlen = VT_UMEGA / 4;
	const loff_t off = base_off;
	const loff_t off_end = base_off + (loff_t)size;
	void *buf1 = vt_new_buf_rands(vte, size);
	void *buf2 = vt_new_buf_zeros(vte, size);
	void *buf3 = vt_new_buf_rands(vte, size);
	const char *path = vt_new_path_unique(vte);
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_ftruncate(fd, off_end);
	vt_fallocate(fd, mode, off, zlen);
	vt_fstat(fd, &st[0]);
	vt_expect_eq(st[0].st_blocks, 0);
	vt_pread(fd, buf1, size, off, &nrd);
	vt_expect_eq(nrd, size);
	vt_expect_eqm(buf1, buf2, size);
	vt_fallocate(fd, mode, off_end - zlen, zlen);
	vt_pread(fd, buf1, size, off_end - zlen, &nrd);
	vt_expect_eq(nrd, zlen);
	vt_expect_eqm(buf1, buf2, (size_t)zlen);
	vt_pwrite(fd, buf3, (size_t)zlen, off, &nrd);
	vt_expect_eq(nrd, zlen);
	vt_fstat(fd, &st[0]);
	vt_expect_gt(st[0].st_blocks, 0);
	vt_fallocate(fd, mode, off + zlen, zlen);
	vt_fstat(fd, &st[1]);
	vt_expect_eq(st[0].st_blocks, st[1].st_blocks);
	vt_fallocate(fd, mode, off, zlen);
	vt_fstat(fd, &st[0]);
	vt_expect_lt(st[0].st_blocks, st[1].st_blocks);
	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_punch_into_hole(struct vt_env *vte)
{
	test_fallocate_punch_into_hole_(vte, 0);
	test_fallocate_punch_into_hole_(vte, VT_UMEGA);
	test_fallocate_punch_into_hole_(vte, VT_UMEGA - 1);
	test_fallocate_punch_into_hole_(vte, VT_UGIGA);
	test_fallocate_punch_into_hole_(vte, VT_UGIGA + 1);
	test_fallocate_punch_into_hole_(vte, VT_UTERA);
	test_fallocate_punch_into_hole_(vte, VT_UTERA - 1);
	test_fallocate_punch_into_hole_(vte, VT_FILESIZE_MAX / 2);
	test_fallocate_punch_into_hole_(vte, (VT_FILESIZE_MAX / 2) + 1);
}

static void test_fallocate_punch_into_allocated(struct vt_env *vte)
{
	int fd = -1;
	loff_t pos;
	size_t nwr = 0;
	size_t nrd = 0;
	const size_t size = 20 * VT_UKILO;
	const size_t nzeros = 4 * VT_UKILO;
	const loff_t off = (loff_t)nzeros;
	const char *path = vt_new_path_unique(vte);
	char *buf1 = vt_new_buf_rands(vte, size);
	char *buf2 = vt_new_buf_zeros(vte, size);
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_ftruncate(fd, (loff_t)size);
	vt_pwrite(fd, buf2, nzeros, off, &nwr);
	vt_expect_eq(nwr, nzeros);
	vt_pread(fd, buf1, size, 0, &nrd);
	vt_expect_eq(nrd, size);
	vt_expect_eqm(buf1, buf2, size);
	vt_llseek(fd, 0, SEEK_SET, &pos);
	vt_expect_eq(pos, 0);
	vt_llseek(fd, 0, SEEK_DATA, &pos);
	vt_expect_eq(pos, off);
	vt_fallocate(fd, mode, off, off);
	vt_pread(fd, buf1, size, 0, &nrd);
	vt_expect_eq(nrd, size);
	vt_expect_eqm(buf1, buf2, size);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests fallocate(2) with FALLOC_FL_COLLAPSE_RANGE on continues range.
 */
static void test_collpase_range_continues(struct vt_env *vte, loff_t base)
{
	int fd = -1;
	loff_t off1 = -1;
	loff_t off2 = -1;
	loff_t off3 = -1;
	loff_t slen1 = 0;
	loff_t slen2 = 0;
	loff_t slen3 = 0;
	size_t nwr = 0;
	size_t nrd = 0;
	size_t len1 = 0;
	size_t len2 = 0;
	size_t len3 = 0;
	size_t len4 = 0;
	char *buf1 = NULL;
	char *buf2 = NULL;
	char *buf3 = NULL;
	char *buf4 = NULL;
	struct stat st;
	const int mode = FALLOC_FL_COLLAPSE_RANGE;
	char *path =  vt_new_path_unique(vte);

	off1 = base;
	len1 = 32 * VT_BK_SIZE;
	slen1 = (loff_t)len1;
	buf1 = vt_new_buf_rands(vte, len1);
	off2 = off1 + (loff_t)(len1);
	len2 = 16 * VT_BK_SIZE;
	slen2 = (loff_t)len2;
	buf2 = vt_new_buf_rands(vte, len2);
	off3 = off2 + (loff_t)(len2);
	len3 = 8 * VT_BK_SIZE;
	slen3 = (loff_t)len3;
	buf3 = vt_new_buf_rands(vte, len3);
	len4 = len1 + len2 + len3;
	buf4 = vt_new_buf_rands(vte, len4);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwrite(fd, buf1, len1, off1, &nwr);
	vt_expect_eq(nwr, len1);
	vt_pwrite(fd, buf2, len2, off2, &nwr);
	vt_expect_eq(nwr, len2);
	vt_pwrite(fd, buf3, len3, off3, &nwr);
	vt_expect_eq(nwr, len3);

	vt_fallocate(fd, mode, off2, slen2);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off1 + slen1 + slen3);
	vt_pread(fd, buf4, len1 + len3, off1, &nrd);
	vt_expect_eq(nrd, len1 + len3);
	vt_expect_eqm(buf1, buf4, len1);

	vt_fallocate(fd, mode, off1, slen1);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off1 + slen3);
	vt_pread(fd, buf4, len3, off1, &nrd);
	vt_expect_eq(nrd, len3);
	vt_expect_eqm(buf3, buf4, len3);

	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_collpase_range_simple(struct vt_env *vte)
{
	test_collpase_range_continues(vte, 0);
	test_collpase_range_continues(vte, VT_BK_SIZE);
	test_collpase_range_continues(vte, VT_UMEGA);
	test_collpase_range_continues(vte, VT_UGIGA);
}

/*
 * Tests fallocate(2) with FALLOC_FL_COLLAPSE_RANGE on range with holes.
 */
static void test_collpase_range_with_holes(struct vt_env *vte, loff_t base,
		loff_t holesz)
{
	int fd = -1;
	loff_t off1 = -1;
	loff_t off2 = -1;
	loff_t off3 = -1;
	loff_t slen1 = -1;
	loff_t slen2 = -1;
	loff_t slen3 = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	size_t len1 = 0;
	size_t len2 = 0;
	size_t len3 = 0;
	size_t len4 = 0;
	char *buf1 = NULL;
	char *buf2 = NULL;
	char *buf3 = NULL;
	char *buf4 = NULL;
	struct stat st;
	const char *path = vt_new_path_unique(vte);
	const int mode = FALLOC_FL_COLLAPSE_RANGE;

	off1 = base;
	len1 = 32 * VT_BK_SIZE;
	slen1 = (loff_t)len1;
	buf1 = vt_new_buf_rands(vte, len1);
	off2 = off1 + holesz + slen1;
	len2 = 16 * VT_BK_SIZE;
	slen2 = (loff_t)len2;
	buf2 = vt_new_buf_rands(vte, len2);
	off3 = off2 + holesz + slen2;
	len3 = 8 * VT_BK_SIZE;
	slen3 = (loff_t)len3;
	buf3 = vt_new_buf_rands(vte, len3);
	len4 = len1 + len2 + len3;
	buf4 = vt_new_buf_rands(vte, len4);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwrite(fd, buf1, len1, off1, &nwr);
	vt_expect_eq(nwr, len1);
	vt_pwrite(fd, buf2, len2, off2, &nwr);
	vt_expect_eq(nwr, len2);
	vt_pwrite(fd, buf3, len3, off3, &nwr);
	vt_expect_eq(nwr, len3);

	vt_fallocate(fd, mode, off3 - holesz, holesz);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off3 + slen3 - holesz);
	vt_fallocate(fd, mode, off2 - holesz, holesz);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off1 + slen1 + slen2 + slen3);
	vt_pread(fd, buf4, len4, off1, &nrd);
	vt_expect_eq(nrd, len4);
	vt_expect_eqm(buf1, buf4, len1);
	vt_expect_eqm(buf2, &buf4[len1], len2);
	vt_expect_eqm(buf3, &buf4[len1 + len2], len3);

	vt_fallocate(fd, mode, off1, slen1);
	vt_fallocate(fd, mode, off1, slen2);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, off1 + slen3);
	vt_pread(fd, buf4, len3, off1, &nrd);
	vt_expect_eq(nrd, len3);
	vt_expect_eqm(buf3, buf4, len3);

	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_collpase_range_holes(struct vt_env *vte)
{
	test_collpase_range_with_holes(vte, 0, VT_BK_SIZE);
	test_collpase_range_with_holes(vte, VT_BK_SIZE, VT_BK_SIZE);
	test_collpase_range_with_holes(vte, VT_UMEGA, VT_BK_SIZE);
	test_collpase_range_with_holes(vte, VT_UGIGA, VT_BK_SIZE);
	test_collpase_range_with_holes(vte, 0, VT_UMEGA);
	test_collpase_range_with_holes(vte, VT_BK_SIZE, VT_UMEGA);
	test_collpase_range_with_holes(vte, VT_UMEGA, VT_UMEGA);
	test_collpase_range_with_holes(vte, VT_UGIGA, VT_UMEGA);
}

/*
 * Tests fallocate(2) with FALLOC_FL_ZERO_RANGE on range with data
 */
struct vt_zero_range_info {
	loff_t data_off;
	size_t data_sz;
	loff_t zero_off;
	size_t zero_sz;
};

static void test_zero_range_data_(struct vt_env *vte,
				  const struct vt_zero_range_info *zri)
{
	int fd = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	size_t len1 = 0;
	size_t len2 = 0;
	size_t pos0 = 0;
	size_t pos1 = 0;
	size_t pos2 = 0;
	const loff_t data_off = zri->data_off;
	const size_t data_sz = zri->data_sz;
	const loff_t zero_off = zri->zero_off;
	const size_t zero_sz = zri->zero_sz;
	const char *path = vt_new_path_unique(vte);
	uint8_t *data_buf1 = vt_new_buf_rands(vte, data_sz);
	uint8_t *data_buf2 = vt_new_buf_rands(vte, data_sz);
	uint8_t *zeros_buf = vt_new_buf_zeros(vte, zero_sz);
	const int mode = FALLOC_FL_ZERO_RANGE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwrite(fd, data_buf1, data_sz, data_off, &nwr);
	vt_fallocate(fd, mode, zero_off, (loff_t)zero_sz);
	vt_pread(fd, data_buf2, data_sz, data_off, &nrd);

	len1 = (size_t)(zero_off - data_off);
	pos1 = len1;
	pos2 = pos1 + zero_sz;
	len2 = (size_t)(data_sz - pos2);
	vt_expect_eqm(data_buf2 + pos0, data_buf1 + pos0, len1);
	vt_expect_eqm(data_buf2 + pos1, zeros_buf, zero_sz);
	vt_expect_eqm(data_buf1 + pos2, data_buf2 + pos2, len2);

	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static const struct vt_zero_range_info s_zero_ranges[] = {
	{ 0, VT_BK_SIZE, 1, VT_BK_SIZE - 1 },
	{ 0, 2 * VT_BK_SIZE, VT_BK_SIZE - 1, 2 },
	{
		(2 * VT_BK_SIZE) - 3, 3 * VT_BK_SIZE,
		(3 * VT_BK_SIZE) - 1, VT_BK_SIZE + 3
	},
	{ 0, VT_UMEGA, 0, VT_BK_SIZE },
	{ 1, VT_UMEGA, 3, 3 * VT_BK_SIZE },
	{ VT_UMEGA - 13, VT_UMEGA + 29, VT_UMEGA - 11, VT_UMEGA },
	{ VT_UGIGA - 11, VT_UMEGA + 11, VT_UGIGA - 3, VT_UMEGA + 3 }
};

static void test_fallocate_zero_range_data(struct vt_env *vte)
{
	for (size_t i = 0; i < VT_ARRAY_SIZE(s_zero_ranges); ++i) {
		test_zero_range_data_(vte, &s_zero_ranges[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects fallocate(2) on sparse file change size and blocks count. Expects
 * wrtie-on-fallocated to change none.
 */
static void test_fallocate_sparse_(struct vt_env *vte,
				   loff_t base_off, loff_t step_size)
{
	int fd = -1;
	size_t nwr = 0;
	size_t nrd = 0;
	loff_t off = -1;
	loff_t len = 0;
	loff_t tmp = 0;
	blkcnt_t blocks = 0;
	struct stat st;
	const char *path = vt_new_path_unique(vte);
	const long cnt = 1024;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fstat(fd, &st);
	vt_expect_eq(st.st_size, 0);
	vt_expect_eq(st.st_blocks, 0);

	blocks = 0;
	off = base_off;
	for (long i = 0; i < cnt; ++i) {
		off = base_off + (i * step_size);
		len = (int)sizeof(off);
		vt_fallocate(fd, 0, off, len);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off + len);
		vt_expect_gt(st.st_blocks, blocks);
		vt_pread(fd, &tmp, (size_t)len, off, &nrd);
		vt_expect_eq(nrd, len);
		vt_expect_eq(tmp, 0);
		blocks = st.st_blocks;
		vt_pwrite(fd, &off, (size_t)len, off, &nwr);
		vt_expect_eq(nwr, len);
		vt_fstat(fd, &st);
		vt_expect_eq(st.st_size, off + len);
		vt_expect_eq(st.st_blocks, blocks);
		vt_pread(fd, &tmp, (size_t)len, off, &nrd);
		vt_expect_eq(nrd, len);
		vt_expect_eq(tmp, off);
	}
	vt_ftruncate(fd, 0);
	vt_close(fd);
	vt_unlink(path);
}

static void test_fallocate_sparse(struct vt_env *vte)
{
	test_fallocate_sparse_(vte, 0, VT_UMEGA);
	test_fallocate_sparse_(vte, 1, VT_UMEGA);
	test_fallocate_sparse_(vte, VT_UMEGA, VT_UGIGA);
	test_fallocate_sparse_(vte, 11 * VT_UMEGA + 1, VT_UGIGA);
	test_fallocate_sparse_(vte, VT_UTERA - 111, VT_UGIGA);
	test_fallocate_sparse_(vte, VT_FILESIZE_MAX / 2, VT_UGIGA);
	test_fallocate_sparse_(vte, (VT_FILESIZE_MAX / 2) - 11,
			       VT_UGIGA + 111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_fallocate_basic),
	VT_DEFTEST(test_fallocate_aligned),
	VT_DEFTEST(test_fallocate_unaligned),
	VT_DEFTEST(test_fallocate_zeros),
	VT_DEFTEST(test_fallocate_truncate),
	VT_DEFTEST(test_fallocate_punch_hole),
	VT_DEFTEST(test_fallocate_sparse),
	VT_DEFTEST(test_fallocate_punch_into_hole),

	/* Unsupported, yet */
	VT_DEFTESTF(test_fallocate_punch_into_allocated, VT_IO_EXTRA),
	VT_DEFTESTF(test_fallocate_collpase_range_simple, VT_IO_EXTRA),
	VT_DEFTESTF(test_fallocate_collpase_range_holes, VT_IO_EXTRA),
	VT_DEFTESTF(test_fallocate_zero_range_data, VT_IO_EXTRA),
};

const struct vt_tests vt_test_fallocate = VT_DEFTESTS(vt_local_tests);
