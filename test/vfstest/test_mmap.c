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
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "vfstest.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * Expects mmap(3p) to successfully establish a mapping between a process'
 * address space and a file.
 */
static void test_mmap_basic_(struct vt_env *vte, loff_t off,
			     size_t nbk)
{
	int fd = -1;
	const int flag = MAP_SHARED;
	const int prot = PROT_READ | PROT_WRITE;
	size_t nwr = 0;
	size_t mlen = VT_BK_SIZE * nbk;
	void *buf = NULL;
	void *addr = NULL;
	const char *path = vt_new_path_unique(vte);

	buf = vt_new_buf_rands(vte, mlen);
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwrite(fd, buf, mlen, off, &nwr);
	vt_expect_eq(mlen, nwr);
	vt_mmap(NULL, mlen, prot, flag, fd, off, &addr);
	vt_expect_eqm(addr, buf, mlen);
	buf = vt_new_buf_rands(vte, mlen);
	memcpy(addr, buf, mlen);
	vt_expect_eqm(addr, buf, mlen);
	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_basic1(struct vt_env *vte)
{
	test_mmap_basic_(vte, 0, 1);
}

static void test_mmap_basic2(struct vt_env *vte)
{
	test_mmap_basic_(vte, 0, 2);
}

static void test_mmap_basic3(struct vt_env *vte)
{
	test_mmap_basic_(vte, VT_BK_SIZE, 3);
}

static void test_mmap_basic4(struct vt_env *vte)
{
	test_mmap_basic_(vte, VT_UMEGA, 4);
}

static void test_mmap_fallocate(struct vt_env *vte)
{
	int fd = -1;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_SHARED;
	size_t mlen = VT_BK_SIZE;
	void *addr;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mlen);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	strncpy((char *)addr, path, mlen);
	vt_expect_eq(strncmp((char *)addr, path, mlen), 0);
	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_simple(struct vt_env *vte)
{
	int fd = -1;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_SHARED;
	size_t mlen = VT_UMEGA;
	void *addr = NULL;
	void *mbuf = vt_new_buf_rands(vte, mlen);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mlen);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	memcpy(addr, mbuf, mlen);
	vt_expect_eqm(addr, mbuf, mlen);
	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_sequential(struct vt_env *vte)
{
	int fd = -1;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_SHARED;
	size_t cnt = 16;
	size_t mmsz;
	char *ptr = NULL;
	void *addr = NULL;
	const size_t bsz = VT_UMEGA;
	const char *path = vt_new_path_unique(vte);
	void *buf = vt_new_buf_rands(vte, bsz);

	mmsz = bsz * cnt;
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mmsz);
	vt_mmap(NULL, mmsz, prot, flag, fd, 0, &addr);

	for (size_t i = 0; i < cnt; ++i) {
		ptr = (char *)addr + (i * bsz);
		memcpy(ptr, buf, bsz);
	}
	for (size_t i = 0; i < cnt; ++i) {
		ptr = (char *)addr + (i * bsz);
		vt_expect_eqm(ptr, buf, bsz);
	}
	vt_munmap(addr, mmsz);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_sparse(struct vt_env *vte)
{
	int fd = -1;
	int prot = PROT_READ | PROT_WRITE;
	int flag = MAP_SHARED;
	size_t bsz, mmsz, nels, nval, nspc;
	uint16_t val1, val2, *ptr, *arr;
	void *addr, *buf;
	const char *path = vt_new_path_unique(vte);

	bsz = VT_BK_SIZE;
	buf = vt_new_buf_rands(vte, bsz);

	nval = (uint16_t)(bsz / sizeof(val1));
	nspc = 256;
	nels = UINT16_MAX * nspc;
	mmsz = nels * sizeof(val1);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mmsz);
	vt_mmap(NULL, mmsz, prot, flag, fd, 0, &addr);

	arr = (uint16_t *)buf;
	ptr = (uint16_t *)addr;
	for (size_t i = 0; i < nval; ++i) {
		val1 = arr[i];
		ptr[val1 * nspc] = val1;
	}
	for (size_t i = 0; i < nval; ++i) {
		val1 = arr[i];
		val2 = ptr[val1 * nspc];
		vt_expect_eq(val1, val2);
	}
	vt_munmap(addr, mmsz);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_msync_at(struct vt_env *vte, loff_t step)
{
	int fd;
	void *addr = NULL;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_SHARED;
	const size_t bsz = 2 * VT_UMEGA;
	const size_t page_size = vt_page_size();
	const loff_t off = step * (loff_t)page_size;
	void *buf = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, off, (loff_t)bsz);
	vt_mmap(NULL, bsz, prot, flag, fd, off, &addr);
	memcpy(addr, buf, bsz);
	vt_msync(addr, bsz, MS_SYNC);
	vt_munmap(addr, bsz);
	vt_mmap(NULL, bsz, prot, flag, fd, off, &addr);
	vt_expect_eqm(addr, buf, bsz);
	vt_munmap(addr, bsz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_msync(struct vt_env *vte)
{
	test_mmap_msync_at(vte, 0);
	test_mmap_msync_at(vte, 1);
	test_mmap_msync_at(vte, 11);
	test_mmap_msync_at(vte, 111);
	test_mmap_msync_at(vte, 1111);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests mmap-ed I/O for unlinked file-path.
 */
static void test_mmap_unlinked(struct vt_env *vte)
{
	int fd = -1;
	int prot = PROT_READ | PROT_WRITE;
	int flag = MAP_SHARED;
	size_t k = 0;
	size_t nn = 2111;
	char *data;
	void *addr;
	struct stat st;
	const size_t mlen = 7 * VT_UMEGA;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mlen);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	vt_unlink(path);
	vt_fstat(fd, &st);

	data = (char *)addr;
	for (size_t i = 0; i < (mlen - nn); i += nn) {
		snprintf(data + i, nn, "%lu", i);
	}
	for (size_t i = 0; i < (mlen - nn); i += nn) {
		vt_expect_eq(1, sscanf(data + i, "%lu", &k));
		vt_expect_eq(i, k);
	}
	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_stat_noent(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests double mmap-ed I/O over same file-path.
 */
static void test_mmap_twice(struct vt_env *vte)
{
	int fd, prot, flag;
	size_t i, cnt, mlen, nn = 2131;
	void *addr;
	uint32_t *dat;
	const char *path = vt_new_path_unique(vte);

	mlen = 11 * VT_UMEGA;
	cnt  = mlen / sizeof(dat[0]);

	prot = PROT_READ | PROT_WRITE;
	flag = MAP_SHARED;
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mlen);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	dat = (uint32_t *)addr;
	for (i = 0; i < (cnt - nn); i += nn) {
		dat[i] = (uint32_t)i;
	}
	vt_munmap(addr, mlen);
	vt_close(fd);

	prot = PROT_READ;
	flag = MAP_SHARED;
	vt_open(path, O_RDONLY, 0, &fd);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	dat = (uint32_t *)addr;
	for (i = 0; i < (cnt - nn); i += nn) {
		vt_expect_eq(i, dat[i]);
	}
	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests write-data followed by read-only mmap
 */
static void test_mmap_after_write_(struct vt_env *vte,
				   loff_t off, size_t bsz)
{
	int fd, prot = PROT_READ, flag = MAP_SHARED;
	void *buf, *mem = NULL;
	size_t nwr = 0;
	const char *path = vt_new_path_unique(vte);

	buf = vt_new_buf_rands(vte, bsz);
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_pwrite(fd, buf, bsz, off, &nwr);
	vt_expect_eq(bsz, nwr);
	vt_close(fd);
	vt_open(path, O_RDONLY, 0600, &fd);
	vt_mmap(NULL, bsz, prot, flag, fd, off, &mem);
	vt_expect_eqm(buf, mem, bsz);
	vt_munmap(mem, bsz);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_before_write_(struct vt_env *vte,
				    loff_t off, size_t bsz)
{
	int fd1, fd2, prot = PROT_READ, flag = MAP_SHARED;
	void *buf, *mem = NULL;
	size_t nwr = 0;
	const char *path = vt_new_path_unique(vte);

	buf = vt_new_buf_rands(vte, bsz);
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_ftruncate(fd1, off + (loff_t)bsz);
	vt_mmap(NULL, bsz, prot, flag, fd1, off, &mem);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_pwrite(fd2, buf, bsz, off, &nwr);
	vt_expect_eq(bsz, nwr);
	vt_expect_eqm(mem, buf, bsz);
	vt_munmap(mem, bsz);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_mmap_after_write(struct vt_env *vte)
{
	test_mmap_after_write_(vte, 0, VT_UMEGA);
	test_mmap_after_write_(vte, 0, 5 * VT_UMEGA + 5);
	test_mmap_after_write_(vte, VT_UMEGA, VT_UMEGA);
	test_mmap_after_write_(vte, VT_UMEGA, 7 * VT_UMEGA + 7);
	test_mmap_after_write_(vte, VT_UGIGA, 11 * VT_UMEGA + 11);
}

static void test_mmap_before_write(struct vt_env *vte)
{
	test_mmap_before_write_(vte, 0, VT_UMEGA);
	test_mmap_before_write_(vte, 0, 5 * VT_UMEGA + 5);
	test_mmap_before_write_(vte, VT_UMEGA, VT_UMEGA);
	test_mmap_before_write_(vte, VT_UMEGA, 7 * VT_UMEGA + 7);
	test_mmap_before_write_(vte, VT_UGIGA, 11 * VT_UMEGA + 11);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests write-data with mmap on both data and holes
 */
static void test_mmap_on_holes_(struct vt_env *vte,
				loff_t base_off, size_t bsz, size_t nsteps)
{
	int fd, prot = PROT_READ | PROT_WRITE, flag = MAP_SHARED;
	void *buf, *mem = NULL;
	uint8_t *dat;
	loff_t len, off, pos, npos;
	size_t mlen, nwr = 0;
	uint64_t num1, num2;
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);

	pos = (loff_t)(2 * nsteps * bsz);
	len = base_off + pos;
	mlen = (size_t)len;
	vt_ftruncate(fd, len);

	buf = vt_new_buf_rands(vte, bsz);
	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;
		vt_pwrite(fd, buf, bsz, off, &nwr);
		vt_expect_eq(bsz, nwr);
	}

	vt_mmap(NULL, mlen, prot, flag, fd, 0, &mem);
	dat = mem;
	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;
		vt_expect_eqm(buf, dat + off, bsz);

		num1 = i + 1;
		npos = off + 1;
		memcpy(dat + npos, &num1, sizeof(num1));
		npos = off + (loff_t)bsz + 1;
		memcpy(dat + npos, &num1, sizeof(num1));
	}


	for (size_t i = 0; i < nsteps; ++i) {
		pos = (loff_t)(2 * i * bsz);
		off = base_off + pos;

		num1 = i + 1;
		npos = off + 1;
		memcpy(&num2, dat + npos, sizeof(num2));
		vt_expect_eq(num1, num2);

		npos = off + (loff_t)bsz + 1;
		memcpy(&num2, dat + npos, sizeof(num2));
		vt_expect_eq(num1, num2);
	}

	vt_munmap(mem, mlen);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_on_holes(struct vt_env *vte)
{
	test_mmap_on_holes_(vte, 0, VT_UMEGA, 3);
	test_mmap_on_holes_(vte, VT_BK_SIZE + 5,
			    5 * VT_BK_SIZE + 5, 5);
	test_mmap_on_holes_(vte, 111 * VT_BK_SIZE + 111, 11111, 111);
	test_mmap_on_holes_(vte, VT_UMEGA, 5 * VT_UMEGA + 5, 5);
	test_mmap_on_holes_(vte, VT_UGIGA, 11 * VT_UMEGA + 11, 11);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Tests mixed mmap and read/write operations
 */
static void test_mmap_rw_mixed_(struct vt_env *vte, size_t bsz)
{
	int fd = -1;
	size_t nrd = 0;
	loff_t off = -1;
	void *addr = NULL;
	char *data = NULL;
	const size_t mlen = 4 * VT_UMEGA;
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_SHARED;
	char *buf1 = vt_new_buf_rands(vte, bsz);
	char *buf2 = vt_new_buf_rands(vte, bsz);
	const char *path = vt_new_path_unique(vte);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_fallocate(fd, 0, 0, (loff_t)mlen);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	vt_expect_ne(addr, NULL);
	data = addr;

	off = 0;
	memcpy(&data[off], buf1, bsz);
	vt_msync(&data[off], bsz, MS_SYNC);
	vt_pread(fd, buf2, bsz, off, &nrd);
	vt_expect_eqm(buf1, buf2, bsz);

	off = (loff_t)(3 * bsz);
	buf1 = vt_new_buf_rands(vte, bsz);
	memcpy(&data[off], buf1, bsz);
	vt_pread(fd, buf2, bsz, off, &nrd);
	vt_expect_eqm(buf1, buf2, bsz);

	off = (loff_t)(11 * bsz);
	buf1 = vt_new_buf_rands(vte, bsz);
	vt_pwrite(fd, buf1, bsz, off, &nrd);
	memcpy(buf2, &data[off], bsz);
	vt_expect_eqm(buf1, buf2, bsz);

	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_rw_mixed(struct vt_env *vte)
{
	test_mmap_rw_mixed_(vte, 4 * VT_KILO);
	test_mmap_rw_mixed_(vte, VT_BK_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * Expects valid semantics for mmap(3p) to file with MAP_PRIVATE
 */
static void test_mmap_private(struct vt_env *vte)
{
	int fd, prot = PROT_READ | PROT_WRITE, flag = MAP_PRIVATE;
	size_t nwr, mlen = 64 * VT_UMEGA;
	void *addr;
	uint8_t *dptr, *data;
	const char *path = vt_new_path_unique(vte);

	data = vt_new_buf_rands(vte, mlen);
	vt_open(path, O_CREAT | O_RDWR, 0600, &fd);
	vt_write(fd, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, flag, fd, 0, &addr);
	dptr = (uint8_t *)addr;
	vt_expect_eqm(dptr, data, mlen);
	vt_munmap(addr, mlen);
	vt_close(fd);
	vt_unlink(path);
}

static void test_mmap_private2(struct vt_env *vte)
{
	int fd1, fd2, prot, flag = MAP_PRIVATE;
	size_t nwr, mlen = 16 * VT_UMEGA;
	char *path;
	void *ad1, *ad2;
	uint8_t *dptr1, *dptr2, *data;

	prot = PROT_READ | PROT_WRITE;
	path = vt_new_path_unique(vte);
	data = vt_new_buf_rands(vte, mlen);

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_write(fd1, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, flag, fd1, 0, &ad1);
	vt_mmap(NULL, mlen, prot, flag, fd2, 0, &ad2);
	dptr1 = (uint8_t *)ad1;
	dptr2 = (uint8_t *)ad2;
	vt_expect_eqm(dptr1, dptr2, mlen);
	vt_munmap(ad1, mlen);
	vt_munmap(ad2, mlen);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void test_mmap_madvise_simple_(struct vt_env *vte, size_t mlen)
{
	int fd1 = -1;
	int fd2 = -1;
	size_t nwr = 0;
	void *addr1 = NULL;
	void *addr2 = NULL;
	void *data = vt_new_buf_rands(vte, mlen);
	const char *path = vt_new_path_unique(vte);
	const int prot = PROT_READ | PROT_WRITE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_write(fd1, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd1, 0, &addr1);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd2, 0, &addr2);
	vt_madvise(addr1, mlen, MADV_RANDOM);
	vt_madvise(addr2, mlen, MADV_SEQUENTIAL);
	vt_expect_eqm(addr1, addr2, mlen);
	vt_munmap(addr1, mlen);
	vt_munmap(addr2, mlen);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_mmap_madvise_simple(struct vt_env *vte)
{
	test_mmap_madvise_simple_(vte, VT_UMEGA);
	test_mmap_madvise_simple_(vte, 16 * VT_UMEGA);
}

static void test_mmap_madvise_dontneed_(struct vt_env *vte, size_t mlen)
{
	int fd1 = -1;
	int fd2 = -1;
	size_t nwr = 0;
	void *addr1 = NULL;
	void *addr2 = NULL;
	void *data = vt_new_buf_rands(vte, mlen);
	const char *path = vt_new_path_unique(vte);
	const int prot = PROT_READ | PROT_WRITE;

	vt_open(path, O_CREAT | O_RDWR, 0600, &fd1);
	vt_open(path, O_RDWR, 0600, &fd2);
	vt_write(fd1, data, mlen, &nwr);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd1, 0, &addr1);
	vt_mmap(NULL, mlen, prot, MAP_SHARED, fd2, 0, &addr2);
	vt_expect_eqm(addr1, addr2, mlen);
	vt_madvise(addr1, mlen, MADV_DONTNEED);
	vt_madvise(addr2, mlen, MADV_DONTNEED);
	vt_suspends(vte, 2);
	vt_expect_eqm(addr1, addr2, mlen);
	vt_munmap(addr1, mlen);
	vt_munmap(addr2, mlen);
	vt_close(fd1);
	vt_close(fd2);
	vt_unlink(path);
}

static void test_mmap_madvise_dontneed(struct vt_env *vte)
{
	test_mmap_madvise_dontneed_(vte, VT_UMEGA);
	test_mmap_madvise_dontneed_(vte, 16 * VT_UMEGA);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct vt_tdef vt_local_tests[] = {
	VT_DEFTEST(test_mmap_basic1),
	VT_DEFTEST(test_mmap_basic2),
	VT_DEFTEST(test_mmap_basic3),
	VT_DEFTEST(test_mmap_basic4),
	VT_DEFTEST(test_mmap_fallocate),
	VT_DEFTEST(test_mmap_simple),
	VT_DEFTEST(test_mmap_sequential),
	VT_DEFTEST(test_mmap_sparse),
	VT_DEFTEST(test_mmap_msync),
	VT_DEFTEST(test_mmap_unlinked),
	VT_DEFTEST(test_mmap_twice),
	VT_DEFTEST(test_mmap_after_write),
	VT_DEFTEST(test_mmap_before_write),
	VT_DEFTEST(test_mmap_on_holes),
	VT_DEFTEST(test_mmap_rw_mixed),
	VT_DEFTEST(test_mmap_private),
	VT_DEFTEST(test_mmap_private2),
	VT_DEFTEST(test_mmap_madvise_simple),
	VT_DEFTEST(test_mmap_madvise_dontneed),
};

const struct vt_tests vt_test_mmap = VT_DEFTESTS(vt_local_tests);

