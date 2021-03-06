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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <time.h>

#include "fstests.h"

#define VT_METATEST(t_) (&(t_))

static const struct vt_tests *const vt_testsbl[]  = {
	VT_METATEST(vt_test_access),
	VT_METATEST(vt_test_stat),
	VT_METATEST(vt_test_statvfs),
	VT_METATEST(vt_test_utimes),
	VT_METATEST(vt_test_mkdir),
	VT_METATEST(vt_test_readdir),
	VT_METATEST(vt_test_create),
	VT_METATEST(vt_test_open),
	VT_METATEST(vt_test_link),
	VT_METATEST(vt_test_unlink),
	VT_METATEST(vt_test_chmod),
	VT_METATEST(vt_test_symlink),
	VT_METATEST(vt_test_mkfifo),
	VT_METATEST(vt_test_fsync),
	VT_METATEST(vt_test_rename),
	VT_METATEST(vt_test_xattr),
	VT_METATEST(vt_test_write),
	VT_METATEST(vt_test_lseek),
	VT_METATEST(vt_test_fiemap),
	VT_METATEST(vt_test_truncate),
	VT_METATEST(vt_test_namespace),
	VT_METATEST(vt_test_rw_basic),
	VT_METATEST(vt_test_boundaries),
	VT_METATEST(vt_test_stat_io),
	VT_METATEST(vt_test_rw_sequencial),
	VT_METATEST(vt_test_rw_sparse),
	VT_METATEST(vt_test_rw_random),
	VT_METATEST(vt_test_rw_large),
	VT_METATEST(vt_test_unlinked_file),
	VT_METATEST(vt_test_truncate_io),
	VT_METATEST(vt_test_fallocate),
	VT_METATEST(vt_test_clone),
	VT_METATEST(vt_test_copy_file_range),
	VT_METATEST(vt_test_tmpfile),
	VT_METATEST(vt_test_mmap),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mask_of(const struct vt_env *vte)
{
	return vte->params.testsmask;
}

static void statvfs_of(const struct vt_env *vte, struct statvfs *stvfs)
{
	vt_statvfs(vte->params.workdir, stvfs);
}

static void list_test(struct vt_env *vte, const struct vt_tdef *tdef)
{
	FILE *fp = stdout;

	vte->currtest = tdef;
	fprintf(fp, "  %-40s\n", vte->currtest->name);
	fflush(fp);
}

static void start_test(struct vt_env *vte, const struct vt_tdef *tdef)
{
	FILE *fp = stdout;

	vte->currtest = tdef;
	vte->nbytes_alloc = 0;
	fprintf(fp, "  %-40s", vte->currtest->name);
	fflush(fp);
	voluta_mclock_now(&vte->ts_start);
	statvfs_of(vte, &vte->stvfs);
}

static void finish_test(struct vt_env *vte)
{
	FILE *fp = stdout;
	struct timespec dur;

	voluta_mclock_dur(&vte->ts_start, &dur);
	fprintf(fp, "OK (%ld.%03lds)\n", dur.tv_sec, dur.tv_nsec / 1000000L);
	fflush(fp);

	umask(vte->umsk);
	vte->currtest = NULL;
	vt_freeall(vte);
}

static void verify_consistent_statvfs(const struct statvfs *stv_beg,
                                      const struct statvfs *stv_end)
{
	fsblkcnt_t bfree_dif;

	vt_expect_lt(stv_end->f_bfree, stv_end->f_blocks);
	vt_expect_lt(stv_end->f_bavail, stv_end->f_blocks);
	vt_expect_lt(stv_end->f_ffree, stv_end->f_files);
	vt_expect_lt(stv_end->f_favail, stv_end->f_files);

	vt_expect_eq(stv_beg->f_namemax, stv_end->f_namemax);
	vt_expect_eq(stv_beg->f_flag, stv_end->f_flag);
	vt_expect_eq(stv_beg->f_bsize, stv_end->f_bsize);
	vt_expect_eq(stv_beg->f_frsize, stv_end->f_frsize);
	vt_expect_eq(stv_beg->f_files, stv_end->f_files);
	vt_expect_eq(stv_beg->f_ffree, stv_end->f_ffree);
	vt_expect_eq(stv_beg->f_favail, stv_end->f_favail);
	vt_expect_eq(stv_beg->f_blocks, stv_end->f_blocks);
	vt_expect_ge(stv_beg->f_bfree, stv_end->f_bfree);
	vt_expect_ge(stv_beg->f_bavail, stv_end->f_bavail);

	bfree_dif = stv_beg->f_bfree - stv_end->f_bfree;
	vt_expect_lt(bfree_dif, 4096);
}

static void verify_fsstat(const struct vt_env *vte)
{
	struct statvfs stvfs_end;

	if (mask_of(vte) & VT_VERIFY) {
		sleep(1); /* TODO: race in FUSE? */
		statvfs_of(vte, &stvfs_end);
		verify_consistent_statvfs(&vte->stvfs, &stvfs_end);
	}
}

static void exec_test(struct vt_env *vte,
                      const struct vt_tdef *tdef)
{
	start_test(vte, tdef);
	tdef->hook(vte);
	verify_fsstat(vte);
	finish_test(vte);
}

static void vt_runtests(struct vt_env *vte)
{
	const struct vt_tdef *tdef;
	const struct vt_tests *tests = &vte->tests;
	const struct vt_params *params = &vte->params;

	for (size_t i = 0; i < tests->len; ++i) {
		tdef = &tests->arr[i];
		if (tdef->flags & VT_IGNORE) {
			continue;
		}
		if (params->listtests) {
			list_test(vte, tdef);
		} else if (params->testname) {
			if (strstr(tdef->name, params->testname)) {
				exec_test(vte, tdef);
			}
		} else if (tdef->flags) {
			if (mask_of(vte) & tdef->flags) {
				exec_test(vte, tdef);
			}
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void copy_testdef(struct vt_tdef *dst,
                         const struct vt_tdef *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static void swap_testdef(struct vt_tdef *td1, struct vt_tdef *td2)
{
	struct vt_tdef tmp;

	copy_testdef(&tmp, td1);
	copy_testdef(td1, td2);
	copy_testdef(td2, &tmp);
}

static void *safe_malloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		error(EXIT_FAILURE, errno, "malloc failed: size=%lu", size);
		abort(); /* makes gcc '-fanalyzer' happy */
	}
	return ptr;
}

static struct vt_tdef *alloc_tests_arr(void)
{
	size_t asz;
	size_t cnt = 0;
	struct vt_tdef *arr;
	const size_t nelems = VT_ARRAY_SIZE(vt_testsbl);

	for (size_t i = 0; i < nelems; ++i) {
		cnt += vt_testsbl[i]->len;
	}
	asz = cnt * sizeof(*arr);
	arr = (struct vt_tdef *)safe_malloc(asz);
	memset(arr, 0, asz);

	return arr;
}

static void random_shuffle_tests(struct vt_env *vte)
{
	size_t pos1;
	size_t pos2;
	uint64_t rand;
	struct vt_tests *tests = &vte->tests;
	struct vt_tdef *tests_arr = voluta_unconst(tests->arr);

	for (size_t i = 0; i < tests->len; ++i) {
		rand = (uint64_t)vt_lrand(vte);
		pos1 = (rand ^ i) % tests->len;
		pos2 = (rand >> 32) % tests->len;
		swap_testdef(&tests_arr[pos1], &tests_arr[pos2]);
	}
}

static void vt_clone_tests(struct vt_env *vte)
{
	size_t len = 0;
	struct vt_tdef *arr = alloc_tests_arr();
	const struct vt_tdef *tdef = NULL;
	const size_t nelems = VT_ARRAY_SIZE(vt_testsbl);

	for (size_t i = 0; i < nelems; ++i) {
		for (size_t j = 0; j < vt_testsbl[i]->len; ++j) {
			tdef = &vt_testsbl[i]->arr[j];
			copy_testdef(&arr[len++], tdef);
		}
	}
	vte->tests.arr = arr;
	vte->tests.len = len;
	if (mask_of(vte) & VT_RANDOM) {
		random_shuffle_tests(vte);
	}
}

static void vt_free_tests(struct vt_env *vte)
{
	free(voluta_unconst(vte->tests.arr));
	vte->tests.arr = NULL;
	vte->tests.len = 0;
}

void vte_exec(struct vt_env *vte)
{
	for (int i = 0; i < vte->params.repeatn; ++i) {
		vt_clone_tests(vte);
		vt_runtests(vte);
		vt_free_tests(vte);
	}
}


