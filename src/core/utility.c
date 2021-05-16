/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * This file is part of libvoluta
 *
 * Copyright (C) 2020-2021 Shachar Sharon
 *
 * Libvoluta is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Libvoluta is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <uuid/uuid.h>
#include "libvoluta.h"


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void do_burnstack_n(int depth, int nbytes)
{
	char buf[1024];
	const int cnt = voluta_min32((int)sizeof(buf), nbytes);

	if (cnt > 0) {
		memset(buf, 0xF4 ^ depth, (size_t)cnt);
		do_burnstack_n(depth + 1, nbytes - cnt);
	}
}

void voluta_burnstack(void)
{
	do_burnstack_n(0, 2 * (int)voluta_sc_page_size());
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* time */
static void do_clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	int err;

	err = voluta_sys_clock_gettime(clock_id, tp);
	if (err) {
		voluta_panic("clock_gettime failure: clock_id=%ld err=%d",
		             (long)clock_id, err);
	}
}

void voluta_rclock_now(struct timespec *ts)
{
	do_clock_gettime(CLOCK_REALTIME, ts);
}

void voluta_mclock_now(struct timespec *ts)
{
	do_clock_gettime(CLOCK_MONOTONIC, ts);
}

static void timespec_dif(const struct timespec *beg,
                         const struct timespec *end, struct timespec *dif)
{
	dif->tv_sec = end->tv_sec - beg->tv_sec;
	if (end->tv_nsec >= beg->tv_nsec) {
		dif->tv_nsec = end->tv_nsec - beg->tv_nsec;
	} else {
		dif->tv_sec -= 1;
		dif->tv_nsec = beg->tv_nsec - end->tv_nsec;
	}
}

void voluta_mclock_dur(const struct timespec *start, struct timespec *dur)
{
	struct timespec now;

	voluta_mclock_now(&now);
	timespec_dif(start, &now, dur);
}

time_t voluta_time_now(void)
{
	return time(NULL);
}

void voluta_ts_copy(struct timespec *dst, const struct timespec *src)
{
	dst->tv_sec = src->tv_sec;
	dst->tv_nsec = src->tv_nsec;
}

int voluta_ts_gettime(struct timespec *ts, bool realtime)
{
	int err = 0;

	if (realtime) {
		err = voluta_sys_clock_gettime(CLOCK_REALTIME, ts);
	} else {
		ts->tv_sec = time(NULL);
		ts->tv_nsec = 0;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* random generator */
static void do_getentropy(void *buf, size_t len)
{
	int err;

	err = getentropy(buf, len);
	if (err) {
		voluta_panic("getentropy failed err=%d", errno);
	}
}

void voluta_getentropy(void *buf, size_t len)
{
	size_t cnt;
	uint8_t *ptr = buf;
	const uint8_t *end = ptr + len;
	const size_t getentropy_max = 256;

	while (ptr < end) {
		cnt = min((size_t)(end - ptr), getentropy_max);
		do_getentropy(ptr, cnt);
		ptr += cnt;
	}
}

uint32_t voluta_getentropy32(void)
{
	uint32_t r;

	do_getentropy(&r, sizeof(r));
	return r;
}

uint64_t voluta_getentropy64(void)
{
	uint64_t r;

	do_getentropy(&r, sizeof(r));
	return r;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* memory utilities */
static size_t size_to_page_up(size_t sz)
{
	const size_t page_size = (size_t)voluta_sc_page_size();

	return ((sz + page_size - 1) / page_size) * page_size;
}

int voluta_mmap_memory(size_t msz, void **mem)
{
	const size_t size = size_to_page_up(msz);

	return voluta_sys_mmap_anon(size, 0, mem);
}

int voluta_mmap_secure_memory(size_t msz, void **mem)
{
	int err;
	const size_t size = size_to_page_up(msz);

	err = voluta_sys_mmap_anon(size, 0, mem);
	if (err) {
		return err;
	}
	err = voluta_sys_madvise(*mem, size, MADV_DONTDUMP);
	if (err) {
		voluta_munmap_memory(*mem, size);
		return err;
	}
	/* TODO: check error of mlock2 when possible by getrlimit */
	voluta_sys_mlock2(*mem, size, MLOCK_ONFAULT);
	if (err) {
		voluta_munmap_memory(*mem, size);
		return err;
	}
	return 0;
}

void voluta_munmap_memory(void *mem, size_t msz)
{
	if (mem) {
		voluta_sys_munmap(mem, size_to_page_up(msz));
	}
}

void voluta_munmap_secure_memory(void *mem, size_t msz)
{
	if (mem) {
		/* TODO: enable if done mlock
		voluta_sys_munlock(mem, msz);
		*/
		voluta_sys_munmap(mem, msz);
	}
}

void voluta_memzero(void *s, size_t n)
{
	memset(s, 0, n);
}

static size_t alignment_of(size_t sz)
{
	size_t al;

	if (sz <= 512) {
		al = 512;
	} else if (sz <= 1024) {
		al = 1024;
	} else if (sz <= 2048) {
		al = 2048;
	} else {
		al = (size_t)voluta_sc_page_size();
	}
	return al;
}

int voluta_zalloc_aligned(size_t sz, void **out_mem)
{
	errno = 0;
	*out_mem = aligned_alloc(alignment_of(sz), sz);
	if (*out_mem == NULL) {
		return errno ? -errno : -ENOMEM;
	}
	memset(*out_mem, 0, sz);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* buffer */
void voluta_buf_init(struct voluta_buf *buf, void *p, size_t n)
{
	buf->buf = p;
	buf->bsz = n;
	buf->len = 0;
}

size_t voluta_buf_append(struct voluta_buf *buf, const void *ptr, size_t len)
{
	size_t cnt;

	cnt = min(len, voluta_buf_rem(buf));
	memcpy((char *)buf->buf + buf->len, ptr, cnt);
	buf->len += cnt;

	return cnt;
}

void *voluta_buf_end(const struct voluta_buf *buf)
{
	return (char *)buf->buf + buf->len;
}

size_t voluta_buf_rem(const struct voluta_buf *buf)
{
	return (buf->bsz - buf->len);
}

void voluta_buf_seteos(struct voluta_buf *buf)
{
	char *s = buf->buf;

	if (buf->len < buf->bsz) {
		s[buf->len] = '\0';
	}
}
