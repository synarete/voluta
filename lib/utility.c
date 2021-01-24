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
#include <ctype.h>
#include <time.h>
#include <uuid/uuid.h>
#include "libvoluta.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void *voluta_unconst(const void *p)
{
	union {
		const void *p;
		void *q;
	} u = {
		.p = p
	};

	return u.q;
}

size_t voluta_min(size_t x, size_t y)
{
	return min(x, y);
}

size_t voluta_max(size_t x, size_t y)
{
	return max(x, y);
}

size_t voluta_clamp(size_t v, size_t lo, size_t hi)
{
	return clamp(v, lo, hi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void do_burnstack_n(int depth, size_t nbytes)
{
	char buf[1024];
	const size_t cnt = min(sizeof(buf), nbytes);

	if (cnt > 0) {
		memset(buf, 0xF4 ^ depth, cnt);
		do_burnstack_n(depth + 1, nbytes - cnt);
	}
}

void voluta_burnstack(void)
{
	do_burnstack_n(0, 2 * voluta_sc_page_size());
}

size_t voluta_clz(uint32_t n)
{
	return n ? (size_t)__builtin_clz(n) : 32;
}

size_t voluta_popcount(uint32_t n)
{
	return n ? (size_t)__builtin_popcount(n) : 0;
}

size_t voluta_popcount64(uint64_t n)
{
	return n ? (size_t)__builtin_popcountl(n) : 0;
}

size_t voluta_sc_l1_dcache_linesize(void)
{
	return (size_t)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
}

size_t voluta_sc_page_size(void)
{
	return (size_t)sysconf(_SC_PAGE_SIZE);
}

size_t voluta_sc_phys_pages(void)
{
	return (size_t)sysconf(_SC_PHYS_PAGES);
}

size_t voluta_sc_avphys_pages(void)
{
	return (size_t)sysconf(_SC_AVPHYS_PAGES);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* UUID */
void voluta_uuid_generate(struct voluta_uuid *uu)
{
	uuid_generate_random(uu->uu);
}

void voluta_uuid_copyto(const struct voluta_uuid *uu1, struct voluta_uuid *uu2)
{
	uuid_copy(uu2->uu, uu1->uu);
}

void voluta_uuid_name(const struct voluta_uuid *uu, struct voluta_namebuf *nb)
{
	char buf[40] = "";
	const char *s = buf;
	char *t = nb->name;

	uuid_unparse_lower(uu->uu, buf);
	while (*s != '\0') {
		if (isxdigit(*s)) {
			*t = *s;
		}
		t++;
		s++;
	}
	*t = '\0';
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* time */
void voluta_mclock_now(struct timespec *ts)
{
	int err;

	err = voluta_sys_clock_gettime(CLOCK_MONOTONIC, ts);
	if (err) {
		voluta_panic("clock_gettime err=%d", err);
	}
}

static void mclock_dif(const struct timespec *beg,
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
	mclock_dif(start, &now, dur);
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
void voluta_getentropy(void *buf, size_t len)
{
	int err;
	size_t cnt;
	uint8_t *ptr = buf;
	const uint8_t *end = ptr + len;
	const size_t getentropy_max = 256;

	while (ptr < end) {
		cnt = min((size_t)(end - ptr), getentropy_max);
		err = getentropy(ptr, cnt);
		if (err) {
			voluta_panic("getentropy failed err=%d", errno);
		}
		ptr += cnt;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* memory utilities */
static size_t size_to_page_up(size_t sz)
{
	const size_t page_size = voluta_sc_page_size();

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
		al = voluta_sc_page_size();
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
/* logging */
#define VOLUTA_LOG_DEFAULT \
	(VOLUTA_LOG_ERROR | VOLUTA_LOG_CRIT | VOLUTA_LOG_STDOUT)

static const int *voluta_g_logmaskp = NULL;

static int log_mask_now(void)
{
	const int *log_mask = voluta_g_logmaskp;

	return (log_mask != NULL) ? *log_mask : VOLUTA_LOG_DEFAULT;
}

void voluta_set_logmaskp(const int *log_maskp)
{
	voluta_g_logmaskp = log_maskp;
}

static void log_to_stdout(const char *msg, const char *file, int line)
{
	FILE *fp = stdout;
	const char *prog = program_invocation_short_name;

	flockfile(fp);
	if (file && line) {
		fprintf(fp, "%s: [%s:%d] \t%s\n", prog, file, line, msg);
	} else {
		fprintf(fp, "%s: %s\n", prog, msg);
	}
	funlockfile(fp);
}

static int syslog_level(int log_mask)
{
	int sl_level;

	if (log_mask & VOLUTA_LOG_CRIT) {
		sl_level = LOG_CRIT;
	} else if (log_mask & VOLUTA_LOG_ERROR) {
		sl_level = LOG_ERR;
	} else if (log_mask & VOLUTA_LOG_WARN) {
		sl_level = LOG_WARNING;
	} else if (log_mask & VOLUTA_LOG_INFO) {
		sl_level = LOG_INFO;
	} else if (log_mask & VOLUTA_LOG_DEBUG) {
		sl_level = LOG_DEBUG;
	} else {
		sl_level = 0;
	}
	return sl_level;
}

static void log_to_syslog(int log_mask, const char *msg,
			  const char *file, int line)
{
	const int level = syslog_level(log_mask);

	if (file && line) {
		syslog(level, "[%s:%d] \t%s", file, line, msg);
	} else {
		syslog(level, "%s", msg);
	}
}

static void log_msg(int log_mask, const char *msg, const char *file, int line)
{
	if (log_mask & VOLUTA_LOG_STDOUT) {
		log_to_stdout(msg, file, line);
	}
	if (log_mask & VOLUTA_LOG_SYSLOG) {
		log_to_syslog(log_mask, msg, file, line);
	}
}

void voluta_logf(int flags, const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	size_t len;
	int saved_errno;
	int log_mask;
	char msg[512];

	log_mask = log_mask_now();
	if ((log_mask & VOLUTA_LOG_FILINE) && file && line) {
		file = voluta_basename(file);
	} else {
		file = NULL;
		line = 0;
	}

	if (flags & log_mask) {
		saved_errno = errno;
		va_start(ap, fmt);
		len = (size_t)vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);
		len = min(len, sizeof(msg) - 1);
		msg[len] = '\0';
		log_msg(flags | log_mask, msg, file, line);
		errno = saved_errno;
	}
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* miscellaneous */
const char *voluta_basename(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

/* Optimal prime-value for hash-table of n-elements */
static const size_t voluta_primes[] = {
	13UL,
	53UL,
	97UL,
	193UL,
	389UL,
	769UL,
	1543UL,
	3079UL,
	6151UL,
	12289UL,
	24593UL,
	49157UL,
	98317UL,
	196613UL,
	393241UL,
	786433UL,
	1572869UL,
	3145739UL,
	6291469UL,
	12582917UL,
	25165843UL,
	50331653UL,
	100663319UL,
	201326611UL,
	402653189UL,
	805306457UL,
	1610612741UL,
	3221225473UL,
	4294967291UL
};

size_t voluta_hash_prime(size_t lim)
{
	size_t p = 3;

	for (size_t i = 0; i < ARRAY_SIZE(voluta_primes); ++i) {
		if (voluta_primes[i] > lim) {
			break;
		}
		p = voluta_primes[i];
	}
	return p;
}
