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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#define UNW_LOCAL_ONLY 1
#include <libunwind.h>

#include <voluta/macros.h>
#include <voluta/logging.h>
#include <voluta/errors.h>
#include <voluta/minmax.h>
#include <voluta/utility.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_bt_info {
	void *ip;
	long  sp;
	const char *sym;
	long  off;
};

static int voluta_backtrace_calls(int (*bt_cb)(const struct voluta_bt_info *))
{
	int err;
	int lim = 64;
	unw_word_t ip;
	unw_word_t sp;
	unw_word_t off;
	unw_context_t context;
	unw_cursor_t cursor;
	char sym[256];
	struct voluta_bt_info bti;

	err = unw_getcontext(&context);
	if (err != UNW_ESUCCESS) {
		return err;
	}
	err = unw_init_local(&cursor, &context);
	if (err != UNW_ESUCCESS) {
		return err;
	}
	memset(sym, 0, sizeof(sym));
	while (lim-- > 0) {
		ip = sp = off = 0;
		err = unw_step(&cursor);
		if (err <= 0) {
			return err;
		}
		err = unw_get_reg(&cursor, UNW_REG_IP, &ip);
		if (err) {
			return err;
		}
		err = unw_get_reg(&cursor, UNW_REG_SP, &sp);
		if (err) {
			return err;
		}
		off = 0;
		err = unw_get_proc_name(&cursor, sym, sizeof(sym) - 1, &off);
		if (err) {
			sym[0] = '\0';
		}
		bti.ip = (void *)ip;
		bti.sp = (long)sp;
		bti.sym = sym;
		bti.off = (long)off;
		err = bt_cb(&bti);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool voluta_enable_backtrace = true;

static int log_err_bt(const struct voluta_bt_info *bti)
{
	voluta_log_error("[<%p>] 0x%lx %s+0x%lx",
	                 bti->ip, bti->sp, bti->sym, bti->off);
	return 0;
}

void voluta_backtrace(void)
{
	if (voluta_enable_backtrace) {
		voluta_backtrace_calls(log_err_bt);
	}
}

static void voluta_dump_backtrace(void)
{
	voluta_backtrace();
	voluta_enable_backtrace = false;
}

static void bt_addrs_to_str(char *buf, size_t bsz, void **bt_arr, int bt_len)
{
	size_t len;

	for (int i = 1; i < bt_len - 2; ++i) {
		len = strlen(buf);
		if ((len + 8) >= bsz) {
			break;
		}
		snprintf(buf + len, bsz - len, "%p ", bt_arr[i]);
	}
}

static void voluta_dump_addr2line(void)
{
	int bt_len;
	void *bt_arr[128];
	char bt_addrs[1024];
	const int bt_cnt = (int)(VOLUTA_ARRAY_SIZE(bt_arr));

	voluta_memzero(bt_arr, sizeof(bt_arr));
	voluta_memzero(bt_addrs, sizeof(bt_addrs));

	bt_len = unw_backtrace(bt_arr, bt_cnt);
	bt_addrs_to_str(bt_addrs, sizeof(bt_addrs) - 1, bt_arr, bt_len);
	voluta_log_error("addr2line -a -C -e %s -f -p -s %s",
	                 program_invocation_name, bt_addrs);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_fatal_msg {
	char str[256];
};

static void fmtmsg(struct voluta_fatal_msg *msg, const char *fmt, ...)
{
	va_list ap;
	size_t len;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(msg->str, sizeof(msg->str) - 1, fmt, ap);
	va_end(ap);

	len = voluta_min(sizeof(msg->str) - 1, (size_t)n);
	msg->str[len] = '\0';
}

__attribute__((__noreturn__))
static void voluta_abort(void)
{
	fflush(stdout);
	fflush(stderr);
	abort();
}

__attribute__((__noreturn__))
static void
voluta_fatal_at(const char *msg, const char *fl, int ln)
{
	voluta_panicf(fl, ln, "failure: `%s'", msg);
	voluta_abort();
}

__attribute__((__noreturn__))
static void voluta_fatal_op(long a, const char *op, long b,
                            const char *fl, int ln)
{
	struct voluta_fatal_msg fm;

	fmtmsg(&fm, "'%ld %s %ld'", a, op, b);
	voluta_fatal_at(fm.str, fl, ln);
}

void voluta_expect_true_(int cond, const char *fl, int ln)
{
	struct voluta_fatal_msg fm;

	if (voluta_unlikely(!cond)) {
		fmtmsg(&fm, "not-true: %d", cond);
		voluta_fatal_at(fm.str, fl, ln);
	}
}

void voluta_expect_cond_(int cond, const char *str, const char *fl, int ln)
{
	if (voluta_unlikely(!cond)) {
		voluta_fatal_at(str, fl, ln);
	}
}

void voluta_expect_eq_(long a, long b, const char *fl, int ln)
{
	if (voluta_unlikely(a != b)) {
		voluta_fatal_op(a, "!=", b, fl, ln);
	}
}

void voluta_expect_ne_(long a, long b, const char *fl, int ln)
{
	if (voluta_unlikely(a == b)) {
		voluta_fatal_op(a, "==", b, fl, ln);
	}
}

void voluta_expect_lt_(long a, long b, const char *fl, int ln)
{
	if (voluta_unlikely(a >= b)) {
		voluta_fatal_op(a, ">=", b, fl, ln);
	}
}

void voluta_expect_le_(long a, long b, const char *fl, int ln)
{
	if (voluta_unlikely(a > b)) {
		voluta_fatal_op(a, ">", b, fl, ln);
	}
}

void voluta_expect_gt_(long a, long b, const char *fl, int ln)
{
	if (voluta_unlikely(a <= b)) {
		voluta_fatal_op(a, "<=", b, fl, ln);
	}
}

void voluta_expect_ge_(long a, long b, const char *fl, int ln)
{
	if (voluta_unlikely(a < b)) {
		voluta_fatal_op(a, "<", b, fl, ln);
	}
}

void voluta_expect_ok_(int err, const char *fl, int ln)
{
	struct voluta_fatal_msg fm;

	if (voluta_unlikely(err != 0)) {
		fmtmsg(&fm, "err=%d", err);
		voluta_fatal_at(fm.str, fl, ln);
	}
}

void voluta_expect_err_(int err, int exp, const char *fl, int ln)
{
	struct voluta_fatal_msg fm;

	if (voluta_unlikely(err != exp)) {
		fmtmsg(&fm, "err=%d exp=%d", err, exp);
		voluta_fatal_at(fm.str, fl, ln);
	}
}

void voluta_expect_not_null_(const void *ptr, const char *fl, int ln)
{
	if (voluta_unlikely(ptr == NULL)) {
		voluta_fatal_at("NULL pointer", fl, ln);
	}
}

void voluta_expect_null_(const void *ptr, const char *fl, int ln)
{
	struct voluta_fatal_msg fm;

	if (voluta_unlikely(ptr != NULL)) {
		fmtmsg(&fm, "not NULL ptr=%p", ptr);
		voluta_fatal_at(fm.str, fl, ln);
	}
}

void voluta_expect_eqs_(const char *s, const char *z, const char *fl, int ln)
{
	struct voluta_fatal_msg msg;
	const int cmp = strcmp(s, z);

	if (voluta_unlikely(cmp != 0)) {
		fmtmsg(&msg, "str-not-equal: %s != %s", s, z);
		voluta_fatal_at(msg.str, fl, ln);
	}
}

static char nibble_to_ascii(unsigned int n)
{
	const char xdigits[] = "0123456789ABCDEF";

	return xdigits[n & 0xF];
}

static void mem_to_str(const void *mem, size_t nn, char *str, size_t len)
{
	size_t pos = 0;
	size_t i = 0;
	const uint8_t *ptr = mem;

	memset(str, 0, len);
	while ((i < nn) && ((pos + 4) < len)) {
		str[pos++] = nibble_to_ascii(ptr[i] >> 4);
		str[pos++] = nibble_to_ascii(ptr[i]);
		i += 1;
	}
	if (i < nn) {
		while ((pos + 2) < len) {
			str[pos++] = '.';
		}
	}
}

static size_t find_first_not_eq(const uint8_t *p, const uint8_t *q, size_t n)
{
	for (size_t i = 0; i < n; ++i) {
		if (p[i] != q[i]) {
			return i;
		}
	}
	return n;
}

static void voluta_die_not_eqm(const uint8_t *p, const uint8_t *q,
                               size_t n, const char *fl, int ln)
{
	char s1[20];
	char s2[20];
	struct voluta_fatal_msg fm;
	const size_t pos = find_first_not_eq(p, q, n);

	if (pos > sizeof(s1)) {
		fmtmsg(&fm, "memory-not-equal-at: %lu (%u != %u)",
		       pos, (uint32_t)(p[pos]), (uint32_t)(q[pos]));
	} else {
		mem_to_str(p, n, s1, sizeof(s1));
		mem_to_str(q, n, s2, sizeof(s2));
		fmtmsg(&fm, "memory-not-equal: %s != %s ", s1, s2);
	}
	voluta_fatal_at(fm.str, fl, ln);
}

void voluta_expect_eqm_(const void *p, const void *q,
                        size_t n, const char *fl, int ln)
{
	if (memcmp(p, q, n)) {
		voluta_die_not_eqm(p, q, n, fl, ln);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

static void voluta_dump_panic_msg(const char *file, int line,
                                  const char *msg, int errnum)
{
	const char *es = " ";
	const char *name = basename_of(file);

	voluta_log_crit("%s", es);
	if (errnum) {
		voluta_log_crit("%s:%d: %s %d", name, line, msg, errnum);
	} else {
		voluta_log_crit("%s:%d: %s", name, line, msg);
	}
	voluta_log_crit("%s", es);
}

__attribute__((__noreturn__))
void voluta_panicf(const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	char msg[512] = "";
	const int errnum = errno;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, ap);
	va_end(ap);

	voluta_dump_panic_msg(file, line, msg, errnum);
	voluta_dump_backtrace();
	voluta_dump_addr2line();
	voluta_abort();
}
