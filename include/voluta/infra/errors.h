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
#ifndef VOLUTA_ERRORS_H_
#define VOLUTA_ERRORS_H_

/* expect-or-die */
void voluta_expect_true_(int cond, const char *fl, int ln);
void voluta_expect_cond_(int cond, const char *str, const char *fl, int ln);
void voluta_expect_eq_(long a, long b, const char *fl, int ln);
void voluta_expect_ne_(long a, long b, const char *fl, int ln);
void voluta_expect_lt_(long a, long b, const char *fl, int ln);
void voluta_expect_le_(long a, long b, const char *fl, int ln);
void voluta_expect_gt_(long a, long b, const char *fl, int ln);
void voluta_expect_ge_(long a, long b, const char *fl, int ln);
void voluta_expect_ok_(int err, const char *fl, int ln);
void voluta_expect_err_(int err, int exp, const char *fl, int ln);
void voluta_expect_not_null_(const void *ptr, const char *fl, int ln);
void voluta_expect_null_(const void *ptr, const char *fl, int ln);
void voluta_expect_eqs_(const char *s, const char *z, const char *fl, int ln);
void voluta_expect_eqm_(const void *p, const void *q,
                        size_t n, const char *fl, int ln);

#define voluta_expect(cond) \
	voluta_expect_cond_((cond), VOLUTA_STR(cond), VOLUTA_FL)
#define voluta_expect_eq(a, b) \
	voluta_expect_eq_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_expect_ne(a, b) \
	voluta_expect_ne_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_expect_lt(a, b) \
	voluta_expect_lt_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_expect_le(a, b) \
	voluta_expect_le_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_expect_gt(a, b) \
	voluta_expect_gt_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_expect_ge(a, b) \
	voluta_expect_ge_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_expect_not_null(ptr) \
	voluta_expect_not_null_(ptr, VOLUTA_FL)
#define voluta_expect_null(ptr) \
	voluta_expect_null_(ptr, VOLUTA_FL)
#define voluta_expect_ok(err) \
	voluta_expect_ok_((int)(err), VOLUTA_FL)
#define voluta_expect_err(err, exp) \
	voluta_expect_err_((int)(err), (int)(exp), VOLUTA_FL)
#define voluta_expect_eqs(s1, s2) \
	voluta_expect_eqs_(s1, s2, VOLUTA_FL)
#define voluta_expect_eqm(m1, m2, nn) \
	voluta_expect_eqm_(m1, m2, nn, VOLUTA_FL)

/* run-time assertions (debug mode only) */
#ifdef NDEBUG
#define voluta_assert(cond)
#define voluta_assert_eq(a, b)
#define voluta_assert_ne(a, b)
#define voluta_assert_lt(a, b)
#define voluta_assert_le(a, b)
#define voluta_assert_gt(a, b)
#define voluta_assert_ge(a, b)
#define voluta_assert_not_null(ptr)
#define voluta_assert_null(ptr)
#define voluta_assert_ok(err)
#define voluta_assert_err(err, exp)
#define voluta_assert_eqs(s1, s2)
#define voluta_assert_eqm(m1, m2, nn)
#else
#define VOLUTA_FL  __FILE__, __LINE__
#define voluta_assert(cond) \
	voluta_expect_cond_((cond), VOLUTA_STR(cond), VOLUTA_FL)
#define voluta_assert_eq(a, b) \
	voluta_expect_eq_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_ne(a, b) \
	voluta_expect_ne_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_lt(a, b) \
	voluta_expect_lt_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_le(a, b) \
	voluta_expect_le_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_gt(a, b) \
	voluta_expect_gt_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_ge(a, b) \
	voluta_expect_ge_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_not_null(ptr) \
	voluta_expect_not_null_(ptr, VOLUTA_FL)
#define voluta_assert_null(ptr) \
	voluta_expect_null_(ptr, VOLUTA_FL)
#define voluta_assert_ok(err) \
	voluta_expect_ok_((int)(err), VOLUTA_FL)
#define voluta_assert_err(err, exp) \
	voluta_expect_err_((int)(err), (int)(exp), VOLUTA_FL)
#define voluta_assert_eqs(s1, s2) \
	voluta_expect_eqs_(s1, s2, VOLUTA_FL)
#define voluta_assert_eqm(m1, m2, nn) \
	voluta_expect_eqm_(m1, m2, nn, VOLUTA_FL)
#endif

/* panic */
#define voluta_panic(fmt, ...) \
	voluta_panicf(__FILE__, __LINE__, fmt, __VA_ARGS__)

__attribute__((__noreturn__))
void voluta_panicf(const char *file, int line, const char *fmt, ...);

/* die */
__attribute__((__noreturn__))
void voluta_die(int errnum, const char *fmt, ...);

__attribute__((__noreturn__))
void voluta_die_at(int errnum, const char *fl, int ln, const char *fmt, ...);

/* backtrace */
void voluta_backtrace(void);

#endif /* VOLUTA_ERRORS_H_ */
