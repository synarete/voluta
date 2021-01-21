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
#ifndef VOLUTA_ERRORS_H_
#define VOLUTA_ERRORS_H_


/* run-time assertions */
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
	voluta_assert_if_((cond), VOLUTA_STR(cond), VOLUTA_FL)
#define voluta_assert_eq(a, b) \
	voluta_assert_eq_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_ne(a, b) \
	voluta_assert_ne_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_lt(a, b) \
	voluta_assert_lt_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_le(a, b) \
	voluta_assert_le_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_gt(a, b) \
	voluta_assert_gt_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_ge(a, b) \
	voluta_assert_ge_((long)(a), (long)(b), VOLUTA_FL)
#define voluta_assert_not_null(ptr) \
	voluta_assert_not_null_(ptr, VOLUTA_FL)
#define voluta_assert_null(ptr) \
	voluta_assert_null_(ptr, VOLUTA_FL)
#define voluta_assert_ok(err) \
	voluta_assert_ok_((int)(err), VOLUTA_FL)
#define voluta_assert_err(err, exp) \
	voluta_assert_err_((int)(err), (int)(exp), VOLUTA_FL)
#define voluta_assert_eqs(s1, s2) \
	voluta_assert_eqs_(s1, s2, VOLUTA_FL)
#define voluta_assert_eqm(m1, m2, nn) \
	voluta_assert_eqm_(m1, m2, nn, VOLUTA_FL)
#endif

void voluta_assert_if_(int cond, const char *str, const char *file, int line);
void voluta_assert_eq_(long a, long b, const char *file, int line);
void voluta_assert_ne_(long a, long b, const char *file, int line);
void voluta_assert_lt_(long a, long b, const char *file, int line);
void voluta_assert_le_(long a, long b, const char *file, int line);
void voluta_assert_gt_(long a, long b, const char *file, int line);
void voluta_assert_ge_(long a, long b, const char *file, int line);
void voluta_assert_ok_(int err, const char *file, int line);
void voluta_assert_err_(int err, int exp, const char *file, int line);
void voluta_assert_not_null_(const void *ptr, const char *file, int line);
void voluta_assert_null_(const void *ptr, const char *file, int line);
void voluta_assert_eqs_(const char *, const char *, const char *, int);
void voluta_assert_eqm_(const void *, const void *, size_t,
			const char *file, int line);

/* panic */
#define voluta_panic(fmt, ...) \
	voluta_panicf(__FILE__, __LINE__, fmt, __VA_ARGS__)

__attribute__((__noreturn__))
void voluta_panicf(const char *file, int line, const char *fmt, ...);

/* backtrace */
void voluta_backtrace(void);

#endif /* VOLUTA_ERRORS_H_ */
