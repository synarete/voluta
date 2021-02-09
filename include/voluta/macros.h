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
#ifndef VOLUTA_MACROS_H_
#define VOLUTA_MACROS_H_

#include <stddef.h>


/* compile-time assertions */
#define VOLUTA_STATICASSERT(expr_)       _Static_assert(expr_, #expr_)
#define VOLUTA_STATICASSERT_EQ(a_, b_)   VOLUTA_STATICASSERT(a_ == b_)
#define VOLUTA_STATICASSERT_LE(a_, b_)   VOLUTA_STATICASSERT(a_ <= b_)
#define VOLUTA_STATICASSERT_LT(a_, b_)   VOLUTA_STATICASSERT(a_ < b_)
#define VOLUTA_STATICASSERT_GE(a_, b_)   VOLUTA_STATICASSERT(a_ >= b_)
#define VOLUTA_STATICASSERT_GT(a_, b_)   VOLUTA_STATICASSERT(a_ > b_)

/* stringify macros */
#define VOLUTA_STR(x_)          VOLUTA_MAKESTR_(x_)
#define VOLUTA_MAKESTR_(x_)     #x_
#define VOLUTA_CONCAT(x_, y_)   x_ ## y_

/* array number of elements */
#define VOLUTA_ARRAY_SIZE(x_)   ( (sizeof((x_))) / (sizeof(((x_)[0]))) )

/* utility macros */
#define VOLUTA_CONTAINER_OF(ptr_, type_, member_) \
	(type_ *)((void *)((char *)ptr_ - offsetof(type_, member_)))

#define VOLUTA_CONTAINER_OF2(ptr_, type_, member_) \
	(const type_ *)((const void *) \
			((const char *)ptr_ - offsetof(type_, member_)))

#define voluta_container_of(ptr_, type_, member_) \
	VOLUTA_CONTAINER_OF(ptr_, type_, member_)

#define voluta_container_of2(ptr_, type_, member_) \
	VOLUTA_CONTAINER_OF2(ptr_, type_, member_)

#define voluta_unused(x_)       ((void)x_)

/* numeric operations */
#define VOLUTA_DIV_ROUND_UP(n, d)       ((n + d - 1) / d)
#define VOLUTA_ROUND_TO(n, k)           (VOLUTA_DIV_ROUND_UP(n, k) * k)
#define VOLUTA_BIT(n)                   (1 << n)

/* branch-redictor helpers */
#define voluta_likely(x_)               __builtin_expect(!!(x_), 1)
#define voluta_unlikely(x_)             __builtin_expect(!!(x_), 0)


#endif /* VOLUTA_MACROS_H_ */
