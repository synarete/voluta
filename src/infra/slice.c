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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <voluta/infra/utility.h>
#include <voluta/infra/slice.h>

void voluta_slice_init(struct voluta_slice *sl, void *p, size_t n)
{
	sl->ptr = p;
	sl->cap = n;
	sl->len = 0;
}

void voluta_slice_fini(struct voluta_slice *sl)
{
	sl->ptr = NULL;
	sl->cap = 0;
	sl->len = 0;
}

static size_t slice_rem(const struct voluta_slice *sl)
{
	return (sl->cap - sl->len);
}

static size_t slice_append_cnt(const struct voluta_slice *sl, size_t len_want)
{
	return voluta_min(len_want, slice_rem(sl));
}

static uint8_t *slice_end(const struct voluta_slice *sl)
{
	return (uint8_t *)sl->ptr + sl->len;
}

void *voluta_slice_end(const struct voluta_slice *sl)
{
	return slice_end(sl);
}

size_t voluta_slice_append(struct voluta_slice *sl, const void *p, size_t len)
{
	const size_t cnt = slice_append_cnt(sl, len);

	memcpy(slice_end(sl), p, cnt);
	sl->len += cnt;
	return cnt;
}

