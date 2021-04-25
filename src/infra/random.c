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
#include <errno.h>
#include <voluta/infra/macros.h>
#include <voluta/infra/utility.h>
#include <voluta/infra/errors.h>
#include <voluta/infra/random.h>

static void do_getentropy(void *buf, size_t len)
{
	int err;

	err = getentropy(buf, len);
	if (err) {
		voluta_panic("getentropy: err=%d", errno);
	}
}

void voluta_getentropy(void *buf, size_t len)
{
	size_t cnt;
	uint8_t *ptr = buf;
	const uint8_t *end = ptr + len;
	const size_t getentropy_max = 256;

	while (ptr < end) {
		cnt = voluta_min((size_t)(end - ptr), getentropy_max);
		do_getentropy(ptr, cnt);
		ptr += cnt;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_random_ascii(char *str, size_t len)
{
	int nrands = 0;
	int print_ch;
	int rands[64];
	const int base = 33;
	const int last = 126;

	for (size_t i = 0; i < len; ++i) {
		if (nrands == 0) {
			nrands = VOLUTA_ARRAY_SIZE(rands);
			voluta_getentropy(rands, sizeof(rands));
		}
		print_ch = (abs(rands[--nrands]) % (last - base)) + base;
		str[i] = (char)print_ch;
	}
}
