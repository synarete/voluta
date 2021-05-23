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
#include <unistd.h>
#include <ctype.h>
#include <voluta/infra/macros.h>
#include <voluta/infra/utility.h>

static const char s_xdigits[] = "0123456789abcdef";

char voluta_nibble_to_ascii(int n)
{
	return s_xdigits[n & 0xF];
}

int voluta_ascii_to_nibble(char a)
{
	const int c = tolower((int)a);

	for (int i = 0; i < 16; ++i) {
		if ((int)s_xdigits[i] == c) {
			return i;
		}
	}
	return -1;
}
