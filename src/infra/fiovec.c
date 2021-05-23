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
#include <voluta/infra/fiovec.h>

void voluta_fiovref_init(struct voluta_fiovref *fir,
                         voluta_fiovref_fn pre, voluta_fiovref_fn post)
{
	fir->pre = pre;
	fir->post = post;
}

void voluta_fiovref_fini(struct voluta_fiovref *fir)
{
	fir->pre = NULL;
	fir->post = NULL;
}

void voluta_fiovref_pre(struct voluta_fiovref *fir)
{
	if (fir && fir->pre) {
		fir->pre(fir);
	}
}

void voluta_fiovref_post(struct voluta_fiovref *fir)
{
	if (fir && fir->post) {
		fir->post(fir);
	}
}
