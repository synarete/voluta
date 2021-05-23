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
#ifndef VOLUTA_FIOVEC_H_
#define VOLUTA_FIOVEC_H_

#include <stdlib.h>

struct voluta_fiovref;
struct voluta_fiovec;

typedef void (*voluta_fiovref_fn)(struct voluta_fiovref *fvr);

struct voluta_fiovref {
	voluta_fiovref_fn pre;
	voluta_fiovref_fn post;
};

struct voluta_fiovec {
	void  *fv_base;
	size_t fv_len;
	loff_t fv_off;
	int    fv_fd;
	struct voluta_fiovref *fv_ref;
};


void voluta_fiovref_init(struct voluta_fiovref *fir,
                         voluta_fiovref_fn pre, voluta_fiovref_fn post);

void voluta_fiovref_fini(struct voluta_fiovref *fir);

void voluta_fiovref_pre(struct voluta_fiovref *fir);

void voluta_fiovref_post(struct voluta_fiovref *fir);

#endif /* VOLUTA_FIOVEC_H_ */
