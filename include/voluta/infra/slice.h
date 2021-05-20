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
#ifndef VOLUTA_SLICE_H_
#define VOLUTA_SLICE_H_

#include <stdlib.h>

struct voluta_slice {
	void  *ptr;
	size_t len;
	size_t cap;
};

void voluta_slice_init(struct voluta_slice *sl, void *p, size_t n);

void voluta_slice_fini(struct voluta_slice *sl);

void *voluta_slice_end(const struct voluta_slice *sl);

size_t voluta_slice_append(struct voluta_slice *sl, const void *p, size_t len);

#endif /* VOLUTA_SLICE_H_ */
