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
#ifndef VOLUTA_MINMAX_H_
#define VOLUTA_MINMAX_H_

#include <stdlib.h>
#include <stdint.h>

uint64_t voluta_min(uint64_t x, uint64_t y);

uint64_t voluta_min3(uint64_t x, uint64_t y, uint64_t z);

uint64_t voluta_max(uint64_t x, uint64_t y);

uint64_t voluta_clamp(uint64_t v, uint64_t lo, uint64_t hi);

size_t voluta_clz32(uint32_t n);

size_t voluta_popcount32(uint32_t n);

size_t voluta_popcount64(uint64_t n);

uint64_t voluta_div_round_up(uint64_t n, uint64_t d);

#endif /* VOLUTA_MINMAX_H_ */
