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
#ifndef VOLUTA_CONSTS_H_
#define VOLUTA_CONSTS_H_

#include <stdint.h>

/* common power-of-2 sizes */
#define VOLUTA_KILO             (1L << 10)
#define VOLUTA_MEGA             (1L << 20)
#define VOLUTA_GIGA             (1L << 30)
#define VOLUTA_TERA             (1L << 40)
#define VOLUTA_PETA             (1L << 50)
#define VOLUTA_UKILO            (1UL << 10)
#define VOLUTA_UMEGA            (1UL << 20)
#define VOLUTA_UGIGA            (1UL << 30)
#define VOLUTA_UTERA            (1UL << 40)
#define VOLUTA_UPETA            (1UL << 50)


/* memory page size */
#define VOLUTA_PAGE_SHIFT       (12)
#define VOLUTA_PAGE_SIZE        (1U << VOLUTA_PAGE_SHIFT)

#define VOLUTA_PAGE_SHIFT_MAX   (16)
#define VOLUTA_PAGE_SIZE_MAX    (1U << VOLUTA_PAGE_SHIFT_MAX)

/* minimal required size for system LEVELx_CACHE_LINESIZE */
#define VOLUTA_CACHELINE_SHIFT  (6)
#define VOLUTA_CACHELINE_SIZE   (1U << VOLUTA_CACHELINE_SHIFT)


#endif /* VOLUTA_CONSTS_H_ */
