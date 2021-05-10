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
#ifndef VOLUTA_UTILITY_H_
#define VOLUTA_UTILITY_H_

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <uuid/uuid.h>


/* commons */

void voluta_burnstack(void);

void *voluta_unconst(const void *p);


/* memory utilities */
int voluta_mmap_memory(size_t, void **);

int voluta_mmap_secure_memory(size_t, void **);

void voluta_munmap_memory(void *, size_t);

void voluta_munmap_secure_memory(void *, size_t);

void voluta_memzero(void *s, size_t n);

int voluta_zalloc_aligned(size_t sz, void **out_mem);

/* sysconf wrappers */
size_t voluta_sc_page_size(void);

size_t voluta_sc_phys_pages(void);

size_t voluta_sc_avphys_pages(void);

size_t voluta_sc_l1_dcache_linesize(void);

/* time wrappers */
void voluta_rclock_now(struct timespec *ts);

void voluta_mclock_now(struct timespec *ts);

void voluta_mclock_dur(const struct timespec *start, struct timespec *dur);

time_t voluta_time_now(void);

void voluta_ts_copy(struct timespec *dst, const struct timespec *src);

int voluta_ts_gettime(struct timespec *ts, bool realtime);

/* getentropy wrapper */
void voluta_getentropy(void *buf, size_t len);

uint32_t voluta_getentropy32(void);

uint64_t voluta_getentropy64(void);

#endif /* VOLUTA_UTILITY_H_ */
