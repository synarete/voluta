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
#ifndef VOLUTA_TIME_H_
#define VOLUTA_TIME_H_

#include <time.h>

time_t voluta_time_now(void);

void voluta_rclock_now(struct timespec *ts);

void voluta_mclock_now(struct timespec *ts);

void voluta_mclock_dur(const struct timespec *start, struct timespec *dur);

void voluta_ts_copy(struct timespec *dst, const struct timespec *src);

int voluta_ts_gettime(struct timespec *ts, int realtime);

#endif /* VOLUTA_TIME_H_ */
