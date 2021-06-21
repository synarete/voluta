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
#ifndef VOLUTA_THREAD_H_
#define VOLUTA_THREAD_H_

#include <pthread.h>

struct voluta_thread;

typedef int (*voluta_execute_fn)(struct voluta_thread *);

struct voluta_thread {
	voluta_execute_fn exec;
	pthread_t       pth;
	char            name[32];
	time_t          start_time;
	time_t          finish_time;
	int             status;
};

struct voluta_mutex {
	pthread_mutex_t mutex;
	int alive;
};


int voluta_thread_sigblock_common(void);

int voluta_thread_create(struct voluta_thread *th,
                         voluta_execute_fn exec, const char *name);

int voluta_thread_join(struct voluta_thread *th);

int voluta_mutex_init(struct voluta_mutex *mutex);

void voluta_mutex_destroy(struct voluta_mutex *mutex);

void voluta_mutex_lock(struct voluta_mutex *mutex);

bool voluta_mutex_trylock(struct voluta_mutex *mutex);

bool voluta_mutex_timedlock(struct voluta_mutex *mutex,
                            const struct timespec *abstime);

void voluta_mutex_unlock(struct voluta_mutex *mutex);

#endif /* VOLUTA_THREAD_H_ */
