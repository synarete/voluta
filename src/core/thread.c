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
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "libvoluta.h"

#if defined(NDEBUG)
#define VOLUTA_MUTEX_KIND PTHREAD_MUTEX_NORMAL
#else
#define VOLUTA_MUTEX_KIND PTHREAD_MUTEX_ERRORCHECK
#endif

static int voluta_thread_sigblock_common(void)
{
	sigset_t sigset_th;

	sigemptyset(&sigset_th);
	sigaddset(&sigset_th, SIGHUP);
	sigaddset(&sigset_th, SIGINT);
	sigaddset(&sigset_th, SIGQUIT);
	sigaddset(&sigset_th, SIGTERM);
	sigaddset(&sigset_th, SIGTRAP);
	sigaddset(&sigset_th, SIGUSR1);
	sigaddset(&sigset_th, SIGUSR2);
	sigaddset(&sigset_th, SIGPIPE);
	sigaddset(&sigset_th, SIGALRM);
	sigaddset(&sigset_th, SIGCHLD);
	sigaddset(&sigset_th, SIGURG);
	sigaddset(&sigset_th, SIGPROF);
	sigaddset(&sigset_th, SIGWINCH);
	sigaddset(&sigset_th, SIGIO);

	return pthread_sigmask(SIG_BLOCK, &sigset_th, NULL);
}

static void voluta_thread_prepare(struct voluta_thread *th)
{
	th->start_time = voluta_time_now();
	th->finish_time = 0;
	if (strlen(th->name)) {
		pthread_setname_np(th->pth, th->name);
	}
}

static void voluta_thread_complete(struct voluta_thread *th, int err)
{
	th->status = err;
	th->finish_time = voluta_time_now();
}

static void *voluta_thread_start(void *arg)
{
	int err;
	struct voluta_thread *th = (struct voluta_thread *)arg;

	voluta_thread_prepare(th);
	err = voluta_thread_sigblock_common();
	if (!err) {
		err = th->exec(th);
	}
	voluta_thread_complete(th, err);
	return th;
}

int voluta_thread_create(struct voluta_thread *th,
                         voluta_execute_fn exec, const char *name)
{
	int err;
	size_t nlen = 0;
	pthread_attr_t attr;
	void *(*start)(void *arg) = voluta_thread_start;

	if (th->pth || th->exec || !exec) {
		return -EINVAL;
	}
	err = pthread_attr_init(&attr);
	if (err) {
		return err;
	}

	memset(th, 0, sizeof(*th));
	th->exec = exec;
	if (name != NULL) {
		nlen = strlen(name);
		memcpy(th->name, name, min(nlen, sizeof(th->name) - 1));
	}

	err = pthread_create(&th->pth, &attr, start, th);
	pthread_attr_destroy(&attr);

	return err;
}

int voluta_thread_join(struct voluta_thread *th)
{
	return pthread_join(th->pth, NULL);
}


int voluta_mutex_init(struct voluta_mutex *mutex)
{
	int err;
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	err = pthread_mutexattr_settype(&attr, VOLUTA_MUTEX_KIND);
	if (err) {
		return err;
	}
	err = pthread_mutex_init(&mutex->mutex, &attr);
	pthread_mutexattr_destroy(&attr);
	if (err) {
		return err;
	}
	mutex->alive = 1;
	return 0;
}

void voluta_mutex_destroy(struct voluta_mutex *mutex)
{
	int err;

	if (mutex->alive) {
		err = pthread_mutex_destroy(&mutex->mutex);
		if (err) {
			voluta_panic("pthread_mutex_destroy: %d", err);
		}
		mutex->alive = 0;
	}
}

void voluta_mutex_lock(struct voluta_mutex *mutex)
{
	int err;

	err = pthread_mutex_lock(&mutex->mutex);
	if (err) {
		voluta_panic("pthread_mutex_lock: %d", err);
	}
}

bool voluta_mutex_trylock(struct voluta_mutex *mutex)
{
	int err;
	bool status = false;

	err = pthread_mutex_trylock(&mutex->mutex);
	if (err == 0) {
		status = true;
	} else if (err == EBUSY) {
		status = false;
	} else {
		voluta_panic("pthread_mutex_trylock: %d", err);
	}
	return status;
}

bool voluta_mutex_timedlock(struct voluta_mutex *mutex,
                            const struct timespec *abstime)
{
	int err;
	bool status = false;

	err = pthread_mutex_timedlock(&mutex->mutex, abstime);
	if (err == 0) {
		status = true;
	} else if (err == ETIMEDOUT) {
		status = false;
	} else {
		voluta_panic("pthread_mutex_timedlock: %d", err);
	}
	return status;
}

void voluta_mutex_unlock(struct voluta_mutex *mutex)
{
	int err;

	err = pthread_mutex_unlock(&mutex->mutex);
	if (err) {
		voluta_panic("pthread_mutex_unlock: %d", err);
	}
}
