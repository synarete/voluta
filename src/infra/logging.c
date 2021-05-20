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
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <voluta/infra/logging.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* logging */
#define VOLUTA_LOG_DEFAULT \
	(VOLUTA_LOG_ERROR | VOLUTA_LOG_CRIT | VOLUTA_LOG_STDOUT)

static const int *voluta_g_logmaskp = NULL;

static int log_mask_now(void)
{
	const int *log_mask = voluta_g_logmaskp;

	return (log_mask != NULL) ? *log_mask : VOLUTA_LOG_DEFAULT;
}

void voluta_set_logmaskp(const int *log_maskp)
{
	voluta_g_logmaskp = log_maskp;
}

static void log_to_stdout(const char *msg, const char *file, int line)
{
	FILE *fp = stdout;
	const char *prog = program_invocation_short_name;

	flockfile(fp);
	if (file && line) {
		fprintf(fp, "%s: [%s:%d] \t%s\n", prog, file, line, msg);
	} else {
		fprintf(fp, "%s: %s\n", prog, msg);
	}
	funlockfile(fp);
}

static int syslog_level(int log_mask)
{
	int sl_level;

	if (log_mask & VOLUTA_LOG_CRIT) {
		sl_level = LOG_CRIT;
	} else if (log_mask & VOLUTA_LOG_ERROR) {
		sl_level = LOG_ERR;
	} else if (log_mask & VOLUTA_LOG_WARN) {
		sl_level = LOG_WARNING;
	} else if (log_mask & VOLUTA_LOG_INFO) {
		sl_level = LOG_INFO;
	} else if (log_mask & VOLUTA_LOG_DEBUG) {
		sl_level = LOG_DEBUG;
	} else {
		sl_level = 0;
	}
	return sl_level;
}

static void log_to_syslog(int log_mask, const char *msg,
                          const char *file, int line)
{
	const int level = syslog_level(log_mask);

	if (file && line) {
		syslog(level, "[%s:%d] \t%s", file, line, msg);
	} else {
		syslog(level, "%s", msg);
	}
}

static void log_msg(int log_mask, const char *msg, const char *file, int line)
{
	if (log_mask & VOLUTA_LOG_STDOUT) {
		log_to_stdout(msg, file, line);
	}
	if (log_mask & VOLUTA_LOG_SYSLOG) {
		log_to_syslog(log_mask, msg, file, line);
	}
}

static const char *basename_of(const char *path)
{
	const char *name = strrchr(path, '/');

	return (name == NULL) ? path : (name + 1);
}

void voluta_logf(int flags, const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	size_t len;
	int saved_errno;
	int log_mask;
	char msg[512];

	log_mask = log_mask_now();
	if ((log_mask & VOLUTA_LOG_FILINE) && file && line) {
		file = basename_of(file);
	} else {
		file = NULL;
		line = 0;
	}

	if (flags & log_mask) {
		saved_errno = errno;
		va_start(ap, fmt);
		len = (size_t)vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);
		if (len >= sizeof(msg)) {
			len = sizeof(msg) - 1;
		}
		msg[len] = '\0';
		log_msg(flags | log_mask, msg, file, line);
		errno = saved_errno;
	}
}

