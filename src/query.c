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
#include "voluta-prog.h"


static void query_finalize(void)
{
	voluta_globals.query_type = 0;
}

static void query_setup_check_params(void)
{
	struct stat st;

	voluta_stat_dir_or_reg(voluta_globals.query_path, &st);
}

static void query_execute(void)
{
	int err;
	int fd = -1;
	const char *path = voluta_globals.query_path;
	struct voluta_ioc_query query = {
		.qtype = voluta_globals.query_type
	};

	if (!query.qtype) {
		query.qtype = VOLUTA_QUERY_VERSION;
	}
	err = voluta_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		voluta_die(err, "failed to open: %s", path);
	}
	err = voluta_sys_ioctlp(fd, VOLUTA_FS_IOC_QUERY, &query);
	voluta_sys_close(fd);
	if (err) {
		voluta_die(err, "ioctl error: %s", path);
	}

	if (query.qtype == VOLUTA_QUERY_VERSION) {
		printf("%s\n", query.u.version.string);
	} else if (query.qtype == VOLUTA_QUERY_VOLUME) {
		printf("%s\n", query.u.volume.path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_query(void)
{
	/* Do all cleanups upon exits */
	atexit(query_finalize);

	/* Verify user's arguments */
	query_setup_check_params();

	/* Do actual query */
	query_execute();

	/* Post execution cleanups */
	query_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_query_usage[] = {
	"query [options] <pathname>",
	"",
	"options:",
	"  -p, --volume                 Show underlying volume path",
	"  -v, --version                Query file-system's version",
	NULL
};


void voluta_getopt_query(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "volume", no_argument, NULL, 'p' },
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("pvh", opts);
		if (opt_chr == 'v') {
			voluta_globals.query_type = VOLUTA_QUERY_VERSION;
		} else if (opt_chr == 'p') {
			voluta_globals.query_type = VOLUTA_QUERY_VOLUME;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_query_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.query_path =
		voluta_consume_cmdarg("pathname", true);
}

