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


static void show_finalize(void)
{
	/* no-op */
}

static void show_setup_check_params(void)
{
	struct stat st;

	voluta_stat_dir_or_reg(voluta_globals.show_path, &st);
}

static void show_ioctl_query(const char *path, struct voluta_ioc_query *query)
{
	int err;
	int fd = -1;

	err = voluta_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		voluta_die(err, "failed to open: %s", path);
	}
	err = voluta_sys_ioctlp(fd, VOLUTA_FS_IOC_QUERY, query);
	voluta_sys_close(fd);
	if (err) {
		voluta_die(err, "ioctl error: %s", path);
	}
}

static void show_version(void)
{
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_VERSION
	};

	show_ioctl_query(voluta_globals.show_path, &query);
	printf("%s\n", query.u.version.string);
}

static void show_volume(void)
{
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_VOLUME
	};

	show_ioctl_query(voluta_globals.show_path, &query);
	printf("%s\n", query.u.volume.path);
}

static void show_execute(void)
{
	if (voluta_globals.show_version) {
		show_version();
	}
	if (voluta_globals.show_volume) {
		show_volume();
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_show(void)
{
	/* Do all cleanups upon exits */
	atexit(show_finalize);

	/* Verify user's arguments */
	show_setup_check_params();

	/* Do actual query + show */
	show_execute();

	/* Post execution cleanups */
	show_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_show_usage[] = {
	"show version <pathname>",
	"show volume <pathname>",
	NULL
};


void voluta_getopt_show(void)
{
	int opt_chr = 1;
	const char *subcmd;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("h", opts);
		if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_show_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	subcmd = voluta_consume_cmdarg("<sub-command>", false);
	if (!strcmp(subcmd, "version")) {
		voluta_globals.show_version = true;
	} else if (!strcmp(subcmd, "volume")) {
		voluta_globals.show_volume = true;
	} else {
		voluta_die(0, "unknown sub-command: %s", subcmd);
	}
	voluta_globals.show_path =
		voluta_consume_cmdarg("pathname", true);
}

