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
	/* TODO */
}


static void show_check_params(void)
{
	struct stat st;

	voluta_stat_dir_or_reg(voluta_globals.show_path, &st);
}

static void show_send_recv(void)
{
	/* TODO: FILLME */
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_show(void)
{
	/* Do all cleanups upon exits */
	atexit(show_finalize);

	/* Verify user's arguments */
	show_check_params();

	/* Do actual show */
	show_send_recv();

	/* Post execution cleanups */
	show_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_show_usage[] = {
	"show [options] <volume-path>",
	"",
	"options:",
	"  -v, --version                Show version and exit",
	"  -p, --public-only            Show only volume's public header",
	NULL
};

void voluta_getopt_show(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "public-only", no_argument, NULL, 'p' },
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("pvh", opts);
		if (opt_chr == 'v') {
			voluta_show_version_and_exit(NULL);
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_show_usage);
		} else if (opt_chr == 'p') {
			voluta_globals.show_public_only = true;
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.show_path =
		voluta_consume_cmdarg("volume-path", true);
}

