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


static void fsck_finalize(void)
{
	voluta_destrpy_fse_inst();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_fsck(void)
{
	/* Do all cleanups upon exits */
	atexit(fsck_finalize);

	/* TODO: FSCK... */

	/* Post execution cleanups */
	fsck_finalize();
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_fsck_usage[] = {
	"fsck [options] <volume-path>",
	"",
	"options:",
	"  -v, --version                Show version and exit",
	NULL
};

void voluta_getopt_fsck(void)
{
	int c = 1;
	int opt_index;
	int argc;
	char **argv;
	const struct option opts[] = {
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	argc = voluta_globals.cmd_argc;
	argv = voluta_globals.cmd_argv;
	while (c > 0) {
		opt_index = 0;
		c = getopt_long(argc, argv, "vh", opts, &opt_index);
		if (c == -1) {
			break;
		}
		if (c == 'v') {
			voluta_show_version_and_exit(NULL);
		} else if (c == 'h') {
			voluta_show_help_and_exit(voluta_fsck_usage);
		} else {
			voluta_die_unsupported_opt();
		}
	}
	if (optind >= argc) {
		voluta_die_no_volume_path();
	}
	voluta_globals.cmd.fsck.volume = argv[optind++];
	voluta_die_if_redundant_arg();
}

