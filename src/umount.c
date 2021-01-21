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


static void umount_finalize(void)
{
	voluta_pfree_string(&voluta_globals.umount_point_real);
}

static void umount_setup_check_params(void)
{
	voluta_globals.umount_point_real =
		voluta_realpath_safe(voluta_globals.umount_point);

	voluta_die_if_not_mntdir(voluta_globals.umount_point_real, false);
	voluta_die_if_no_mountd();
}

static void umount_send_recv(void)
{
	int err;
	const char *path;

	if (voluta_globals.umount_point_real != NULL) {
		path = voluta_globals.umount_point_real;
	} else {
		path = voluta_globals.umount_point;
	}
	err = voluta_rpc_umount(path, getuid(), getgid());
	if (err) {
		voluta_die(err, "umount failed: %s", path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_umount(void)
{
	/* Do all cleanups upon exits */
	atexit(umount_finalize);

	/* Verify user's arguments */
	umount_setup_check_params();

	/* Do actual umount */
	umount_send_recv();

	/* Post execution cleanups */
	umount_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_umount_usage[] = {
	"umount [options] <mount-point>",
	"",
	"options:",
	"  -f, --force                  Forced umount",
	NULL
};

void voluta_getopt_umount(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "force", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("fh", opts);
		if (opt_chr == 'f') {
			voluta_globals.umount_force = true;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_umount_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.umount_point =
		voluta_consume_cmdarg("mount-point", true);
}

