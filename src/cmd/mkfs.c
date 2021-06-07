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
#include <stdlib.h>
#include <voluta/cmd.h>


static const char *mkfs_usage[] = {
	"mkfs [options] <repository-path>",
	"",
	"options:",
	"  -s, --size=NBYTES            File-system size",
	"  -n, --name=NAME              Private name",
	"  -e, --encrypted              Encrypted volume",
	"  -F, --force                  Force overwrite if already exists",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void mkfs_getopt(void)
{
	int opt_chr = 1;
	long size = 0;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "size", required_argument, NULL, 's' },
		{ "name", required_argument, NULL, 'n' },
		{ "encrypted", no_argument, NULL, 'e' },
		{ "force", no_argument, NULL, 'F' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("V:s:n:eFP:h", opts);
		if (opt_chr == 'V') {
			voluta_set_verbose_mode(optarg);
		} else if (opt_chr == 's') {
			size = voluta_parse_size(optarg);
			voluta_globals.cmd.mkfs.size = optarg;
			voluta_globals.cmd.mkfs.fs_size = size;
		} else if (opt_chr == 'n') {
			voluta_globals.cmd.mkfs.name = optarg;
		} else if (opt_chr == 'e') {
			voluta_globals.cmd.mkfs.encrypted = true;
		} else if (opt_chr == 'F') {
			voluta_globals.cmd.mkfs.force = true;
		} else if (opt_chr == 'P') {
			voluta_globals.cmd.mkfs.passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(mkfs_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.mkfs.repodir =
	        voluta_consume_cmdarg("repository-path", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mkfs_finalize(void)
{
	voluta_destrpy_fse_inst();
	voluta_delpass(&voluta_globals.cmd.mkfs.passphrase);
	voluta_pfree_string(&voluta_globals.cmd.mkfs.repodir_real);
}

static void mkfs_setup_check_params(void)
{
	const char *path = NULL;
	const char *passfile = NULL;

	voluta_globals.cmd.mkfs.repodir_real =
	        voluta_realpath_safe(voluta_globals.cmd.mkfs.repodir);

	path = voluta_globals.cmd.mkfs.repodir_real;
	voluta_die_if_not_empty_dir(path, true);

	if (strlen(path) >= VOLUTA_REPO_PATH_MAX) {
		voluta_die(-ENAMETOOLONG, "illegal repository path");
	}
	if (!voluta_globals.cmd.mkfs.size) {
		voluta_die_missing_arg("size");
	}
	if (voluta_globals.cmd.mkfs.encrypted) {
		passfile = voluta_globals.cmd.mkfs.passphrase_file;
		voluta_globals.cmd.mkfs.passphrase = voluta_getpass2(passfile);
	}
}

static void mkfs_create_fs_env(void)
{
	const struct voluta_fs_args args = {
		.superid =
		"11111111111111111111111111111111" \
		"11111111111111111111111111111111", /* XXX FIXME */
		.repodir = voluta_globals.cmd.mkfs.repodir_real,
		.fsname = voluta_globals.cmd.mkfs.name,
		.passwd = voluta_globals.cmd.mkfs.passphrase,
		.encrypted = voluta_globals.cmd.mkfs.encrypted,
		.encryptwr = voluta_globals.cmd.mkfs.encrypted,
		.vsize = voluta_globals.cmd.mkfs.fs_size,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	voluta_create_fse_inst(&args);
}

static void mkfs_format_volume(void)
{
	int err;
	struct voluta_fs_env *fse;

	fse = voluta_fse_inst();
	err = voluta_fse_format(fse);
	if (err) {
		voluta_die(err, "format error: %s",
		           voluta_globals.cmd.mkfs.repodir);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_mkfs(void)
{
	/* Do all cleanups upon exits */
	atexit(mkfs_finalize);

	/* Parse command's arguments */
	mkfs_getopt();

	/* Verify user's arguments */
	mkfs_setup_check_params();

	/* Prepare environment */
	mkfs_create_fs_env();

	/* Do actual mkfs */
	mkfs_format_volume();

	/* Post execution cleanups */
	mkfs_finalize();
}


