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


static const char *mkfs_usage[] = {
	"mkfs [options] <volume-path>",
	"",
	"options:",
	"  -s, --size=NBYTES            Volume size",
	"  -n, --name=NAME              Private name",
	"  -e, --encrypted              Encrypted volume",
	"  -F, --force                  Force overwrite if volume exists",
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
			voluta_globals.cmd.mkfs.volume_size = size;
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
	voluta_globals.cmd.mkfs.volume =
	        voluta_consume_cmdarg("volume-path", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mkfs_finalize(void)
{
	voluta_destrpy_fse_inst();
	voluta_delpass(&voluta_globals.cmd.mkfs.passphrase);
	voluta_pfree_string(&voluta_globals.cmd.mkfs.volume_abs);
}

static void mkfs_setup_check_params(void)
{
	int err;
	int exists;
	int blkdev;
	size_t len = 0;
	loff_t size = 0;
	loff_t *psz = NULL;
	struct stat st = { .st_size = 0 };
	const mode_t mask = S_IRUSR | S_IWUSR;
	const char *path = NULL;
	const char *passfile = NULL;

	voluta_globals.cmd.mkfs.volume_abs =
	        voluta_abspath_safe(voluta_globals.cmd.mkfs.volume);

	path = voluta_globals.cmd.mkfs.volume_abs;
	len = strlen(path);
	if (len >= VOLUTA_VOLUME_PATH_MAX) {
		voluta_die(-ENAMETOOLONG, "illegal volume path");
	}
	err = voluta_sys_stat(path, &st);
	if (err && (err != -ENOENT)) {
		voluta_die(err, "stat failure: %s", path);
	}
	exists = !err;
	if (exists && S_ISDIR(st.st_mode)) {
		voluta_die(-EISDIR, "illegal volume path: %s", path);
	}
	blkdev = S_ISBLK(st.st_mode);
	if (exists && !blkdev && !voluta_globals.cmd.mkfs.force) {
		voluta_die(err, "file exists: %s", path);
	}
	if (exists && ((st.st_mode & mask) != mask)) {
		voluta_die(-EPERM, "no read-write permissions: %s", path);
	}
	if (blkdev) {
		voluta_globals.cmd.mkfs.volume_size =
		        voluta_blkgetsize_safe(path);
	} else if (!voluta_globals.cmd.mkfs.size) {
		voluta_die_missing_arg("size");
	}
	psz = &voluta_globals.cmd.mkfs.volume_size;
	size = voluta_globals.cmd.mkfs.volume_size;
	err = voluta_resolve_volume_size(path, size, psz);
	if (err) {
		voluta_die(0, "unsupported size: %ld", size);
	}
	if (voluta_globals.cmd.mkfs.encrypted) {
		passfile = voluta_globals.cmd.mkfs.passphrase_file;
		voluta_globals.cmd.mkfs.passphrase = voluta_getpass2(passfile);
	}
}

static void mkfs_create_fs_env(void)
{
	const struct voluta_fs_args args = {
		.fsname = voluta_globals.cmd.mkfs.name,
		.volume = voluta_globals.cmd.mkfs.volume_abs,
		.passwd = voluta_globals.cmd.mkfs.passphrase,
		.encrypted = voluta_globals.cmd.mkfs.encrypted,
		.encryptwr = voluta_globals.cmd.mkfs.encrypted,
		.vsize = voluta_globals.cmd.mkfs.volume_size,
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
	const char *volume_path = voluta_globals.cmd.mkfs.volume;

	fse = voluta_fse_inst();
	err = voluta_fse_format(fse);
	if (err) {
		voluta_die(err, "format error: %s", volume_path);
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


