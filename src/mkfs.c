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


static void mkfs_finalize(void)
{
	voluta_fini_fs_env();
	voluta_delpass(&voluta_globals.cmd.mkfs.passphrase);
}

static void mkfs_setup_check_params(void)
{
	int err;
	int exists;
	size_t len;
	loff_t size;
	loff_t *psz;
	struct stat st;
	const char *passfile;
	const char *path = voluta_globals.cmd.mkfs.volume;

	len = strlen(path);
	if (len >= VOLUTA_VOLUME_PATH_MAX) {
		voluta_die(-ENAMETOOLONG, "illegal volume path");
	}
	err = voluta_sys_stat(path, &st);
	exists = !err;

	if (exists && S_ISDIR(st.st_mode)) {
		voluta_die(-EISDIR, "illegal volume path: %s", path);
	}
	if (exists && !S_ISBLK(st.st_mode) &&
	    !voluta_globals.cmd.mkfs.force && !S_ISBLK(st.st_mode)) {
		voluta_die(err, "file exists: %s", path);
	}
	if (err && (err != -ENOENT)) {
		voluta_die(err, "stat failure: %s", path);
	}
	if (!voluta_globals.cmd.mkfs.size) {
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

static void mkfs_create_setup_fs_env(void)
{
	int err;
	struct voluta_fs_env *fse = NULL;
	const struct voluta_fs_args args = {
		.fsname = voluta_globals.cmd.mkfs.name,
		.volume = voluta_globals.cmd.mkfs.volume,
		.passwd = voluta_globals.cmd.mkfs.passphrase,
		.encrypted = voluta_globals.cmd.mkfs.encrypted,
		.encryptwr = voluta_globals.cmd.mkfs.encrypted,
		.vsize = voluta_globals.cmd.mkfs.volume_size,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	voluta_init_fs_env();
	fse = voluta_fs_env_inst();
	err = voluta_fse_setargs(fse, &args);
	if (err) {
		voluta_die(err, "illegal mkfs params");
	}
}

static void mkfs_format_volume(void)
{
	int err;
	struct voluta_fs_env *fse;
	const char *volume_path = voluta_globals.cmd.mkfs.volume;

	fse = voluta_fs_env_inst();
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

	/* Verify user's arguments */
	mkfs_setup_check_params();

	/* Prepare environment */
	mkfs_create_setup_fs_env();

	/* Do actual mkfs */
	mkfs_format_volume();

	/* Post execution cleanups */
	mkfs_finalize();
}


/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_mkfs_usage[] = {
	"mkfs [options] <volume-path>",
	"",
	"options:",
	"  -s, --size=NBYTES            Volume size",
	"  -n, --name=NAME              Private name",
	"  -e, --encrypted              Encrypted volume",
	"  -F, --force                  Force overwrite if volume exists",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

void voluta_getopt_mkfs(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "size", required_argument, NULL, 's' },
		{ "name", required_argument, NULL, 'n' },
		{ "encrypted", no_argument, NULL, 'e' },
		{ "force", no_argument, NULL, 'F' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("s:n:eFP:h", opts);
		if (opt_chr == 's') {
			voluta_globals.cmd.mkfs.size = optarg;
			voluta_globals.cmd.mkfs.volume_size =
				voluta_parse_size(optarg);
		} else if (opt_chr == 'n') {
			voluta_globals.cmd.mkfs.name = optarg;
		} else if (opt_chr == 'e') {
			voluta_globals.cmd.mkfs.encrypted = true;
		} else if (opt_chr == 'F') {
			voluta_globals.cmd.mkfs.force = true;
		} else if (opt_chr == 'P') {
			voluta_globals.cmd.mkfs.passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_mkfs_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.mkfs.volume =
		voluta_consume_cmdarg("volume-path", true);
}

