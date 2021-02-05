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


static void encrypt_finalize(void)
{
	voluta_fini_fs_env();
	voluta_delpass(&voluta_globals.encrypt_passphrase);
	voluta_pfree_string(&voluta_globals.encrypt_volume_real);
}

static void encrypt_setup_check_params(void)
{
	const char *passfile;
	const char *path;

	voluta_globals.encrypt_volume_real =
		voluta_realpath_safe(voluta_globals.encrypt_volume);

	path = voluta_globals.encrypt_volume_real;
	voluta_die_if_not_volume(path, true, false, true, NULL);
	passfile = voluta_globals.encrypt_passphrase_file;
	voluta_globals.encrypt_passphrase = voluta_getpass2(passfile);
}

static void encrypt_create_setup_fs_env(void)
{
	int err;
	struct voluta_fs_env *fse = NULL;
	const struct voluta_fs_args args = {
		.volume = voluta_globals.encrypt_volume,
		.passwd = voluta_globals.encrypt_passphrase,
		.encrypted = false,
		.encryptwr = true,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	voluta_init_fs_env();
	fse = voluta_fs_env_inst();
	err = voluta_fse_setargs(fse, &args);
	if (err) {
		voluta_die(err, "illegal encrypt params");
	}
}

static void encrypt_apply_volume(void)
{
	int err;
	struct voluta_fs_env *fse;
	const char *volume_path = voluta_globals.encrypt_volume;

	fse = voluta_fs_env_inst();
	err = voluta_fse_encrypt(fse);
	if (err) {
		voluta_die(err, "encrypt failure: %s", volume_path);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_encrypt(void)
{
	/* Do all cleanups upon exits */
	atexit(encrypt_finalize);

	/* Verify user's arguments */
	encrypt_setup_check_params();

	/* Prepare environment */
	encrypt_create_setup_fs_env();

	/* Do actual encrypt */
	encrypt_apply_volume();

	/* Post execution cleanups */
	encrypt_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_encrypt_usage[] = {
	"encrypt [options] <volume-path>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

void voluta_getopt_encrypt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "verbose", required_argument, NULL, 'V' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("V:P:h", opts);
		if (opt_chr == 'V') {
			voluta_set_verbose_mode(optarg);
		} else if (opt_chr == 'P') {
			voluta_globals.encrypt_passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_encrypt_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.encrypt_volume =
		voluta_consume_cmdarg("volume-path", true);
}

