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
	voluta_destrpy_fse_inst();
	voluta_delpass(&voluta_globals.cmd.encrypt.passphrase);
	voluta_pfree_string(&voluta_globals.cmd.encrypt.volume_real);
	voluta_pfree_string(&voluta_globals.cmd.encrypt.volume_clone);
}

static void encrypt_setup_check_params(void)
{
	const char *passfile;
	const char *path;

	voluta_globals.cmd.encrypt.volume_real =
	        voluta_realpath_safe(voluta_globals.cmd.encrypt.volume);
	voluta_globals.cmd.encrypt.volume_active =
	        voluta_globals.cmd.encrypt.volume_real;

	path = voluta_globals.cmd.encrypt.volume_real;
	voluta_die_if_not_volume(path, true, false, true, NULL);
	passfile = voluta_globals.cmd.encrypt.passphrase_file;
	voluta_globals.cmd.encrypt.passphrase = voluta_getpass2(passfile);
	voluta_die_if_bad_sb(path, voluta_globals.cmd.encrypt.passphrase);
}

static void encrypt_prepare_volume_clone(void)
{
	char *volume_real = voluta_globals.cmd.encrypt.volume_real;
	char *volume_clone = voluta_clone_as_tmppath(volume_real);

	voluta_globals.cmd.encrypt.volume_clone = volume_clone;
	if (volume_clone != NULL) {
		voluta_globals.cmd.encrypt.volume_active = volume_clone;
	}
}

static void encrypt_create_fs_env(void)
{
	const struct voluta_fs_args args = {
		.volume = voluta_globals.cmd.encrypt.volume_active,
		.passwd = voluta_globals.cmd.encrypt.passphrase,
		.encrypted = false,
		.encryptwr = true,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
	};

	voluta_create_fse_inst(&args);
}

static void encrypt_volume_inplace(void)
{
	int err;
	struct voluta_fs_env *fse;
	const char *volume_path = voluta_globals.cmd.encrypt.volume;

	fse = voluta_fse_inst();
	err = voluta_fse_traverse(fse);
	if (err) {
		voluta_die(err, "encrypt failure: %s", volume_path);
	}
	err = voluta_fse_term(fse);
	if (err) {
		voluta_die(err, "terminate-fs failure: %s", volume_path);
	}
}

static void encrypt_fixup_volume_clone(void)
{
	char *volume_real = voluta_globals.cmd.encrypt.volume_real;
	char *volume_clone = voluta_globals.cmd.encrypt.volume_clone;

	if (volume_clone != NULL) {
		voluta_sys_rename(volume_clone, volume_real);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_encrypt(void)
{
	/* Do all cleanups upon exits */
	atexit(encrypt_finalize);

	/* Verify user's arguments */
	encrypt_setup_check_params();

	/* Try to use a clone */
	encrypt_prepare_volume_clone();

	/* Prepare environment */
	encrypt_create_fs_env();

	/* Do actual encrypt */
	encrypt_volume_inplace();

	/* Override volume with updated clone */
	encrypt_fixup_volume_clone();

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
			voluta_globals.cmd.encrypt.passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_encrypt_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.encrypt.volume =
	        voluta_consume_cmdarg("volume-path", true);
}

