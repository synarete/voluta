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

static void export_finalize(void)
{
	voluta_fini_archiver_inst();
	voluta_delpass(&voluta_globals.cmd.export.passphrase);
	voluta_pfree_string(&voluta_globals.cmd.export.volume_real);
	voluta_pfree_string(&voluta_globals.cmd.export.volume_name);
	voluta_pfree_string(&voluta_globals.cmd.export.archive_real);
	voluta_pfree_string(&voluta_globals.cmd.export.archive_path);
}

static void export_setup_check_volume(void)
{
	voluta_globals.cmd.export.volume_real =
		voluta_realpath_safe(voluta_globals.cmd.export.volume);
	voluta_die_if_not_reg(voluta_globals.cmd.export.volume_real, false);

	voluta_globals.cmd.export.volume_name =
		voluta_basename_safe(voluta_globals.cmd.export.volume_real);
	voluta_die_if_not_volume(voluta_globals.cmd.export.volume_real,
				 false, false, false, NULL);
}

static void export_setup_check_archive(void)
{
	voluta_globals.cmd.export.archive_real =
		voluta_realpath_safe(voluta_globals.cmd.export.archive);
	voluta_die_if_not_dir(voluta_globals.cmd.export.archive_real, false);
	voluta_globals.cmd.export.archive_path =
		voluta_joinpath_safe(voluta_globals.cmd.export.archive_real,
				     voluta_globals.cmd.export.volume_name);
	voluta_die_if_exists(voluta_globals.cmd.export.archive_path);
}

static void export_setup_check_pass(void)
{
	const char *path = voluta_globals.cmd.export.volume_real;

	voluta_die_if_not_volume(path, false, false, false, NULL);
}

static void export_setup_check_params(void)
{
	export_setup_check_volume();
	export_setup_check_archive();
	export_setup_check_pass();
}

static void export_create_setup_env(void)
{
	int err;
	struct voluta_archiver *arc = NULL;
	struct voluta_ar_args args = {
		.passph = voluta_globals.cmd.export.passphrase,
		.volume = voluta_globals.cmd.export.volume_real,
		.blobsdir = voluta_globals.cmd.export.archive_real,
		.arcname = voluta_globals.cmd.export.volume_name,
	};

	voluta_init_archiver_inst();
	arc = voluta_archiver_inst();
	err = voluta_archiver_setargs(arc, &args);
	if (err) {
		voluta_die(err, "illegal params");
	}
}

static void export_run(void)
{
	int err;
	struct voluta_archiver *arc = voluta_archiver_inst();

	err = voluta_archiver_export(arc);
	if (err) {
		voluta_die(err, "export failed");
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_export(void)
{
	/* Do all cleanups upon exits */
	atexit(export_finalize);

	/* Verify user's arguments */
	export_setup_check_params();

	/* Setup environment instance */
	export_create_setup_env();

	/* Do actual export */
	export_run();

	/* Post execution cleanups */
	export_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_export_usage[] = {
	"export <volume-file> <export-dir>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase input file (unsafe)",
	NULL
};

void voluta_getopt_export(void)
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
			voluta_globals.cmd.export.passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_export_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.export.volume =
		voluta_consume_cmdarg("volume-file", false);
	voluta_globals.cmd.export.archive =
		voluta_consume_cmdarg("export-dir", true);
}

