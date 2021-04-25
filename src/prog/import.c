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


static const char *import_usage[] = {
	"import <archive-file> <volume-dir>",
	"",
	"options:",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..3)",
	"  -P, --passphrase-file=PATH   Passphrase input file (unsafe)",
	NULL
};

static void import_getopt(void)
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
			voluta_globals.cmd.import.passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(import_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.import.archive =
	        voluta_consume_cmdarg("archive-file", false);
	voluta_globals.cmd.import.volume =
	        voluta_consume_cmdarg("volume-dir", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void import_finalize(void)
{
	voluta_destroy_arc_inst();
	voluta_delpass(&voluta_globals.cmd.import.passphrase);
	voluta_pfree_string(&voluta_globals.cmd.import.archive_real);
	voluta_pfree_string(&voluta_globals.cmd.import.archive_dir);
	voluta_pfree_string(&voluta_globals.cmd.import.archive_name);
	voluta_pfree_string(&voluta_globals.cmd.import.volume_real);
	voluta_pfree_string(&voluta_globals.cmd.import.volume_path);
}

static void import_setup_check_archive(void)
{
	voluta_globals.cmd.import.archive_real =
	        voluta_realpath_safe(voluta_globals.cmd.import.archive);
	voluta_die_if_not_reg(voluta_globals.cmd.import.archive_real, false);

	voluta_globals.cmd.import.archive_dir =
	        voluta_dirpath_safe(voluta_globals.cmd.import.archive_real);
	voluta_globals.cmd.import.archive_name =
	        voluta_basename_safe(voluta_globals.cmd.import.archive_real);
}

static void import_setup_check_volume(void)
{
	voluta_globals.cmd.import.volume_real =
	        voluta_realpath_safe(voluta_globals.cmd.import.volume);
	voluta_die_if_not_dir(voluta_globals.cmd.import.volume_real, false);
	voluta_globals.cmd.import.volume_path =
	        voluta_joinpath_safe(voluta_globals.cmd.import.volume_real,
	                             voluta_globals.cmd.import.archive_name);
	voluta_die_if_exists(voluta_globals.cmd.import.volume_path);
}

static void import_setup_check_pass(void)
{
	voluta_die_if_not_archive(voluta_globals.cmd.import.archive_real);
}

static void import_setup_check_params(void)
{
	import_setup_check_archive();
	import_setup_check_volume();
	import_setup_check_pass();
}

static void import_create_arc_inst(void)
{
	struct voluta_ar_args args = {
		.passwd = voluta_globals.cmd.import.passphrase,
		.volume = voluta_globals.cmd.import.volume_path,
		.blobsdir = voluta_globals.cmd.import.archive_dir,
		.arcname = voluta_globals.cmd.import.archive_name,
		.memwant = 4 * VOLUTA_GIGA /* TODO: from command line */
	};

	voluta_create_arc_inst(&args);
}

static void import_run(void)
{
	int err;
	struct voluta_archiver *arc = voluta_arc_inst();

	err = voluta_archiver_import(arc);
	if (err) {
		voluta_die(err, "import failed");
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_import(void)
{
	/* Do all cleanups upon exits */
	atexit(import_finalize);

	/* Parse command's arguments */
	import_getopt();

	/* Verify user's arguments */
	import_setup_check_params();

	/* Setup environment instance */
	import_create_arc_inst();

	/* Do actual import */
	import_run();

	/* Post execution cleanups */
	import_finalize();
}
