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

static void archive_finalize(void)
{
	voluta_fini_archiver_inst();
	voluta_delpass(&voluta_globals.archive_passphrase);
	voluta_pfree_string(&voluta_globals.archive_src_real);
	voluta_pfree_string(&voluta_globals.archive_src_dir);
	voluta_pfree_string(&voluta_globals.archive_src_name);
	voluta_pfree_string(&voluta_globals.archive_dst_real);
	voluta_pfree_string(&voluta_globals.archive_dst_path);
}

static void archive_setup_check_source(void)
{
	voluta_globals.archive_src_real =
		voluta_realpath_safe(voluta_globals.archive_src);
	voluta_die_if_not_reg(voluta_globals.archive_src_real, false);

	voluta_globals.archive_src_dir =
		voluta_dirpath_safe(voluta_globals.archive_src_real);
	voluta_globals.archive_src_name =
		voluta_basename_safe(voluta_globals.archive_src_real);
}

static void archive_setup_check_dest(void)
{
	voluta_globals.archive_dst_real =
		voluta_realpath_safe(voluta_globals.archive_dst);
	voluta_die_if_not_dir(voluta_globals.archive_dst_real, false);
	voluta_globals.archive_dst_path =
		voluta_joinpath_safe(voluta_globals.archive_dst_real,
				     voluta_globals.archive_src_name);
	voluta_die_if_exists(voluta_globals.archive_dst_path);
}

static void archive_setup_check_pass(void)
{
	enum voluta_zb_flags zbf;

	voluta_die_if_not_volume(voluta_globals.archive_src_real, NULL, &zbf);
}

static void archive_setup_check_params(void)
{
	archive_setup_check_source();
	archive_setup_check_dest();
	archive_setup_check_pass();
}

static void archive_create_setup_env(void)
{
	int err;
	struct voluta_archiver *arc = NULL;
	struct voluta_ar_args args = {
		.passph = voluta_globals.archive_passphrase,
		.volume = voluta_globals.archive_src_real,
		.blobsdir = voluta_globals.archive_dst_real,
		.arcname = voluta_globals.archive_src_name,
	};

	voluta_init_archiver_inst();
	arc = voluta_archiver_inst();
	err = voluta_archiver_setargs(arc, &args);
	if (err) {
		voluta_die(err, "illegal params");
	}
}

static void archive_run(void)
{
	int err;
	struct voluta_archiver *arc = voluta_archiver_inst();

	err = voluta_archiver_export(arc);
	if (err) {
		voluta_die(err, "archive failed");
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_archive(void)
{
	/* Do all cleanups upon exits */
	atexit(archive_finalize);

	/* Verify user's arguments */
	archive_setup_check_params();

	/* Setup environment instance */
	archive_create_setup_env();

	/* Do actual archive */
	archive_run();

	/* Post execution cleanups */
	archive_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_archive_usage[] = {
	"archive <volume-file> <archive-dir>",
	"",
	"options:",
	"  -P, --passphrase-file=PATH   Passphrase input file (unsafe)",
	NULL
};

void voluta_getopt_archive(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("P:h", opts);
		if (opt_chr == 'P') {
			voluta_globals.archive_passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_archive_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.archive_src =
		voluta_consume_cmdarg("volume-file", false);
	voluta_globals.archive_dst =
		voluta_consume_cmdarg("archive-dir", true);
}

