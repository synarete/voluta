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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <locale.h>
#include <getopt.h>

#include "unitest.h"

/* Local variables */
struct ut_globals ut_globals;

/* Local functions */
static void ut_setup_globals(int argc, char *argv[]);
static void ut_show_program_info(void);
static void ut_show_done(void);
static void ut_parse_args(void);
static void ut_setup_tracing(void);
static void ut_setup_args(void);
static void ut_init_lib(void);
static void ut_atexit(void);

/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *                        Voluta unit-testing program                        *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Do all cleanups upon exits */
	atexit(ut_atexit);

	/* Setup process defaults */
	ut_setup_globals(argc, argv);

	/* Disable tracing */
	ut_setup_tracing();

	/* Parse command-line arguments */
	ut_parse_args();

	/* Require valid test directory */
	ut_setup_args();

	/* Prepare libvoluta */
	ut_init_lib();

	/* Show generic info */
	ut_show_program_info();

	/* Actual tests execution... */
	ut_execute_tests();

	/* ...and we are done! */
	ut_show_done();

	return 0;
}

static void ut_setup_globals(int argc, char *argv[])
{
	ut_globals.argc = argc;
	ut_globals.argv = argv;

	umask(0002);
	setlocale(LC_ALL, "");
	voluta_mclock_now(&ut_globals.start_ts);
}

static void ut_setup_tracing(void)
{
	ut_globals.log_mask =
		VOLUTA_LOG_ERROR | VOLUTA_LOG_CRIT | VOLUTA_LOG_STDOUT;
	voluta_set_logmaskp(&ut_globals.log_mask);
}

static void ut_show_program_info(void)
{
	printf("%s %s (encrypt=%d spliced=%d)\n",
	       program_invocation_short_name, voluta_version.string,
	       ut_globals.encrypt_mode, ut_globals.spliced_mode);
}

static void ut_show_done(void)
{
	struct timespec dur;

	voluta_mclock_dur(&ut_globals.start_ts, &dur);
	printf("%s: done (%ld.%03lds)\n", program_invocation_short_name,
	       dur.tv_sec, dur.tv_nsec / 1000000L);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void show_help_and_exit(void)
{
	printf("%s <testdir> \n\n", program_invocation_short_name);
	puts("options:");
	puts(" -t, --test=<name>     Run tests which contains name");
	puts(" -e, --encrypt=<0|1>   Encrypted mode");
	puts(" -s, --spliced=<0|1>   Spliced mode");
	puts(" -v, --version         Show version info");
	exit(EXIT_SUCCESS);
}

static void show_version_and_exit(void)
{
	ut_show_program_info();
	exit(EXIT_SUCCESS);
}

static void ut_parse_args(void)
{
	int opt_chr = 1;
	int opt_index;
	struct option long_opts[] = {
		{ "test", required_argument, NULL, 't' },
		{ "encrypt", required_argument, NULL, 'e' },
		{ "spliced", required_argument, NULL, 's' },
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_index = 0;
		opt_chr = getopt_long(ut_globals.argc, ut_globals.argv,
				      "vht:e:s:", long_opts, &opt_index);
		if (opt_chr == 't') {
			ut_globals.test_name = optarg;
		} else if (opt_chr == 'e') {
			ut_globals.encrypt_mode = !strcmp(optarg, "1");
		} else if (opt_chr == 's') {
			ut_globals.spliced_mode = !strcmp(optarg, "1");
		} else if (opt_chr == 'v') {
			show_version_and_exit();
		} else if (opt_chr == 'h') {
			show_help_and_exit();
		} else if (opt_chr > 0) {
			error(EXIT_FAILURE, 0, "bad option 0%o", opt_chr);
		}
	}

	if (optind >= ut_globals.argc) {
		/* no-run without test-dir */
		exit(EXIT_SUCCESS);
	}
	ut_globals.test_dir = ut_globals.argv[optind++];
	if (optind < ut_globals.argc) {
		error(EXIT_FAILURE, 0,
		      "redundant: %s", ut_globals.argv[optind]);
	}
}

static void ut_setup_args(void)
{
	int err;
	struct stat st;

	ut_globals.test_dir_real = realpath(ut_globals.test_dir, NULL);
	if (ut_globals.test_dir_real == NULL) {
		error(EXIT_FAILURE, errno,
		      "no realpath: %s", ut_globals.test_dir);
	}
	err = voluta_sys_stat(ut_globals.test_dir_real, &st);
	if (err) {
		error(EXIT_FAILURE, errno,
		      "stat failure: %s", ut_globals.test_dir_real);
	}
	if (!S_ISDIR(st.st_mode)) {
		error(EXIT_FAILURE, ENOTDIR,
		      "invalid: %s", ut_globals.test_dir_real);
	}
	err = voluta_sys_access(ut_globals.test_dir_real, R_OK | W_OK | X_OK);
	if (err) {
		error(EXIT_FAILURE, -err,
		      "no access: %s", ut_globals.test_dir_real);
	}
}

static void ut_init_lib(void)
{
	int err;

	err = voluta_lib_init();
	if (err) {
		error(EXIT_FAILURE, -err, "failed to init libvoluta");
	}
}

static void ut_pfree(char **pp)
{
	if (*pp != NULL) {
		free(*pp);
		*pp = NULL;
	}
}

static void ut_atexit(void)
{
	ut_pfree(&ut_globals.test_dir_real);
}


