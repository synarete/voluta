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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <locale.h>
#include <getopt.h>

#include "voluta-prog.h"

static void mountd_getopt(void);
static void mountd_init_process(void);
static void mountd_enable_signals(void);
static void mountd_boostrap_process(void);
static void mountd_create_setup_env(void);
static void mountd_trace_start(void);
static void mound_execute_ms(void);
static void mountd_finalize(void);
static void mountd_load_mntrules(void);

static struct voluta_mntrules *g_mountd_mntrules;


/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *                         Voluta's Mounting-Daemon                          *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Setup process defaults */
	voluta_setup_globals(argc, argv);

	/* Parse command-line options */
	mountd_getopt();

	/* Common process initializations */
	mountd_init_process();

	/* Process specific bootstrap sequence */
	mountd_boostrap_process();

	/* Load mount-rules from config-file */
	mountd_load_mntrules();

	/* Setup enviroment instance */
	mountd_create_setup_env();

	/* Say something */
	mountd_trace_start();

	/* Allow halt by signal */
	mountd_enable_signals();

	/* Execute as long as needed... */
	mound_execute_ms();

	/* Post execution cleanups */
	mountd_finalize();

	/* Goodbye ;) */
	return 0;
}

static void mountd_init_process(void)
{
	voluta_globals.log_mask |=
		VOLUTA_LOG_WARN | VOLUTA_LOG_ERROR | \
		VOLUTA_LOG_CRIT | VOLUTA_LOG_STDOUT;
	voluta_init_process();
}

static void mountd_halt_by_signal(int signum)
{
	struct voluta_ms_env *ms_env = voluta_ms_env_inst();

	if (ms_env) {
		voluta_mse_halt(ms_env, signum);
	}
}

static void mountd_enable_signals(void)
{
	voluta_signal_callback_hook = mountd_halt_by_signal;
	voluta_register_sigactions();
}

static void mountd_boostrap_process(void)
{
	if (!voluta_globals.allow_coredump) {
		voluta_setrlimit_nocore();
	}
	if (!voluta_globals.disable_ptrace) {
		voluta_prctl_non_dumpable();
	}
	atexit(mountd_finalize);
}

static void mountd_create_setup_env(void)
{
	struct voluta_ms_env *ms_env = NULL;

	voluta_init_ms_env();
	ms_env = voluta_ms_env_inst();
	if (ms_env == NULL) {
		voluta_die(0, "ilternal error");
	}
}

static void mountd_trace_start(void)
{
	voluta_log_process_info();
}

static void mountd_load_mntrules(void)
{
	g_mountd_mntrules =
		voluta_parse_mntrules(voluta_globals.mountd_confpath);
}

static void mountd_drop_mntrules(void)
{
	if (g_mountd_mntrules != NULL) {
		voluta_free_mntrules(g_mountd_mntrules);
		g_mountd_mntrules = NULL;
	}
}

static void mountd_finalize(void)
{
	voluta_fini_ms_env();
	mountd_drop_mntrules();
}

static void mound_execute_ms(void)
{
	int err;
	struct voluta_ms_env *ms_env = voluta_ms_env_inst();

	err = voluta_mse_serve(ms_env, g_mountd_mntrules);
	if (err) {
		voluta_die(err, "mount-service error");
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_mountd_usage[] = {
	"[options] [-f conf]",
	"",
	"options:",
	"  -f, --conf=CONF              Mount-rules config file",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..2)",
	"  -v, --version                Show version and exit",
	NULL
};

static void mountd_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "conf", required_argument, NULL, 'f' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "version", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("f:V:vh", opts);
		if (opt_chr == -1) {
			break;
		}
		if (opt_chr == 'f') {
			voluta_globals.mountd_confpath = optarg;
		} else if (opt_chr == 'V') {
			voluta_set_verbose_mode(optarg);
		} else if (opt_chr == 'v') {
			voluta_show_version_and_exit("voluta-mountd");
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_mountd_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_die_if_redundant_arg();
	if (!voluta_globals.mountd_confpath) {
		voluta_die_missing_arg("conf");
	}
}

