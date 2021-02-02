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
#include <sys/resource.h>
#include <sys/capability.h>
#include <unistd.h>
#include <error.h>
#include <locale.h>
#include <time.h>
#include "voluta-prog.h"


/* Local functions forward declarations */
static void voluta_parse_global_args(void);
static void voluta_parse_command_args(void);
static void voluta_exec_subcmd(void);


/*
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                           *
 *                                                                           *
 *                       Voluta: File-System in a File                       *
 *                                                                           *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
int main(int argc, char *argv[])
{
	/* Setup process defaults */
	voluta_setup_globals(argc, argv);

	/* Parse top-level arguments */
	voluta_parse_global_args();

	/* Parse sub-command arguments */
	voluta_parse_command_args();

	/* Common process initializations */
	voluta_init_process();

	/* Execute sub-command by hook */
	voluta_exec_subcmd();

	/* Post execution cleanup */
	voluta_burnstack();

	/* Goodbye ;) */
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define DEFCMD(cmd_) \
	{ #cmd_, voluta_getopt_##cmd_, voluta_execute_##cmd_ }

static bool equals(const char *s1, const char *s2)
{
	return (s1 && s2 && !strcmp(s1, s2));
}

static bool equals2(const char *s, const char *s1, const char *s2)
{
	return equals(s, s1) || equals(s, s2);
}

static const struct voluta_cmd_info g_cmd_info[] = {
	DEFCMD(mkfs),
	DEFCMD(mount),
	DEFCMD(umount),
	DEFCMD(fsck),
	DEFCMD(show),
	DEFCMD(clone),
	DEFCMD(export),
	DEFCMD(import),
};

static const struct voluta_cmd_info *cmt_info_of(const char *cmd_name)
{
	const struct voluta_cmd_info *cmdi = NULL;

	for (size_t i = 0; i < VOLUTA_ARRAY_SIZE(g_cmd_info); ++i) {
		cmdi = &g_cmd_info[i];
		if (equals(cmd_name, cmdi->name)) {
			return cmdi;
		}
	}
	return NULL;
}

static void show_main_help_and_exit(int exit_code)
{
	printf("%s <command> [options]\n\n", voluta_globals.name);
	printf("main commands: \n");
	for (size_t i = 0; i < VOLUTA_ARRAY_SIZE(g_cmd_info); ++i) {
		printf("  %s\n", g_cmd_info[i].name);
	}
	exit(exit_code);
}

static void voluta_grab_args(void)
{
	if (voluta_globals.argc <= 1) {
		show_main_help_and_exit(1);
	}
	voluta_globals.cmd_name = voluta_globals.argv[1];
	voluta_globals.cmd_argc = voluta_globals.argc - 1;
	voluta_globals.cmd_argv = voluta_globals.argv + 1;
}

static void voluta_parse_global_args(void)
{
	const char *cmd_name = NULL;

	voluta_grab_args();
	cmd_name = voluta_globals.cmd_name;

	if (equals2(cmd_name, "-v", "--version")) {
		voluta_show_version_and_exit(NULL);
	}
	if (equals2(cmd_name, "-h", "--help")) {
		show_main_help_and_exit(0);
	}
	voluta_globals.cmd_info = cmt_info_of(cmd_name);
}

static void voluta_parse_command_args(void)
{
	if (voluta_globals.cmd_info == NULL) {
		show_main_help_and_exit(1);
	}
	voluta_globals.cmd_info->getopt_hook();
}

static void voluta_exec_subcmd(void)
{
	const struct voluta_cmd_info *cmdi = voluta_globals.cmd_info;

	if (cmdi && cmdi->action_hook) {
		cmdi->action_hook();
	}
}
