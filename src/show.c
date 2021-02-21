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
#include <sys/mount.h>
#include "voluta-prog.h"


static void show_finalize(void)
{
	/* no-op */
}

static void show_setup_check_params(void)
{
	struct stat st;

	voluta_stat_dir_or_reg(voluta_globals.cmd.show.pathname, &st);
}

static void show_do_ioctl_query(struct voluta_ioc_query *query)
{
	int err;
	int fd = -1;
	const char *path = voluta_globals.cmd.show.pathname;

	err = voluta_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		voluta_die(err, "failed to open: %s", path);
	}
	err = voluta_sys_ioctlp(fd, VOLUTA_FS_IOC_QUERY, query);
	voluta_sys_close(fd);
	if (err) {
		voluta_die(err, "ioctl error: %s", path);
	}
}

static void show_version(void)
{
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_VERSION
	};

	show_do_ioctl_query(&query);
	printf("version:        %s\n", query.u.version.string);
}

static void show_volume(void)
{
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_VOLUME
	};

	show_do_ioctl_query(&query);
	printf("volume:         %s\n", query.u.volume.path);
}

static const char *show_ms_flag(long flag, long mask)
{
	return ((flag & mask) == mask) ? "1" : "0";
}

static void show_fsinfo(void)
{
	long ms_flags;
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_FSINFO
	};

	show_do_ioctl_query(&query);
	ms_flags = (long)query.u.fsinfo.msflags;

	printf("uptime-seconds: %ld\n", query.u.fsinfo.uptime);
	printf("encrypt:        %d\n", (int)query.u.fsinfo.encrypt);
	printf("mount-rdonly:   %s\n", show_ms_flag(ms_flags, MS_RDONLY));
	printf("mount-nodev:    %s\n", show_ms_flag(ms_flags, MS_NODEV));
	printf("mount-nosuid:   %s\n", show_ms_flag(ms_flags, MS_NOSUID));
	printf("mount-noexec:   %s\n", show_ms_flag(ms_flags, MS_NOEXEC));
	printf("mount-noexec:   %s\n", show_ms_flag(ms_flags, MS_NOEXEC));
}

static void show_execute(void)
{
	show_version();
	show_volume();
	show_fsinfo();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_show(void)
{
	/* Do all cleanups upon exits */
	atexit(show_finalize);

	/* Verify user's arguments */
	show_setup_check_params();

	/* Do actual query + show */
	show_execute();

	/* Post execution cleanups */
	show_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_show_usage[] = {
	"show <pathname>",
	NULL
};


void voluta_getopt_show(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("h", opts);
		if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_show_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.show.pathname =
	        voluta_consume_cmdarg("pathname", true);
}

