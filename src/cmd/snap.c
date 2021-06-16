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
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <voluta/cmd.h>


static const char *snap_usage[] = {
	"snap [options] <mount-point> <volume-path>",
	"",
	NULL
};

static void snap_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("h", opts);
		if (opt_chr == 'h') {
			voluta_show_help_and_exit(snap_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.snap.point =
	        voluta_consume_cmdarg("mount-point", false);
	voluta_globals.cmd.snap.volume =
	        voluta_consume_cmdarg("volume-path", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void snap_finalize(void)
{
	voluta_pfree_string(&voluta_globals.cmd.snap.point_real);
	voluta_pfree_string(&voluta_globals.cmd.snap.volume_real);
	voluta_pfree_string(&voluta_globals.cmd.snap.volume_tmp);
}

static void snap_setup_check_params(void)
{
	int err;
	int fd = -1;
	struct stat st;
	const char *path;

	path = voluta_globals.cmd.snap.point;
	voluta_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		voluta_die(-ENOTDIR, "bad mount-point: %s", path);
	}
	if (st.st_ino != VOLUTA_INO_ROOT) {
		voluta_die(0, "not a voluta mount-point: %s", path);
	}
	voluta_globals.cmd.snap.point_real = voluta_realpath_safe(path);

	path = voluta_globals.cmd.snap.volume;
	err = voluta_sys_stat(path, &st);
	if (!err) {
		voluta_die(-EEXIST, "snap volume exists: %s", path);
	}
	if (err != -ENOENT) {
		voluta_die(err, "illegal snap volume: %s", path);
	}
	err = voluta_sys_open(path, O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		voluta_die(err, "failed to create: %s", path);
	}
	voluta_globals.cmd.snap.volume_real = voluta_realpath_safe(path);
	voluta_sys_closefd(&fd);

	path = voluta_globals.cmd.snap.volume_real;
	err = voluta_sys_unlink(path);
	if (err) {
		voluta_die(err, "unlink failed: %s", path);
	}
}

static void snap_execute(void)
{
	int err;
	int dfd = -1;
	char *last;
	char *path;
	struct stat st;
	struct voluta_ioc_snap snap = {
		.name[0] = '\0'
	};
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_VOLUME
	};

	path = voluta_globals.cmd.snap.point_real;
	err = voluta_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		voluta_die(err, "failed to open-dir: %s", path);
	}
	err = voluta_sys_syncfs(dfd);
	if (err) {
		voluta_die(err, "syncfs error: %s", path);
	}
	err = voluta_sys_ioctlp(dfd, VOLUTA_FS_IOC_QUERY, &query);
	if (err) {
		voluta_die(err, "ioctl error: %s", path);
	}
	err = voluta_sys_ioctlp(dfd, VOLUTA_FS_IOC_SNAP, &snap);
	if (err) {
		voluta_die(err, "ioctl error: %s", path);
	}
	voluta_sys_close(dfd);

	path = query.u.volume.path;
	last = strrchr(path, '/');
	if (last == NULL) {
		voluta_die(err, "can not snap: %s", path);
	}
	*last = '\0';

	voluta_globals.cmd.snap.volume_tmp =
	        path = voluta_joinpath_safe(path, snap.name);
	err = voluta_sys_stat(path, &st);
	if (err) {
		voluta_die(err, "can not stat snap: %s", path);
	}
	err = voluta_sys_rename(path, voluta_globals.cmd.snap.volume_real);
	if (err) {
		voluta_die(err, "rename failed: %s -> %s",
		           path, voluta_globals.cmd.snap.volume_real);
	}
}

static void snap_reopen_and_sync(void)
{
	int err;
	int fd = -1;
	const char *path = voluta_globals.cmd.snap.volume_real;

	err = voluta_sys_open(path, O_RDWR, 0, &fd);
	if (err) {
		voluta_die(err, "failed to open snapd volume: %s", path);
	}
	err = voluta_sys_fsync(fd);
	if (err) {
		voluta_die(err, "failed to sync snapd volume: %s", path);
	}
	voluta_sys_closefd(&fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_snap(void)
{
	/* Do all cleanups upon exits */
	atexit(snap_finalize);

	/* Parse command's arguments */
	snap_getopt();

	/* Verify user's arguments */
	snap_setup_check_params();

	/* Do actual snap */
	snap_execute();

	/* Post snap verify */
	snap_reopen_and_sync();

	/* Post execution cleanups */
	snap_finalize();
}

