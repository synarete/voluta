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
#include "voluta-prog.h"


static void clone_finalize(void)
{
	voluta_pfree_string(&voluta_globals.clone_volume_tmp);
}

static void clone_setup_check_params(void)
{
	int err;
	struct stat st;
	const char *path = voluta_globals.clone_point;

	voluta_statpath_safe(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		voluta_die(-ENOTDIR, "bad mount-point: %s", path);
	}
	if (st.st_ino != VOLUTA_INO_ROOT) {
		voluta_die(0, "not a voluta mount-point: %s", path);
	}
	path = voluta_globals.clone_volume;
	err = voluta_sys_stat(path, &st);
	if (!err) {
		voluta_die(-EEXIST, "clone volume exists: %s", path);
	}
	if (err != -ENOENT) {
		voluta_die(err, "illegal clone volume: %s", path);
	}
}

static void clone_execute(void)
{
	int err;
	int dfd = -1;
	char *last;
	char *path;
	struct stat st;
	struct voluta_ioc_clone clone = {
		.name[0] = '\0'
	};
	struct voluta_ioc_query query = {
		.qtype = VOLUTA_QUERY_VOLUME
	};

	path = voluta_globals.clone_point;
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
	err = voluta_sys_ioctlp(dfd, VOLUTA_FS_IOC_CLONE, &clone);
	if (err) {
		voluta_die(err, "ioctl error: %s", path);
	}
	voluta_sys_close(dfd);

	path = query.u.volume.path;
	last = strrchr(path, '/');
	if (last == NULL) {
		voluta_die(err, "can not clone: %s", path);
	}
	*last = '\0';

	voluta_globals.clone_volume_tmp =
		path = voluta_joinpath_safe(path, clone.name);
	err = voluta_sys_stat(path, &st);
	if (err) {
		voluta_die(err, "can not stat clone: %s", path);
	}
	err = voluta_sys_rename(path, voluta_globals.clone_volume);
	if (err) {
		voluta_die(err, "rename failed: %s -> %s",
			   path, voluta_globals.clone_volume);
	}
}

static void clone_reopen_and_sync(void)
{
	int err;
	int fd = -1;
	const char *path = voluta_globals.clone_volume;

	err = voluta_sys_open(path, O_RDWR, 0, &fd);
	if (err) {
		voluta_die(err, "failed to open cloned volume: %s", path);
	}
	err = voluta_sys_fsync(fd);
	if (err) {
		voluta_die(err, "failed to sync cloned volume: %s", path);
	}
	voluta_sys_closefd(&fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_clone(void)
{
	/* Do all cleanups upon exits */
	atexit(clone_finalize);

	/* Verify user's arguments */
	clone_setup_check_params();

	/* Do actual clone */
	clone_execute();

	/* Post clone verify */
	clone_reopen_and_sync();

	/* Post execution cleanups */
	clone_finalize();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_clone_usage[] = {
	"clone [options] <mount-point> <volume-path>",
	"",
	NULL
};

void voluta_getopt_clone(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("h", opts);
		if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_clone_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.clone_point =
		voluta_consume_cmdarg("mount-point", false);
	voluta_globals.clone_volume =
		voluta_consume_cmdarg("volume-path", true);
}

