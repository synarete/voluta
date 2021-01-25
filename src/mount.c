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
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include "voluta-prog.h"


static void mount_halt_by_signal(int signum)
{
	struct voluta_fs_env *fse = voluta_fs_env_inst();

	if (fse) {
		voluta_fse_halt(fse, signum);
	}
}

static void mount_enable_signals(void)
{
	voluta_signal_callback_hook = mount_halt_by_signal;
	voluta_register_sigactions();
}

static void mount_execute_fs(void)
{
	int err;
	struct voluta_fs_env *fse = voluta_fs_env_inst();

	err = voluta_fse_serve(fse);
	if (err) {
		voluta_die(err, "fs failure: %s %s",
			   voluta_globals.mount_volume,
			   voluta_globals.mount_point_real);
	}
}

static void mount_finalize(void)
{
	voluta_fini_fs_env();
	voluta_pfree_string(&voluta_globals.mount_volume_real);
	voluta_pfree_string(&voluta_globals.mount_volume_clone);
	voluta_pfree_string(&voluta_globals.mount_point_real);
	voluta_close_syslog();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mount_setup_check_mntpoint(void)
{
	voluta_globals.mount_point_real =
		voluta_realpath_safe(voluta_globals.mount_point);

	voluta_die_if_not_mntdir(voluta_globals.mount_point_real, true);
	voluta_die_if_no_mountd();
}

static void mount_setup_check_volume(void)
{
	enum voluta_zbf zbf;
	const char *pass = NULL;
	const char *path = NULL;

	voluta_globals.mount_volume_real =
		voluta_realpath_safe(voluta_globals.mount_volume);

	path = voluta_globals.mount_volume_real;
	voluta_die_if_not_volume(path, pass, &zbf);

	if (zbf & VOLUTA_ZBF_ENCRYPTED) {
		voluta_globals.mount_passphrase =
			voluta_getpass(voluta_globals.mount_passphrase_file);

		pass = voluta_globals.mount_passphrase;
		voluta_die_if_not_volume(path, pass, &zbf);

		voluta_globals.mount_encrypted = true;
	}
}

static char *mount_volume_clone_path(void)
{
	int err;
	struct stat st = { .st_ino = 0 };
	char *volume_clone = NULL;
	const char *volume_real = voluta_globals.mount_volume_real;

	for (int i = 1; i < 100; ++i) {
		volume_clone = voluta_sprintf_path("%s.%02d", volume_real, i);
		err = voluta_sys_stat(volume_clone, &st);
		if (err == -ENOENT) {
			return volume_clone;
		}
		voluta_pfree_string(&volume_clone);
	}
	return NULL;
}

static void mount_prepare_volume_clone(void)
{
	int err = 0;
	int dst_fd = -1;
	int src_fd = -1;
	int o_flags;
	loff_t off_out = 0;
	mode_t mode = 0;
	struct stat st = { .st_ino = 0 };
	char *volume_clone = NULL;
	const char *volume_real = voluta_globals.mount_volume_real;

	if (voluta_globals.mount_rdonly) {
		goto out;
	}
	err = voluta_sys_stat(volume_real, &st);
	if (err) {
		goto out;
	}
	volume_clone = mount_volume_clone_path();
	if (volume_clone == NULL) {
		goto out;
	}
	o_flags = O_CREAT | O_RDWR | O_EXCL;
	mode = S_IRUSR | S_IWUSR;
	err = voluta_sys_open(volume_clone, o_flags, mode, &dst_fd);
	if (err) {
		goto out;
	}
	err = voluta_sys_ftruncate(dst_fd, st.st_size);
	if (err) {
		goto out;
	}
	err = voluta_sys_llseek(dst_fd, 0, SEEK_SET, &off_out);
	if (err) {
		goto out;
	}
	o_flags = O_RDONLY;
	mode = 0;
	err = voluta_sys_open(volume_real, o_flags, mode, &src_fd);
	if (err) {
		goto out;
	}
	err = voluta_sys_ioctl_ficlone(dst_fd, src_fd);
	if (err) {
		goto out;
	}
out:
	voluta_sys_closefd(&src_fd);
	voluta_sys_closefd(&dst_fd);
	if (err && volume_clone) {
		voluta_sys_unlink(volume_clone);
		voluta_pfree_string(&volume_clone);
	}
	voluta_globals.mount_volume_clone = volume_clone;
}

static void mount_complete_volume_clone(void)
{
	const char *volume_real = voluta_globals.mount_volume_real;
	const char *volume_clone = voluta_globals.mount_volume_clone;

	if (volume_clone != NULL) {
		voluta_sys_rename(volume_clone, volume_real);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0015: Use inotify to monitor available mount
 *
 * Better user modern inotify interface on mount-directory instead of this
 * naive busy-loop.
 */
static int mount_probe_rootdir(void)
{
	struct stat st;
	const char *path = voluta_globals.mount_point_real;

	voluta_statpath_safe(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		voluta_die(0, "illegal mount-point: %s", path);
	}
	return (st.st_ino == VOLUTA_INO_ROOT) ? 0 : -1;
}

static void mount_finish_parent(void)
{
	int err = -1;
	size_t retry = 20;

	while (retry-- && err) {
		err = mount_probe_rootdir();
		sleep(1);
	}
	exit(err);
}

static void mount_start_daemon(void)
{
	const pid_t pre_pid = getpid();

	voluta_fork_daemon();

	if (pre_pid == getpid()) {
		/* I am the parent: wait for active mount & exit */
		mount_finish_parent();
	}
}

static void mount_boostrap_process(void)
{
	if (!voluta_globals.dont_daemonize) {
		mount_start_daemon();
		voluta_open_syslog();
	}
	if (!voluta_globals.allow_coredump) {
		voluta_setrlimit_nocore();
	}
	if (!voluta_globals.disable_ptrace) {
		voluta_prctl_non_dumpable();
	}
}

static void mount_setup_fs_args(struct voluta_fs_args *args)
{
	memset(args, 0, sizeof(*args));
	args->uid = getuid();
	args->gid = getgid();
	args->pid = getpid();
	args->umask = 0022;
	args->mountp = voluta_globals.mount_point_real;
	args->passwd = voluta_globals.mount_passphrase;
	args->encrypted = voluta_globals.mount_encrypted;
	args->lazytime = voluta_globals.mount_lazytime;
	args->noexec = voluta_globals.mount_noexec;
	args->nosuid = voluta_globals.mount_nosuid;
	args->nodev = voluta_globals.mount_nodev;
	args->rdonly = voluta_globals.mount_rdonly;
	args->pedantic = false;
	args->spliced = true;
	if (voluta_globals.mount_volume_clone != NULL) {
		args->volume = voluta_globals.mount_volume_clone;
	} else {
		args->volume = voluta_globals.mount_volume_real;
	}
}

static void mount_create_setup_env(void)
{
	int err;
	struct voluta_fs_args args;
	struct voluta_fs_env *fse = NULL;

	mount_setup_fs_args(&args);
	voluta_init_fs_env();

	fse = voluta_fs_env_inst();
	err = voluta_fse_setargs(fse, &args);
	if (err) {
		voluta_die(err, "illegal params");
	}
	err = voluta_fse_verify(fse);
	if (err == -EUCLEAN) {
		voluta_die(0, "not a voluta volume: %s", args.volume);
	} else if (err == -EKEYEXPIRED) {
		voluta_die(0, "wrong passphrase: %s", args.volume);
	} else if (err != 0) {
		voluta_die(err, "illegal volume: %s", args.volume);
	}
}

/*
 * Trace global setting to user. When running as daemon on systemd-based
 * environments, users should use the following command to view voluta's
 * traces:
 *
 *   $ journalctl -b -n 60 -f -t voluta
 */
static void mount_trace_start(void)
{
	voluta_log_process_info();
	voluta_log_info("mount-point: %s", voluta_globals.mount_point_real);
	if (voluta_globals.mount_volume) {
		voluta_log_info("volume: %s", voluta_globals.mount_volume);
	}
}

static void mount_trace_finish(void)
{
	const time_t exec_time = time(NULL) - voluta_globals.start_time;

	voluta_log_info("mount done: %s", voluta_globals.mount_point_real);
	voluta_log_info("execution time: %ld seconds", exec_time);
	voluta_log_info("finish: %s", voluta_globals.version);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_mount(void)
{
	/* Do all cleanups upon exits */
	atexit(mount_finalize);

	/* Require valid mount-point */
	mount_setup_check_mntpoint();

	/* Require valid back-end storage volume */
	mount_setup_check_volume();

	/* If supported, use a clone of the volume */
	mount_prepare_volume_clone();

	/* Become daemon process */
	mount_boostrap_process();

	/* Setup environment instance */
	mount_create_setup_env();

	/* Report beginning-of-mount */
	mount_trace_start();

	/* Allow halt by signal */
	mount_enable_signals();

	/* Execute as long as needed... */
	mount_execute_fs();

	/* Report end-of-mount */
	mount_trace_finish();

	/* Override volume with updated clone */
	mount_complete_volume_clone();

	/* Post execution cleanups */
	mount_finalize();

	/* Return to main for global cleanups */
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const char *voluta_mount_usage[] = {
	"mount [options] <volume-path> <mount-point>",
	"",
	"options:",
	"  -r  --rdonly                 Mount filesystem read-only",
	"  -x, --noexec                 Do not allow programs execution",
	"  -S, --nosuid                 Do not honor special bits",
	"      --nodev                  Do not allow access to device files",
	"  -D, --nodaemon               Do not run as daemon process",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..2)",
	"  -C, --coredump               Allow core-dumps upon fatal errors",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

void voluta_getopt_mount(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "rdonly", no_argument, NULL, 'r' },
		{ "noexec", no_argument, NULL, 'x' },
		{ "nosuid", no_argument, NULL, 'S' },
		{ "nodev", no_argument, NULL, 'Z' },
		{ "nodaemon", no_argument, NULL, 'D' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "coredump", no_argument, NULL, 'C' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("rxSZDV:CP:h", opts);
		if (opt_chr == 'r') {
			voluta_globals.mount_rdonly = true;
		} else if (opt_chr == 'x') {
			voluta_globals.mount_noexec = true;
		} else if (opt_chr == 'S') {
			voluta_globals.mount_nosuid = true;
		} else if (opt_chr == 'Z') {
			voluta_globals.mount_nodev = true;
		} else if (opt_chr == 'D') {
			voluta_globals.dont_daemonize = true;
		} else if (opt_chr == 'V') {
			voluta_set_verbose_mode(optarg);
		} else if (opt_chr == 'C') {
			voluta_globals.allow_coredump = true;
		} else if (opt_chr == 'P') {
			voluta_globals.mount_passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(voluta_mount_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.mount_volume =
		voluta_consume_cmdarg("volume-path", false);
	voluta_globals.mount_point =
		voluta_consume_cmdarg("mount-point", true);
}

