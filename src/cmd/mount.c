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
#include <voluta/cmd.h>


/* Locals */
static char g_mount_rootid[256];


static const char *mount_usage[] = {
	"mount [options] <repo-path> <mount-point>",
	"",
	"options:",
	"  -r, --rdonly                 Mount filesystem read-only",
	"  -x, --noexec                 Do not allow programs execution",
	"  -S, --nosuid                 Do not honor special bits",
	"      --nodev                  Do not allow access to device files",
	"  -o  --options                Additional mount options",
	"  -A  --allow-other            Allow other users to access fs",
	"  -D, --nodaemon               Do not run as daemon process",
	"  -V, --verbose=LEVEL          Run in verbose mode (0..2)",
	"  -C, --coredump               Allow core-dumps upon fatal errors",
	"  -P, --passphrase-file=PATH   Passphrase file (unsafe)",
	NULL
};

static void mount_getopt(void)
{
	int opt_chr = 1;
	const struct option opts[] = {
		{ "rdonly", no_argument, NULL, 'r' },
		{ "noexec", no_argument, NULL, 'x' },
		{ "nosuid", no_argument, NULL, 'S' },
		{ "nodev", no_argument, NULL, 'Z' },
		{ "options", required_argument, NULL, 'o' },
		{ "allow-other", no_argument, NULL, 'A' },
		{ "nodaemon", no_argument, NULL, 'D' },
		{ "verbose", required_argument, NULL, 'V' },
		{ "coredump", no_argument, NULL, 'C' },
		{ "passphrase-file", required_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, no_argument, NULL, 0 },
	};

	while (opt_chr > 0) {
		opt_chr = voluta_getopt_subcmd("rxSZo:ADV:CP:h", opts);
		if (opt_chr == 'r') {
			voluta_globals.cmd.mount.rdonly = true;
		} else if (opt_chr == 'x') {
			voluta_globals.cmd.mount.noexec = true;
		} else if (opt_chr == 'S') {
			voluta_globals.cmd.mount.nosuid = true;
		} else if (opt_chr == 'Z') {
			voluta_globals.cmd.mount.nodev = true;
		} else if (opt_chr == 'o') {
			/* currently, only for xfstests */
			voluta_globals.cmd.mount.options = optarg;
		} else if (opt_chr == 'A') {
			voluta_globals.cmd.mount.allowother = true;
		} else if (opt_chr == 'D') {
			voluta_globals.dont_daemonize = true;
		} else if (opt_chr == 'V') {
			voluta_set_verbose_mode(optarg);
		} else if (opt_chr == 'C') {
			voluta_globals.allow_coredump = true;
		} else if (opt_chr == 'P') {
			voluta_globals.cmd.mount.passphrase_file = optarg;
		} else if (opt_chr == 'h') {
			voluta_show_help_and_exit(mount_usage);
		} else if (opt_chr > 0) {
			voluta_die_unsupported_opt();
		}
	}
	voluta_globals.cmd.mount.repodir =
	        voluta_consume_cmdarg("repo-path", false);
	voluta_globals.cmd.mount.mntpoint =
	        voluta_consume_cmdarg("mount-point", true);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mount_halt_by_signal(int signum)
{
	struct voluta_fs_env *fse = voluta_fse_inst();

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
	struct voluta_fs_env *fse = voluta_fse_inst();

	err = voluta_fse_serve(fse);
	if (err) {
		voluta_die(err, "fs failure: %s %s",
		           voluta_globals.cmd.mount.repodir,
		           voluta_globals.cmd.mount.mntpoint_real);
	}
}

static void mount_finalize(void)
{
	voluta_destroy_fse_inst();
	voluta_pfree_string(&voluta_globals.cmd.mount.mntpoint_real);
	voluta_repo_finalize(&voluta_globals.repoi);
	voluta_close_syslog();
	voluta_burnstack();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mount_setup_check_mntpoint(void)
{
	voluta_globals.cmd.mount.mntpoint_real =
	        voluta_realpath_safe(voluta_globals.cmd.mount.mntpoint);

	voluta_die_if_not_mntdir(voluta_globals.cmd.mount.mntpoint_real, true);
	voluta_die_if_no_mountd();
}

static void mount_setup_check_repo(void)
{
	const char *path = NULL;
	const bool rw = !voluta_globals.cmd.mount.rdonly;
	struct voluta_repo_info *repoi = &voluta_globals.repoi;

	path = voluta_globals.cmd.mount.repodir;
	voluta_repo_setup(repoi, path, rw);
	voluta_repo_require_skel(repoi);
	voluta_repo_require_lockable(repoi);
	voluta_repo_load_head(repoi, g_mount_rootid, sizeof(g_mount_rootid));

	voluta_globals.cmd.mount.passphrase =
	        voluta_getpass(voluta_globals.cmd.mount.passphrase_file);
}

static void mount_setup_check_sb(void)
{
	int err;
	char *sb_path = NULL;
	const char *objs_dir = voluta_globals.repoi.objs_dir;
	struct voluta_namebuf nb;

	err = voluta_resolve_sb_path(g_mount_rootid, &nb);
	if (err) {
		voluta_die(err, "could not resolve super: %s", g_mount_rootid);
	}
	sb_path = voluta_joinpath_safe(objs_dir, nb.name);
	voluta_die_if_bad_sb(sb_path, voluta_globals.cmd.mount.passphrase);
	voluta_pfree_string(&sb_path);
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
	const char *path = voluta_globals.cmd.mount.mntpoint_real;

	voluta_stat_ok(path, &st);
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
	voluta_globals.log_mask |= VOLUTA_LOG_INFO;

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

static void mount_lock_repo(void)
{
	voluta_repo_acquire_lock(&voluta_globals.repoi);
}

static void mount_unlock_repo(void)
{
	voluta_repo_release_lock(&voluta_globals.repoi);
}


static void mount_create_fs_env(void)
{
	const struct voluta_fs_args args = {
		.rootid = g_mount_rootid,
		.uid = getuid(),
		.gid = getgid(),
		.pid = getpid(),
		.umask = 0022,
		.objsdir = voluta_globals.repoi.objs_dir,
		.mntdir = voluta_globals.cmd.mount.mntpoint_real,
		.passwd = voluta_globals.cmd.mount.passphrase,
		.allowother = voluta_globals.cmd.mount.allowother,
		.lazytime = voluta_globals.cmd.mount.lazytime,
		.noexec = voluta_globals.cmd.mount.noexec,
		.nosuid = voluta_globals.cmd.mount.nosuid,
		.nodev = voluta_globals.cmd.mount.nodev,
		.rdonly = voluta_globals.cmd.mount.rdonly,
		.pedantic = false,
		.with_fuseq = true,
		.kcopy_mode = true,

	};
	voluta_create_fse_inst(&args);
}

static void mount_verify_fs_env(void)
{
	int err;
	struct voluta_fs_env *fse = voluta_fse_inst();
	const char *volume = voluta_globals.cmd.mount.repodir;

	err = voluta_fse_verify(fse);
	if (err == -EUCLEAN) {
		voluta_die(0, "not a voluta volume: %s", volume);
	} else if (err == -EKEYEXPIRED) {
		voluta_die(0, "wrong passphrase: %s", volume);
	} else if (err != 0) {
		voluta_die(err, "illegal volume: %s", volume);
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
	voluta_log_meta_banner(voluta_globals.name, 1);
	voluta_log_info("executable: %s", voluta_globals.prog);
	voluta_log_info("mountpoint: %s",
	                voluta_globals.cmd.mount.mntpoint_real);
	voluta_log_info("repodir: %s", voluta_globals.cmd.mount.repodir);
	voluta_log_info("modes: rdonly=%d noexec=%d nodev=%d nosuid=%d",
	                (int)voluta_globals.cmd.mount.rdonly,
	                (int)voluta_globals.cmd.mount.noexec,
	                (int)voluta_globals.cmd.mount.nodev,
	                (int)voluta_globals.cmd.mount.nosuid);
}

static void mount_trace_finish(void)
{
	const time_t exec_time = time(NULL) - voluta_globals.start_time;

	voluta_log_info("mount done: %s",
	                voluta_globals.cmd.mount.mntpoint_real);
	voluta_log_info("execution time: %ld seconds", exec_time);
	voluta_log_meta_banner(voluta_globals.name, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_execute_mount(void)
{
	/* Do all cleanups upon exits */
	atexit(mount_finalize);

	/* Parse command's arguments */
	mount_getopt();

	/* Require valid mount-point */
	mount_setup_check_mntpoint();

	/* Require valid back-end storage repository */
	mount_setup_check_repo();

	/* Require valid super-block object reference */
	mount_setup_check_sb();

	/* Become daemon process */
	mount_boostrap_process();

	/* Lock repository as daemon process */
	mount_lock_repo();

	/* Setup environment instance */
	mount_create_fs_env();

	/* Re-verify input arguments */
	mount_verify_fs_env();

	/* Report beginning-of-mount */
	mount_trace_start();

	/* Allow halt by signal */
	mount_enable_signals();

	/* Execute as long as needed... */
	mount_execute_fs();

	/* Unlock repository */
	mount_unlock_repo();

	/* Report end-of-mount */
	mount_trace_finish();

	/* Post execution cleanups */
	mount_finalize();

	/* Return to main for global cleanups */
}
