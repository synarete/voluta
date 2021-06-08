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
#ifndef VOLUTA_CMD_H_
#define VOLUTA_CMD_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <voluta/infra.h>
#include <voluta/fs.h>
#include <voluta/ioctls.h>


typedef void (*voluta_exec_fn)(void);

/* sub-command descriptor */
struct voluta_cmd_info {
	const char *name;
	voluta_exec_fn action_hook;
};

/* arguments for 'mkfs' sub-command */
struct voluta_subcmd_mkfs {
	char   *passphrase;
	char   *passphrase_file;
	char   *repodir;
	char   *repodir_real;
	char   *repo_lock;
	char   *name;
	char   *size;
	long    fs_size;
	bool    encrypted;
	bool    force;
};

/* arguments for 'mount' sub-command */
struct voluta_subcmd_mount {
	char   *passphrase;
	char   *passphrase_file;
	char   *repodir;
	char   *repodir_real;
	char   *repo_lock;
	int     repo_lock_fd;
	char   *mntpoint;
	char   *mntpoint_real;
	char   *options;
	bool    encrypted;
	bool    allowother;
	bool    lazytime;
	bool    noexec;
	bool    nosuid;
	bool    nodev;
	bool    rdonly;
};

/* arguments for 'umount' sub-command */
struct voluta_subcmd_umount {
	char   *point;
	char   *point_real;
	bool    force;
	bool    lazy;
};

/* arguments for 'clone' sub-command */
struct voluta_subcmd_clone {
	char   *point;
	char   *point_real;
	char   *volume;
	char   *volume_real;
	char   *volume_tmp;
};

/* arguments for 'show' sub-command */
struct voluta_subcmd_show {
	char   *pathname;
	bool    volume;
	bool    version;
	bool    fsinfo;
};

/* arguments for 'fsck' sub-command */
struct voluta_subcmd_fsck {
	char   *volume;
};

/* sub-commands options */
union voluta_subcmd_args {
	struct voluta_subcmd_mkfs       mkfs;
	struct voluta_subcmd_mount      mount;
	struct voluta_subcmd_umount     umount;
	struct voluta_subcmd_clone      clone;
	struct voluta_subcmd_show       show;
	struct voluta_subcmd_fsck       fsck;
};

/* global settings */
struct voluta_globals {
	/* program's version string */
	const char *version;

	/* program's arguments */
	char   *name;
	char   *prog;
	int     argc;
	char  **argv;
	char   *cmd_name;
	char  **cmd_argv;
	int     cmd_argc;
	int     log_mask;

	/* process ids */
	pid_t   pid;
	uid_t   uid;
	gid_t   gid;
	mode_t  umsk;

	/* common process settings */
	bool    dont_daemonize;
	bool    allow_coredump;
	bool    disable_ptrace; /* XXX: TODO: allow set */

	/* capability */
	bool    cap_sys_admin;

	/* signals info */
	int     sig_halt;
	int     sig_fatal;

	/* execution start-time */
	time_t  start_time;

	/* sub-commands arguments */
	union voluta_subcmd_args cmd;

	/* sub-command execution hook */
	const struct voluta_cmd_info *cmd_info;
};

extern struct voluta_globals voluta_globals;


/* execution hooks */
void voluta_execute_mkfs(void);

void voluta_execute_mount(void);

void voluta_execute_umount(void);

void voluta_execute_fsck(void);

void voluta_execute_show(void);

void voluta_execute_clone(void);

void voluta_execute_encrypt(void);

void voluta_execute_decrypt(void);


/* common utilities */

__attribute__((__noreturn__))
void voluta_die_redundant_arg(const char *s);

__attribute__((__noreturn__))
void voluta_die_missing_arg(const char *s);

__attribute__((__noreturn__))
void voluta_die_no_volume_path(void);

__attribute__((__noreturn__))
void voluta_die_unsupported_opt(void);

void voluta_die_if_redundant_arg(void);

void voluta_die_if_illegal_name(const char *name);

void voluta_die_if_not_dir(const char *path, bool w_ok);

void voluta_die_if_not_empty_dir(const char *path, bool w_ok);

void voluta_die_if_not_mntdir(const char *path, bool mount);

void voluta_die_if_not_reg(const char *path, bool w_ok);

void voluta_die_if_exists(const char *path);

void voluta_die_if_bad_sb(const char *path, const char *pass);

void voluta_die_if_not_repository(const char *path);

void voluta_die_if_not_lockable(const char *path, bool rw);

void voluta_die_if_no_mountd(void);


void voluta_open_and_flock(const char *path, bool rw, int *out_fd);

void voluta_funlock_and_close(const char *path, int *pfd);

char *voluta_clone_as_tmppath(const char *path);

char *voluta_consume_cmdarg(const char *arg_name, bool last);

int voluta_getopt_subcmd(const char *sopts, const struct option *lopts);

void voluta_register_sigactions(void);

long voluta_parse_size(const char *str);

void voluta_daemonize(void);

void voluta_fork_daemon(void);

void voluta_open_syslog(void);

void voluta_close_syslog(void);

void voluta_setrlimit_nocore(void);

void voluta_prctl_non_dumpable(void);

void voluta_statfs_ok(const char *path, struct statfs *stfs);

void voluta_stat_ok(const char *path, struct stat *st);

void voluta_stat_reg(const char *path, struct stat *st);

void voluta_stat_reg_or_dir(const char *path, struct stat *st);

void voluta_stat_reg_or_blk(const char *path, struct stat *st, loff_t *out_sz);

loff_t voluta_blkgetsize_ok(const char *path);

char *voluta_realpath_safe(const char *path);

char *voluta_basename_safe(const char *path);

char *voluta_joinpath_safe(const char *path, const char *base);

char *voluta_lockfile_path(const char *dirpath);

void voluta_setup_globals(int argc, char *argv[]);

void voluta_init_process(void);

void voluta_set_verbose_mode(const char *mode);

void voluta_show_help_and_exit(const char **help_strings);

void voluta_show_version_and_exit(const char *prog);

void voluta_pretty_size(size_t n, char *buf, size_t bsz);


void *voluta_zalloc_safe(size_t n);

void voluta_pfree_string(char **pp);

char *voluta_strdup_safe(const char *s);

char *voluta_strndup_safe(const char *s, size_t n);

char *voluta_sprintf_path(const char *fmt, ...);

/* singleton instance */
void voluta_create_fse_inst(const struct voluta_fs_args *args);

void voluta_destrpy_fse_inst(void);

struct voluta_fs_env *voluta_fse_inst(void);


/* signal call-back hook */
typedef void (*voluta_signal_hook_fn)(int);

extern voluta_signal_hook_fn voluta_signal_callback_hook;

/* passphrase input */
char *voluta_getpass(const char *path);

char *voluta_getpass2(const char *path);

void voluta_delpass(char **pass);


/* HEAD reference */
void voluta_save_headref(const char *repodir, const char *rootid);

void voluta_load_headref(const char *repodir, char *buf, size_t bsz);

#endif /* VOLUTA_CMD_H_ */
