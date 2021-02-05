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
#ifndef VOLUTA_PROG_H_
#define VOLUTA_PROG_H_

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
#include <voluta/syscall.h>
#include <voluta/voluta.h>



typedef void (*voluta_exec_fn)(void);

/* sub-command descriptor */
struct voluta_cmd_info {
	const char *name;
	voluta_exec_fn getopt_hook;
	voluta_exec_fn action_hook;
};

/* arguments for 'mkfs' sub-command */
struct voluta_subcmd_mkfs {
	char   *passphrase;
	char   *passphrase_file;
	char   *volume;
	char   *name;
	char   *size;
	long    volume_size;
	bool    encrypted;
	bool    force;
};

/* arguments for 'mount' sub-command */
struct voluta_subcmd_mount {
	char   *passphrase;
	char   *passphrase_file;
	char   *volume;
	char   *volume_real;
	char   *volume_clone;
	char   *point;
	char   *point_real;
	bool    encrypted;
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
	char   *volume;
	char   *volume_tmp;
};

/* arguments for 'encrypt' sub-command */
struct voluta_subcmd_encrypt {
	char   *passphrase;
	char   *passphrase_file;
	char   *volume;
	char   *volume_real;
};

/* arguments for 'encrypt' sub-command */
struct voluta_subcmd_decrypt {
	char   *passphrase;
	char   *passphrase_file;
	char   *volume;
	char   *volume_real;
};

/* arguments for 'export' sub-command */
struct voluta_subcmd_export {
	char   *passphrase;
	char   *passphrase_file;
	char   *volume;
	char   *volume_real;
	char   *volume_dir;
	char   *volume_name;
	char   *archive;
	char   *archive_real;
	char   *archive_path;
};

/* arguments for 'import' sub-command */
struct voluta_subcmd_import {
	char   *passphrase;
	char   *passphrase_file;
	char   *archive;
	char   *archive_real;
	char   *archive_dir;
	char   *archive_name;
	char   *volume;
	char   *volume_real;
	char   *volume_path;
};

/* arguments for 'show' sub-command */
struct voluta_subcmd_show {
	char   *pathname;
	bool    volume;
	bool    version;
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
	struct voluta_subcmd_encrypt    encrypt;
	struct voluta_subcmd_decrypt    decrypt;
	struct voluta_subcmd_export     export;
	struct voluta_subcmd_import     import;
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

	/* options for 'mountd' */
	char   *mountd_confpath;

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

void voluta_execute_export(void);

void voluta_execute_import(void);


void voluta_getopt_mkfs(void);

void voluta_getopt_fsck(void);

void voluta_getopt_mount(void);

void voluta_getopt_umount(void);

void voluta_getopt_show(void);

void voluta_getopt_clone(void);

void voluta_getopt_encrypt(void);

void voluta_getopt_decrypt(void);

void voluta_getopt_export(void);

void voluta_getopt_import(void);


/* common utilities */
__attribute__((__noreturn__))
void voluta_die(int errnum, const char *fmt, ...);

__attribute__((__noreturn__))
void voluta_die_at(int errnum, const char *fl, int ln, const char *fmt, ...);

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

void voluta_die_if_not_volume(const char *path, bool rw, bool must_be_enc,
			      bool mustnot_be_enc, bool *out_is_encrypted);

void voluta_die_if_not_archive(const char *path);

void voluta_die_if_no_mountd(void);

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

char *voluta_strdup_safe(const char *s);

void voluta_pfree_string(char **pp);

char *voluta_sprintf_path(const char *fmt, ...);

void voluta_statpath_safe(const char *path, struct stat *st);

void voluta_stat_reg(const char *path, struct stat *st);

void voluta_stat_dir_or_reg(const char *path, struct stat *st);

char *voluta_realpath_safe(const char *path);

char *voluta_dirpath_safe(const char *path);

char *voluta_basename_safe(const char *path);

char *voluta_joinpath_safe(const char *path, const char *base);

void *voluta_malloc_safe(size_t n);

void voluta_setup_globals(int argc, char *argv[]);

void voluta_init_process(void);

void voluta_log_meta_banner(bool start);

void voluta_set_verbose_mode(const char *mode);

void voluta_show_help_and_exit(const char **help_strings);

void voluta_show_version_and_exit(const char *prog);

void voluta_pretty_size(size_t n, char *buf, size_t bsz);

/* singleton instances */
void voluta_init_fs_env(void);

void voluta_fini_fs_env(void);

struct voluta_fs_env *voluta_fs_env_inst(void);

void voluta_init_ms_env(void);

void voluta_fini_ms_env(void);

struct voluta_ms_env *voluta_ms_env_inst(void);

void voluta_init_archiver_inst(void);

void voluta_fini_archiver_inst(void);

struct voluta_archiver *voluta_archiver_inst(void);


/* signal call-back hook */
typedef void (*voluta_signal_hook_fn)(int);

extern voluta_signal_hook_fn voluta_signal_callback_hook;

/* passphrase input */
char *voluta_getpass(const char *path);

char *voluta_getpass2(const char *path);

void voluta_delpass(char **pass);

/* mount-config */
struct voluta_mntrules *voluta_parse_mntrules(const char *pathname);

void voluta_free_mntrules(struct voluta_mntrules *mnt_conf);

#endif /* VOLUTA_PROG_H_ */
