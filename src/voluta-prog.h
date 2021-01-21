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

/* Sub-command descriptor */
struct voluta_cmd_info {
	const char *name;
	voluta_exec_fn getopt_hook;
	voluta_exec_fn action_hook;
};

/* Global settings */
struct voluta_globals {
	/* Program's version string */
	const char *version;

	/* Program's arguments */
	char   *name;
	char   *prog;
	int     argc;
	char  **argv;
	char   *cmd_name;
	char  **cmd_argv;
	int     cmd_argc;
	int     log_mask;

	/* Process ids */
	pid_t   pid;
	uid_t   uid;
	gid_t   gid;
	mode_t  umsk;

	/* Common process settings */
	bool    dont_daemonize;
	bool    allow_coredump;
	bool    disable_ptrace; /* XXX: TODO: allow set */

	/* Capability */
	bool    cap_sys_admin;

	/* Signals info */
	int     sig_halt;
	int     sig_fatal;

	/* Execution start-time */
	time_t  start_time;

	/* Options for 'mountd' */
	char   *mountd_confpath;

	/* Options for 'mkfs' sub-command */
	char   *mkfs_passphrase;
	char   *mkfs_passphrase_file;
	char   *mkfs_volume;
	char   *mkfs_name;
	char   *mkfs_size;
	long    mkfs_volume_size;
	bool    mkfs_encrypted;
	bool    mkfs_force;

	/* Options for 'mount' sub-command */
	char   *mount_passphrase;
	char   *mount_passphrase_file;
	char   *mount_volume;
	char   *mount_volume_real;
	char   *mount_point;
	char   *mount_point_real;
	bool    mount_encrypted;
	bool    mount_lazytime;
	bool    mount_noexec;
	bool    mount_nosuid;
	bool    mount_nodev;
	bool    mount_rdonly;

	/* Options for 'umount' sub-command */
	char   *umount_point;
	char   *umount_point_real;
	bool    umount_force;

	/* Options for 'fsck' sub-command */
	char   *fsck_volume;

	/* Options for 'show' sub-command */
	char   *show_path;
	bool    show_public_only;

	/* Options for 'query' sub-command */
	char   *query_path;
	int     query_type;

	/* Options for 'clone' sub-command */
	char   *clone_point;
	char   *clone_volume;
	char   *clone_volume_tmp;

	/* Options for 'export' sub-command */
	char   *export_passphrase;
	char   *export_passphrase_file;
	char   *export_src;
	char   *export_src_real;
	char   *export_src_dir;
	char   *export_src_name;
	char   *export_dst;
	char   *export_dst_real;
	char   *export_dst_path;

	/* Options for 'import' sub-command */
	char   *import_passphrase;
	char   *import_passphrase_file;
	char   *import_src;
	char   *import_src_real;
	char   *import_src_dir;
	char   *import_src_name;
	char   *import_dst;
	char   *import_dst_real;
	char   *import_dst_path;

	/* Sub-command execution hook */
	const struct voluta_cmd_info *cmd_info;
};

extern struct voluta_globals voluta_globals;


/* Execution hooks */
void voluta_execute_mkfs(void);

void voluta_execute_mount(void);

void voluta_execute_umount(void);

void voluta_execute_fsck(void);

void voluta_execute_show(void);

void voluta_execute_query(void);

void voluta_execute_clone(void);

void voluta_execute_export(void);

void voluta_execute_import(void);

void voluta_getopt_mkfs(void);

void voluta_getopt_fsck(void);

void voluta_getopt_show(void);

void voluta_getopt_mount(void);

void voluta_getopt_umount(void);

void voluta_getopt_query(void);

void voluta_getopt_clone(void);

void voluta_getopt_export(void);

void voluta_getopt_import(void);

/* Common utilities */
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

void voluta_die_if_bad_zb(const char *path, const char *pass,
			  enum voluta_ztype *out_ztype,
			  enum voluta_zbf *out_zbf);

void voluta_die_if_not_volume(const char *path, const char *pass,
			      enum voluta_zbf *out_zbf);

void voluta_die_if_not_archive(const char *path, const char *pass);

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

void voluta_log_process_info(void);

void voluta_set_verbose_mode(const char *mode);

void voluta_show_help_and_exit(const char **help_strings);

void voluta_show_version_and_exit(const char *prog);

void voluta_pretty_size(size_t n, char *buf, size_t bsz);

/* Singleton instances */
void voluta_init_fs_env(void);

void voluta_fini_fs_env(void);

struct voluta_fs_env *voluta_fs_env_inst(void);

void voluta_init_ms_env(void);

void voluta_fini_ms_env(void);

struct voluta_ms_env *voluta_ms_env_inst(void);

void voluta_init_archiver_inst(void);

void voluta_fini_archiver_inst(void);

struct voluta_archiver *voluta_archiver_inst(void);


/* Signal call-back hook */
typedef void (*voluta_signal_hook_fn)(int);

extern voluta_signal_hook_fn voluta_signal_callback_hook;

/* Passphrase input */
char *voluta_getpass(const char *path);

char *voluta_getpass2(const char *path);

void voluta_delpass(char **pass);

/* Mount-config */
struct voluta_mntrules *voluta_parse_mntrules(const char *pathname);

void voluta_free_mntrules(struct voluta_mntrules *mnt_conf);

#endif /* VOLUTA_PROG_H_ */
