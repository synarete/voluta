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
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <dirent.h>
#include <locale.h>
#include <getopt.h>
#include <voluta/cmd.h>


#define VOLUTA_LOG_DEFAULT  \
	(VOLUTA_LOG_WARN  | \
	 VOLUTA_LOG_ERROR | \
	 VOLUTA_LOG_CRIT  | \
	 VOLUTA_LOG_STDOUT)

/* Global process' variables */
struct voluta_globals voluta_globals;


__attribute__((__noreturn__))
void voluta_die_redundant_arg(const char *s)
{
	voluta_die(0, "redundant argument: %s", s);
}

__attribute__((__noreturn__))
void voluta_die_missing_arg(const char *s)
{
	voluta_die(0, "missing argument: %s", s);
}

__attribute__((__noreturn__))
void voluta_die_no_volume_path(void)
{
	voluta_die(0, "missing volume path");
}

__attribute__((__noreturn__))
void voluta_die_unsupported_opt(void)
{
	exit(EXIT_FAILURE);
}

void voluta_die_if_redundant_arg(void)
{
	int argc = voluta_globals.cmd_argc;
	char **argv = voluta_globals.cmd_argv;

	if (optind < argc) {
		voluta_die_redundant_arg(argv[optind]);
	}
}

void voluta_die_if_illegal_name(const char *name)
{
	int err;

	err = voluta_check_name(name);
	if (err) {
		voluta_die(err, "illegal name: %s", name);
	}
}

void voluta_die_if_not_dir(const char *path, bool w_ok)
{
	int err;
	struct stat st;
	int access_mode = R_OK | X_OK | (w_ok ? W_OK : 0);

	voluta_stat_ok(path, &st);
	if (!S_ISDIR(st.st_mode)) {
		voluta_die(-ENOTDIR, "illegal dir-path: %s", path);
	}
	err = voluta_sys_access(path, access_mode);
	if (err) {
		voluta_die(err, "no-access: %s", path);
	}
}

void voluta_die_if_not_reg(const char *path, bool w_ok)
{
	int err;
	struct stat st;
	int access_mode = R_OK | (w_ok ? W_OK : 0);

	voluta_stat_ok(path, &st);
	if (S_ISDIR(st.st_mode)) {
		voluta_die(-EISDIR, "illegal: %s", path);
	}
	if (!S_ISREG(st.st_mode)) {
		voluta_die(0, "not reg: %s", path);
	}
	err = voluta_sys_access(path, access_mode);
	if (err) {
		voluta_die(err, "no-access: %s", path);
	}
}

void voluta_die_if_exists(const char *path)
{
	int err;
	struct stat st;

	err = voluta_sys_stat(path, &st);
	if (!err) {
		voluta_die(0, "file exists: %s", path);
	}
	if (err != -ENOENT) {
		voluta_die(err, "stat failure: %s", path);
	}
}

static struct voluta_super_block *new_super_block(void)
{
	struct voluta_super_block *sb = NULL;

	sb = voluta_zalloc_safe(sizeof(*sb));
	return sb;
}

static void del_super_block(struct voluta_super_block *sb)
{
	memset(sb, 0xFE, sizeof(*sb));
	free(sb);
}

static struct voluta_super_block *read_super_block(const char *path)
{
	int fd = -1;
	int err;
	loff_t size = 0;
	struct stat st = { .st_size = 0 };
	struct voluta_super_block *sb = NULL;
	const loff_t sb_off = VOLUTA_LBA_SB * VOLUTA_BK_SIZE;

	voluta_stat_reg_or_blk(path, &st, &size);
	if (size == 0) {
		voluta_die(0, "empty volume: %s", path);
	}
	if (size < (int)sizeof(*sb)) {
		voluta_die(0, "no zero-block in: %s", path);
	}
	err = voluta_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		voluta_die(err, "open failed: %s", path);
	}
	sb = new_super_block();
	err = voluta_sys_preadn(fd, sb, sizeof(*sb), sb_off);
	if (err) {
		voluta_die(err, "pread error: %s", path);
	}
	voluta_sys_close(fd);
	return sb;
}

void voluta_die_if_bad_sb(const char *path, const char *pass)
{
	int err;
	enum voluta_brf brf;
	struct voluta_super_block *sb = NULL;

	sb = read_super_block(path);
	err = voluta_check_boot_record(sb);
	if (err) {
		goto out;
	}
	brf = voluta_br_flags(&sb->sb_boot_rec);
	if (!(brf & VOLUTA_ZBF_ENCRYPTED)) {
		err = 0;
		goto out;
	}
	if (pass == NULL) {
		err = -ENOKEY;
		goto out;
	}
	err = voluta_decipher_super_block(sb, pass);
out:
	del_super_block(sb);
	if (err == -EAGAIN) {
		voluta_die(err, "already in use: %s", path);
	} else if (err == -EUCLEAN) {
		voluta_die(0, "not a valid voluta volume: %s", path);
	} else if (err == -ENOKEY) {
		voluta_die(0, "missing passphrase: %s", path);
	} else if (err == -EKEYEXPIRED) {
		voluta_die(0, "illegal passphrase: %s", path);
	} else if (err) {
		voluta_die(err, "failed to parse super block: %s", path);
	}
}

void voluta_die_if_not_repository(const char *path)
{
	int err;
	char *lockfile = NULL;
	struct stat st = { .st_size = 0 };

	err = voluta_require_objstore_path(path);
	if ((err == -EPERM) || (err == -EACCES)) {
		voluta_die(err, "can not access repository: %s", path);
	} else if (err) {
		voluta_die(err, "not a valid repository: %s", path);
	}
	lockfile = voluta_lockfile_path(path);
	voluta_stat_reg(lockfile, &st);
	if (st.st_size > 0) {
		voluta_die(0, "lock-file not empty: %s", lockfile);
	}
	voluta_pfree_string(&lockfile);
}

void voluta_die_if_not_lockable(const char *path, bool rw)
{
	int fd = -1;

	voluta_open_and_flock(path, rw, &fd);
	voluta_funlock_and_close(path, &fd);
}

void voluta_die_if_no_mountd(void)
{
	int err;
	const char *sock = VOLUTA_MNTSOCK_NAME;

	err = voluta_rpc_handshake(getuid(), getgid());
	if (err) {
		voluta_die(err, "failed to handshake with mountd: "
		           "sock=@%s", sock);
	}
}

void voluta_die_if_not_empty_dir(const char *path, bool w_ok)
{
	int err;
	int dfd = -1;
	size_t ndes = 0;
	struct dirent64 de[8];
	const size_t nde = VOLUTA_ARRAY_SIZE(de);
	char buf[1024] = "";

	voluta_die_if_not_dir(path, w_ok);

	err = voluta_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		voluta_die(err, "open-dir error: %s", path);
	}
	err = voluta_sys_getdents(dfd, buf, sizeof(buf), de, nde, &ndes);
	if (err) {
		voluta_die(err, "read dir failure: %s", path);
	}
	err = voluta_sys_close(dfd);
	if (err) {
		voluta_die(err, "close-dir error: %s", path);
	}
	if (ndes > 2) {
		voluta_die(0, "not an empty directory: %s", path);
	}
}

void voluta_die_if_not_mntdir(const char *path, bool mount)
{
	long fstype;
	struct stat st;
	struct statfs stfs;
	const struct voluta_fsinfo *fsi = NULL;


	if (strlen(path) >= VOLUTA_MNTPATH_MAX) {
		voluta_die(0, "illegal mount-path length: %s", path);
	}
	voluta_die_if_not_dir(path, mount);

	if (mount) {
		voluta_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi = voluta_fsinfo_by_vfstype(fstype);
		if (fsi == NULL) {
			voluta_die(0, "unknown fstype at: "
			           "%s fstype=0x%lx", path, fstype);
		}
		if (fsi->isfuse) {
			voluta_die(0, "can not mount over FUSE file-system: "
			           "%s fstype=0x%lx", path, fstype);
		}
		if (!fsi->allowed) {
			voluta_die(0, "not allowed to mount over: "
			           "%s fstype=0x%lx", path, fstype);
		}
		voluta_die_if_not_empty_dir(path, true);
	} else {
		voluta_statfs_ok(path, &stfs);
		fstype = (long)stfs.f_type;
		fsi = voluta_fsinfo_by_vfstype(fstype);
		if (fsi == NULL) {
			voluta_die(0, "unknown fstype at: "
			           "%s fstype=0x%lx", path, fstype);
		}
		if (!fsi->isfuse) {
			voluta_die(0, "not a FUSE file-system: %s", path);
		}
		voluta_stat_ok(path, &st);
		if (st.st_ino != VOLUTA_INO_ROOT) {
			voluta_die(0, "not a voluta mount-point: %s", path);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_open_and_flock(const char *path, bool rw, int *out_fd)
{
	int err;
	const int o_flags = rw ? O_RDWR : O_RDONLY;
	struct flock fl = {
		.l_type = rw ? F_WRLCK : F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	*out_fd = -1;
	err = voluta_sys_open(path, o_flags, 0, out_fd);
	if (err) {
		voluta_die(err, "failed to opendir: %s", path);
	}
	err = voluta_sys_fcntl_flock(*out_fd, F_SETLK, &fl);
	if (err) {
		voluta_die(err, "failed to flock: %s", path);
	}
}

void voluta_funlock_and_close(const char *path, int *pfd)
{
	int err;
	struct flock fl = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};

	if ((path != NULL) && (*pfd > 0)) {
		err = voluta_sys_fcntl_flock(*pfd, F_SETLK, &fl);
		if (err) {
			voluta_die(err, "failed to funlock: %s", path);
		}
		voluta_sys_closefd(pfd);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *discover_unused_tmppath(const char *path)
{
	int err;
	char *tmppath = NULL;
	struct stat st = { .st_ino = 0 };

	for (int i = 1; i < 100; ++i) {
		tmppath = voluta_sprintf_path("%s.%02d~", path, i);
		err = voluta_sys_stat(tmppath, &st);
		if (err == -ENOENT) {
			break;
		}
		voluta_pfree_string(&tmppath);
	}
	return tmppath;
}

char *voluta_clone_as_tmppath(const char *path)
{
	int err = 0;
	int dst_fd = -1;
	int src_fd = -1;
	loff_t off_out = 0;
	struct stat st;
	const mode_t mode = S_IRUSR | S_IWUSR;
	char *tpath = NULL;

	err = voluta_sys_stat(path, &st);
	if (err) {
		goto out;
	}
	tpath = discover_unused_tmppath(path);
	if (tpath == NULL) {
		goto out;
	}
	err = voluta_sys_open(tpath, O_CREAT | O_RDWR | O_EXCL, mode, &dst_fd);
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
	err = voluta_sys_open(path, O_RDONLY, 0, &src_fd);
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
	if (err && tpath) {
		voluta_sys_unlink(tpath);
		voluta_pfree_string(&tpath);
	}
	return tpath;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

char *voluta_consume_cmdarg(const char *arg_name, bool last)
{
	char *arg = NULL;
	int argc = voluta_globals.cmd_argc;
	char **argv = voluta_globals.cmd_argv;

	if (optind >= argc) {
		voluta_die_missing_arg(arg_name);
	}
	arg = argv[optind++];
	if (last) {
		voluta_die_if_redundant_arg();
	}
	return arg;
}

int voluta_getopt_subcmd(const char *sopts, const struct option *lopts)
{
	int opt_index = 0;
	int argc = voluta_globals.cmd_argc;
	char **argv = voluta_globals.cmd_argv;

	return getopt_long(argc, argv, sopts, lopts, &opt_index);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

voluta_signal_hook_fn voluta_signal_callback_hook = NULL;


static void sigaction_info_handler(int signum)
{
	voluta_log_debug("signal: %d", signum);
}

static void sigaction_halt_handler(int signum)
{
	voluta_log_info("halt-signal: %d", signum);
	voluta_globals.sig_halt = signum;
	if (voluta_signal_callback_hook != NULL) {
		/* Call sub-program specific logic */
		voluta_signal_callback_hook(signum);
	} else {
		/* Force re-wake-up */
		raise(SIGHUP);
	}
}

static void sigaction_term_handler(int signum)
{
	voluta_backtrace();
	voluta_log_crit("term-signal: %d", signum);
	voluta_globals.sig_halt = signum;
	voluta_globals.sig_fatal = signum;
	exit(EXIT_FAILURE);
}

static void sigaction_abort_handler(int signum)
{
	if (voluta_globals.sig_fatal) {
		_exit(EXIT_FAILURE);
	}

	voluta_backtrace();
	voluta_log_crit("abort-signal: %d", signum);
	voluta_globals.sig_halt = signum;
	voluta_globals.sig_fatal = signum;
	abort(); /* Re-raise to _exit */
}

static struct sigaction s_sigaction_info = {
	.sa_handler = sigaction_info_handler
};

static struct sigaction s_sigaction_halt = {
	.sa_handler = sigaction_halt_handler
};

static struct sigaction s_sigaction_term = {
	.sa_handler = sigaction_term_handler
};

static struct sigaction s_sigaction_abort = {
	.sa_handler = sigaction_abort_handler
};

static void register_sigaction(int signum, struct sigaction *sa)
{
	int err;

	err = voluta_sys_sigaction(signum, sa, NULL);
	if (err) {
		voluta_die(err, "sigaction error: signum=%d", signum);
	}
}

static void sigaction_info(int signum)
{
	register_sigaction(signum, &s_sigaction_info);
}

static void sigaction_halt(int signum)
{
	register_sigaction(signum, &s_sigaction_halt);
}

static void sigaction_term(int signum)
{
	register_sigaction(signum, &s_sigaction_term);
}

static void sigaction_abort(int signum)
{
	register_sigaction(signum, &s_sigaction_abort);
}

void voluta_register_sigactions(void)
{
	sigaction_info(SIGHUP);
	sigaction_halt(SIGINT);
	sigaction_halt(SIGQUIT);
	sigaction_term(SIGILL);
	sigaction_info(SIGTRAP);
	sigaction_abort(SIGABRT);
	sigaction_term(SIGBUS);
	sigaction_term(SIGFPE);
	sigaction_info(SIGUSR1);
	sigaction_term(SIGSEGV);
	sigaction_info(SIGUSR2);
	sigaction_info(SIGPIPE);
	sigaction_info(SIGALRM);
	sigaction_halt(SIGTERM);
	sigaction_term(SIGSTKFLT);
	sigaction_info(SIGCHLD);
	sigaction_info(SIGCONT);
	sigaction_halt(SIGTSTP);
	sigaction_halt(SIGTTIN);
	sigaction_halt(SIGTTOU);
	sigaction_info(SIGURG);
	sigaction_halt(SIGXCPU);
	sigaction_halt(SIGXFSZ);
	sigaction_halt(SIGVTALRM);
	sigaction_info(SIGPROF);
	sigaction_info(SIGWINCH);
	sigaction_info(SIGIO);
	sigaction_halt(SIGPWR);
	sigaction_halt(SIGSYS);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long voluta_parse_size(const char *str)
{
	long mul = 0;
	char *endptr = NULL;
	long double val;
	long double iz;

	errno = 0;
	val = strtold(str, &endptr);
	if ((endptr == str) || (errno == ERANGE) || isnan(val)) {
		goto illegal_value;
	}
	if (strlen(endptr) > 1) {
		goto illegal_value;
	}
	switch (toupper(*endptr)) {
	case 'K':
		mul = VOLUTA_KILO;
		break;
	case 'M':
		mul = VOLUTA_MEGA;
		break;
	case 'G':
		mul = VOLUTA_GIGA;
		break;
	case 'T':
		mul = VOLUTA_TERA;
		break;
	case 'P':
		mul = VOLUTA_PETA;
		break;
	case '\0':
		mul = 1;
		break;
	default:
		goto illegal_value;
	}
	modfl(val, &iz);
	if ((iz < 0.0F) || isnan(iz)) {
		goto illegal_value;
	}
	return (long)(val * (long double)mul);

illegal_value:
	voluta_die(0, "illegal value: %s", str);
	return -EINVAL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0014: Dance with systemd upon logout
 *
 * May need to call 'loginctl enable-linger username' if we want daemon to
 * stay alive after login. Need more investigating.
 */
void voluta_daemonize(void)
{
	int err;

	err = daemon(0, 1);
	if (err) {
		voluta_die(0, "failed to daemonize");
	}
	voluta_globals.log_mask |= VOLUTA_LOG_SYSLOG;
	voluta_globals.log_mask &= ~VOLUTA_LOG_STDOUT;
}

void voluta_fork_daemon(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		voluta_die(errno, "fork error");
	}
	if (pid == 0) {
		voluta_daemonize();
	}
}

void voluta_open_syslog(void)
{
	voluta_globals.log_mask |= VOLUTA_LOG_SYSLOG;
	openlog(voluta_globals.name, LOG_CONS | LOG_NDELAY, 0);
}

void voluta_close_syslog(void)
{
	if (voluta_globals.log_mask & VOLUTA_LOG_SYSLOG) {
		closelog();
		voluta_globals.log_mask &= ~VOLUTA_LOG_SYSLOG;
	}
}

void voluta_setrlimit_nocore(void)
{
	int err;
	struct rlimit rlim = { .rlim_cur = 0, .rlim_max = 0 };

	err = voluta_sys_setrlimit(RLIMIT_CORE, &rlim);
	if (err) {
		voluta_die(err, "failed to disable core-dupms");
	}
}

void voluta_prctl_non_dumpable(void)
{
	int err;

	err = voluta_sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (err) {
		voluta_die(err, "failed to prctl non-dumpable");
	}
}

char *voluta_joinpath_safe(const char *path, const char *base)
{
	char *rpath;
	const size_t plen = strlen(path);
	const size_t blen = strlen(base);

	rpath = voluta_zalloc_safe(plen + blen + 2);
	memcpy(rpath, path, plen);
	memcpy(rpath + 1 + plen, base, blen);
	rpath[plen] = '/';
	rpath[plen + blen + 1] = '\0';
	return rpath;
}

char *voluta_realpath_safe(const char *path)
{
	char *real_path;

	real_path = realpath(path, NULL);
	if (real_path == NULL) {
		voluta_die(-errno, "realpath failure: '%s'", path);
	}
	return real_path;
}

char *voluta_basename_safe(const char *path)
{
	const char *base;
	const char *last = strrchr(path, '/');

	base = (last == NULL) ? path : (last + 1);
	voluta_die_if_illegal_name(base);

	return voluta_strdup_safe(base);
}

char *voluta_lockfile_path(const char *dirpath)
{
	return voluta_joinpath_safe(dirpath, "voluta.lock");
}

static void voluta_access_ok(const char *path)
{
	int err;
	const uid_t uid = getuid();
	const gid_t gid = getgid();

	err = voluta_sys_access(path, R_OK);
	if (err == -ENOENT) {
		voluta_die(err, "no such path: %s", path);
	}
	if (err) {
		voluta_die(err, "no access: %s uid=%d gid=%d", path, uid, gid);
	}
}

void voluta_statfs_ok(const char *path, struct statfs *stfs)
{
	int err;

	voluta_access_ok(path);

	err = voluta_sys_statfs(path, stfs);
	if (err) {
		voluta_die(err, "statfs failure: %s", path);
	}
}

void voluta_stat_ok(const char *path, struct stat *st)
{
	int err;
	mode_t mode;

	voluta_access_ok(path);

	err = voluta_sys_stat(path, st);
	if (err) {
		voluta_die(err, "stat failure: %s", path);
	}
	mode = st->st_mode;
	if (!S_ISREG(mode) && !S_ISDIR(mode) && !S_ISBLK(mode)) {
		voluta_die(0, "unsupported mode: 0%o %s", mode, path);
	}
}

void voluta_stat_reg(const char *path, struct stat *st)
{
	voluta_stat_ok(path, st);
	if (!S_ISREG(st->st_mode)) {
		voluta_die(0, "not a regular file: %s", path);
	}
}

void voluta_stat_reg_or_dir(const char *path, struct stat *st)
{
	voluta_stat_ok(path, st);
	if (!S_ISDIR(st->st_mode) && !S_ISREG(st->st_mode)) {
		voluta_die(0, "not dir-or-reg: %s", path);
	}
}

void voluta_stat_reg_or_blk(const char *path, struct stat *st, loff_t *out_sz)
{
	voluta_stat_ok(path, st);
	if (!S_ISREG(st->st_mode) && !S_ISBLK(st->st_mode)) {
		voluta_die(0, "not a regular-file or block-device: %s", path);
	}
	if (S_ISREG(st->st_mode)) {
		*out_sz = st->st_size;
	} else {
		*out_sz = voluta_blkgetsize_ok(path);
	}
}


loff_t voluta_blkgetsize_ok(const char *path)
{
	int fd = -1;
	int err;
	size_t sz;

	err = voluta_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		voluta_die(err, "open failure: %s", path);
	}
	err = voluta_sys_ioctl_blkgetsize64(fd, &sz);
	voluta_sys_close(fd);
	if (err) {
		voluta_die(err, "ioctl BLKGETSIZE64 failed: %s", path);
	}
	if (sz >= (size_t)(LONG_MAX)) {
		voluta_die(0, "illegal block-device size: %lu", sz);
	}
	return (loff_t)sz;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void *voluta_zalloc_safe(size_t nbytes)
{
	int err;
	void *mem = NULL;

	err = voluta_zmalloc(nbytes, &mem);
	if (err) {
		voluta_die(-err, "alloc failed: nbytes=%lu", nbytes);
	}
	return mem;
}

void voluta_pfree_string(char **pp)
{
	if (*pp != NULL) {
		free(*pp);
		*pp = NULL;
	}
}

char *voluta_strdup_safe(const char *s)
{
	char *d = strdup(s);

	if (d == NULL) {
		voluta_die(errno, "strdup failed");
	}
	return d;
}

char *voluta_strndup_safe(const char *s, size_t n)
{
	char *d = strndup(s, n);

	if (d == NULL) {
		voluta_die(errno, "strndup failed: n=%lu", n);
	}
	return d;
}

char *voluta_sprintf_path(const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t path_size = PATH_MAX;
	char *path = voluta_zalloc_safe(path_size);
	char *path_dup;

	va_start(ap, fmt);
	n = vsnprintf(path, path_size - 1, fmt, ap);
	va_end(ap);

	if (n >= (int)path_size) {
		voluta_die(0, "illegal path-len %d", n);
	}
	path_dup = voluta_strdup_safe(path);
	voluta_pfree_string(&path);
	return path_dup;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Singleton instance */
static struct voluta_fs_env *g_fs_env_inst;

static void voluta_require_no_inst(const void *inst)
{
	if (inst != NULL) {
		voluta_die(0, "internal error: singleton already at %p", inst);
	}
}

void voluta_create_fse_inst(const struct voluta_fs_args *args)
{
	int err;

	voluta_require_no_inst(g_fs_env_inst);
	err = voluta_fse_new(args, &g_fs_env_inst);
	if (err) {
		voluta_die(err, "failed to create instance");
	}
}

void voluta_destrpy_fse_inst(void)
{
	if (g_fs_env_inst) {
		voluta_fse_del(g_fs_env_inst);
		g_fs_env_inst = NULL;
	}
}

struct voluta_fs_env *voluta_fse_inst(void)
{
	return g_fs_env_inst;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void show_help_strings(FILE *fp, const char *name,
                              const char **help_strings)
{
	size_t idx = 0;
	const char *help_string = NULL;
	bool with_name = (name != NULL) && strlen(name);

	help_string = help_strings[idx++];
	while (help_string != NULL) {
		if (with_name && !strlen(help_string)) {
			with_name = false;
		}
		if (with_name) {
			fprintf(fp, "%s %s\n", name, help_string);
		} else {
			fprintf(fp, "%s\n", help_string);
		}
		help_string = help_strings[idx++];
	}
	fputs("\n", fp);
	fflush(fp);
}

void voluta_show_help_and_exit(const char **help_strings)
{
	const char *prefix = voluta_globals.name;

	show_help_strings(stdout, prefix, help_strings);
	exit(EXIT_SUCCESS);
}

void voluta_show_version_and_exit(const char *prog)
{
	fprintf(stdout, "%s %s\n",
	        (prog != NULL) ? prog : "voluta", voluta_globals.version);
	exit(0);
}

static void voluta_atexit_flush(void)
{
	fflush(stdout);
	fflush(stderr);
}

static void voluta_error_print_progname(void)
{
	FILE *fp = stderr;
	const char *name = voluta_globals.name;
	const char *subcmd = voluta_globals.cmd_name;

	if (subcmd && (subcmd[0] != '-')) {
		fprintf(fp, "%s %s: ", name, subcmd);
	} else {
		fprintf(fp, "%s: ", name);
	}
	fflush(fp);
}

void voluta_setup_globals(int argc, char *argv[])
{
	VOLUTA_STATICASSERT_LT(sizeof(voluta_globals), 1024);

	voluta_globals.version = voluta_version.string;
	voluta_globals.name = program_invocation_short_name;
	voluta_globals.prog = program_invocation_name;
	voluta_globals.argc = argc;
	voluta_globals.argv = argv;
	voluta_globals.cmd_argc = argc;
	voluta_globals.cmd_argv = argv;
	voluta_globals.cmd_name = NULL;
	voluta_globals.pid = getpid();
	voluta_globals.uid = getuid();
	voluta_globals.gid = getgid();
	voluta_globals.umsk = umask(0022);
	voluta_globals.umsk = umask(0022);
	voluta_globals.start_time = time(NULL);
	voluta_globals.dont_daemonize = false;
	voluta_globals.allow_coredump = false;
	voluta_globals.disable_ptrace = true; /* XXX */
	voluta_globals.log_mask = VOLUTA_LOG_DEFAULT;

	setlocale(LC_ALL, "");
	atexit(voluta_atexit_flush);
	error_print_progname = voluta_error_print_progname;
}

static void voluta_resolve_caps(void)
{
	int err = 1;
	pid_t pid;
	cap_t cap;
	cap_flag_value_t flag = CAP_CLEAR;

	pid = getpid();
	cap = cap_get_pid(pid);
	if (cap != NULL) {
		err = cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &flag);
		cap_free(cap);
	}
	voluta_globals.cap_sys_admin = (!err && (flag == CAP_SET));
}

void voluta_init_process(void)
{
	int err;

	err = voluta_init_lib();
	if (err) {
		voluta_die(err, "unable to init lib");
	}
	voluta_set_logmaskp(&voluta_globals.log_mask);
	voluta_resolve_caps();
}

void voluta_set_verbose_mode(const char *mode)
{
	voluta_log_mask_by_str(&voluta_globals.log_mask, mode);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_pretty_size(size_t n, char *buf, size_t bsz)
{
	const size_t k = VOLUTA_UKILO;
	const size_t m = VOLUTA_UMEGA;
	const size_t g = VOLUTA_UGIGA;

	if (n >= g) {
		snprintf(buf, bsz, "%0.1fG", (float)n / (float)g);
	} else if (n >= m) {
		snprintf(buf, bsz, "%0.1fM", (float)n / (float)m);
	} else if (n >= k) {
		snprintf(buf, bsz, "%0.1fK", (float)n / (float)k);
	} else {
		snprintf(buf, bsz, "%0.1f", (float)n);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *headref_path(const char *repodir)
{
	return voluta_joinpath_safe(repodir, "HEAD");
}

void voluta_save_headref(const char *repodir, const char *rootid)
{
	int err;
	int fd = -1;
	char *path = headref_path(repodir);
	const size_t len = strlen(rootid);

	err = voluta_sys_open(path, O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		voluta_die(err, "failed to create: %s", path);
	}
	err = voluta_sys_pwriten(fd, rootid, len, 0);
	if (err) {
		voluta_die(err, "write error: %s", path);
	}
	err = voluta_sys_pwriten(fd, "\n", 1, (loff_t)len);
	if (err) {
		voluta_die(err, "write error: %s", path);
	}
	voluta_sys_closefd(&fd);
	voluta_pfree_string(&path);
}

static void strip_headref(char *buf, size_t len)
{
	struct voluta_substr ss;

	buf[len] = '\0';
	voluta_substr_init_rw(&ss, buf, len, len);
	voluta_substr_strip_if(&ss, voluta_chr_isspace, &ss);
	voluta_substr_copyto(&ss, buf, len);
}

void voluta_load_headref(const char *repodir, char *buf, size_t bsz)
{
	int err;
	int fd = -1;
	size_t nrd = 0;
	char *path = headref_path(repodir);

	err = voluta_sys_open(path, O_RDONLY, 0600, &fd);
	if (err) {
		voluta_die(err, "failed to open: %s", path);
	}
	err = voluta_sys_pread(fd, buf, bsz - 1, 0, &nrd);
	if (err) {
		voluta_die(err, "read error: %s", path);
	}
	voluta_sys_closefd(&fd);
	voluta_pfree_string(&path);

	strip_headref(buf, nrd);
}

