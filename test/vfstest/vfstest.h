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

#ifndef VOLUTA_VFSTEST_H_
#define VOLUTA_VFSTEST_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>

#include <voluta/voluta.h>
#include <voluta/syscall.h>

/* Re-mapped macros */
#define VT_KILO                 VOLUTA_KILO
#define VT_MEGA                 VOLUTA_MEGA
#define VT_GIGA                 VOLUTA_GIGA
#define VT_TERA                 VOLUTA_TERA
#define VT_PETA                 VOLUTA_PETA

#define VT_UKILO                VOLUTA_UKILO
#define VT_UMEGA                VOLUTA_UMEGA
#define VT_UGIGA                VOLUTA_UGIGA
#define VT_UTERA                VOLUTA_UTERA
#define VT_UPETA                VOLUTA_UPETA

#define VT_FRGSIZE              (512) /* Fragment size (see stat(2)) */
#define VT_BK_SIZE              VOLUTA_BK_SIZE
#define VT_FILEMAP_NCHILD       VOLUTA_FILE_TREE_NCHILDS
#define VT_FILESIZE_MAX         VOLUTA_FILE_SIZE_MAX
#define VT_IOSIZE_MAX           VOLUTA_IO_SIZE_MAX
#define VT_STR(x_)              VOLUTA_STR(x_)
#define VT_ARRAY_SIZE(x_)       VOLUTA_ARRAY_SIZE(x_)

#define vt_expect_true(p)       voluta_expect(p)
#define vt_expect_false(p)      voluta_expect(!(p))
#define vt_expect_err(err, x)   voluta_expect_err(err, x)
#define vt_expect_eq(a, b)      voluta_expect_eq(a, b)
#define vt_expect_ne(a, b)      voluta_expect_ne(a, b)
#define vt_expect_lt(a, b)      voluta_expect_lt(a, b)
#define vt_expect_le(a, b)      voluta_expect_le(a, b)
#define vt_expect_gt(a, b)      voluta_expect_gt(a, b)
#define vt_expect_ge(a, b)      voluta_expect_ge(a, b)
#define vt_expect_eqm(a, b, n)  voluta_expect_eqm(a, b, n)

#define vt_expect_ts_eq(t1, t2) \
	vt_expect_eq(vt_timespec_diff(t1, t2), 0)
#define vt_expect_ts_gt(t1, t2) \
	vt_expect_gt(vt_timespec_diff(t1, t2), 0)
#define vt_expect_ts_ge(t1, t2) \
	vt_expect_ge(vt_timespec_diff(t1, t2), 0)
#define vt_expect_mtime_eq(st1, st2) \
	vt_expect_ts_eq(&((st1)->st_mtim), &((st2)->st_mtim))
#define vt_expect_mtime_gt(st1, st2) \
	vt_expect_ts_gt(&((st1)->st_mtim), &((st2)->st_mtim))
#define vt_expect_ctime_eq(st1, st2) \
	vt_expect_ts_eq(&((st1)->st_ctim), &((st2)->st_ctim))
#define vt_expect_ctime_gt(st1, st2) \
	vt_expect_ts_gt(&((st1)->st_ctim), &((st2)->st_ctim))
#define vt_expect_ctime_ge(st1, st2) \
	vt_expect_ts_ge(&((st1)->st_ctim), &((st2)->st_ctim))

#define vt_expect_dir(m)        vt_expect_true(S_ISDIR(m))
#define vt_expect_reg(m)        vt_expect_true(S_ISREG(m))
#define vt_expect_lnk(m)        vt_expect_true(S_ISLNK(m))


/* Tests control flags */
enum vt_flags {
	VT_IGNORE             = (1 << 1),
	VT_NORMAL             = (1 << 2),
	VT_POSIX_EXTRA        = (1 << 3),
	VT_STAVFS             = (1 << 4),
	VT_IO_EXTRA           = (1 << 5),
	VT_IO_TMPFILE         = (1 << 6),
	VT_VERIFY             = (1 << 7),
	VT_RANDOM             = (1 << 8),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct vt_env;

struct vt_mchunk {
	struct vt_mchunk *next;
	size_t  size;
	uint8_t data[40];
};


/* Test define */
struct vt_tdef {
	void (*hook)(struct vt_env *);
	const char  *name;
	int flags;
	int pad;
};


/* Tests-array define */
struct vt_tests {
	const struct vt_tdef *arr;
	size_t len;
};


/* Tests execution parameters */
struct vt_params {
	const char *progname;
	const char *workdir;
	const char *testname;
	long repeatn;
	int testsmask;
	int listtests;
	int pad;
};


/* Tests execution environment context */
struct vt_env {
	struct vt_params params;
	const struct vt_tdef *currtest;
	struct statvfs stvfs;
	struct timespec ts_start;
	size_t  seqn;
	time_t  start;
	pid_t   pid;
	uid_t   uid;
	gid_t   gid;
	mode_t  umsk;
	size_t  nbytes_alloc;
	struct vt_mchunk *malloc_list;
	struct vt_tests   tests;
};


/* Sanity-testing utility */
void vte_init(struct vt_env *vte, const struct vt_params *params);

void vte_exec(struct vt_env *vte);

void vte_fini(struct vt_env *vte);

void vt_suspend(const struct vt_env *vte, int sec, int part);

void vt_suspends(const struct vt_env *vte, int sec);

char *vt_strdup(struct vt_env *vte, const char *str);

char *vt_strcat(struct vt_env *vte, const char *str1, const char *str2);

void vt_freeall(struct vt_env *vte);

char *vt_strfmt(struct vt_env *vte, const char *fmt, ...);

char *vt_make_name(struct vt_env *vte, unsigned long key);

char *vt_new_name_unique(struct vt_env *vte);

char *vt_new_path_unique(struct vt_env *vte);

char *vt_new_path_under(struct vt_env *vte, const char *base);

char *vt_new_path_name(struct vt_env *vte, const char *name);

char *vt_new_path_nested(struct vt_env *vte,
			 const char *base, const char *name);

char *vt_new_pathf(struct vt_env *vte, const char *p, const char *fmt, ...);

void *vt_new_buf_zeros(struct vt_env *vte, size_t bsz);

void *vt_new_buf_rands(struct vt_env *vte, size_t bsz);

void *vt_new_buf_nums(struct vt_env *vte,
		      unsigned long base, size_t bsz);

long *vt_new_randseq(struct vt_env *vte, size_t cnt, long base);

long vt_lrand(struct vt_env *vte);

long vt_timespec_diff(const struct timespec *ts1, const struct timespec *ts2);

size_t vt_page_size(void);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Wrapper over system calls */
void vt_syncfs(int fd);

void vt_fsync(int fd);

void vt_statvfs(const char *path, struct statvfs *stv);

void vt_statvfs_err(const char *path, int err);

void vt_fstatvfs(int fd, struct statvfs *stvfs);

void vt_utime(const char *filename, const struct utimbuf *times);

void vt_utimes(const char *filename, const struct timeval tm[2]);

void vt_utimensat(int dirfd, const char *pathname,
		  const struct timespec tm[2], int flags);

void vt_futimens(int fd, const struct timespec times[2]);

void vt_stat(const char *path, struct stat *st);

void vt_fstat(int fd, struct stat *st);

void vt_fstatat(int dirfd, const char *path, struct stat *st, int flags);

void vt_fstatat_err(int dirfd, const char *path, int flags, int err);

void vt_lstat(const char *path, struct stat *st);

void vt_lstat_err(const char *path, int err);

void vt_stat_exists(const char *path);

void vt_stat_err(const char *path, int err);

void vt_stat_noent(const char *path);

void vt_mkdir(const char *path, mode_t mode);

void vt_mkdir_err(const char *path, mode_t mode, int err);

void vt_mkdirat(int dirfd, const char *pathname, mode_t mode);

void vt_rmdir(const char *path);

void vt_rmdir_err(const char *path, int err);

void vt_unlink(const char *path);

void vt_unlink_err(const char *path, int err);

void vt_unlink_noent(const char *path);

void vt_unlinkat(int dirfd, const char *pathname, int flags);

void vt_open(const char *path, int flags, mode_t mode, int *fd);

void vt_open_err(const char *path, int flags, mode_t mode, int err);

void vt_openat(int dirfd, const char *path,
	       int flags, mode_t mode, int *fd);

void vt_openat_err(int dirfd, const char *path,
		   int flags, mode_t mode, int err);

void vt_creat(const char *path, mode_t mode, int *fd);

void vt_truncate(const char *path, loff_t len);

void vt_ftruncate(int fd, loff_t len);

void vt_llseek(int fd, loff_t off, int whence, loff_t *pos);

void vt_llseek_err(int fd, loff_t off, int whence, int err);

void vt_write(int fd, const void *buf, size_t cnt, size_t *nwr);

void vt_pwrite(int fd, const void *buf, size_t cnt, loff_t off, size_t *nwr);

void vt_pwrite_err(int fd, const void *buf,
		   size_t cnt, loff_t off, int err);

void vt_read(int fd, void *buf, size_t cnt, size_t *nrd);

void vt_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *nrd);

void vt_fallocate(int fd, int mode, loff_t off, loff_t len);

void vt_fallocate_err(int fd, int mode, loff_t off, loff_t len, int err);

void vt_fdatasync(int fd);

void vt_mkfifo(const char *path, mode_t mode);

void vt_mkfifoat(int dirfd, const char *pathname, mode_t mode);

void vt_mknod(const char *pathname, mode_t mode, dev_t dev);

void vt_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);

void vt_symlink(const char *oldpath, const char *newpath);

void vt_symlinkat(const char *target, int dirfd, const char *linkpath);

void vt_readlink(const char *path, char *buf, size_t bsz, size_t *cnt);

void vt_readlink_err(const char *path, char *buf, size_t bsz, int err);

void vt_readlinkat(int dirfd, const char *pathname,
		   char *buf, size_t bsz, size_t *cnt);

void vt_rename(const char *oldpath, const char *newpath);

void vt_rename_err(const char *oldpath, const char *newpath, int err);

void vt_renameat(int olddirfd, const char *oldpath,
		 int newdirfd, const char *newpath);

void vt_renameat2(int olddirfd, const char *oldpath,
		  int newdirfd, const char *newpath, unsigned int flags);

void vt_link(const char *path1, const char *path2);

void vt_link_err(const char *path1, const char *path2, int err);

void vt_linkat(int olddirfd, const char *oldpath,
	       int newdirfd, const char *newpath, int flags);

void vt_linkat_err(int olddirfd, const char *oldpath,
		   int newdirfd, const char *newpath, int flags, int err);

void vt_chmod(const char *path, mode_t mode);

void vt_fchmod(int fd, mode_t mode);

void vt_chown(const char *path, uid_t uid, gid_t gid);

void vt_fchown(int fd, uid_t uid, gid_t gid);

void vt_access(const char *path, int mode);

void vt_access_err(const char *path, int mode, int err);

void vt_close(int fd);

void vt_mmap(void *addr, size_t length, int prot, int flags,
	     int fd, off_t offset, void **out);

void vt_munmap(void *addr, size_t length);

void vt_msync(void *addr, size_t len, int flags);

void vt_madvise(void *addr, size_t len, int advice);

void vt_setxattr(const char *path, const char *name,
		 const void *value, size_t size, int flags);

void vt_lsetxattr(const char *path, const char *name,
		  const void *value, size_t size, int flags);

void vt_fsetxattr(int fd, const char *name,
		  const void *value, size_t size, int flags);

void vt_getxattr(const char *path, const char *name,
		 void *value, size_t size, size_t *cnt);

void vt_getxattr_err(const char *path, const char *name, int err);

void vt_lgetxattr(const char *path, const char *name,
		  void *value, size_t size, size_t *cnt);

void vt_fgetxattr(int fd, const char *name,
		  void *value, size_t size, size_t *cnt);

void vt_removexattr(const char *path, const char *name);

void vt_lremovexattr(const char *path, const char *name);

void vt_fremovexattr(int fd, const char *name);

void vt_fremovexattr_err(int fd, const char *name, int err);

void vt_listxattr(const char *path, char *list, size_t size, size_t *out);

void vt_llistxattr(const char *path, char *list, size_t size, size_t *out);

void vt_flistxattr(int fd, char *list, size_t size, size_t *out);

void vt_flistxattr_err(int fd, char *list, size_t size, int err);

void vt_getdent(int fd, struct dirent64 *dent);

void vt_getdents(int fd, void *buf, size_t bsz,
		 struct dirent64 *des, size_t ndes, size_t *out_ndes);

void vt_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
			loff_t *off_out, size_t len, size_t *out_ncp);

void vt_ioctl_ficlone(int dest_fd, int src_fd);

void vt_fiemap(int fd, struct fiemap *fm);

/* Complex wrappers */
void vt_readn(int fd, void *buf, size_t cnt);

void vt_preadn(int fd, void *buf, size_t cnt, loff_t offset);

void vt_writen(int fd, const void *buf, size_t cnt);

void vt_pwriten(int fd, const void *buf, size_t cnt, loff_t offset);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Sub-tests grouped by topic */
extern const struct vt_tests vt_test_access;
extern const struct vt_tests vt_test_stat;
extern const struct vt_tests vt_test_statvfs;
extern const struct vt_tests vt_test_utimes;
extern const struct vt_tests vt_test_mkdir;
extern const struct vt_tests vt_test_readdir;
extern const struct vt_tests vt_test_create;
extern const struct vt_tests vt_test_open;
extern const struct vt_tests vt_test_link;
extern const struct vt_tests vt_test_unlink;
extern const struct vt_tests vt_test_chmod;
extern const struct vt_tests vt_test_symlink;
extern const struct vt_tests vt_test_mkfifo;
extern const struct vt_tests vt_test_fsync;
extern const struct vt_tests vt_test_rename;
extern const struct vt_tests vt_test_xattr;
extern const struct vt_tests vt_test_write;
extern const struct vt_tests vt_test_truncate;
extern const struct vt_tests vt_test_lseek;
extern const struct vt_tests vt_test_fiemap;
extern const struct vt_tests vt_test_boundaries;
extern const struct vt_tests vt_test_tmpfile;
extern const struct vt_tests vt_test_stat_io;
extern const struct vt_tests vt_test_rw_basic;
extern const struct vt_tests vt_test_rw_sequencial;
extern const struct vt_tests vt_test_rw_sparse;
extern const struct vt_tests vt_test_rw_random;
extern const struct vt_tests vt_test_rw_large;
extern const struct vt_tests vt_test_unlinked_file;
extern const struct vt_tests vt_test_truncate_io;
extern const struct vt_tests vt_test_fallocate;
extern const struct vt_tests vt_test_clone;
extern const struct vt_tests vt_test_copy_file_range;
extern const struct vt_tests vt_test_mmap;
extern const struct vt_tests vt_test_namespace;

/* Test-define helper macros */
#define VT_DEFTESTF(fn_, fl_) \
	{ .hook = (fn_), .name = VT_STR(fn_), .flags = (fl_) }

#define VT_DEFTEST(fn_) \
	VT_DEFTESTF(fn_, VT_NORMAL)

#define VT_DEFTESTS(a_) \
	{ .arr = (a_), .len = VT_ARRAY_SIZE(a_) }

#endif /* VOLUTA_VFSTEST_H_ */

