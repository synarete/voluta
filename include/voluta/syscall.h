/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * This file is part of libvoluta
 *
 * Copyright (C) 2020-2021 Shachar Sharon
 *
 * Libvoluta is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Libvoluta is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
#ifndef VOLUTA_SYSCALL_H_
#define VOLUTA_SYSCALL_H_

struct stat;
struct statvfs;
struct statfs;
struct dirent64;
struct iovec;
struct utimbuf;
struct timeval;
struct timespec;
struct sigaction;
struct rlimit;
struct flock;
struct fiemap;
struct sockaddr;
struct msghdr;


/* syscall */
int voluta_sys_mount(const char *source, const char *target, const char *fstyp,
                     unsigned long mntflags, const void *data);

int voluta_sys_umount(const char *target);

int voluta_sys_umount2(const char *target, int flags);

int voluta_sys_access(const char *path, int mode);

int voluta_sys_faccessat(int dirfd, const char *pathname, int mode, int flags);

int voluta_sys_link(const char *path1, const char *path2);

int voluta_sys_linkat(int olddirfd, const char *oldpath,
                      int newdirfd, const char *newpath, int flags);

int voluta_sys_unlink(const char *path);

int voluta_sys_unlinkat(int dirfd, const char *pathname, int flags);

int voluta_sys_rename(const char *oldpath, const char *newpath);

int voluta_sys_renameat(int olddirfd, const char *oldpath,
                        int newdirfd, const char *newpath);

int voluta_sys_renameat2(int olddirfd, const char *oldpath,
                         int newdirfd, const char *newpath,
                         unsigned int flags);

int voluta_sys_fstatvfs(int fd, struct statvfs *stv);

int voluta_sys_statfs(const char *path, struct statfs *stfs);

int voluta_sys_fstatfs(int fd, struct statfs *stfs);

int voluta_sys_flock(int fd, int operation);

int voluta_sys_statvfs(const char *path, struct statvfs *stv);

int voluta_sys_fstat(int fd, struct stat *st);

int voluta_sys_fstatat(int dirfd, const char *path,
                       struct stat *st, int flags);

int voluta_sys_stat(const char *path, struct stat *st);

int voluta_sys_lstat(const char *path, struct stat *st);

int voluta_sys_statx(int dfd, const char *pathname, int flags,
                     unsigned int mask, struct statx *stx);

int voluta_sys_chmod(const char *path, mode_t mode);

int voluta_sys_fchmod(int fd, mode_t mode);

int voluta_sys_fchmodat(int dirfd, const char *pathname,
                        mode_t mode, int flags);

int voluta_sys_chown(const char *path, uid_t uid, gid_t gid);

int voluta_sys_fchown(int fd, uid_t uid, gid_t gid);

int voluta_sys_fchownat(int dirfd, const char *pathname,
                        uid_t uid, gid_t gid, int flags);

int voluta_sys_utime(const char *filename, const struct utimbuf *times);

int voluta_sys_utimes(const char *filename, const struct timeval times[2]);

int voluta_sys_utimensat(int dirfd, const char *pathname,
                         const struct timespec times[2], int flags);

int voluta_sys_futimens(int fd, const struct timespec times[2]);

int voluta_sys_mkdir(const char *path, mode_t mode);

int voluta_sys_mkdirat(int dirfd, const char *pathname, mode_t mode);

int voluta_sys_rmdir(const char *path);

int voluta_sys_getdents(int fd, void *buf, size_t bsz, struct dirent64 *dents,
                        size_t ndents, size_t *out_ndents);

int voluta_sys_creat(const char *path, mode_t mode, int *fd);

int voluta_sys_memfd_create(const char *name, unsigned int flags, int *fd);

int voluta_sys_open(const char *path, int flags, mode_t mode, int *fd);

int voluta_sys_openat(int dirfd, const char *path,
                      int flags, mode_t mode, int *fd);

int voluta_sys_close(int fd);

int voluta_sys_llseek(int fd, loff_t off, int whence, loff_t *pos);

int voluta_sys_syncfs(int fd);

int voluta_sys_fsync(int fd);

int voluta_sys_fdatasync(int fd);

int voluta_sys_fallocate(int fd, int mode, loff_t off, loff_t len);

int voluta_sys_truncate(const char *path, loff_t len);

int voluta_sys_ftruncate(int fd, loff_t len);

int voluta_sys_readlink(const char *path, char *buf, size_t bsz, size_t *cnt);

int voluta_sys_readlinkat(int dirfd, const char *pathname,
                          char *buf, size_t bsz, size_t *cnt);

int voluta_sys_symlink(const char *oldpath, const char *newpath);

int voluta_sys_symlinkat(const char *target, int dirfd, const char *linkpath);

int voluta_sys_mkfifo(const char *path, mode_t mode);

int voluta_sys_mkfifoat(int dirfd, const char *pathname, mode_t mode);

int voluta_sys_mknod(const char *pathname, mode_t mode, dev_t dev);

int voluta_sys_mknodat(int dirfd, const char *pathname,
                       mode_t mode, dev_t dev);

int voluta_sys_mmap(void *addr, size_t length, int prot, int flags,
                    int fd, off_t offset, void **out_addr);

int voluta_sys_mmap_anon(size_t length, int flags, void **out_addr);

int voluta_sys_munmap(void *addr, size_t length);

int voluta_sys_msync(void *addr, size_t len, int flags);

int voluta_sys_madvise(void *addr, size_t len, int advice);

int voluta_sys_mlock(const void *addr, size_t len);

int voluta_sys_mlock2(const void *addr, size_t len, unsigned int flags);

int voluta_sys_munlock(const void *addr, size_t len);

int voluta_sys_mlockall(int flags);

int voluta_sys_munlockall(void);

int voluta_sys_brk(void *addr);

int voluta_sys_sbrk(intptr_t increment, void **out_addr);

int voluta_sys_ioctl_blkgetsize64(int fd, size_t *sz);

int voluta_sys_ioctl_ficlone(int dest_fd, int src_fd);

int voluta_sys_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                               loff_t *off_out, size_t len, unsigned int flags,
                               size_t *out_ncp);

int voluta_sys_read(int fd, void *buf, size_t cnt, size_t *nrd);

int voluta_sys_pread(int fd, void *buf, size_t cnt, loff_t off, size_t *);

int voluta_sys_write(int fd, const void *buf, size_t cnt, size_t *nwr);

int voluta_sys_pwrite(int fd, const void *buf, size_t cnt,
                      loff_t off, size_t *nwr);

int voluta_sys_readv(int fd, const struct iovec *iov,
                     int iovcnt, size_t *nrd);

int voluta_sys_writev(int fd, const struct iovec *iov,
                      int iovcnt, size_t *nwr);

int voluta_sys_preadv(int fd, const struct iovec *iov,
                      int iovcnt, off_t off, size_t *nrd);

int voluta_sys_pwritev(int fd, const struct iovec *iov, int iovcnt,
                       off_t off, size_t *nwr);

int voluta_sys_preadv2(int fd, const struct iovec *iov, int iovcnt,
                       off_t off, int flags, size_t *nrd);

int voluta_sys_pwritev2(int fd, const struct iovec *iov, int iovcnt,
                        off_t off, int flags, size_t *nwr);

int voluta_sys_splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags, size_t *nsp);

int voluta_sys_vmsplice(int fd, const struct iovec *iov, size_t nr_segs,
                        unsigned int flags, size_t *nsp);

int voluta_sys_ioctlp(int fd, unsigned long int cmd, void *ptr);

int voluta_sys_fiemap(int fd, struct fiemap *fm);

int voluta_sys_setxattr(const char *path, const char *name,
                        const void *value, size_t size, int flags);

int voluta_sys_lsetxattr(const char *path, const char *name,
                         const void *value, size_t size, int flags);

int voluta_sys_fsetxattr(int fd, const char *name,
                         const void *value, size_t size, int flags);

int voluta_sys_getxattr(const char *path, const char *name,
                        void *value, size_t size, size_t *cnt);

int voluta_sys_lgetxattr(const char *path, const char *name,
                         void *value, size_t size, size_t *cnt);

int voluta_sys_fgetxattr(int fd, const char *name,
                         void *value, size_t size, size_t *cnt);

int voluta_sys_removexattr(const char *path, const char *name);

int voluta_sys_lremovexattr(const char *path, const char *name);

int voluta_sys_fremovexattr(int fd, const char *name);

int voluta_sys_listxattr(const char *path, char *list,
                         size_t size, size_t *out_size);

int voluta_sys_llistxattr(const char *path, char *list,
                          size_t size, size_t *out_size);

int voluta_sys_flistxattr(int fd, char *list, size_t size, size_t *out_size);

int voluta_sys_sigaction(int, const struct sigaction *, struct sigaction *);

int voluta_sys_getrlimit(int resource, struct rlimit *rlim);

int voluta_sys_setrlimit(int resource, const struct rlimit *rlim);

int voluta_sys_prctl(int option, unsigned long arg2, unsigned long arg3,
                     unsigned long arg4, unsigned long arg5);

int voluta_sys_clock_gettime(clockid_t clock_id, struct timespec *tp);

int voluta_sys_fcntl_flock(int fd, int cmd, struct flock *fl);

int voluta_sys_fcntl_getfl(int fd, int *out_fl);

int voluta_sys_fcntl_setfl(int fd, int fl);

int voluta_sys_fcntl_setpipesz(int fd, int pipesize);

int voluta_sys_fcntl_getpipesz(int fd, int *out_pipesize);

int voluta_sys_socket(int domain, int type, int protocol, int *out_sd);

int voluta_sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, const struct timespec *timeout,
                       const sigset_t *sigmask, int *out_nfds);

int voluta_sys_bind(int sd, const struct sockaddr *addr, socklen_t addrlen);

int voluta_sys_send(int sd, const void *buf, size_t len,
                    int flags, size_t *out_sent);

int voluta_sys_sendto(int sd, const void *buf, size_t len, int flags,
                      const struct sockaddr *addr, socklen_t addrlen,
                      size_t *out_sent);

int voluta_sys_sendmsg(int sd, const struct msghdr *msg,
                       int flags, size_t *out_sent);

int voluta_sys_recv(int sd, void *buf, size_t len,
                    int flags, size_t *out_recv);

int voluta_sys_recvfrom(int sd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen,
                        size_t *out_recv);

int voluta_sys_recvmsg(int sd, struct msghdr *msg,
                       int flags, size_t *out_recv);

int voluta_sys_listen(int sd, int backlog);

int voluta_sys_accept(int sd, struct sockaddr *addr,
                      socklen_t *addrlen, int *out_sd);

int voluta_sys_connect(int sd, const struct sockaddr *addr, socklen_t addrlen);

int voluta_sys_shutdown(int sd, int how);

int voluta_sys_setsockopt(int sd, int level, int optname,
                          const void *optval, socklen_t optlen);

int voluta_sys_getsockopt(int sd, int level, int optname,
                          void *optval, socklen_t *optlen);

int voluta_sys_pipe2(int pipefd[2], int flags);

int voluta_sys_seteuid(uid_t euid);

int voluta_sys_setegid(gid_t egid);

int voluta_sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);

int voluta_sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);

int voluta_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);

int voluta_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);


/* syscallx */
int voluta_sys_readn(int fd, void *buf, size_t cnt);

int voluta_sys_preadn(int fd, void *buf, size_t cnt, loff_t offset);

int voluta_sys_writen(int fd, const void *buf, size_t cnt);

int voluta_sys_pwriten(int fd, const void *buf, size_t cnt, loff_t offset);

int voluta_sys_opendir(const char *path, int *out_fd);

int voluta_sys_opendirat(int dfd, const char *path, int *out_fd);

int voluta_sys_closefd(int *pfd);

int voluta_sys_llseek_data(int fd, loff_t off, loff_t *out_data_off);

int voluta_proc_pipe_max_size(long *out_value);

int voluta_sys_pselect_rfd(int fd, const struct timespec *ts);

#endif /* VOLUTA_SYSCALL_H_ */

