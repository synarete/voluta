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
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <voluta/infra.h>
#include <voluta/defs.h>
#include <voluta/fs/types.h>
#include <voluta/fs/mount.h>
#include <voluta/fs/private.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

enum voluta_mntcmd {
	VOLUTA_MNTCMD_NONE      = 0,
	VOLUTA_MNTCMD_HANDSHAKE = 1,
	VOLUTA_MNTCMD_MOUNT     = 2,
	VOLUTA_MNTCMD_UMOUNT    = 3,
};

struct voluta_mntmsg {
	uint32_t        mn_magic;
	uint16_t        mn_version_major;
	uint16_t        mn_version_minor;
	uint32_t        mn_cmd;
	uint32_t        mn_status;
	uint64_t        mn_flags;
	uint32_t        mn_user_id;
	uint32_t        mn_group_id;
	uint32_t        mn_root_mode;
	uint32_t        mn_max_read;
	uint8_t         mn_allowother;
	uint8_t         mn_reserved2[87];
	uint8_t         mn_path[VOLUTA_MNTPATH_MAX];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_cmsg_buf {
	long cms[CMSG_SPACE(sizeof(int)) / sizeof(long)];
	long pad;
} voluta_aligned8;

struct voluta_mntparams {
	const char *path;
	uint64_t flags;
	uid_t  user_id;
	gid_t  group_id;
	mode_t root_mode;
	size_t max_read;
	bool allowother;
};

struct voluta_mntclnt {
	struct voluta_socket    mc_sock;
	struct voluta_sockaddr  mc_srvaddr;
};


struct voluta_mntsvc {
	struct voluta_mntsrv   *ms_srv;
	struct voluta_socket    ms_asock;
	struct voluta_sockaddr  ms_peer;
	struct ucred            ms_peer_ucred;
	int ms_fuse_fd;
};

struct voluta_mntsrv {
	const struct voluta_mntrules *ms_rules;
	struct voluta_socket    ms_lsock;
	struct voluta_mntsvc    ms_svc;
};

struct voluta_ms_env {
	struct voluta_mntsrv *srv;
	int active;
	int signum;
};

struct voluta_ms_env_obj {
	struct voluta_mntsrv    ms_srv;
	struct voluta_ms_env    ms_env;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* Known file-systems */
#define FUSE_SUPER_MAGIC        0x65735546 /*  from kernel 'fs/fuse/inode.c' */
#define TMPFS_MAGIC             0x01021994
#define XFS_SB_MAGIC            0x58465342
#define EXT234_SUPER_MAGIC      0x0000EF53
#define ZFS_SUPER_MAGIC         0x2FC12FC1
#define BTRFS_SUPER_MAGIC       0x9123683E
#define CEPH_SUPER_MAGIC        0x00C36400
#define CIFS_MAGIC_NUMBER       0xFF534D42
#define ECRYPTFS_SUPER_MAGIC    0x0000F15F
#define F2FS_SUPER_MAGIC        0xF2F52010
#define NFS_SUPER_MAGIC         0x00006969
#define NTFS_SB_MAGIC           0x5346544E
#define OVERLAYFS_SUPER_MAGIC   0x794C7630

#define MKFSINFO(t_, n_, a_, i_) \
	{ .vfstype = (t_), .name = (n_), .allowed = (a_), .isfuse = (i_) }


static const struct voluta_fsinfo fsinfo_allowed[] = {
	MKFSINFO(FUSE_SUPER_MAGIC, "FUSE", 0, 1),
	MKFSINFO(TMPFS_MAGIC, "TMPFS", 0, 0),
	MKFSINFO(XFS_SB_MAGIC, "XFS", 1, 0),
	MKFSINFO(EXT234_SUPER_MAGIC, "EXT234", 1, 0),
	MKFSINFO(ZFS_SUPER_MAGIC, "ZFS", 1, 0),
	MKFSINFO(BTRFS_SUPER_MAGIC, "BTRFS", 1, 0),
	MKFSINFO(CEPH_SUPER_MAGIC, "CEPH", 1, 0),
	MKFSINFO(CIFS_MAGIC_NUMBER, "CIFS", 1, 0),
	MKFSINFO(ECRYPTFS_SUPER_MAGIC, "ECRYPTFS", 0, 0),
	MKFSINFO(F2FS_SUPER_MAGIC, "F2FS", 1, 0),
	MKFSINFO(NFS_SUPER_MAGIC, "NFS", 1, 0),
	MKFSINFO(NTFS_SB_MAGIC, "NTFS", 1, 0),
	MKFSINFO(OVERLAYFS_SUPER_MAGIC, "OVERLAYFS", 0, 0)
};

const struct voluta_fsinfo *voluta_fsinfo_by_vfstype(long vfstype)
{
	const struct voluta_fsinfo *fsinfo = NULL;

	for (size_t i = 0; i < VOLUTA_ARRAY_SIZE(fsinfo_allowed); ++i) {
		fsinfo = &fsinfo_allowed[i];
		if (fsinfo->vfstype == vfstype) {
			break;
		}
		fsinfo = NULL;
	}
	return fsinfo;
}

int voluta_check_mntdir_fstype(long vfstype)
{
	const struct voluta_fsinfo *fsinfo;

	fsinfo = voluta_fsinfo_by_vfstype(vfstype);
	if (fsinfo == NULL) {
		return -EINVAL;
	}
	if (fsinfo->isfuse || !fsinfo->allowed) {
		return -EPERM;
	}
	return 0;
}

static int voluta_check_mntpoint(const char *path,
                                 uid_t caller_uid, bool mounting)
{
	int err;
	struct stat st;
	struct statfs stfs;

	err = voluta_sys_stat(path, &st);
	if ((err == -EACCES) && !mounting) {
		/*
		 * special case where having a live mount without FUSE
		 * 'allow_other' option; thus even privileged user can not
		 * access to mount point. Fine with us
		 *
		 * TODO: at least type to parse '/proc/self/mounts'
		 */
		return 0;
	}
	if (err) {
		return err;
	}
	if (!S_ISDIR(st.st_mode)) {
		return -ENOTDIR;
	}
	if (mounting && (st.st_nlink > 2)) {
		return -ENOTEMPTY;
	}
	if (mounting && (st.st_ino == VOLUTA_INO_ROOT)) {
		return -EBUSY;
	}
	if (!mounting && (st.st_ino != VOLUTA_INO_ROOT)) {
		return -EINVAL;
	}
	err = voluta_sys_statfs(path, &stfs);
	if (err) {
		return err;
	}
	if (caller_uid != st.st_uid) {
		return -EPERM;
	}
	if (mounting) {
		err = voluta_check_mntdir_fstype(stfs.f_type);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void close_fd(int *pfd)
{
	int err;

	if ((pfd != NULL) && (*pfd > 0)) {
		err = voluta_sys_close(*pfd);
		if (err) {
			voluta_panic("close-error: fd=%d err=%d", *pfd, err);
		}
		*pfd = -1;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool equal_path_by_stat(const char *path1, const struct stat *st2)
{
	int err;
	struct stat st1;

	err = voluta_sys_stat(path1, &st1);
	if (err) {
		return false;
	}
	if (st1.st_ino != st2->st_ino) {
		return false;
	}
	if (st1.st_dev != st2->st_dev) {
		return false;
	}
	if (st1.st_mode != st2->st_mode) {
		return false;
	}
	return true;
}

static int check_canonical_path(const char *path)
{
	int err = 0;
	char *cpath;

	if (!path || !strlen(path)) {
		return -EINVAL;
	}
	cpath = canonicalize_file_name(path);
	if (cpath == NULL) {
		return -errno;
	}
	if (strcmp(path, cpath) != 0) {
		log_info("canonical-path-mismatch: '%s' '%s'", path, cpath);
		err = -EINVAL;
	}
	free(cpath);
	return err;
}

static int check_mount_path(const char *path, uid_t caller_uid)
{
	int err;

	err = check_canonical_path(path);
	if (err) {
		return err;
	}
	err = voluta_check_mntpoint(path, caller_uid, true);
	if (err) {
		log_info("illegal mount-point: %s %d", path, err);
	}
	return err;
}

static int check_umount_path(const char *path, uid_t caller_uid)
{
	int err;

	err = voluta_check_mntpoint(path, caller_uid, false);
	if (err && (err != -ENOTCONN)) {
		log_info("illegal umount: %s %d", path, err);
	}
	return err;
}

static int check_fuse_dev(const char *devname)
{
	int err;
	struct stat st;

	err = voluta_sys_stat(devname, &st);
	if (err) {
		log_info("no-stat: %s %d", devname, err);
		return err;
	}
	if (!S_ISCHR(st.st_mode)) {
		log_info("not-a-char-device: %s", devname);
		return -EINVAL;
	}
	return 0;
}

static int open_fuse_dev(const char *devname, int *out_fd)
{
	int err;

	*out_fd = -1;
	err = check_fuse_dev(devname);
	if (err) {
		return err;
	}
	err = voluta_sys_open(devname, O_RDWR | O_CLOEXEC, 0, out_fd);
	if (err) {
		log_info("failed to open fuse device: %s", devname);
		return err;
	}
	return 0;
}

static int format_mount_data(const struct voluta_mntparams *mntp,
                             int fd, char *dat, int dat_size)
{
	int ret;
	size_t len;

	ret = snprintf(dat, (size_t)dat_size,
	               "default_permissions,max_read=%d,fd=%d,"
	               "rootmode=0%o,user_id=%d,group_id=%d,%s",
	               (int)mntp->max_read, fd, mntp->root_mode,
	               mntp->user_id, mntp->group_id,
	               mntp->allowother ? "allow_other" : "");
	if ((ret <= 0) || (ret >= dat_size)) {
		return -EINVAL;
	}
	len = strlen(dat);
	if (dat[len - 1] == ',') {
		dat[len - 1] = '\0';
	}
	return 0;
}

static int do_fuse_mount(const struct voluta_mntparams *mntp, int *out_fd)
{
	int err;
	const char *dev = "/dev/fuse";
	const char *src = "voluta";
	const char *fst = "fuse.voluta";
	char data[256] = "";

	err = open_fuse_dev(dev, out_fd);
	if (err) {
		return err;
	}
	err = format_mount_data(mntp, *out_fd, data, (int)sizeof(data));
	if (err) {
		close_fd(out_fd);
		return err;
	}
	err = voluta_sys_mount(src, mntp->path, fst, mntp->flags, data);
	if (err) {
		close_fd(out_fd);
		return err;
	}
	return 0;
}

static int do_fuse_umount(const struct voluta_mntparams *mntp)
{
	return voluta_sys_umount2(mntp->path, (int)mntp->flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mntmsg_status(const struct voluta_mntmsg *mmsg)
{
	return -((int)mmsg->mn_status);
}

static void mntmsg_set_status(struct voluta_mntmsg *mmsg, int status)
{
	mmsg->mn_status = (uint32_t)abs(status);
}

static void mntmsg_init(struct voluta_mntmsg *mmsg, int cmd)
{
	VOLUTA_STATICASSERT_LE(sizeof(struct voluta_mntmsg), 2048);

	voluta_memzero(mmsg, sizeof(*mmsg));
	mntmsg_set_status(mmsg, 0);
	mmsg->mn_magic = VOLUTA_ZTYPE_MAGIC;
	mmsg->mn_version_major = (uint16_t)voluta_version.major;
	mmsg->mn_version_minor = (uint16_t)voluta_version.minor;
	mmsg->mn_cmd = (uint32_t)cmd;
}

static void mntmsg_reset(struct voluta_mntmsg *mmsg)
{
	mntmsg_init(mmsg, 0);
}

static const char *mntmsg_path(const struct voluta_mntmsg *mmsg)
{
	const char *path = (const char *)(mmsg->mn_path);
	const size_t maxlen = sizeof(mmsg->mn_path);
	const size_t len = strnlen(path, maxlen);

	return (len && (len < maxlen)) ? path : NULL;
}

static int mntmsg_set_path(struct voluta_mntmsg *mmsg, const char *path)
{
	size_t len;

	if (path == NULL) {
		return -EINVAL;
	}
	len = strlen(path);
	if (len >= sizeof(mmsg->mn_path)) {
		return -EINVAL;
	}
	memcpy(mmsg->mn_path, path, len);
	return 0;
}

static void mntmsg_to_params(const struct voluta_mntmsg *mmsg,
                             struct voluta_mntparams *mntp)
{
	mntp->path = mntmsg_path(mmsg);
	mntp->flags = mmsg->mn_flags;
	mntp->user_id = mmsg->mn_user_id;
	mntp->group_id = mmsg->mn_group_id;
	mntp->root_mode = mmsg->mn_root_mode;
	mntp->max_read = mmsg->mn_max_read;
	mntp->allowother = (mmsg->mn_allowother > 0);
}

static int mntmsg_set_from_params(struct voluta_mntmsg *mmsg,
                                  const struct voluta_mntparams *mntp)
{
	mmsg->mn_flags = mntp->flags;
	mmsg->mn_user_id = (uint32_t)mntp->user_id;
	mmsg->mn_group_id = (uint32_t)mntp->group_id;
	mmsg->mn_root_mode = (uint32_t)mntp->root_mode;
	mmsg->mn_max_read = (uint32_t)mntp->max_read;
	mmsg->mn_allowother = mntp->allowother ? 1 : 0;

	return mntp->path ? mntmsg_set_path(mmsg, mntp->path) : 0;
}

static int mntmsg_setup(struct voluta_mntmsg *mmsg, int cmd,
                        const struct voluta_mntparams *mntp)
{
	mntmsg_init(mmsg, cmd);
	return mntmsg_set_from_params(mmsg, mntp);
}

static int mntmsg_mount(struct voluta_mntmsg *mmsg,
                        const struct voluta_mntparams *mntp)
{
	return mntmsg_setup(mmsg, VOLUTA_MNTCMD_MOUNT, mntp);
}

static int mntmsg_umount(struct voluta_mntmsg *mmsg,
                         const struct voluta_mntparams *mntp)
{
	return mntmsg_setup(mmsg, VOLUTA_MNTCMD_UMOUNT, mntp);
}

static int mntmsg_handshake(struct voluta_mntmsg *mmsg,
                            const struct voluta_mntparams *mntp)
{
	return mntmsg_setup(mmsg, VOLUTA_MNTCMD_HANDSHAKE, mntp);
}

static enum voluta_mntcmd mntmsg_cmd(const struct voluta_mntmsg *mmsg)
{
	return (enum voluta_mntcmd)mmsg->mn_cmd;
}

static int mntmsg_check(const struct voluta_mntmsg *mmsg)
{
	if (mmsg->mn_magic != VOLUTA_ZTYPE_MAGIC) {
		return -EINVAL;
	}
	if (mmsg->mn_version_major != voluta_version.major) {
		return -EPROTO;
	}
	if (mmsg->mn_version_minor > voluta_version.minor) {
		return -EPROTO;
	}
	switch (mntmsg_cmd(mmsg)) {
	case VOLUTA_MNTCMD_HANDSHAKE:
	case VOLUTA_MNTCMD_MOUNT:
	case VOLUTA_MNTCMD_UMOUNT:
		break;
	case VOLUTA_MNTCMD_NONE:
	default:
		return -EINVAL;
	}
	return 0;
}

static int do_sendmsg(const struct voluta_socket *sock,
                      const struct msghdr *msg)
{
	int err;
	size_t nbytes = 0;

	err = voluta_socket_sendmsg(sock, msg, MSG_NOSIGNAL, &nbytes);
	if (err) {
		return err;
	}
	if (nbytes < sizeof(*msg)) {
		return -ECOMM; /* XXX is it? */
	}
	return 0;
}

static void do_pack_fd(struct msghdr *msg, int fd)
{
	struct cmsghdr *cmsg = NULL;

	if (fd > 0) {
		cmsg = voluta_cmsg_firsthdr(msg);
		voluta_cmsg_pack_fd(cmsg, fd);
	}
}

static int mntmsg_send(const struct voluta_mntmsg *mmsg,
                       const struct voluta_socket *sock, int fd)
{
	struct voluta_cmsg_buf cb = {
		.pad = 0
	};
	struct iovec iov = {
		.iov_base = unconst(mmsg),
		.iov_len  = sizeof(*mmsg)
	};
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cb.cms,
		.msg_controllen = (fd > 0) ? sizeof(cb.cms) : 0,
		.msg_flags = 0
	};

	do_pack_fd(&msg, fd);
	return do_sendmsg(sock, &msg);
}

static int do_recvmsg(const struct voluta_socket *sock, struct msghdr *msg)
{
	int err;
	size_t nbytes = 0;

	err = voluta_socket_recvmsg(sock, msg, MSG_NOSIGNAL, &nbytes);
	if (err) {
		return err;
	}
	if (nbytes < sizeof(*msg)) {
		return -ECOMM; /* XXX is it? */
	}
	return 0;
}

static int do_unpack_fd(struct msghdr *msg, int *out_fd)
{
	int err;
	struct cmsghdr *cmsg;

	cmsg = voluta_cmsg_firsthdr(msg);
	if (cmsg != NULL) {
		err = voluta_cmsg_unpack_fd(cmsg, out_fd);
	} else {
		*out_fd = -1;
		err = 0;
	}
	return err;
}

static int mntmsg_recv(const struct voluta_mntmsg *mmsg,
                       const struct voluta_socket *sock, int *out_fd)
{
	int err;
	struct voluta_cmsg_buf cb = {
		.pad = 0
	};
	struct iovec iov = {
		.iov_base = unconst(mmsg),
		.iov_len  = sizeof(*mmsg)
	};
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cb.cms,
		.msg_controllen = sizeof(cb.cms),
		.msg_flags = 0
	};

	*out_fd = -1;
	err = do_recvmsg(sock, &msg);
	if (err) {
		return err;
	}
	err = do_unpack_fd(&msg, out_fd);
	if (err) {
		return err;
	}
	return 0;
}

static int mntmsg_recv2(const struct voluta_mntmsg *mmsg,
                        const struct voluta_socket *sock)
{
	int err;
	int dummy_fd = -1;

	err = mntmsg_recv(mmsg, sock, &dummy_fd);
	close_fd(&dummy_fd);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mntsvc_reset_peer_ucred(struct voluta_mntsvc *msvc)
{
	msvc->ms_peer_ucred.pid = (pid_t)(-1);
	msvc->ms_peer_ucred.uid = (uid_t)(-1);
	msvc->ms_peer_ucred.gid = (gid_t)(-1);
}

static void mntsvc_init(struct voluta_mntsvc *msvc)
{
	voluta_streamsock_initu(&msvc->ms_asock);
	voluta_sockaddr_none(&msvc->ms_peer);
	mntsvc_reset_peer_ucred(msvc);
	msvc->ms_fuse_fd = -1;
	msvc->ms_srv = NULL;
}

static void mntsvc_close_fd(struct voluta_mntsvc *msvc)
{
	close_fd(&msvc->ms_fuse_fd);
}

static void mntsvc_close_sock(struct voluta_mntsvc *msvc)
{
	voluta_socket_fini(&msvc->ms_asock);
	voluta_sockaddr_none(&msvc->ms_peer);
}

static void mntsvc_fini(struct voluta_mntsvc *msvc)
{
	mntsvc_close_sock(msvc);
	mntsvc_close_fd(msvc);
	mntsvc_reset_peer_ucred(msvc);
	msvc->ms_srv = NULL;
}

static int mntsvc_accept_from(struct voluta_mntsvc *msvc,
                              const struct voluta_socket *sock)
{
	int err;
	struct ucred *cred = &msvc->ms_peer_ucred;

	err = voluta_socket_accept(sock, &msvc->ms_asock, &msvc->ms_peer);
	if (err) {
		return err;
	}
	err = voluta_socket_getpeercred(&msvc->ms_asock, cred);
	if (err) {
		voluta_socket_fini(&msvc->ms_asock);
		return err;
	}

	log_info("new-connection: pid=%d uid=%d gid=%d",
	         cred->pid, cred->uid, cred->gid);
	return 0;
}

static void mntsvc_term_peer(struct voluta_mntsvc *msvc)
{
	const struct ucred *cred = &msvc->ms_peer_ucred;

	log_info("end-connection: pid=%d uid=%d gid=%d",
	         cred->pid, cred->uid, cred->gid);

	voluta_socket_shutdown_rdwr(&msvc->ms_asock);
	voluta_socket_fini(&msvc->ms_asock);
	voluta_streamsock_initu(&msvc->ms_asock);
	mntsvc_reset_peer_ucred(msvc);
}

static int mntsvc_recv_request(struct voluta_mntsvc *msvc,
                               struct voluta_mntmsg *mmsg)
{
	int err;

	mntmsg_reset(mmsg);
	err = mntmsg_recv2(mmsg, &msvc->ms_asock);
	if (err) {
		return err;
	}
	err = mntmsg_check(mmsg);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_check_mntrule(const struct voluta_mntsvc *msvc,
                                const struct voluta_mntparams *mntp)
{
	int err;
	bool has_rule = false;
	struct stat st;
	const struct voluta_mntrule *mrule;
	const struct voluta_mntrules *mrules = msvc->ms_srv->ms_rules;

	if (mrules == NULL) {
		log_info("no rules for: '%s'", mntp->path);
		return -EPERM;
	}
	err = voluta_sys_stat(mntp->path, &st);
	if (err) {
		log_info("no stat for: '%s'", mntp->path);
		return err;
	}
	for (size_t i = 0; (i < mrules->nrules) && !has_rule; ++i) {
		mrule = &mrules->rules[i];
		/* TODO: take into account 'recursive' and 'uid' */
		has_rule = equal_path_by_stat(mrule->path, &st);
	}
	if (!has_rule) {
		log_info("no valid mount-rule for: '%s'", mntp->path);
		return -EPERM;
	}
	return 0;
}

static int mntsvc_check_mount(const struct voluta_mntsvc *msvc,
                              const struct voluta_mntparams *mntp)
{
	int err;
	size_t page_size;
	const struct ucred *peer_cred = &msvc->ms_peer_ucred;
	const unsigned long sup_mnt_mask =
	        (MS_LAZYTIME | MS_NOEXEC | MS_NOSUID | MS_NODEV | MS_RDONLY);

	if (mntp->flags & ~sup_mnt_mask) {
		return -EOPNOTSUPP;
	}
	if ((mntp->root_mode & S_IRWXU) == 0) {
		return -EOPNOTSUPP;
	}
	if ((mntp->root_mode & S_IFDIR) == 0) {
		return -EINVAL;
	}
	if ((mntp->user_id != peer_cred->uid) ||
	    (mntp->group_id != peer_cred->gid)) {
		return -EACCES;
	}
	page_size = (size_t)voluta_sc_page_size();
	if (mntp->max_read < (2 * page_size)) {
		return -EINVAL;
	}
	if (mntp->max_read > (512 * page_size)) {
		return -EINVAL;
	}
	if (mntp->path == NULL) {
		return -EINVAL;
	}
	err = mntsvc_check_mntrule(msvc, mntp);
	if (err) {
		return err;
	}
	err = check_mount_path(mntp->path, peer_cred->uid);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_do_mount(struct voluta_mntsvc *msvc,
                           const struct voluta_mntparams *mntp)
{
	int err;

	err = do_fuse_mount(mntp, &msvc->ms_fuse_fd);
	log_info("mount: '%s' flags=0x%lx uid=%d gid=%d rootmode=0%o "
	         "max_read=%u fuse_fd=%d err=%d", mntp->path, mntp->flags,
	         mntp->user_id, mntp->group_id, mntp->root_mode,
	         mntp->max_read, msvc->ms_fuse_fd, err);

	return err;
}

static int mntsvc_exec_mount(struct voluta_mntsvc *msvc,
                             const struct voluta_mntparams *mntp)
{
	int err;

	err = mntsvc_check_mount(msvc, mntp);
	if (err) {
		return err;
	}
	err = mntsvc_do_mount(msvc, mntp);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_check_umount(const struct voluta_mntsvc *msvc,
                               const struct voluta_mntparams *mntp)
{
	int err;
	const uint64_t mnt_allow = MNT_DETACH | MNT_FORCE;
	const struct ucred *peer_cred = &msvc->ms_peer_ucred;
	const char *path = mntp->path;

	unused(msvc);
	if (!strlen(path)) {
		return -EPERM;
	}
	if (mntp->flags & ~mnt_allow) {
		return -EINVAL;
	}
	if ((mntp->flags | mnt_allow) != mnt_allow) {
		return -EINVAL;
	}
	/* TODO: for MNT_FORCE, require valid uig/gid */
	err = check_umount_path(path, peer_cred->uid);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_do_umount(struct voluta_mntsvc *msvc,
                            const struct voluta_mntparams *mntp)
{
	int err;

	err = do_fuse_umount(mntp);
	log_info("umount: '%s' flags=0x%lx err=%d",
	         mntp->path, mntp->flags, err);

	unused(msvc);
	return err;
}

static int mntsvc_exec_umount(struct voluta_mntsvc *msvc,
                              const struct voluta_mntparams *mntp)
{
	int err;

	err = mntsvc_check_umount(msvc, mntp);
	if (err && (err != -ENOTCONN)) {
		return err;
	}
	err = mntsvc_do_umount(msvc, mntp);
	if (err) {
		return err;
	}
	return 0;
}

static int mntsvc_exec_handshake(struct voluta_mntsvc *msvc,
                                 const struct voluta_mntparams *mntp)
{
	/* TODO: check params */
	unused(msvc);
	unused(mntp);

	return 0;
}

static void mntsvc_exec_request(struct voluta_mntsvc *msvc,
                                struct voluta_mntmsg *mmsg)
{
	int err = 0;
	struct voluta_mntparams mntp;
	const enum voluta_mntcmd cmd = mntmsg_cmd(mmsg);

	mntmsg_to_params(mmsg, &mntp);

	log_info("exec-request: cmd=%d", cmd);
	switch (cmd) {
	case VOLUTA_MNTCMD_HANDSHAKE:
		err = mntsvc_exec_handshake(msvc, &mntp);
		break;
	case VOLUTA_MNTCMD_MOUNT:
		err = mntsvc_exec_mount(msvc, &mntp);
		break;
	case VOLUTA_MNTCMD_UMOUNT:
		err = mntsvc_exec_umount(msvc, &mntp);
		break;
	case VOLUTA_MNTCMD_NONE:
	default:
		err = -EOPNOTSUPP;
		break;
	}
	mntmsg_set_status(mmsg, err);
}

static void mntsvc_fill_response(const struct voluta_mntsvc *msvc,
                                 struct voluta_mntmsg *mmsg)
{
	const int status = mntmsg_status(mmsg);
	const enum voluta_mntcmd cmd = mntmsg_cmd(mmsg);

	mntmsg_init(mmsg, cmd);
	mntmsg_set_status(mmsg, status);
	unused(msvc);
}

static void mntsvc_send_response(struct voluta_mntsvc *msvc,
                                 const struct voluta_mntmsg *mmsg)
{
	int err;

	err = mntmsg_send(mmsg, &msvc->ms_asock, msvc->ms_fuse_fd);
	if (err) {
		log_err("failed to send response: cmd=%d err=%d",
		        (int)mmsg->mn_cmd, err);
	}
}

static void mntsvc_serve_request(struct voluta_mntsvc *msvc)
{
	int err;
	struct voluta_mntmsg mmsg;

	mntmsg_reset(&mmsg);
	err = mntsvc_recv_request(msvc, &mmsg);
	if (!err) {
		mntsvc_exec_request(msvc, &mmsg);
		mntsvc_fill_response(msvc, &mmsg);
		mntsvc_send_response(msvc, &mmsg);
		mntsvc_term_peer(msvc);
		mntsvc_close_fd(msvc);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void mntsrv_init(struct voluta_mntsrv *msrv)
{
	voluta_streamsock_initu(&msrv->ms_lsock);
	mntsvc_init(&msrv->ms_svc);
	msrv->ms_rules = NULL;
}

static void mntsrv_fini_sock(struct voluta_mntsrv *msrv)
{
	voluta_socket_shutdown_rdwr(&msrv->ms_lsock);
	voluta_socket_fini(&msrv->ms_lsock);
}

static void mntsrv_fini(struct voluta_mntsrv *msrv)
{
	mntsrv_fini_sock(msrv);
	mntsvc_fini(&msrv->ms_svc);
	msrv->ms_rules = NULL;
}

static int mntsrv_setrules(struct voluta_mntsrv *msrv,
                           const struct voluta_mntrules *mrules)
{
	msrv->ms_rules = mrules;
	/* TODO: check rules validity */
	return 0;
}

static int mntsrv_open(struct voluta_mntsrv *msrv)
{
	int err;
	struct voluta_socket *sock = &msrv->ms_lsock;

	err = voluta_socket_open(sock);
	if (err) {
		return err;
	}
	err = voluta_socket_setkeepalive(sock);
	if (err) {
		return err;
	}
	err = voluta_socket_setnonblock(sock);
	if (err) {
		return err;
	}
	return 0;
}

static void mntsrv_close(struct voluta_mntsrv *msrv)
{
	voluta_socket_close(&msrv->ms_lsock);
}

static int mntsrv_bind(struct voluta_mntsrv *msrv)
{
	int err;
	struct voluta_sockaddr saddr;
	struct voluta_socket *sock = &msrv->ms_lsock;
	const char *sock_name = VOLUTA_MNTSOCK_NAME;

	voluta_sockaddr_abstract(&saddr, sock_name);
	err = voluta_socket_bind(sock, &saddr);
	if (err) {
		return err;
	}
	log_info("bind-socket: @%s", sock_name);
	return 0;
}

static int mntsrv_wait_incoming(struct voluta_mntsrv *msrv)
{
	struct timespec ts = { .tv_sec = 1 };

	return voluta_socket_rselect(&msrv->ms_lsock, &ts);
}

static int mntsrv_listen(struct voluta_mntsrv *msrv)
{
	return voluta_socket_listen(&msrv->ms_lsock, 1);
}

static int mntsrv_wait_conn(struct voluta_mntsrv *msrv, long sec_wait)
{
	int err;
	const struct timespec ts = {
		.tv_sec = sec_wait,
		.tv_nsec = 0
	};

	err = voluta_socket_rselect(&msrv->ms_lsock, &ts);
	if (err) {
		return err;
	}
	mntsvc_init(&msrv->ms_svc);
	return 0;
}

static int mntsrv_accept_conn(struct voluta_mntsrv *msrv)
{
	int err;
	struct voluta_mntsvc *msvc = &msrv->ms_svc;

	err = mntsvc_accept_from(msvc, &msrv->ms_lsock);
	if (err) {
		return err;
	}
	msvc->ms_srv = msrv;
	return 0;
}

static void mntsrv_fini_conn(struct voluta_mntsrv *msrv)
{
	mntsvc_fini(&msrv->ms_svc);
}

static int mntsrv_serve_conn(struct voluta_mntsrv *msrv)
{
	int err;

	err = mntsrv_accept_conn(msrv);
	if (!err) {
		mntsvc_serve_request(&msrv->ms_svc);
	}
	mntsrv_fini_conn(msrv);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int mse_init(struct voluta_ms_env *mse)
{
	mntsrv_init(mse->srv);
	mse->active = 0;
	mse->signum = 0;
	return 0;
}

static void mse_fini(struct voluta_ms_env *mse)
{
	mntsrv_fini(mse->srv);
	mse->active = 0;
}

int voluta_mse_new(struct voluta_ms_env **out_mse)
{
	int err;
	void *mem = NULL;
	struct voluta_ms_env *mse = NULL;
	struct voluta_ms_env_obj *mse_obj = NULL;

	err = voluta_zmalloc(sizeof(*mse_obj), &mem);
	if (err) {
		return err;
	}
	mse_obj = mem;
	mse = &mse_obj->ms_env;
	mse->srv = &mse_obj->ms_srv;

	err = mse_init(mse);
	if (err) {
		mse_fini(mse);
		free(mem);
		return err;
	}
	*out_mse = mse;
	voluta_burnstack();
	return 0;
}

static struct voluta_ms_env_obj *mse_obj_of(struct voluta_ms_env *mse)
{
	return container_of(mse, struct voluta_ms_env_obj, ms_env);
}

void voluta_mse_del(struct voluta_ms_env *mse)
{
	struct voluta_ms_env_obj *mse_obj = mse_obj_of(mse);

	mse_fini(mse);
	voluta_zfree(mse_obj, sizeof(*mse_obj));
	voluta_burnstack();
}

static int voluta_mse_open(struct voluta_ms_env *mse,
                           const struct voluta_mntrules *mrules)
{
	int err;
	struct voluta_mntsrv *msrv = mse->srv;

	err = mntsrv_setrules(msrv, mrules);
	if (err) {
		return err;
	}
	err = mntsrv_open(msrv);
	if (err) {
		mntsrv_fini_sock(msrv);
		return err;
	}
	err = mntsrv_bind(msrv);
	if (err) {
		mntsrv_fini_sock(msrv);
		return err;
	}
	return 0;
}

static int voluta_mse_exec_one(struct voluta_ms_env *mse)
{
	int err;
	struct voluta_mntsrv *msrv = mse->srv;

	err = mntsrv_wait_incoming(msrv);
	if (err) {
		return err;
	}
	err = mntsrv_listen(msrv);
	if (err) {
		return err;
	}
	err = mntsrv_wait_conn(msrv, 10);
	if (err) {
		return err;
	}
	err = mntsrv_serve_conn(msrv);
	if (err) {
		return err;
	}
	return 0;
}

static int voluta_mse_exec(struct voluta_ms_env *mse)
{
	int err;

	mse->active = 1;
	while (mse->active) {
		err = voluta_mse_exec_one(mse);
		voluta_burnstack();

		if (err == -ETIMEDOUT) {
			sleep(1);
		}
		/* TODO: handle non-valid terminating errors */
		usleep(1000);
	}
	return 0;
}

static void voluta_mse_close(struct voluta_ms_env *mse)
{
	struct voluta_mntsrv *msrv = mse->srv;

	mntsrv_close(msrv);
	mntsrv_fini(msrv);
}

int voluta_mse_serve(struct voluta_ms_env *mse,
                     const struct voluta_mntrules *mrules)
{
	int err = 0;

	err = voluta_mse_open(mse, mrules);
	if (!err) {
		err = voluta_mse_exec(mse);
		voluta_mse_close(mse);
	}
	return err;
}

void voluta_mse_halt(struct voluta_ms_env *mse, int signum)
{
	mse->signum = signum;
	mse->active = 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void mntclnt_init(struct voluta_mntclnt *mclnt)
{
	voluta_streamsock_initu(&mclnt->mc_sock);
	voluta_sockaddr_abstract(&mclnt->mc_srvaddr, VOLUTA_MNTSOCK_NAME);
}

static void mntclnt_fini(struct voluta_mntclnt *mclnt)
{
	voluta_socket_fini(&mclnt->mc_sock);
	voluta_memzero(mclnt, sizeof(*mclnt));
}

static int mntclnt_connect(struct voluta_mntclnt *mclnt)
{
	int err;
	struct voluta_socket *sock = &mclnt->mc_sock;

	err = voluta_socket_open(sock);
	if (err) {
		return err;
	}
	err = voluta_socket_connect(sock, &mclnt->mc_srvaddr);
	if (err) {
		voluta_socket_fini(sock);
		return err;
	}
	return 0;
}

static int mntclnt_disconnect(struct voluta_mntclnt *mclnt)
{
	int err;

	err = voluta_socket_shutdown_rdwr(&mclnt->mc_sock);
	return err;
}

static int mntclnt_handshake(const struct voluta_mntclnt *mclnt,
                             const struct voluta_mntparams *mntp,
                             int *out_status)
{
	int err;
	struct voluta_mntmsg mmsg;
	const struct voluta_socket *sock = &mclnt->mc_sock;

	*out_status = -ECOMM;

	err = mntmsg_handshake(&mmsg, mntp);
	if (err) {
		return err;
	}
	err = mntmsg_send(&mmsg, sock, -1);
	if (err) {
		return err;
	}
	err = mntmsg_recv2(&mmsg, sock);
	if (err) {
		return err;
	}
	err = mntmsg_check(&mmsg);
	if (err) {
		return err;
	}
	*out_status = mntmsg_status(&mmsg);
	return 0;
}

static int mntclnt_mount(const struct voluta_mntclnt *mclnt,
                         const struct voluta_mntparams *mntp,
                         int *out_status, int *out_fd)
{
	int err;
	struct voluta_mntmsg mmsg;
	const struct voluta_socket *sock = &mclnt->mc_sock;

	*out_status = -ECOMM;
	*out_fd = -1;

	err = mntmsg_mount(&mmsg, mntp);
	if (err) {
		return err;
	}
	err = mntmsg_send(&mmsg, sock, -1);
	if (err) {
		return err;
	}
	err = mntmsg_recv(&mmsg, sock, out_fd);
	if (err) {
		return err;
	}
	err = mntmsg_check(&mmsg);
	if (err) {
		return err;
	}
	*out_status = mntmsg_status(&mmsg);
	return 0;
}

static int mntclnt_umount(const struct voluta_mntclnt *mclnt,
                          const struct voluta_mntparams *mntp, int *out_status)
{
	int err;
	struct voluta_mntmsg mmsg;
	const struct voluta_socket *sock = &mclnt->mc_sock;

	*out_status = -ECOMM;

	err = mntmsg_umount(&mmsg, mntp);
	if (err) {
		return err;
	}
	err = mntmsg_send(&mmsg, sock, -1);
	if (err) {
		return err;
	}
	err = mntmsg_recv2(&mmsg, sock);
	if (err) {
		return err;
	}
	err = mntmsg_check(&mmsg);
	if (err) {
		return err;
	}
	*out_status = mntmsg_status(&mmsg);
	return 0;
}

static int do_rpc_mount(struct voluta_mntclnt *mclnt,
                        const struct voluta_mntparams *mntp, int *out_fd)
{
	int err;
	int status = -1;

	err = mntclnt_connect(mclnt);
	if (err) {
		return err;
	}
	err = mntclnt_mount(mclnt, mntp, &status, out_fd);
	if (err) {
		return err;
	}
	err = mntclnt_disconnect(mclnt);
	if (err) {
		return err;
	}
	return status;
}

int voluta_rpc_mount(const char *mountpoint, uid_t uid, gid_t gid,
                     size_t max_read, unsigned long ms_flags,
                     bool allow_other, int *out_fd)
{
	int err;
	struct voluta_mntclnt mclnt;
	struct voluta_mntparams mntp = {
		.path = mountpoint,
		.flags = ms_flags,
		.root_mode = S_IFDIR | S_IRWXU,
		.user_id = uid,
		.group_id = gid,
		.max_read = max_read,
		.allowother = allow_other
	};

	*out_fd = -1;
	mntclnt_init(&mclnt);
	err = do_rpc_mount(&mclnt, &mntp, out_fd);
	mntclnt_fini(&mclnt);

	if (err) {
		close_fd(out_fd);
	}
	return err;
}

static int do_rpc_umount(struct voluta_mntclnt *mclnt,
                         const struct voluta_mntparams *mntp)
{
	int err;
	int status = -1;

	err = mntclnt_connect(mclnt);
	if (err) {
		return err;
	}
	err = mntclnt_umount(mclnt, mntp, &status);
	if (err) {
		return err;
	}
	err = mntclnt_disconnect(mclnt);
	if (err) {
		return err;
	}
	return status;
}

int voluta_rpc_umount(const char *mountpoint,
                      uid_t uid, gid_t gid, int mnt_flags)
{
	int err;
	struct voluta_mntclnt mclnt;
	struct voluta_mntparams mntp = {
		.path = mountpoint,
		.flags = (uint64_t)mnt_flags,
		.user_id = uid,
		.group_id = gid,
	};

	mntclnt_init(&mclnt);
	err = do_rpc_umount(&mclnt, &mntp);
	mntclnt_fini(&mclnt);

	return err;
}

static int do_rpc_handshake(struct voluta_mntclnt *mclnt,
                            const struct voluta_mntparams *mntp)
{
	int err;
	int status = -1;

	err = mntclnt_connect(mclnt);
	if (err) {
		return err;
	}
	err = mntclnt_handshake(mclnt, mntp, &status);
	if (err) {
		return err;
	}
	err = mntclnt_disconnect(mclnt);
	if (err) {
		return err;
	}
	return status;
}

int voluta_rpc_handshake(uid_t uid, gid_t gid)
{
	int err;
	struct voluta_mntclnt mclnt;
	struct voluta_mntparams mntp = {
		.user_id = uid,
		.group_id = gid,
	};

	mntclnt_init(&mclnt);
	err = do_rpc_handshake(&mclnt, &mntp);
	mntclnt_fini(&mclnt);

	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool voluta_is_fuse_fstype(long fstype)
{
	return (fstype == FUSE_SUPER_MAGIC);
}

