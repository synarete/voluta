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
#ifndef VOLUTA_SOCKET_H_
#define VOLUTA_SOCKET_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

struct ucred;

/* network & sockets wrappers */
union voluta_sockaddr_u {
	struct sockaddr     sa;
	struct sockaddr_in  sa_in;
	struct sockaddr_in6 sa_in6;
	struct sockaddr_un  sa_un;
	struct sockaddr_storage sas;
};

struct voluta_sockaddr {
	union voluta_sockaddr_u u;
};

struct voluta_socket {
	int     fd;
	short   family;
	short   type;
	short   proto;
	short   pad_[3];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

uint16_t voluta_htons(uint16_t n);

uint32_t voluta_htonl(uint32_t n);

uint16_t voluta_ntohs(uint16_t n);

uint32_t voluta_ntohl(uint32_t n);

void voluta_ucred_self(struct ucred *uc);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_msghdr_setaddr(struct msghdr *mh,
                           const struct voluta_sockaddr *sa);

struct cmsghdr *voluta_cmsg_firsthdr(struct msghdr *mh);

struct cmsghdr *voluta_cmsg_nexthdr(struct msghdr *mh, struct cmsghdr *cmh);

size_t voluta_cmsg_align(size_t length);

size_t voluta_cmsg_space(size_t length);

size_t voluta_cmsg_len(size_t length);

void voluta_cmsg_pack_fd(struct cmsghdr *cmh, int fd);

int voluta_cmsg_unpack_fd(const struct cmsghdr *cmh, int *out_fd);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_check_portnum(int portnum);

int voluta_check_unixsock(const char *upath);

void voluta_sockaddr_none(struct voluta_sockaddr *sa);

void voluta_sockaddr_any(struct voluta_sockaddr *sa);

void voluta_sockaddr_any6(struct voluta_sockaddr *sa);

void voluta_sockaddr_loopback(struct voluta_sockaddr *sa, in_port_t port);

void voluta_sockaddr_setport(struct voluta_sockaddr *sa, in_port_t port);

int voluta_sockaddr_unix(struct voluta_sockaddr *sa, const char *path);

int voluta_sockaddr_abstract(struct voluta_sockaddr *sa, const char *name);

int voluta_sockaddr_pton(struct voluta_sockaddr *sa, const char *str);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_socket_open(struct voluta_socket *sock);

void voluta_socket_close(struct voluta_socket *sock);

void voluta_socket_fini(struct voluta_socket *sock);

int voluta_socket_rselect(const struct voluta_socket *sock,
                          const struct timespec *ts);

int voluta_socket_bind(struct voluta_socket *sock,
                       const struct voluta_sockaddr *sa);

int voluta_socket_listen(const struct voluta_socket *sock, int backlog);

int voluta_socket_accept(const struct voluta_socket *sock,
                         struct voluta_socket *acsock,
                         struct voluta_sockaddr *peer);

int voluta_socket_connect(const struct voluta_socket *sock,
                          const struct voluta_sockaddr *sa);

int voluta_socket_shutdown(const struct voluta_socket *sock, int how);

int voluta_socket_shutdown_rdwr(const struct voluta_socket *sock);

int voluta_socket_setnodelay(const struct voluta_socket *sock);

int voluta_socket_setkeepalive(const struct voluta_socket *sock);

int voluta_socket_setreuseaddr(const struct voluta_socket *sock);

int voluta_socket_setnonblock(const struct voluta_socket *sock);

int voluta_socket_getpeercred(const struct voluta_socket *sock,
                              struct ucred *cred);

int voluta_socket_getsockerror(const struct voluta_socket *sock, int *out_err);


int voluta_socket_send(const struct voluta_socket *sock,
                       const void *buf, size_t len, size_t *out_sent);

int voluta_socket_sendto(const struct voluta_socket *sock, const void *buf,
                         size_t bsz, const struct voluta_sockaddr *dst_sa,
                         size_t *out_sent);

int voluta_socket_sendmsg(const struct voluta_socket *sock,
                          const struct msghdr *msgh, int flags,
                          size_t *out_sent);

int voluta_socket_recv(const struct voluta_socket *sock,
                       void *buf, size_t len, size_t *out_recv);

int voluta_socket_recvfrom(const struct voluta_socket *sock, void *buf,
                           size_t bsz, struct voluta_sockaddr *sa,
                           size_t *out_recv);

int voluta_socket_recvmsg(const struct voluta_socket *sock,
                          struct msghdr *msgh, int flags, size_t *out_recv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_dgramsock_init(struct voluta_socket *sock);

void voluta_dgramsock_init6(struct voluta_socket *sock);

void voluta_dgramsock_initu(struct voluta_socket *sock);


void voluta_streamsock_init(struct voluta_socket *sock);

void voluta_streamsock_init6(struct voluta_socket *sock);

void voluta_streamsock_initu(struct voluta_socket *sock);


#endif /* VOLUTA_SOCKET_H_ */

