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
#ifndef VOLUTA_IOCTLS_H_
#define VOLUTA_IOCTLS_H_

#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <voluta/defs.h>


enum voluta_query_type {
	VOLUTA_QUERY_NONE = 0,
	VOLUTA_QUERY_VERSION = 1,
	VOLUTA_QUERY_VOLUME = 2,
	VOLUTA_QUERY_FSINFO = 3,
	VOLUTA_QUERY_INODE = 4,
};

struct voluta_query_version {
	char string[VOLUTA_NAME_MAX + 1];
	uint32_t major;
	uint32_t minor;
	uint32_t sublevel;
};

struct voluta_query_volume {
	uint64_t size;
	char     path[VOLUTA_REPO_PATH_MAX];
};

struct voluta_query_fsinfo {
	int64_t uptime;
	uint64_t msflags;
};

struct voluta_query_inode {
	uint32_t iflags;
	uint32_t dirflags;
};

union voluta_query_u {
	struct voluta_query_version     version;
	struct voluta_query_volume      volume;
	struct voluta_query_fsinfo      fsinfo;
	struct voluta_query_inode       inode;
	uint8_t pad[2040];
};

struct voluta_ioc_query {
	int32_t  qtype;
	uint32_t reserved;
	union voluta_query_u u;
};

enum voluta_tweak_type {
	VOLUTA_TWEAK_NONE = 0,
	VOLUTA_TWEAK_IFLAGS = 1,
	VOLUTA_TWEAK_DIRFLAGS = 2,
};

struct voluta_tweak_flags {
	int32_t  flags;
};

union voluta_tweak_u {
	struct voluta_tweak_flags       iflags;
	struct voluta_tweak_flags       dirflags;
};

struct voluta_ioc_tweak {
	int32_t  ttype;
	uint32_t reserved;
	union voluta_tweak_u u;
};


struct voluta_ioc_clone {
	int32_t  flags;
	uint32_t reserved;
	uint64_t reserved2;
	char     name[VOLUTA_NAME_MAX + 1];
	uint8_t  reserved3[248];
};


#define VOLUTA_FS_IOC_QUERY   _IOWR('V', 1, struct voluta_ioc_query)
#define VOLUTA_FS_IOC_TWEAK   _IOWR('V', 2, struct voluta_ioc_tweak)
#define VOLUTA_FS_IOC_CLONE   _IOWR('V', 3, struct voluta_ioc_clone)

#endif /* VOLUTA_IOCTLS_H_ */
