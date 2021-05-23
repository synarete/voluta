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
#include <voluta/infra/version.h>

#ifdef HAVE_CONFIG_H
#if !defined(VERSION)
#error "missing VERSION in config.h"
#endif
#if !defined(VERSION_MAJOR)
#error "missing VERSION_MAJOR in config.h"
#endif
#if !defined(VERSION_MINOR)
#error "missing VERSION_MINOR in config.h"
#endif
#if !defined(VERSION_SUBLEVEL)
#error "missing VERSION_SUBLEVEL in config.h"
#endif
#if !defined(RELEASE)
#error "missing RELEASE in config.h"
#endif
#if !defined(REVISION)
#error "missing REVISION in config.h"
#endif
#else
#define VERSION         "0"
#define VERSION_MAJOR    0
#define VERSION_MINOR    1
#define VERSION_SUBLEVEL 1
#define RELEASE         "0"
#define REVISION        "xxxxxxx"
#endif

#define VOLUTA_VERSION_STRING    VERSION "-" RELEASE "." REVISION


const struct voluta_version voluta_version = {
	.string = VOLUTA_VERSION_STRING,
	.major = VERSION_MAJOR,
	.minor = VERSION_MINOR,
	.sublevel = VERSION_SUBLEVEL
};

