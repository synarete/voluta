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
#ifndef VOLUTA_MOUNTD_H_
#define VOLUTA_MOUNTD_H_

#include <voluta/infra.h>
#include <voluta/defs.h>
#include <voluta/fs.h>

struct voluta_mntrules *voluta_parse_mntrules(const char *pathname);

void voluta_free_mntrules(struct voluta_mntrules *mnt_conf);

#endif /* VOLUTA_MOUNTD_H_ */
