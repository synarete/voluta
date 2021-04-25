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
#ifndef VOLUTA_ARCHIVE_H_
#define VOLUTA_ARCHIVE_H_


int voluta_archiver_new(const struct voluta_ar_args *args,
                        struct voluta_archiver **out_arc);

void voluta_archiver_del(struct voluta_archiver *arc);

int voluta_archiver_export(struct voluta_archiver *arc);

int voluta_archiver_import(struct voluta_archiver *arc);


#endif /* VOLUTA_ARCHIVE_H_ */
