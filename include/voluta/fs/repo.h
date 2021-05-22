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
#ifndef VOLUTA_REPO_H_
#define VOLUTA_REPO_H_

#include <stdlib.h>

struct voluta_repo;
struct voluta_qalloc;
struct voluta_baddr;
struct voluta_blob_info;
struct voluta_fiovec;

int voluta_repo_init(struct voluta_repo *repo,
                     struct voluta_qalloc *qalloc);

void voluta_repo_fini(struct voluta_repo *repo);

int voluta_repo_open(struct voluta_repo *repo, const char *path);

int voluta_repo_close(struct voluta_repo *repo);

int voluta_repo_format(struct voluta_repo *repo);

int voluta_repo_create_blob(struct voluta_repo *repo,
                            const struct voluta_baddr *baddr,
                            struct voluta_blob_info **out_bli);

int voluta_repo_fetch_blob(struct voluta_repo *repo,
                           const struct voluta_baddr *baddr,
                           struct voluta_blob_info **out_bli);

void voluta_repo_forget_blob(struct voluta_repo *repo,
                             struct voluta_blob_info *bli);

int voluta_resolve_fiovec_at(const struct voluta_blob_info *bli,
                             loff_t off, size_t len,
                             struct voluta_fiovec *fiov);

#endif /* VOLUTA_REPO_H_ */