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
struct voluta_bref_info;
struct voluta_fiovec;
struct voluta_cache;

int voluta_repo_init(struct voluta_repo *repo,
                     struct voluta_alloc_if *alif);

void voluta_repo_fini(struct voluta_repo *repo);

int voluta_repo_open(struct voluta_repo *repo, const char *path);

int voluta_repo_close(struct voluta_repo *repo);

int voluta_repo_format(struct voluta_repo *repo);

int voluta_repo_sync(struct voluta_repo *repo);


int voluta_repo_create_blob(struct voluta_repo *repo,
                            const struct voluta_blobid *bid);

int voluta_repo_store_bobj(struct voluta_repo *repo,
                           const struct voluta_baddr *baddr,
                           const void *bobj);

int voluta_repo_storev_bobj(struct voluta_repo *repo,
                            const struct voluta_baddr *baddr,
                            const struct iovec *iov, size_t cnt);

int voluta_repo_load_bobj(struct voluta_repo *repo,
                          const struct voluta_baddr *baddr, void *bobj);

int voluta_repo_resolve_bobj(struct voluta_repo *repo,
                             const struct voluta_baddr *baddr,
                             loff_t off_within, size_t len,
                             struct voluta_fiovec *out_fiov);


int voluta_flush_dirty_vnodes(const struct voluta_cache *cache,
                              struct voluta_repo *repo, long ds_key);

int voluta_require_repo_path(const char *path);

#endif /* VOLUTA_REPO_H_ */
