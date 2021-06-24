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
#ifndef VOLUTA_LOCOSD_H_
#define VOLUTA_LOCOSD_H_

#include <stdlib.h>

struct voluta_locosd;
struct voluta_qalloc;
struct voluta_baddr;
struct voluta_bref_info;
struct voluta_fiovec;
struct voluta_cache;

int voluta_locosd_init(struct voluta_locosd *locosd,
                       struct voluta_alloc_if *alif);

void voluta_locosd_fini(struct voluta_locosd *locosd);

int voluta_locosd_open(struct voluta_locosd *locosd, const char *path);

int voluta_locosd_close(struct voluta_locosd *locosd);

int voluta_locosd_format(struct voluta_locosd *locosd);

int voluta_locosd_sync(struct voluta_locosd *locosd);


int voluta_locosd_create(struct voluta_locosd *locosd,
                         const struct voluta_blobid *bid);

int voluta_locosd_store(struct voluta_locosd *locosd,
                        const struct voluta_baddr *baddr, const void *bobj);

int voluta_locosd_storev(struct voluta_locosd *locosd,
                         const struct voluta_baddr *baddr,
                         const struct iovec *iov, size_t cnt);

int voluta_locosd_load(struct voluta_locosd *locosd,
                       const struct voluta_baddr *baddr, void *bobj);

int voluta_locosd_resolve(struct voluta_locosd *locosd,
                          const struct voluta_baddr *baddr,
                          loff_t off_within, size_t len,
                          struct voluta_fiovec *out_fiov);

int voluta_flush_dirty_vnodes(const struct voluta_cache *cache,
                              struct voluta_locosd *locosd, long ds_key);

int voluta_resolve_sb_path(const char *id, struct voluta_namebuf *out_nb);

#endif /* VOLUTA_LOCOSD_H_ */
