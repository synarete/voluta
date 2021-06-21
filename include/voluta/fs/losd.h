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
#ifndef VOLUTA_LOSD_H_
#define VOLUTA_LOSD_H_

#include <stdlib.h>

struct voluta_losd;
struct voluta_qalloc;
struct voluta_baddr;
struct voluta_bref_info;
struct voluta_fiovec;
struct voluta_cache;

int voluta_losd_init(struct voluta_losd *losd,
                     struct voluta_alloc_if *alif);

void voluta_losd_fini(struct voluta_losd *losd);

int voluta_losd_open(struct voluta_losd *losd, const char *path);

int voluta_losd_close(struct voluta_losd *losd);

int voluta_losd_format(struct voluta_losd *losd);

int voluta_losd_sync(struct voluta_losd *losd);


int voluta_losd_create(struct voluta_losd *losd,
                       const struct voluta_blobid *bid);

int voluta_losd_store(struct voluta_losd *losd,
                      const struct voluta_baddr *baddr, const void *bobj);

int voluta_losd_storev(struct voluta_losd *losd,
                       const struct voluta_baddr *baddr,
                       const struct iovec *iov, size_t cnt);

int voluta_losd_load(struct voluta_losd *losd,
                     const struct voluta_baddr *baddr, void *bobj);

int voluta_losd_resolve(struct voluta_losd *losd,
                        const struct voluta_baddr *baddr,
                        loff_t off_within, size_t len,
                        struct voluta_fiovec *out_fiov);

int voluta_flush_dirty_vnodes(const struct voluta_cache *cache,
                              struct voluta_losd *losd, long ds_key);

int voluta_resolve_sb_path(const char *id, struct voluta_namebuf *out_nb);

#endif /* VOLUTA_LOSD_H_ */
