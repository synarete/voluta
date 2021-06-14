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
#ifndef VOLUTA_OSDC_H_
#define VOLUTA_OSDC_H_

#include <stdlib.h>

struct voluta_osdctl;
struct voluta_qalloc;
struct voluta_baddr;
struct voluta_bref_info;
struct voluta_fiovec;
struct voluta_cache;

int voluta_osdc_init(struct voluta_osdctl *osdc,
                     struct voluta_alloc_if *alif);

void voluta_osdc_fini(struct voluta_osdctl *osdc);

int voluta_osdc_open(struct voluta_osdctl *osdc, const char *path);

int voluta_osdc_close(struct voluta_osdctl *osdc);

int voluta_osdc_format(struct voluta_osdctl *osdc);

int voluta_osdc_sync(struct voluta_osdctl *osdc);


int voluta_osdc_create(struct voluta_osdctl *osdc,
                       const struct voluta_blobid *bid);

int voluta_osdc_store(struct voluta_osdctl *osdc,
                      const struct voluta_baddr *baddr, const void *bobj);

int voluta_osdc_storev(struct voluta_osdctl *osdc,
                       const struct voluta_baddr *baddr,
                       const struct iovec *iov, size_t cnt);

int voluta_osdc_load(struct voluta_osdctl *osdc,
                     const struct voluta_baddr *baddr, void *bobj);

int voluta_osdc_resolve(struct voluta_osdctl *osdc,
                        const struct voluta_baddr *baddr,
                        loff_t off_within, size_t len,
                        struct voluta_fiovec *out_fiov);

int voluta_flush_dirty_vnodes(const struct voluta_cache *cache,
                              struct voluta_osdctl *osdc, long ds_key);

int voluta_require_objstore_path(const char *path);

#endif /* VOLUTA_OSDC_H_ */