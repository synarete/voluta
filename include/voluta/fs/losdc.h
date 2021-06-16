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
#ifndef VOLUTA_LOSDC_H_
#define VOLUTA_LOSDC_H_

#include <stdlib.h>

struct voluta_losdctl;
struct voluta_qalloc;
struct voluta_baddr;
struct voluta_bref_info;
struct voluta_fiovec;
struct voluta_cache;

int voluta_losdc_init(struct voluta_losdctl *losdc,
                      struct voluta_alloc_if *alif);

void voluta_losdc_fini(struct voluta_losdctl *losdc);

int voluta_losdc_open(struct voluta_losdctl *losdc, const char *path);

int voluta_losdc_close(struct voluta_losdctl *losdc);

int voluta_losdc_format(struct voluta_losdctl *losdc);

int voluta_losdc_sync(struct voluta_losdctl *losdc);


int voluta_losdc_create(struct voluta_losdctl *losdc,
                        const struct voluta_blobid *bid);

int voluta_losdc_store(struct voluta_losdctl *losdc,
                       const struct voluta_baddr *baddr, const void *bobj);

int voluta_losdc_storev(struct voluta_losdctl *losdc,
                        const struct voluta_baddr *baddr,
                        const struct iovec *iov, size_t cnt);

int voluta_losdc_load(struct voluta_losdctl *losdc,
                      const struct voluta_baddr *baddr, void *bobj);

int voluta_losdc_resolve(struct voluta_losdctl *losdc,
                         const struct voluta_baddr *baddr,
                         loff_t off_within, size_t len,
                         struct voluta_fiovec *out_fiov);

int voluta_flush_dirty_vnodes(const struct voluta_cache *cache,
                              struct voluta_losdctl *losdc, long ds_key);

#endif /* VOLUTA_LOSDC_H_ */
