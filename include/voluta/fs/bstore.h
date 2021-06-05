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
#ifndef VOLUTA_BSTORE_H_
#define VOLUTA_BSTORE_H_

#include <stdlib.h>

struct voluta_bstore;
struct voluta_qalloc;
struct voluta_baddr;
struct voluta_bref_info;
struct voluta_fiovec;

int voluta_bstore_init(struct voluta_bstore *bstore,
                       struct voluta_qalloc *qalloc);

void voluta_bstore_fini(struct voluta_bstore *bstore);

int voluta_bstore_open(struct voluta_bstore *bstore, const char *path);

int voluta_bstore_close(struct voluta_bstore *bstore);

int voluta_bstore_format(struct voluta_bstore *bstore);


int voluta_bstore_create_blob(struct voluta_bstore *bstore,
                              const struct voluta_blobid *bid);

int voluta_bstore_store_bobj(struct voluta_bstore *bstore,
                             const struct voluta_baddr *baddr,
                             const void *bobj);

int voluta_bstore_storev_bobj(struct voluta_bstore *bstore,
                              const struct voluta_baddr *baddr,
                              const struct iovec *iov, size_t cnt);

int voluta_bstore_load_bobj(struct voluta_bstore *bstore,
                            const struct voluta_baddr *baddr, void *bobj);

#endif /* VOLUTA_BSTORE_H_ */
