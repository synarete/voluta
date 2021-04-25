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
#ifndef VOLUTA_PSTORE_H_
#define VOLUTA_PSTORE_H_

#include <stdlib.h>

int voluta_pstore_init(struct voluta_pstore *pstore);

void voluta_pstore_fini(struct voluta_pstore *pstore);

int voluta_pstore_expand(struct voluta_pstore *pstore, loff_t cap);

int voluta_pstore_create(struct voluta_pstore *pstore,
                         const char *path, loff_t size);

int voluta_pstore_open(struct voluta_pstore *pstore,
                       const char *path, bool rw);

int voluta_pstore_close(struct voluta_pstore *pstore);

int voluta_pstore_check_io(const struct voluta_pstore *pstore,
                           bool rw, loff_t off, size_t len);

int voluta_pstore_read(const struct voluta_pstore *pstore,
                       loff_t off, size_t bsz, void *buf);

int voluta_pstore_write(struct voluta_pstore *pstore,
                        loff_t off, size_t bsz, const void *buf);

int voluta_pstore_writev(struct voluta_pstore *pstore, loff_t off,
                         size_t len, const struct iovec *iov, size_t cnt);

int voluta_pstore_sync(struct voluta_pstore *pstore, bool all);

int voluta_pstore_clone(const struct voluta_pstore *pstore,
                        const struct voluta_str *name);

int voluta_pstore_punch_hole(const struct voluta_pstore *pstore,
                             loff_t off, size_t len);

int voluta_pstore_zero_range(const struct voluta_pstore *pstore,
                             loff_t off, size_t len);

int voluta_calc_vsize(loff_t size_cur, loff_t size_want, loff_t *out_size);



int voluta_resolve_volume_size(const char *path,
                               loff_t size_want, loff_t *out_size);

int voluta_require_volume_path(const char *path, bool rw);

#endif /* VOLUTA_PSTORE_H_ */
