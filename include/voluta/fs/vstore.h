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
#ifndef VOLUTA_VSTORE_H_
#define VOLUTA_VSTORE_H_

#include <voluta/fs/types.h>

int voluta_verify_meta(const struct voluta_vnode_info *vi);

void voluta_stamp_view(struct voluta_view *view,
                       const struct voluta_vaddr *vaddr);

bool voluta_vi_isdata(const struct voluta_vnode_info *vi);

void *voluta_vi_dat_of(const struct voluta_vnode_info *vi);


int voluta_decrypt_vnode(const struct voluta_vnode_info *vi, const void *buf);


int voluta_vstore_init(struct voluta_vstore *vstore,
                       struct voluta_qalloc *qalloc);

void voluta_vstore_fini(struct voluta_vstore *vstore);

void voluta_vstore_add_ctlflags(struct voluta_vstore *vstore,
                                enum voluta_flags flags);

int voluta_vstore_check_size(const struct voluta_vstore *vstore);

int voluta_vstore_open(struct voluta_vstore *vstore,
                       const char *path, bool rw);

int voluta_vstore_close(struct voluta_vstore *vstore);

int voluta_vstore_create(struct voluta_vstore *vstore,
                         const char *path, loff_t size);

int voluta_vstore_expand(struct voluta_vstore *vstore, loff_t cap);

int voluta_vstore_write(struct voluta_vstore *vstore,
                        loff_t off, size_t bsz, const void *buf);

int voluta_vstore_writev(struct voluta_vstore *vstore, loff_t off,
                         size_t len, const struct iovec *iov, size_t cnt);

int voluta_vstore_read(const struct voluta_vstore *vstore,
                       loff_t off, size_t bsz, void *buf);

int voluta_vstore_clone(const struct voluta_vstore *vstore,
                        const struct voluta_str *name);

int voluta_vstore_sync(struct voluta_vstore *vstore);

int voluta_vstore_fiovec(const struct voluta_vstore *vstore,
                         loff_t off, size_t len, struct voluta_fiovec *fiov);

int voluta_vstore_flush(struct voluta_vstore *vstore,
                        const struct voluta_cache *cache, long ds_key);

int voluta_vstore_clear_bk(struct voluta_vstore *vstore, voluta_lba_t lba);


#endif /* VOLUTA_VSTORE_H_ */
