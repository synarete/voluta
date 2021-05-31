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
#ifndef VOLUTA_MPOOL_H_
#define VOLUTA_MPOOL_H_

#include <voluta/fs/types.h>

/* pool-based memory-allocator */
struct voluta_mpool {
	struct voluta_qalloc   *mp_qal;
	struct voluta_listq     mp_bq;
	struct voluta_listq     mp_vq;
	struct voluta_listq     mp_iq;
	struct voluta_alloc_if  mp_alif;
};

void voluta_mpool_init(struct voluta_mpool *mpool, struct voluta_qalloc *qal);

void voluta_mpool_fini(struct voluta_mpool *mpool);

#endif /* VOLUTA_MPOOL_H_ */
