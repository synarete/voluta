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
#ifndef VOLUTA_QALLOC_H_
#define VOLUTA_QALLOC_H_

/* quick memory allocator */
struct voluta_qastat {
	size_t memsz_data;
	size_t memsz_meta;
	size_t npages;
	size_t npages_used;
	size_t nbytes_used;
};

struct voluta_xiovec {
	void  *base;
	size_t len;
	loff_t off;
	int    fd;
	void  *cookie;
};

struct voluta_slab {
	struct voluta_list_head free_list;
	size_t sindex;
	size_t elemsz;
	size_t nfree;
	size_t nused;
};

struct voluta_qalloc {
	int mode;
	int memfd_indx;
	int memfd_data;
	int memfd_meta;
	void *mem_data;
	void *mem_meta;
	struct voluta_qastat st;
	struct voluta_list_head free_list;
	struct voluta_slab slabs[8];
} voluta_aligned64;


int voluta_resolve_memsize(size_t mem_want, size_t *out_mem_size);

int voluta_qalloc_init(struct voluta_qalloc *qal, size_t memsize);

int voluta_qalloc_init2(struct voluta_qalloc *qal, size_t memwant);

int voluta_qalloc_fini(struct voluta_qalloc *qal);

void *voluta_qalloc_malloc(struct voluta_qalloc *qal, size_t nbytes);

void *voluta_qalloc_zmalloc(struct voluta_qalloc *qal, size_t nbytes);

void voluta_qalloc_free(struct voluta_qalloc *qal, void *ptr, size_t nbytes);

void voluta_qalloc_zfree(struct voluta_qalloc *qal, void *ptr, size_t nbytes);

void voluta_qalloc_stat(const struct voluta_qalloc *qal,
                        struct voluta_qastat *qast);

int voluta_qalloc_xiovec(const struct voluta_qalloc *qal, void *ptr,
                         size_t len, struct voluta_xiovec *xiov);

int voluta_qalloc_mcheck(const struct voluta_qalloc *qal,
                         const void *ptr, size_t nbytes);

#endif /* VOLUTA_QALLOC_H_ */
