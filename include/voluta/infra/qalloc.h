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
#ifndef VOLUTA_QALLOC_H_
#define VOLUTA_QALLOC_H_

struct voluta_fiovec;

/* allocator stats */
struct voluta_alloc_stat {
	size_t page_size;
	size_t memsz_data;
	size_t memsz_meta;
	size_t npages_tota;
	size_t npages_used;
	size_t nbytes_used;
};

/* allocator interface */
struct voluta_alloc_if {
	void *(*malloc_fn)(struct voluta_alloc_if *alif, size_t size);
	void (*free_fn)(struct voluta_alloc_if *alif, void *ptr, size_t size);
	void (*stat_fn)(const struct voluta_alloc_if *alif,
	                struct voluta_alloc_stat *out_stat);
};

/* quick memory allocator */
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
	struct voluta_alloc_stat st;
	struct voluta_list_head free_list;
	struct voluta_slab slabs[8];
	struct voluta_alloc_if alif;
};


/* allocation via interface */
void *voluta_allocate(struct voluta_alloc_if *alif, size_t size);

void voluta_deallocate(struct voluta_alloc_if *alif, void *ptr, size_t size);

void voluta_allocstat(const struct voluta_alloc_if *alif,
                      struct voluta_alloc_stat *out_stat);

/* quick allocator */
int voluta_qalloc_init(struct voluta_qalloc *qal, size_t memsize);

int voluta_qalloc_fini(struct voluta_qalloc *qal);

void *voluta_qalloc_malloc(struct voluta_qalloc *qal, size_t nbytes);

void *voluta_qalloc_zmalloc(struct voluta_qalloc *qal, size_t nbytes);

void voluta_qalloc_free(struct voluta_qalloc *qal, void *ptr, size_t nbytes);

void voluta_qalloc_zfree(struct voluta_qalloc *qal, void *ptr, size_t nbytes);

void voluta_qalloc_stat(const struct voluta_qalloc *qal,
                        struct voluta_alloc_stat *out_stat);

int voluta_qalloc_fiovec(const struct voluta_qalloc *qal, void *ptr,
                         size_t len, struct voluta_fiovec *fiov);

int voluta_qalloc_mcheck(const struct voluta_qalloc *qal,
                         const void *ptr, size_t nbytes);


/* memory utilities */
void voluta_burnstackn(int n);

void voluta_burnstack(void);

void voluta_memzero(void *s, size_t n);

int voluta_zmalloc(size_t sz, void **out_mem);

void voluta_zfree(void *mem, size_t sz);


#endif /* VOLUTA_QALLOC_H_ */
