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
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <voluta/infra.h>
#include <voluta/fs/address.h>
#include <voluta/fs/repo.h>
#include <voluta/fs/private.h>


/* blob cache-entry */
struct voluta_blob_info {
	struct voluta_baddr     b_baddr;
	struct voluta_repo     *b_repo;
	struct voluta_list_head b_htb_lh;
	struct voluta_list_head b_lru_lh;
	unsigned long           b_hkey;
	loff_t                  b_beg;
	int                     b_fd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static loff_t off_start_of(loff_t off, size_t bsize)
{
	return (loff_t)(((size_t)off / bsize) * bsize);
}

static voluta_index_t baddr_to_index(const struct voluta_baddr *baddr,
                                     const voluta_index_t index_max)
{
	uint64_t idx = 0;

	for (size_t i = 0; i < ARRAY_SIZE(baddr->bid.oid); ++i) {
		idx = (idx << 8) | (idx >> 56);
		idx ^= (uint64_t)(baddr->bid.oid[i]);
	}
	return idx % index_max;
}

static size_t index_to_name(voluta_index_t idx, char *name, size_t nmax)
{
	int n;

	n = snprintf(name, nmax, "%02x", (int)idx);
	return (n <= (int)nmax) ? (size_t)n : nmax;
}

static void index_to_namebuf(voluta_index_t idx, struct voluta_namebuf *nb)
{
	size_t len;

	len = index_to_name(idx, nb->name, sizeof(nb->name) - 1);
	nb->name[len] = '\0';
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_blob_info *bi_unconst(const struct voluta_blob_info *bi)
{
	union {
		const struct voluta_blob_info *p;
		struct voluta_blob_info *q;
	} u = {
		.p = bi
	};
	return u.q;
}

static struct voluta_blob_info *
bi_from_htb_lh(const struct voluta_list_head *lh)
{
	const struct voluta_blob_info *bi = NULL;

	if (lh != NULL) {
		bi = container_of2(lh, struct voluta_blob_info, b_htb_lh);
	}
	return bi_unconst(bi);
}

static struct voluta_blob_info *
bi_from_lru_lh(const struct voluta_list_head *lh)
{
	const struct voluta_blob_info *bi = NULL;

	if (lh != NULL) {
		bi = container_of2(lh, struct voluta_blob_info, b_lru_lh);
	}
	return bi_unconst(bi);
}

static void bi_init(struct voluta_blob_info *bi, loff_t off_start,
                    const struct voluta_baddr *baddr, int fd)
{
	baddr_copyto(baddr, &bi->b_baddr);
	list_head_init(&bi->b_htb_lh);
	list_head_init(&bi->b_lru_lh);
	bi->b_hkey = voluta_baddr_hkey(baddr);
	bi->b_fd = fd;
	bi->b_beg = off_start;
}

static void bi_fini(struct voluta_blob_info *bi)
{
	baddr_reset(&bi->b_baddr);
	list_head_fini(&bi->b_htb_lh);
	list_head_fini(&bi->b_lru_lh);
	bi->b_fd = -1;
	bi->b_beg = -1;
}

static bool bi_has_baddr(const struct voluta_blob_info *bi,
                         const struct voluta_baddr *baddr)
{
	return voluta_baddr_isequal(&bi->b_baddr, baddr);
}

static struct voluta_blob_info *
bi_new(struct voluta_qalloc *qal, loff_t off,
       const struct voluta_baddr *baddr, int fd)
{
	struct voluta_blob_info *bi;

	bi = voluta_qalloc_malloc(qal, sizeof(*bi));
	if (bi != NULL) {
		bi_init(bi, off_start_of(off, baddr->size), baddr, fd);
	}
	return bi;
}

static void bi_del(struct voluta_blob_info *bi, struct voluta_qalloc *qal)
{
	voluta_assert_lt(bi->b_fd, 0);

	bi_fini(bi);
	voluta_qalloc_free(qal, bi, sizeof(*bi));
}

static size_t bi_size(const struct voluta_blob_info *bi)
{
	return (size_t)(bi->b_baddr.size);
}

static loff_t bi_end(const struct voluta_blob_info *bi)
{
	return off_end(bi->b_beg, bi_size(bi));
}

static int bi_check_io_range(const struct voluta_blob_info *bi,
                             loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const loff_t beg = bi->b_beg;

	return ((off >= beg) && (end <= bi_end(bi))) ? 0 : -EINVAL;
}

static int bi_resolve_fiovec(const struct voluta_blob_info *bi,
                             loff_t off, size_t len,
                             struct voluta_fiovec *fiov)
{
	int err;

	voluta_assert_gt(bi->b_fd, 0);

	err = bi_check_io_range(bi, off, len);
	if (err) {
		return err;
	}
	fiov->fv_off = off - bi->b_beg;
	fiov->fv_len = len;
	fiov->fv_base = NULL;
	fiov->fv_fd = bi->b_fd;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_htbl_init(struct voluta_repo *repo)
{
	list_head_initn(repo->re_htbl, ARRAY_SIZE(repo->re_htbl));
	repo->re_hsize = 0;
}

static void repo_htbl_fini(struct voluta_repo *repo)
{
	list_head_finin(repo->re_htbl, ARRAY_SIZE(repo->re_htbl));
	repo->re_hsize = 0;
}

static struct voluta_list_head *
repo_htbl_list_by(const struct voluta_repo *repo, const uint64_t hkey)
{
	const size_t slot = hkey % ARRAY_SIZE(repo->re_htbl);
	const struct voluta_list_head *lst = &repo->re_htbl[slot];

	return unconst(lst);
}

static struct voluta_blob_info *
repo_htbl_lookup(const struct voluta_repo *repo,
                 const struct voluta_baddr *baddr)
{
	const struct voluta_blob_info *bi;
	const struct voluta_list_head *itr;
	const struct voluta_list_head *lst;
	const uint64_t hkey = voluta_baddr_hkey(baddr);

	itr = lst = repo_htbl_list_by(repo, hkey);
	while (itr->next != lst) {
		itr = itr->next;
		bi = bi_from_htb_lh(itr);
		if (bi_has_baddr(bi, baddr)) {
			return bi_unconst(bi);
		}
	}
	return NULL;
}

static void repo_htbl_insert(struct voluta_repo *repo,
                             struct voluta_blob_info *bi)
{
	struct voluta_list_head *lst;

	lst = repo_htbl_list_by(repo, bi->b_hkey);
	list_push_front(lst, &bi->b_htb_lh);
}

static void repo_htbl_remove(struct voluta_repo *repo,
                             struct voluta_blob_info *bi)
{
	struct voluta_list_head *lst;

	lst = repo_htbl_list_by(repo, bi->b_hkey);
	voluta_assert(!list_isempty(lst));
	list_head_remove(&bi->b_htb_lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_lru_init(struct voluta_repo *repo)
{
	listq_init(&repo->re_lru);
}

static void repo_lru_fini(struct voluta_repo *repo)
{
	listq_fini(&repo->re_lru);
}

static void repo_lru_insert(struct voluta_repo *repo,
                            struct voluta_blob_info *bi)
{
	listq_push_front(&repo->re_lru, &bi->b_lru_lh);
}

static void repo_lru_remove(struct voluta_repo *repo,
                            struct voluta_blob_info *bi)
{
	voluta_assert_gt(repo->re_lru.sz, 0);
	listq_remove(&repo->re_lru, &bi->b_lru_lh);
}

static struct voluta_blob_info *repo_lru_front(const struct voluta_repo *repo)
{
	struct voluta_list_head *lh;

	lh = listq_front(&repo->re_lru);
	return bi_from_lru_lh(lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_cache_init(struct voluta_repo *repo)
{
	repo_htbl_init(repo);
	repo_lru_init(repo);
}

static void repo_cache_fini(struct voluta_repo *repo)
{
	repo_htbl_fini(repo);
	repo_lru_fini(repo);
}

static void repo_cache_insert(struct voluta_repo *repo,
                              struct voluta_blob_info *bi)
{
	repo_htbl_insert(repo, bi);
	repo_lru_insert(repo, bi);
}

static void repo_cache_remove(struct voluta_repo *repo,
                              struct voluta_blob_info *bi)
{
	repo_lru_remove(repo, bi);
	repo_htbl_remove(repo, bi);
}

static void repo_cache_relru(struct voluta_repo *repo,
                             struct voluta_blob_info *bi)
{
	repo_lru_remove(repo, bi);
	repo_lru_insert(repo, bi);
}

static int repo_cache_lookup(struct voluta_repo *repo,
                             const struct voluta_baddr *baddr,
                             struct voluta_blob_info **out_bi)
{
	*out_bi = repo_htbl_lookup(repo, baddr);
	if (*out_bi == NULL) {
		return -ENOENT;
	}
	repo_cache_relru(repo, *out_bi);
	return 0;
}

static struct voluta_blob_info *
repo_cache_front(const struct voluta_repo *repo)
{
	return repo_lru_front(repo);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_repo_init(struct voluta_repo *repo,
                     struct voluta_qalloc *qalloc)
{
	repo_cache_init(repo);
	repo->re_dfd = -1;
	repo->re_nsubs = 256;
	repo->re_qalloc = qalloc;
	return 0;
}

void voluta_repo_fini(struct voluta_repo *repo)
{
	voluta_repo_close(repo);
	repo_cache_fini(repo);
	repo->re_nsubs = 0;
	repo->re_qalloc = NULL;
}

int voluta_repo_open(struct voluta_repo *repo, const char *path)
{
	int err;

	voluta_assert_lt(repo->re_dfd, 0);
	err = voluta_sys_opendir(path, &repo->re_dfd);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_format_sub(const struct voluta_repo *repo, voluta_index_t idx)
{
	int err;
	struct stat st;
	struct voluta_namebuf nb;
	const int dfd = repo->re_dfd;

	index_to_namebuf(idx, &nb);
	err = voluta_sys_fstatat(dfd, nb.name, &st, 0);
	if (!err) {
		if (!S_ISDIR(st.st_mode)) {
			log_err("exists but not dir: %s", nb.name);
			return -ENOTDIR;
		}
		err = voluta_sys_faccessat(dfd, nb.name, R_OK | X_OK, 0);
		if (err) {
			return err;
		}
	} else {
		err = voluta_sys_mkdirat(dfd, nb.name, 0700);
		if (err) {
			return err;
		}
	}
	return 0;
}

int voluta_repo_format(struct voluta_repo *repo)
{
	int err;

	for (size_t i = 0; i < repo->re_nsubs; ++i) {
		err = repo_format_sub(repo, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int repo_sub_pathname_of(const struct voluta_repo *repo,
                                const struct voluta_baddr *baddr,
                                struct voluta_namebuf *out_nb)
{
	int err;
	size_t len = 0;
	size_t nlen = 0;
	voluta_index_t idx;
	char *nbuf = out_nb->name;
	const size_t nmax = sizeof(out_nb->name);

	idx = baddr_to_index(baddr, repo->re_nsubs);
	len += index_to_name(idx, nbuf, nmax);
	if (len > (nmax / 2)) {
		return -EINVAL;
	}
	nbuf[len++] = '/';
	err = voluta_baddr_to_name(baddr, nbuf + len, nmax - len - 1, &nlen);
	if (err) {
		return err;
	}
	len += nlen;
	nbuf[len] = '\0';
	return 0;
}

static int repo_create_blob(const struct voluta_repo *repo,
                            const struct voluta_baddr *baddr, int *out_fd)
{
	int err;
	int fd = -1;
	int o_flags;
	struct stat st;
	struct voluta_namebuf nb;

	err = repo_sub_pathname_of(repo, baddr, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(repo->re_dfd, nb.name, &st, 0);
	if (err != -ENOENT) {
		log_err("can not create blob: name=%s err=%d", nb.name, err);
		return err;
	}
	o_flags = O_CREAT | O_RDWR | O_TRUNC;
	err = voluta_sys_openat(repo->re_dfd, nb.name, o_flags, 0600, &fd);
	if (err) {
		return err;
	}
	err = voluta_sys_ftruncate(fd, (loff_t)baddr->size);
	if (err) {
		goto out_err;
	}
	*out_fd = fd;
	return 0;
out_err:
	voluta_sys_unlinkat(repo->re_dfd, nb.name, 0);
	voluta_sys_closefd(&fd);
	return err;
}

static int repo_unlink_blob(const struct voluta_repo *repo,
                            const struct voluta_baddr *baddr)
{
	int err;
	struct voluta_namebuf nb;

	err = repo_sub_pathname_of(repo, baddr, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_unlinkat(repo->re_dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

static int repo_remove_blob(const struct voluta_repo *repo,
                            const struct voluta_baddr *baddr, int *pfd)
{
	voluta_sys_closefd(pfd);
	return repo_unlink_blob(repo, baddr);
}

static int repo_open_blob(const struct voluta_repo *repo,
                          const struct voluta_baddr *baddr, int *out_fd)
{
	int err;
	int fd = -1;
	struct stat st;
	struct voluta_namebuf nb;

	err = repo_sub_pathname_of(repo, baddr, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(repo->re_dfd, nb.name, &st, 0);
	if (err) {
		return err;
	}
	if (st.st_size != (loff_t)baddr->size) {
		log_warn("blob-size mismatch: %s size=%lu st_size=%ld",
		         nb.name, baddr->size, st.st_size);
		err = -ENOENT;
		return err;
	}
	err = voluta_sys_openat(repo->re_dfd, nb.name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	*out_fd = fd;
	return 0;
}

static int repo_close_blob(const struct voluta_repo *repo,
                           const struct voluta_baddr *baddr, int *pfd)
{
	int err;
	struct stat st;
	struct voluta_namebuf nb;

	err = repo_sub_pathname_of(repo, baddr, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(repo->re_dfd, nb.name, &st, 0);
	if (err) {
		log_warn("missing blob: name=%s err=%d", nb.name, err);
	}
	return voluta_sys_closefd(pfd);
}

static int repo_close_blob_of(const struct voluta_repo *repo,
                              struct voluta_blob_info *bi)
{
	voluta_assert_gt(bi->b_fd, 0);
	return repo_close_blob(repo, &bi->b_baddr, &bi->b_fd);
}

static int repo_new_bi(struct voluta_repo *repo, loff_t off,
                       const struct voluta_baddr *baddr, int fd,
                       struct voluta_blob_info **out_bi)
{
	*out_bi = bi_new(repo->re_qalloc, off, baddr, fd);

	return (*out_bi == NULL) ? -ENOMEM : 0;
}

static void repo_del_bi(const struct voluta_repo *repo,
                        struct voluta_blob_info *bi)
{
	bi_del(bi, repo->re_qalloc);
}

int voluta_repo_prep_blob(struct voluta_repo *repo, loff_t off,
                          const struct voluta_baddr *baddr)
{
	int err;
	int fd = -1;
	struct voluta_blob_info *bi = NULL;

	voluta_assert_gt(baddr->size, 0);

	err = repo_create_blob(repo, baddr, &fd);
	if (err) {
		return err;
	}
	err = repo_new_bi(repo, off, baddr, fd, &bi);
	if (err) {
		repo_remove_blob(repo, baddr, &fd);
		return err;
	}
	repo_cache_insert(repo, bi);
	return 0;
}

static int repo_open_blob_of(struct voluta_repo *repo, loff_t off,
                             const struct voluta_baddr *baddr,
                             struct voluta_blob_info **out_bi)
{
	int err;
	int fd = -1;

	err = repo_open_blob(repo, baddr, &fd);
	if (err) {
		return err;
	}
	err = repo_new_bi(repo, off, baddr, fd, out_bi);
	if (err) {
		repo_close_blob(repo, baddr, &fd);
		return err;
	}
	return 0;
}

static int repo_stage_blob(struct voluta_repo *repo, loff_t off,
                           const struct voluta_baddr *baddr,
                           struct voluta_blob_info **out_bi)
{
	int err;

	err = repo_cache_lookup(repo, baddr, out_bi);
	if (!err) {
		return 0; /* cache hit */
	}
	err = repo_open_blob_of(repo, off, baddr, out_bi);
	if (err) {
		return err;
	}
	repo_cache_insert(repo, *out_bi);
	return 0;
}

static void repo_forget_blob(struct voluta_repo *repo,
                             struct voluta_blob_info *bi)
{
	repo_close_blob_of(repo, bi);
	repo_cache_remove(repo, bi);
	repo_del_bi(repo, bi);
}

static void repo_forget_all(struct voluta_repo *repo)
{
	struct voluta_blob_info *bi;

	bi = repo_cache_front(repo);
	while (bi != NULL) {
		repo_forget_blob(repo, bi);
		bi = repo_cache_front(repo);
	}
}

int voluta_repo_close(struct voluta_repo *repo)
{
	repo_forget_all(repo);
	return voluta_sys_closefd(&repo->re_dfd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_repo_stage_blob(struct voluta_repo *repo, loff_t off,
                           const struct voluta_baddr *baddr)
{
	struct voluta_blob_info *bi = NULL;

	return repo_stage_blob(repo, off, baddr, &bi);
}

int voluta_repo_save_blob(struct voluta_repo *repo,
                          const struct voluta_baddr *baddr,
                          const void *blob, loff_t off, size_t len)
{
	int err;
	struct voluta_blob_info *bi = NULL;
	struct voluta_fiovec fiov = { .fv_off = -1 };

	err = repo_stage_blob(repo, off, baddr, &bi);
	if (err) {
		return err;
	}
	err = bi_resolve_fiovec(bi, off, len, &fiov);
	if (err) {
		return err;
	}
	err = voluta_sys_pwriten(fiov.fv_fd, blob, fiov.fv_len, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_repo_load_blob(struct voluta_repo *repo,
                          const struct voluta_baddr *baddr,
                          void *blob, loff_t off, size_t len)
{
	int err;
	struct voluta_blob_info *bi = NULL;
	struct voluta_fiovec fiov = { .fv_off = -1 };

	err = repo_stage_blob(repo, off, baddr, &bi);
	if (err) {
		return err;
	}
	err = bi_resolve_fiovec(bi, off, len, &fiov);
	if (err) {
		return err;
	}
	err = voluta_sys_preadn(fiov.fv_fd, blob, fiov.fv_len, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}


