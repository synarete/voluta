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
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <voluta/infra.h>
#include <voluta/core/address.h>
#include <voluta/core/repo.h>
#include <voluta/core/private.h>

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

static size_t baddr_to_name(const struct voluta_baddr *baddr,
                            char *name, size_t nmax)
{
	size_t len = 0;
	unsigned int b;

	for (size_t i = 0; i < ARRAY_SIZE(baddr->bid.oid); ++i) {
		if ((len + 2) > nmax) {
			break;
		}
		b = baddr->bid.oid[i];
		name[len] = voluta_nibble_to_ascii(b >> 4);
		name[len + 1] = voluta_nibble_to_ascii(b & 0xF);
		len += 2;
	}
	return len;
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

static struct voluta_blob_info *bli_unconst(const struct voluta_blob_info *bli)
{
	union {
		const struct voluta_blob_info *p;
		struct voluta_blob_info *q;
	} u = {
		.p = bli
	};
	return u.q;
}

static struct voluta_blob_info *bli_from_lh(const struct voluta_list_head *lh)
{
	const struct voluta_blob_info *bli;

	bli = container_of2(lh, struct voluta_blob_info, bi_htb_lh);
	return bli_unconst(bli);
}

static void bli_init(struct voluta_blob_info *bli,
                     const struct voluta_baddr *baddr, int fd)
{
	baddr_copyto(baddr, &bli->bi_baddr);
	list_head_init(&bli->bi_htb_lh);
	bli->bi_hkey = voluta_baddr_hkey(baddr);
	bli->bi_fd = fd;
}

static void bli_fini(struct voluta_blob_info *bli)
{
	baddr_reset(&bli->bi_baddr);
	list_head_fini(&bli->bi_htb_lh);
	bli->bi_fd = -1;
}

static bool bli_has_baddr(const struct voluta_blob_info *bli,
                          const struct voluta_baddr *baddr)
{
	return voluta_baddr_isequal(&bli->bi_baddr, baddr);
}

static struct voluta_blob_info *
bli_new(struct voluta_qalloc *qal, const struct voluta_baddr *baddr, int fd)
{
	struct voluta_blob_info *bli;

	bli = voluta_qalloc_malloc(qal, sizeof(*bli));
	if (bli != NULL) {
		bli_init(bli, baddr, fd);
	}
	return bli;
}

static void bli_del(struct voluta_blob_info *bli, struct voluta_qalloc *qal)
{
	voluta_assert_lt(bli->bi_fd, 0);

	bli_fini(bli);
	voluta_qalloc_free(qal, bli, sizeof(*bli));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void repo_htbl_init(struct voluta_repo *repo)
{
	list_head_initn(repo->re_htbl, ARRAY_SIZE(repo->re_htbl));
	repo->re_hsize = 0;
}

static size_t repo_htbl_slot_of(const struct voluta_repo *repo,
                                const struct voluta_baddr *baddr)
{
	const uint64_t hkey = voluta_baddr_hkey(baddr);

	return hkey % ARRAY_SIZE(repo->re_htbl);
}

static struct voluta_list_head *
repo_htbl_list_of(const struct voluta_repo *repo,
                  const struct voluta_baddr *baddr)
{
	size_t slot;
	const struct voluta_list_head *lst;

	slot = repo_htbl_slot_of(repo, baddr);
	lst = &repo->re_htbl[slot];
	return unconst(lst);
}

static struct voluta_blob_info *
repo_htbl_lookup(const struct voluta_repo *repo,
                 const struct voluta_baddr *baddr)
{
	const struct voluta_list_head *itr;
	const struct voluta_list_head *lst;
	const struct voluta_blob_info *bli;

	itr = lst = repo_htbl_list_of(repo, baddr);
	while (itr->next != lst) {
		itr = itr->next;
		bli = bli_from_lh(itr);
		if (bli_has_baddr(bli, baddr)) {
			return bli_unconst(bli);
		}
	}
	return NULL;
}

static void repo_htbl_insert(struct voluta_repo *repo,
                             struct voluta_blob_info *bli)
{
	struct voluta_list_head *lst;

	lst = repo_htbl_list_of(repo, &bli->bi_baddr);
	list_push_front(lst, &bli->bi_htb_lh);
	repo->re_hsize++;
}

static void repo_htbl_remove(struct voluta_repo *repo,
                             struct voluta_blob_info *bli)
{
	struct voluta_list_head *lst;

	voluta_assert_gt(repo->re_hsize, 0);

	lst = repo_htbl_list_of(repo, &bli->bi_baddr);
	voluta_assert(!list_isempty(lst));

	list_head_remove(&bli->bi_htb_lh);
	repo->re_hsize--;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_repo_init(struct voluta_repo *repo,
                     struct voluta_qalloc *qalloc)
{
	repo_htbl_init(repo);
	repo->re_dfd = -1;
	repo->re_nsubs = 256;
	repo->re_qalloc = qalloc;
	return 0;
}

void voluta_repo_fini(struct voluta_repo *repo)
{
	voluta_repo_close(repo);
	repo->re_nsubs = 0;
	repo->re_qalloc = NULL;
}

int voluta_repo_open(struct voluta_repo *repo, const char *path)
{
	int err;

	err = voluta_sys_opendir(path, &repo->re_dfd);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_repo_close(struct voluta_repo *repo)
{
	return voluta_sys_closefd(&repo->re_dfd);
}

int voluta_repo_format(struct voluta_repo *repo)
{
	int err;
	struct voluta_namebuf nb;

	for (size_t i = 0; i < repo->re_nsubs; ++i) {
		index_to_namebuf(i, &nb);
		err = voluta_sys_mkdirat(repo->re_dfd, nb.name, 0700);
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
	size_t len = 0;
	voluta_index_t idx;
	const size_t nmax = sizeof(out_nb->name);

	idx = baddr_to_index(baddr, repo->re_nsubs);
	len += index_to_name(idx, out_nb->name, nmax);
	if (len > (nmax / 2)) {
		return -EINVAL;
	}
	out_nb->name[len++] = '/';
	len += baddr_to_name(baddr, out_nb->name + len, nmax - len);
	if (len > (nmax / 2)) {
		return -EINVAL;
	}
	out_nb->name[len] = '\0';
	return 0;
}

static int repo_create_blob_of(const struct voluta_repo *repo,
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
	err = voluta_sys_ftruncate(fd, baddr->size);
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

static int repo_unlink_blob_of(const struct voluta_repo *repo,
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

static int repo_open_blob_of(const struct voluta_repo *repo,
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
	if (st.st_size != baddr->size) {
		log_warn("blob-size mismatch: %s size=%ld st_size=%ld",
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

static int repo_close_blob_of(const struct voluta_repo *repo,
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

static int repo_close_blob(const struct voluta_repo *repo,
                           struct voluta_blob_info *bli)
{
	return repo_close_blob_of(repo, &bli->bi_baddr, &bli->bi_fd);
}

static int repo_new_bli(const struct voluta_repo *repo,
                        const struct voluta_baddr *baddr, int fd,
                        struct voluta_blob_info **out_bli)
{
	*out_bli = bli_new(repo->re_qalloc, baddr, fd);
	return (*out_bli == NULL) ? -ENOMEM : 0;
}

static void repo_del_bli(const struct voluta_repo *repo,
                         struct voluta_blob_info *bli)
{
	bli_del(bli, repo->re_qalloc);
}

int voluta_repo_create_blob(struct voluta_repo *repo,
                            const struct voluta_baddr *baddr,
                            struct voluta_blob_info **out_bli)
{
	int err;
	int fd = -1;

	voluta_assert_gt(baddr->size, 0);

	err = repo_create_blob_of(repo, baddr, &fd);
	if (err) {
		return err;
	}
	err = repo_new_bli(repo, baddr, fd, out_bli);
	if (err) {
		repo_unlink_blob_of(repo, baddr);
		return err;
	}
	repo_htbl_insert(repo, *out_bli);
	return 0;
}

static int repo_open_blob(struct voluta_repo *repo,
                          const struct voluta_baddr *baddr,
                          struct voluta_blob_info **out_bli)
{
	int err;
	int fd = -1;

	err = repo_open_blob_of(repo, baddr, &fd);
	if (err) {
		return err;
	}
	err = repo_new_bli(repo, baddr, fd, out_bli);
	if (err) {
		repo_close_blob_of(repo, baddr, &fd);
		return err;
	}
	repo_htbl_insert(repo, *out_bli);
	return 0;
}

int voluta_repo_fetch_blob(struct voluta_repo *repo,
                           const struct voluta_baddr *baddr,
                           struct voluta_blob_info **out_bli)
{
	int err;
	const struct voluta_blob_info *bli = NULL;

	*out_bli = repo_htbl_lookup(repo, baddr);
	if (bli != NULL) {
		return 0; /* cache hit */
	}
	err = repo_open_blob(repo, baddr, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

void voluta_repo_forget_blob(struct voluta_repo *repo,
                             struct voluta_blob_info *bli)
{
	repo_close_blob(repo, bli);
	repo_htbl_remove(repo, bli);
	repo_del_bli(repo, bli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int bli_check_io_range(const struct voluta_blob_info *bli,
                              loff_t off, size_t len)
{
	const loff_t end = off_end(off, len);
	const struct voluta_baddr *baddr = &bli->bi_baddr;

	return ((off >= 0) && (end <= baddr->size)) ? 0 : -EINVAL;
}

int voluta_resolve_fiovec_at(const struct voluta_blob_info *bli,
                             loff_t off, size_t len,
                             struct voluta_fiovec *fiov)
{
	int err;

	voluta_assert_gt(bli->bi_fd, 0);

	err = bli_check_io_range(bli, off, len);
	if (!err) {
		fiov->fv_off = off;
		fiov->fv_len = len;
		fiov->fv_base = NULL;
		fiov->fv_fd = bli->bi_fd;
	}
	return err;
}

