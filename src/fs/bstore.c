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
#include <voluta/fs/bstore.h>
#include <voluta/fs/private.h>


/* blob-reference cache-entry */
struct voluta_bref_info {
	struct voluta_blobid    bid;
	struct voluta_list_head b_htb_lh;
	struct voluta_list_head b_lru_lh;
	unsigned long           b_hkey;
	int                     b_refcnt;
	int                     b_fd;
};

typedef bool (*voluta_bri_pred_fn)(const struct voluta_bref_info *);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
static voluta_index_t blobid_to_index(const struct voluta_blobid *bid,
                                      const voluta_index_t index_max)
{
	uint64_t idx = 0;

	for (size_t i = 0; i < ARRAY_SIZE(bid->id); ++i) {
		idx = (idx << 8) | (idx >> 56);
		idx ^= (uint64_t)(bid->id[i]);
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

static struct voluta_bref_info *
bri_unconst(const struct voluta_bref_info *bri)
{
	union {
		const struct voluta_bref_info *p;
		struct voluta_bref_info *q;
	} u = {
		.p = bri
	};
	return u.q;
}

static struct voluta_bref_info *
bri_from_htb_lh(const struct voluta_list_head *lh)
{
	const struct voluta_bref_info *bri = NULL;

	if (lh != NULL) {
		bri = container_of2(lh, struct voluta_bref_info, b_htb_lh);
	}
	return bri_unconst(bri);
}

static struct voluta_bref_info *
bri_from_lru_lh(const struct voluta_list_head *lh)
{
	const struct voluta_bref_info *bri = NULL;

	if (lh != NULL) {
		bri = container_of2(lh, struct voluta_bref_info, b_lru_lh);
	}
	return bri_unconst(bri);
}

static void bri_init(struct voluta_bref_info *bri,
                     const struct voluta_blobid *bid, int fd)
{
	blobid_copyto(bid, &bri->bid);
	list_head_init(&bri->b_htb_lh);
	list_head_init(&bri->b_lru_lh);
	bri->b_hkey = voluta_blobid_hkey(bid);
	bri->b_refcnt = 0;
	bri->b_fd = fd;
}

static void bri_fini(struct voluta_bref_info *bri)
{
	list_head_fini(&bri->b_htb_lh);
	list_head_fini(&bri->b_lru_lh);
	bri->b_refcnt = -1;
	bri->b_fd = -1;
}

static bool bri_has_blobid(const struct voluta_bref_info *bri,
                           const struct voluta_blobid *bid)
{
	return blobid_isequal(&bri->bid, bid);
}

static struct voluta_bref_info *
bri_new(struct voluta_qalloc *qal, const struct voluta_blobid *bid, int fd)
{
	struct voluta_bref_info *bri;

	bri = voluta_qalloc_malloc(qal, sizeof(*bri));
	if (bri != NULL) {
		bri_init(bri, bid, fd);
	}
	return bri;
}

static void bri_del(struct voluta_bref_info *bri, struct voluta_qalloc *qal)
{
	voluta_assert_lt(bri->b_fd, 0);

	bri_fini(bri);
	voluta_qalloc_free(qal, bri, sizeof(*bri));
}

static size_t bri_size(const struct voluta_bref_info *bri)
{
	return blobid_size(&bri->bid);
}

static loff_t bri_off_end(const struct voluta_bref_info *bri)
{
	return (loff_t)bri_size(bri);
}

static int bri_check_io_range(const struct voluta_bref_info *bri,
                              loff_t off, size_t len)
{
	loff_t end1;
	loff_t end2;

	if (off < 0) {
		return -EINVAL;
	}
	end1 = off_end(off, len);
	end2 = bri_off_end(bri);

	/*
	 * XXX FIXME
	 *
	 * This logic is true when there are still u-objects which are smaller
	 * then bksec size. Need to be removed.
	 */
	if (end1 >= (end2 + VOLUTA_BKSEC_SIZE)) {
		return -EINVAL;
	}
	return 0;
}

static int bri_resolve_fiovec(const struct voluta_bref_info *bri,
                              loff_t off, size_t len,
                              struct voluta_fiovec *fiov)
{
	int err;

	voluta_assert_gt(bri->b_fd, 0);

	err = bri_check_io_range(bri, off, len);
	if (err) {
		return err;
	}
	fiov->fv_off = off;
	fiov->fv_len = len;
	fiov->fv_base = NULL;
	fiov->fv_fd = bri->b_fd;
	return 0;
}

static bool bri_is_evictable(const struct voluta_bref_info *bri)
{
	voluta_assert_ge(bri->b_refcnt, 0);

	return (bri->b_refcnt == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bstore_htbl_init(struct voluta_bstore *bstore)
{
	list_head_initn(bstore->re_htbl, ARRAY_SIZE(bstore->re_htbl));
	bstore->re_hsize = 0;
}

static void bstore_htbl_fini(struct voluta_bstore *bstore)
{
	list_head_finin(bstore->re_htbl, ARRAY_SIZE(bstore->re_htbl));
	bstore->re_hsize = 0;
}

static struct voluta_list_head *
bstore_htbl_list_by(const struct voluta_bstore *bstore, const uint64_t hkey)
{
	const size_t slot = hkey % ARRAY_SIZE(bstore->re_htbl);
	const struct voluta_list_head *lst = &bstore->re_htbl[slot];

	return unconst(lst);
}

static struct voluta_bref_info *
bstore_htbl_lookup(const struct voluta_bstore *bstore,
                   const struct voluta_blobid *bid)
{
	const struct voluta_bref_info *bri;
	const struct voluta_list_head *itr;
	const struct voluta_list_head *lst;
	const uint64_t hkey = voluta_blobid_hkey(bid);

	itr = lst = bstore_htbl_list_by(bstore, hkey);
	while (itr->next != lst) {
		itr = itr->next;
		bri = bri_from_htb_lh(itr);
		if (bri_has_blobid(bri, bid)) {
			return bri_unconst(bri);
		}
	}
	return NULL;
}

static void bstore_htbl_insert(struct voluta_bstore *bstore,
                               struct voluta_bref_info *bri)
{
	struct voluta_list_head *lst;

	lst = bstore_htbl_list_by(bstore, bri->b_hkey);
	list_push_front(lst, &bri->b_htb_lh);
}

static void bstore_htbl_remove(struct voluta_bstore *bstore,
                               struct voluta_bref_info *bri)
{
	struct voluta_list_head *lst;

	lst = bstore_htbl_list_by(bstore, bri->b_hkey);
	voluta_assert(!list_isempty(lst));
	list_head_remove(&bri->b_htb_lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bstore_lru_init(struct voluta_bstore *bstore)
{
	listq_init(&bstore->re_lru);
}

static void bstore_lru_fini(struct voluta_bstore *bstore)
{
	listq_fini(&bstore->re_lru);
}

static void bstore_lru_insert(struct voluta_bstore *bstore,
                              struct voluta_bref_info *bri)
{
	listq_push_front(&bstore->re_lru, &bri->b_lru_lh);
}

static void bstore_lru_remove(struct voluta_bstore *bstore,
                              struct voluta_bref_info *bri)
{
	voluta_assert_gt(bstore->re_lru.sz, 0);
	listq_remove(&bstore->re_lru, &bri->b_lru_lh);
}

static struct voluta_bref_info *bstore_lru_front(const struct voluta_bstore
                *bstore)
{
	struct voluta_list_head *lh;

	lh = listq_front(&bstore->re_lru);
	return bri_from_lru_lh(lh);
}

static struct voluta_bref_info *
bstore_cahce_rfind(const struct voluta_bstore *bstore, voluta_bri_pred_fn fn)
{
	const struct voluta_bref_info *bi;
	const struct voluta_list_head *lh;
	const struct voluta_listq *lru = &bstore->re_lru;

	lh = listq_back(lru);
	while (lh != &lru->ls) {
		bi = bri_from_lru_lh(lh);
		if (fn(bi)) {
			return bri_unconst(bi);
		}
		lh = lh->prev;
	}
	return NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bstore_cache_init(struct voluta_bstore *bstore)
{
	bstore_htbl_init(bstore);
	bstore_lru_init(bstore);
}

static void bstore_cache_fini(struct voluta_bstore *bstore)
{
	bstore_htbl_fini(bstore);
	bstore_lru_fini(bstore);
}

static void bstore_cache_insert(struct voluta_bstore *bstore,
                                struct voluta_bref_info *bri)
{
	bstore_htbl_insert(bstore, bri);
	bstore_lru_insert(bstore, bri);
}

static void bstore_cache_remove(struct voluta_bstore *bstore,
                                struct voluta_bref_info *bri)
{
	bstore_lru_remove(bstore, bri);
	bstore_htbl_remove(bstore, bri);
}

static void bstore_cache_relru(struct voluta_bstore *bstore,
                               struct voluta_bref_info *bri)
{
	bstore_lru_remove(bstore, bri);
	bstore_lru_insert(bstore, bri);
}

static int bstore_cache_lookup(struct voluta_bstore *bstore,
                               const struct voluta_blobid *bid,
                               struct voluta_bref_info **out_bri)
{
	*out_bri = bstore_htbl_lookup(bstore, bid);
	if (*out_bri == NULL) {
		return -ENOENT;
	}
	bstore_cache_relru(bstore, *out_bri);
	return 0;
}

static struct voluta_bref_info *
bstore_cache_front(const struct voluta_bstore *bstore)
{
	return bstore_lru_front(bstore);
}

static struct voluta_bref_info *
bstore_cache_find_evictable(const struct voluta_bstore *bstore)
{
	return bstore_cahce_rfind(bstore, bri_is_evictable);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_bstore_init(struct voluta_bstore *bstore,
                       struct voluta_qalloc *qalloc)
{
	bstore_cache_init(bstore);
	bstore->re_dfd = -1;
	bstore->re_nsubs = 256;
	bstore->re_qalloc = qalloc;
	return 0;
}

void voluta_bstore_fini(struct voluta_bstore *bstore)
{
	voluta_bstore_close(bstore);
	bstore_cache_fini(bstore);
	bstore->re_nsubs = 0;
	bstore->re_qalloc = NULL;
}

int voluta_bstore_open(struct voluta_bstore *bstore, const char *path)
{
	int err;

	voluta_assert_lt(bstore->re_dfd, 0);
	err = voluta_sys_opendir(path, &bstore->re_dfd);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_format_sub(const struct voluta_bstore *bstore,
                             voluta_index_t idx)
{
	int err;
	struct stat st;
	struct voluta_namebuf nb;
	const int dfd = bstore->re_dfd;

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

int voluta_bstore_format(struct voluta_bstore *bstore)
{
	int err;

	for (size_t i = 0; i < bstore->re_nsubs; ++i) {
		err = bstore_format_sub(bstore, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int bstore_sub_pathname_of(const struct voluta_bstore *bstore,
                                  const struct voluta_blobid *bid,
                                  struct voluta_namebuf *out_nb)
{
	int err;
	size_t len = 0;
	size_t nlen = 0;
	voluta_index_t idx;
	char *nbuf = out_nb->name;
	const size_t nmax = sizeof(out_nb->name);

	idx = blobid_to_index(bid, bstore->re_nsubs);
	len += index_to_name(idx, nbuf, nmax);
	if (len > (nmax / 2)) {
		return -EINVAL;
	}
	nbuf[len++] = '/';
	err = voluta_blobid_to_name(bid, nbuf + len, nmax - len - 1, &nlen);
	if (err) {
		return err;
	}
	len += nlen;
	nbuf[len] = '\0';
	return 0;
}

static ssize_t blob_ssize(const struct voluta_blobid *bid)
{
	return (ssize_t)blobid_size(bid);
}

static int bstore_create_blob(const struct voluta_bstore *bstore,
                              const struct voluta_blobid *bid, int *out_fd)
{
	int err;
	int fd = -1;
	int o_flags;
	ssize_t len;
	struct stat st;
	struct voluta_namebuf nb;

	err = bstore_sub_pathname_of(bstore, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(bstore->re_dfd, nb.name, &st, 0);
	if (err != -ENOENT) {
		log_err("can not create blob: name=%s err=%d", nb.name, err);
		return err;
	}
	o_flags = O_CREAT | O_RDWR | O_TRUNC;
	err = voluta_sys_openat(bstore->re_dfd, nb.name, o_flags, 0600, &fd);
	if (err) {
		return err;
	}
	len = voluta_max64(blob_ssize(bid), VOLUTA_BKSEC_SIZE);
	err = voluta_sys_ftruncate(fd, len);
	if (err) {
		goto out_err;
	}
	*out_fd = fd;
	return 0;
out_err:
	voluta_sys_unlinkat(bstore->re_dfd, nb.name, 0);
	voluta_sys_closefd(&fd);
	return err;
}

static int bstore_unlink_blob(const struct voluta_bstore *bstore,
                              const struct voluta_blobid *bid)
{
	int err;
	struct voluta_namebuf nb;

	err = bstore_sub_pathname_of(bstore, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_unlinkat(bstore->re_dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_remove_blob(const struct voluta_bstore *bstore,
                              const struct voluta_blobid *bid, int *pfd)
{
	voluta_sys_closefd(pfd);
	return bstore_unlink_blob(bstore, bid);
}

static int bstore_open_blob(const struct voluta_bstore *bstore,
                            const struct voluta_blobid *bid, int *out_fd)
{
	int err;
	int fd = -1;
	struct stat st;
	struct voluta_namebuf nb;

	err = bstore_sub_pathname_of(bstore, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(bstore->re_dfd, nb.name, &st, 0);
	if (err) {
		return err;
	}
	if (st.st_size < blob_ssize(bid)) {
		log_warn("blob-size mismatch: %s size=%ld st_size=%ld",
		         nb.name, blob_ssize(bid), st.st_size);
		err = -ENOENT;
		return err;
	}
	err = voluta_sys_openat(bstore->re_dfd, nb.name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	*out_fd = fd;
	return 0;
}

static int bstore_close_blob(const struct voluta_bstore *bstore,
                             const struct voluta_blobid *bid, int *pfd)
{
	int err;
	struct stat st;
	struct voluta_namebuf nb;

	err = bstore_sub_pathname_of(bstore, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(bstore->re_dfd, nb.name, &st, 0);
	if (err) {
		log_warn("missing blob: name=%s err=%d", nb.name, err);
	}
	return voluta_sys_closefd(pfd);
}

static int bstore_close_bref_of(const struct voluta_bstore *bstore,
                                struct voluta_bref_info *bri)
{
	voluta_assert_gt(bri->b_fd, 0);
	voluta_assert_eq(bri->b_refcnt, 0);

	return bstore_close_blob(bstore, &bri->bid, &bri->b_fd);
}

static int bstore_new_bref(struct voluta_bstore *bstore,
                           const struct voluta_blobid *bid, int fd,
                           struct voluta_bref_info **out_bri)
{
	*out_bri = bri_new(bstore->re_qalloc, bid, fd);

	return (*out_bri == NULL) ? -ENOMEM : 0;
}

static void bstore_del_bref(const struct voluta_bstore *bstore,
                            struct voluta_bref_info *bri)
{
	bri_del(bri, bstore->re_qalloc);
}

static void bstore_forget_bref(struct voluta_bstore *bstore,
                               struct voluta_bref_info *bri)
{
	bstore_close_bref_of(bstore, bri);
	bstore_cache_remove(bstore, bri);
	bstore_del_bref(bstore, bri);
}

static void bstore_forget_all(struct voluta_bstore *bstore)
{
	struct voluta_bref_info *bri;

	bri = bstore_cache_front(bstore);
	while (bri != NULL) {
		bstore_forget_bref(bstore, bri);
		bri = bstore_cache_front(bstore);
	}
}

int voluta_bstore_close(struct voluta_bstore *bstore)
{
	bstore_forget_all(bstore);
	return voluta_sys_closefd(&bstore->re_dfd);
}

static int bstore_relax_once(struct voluta_bstore *bstore)
{
	struct voluta_bref_info *bri = NULL;
	const size_t ncached = bstore->re_lru.sz;

	if (!ncached || (ncached < 512)) { /* XXX make upper bound tweak */
		return 0;
	}
	bri = bstore_cache_find_evictable(bstore);
	if (bri == NULL) {
		return -ENOENT;
	}
	bstore_forget_bref(bstore, bri);
	return 0;
}

static int bstore_open_blob_of(struct voluta_bstore *bstore,
                               const struct voluta_blobid *bid,
                               struct voluta_bref_info **out_bri)
{
	int err;
	int fd = -1;

	voluta_assert_ge(bid->size, VOLUTA_BK_SIZE);
	err = bstore_relax_once(bstore);
	if (err) {
		return err;
	}
	err = bstore_open_blob(bstore, bid, &fd);
	if (err) {
		return err;
	}
	err = bstore_new_bref(bstore, bid, fd, out_bri);
	if (err) {
		bstore_close_blob(bstore, bid, &fd);
		return err;
	}
	bstore_cache_insert(bstore, *out_bri);
	return 0;
}

static int bstore_create_blob_of(struct voluta_bstore *bstore,
                                 const struct voluta_blobid *bid,
                                 struct voluta_bref_info **out_bri)
{
	int err;
	int fd = -1;

	err = bstore_relax_once(bstore);
	if (err) {
		return err;
	}
	err = bstore_create_blob(bstore, bid, &fd);
	if (err) {
		return err;
	}
	err = bstore_new_bref(bstore, bid, fd, out_bri);
	if (err) {
		bstore_remove_blob(bstore, bid, &fd);
		return err;
	}
	bstore_cache_insert(bstore, *out_bri);
	return 0;
}

static int bstore_stage_blob(struct voluta_bstore *bstore, bool may_create,
                             const struct voluta_blobid *bid,
                             struct voluta_bref_info **out_bri)
{
	int err;

	voluta_assert_ge(bid->size, VOLUTA_BK_SIZE);

	err = bstore_cache_lookup(bstore, bid, out_bri);
	if (!err) {
		return 0; /* cache hit */
	}
	err = bstore_open_blob_of(bstore, bid, out_bri);
	if (!err) {
		return 0;
	}
	if (err != -ENOENT) {
		return err;
	}
	if (!may_create) {
		return -ENOENT;
	}
	err = bstore_create_blob_of(bstore, bid, out_bri);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_bstore_create_blob(struct voluta_bstore *bstore,
                              const struct voluta_blobid *bid)
{
	struct voluta_bref_info *bri = NULL;

	return bstore_stage_blob(bstore, true, bid, &bri);
}

int voluta_bstore_store_bobj(struct voluta_bstore *bstore,
                             const struct voluta_baddr *baddr,
                             const void *bobj)
{
	int err;
	struct voluta_bref_info *bri = NULL;
	struct voluta_fiovec fiov = { .fv_off = -1 };

	err = bstore_stage_blob(bstore, true, &baddr->bid, &bri);
	if (err) {
		return err;
	}
	err = bri_resolve_fiovec(bri, baddr->off, baddr->len, &fiov);
	if (err) {
		return err;
	}
	err = voluta_sys_pwriten(fiov.fv_fd, bobj, fiov.fv_len, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}

static size_t iovec_length(const struct iovec *iov, size_t cnt)
{
	size_t len = 0;

	for (size_t i = 0; i < cnt; ++i) {
		len += iov[i].iov_len;
	}
	return len;
}

static int check_baddr_iovec(const struct voluta_baddr *baddr,
                             const struct iovec *iov, size_t cnt)
{
	return (iovec_length(iov, cnt) == baddr->len) ? 0 : -EINVAL;
}

int voluta_bstore_storev_bobj(struct voluta_bstore *bstore,
                              const struct voluta_baddr *baddr,
                              const struct iovec *iov, size_t cnt)
{
	int err;
	size_t nwr = 0;
	struct voluta_bref_info *bri = NULL;
	struct voluta_fiovec fiov = { .fv_off = -1 };

	err = check_baddr_iovec(baddr, iov, cnt);
	if (err) {
		return err;
	}
	err = bstore_stage_blob(bstore, true, &baddr->bid, &bri);
	if (err) {
		return err;
	}
	err = bri_resolve_fiovec(bri, baddr->off, baddr->len, &fiov);
	if (err) {
		return err;
	}
	/* TODO: impl voluta_sys_pwritevn (like voluta_sys_pwriten) */
	err = voluta_sys_pwritev(fiov.fv_fd, iov, (int)cnt, fiov.fv_off, &nwr);
	if (err) {
		return err;
	}
	if (nwr != baddr->len) {
		/* XXX -- wrong, need to retry again */
		return -EIO;
	}
	return 0;
}

int voluta_bstore_load_bobj(struct voluta_bstore *bstore,
                            const struct voluta_baddr *baddr, void *bobj)
{
	int err;
	struct voluta_bref_info *bri = NULL;
	struct voluta_fiovec fiov = { .fv_off = -1 };

	err = bstore_stage_blob(bstore, false, &baddr->bid, &bri);
	if (err) {
		return err;
	}
	err = bri_resolve_fiovec(bri, baddr->off, baddr->len, &fiov);
	if (err) {
		return err;
	}
	err = voluta_sys_preadn(fiov.fv_fd, bobj, fiov.fv_len, fiov.fv_off);
	if (err) {
		return err;
	}
	return 0;
}

