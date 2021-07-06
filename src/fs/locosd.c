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
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <voluta/infra.h>
#include <voluta/fs/address.h>
#include <voluta/fs/locosd.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/super.h>
#include <voluta/fs/private.h>

#define LOCOSD_NSUBS 256

/* blob-reference cache-entry */
struct voluta_bref_info {
	struct voluta_blobid    bid;
	struct voluta_fiovref   b_fir;
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

static int blobid_to_pathname(const struct voluta_blobid *bid,
                              size_t nsubs, struct voluta_namebuf *out_nb)
{
	int err;
	size_t len = 0;
	size_t nlen = 0;
	voluta_index_t idx;
	char *nbuf = out_nb->name;
	const size_t nmax = sizeof(out_nb->name);

	idx = blobid_to_index(bid, nsubs);
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
bri_from_fiovref(const struct voluta_fiovref *fvr)
{
	const struct voluta_bref_info *bri = NULL;

	bri = container_of2(fvr, struct voluta_bref_info, b_fir);
	return bri_unconst(bri);
}

static struct voluta_bref_info *
bri_from_htb_lh(const struct voluta_list_head *lh)
{
	const struct voluta_bref_info *bri = NULL;

	if (likely(lh != NULL)) {
		bri = container_of2(lh, struct voluta_bref_info, b_htb_lh);
	}
	return bri_unconst(bri);
}

static struct voluta_bref_info *
bri_from_lru_lh(const struct voluta_list_head *lh)
{
	const struct voluta_bref_info *bri = NULL;

	if (likely(lh != NULL)) {
		bri = container_of2(lh, struct voluta_bref_info, b_lru_lh);
	}
	return bri_unconst(bri);
}

static void bri_incref(struct voluta_bref_info *bri)
{
	bri->b_refcnt++;
}

static void bri_decref(struct voluta_bref_info *bri)
{
	voluta_assert_gt(bri->b_refcnt, 0);

	bri->b_refcnt--;
}

static void bri_fiov_pre(struct voluta_fiovref *fir)
{
	struct voluta_bref_info *bri = bri_from_fiovref(fir);

	bri_incref(bri);
}

static void bri_fiov_post(struct voluta_fiovref *fir)
{
	struct voluta_bref_info *bri = bri_from_fiovref(fir);

	bri_decref(bri);
}

static void bri_init(struct voluta_bref_info *bri,
                     const struct voluta_blobid *bid, int fd)
{
	blobid_copyto(bid, &bri->bid);
	list_head_init(&bri->b_htb_lh);
	list_head_init(&bri->b_lru_lh);
	voluta_fiovref_init(&bri->b_fir, bri_fiov_pre, bri_fiov_post);
	bri->b_hkey = voluta_blobid_hkey(bid);
	bri->b_refcnt = 0;
	bri->b_fd = fd;
}

static void bri_fini(struct voluta_bref_info *bri)
{
	voluta_fiovref_fini(&bri->b_fir);
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
bri_new(struct voluta_alloc_if *alif, const struct voluta_blobid *bid, int fd)
{
	struct voluta_bref_info *bri;

	bri = voluta_allocate(alif, sizeof(*bri));
	if (bri != NULL) {
		bri_init(bri, bid, fd);
	}
	return bri;
}

static void bri_del(struct voluta_bref_info *bri, struct voluta_alloc_if *alif)
{
	voluta_assert_lt(bri->b_fd, 0);

	bri_fini(bri);
	voluta_deallocate(alif, bri, sizeof(*bri));
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

static int bri_resolve_fiovec(struct voluta_bref_info *bri,
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
	fiov->fv_ref = &bri->b_fir;
	return 0;
}

static bool bri_is_evictable(const struct voluta_bref_info *bri)
{
	voluta_assert_ge(bri->b_refcnt, 0);

	return (bri->b_refcnt == 0);
}

static int bri_datasync(const struct voluta_bref_info *bri)
{
	voluta_assert_gt(bri->b_fd, 0);

	return voluta_sys_fdatasync(bri->b_fd);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void locosd_htbl_init(struct voluta_locosd *locosd)
{
	list_head_initn(locosd->lo_htbl, ARRAY_SIZE(locosd->lo_htbl));
}

static void locosd_htbl_fini(struct voluta_locosd *locosd)
{
	list_head_finin(locosd->lo_htbl, ARRAY_SIZE(locosd->lo_htbl));
}

static struct voluta_list_head *
locosd_htbl_list_by(const struct voluta_locosd *locosd, const uint64_t hkey)
{
	const size_t slot = hkey % ARRAY_SIZE(locosd->lo_htbl);
	const struct voluta_list_head *lst = &locosd->lo_htbl[slot];

	return unconst(lst);
}

static struct voluta_bref_info *
locosd_htbl_lookup(const struct voluta_locosd *locosd,
                   const struct voluta_blobid *bid, uint64_t bid_hkey)
{
	const struct voluta_bref_info *bri;
	const struct voluta_list_head *itr;
	const struct voluta_list_head *lst;

	itr = lst = locosd_htbl_list_by(locosd, bid_hkey);
	while (itr->next != lst) {
		itr = itr->next;
		bri = bri_from_htb_lh(itr);
		if (bri_has_blobid(bri, bid)) {
			return bri_unconst(bri);
		}
	}
	return NULL;
}

static void locosd_htbl_insert(struct voluta_locosd *locosd,
                               struct voluta_bref_info *bri)
{
	struct voluta_list_head *lst;

	lst = locosd_htbl_list_by(locosd, bri->b_hkey);
	list_push_front(lst, &bri->b_htb_lh);
}

static void locosd_htbl_remove(struct voluta_locosd *locosd,
                               struct voluta_bref_info *bri)
{
	struct voluta_list_head *lst;

	lst = locosd_htbl_list_by(locosd, bri->b_hkey);
	voluta_assert(!list_isempty(lst));
	list_head_remove(&bri->b_htb_lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void locosd_lru_init(struct voluta_locosd *locosd)
{
	listq_init(&locosd->lo_lru);
}

static void locosd_lru_fini(struct voluta_locosd *locosd)
{
	listq_fini(&locosd->lo_lru);
}

static void locosd_lru_insert(struct voluta_locosd *locosd,
                              struct voluta_bref_info *bri)
{
	listq_push_front(&locosd->lo_lru, &bri->b_lru_lh);
}

static void locosd_lru_remove(struct voluta_locosd *locosd,
                              struct voluta_bref_info *bri)
{
	voluta_assert_gt(locosd->lo_lru.sz, 0);
	listq_remove(&locosd->lo_lru, &bri->b_lru_lh);
}

static struct voluta_bref_info *
locosd_lru_front(const struct voluta_locosd *locosd)
{
	struct voluta_list_head *lh;

	lh = listq_front(&locosd->lo_lru);
	return bri_from_lru_lh(lh);
}

static struct voluta_bref_info *
locosd_lru_nextof(const struct voluta_locosd *locosd,
                  const struct voluta_bref_info *bri)
{
	struct voluta_list_head *lh_next = bri->b_lru_lh.next;

	if (lh_next == &locosd->lo_lru.ls) {
		return NULL;
	}
	return bri_from_lru_lh(lh_next);
}

static struct voluta_bref_info *
locosd_cahce_rfind(const struct voluta_locosd *locosd, voluta_bri_pred_fn fn)
{
	const struct voluta_bref_info *bi;
	const struct voluta_list_head *lh;
	const struct voluta_listq *lru = &locosd->lo_lru;

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

static void locosd_cache_init(struct voluta_locosd *locosd)
{
	locosd_htbl_init(locosd);
	locosd_lru_init(locosd);
}

static void locosd_cache_fini(struct voluta_locosd *locosd)
{
	locosd_htbl_fini(locosd);
	locosd_lru_fini(locosd);
}

static void locosd_cache_insert(struct voluta_locosd *locosd,
                                struct voluta_bref_info *bri)
{
	locosd_htbl_insert(locosd, bri);
	locosd_lru_insert(locosd, bri);
}

static void locosd_cache_remove(struct voluta_locosd *locosd,
                                struct voluta_bref_info *bri)
{
	locosd_lru_remove(locosd, bri);
	locosd_htbl_remove(locosd, bri);
}

static void locosd_cache_relru(struct voluta_locosd *locosd,
                               struct voluta_bref_info *bri)
{
	locosd_lru_remove(locosd, bri);
	locosd_lru_insert(locosd, bri);
}

static int
locosd_cache_lookup(struct voluta_locosd *locosd,
                    const struct voluta_blobid *bid,
                    uint64_t bid_hkey, struct voluta_bref_info **out_bri)
{
	*out_bri = locosd_htbl_lookup(locosd, bid, bid_hkey);
	if (*out_bri == NULL) {
		return -ENOENT;
	}
	locosd_cache_relru(locosd, *out_bri);
	return 0;
}

static struct voluta_bref_info *
locosd_cache_front(const struct voluta_locosd *locosd)
{
	return locosd_lru_front(locosd);
}

static struct voluta_bref_info *
locosd_cache_nextof(const struct voluta_locosd *locosd,
                    const struct voluta_bref_info *bri)
{
	return locosd_lru_nextof(locosd, bri);
}


static struct voluta_bref_info *
locosd_cache_find_evictable(const struct voluta_locosd *locosd)
{
	return locosd_cahce_rfind(locosd, bri_is_evictable);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_locosd_init(struct voluta_locosd *locosd,
                       struct voluta_alloc_if *alif)
{
	locosd_cache_init(locosd);
	locosd->lo_dfd = -1;
	locosd->lo_nsubs = LOCOSD_NSUBS;
	locosd->lo_alif = alif;
	locosd->lo_basedir = NULL;
	return 0;
}

void voluta_locosd_fini(struct voluta_locosd *locosd)
{
	voluta_locosd_close(locosd);
	locosd_cache_fini(locosd);
	locosd->lo_nsubs = 0;
	locosd->lo_alif = NULL;
	locosd->lo_basedir = NULL;
}

int voluta_locosd_open(struct voluta_locosd *locosd, const char *path)
{
	int err;

	voluta_assert_lt(locosd->lo_dfd, 0);
	err = voluta_sys_opendir(path, &locosd->lo_dfd);
	if (err) {
		return err;
	}
	locosd->lo_basedir = path;
	return 0;
}

static int locosd_format_sub(const struct voluta_locosd *locosd,
                             voluta_index_t idx)
{
	int err;
	struct stat st;
	struct voluta_namebuf nb;
	const int dfd = locosd->lo_dfd;

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

int voluta_locosd_format(struct voluta_locosd *locosd)
{
	int err;

	for (size_t i = 0; i < locosd->lo_nsubs; ++i) {
		err = locosd_format_sub(locosd, i);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int locosd_sub_pathname_of(const struct voluta_locosd *locosd,
                                  const struct voluta_blobid *bid,
                                  struct voluta_namebuf *out_nb)
{
	return blobid_to_pathname(bid, locosd->lo_nsubs, out_nb);
}

static ssize_t blob_ssize(const struct voluta_blobid *bid)
{
	return (ssize_t)blobid_size(bid);
}

static int locosd_create_blob(const struct voluta_locosd *locosd,
                              const struct voluta_blobid *bid, int *out_fd)
{
	int err;
	int fd = -1;
	int o_flags;
	ssize_t len;
	struct stat st;
	struct voluta_namebuf nb;

	err = locosd_sub_pathname_of(locosd, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(locosd->lo_dfd, nb.name, &st, 0);
	if (err != -ENOENT) {
		log_err("can not create blob: name=%s err=%d", nb.name, err);
		return err;
	}
	o_flags = O_CREAT | O_RDWR | O_TRUNC;
	err = voluta_sys_openat(locosd->lo_dfd, nb.name, o_flags, 0600, &fd);
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
	voluta_sys_unlinkat(locosd->lo_dfd, nb.name, 0);
	voluta_sys_closefd(&fd);
	return err;
}

static int locosd_unlink_blob(const struct voluta_locosd *locosd,
                              const struct voluta_blobid *bid)
{
	int err;
	struct voluta_namebuf nb;

	err = locosd_sub_pathname_of(locosd, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_unlinkat(locosd->lo_dfd, nb.name, 0);
	if (err) {
		return err;
	}
	return 0;
}

static int locosd_remove_blob(const struct voluta_locosd *locosd,
                              const struct voluta_blobid *bid, int *pfd)
{
	voluta_sys_closefd(pfd);
	return locosd_unlink_blob(locosd, bid);
}

static int locosd_open_blob(const struct voluta_locosd *locosd,
                            const struct voluta_blobid *bid, int *out_fd)
{
	int err;
	int fd = -1;
	struct stat st;
	struct voluta_namebuf nb;

	err = locosd_sub_pathname_of(locosd, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(locosd->lo_dfd, nb.name, &st, 0);
	if (err) {
		return err;
	}
	if (st.st_size < blob_ssize(bid)) {
		log_warn("blob-size mismatch: %s size=%ld st_size=%ld",
		         nb.name, blob_ssize(bid), st.st_size);
		err = -ENOENT;
		return err;
	}
	err = voluta_sys_openat(locosd->lo_dfd, nb.name, O_RDWR, 0600, &fd);
	if (err) {
		return err;
	}
	*out_fd = fd;
	return 0;
}

static int locosd_close_blob(const struct voluta_locosd *locosd,
                             const struct voluta_blobid *bid, int *pfd)
{
	int err;
	struct stat st;
	struct voluta_namebuf nb;

	err = locosd_sub_pathname_of(locosd, bid, &nb);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(locosd->lo_dfd, nb.name, &st, 0);
	if (err) {
		log_warn("missing blob: name=%s err=%d", nb.name, err);
	}
	return voluta_sys_closefd(pfd);
}

static int locosd_close_bref_of(const struct voluta_locosd *locosd,
                                struct voluta_bref_info *bri)
{
	voluta_assert_gt(bri->b_fd, 0);
	voluta_assert_eq(bri->b_refcnt, 0);

	return locosd_close_blob(locosd, &bri->bid, &bri->b_fd);
}

static int locosd_new_bref(struct voluta_locosd *locosd,
                           const struct voluta_blobid *bid, int fd,
                           struct voluta_bref_info **out_bri)
{
	*out_bri = bri_new(locosd->lo_alif, bid, fd);

	return (*out_bri == NULL) ? -ENOMEM : 0;
}

static void locosd_del_bref(const struct voluta_locosd *locosd,
                            struct voluta_bref_info *bri)
{
	bri_del(bri, locosd->lo_alif);
}

static void locosd_forget_bref(struct voluta_locosd *locosd,
                               struct voluta_bref_info *bri)
{
	locosd_close_bref_of(locosd, bri);
	locosd_cache_remove(locosd, bri);
	locosd_del_bref(locosd, bri);
}

int voluta_locosd_sync(struct voluta_locosd *locosd)
{
	int err;
	struct voluta_bref_info *bri;

	bri = locosd_cache_front(locosd);
	while (bri != NULL) {
		err = bri_datasync(bri);
		if (err) {
			return err;
		}
		bri = locosd_cache_nextof(locosd, bri);
	}
	return 0;
}

static void locosd_forget_all(struct voluta_locosd *locosd)
{
	struct voluta_bref_info *bri;

	bri = locosd_cache_front(locosd);
	while (bri != NULL) {
		locosd_forget_bref(locosd, bri);
		bri = locosd_cache_front(locosd);
	}
}

int voluta_locosd_close(struct voluta_locosd *locosd)
{
	locosd_forget_all(locosd);
	return voluta_sys_closefd(&locosd->lo_dfd);
}

static int locosd_relax_once(struct voluta_locosd *locosd)
{
	struct voluta_bref_info *bri = NULL;
	const size_t ncached = locosd->lo_lru.sz;

	if (!ncached || (ncached < 128)) { /* XXX make upper bound tweak */
		return 0;
	}
	bri = locosd_cache_find_evictable(locosd);
	if (bri == NULL) {
		return -ENOENT;
	}
	locosd_forget_bref(locosd, bri);
	return 0;
}

static int locosd_open_blob_of(struct voluta_locosd *locosd,
                               const struct voluta_blobid *bid,
                               struct voluta_bref_info **out_bri)
{
	int err;
	int fd = -1;

	voluta_assert_ge(bid->size, VOLUTA_BK_SIZE);
	err = locosd_relax_once(locosd);
	if (err) {
		return err;
	}
	err = locosd_open_blob(locosd, bid, &fd);
	if (err) {
		return err;
	}
	err = locosd_new_bref(locosd, bid, fd, out_bri);
	if (err) {
		locosd_close_blob(locosd, bid, &fd);
		return err;
	}
	locosd_cache_insert(locosd, *out_bri);
	return 0;
}

static int locosd_create_blob_of(struct voluta_locosd *locosd,
                                 const struct voluta_blobid *bid,
                                 struct voluta_bref_info **out_bri)
{
	int err;
	int fd = -1;

	err = locosd_relax_once(locosd);
	if (err) {
		return err;
	}
	err = locosd_create_blob(locosd, bid, &fd);
	if (err) {
		return err;
	}
	err = locosd_new_bref(locosd, bid, fd, out_bri);
	if (err) {
		locosd_remove_blob(locosd, bid, &fd);
		return err;
	}
	locosd_cache_insert(locosd, *out_bri);
	return 0;
}

static int
locosd_stage_blob(struct voluta_locosd *locosd, bool may_create,
                  const struct voluta_blobid *bid, uint64_t bid_hkey,
                  struct voluta_bref_info **out_bri)
{
	int err;

	voluta_assert_ge(bid->size, VOLUTA_BK_SIZE);

	err = locosd_cache_lookup(locosd, bid, bid_hkey, out_bri);
	if (!err) {
		return 0; /* cache hit */
	}
	err = locosd_open_blob_of(locosd, bid, out_bri);
	if (!err) {
		return 0;
	}
	if (err != -ENOENT) {
		return err;
	}
	if (!may_create) {
		return -ENOENT;
	}
	err = locosd_create_blob_of(locosd, bid, out_bri);
	if (err) {
		return err;
	}
	return 0;
}

static int locosd_stage_blob_of(struct voluta_locosd *locosd, bool may_create,
                                const struct voluta_baddr *baddr,
                                struct voluta_bref_info **out_bri)
{
	const struct voluta_blobid *bid = &baddr->bid;
	const uint64_t bid_hkey = voluta_blobid_hkey(bid);

	return locosd_stage_blob(locosd, may_create, bid, bid_hkey, out_bri);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_locosd_create(struct voluta_locosd *locosd,
                         const struct voluta_blobid *bid)
{
	struct voluta_bref_info *bri = NULL;
	const uint64_t bid_hkey = voluta_blobid_hkey(bid);

	return locosd_stage_blob(locosd, true, bid, bid_hkey, &bri);
}

int voluta_locosd_store(struct voluta_locosd *locosd,
                        const struct voluta_baddr *baddr,
                        const void *bobj)
{
	int err;
	struct voluta_bref_info *bri = NULL;
	struct voluta_fiovec fiov = { .fv_off = -1 };

	err = locosd_stage_blob_of(locosd, true, baddr, &bri);
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

int voluta_locosd_storev(struct voluta_locosd *locosd,
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
	err = locosd_stage_blob_of(locosd, true, baddr, &bri);
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

int voluta_locosd_load(struct voluta_locosd *locosd,
                       const struct voluta_baddr *baddr, void *bobj)
{
	int err;
	struct voluta_bref_info *bri = NULL;
	struct voluta_fiovec fiov = { .fv_off = -1 };

	err = locosd_stage_blob_of(locosd, false, baddr, &bri);
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

int voluta_locosd_resolve(struct voluta_locosd *locosd,
                          const struct voluta_baddr *baddr,
                          loff_t off_within, size_t len,
                          struct voluta_fiovec *out_fiov)
{
	int err;
	struct voluta_bref_info *bri = NULL;

	err = locosd_stage_blob_of(locosd, false, baddr, &bri);
	if (err) {
		return err;
	}
	err = bri_resolve_fiovec(bri, baddr->off + off_within, len, out_fiov);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct voluta_sgvec {
	struct iovec iov[VOLUTA_NKB_IN_BK];
	struct voluta_blobid bid;
	loff_t off;
	size_t len;
	size_t cnt;
	size_t lim;
};

static void sgvec_setup(struct voluta_sgvec *sgv)
{
	sgv->bid.size = 0;
	sgv->off = -1;
	sgv->lim = 2 * VOLUTA_MEGA;
	sgv->cnt = 0;
	sgv->len = 0;
}

static bool sgvec_isappendable(const struct voluta_sgvec *sgv,
                               const struct voluta_baddr *baddr)
{
	if (sgv->cnt == 0) {
		return true;
	}
	if (sgv->cnt == ARRAY_SIZE(sgv->iov)) {
		return false;
	}
	if (baddr->off != off_end(sgv->off, sgv->len)) {
		return false;
	}
	voluta_assert_lt(baddr->len, sgv->lim);
	if ((sgv->len + baddr->len) > sgv->lim) {
		return false;
	}
	if (!blobid_isequal(&baddr->bid, &sgv->bid)) {
		return false;
	}
	return true;
}

static int sgvec_append(struct voluta_sgvec *sgv,
                        const struct voluta_baddr *baddr, const void *dat)
{
	const size_t idx = sgv->cnt;

	if (idx == 0) {
		blobid_copyto(&baddr->bid, &sgv->bid);
		sgv->off = baddr->off;
	}
	sgv->iov[idx].iov_base = unconst(dat);
	sgv->iov[idx].iov_len = baddr->len;
	sgv->len += baddr->len;
	sgv->cnt += 1;
	return 0;
}

static int sgvec_populate(struct voluta_sgvec *sgv,
                          struct voluta_cnode_info **ciq)
{
	int err;
	struct voluta_baddr baddr;
	struct voluta_cnode_info *ci;

	while (*ciq != NULL) {
		ci = *ciq;
		err = ci->c_vtbl->resolve(ci, &baddr);
		if (err) {
			return err;
		}
		if (!sgvec_isappendable(sgv, &baddr)) {
			break;
		}
		err = sgvec_append(sgv, &baddr, ci->c_xref);
		if (err) {
			return err;
		}
		*ciq = ci->c_ds_next;
	}
	return 0;
}

static int sgvec_store_in_blob(const struct voluta_sgvec *sgv,
                               struct voluta_locosd *locosd)
{
	struct voluta_baddr baddr;

	voluta_assert_gt(sgv->cnt, 0);
	baddr_setup(&baddr, &sgv->bid, sgv->len, sgv->off);
	return voluta_locosd_storev(locosd, &baddr, sgv->iov, sgv->cnt);
}

static int sgvec_flush_dset(struct voluta_sgvec *sgv,
                            const struct voluta_dset *dset,
                            struct voluta_locosd *locosd)
{
	int err;
	struct voluta_cnode_info *ciq = dset->ds_ciq;

	while (ciq != NULL) {
		sgvec_setup(sgv);
		err = sgvec_populate(sgv, &ciq);
		if (err) {
			return err;
		}
		err = sgvec_store_in_blob(sgv, locosd);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long ckey_compare(const void *x, const void *y)
{
	const struct voluta_ckey *ckey_x = x;
	const struct voluta_ckey *ckey_y = y;

	return voluta_ckey_compare(ckey_x, ckey_y);
}

static struct voluta_cnode_info *
avl_node_to_ci(const struct voluta_avl_node *an)
{
	const struct voluta_cnode_info *ci;

	ci = container_of2(an, struct voluta_cnode_info, c_ds_an);
	return unconst(ci);
}

static const void *ci_getkey(const struct voluta_avl_node *an)
{
	const struct voluta_cnode_info *ci = avl_node_to_ci(an);

	return &ci->ce.ce_ckey;
}

static void ci_visit_reinit(struct voluta_avl_node *an, void *p)
{
	struct voluta_cnode_info *ci = avl_node_to_ci(an);

	voluta_avl_node_init(&ci->c_ds_an);
	unused(p);
}

static void dset_clear_map(struct voluta_dset *dset)
{
	voluta_avl_clear(&dset->ds_avl, ci_visit_reinit, NULL);
}

static void dset_add_dirty(struct voluta_dset *dset,
                           struct voluta_cnode_info *ci)
{
	voluta_avl_insert(&dset->ds_avl, &ci->c_ds_an);
}

static void dset_init(struct voluta_dset *dset)
{
	voluta_avl_init(&dset->ds_avl, ci_getkey, ckey_compare, dset);
	dset->ds_ciq = NULL;
	dset->ds_add_fn = dset_add_dirty;
}

static void dset_fini(struct voluta_dset *dset)
{
	voluta_avl_fini(&dset->ds_avl);
	dset->ds_ciq = NULL;
	dset->ds_add_fn = NULL;
}

static void dset_push_front_ciq(struct voluta_dset *dset,
                                struct voluta_cnode_info *ci)
{
	ci->c_ds_next = dset->ds_ciq;
	dset->ds_ciq = ci;
}

static void dset_make_fifo(struct voluta_dset *dset)
{
	struct voluta_cnode_info *ci;
	const struct voluta_avl_node *end;
	const struct voluta_avl_node *itr;
	const struct voluta_avl *avl = &dset->ds_avl;

	dset->ds_ciq = NULL;
	end = voluta_avl_end(avl);
	itr = voluta_avl_rbegin(avl);
	while (itr != end) {
		ci = avl_node_to_ci(itr);
		dset_push_front_ciq(dset, ci);
		itr = voluta_avl_prev(avl, itr);
	}
}

static void dset_seal_all(const struct voluta_dset *dset)
{
	struct voluta_cnode_info *ci = dset->ds_ciq;

	while (ci != NULL) {
		ci->c_vtbl->seal(ci);
		ci = ci->c_ds_next;
	}
}

static int dset_flush(const struct voluta_dset *dset,
                      struct voluta_locosd *locosd)
{
	struct voluta_sgvec sgv;

	return sgvec_flush_dset(&sgv, dset, locosd);
}

static int dset_collect_flush_vnodes(struct voluta_dset *dset,
                                     struct voluta_cache *cache,
                                     struct voluta_locosd *locosd)
{
	int err;

	voluta_cache_fill_into_dset(cache, dset);
	dset_make_fifo(dset);
	dset_seal_all(dset);
	err = dset_flush(dset, locosd);
	if (!err) {
		voluta_cache_undirtify_by_dset(cache, dset);
	}
	dset_clear_map(dset);
	return err;
}

int voluta_collect_flush_dirty(struct voluta_cache *cache,
                               struct voluta_locosd *locosd)
{
	int err;
	struct voluta_dset dset;

	dset_init(&dset);
	err = dset_collect_flush_vnodes(&dset, cache, locosd);
	dset_fini(&dset);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_resolve_sb_path(const char *id, struct voluta_namebuf *out_nb)
{
	int err;
	struct voluta_blobid bid;

	err = voluta_blobid_from_name(&bid, id, strlen(id));
	if (err) {
		return err;
	}
	err = blobid_to_pathname(&bid, LOCOSD_NSUBS, out_nb);
	if (err) {
		return err;
	}
	return 0;
}
