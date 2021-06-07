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
#include <voluta/infra.h>
#include <voluta/fs/types.h>
#include <voluta/fs/address.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/crypto.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/vstore.h>
#include <voluta/fs/bstore.h>
#include <voluta/fs/super.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/itable.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/dir.h>
#include <voluta/fs/file.h>
#include <voluta/fs/symlink.h>
#include <voluta/fs/xattr.h>
#include <voluta/fs/pstore.h>
#include <voluta/fs/private.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/



static const struct voluta_cipher *
vi_cipher(const struct voluta_vnode_info *vi)
{
	return &vi->v_sbi->sb_crypto.ci;
}

static int encrypt_vnode(const struct voluta_vnode_info *vi,
                         const struct voluta_cipher *cipher, void *buf)
{
	int err;
	struct voluta_kivam kivam;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	err = voluta_kivam_of(vi, &kivam);
	if (err) {
		return err;
	}
	err = voluta_encrypt_buf(cipher, &kivam, vi->view, buf, vaddr->len);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_decrypt_vnode(const struct voluta_vnode_info *vi, const void *buf)
{
	int err;
	struct voluta_kivam kivam;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);
	const struct voluta_cipher *cipher = vi_cipher(vi);

	err = voluta_kivam_of(vi, &kivam);
	if (err) {
		return err;
	}
	err = voluta_decrypt_buf(cipher, &kivam, buf, vi->view, vaddr->len);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int vstore_init_crypto(struct voluta_vstore *vstore)
{
	return voluta_crypto_init(&vstore->vs_crypto);
}

static void vstore_fini_crypto(struct voluta_vstore *vstore)
{
	voluta_crypto_fini(&vstore->vs_crypto);
}

static int vstore_init_pipe(struct voluta_vstore *vstore)
{
	int err;
	const size_t pipesz_want = VOLUTA_BK_SIZE;
	struct voluta_pipe *pipe = &vstore->vs_pipe;

	voluta_pipe_init(pipe);
	err = voluta_pipe_open(pipe);
	if (err) {
		return err;
	}
	err = voluta_pipe_setsize(pipe, pipesz_want);
	if (err) {
		return err;
	}
	return 0;
}

static void vstore_fini_pipe(struct voluta_vstore *vstore)
{
	struct voluta_pipe *pipe = &vstore->vs_pipe;

	voluta_pipe_close(pipe);
	voluta_pipe_fini(pipe);
}

static int vstore_init_encbuf(struct voluta_vstore *vstore)
{
	vstore->vs_encbuf = voluta_qalloc_zmalloc(vstore->vs_qalloc,
	                    sizeof(*vstore->vs_encbuf));

	return (vstore->vs_encbuf == NULL) ? -ENOMEM : 0;
}

static void vstore_fini_encbuf(struct voluta_vstore *vstore)
{
	if (vstore->vs_encbuf != NULL) {
		voluta_qalloc_zfree(vstore->vs_qalloc, vstore->vs_encbuf,
		                    sizeof(*vstore->vs_encbuf));
		vstore->vs_encbuf = NULL;
	}
}

static int vstore_init_pstore(struct voluta_vstore *vstore)
{
	return voluta_pstore_init(&vstore->vs_pstore);
}

static void vstore_fini_pstore(struct voluta_vstore *vstore)
{
	voluta_pstore_fini(&vstore->vs_pstore);
}

int voluta_vstore_init(struct voluta_vstore *vstore,
                       struct voluta_qalloc *qalloc)
{
	int err;

	voluta_memzero(vstore, sizeof(*vstore));
	vstore->vs_qalloc = qalloc;
	vstore->vs_volpath = NULL;
	vstore->vs_ctl_flags = 0;

	err = vstore_init_crypto(vstore);
	if (err) {
		return err;
	}
	err = vstore_init_pipe(vstore);
	if (err) {
		goto out;
	}
	err = vstore_init_encbuf(vstore);
	if (err) {
		goto out;
	}
	err = vstore_init_pstore(vstore);
	if (err) {
		goto out;
	}
out:
	if (err) {
		vstore_fini_pstore(vstore);
		vstore_fini_encbuf(vstore);
		vstore_fini_pipe(vstore);
		vstore_fini_crypto(vstore);
	}
	return err;
}

void voluta_vstore_fini(struct voluta_vstore *vstore)
{
	vstore_fini_pstore(vstore);
	vstore_fini_encbuf(vstore);
	vstore_fini_pipe(vstore);
	vstore_fini_crypto(vstore);
	vstore->vs_qalloc = NULL;
	vstore->vs_volpath = NULL;
	vstore->vs_ctl_flags = 0;
}

void voluta_vstore_add_ctlflags(struct voluta_vstore *vstore,
                                enum voluta_flags flags)
{
	vstore->vs_ctl_flags |= flags;
}

int voluta_vstore_check_size(const struct voluta_vstore *vstore)
{
	const loff_t size_min = VOLUTA_VOLUME_SIZE_MIN;
	const loff_t size_max = VOLUTA_VOLUME_SIZE_MAX;
	const loff_t size_cur = vstore->vs_pstore.ps_size;

	return ((size_cur < size_min) || (size_cur > size_max)) ? -EINVAL : 0;
}

int voluta_vstore_open(struct voluta_vstore *vstore, const char *path, bool rw)
{
	int err;

	err = voluta_pstore_open(&vstore->vs_pstore, path, rw);
	if (err) {
		return err;
	}
	vstore->vs_volpath = path;
	return 0;
}

int voluta_vstore_create(struct voluta_vstore *vstore,
                         const char *path, loff_t size)
{
	int err;

	err = voluta_pstore_create(&vstore->vs_pstore, path, size);
	if (err) {
		return err;
	}
	vstore->vs_volpath = path;
	return 0;
}

int voluta_vstore_close(struct voluta_vstore *vstore)
{
	return voluta_pstore_close(&vstore->vs_pstore);
}

int voluta_vstore_expand(struct voluta_vstore *vstore, loff_t cap)
{
	return voluta_pstore_expand(&vstore->vs_pstore, cap);
}

int voluta_vstore_write(struct voluta_vstore *vstore,
                        loff_t off, size_t bsz, const void *buf)
{
	return voluta_pstore_write(&vstore->vs_pstore, off, bsz, buf);
}

int voluta_vstore_writev(struct voluta_vstore *vstore, loff_t off,
                         size_t len, const struct iovec *iov, size_t cnt)
{
	return voluta_pstore_writev(&vstore->vs_pstore, off, len, iov, cnt);
}

int voluta_vstore_read(const struct voluta_vstore *vstore,
                       loff_t off, size_t bsz, void *buf)
{
	return voluta_pstore_read(&vstore->vs_pstore, off, bsz, buf);
}

int voluta_vstore_clone(const struct voluta_vstore *vstore,
                        const struct voluta_str *name)
{
	return voluta_pstore_clone(&vstore->vs_pstore, name);
}

int voluta_vstore_sync(struct voluta_vstore *vstore)
{
	return voluta_pstore_sync(&vstore->vs_pstore, false);
}

int voluta_vstore_fiovec(const struct voluta_vstore *vstore,
                         loff_t off, size_t len, struct voluta_fiovec *fiov)
{
	int err;
	const bool rw = false; /* TODO: propagate from top */
	const struct voluta_pstore *pstore = &vstore->vs_pstore;

	err = voluta_pstore_check_io(pstore, rw, off, len);
	if (!err) {
		fiov->fv_off = off;
		fiov->fv_len = len;
		fiov->fv_base = NULL;
		fiov->fv_fd = pstore->ps_vfd;
	}
	return err;
}

static const struct voluta_cipher *
vstore_cipher(const struct voluta_vstore *vstore)
{
	return &vstore->vs_crypto.ci;
}

static bool vstore_encryptwr(const struct voluta_vstore *vstore)
{
	const unsigned long mask = VOLUTA_F_ENCRYPTWR;

	return ((vstore->vs_ctl_flags & mask) == mask);
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

static void sgv_setup(struct voluta_sgvec *sgv)
{
	sgv->bid.size = 0;
	sgv->off = -1;
	sgv->lim = 2 * VOLUTA_MEGA;
	sgv->cnt = 0;
	sgv->len = 0;
}

static bool sgv_isappendable(const struct voluta_sgvec *sgv,
                             const struct voluta_vnode_info *vi)
{
	loff_t off;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	voluta_assert_lt(vaddr->len, sgv->lim);

	if (sgv->cnt == 0) {
		return true;
	}
	if (sgv->cnt == ARRAY_SIZE(sgv->iov)) {
		return false;
	}
	off = off_end(sgv->off, sgv->len);
	if (vaddr->off != off) {
		return false;
	}
	if ((sgv->len + vaddr->len) > sgv->lim) {
		return false;
	}
	if (!blobid_isequal(vi_blobid(vi), &sgv->bid)) {
		return false;
	}
	return true;
}

static int sgv_append(struct voluta_sgvec *sgv,
                      const struct voluta_vnode_info *vi)
{
	const size_t idx = sgv->cnt;
	const size_t len = vi_length(vi);
	const struct voluta_blobid *bid = vi_blobid(vi);

	if (idx == 0) {
		blobid_copyto(bid, &sgv->bid);
		sgv->off = vi_offset(vi);
	}
	sgv->iov[idx].iov_base = vi->view;
	sgv->iov[idx].iov_len = len;
	sgv->len += len;
	sgv->cnt += 1;
	return 0;
}

static int sgv_populate(struct voluta_sgvec *sgv,
                        struct voluta_vnode_info **viq)
{
	int err;
	struct voluta_vnode_info *vi;

	while (*viq != NULL) {
		vi = *viq;
		if (!sgv_isappendable(sgv, vi)) {
			break;
		}
		err = sgv_append(sgv, vi);
		if (err) {
			return err;
		}
		*viq = vi->v_ds_next;
	}
	return 0;
}

static int sgv_destage(const struct voluta_sgvec *sgv,
                       struct voluta_vstore *vstore)
{
	return voluta_vstore_writev(vstore, sgv->off,
	                            sgv->len, sgv->iov, sgv->cnt);
}

static int sgv_destage_into_blob(const struct voluta_sgvec *sgv,
                                 struct voluta_bstore *bstore)
{
	struct voluta_baddr baddr;

	voluta_assert_gt(sgv->cnt, 0);
	baddr_setup(&baddr, &sgv->bid, sgv->len, sgv->off);
	return voluta_bstore_storev_bobj(bstore, &baddr, sgv->iov, sgv->cnt);
}

static int sgv_flush_dset(struct voluta_sgvec *sgv,
                          const struct voluta_dset *dset,
                          struct voluta_vstore *vstore,
                          struct voluta_bstore *bstore)
{
	int err;
	struct voluta_vnode_info *viq = dset->ds_viq;

	while (viq != NULL) {
		sgv_setup(sgv);
		err = sgv_populate(sgv, &viq);
		if (err) {
			return err;
		}
		err = sgv_destage(sgv, vstore);
		if (err) {
			return err;
		}
		err = sgv_destage_into_blob(sgv, bstore);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_iobuf {
	struct voluta_slice buf;
	loff_t off;
};

static void iob_setup(struct voluta_iobuf *iob, struct voluta_encbuf *eb)
{
	iob->buf.len = 0;
	iob->buf.ptr = eb->b;
	iob->buf.cap = sizeof(eb->b);
	iob->off = -1;
}

static bool iob_isappendable(const struct voluta_iobuf *iob,
                             const struct voluta_vnode_info *vi)
{
	loff_t off;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if ((iob->buf.len == 0) && (vaddr->len < iob->buf.cap)) {
		return true;
	}
	off = off_end(iob->off, iob->buf.len);
	if (vaddr->off != off) {
		return false;
	}
	if ((iob->buf.len + vaddr->len) > iob->buf.cap) {
		return false;
	}
	return true;
}

static int iob_append(struct voluta_iobuf *iob,
                      const struct voluta_cipher *ci,
                      const struct voluta_vnode_info *vi)
{
	int err;
	void *ptr;
	const size_t len = vi_length(vi);

	if (iob->off == -1) {
		iob->off = vi_offset(vi);
	}
	ptr = voluta_slice_end(&iob->buf);
	err = encrypt_vnode(vi, ci, ptr);
	if (err) {
		return err;
	}
	iob->buf.len += len;
	return 0;
}

static int iob_populate(struct voluta_iobuf *iob,
                        struct voluta_vnode_info **viq,
                        const struct voluta_cipher *ci)
{
	int err;
	struct voluta_vnode_info *vi;

	while (*viq != NULL) {
		vi = *viq;
		if (!iob_isappendable(iob, vi)) {
			break;
		}
		err = iob_append(iob, ci, vi);
		if (err) {
			return err;
		}
		*viq = vi->v_ds_next;
	}
	return 0;
}

static int iob_destage(const struct voluta_iobuf *iob,
                       struct voluta_vstore *vstore)
{
	const voluta_lba_t lba = off_to_lba(iob->off);

	voluta_assert(!off_isnull(iob->off));
	voluta_assert(!lba_isnull(lba));
	voluta_assert_gt(lba, VOLUTA_LBA_SB);

	return voluta_vstore_write(vstore, iob->off,
	                           iob->buf.len, iob->buf.ptr);
}

static int iob_flush_dset(struct voluta_iobuf *iob,
                          const struct voluta_dset *dset,
                          struct voluta_vstore *vstore)
{
	int err;
	struct voluta_vnode_info *viq = dset->ds_viq;
	const struct voluta_cipher *cipher = vstore_cipher(vstore);

	while (viq != NULL) {
		iob_setup(iob, vstore->vs_encbuf);
		err = iob_populate(iob, &viq, cipher);
		if (err) {
			return err;
		}
		err = iob_destage(iob, vstore);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long off_compare(const void *x, const void *y)
{
	const long x_off = *((const loff_t *)x);
	const long y_off = *((const loff_t *)y);

	return y_off - x_off;
}

static struct voluta_vnode_info *
avl_node_to_vi(const struct voluta_avl_node *an)
{
	const struct voluta_vnode_info *vi;

	vi = container_of2(an, struct voluta_vnode_info, v_ds_an);
	return unconst(vi);
}

static const void *vi_getkey(const struct voluta_avl_node *an)
{
	const struct voluta_vnode_info *vi = avl_node_to_vi(an);

	return &vi->vaddr.off;
}

static void vi_visit_reinit(struct voluta_avl_node *an, void *p)
{
	struct voluta_vnode_info *vi = avl_node_to_vi(an);

	voluta_avl_node_init(&vi->v_ds_an);
	unused(p);
}

static void dset_clear_map(struct voluta_dset *dset)
{
	voluta_avl_clear(&dset->ds_avl, vi_visit_reinit, NULL);
}

static void dset_add_dirty_vi(struct voluta_dset *dset,
                              struct voluta_vnode_info *vi)
{
	voluta_avl_insert(&dset->ds_avl, &vi->v_ds_an);
}

static void dset_init(struct voluta_dset *dset, long key)
{
	voluta_avl_init(&dset->ds_avl, vi_getkey, off_compare, dset);
	dset->ds_viq = NULL;
	dset->ds_key = key;
	dset->ds_add_fn = dset_add_dirty_vi;
}

static void dset_fini(struct voluta_dset *dset)
{
	voluta_avl_fini(&dset->ds_avl);
	dset->ds_viq = NULL;
	dset->ds_add_fn = NULL;
}

static void dset_purge(const struct voluta_dset *dset)
{
	struct voluta_vnode_info *vi;
	struct voluta_vnode_info *next;

	vi = dset->ds_viq;
	while (vi != NULL) {
		next = vi->v_ds_next;

		vi_undirtify(vi);
		vi->v_ds_next = NULL;

		vi = next;
	}
}

static void dset_push_front_viq(struct voluta_dset *dset,
                                struct voluta_vnode_info *vi)
{
	vi->v_ds_next = dset->ds_viq;
	dset->ds_viq = vi;
}

static void dset_make_fifo(struct voluta_dset *dset)
{
	struct voluta_vnode_info *vi;
	const struct voluta_avl_node *end;
	const struct voluta_avl_node *itr;
	const struct voluta_avl *avl = &dset->ds_avl;

	dset->ds_viq = NULL;
	end = voluta_avl_end(avl);
	itr = voluta_avl_rbegin(avl);
	while (itr != end) {
		vi = avl_node_to_vi(itr);
		dset_push_front_viq(dset, vi);
		itr = voluta_avl_prev(avl, itr);
	}
}

static void dset_inhabit(struct voluta_dset *dset,
                         const struct voluta_cache *cache)
{
	voluta_cache_inhabit_dset(cache, dset);
}

static void dset_seal_meta(const struct voluta_dset *dset)
{
	const struct voluta_vnode_info *vi = dset->ds_viq;

	while (vi != NULL) {
		if (!vi_isdata(vi)) {
			voluta_vi_seal_meta(vi);
		}
		vi = vi->v_ds_next;
	}
}

static void dset_cleanup(struct voluta_dset *dset)
{
	dset_clear_map(dset);
	dset_purge(dset);
}

static int dset_flush(const struct voluta_dset *dset,
                      struct voluta_vstore *vstore,
                      struct voluta_bstore *bstore)
{
	struct voluta_sgvec sgv;
	struct voluta_iobuf iob;

	return vstore_encryptwr(vstore) ?
	       iob_flush_dset(&iob, dset, vstore) :
	       sgv_flush_dset(&sgv, dset, vstore, bstore);
}

static int dset_collect_flush(struct voluta_dset *dset,
                              const struct voluta_cache *cache,
                              struct voluta_vstore *vstore,
                              struct voluta_bstore *bstore)
{
	int err;

	dset_inhabit(dset, cache);
	dset_make_fifo(dset);
	dset_seal_meta(dset);
	err = dset_flush(dset, vstore, bstore);
	dset_cleanup(dset);
	return err;
}

int voluta_vstore_flush(struct voluta_vstore *vstore,
                        struct voluta_bstore *bstore,
                        const struct voluta_cache *cache, long ds_key)
{
	int err;
	struct voluta_dset dset;

	dset_init(&dset, ds_key);
	err = dset_collect_flush(&dset, cache, vstore, bstore);
	dset_fini(&dset);
	return err;
}
