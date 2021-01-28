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
#include <stdlib.h>
#include <stdbool.h>
#include "libvoluta.h"



struct voluta_sgvec {
	struct iovec iov[VOLUTA_NKB_IN_BK];
	loff_t off;
	size_t len;
	size_t cnt;
	size_t lim;
};

static void sgv_setup(struct voluta_sgvec *sgv)
{
	memset(sgv, 0, sizeof(*sgv));
	sgv->off = -1;
	sgv->lim = 2 * VOLUTA_MEGA;
}

static bool sgv_isappendable(const struct voluta_sgvec *sgv,
			     const struct voluta_vnode_info *vi)
{
	loff_t off;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if ((sgv->cnt == 0) && (vaddr->len < sgv->lim)) {
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
	return true;
}

static int sgv_append(struct voluta_sgvec *sgv,
		      const struct voluta_vnode_info *vi)
{
	const size_t idx = sgv->cnt;
	const size_t len = vi_length(vi);

	if (idx == 0) {
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
		       struct voluta_pstore *pstore)
{
	return voluta_pstore_writev(pstore, sgv->off,
				    sgv->len, sgv->iov, sgv->cnt);
}

static int sgv_flush_dset(struct voluta_sgvec *sgv,
			  const struct voluta_dset *dset,
			  struct voluta_pstore *pstore)
{
	int err;
	struct voluta_vnode_info *viq = dset->ds_viq;

	while (viq != NULL) {
		sgv_setup(sgv);
		err = sgv_populate(sgv, &viq);
		if (err) {
			return err;
		}
		err = sgv_destage(sgv, pstore);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_xbuf {
	struct voluta_buf buf;
	loff_t off;
};

static void xb_setup(struct voluta_xbuf *xb, struct voluta_encbuf *eb)
{
	xb->buf.len = 0;
	xb->buf.buf = eb->b;
	xb->buf.bsz = sizeof(eb->b);
	xb->off = -1;
}

static bool xb_isappendable(const struct voluta_xbuf *xb,
			    const struct voluta_vnode_info *vi)
{
	loff_t off;
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if ((xb->buf.len == 0) && (vaddr->len < xb->buf.bsz)) {
		return true;
	}
	off = off_end(xb->off, xb->buf.len);
	if (vaddr->off != off) {
		return false;
	}
	if ((xb->buf.len + vaddr->len) > xb->buf.bsz) {
		return false;
	}
	return true;
}

static int xb_append(struct voluta_xbuf *xb,
		     const struct voluta_vnode_info *vi)
{
	int err;
	void *ptr;
	const size_t len = vi_length(vi);

	if (xb->off == -1) {
		xb->off = vi_offset(vi);
	}
	voluta_assert_ge(buf_rem(&xb->buf), len);

	ptr = buf_end(&xb->buf);
	err = voluta_encrypt_vnode(vi, ptr);
	if (err) {
		return err;
	}
	xb->buf.len += len;
	return 0;
}

static int xb_populate(struct voluta_xbuf *xb,
		       struct voluta_vnode_info **viq)
{
	int err;
	struct voluta_vnode_info *vi;

	while (*viq != NULL) {
		vi = *viq;
		if (!xb_isappendable(xb, vi)) {
			break;
		}
		err = xb_append(xb, vi);
		if (err) {
			return err;
		}
		*viq = vi->v_ds_next;
	}
	return 0;
}

static int xb_destage(const struct voluta_xbuf *xb,
		      struct voluta_pstore *pstore)
{
	const loff_t lba = off_to_lba(xb->off);

	voluta_assert(!off_isnull(xb->off));
	voluta_assert(!lba_isnull(lba));
	voluta_assert_gt(lba, VOLUTA_LBA_SB);

	return voluta_pstore_write(pstore, xb->off, xb->buf.len, xb->buf.buf);
}

static int xb_flush_dset(struct voluta_xbuf *xb,
			 const struct voluta_dset *dset,
			 struct voluta_pstore *pstore,
			 struct voluta_encbuf *encbuf)
{
	int err;
	struct voluta_vnode_info *viq = dset->ds_viq;

	while (viq != NULL) {
		xb_setup(xb, encbuf);
		err = xb_populate(xb, &viq);
		if (err) {
			return err;
		}
		err = xb_destage(xb, pstore);
		if (err) {
			return err;
		}
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int dset_flush(const struct voluta_dset *dset,
		      struct voluta_pstore *pstore,
		      struct voluta_encbuf *encbuf)
{
	struct voluta_sgvec sgv = {
		.off = -1
	};
	struct voluta_xbuf xb = {
		.off = -1
	};

	return (encbuf != NULL) ?
	       xb_flush_dset(&xb, dset, pstore, encbuf) :
	       sgv_flush_dset(&sgv, dset, pstore);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void seal_dirty_vnodes(const struct voluta_dset *dset)
{
	const struct voluta_vnode_info *vi = dset->ds_viq;

	while (vi != NULL) {
		if (!vi_isdata(vi)) {
			voluta_seal_meta(vi);
		}
		vi = vi->v_ds_next;
	}
}

static bool sbi_testf(const struct voluta_sb_info *sbi, unsigned long f)
{
	return (sbi->sb_ctl_flags & f) == f;
}

static bool with_encbuf(const struct voluta_sb_info *sbi)
{
	return sbi_testf(sbi, VOLUTA_F_ENCRYPT) ||
	       !sbi_testf(sbi, VOLUTA_F_SPLICED);
}

int voluta_collect_flush_dirty(struct voluta_sb_info *sbi, long ds_key)
{
	int err;
	struct voluta_dset dset;
	struct voluta_encbuf *eb =
		with_encbuf(sbi) ? sbi->sb_encbuf : NULL;

	voluta_dset_build(&dset, sbi->sb_cache, ds_key);
	seal_dirty_vnodes(&dset);

	err = dset_flush(&dset, sbi->sb_pstore, eb);
	voluta_dset_cleanup(&dset);
	return err;
}
