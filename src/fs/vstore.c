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
#include <voluta/fs/repo.h>
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

static uint32_t hdr_magic(const struct voluta_header *hdr)
{
	return voluta_le32_to_cpu(hdr->h_magic);
}

static void hdr_set_magic(struct voluta_header *hdr, uint32_t magic)
{
	hdr->h_magic = voluta_cpu_to_le32(magic);
}

static size_t hdr_size(const struct voluta_header *hdr)
{
	return voluta_le32_to_cpu(hdr->h_size);
}

static size_t hdr_payload_size(const struct voluta_header *hdr)
{
	return hdr_size(hdr) - sizeof(*hdr);
}

static void hdr_set_size(struct voluta_header *hdr, size_t size)
{
	hdr->h_size = voluta_cpu_to_le32((uint32_t)size);
}

static enum voluta_vtype hdr_vtype(const struct voluta_header *hdr)
{
	return (enum voluta_vtype)(hdr->h_vtype);
}

static void hdr_set_vtype(struct voluta_header *hdr, enum voluta_vtype vtype)
{
	hdr->h_vtype = (uint8_t)vtype;
}

static uint32_t hdr_csum(const struct voluta_header *hdr)
{
	return voluta_le32_to_cpu(hdr->h_csum);
}

static void hdr_set_csum(struct voluta_header *hdr, uint32_t csum)
{
	hdr->h_csum = voluta_cpu_to_le32(csum);
}

static const void *hdr_payload(const struct voluta_header *hdr)
{
	return hdr + 1;
}

static struct voluta_header *hdr_of(const struct voluta_view *view)
{
	const struct voluta_header *hdr = &view->u.hdr;

	return unconst(hdr);
}

static void hdr_stamp(struct voluta_header *hdr,
                      enum voluta_vtype vtype, size_t size)
{
	hdr_set_magic(hdr, VOLUTA_VTYPE_MAGIC);
	hdr_set_size(hdr, size);
	hdr_set_vtype(hdr, vtype);
	hdr_set_csum(hdr, 0);
	hdr->h_flags = 0;
	hdr->h_reserved = 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_header *
vi_hdr_of(const struct voluta_vnode_info *vi)
{
	return hdr_of(vi->view);
}

static bool vi_isdatabk(const struct voluta_vnode_info *vi)
{
	return vtype_isequal(vi_vtype(vi), VOLUTA_VTYPE_DATABK);
}

void *voluta_vi_dat_of(const struct voluta_vnode_info *vi)
{
	return vi_isdatabk(vi) ? vi->vu.db->dat : vi->vu.db4->dat;
}

static uint32_t calc_meta_chekcsum(const struct voluta_header *hdr,
                                   const struct voluta_mdigest *md)
{
	uint32_t csum = 0;
	const void *payload = hdr_payload(hdr);
	const size_t pl_size = hdr_payload_size(hdr);

	voluta_assert_le(pl_size, VOLUTA_BK_SIZE - VOLUTA_HEADER_SIZE);

	voluta_crc32_of(md, payload, pl_size, &csum);
	return csum;
}

static uint32_t calc_data_checksum(const void *dat, size_t len,
                                   const struct voluta_mdigest *md)
{
	uint32_t csum = 0;

	voluta_crc32_of(md, dat, len, &csum);
	return csum;
}

static uint32_t calc_chekcsum_of(const struct voluta_vnode_info *vi)
{
	uint32_t csum;
	const struct voluta_mdigest *md = vi_mdigest(vi);
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	if (vaddr_isdata(vaddr)) {
		csum = calc_data_checksum(vi_dat_of(vi), vaddr->len, md);
	} else {
		csum = calc_meta_chekcsum(vi_hdr_of(vi), md);
	}
	return csum;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_hdr(const struct voluta_view *view, enum voluta_vtype vtype)
{
	const struct voluta_header *hdr = hdr_of(view);
	const size_t hsz = hdr_size(hdr);
	const size_t psz = vtype_size(vtype);

	if (vtype_isdata(vtype)) {
		return 0;
	}
	if (hdr_magic(hdr) != VOLUTA_VTYPE_MAGIC) {
		return -EFSCORRUPTED;
	}
	if (hdr_vtype(hdr) != vtype) {
		return -EFSCORRUPTED;
	}
	if (hsz != psz) {
		return -EFSCORRUPTED;
	}

	return 0;
}

static int verify_checksum(const struct voluta_view *view,
                           const struct voluta_mdigest *md)
{
	uint32_t csum;
	const struct voluta_header *hdr = hdr_of(view);

	csum = calc_meta_chekcsum(hdr, md);
	return (csum == hdr_csum(hdr)) ? 0 : -EFSCORRUPTED;
}

static int verify_sub(const struct voluta_view *view, enum voluta_vtype vtype)
{
	int err;

	switch (vtype) {
	case VOLUTA_VTYPE_HSMAP:
		err = voluta_verify_hspace_map(&view->u.hsm);
		break;
	case VOLUTA_VTYPE_AGMAP:
		err = voluta_verify_agroup_map(&view->u.agm);
		break;
	case VOLUTA_VTYPE_ITNODE:
		err = voluta_verify_itnode(&view->u.itn);
		break;
	case VOLUTA_VTYPE_INODE:
		err = voluta_verify_inode(&view->u.inode);
		break;
	case VOLUTA_VTYPE_XANODE:
		err = voluta_verify_xattr_node(&view->u.xan);
		break;
	case VOLUTA_VTYPE_HTNODE:
		err = voluta_verify_dir_htree_node(&view->u.htn);
		break;
	case VOLUTA_VTYPE_RTNODE:
		err = voluta_verify_radix_tnode(&view->u.rtn);
		break;
	case VOLUTA_VTYPE_SYMVAL:
		err = voluta_verify_lnk_value(&view->u.lnv);
		break;
	case VOLUTA_VTYPE_SUPER:
	case VOLUTA_VTYPE_DATA1K:
	case VOLUTA_VTYPE_DATA4K:
	case VOLUTA_VTYPE_DATABK:
	case VOLUTA_VTYPE_AGBKS:
		err = 0;
		break;
	case VOLUTA_VTYPE_NONE:
	default:
		err = -EFSCORRUPTED;
		break;
	}
	return err;
}

static int verify_view(const struct voluta_view *view,
                       enum voluta_vtype vtype,
                       const struct voluta_mdigest *md)
{
	int err;

	if (vtype_isdata(vtype)) {
		return 0;
	}
	err = verify_hdr(view, vtype);
	if (err) {
		return err;
	}
	err = verify_checksum(view, md);
	if (err) {
		return err;
	}
	err = verify_sub(view, vtype);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_verify_meta(const struct voluta_vnode_info *vi)
{
	const struct voluta_vaddr *vaddr = vi_vaddr(vi);

	return verify_view(vi->view, vaddr->vtype, vi_mdigest(vi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


void voluta_stamp_view(struct voluta_view *view,
                       const struct voluta_vaddr *vaddr)
{
	struct voluta_header *hdr = hdr_of(view);

	voluta_memzero(view, vaddr->len);
	hdr_stamp(hdr, vaddr->vtype, vaddr->len);
}

static void seal_meta_vnode(const struct voluta_vnode_info *vi)
{
	uint32_t csum;
	struct voluta_header *hdr = hdr_of(vi->view);

	csum = calc_chekcsum_of(vi);
	hdr_set_csum(hdr, csum);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool voluta_vi_isdata(const struct voluta_vnode_info *vi)
{
	return voluta_vtype_isdata(vi_vtype(vi));
}


static const struct voluta_cipher *
vi_cipher(const struct voluta_vnode_info *vi)
{
	return &vi->v_sbi->sb_vstore->vs_crypto.ci;
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
                                 struct voluta_repo *repo)
{
	struct voluta_baddr baddr;

	voluta_assert_gt(sgv->cnt, 0);
	baddr_setup(&baddr, &sgv->bid, sgv->len, sgv->off);
	return voluta_repo_storev_blob(repo, &baddr, sgv->iov, sgv->cnt);
}

static int sgv_flush_dset(struct voluta_sgvec *sgv,
                          const struct voluta_dset *dset,
                          struct voluta_vstore *vstore,
                          struct voluta_repo *repo)
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
		err = sgv_destage_into_blob(sgv, repo);
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
			seal_meta_vnode(vi);
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
                      struct voluta_repo *repo)
{
	struct voluta_sgvec sgv;
	struct voluta_iobuf iob;

	return vstore_encryptwr(vstore) ?
	       iob_flush_dset(&iob, dset, vstore) :
	       sgv_flush_dset(&sgv, dset, vstore, repo);
}

static int dset_collect_flush(struct voluta_dset *dset,
                              const struct voluta_cache *cache,
                              struct voluta_vstore *vstore,
                              struct voluta_repo *repo)
{
	int err;

	dset_inhabit(dset, cache);
	dset_make_fifo(dset);
	dset_seal_meta(dset);
	err = dset_flush(dset, vstore, repo);
	dset_cleanup(dset);
	return err;
}

int voluta_vstore_flush(struct voluta_vstore *vstore, struct voluta_repo *repo,
                        const struct voluta_cache *cache, long ds_key)
{
	int err;
	struct voluta_dset dset;

	dset_init(&dset, ds_key);
	err = dset_collect_flush(&dset, cache, vstore, repo);
	dset_fini(&dset);
	return err;
}
