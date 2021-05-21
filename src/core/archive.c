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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <voluta/core/private.h>

#include "libvoluta.h"

#define BSTORE_NSUBDIRS         256
#define BSTORE_ROOTINDEX        UINT_MAX


static loff_t off_mega(loff_t off)
{
	return off / VOLUTA_MEGA;
}

static loff_t off_end_mega(loff_t off, size_t len)
{
	return off_mega(off_end(off, len));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* blob-storage I/O-control */
struct voluta_bstore {
	loff_t  bs_vsz;
	int     bs_vfd;
	int     bs_dfd;
};

static int bstore_init(struct voluta_bstore *bstore)
{
	bstore->bs_vsz = -1;
	bstore->bs_vfd = -1;
	bstore->bs_dfd = -1;
	return 0;
}

static int bstore_close(struct voluta_bstore *bstore)
{
	int status;
	int err = 0;

	status = voluta_sys_closefd(&bstore->bs_vfd);
	err = err ? err : status;

	status = voluta_sys_closefd(&bstore->bs_dfd);
	err = err ? err : status;

	return err;
}

static void bstore_fini(struct voluta_bstore *bstore)
{
	bstore_close(bstore);
}


static int bstore_open_volume(struct voluta_bstore *bstore, const char *path)
{
	return voluta_sys_open(path, O_RDONLY, 0, &bstore->bs_vfd);
}

static int bstore_create_volume(struct voluta_bstore *bstore, const char *path)
{
	const mode_t mode = S_IFREG | S_IRUSR | S_IWUSR;

	return voluta_sys_open(path, O_CREAT | O_RDWR, mode, &bstore->bs_vfd);
}

static int bstore_open_bucket(struct voluta_bstore *bstore, const char *path)
{
	return voluta_sys_opendir(path, &bstore->bs_dfd);
}

static int bstore_resolve_volsize(struct voluta_bstore *bstore)
{
	int err;
	struct stat st;

	err = voluta_sys_fstat(bstore->bs_vfd, &st);
	if (!err) {
		bstore->bs_vsz = st.st_size;
	}
	return err;
}

static int bstore_open_for_export(struct voluta_bstore *bstore,
                                  const char *vpath, const char *bpath)
{
	int err;

	err = bstore_open_volume(bstore, vpath);
	if (err) {
		goto out;
	}
	err = bstore_resolve_volsize(bstore);
	if (err) {
		goto out;
	}
	err = bstore_open_bucket(bstore, bpath);
	if (err) {
		goto out;
	}
out:
	if (err) {
		bstore_close(bstore);
	}
	return err;
}

static int bstore_open_for_import(struct voluta_bstore *bstore,
                                  const char *vpath, const char *bpath)
{
	int err;

	err = bstore_create_volume(bstore, vpath);
	if (err) {
		goto out;
	}
	err = bstore_open_bucket(bstore, bpath);
	if (err) {
		goto out;
	}
out:
	if (err) {
		bstore_close(bstore);
	}
	return err;
}

static int bstore_resize(struct voluta_bstore *bstore, loff_t vsz)
{
	int err;

	err = voluta_sys_ftruncate(bstore->bs_vfd, vsz);
	if (err) {
		return err;
	}
	bstore->bs_vsz = vsz;
	return 0;
}

static int bstore_expand(struct voluta_bstore *bstore, loff_t vsz)
{
	return (vsz > bstore->bs_vsz) ? bstore_resize(bstore, vsz) : 0;
}

static int bstore_read_v2x(const struct voluta_bstore *bstore,
                           void *buf, size_t bsz, loff_t voff)
{
	return voluta_sys_preadn(bstore->bs_vfd, buf, bsz, voff);
}

static int bstore_write_x2v(const struct voluta_bstore *bstore,
                            const void *buf, size_t bsz, loff_t voff)
{
	return voluta_sys_pwriten(bstore->bs_vfd, buf, bsz, voff);
}

static void make_idxname(struct voluta_namebuf *nb, size_t idx)
{
	const size_t nsubs = BSTORE_NSUBDIRS;

	snprintf(nb->name, sizeof(nb->name) - 1, "%02x", (int)(idx % nsubs));
}

static int bstore_open_subdir(const struct voluta_bstore *bstore,
                              size_t idx, bool mk, int *out_dfd_sub)
{
	int err;
	const int dfd = bstore->bs_dfd;
	struct voluta_namebuf nb;

	make_idxname(&nb, idx);
	err = voluta_sys_opendirat(dfd, nb.name, out_dfd_sub);
	if (!err) {
		return 0;
	}
	if (err != -ENOENT) {
		return err;
	}
	if (!mk) {
		return -ENOENT;
	}
	err = voluta_sys_mkdirat(dfd, nb.name, 0700);
	if (err) {
		return err;
	}
	err = voluta_sys_opendirat(dfd, nb.name, out_dfd_sub);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_grab_dfd(const struct voluta_bstore *bstore,
                           size_t idx, bool mk, int *out_dfd)
{
	int err;

	if (idx == BSTORE_ROOTINDEX) {
		*out_dfd = bstore->bs_dfd;
		err = 0;
	} else {
		err = bstore_open_subdir(bstore, idx, mk, out_dfd);
	}
	return err;
}

static void bstore_done_fds(const struct voluta_bstore *bstore, int *dfd,
                            int *fd)
{
	voluta_sys_closefd(fd);
	if (dfd && (*dfd != bstore->bs_dfd)) {
		voluta_sys_closefd(dfd);
	}
}

static int bstore_store_x2d(const struct voluta_bstore *bstore, size_t idx,
                            const char *name, const void *buf, size_t bsz)
{
	int err;
	int fd = -1;
	int dfd = -1;

	err = bstore_grab_dfd(bstore, idx, true, &dfd);
	if (err) {
		return err;
	}
	err = voluta_sys_unlinkat(dfd, name, 0);
	if (err && (err != -ENOENT)) {
		goto out;
	}
	err = voluta_sys_openat(dfd, name, O_CREAT | O_WRONLY, 0600, &fd);
	if (err) {
		goto out;
	}
	err = voluta_sys_fchmodat(dfd, name, S_IRUSR, 0);
	if (err) {
		goto out;
	}
	err = voluta_sys_pwriten(fd, buf, bsz, 0);
	if (err) {
		goto out;
	}
out:
	bstore_done_fds(bstore, &dfd, &fd);
	return err;
}

static int bstore_store_root(const struct voluta_bstore *bstore,
                             const char *name, const void *buf, size_t bsz)
{
	return bstore_store_x2d(bstore, BSTORE_ROOTINDEX, name, buf, bsz);
}

static int bstore_load_d2x(const struct voluta_bstore *bstore, size_t idx,
                           const char *name, void *buf, size_t bsz)
{
	int err;
	int fd = -1;
	int dfd = -1;

	err = bstore_grab_dfd(bstore, idx, false, &dfd);
	if (err) {
		return err;
	}
	err = voluta_sys_openat(dfd, name, O_RDONLY, 0600, &fd);
	if (err) {
		goto out;
	}
	err = voluta_sys_preadn(fd, buf, bsz, 0);
	if (err) {
		goto out;
	}
out:
	bstore_done_fds(bstore, &dfd, &fd);
	return err;
}

static int bstore_clone_v2d(const struct voluta_bstore *bstore, size_t idx,
                            const char *name, loff_t voff, size_t bsz)
{
	int err;
	int fd = -1;
	int dfd = -1;
	loff_t off = voff;
	size_t ncp = 0;

	err = bstore_grab_dfd(bstore, idx, true, &dfd);
	if (err) {
		return err;
	}
	err = voluta_sys_openat(dfd, name, O_CREAT | O_WRONLY, 0600, &fd);
	if (err) {
		goto out;
	}
	err = voluta_sys_copy_file_range(bstore->bs_vfd, &off, fd,
	                                 NULL, bsz, 0, &ncp);
	if (err) {
		goto out;
	}
	if (ncp != bsz) {
		err = -EIO;
	}
out:
	bstore_done_fds(bstore, &dfd, &fd);
	return err;
}

static int bstore_clone_d2v(const struct voluta_bstore *bstore, size_t idx,
                            const char *name, loff_t voff, size_t bsz)
{
	int err;
	int fd = -1;
	int dfd = -1;
	loff_t off = voff;
	size_t ncp = 0;

	err = bstore_grab_dfd(bstore, idx, false, &dfd);
	if (err) {
		return err;
	}
	err = voluta_sys_openat(dfd, name, O_RDONLY, 0600, &fd);
	if (err) {
		goto out;
	}
	err = voluta_sys_copy_file_range(fd, NULL, bstore->bs_vfd,
	                                 &off, bsz, 0, &ncp);
	if (err) {
		goto out;
	}
	if (ncp != bsz) {
		err = -EIO;
	}
out:
	bstore_done_fds(bstore, &dfd, &fd);
	return err;
}

static int bstore_load_root(const struct voluta_bstore *bstore,
                            const char *name, void *buf, size_t bsz)
{
	return bstore_load_d2x(bstore, BSTORE_ROOTINDEX, name, buf, bsz);
}

static int bstore_stat_blob(const struct voluta_bstore *bstore, size_t idx,
                            const char *name, size_t *out_bsz)
{
	int err;
	int dfd = -1;
	struct stat st;

	err = bstore_grab_dfd(bstore, idx, false, &dfd);
	if (err) {
		return err;
	}
	err = voluta_sys_fstatat(dfd, name, &st, 0);
	if (err) {
		goto out;
	}
	if (!S_ISREG(st.st_mode)) {
		err = -EINVAL;
		goto out;
	}
	*out_bsz = (size_t)st.st_size;
out:
	bstore_done_fds(bstore, &dfd, NULL);
	return err;
}

static int bstore_stat_root(const struct voluta_bstore *bstore,
                            const char *name, size_t *out_size)
{
	return bstore_stat_blob(bstore, BSTORE_ROOTINDEX, name, out_size);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#define ROUND_TO_K(n)  VOLUTA_ROUND_TO(n, 1024)

struct voluta_ar_core {
	struct voluta_qalloc    qalloc;
	struct voluta_crypto    crypto;
	struct voluta_bstore    bstore;
};

union voluta_ar_core_u {
	struct voluta_ar_core c;
	uint8_t dat[ROUND_TO_K(sizeof(struct voluta_ar_core))];
};

struct voluta_archiver_obj {
	union voluta_ar_core_u  ar_core;
	struct voluta_archiver  arc;
};


struct voluta_ar_blob_info {
	struct voluta_hash256   b_hash;
	struct voluta_namebuf   b_name;
	struct voluta_ar_blob  *blob;
	uint16_t                b_xbin;
	loff_t                  b_voff;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t arm_nents(const struct voluta_meta_block4 *arm)
{
	return voluta_le64_to_cpu(arm->sb_ar_nents);
}

static void arm_set_nents(struct voluta_meta_block4 *arm, size_t nents)
{
	arm->sb_ar_nents = voluta_cpu_to_le64(nents);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void hash256_reset(struct voluta_hash256 *hash)
{
	memset(hash, 0, sizeof(*hash));
}

static void hash256_assign(struct voluta_hash256 *hash,
                           const struct voluta_hash256 *other)
{
	memcpy(hash, other, sizeof(*hash));
}

static uint16_t hash256_to_u16(const struct voluta_hash256 *hash)
{
	uint32_t u = 0;

	for (size_t i = 0; i < ARRAY_SIZE(hash->hash); i += 2) {
		u ^= hash->hash[i];
		u ^= (uint32_t)(hash->hash[i + 1]) << 8;
	}
	return (uint16_t)u;
}

static char byte_to_ascii(uint8_t byte, int hi)
{
	const char *xdigits = "0123456789abcdef";
	const size_t pos = hi ? byte >> 4 : byte;

	return xdigits[pos & 0x0F];
}

static void hash256_to_name(const struct voluta_hash256 *hash,
                            struct voluta_namebuf *nbuf)
{
	uint8_t byte;
	size_t len = 0;

	STATICASSERT_GT(sizeof(nbuf->name), 2 * ARRAY_SIZE(hash->hash));

	for (size_t i = 0; i < ARRAY_SIZE(hash->hash); ++i) {
		byte = hash->hash[i];
		nbuf->name[len++] = byte_to_ascii(byte, 1);
		nbuf->name[len++] = byte_to_ascii(byte, 0);
	}
	nbuf->name[len] = '\0';
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void bref_set_magic(struct voluta_ar_blobref *bref, uint32_t magic)
{
	bref->br_magic = voluta_cpu_to_le32(magic);
}

static void bref_set_hfunc(struct voluta_ar_blobref *bref, int hfunc)
{
	bref->br_hfunc = voluta_cpu_to_le16((uint16_t)hfunc);
}

static size_t bref_length(const struct voluta_ar_blobref *bref)
{
	return voluta_le32_to_cpu(bref->br_length);
}

static void bref_set_length(struct voluta_ar_blobref *bref, size_t len)
{
	bref->br_length = voluta_cpu_to_le32((uint32_t)len);
}

static loff_t bref_voff(const struct voluta_ar_blobref *bref)
{
	return voluta_off_to_cpu(bref->br_voff);
}

static void bref_set_voff(struct voluta_ar_blobref *bref, loff_t voff)
{
	bref->br_voff = voluta_cpu_to_off(voff);
}

static void bref_init(struct voluta_ar_blobref *bref, loff_t voff, size_t len)
{
	voluta_memzero(bref, sizeof(*bref));
	bref_set_magic(bref, VOLUTA_VTYPE_MAGIC);
	bref_set_hfunc(bref, VOLUTA_MD_SHA256);
	bref_set_length(bref, len);
	bref_set_voff(bref, voff);
}

static void bref_set_hash(struct voluta_ar_blobref *bref,
                          const struct voluta_hash256 *hash)
{
	hash256_assign(&bref->br_hash, hash);
}

static void bref_copyto(const struct voluta_ar_blobref *bref,
                        struct voluta_ar_blobref *other)
{
	memcpy(other, bref, sizeof(*other));
}

static uint16_t bref_xbin(const struct voluta_ar_blobref *bref)
{
	return voluta_le16_to_cpu(bref->br_xbin);
}

static void bref_set_xbin(struct voluta_ar_blobref *bref, uint16_t xbin)
{
	bref->br_xbin = voluta_cpu_to_le16(xbin);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/*
 * TODO-0021: Use multihash formats for blob names?
 *
 * https://multiformats.io
 * https://github.com/multiformats/multicodec/
 */
static void calc_hash_of(const struct voluta_mdigest *md, const void *dat,
                         size_t len, struct voluta_hash256 *out_hash)
{
	voluta_sha256_of(md, dat, len, out_hash);
}


static struct voluta_ar_blob *blob_new(struct voluta_qalloc *qal)
{
	struct voluta_ar_blob *blob;

	blob = voluta_qalloc_malloc(qal, sizeof(*blob));
	return blob;
}

static void blob_del(struct voluta_ar_blob *blob, struct voluta_qalloc *qal)
{
	voluta_qalloc_free(qal, blob, sizeof(*blob));
}

static void bli_reset(struct voluta_ar_blob_info *bli)
{
	hash256_reset(&bli->b_hash);
	bli->b_name.name[0] = '\0';
	bli->b_voff = -1;
}

static void bli_init(struct voluta_ar_blob_info *bli,
                     struct voluta_ar_blob *blob)
{
	bli_reset(bli);
	bli->blob = blob;
}

static void bli_fini(struct voluta_ar_blob_info *bli)
{
	bli_reset(bli);
	bli->blob = NULL;
}

static struct voluta_ar_blob_info *bli_new(struct voluta_qalloc *qal)
{
	struct voluta_ar_blob *blob;
	struct voluta_ar_blob_info *bli;

	blob = blob_new(qal);
	if (blob == NULL) {
		return NULL;
	}
	bli = voluta_qalloc_zmalloc(qal, sizeof(*bli));
	if (bli == NULL) {
		blob_del(blob, qal);
		return NULL;
	}
	bli_init(bli, blob);
	return bli;
}

static void bli_del(struct voluta_ar_blob_info *bli, struct voluta_qalloc *qal)
{
	struct voluta_ar_blob *blob = bli->blob;

	bli_fini(bli);
	blob_del(blob, qal);
	voluta_qalloc_free(qal, bli, sizeof(*bli));
}

static void bli_reassign_name(struct voluta_ar_blob_info *bli)
{
	hash256_to_name(&bli->b_hash, &bli->b_name);
}

static void bli_update(struct voluta_ar_blob_info *bli,
                       const struct voluta_mdigest *md)
{
	struct voluta_hash256 *hash = &bli->b_hash;
	const struct voluta_ar_blob *blob = bli->blob;

	calc_hash_of(md, blob->b, sizeof(blob->b), hash);
	bli_reassign_name(bli);
	bli->b_xbin = hash256_to_u16(hash);
}

static void bli_to_bref(const struct voluta_ar_blob_info *bli,
                        struct voluta_ar_blobref *bref)
{
	bref_init(bref, bli->b_voff, sizeof(*bli->blob));
	bref_set_hash(bref, &bli->b_hash);
	bref_set_xbin(bref, bli->b_xbin);
}

static int bli_from_bref(struct voluta_ar_blob_info *bli,
                         const struct voluta_ar_blobref *bref)
{
	const size_t len = bref_length(bref);
	const size_t bsz = sizeof(*bli->blob);

	if (len != bsz) {
		return -EFSCORRUPTED;
	}
	bli->b_voff = bref_voff(bref);
	bli->b_xbin = bref_xbin(bref);
	hash256_assign(&bli->b_hash, &bref->br_hash);
	bli_reassign_name(bli);
	return 0;
}

static loff_t bli_next_voff(const struct voluta_ar_blob_info *bli)
{
	loff_t next = -1;

	if (bli->b_voff >= 0) {
		next = off_next(bli->b_voff, sizeof(*bli->blob));
	}
	return next;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_mdigest *
arc_mdigest(const struct voluta_archiver *arc)
{
	return &arc->ar_crypto->md;
}

static int arc_read_blob(const struct voluta_archiver *arc,
                         struct voluta_ar_blob_info *bli, loff_t voff)
{
	struct voluta_ar_blob *blob = bli->blob;

	bli->b_voff = voff;
	return bstore_read_v2x(arc->ar_bstore, blob, sizeof(*blob), voff);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t spec_nents_per_bk(void)
{
	const struct voluta_ar_blobrefs *brefs = NULL;

	return ARRAY_SIZE(brefs->ar_bref);
}

static size_t spec_nents_max(size_t nents)
{
	const size_t nents_per_bk = spec_nents_per_bk();

	return div_round_up(nents, nents_per_bk) * nents_per_bk;
}

static size_t spec_size_of(size_t nents)
{
	size_t size;
	size_t nbrefs;
	const struct voluta_ar_spec *spec = NULL;
	const struct voluta_ar_blobrefs *brefs = NULL;
	const size_t nents_in_bref = ARRAY_SIZE(brefs->ar_bref);

	nbrefs = div_round_up(nents, nents_in_bref);
	size = sizeof(*spec) + (nbrefs * sizeof(*brefs));
	voluta_assert_eq(size % VOLUTA_BK_SIZE, 0);

	return size;
}

static size_t spec_nents_of(size_t size)
{
	size_t nents = 0;
	const struct voluta_ar_spec *spec = NULL;
	const struct voluta_ar_blobrefs *brefs = NULL;
	const size_t spec_size = sizeof(*spec);
	const size_t bref_size = sizeof(brefs->ar_bref[0]);

	if (size > spec_size) {
		nents += (size - spec_size) / bref_size;
	}
	return nents;
}

static struct voluta_ar_spec *
spec_new(struct voluta_qalloc *qal, size_t nents)
{
	struct voluta_ar_spec *spec;

	spec = voluta_qalloc_zmalloc(qal, spec_size_of(nents));
	return spec;
}

static void spec_del(struct voluta_qalloc *qal,
                     struct voluta_ar_spec *spec, size_t nents)
{
	voluta_qalloc_free(qal, spec, spec_size_of(nents));
}

static struct voluta_ar_spec *
spec_xclone(struct voluta_qalloc *qal,
            const struct voluta_ar_spec *spec, size_t nents, size_t xnents)
{
	struct voluta_ar_spec *xspec;

	xspec = spec_new(qal, xnents);
	if (xspec != NULL) {
		memcpy(xspec, spec, spec_size_of(nents));
	}
	return xspec;
}

static struct voluta_ar_spec_brefs *
spec_to_brefs(const struct voluta_ar_spec *spec_const)
{
	struct voluta_ar_spec *spec = unconst(spec_const);

	return container_of(spec, struct voluta_ar_spec_brefs, spec);
}

static struct voluta_ar_blobref *
spec_bref_at(const struct voluta_ar_spec *spec, size_t ent_index)
{
	const struct voluta_ar_blobref *bref = NULL;
	struct voluta_ar_spec_brefs *brefs = spec_to_brefs(spec);

	bref = &brefs->brefs.ar_bref[ent_index];
	return unconst(bref);
}

static void spec_append_bref(struct voluta_ar_spec *spec, size_t ent_index,
                             const struct voluta_ar_blobref *bref)
{
	struct voluta_ar_blobref *dst_bref = spec_bref_at(spec, ent_index);

	bref_copyto(bref, dst_bref);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_archiver_obj *
archive_obj_of(struct voluta_archiver *arc)
{
	return container_of(arc, struct voluta_archiver_obj, arc);
}

static int arc_init_qalloc(struct voluta_archiver *arc, size_t memwant)
{
	int err;
	struct voluta_qalloc *qalloc =
	        &archive_obj_of(arc)->ar_core.c.qalloc;

	err = voluta_setup_qalloc_with(qalloc, memwant);
	if (!err) {
		arc->ar_qalloc = qalloc;
	}
	return err;
}

static void arc_fini_qalloc(struct voluta_archiver *arc)
{
	if (arc->ar_qalloc != NULL) {
		voluta_qalloc_fini(arc->ar_qalloc);
		arc->ar_qalloc = NULL;
	}
}

static int arc_init_crypto(struct voluta_archiver *arc)
{
	int err;
	struct voluta_crypto *crypto =
	        &archive_obj_of(arc)->ar_core.c.crypto;

	err = voluta_crypto_init(crypto);
	if (!err) {
		arc->ar_crypto = crypto;
	}
	return err;
}

static void arc_fini_crypto(struct voluta_archiver *arc)
{
	if (arc->ar_crypto != NULL) {
		voluta_crypto_fini(arc->ar_crypto);
		arc->ar_crypto = NULL;
	}
}

static int arc_init_bstore(struct voluta_archiver *arc)
{
	int err;
	struct voluta_bstore *bstore =
	        &archive_obj_of(arc)->ar_core.c.bstore;

	err = bstore_init(bstore);
	if (!err) {
		arc->ar_bstore = bstore;
	}
	return err;
}

static void arc_fini_bstore(struct voluta_archiver *arc)
{
	if (arc->ar_bstore != NULL) {
		bstore_fini(arc->ar_bstore);
		arc->ar_bstore = NULL;
	}
}

static int arc_init_blob(struct voluta_archiver *arc)
{
	arc->ar_bli = bli_new(arc->ar_qalloc);

	return (arc->ar_bli == NULL) ? -ENOMEM : 0;
}

static void arc_fini_blob(struct voluta_archiver *arc)
{
	if (arc->ar_bli != NULL) {
		bli_del(arc->ar_bli, arc->ar_qalloc);
		arc->ar_bli = NULL;
	}
}

static void arc_setup_rands(const struct voluta_archiver *arc)
{
	struct voluta_ar_spec *spec = arc->ar_spec;

	for (size_t i = 0; i < ARRAY_SIZE(spec->ar_rand); ++i) {
		voluta_hrec_setup(&spec->ar_rand[i], arc_mdigest(arc));
	}
}

static int arc_init_spec(struct voluta_archiver *arc, size_t nents)
{
	size_t size;
	struct voluta_ar_spec *spec;

	arc->ar_spec_nents = 0;
	arc->ar_spec_nents_max = spec_nents_max(nents);

	spec = spec_new(arc->ar_qalloc, arc->ar_spec_nents_max);
	if (spec == NULL) {
		return -ENOMEM;
	}
	arc->ar_spec = spec;

	size = spec_size_of(nents);
	voluta_br_init(&spec->ar_zero, VOLUTA_ZTYPE_ARCHIVE, size);
	arm_set_nents(&spec->ar_meta, nents);
	arc_setup_rands(arc);
	return 0;
}

static void arc_fini_spec(struct voluta_archiver *arc)
{
	if (arc->ar_spec != NULL) {
		spec_del(arc->ar_qalloc, arc->ar_spec, arc->ar_spec_nents_max);
		arc->ar_spec_nents = 0;
		arc->ar_spec_nents_max = 0;
	}
}

static int arc_init(struct voluta_archiver *arc)
{
	int err;
	const size_t memwant = arc->ar_args.memwant;

	arc->try_clone = 1;
	voluta_kivam_init(&arc->ar_kivam);

	err = arc_init_qalloc(arc, memwant);
	if (err) {
		return err;
	}
	err = arc_init_crypto(arc);
	if (err) {
		return err;
	}
	err = arc_init_bstore(arc);
	if (err) {
		return err;
	}
	err = arc_init_blob(arc);
	if (err) {
		return err;
	}
	err = arc_init_spec(arc, 1);
	if (err) {
		return err;
	}
	return 0;
}

static void arc_fini(struct voluta_archiver *arc)
{
	arc_fini_spec(arc);
	arc_fini_blob(arc);
	arc_fini_bstore(arc);
	arc_fini_crypto(arc);
	arc_fini_qalloc(arc);
	voluta_kivam_fini(&arc->ar_kivam);
}

static int arc_setargs(struct voluta_archiver *arc,
                       const struct voluta_ar_args *args)
{
	/* TODO: check, strdup */
	memcpy(&arc->ar_args, args, sizeof(arc->ar_args));
	return 0;
}

int voluta_archiver_new(const struct voluta_ar_args *args,
                        struct voluta_archiver **out_arc)
{
	int err;
	void *mem = NULL;
	struct voluta_archiver *arc = NULL;
	struct voluta_archiver_obj *arc_obj = NULL;

	err = voluta_zalloc_aligned(sizeof(*arc_obj), &mem);
	if (err) {
		return err;
	}
	arc_obj = mem;
	arc = &arc_obj->arc;

	err = arc_setargs(arc, args);
	if (err) {
		free(mem);
		return err;
	}
	err = arc_init(arc);
	if (err) {
		arc_fini(arc);
		free(mem);
		return err;
	}
	*out_arc = arc;
	voluta_burnstack();
	return 0;
}

void voluta_archiver_del(struct voluta_archiver *arc)
{
	struct voluta_archiver_obj *arc_obj;

	arc_obj = archive_obj_of(arc);
	arc_fini(arc);

	memset(arc_obj, 11, sizeof(*arc_obj));
	free(arc_obj);
	voluta_burnstack();
}

static int arc_open_for_export(struct voluta_archiver *arc, loff_t *out_vsize)
{
	int err;
	const char *volume = arc->ar_args.volume;
	const char *bucket = arc->ar_args.blobsdir;

	err = bstore_open_for_export(arc->ar_bstore, volume, bucket);
	if (err) {
		log_dbg("open bstore failed: volume=%s bucket=%s err=%d",
		        volume, bucket, err);
		return err;
	}
	err = voluta_calc_vsize(arc->ar_bstore->bs_vsz, 0, out_vsize);
	if (err) {
		log_dbg("illegal vsize: %ld", arc->ar_bstore->bs_vsz);
		return err;
	}
	return 0;
}

static int arc_open_for_import(struct voluta_archiver *arc)
{
	int err;
	const char *volume = arc->ar_args.volume;
	const char *bucket = arc->ar_args.blobsdir;

	err = bstore_open_for_import(arc->ar_bstore, volume, bucket);
	if (err) {
		log_dbg("open bstore failed: volume=%s bucket=%s err=%d",
		        volume, bucket, err);
	}
	return err;
}

static int arc_close(struct voluta_archiver *arc)
{
	int err;

	err = bstore_close(arc->ar_bstore);
	if (err) {
		log_dbg("close bstore failed: volume=%s bucket=%s err=%d",
		        arc->ar_args.volume, arc->ar_args.blobsdir, err);
	}
	return err;
}

static int arc_setup_keys(struct voluta_archiver *arc)
{
	int err = 0;
	struct voluta_zcrypt_params zcp;
	struct voluta_passphrase passph;
	const struct voluta_mdigest *md = arc_mdigest(arc);

	if (arc->ar_args.passwd == NULL) {
		return 0;
	}
	err = voluta_passphrase_setup(&passph, arc->ar_args.passwd);
	if (err) {
		return err;
	}
	voluta_br_crypt_params(&arc->ar_spec->ar_zero, &zcp);
	err = voluta_derive_kivam(&zcp, &passph, md, &arc->ar_kivam);
	if (err) {
		return err;
	}
	voluta_passphrase_reset(&passph);
	return 0;
}

static int arc_require_room(struct voluta_archiver *arc)
{
	size_t xnents;
	struct voluta_ar_spec *xspec;

	if (arc->ar_spec_nents < arc->ar_spec_nents_max) {
		return 0;
	}
	xnents = spec_nents_max(arc->ar_spec_nents_max + 1);
	xspec = spec_xclone(arc->ar_qalloc, arc->ar_spec,
	                    arc->ar_spec_nents, xnents);
	if (xspec == NULL) {
		return -ENOMEM;
	}
	spec_del(arc->ar_qalloc, arc->ar_spec, arc->ar_spec_nents);
	arc->ar_spec = xspec;
	arc->ar_spec_nents_max = xnents;
	return 0;
}

static int arc_append_bref(struct voluta_archiver *arc,
                           const struct voluta_ar_blob_info *bli)
{
	int err;
	struct voluta_ar_blobref bref;

	err = arc_require_room(arc);
	if (err) {
		return err;
	}
	bli_to_bref(bli, &bref);
	spec_append_bref(arc->ar_spec, arc->ar_spec_nents++, &bref);
	return 0;
}

static int arc_stat_blob(const struct voluta_archiver *arc,
                         const struct voluta_ar_blob_info *bli)
{
	int err;
	size_t len = 0;
	const size_t bsz = sizeof(*bli->blob);
	const size_t idx = bli->b_xbin;
	const char *name = bli->b_name.name;

	err = bstore_stat_blob(arc->ar_bstore, idx, name, &len);
	if (!err) {
		if (len == bsz) {
			log_info("blob-exists: %s", name);
		} else {
			log_info("wrong-blob-size: %s size=%lu", name, len);
			err = -ENOENT;
		}
	} else if (err != -ENOENT) {
		log_warn("stat-blob: %s err=%d", name, err);
	}
	return err;
}

static int arc_clone_blob(struct voluta_archiver *arc,
                          const struct voluta_ar_blob_info *bli)
{
	int err;
	const loff_t voff = bli->b_voff;
	const size_t bsz = sizeof(*bli->blob);
	const size_t idx = bli->b_xbin;
	const char *name = bli->b_name.name;

	if (!arc->try_clone) {
		return -EOPNOTSUPP;
	}
	log_info("clone-blob: %s %ldM..%ldM", name,
	         off_mega(voff), off_end_mega(voff, bsz));
	err = bstore_clone_v2d(arc->ar_bstore, idx, name, voff, bsz);
	if (err == -EOPNOTSUPP) {
		arc->try_clone = 0;
	}
	return err;
}

static int arc_store_blob(const struct voluta_archiver *arc,
                          const struct voluta_ar_blob_info *bli)
{
	const loff_t voff = bli->b_voff;
	const size_t bsz = sizeof(*bli->blob);
	const size_t idx = bli->b_xbin;
	const char *name = bli->b_name.name;

	log_info("store-blob: %s %ldM..%ldM", name,
	         off_mega(voff), off_end_mega(voff, bsz));
	return bstore_store_x2d(arc->ar_bstore, idx, name, bli->blob, bsz);
}

static int arc_save_blob(struct voluta_archiver *arc,
                         const struct voluta_ar_blob_info *bli)
{
	int err;

	err = arc_stat_blob(arc, bli);
	if (err != -ENOENT) {
		return err;
	}
	err = arc_clone_blob(arc, bli);
	if (err != -EOPNOTSUPP) {
		return err;
	}
	err = arc_store_blob(arc, bli);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_export_blobs(struct voluta_archiver *arc, loff_t vsize)
{
	int err;
	loff_t voff = 0;
	struct voluta_ar_blob_info *bli = arc->ar_bli;

	arc->ar_spec_nents = 0;
	while (voff < vsize) {
		bli_reset(bli);
		err = arc_read_blob(arc, bli, voff);
		if (err) {
			return err;
		}
		bli_update(bli, arc_mdigest(arc));

		err = arc_save_blob(arc, bli);
		if (err) {
			return err;
		}
		err = arc_append_bref(arc, bli);
		if (err) {
			return err;
		}
		voff = bli_next_voff(bli);
		voluta_assert_gt(voff, 0);
	}
	return 0;
}

static int arc_export_spec(const struct voluta_archiver *arc, loff_t vsize)
{
	size_t spec_size;
	const char *name = arc->ar_args.arcname;
	struct voluta_ar_spec *spec = arc->ar_spec;

	voluta_br_set_size(&spec->ar_zero, (size_t)vsize);
	arm_set_nents(&spec->ar_meta, arc->ar_spec_nents);
	arc_setup_rands(arc);

	spec_size = spec_size_of(arc->ar_spec_nents);
	return bstore_store_root(arc->ar_bstore, name, spec, spec_size);
}

int voluta_archiver_export(struct voluta_archiver *arc)
{
	int err;
	loff_t vsize = -1;

	err = arc_open_for_export(arc, &vsize);
	if (err) {
		return err;
	}
	err = arc_setup_keys(arc);
	if (err) {
		goto out;
	}
	err = arc_export_blobs(arc, vsize);
	if (err) {
		goto out;
	}
	err = arc_export_spec(arc, vsize);
	if (err) {
		goto out;
	}
out:
	arc_close(arc);
	return err;
}

static int arc_find_blob(const struct voluta_archiver *arc,
                         const struct voluta_ar_blob_info *bli)
{
	int err;
	size_t len;
	struct voluta_ar_blob *blob = bli->blob;
	const size_t idx = bli->b_xbin;
	const size_t bsz = sizeof(*blob);
	const char *name = bli->b_name.name;

	err = bstore_stat_blob(arc->ar_bstore, idx, name, &len);
	if (err) {
		log_warn("blob-not-found: %s", blob);
		return err;
	}
	if (len != bsz) {
		log_warn("bad-blob-size: %s len=%lu", blob, len);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int arc_load_blob(const struct voluta_archiver *arc,
                         const struct voluta_ar_blob_info *bli)
{
	int err;
	struct voluta_ar_blob *blob = bli->blob;
	const size_t idx = bli->b_xbin;
	const size_t bsz = sizeof(*blob);
	const char *name = bli->b_name.name;

	err = arc_find_blob(arc, bli);
	if (err) {
		return err;
	}
	log_warn("load-blob: %s", name);
	err = bstore_load_d2x(arc->ar_bstore, idx, name, blob, bsz);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_write_blob(const struct voluta_archiver *arc,
                          const struct voluta_ar_blob_info *bli)
{
	int err;
	const loff_t voff = bli->b_voff;
	const struct voluta_ar_blob *blob = bli->blob;
	const size_t bsz = sizeof(*blob);
	const char *name = bli->b_name.name;

	err = bstore_expand(arc->ar_bstore, off_end(voff, bsz));
	if (err) {
		return err;
	}
	log_info("write-blob: %s %ldM..%ldM", name,
	         off_mega(voff), off_end_mega(voff, bsz));
	err = bstore_write_x2v(arc->ar_bstore, blob, bsz, voff);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_rclone_blob(struct voluta_archiver *arc,
                           const struct voluta_ar_blob_info *bli)
{
	int err;
	const loff_t voff = bli->b_voff;
	const size_t idx = bli->b_xbin;
	const size_t bsz = sizeof(*bli->blob);
	const char *name = bli->b_name.name;

	if (!arc->try_clone) {
		return -EOPNOTSUPP;
	}
	err = arc_find_blob(arc, bli);
	if (err) {
		return err;
	}
	err = bstore_expand(arc->ar_bstore, off_end(voff, bsz));
	if (err) {
		return err;
	}
	log_info("reclone-blob: %s %ldM..%ldM", name,
	         off_mega(voff), off_end_mega(voff, bsz));
	err = bstore_clone_d2v(arc->ar_bstore, idx, name, voff, bsz);
	if (err) {
		return err;
	}
	if (err == -EOPNOTSUPP) {
		arc->try_clone = 0;
	}
	return err;
}

static int arc_restore_blob(struct voluta_archiver *arc,
                            const struct voluta_ar_blob_info *bli)
{
	int err;

	err = arc_rclone_blob(arc, bli);
	if (err != -EOPNOTSUPP) {
		return err;
	}
	err = arc_load_blob(arc, bli);
	if (err) {
		return err;
	}
	err = arc_write_blob(arc, bli);
	if (err) {
		return err;
	}
	return 0;
}

static int arc_import_blobs(struct voluta_archiver *arc)
{
	int err;
	loff_t voff = 0;
	const struct voluta_ar_blobref *bref;
	struct voluta_ar_blob_info *bli = arc->ar_bli;

	for (size_t i = 0; i < arc->ar_spec_nents; ++i) {
		bli_reset(bli);

		bref = spec_bref_at(arc->ar_spec, i);
		err = bli_from_bref(bli, bref);
		if (err) {
			return err;
		}
		if (bli->b_voff < voff) {
			return -EFSCORRUPTED;
		}
		err = arc_restore_blob(arc, bli);
		if (err) {
			return err;
		}
		voff = bli->b_voff;
	}
	return 0;
}

static int arc_reinit_spec(struct voluta_archiver *arc, size_t nents)
{
	arc_fini_spec(arc);
	return arc_init_spec(arc, nents);
}

static int arc_check_rands(const struct voluta_archiver *arc)
{
	int err;
	const struct voluta_ar_spec *spec = arc->ar_spec;

	for (size_t i = 0; i < ARRAY_SIZE(spec->ar_rand); ++i) {
		err = voluta_hrec_check(&spec->ar_rand[i], arc_mdigest(arc));
		if (err) {
			return err;
		}
	}
	return 0;
}

static int arc_import_spec(struct voluta_archiver *arc)
{
	int err;
	size_t asize;
	size_t nents;
	const char *name = arc->ar_args.arcname;
	struct voluta_ar_spec *spec = arc->ar_spec;

	err = bstore_stat_root(arc->ar_bstore, name, &asize);
	if (err) {
		return err;
	}
	if (asize < sizeof(*arc->ar_spec)) {
		return -EFSCORRUPTED;
	}
	nents = spec_nents_of(asize);
	err = arc_reinit_spec(arc, nents);
	if (err) {
		return err;
	}
	err = bstore_load_root(arc->ar_bstore, name, spec, asize);
	if (err) {
		return err;
	}
	err = -1; /* XXX voluta_br_check(&spec->ar_zero); */
	voluta_assert_ok(err);
	if (err) {
		return err;
	}
	if (voluta_br_type(&spec->ar_zero) != VOLUTA_ZTYPE_ARCHIVE) {
		return -EINVAL;
	}
	err = arc_check_rands(arc);
	if (err) {
		return err;
	}
	nents = arm_nents(&spec->ar_meta);
	if (nents > arc->ar_spec_nents_max) {
		return -EFSCORRUPTED;
	}
	arc->ar_spec_nents = nents;

	return 0;
}

int voluta_archiver_import(struct voluta_archiver *arc)
{
	int err;

	err = arc_open_for_import(arc);
	if (err) {
		return err;
	}
	err = arc_setup_keys(arc);
	if (err) {
		goto out;
	}
	err = arc_import_spec(arc);
	if (err) {
		goto out;
	}
	err = arc_import_blobs(arc);
	if (err) {
		return err;
	}
out:
	arc_close(arc);
	return err;
}

