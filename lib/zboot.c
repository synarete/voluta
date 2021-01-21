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


static const struct voluta_kdf_pair voluta_default_kdf = {
	.kdf_iv.kd_algo = VOLUTA_KDF_PBKDF2,
	.kdf_iv.kd_subalgo = VOLUTA_MD_SHA256,
	.kdf_iv.kd_iterations = 4096,
	.kdf_key.kd_algo = VOLUTA_KDF_SCRYPT,
	.kdf_key.kd_subalgo = 8,
	.kdf_key.kd_iterations = 256
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t namelen_of(const char *name)
{
	return (name != NULL) ? strnlen(name, VOLUTA_NAME_MAX) : 0;
}

static void hash512_assign(struct voluta_hash512 *hash,
			   const struct voluta_hash512 *other)
{
	memcpy(hash, other, sizeof(*hash));
}

static bool hash512_isequal(const struct voluta_hash512 *hash,
			    const struct voluta_hash512 *other)
{
	return (memcmp(hash, other, sizeof(*hash)) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void kdf_to_cpu(const struct voluta_kdf_desc *kd_le,
		       struct voluta_kdf_desc *kd)
{
	kd->kd_algo = le32_to_cpu(kd_le->kd_algo);
	kd->kd_subalgo = le32_to_cpu(kd_le->kd_subalgo);
	kd->kd_iterations = le32_to_cpu(kd_le->kd_iterations);
}

static void cpu_to_kdf(const struct voluta_kdf_desc *kd,
		       struct voluta_kdf_desc *kd_le)
{
	kd_le->kd_algo = cpu_to_le32(kd->kd_algo);
	kd_le->kd_subalgo = cpu_to_le32(kd->kd_subalgo);
	kd_le->kd_iterations = cpu_to_le32(kd->kd_iterations);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t zb_marker(const struct voluta_zero_block *zb)
{
	return le64_to_cpu(zb->z_hdr.z_marker);
}

static void zb_set_marker(struct voluta_zero_block *zb, uint64_t mark)
{
	zb->z_hdr.z_marker = cpu_to_le64(mark);
}

static long zb_version(const struct voluta_zero_block *zb)
{
	return (long)le64_to_cpu(zb->z_hdr.z_version);
}

static void zb_set_version(struct voluta_zero_block *zb, long version)
{
	zb->z_hdr.z_version = cpu_to_le64((uint64_t)version);
}

static enum voluta_ztype zb_type(const struct voluta_zero_block *zb)
{
	return le16_to_cpu(zb->z_hdr.z_type);
}

static void zb_set_type(struct voluta_zero_block *zb, enum voluta_ztype type)
{
	zb->z_hdr.z_type = cpu_to_le16(type);
}

static enum voluta_zb_flags zb_flags(const struct voluta_zero_block *zb)
{
	const uint32_t flags = le32_to_cpu(zb->z_hdr.z_flags);

	return (enum voluta_zb_flags)flags;
}

static void zb_set_flags(struct voluta_zero_block *zb, enum voluta_zb_flags f)
{
	zb->z_hdr.z_flags = cpu_to_le32((uint32_t)f);
}

static void zd_add_flag(struct voluta_zero_block *zb, enum voluta_zb_flags f)
{
	zb_set_flags(zb, zb_flags(zb) | f);
}

static bool zb_test_flag(const struct voluta_zero_block *zb,
			 enum voluta_zb_flags f)
{
	return ((zb_flags(zb) & f) == f);
}

void voluta_zb_set_encrypted(struct voluta_zero_block *zb)
{
	zd_add_flag(zb, VOLUTA_ZBF_ENCRYPTED);
}

bool voluta_zb_is_encrypted(const struct voluta_zero_block *zb)
{
	return zb_test_flag(zb, VOLUTA_ZBF_ENCRYPTED);
}

enum voluta_zb_flags voluta_zb_flags(const struct voluta_zero_block *zb)
{
	return zb_flags(zb);
}

static void zb_set_sw_version(struct voluta_zero_block *zb,
			      const char *sw_version)
{
	const size_t len = strlen(sw_version);
	const size_t len_max = ARRAY_SIZE(zb->z_hdr.z_sw_version) - 1;

	memcpy(zb->z_hdr.z_sw_version, sw_version, min(len, len_max));
}

static void zb_set_uuid(struct voluta_zero_block *zb)
{
	voluta_uuid_generate(&zb->z_hdr.z_uuid);
}

size_t voluta_zb_size(const struct voluta_zero_block *zb)
{
	return le64_to_cpu(zb->z_hdr.z_size);
}

void voluta_zb_set_size(struct voluta_zero_block *zb, size_t size)
{
	zb->z_hdr.z_size = cpu_to_le64(size);
}

static struct voluta_zero_block_meta *
zb_meta(const struct voluta_zero_block *zb)
{
	const struct voluta_zero_block_meta *z_meta = &zb->z_meta;

	return unconst(z_meta);
}

void voluta_zb_kdf(const struct voluta_zero_block *zb,
		   struct voluta_kdf_pair *kdf)
{
	kdf_to_cpu(&zb->z_hdr.z_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&zb->z_hdr.z_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void zb_set_kdf(struct voluta_zero_block *zb,
		       const struct voluta_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &zb->z_hdr.z_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &zb->z_hdr.z_kdf_pair.kdf_key);
}

static void zb_fini(struct voluta_zero_block *zb)
{
	memset(zb, 0xFF, sizeof(*zb));
	zb_set_marker(zb, 0);
	voluta_zb_set_size(zb, 0);
}

void voluta_zb_set_name(struct voluta_zero_block *zb, const char *name)
{
	struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	if (name != NULL) {
		memcpy(z_meta->z_name.name, name, namelen_of(name));
	} else {
		memset(&z_meta->z_name, 0, sizeof(z_meta->z_name));
	}
}

const struct voluta_iv_key *
voluta_zb_iv_key(const struct voluta_zero_block *zb)
{
	const struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	return &z_meta->z_iv_key;
}

static void zb_set_rand_iv_key(struct voluta_zero_block *zb)
{
	struct voluta_zero_block_meta *z_meta = zb_meta(zb);
	struct voluta_iv *z_iv = &z_meta->z_iv_key.iv;
	struct voluta_key *z_key = &z_meta->z_iv_key.key;

	voluta_fill_random(z_iv, sizeof(*z_iv), true);
	voluta_fill_random(z_key, sizeof(*z_key), true);
}

static void zb_rfill_random(struct voluta_zero_block *zb)
{
	struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	voluta_fill_random(z_meta->z_rfill, sizeof(z_meta->z_rfill), false);
}

static void zb_calc_rhash(const struct voluta_zero_block *zb,
			  const struct voluta_mdigest *md,
			  struct voluta_hash512 *out_hash)
{
	const struct voluta_zero_block_meta *z_meta = zb_meta(zb);
	const size_t rfill_size = sizeof(z_meta->z_rfill);

	voluta_sha3_512_of(md, z_meta->z_rfill, rfill_size, out_hash);
}

static void zb_set_rhash(struct voluta_zero_block *zb,
			 const struct voluta_hash512 *h)
{
	struct voluta_zero_block_meta *z_arc = zb_meta(zb);

	hash512_assign(&z_arc->z_rhash, h);
}

static bool zb_has_rhash(const struct voluta_zero_block *zb,
			 const struct voluta_hash512 *h)
{
	const struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	return hash512_isequal(&z_meta->z_rhash, h);
}

static void zb_assign_rfillhash(struct voluta_zero_block *zb,
				const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	zb_rfill_random(zb);
	zb_calc_rhash(zb, md, &hash);
	zb_set_rhash(zb, &hash);
}

size_t voluta_zb_arc_nents(const struct voluta_zero_block *zb)
{
	const struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	return le64_to_cpu(z_meta->z_arc_nents);
}

void voluta_zb_set_arc_nents(struct voluta_zero_block *zb, size_t nents)
{
	struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	z_meta->z_arc_nents = cpu_to_le64(nents);
}

int voluta_zb_encrypt_meta(struct voluta_zero_block *zb,
			   const struct voluta_cipher *ci,
			   const struct voluta_iv_key *iv_key)
{
	int err;
	struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	err = voluta_encrypt_buf(ci, iv_key, z_meta, z_meta, sizeof(*z_meta));
	if (err) {
		log_err("encrypt zero-block failed: err=%d", err);
	}
	return err;
}

int voluta_zb_decrypt_meta(struct voluta_zero_block *zb,
			   const struct voluta_cipher *ci,
			   const struct voluta_iv_key *iv_key)
{
	int err;
	struct voluta_zero_block_meta *z_meta = zb_meta(zb);

	err = voluta_decrypt_buf(ci, iv_key, z_meta, z_meta, sizeof(*z_meta));
	if (err) {
		log_dbg("decrypt zero-block failed: err=%d", err);
	}
	return err;
}

static enum voluta_ztype zb_type_safe(const struct voluta_zero_block *zb)
{
	enum voluta_ztype ztype = zb_type(zb);

	switch (ztype) {
	case VOLUTA_ZTYPE_NONE:
	case VOLUTA_ZTYPE_VOLUME:
	case VOLUTA_ZTYPE_ARCHIVE:
		break;
	default:
		ztype = VOLUTA_ZTYPE_NONE;
		break;
	}
	return ztype;
}

static int zb_check(const struct voluta_zero_block *zb,
		    enum voluta_ztype ztype)
{
	if (zb_marker(zb) != VOLUTA_ZB_MARK) {
		return -EINVAL;
	}
	if (zb_version(zb) != VOLUTA_FMT_VERSION) {
		return -EFSCORRUPTED;
	}
	if (zb_type_safe(zb) != ztype) {
		return -EFSCORRUPTED;
	}
	return 0;
}

static void zb_setup(struct voluta_zero_block *zb,
		     enum voluta_ztype ztype, size_t size)
{
	memset(zb, 0, sizeof(*zb));
	zb_set_marker(zb, VOLUTA_ZB_MARK);
	zb_set_version(zb, VOLUTA_FMT_VERSION);
	zb_set_type(zb, ztype);
	zb_set_flags(zb, VOLUTA_ZBF_NONE);
	zb_set_kdf(zb, &voluta_default_kdf);
	zb_set_sw_version(zb, voluta_version.string);
	zb_set_rand_iv_key(zb);
	zb_set_uuid(zb);

	voluta_zb_set_size(zb, size);
	voluta_zb_set_arc_nents(zb, 0);
}

void voluta_zb_setup_volume(struct voluta_zero_block *zb, size_t size)
{
	zb_setup(zb, VOLUTA_ZTYPE_VOLUME, size);
}

void voluta_zb_setup_archive(struct voluta_zero_block *zb, size_t size)
{
	zb_setup(zb, VOLUTA_ZTYPE_ARCHIVE, size);
}

void voluta_zb_set_randfill(struct voluta_zero_block *zb,
			    const struct voluta_mdigest *md)
{
	zb_assign_rfillhash(zb, md);
}

int voluta_zb_check_volume(const struct voluta_zero_block *zb)
{
	return zb_check(zb, VOLUTA_ZTYPE_VOLUME);
}

int voluta_zb_check_archive(const struct voluta_zero_block *zb)
{
	return zb_check(zb, VOLUTA_ZTYPE_ARCHIVE);
}

int voluta_zb_check_randfill(const struct voluta_zero_block *zb,
			     const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	zb_calc_rhash(zb, md, &hash);
	return zb_has_rhash(zb, &hash) ? 0 : -EKEYEXPIRED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_zb_parse_hdr(const struct voluta_zero_block *zb,
			enum voluta_ztype *out_ztype,
			enum voluta_zb_flags *out_zbf)
{
	*out_ztype = zb_type(zb);
	*out_zbf = zb_flags(zb);
	return zb_check(zb, *out_ztype);
}

int voluta_zb_decipher(struct voluta_zero_block *zb, const char *pass)
{
	int err;
	struct voluta_crypto crypto;
	struct voluta_kdf_pair kdf;
	struct voluta_iv_key iv_key;
	struct voluta_passphrase passph;

	voluta_zb_kdf(zb, &kdf);
	err = voluta_passphrase_setup(&passph, pass);
	if (err) {
		return err;
	}
	err = voluta_crypto_init(&crypto);
	if (err) {
		goto out;
	}
	err = voluta_derive_iv_key(&passph, &kdf, &crypto.md, &iv_key);
	if (err) {
		goto out;
	}
	err = voluta_zb_decrypt_meta(zb, &crypto.ci, &iv_key);
	if (err) {
		goto out;
	}
	err = voluta_zb_check_randfill(zb, &crypto.md);
	if (err) {
		goto out;
	}
out:
	voluta_iv_key_reset(&iv_key);
	voluta_crypto_fini(&crypto);
	voluta_passphrase_reset(&passph);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_zero_block *
voluta_zb_new(struct voluta_qalloc *qal, enum voluta_ztype ztype)
{
	struct voluta_zero_block *zb;

	zb = voluta_qalloc_zalloc(qal, sizeof(*zb));
	if (zb != NULL) {
		zb_setup(zb, ztype, sizeof(*zb));
	}
	return zb;
}

void voluta_zb_del(struct voluta_zero_block *zb, struct voluta_qalloc *qal)
{
	zb_fini(zb);
	voluta_qalloc_free(qal, zb, sizeof(*zb));
}


