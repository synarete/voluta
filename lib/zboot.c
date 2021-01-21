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

static uint64_t zb_marker(const struct voluta_zero_block4 *zb)
{
	return le64_to_cpu(zb->z_marker);
}

static void zb_set_marker(struct voluta_zero_block4 *zb, uint64_t mark)
{
	zb->z_marker = cpu_to_le64(mark);
}

static long zb_version(const struct voluta_zero_block4 *zb)
{
	return (long)le64_to_cpu(zb->z_version);
}

static void zb_set_version(struct voluta_zero_block4 *zb, long version)
{
	zb->z_version = cpu_to_le64((uint64_t)version);
}

enum voluta_ztype voluta_zb_type(const struct voluta_zero_block4 *zb)
{
	return le32_to_cpu(zb->z_type);
}

static void zb_set_type(struct voluta_zero_block4 *zb,
			enum voluta_ztype type)
{
	zb->z_type = cpu_to_le32(type);
}

static enum voluta_zbf zb_flags(const struct voluta_zero_block4 *zb)
{
	const uint32_t flags = le32_to_cpu(zb->z_flags);

	return (enum voluta_zbf)flags;
}

static void zb_set_flags(struct voluta_zero_block4 *zb,
			 enum voluta_zbf f)
{
	zb->z_flags = cpu_to_le32((uint32_t)f);
}

static void zb_add_flag(struct voluta_zero_block4 *zb,
			enum voluta_zbf f)
{
	zb_set_flags(zb, zb_flags(zb) | f);
}

static bool zb_test_flag(const struct voluta_zero_block4 *zb,
			 enum voluta_zbf f)
{
	return ((zb_flags(zb) & f) == f);
}

void voluta_zb_set_encrypted(struct voluta_zero_block4 *zb)
{
	zb_add_flag(zb, VOLUTA_ZBF_ENCRYPTED);
}

bool voluta_zb_is_encrypted(const struct voluta_zero_block4 *zb)
{
	return zb_test_flag(zb, VOLUTA_ZBF_ENCRYPTED);
}

enum voluta_zbf voluta_zb_flags(const struct voluta_zero_block4 *zb)
{
	return zb_flags(zb);
}

static void zb_set_sw_version(struct voluta_zero_block4 *zb,
			      const char *sw_version)
{
	const size_t len = strlen(sw_version);
	const size_t len_max = ARRAY_SIZE(zb->z_sw_version) - 1;

	memcpy(zb->z_sw_version, sw_version, min(len, len_max));
}

static void zb_set_uuid(struct voluta_zero_block4 *zb)
{
	voluta_uuid_generate(&zb->z_uuid);
}

size_t voluta_zb_size(const struct voluta_zero_block4 *zb)
{
	return le64_to_cpu(zb->z_size);
}

void voluta_zb_set_size(struct voluta_zero_block4 *zb, size_t size)
{
	zb->z_size = cpu_to_le64(size);
}

void voluta_zb_kdf(const struct voluta_zero_block4 *zb,
		   struct voluta_kdf_pair *kdf)
{
	kdf_to_cpu(&zb->z_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&zb->z_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void zb_set_kdf(struct voluta_zero_block4 *zb,
		       const struct voluta_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &zb->z_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &zb->z_kdf_pair.kdf_key);
}

void voluta_zb_init(struct voluta_zero_block4 *zb,
		    enum voluta_ztype ztype, size_t size)
{
	memset(zb, 0, sizeof(*zb));
	zb_set_marker(zb, VOLUTA_ZB_MARK);
	zb_set_version(zb, VOLUTA_FMT_VERSION);
	zb_set_type(zb, ztype);
	zb_set_flags(zb, VOLUTA_ZBF_NONE);
	zb_set_kdf(zb, &voluta_default_kdf);
	zb_set_sw_version(zb, voluta_version.string);
	zb_set_uuid(zb);
	voluta_zb_set_size(zb, size);
}

void voluta_zb_fini(struct voluta_zero_block4 *zb)
{
	memset(zb, 0xFF, sizeof(*zb));
	zb_set_marker(zb, 0);
	voluta_zb_set_size(zb, 0);
}

static int ztype_check(enum voluta_ztype ztype)
{
	int err;

	switch (ztype) {
	case VOLUTA_ZTYPE_VOLUME:
	case VOLUTA_ZTYPE_ARCHIVE:
		err = 0;
		break;
	case VOLUTA_ZTYPE_NONE:
	default:
		err = -EFSCORRUPTED;
		break;
	}
	return err;
}

int voluta_zb_check(const struct voluta_zero_block4 *zb)
{
	int err;
	enum voluta_ztype ztype;

	if (zb_marker(zb) != VOLUTA_ZB_MARK) {
		return -EINVAL;
	}
	if (zb_version(zb) != VOLUTA_FMT_VERSION) {
		return -EFSCORRUPTED;
	}
	ztype = voluta_zb_type(zb);
	err = ztype_check(ztype);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void rb_fill_random(struct voluta_rand_block4 *rb)
{
	voluta_fill_random(rb->r_fill, sizeof(rb->r_fill), false);
}

static void rb_calc_hash(const struct voluta_rand_block4 *rb,
			 const struct voluta_mdigest *md,
			 struct voluta_hash512 *out_hash)
{
	voluta_sha3_512_of(md, rb->r_fill, sizeof(rb->r_fill), out_hash);
}

static void rb_set_hash(struct voluta_rand_block4 *rb,
			const struct voluta_hash512 *hash)
{
	hash512_assign(&rb->r_hash, hash);
}

static bool rb_has_rhash(const struct voluta_rand_block4 *rb,
			 const struct voluta_hash512 *hash)
{
	return hash512_isequal(&rb->r_hash, hash);
}

void voluta_rb_setup(struct voluta_rand_block4 *rb,
		     const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	rb_fill_random(rb);
	rb_calc_hash(rb, md, &hash);
	rb_set_hash(rb, &hash);
}

int voluta_rb_check(const struct voluta_rand_block4 *rb,
		    const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	rb_calc_hash(rb, md, &hash);
	return rb_has_rhash(rb, &hash) ? 0 : -EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_init(struct voluta_super_block *sb, enum voluta_ztype ztype)
{
	voluta_memzero(sb, sizeof(*sb));
	voluta_zb_init(&sb->s_zero, ztype, sizeof(*sb));
}

static void sb_fini(struct voluta_super_block *sb)
{
	voluta_zb_fini(&sb->s_zero);
	voluta_memzero(sb, sizeof(*sb));
}

struct voluta_super_block *
voluta_sb_new(struct voluta_qalloc *qal, enum voluta_ztype ztype)
{
	struct voluta_super_block *sb;

	sb = voluta_qalloc_malloc(qal, sizeof(*sb));
	if (sb != NULL) {
		sb_init(sb, ztype);
	}
	return sb;
}

void voluta_sb_del(struct voluta_super_block *sb, struct voluta_qalloc *qal)
{
	sb_fini(sb);
	voluta_qalloc_free(qal, sb, sizeof(*sb));
}

void voluta_sb_set_birth_time(struct voluta_super_block *sb, time_t btime)
{
	sb->s_meta.m_birth_time = cpu_to_le64((uint64_t)btime);
}

void voluta_sb_set_ag_count(struct voluta_super_block *sb, size_t ag_count)
{
	sb->s_meta.m_ag_count = cpu_to_le64(ag_count);
}

void voluta_sb_setup_ivks(struct voluta_super_block *sb)
{
	struct voluta_ivks_block4 *ivks = &sb->s_ivks;

	for (size_t i = 0; i < ARRAY_SIZE(ivks->ivk); ++i) {
		voluta_iv_key_rand(&ivks->ivk[i]);
	}
}

const struct voluta_iv_key *
voluta_sb_iv_key_of(const struct voluta_super_block *sb, size_t hs_index)
{
	const struct voluta_ivks_block4 *ivks = &sb->s_ivks;
	const size_t slot = (hs_index - 1) % ARRAY_SIZE(ivks->ivk);

	voluta_assert_gt(hs_index, 0);
	return &ivks->ivk[slot];
}

void voluta_sb_setup_rand(struct voluta_super_block *sb,
			  const struct voluta_mdigest *md)
{
	for (size_t i = 0; i < ARRAY_SIZE(sb->s_rand); ++i) {
		voluta_rb_setup(&sb->s_rand[i], md);
	}
}

int voluta_sb_check_volume(const struct voluta_super_block *sb)
{
	int err;
	enum voluta_ztype ztype;

	err = voluta_zb_check(&sb->s_zero);
	if (err) {
		return err;
	}
	ztype = voluta_zb_type(&sb->s_zero);
	if (ztype != VOLUTA_ZTYPE_VOLUME) {
		return -EINVAL;
	}
	return 0;
}

int voluta_sb_check_rand(const struct voluta_super_block *sb,
			 const struct voluta_mdigest *md)
{
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(sb->s_rand); ++i) {
		err = voluta_rb_check(&sb->s_rand[i], md);
		if (err) {
			return err;
		}
	}
	return 0;
}

static void *sb_enc_start(struct voluta_super_block *sb)
{
	return &sb->s_meta;
}

static size_t sb_enc_length(const struct voluta_super_block *sb)
{
	const size_t start_off = offsetof(typeof(*sb), s_meta);

	return sizeof(*sb) - start_off;
}

static int sb_encrypt_tail(struct voluta_super_block *sb,
			   const struct voluta_cipher *ci,
			   const struct voluta_iv_key *iv_key)
{
	int err;
	void *enc_buf = sb_enc_start(sb);
	const size_t enc_len = sb_enc_length(sb);

	err = voluta_encrypt_buf(ci, iv_key, enc_buf, enc_buf, enc_len);
	if (err) {
		log_err("encrypt super-block failed: err=%d", err);
	}
	return err;
}

static int sb_decrypt_tail(struct voluta_super_block *sb,
			   const struct voluta_cipher *ci,
			   const struct voluta_iv_key *iv_key)
{
	int err;
	void *enc_buf = sb_enc_start(sb);
	const size_t enc_len = sb_enc_length(sb);

	err = voluta_decrypt_buf(ci, iv_key, enc_buf, enc_buf, enc_len);
	if (err) {
		log_dbg("decrypt super-block failed: err=%d", err);
	}
	return err;
}

int voluta_sb_encrypt(struct voluta_super_block *sb,
		      const struct voluta_crypto *crypto, const char *pass)
{
	int err;
	struct voluta_kdf_pair kdf;
	struct voluta_iv_key iv_key;
	struct voluta_passphrase passph;

	err = voluta_passphrase_setup(&passph, pass);
	if (err) {
		return err;
	}
	voluta_zb_kdf(&sb->s_zero, &kdf);
	err = voluta_derive_iv_key(&passph, &kdf, &crypto->md, &iv_key);
	if (err) {
		goto out;
	}
	err = sb_encrypt_tail(sb, &crypto->ci, &iv_key);
	if (err) {
		goto out;
	}
	voluta_zb_set_encrypted(&sb->s_zero);
out:
	voluta_passphrase_reset(&passph);
	voluta_iv_key_reset(&iv_key);
	return err;
}

int voluta_sb_decrypt(struct voluta_super_block *sb,
		      const struct voluta_crypto *crypto, const char *pass)
{
	int err;
	struct voluta_kdf_pair kdf;
	struct voluta_iv_key iv_key;
	struct voluta_passphrase passph;

	err = voluta_passphrase_setup(&passph, pass);
	if (err) {
		goto out;
	}
	voluta_zb_kdf(&sb->s_zero, &kdf);
	err = voluta_derive_iv_key(&passph, &kdf, &crypto->md, &iv_key);
	if (err) {
		goto out;
	}
	err = sb_decrypt_tail(sb, &crypto->ci, &iv_key);
	if (err) {
		goto out;
	}
out:
	voluta_passphrase_reset(&passph);
	voluta_iv_key_reset(&iv_key);
	return err;
}


int voluta_sb_decipher(struct voluta_super_block *sb, const char *pass)
{
	int err;
	struct voluta_crypto crypto;
	struct voluta_kdf_pair kdf;
	struct voluta_iv_key iv_key;
	struct voluta_passphrase passph;

	voluta_zb_kdf(&sb->s_zero, &kdf);
	err = voluta_passphrase_setup(&passph, pass);
	if (err) {
		return err;
	}
	err = voluta_crypto_init(&crypto);
	if (err) {
		goto out;
	}
	err = voluta_sb_decrypt(sb, &crypto, pass);
	if (err) {
		goto out;
	}
	err = voluta_sb_check_rand(sb, &crypto.md);
	if (err) {
		goto out;
	}
out:
	voluta_iv_key_reset(&iv_key);
	voluta_crypto_fini(&crypto);
	voluta_passphrase_reset(&passph);
	return err;
}
