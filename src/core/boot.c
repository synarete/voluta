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


static const struct voluta_zcrypt_params voluta_default_zcrypt = {
	.kdf = {
		.kdf_iv = {
			.kd_iterations = 4096,
			.kd_algo = VOLUTA_KDF_PBKDF2,
			.kd_subalgo = VOLUTA_MD_SHA256,
			.kd_salt_md = VOLUTA_MD_SHA3_256,
		},
		.kdf_key = {
			.kd_iterations = 256,
			.kd_algo = VOLUTA_KDF_SCRYPT,
			.kd_subalgo = 8,
			.kd_salt_md = VOLUTA_MD_SHA3_512,
		}
	},
	.cipher_algo = VOLUTA_CIPHER_AES256,
	.cipher_mode = VOLUTA_CIPHER_MODE_GCM,
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
	kd->kd_iterations = le32_to_cpu(kd_le->kd_iterations);
	kd->kd_algo = le32_to_cpu(kd_le->kd_algo);
	kd->kd_subalgo = le16_to_cpu(kd_le->kd_subalgo);
	kd->kd_salt_md = le16_to_cpu(kd_le->kd_salt_md);
}

static void cpu_to_kdf(const struct voluta_kdf_desc *kd,
                       struct voluta_kdf_desc *kd_le)
{
	kd_le->kd_iterations = cpu_to_le32(kd->kd_iterations);
	kd_le->kd_algo = cpu_to_le32(kd->kd_algo);
	kd_le->kd_subalgo = cpu_to_le16(kd->kd_subalgo);
	kd_le->kd_salt_md = cpu_to_le16(kd->kd_salt_md);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t br_magic(const struct voluta_boot_record *br)
{
	return le64_to_cpu(br->br_magic);
}

static void br_set_magic(struct voluta_boot_record *br, uint64_t magic)
{
	br->br_magic = cpu_to_le64(magic);
}

static long br_version(const struct voluta_boot_record *br)
{
	return (long)le64_to_cpu(br->br_version);
}

static void br_set_version(struct voluta_boot_record *br, long version)
{
	br->br_version = cpu_to_le64((uint64_t)version);
}

enum voluta_ztype voluta_br_type(const struct voluta_boot_record *br)
{
	return le32_to_cpu(br->br_type);
}

static void br_set_type(struct voluta_boot_record *br,
                        enum voluta_ztype type)
{
	br->br_type = cpu_to_le32(type);
}

static enum voluta_brf br_flags(const struct voluta_boot_record *br)
{
	const uint32_t flags = le32_to_cpu(br->br_flags);

	return (enum voluta_brf)flags;
}

static void br_set_flags(struct voluta_boot_record *br,
                         enum voluta_brf f)
{
	br->br_flags = cpu_to_le32((uint32_t)f);
}

static void br_add_flag(struct voluta_boot_record *br, enum voluta_brf f)
{
	br_set_flags(br, br_flags(br) | f);
}

static void br_remove_flag(struct voluta_boot_record *br, enum voluta_brf f)
{
	br_set_flags(br, br_flags(br) & ~f);
}

static bool br_test_flag(const struct voluta_boot_record *br,
                         enum voluta_brf f)
{
	return ((br_flags(br) & f) == f);
}

void voluta_br_set_encrypted(struct voluta_boot_record *br, bool enc)
{
	if (enc) {
		br_add_flag(br, VOLUTA_ZBF_ENCRYPTED);
	} else {
		br_remove_flag(br, VOLUTA_ZBF_ENCRYPTED);
	}
}

bool voluta_br_is_encrypted(const struct voluta_boot_record *br)
{
	return br_test_flag(br, VOLUTA_ZBF_ENCRYPTED);
}

enum voluta_brf voluta_br_flags(const struct voluta_boot_record *br)
{
	return br_flags(br);
}

static void br_set_sw_version(struct voluta_boot_record *br,
                              const char *sw_version)
{
	const size_t len = strlen(sw_version);
	const size_t len_max = ARRAY_SIZE(br->br_sw_version) - 1;

	memcpy(br->br_sw_version, sw_version, min(len, len_max));
}

static void br_set_uuid(struct voluta_boot_record *br)
{
	voluta_uuid_generate(&br->br_uuid);
}

size_t voluta_br_size(const struct voluta_boot_record *br)
{
	return le64_to_cpu(br->br_size);
}

void voluta_br_set_size(struct voluta_boot_record *br, size_t size)
{
	br->br_size = cpu_to_le64(size);
}

static void br_kdf(const struct voluta_boot_record *br,
                   struct voluta_kdf_pair *kdf)
{
	kdf_to_cpu(&br->br_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&br->br_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void br_set_kdf(struct voluta_boot_record *br,
                       const struct voluta_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &br->br_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &br->br_kdf_pair.kdf_key);
}

static uint32_t br_chiper_algo(const struct voluta_boot_record *br)
{
	return le32_to_cpu(br->br_chiper_algo);
}

static uint32_t br_chiper_mode(const struct voluta_boot_record *br)
{
	return le32_to_cpu(br->br_chiper_mode);
}

static void br_set_cipher(struct voluta_boot_record *br,
                          uint32_t cipher_algo, uint32_t cipher_mode)
{
	br->br_chiper_algo = cpu_to_le32(cipher_algo);
	br->br_chiper_mode = cpu_to_le32(cipher_mode);
}

void voluta_br_crypt_params(const struct voluta_boot_record *br,
                            struct voluta_zcrypt_params *zcp)
{
	memset(zcp, 0, sizeof(*zcp));
	br_kdf(br, &zcp->kdf);
	zcp->cipher_algo = br_chiper_algo(br);
	zcp->cipher_mode = br_chiper_mode(br);
}

void voluta_br_init(struct voluta_boot_record *br,
                    enum voluta_ztype ztype, size_t size)
{
	memset(br, 0, sizeof(*br));
	br_set_magic(br, VOLUTA_BOOT_MARK);
	br_set_version(br, VOLUTA_FMT_VERSION);
	br_set_type(br, ztype);
	br_set_flags(br, VOLUTA_ZBF_NONE);
	br_set_sw_version(br, voluta_version.string);
	br_set_uuid(br);
	voluta_br_set_size(br, size);
	br_set_kdf(br, &voluta_default_zcrypt.kdf);
	br_set_cipher(br, voluta_default_zcrypt.cipher_algo,
	              voluta_default_zcrypt.cipher_mode);
	br->br_endianness = VOLUTA_ENDIANNESS_LE;
}

void voluta_br_fini(struct voluta_boot_record *br)
{
	memset(br, 0xFF, sizeof(*br));
	br_set_magic(br, 0);
	voluta_br_set_size(br, 0);
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

int voluta_check_boot_record(const struct voluta_super_block *sb)
{
	int err;
	enum voluta_ztype ztype;
	const struct voluta_boot_record *br = &sb->sb_boot_rec;

	if (br_magic(br) != VOLUTA_BOOT_MARK) {
		return -EINVAL;
	}
	if (br_version(br) != VOLUTA_FMT_VERSION) {
		return -EFSCORRUPTED;
	}
	ztype = voluta_br_type(br);
	err = ztype_check(ztype);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static void hr_set_pass_hash(struct voluta_hash_record *hr,
                             const struct voluta_hash512 *hash)
{
	hash512_assign(&hr->hr_pass_hash, hash);
}

static bool hr_has_pass_hash(const struct voluta_hash_record *hr,
                             const struct voluta_hash512 *hash)
{
	return hash512_isequal(&hr->hr_pass_hash, hash);
}

static void hr_fill_random(struct voluta_hash_record *hr)
{
	voluta_getentropy(hr->hr_fill, sizeof(hr->hr_fill));
}

static void hr_calc_fill_hash(const struct voluta_hash_record *hr,
                              const struct voluta_mdigest *md,
                              struct voluta_hash512 *out_hash)
{
	voluta_sha3_512_of(md, hr->hr_fill, sizeof(hr->hr_fill), out_hash);
}

static void hr_set_fill_hash(struct voluta_hash_record *hr,
                             const struct voluta_hash512 *hash)
{
	hash512_assign(&hr->hr_fill_hash, hash);
}

static bool hr_has_hash(const struct voluta_hash_record *hr,
                        const struct voluta_hash512 *hash)
{
	return hash512_isequal(&hr->hr_fill_hash, hash);
}

void voluta_hrec_setup(struct voluta_hash_record *hr,
                       const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	hr_fill_random(hr);
	hr_calc_fill_hash(hr, md, &hash);
	hr_set_fill_hash(hr, &hash);
}

int voluta_hrec_check(const struct voluta_hash_record *hr,
                      const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	hr_calc_fill_hash(hr, md, &hash);
	return hr_has_hash(hr, &hash) ? 0 : -EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_init(struct voluta_super_block *sb, enum voluta_ztype ztype)
{
	voluta_memzero(sb, sizeof(*sb));
	voluta_br_init(&sb->sb_boot_rec, ztype, sizeof(*sb));
}

static void sb_fini(struct voluta_super_block *sb)
{
	voluta_br_fini(&sb->sb_boot_rec);
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

void voluta_sb_set_pass_hash(struct voluta_super_block *sb,
                             const struct voluta_hash512 *hash)
{
	hr_set_pass_hash(&sb->sb_hash_rec, hash);
}

static bool sb_has_pass_hash(const struct voluta_super_block *sb,
                             const struct voluta_hash512 *hash)
{
	return hr_has_pass_hash(&sb->sb_hash_rec, hash);
}

void voluta_sb_set_birth_time(struct voluta_super_block *sb, time_t btime)
{
	sb->sb_birth_time = cpu_to_le64((uint64_t)btime);
}

void voluta_sb_set_ag_count(struct voluta_super_block *sb, size_t ag_count)
{
	sb->sb_ag_count = cpu_to_le64(ag_count);
}

void voluta_sb_self_vaddr(const struct voluta_super_block *sb,
                          struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&sb->sb_self_vaddr, out_vaddr);
}

void voluta_sb_set_self_vaddr(struct voluta_super_block *sb,
                              const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&sb->sb_self_vaddr, vaddr);
}

void voluta_sb_itable_root(const struct voluta_super_block *sb,
                           struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&sb->sb_itable_root, out_vaddr);
}

void voluta_sb_set_itable_root(struct voluta_super_block *sb,
                               const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&sb->sb_itable_root, vaddr);
}

void voluta_sb_setup_keys(struct voluta_super_block *sb)
{
	voluta_krec_setup(&sb->sb_keys_rec);
}

void voluta_sb_kivam_of(const struct voluta_super_block *sb,
                        const struct voluta_vaddr *vaddr,
                        struct voluta_kivam *out_kivam)
{
	return voluta_krec_kivam_of(&sb->sb_keys_rec, vaddr, out_kivam);
}

void voluta_sb_setup_rand(struct voluta_super_block *sb,
                          const struct voluta_mdigest *md)
{
	voluta_hrec_setup(&sb->sb_hash_rec, md);
}

int voluta_sb_check_volume(const struct voluta_super_block *sb)
{
	int err;
	enum voluta_ztype ztype;

	err = voluta_check_boot_record(sb);
	if (err) {
		return err;
	}
	ztype = voluta_br_type(&sb->sb_boot_rec);
	if (ztype != VOLUTA_ZTYPE_VOLUME) {
		return -EINVAL;
	}
	return 0;
}

int voluta_sb_check_pass_hash(const struct voluta_super_block *sb,
                              const struct voluta_hash512 *hash)
{
	return sb_has_pass_hash(sb, hash) ? 0 : -EKEYEXPIRED;
}

int voluta_sb_check_rand(const struct voluta_super_block *sb,
                         const struct voluta_mdigest *md)
{
	return voluta_hrec_check(&sb->sb_hash_rec, md);
}

static void *sb_enc_start(struct voluta_super_block *sb)
{
	return &sb->sb_hash_rec;
}

static size_t sb_enc_length(const struct voluta_super_block *sb)
{
	const size_t start_off = offsetof(typeof(*sb), sb_hash_rec);

	return sizeof(*sb) - start_off;
}

int voluta_sb_encrypt_tail(struct voluta_super_block *sb,
                           const struct voluta_cipher *ci,
                           const struct voluta_kivam *kivam)
{
	int err;
	void *enc_buf = sb_enc_start(sb);
	const size_t enc_len = sb_enc_length(sb);

	err = voluta_encrypt_buf(ci, kivam, enc_buf, enc_buf, enc_len);
	if (err) {
		log_err("encrypt super-block failed: err=%d", err);
	}
	return err;
}

int voluta_sb_decrypt_tail(struct voluta_super_block *sb,
                           const struct voluta_cipher *ci,
                           const struct voluta_kivam *kivam)
{
	int err;
	void *enc_buf = sb_enc_start(sb);
	const size_t enc_len = sb_enc_length(sb);

	err = voluta_decrypt_buf(ci, kivam, enc_buf, enc_buf, enc_len);
	if (err) {
		log_dbg("decrypt super-block failed: err=%d", err);
	}
	return err;
}

int voluta_sb_encrypt(struct voluta_super_block *sb,
                      const struct voluta_crypto *crypto,
                      const struct voluta_passphrase *passph)
{
	int err;
	struct voluta_kivam kivam;
	struct voluta_zcrypt_params zcp;

	voluta_kivam_init(&kivam);
	voluta_br_crypt_params(&sb->sb_boot_rec, &zcp);

	err = voluta_derive_kivam(&zcp, passph, &crypto->md, &kivam);
	if (err) {
		goto out;
	}
	/* TODO: use zcp cipher_algo/mode */
	err = voluta_sb_encrypt_tail(sb, &crypto->ci, &kivam);
	if (err) {
		goto out;
	}
	voluta_br_set_encrypted(&sb->sb_boot_rec, true);
out:
	voluta_kivam_fini(&kivam);
	return err;
}

int voluta_sb_decrypt(struct voluta_super_block *sb,
                      const struct voluta_crypto *crypto,
                      const struct voluta_passphrase *passph)
{
	int err;
	struct voluta_kivam kivam;
	struct voluta_zcrypt_params zcp;

	voluta_kivam_init(&kivam);
	voluta_br_crypt_params(&sb->sb_boot_rec, &zcp);

	err = voluta_derive_kivam(&zcp, passph, &crypto->md, &kivam);
	if (err) {
		goto out;
	}
	/* TODO: use zcp cipher_algo/mode */
	err = voluta_sb_decrypt_tail(sb, &crypto->ci, &kivam);
	if (err) {
		goto out;
	}
out:
	voluta_kivam_fini(&kivam);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_decipher_super_block(struct voluta_super_block *sb,
                                const char *password)
{
	int err;
	struct voluta_crypto crypto;
	struct voluta_hash512 hash;
	struct voluta_passphrase passph;

	err = voluta_crypto_init(&crypto);
	if (err) {
		return err;
	}
	err = voluta_passphrase_setup(&passph, password);
	if (err) {
		goto out;
	}
	err = voluta_sb_decrypt(sb, &crypto, &passph);
	if (err) {
		goto out;
	}
	voluta_sha3_512_of(&crypto.md, passph.pass, passph.passlen, &hash);
	err = voluta_sb_check_pass_hash(sb, &hash);
	if (err) {
		goto out;
	}
	err = voluta_sb_check_rand(sb, &crypto.md);
	if (err) {
		goto out;
	}
out:
	voluta_crypto_fini(&crypto);
	voluta_passphrase_reset(&passph);
	return err;
}
