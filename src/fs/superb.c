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
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <voluta/fs/address.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/superb.h>
#include <voluta/fs/crypto.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/private.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static const struct voluta_crypt_params voluta_default_cryp = {
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

static void iv_snap(const struct voluta_iv *iv, struct voluta_iv *other)
{
	memcpy(other, iv, sizeof(*other));
}

static void iv_rand(struct voluta_iv *iv, size_t n)
{
	voluta_gcry_randomize(iv, n * sizeof(*iv), false);
}

static void key_snap(const struct voluta_key *key, struct voluta_key *other)
{
	memcpy(other, key, sizeof(*other));
}

static void key_rand(struct voluta_key *key, size_t n)
{
	voluta_gcry_randomize(key, n * sizeof(*key), true);
}

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
	kd->kd_iterations = voluta_le32_to_cpu(kd_le->kd_iterations);
	kd->kd_algo = voluta_le32_to_cpu(kd_le->kd_algo);
	kd->kd_subalgo = voluta_le16_to_cpu(kd_le->kd_subalgo);
	kd->kd_salt_md = voluta_le16_to_cpu(kd_le->kd_salt_md);
}

static void cpu_to_kdf(const struct voluta_kdf_desc *kd,
                       struct voluta_kdf_desc *kd_le)
{
	kd_le->kd_iterations = voluta_cpu_to_le32(kd->kd_iterations);
	kd_le->kd_algo = voluta_cpu_to_le32(kd->kd_algo);
	kd_le->kd_subalgo = voluta_cpu_to_le16(kd->kd_subalgo);
	kd_le->kd_salt_md = voluta_cpu_to_le16(kd->kd_salt_md);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t sbr_magic(const struct voluta_sb_root *sbr)
{
	return voluta_le64_to_cpu(sbr->sr_magic);
}

static void sbr_set_magic(struct voluta_sb_root *sbr, uint64_t magic)
{
	sbr->sr_magic = voluta_cpu_to_le64(magic);
}

static long sbr_version(const struct voluta_sb_root *sbr)
{
	return (long)voluta_le64_to_cpu(sbr->sr_version);
}

static void sbr_set_version(struct voluta_sb_root *sbr, long version)
{
	sbr->sr_version = voluta_cpu_to_le64((uint64_t)version);
}

static void sbr_set_sw_version(struct voluta_sb_root *sbr,
                               const char *sw_version)
{
	const size_t len = strlen(sw_version);
	const size_t len_max = ARRAY_SIZE(sbr->sr_sw_version) - 1;

	memcpy(sbr->sr_sw_version, sw_version, min(len, len_max));
}

static void sbr_set_uuid(struct voluta_sb_root *sbr)
{
	voluta_uuid_generate(&sbr->sr_uuid);
}

static ssize_t sbr_volume_size(const struct voluta_sb_root *sbr)
{
	return (ssize_t)voluta_le64_to_cpu(sbr->sr_volume_size);
}

static void sbr_set_volume_size(struct voluta_sb_root *sbr, ssize_t size)
{
	sbr->sr_volume_size = voluta_cpu_to_le64((uint64_t)size);
}

static void sbr_kdf(const struct voluta_sb_root *sbr,
                    struct voluta_kdf_pair *kdf)
{
	kdf_to_cpu(&sbr->sr_kdf_pair.kdf_iv, &kdf->kdf_iv);
	kdf_to_cpu(&sbr->sr_kdf_pair.kdf_key, &kdf->kdf_key);
}

static void sbr_set_kdf(struct voluta_sb_root *sbr,
                        const struct voluta_kdf_pair *kdf)
{
	cpu_to_kdf(&kdf->kdf_iv, &sbr->sr_kdf_pair.kdf_iv);
	cpu_to_kdf(&kdf->kdf_key, &sbr->sr_kdf_pair.kdf_key);
}

static uint32_t sbr_chiper_algo(const struct voluta_sb_root *sbr)
{
	return voluta_le32_to_cpu(sbr->sr_chiper_algo);
}

static uint32_t sbr_chiper_mode(const struct voluta_sb_root *sbr)
{
	return voluta_le32_to_cpu(sbr->sr_chiper_mode);
}

static void sbr_set_cipher(struct voluta_sb_root *sbr,
                           uint32_t cipher_algo, uint32_t cipher_mode)
{
	sbr->sr_chiper_algo = voluta_cpu_to_le32(cipher_algo);
	sbr->sr_chiper_mode = voluta_cpu_to_le32(cipher_mode);
}

static void sbr_crypt_params(const struct voluta_sb_root *sbr,
                             struct voluta_crypt_params *cryp)
{
	sbr_kdf(sbr, &cryp->kdf);
	cryp->cipher_algo = sbr_chiper_algo(sbr);
	cryp->cipher_mode = sbr_chiper_mode(sbr);
}

static void sbr_init(struct voluta_sb_root *sbr, ssize_t size)
{
	memset(sbr, 0, sizeof(*sbr));
	sbr_set_magic(sbr, VOLUTA_SBROOT_MARK);
	sbr_set_version(sbr, VOLUTA_FMT_VERSION);
	sbr_set_sw_version(sbr, voluta_version.string);
	sbr_set_uuid(sbr);
	sbr_set_volume_size(sbr, size);
	sbr_set_kdf(sbr, &voluta_default_cryp.kdf);
	sbr_set_cipher(sbr, voluta_default_cryp.cipher_algo,
	               voluta_default_cryp.cipher_mode);
	sbr->sr_endianness = VOLUTA_ENDIANNESS_LE;
}

static void sbr_fini(struct voluta_sb_root *sbr)
{
	memset(sbr, 0xFF, sizeof(*sbr));
	sbr_set_magic(sbr, 0);
	sbr_set_volume_size(sbr, 0);
}

int voluta_sb_check_root(const struct voluta_super_block *sb)
{
	const struct voluta_sb_root *sbr = &sb->sb_boot;

	if (sbr_magic(sbr) != VOLUTA_SBROOT_MARK) {
		return -EINVAL;
	}
	if (sbr_version(sbr) != VOLUTA_FMT_VERSION) {
		return -EFSCORRUPTED;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbh_set_pass_hash(struct voluta_sb_hash *sbh,
                              const struct voluta_hash512 *hash)
{
	hash512_assign(&sbh->sh_pass_hash, hash);
}

static bool sbh_has_pass_hash(const struct voluta_sb_hash *sbh,
                              const struct voluta_hash512 *hash)
{
	return hash512_isequal(&sbh->sh_pass_hash, hash);
}

static void sbh_fill_random(struct voluta_sb_hash *sbh)
{
	voluta_getentropy(sbh->sh_fill, sizeof(sbh->sh_fill));
}

static void sbh_calc_fill_hash(const struct voluta_sb_hash *sbh,
                               const struct voluta_mdigest *md,
                               struct voluta_hash512 *out_hash)
{
	voluta_sha3_512_of(md, sbh->sh_fill, sizeof(sbh->sh_fill), out_hash);
}

static void sbr_set_fill_hash(struct voluta_sb_hash *sbh,
                              const struct voluta_hash512 *hash)
{
	hash512_assign(&sbh->sh_fill_hash, hash);
}

static bool sbh_has_hash(const struct voluta_sb_hash *sbh,
                         const struct voluta_hash512 *hash)
{
	return hash512_isequal(&sbh->sh_fill_hash, hash);
}

static void sbh_setup(struct voluta_sb_hash *sbh,
                      const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	sbh_fill_random(sbh);
	sbh_calc_fill_hash(sbh, md, &hash);
	sbr_set_fill_hash(sbh, &hash);
}

static int sbh_check(const struct voluta_sb_hash *sbh,
                     const struct voluta_mdigest *md)
{
	struct voluta_hash512 hash;

	sbh_calc_fill_hash(sbh, md, &hash);
	return sbh_has_hash(sbh, &hash) ? 0 : -EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint32_t sbk_cipher_algo(const struct voluta_sb_keys *sbk)
{
	return voluta_le32_to_cpu(sbk->sk_cipher_algo);
}

static void sbk_set_cipher_algo(struct voluta_sb_keys *sbk, uint32_t algo)
{
	sbk->sk_cipher_algo = voluta_cpu_to_le32(algo);
}

static uint32_t sbk_cipher_mode(const struct voluta_sb_keys *sbk)
{
	return voluta_le32_to_cpu(sbk->sk_cipher_mode);
}

static void sbk_set_cipher_mode(struct voluta_sb_keys *sbk, uint32_t mode)
{
	sbk->sk_cipher_mode = voluta_cpu_to_le32(mode);
}

static void sbk_setup(struct voluta_sb_keys *sbk)
{
	sbk_set_cipher_algo(sbk, VOLUTA_CIPHER_AES256);
	sbk_set_cipher_mode(sbk, VOLUTA_CIPHER_MODE_GCM);
	voluta_memzero(sbk->sk_reserved1, sizeof(sbk->sk_reserved1));
	iv_rand(sbk->sk_iv, ARRAY_SIZE(sbk->sk_iv));
	key_rand(sbk->sk_key, ARRAY_SIZE(sbk->sk_key));
}

static const struct voluta_key *
sbk_key_by_lba(const struct voluta_sb_keys *sbk, voluta_lba_t lba)
{
	const size_t key_slot = (uint64_t)lba % ARRAY_SIZE(sbk->sk_key);

	return &sbk->sk_key[key_slot];
}

static const struct voluta_iv *
kr_iv_by_ag_index(const struct voluta_sb_keys *sbk, voluta_index_t ag_index)
{
	const size_t iv_slot = (uint64_t)ag_index % ARRAY_SIZE(sbk->sk_iv);

	return &sbk->sk_iv[iv_slot];
}

static void sbk_kivam_of(const struct voluta_sb_keys *sbk,
                         const struct voluta_vaddr *vaddr,
                         struct voluta_kivam *kivam)
{
	const struct voluta_iv *iv = kr_iv_by_ag_index(sbk, vaddr->ag_index);
	const struct voluta_key *key = sbk_key_by_lba(sbk, vaddr->lba);

	voluta_kivam_init(kivam);
	key_snap(key, &kivam->key);
	iv_snap(iv, &kivam->iv);
	kivam->cipher_algo = sbk_cipher_algo(sbk);
	kivam->cipher_mode = sbk_cipher_mode(sbk);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbu_init(struct voluta_sb_uspace_map *sbu)
{
	voluta_bls_initn(sbu->su_hsm_bls, ARRAY_SIZE(sbu->su_hsm_bls));
}

static size_t sbu_slot_of(const struct voluta_sb_uspace_map *sbu,
                          voluta_index_t hs_index)
{
	voluta_assert_gt(hs_index, 0);
	voluta_assert_lt(hs_index, ARRAY_SIZE(sbu->su_hsm_bls));

	return hs_index % ARRAY_SIZE(sbu->su_hsm_bls);
}

static struct voluta_blobspec *
sbu_blobspec_at(const struct voluta_sb_uspace_map *sbu, size_t slot)
{
	const struct voluta_blobspec *bls = &sbu->su_hsm_bls[slot];

	voluta_assert_lt(slot, ARRAY_SIZE(sbu->su_hsm_bls));
	return unconst(bls);
}

static struct voluta_blobspec *
sbu_blobspec_of(const struct voluta_sb_uspace_map *sbu,
                voluta_index_t hs_index)
{
	return sbu_blobspec_at(sbu, sbu_slot_of(sbu, hs_index));
}

static void sbu_hsm_vba(const struct voluta_sb_uspace_map *sbu,
                        voluta_index_t hs_index, struct voluta_vba *out_vba)
{
	const struct voluta_blobspec *bls = sbu_blobspec_of(sbu, hs_index);

	voluta_bls_vba(bls, out_vba);
}

static void sbu_set_hsm_vba(struct voluta_sb_uspace_map *usm,
                            voluta_index_t hs_index,
                            const struct voluta_vba *vba)
{
	struct voluta_blobspec *bls = sbu_blobspec_of(usm, hs_index);

	voluta_bls_set_vba(bls, vba);
}

void voluta_sb_resolve_hsm(const struct voluta_super_block *sb,
                           voluta_index_t hs_index,
                           struct voluta_vba *out_hsm_vba)
{
	sbu_hsm_vba(&sb->sb_usm, hs_index, out_hsm_vba);
}

void voluta_sb_bind_hsm(struct voluta_super_block *sb,
                        voluta_index_t hs_index,
                        const struct voluta_vba *hsm_vba)
{
	sbu_set_hsm_vba(&sb->sb_usm, hs_index, hsm_vba);
}

bool voluta_sb_has_hsm(struct voluta_super_block *sb, voluta_index_t hs_index)
{
	struct voluta_vba vba;

	voluta_sb_resolve_hsm(sb, hs_index, &vba);
	return !vaddr_isnull(&vba.vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_init(struct voluta_super_block *sb)
{
	voluta_memzero(sb, sizeof(*sb));
	sbr_init(&sb->sb_boot, sizeof(*sb));
	sbu_init(&sb->sb_usm);
}

static void sb_fini(struct voluta_super_block *sb)
{
	sbr_fini(&sb->sb_boot);
	voluta_memzero(sb, sizeof(*sb));
}

struct voluta_super_block *voluta_sb_new(struct voluta_alloc_if *alif)
{
	struct voluta_super_block *sb;

	sb = voluta_allocate(alif, sizeof(*sb));
	if (sb != NULL) {
		sb_init(sb);
	}
	return sb;
}

void voluta_sb_del(struct voluta_super_block *sb, struct voluta_alloc_if *alif)
{
	sb_fini(sb);
	voluta_deallocate(alif, sb, sizeof(*sb));
}

void voluta_sb_set_pass_hash(struct voluta_super_block *sb,
                             const struct voluta_hash512 *hash)
{
	sbh_set_pass_hash(&sb->sb_hash, hash);
}

static bool sb_has_pass_hash(const struct voluta_super_block *sb,
                             const struct voluta_hash512 *hash)
{
	return sbh_has_pass_hash(&sb->sb_hash, hash);
}

void voluta_sb_set_birth_time(struct voluta_super_block *sb, time_t btime)
{
	sb->sb_birth_time = voluta_cpu_to_le64((uint64_t)btime);
}

void voluta_sb_set_ag_count(struct voluta_super_block *sb, size_t ag_count)
{
	sb->sb_ag_count = voluta_cpu_to_le64(ag_count);
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
	sbk_setup(&sb->sb_keys);
}

void voluta_sb_kivam_of(const struct voluta_super_block *sb,
                        const struct voluta_vaddr *vaddr,
                        struct voluta_kivam *out_kivam)
{
	return sbk_kivam_of(&sb->sb_keys, vaddr, out_kivam);
}

void voluta_sb_setup_rand(struct voluta_super_block *sb,
                          const struct voluta_mdigest *md)
{
	sbh_setup(&sb->sb_hash, md);
}

int voluta_sb_check_volume(const struct voluta_super_block *sb)
{
	return voluta_sb_check_root(sb);
}

int voluta_sb_check_pass_hash(const struct voluta_super_block *sb,
                              const struct voluta_hash512 *hash)
{
	return sb_has_pass_hash(sb, hash) ? 0 : -EKEYEXPIRED;
}

int voluta_sb_check_rand(const struct voluta_super_block *sb,
                         const struct voluta_mdigest *md)
{
	return sbh_check(&sb->sb_hash, md);
}

static void *sb_enc_start(struct voluta_super_block *sb)
{
	return &sb->sb_hash;
}

static size_t sb_enc_length(const struct voluta_super_block *sb)
{
	const size_t start_off = offsetof(typeof(*sb), sb_hash);

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
	struct voluta_crypt_params cryp;

	voluta_kivam_init(&kivam);
	voluta_sb_crypt_params(sb, &cryp);

	err = voluta_derive_kivam(&cryp, passph, &crypto->md, &kivam);
	if (err) {
		goto out;
	}
	/* TODO: use zcp cipher_algo/mode */
	err = voluta_sb_encrypt_tail(sb, &crypto->ci, &kivam);
	if (err) {
		goto out;
	}
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
	struct voluta_crypt_params cryp;

	voluta_kivam_init(&kivam);
	voluta_sb_crypt_params(sb, &cryp);

	err = voluta_derive_kivam(&cryp, passph, &crypto->md, &kivam);
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

void voluta_sb_setup_new(struct voluta_super_block *sb,
                         time_t btime, ssize_t vsize)
{
	voluta_sb_set_birth_time(sb, btime);
	voluta_sb_set_itable_root(sb, vaddr_none());
	voluta_sb_setup_keys(sb);
	voluta_sb_set_volume_size(sb, vsize);
}

void voluta_sb_crypt_params(const struct voluta_super_block *sb,
                            struct voluta_crypt_params *zcp)
{
	memset(zcp, 0, sizeof(*zcp));
	sbr_crypt_params(&sb->sb_boot, zcp);
}

ssize_t voluta_sb_volume_size(const struct voluta_super_block *sb)
{
	return (ssize_t)sbr_volume_size(&sb->sb_boot);
}

void voluta_sb_set_volume_size(struct voluta_super_block *sb, ssize_t sz)
{
	sbr_set_volume_size(&sb->sb_boot, sz);
}

