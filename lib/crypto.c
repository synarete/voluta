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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <gcrypt.h>
#include "libvoluta.h"

#define VOLUTA_SECMEM_SIZE      (64L * VOLUTA_KILO)

#define log_gcrypt_err(fn, err) \
	do { voluta_log_error("%s: %s", fn, gcry_strerror(err)); } while (0)


static int gcrypt_err(gcry_error_t gcry_err)
{
	const int err = (int)gcry_err;

	return (err > 0) ? -err : err;
}

int voluta_init_gcrypt(void)
{
	gcry_error_t err;
	enum gcry_ctl_cmds cmd;
	const char *version;
	const char *expected_version = GCRYPT_VERSION;

	version = gcry_check_version(expected_version);
	if (!version) {
		log_warn("libgcrypt version != %s", expected_version);
		return -1;
	}
	cmd = GCRYCTL_SUSPEND_SECMEM_WARN;
	err = gcry_control(cmd);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_INIT_SECMEM;
	err = gcry_control(cmd, VOLUTA_SECMEM_SIZE, 0);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_RESUME_SECMEM_WARN;
	err = gcry_control(cmd);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_INITIALIZATION_FINISHED;
	gcry_control(cmd, 0);
	if (err) {
		goto out_control_err;
	}
	return 0;

out_control_err:
	log_gcrypt_err("gcry_control", err);
	return gcrypt_err(err);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_mdigest_init(struct voluta_mdigest *md)
{
	int algo;
	gcry_error_t err;
	const int algos[] = {
		GCRY_MD_MD5,
		GCRY_MD_CRC32,
		GCRY_MD_CRC32_RFC1510,
		GCRY_MD_CRC24_RFC2440,
		GCRY_MD_SHA256,
		GCRY_MD_SHA3_256,
		GCRY_MD_SHA3_512,
		GCRY_MD_BLAKE2S_128,
	};

	err = gcry_md_open(&md->md_hd, 0, GCRY_MD_FLAG_SECURE);
	if (err) {
		log_gcrypt_err("gcry_md_open", err);
		return gcrypt_err(err);
	}
	for (size_t i = 0; i < ARRAY_SIZE(algos); ++i) {
		algo = algos[i];
		err = gcry_md_enable(md->md_hd, algo);
		if (err) {
			log_gcrypt_err("gcry_md_enable", err);
			return gcrypt_err(err);
		}
	}
	return 0;
}

void voluta_mdigest_fini(struct voluta_mdigest *md)
{
	if (md->md_hd != NULL) {
		gcry_md_close(md->md_hd);
		md->md_hd = NULL;
	}
}

static void mdigest_calc(const struct voluta_mdigest *md, int algo,
			 const void *buf, size_t bsz, size_t hash_len,
			 void *out_hash_buf)
{
	const void *hval;

	gcry_md_reset(md->md_hd);
	gcry_md_write(md->md_hd, buf, bsz);
	gcry_md_final(md->md_hd);

	hval = gcry_md_read(md->md_hd, algo);
	memcpy(out_hash_buf, hval, hash_len);
}

static void require_algo_dlen(int algo, size_t hlen)
{
	const size_t dlen = gcry_md_get_algo_dlen(algo);

	if (dlen != hlen) {
		voluta_panic("algo-dlen mismatch: "
			     "algo=%d dlen=%lu hlen=%lu", algo, dlen, hlen);
	}
}

void voluta_blake2s128_of(const struct voluta_mdigest *md,
			  const void *buf, size_t bsz,
			  struct voluta_hash128 *out_hash)
{
	const int algo = GCRY_MD_BLAKE2S_128;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

void voluta_sha256_of(const struct voluta_mdigest *md,
		      const void *buf, size_t bsz,
		      struct voluta_hash256 *out_hash)
{
	const int algo = GCRY_MD_SHA256;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

void voluta_sha3_256_of(const struct voluta_mdigest *md,
			const void *buf, size_t bsz,
			struct voluta_hash256 *out_hash)
{
	const int algo = GCRY_MD_SHA3_256;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

void voluta_sha3_512_of(const struct voluta_mdigest *md,
			const void *buf, size_t bsz,
			struct voluta_hash512 *out_hash)
{
	const int algo = GCRY_MD_SHA3_512;
	const size_t hlen = sizeof(out_hash->hash);

	require_algo_dlen(algo, hlen);
	mdigest_calc(md, algo, buf, bsz, hlen, out_hash->hash);
}

static uint32_t digest_to_uint32(const uint8_t *digest)
{
	const uint32_t d0 = digest[0];
	const uint32_t d1 = digest[1];
	const uint32_t d2 = digest[2];
	const uint32_t d3 = digest[3];

	return (d0 << 24) | (d1 << 16) | (d2 << 8) << d3;
}

void voluta_crc32_of(const struct voluta_mdigest *md,
		     const void *buf, size_t bsz, uint32_t *out_crc32)
{
	const void *ptr;
	const int algo = GCRY_MD_CRC32;
	const size_t hlen = sizeof(*out_crc32);

	require_algo_dlen(algo, hlen);

	gcry_md_reset(md->md_hd);
	gcry_md_write(md->md_hd, buf, bsz);
	gcry_md_final(md->md_hd);
	ptr = gcry_md_read(md->md_hd, algo);

	*out_crc32 = digest_to_uint32(ptr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cipher_init(struct voluta_cipher *ci)
{
	gcry_error_t err;
	const int algo = GCRY_CIPHER_AES256;
	const int mode = GCRY_CIPHER_MODE_GCM;
	const unsigned int flags = GCRY_CIPHER_SECURE;

	err = gcry_cipher_open(&ci->cipher_hd, algo, mode, flags);
	if (err) {
		log_gcrypt_err("gcry_cipher_open", err);
		return gcrypt_err(err);
	}
	return 0;
}

static void cipher_fini(struct voluta_cipher *ci)
{
	if (ci->cipher_hd != NULL) {
		gcry_cipher_close(ci->cipher_hd);
		ci->cipher_hd = NULL;
	}
}

static int cipher_prepare(const struct voluta_cipher *ci,
			  const struct voluta_iv_key *iv_key)
{
	size_t blklen;
	gcry_error_t err;
	const struct voluta_iv *iv = &iv_key->iv;
	const struct voluta_key *key = &iv_key->key;

	blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	if (blklen > sizeof(iv->iv)) {
		log_warn("bad blklen: %lu", blklen);
		return -1;
	}
	err = gcry_cipher_reset(ci->cipher_hd);
	if (err) {
		log_gcrypt_err("gcry_cipher_reset", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_setkey(ci->cipher_hd, key->key, sizeof(key->key));
	if (err) {
		log_gcrypt_err("gcry_cipher_setkey", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_setiv(ci->cipher_hd, iv->iv, blklen);
	if (err) {
		log_gcrypt_err("gcry_cipher_setiv", err);
		return gcrypt_err(err);
	}
	return 0;
}

static int cipher_encrypt(const struct voluta_cipher *ci,
			  const void *in_dat, void *out_dat, size_t dat_len)
{
	gcry_error_t err;

	err = gcry_cipher_encrypt(ci->cipher_hd, out_dat,
				  dat_len, in_dat, dat_len);
	if (err) {
		log_gcrypt_err("gcry_cipher_encrypt", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_final(ci->cipher_hd);
	if (err) {
		log_gcrypt_err("gcry_cipher_final", err);
		return gcrypt_err(err);
	}
	return 0;
}

static int cipher_decrypt(const struct voluta_cipher *ci,
			  const void *in_dat, void *out_dat, size_t dat_len)
{
	gcry_error_t err;

	err = gcry_cipher_decrypt(ci->cipher_hd, out_dat,
				  dat_len, in_dat, dat_len);
	if (err) {
		log_gcrypt_err("gcry_cipher_decrypt", err);
		return gcrypt_err(err);
	}
	err = gcry_cipher_final(ci->cipher_hd);
	if (err) {
		log_gcrypt_err("gcry_cipher_final", err);
		return gcrypt_err(err);
	}
	return 0;
}

int voluta_encrypt_buf(const struct voluta_cipher *ci,
		       const struct voluta_iv_key *iv_key,
		       const void *in_dat, void *out_dat, size_t dat_len)
{
	int err;

	err = cipher_prepare(ci, iv_key);
	if (err) {
		return err;
	}
	err = cipher_encrypt(ci, in_dat, out_dat, dat_len);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_decrypt_buf(const struct voluta_cipher *ci,
		       const struct voluta_iv_key *iv_key,
		       const void *in_dat, void *out_dat, size_t dat_len)
{
	int err;

	err = cipher_prepare(ci, iv_key);
	if (err) {
		return err;
	}
	err = cipher_decrypt(ci, in_dat, out_dat, dat_len);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void passphrase_setup(struct voluta_passphrase *pp,
			     const void *pass, size_t passlen)
{
	voluta_memzero(pp, sizeof(*pp));
	if (passlen > 0) {
		memcpy(pp->pass, pass, passlen);
	}
	pp->passlen = passlen;
}

int voluta_passphrase_setup(struct voluta_passphrase *pp, const void *pass)
{
	size_t passlen;

	if (pass == NULL) {
		return -EINVAL;
	}
	passlen = strlen(pass);
	if (passlen >= sizeof(pp->pass)) {
		return -EINVAL;
	}
	passphrase_setup(pp, pass, passlen);
	return 0;
}

void voluta_passphrase_reset(struct voluta_passphrase *pp)
{
	voluta_memzero(pp, sizeof(*pp));
	pp->passlen = 0;
}

static int passphrase_check(const struct voluta_passphrase *pp)
{
	if (!pp->passlen || (pp->passlen > sizeof(pp->pass))) {
		return -EINVAL;
	}
	return 0;
}

static int derive_iv(const void *pass, size_t passlen,
		     const void *salt, size_t saltlen,
		     const struct voluta_kdf_desc *kd,
		     struct voluta_iv *iv)
{
	int ret = 0;
	gpg_error_t gcry_err;

	gcry_err = gcry_kdf_derive(pass, passlen,
				   (int)kd->kd_algo, /* GCRY_KDF_PBKDF2 */
				   (int)kd->kd_subalgo, /* GCRY_MD_SHA256 */
				   salt, saltlen,
				   kd->kd_iterations, /* 4096 */
				   sizeof(iv->iv), iv->iv);
	if (gcry_err) {
		log_gcrypt_err("gcry_kdf_derive", gcry_err);
		ret = gcrypt_err(gcry_err);
	}
	return ret;
}

static int derive_key(const void *pass, size_t passlen,
		      const void *salt, size_t saltlen,
		      const struct voluta_kdf_desc *kd,
		      struct voluta_key *key)
{
	int ret = 0;
	gpg_error_t gcry_err;

	gcry_err = gcry_kdf_derive(pass, passlen,
				   (int)kd->kd_algo, /* GCRY_KDF_SCRYPT */
				   (int)kd->kd_subalgo, /* 8 */
				   salt, saltlen,
				   kd->kd_iterations, /* 1024 */
				   sizeof(key->key), key->key);
	if (gcry_err) {
		log_gcrypt_err("gcry_kdf_derive", gcry_err);
		ret = gcrypt_err(gcry_err);
	}
	return ret;
}

int voluta_derive_iv_key(const struct voluta_passphrase *pp,
			 const struct voluta_kdf_pair *kdf,
			 const struct voluta_mdigest *md,
			 struct voluta_iv_key *iv_key)
{
	int err;
	struct voluta_hash512 sha;

	err = passphrase_check(pp);
	if (err) {
		return err;
	}
	voluta_sha3_512_of(md, pp->pass, pp->passlen, &sha);
	err = derive_iv(pp->pass, pp->passlen, sha.hash, sizeof(sha.hash),
			&kdf->kdf_iv, &iv_key->iv);
	if (err) {
		return err;
	}
	err = derive_key(pp->pass, pp->passlen, sha.hash, sizeof(sha.hash),
			 &kdf->kdf_key, &iv_key->key);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_fill_random(void *buf, size_t len, bool very_strong)
{
	const enum gcry_random_level random_level =
		very_strong ? GCRY_VERY_STRONG_RANDOM : GCRY_STRONG_RANDOM;

	gcry_randomize(buf, len, random_level);
}

void voluta_fill_random_ascii(char *str, size_t len)
{
	int nrands = 0;
	int print_ch;
	int rands[64];
	const int base = 33;
	const int last = 126;

	for (size_t i = 0; i < len; ++i) {
		if (nrands == 0) {
			nrands = ARRAY_SIZE(rands);
			voluta_fill_random(rands, sizeof(rands), 0);
		}
		print_ch = (abs(rands[--nrands]) % (last - base)) + base;
		str[i] = (char)print_ch;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_crypto_init(struct voluta_crypto *crypto)
{
	int err;

	memset(crypto, 0, sizeof(*crypto));
	err = voluta_mdigest_init(&crypto->md);
	if (err) {
		return err;
	}
	err = cipher_init(&crypto->ci);
	if (err) {
		voluta_mdigest_fini(&crypto->md);
		return err;
	}
	return 0;
}

void voluta_crypto_fini(struct voluta_crypto *crypto)
{
	cipher_fini(&crypto->ci);
	voluta_mdigest_fini(&crypto->md);

	memset(crypto, 0xEF, sizeof(*crypto));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void voluta_iv_key_reset(struct voluta_iv_key *iv_key)
{
	memset(iv_key, 0, sizeof(*iv_key));
}

static void iv_copyto(const struct voluta_iv *iv, struct voluta_iv *other)
{
	memcpy(other, iv, sizeof(*other));
}

static void key_copyto(const struct voluta_key *key, struct voluta_key *other)
{
	memcpy(other, key, sizeof(*other));
}

static void iv_key_zeropad(struct voluta_iv_key *iv_key)
{
	memset(iv_key->pad, 0, sizeof(iv_key->pad));
}

void voluta_iv_key_copyto(const struct voluta_iv_key *iv_key,
			  struct voluta_iv_key *other)
{
	iv_copyto(&iv_key->iv, &other->iv);
	key_copyto(&iv_key->key, &other->key);
	iv_key_zeropad(other);
}

void voluta_iv_key_assign(struct voluta_iv_key *iv_key,
			  const struct voluta_iv *iv,
			  const struct voluta_key *key)
{
	iv_copyto(iv, &iv_key->iv);
	key_copyto(key, &iv_key->key);
	iv_key_zeropad(iv_key);
}

void voluta_iv_rand(struct voluta_iv *iv)
{
	voluta_getentropy(iv, sizeof(*iv));
}

void voluta_key_rand(struct voluta_key *key, size_t nk)
{
	voluta_getentropy(key, nk * sizeof(*key));
}

void voluta_iv_key_rand(struct voluta_iv_key *iv_key)
{
	voluta_iv_rand(&iv_key->iv);
	voluta_key_rand(&iv_key->key, 1);
	voluta_memzero(iv_key->pad, sizeof(iv_key->pad));
}

