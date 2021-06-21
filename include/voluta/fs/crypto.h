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
#ifndef VOLUTA_CRYPTO_H_
#define VOLUTA_CRYPTO_H_


int voluta_init_gcrypt(void);

int voluta_crypto_init(struct voluta_crypto *crypto);

void voluta_crypto_fini(struct voluta_crypto *crypto);

int voluta_derive_kivam(const struct voluta_crypt_params *zcp,
                        const struct voluta_passphrase *pp,
                        const struct voluta_mdigest *md,
                        struct voluta_kivam *kivam);


void voluta_blake2s128_of(const struct voluta_mdigest *md,
                          const void *buf, size_t bsz,
                          struct voluta_hash128 *out_hash);

void voluta_sha256_of(const struct voluta_mdigest *md,
                      const void *buf, size_t bsz,
                      struct voluta_hash256 *out_hash);

void voluta_sha3_256_of(const struct voluta_mdigest *md,
                        const void *buf, size_t bsz,
                        struct voluta_hash256 *out_hash);

void voluta_sha3_512_of(const struct voluta_mdigest *md,
                        const void *buf, size_t bsz,
                        struct voluta_hash512 *out_hash);

void voluta_crc32_of(const struct voluta_mdigest *md,
                     const void *buf, size_t bsz, uint32_t *out_crc32);

int voluta_encrypt_buf(const struct voluta_cipher *ci,
                       const struct voluta_kivam *kivam,
                       const void *in_dat, void *out_dat, size_t dat_len);

int voluta_decrypt_buf(const struct voluta_cipher *ci,
                       const struct voluta_kivam *kivam,
                       const void *in_dat, void *out_dat, size_t dat_len);


int voluta_passphrase_setup(struct voluta_passphrase *pp, const void *pass);

void voluta_passphrase_reset(struct voluta_passphrase *pp);


void voluta_kivam_init(struct voluta_kivam *kivam);

void voluta_kivam_fini(struct voluta_kivam *kivam);

void voluta_kivam_copyto(const struct voluta_kivam *kivam,
                         struct voluta_kivam *other);

void voluta_gcry_randomize(void *buf, size_t len, bool very_strong);


#endif /* VOLUTA_CRYPTO_H_ */
