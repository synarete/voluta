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
#ifndef VOLUTA_SUPERB_H_
#define VOLUTA_SUPERB_H_

#include <unistd.h>
#include <voluta/defs.h>


struct voluta_super_block *voluta_sb_new(struct voluta_alloc_if *alif);

void voluta_sb_del(struct voluta_super_block *sb,
                   struct voluta_alloc_if *alif);

void voluta_sb_bind_hsm(struct voluta_super_block *sb,
                        voluta_index_t hs_index,
                        const struct voluta_vba *hsm_vba);

void voluta_sb_resolve_hsm(const struct voluta_super_block *sb,
                           voluta_index_t hs_index,
                           struct voluta_vba *out_vba);

bool voluta_sb_has_hsm(struct voluta_super_block *sb, voluta_index_t hs_index);


void voluta_sb_set_pass_hash(struct voluta_super_block *sb,
                             const struct voluta_hash512 *hash);

void voluta_sb_set_birth_time(struct voluta_super_block *sb, time_t btime);

void voluta_sb_set_ag_count(struct voluta_super_block *sb, size_t ag_count);

void voluta_sb_self_vaddr(const struct voluta_super_block *sb,
                          struct voluta_vaddr *out_vaddr);

void voluta_sb_set_self_vaddr(struct voluta_super_block *sb,
                              const struct voluta_vaddr *vaddr);

void voluta_sb_itable_root(const struct voluta_super_block *sb,
                           struct voluta_vaddr *out_vaddr);

void voluta_sb_set_itable_root(struct voluta_super_block *sb,
                               const struct voluta_vaddr *vaddr);

void voluta_sb_setup_keys(struct voluta_super_block *sb);

void voluta_sb_kivam_of(const struct voluta_super_block *sb,
                        const struct voluta_vaddr *vaddr,
                        struct voluta_kivam *out_kivam);

void voluta_sb_setup_rand(struct voluta_super_block *sb,
                          const struct voluta_mdigest *md);

int voluta_sb_check_volume(const struct voluta_super_block *sb);

int voluta_sb_check_pass_hash(const struct voluta_super_block *sb,
                              const struct voluta_hash512 *hash);

int voluta_sb_check_rand(const struct voluta_super_block *sb,
                         const struct voluta_mdigest *md);

int voluta_sb_encrypt_tail(struct voluta_super_block *sb,
                           const struct voluta_cipher *ci,
                           const struct voluta_kivam *kivam);

int voluta_sb_decrypt_tail(struct voluta_super_block *sb,
                           const struct voluta_cipher *ci,
                           const struct voluta_kivam *kivam);

int voluta_sb_encrypt(struct voluta_super_block *sb,
                      const struct voluta_crypto *crypto,
                      const struct voluta_passphrase *passph);

int voluta_sb_decrypt(struct voluta_super_block *sb,
                      const struct voluta_crypto *crypto,
                      const struct voluta_passphrase *passph);

void voluta_sb_setup_new(struct voluta_super_block *sb,
                         time_t btime, ssize_t vsize);

void voluta_sb_crypt_params(const struct voluta_super_block *sb,
                            struct voluta_crypt_params *cryp);

int voluta_sb_check_root(const struct voluta_super_block *sb);

ssize_t voluta_sb_volume_size(const struct voluta_super_block *sb);

void voluta_sb_set_volume_size(struct voluta_super_block *sb, ssize_t sz);

#endif /* VOLUTA_SUPERB_H_ */
