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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <uuid/uuid.h>
#include "libvoluta.h"

#define ROUND_TO_HK(n)  VOLUTA_ROUND_TO(n, 512)

struct voluta_fs_core {
	struct voluta_qalloc    qalloc;
	struct voluta_mpool     mpool;
	struct voluta_cache     cache;
	struct voluta_vstore    vstore;
	struct voluta_sb_info   sbi;
};

union voluta_fs_core_u {
	struct voluta_fs_core c;
	uint8_t dat[ROUND_TO_HK(sizeof(struct voluta_fs_core))];
};

union voluta_fuseq_page {
	struct voluta_fuseq     fuseq;
	uint8_t page[VOLUTA_PAGE_SIZE];
};

struct voluta_fs_env_obj {
	union voluta_fs_core_u   fs_core;
	struct voluta_fs_env     fs_env;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_sb_info *sbi_of(const struct voluta_fs_env *fse)
{
	return fse->sbi;
}

static struct voluta_fs_env_obj *fse_obj_of(struct voluta_fs_env *fse)
{
	return container_of(fse, struct voluta_fs_env_obj, fs_env);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fse_init_commons(struct voluta_fs_env *fse)
{
	voluta_memzero(fse, sizeof(*fse));
	voluta_kivam_init(&fse->kivam);
	voluta_passphrase_reset(&fse->passph);
	fse->args.uid = getuid();
	fse->args.gid = getgid();
	fse->args.pid = getpid();
	fse->args.umask = 0022;

	fse->volume_size = -1;
	fse->signum = 0;
}

static int fse_init_qalloc(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_qalloc *qalloc = &fse_obj_of(fse)->fs_core.c.qalloc;

	err = voluta_qalloc_init2(qalloc, fse->args.memwant);
	if (!err) {
		fse->qalloc = qalloc;
		fse->qalloc->mode = fse->args.pedantic;
	}
	return err;
}

static void fse_fini_qalloc(struct voluta_fs_env *fse)
{
	if (fse->qalloc != NULL) {
		voluta_qalloc_fini(fse->qalloc);
		fse->qalloc = NULL;
	}
}

static int fse_init_mpool(struct voluta_fs_env *fse)
{
	struct voluta_mpool *mpool = &fse_obj_of(fse)->fs_core.c.mpool;

	voluta_mpool_init(mpool, fse->qalloc);
	fse->mpool = mpool;
	return 0;
}

static void fse_fini_mpool(struct voluta_fs_env *fse)
{
	if (fse->mpool != NULL) {
		voluta_mpool_fini(fse->mpool);
		fse->mpool = NULL;
	}
}

static int fse_init_cache(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_cache *cache = &fse_obj_of(fse)->fs_core.c.cache;

	err = voluta_cache_init(cache, fse->mpool);
	if (!err) {
		fse->cache = cache;
	}
	return err;
}

static void fse_fini_cache(struct voluta_fs_env *fse)
{
	if (fse->cache != NULL) {
		voluta_cache_fini(fse->cache);
		fse->cache = NULL;
	}
}

static int fse_init_sb(struct voluta_fs_env *fse)
{
	fse->sb = voluta_sb_new(fse->qalloc, VOLUTA_ZTYPE_VOLUME);
	return (fse->sb == NULL) ? -ENOMEM : 0;
}

static void fse_fini_sb(struct voluta_fs_env *fse)
{
	if (fse->sb != NULL) {
		voluta_sb_del(fse->sb, fse->qalloc);
		fse->sb = NULL;
	}
}

static int fse_init_sbi(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_sb_info *sbi = &fse_obj_of(fse)->fs_core.c.sbi;

	err = voluta_sbi_init(sbi, fse->sb, fse->cache, fse->vstore);
	if (err) {
		return err;
	}
	fse->sbi = sbi;
	return 0;
}

static void fse_fini_sbi(struct voluta_fs_env *fse)
{
	if (fse->sbi != NULL) {
		voluta_sbi_fini(fse->sbi);
		fse->sbi = NULL;
	}
}

static int fse_init_vstore(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_vstore *vstore = &fse_obj_of(fse)->fs_core.c.vstore;

	err = voluta_vstore_init(vstore, fse->qalloc);
	if (!err) {
		fse->vstore = vstore;
	}
	return err;
}

static void fse_fini_vstore(struct voluta_fs_env *fse)
{
	if (fse->vstore != NULL) {
		voluta_vstore_fini(fse->vstore);
		fse->vstore = NULL;
	}
}

static union voluta_fuseq_page *fuseq_to_page(struct voluta_fuseq *fuseq)
{
	return container_of(fuseq, union voluta_fuseq_page, fuseq);
}

static int fse_init_fuseq(struct voluta_fs_env *fse)
{
	int err;
	void *mem;
	union voluta_fuseq_page *fuseq_pg = NULL;
	const size_t fuseq_pg_size = sizeof(*fuseq_pg);

	STATICASSERT_EQ(sizeof(*fuseq_pg), VOLUTA_PAGE_SIZE);

	if (!fse->args.with_fuseq) {
		return 0;
	}
	mem = voluta_qalloc_malloc(fse->qalloc, fuseq_pg_size);
	if (mem == NULL) {
		log_warn("failed to allocate fuseq: size=%lu", fuseq_pg_size);
		return -ENOMEM;
	}
	fuseq_pg = mem;
	err = voluta_fuseq_init(&fuseq_pg->fuseq, fse->sbi);
	if (err) {
		voluta_qalloc_free(fse->qalloc, mem, fuseq_pg_size);
		return err;
	}
	fse->fuseq = &fuseq_pg->fuseq;
	return 0;
}

static void fse_fini_fuseq(struct voluta_fs_env *fse)
{
	union voluta_fuseq_page *fuseq_pg = NULL;

	if (fse->fuseq != NULL) {
		fuseq_pg = fuseq_to_page(fse->fuseq);

		voluta_fuseq_fini(fse->fuseq);
		fse->fuseq = NULL;

		voluta_qalloc_free(fse->qalloc, fuseq_pg, sizeof(*fuseq_pg));
	}
}

static void fse_update_qalloc(struct voluta_fs_env *fse,
                              const struct voluta_fs_args *args)
{
	if (args->pedantic) {
		fse->qalloc->mode = true;
	}
}

static void fse_update_owner(struct voluta_fs_env *fse,
                             const struct voluta_fs_args *args)
{
	const struct voluta_ucred ucred = {
		.uid = args->uid,
		.gid = args->gid,
		.pid = args->pid,
		.umask = args->umask
	};

	voluta_sbi_setowner(fse->sbi, &ucred);
}

static void fse_update_mount_flags(struct voluta_fs_env *fse,
                                   const struct voluta_fs_args *args)
{
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;
	struct voluta_sb_info *sbi = fse->sbi;

	if (args->lazytime) {
		ms_flag_with |= MS_LAZYTIME;
	} else {
		ms_flag_dont |= MS_LAZYTIME;
	}
	if (args->noexec) {
		ms_flag_with |= MS_NOEXEC;
	} else {
		ms_flag_dont |= MS_NOEXEC;
	}
	if (args->nosuid) {
		ms_flag_with |= MS_NOSUID;
	} else {
		ms_flag_dont |= MS_NOSUID;
	}
	if (args->nodev) {
		ms_flag_with |= MS_NODEV;
	} else {
		ms_flag_dont |= MS_NODEV;
	}
	if (args->rdonly) {
		ms_flag_with |= MS_RDONLY;
	} else {
		ms_flag_dont |= MS_RDONLY;
	}
	sbi->sb_ms_flags |= ms_flag_with;
	sbi->sb_ms_flags &= ~ms_flag_dont;
}

static int fse_check_args(const struct voluta_fs_args *args)
{
	int err;
	struct voluta_passphrase passph;

	/* TODO: check more */
	if (args->encrypted || args->encryptwr || args->passwd) {
		err = voluta_passphrase_setup(&passph, args->passwd);
		if (err) {
			return err;
		}
	}
	return 0;
}

static int fse_copy_args(struct voluta_fs_env *fse,
                         const struct voluta_fs_args *args)
{
	int err;
	struct voluta_passphrase *passph = &fse->passph;

	/* TODO: check more */
	if (args->encrypted || args->encryptwr || args->passwd) {
		err = voluta_passphrase_setup(passph, args->passwd);
		if (err) {
			return err;
		}
	}
	/* TODO: maybe strdup? */
	memcpy(&fse->args, args, sizeof(fse->args));
	return 0;
}

static enum voluta_flags fs_args_to_ctlflags(const struct voluta_fs_args *args)
{
	enum voluta_flags ctl_flags = 0;

	if (args->encrypted || args->encryptwr) {
		if (args->encrypted) {
			ctl_flags |= VOLUTA_F_ENCRYPTED;
		}
		if (args->encryptwr) {
			ctl_flags |= VOLUTA_F_ENCRYPTWR;
		}
	}
	if (args->allowother) {
		ctl_flags |= VOLUTA_F_ALLOWOTHER;
	}
	return ctl_flags;
}

static int fse_update_by_args(struct voluta_fs_env *fse)
{
	const struct voluta_fs_args *args = &fse->args;
	const enum voluta_flags ctl_flags = fs_args_to_ctlflags(args);

	fse_update_owner(fse, args);
	fse_update_mount_flags(fse, args);
	fse_update_qalloc(fse, args);
	voluta_vstore_add_ctlflags(fse->vstore, ctl_flags);
	voluta_sbi_add_ctlflags(fse->sbi, ctl_flags);
	return 0;
}

static int fse_init(struct voluta_fs_env *fse,
                    const struct voluta_fs_args *args)
{
	int err;

	fse_init_commons(fse);
	err = fse_copy_args(fse, args);
	if (err) {
		return err;
	}
	err = fse_init_qalloc(fse);
	if (err) {
		return err;
	}
	err = fse_init_mpool(fse);
	if (err) {
		return err;
	}
	err = fse_init_cache(fse);
	if (err) {
		return err;
	}
	err = fse_init_vstore(fse);
	if (err) {
		return err;
	}
	err = fse_init_sb(fse);
	if (err) {
		return err;
	}
	err = fse_init_sbi(fse);
	if (err) {
		return err;
	}
	err = fse_init_fuseq(fse);
	if (err) {
		return err;
	}
	err = fse_update_by_args(fse);
	if (err) {
		return err;
	}
	return 0;
}

static void fse_fini_commons(struct voluta_fs_env *fse)
{
	voluta_kivam_fini(&fse->kivam);
	voluta_passphrase_reset(&fse->passph);
	fse->volume_size = -1;
}

static void fse_fini(struct voluta_fs_env *fse)
{
	fse_fini_fuseq(fse);
	fse_fini_sbi(fse);
	fse_fini_sb(fse);
	fse_fini_vstore(fse);
	fse_fini_cache(fse);
	fse_fini_mpool(fse);
	fse_fini_qalloc(fse);
	fse_fini_commons(fse);
}

int voluta_fse_new(const struct voluta_fs_args *args,
                   struct voluta_fs_env **out_fse)
{
	int err;
	void *mem = NULL;
	struct voluta_fs_env *fse = NULL;
	struct voluta_fs_env_obj *fse_obj = NULL;

	err = fse_check_args(args);
	if (err) {
		return err;
	}
	err = voluta_zalloc_aligned(sizeof(*fse_obj), &mem);
	if (err) {
		return err;
	}
	fse_obj = mem;
	fse = &fse_obj->fs_env;

	err = fse_init(fse, args);
	if (err) {
		fse_fini(fse);
		free(mem);
		return err;
	}
	*out_fse = fse;
	voluta_burnstack();
	return 0;
}

void voluta_fse_del(struct voluta_fs_env *fse)
{
	struct voluta_fs_env_obj *fse_obj;

	fse_obj = fse_obj_of(fse);
	fse_fini(fse);

	memset(fse_obj, 7, sizeof(*fse_obj));
	free(fse_obj);
	voluta_burnstack();
}

static void fse_relax_cache(struct voluta_fs_env *fse)
{
	voluta_cache_relax(fse->cache, VOLUTA_F_BRINGUP);
}

static int fse_preset_space(struct voluta_fs_env *fse, loff_t size)
{
	int err;

	err = voluta_sbi_setspace(fse->sbi, size);
	if (err) {
		log_err("illegal volume size: %ld %s", size, fse->args.volume);
		return err;
	}
	return 0;
}

static loff_t fse_vstore_size(const struct voluta_fs_env *fse)
{
	return fse->vstore->vs_pstore.ps_size;
}

static int fse_reload_space(struct voluta_fs_env *fse)
{
	int err;
	loff_t zsize;
	loff_t persistent_size;
	loff_t capacity_size;
	loff_t address_space;

	zsize = (loff_t)voluta_zb_size(&fse->sb->s_zero);
	err = voluta_calc_volume_space(zsize, &capacity_size, &address_space);
	if (err) {
		log_err("illegal volume zsize: %ld ", zsize);
		return err;
	}
	persistent_size = fse_vstore_size(fse);
	if (persistent_size > address_space) {
		log_err("illegal volume: address_space=%ld "
		        "persistent_size=%ld", address_space, persistent_size);
		return -EINVAL;
	}
	err = fse_preset_space(fse, zsize);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_reload_meta(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_sb_info *sbi = sbi_of(fse);

	err = fse_reload_space(fse);
	if (err) {
		return err;
	}
	err = voluta_adjust_super(sbi);
	if (err) {
		return err;
	}
	err = voluta_reload_spmaps(sbi);
	if (err) {
		return err;
	}
	err = voluta_reload_itable(sbi);
	if (err) {
		return err;
	}
	fse_relax_cache(fse);
	return 0;
}

static int fse_open_vstore(struct voluta_fs_env *fse)
{
	int err;
	const char *path = fse->args.volume;
	const bool rw = !fse->args.rdonly;

	err = voluta_require_volume_path(path, rw);
	if (err) {
		return err;
	}
	err = voluta_vstore_open(fse->vstore, path, rw);
	if (err) {
		return err;
	}
	err = voluta_vstore_check_size(fse->vstore);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_create_vstore(struct voluta_fs_env *fse)
{
	int err;
	const char *path = fse->args.volume;
	const loff_t address_space = fse->sbi->sb_spi.sp_address_space;

	err = voluta_vstore_create(fse->vstore, path, address_space);
	if (err) {
		return err;
	}
	err = voluta_vstore_expand(fse->vstore, address_space);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_close_vstore(struct voluta_fs_env *fse)
{
	voluta_vstore_close(fse->vstore);
	return 0;
}

static int commit_dirty_now(struct voluta_sb_info *sbi, bool drop_caches)
{
	int err;

	err = voluta_flush_dirty(sbi, VOLUTA_F_NOW);
	if (!err && drop_caches) {
		voluta_cache_drop(sbi->sb_cache);
	}
	return err;
}

static int fse_flush_dirty(const struct voluta_fs_env *fse, bool drop_caches)
{
	return commit_dirty_now(fse->sbi, drop_caches);
}

static int voluta_fse_shut(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_sb_info *sbi = sbi_of(fse);

	err = fse_flush_dirty(fse, false);
	if (err) {
		return err;
	}
	err = voluta_shut_super(sbi);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse, true);
	if (err) {
		return err;
	}
	voluta_burnstack();
	return err;
}

static int voluta_fse_exec(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_fuseq *fq = fse->fuseq;
	const char *mount_point = fse->args.mountp;

	err = voluta_fuseq_mount(fq, mount_point);
	if (!err) {
		err = voluta_fuseq_exec(fq);
	}
	voluta_fuseq_term(fq);

	return err;
}

int voluta_fse_term(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_sb_info *sbi = sbi_of(fse);

	err = voluta_shut_super(sbi);
	if (err) {
		return err;
	}
	err = fse_close_vstore(fse);
	if (err) {
		return err;
	}
	voluta_burnstack();
	return 0;
}

void voluta_fse_halt(struct voluta_fs_env *fse, int signum)
{
	fse->signum = signum;
	if (fse->fuseq != NULL) {
		fse->fuseq->fq_active = 0;
	}
}

int voluta_fse_sync_drop(struct voluta_fs_env *fse)
{
	return fse_flush_dirty(fse, true);
}

void voluta_fse_stats(const struct voluta_fs_env *fse,
                      struct voluta_fs_stats *st)
{
	const struct voluta_cache *cache = fse->cache;

	st->nalloc_bytes = cache->c_qalloc->st.nbytes_used;
	st->ncache_blocks = cache->c_blm.htbl_size;
	st->ncache_inodes = cache->c_ilm.htbl_size;
	st->ncache_vnodes = cache->c_vlm.htbl_size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_crypto *fse_crypto(const struct voluta_fs_env *fse)
{
	return &fse->sbi->sb_vstore->vs_crypto;
}

static const struct voluta_cipher *fse_cipher(const struct voluta_fs_env *fse)
{
	return &fse_crypto(fse)->ci;
}

static const struct voluta_mdigest *
fse_mdigest(const struct voluta_fs_env *fse)
{
	return &fse_crypto(fse)->md;
}

static int fse_save_sb(struct voluta_fs_env *fse)
{
	int err;
	const loff_t off = lba_to_off(VOLUTA_LBA_SB);
	const struct voluta_super_block *sb = fse->sb;

	err = voluta_vstore_write(fse->vstore, off, sizeof(*sb), sb);
	if (err) {
		log_err("write sb failed: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_load_sb(struct voluta_fs_env *fse)
{
	int err;
	const loff_t off = lba_to_off(VOLUTA_LBA_SB);
	struct voluta_super_block *sb = fse->sb;

	err = voluta_vstore_read(fse->vstore, off, sizeof(*sb), sb);
	if (err) {
		log_err("read sb failed: err=%d", err);
		return err;
	}
	err = voluta_sb_check_volume(sb);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_check_zb_mode(const struct voluta_fs_env *fse)
{
	const enum voluta_flags ctl_flags = fse->sbi->sb_ctl_flags;
	const struct voluta_zero_block4 *zb = &fse->sb->s_zero;
	const bool zb_enc = voluta_zb_is_encrypted(zb);

	if (zb_enc && !(ctl_flags & VOLUTA_F_ENCRYPTED)) {
		log_err("encrypted zb: %s", fse->args.volume);
		return -ENOKEY;
	}
	if (!zb_enc && (ctl_flags & VOLUTA_F_ENCRYPTED)) {
		log_err("non encrypted zb: %s", fse->args.volume);
		return -EKEYREJECTED;
	}
	return 0;
}

static bool fse_encrypted_mode(const struct voluta_fs_env *fse)
{
	const enum voluta_flags ctl_flags = fse->sbi->sb_ctl_flags;

	return (ctl_flags & VOLUTA_F_ENCRYPTED) > 0;
}

static bool fse_encrypt_mode(const struct voluta_fs_env *fse)
{
	const enum voluta_flags ctl_flags = fse->sbi->sb_ctl_flags;

	return (ctl_flags & (VOLUTA_F_ENCRYPTED | VOLUTA_F_ENCRYPTWR)) > 0;
}

static void fse_calc_pass_hash(const struct voluta_fs_env *fse,
                               struct voluta_hash512 *out_hash)
{
	const struct voluta_mdigest *md = fse_mdigest(fse);
	const struct voluta_passphrase *pp = &fse->passph;

	if (pp->passlen) {
		voluta_sha3_512_of(md, pp->pass, pp->passlen, out_hash);
	} else {
		voluta_memzero(out_hash, sizeof(*out_hash));
	}
}

static int fse_update_sb(struct voluta_fs_env *fse)
{
	struct voluta_hash512 pass_hash;

	fse_calc_pass_hash(fse, &pass_hash);
	voluta_sb_set_pass_hash(fse->sb, &pass_hash);
	return 0;
}

static int fse_prepare_sb_key(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_zcrypt_params *zcp = &fse->zcryp;
	const struct voluta_passphrase *pp = &fse->passph;
	const struct voluta_zero_block4 *zb = &fse->sb->s_zero;

	if (fse_encrypt_mode(fse) && !fse->passph.passlen) {
		log_err("missing passphrase of: %s", fse->args.volume);
		return -ENOKEY;
	}
	if (!fse->passph.passlen) {
		return 0;
	}
	voluta_zb_crypt_params(zb, zcp);
	err = voluta_derive_kivam(zcp, pp, fse_mdigest(fse), &fse->kivam);
	if (err) {
		log_err("derive iv-key failed: %s err=%d",
		        fse->args.volume, err);
		return err;
	}
	return 0;
}

static int fse_decrypt_sb(struct voluta_fs_env *fse)
{
	int err;

	if (!voluta_zb_is_encrypted(&fse->sb->s_zero)) {
		return 0;
	}
	err = voluta_sb_decrypt_tail(fse->sb, fse_cipher(fse), &fse->kivam);
	if (err) {
		return err;
	}
	voluta_zb_set_encrypted(&fse->sb->s_zero, false);
	return 0;
}

static int fse_recheck_pass_hash(const struct voluta_fs_env *fse)
{
	int err = 0;
	struct voluta_hash512 hash;

	if (fse->passph.passlen && fse_encrypted_mode(fse)) {
		fse_calc_pass_hash(fse, &hash);
		err = voluta_sb_check_pass_hash(fse->sb, &hash);
	}
	return err;
}

static int fse_recheck_sb(const struct voluta_fs_env *fse)
{
	int err;

	err = voluta_sb_check_volume(fse->sb);
	if (err) {
		return err;
	}
	err = fse_recheck_pass_hash(fse);
	if (err) {
		return err;
	}
	err = voluta_sb_check_rand(fse->sb, fse_mdigest(fse));
	if (err) {
		return err;
	}
	return 0;
}

static int fse_stage_sb(struct voluta_fs_env *fse)
{
	int err;

	err = fse_load_sb(fse);
	if (err) {
		return err;
	}
	err = fse_check_zb_mode(fse);
	if (err) {
		return err;
	}
	err = fse_prepare_sb_key(fse);
	if (err) {
		return err;
	}
	err = fse_decrypt_sb(fse);
	if (err) {
		return err;
	}
	err = fse_recheck_sb(fse);
	if (err) {
		return err;
	}
	return 0;
}

static bool fse_want_encryptwr(const struct voluta_fs_env *fse)
{
	const unsigned long mask = VOLUTA_F_ENCRYPTWR;
	const unsigned long sb_flags = fse->sbi->sb_ctl_flags;

	return ((sb_flags & mask) == mask);
}

static int fse_encrypt_sb(struct voluta_fs_env *fse)
{
	int err;
	const bool want_enc = fse_want_encryptwr(fse);
	const bool curr_enc = voluta_zb_is_encrypted(&fse->sb->s_zero);

	if (want_enc == curr_enc) {
		return 0;
	}
	err = voluta_sb_encrypt_tail(fse->sb, fse_cipher(fse), &fse->kivam);
	if (err) {
		return err;
	}
	voluta_zb_set_encrypted(&fse->sb->s_zero, true);
	return 0;
}

static int fse_store_sb(struct voluta_fs_env *fse)
{
	int err;

	err = fse_recheck_sb(fse);
	if (err) {
		return err;
	}
	err = fse_update_sb(fse);
	if (err) {
		return err;
	}
	err = fse_encrypt_sb(fse);
	if (err) {
		return err;
	}
	err = fse_save_sb(fse);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_fse_reload(struct voluta_fs_env *fse)
{
	int err;

	err = fse_open_vstore(fse);
	if (err) {
		return err;
	}
	err = fse_stage_sb(fse);
	if (err) {
		return err;
	}
	err = fse_reload_meta(fse);
	if (err) {
		return err;
	}
	voluta_burnstack();
	return 0;
}

int voluta_fse_verify(struct voluta_fs_env *fse)
{
	int err;

	err = fse_open_vstore(fse);
	if (err) {
		return err;
	}
	err = fse_stage_sb(fse);
	if (err) {
		fse_close_vstore(fse);
		return err;
	}
	err = fse_close_vstore(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_format_rootdir(const struct voluta_fs_env *fse,
                              const struct voluta_oper *op)
{
	int err;
	const mode_t mode = S_IFDIR | 0755;
	struct voluta_inode_info *root_ii = NULL;
	struct voluta_sb_info *sbi = fse->sbi;
	const ino_t parent_ino = VOLUTA_INO_NULL;

	err = voluta_create_inode(sbi, op, parent_ino, 0, mode, 0, &root_ii);
	if (err) {
		return err;
	}
	voluta_fixup_rootdir(root_ii);
	err = voluta_bind_rootdir(sbi, root_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_format_fs_meta(const struct voluta_fs_env *fse,
                              const struct voluta_oper *op)
{
	int err;

	err = voluta_adjust_super(fse->sbi);
	if (err) {
		return err;
	}
	err = voluta_format_spmaps(fse->sbi);
	if (err) {
		return err;
	}
	err = voluta_format_itable(fse->sbi);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse, false);
	if (err) {
		return err;
	}
	err = fse_format_rootdir(fse, op);
	if (err) {
		return err;
	}
	voluta_burnstack();
	return 0;
}

static int fse_setup_sb(struct voluta_fs_env *fse,
                        const struct voluta_oper *op)
{
	struct voluta_hash512 pass_hash;
	struct voluta_super_block *sb = fse->sb;

	fse_calc_pass_hash(fse, &pass_hash);
	voluta_sb_set_pass_hash(sb, &pass_hash);
	voluta_sb_set_birth_time(sb, op->xtime.tv_sec);
	voluta_sb_setup_keys(sb);
	voluta_sb_setup_rand(sb, fse_mdigest(fse));
	voluta_zb_set_size(&sb->s_zero, (size_t)fse->args.vsize);
	return 0;
}

static int fse_preformat_volume(struct voluta_fs_env *fse)
{
	int err;

	err = fse_preset_space(fse, fse->args.vsize);
	if (err) {
		return err;
	}
	err = fse_create_vstore(fse);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_make_oper_self(struct voluta_fs_env *fse,
                              struct voluta_oper *op)
{
	voluta_memzero(op, sizeof(*op));

	op->ucred.uid = fse->args.uid;
	op->ucred.gid = fse->args.gid;
	op->ucred.pid = fse->args.pid;
	op->ucred.umask = fse->args.umask;
	op->unique = -1; /* TODO: make me a negative running sequence no */

	return voluta_ts_gettime(&op->xtime, true);
}

int voluta_fse_format(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_oper op;

	err = fse_make_oper_self(fse, &op);
	if (err) {
		return err;
	}
	err = fse_setup_sb(fse, &op);
	if (err) {
		return err;
	}
	err = fse_preformat_volume(fse);
	if (err) {
		return err;
	}
	err = fse_prepare_sb_key(fse);
	if (err) {
		return err;
	}
	err = fse_format_fs_meta(fse, &op);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse, true);
	if (err) {
		return err;
	}
	err = fse_store_sb(fse);
	if (err) {
		return err;
	}
	err = fse_stage_sb(fse);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_fse_traverse(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_oper op;

	err = fse_make_oper_self(fse, &op);
	if (err) {
		return err;
	}
	err = voluta_fse_reload(fse);
	if (err) {
		return err;
	}
	err = voluta_traverse_space(fse->sbi);
	if (err) {
		return err;
	}
	err = fse_flush_dirty(fse, true);
	if (err) {
		return err;
	}
	err = fse_store_sb(fse);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_fse_serve(struct voluta_fs_env *fse)
{
	int err;
	const char *volume = fse->args.volume;
	const char *mntpath = fse->args.mountp;

	if (!fse->args.with_fuseq || (fse->fuseq == NULL)) {
		return -EINVAL;
	}
	err = voluta_fse_reload(fse);
	if (err) {
		log_err("load-fs error: %s %d", volume, err);
		return err;
	}
	err = voluta_fse_exec(fse);
	if (err) {
		log_err("exec-fs error: %s %d", mntpath, err);
		/* no return -- do post-exec cleanups */
	}
	err = voluta_fse_shut(fse);
	if (err) {
		log_err("shut-fs error: %s %d", volume, err);
		return err;
	}
	err = voluta_fse_term(fse);
	if (err) {
		log_err("term-fs error: %s %d", mntpath, err);
		return err;
	}
	return 0;
}



