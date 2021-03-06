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
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <voluta/fs/types.h>
#include <voluta/fs/address.h>
#include <voluta/fs/mpool.h>
#include <voluta/fs/nodes.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/crypto.h>
#include <voluta/fs/locosd.h>
#include <voluta/fs/super.h>
#include <voluta/fs/superb.h>
#include <voluta/fs/spmaps.h>
#include <voluta/fs/itable.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/fuseq.h>
#include <voluta/fs/boot.h>
#include <voluta/fs/exec.h>
#include <voluta/fs/private.h>

#define ROUND_TO_K(n)  VOLUTA_ROUND_TO(n, VOLUTA_KILO)

struct voluta_fs_core {
	struct voluta_qalloc    qalloc;
	struct voluta_mpool     mpool;
	struct voluta_cache     cache;
	struct voluta_locosd    locosd;
	struct voluta_sb_info   sbinfo;
};

union voluta_fs_core_u {
	struct voluta_fs_core c;
	uint8_t dat[ROUND_TO_K(sizeof(struct voluta_fs_core))];
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
	size_t memsize = 0;
	struct voluta_qalloc *qalloc = &fse_obj_of(fse)->fs_core.c.qalloc;

	err = voluta_boot_memsize(fse->args.memwant, &memsize);
	if (err) {
		return err;
	}
	err = voluta_qalloc_init(qalloc, memsize);
	if (err) {
		return err;
	}
	fse->qalloc = qalloc;
	fse->alif = &qalloc->alif;
	return 0;
}

static void fse_fini_qalloc(struct voluta_fs_env *fse)
{
	if (fse->qalloc != NULL) {
		voluta_qalloc_fini(fse->qalloc);
		fse->qalloc = NULL;
		fse->alif = NULL;
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
		voluta_assert_eq(fse->mpool->mp_nbytes_alloc, 0);
		voluta_mpool_fini(fse->mpool);
		fse->mpool = NULL;
	}
}

static int fse_init_cache(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_cache *cache = &fse_obj_of(fse)->fs_core.c.cache;

	err = voluta_cache_init(cache, fse->qalloc, &fse->mpool->mp_alif);
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
	fse->sb = voluta_sb_new(&fse->qalloc->alif);
	return (fse->sb == NULL) ? -ENOMEM : 0;
}

static void fse_fini_sb(struct voluta_fs_env *fse)
{
	if (fse->sb != NULL) {
		voluta_sb_del(fse->sb, &fse->qalloc->alif);
		fse->sb = NULL;
	}
}

static int fse_init_sbi(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_sb_info *sbi = &fse_obj_of(fse)->fs_core.c.sbinfo;

	err = voluta_sbi_init(sbi, fse->cache, fse->locosd);
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

static int fse_init_locosd(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_locosd *locosd = &fse_obj_of(fse)->fs_core.c.locosd;

	err = voluta_locosd_init(locosd, &fse->qalloc->alif);
	if (!err) {
		fse->locosd = locosd;
	}
	return err;
}

static void fse_fini_locosd(struct voluta_fs_env *fse)
{
	if (fse->locosd != NULL) {
		voluta_locosd_fini(fse->locosd);
		fse->locosd = NULL;
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
		fse->qalloc->mode = 1;
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
	sbi->s_ms_flags |= ms_flag_with;
	sbi->s_ms_flags &= ~ms_flag_dont;
}

static int fse_check_args(const struct voluta_fs_args *args)
{
	int err;
	struct voluta_passphrase passph;

	if (!args->passwd) {
		return -ENOKEY;
	}
	err = voluta_passphrase_setup(&passph, args->passwd);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_apply_args(struct voluta_fs_env *fse,
                          const struct voluta_fs_args *args)
{
	int err;
	struct voluta_passphrase *passph = &fse->passph;

	/* TODO: check more */
	err = voluta_passphrase_setup(passph, args->passwd);
	if (err) {
		return err;
	}
	/* TODO: maybe strdup? */
	memcpy(&fse->args, args, sizeof(fse->args));
	return 0;
}

static enum voluta_flags fs_args_to_ctlflags(const struct voluta_fs_args *args)
{
	enum voluta_flags ctl_flags = 0;

	if (args->kcopy_mode) {
		ctl_flags |= VOLUTA_F_KCOPY;
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
	voluta_sbi_add_ctlflags(fse->sbi, ctl_flags);
	return 0;
}

static int fse_init(struct voluta_fs_env *fse,
                    const struct voluta_fs_args *args)
{
	int err;

	fse_init_commons(fse);
	err = fse_apply_args(fse, args);
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
	err = fse_init_locosd(fse);
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
	fse_fini_locosd(fse);
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
	err = voluta_zmalloc(sizeof(*fse_obj), &mem);
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
	struct voluta_fs_env_obj *fse_obj = fse_obj_of(fse);

	fse_fini(fse);
	voluta_zfree(fse_obj, sizeof(*fse_obj));
	voluta_burnstack();
}

static void fse_relax_cache(struct voluta_fs_env *fse)
{
	voluta_cache_relax(fse->cache, VOLUTA_F_BRINGUP);
}

static int fse_preset_space(struct voluta_fs_env *fse, loff_t volume_size)
{
	int err;

	err = voluta_sbi_setspace(fse->sbi, volume_size);
	if (err) {
		log_err("illegal volume size: %ld", volume_size);
		return err;
	}
	return 0;
}

static int fse_reload_space(struct voluta_fs_env *fse)
{
	int err;
	ssize_t volume_size;
	ssize_t capacity_size;

	volume_size = voluta_sb_volume_size(fse->sb);
	err = voluta_calc_volume_space(volume_size, &capacity_size);
	if (err) {
		log_err("illegal volume-size: %ld ", volume_size);
		return err;
	}
	err = fse_preset_space(fse, volume_size);
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

static int fse_create_osd(struct voluta_fs_env *fse)
{
	int err;

	err = voluta_locosd_open(fse->locosd, fse->args.objsdir);
	if (err) {
		return err;
	}
	err = voluta_locosd_format(fse->locosd);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_open_osd(struct voluta_fs_env *fse)
{
	int err;

	err = voluta_locosd_open(fse->locosd, fse->args.objsdir);
	if (err) {
		return err;
	}
	/* XXX TODO: check validity */
	return 0;
}

static int fse_close_locosd(struct voluta_fs_env *fse)
{
	return voluta_locosd_close(fse->locosd);
}

static int commit_dirty_now(struct voluta_sb_info *sbi, bool drop_caches)
{
	int err;

	err = voluta_flush_dirty(sbi, VOLUTA_F_NOW);
	if (!err && drop_caches) {
		voluta_cache_drop(sbi->s_cache);
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
	const char *mount_point = fse->args.mntdir;

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
	err = fse_close_locosd(fse);
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
	struct voluta_alloc_stat alst = { .nbytes_used = 0 };
	const struct voluta_cache *cache = fse->cache;
	const size_t nbk_in_bksec = VOLUTA_NBK_IN_BKSEC;

	voluta_allocstat(fse->alif, &alst);
	st->nalloc_bytes = alst.nbytes_used;
	st->ncache_blocks = cache->c_bsi_lm.htbl_size * nbk_in_bksec;
	st->ncache_znodes = cache->c_ci_lm.htbl_size;
}

int voluta_fse_rootid(const struct voluta_fs_env *fse, char *buf, size_t bsz)
{
	int err;
	size_t len = 0;
	const struct voluta_sb_info *sbi = fse->sbi;
	const struct voluta_blobid *root_bid = &sbi->s_vba.baddr.bid;

	if (bsz <= (2 * VOLUTA_BLOBID_LEN)) {
		return -EINVAL;
	}
	err = voluta_blobid_to_name(root_bid, buf, bsz - 1, &len);
	if (err) {
		return err;
	}
	buf[len] = '\0';
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_crypto *fse_crypto(const struct voluta_fs_env *fse)
{
	return &fse->sbi->s_crypto;
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
	return voluta_sbi_save_sb(fse->sbi);
}

static int fse_load_sb(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_sb_info *sbi = fse->sbi;

	err = voluta_sbi_load_sb(sbi);
	voluta_assert_ok(err);
	if (err) {
		return err;
	}
	err = voluta_sb_check_volume(sbi->sb);
	if (err) {
		voluta_assert_ok(err);
		return err;
	}
	return 0;
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
	struct voluta_crypt_params *cryp = &fse->cryp;
	const struct voluta_passphrase *pp = &fse->passph;

	if (!fse->passph.passlen) {
		log_err("missing passphrase of: %s", fse->args.objsdir);
		return -ENOKEY;
	}
	voluta_sb_crypt_params(fse->sb, cryp);
	err = voluta_derive_kivam(cryp, pp, fse_mdigest(fse), &fse->kivam);
	if (err) {
		log_err("derive iv-key failed: %s err=%d",
		        fse->args.objsdir, err);
		return err;
	}
	return 0;
}

static int fse_decrypt_sb(struct voluta_fs_env *fse)
{
	return voluta_sb_decrypt_tail(fse->sb, fse_cipher(fse), &fse->kivam);
}

static int fse_recheck_pass_hash(const struct voluta_fs_env *fse)
{
	struct voluta_hash512 hash;

	fse_calc_pass_hash(fse, &hash);
	return voluta_sb_check_pass_hash(fse->sb, &hash);
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

static int fse_encrypt_sb(struct voluta_fs_env *fse)
{
	return voluta_sb_encrypt_tail(fse->sb, fse_cipher(fse), &fse->kivam);
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

static int fse_resolve_sb_vba(const struct voluta_fs_env *fse,
                              struct voluta_vba *out_vba)
{
	int err = 0;
	const char *rootid = fse->args.rootid;

	voluta_vba_for_super(out_vba);
	if (rootid && strlen(rootid)) {
		err = voluta_baddr_parse_super(&out_vba->baddr, rootid);
	}
	return err;
}

static int fse_setup_sb(struct voluta_fs_env *fse, time_t birth_time)
{
	int err;
	struct voluta_vba vba;
	struct voluta_hash512 pass_hash;
	struct voluta_super_block *sb = fse->sb;
	const ssize_t vsize = fse->args.vsize;
	const time_t btime = birth_time ? birth_time : voluta_time_now();

	voluta_sb_setup_new(sb, btime, vsize);
	voluta_sb_setup_rand(sb, fse_mdigest(fse));

	fse_calc_pass_hash(fse, &pass_hash);
	voluta_sb_set_pass_hash(sb, &pass_hash);

	err = fse_resolve_sb_vba(fse, &vba);
	if (err) {
		return err;
	}
	voluta_sbi_bind_sb(fse->sbi, sb, &vba);
	return 0;
}

int voluta_fse_reload(struct voluta_fs_env *fse)
{
	int err;

	err = fse_setup_sb(fse, 0);
	if (err) {
		return err;
	}
	err = fse_open_osd(fse);
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

	err = fse_setup_sb(fse, 0);
	if (err) {
		return err;
	}
	err = fse_open_osd(fse);
	if (err) {
		return err;
	}
	err = fse_stage_sb(fse);
	if (err) {
		fse_close_locosd(fse);
		return err;
	}
	err = fse_close_locosd(fse);
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

	err = voluta_spawn_inode(sbi, op, parent_ino, 0, mode, 0, &root_ii);
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
	struct voluta_sb_info *sbi = fse->sbi;

	err = voluta_format_super(sbi);
	if (err) {
		return err;
	}
	err = voluta_format_spmaps(sbi);
	if (err) {
		return err;
	}
	err = voluta_format_itable(sbi);
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

static int fse_preformat_volume(struct voluta_fs_env *fse)
{
	int err;

	err = fse_preset_space(fse, fse->args.vsize);
	if (err) {
		return err;
	}
	err = fse_create_osd(fse);
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
	err = fse_setup_sb(fse, op.xtime.tv_sec);
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

int voluta_fse_serve(struct voluta_fs_env *fse)
{
	int err;

	if (!fse->args.with_fuseq || (fse->fuseq == NULL)) {
		return -EINVAL;
	}
	err = voluta_fse_reload(fse);
	if (err) {
		log_err("load-fs error: %s %d", fse->args.objsdir, err);
		return err;
	}
	err = voluta_fse_exec(fse);
	if (err) {
		log_err("exec-fs error: %s %d", fse->args.mntdir, err);
		/* no return -- do post-exec cleanups */
	}
	err = voluta_fse_shut(fse);
	if (err) {
		log_err("shut-fs error: %s %d", fse->args.objsdir, err);
		return err;
	}
	err = voluta_fse_term(fse);
	if (err) {
		log_err("term-fs error: %s %d", fse->args.mntdir, err);
		return err;
	}
	return 0;
}
