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
	struct voluta_sb_info   sbi;
	struct voluta_fuseq     fuseq;
	struct voluta_cache     cache;
	struct voluta_pstore    pstore;
};

union voluta_fs_core_u {
	struct voluta_fs_core c;
	uint8_t dat[ROUND_TO_HK(sizeof(struct voluta_fs_core))];
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

static void fse_init_defaults(struct voluta_fs_env *fse)
{
	voluta_memzero(fse, sizeof(*fse));
	fse->args.uid = getuid();
	fse->args.gid = getgid();
	fse->args.pid = getpid();
	fse->args.umask = 0022;
}

static int fse_init_qalloc(struct voluta_fs_env *fse, size_t memwant)
{
	int err;
	struct voluta_qalloc *qalloc = &fse_obj_of(fse)->fs_core.c.qalloc;

	err = voluta_qalloc_init2(qalloc, memwant);
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

	err = voluta_sbi_init(sbi, fse->sb, fse->cache, fse->pstore);
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

static int fse_init_pstore(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_pstore *pstore = &fse_obj_of(fse)->fs_core.c.pstore;

	err = voluta_pstore_init(pstore);
	if (!err) {
		fse->pstore = pstore;
	}
	return err;
}

static void fse_fini_pstore(struct voluta_fs_env *fse)
{
	if (fse->pstore != NULL) {
		voluta_pstore_fini(fse->pstore);
		fse->pstore = NULL;
	}
}

static int fse_init_fuseq(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_fuseq *fuseq = &fse_obj_of(fse)->fs_core.c.fuseq;

	err = voluta_fuseq_init(fuseq, fse->sbi);
	if (!err) {
		fse->fuseq = fuseq;
	}
	return err;
}

static void fse_fini_fuseq(struct voluta_fs_env *fse)
{
	if (fse->fuseq != NULL) {
		voluta_fuseq_fini(fse->fuseq);
		fse->fuseq = NULL;
	}
}

static int fse_init(struct voluta_fs_env *fse, size_t memwant)
{
	int err;

	fse_init_defaults(fse);
	err = fse_init_qalloc(fse, memwant);
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
	err = fse_init_pstore(fse);
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
	return 0;
}

static void fse_fini(struct voluta_fs_env *fse)
{
	fse_fini_fuseq(fse);
	fse_fini_sbi(fse);
	fse_fini_sb(fse);
	fse_fini_pstore(fse);
	fse_fini_cache(fse);
	fse_fini_mpool(fse);
	fse_fini_qalloc(fse);
}

int voluta_fse_new(size_t memwant, struct voluta_fs_env **out_fse)
{
	int err;
	void *mem = NULL;
	struct voluta_fs_env *fse = NULL;
	struct voluta_fs_env_obj *fse_obj = NULL;

	err = voluta_zalloc_aligned(sizeof(*fse_obj), &mem);
	if (err) {
		return err;
	}
	fse_obj = mem;
	fse = &fse_obj->fs_env;

	err = fse_init(fse, memwant);
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
	loff_t sp_size;

	err = voluta_resolve_volume_size(fse->args.volume, size, &sp_size);
	if (err) {
		log_err("illegal volume size: %s", fse->args.volume);
		return err;
	}
	voluta_sbi_setspace(fse->sbi, sp_size);
	fse->sbi->sb_volpath = fse->args.volume;
	return 0;
}

static loff_t fse_pstore_size(const struct voluta_fs_env *fse)
{
	return fse->pstore->ps_size;
}

static int fse_reload_space(struct voluta_fs_env *fse)
{
	int err;
	loff_t zsize;
	loff_t vsize;
	loff_t psize;

	zsize = (loff_t)voluta_zb_size(&fse->sb->s_zero);
	err = voluta_calc_vsize(zsize, 0, &vsize);
	if (err) {
		return err;
	}
	psize = fse_pstore_size(fse);
	if (psize > vsize) {
		log_err("illegal volume: vsize=%lu psize=%ld", vsize, psize);
		return -EINVAL;
	}
	err = fse_preset_space(fse, vsize);
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

static int fse_open_pstore(struct voluta_fs_env *fse)
{
	int err;
	const char *path = fse->args.volume;

	err = voluta_require_volume_path(path, R_OK | W_OK);
	if (err) {
		return err;
	}
	err = voluta_pstore_open(fse->pstore, path, true);
	if (err) {
		return err;
	}
	err = voluta_pstore_check_volsize(fse->pstore);
	if (err) {
		return err;
	}
	err = voluta_pstore_flock(fse->pstore);
	if (err) {
		return err;
	}
	fse->sbi->sb_volpath = path;
	return 0;
}

static int fse_create_pstore(struct voluta_fs_env *fse)
{
	int err;
	const loff_t vsize_min = VOLUTA_VOLUME_SIZE_MIN;

	err = voluta_pstore_create(fse->pstore, fse->args.volume, 0);
	if (err) {
		return err;
	}
	err = voluta_pstore_expand(fse->pstore, vsize_min);
	if (err) {
		return err;
	}
	err = voluta_pstore_flock(fse->pstore);
	if (err) {
		return err;
	}
	return 0;
}

static int fse_close_pstore(struct voluta_fs_env *fse)
{
	int err;

	err = voluta_pstore_funlock(fse->pstore);
	if (err) {
		return err;
	}
	voluta_pstore_close(fse->pstore);
	fse->sbi->sb_volpath = NULL;
	return 0;
}

static int commit_dirty_now(struct voluta_sb_info *sbi, bool drop_caches)
{
	int err;

	err = voluta_flush_dirty(sbi, VOLUTA_F_SYNC | VOLUTA_F_NOW);
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
	err = fse_close_pstore(fse);
	if (err) {
		return err;
	}
	voluta_burnstack();
	return 0;
}

void voluta_fse_halt(struct voluta_fs_env *fse, int signum)
{
	fse->signum = signum;
	fse->fuseq->fq_active = 0;
}

int voluta_fse_sync_drop(struct voluta_fs_env *fse)
{
	return fse_flush_dirty(fse, true);
}
static void fse_update_owner(struct voluta_fs_env *fse)
{
	const struct voluta_fs_args *args = &fse->args;
	const struct voluta_ucred ucred = {
		.uid = args->uid,
		.gid = args->gid,
		.pid = args->pid,
		.umask = args->umask
	};

	voluta_sbi_setowner(fse->sbi, &ucred);
}
static void fse_update_mnt_flags(struct voluta_fs_env *fse)
{
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;
	struct voluta_sb_info *sbi = fse->sbi;
	const struct voluta_fs_args *args = &fse->args;

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

int voluta_fse_setargs(struct voluta_fs_env *fse,
		       const struct voluta_fs_args *args)
{
	int err;
	struct voluta_passphrase passph;

	/* TODO: check params, strdup */
	memcpy(&fse->args, args, sizeof(fse->args));
	fse_update_owner(fse);
	fse_update_mnt_flags(fse);

	if (args->encrypted) {
		err = voluta_passphrase_setup(&passph, args->passwd);
		if (err) {
			return err;
		}
		voluta_sbi_addflags(fse->sbi, VOLUTA_F_ENCRYPT);
	}
	if (args->spliced) {
		voluta_sbi_addflags(fse->sbi, VOLUTA_F_SPLICED);
	}
	if (args->pedantic) {
		fse->qalloc->mode = true;
	}
	return 0;
}

void voluta_fse_stats(const struct voluta_fs_env *fse,
		      struct voluta_fs_stats *st)
{
	const struct voluta_cache *cache = fse->cache;

	st->nalloc_bytes = cache->c_qalloc->st.nbytes_used;
	st->ncache_blocks = cache->c_blm.count;
	st->ncache_inodes = cache->c_ilm.count;
	st->ncache_vnodes = cache->c_vlm.count;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_crypto *fse_crypto(const struct voluta_fs_env *fse)
{
	return &fse->sbi->sb_crypto;
}

static const struct voluta_mdigest *
fse_mdigest(const struct voluta_fs_env *fse)
{
	return &fse_crypto(fse)->md;
}

static int fse_encrypt_sb(struct voluta_fs_env *fse)
{
	return !fse->args.encrypted ? 0 :
	       voluta_sb_encrypt(fse->sb, fse_crypto(fse), fse->args.passwd);
}

static int fse_save_sb(struct voluta_fs_env *fse)
{
	int err;
	const struct voluta_super_block *sb = fse->sb;

	err = voluta_pstore_write(fse->pstore, 0, sizeof(*sb), sb);
	if (err) {
		log_err("write sb failed: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_store_sb(struct voluta_fs_env *fse)
{
	int err;

	err = voluta_sb_check_volume(fse->sb);
	if (err) {
		return err;
	}
	err = voluta_sb_check_rand(fse->sb, fse_mdigest(fse));
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

static int fse_load_sb(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_super_block *sb = fse->sb;

	err = voluta_pstore_read(fse->pstore, 0, sizeof(*sb), sb);
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

static int fse_decrypt_sb(struct voluta_fs_env *fse)
{
	int err;
	int zb_enc;
	enum voluta_zbf zbf;

	zbf = voluta_zb_flags(&fse->sb->s_zero);
	zb_enc = (int)zbf & VOLUTA_ZBF_ENCRYPTED;
	if (zb_enc && !fse->args.encrypted) {
		log_err("encrypted zb: flags=0x%x", zbf);
		return -ENOKEY;
	}
	if (!zb_enc && fse->args.encrypted) {
		log_err("non encrypted zb: flags=0x%x", zbf);
		return -EKEYREJECTED;
	}
	if (!zb_enc) {
		return 0;
	}
	err = voluta_sb_decrypt(fse->sb, fse_crypto(fse), fse->args.passwd);
	if (err) {
		log_err("decrypt sb tail failed: err=%d", err);
		return err;
	}
	return 0;
}

static int fse_recheck_sb(struct voluta_fs_env *fse)
{
	int err;

	err = voluta_sb_check_volume(fse->sb);
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

int voluta_fse_reload(struct voluta_fs_env *fse)
{
	int err;

	err = fse_open_pstore(fse);
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

	err = fse_open_pstore(fse);
	if (err) {
		return err;
	}
	err = fse_stage_sb(fse);
	if (err) {
		fse_close_pstore(fse);
		return err;
	}
	err = fse_close_pstore(fse);
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

	err = voluta_create_inode(sbi, op, mode, VOLUTA_INO_NULL, 0, &root_ii);
	if (err) {
		return err;
	}
	voluta_fixup_rootdir(root_ii);
	voluta_bind_rootdir(sbi, root_ii);
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
	size_t vol_size;
	size_t ag_count;
	struct voluta_super_block *sb = fse->sb;

	vol_size = (size_t)fse->args.vsize;
	ag_count = voluta_size_to_ag_count(vol_size);
	voluta_sb_set_birth_time(sb, op->xtime.tv_sec);
	voluta_sb_setup_ivks(sb);
	voluta_sb_setup_rand(sb, fse_mdigest(fse));
	voluta_sb_set_ag_count(sb, ag_count);
	voluta_zb_set_size(&sb->s_zero, vol_size);
	return 0;
}

static int fse_prepare_volume(struct voluta_fs_env *fse,
			      const struct voluta_oper *op)
{
	int err;

	err = fse_preset_space(fse, fse->args.vsize);
	if (err) {
		return err;
	}
	err = fse_create_pstore(fse);
	if (err) {
		return err;
	}
	err = fse_setup_sb(fse, op);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_fse_format(struct voluta_fs_env *fse)
{
	int err;
	struct voluta_oper op = {
		.ucred.uid = fse->args.uid,
		.ucred.gid = fse->args.gid,
		.ucred.pid = fse->args.pid,
		.ucred.umask = fse->args.umask,
		.unique = 1,
	};

	err = voluta_ts_gettime(&op.xtime, true);
	if (err) {
		return err;
	}
	err = fse_prepare_volume(fse, &op);
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
	return 0;
}

int voluta_fse_serve(struct voluta_fs_env *fse)
{
	int err;
	const char *volume = fse->args.volume;
	const char *mntpath = fse->args.mountp;

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



