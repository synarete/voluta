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
#ifndef LIBVOLUTA_H_
#define LIBVOLUTA_H_

#ifndef VOLUTA_LIBPRIVATE
#error "internal library header -- do not include!"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <voluta/voluta.h>
#include <voluta/syscall.h>
#include "aliases.h"
#include "inlines.h"

struct statvfs;
struct fiemap;

/* zboot */
void voluta_zb_init(struct voluta_zero_block4 *zb,
                    enum voluta_ztype ztype, size_t size);

void voluta_zb_fini(struct voluta_zero_block4 *zb);

void voluta_zb_set_size(struct voluta_zero_block4 *zb, size_t size);

void voluta_zb_set_encrypted(struct voluta_zero_block4 *zb, bool enc);

bool voluta_zb_is_encrypted(const struct voluta_zero_block4 *zb);

size_t voluta_zb_size(const struct voluta_zero_block4 *zb);

void voluta_zb_crypt_params(const struct voluta_zero_block4 *zb,
                            struct voluta_zcrypt_params *zcp);

struct voluta_super_block *
voluta_sb_new(struct voluta_qalloc *qal, enum voluta_ztype ztype);

void voluta_sb_del(struct voluta_super_block *sb,
                   struct voluta_qalloc *qal);

void voluta_sb_set_pass_hash(struct voluta_super_block *sb,
                             const struct voluta_hash512 *hash);

void voluta_sb_set_birth_time(struct voluta_super_block *sb, time_t btime);

void voluta_sb_set_ag_count(struct voluta_super_block *sb, size_t ag_count);

void voluta_sb_setup_keys(struct voluta_super_block *sb);

const struct voluta_kivam *
voluta_sb_kivam_of(const struct voluta_super_block *sb, size_t hs_index);

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

void voluta_rb_setup(struct voluta_rand_block4 *rb,
                     const struct voluta_mdigest *md);

int voluta_rb_check(const struct voluta_rand_block4 *rb,
                    const struct voluta_mdigest *md);

/* opers */
int voluta_fs_forget(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino, size_t nlookup);

int voluta_fs_statfs(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino,
                     struct statvfs *stvfs);

int voluta_fs_lookup(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, struct stat *out_stat);

int voluta_fs_getattr(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op,
                      ino_t ino, struct stat *out_stat);

int voluta_fs_mkdir(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t parent,
                    const char *name, mode_t mode, struct stat *out_stat);

int voluta_fs_rmdir(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op,
                    ino_t parent, const char *name);

int voluta_fs_access(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino, int mode);

int voluta_fs_chmod(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino, mode_t mode,
                    const struct stat *st, struct stat *out_stat);

int voluta_fs_chown(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino, uid_t uid,
                    gid_t gid, const struct stat *st, struct stat *out_stat);

int voluta_fs_truncate(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino, loff_t len,
                       struct stat *out_stat);

int voluta_fs_utimens(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino,
                      const struct stat *times, struct stat *out_stat);

int voluta_fs_symlink(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t parent,
                      const char *name, const char *symval,
                      struct stat *out_stat);

int voluta_fs_readlink(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op,
                       ino_t ino, char *ptr, size_t lim, size_t *out_len);

int voluta_fs_unlink(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op,
                     ino_t parent, const char *name);

int voluta_fs_link(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, ino_t parent,
                   const char *name, struct stat *out_stat);

int voluta_fs_rename(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, ino_t newparent,
                     const char *newname, int flags);

int voluta_fs_opendir(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino);

int voluta_fs_releasedir(struct voluta_sb_info *sbi,
                         const struct voluta_oper *op, ino_t ino, int o_flags);

int voluta_fs_readdir(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op, ino_t ino,
                      struct voluta_readdir_ctx *rd_ctx);

int voluta_fs_readdirplus(struct voluta_sb_info *sbi,
                          const struct voluta_oper *op, ino_t ino,
                          struct voluta_readdir_ctx *rd_ctx);

int voluta_fs_fsyncdir(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino, bool datasync);

int voluta_fs_create(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t parent,
                     const char *name, int o_flags, mode_t mode,
                     struct stat *out_stat);

int voluta_fs_open(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, int o_flags);

int voluta_fs_mknod(struct voluta_sb_info *sbi, const struct voluta_oper *op,
                    ino_t parent, const char *name, mode_t mode, dev_t rdev,
                    struct stat *out_stat);

int voluta_fs_release(struct voluta_sb_info *sbi,
                      const struct voluta_oper *op,
                      ino_t ino, int o_flags, bool flush);

int voluta_fs_flush(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino);

int voluta_fs_fsync(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op,
                    ino_t ino, bool datasync);

int voluta_fs_getxattr(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino,
                       const char *name, void *buf, size_t size,
                       size_t *out_size);

int voluta_fs_setxattr(struct voluta_sb_info *sbi,
                       const struct voluta_oper *op, ino_t ino,
                       const char *name, const void *value,
                       size_t size, int flags);

int voluta_fs_listxattr(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        struct voluta_listxattr_ctx *lxa_ctx);

int voluta_fs_removexattr(struct voluta_sb_info *sbi,
                          const struct voluta_oper *op,
                          ino_t ino, const char *name);

int voluta_fs_fallocate(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        int mode, loff_t offset, loff_t length);

int voluta_fs_lseek(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    loff_t off, int whence, loff_t *out_off);

int voluta_fs_copy_file_range(struct voluta_sb_info *sbi,
                              const struct voluta_oper *op, ino_t ino_in,
                              loff_t off_in, ino_t ino_out, loff_t off_out,
                              size_t len, int flags, size_t *out_ncp);

int voluta_fs_read(struct voluta_sb_info *sbi,
                   const struct voluta_oper *op, ino_t ino, void *buf,
                   size_t len, loff_t off, size_t *out_len);

int voluta_fs_read_iter(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        struct voluta_rwiter_ctx *rwi_ctx);

int voluta_fs_write(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    const void *buf, size_t len, off_t off, size_t *out_len);

int voluta_fs_write_iter(struct voluta_sb_info *sbi,
                         const struct voluta_oper *op, ino_t ino,
                         struct voluta_rwiter_ctx *rwi_ctx);

int voluta_fs_rdwr_post(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op, ino_t ino,
                        const struct voluta_xiovec *xiov, size_t cnt);

int voluta_fs_statx(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    struct statx *out_stx);

int voluta_fs_fiemap(struct voluta_sb_info *sbi,
                     const struct voluta_oper *op, ino_t ino,
                     struct fiemap *fm);

int voluta_fs_query(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op, ino_t ino,
                    struct voluta_ioc_query *out_qry);

int voluta_fs_clone(struct voluta_sb_info *sbi,
                    const struct voluta_oper *op,
                    ino_t ino, char *str, size_t lim);

/* vstore */
int voluta_verify_ino(ino_t ino);

int voluta_verify_off(loff_t off);

int voluta_verify_meta(const struct voluta_vnode_info *vi);

void voluta_stamp_view(struct voluta_view *view,
                       const struct voluta_vaddr *vaddr);

bool voluta_vi_isdata(const struct voluta_vnode_info *vi);

void *voluta_vi_dat_of(const struct voluta_vnode_info *vi);


bool voluta_vtype_isubermap(enum voluta_vtype vtype);

bool voluta_vtype_isdata(enum voluta_vtype vtype);

size_t voluta_vtype_size(enum voluta_vtype vtype);

ssize_t voluta_vtype_ssize(enum voluta_vtype vtype);

size_t voluta_vtype_nkbs(enum voluta_vtype vtype);

bool voluta_vtype_ismeta(enum voluta_vtype vtype);


size_t voluta_hs_index_of_ag(size_t ag_index);

size_t voluta_ag_index_by_hs(size_t hs_index, size_t ag_slot);

size_t voluta_ag_index_to_hs_slot(size_t ag_index);

size_t voluta_size_to_ag_count(size_t nbytes);

loff_t voluta_lba_by_ag(size_t ag_index, size_t bn);


void voluta_vaddr_reset(struct voluta_vaddr *vaddr);

bool voluta_vaddr_isnull(const struct voluta_vaddr *vaddr);

bool voluta_vaddr_isdata(const struct voluta_vaddr *vaddr);

void voluta_vaddr_of_hsmap(struct voluta_vaddr *vaddr, size_t hs_index);

void voluta_vaddr_of_agmap(struct voluta_vaddr *vaddr, size_t ag_index);

void voluta_vaddr_of_itnode(struct voluta_vaddr *vaddr, loff_t off);

void voluta_vaddr_by_ag(struct voluta_vaddr *vaddr, enum voluta_vtype vtype,
                        size_t ag_index, size_t bn, size_t kbn);


void voluta_vaddr56_set(struct voluta_vaddr56 *va, loff_t off);

loff_t voluta_vaddr56_parse(const struct voluta_vaddr56 *va);

void voluta_vaddr64_set(struct voluta_vaddr64 *va,
                        const struct voluta_vaddr *vaddr);

void voluta_vaddr64_parse(const struct voluta_vaddr64 *va,
                          struct voluta_vaddr *vaddr);

int voluta_decrypt_vnode(const struct voluta_vnode_info *vi, const void *buf);


int voluta_vstore_init(struct voluta_vstore *vstore,
                       struct voluta_qalloc *qalloc);

void voluta_vstore_fini(struct voluta_vstore *vstore);

void voluta_vstore_add_ctlflags(struct voluta_vstore *vstore,
                                enum voluta_flags flags);

int voluta_vstore_check_size(const struct voluta_vstore *vstore);

int voluta_vstore_open(struct voluta_vstore *vstore,
                       const char *path, bool rw);

int voluta_vstore_close(struct voluta_vstore *vstore);

int voluta_vstore_create(struct voluta_vstore *vstore,
                         const char *path, loff_t size);

int voluta_vstore_flock(const struct voluta_vstore *vstore);

int voluta_vstore_funlock(const struct voluta_vstore *vstore);

int voluta_vstore_expand(struct voluta_vstore *vstore, loff_t cap);

int voluta_vstore_write(struct voluta_vstore *vstore,
                        loff_t off, size_t bsz, const void *buf);

int voluta_vstore_writev(struct voluta_vstore *vstore, loff_t off,
                         size_t len, const struct iovec *iov, size_t cnt);

int voluta_vstore_read(const struct voluta_vstore *vstore,
                       loff_t off, size_t bsz, void *buf);

int voluta_vstore_clone(const struct voluta_vstore *vstore,
                        const struct voluta_str *name);

int voluta_vstore_sync(struct voluta_vstore *vstore);

int voluta_vstore_xiovec(const struct voluta_vstore *vstore,
                         loff_t off, size_t len, struct voluta_xiovec *xiov);

int voluta_vstore_flush(struct voluta_vstore *vstore,
                        const struct voluta_cache *cache, long ds_key);

int voluta_vstore_punch_bk(const struct voluta_vstore *vstore, loff_t lba);

/* super */
int voluta_sbi_init(struct voluta_sb_info *sbi,
                    struct voluta_super_block *sb,
                    struct voluta_cache *cache, struct voluta_vstore *vstore);

void voluta_sbi_fini(struct voluta_sb_info *sbi);

void voluta_sbi_setowner(struct voluta_sb_info *sbi,
                         const struct voluta_ucred *cred);

void voluta_sbi_setspace(struct voluta_sb_info *sbi, loff_t sp_size);

void voluta_sbi_add_ctlflags(struct voluta_sb_info *sbi, enum voluta_flags f);



void voluta_vaddr_copyto(const struct voluta_vaddr *vaddr,
                         struct voluta_vaddr *other);

size_t voluta_vaddr_ag_index(const struct voluta_vaddr *vaddr);

size_t voluta_vaddr_hs_index(const struct voluta_vaddr *vaddr);

void voluta_vaddr_setup(struct voluta_vaddr *vaddr,
                        enum voluta_vtype vtype, loff_t off);

int voluta_adjust_super(struct voluta_sb_info *sbi);

int voluta_format_spmaps(struct voluta_sb_info *sbi);

int voluta_format_itable(struct voluta_sb_info *sbi);

int voluta_reload_super(struct voluta_sb_info *sbi);

int voluta_reload_spmaps(struct voluta_sb_info *sbi);

int voluta_reload_itable(struct voluta_sb_info *sbi);

int voluta_traverse_space(struct voluta_sb_info *sbi);

void voluta_statvfs_of(const struct voluta_sb_info *sbi,
                       struct statvfs *out_stvfs);

int voluta_flush_dirty(struct voluta_sb_info *sbi, int flags);

int voluta_flush_dirty_of(const struct voluta_inode_info *ii, int flags);

int voluta_fs_timedout(struct voluta_sb_info *sbi, int flags);

int voluta_shut_super(struct voluta_sb_info *sbi);

int voluta_fetch_inode(struct voluta_sb_info *sbi, ino_t xino,
                       struct voluta_inode_info **out_ii);

int voluta_stage_inode(struct voluta_sb_info *sbi, ino_t xino,
                       struct voluta_inode_info **out_ii);

int voluta_fetch_vnode(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_inode_info *pii,
                       struct voluta_vnode_info **out_vi);

int voluta_stage_data(struct voluta_sb_info *sbi,
                      const struct voluta_vaddr *vaddr,
                      struct voluta_inode_info *pii,
                      struct voluta_vnode_info **out_vi);

int voluta_create_inode(struct voluta_sb_info *sbi,
                        const struct voluta_oper *op,
                        mode_t mode, ino_t parent, dev_t rdev,
                        struct voluta_inode_info **out_ii);

int voluta_create_vnode(struct voluta_sb_info *sbi,
                        struct voluta_inode_info *pii,
                        enum voluta_vtype vtype,
                        struct voluta_vnode_info **out_vi);

int voluta_create_vspace(struct voluta_sb_info *sbi,
                         enum voluta_vtype vtype,
                         struct voluta_vaddr *out_vaddr);

int voluta_remove_inode(struct voluta_sb_info *sbi,
                        struct voluta_inode_info *ii);

int voluta_remove_vnode(struct voluta_sb_info *sbi,
                        struct voluta_vnode_info *vi);

int voluta_remove_vnode_at(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr);

int voluta_probe_unwritten(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr, bool *out_res);

int voluta_clear_unwritten(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr);

int voluta_verify_uspace_map(const struct voluta_hspace_map *hsm);

int voluta_verify_agroup_map(const struct voluta_agroup_map *agm);

void voluta_kivam_of(const struct voluta_vnode_info *vi,
                     struct voluta_kivam *out_kivam);

/* itable */
int voluta_iti_init(struct voluta_itable_info *iti, struct voluta_qalloc *qal);

void voluta_iti_reinit(struct voluta_itable_info *iti);

void voluta_iti_fini(struct voluta_itable_info *iti);

int voluta_acquire_ino(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_iaddr *out_iaddr);

int voluta_update_ino(struct voluta_sb_info *sbi,
                      const struct voluta_iaddr *iaddr);

int voluta_discard_ino(struct voluta_sb_info *sbi, ino_t ino);

int voluta_resolve_ino(struct voluta_sb_info *sbi,
                       ino_t xino, struct voluta_iaddr *out_iaddr);

int voluta_create_itable(struct voluta_sb_info *sbi);

int voluta_real_ino(const struct voluta_sb_info *sbi,
                    ino_t ino, ino_t *out_ino);

const struct voluta_vaddr *
voluta_root_of_itable(const struct voluta_sb_info *sbi);

void voluta_bind_rootdir(struct voluta_sb_info *sbi,
                         const struct voluta_inode_info *ii);

int voluta_reload_itable_at(struct voluta_sb_info *sbi,
                            const struct voluta_vaddr *vaddr);

int voluta_verify_itnode(const struct voluta_itable_tnode *itn);


/* namei */
int voluta_authorize(const struct voluta_sb_info *sbi,
                     const struct voluta_oper *op);

int voluta_make_namestr(const struct voluta_inode_info *ii,
                        const char *name, struct voluta_namestr *str);

int voluta_do_forget_inode(struct voluta_sb_info *sbi,
                           ino_t xino, size_t nlookup);

int voluta_do_statvfs(const struct voluta_oper *op,
                      struct voluta_inode_info *ii,
                      struct statvfs *out_stvfs);

int voluta_do_access(const struct voluta_oper *op,
                     const struct voluta_inode_info *ii, int mode);

int voluta_do_open(const struct voluta_oper *op,
                   struct voluta_inode_info *ii, int flags);

int voluta_do_release(const struct voluta_oper *op,
                      struct voluta_inode_info *ii);

int voluta_do_mkdir(const struct voluta_oper *op,
                    struct voluta_inode_info *dir_ii,
                    const struct voluta_namestr *name, mode_t mode,
                    struct voluta_inode_info **out_ii);

int voluta_do_rmdir(const struct voluta_oper *op,
                    struct voluta_inode_info *dir_ii,
                    const struct voluta_namestr *name);

int voluta_do_rename(const struct voluta_oper *op,
                     struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name,
                     struct voluta_inode_info *newdir_ii,
                     const struct voluta_namestr *newname, int flags);

int voluta_do_symlink(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      const struct voluta_namestr *name,
                      const struct voluta_str *symval,
                      struct voluta_inode_info **out_ii);

int voluta_do_link(const struct voluta_oper *op,
                   struct voluta_inode_info *dir_ii,
                   const struct voluta_namestr *name,
                   struct voluta_inode_info *ii);

int voluta_do_unlink(const struct voluta_oper *op,
                     struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name);

int voluta_do_create(const struct voluta_oper *op,
                     struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name, mode_t mode,
                     struct voluta_inode_info **out_ii);

int voluta_do_mknod(const struct voluta_oper *op,
                    struct voluta_inode_info *dir_ii,
                    const struct voluta_namestr *name, mode_t mode, dev_t dev,
                    struct voluta_inode_info **out_ii);

int voluta_do_lookup(const struct voluta_oper *op,
                     const struct voluta_inode_info *dir_ii,
                     const struct voluta_namestr *name,
                     struct voluta_inode_info **out_ii);

int voluta_do_opendir(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii);

int voluta_do_releasedir(const struct voluta_oper *op,
                         struct voluta_inode_info *dir_ii);

int voluta_do_fsyncdir(const struct voluta_oper *op,
                       struct voluta_inode_info *dir_ii, bool dsync);

int voluta_do_fsync(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, bool datasync);

int voluta_do_flush(const struct voluta_oper *op,
                    struct voluta_inode_info *ii);

int voluta_do_query(const struct voluta_oper *op,
                    const struct voluta_inode_info *ii,
                    struct voluta_ioc_query *out_qry);

int voluta_do_clone(const struct voluta_oper *op,
                    const struct voluta_inode_info *ii, char *str, size_t lim);

/* inode */
ino_t voluta_inode_ino(const struct voluta_inode *inode);

ino_t voluta_ino_of(const struct voluta_inode_info *ii);

ino_t voluta_ii_parent(const struct voluta_inode_info *ii);

ino_t voluta_ii_xino(const struct voluta_inode_info *ii);

uid_t voluta_ii_uid(const struct voluta_inode_info *ii);

gid_t voluta_ii_gid(const struct voluta_inode_info *ii);

mode_t voluta_ii_mode(const struct voluta_inode_info *ii);

nlink_t voluta_ii_nlink(const struct voluta_inode_info *ii);

loff_t voluta_ii_size(const struct voluta_inode_info *ii);

blkcnt_t voluta_ii_blocks(const struct voluta_inode_info *ii);

bool voluta_ii_isdir(const struct voluta_inode_info *ii);

bool voluta_ii_isreg(const struct voluta_inode_info *ii);

bool voluta_ii_isfifo(const struct voluta_inode_info *ii);

bool voluta_ii_issock(const struct voluta_inode_info *ii);

bool voluta_ii_islnk(const struct voluta_inode_info *ii);

bool voluta_ii_isrootd(const struct voluta_inode_info *ii);

void voluta_fixup_rootdir(struct voluta_inode_info *ii);

bool voluta_is_rootdir(const struct voluta_inode_info *ii);

enum voluta_inodef voluta_ii_flags(const struct voluta_inode_info *ii);

int voluta_do_getattr(const struct voluta_oper *op,
                      const struct voluta_inode_info *ii,
                      struct stat *out_st);

int voluta_do_statx(const struct voluta_oper *op,
                    const struct voluta_inode_info *ii,
                    struct statx *out_stx);

int voluta_do_chmod(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, mode_t mode,
                    const struct voluta_itimes *itimes);

int voluta_do_chown(const struct voluta_oper *op,
                    struct voluta_inode_info *ii, uid_t uid, gid_t gid,
                    const struct voluta_itimes *itimes);

int voluta_do_utimens(const struct voluta_oper *op,
                      struct voluta_inode_info *ii,
                      const struct voluta_itimes *itimes);

int voluta_verify_inode(const struct voluta_inode *inode);

void voluta_update_itimes(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          enum voluta_iattr_flags attr_flags);

void voluta_update_iblocks(const struct voluta_oper *op,
                           struct voluta_inode_info *ii,
                           enum voluta_vtype vtype, long dif);

void voluta_update_isize(const struct voluta_oper *op,
                         struct voluta_inode_info *ii, loff_t size);

void voluta_update_iattrs(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          const struct voluta_iattr *attr);

void voluta_iattr_setup(struct voluta_iattr *iattr, ino_t ino);

void voluta_refresh_atime(struct voluta_inode_info *ii, bool to_volatile);

void voluta_setup_inode(struct voluta_inode_info *ii,
                        const struct voluta_ucred *ucred,
                        mode_t mode, ino_t parent, dev_t rdev);

void voluta_clone_inode(struct voluta_inode_info *ii,
                        const struct voluta_inode_info *ii_other);

void voluta_stat_of(const struct voluta_inode_info *ii, struct stat *st);


/* dir */
size_t voluta_dir_ndentries(const struct voluta_inode_info *dir_ii);

enum voluta_dirf voluta_dir_flags(const struct voluta_inode_info *dir_ii);

int voluta_verify_dir_inode(const struct voluta_inode *inode);

int voluta_verify_dir_htree_node(const struct voluta_dir_htnode *htn);

void voluta_setup_dir(struct voluta_inode_info *dir_ii, nlink_t nlink);

int voluta_lookup_dentry(const struct voluta_oper *op,
                         const struct voluta_inode_info *dir_ii,
                         const struct voluta_qstr *name,
                         struct voluta_ino_dt *out_idt);

int voluta_add_dentry(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      const struct voluta_qstr *name,
                      struct voluta_inode_info *ii);

int voluta_remove_dentry(const struct voluta_oper *op,
                         struct voluta_inode_info *dir_ii,
                         const struct voluta_qstr *name);

int voluta_do_readdir(const struct voluta_oper *op,
                      struct voluta_inode_info *dir_ii,
                      struct voluta_readdir_ctx *rd_ctx);

int voluta_do_readdirplus(const struct voluta_oper *op,
                          struct voluta_inode_info *dir_ii,
                          struct voluta_readdir_ctx *rd_ctx);

int voluta_drop_dir(struct voluta_inode_info *dir_ii);

/* file */
void voluta_setup_reg(struct voluta_inode_info *ii);

int voluta_drop_reg(struct voluta_inode_info *ii);

int voluta_do_write(const struct voluta_oper *op,
                    struct voluta_inode_info *ii,
                    const void *buf, size_t len,
                    loff_t off, size_t *out_len);

int voluta_do_write_iter(const struct voluta_oper *op,
                         struct voluta_inode_info *ii,
                         struct voluta_rwiter_ctx *rwi_ctx);

int voluta_do_rdwr_post(const struct voluta_oper *op,
                        const struct voluta_inode_info *ii,
                        const struct voluta_xiovec *xiov, size_t cnt);

int voluta_do_read_iter(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        struct voluta_rwiter_ctx *rwi_ctx);

int voluta_do_read(const struct voluta_oper *op,
                   struct voluta_inode_info *ii,
                   void *buf, size_t len, loff_t off, size_t *out_len);

int voluta_do_lseek(const struct voluta_oper *op,
                    struct voluta_inode_info *ii,
                    loff_t off, int whence, loff_t *out_off);

int voluta_do_fallocate(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        int mode, loff_t off, loff_t length);

int voluta_do_truncate(const struct voluta_oper *op,
                       struct voluta_inode_info *ii, loff_t off);

int voluta_do_fiemap(const struct voluta_oper *op,
                     struct voluta_inode_info *ii, struct fiemap *fm);

int voluta_do_copy_file_range(const struct voluta_oper *op,
                              struct voluta_inode_info *ii_in,
                              struct voluta_inode_info *ii_out,
                              loff_t off_in, loff_t off_out, size_t len,
                              int flags, size_t *out_ncp);

int voluta_verify_radix_tnode(const struct voluta_radix_tnode *rtn);

/* symlink */
void voluta_setup_symlnk(struct voluta_inode_info *lnk_ii);

int voluta_drop_symlink(struct voluta_inode_info *lnk_ii);

int voluta_do_readlink(const struct voluta_oper *op,
                       struct voluta_inode_info *lnk_ii,
                       void *ptr, size_t lim, size_t *out_len);

int voluta_setup_symlink(const struct voluta_oper *op,
                         struct voluta_inode_info *lnk_ii,
                         const struct voluta_str *symval);

int voluta_verify_lnk_value(const struct voluta_lnk_value *lnv);

/* xattr */
void voluta_setup_xattr(struct voluta_inode_info *ii);

int voluta_do_getxattr(const struct voluta_oper *op,
                       struct voluta_inode_info *ii,
                       const struct voluta_namestr *name,
                       void *buf, size_t size, size_t *out_size);

int voluta_do_setxattr(const struct voluta_oper *op,
                       struct voluta_inode_info *ii,
                       const struct voluta_namestr *name,
                       const void *value, size_t size, int flags);

int voluta_do_removexattr(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          const struct voluta_namestr *name);

int voluta_do_listxattr(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        struct voluta_listxattr_ctx *lxa_ctx);

int voluta_drop_xattr(struct voluta_inode_info *ii);

int voluta_verify_inode_xattr(const struct voluta_inode *inode);

int voluta_verify_xattr_node(const struct voluta_xattr_node *xan);

/* pstore */
int voluta_pstore_init(struct voluta_pstore *pstore);

void voluta_pstore_fini(struct voluta_pstore *pstore);

int voluta_pstore_expand(struct voluta_pstore *pstore, loff_t cap);

int voluta_pstore_create(struct voluta_pstore *pstore,
                         const char *path, loff_t size);

int voluta_pstore_open(struct voluta_pstore *pstore,
                       const char *path, bool rw);

int voluta_pstore_close(struct voluta_pstore *pstore);

int voluta_pstore_check_io(const struct voluta_pstore *pstore,
                           loff_t off, size_t len);

int voluta_pstore_read(const struct voluta_pstore *pstore,
                       loff_t off, size_t bsz, void *buf);

int voluta_pstore_write(struct voluta_pstore *pstore,
                        loff_t off, size_t bsz, const void *buf);

int voluta_pstore_writev(struct voluta_pstore *pstore, loff_t off,
                         size_t len, const struct iovec *iov, size_t cnt);

int voluta_pstore_sync(struct voluta_pstore *pstore, bool all);

int voluta_pstore_flock(const struct voluta_pstore *pstore);

int voluta_pstore_funlock(const struct voluta_pstore *pstore);

int voluta_pstore_clone(const struct voluta_pstore *pstore,
                        const struct voluta_str *name);

int voluta_pstore_punch_hole(const struct voluta_pstore *pstore,
                             loff_t off, size_t len);

int voluta_calc_vsize(loff_t size_cur, loff_t size_want, loff_t *out_size);

/* crypto */
int voluta_init_gcrypt(void);

void voluta_fill_random_ascii(char *str, size_t len);

int voluta_crypto_init(struct voluta_crypto *crypto);

void voluta_crypto_fini(struct voluta_crypto *crypto);

int voluta_derive_kivam(const struct voluta_zcrypt_params *zcp,
                        const struct voluta_passphrase *pp,
                        const struct voluta_mdigest *md,
                        struct voluta_kivam *kivam);

int voluta_mdigest_init(struct voluta_mdigest *md);

void voluta_mdigest_fini(struct voluta_mdigest *md);


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

void voluta_kivam_setup(struct voluta_kivam *kivam);

void voluta_kivam_setup_n(struct voluta_kivam *kivam, size_t n);

void voluta_kivam_copyto(const struct voluta_kivam *kivam,
                         struct voluta_kivam *other);

void voluta_kivam_xor_iv(struct voluta_kivam *kivam,
                         loff_t off, uint64_t seed);

/* cache */
int voluta_cache_init(struct voluta_cache *cache, struct voluta_mpool *mpool);

void voluta_cache_fini(struct voluta_cache *cache);

void voluta_cache_relax(struct voluta_cache *cache, int flags);

void voluta_cache_drop(struct voluta_cache *cache);

void voluta_cache_shrink_once(struct voluta_cache *cache);

bool voluta_cache_need_flush(const struct voluta_cache *cache, int flags);

bool voluta_cache_need_flush_of(const struct voluta_cache *cache,
                                const struct voluta_inode_info *ii, int flags);

void voluta_cache_inhabit_dset(const struct voluta_cache *cache,
                               struct voluta_dset *dset);

struct voluta_bk_info *
voluta_cache_lookup_bki(struct voluta_cache *cache, loff_t lba);

struct voluta_bk_info *
voluta_cache_spawn_bki(struct voluta_cache *cache, loff_t lba);

void voluta_cache_forget_bki(struct voluta_cache *cache,
                             struct voluta_bk_info *bki);

struct voluta_inode_info *
voluta_cache_spawn_ii(struct voluta_cache *cache,
                      const struct voluta_iaddr *iaddr);

void voulta_cache_forget_ii(struct voluta_cache *cache,
                            struct voluta_inode_info *ii);

struct voluta_inode_info *
voluta_cache_lookup_ii(struct voluta_cache *cache,
                       const struct voluta_iaddr *iaddr);

struct voluta_vnode_info *
voluta_cache_lookup_vi(struct voluta_cache *cache,
                       const struct voluta_vaddr *vaddr);

struct voluta_vnode_info *
voluta_cache_spawn_vi(struct voluta_cache *cache,
                      const struct voluta_vaddr *vaddr);

void voulta_cache_forget_vi(struct voluta_cache *cache,
                            struct voluta_vnode_info *vi);

void voluta_vi_dirtify(struct voluta_vnode_info *vi);

void voluta_vi_undirtify(struct voluta_vnode_info *vi);

void voluta_ii_dirtify(struct voluta_inode_info *ii);

bool voluta_ii_isrdonly(const struct voluta_inode_info *ii);

bool voluta_ii_isevictable(const struct voluta_inode_info *ii);

void voluta_vi_attach_to(struct voluta_vnode_info *vi,
                         struct voluta_bk_info *bki,
                         struct voluta_vnode_info *pvi);

void voluta_vi_incref(struct voluta_vnode_info *vi);

void voluta_vi_decref(struct voluta_vnode_info *vi);

size_t voluta_vi_refcnt(const struct voluta_vnode_info *vi);


void voluta_mark_visible(const struct voluta_vnode_info *vi);

void voluta_mark_opaque_at(struct voluta_bk_info *bki,
                           const struct voluta_vaddr *vaddr);

void voluta_mark_opaque(const struct voluta_vnode_info *vi);

bool voluta_is_visible(const struct voluta_vnode_info *vi);


/* fuseq */
int voluta_fuseq_init(struct voluta_fuseq *fq, struct voluta_sb_info *sbi);

void voluta_fuseq_fini(struct voluta_fuseq *fq);

int voluta_fuseq_mount(struct voluta_fuseq *fq, const char *path);

int voluta_fuseq_exec(struct voluta_fuseq *fq);

void voluta_fuseq_term(struct voluta_fuseq *fq);

/* mpool */
void voluta_mpool_init(struct voluta_mpool *mpool, struct voluta_qalloc *qal);

void voluta_mpool_fini(struct voluta_mpool *mpool);

struct voluta_bk_info *voluta_malloc_bki(struct voluta_mpool *mpool);

void voluta_free_bki(struct voluta_mpool *mpool, struct voluta_bk_info *bki);

struct voluta_vnode_info *voluta_malloc_vi(struct voluta_mpool *mpool);

void voluta_free_vi(struct voluta_mpool *mpool, struct voluta_vnode_info *vi);

struct voluta_inode_info *voluta_malloc_ii(struct voluta_mpool *mpool);

void voluta_free_ii(struct voluta_mpool *mpool, struct voluta_inode_info *ii);

/* thread */
int voluta_thread_create(struct voluta_thread *th,
                         voluta_execute_fn exec, const char *name);

int voluta_thread_join(struct voluta_thread *th);

int voluta_mutex_init(struct voluta_mutex *mutex);

void voluta_mutex_destroy(struct voluta_mutex *mutex);

void voluta_mutex_lock(struct voluta_mutex *mutex);

bool voluta_mutex_trylock(struct voluta_mutex *mutex);

bool voluta_mutex_timedlock(struct voluta_mutex *mutex,
                            const struct timespec *abstime);

void voluta_mutex_unlock(struct voluta_mutex *mutex);

/* utility */
void voluta_uuid_generate(struct voluta_uuid *uu);

void voluta_uuid_copyto(const struct voluta_uuid *u1, struct voluta_uuid *u2);

void voluta_uuid_name(const struct voluta_uuid *uu, struct voluta_namebuf *nb);

void voluta_ts_now(struct timespec *ts);

size_t voluta_hash_prime(size_t lim);

const char *voluta_basename(const char *path);


void voluta_buf_init(struct voluta_buf *buf, void *p, size_t n);

size_t voluta_buf_append(struct voluta_buf *buf, const void *ptr, size_t len);

size_t voluta_buf_rem(const struct voluta_buf *buf);

void *voluta_buf_end(const struct voluta_buf *buf);

void voluta_buf_seteos(struct voluta_buf *buf);

/* guarantee */
void voluta_guarantee_persistent_format(void);

#endif /* LIBVOLUTA_H_ */

