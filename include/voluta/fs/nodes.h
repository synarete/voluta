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
#ifndef VOLUTA_NODES_H_
#define VOLUTA_NODES_H_

struct voluta_vnode_info;
struct voluta_mpool;


typedef void (*voluta_vi_delete_fn)(struct voluta_vnode_info *vi,
                                    struct voluta_alloc_if *alif);


/* bnode */
struct voluta_bnode_info {
	struct voluta_baddr             baddr;
	void *bp;
};

/* vnode */
union voluta_vnode_u {
	struct voluta_hspace_map        *hsm;
	struct voluta_agroup_map        *agm;
	struct voluta_itable_tnode      *itn;
	struct voluta_inode             *inode;
	struct voluta_radix_tnode       *rtn;
	struct voluta_dir_htnode        *htn;
	struct voluta_xattr_node        *xan;
	struct voluta_lnk_value         *lnv;
	struct voluta_data_block1       *db1;
	struct voluta_data_block4       *db4;
	struct voluta_data_block        *db;
	void *p;
};

struct voluta_vnode_info {
	struct voluta_bnode_info        v_bi;
	union voluta_vnode_u            vu;
	struct voluta_view             *view;
	struct voluta_vaddr             vaddr;
	struct voluta_sb_info          *v_sbi;
	struct voluta_bksec_info       *v_bsi;
	struct voluta_cache_elem        v_ce;
	struct voluta_list_head         v_dq_mlh;
	struct voluta_list_head         v_dq_blh;
	struct voluta_avl_node          v_ds_an;
	struct voluta_vnode_info       *v_ds_next;
	voluta_vi_delete_fn             v_del_hook;
	long v_ds_key;
	int  v_verify;
	int  v_dirty;
};

/* space-maps */
struct voluta_hspace_info {
	struct voluta_vnode_info        hs_vi;
	voluta_index_t                  hs_index;
};

struct voluta_agroup_info {
	struct voluta_vnode_info        ag_vi;
	voluta_index_t                  ag_index;
};

/* inode */
struct voluta_inode_info {
	struct voluta_vnode_info        i_vi;
	struct voluta_inode            *inode;
	struct timespec                 i_atime_lazy;
	ino_t  i_ino;
	long   i_nopen;
	long   i_nlookup;
	bool   i_pinned;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_vnode_info *
voluta_vi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba);

struct voluta_hspace_info *
voluta_hsi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba);

struct voluta_agroup_info *
voluta_agi_new(struct voluta_alloc_if *alif, const struct voluta_vba *vba);

struct voluta_inode_info *
voluta_ii_new(struct voluta_alloc_if *alif,
              const struct voluta_vba *vba, ino_t ino);

struct voluta_hspace_info *
voluta_hsi_from_vi(const struct voluta_vnode_info *vi);

struct voluta_inode_info *
voluta_ii_from_vi(const struct voluta_vnode_info *vi);


void voluta_vi_vba(const struct voluta_vnode_info *vi,
                   struct voluta_vba *out_vba);

#endif /* VOLUTA_NODES_H_ */
