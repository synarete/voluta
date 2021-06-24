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
#ifndef VOLUTA_NODES_H_
#define VOLUTA_NODES_H_

struct voluta_unode_info;
struct voluta_vnode_info;
struct voluta_mpool;


/* unode */
struct voluta_unode_vtbl {
	bool (*evictable)(const struct voluta_unode_info *ui);
	void (*del)(struct voluta_unode_info *ui, struct voluta_alloc_if *aif);
};

struct voluta_unode_info {
	struct voluta_uaddr             uaddr;
	const struct voluta_unode_vtbl *u_vtbl;
	struct voluta_cache_elem        u_ce;
	struct voluta_baddr             u_baddr;
	struct voluta_bksec_info       *u_bsi;
	int  u_dirty;
};

/* vnode */
struct voluta_vnode_vtbl {
	bool (*evictable)(const struct voluta_vnode_info *vi);
	void (*del)(struct voluta_vnode_info *vi, struct voluta_alloc_if *aif);
};

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
	struct voluta_vaddr             vaddr;
	const struct voluta_vnode_vtbl *v_vtbl;
	struct voluta_cache_elem        v_ce;
	union voluta_vnode_u            vu;
	struct voluta_view             *view;
	struct voluta_fiovref           v_fir;
	struct voluta_sb_info          *v_sbi;
	struct voluta_bksec_info       *v_bsi;
	struct voluta_list_head         v_dq_mlh;
	struct voluta_list_head         v_dq_blh;
	struct voluta_avl_node          v_ds_an;
	struct voluta_vnode_info       *v_ds_next;
	long v_ds_key;
	int  v_verify;
	int  v_dirty;
};

/* space-maps */
struct voluta_hspace_info {
	struct voluta_unode_info        hs_ui;
	struct voluta_vnode_info        hs_vi;
	voluta_index_t                  hs_index;
	struct voluta_hspace_map       *hsm;
};

struct voluta_agroup_info {
	struct voluta_unode_info        ag_ui;
	struct voluta_vnode_info        ag_vi;
	voluta_index_t                  ag_index;
	struct voluta_agroup_map       *agm;
};

/* itable */
struct voluta_itnode_info {
	struct voluta_vnode_info        itn_vi;
	struct voluta_itable_tnode     *itn;
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

struct voluta_unode_info *
voluta_ui_new_by_vba(struct voluta_alloc_if *alif,
                     const struct voluta_vba *vba);

struct voluta_vnode_info *
voluta_vi_new_by_vba(struct voluta_alloc_if *alif,
                     const struct voluta_vba *vba);

struct voluta_hspace_info *
voluta_hsi_from_vi(const struct voluta_vnode_info *vi);

struct voluta_agroup_info *
voluta_agi_from_vi(const struct voluta_vnode_info *vi);

struct voluta_itnode_info *
voluta_itni_from_vi(const struct voluta_vnode_info *vi);

void voluta_itni_rebind(struct voluta_itnode_info *itni);

struct voluta_inode_info *
voluta_ii_from_vi(const struct voluta_vnode_info *vi);

bool voluta_ii_isevictable(const struct voluta_inode_info *ii);


bool voluta_vi_isdata(const struct voluta_vnode_info *vi);

void *voluta_vi_dat_of(const struct voluta_vnode_info *vi);


int voluta_verify_meta(const struct voluta_vnode_info *vi);

void voluta_vi_stamp_view(const struct voluta_vnode_info *vi);

void voluta_vi_seal_meta(const struct voluta_vnode_info *vi);

#endif /* VOLUTA_NODES_H_ */
