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


/* cached-node */
struct voluta_cnode_info {
	struct voluta_cache_elem        ce;
	const struct voluta_cnode_vtbl *c_vtbl;
	struct voluta_sb_info          *c_sbi;
	struct voluta_list_head         c_dq_lh;
	struct voluta_avl_node          c_ds_an;
	struct voluta_vnode_info       *c_ds_next;
	const void *c_xref;
};

struct voluta_cnode_vtbl {
	bool (*evictable)(const struct voluta_cnode_info *ci);
	void (*del)(struct voluta_cnode_info *ci, struct voluta_alloc_if *aif);
	int (*resolve)(const struct voluta_cnode_info *ci,
	               struct voluta_baddr *out_baddr);
};

/* unode */
struct voluta_unode_info {
	struct voluta_uba               uba;
	struct voluta_cnode_info        u_ci;
	struct voluta_bksec_info       *u_bsi;
	struct voluta_list_head         u_dq_lh;
};

/* vnode */
struct voluta_vnode_info {
	struct voluta_vaddr             vaddr;
	struct voluta_cnode_info        v_ci;
	union voluta_view              *view;
	struct voluta_fiovref           v_fir;
	struct voluta_bksec_info       *v_bsi;
	struct voluta_list_head         v_dq_lh;
	struct voluta_avl_node          v_ds_an;
	struct voluta_vnode_info       *v_ds_next;
	ino_t v_iowner;
	int  v_verify;
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

/* xattr */
struct voluta_xanode_info {
	struct voluta_vnode_info        xa_vi;
	struct voluta_xattr_node       *xan;
};

/* symval */
struct voluta_symval_info {
	struct voluta_vnode_info        sy_vi;
	struct voluta_symlnk_value     *syv;
};

/* dtnode */
struct voluta_dtnode_info {
	struct voluta_vnode_info        dt_vi;
	struct voluta_dir_tnode        *dtn;
};

/* rtnode */
struct voluta_rtnode_info {
	struct voluta_vnode_info        rt_vi;
	struct voluta_radix_tnode      *rtn;
};

/* fleaf */
union voluta_fleaf_u {
	struct voluta_data_block1       *db1;
	struct voluta_data_block4       *db4;
	struct voluta_data_block        *db;
};

struct voluta_fleaf_info {
	struct voluta_vnode_info        fl_vi;
	union voluta_fleaf_u            flu;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


struct voluta_hspace_info *
voluta_hsi_from_ui(const struct voluta_unode_info *ui);

struct voluta_hspace_info *
voluta_hsi_from_vi(const struct voluta_vnode_info *vi);

struct voluta_hspace_info *
voluta_hsi_from_vi_rebind(const struct voluta_vnode_info *vi,
                          voluta_index_t hs_index);


struct voluta_agroup_info *
voluta_agi_from_ui(const struct voluta_unode_info *ui);

struct voluta_agroup_info *
voluta_agi_from_vi(const struct voluta_vnode_info *vi);


struct voluta_agroup_info *
voluta_agi_from_vi_rebind(struct voluta_vnode_info *vi,
                          voluta_index_t ag_index);


struct voluta_itnode_info *
voluta_itni_from_vi(const struct voluta_vnode_info *vi);

struct voluta_itnode_info *
voluta_itni_from_vi_rebind(struct voluta_vnode_info *vi);


struct voluta_inode_info *
voluta_ii_from_vi(const struct voluta_vnode_info *vi);

struct voluta_inode_info *
voluta_ii_from_vi_rebind(struct voluta_vnode_info *vi, ino_t ino);


struct voluta_xanode_info *
voluta_xai_from_vi(const struct voluta_vnode_info *vi);

struct voluta_xanode_info *
voluta_xai_from_vi_rebind(struct voluta_vnode_info *vi);


struct voluta_symval_info *
voluta_syi_from_vi(const struct voluta_vnode_info *vi);

struct voluta_symval_info *
voluta_syi_from_vi_rebind(struct voluta_vnode_info *vi);


struct voluta_dtnode_info *
voluta_dti_from_vi(const struct voluta_vnode_info *vi);

struct voluta_dtnode_info *
voluta_dti_from_vi_rebind(struct voluta_vnode_info *vi);


struct voluta_rtnode_info *
voluta_rti_from_vi(const struct voluta_vnode_info *vi);

struct voluta_rtnode_info *
voluta_rti_from_vi_rebind(struct voluta_vnode_info *vi);


struct voluta_fleaf_info *
voluta_fli_from_vi(const struct voluta_vnode_info *vi);

struct voluta_fleaf_info *
voluta_fli_from_vi_rebind(struct voluta_vnode_info *vi);


struct voluta_vnode_info *
voluta_vi_from_ci(const struct voluta_cnode_info *ci);

bool voluta_vi_isdata(const struct voluta_vnode_info *vi);

int voluta_vi_verify_meta(const struct voluta_vnode_info *vi);

void voluta_vi_stamp_view(const struct voluta_vnode_info *vi);

void voluta_vi_seal_meta(const struct voluta_vnode_info *vi);


struct voluta_unode_info *
voluta_ui_from_ci(const struct voluta_cnode_info *ci);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_unode_info *
voluta_new_ui(struct voluta_alloc_if *alif, const struct voluta_uba *uba);

struct voluta_vnode_info *
voluta_new_vi(struct voluta_alloc_if *alif, const struct voluta_vba *vba);


#endif /* VOLUTA_NODES_H_ */
