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
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <limits.h>
#include <voluta/fs/types.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/address.h>
#include <voluta/fs/superb.h>
#include <voluta/fs/super.h>
#include <voluta/fs/itable.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/private.h>


#define ITNODE_ROOT_DEPTH 1

struct voluta_ino_set {
	size_t cnt;
	ino_t ino[VOLUTA_ITNODE_NENTS];
};

static int lookup_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni, ino_t ino,
                       struct voluta_iaddr *out_iaddr);

static int insert_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni,
                       const struct voluta_iaddr *iaddr);

static int update_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni,
                       const struct voluta_iaddr *iaddr);

static int remove_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni, ino_t ino);

static int scan_subtree(struct voluta_sb_info *sbi,
                        struct voluta_itnode_info *itni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void iaddr_reset(struct voluta_iaddr *iaddr)
{
	vaddr_reset(&iaddr->vaddr);
	iaddr->ino = VOLUTA_INO_NULL;
}

static void iaddr_setup(struct voluta_iaddr *iaddr, ino_t ino,
                        const struct voluta_vaddr *vaddr)
{
	vaddr_copyto(vaddr, &iaddr->vaddr);
	iaddr->ino = ino;
}

static void iaddr_copyto(const struct voluta_iaddr *iaddr,
                         struct voluta_iaddr *other)
{
	vaddr_copyto(&iaddr->vaddr, &other->vaddr);
	other->ino = iaddr->ino;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t ite_ino(const struct voluta_itable_entry *ite)
{
	return voluta_ino_to_cpu(ite->ino);
}

static void ite_set_ino(struct voluta_itable_entry *ite, ino_t ino)
{
	ite->ino = voluta_cpu_to_ino(ino);
}

static void ite_vaddr(const struct voluta_itable_entry *ite,
                      struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&ite->vaddr, out_vaddr);
}

static void ite_set_vaddr(struct voluta_itable_entry *ite,
                          const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&ite->vaddr, vaddr);
}

static bool ite_isfree(const struct voluta_itable_entry *ite)
{
	return ino_isnull(ite_ino(ite));
}

static bool ite_has_ino(const struct voluta_itable_entry *ite, ino_t ino)
{
	return (ite_ino(ite) == ino);
}

static void ite_setup(struct voluta_itable_entry *ite, ino_t ino,
                      const struct voluta_vaddr *vaddr)
{
	ite_set_ino(ite, ino);
	ite_set_vaddr(ite, vaddr);
}

static void ite_reset(struct voluta_itable_entry *ite)
{
	ite_set_ino(ite, VOLUTA_INO_NULL);
	ite_set_vaddr(ite, vaddr_none());
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void itn_parent(const struct voluta_itable_tnode *itn,
                       struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&itn->it_parent, out_vaddr);
}

static void itn_set_parent(struct voluta_itable_tnode *itn,
                           const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&itn->it_parent, vaddr);
}

static void itn_reset_parent(struct voluta_itable_tnode *itn)
{
	itn_set_parent(itn, vaddr_none());
}

static size_t itn_depth(const struct voluta_itable_tnode *itn)
{
	return voluta_le16_to_cpu(itn->it_depth);
}

static void itn_set_depth(struct voluta_itable_tnode *itn, size_t depth)
{
	itn->it_depth = voluta_cpu_to_le16((uint16_t)depth);
}

static size_t itn_nents(const struct voluta_itable_tnode *itn)
{
	return voluta_le16_to_cpu(itn->it_nents);
}

static void itn_set_nents(struct voluta_itable_tnode *itn, size_t nents)
{
	itn->it_nents = voluta_cpu_to_le16((uint16_t)nents);
}

static void itn_inc_nents(struct voluta_itable_tnode *itn)
{
	itn_set_nents(itn, itn_nents(itn) + 1);
}

static void itn_dec_nents(struct voluta_itable_tnode *itn)
{
	itn_set_nents(itn, itn_nents(itn) - 1);
}

static size_t itn_nchilds(const struct voluta_itable_tnode *itn)
{
	return voluta_le16_to_cpu(itn->it_nchilds);
}

static size_t itn_nchilds_max(const struct voluta_itable_tnode *itn)
{
	return ARRAY_SIZE(itn->it_child);
}

static void itn_set_nchilds(struct voluta_itable_tnode *itn, size_t nchilds)
{
	voluta_assert_le(nchilds, itn_nchilds_max(itn));
	itn->it_nchilds = voluta_cpu_to_le16((uint16_t)nchilds);
}

static void itn_inc_nchilds(struct voluta_itable_tnode *itn)
{
	itn_set_nchilds(itn, itn_nchilds(itn) + 1);
}

static void itn_dec_nchilds(struct voluta_itable_tnode *itn)
{
	itn_set_nchilds(itn, itn_nchilds(itn) - 1);
}

static void itn_child_at(const struct voluta_itable_tnode *itn,
                         size_t slot, struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&itn->it_child[slot], out_vaddr);
}

static void itn_set_child_at(struct voluta_itable_tnode *itn,
                             size_t slot, const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&itn->it_child[slot], vaddr);
}

static void itn_clear_child_at(struct voluta_itable_tnode *itn, size_t slot)
{
	itn_set_child_at(itn, slot, vaddr_none());
}

static size_t itn_child_slot(const struct voluta_itable_tnode *itn, ino_t ino)
{
	size_t slot;
	const size_t depth = itn_depth(itn);
	const size_t shift = depth * VOLUTA_ITNODE_SHIFT;

	slot = (ino >> shift) % itn_nchilds_max(itn);
	return slot;
}

static size_t itn_nents_max(const struct voluta_itable_tnode *itn)
{
	return ARRAY_SIZE(itn->ite);
}

static struct voluta_itable_entry *
itn_entry_at(const struct voluta_itable_tnode *itn, size_t slot)
{
	const struct voluta_itable_entry *ite = &itn->ite[slot];

	return unconst(ite);
}

static void itn_init(struct voluta_itable_tnode *itn, size_t depth)
{
	const size_t nents_max = itn_nents_max(itn);
	const size_t nchilds_max = itn_nchilds_max(itn);

	itn_reset_parent(itn);
	itn_set_depth(itn, depth);
	itn_set_nents(itn, 0);
	itn_set_nchilds(itn, 0);

	for (size_t i = 0; i < nents_max; ++i) {
		ite_reset(itn_entry_at(itn, i));
	}
	for (size_t i = 0; i < nchilds_max; ++i) {
		itn_clear_child_at(itn, i);
	}
}

static bool itn_isfull(const struct voluta_itable_tnode *itn)
{
	return (itn_nents(itn) == itn_nents_max(itn));
}

static bool itn_isempty(const struct voluta_itable_tnode *itn)
{
	return (itn_nents(itn) == 0);
}

static const struct voluta_itable_entry *
itn_find_next(const struct voluta_itable_tnode *itn,
              const struct voluta_itable_entry *from)
{
	size_t slot_beg;
	const struct voluta_itable_entry *ite;
	const size_t nents_max = itn_nents_max(itn);

	if (itn_isempty(itn)) {
		return NULL;
	}
	slot_beg = (from != NULL) ? (size_t)(from - itn->ite) : 0;
	for (size_t i = slot_beg; i < nents_max; ++i) {
		ite = itn_entry_at(itn, i);
		if (!ite_isfree(ite)) {
			return ite;
		}
	}
	return NULL;
}

static size_t itn_slot_by_ino(const struct voluta_itable_tnode *itn, ino_t ino)
{
	return ino % itn_nents_max(itn);
}

static struct voluta_itable_entry *
itn_lookup(const struct voluta_itable_tnode *itn, ino_t ino)
{
	size_t slot;
	const struct voluta_itable_entry *ite;

	if (itn_isempty(itn)) {
		return NULL;
	}
	slot = itn_slot_by_ino(itn, ino);
	ite = itn_entry_at(itn, slot);
	if (!ite_has_ino(ite, ino)) {
		return NULL;
	}
	return unconst(ite);
}

static struct voluta_itable_entry *
itn_update(struct voluta_itable_tnode *itn, ino_t ino,
           const struct voluta_vaddr *vaddr)
{
	struct voluta_itable_entry *ite;

	ite = itn_lookup(itn, ino);
	if (ite == NULL) {
		return NULL;
	}
	ite_setup(ite, ino, vaddr);
	return ite;
}

static struct voluta_itable_entry *
itn_insert(struct voluta_itable_tnode *itn, ino_t ino,
           const struct voluta_vaddr *vaddr)
{
	size_t slot;
	struct voluta_itable_entry *ite;

	if (itn_isfull(itn)) {
		return NULL;
	}
	slot = itn_slot_by_ino(itn, ino);
	ite = itn_entry_at(itn, slot);
	if (!ite_isfree(ite)) {
		return NULL;
	}
	ite_setup(ite, ino, vaddr);
	itn_inc_nents(itn);
	return ite;
}

static struct voluta_itable_entry *
itn_remove(struct voluta_itable_tnode *itn, ino_t ino)
{
	struct voluta_itable_entry *ite;

	ite = itn_lookup(itn, ino);
	if (ite == NULL) {
		return ite;
	}
	ite_reset(ite);
	itn_dec_nents(itn);
	return ite;
}

static void itn_set_child(struct voluta_itable_tnode *itn, ino_t ino,
                          const struct voluta_vaddr *vaddr)
{
	const size_t slot = itn_child_slot(itn, ino);

	itn_set_child_at(itn, slot, vaddr);
	itn_inc_nchilds(itn);
}

static void itn_clear_child(struct voluta_itable_tnode *itn, ino_t ino)
{
	const size_t slot = itn_child_slot(itn, ino);

	itn_clear_child_at(itn, slot);
	itn_dec_nchilds(itn);
}

static bool itn_isleaf(const struct voluta_itable_tnode *itn)
{
	return (itn_nchilds(itn) == 0);
}

static bool itn_isroot(const struct voluta_itable_tnode *itn)
{
	return (itn_depth(itn) == ITNODE_ROOT_DEPTH);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void itc_ent_reset(struct voluta_itcentry *itc_ent)
{
	itc_ent->ino = VOLUTA_INO_NULL;
	itc_ent->off = VOLUTA_OFF_NULL;
}

static void itc_ent_reset_arr(struct voluta_itcentry *itc_ent_arr, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		itc_ent_reset(&itc_ent_arr[i]);
	}
}

static int itc_init(struct voluta_itcache *itc, struct voluta_alloc_if *alif)
{
	const size_t elemsz = sizeof(*itc->itc_htable);
	const size_t nelems = ((2 * VOLUTA_MEGA) / elemsz);

	STATICASSERT_EQ(sizeof(*itc->itc_htable), 16);

	itc->itc_alif = alif;
	itc->itc_nelems = 0;
	itc->itc_htable = voluta_allocate(alif, nelems * elemsz);
	if (itc->itc_htable == NULL) {
		return -ENOMEM;
	}
	itc_ent_reset_arr(itc->itc_htable, nelems);
	itc->itc_nelems = nelems;
	return 0;
}

static void itc_fini(struct voluta_itcache *itc)
{
	const size_t nelems = itc->itc_nelems;
	const size_t elemsz = sizeof(*itc->itc_htable);

	voluta_deallocate(itc->itc_alif, itc->itc_htable, nelems * elemsz);
	itc->itc_nelems = 0;
	itc->itc_htable = NULL;
	itc->itc_alif = NULL;
}

static size_t itc_ino_to_slot(const struct voluta_itcache *itc, ino_t ino)
{
	return ino % itc->itc_nelems;
}

static struct voluta_itcentry *
itc_entry_at(const struct voluta_itcache *itc, size_t slot)
{
	const struct voluta_itcentry *itc_ent = &itc->itc_htable[slot];

	return unconst(itc_ent);
}

static struct voluta_itcentry *
itc_entry_of(const struct voluta_itcache *itc, ino_t ino)
{
	return itc_entry_at(itc, itc_ino_to_slot(itc, ino));
}

static int itc_lookup(const struct voluta_itcache *itc, ino_t ino,
                      struct voluta_iaddr *out_iaddr)
{
	struct voluta_vaddr vaddr;
	const struct voluta_itcentry *itc_ent = itc_entry_of(itc, ino);

	if (itc_ent->ino != ino) {
		return -ENOENT;
	}
	vaddr_setup(&vaddr, VOLUTA_ZTYPE_INODE, itc_ent->off);
	iaddr_setup(out_iaddr, itc_ent->ino, &vaddr);
	return 0;
}

static void itc_update(struct voluta_itcache *itc,
                       const struct voluta_iaddr *iaddr)
{
	struct voluta_itcentry *itc_ent = itc_entry_of(itc, iaddr->ino);

	itc_ent->ino = iaddr->ino;
	itc_ent->off = iaddr->vaddr.off;
}

static void itc_remove(const struct voluta_itcache *itc, ino_t ino)
{
	struct voluta_itcentry *itc_ent = itc_entry_of(itc, ino);

	itc_ent_reset(itc_ent);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_itable_info *itbi_of(const struct voluta_sb_info *sbi)
{
	const struct voluta_itable_info *itbi = &sbi->s_itbi;

	return unconst(itbi);
}

static const struct voluta_vaddr *
itbi_root(const struct voluta_itable_info *itbi)
{
	return &itbi->it_treeroot;
}

static void itbi_set_root(struct voluta_itable_info *itbi,
                          const struct voluta_vaddr *vaddr)
{
	vaddr_copyto(vaddr, &itbi->it_treeroot);
}

static void itbi_init_common(struct voluta_itable_info *itbi)
{
	itbi_set_root(itbi, vaddr_none());
	iaddr_reset(&itbi->it_rootdir);
	itbi->it_apex_ino = VOLUTA_INO_ROOT + VOLUTA_INO_PSEUDO_MAX;
	itbi->it_ninodes_max = ULONG_MAX / 2;
	itbi->it_ninodes = 0;
}

int voluta_itbi_init(struct voluta_itable_info *itbi,
                     struct voluta_alloc_if *alif)
{
	itbi_init_common(itbi);
	return itc_init(&itbi->it_cache, alif);
}

void voluta_itbi_reinit(struct voluta_itable_info *itbi)
{
	itbi_init_common(itbi);
}

void voluta_itbi_fini(struct voluta_itable_info *itbi)
{
	itc_fini(&itbi->it_cache);
	itbi_init_common(itbi);
	itbi->it_ninodes_max = 0;
}

static int itbi_set_rootdir(struct voluta_itable_info *itbi, ino_t ino,
                            const struct voluta_vaddr *vaddr)
{
	int err = 0;

	if (ino > VOLUTA_INO_PSEUDO_MAX) {
		iaddr_setup(&itbi->it_rootdir, ino, vaddr);
	} else {
		log_err("illegal root-ino: ino=%ld off=%ld", ino, vaddr->off);
		err = -EINVAL;
	}
	return err;
}

static int itbi_next_ino(struct voluta_itable_info *itbi, ino_t *out_ino)
{
	if (itbi->it_ninodes >= itbi->it_ninodes_max) {
		return -ENOSPC;
	}
	itbi->it_apex_ino += 1;
	*out_ino = itbi->it_apex_ino;
	return 0;
}

static void itbi_fixup_apex_ino(struct voluta_itable_info *itbi, ino_t ino)
{
	if (itbi->it_apex_ino < ino) {
		itbi->it_apex_ino = ino;
	}
}

static void itbi_add_ino(struct voluta_itable_info *itbi, ino_t ino)
{
	itbi->it_ninodes++;
	itbi_fixup_apex_ino(itbi, ino);
}

static void itbi_remove_ino(struct voluta_itable_info *itbi, ino_t ino)
{
	voluta_assert_gt(itbi->it_ninodes, 0);
	voluta_assert_ge(itbi->it_apex_ino, ino);

	itbi->it_ninodes--;
}

static void itbi_parse_inos_of(struct voluta_itable_info *itbi,
                               const struct voluta_itable_tnode *itn)
{
	ino_t ino;
	const struct voluta_itable_entry *ite;

	ite = itn_find_next(itn, NULL);
	while (ite != NULL) {
		ino = ite_ino(ite);
		itbi_add_ino(itbi, ino);
		ite = itn_find_next(itn, ite + 1);
	}
}

static int itbi_lookup_cached(const struct voluta_itable_info *itbi, ino_t ino,
                              struct voluta_iaddr *out_iaddr)
{
	int err;

	if (ino_isnull(ino)) {
		err = -ENOENT;
	} else if (ino == itbi->it_rootdir.ino) {
		iaddr_copyto(&itbi->it_rootdir, out_iaddr);
		err = 0;
	} else {
		err = itc_lookup(&itbi->it_cache, ino, out_iaddr);
	}
	return err;
}

static void itbi_update_cache(struct voluta_itable_info *itbi,
                              const struct voluta_iaddr *iaddr)
{
	itc_update(&itbi->it_cache, iaddr);
}

static void itbi_remove_cached(const struct voluta_itable_info *itbi,
                               ino_t ino)
{
	itc_remove(&itbi->it_cache, ino);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void itni_incref(struct voluta_itnode_info *itni)
{
	vi_incref(&itni->itn_vi);
}

static void itni_decref(struct voluta_itnode_info *itni)
{
	vi_decref(&itni->itn_vi);
}

static const struct voluta_vaddr *
itni_vaddr(const struct voluta_itnode_info *itni)
{
	return vi_vaddr(&itni->itn_vi);
}

static void itni_dirtify(struct voluta_itnode_info *itni)
{
	vi_dirtify(&itni->itn_vi);
}

static size_t itni_depth(const struct voluta_itnode_info *itni)
{
	return itn_depth(itni->itn);
}

static void itni_setup_parent(struct voluta_itnode_info *child_itni,
                              const struct voluta_itnode_info *parent_itni)
{
	if (parent_itni != NULL) {
		itn_set_parent(child_itni->itn, itni_vaddr(parent_itni));
	} else {
		itn_reset_parent(child_itni->itn);
	}
	itni_dirtify(child_itni);
}

static void itni_setup(struct voluta_itnode_info *itni,
                       const struct voluta_itnode_info *parent_itni)
{
	const size_t depth = (parent_itni != NULL) ?
	                     itni_depth(parent_itni) + 1 : ITNODE_ROOT_DEPTH;

	itn_init(itni->itn, depth);
	itni_setup_parent(itni, parent_itni);
}

static int itni_check_root(const struct voluta_itnode_info *itni)
{
	return itn_isroot(itni->itn) ? 0 : -EFSCORRUPTED;
}

static void itni_resolve_child_at(const struct voluta_itnode_info *parent_itni,
                                  size_t slot, struct voluta_vaddr *out_vaddr)
{
	itn_child_at(parent_itni->itn, slot, out_vaddr);
}

static void itni_resolve_child(const struct voluta_itnode_info *parent_itni,
                               ino_t ino, struct voluta_vaddr *out_vaddr)
{
	const size_t slot = itn_child_slot(parent_itni->itn, ino);

	itni_resolve_child_at(parent_itni, slot, out_vaddr);
}

static void itni_bind_child(struct voluta_itnode_info *itni, ino_t ino,
                            struct voluta_itnode_info *child_itni)
{
	itn_set_child(itni->itn, ino, itni_vaddr(child_itni));
	itni_dirtify(itni);
}

static void itni_unbind_child(struct voluta_itnode_info *itni, ino_t ino)
{
	itn_clear_child(itni->itn, ino);
	itni_dirtify(itni);
}

static int spawn_itnode(struct voluta_sb_info *sbi,
                        struct voluta_itnode_info **out_itni)
{
	int err;
	struct voluta_vnode_info *vi = NULL;
	const enum voluta_ztype ztype = VOLUTA_ZTYPE_ITNODE;

	err = voluta_spawn_vnode(sbi, NULL, ztype, &vi);
	if (err) {
		return err;
	}
	*out_itni = voluta_itni_from_vi_rebind(vi);
	return 0;
}

static int spawn_setup_itnode(struct voluta_sb_info *sbi,
                              const struct voluta_itnode_info *parent_itni,
                              struct voluta_itnode_info **out_itni)
{
	int err;

	err = spawn_itnode(sbi, out_itni);
	if (err) {
		return err;
	}
	itni_setup(*out_itni, parent_itni);
	return 0;
}

static int remove_itnode(struct voluta_sb_info *sbi,
                         struct voluta_itnode_info *itni)
{
	return voluta_remove_vnode(sbi, &itni->itn_vi);
}

static int stage_itnode_at(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr,
                           struct voluta_itnode_info **out_itni)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	err = voluta_stage_cached_vnode(sbi, vaddr, &vi);
	if (!err) {
		*out_itni = voluta_itni_from_vi(vi);
		return 0;
	}
	err = voluta_stage_vnode(sbi, vaddr, NULL, &vi);
	if (err) {
		return err;
	}
	*out_itni = voluta_itni_from_vi_rebind(vi);
	return 0;
}

static int stage_itnode(struct voluta_sb_info *sbi,
                        struct voluta_itnode_info *parent_itni, ino_t ino,
                        struct voluta_itnode_info **out_child_itni)
{
	struct voluta_vaddr vaddr;

	itni_resolve_child(parent_itni, ino, &vaddr);
	return stage_itnode_at(sbi, &vaddr, out_child_itni);
}

static const struct voluta_vaddr *
itreeroot_vaddr(const struct voluta_sb_info *sbi)
{
	const struct voluta_itable_info *itbi = itbi_of(sbi);

	return itbi_root(itbi);
}

static int stage_itroot(struct voluta_sb_info *sbi,
                        struct voluta_itnode_info **out_itni)
{
	int err;

	err = stage_itnode_at(sbi, itreeroot_vaddr(sbi), out_itni);
	if (err) {
		return err;
	}
	err = itni_check_root(*out_itni);
	if (err) {
		return err;
	}
	return 0;
}

static void iaddr_by_ite(struct voluta_iaddr *iaddr,
                         const struct voluta_itable_entry *ite)
{
	struct voluta_vaddr vaddr;

	ite_vaddr(ite, &vaddr);
	iaddr_setup(iaddr, ite_ino(ite), &vaddr);
}

static int lookup_at(const struct voluta_itnode_info *itni,
                     ino_t ino, struct voluta_iaddr *out_iaddr)
{
	const struct voluta_itable_entry *ite;

	ite = itn_lookup(itni->itn, ino);
	if (ite == NULL) {
		return -ENOENT;
	}
	iaddr_by_ite(out_iaddr, ite);
	return 0;
}

static int do_lookup_iref(struct voluta_sb_info *sbi,
                          struct voluta_itnode_info *itni, ino_t ino,
                          struct voluta_iaddr *out_iaddr)
{
	int err;
	struct voluta_itnode_info *child_itni;

	err = lookup_at(itni, ino, out_iaddr);
	if (!err) {
		return 0;
	}
	err = stage_itnode(sbi, itni, ino, &child_itni);
	if (err) {
		return err;
	}
	err = lookup_iref(sbi, child_itni, ino, out_iaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int lookup_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni, ino_t ino,
                       struct voluta_iaddr *out_iaddr)
{
	int err;

	itni_incref(itni);
	err = do_lookup_iref(sbi, itni, ino, out_iaddr);
	itni_decref(itni);
	return err;
}

static int lookup_iaddr_of(struct voluta_sb_info *sbi, ino_t ino,
                           struct voluta_iaddr *out_iaddr)
{
	int err;
	struct voluta_itnode_info *itni = NULL;

	err = stage_itroot(sbi, &itni);
	if (err) {
		return err;
	}
	err = lookup_iref(sbi, itni, ino, out_iaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int create_child(struct voluta_sb_info *sbi,
                        struct voluta_itnode_info *parent_itni, ino_t ino,
                        struct voluta_itnode_info **out_child_itni)
{
	int err;
	size_t depth;
	const size_t depth_max = 16;

	depth = itni_depth(parent_itni);
	if (depth >= depth_max) {
		return -ENOSPC;
	}
	err = spawn_setup_itnode(sbi, parent_itni, out_child_itni);
	if (err) {
		return err;
	}
	itni_bind_child(parent_itni, ino, *out_child_itni);
	return 0;
}

static int require_child(struct voluta_sb_info *sbi,
                         struct voluta_itnode_info *itni, ino_t ino,
                         struct voluta_itnode_info **out_child_itni)
{
	int err;

	err = stage_itnode(sbi, itni, ino, out_child_itni);
	if (!err || (err != -ENOENT)) {
		return err;
	}
	err = create_child(sbi, itni, ino, out_child_itni);
	if (err) {
		return err;
	}
	return 0;
}

static int try_insert_at(struct voluta_sb_info *sbi,
                         struct voluta_itnode_info *itni,
                         const struct voluta_iaddr *iaddr)
{
	struct voluta_itable_entry *ite;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	ite = itn_insert(itni->itn, iaddr->ino, &iaddr->vaddr);
	if (ite == NULL) {
		return -ENOSPC;
	}
	itbi_add_ino(itbi, iaddr->ino);
	itni_dirtify(itni);
	return 0;
}

static int do_insert_iref(struct voluta_sb_info *sbi,
                          struct voluta_itnode_info *itni,
                          const struct voluta_iaddr *iaddr)
{
	int err;
	struct voluta_itnode_info *child_itni = NULL;

	err = try_insert_at(sbi, itni, iaddr);
	if (!err) {
		return 0;
	}
	err = require_child(sbi, itni, iaddr->ino, &child_itni);
	if (err) {
		return err;
	}
	err = insert_iref(sbi, child_itni, iaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int insert_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni,
                       const struct voluta_iaddr *iaddr)
{
	int err;

	itni_incref(itni);
	err = do_insert_iref(sbi, itni, iaddr);
	itni_decref(itni);
	return err;
}

static int try_update_at(struct voluta_sb_info *sbi,
                         struct voluta_itnode_info *itni,
                         const struct voluta_iaddr *iaddr)
{
	struct voluta_itable_entry *ite;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	ite = itn_update(itni->itn, iaddr->ino, &iaddr->vaddr);
	if (ite == NULL) {
		return -ENOENT;
	}
	itbi_fixup_apex_ino(itbi, iaddr->ino);
	itni_dirtify(itni);
	return 0;
}

static int do_update_iref(struct voluta_sb_info *sbi,
                          struct voluta_itnode_info *itni,
                          const struct voluta_iaddr *iaddr)
{
	int err;
	struct voluta_itnode_info *child_itni = NULL;

	err = try_update_at(sbi, itni, iaddr);
	if (!err) {
		return 0;
	}
	err = stage_itnode(sbi, itni, iaddr->ino, &child_itni);
	if (err) {
		return err;
	}
	err = update_iref(sbi, child_itni, iaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int update_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni,
                       const struct voluta_iaddr *iaddr)
{
	int err;

	itni_incref(itni);
	err = do_update_iref(sbi, itni, iaddr);
	itni_decref(itni);
	return err;
}

static int try_remove_at(struct voluta_sb_info *sbi,
                         struct voluta_itnode_info *itni, ino_t ino)
{
	struct voluta_itable_entry *ite;

	ite = itn_remove(itni->itn, ino);
	if (ite == NULL) {
		return -ENOENT;
	}
	itbi_remove_ino(itbi_of(sbi), ino);
	itni_dirtify(itni);
	return 0;
}

static int try_prune_leaf(struct voluta_sb_info *sbi,
                          struct voluta_itnode_info *parent_itni,
                          struct voluta_itnode_info *child_itni, ino_t ino)
{
	int err;

	if (!itn_isempty(child_itni->itn)) {
		return 0;
	}
	if (!itn_isleaf(child_itni->itn)) {
		return 0;
	}
	if (itn_isroot(child_itni->itn)) {
		return 0;
	}
	err = remove_itnode(sbi, child_itni);
	if (err) {
		return err;
	}
	itni_unbind_child(parent_itni, ino);
	return 0;
}

static int do_remove_iref(struct voluta_sb_info *sbi,
                          struct voluta_itnode_info *itni, ino_t ino)
{
	int err;
	struct voluta_itnode_info *child_itni = NULL;

	err = try_remove_at(sbi, itni, ino);
	if (!err) {
		return 0;
	}
	err = stage_itnode(sbi, itni, ino, &child_itni);
	if (err) {
		return err;
	}
	err = remove_iref(sbi, child_itni, ino);
	if (err) {
		return err;
	}
	err = try_prune_leaf(sbi, itni, child_itni, ino);
	if (err) {
		return err;
	}
	return 0;
}

static int remove_iref(struct voluta_sb_info *sbi,
                       struct voluta_itnode_info *itni, ino_t ino)
{
	int err;

	itni_incref(itni);
	err = do_remove_iref(sbi, itni, ino);
	itni_decref(itni);
	return err;
}

static int remove_itentry(struct voluta_sb_info *sbi, ino_t ino)
{
	int err;
	struct voluta_itnode_info *itni = NULL;

	err = stage_itroot(sbi, &itni);
	if (err) {
		return err;
	}
	err = remove_iref(sbi, itni, ino);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_acquire_ino(struct voluta_sb_info *sbi,
                       const struct voluta_vaddr *vaddr,
                       struct voluta_iaddr *out_iaddr)
{
	int err;
	ino_t ino;
	struct voluta_itnode_info *itni = NULL;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	iaddr_reset(out_iaddr);
	err = itbi_next_ino(itbi, &ino);
	if (err) {
		return err;
	}
	err = stage_itroot(sbi, &itni);
	if (err) {
		return err;
	}
	iaddr_setup(out_iaddr, ino, vaddr);
	err = insert_iref(sbi, itni, out_iaddr);
	if (err) {
		return err;
	}
	itbi_update_cache(itbi, out_iaddr);
	return 0;
}

int voluta_update_ino(struct voluta_sb_info *sbi,
                      const struct voluta_iaddr *iaddr)
{
	int err;
	struct voluta_itnode_info *itni = NULL;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	err = stage_itroot(sbi, &itni);
	if (err) {
		return err;
	}
	err = update_iref(sbi, itni, iaddr);
	if (err) {
		return err;
	}
	itbi_update_cache(itbi, iaddr);
	return 0;
}

int voluta_real_ino(const struct voluta_sb_info *sbi,
                    ino_t ino, ino_t *out_ino)
{
	int err = 0;
	const ino_t ino_max = VOLUTA_INO_MAX;
	const ino_t ino_root = VOLUTA_INO_ROOT;
	const struct voluta_itable_info *itbi = itbi_of(sbi);

	if ((ino < ino_root) || (ino > ino_max)) {
		ino = VOLUTA_INO_NULL;
		err = -EINVAL;
	} else if (ino == ino_root) {
		ino = itbi->it_rootdir.ino;
		err = unlikely(ino_isnull(ino)) ? -ENOENT : 0;
	}
	*out_ino = ino;
	return err;
}

int voluta_discard_ino(struct voluta_sb_info *sbi, ino_t xino)
{
	int err;
	ino_t ino;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	err = voluta_real_ino(sbi, xino, &ino);
	if (err) {
		return err;
	}
	err = remove_itentry(sbi, ino);
	if (err) {
		return err;
	}
	itbi_remove_cached(itbi, ino);
	return 0;
}

int voluta_resolve_ino(struct voluta_sb_info *sbi, ino_t xino,
                       struct voluta_iaddr *out_iaddr)
{
	int err;
	ino_t ino;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	err = voluta_real_ino(sbi, xino, &ino);
	if (err) {
		return err;
	}
	err = itbi_lookup_cached(itbi, ino, out_iaddr);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = lookup_iaddr_of(sbi, ino, out_iaddr);
	if (err) {
		return err;
	}
	itbi_update_cache(itbi, out_iaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_ino_set *ino_set_new(struct voluta_qalloc *qal)
{
	struct voluta_ino_set *ino_set;

	ino_set = voluta_qalloc_zmalloc(qal, sizeof(*ino_set));
	if (ino_set != NULL) {
		ino_set->cnt = 0;
	}
	return ino_set;
}

static void ino_set_del(struct voluta_ino_set *ino_set,
                        struct voluta_qalloc *qal)
{
	ino_set->cnt = 0;
	voluta_qalloc_free(qal, ino_set, sizeof(*ino_set));
}

static bool ino_set_isfull(const struct voluta_ino_set *ino_set)
{
	return (ino_set->cnt >= ARRAY_SIZE(ino_set->ino));
}

static void ino_set_append(struct voluta_ino_set *ino_set, ino_t ino)
{
	ino_set->ino[ino_set->cnt++] = ino;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_format_itable(struct voluta_sb_info *sbi)
{
	int err;
	const struct voluta_vaddr *vaddr = NULL;
	struct voluta_itnode_info *itni = NULL;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	err = spawn_setup_itnode(sbi, NULL, &itni);
	if (err) {
		return err;
	}
	vaddr = itni_vaddr(itni);
	itbi_set_root(itbi, vaddr);
	voluta_sb_set_itable_root(sbi->sb, vaddr);
	return 0;
}

static int reload_itable_root(struct voluta_sb_info *sbi,
                              const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_itnode_info *root_itni;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	err = stage_itnode_at(sbi, vaddr, &root_itni);
	if (err) {
		return err;
	}
	if (!itn_isroot(root_itni->itn)) {
		return -ENOENT;
	}
	vaddr_copyto(vaddr, &itbi->it_treeroot);
	return 0;
}

static void scan_entries_of(struct voluta_sb_info *sbi,
                            const struct voluta_itnode_info *itni)
{
	itbi_parse_inos_of(itbi_of(sbi), itni->itn);
}

static int scan_subtree_at(struct voluta_sb_info *sbi,
                           const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_itnode_info *itni;

	if (vaddr_isnull(vaddr)) {
		return 0;
	}
	err = stage_itnode_at(sbi, vaddr, &itni);
	if (err) {
		return err;
	}
	err = scan_subtree(sbi, itni);
	if (err) {
		return err;
	}
	return 0;
}

static int do_scan_subtree(struct voluta_sb_info *sbi,
                           const struct voluta_itnode_info *itni)
{
	int err = 0;
	struct voluta_vaddr vaddr;
	const size_t nchilds = itn_nchilds(itni->itn);
	const size_t nchilds_max = itn_nchilds_max(itni->itn);

	scan_entries_of(sbi, itni);
	if (!nchilds) {
		return 0;
	}
	for (size_t i = 0; (i < nchilds_max) && !err; ++i) {
		itni_resolve_child_at(itni, i, &vaddr);
		err = scan_subtree_at(sbi, &vaddr);
	}
	return err;
}

static int scan_subtree(struct voluta_sb_info *sbi,
                        struct voluta_itnode_info *itni)
{
	int err;

	itni_incref(itni);
	err = do_scan_subtree(sbi, itni);
	itni_decref(itni);
	return err;
}

static void fill_ino_set(const struct voluta_itnode_info *itni,
                         struct voluta_ino_set *ino_set)
{
	const struct voluta_itable_entry *ite;

	ino_set->cnt = 0;
	ite = itn_find_next(itni->itn, NULL);
	while (ite != NULL) {
		if (ino_set_isfull(ino_set)) {
			break;
		}
		ino_set_append(ino_set, ite_ino(ite));
		ite = itn_find_next(itni->itn, ite + 1);
	}
}

static int parse_itable_top(struct voluta_sb_info *sbi,
                            struct voluta_ino_set *ino_set)
{
	int err;
	struct voluta_itnode_info *itni = NULL;
	struct voluta_itable_info *itbi = itbi_of(sbi);

	err = stage_itnode_at(sbi, &itbi->it_treeroot, &itni);
	if (err) {
		return err;
	}
	fill_ino_set(itni, ino_set);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int scan_stage_root(struct voluta_sb_info *sbi,
                           const struct voluta_ino_set *ino_set,
                           struct voluta_inode_info **out_root_ii)
{
	int err;
	ino_t ino;
	struct voluta_inode_info *ii;

	for (size_t i = 0; i < ino_set->cnt; ++i) {
		ino = ino_set->ino[i];
		err = voluta_fetch_inode(sbi, ino, &ii);
		if (err) {
			return err;
		}
		if (voluta_is_rootdir(ii)) {
			*out_root_ii = ii;
			return 0;
		}
	}
	return -ENOENT;
}

static int do_scan_root_inode(struct voluta_sb_info *sbi,
                              struct voluta_ino_set *ino_set,
                              struct voluta_inode_info **out_root_ii)
{
	int err;

	err = parse_itable_top(sbi, ino_set);
	if (err) {
		return err;
	}
	err = scan_stage_root(sbi, ino_set, out_root_ii);
	if (err) {
		return err;
	}
	return 0;
}

static int scan_root_inode(struct voluta_sb_info *sbi,
                           struct voluta_inode_info **out_root_ii)
{
	int err;
	struct voluta_ino_set *ino_set;

	ino_set = ino_set_new(sbi->s_qalloc);
	if (ino_set == NULL) {
		return -ENOMEM;
	}
	err = do_scan_root_inode(sbi, ino_set, out_root_ii);
	ino_set_del(ino_set, sbi->s_qalloc);
	return err;
}

static int reload_scan_itable(struct voluta_sb_info *sbi,
                              const struct voluta_vaddr *vaddr)
{
	int err;
	struct voluta_itnode_info *itni;

	err = reload_itable_root(sbi, vaddr);
	if (err) {
		return err;
	}
	err = stage_itroot(sbi, &itni);
	if (err) {
		return err;
	}
	err = scan_subtree(sbi, itni);
	if (err) {
		return err;
	}
	return 0;
}

static bool vaddr_isitnode(const struct voluta_vaddr *vaddr)
{
	return !vaddr_isnull(vaddr) &&
	       ztype_isequal(vaddr->ztype, VOLUTA_ZTYPE_ITNODE);
}

static int resolve_itroot(struct voluta_sb_info *sbi,
                          struct voluta_vaddr *out_vaddr)
{
	voluta_sb_itable_root(sbi->sb, out_vaddr);
	if (!vaddr_isitnode(out_vaddr)) {
		log_err("non valid itable-root: off=0x%lx ztype=%d",
		        out_vaddr->off, out_vaddr->ztype);
		return -EFSCORRUPTED;
	}
	return 0;
}

int voluta_reload_itable(struct voluta_sb_info *sbi)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_inode_info *root_ii;

	err = resolve_itroot(sbi, &vaddr);
	if (err) {
		return err;
	}
	err = reload_scan_itable(sbi, &vaddr);
	if (err) {
		return err;
	}
	err = scan_root_inode(sbi, &root_ii);
	if (err) {
		return err;
	}
	err = voluta_bind_rootdir(sbi, root_ii);
	if (err) {
		return err;
	}
	return 0;
}

const struct voluta_vaddr *
voluta_root_of_itable(const struct voluta_sb_info *sbi)
{
	return itreeroot_vaddr(sbi);
}

int voluta_bind_rootdir(struct voluta_sb_info *sbi,
                        const struct voluta_inode_info *ii)
{
	int err;
	const ino_t ino = ii_ino(ii);
	struct voluta_itable_info *itbi = itbi_of(sbi);

	err = itbi_set_rootdir(itbi, ino, ii_vaddr(ii));
	if (!err) {
		itbi_fixup_apex_ino(itbi, ino);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int verify_itable_entry(const struct voluta_itable_entry *ite)
{
	int err;
	struct voluta_vaddr vaddr;
	const ino_t ino = ite_ino(ite);

	ite_vaddr(ite, &vaddr);
	err = voluta_verify_off(vaddr.off);
	if (err) {
		return err;
	}
	if (ztype_isnone(vaddr.ztype)) {
		if (!ino_isnull(ino)) {
			return -EFSCORRUPTED;
		}
	} else {
		if (!ztype_isinode(vaddr.ztype)) {
			return -EFSCORRUPTED;
		}
	}
	return 0;
}

static int verify_count(size_t count, size_t expected)
{
	return (count == expected) ? 0 : -EFSCORRUPTED;
}

static int verify_itnode_entries(const struct voluta_itable_tnode *itn)
{
	int err;
	ino_t ino;
	size_t count = 0;
	const struct voluta_itable_entry *ite;
	const size_t nents_max = itn_nents_max(itn);

	for (size_t i = 0; (i < nents_max); ++i) {
		ite = itn_entry_at(itn, i);
		err = verify_itable_entry(ite);
		if (err) {
			return err;
		}
		ino = ite_ino(ite);
		if (!ino_isnull(ino)) {
			count++;
		}
	}
	return verify_count(count, itn_nents(itn));
}

static int verify_itnode_childs(const struct voluta_itable_tnode *itn)
{
	int err;
	size_t nchilds = 0;
	struct voluta_vaddr vaddr;
	const size_t nchilds_max = itn_nchilds_max(itn);

	for (size_t slot = 0; slot < nchilds_max; ++slot) {
		itn_child_at(itn, slot, &vaddr);
		if (vaddr_isnull(&vaddr)) {
			continue;
		}
		err = voluta_verify_off(vaddr.off);
		if (err) {
			return err;
		}
		if (!ztype_isequal(vaddr.ztype, VOLUTA_ZTYPE_ITNODE)) {
			return -EFSCORRUPTED;
		}
		nchilds++;
	}
	return verify_count(nchilds, itn_nchilds(itn));
}

static int verify_itnode_parent(const struct voluta_itable_tnode *itn)
{
	int err;
	struct voluta_vaddr vaddr;

	itn_parent(itn, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return 0;
	}
	err = voluta_verify_off(vaddr.off);
	if (err) {
		return err;
	}
	if (!ztype_isequal(vaddr.ztype, VOLUTA_ZTYPE_ITNODE)) {
		return -EFSCORRUPTED;
	}
	return 0;
}

int voluta_verify_itnode(const struct voluta_itable_tnode *itn)
{
	int err;

	err = verify_itnode_parent(itn);
	if (err) {
		return err;
	}
	err = verify_itnode_entries(itn);
	if (err) {
		return err;
	}
	err = verify_itnode_childs(itn);
	if (err) {
		return err;
	}
	return 0;
}
