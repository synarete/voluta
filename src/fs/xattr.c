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
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <voluta/infra.h>
#include <voluta/fs/types.h>
#include <voluta/fs/address.h>
#include <voluta/fs/cache.h>
#include <voluta/fs/super.h>
#include <voluta/fs/namei.h>
#include <voluta/fs/inode.h>
#include <voluta/fs/xattr.h>
#include <voluta/fs/private.h>


#define XATTR_DATA_MAX \
	(VOLUTA_NAME_MAX + 1 + VOLUTA_XATTR_VALUE_MAX)

#define XATTRF_DISABLE 1

#define MKPREFIX(p_, n_, f_) \
	{ .prefix = (p_), .ns = (n_), .flags = (f_) }


struct voluta_xentry_view {
	struct voluta_xattr_entry xe;
	uint8_t  xe_data[XATTR_DATA_MAX];
} voluta_packed_aligned8;


struct voluta_xattr_prefix {
	const char *prefix;
	enum voluta_xattr_ns ns;
	int flags;
};


/*
 * TODO: For well-known xattr prefix, do not store the prefix-part as string
 * but as 'enum voluta_xattr_ns' value within 'xe_namespace'.
 */
static const struct voluta_xattr_prefix s_xattr_prefix[] = {
	MKPREFIX(XATTR_SECURITY_PREFIX, VOLUTA_XATTR_SECURITY, 0),
	MKPREFIX(XATTR_SYSTEM_PREFIX, VOLUTA_XATTR_SYSTEM, XATTRF_DISABLE),
	MKPREFIX(XATTR_TRUSTED_PREFIX, VOLUTA_XATTR_TRUSTED, 0),
	MKPREFIX(XATTR_USER_PREFIX, VOLUTA_XATTR_USER, 0),
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t xe_aligned_size(size_t size)
{
	const size_t align = sizeof(struct voluta_xattr_entry);

	return (align * div_round_up(size, align));
}

static size_t xe_calc_payload_nents(size_t name_len, size_t value_size)
{
	const size_t payload_size =
	        xe_aligned_size(name_len) + xe_aligned_size(value_size);

	return payload_size / sizeof(struct voluta_xattr_entry);
}

static size_t xe_calc_nents(size_t name_len, size_t value_size)
{
	return 1 + xe_calc_payload_nents(name_len, value_size);
}

static size_t xe_calc_nents_of(const struct voluta_str *name,
                               const struct voluta_slice *value)
{
	return xe_calc_nents(name->len, value->len);
}

static size_t xe_diff(const struct voluta_xattr_entry *beg,
                      const struct voluta_xattr_entry *end)
{
	return (size_t)(end - beg);
}

static struct voluta_xattr_entry *
xe_unconst(const struct voluta_xattr_entry *xe)
{
	return unconst(xe);
}

static struct voluta_xentry_view *
xe_view_of(const struct voluta_xattr_entry *xe)
{
	const struct voluta_xentry_view *xe_view =
	        container_of2(xe, struct voluta_xentry_view, xe);

	return unconst(xe_view);
}

static size_t xe_name_len(const struct voluta_xattr_entry *xe)
{
	return voluta_le16_to_cpu(xe->xe_name_len);
}

static void xe_set_name_len(struct voluta_xattr_entry *xe, size_t name_len)
{
	xe->xe_name_len = voluta_cpu_to_le16((uint16_t)name_len);
}

static size_t xe_value_size(const struct voluta_xattr_entry *xe)
{
	return voluta_le16_to_cpu(xe->xe_value_size);
}

static void xe_set_value_size(struct voluta_xattr_entry *xe, size_t value_size)
{
	xe->xe_value_size = voluta_cpu_to_le16((uint16_t)value_size);
}

static char *xe_name(const struct voluta_xattr_entry *xe)
{
	struct voluta_xentry_view *xeview = xe_view_of(xe);

	return (char *)xeview->xe_data;
}

static void *xe_value(const struct voluta_xattr_entry *xe)
{
	struct voluta_xentry_view *xeview = xe_view_of(xe);

	return xeview->xe_data + xe_aligned_size(xe_name_len(xe));
}

static bool xe_has_name(const struct voluta_xattr_entry *xe,
                        const struct voluta_str *name)
{
	return (name->len == xe_name_len(xe)) &&
	       !memcmp(xe_name(xe), name->str, name->len);
}

static size_t xe_nents(const struct voluta_xattr_entry *xe)
{
	return xe_calc_nents(xe_name_len(xe), xe_value_size(xe));
}

static struct voluta_xattr_entry *xe_next(const struct voluta_xattr_entry *xe)
{
	return xe_unconst(xe + xe_nents(xe));
}

static void xe_assign(struct voluta_xattr_entry *xe,
                      const struct voluta_str *name,
                      const struct voluta_slice *value)
{
	xe_set_name_len(xe, name->len);
	xe_set_value_size(xe, value->len);
	memcpy(xe_name(xe), name->str, name->len);
	memcpy(xe_value(xe), value->ptr, value->len);
}

static void xe_reset(struct voluta_xattr_entry *xe)
{
	voluta_memzero(xe, sizeof(*xe));
}

static void xe_reset_arr(struct voluta_xattr_entry *xe, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		xe_reset(&xe[i]);
	}
}

static void xe_squeeze(struct voluta_xattr_entry *xe,
                       const struct voluta_xattr_entry *last)
{
	const struct voluta_xattr_entry *next = xe_next(xe);

	memmove(xe, next, xe_diff(next, last) * sizeof(*xe));
}

static void xe_copy_value(const struct voluta_xattr_entry *xe,
                          struct voluta_slice *buf)
{
	voluta_slice_append(buf, xe_value(xe), xe_value_size(xe));
}

static struct voluta_xattr_entry *
xe_search(const struct voluta_xattr_entry *itr,
          const struct voluta_xattr_entry *end,
          const struct voluta_str *name)
{
	while (itr < end) {
		if (xe_has_name(itr, name)) {
			return unconst(itr);
		}
		itr = xe_next(itr);
	}
	return NULL;
}

static struct voluta_xattr_entry *
xe_append(struct voluta_xattr_entry *xe,
          const struct voluta_xattr_entry *end,
          const struct voluta_str *name,
          const struct voluta_slice *value)
{
	const size_t nfree = xe_diff(xe, end);
	const size_t nents = xe_calc_nents_of(name, value);

	if (nfree < nents) {
		return NULL;
	}
	xe_assign(xe, name, value);
	return xe;
}

static int xe_verify(const struct voluta_xattr_entry *xe,
                     const struct voluta_xattr_entry *end)
{
	size_t nents;
	const struct voluta_xattr_entry *itr = xe;

	while (itr < end) {
		nents = xe_nents(xe);
		if (!nents || ((xe + nents) > end)) {
			return -EFSCORRUPTED;
		}
		itr += nents;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ino_t xan_ino(const struct voluta_xattr_node *xan)
{
	return voluta_ino_to_cpu(xan->xa_ino);
}

static void xan_set_ino(struct voluta_xattr_node *xan, ino_t ino)
{
	xan->xa_ino = voluta_cpu_to_ino(ino);
}

static size_t xan_nents(const struct voluta_xattr_node *xan)
{
	return voluta_le16_to_cpu(xan->xa_nents);
}

static void xan_set_nents(struct voluta_xattr_node *xan, size_t n)
{
	xan->xa_nents = voluta_cpu_to_le16((uint16_t)n);
}

static void xan_inc_nents(struct voluta_xattr_node *xan, size_t n)
{
	xan_set_nents(xan, xan_nents(xan) + n);
}

static void xan_dec_nents(struct voluta_xattr_node *xan, size_t n)
{
	voluta_assert_gt(xan_nents(xan), 0);

	xan_set_nents(xan, xan_nents(xan) - n);
}

static void xan_setup(struct voluta_xattr_node *xan, ino_t ino)
{
	xan_set_ino(xan, ino);
	xan_set_nents(xan, 0);
	xe_reset_arr(xan->xe, ARRAY_SIZE(xan->xe));
}

static struct voluta_xattr_entry *
xan_begin(const struct voluta_xattr_node *xan)
{
	return xe_unconst(xan->xe);
}

static const struct voluta_xattr_entry *
xan_end(const struct voluta_xattr_node *xan)
{
	return xan->xe + ARRAY_SIZE(xan->xe);
}

static struct voluta_xattr_entry *
xan_last(const struct voluta_xattr_node *xan)
{
	return xe_unconst(xan->xe) + xan_nents(xan);
}

static struct voluta_xattr_entry *
xan_search(const struct voluta_xattr_node *xan, const struct voluta_str *str)
{
	struct voluta_xattr_entry *xe = NULL;
	const size_t nmin = xe_calc_nents(str->len, 0);

	if (xan_nents(xan) >= nmin) {
		xe = xe_search(xan_begin(xan), xan_last(xan), str);
	}
	return xe;
}

static struct voluta_xattr_entry *
xan_insert(struct voluta_xattr_node *xan,
           const struct voluta_str *name, const struct voluta_slice *value)
{
	struct voluta_xattr_entry *xe;

	xe = xe_append(xan_last(xan), xan_end(xan), name, value);
	if (xe != NULL) {
		xan_inc_nents(xan, xe_nents(xe));
	}
	return xe;
}

static void xan_remove(struct voluta_xattr_node *xan,
                       struct voluta_xattr_entry *xe)
{
	const size_t nents = xe_nents(xe);

	xe_squeeze(xe, xan_last(xan));
	xan_dec_nents(xan, nents);
}

static int xan_verify(const struct voluta_xattr_node *xan)
{
	return xe_verify(xan_begin(xan), xan_end(xan));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct voluta_inode_xattr *
inode_xattr_of(const struct voluta_inode *inode)
{
	const struct voluta_inode_xattr *ixa = &inode->i_xa;

	return unconst(ixa);
}

static struct voluta_inode_xattr *ixa_of(const struct voluta_inode_info *ii)
{
	return inode_xattr_of(ii->inode);
}

static size_t ixa_nents(const struct voluta_inode_xattr *ixa)
{
	return voluta_le16_to_cpu(ixa->ix_nents);
}

static void ixa_set_nents(struct voluta_inode_xattr *ixa, size_t n)
{
	ixa->ix_nents = voluta_cpu_to_le16((uint16_t)n);
}

static void ixa_inc_nents(struct voluta_inode_xattr *ixa, size_t n)
{
	ixa_set_nents(ixa, ixa_nents(ixa) + n);
}

static void ixa_dec_nents(struct voluta_inode_xattr *ixa, size_t n)
{
	ixa_set_nents(ixa, ixa_nents(ixa) - n);
}

static void ixa_vaddr(const struct voluta_inode_xattr *ixa, size_t slot,
                      struct voluta_vaddr *out_vaddr)
{
	voluta_vaddr64_parse(&ixa->ix_vaddr[slot], out_vaddr);
}

static void ixa_set_vaddr(struct voluta_inode_xattr *ixa, size_t slot,
                          const struct voluta_vaddr *vaddr)
{
	voluta_vaddr64_set(&ixa->ix_vaddr[slot], vaddr);
}

static void ixa_reset_vaddr(struct voluta_inode_xattr *ixa, size_t slot)
{
	ixa_set_vaddr(ixa, slot, vaddr_none());
}

static size_t ixa_nslots_max(const struct voluta_inode_xattr *ixa)
{
	return ARRAY_SIZE(ixa->ix_vaddr);
}

static void ixa_reset_slots(struct voluta_inode_xattr *ixa)
{
	const size_t nslots = ixa_nslots_max(ixa);

	for (size_t slot = 0; slot < nslots; ++slot) {
		ixa_reset_vaddr(ixa, slot);
	}
}

static void ixa_setup(struct voluta_inode_xattr *ixa)
{
	ixa_set_nents(ixa, 0);
	ixa_reset_slots(ixa);
	xe_reset_arr(ixa->ixe, ARRAY_SIZE(ixa->ixe));
}

static struct voluta_xattr_entry *
ixa_begin(const struct voluta_inode_xattr *ixa)
{
	return xe_unconst(ixa->ixe);
}

static const struct voluta_xattr_entry *
ixa_end(const struct voluta_inode_xattr *ixa)
{
	return ixa->ixe + ARRAY_SIZE(ixa->ixe);
}

static struct voluta_xattr_entry *
ixa_last(const struct voluta_inode_xattr *ixa)
{
	return xe_unconst(ixa->ixe) + ixa_nents(ixa);
}

static struct voluta_xattr_entry *
ixa_search(const struct voluta_inode_xattr *ixa,
           const struct voluta_str *str)
{
	struct voluta_xattr_entry *xe = NULL;
	const size_t nmin = xe_calc_nents(str->len, 0);

	if (ixa_nents(ixa) >= nmin) {
		xe = xe_search(ixa_begin(ixa), ixa_last(ixa), str);
	}
	return xe;
}

static struct voluta_xattr_entry *
ixa_insert(struct voluta_inode_xattr *ixa,
           const struct voluta_str *name,
           const struct voluta_slice *value)
{
	struct voluta_xattr_entry *xe;

	xe = xe_append(ixa_last(ixa), ixa_end(ixa), name, value);
	if (xe != NULL) {
		ixa_inc_nents(ixa, xe_nents(xe));
	}
	return xe;
}

static void ixa_remove(struct voluta_inode_xattr *ixa,
                       struct voluta_xattr_entry *xe)
{
	const size_t nents = xe_nents(xe);

	xe_squeeze(xe, ixa_last(ixa));
	ixa_dec_nents(ixa, nents);
}

static int ixa_verify(const struct voluta_inode_xattr *ixa)
{
	return xe_verify(ixa_begin(ixa), ixa_end(ixa));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t ii_xa_nslots_max(const struct voluta_inode_info *ii)
{
	return ixa_nslots_max(ixa_of(ii));
}

static void ii_xa_unset_at(struct voluta_inode_info *ii, size_t sloti)
{
	ixa_reset_vaddr(ixa_of(ii), sloti);
}

static void ii_xa_get_at(const struct voluta_inode_info *ii, size_t sloti,
                         struct voluta_vaddr *out_vaddr)
{
	ixa_vaddr(ixa_of(ii), sloti, out_vaddr);
}

static void ii_xa_set_at(const struct voluta_inode_info *ii, size_t sloti,
                         const struct voluta_vaddr *vaddr)
{
	ixa_set_vaddr(ixa_of(ii), sloti, vaddr);
}

void voluta_ii_setup_xattr(struct voluta_inode_info *ii)
{
	ixa_setup(ixa_of(ii));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_xattr_ctx {
	struct voluta_sb_info *sbi;
	const struct voluta_oper *op;
	struct voluta_listxattr_ctx *lxa_ctx;
	struct voluta_inode_info *ii;
	const struct voluta_namestr *name;
	struct voluta_slice value;
	size_t size;
	int flags;
	int keep_iter;
};

struct voluta_xentry_info {
	struct voluta_inode_info  *ii;
	struct voluta_xanode_info *xai;
	struct voluta_xattr_entry *xe;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct voluta_vaddr *
xai_vaddr(const struct voluta_xanode_info *xai)
{
	return vi_vaddr(&xai->xa_vi);
}

static void xai_dirtify(struct voluta_xanode_info *xai)
{
	vi_dirtify(&xai->xa_vi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int check_staged_xanode(const struct voluta_xattr_ctx *xa_ctx,
                               const struct voluta_xanode_info *xai)
{
	const ino_t ino = ii_ino(xa_ctx->ii);
	const ino_t xa_ino = xan_ino(xai->xan);

	if (ino != xa_ino) {
		log_err("bad xanode ino: ino=%lu xa_ino=%lu", ino, xa_ino);
		return -EFSCORRUPTED;
	}
	return 0;
}

static int stage_xanode(const struct voluta_xattr_ctx *xa_ctx,
                        const struct voluta_vaddr *vaddr,
                        struct voluta_xanode_info **out_xai)
{
	int err;
	struct voluta_vnode_info *vi = NULL;

	err = voluta_stage_cached_vnode(xa_ctx->sbi, vaddr, &vi);
	if (!err) {
		*out_xai = voluta_xai_from_vi(vi);
		return 0;
	}
	err = voluta_stage_vnode(xa_ctx->sbi, vaddr, xa_ctx->ii, &vi);
	if (err) {
		return err;
	}
	*out_xai = voluta_xai_from_vi_rebind(vi);
	err = check_staged_xanode(xa_ctx, *out_xai);
	if (err) {
		return err;
	}
	return 0;
}

static bool is_valid_xflags(int flags)
{
	return !flags || (flags == XATTR_CREATE) || (flags == XATTR_REPLACE);
}

static bool has_prefix(const struct voluta_xattr_prefix *xap,
                       const struct voluta_str *name)
{
	const size_t len = strlen(xap->prefix);

	return (name->len > len) && !strncmp(name->str, xap->prefix, len);
}

static const struct voluta_xattr_prefix *
search_prefix(const struct voluta_namestr *name)
{
	const struct voluta_xattr_prefix *xap;

	for (size_t i = 0; i < ARRAY_SIZE(s_xattr_prefix); ++i) {
		xap = &s_xattr_prefix[i];
		if (has_prefix(xap, &name->str)) {
			return xap;
		}
	}
	return NULL;
}

static int check_xattr_name(const struct voluta_namestr *name)
{
	const struct voluta_xattr_prefix *xap;

	if (!name) {
		return 0;
	}
	if (name->str.len > VOLUTA_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	xap = search_prefix(name);
	if (xap && (xap->flags & XATTRF_DISABLE)) {
		return -EOPNOTSUPP;
	}
	return 0;
}

static int check_xattr(const struct voluta_xattr_ctx *xa_ctx, int access_mode)
{
	int err;
	struct voluta_inode_info *ii = xa_ctx->ii;

	if (!ii_isreg(ii) && !ii_isdir(ii) && !ii_islnk(ii)) {
		return -EINVAL;
	}
	err = check_xattr_name(xa_ctx->name);
	if (err) {
		return err;
	}
	if (xa_ctx->size > VOLUTA_XATTR_VALUE_MAX) {
		return -EINVAL;
	}
	if (!is_valid_xflags(xa_ctx->flags)) {
		return -EOPNOTSUPP;
	}
	err = voluta_do_access(xa_ctx->op, ii, access_mode);
	if (err) {
		return err;
	}
	return 0;
}

static int lookup_xentry_in_xan(const struct voluta_xattr_ctx *xa_ctx,
                                const struct voluta_vaddr *vaddr,
                                struct voluta_xentry_info *xei)
{
	int err;
	struct voluta_xattr_entry *xe = NULL;
	struct voluta_xanode_info *xai = NULL;

	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	err = stage_xanode(xa_ctx, vaddr, &xai);
	if (err) {
		return err;
	}
	xe = xan_search(xai->xan, &xa_ctx->name->str);
	if (xe == NULL) {
		return -ENOENT;
	}
	xei->xai = xai;
	xei->xe = xe;
	return 0;
}

static int lookup_xentry_at_xan(struct voluta_xattr_ctx *xa_ctx,
                                struct voluta_xentry_info *xei)
{
	int err = -ENOENT;
	struct voluta_vaddr vaddr;
	const struct voluta_inode_info *ii = xa_ctx->ii;

	for (size_t sloti = 0; sloti < ii_xa_nslots_max(ii); ++sloti) {
		ii_xa_get_at(ii, sloti, &vaddr);
		err = lookup_xentry_in_xan(xa_ctx, &vaddr, xei);
		if (err != -ENOENT) {
			break;
		}
	}
	return err;
}

static int lookup_xentry_at_ixa(struct voluta_xattr_ctx *xa_ctx,
                                struct voluta_xentry_info *xei)
{
	struct voluta_xattr_entry *xe;
	struct voluta_inode_info *ii = xa_ctx->ii;

	xe = ixa_search(ixa_of(ii), &xa_ctx->name->str);
	if (xe == NULL) {
		return -ENOENT;
	}
	xei->ii = ii;
	xei->xe = xe;
	return 0;
}

static int lookup_xentry(struct voluta_xattr_ctx *xa_ctx,
                         struct voluta_xentry_info *xei)
{
	int err;

	err = lookup_xentry_at_ixa(xa_ctx, xei);
	if (err != -ENOENT) {
		goto out;
	}
	err = lookup_xentry_at_xan(xa_ctx, xei);
	if (err != -ENOENT) {
		goto out;
	}
out:
	return (err == -ENOENT) ? -ENOATTR : err;
}

static int do_getxattr(struct voluta_xattr_ctx *xa_ctx, size_t *out_size)
{
	int err;
	struct voluta_slice *buf = &xa_ctx->value;
	struct voluta_xentry_info xei = { .xe = NULL };

	err = check_xattr(xa_ctx, R_OK);
	if (err) {
		return err;
	}
	err = lookup_xentry(xa_ctx, &xei);
	if (err) {
		return err;
	}
	*out_size = xe_value_size(xei.xe);
	if (!buf->cap || (buf->ptr == NULL)) {
		return 0;
	}
	if (buf->cap < (buf->len + *out_size)) {
		return -ERANGE;
	}
	xe_copy_value(xei.xe, buf);
	return 0;
}

int voluta_do_getxattr(const struct voluta_oper *op,
                       struct voluta_inode_info *ii,
                       const struct voluta_namestr *name,
                       void *buf, size_t size, size_t *out_size)
{
	int err;
	struct voluta_xattr_ctx xa_ctx = {
		.sbi = ii_sbi(ii),
		.op = op,
		.ii = ii,
		.name = name,
		.value.ptr = buf,
		.value.len = 0,
		.value.cap = size
	};

	ii_incref(ii);
	err = do_getxattr(&xa_ctx, out_size);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void discard_xentry(const struct voluta_xentry_info *xei)
{
	struct voluta_inode_info *ii = xei->ii;
	struct voluta_xanode_info *xai = xei->xai;

	if (ii != NULL) {
		ixa_remove(ixa_of(ii), xei->xe);
		ii_dirtify(ii);
	} else if (xai != NULL) {
		xan_remove(xai->xan, xei->xe);
		xai_dirtify(xai);
	}
}

static int spawn_xanode(const struct voluta_xattr_ctx *xa_ctx,
                        struct voluta_xanode_info **out_xai)
{
	int err;
	struct voluta_vnode_info *vi = NULL;
	const enum voluta_ztype ztype = VOLUTA_ZTYPE_XANODE;

	err = voluta_spawn_vnode(xa_ctx->sbi, xa_ctx->ii, ztype, &vi);
	if (err) {
		return err;
	}
	*out_xai = voluta_xai_from_vi_rebind(vi);
	return 0;
}

static void setup_xanode(struct voluta_xanode_info *xai, ino_t ino)
{
	xan_setup(xai->xan, ino);
}

static int create_xanode(const struct voluta_xattr_ctx *xa_ctx,
                         size_t sloti, struct voluta_xanode_info **out_xai)
{
	int err;
	struct voluta_inode_info *ii = xa_ctx->ii;

	err = spawn_xanode(xa_ctx, out_xai);
	if (err) {
		return err;
	}
	setup_xanode(*out_xai, ii_ino(ii));

	ii_xa_set_at(ii, sloti, xai_vaddr(*out_xai));
	ii_dirtify(ii);
	return 0;
}

static int remove_xanode_at(const struct voluta_xattr_ctx *xa_ctx,
                            const struct voluta_vaddr *vaddr)
{
	return voluta_remove_vnode_at(xa_ctx->sbi, vaddr);
}

static int
stage_or_create_xanode(const struct voluta_xattr_ctx *xa_ctx,
                       size_t sloti, struct voluta_xanode_info **out_xai)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_inode_info *ii = xa_ctx->ii;

	ii_xa_get_at(ii, sloti, &vaddr);
	if (!vaddr_isnull(&vaddr)) {
		err = stage_xanode(xa_ctx, &vaddr, out_xai);
	} else {
		err = create_xanode(xa_ctx, sloti, out_xai);
	}
	return err;
}

static int try_insert_at(const struct voluta_xattr_ctx *xa_ctx,
                         struct voluta_xanode_info *xai,
                         struct voluta_xentry_info *xei)
{
	struct voluta_xattr_entry *xe;

	xe = xan_insert(xai->xan, &xa_ctx->name->str, &xa_ctx->value);
	if (xe == NULL) {
		return -ENOSPC;
	}
	xei->xai = xai;
	xei->xe = xe;
	xai_dirtify(xai);
	return 0;
}

static int try_insert_at_xan(const struct voluta_xattr_ctx *xa_ctx,
                             struct voluta_xentry_info *xei)
{
	int err;
	struct voluta_xanode_info *xai = NULL;
	const size_t nslots_max = ii_xa_nslots_max(xa_ctx->ii);

	for (size_t sloti = 0; sloti < nslots_max; ++sloti) {
		err = stage_or_create_xanode(xa_ctx, sloti, &xai);
		if (err) {
			break;
		}
		err = try_insert_at(xa_ctx, xai, xei);
		if (!err) {
			break;
		}
	}
	return err;
}

static int try_insert_at_ixa(const struct voluta_xattr_ctx *xa_ctx,
                             struct voluta_xentry_info *xei)
{
	struct voluta_xattr_entry *xe;
	struct voluta_inode_info *ii = xa_ctx->ii;

	xe = ixa_insert(ixa_of(ii), &xa_ctx->name->str, &xa_ctx->value);
	if (xe == NULL) {
		return -ENOSPC;
	}
	xei->ii = ii;
	xei->xe = xe;
	ii_dirtify(ii);
	return 0;
}

static int setxattr_create(struct voluta_xattr_ctx *xa_ctx,
                           struct voluta_xentry_info *xei)
{
	int err;

	if ((xa_ctx->flags == XATTR_CREATE) && xei->xe) {
		return -EEXIST;
	}
	err = try_insert_at_ixa(xa_ctx, xei);
	if (err != -ENOSPC) {
		return err;
	}
	err = try_insert_at_xan(xa_ctx, xei);
	if (err) {
		return err;
	}
	return 0;
}

/*
 * TODO-0007: XATTR_REPLACE in-place
 *
 * When possible in term of space, do simple replace-overwrite.
 */
static int setxattr_replace(struct voluta_xattr_ctx *xa_ctx,
                            struct voluta_xentry_info *xei)
{
	int err;
	struct voluta_xentry_info xei_cur = {
		.xai = xei->xai,
		.ii = xei->ii,
		.xe = xei->xe
	};

	/* TODO: Try replace in-place */
	if ((xa_ctx->flags == XATTR_REPLACE) && !xei->xe) {
		return -ENOATTR;
	}
	err = setxattr_create(xa_ctx, xei);
	if (!err) {
		discard_xentry(&xei_cur);
	}
	return err;
}

static int setxattr_new(struct voluta_xattr_ctx *xa_ctx)
{
	int err;
	struct voluta_xentry_info xei = { .xe = NULL };

	err = lookup_xentry(xa_ctx, &xei);
	if (err && (err != -ENOATTR)) {
		return err;
	}
	if (xa_ctx->flags == XATTR_CREATE) {
		return setxattr_create(xa_ctx, &xei);
	}
	if (xa_ctx->flags == XATTR_REPLACE) {
		return setxattr_replace(xa_ctx, &xei);
	}
	if (xei.xe) { /* implicit replace */
		xa_ctx->flags = XATTR_REPLACE;
		return setxattr_replace(xa_ctx, &xei);
	}
	/* by-default, create */
	return setxattr_create(xa_ctx, &xei);
}

static int do_setxattr(struct voluta_xattr_ctx *xa_ctx)
{
	int err;

	err = check_xattr(xa_ctx, W_OK);
	if (err) {
		return err;
	}
	err = setxattr_new(xa_ctx);
	if (err) {
		return err;
	}
	update_itimes(xa_ctx->op, xa_ctx->ii, VOLUTA_IATTR_CTIME);
	return 0;
}

int voluta_do_setxattr(const struct voluta_oper *op,
                       struct voluta_inode_info *ii,
                       const struct voluta_namestr *name,
                       const void *value, size_t size, int flags)
{
	int err;
	struct voluta_xattr_ctx xa_ctx = {
		.sbi = ii_sbi(ii),
		.op = op,
		.ii = ii,
		.name = name,
		.value.ptr = unconst(value),
		.value.len = size,
		.value.cap = size,
		.size = size,
		.flags = flags
	};

	ii_incref(ii);
	err = do_setxattr(&xa_ctx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0003: Delete node if empty
 *
 * Free xattr-node upon last-entry removal and update parent-slot.
 */
static int do_removexattr(struct voluta_xattr_ctx *xa_ctx)
{
	int err;
	struct voluta_xentry_info xei = { .xe = NULL };

	err = check_xattr(xa_ctx, W_OK);
	if (err) {
		return err;
	}
	err = lookup_xentry(xa_ctx, &xei);
	if (err) {
		return err;
	}
	discard_xentry(&xei);
	update_itimes(xa_ctx->op, xa_ctx->ii, VOLUTA_IATTR_CTIME);

	return 0;
}

int voluta_do_removexattr(const struct voluta_oper *op,
                          struct voluta_inode_info *ii,
                          const struct voluta_namestr *name)
{
	int err;
	struct voluta_xattr_ctx xa_ctx = {
		.sbi = ii_sbi(ii),
		.op = op,
		.ii = ii,
		.name = name
	};

	ii_incref(ii);
	err = do_removexattr(&xa_ctx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int emit(struct voluta_xattr_ctx *xa_ctx, const char *name, size_t nlen)
{
	return xa_ctx->lxa_ctx->actor(xa_ctx->lxa_ctx, name, nlen);
}

static int emit_xentry(struct voluta_xattr_ctx *xa_ctx,
                       const struct voluta_xattr_entry *xe)
{
	return emit(xa_ctx, xe_name(xe), xe_name_len(xe));
}

static int emit_range(struct voluta_xattr_ctx *xa_ctx,
                      const struct voluta_xattr_entry *itr,
                      const struct voluta_xattr_entry *lst)
{
	int err = 0;

	while ((itr < lst) && !err) {
		err = emit_xentry(xa_ctx, itr);
		itr = xe_next(itr);
	}
	return err;
}

static int emit_ixa(struct voluta_xattr_ctx *xa_ctx)
{
	const struct voluta_inode_xattr *ixa = ixa_of(xa_ctx->ii);

	return emit_range(xa_ctx, ixa_begin(ixa), ixa_last(ixa));
}

static int emit_xan(struct voluta_xattr_ctx *xa_ctx,
                    const struct voluta_xanode_info *xai)
{
	return emit_range(xa_ctx, xan_begin(xai->xan), xan_last(xai->xan));
}

static int emit_xan_at(struct voluta_xattr_ctx *xa_ctx, size_t sloti)
{
	int err;
	struct voluta_vaddr vaddr;
	struct voluta_xanode_info *xai = NULL;

	ii_xa_get_at(xa_ctx->ii, sloti, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return 0;
	}
	err = stage_xanode(xa_ctx, &vaddr, &xai);
	if (err) {
		return err;
	}
	err = emit_xan(xa_ctx, xai);
	if (err) {
		return err;
	}
	return 0;
}

static int emit_by_xan(struct voluta_xattr_ctx *xa_ctx)
{
	int err = 0;
	const size_t nslots_max = ii_xa_nslots_max(xa_ctx->ii);

	for (size_t sloti = 0; sloti < nslots_max; ++sloti) {
		err = emit_xan_at(xa_ctx, sloti);
		if (err) {
			break;
		}
	}
	return err;
}

static int emit_by_ixa(struct voluta_xattr_ctx *xa_ctx)
{
	return emit_ixa(xa_ctx);
}

static int emit_xattr_names(struct voluta_xattr_ctx *xa_ctx)
{
	int err;

	err = emit_by_ixa(xa_ctx);
	if (err) {
		return err;
	}
	err = emit_by_xan(xa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

static int do_listxattr(struct voluta_xattr_ctx *xa_ctx)
{
	int err;

	err = check_xattr(xa_ctx, R_OK);
	if (err) {
		return err;
	}
	err = emit_xattr_names(xa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

int voluta_do_listxattr(const struct voluta_oper *op,
                        struct voluta_inode_info *ii,
                        struct voluta_listxattr_ctx *lxa_ctx)
{
	int err;
	struct voluta_xattr_ctx xa_ctx = {
		.sbi = ii_sbi(ii),
		.op = op,
		.ii = ii,
		.lxa_ctx = lxa_ctx,
		.keep_iter = true
	};

	ii_incref(ii);
	err = do_listxattr(&xa_ctx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int drop_xan_at(struct voluta_xattr_ctx *xa_ctx, size_t sloti)
{
	int err;
	struct voluta_vaddr vaddr;

	ii_xa_get_at(xa_ctx->ii, sloti, &vaddr);
	if (vaddr_isnull(&vaddr)) {
		return 0;
	}
	err = remove_xanode_at(xa_ctx, &vaddr);
	if (err) {
		return err;
	}
	ii_xa_unset_at(xa_ctx->ii, sloti);
	return 0;
}

static int drop_xattr_slots(struct voluta_xattr_ctx *xa_ctx)
{
	int err = 0;
	const size_t nslots_max = ii_xa_nslots_max(xa_ctx->ii);

	for (size_t i = 0; (i < nslots_max) && !err; ++i) {
		err = drop_xan_at(xa_ctx, i);
	}
	return err;
}

int voluta_drop_xattr(struct voluta_inode_info *ii)
{
	int err;
	struct voluta_xattr_ctx xa_ctx = {
		.sbi = ii_sbi(ii),
		.ii = ii,
	};

	ii_incref(ii);
	err = drop_xattr_slots(&xa_ctx);
	ii_decref(ii);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int voluta_verify_inode_xattr(const struct voluta_inode *inode)
{
	const struct voluta_inode_xattr *ixa = inode_xattr_of(inode);

	/* TODO: check nodes offsets */

	return ixa_verify(ixa);
}

int voluta_verify_xattr_node(const struct voluta_xattr_node *xan)
{
	int err;

	err = voluta_verify_ino(xan_ino(xan));
	if (err) {
		return err;
	}
	err = xan_verify(xan);
	if (err) {
		return err;
	}
	return 0;
}

