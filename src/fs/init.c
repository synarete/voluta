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
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#include <voluta/infra.h>
#include <voluta/defs.h>
#include <voluta/ioctls.h>
#include <voluta/fs/types.h>
#include <voluta/fs/init.h>


#define BITS_SIZE(a)    (CHAR_BIT * sizeof(a))

#define MEMBER_SIZE(type, member) \
	sizeof(((const type *)NULL)->member)

#define MEMBER_NELEMS(type, member) \
	VOLUTA_ARRAY_SIZE(((const type *)NULL)->member)

#define MEMBER_NBITS(type, member) \
	BITS_SIZE(((const type *)NULL)->member)

#define SWORD(a) ((long)(a))

#define REQUIRE_EQ(a, b) \
	VOLUTA_STATICASSERT_EQ(SWORD(a), SWORD(b))

#define REQUIRE_LT(a, b) \
	VOLUTA_STATICASSERT_LT(SWORD(a), SWORD(b))

#define REQUIRE_GT(a, b) \
	VOLUTA_STATICASSERT_GT(SWORD(a), SWORD(b))

#define REQUIRE_GE(a, b) \
	VOLUTA_STATICASSERT_GE(SWORD(a), SWORD(b))

#define REQUIRE_BK_SIZE(a) \
	REQUIRE_EQ(a, VOLUTA_BK_SIZE)

#define REQUIRE_SIZEOF(type, size) \
	REQUIRE_EQ(sizeof(type), size)

#define REQUIRE_SIZEOF_BK(type) \
	REQUIRE_BK_SIZE(sizeof(type))

#define REQUIRE_SIZEOF_KB(type) \
	REQUIRE_SIZEOF(type, VOLUTA_KB_SIZE)

#define REQUIRE_SIZEOF_NK(type, nk) \
	REQUIRE_SIZEOF(type, (nk) * VOLUTA_KILO)

#define REQUIRE_SIZEOF_4K(type) \
	REQUIRE_SIZEOF_NK(type, 4)

#define REQUIRE_SIZEOF_8K(type) \
	REQUIRE_SIZEOF_NK(type, 8)

#define REQUIRE_SIZEOF_16K(type) \
	REQUIRE_SIZEOF_NK(type, 16)

#define REQUIRE_SIZEOF_32K(type) \
	REQUIRE_SIZEOF_NK(type, 32)

#define REQUIRE_MEMBER_SIZE(type, f, size) \
	REQUIRE_EQ(MEMBER_SIZE(type, f), size)

#define REQUIRE_NELEMS(type, f, nelems) \
	REQUIRE_EQ(MEMBER_NELEMS(type, f), nelems)

#define REQUIRE_NBITS(type, f, nbits) \
	REQUIRE_EQ(MEMBER_NBITS(type, f), nbits)

#define ISALIGNED32(off) \
	(((off) % 4) == 0)

#define ISALIGNED64(off) \
	(((off) % 8) == 0)

#define ISOFFSET(type, member, off) \
	(offsetof(type, member) == (off))

#define REQUIRE_XOFFSET(type, member, off) \
	VOLUTA_STATICASSERT(ISOFFSET(type, member, off))

#define REQUIRE_AOFFSET(type, member, off) \
	VOLUTA_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED32(off))

#define REQUIRE_AOFFSET64(type, member, off) \
	VOLUTA_STATICASSERT(ISOFFSET(type, member, off) && ISALIGNED64(off))

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void guarantee_fundamental_types_size(void)
{
	REQUIRE_SIZEOF(uint8_t, 1);
	REQUIRE_SIZEOF(uint16_t, 2);
	REQUIRE_SIZEOF(uint32_t, 4);
	REQUIRE_SIZEOF(uint64_t, 8);
	REQUIRE_SIZEOF(int8_t, 1);
	REQUIRE_SIZEOF(int16_t, 2);
	REQUIRE_SIZEOF(int32_t, 4);
	REQUIRE_SIZEOF(int64_t, 8);
	REQUIRE_SIZEOF(size_t, 8);
	REQUIRE_SIZEOF(loff_t, 8);
	REQUIRE_SIZEOF(ino_t, 8);
}

static void guarantee_persistent_types_size(void)
{
	REQUIRE_SIZEOF(struct voluta_vaddr56, 7);
	REQUIRE_SIZEOF(struct voluta_vaddr64, 8);
	REQUIRE_SIZEOF(struct voluta_blobid, 32);
	REQUIRE_SIZEOF(struct voluta_timespec, 16);
	REQUIRE_SIZEOF(struct voluta_kdf_desc, 16);
	REQUIRE_SIZEOF(struct voluta_kdf_pair, 32);
	REQUIRE_SIZEOF(struct voluta_iv, VOLUTA_IV_SIZE);
	REQUIRE_SIZEOF(struct voluta_key, VOLUTA_KEY_SIZE);
	REQUIRE_SIZEOF(struct voluta_blobspec, 64);
	REQUIRE_SIZEOF_4K(struct voluta_data_block4);
	REQUIRE_SIZEOF(struct voluta_data_block4, VOLUTA_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_SIZEOF_KB(struct voluta_inode);
	REQUIRE_SIZEOF_KB(struct voluta_lnk_value);
	REQUIRE_SIZEOF_16K(struct voluta_keys_record);
	REQUIRE_SIZEOF_32K(struct voluta_uspace_map);
	REQUIRE_SIZEOF_BK(struct voluta_super_block);
	REQUIRE_SIZEOF(struct voluta_super_block, VOLUTA_SB_SIZE);
	REQUIRE_SIZEOF_BK(struct voluta_hspace_map);
	REQUIRE_SIZEOF_BK(struct voluta_agroup_map);
	REQUIRE_SIZEOF_16K(struct voluta_itable_tnode);
	REQUIRE_SIZEOF_8K(struct voluta_xattr_node);
	REQUIRE_SIZEOF_8K(struct voluta_dir_htnode);
	REQUIRE_SIZEOF_8K(struct voluta_radix_tnode);
	REQUIRE_SIZEOF_BK(struct voluta_data_block);
	REQUIRE_SIZEOF_BK(union voluta_block_u);
	REQUIRE_SIZEOF_BK(struct voluta_block);
	REQUIRE_SIZEOF_BK(struct voluta_block);
	REQUIRE_SIZEOF(struct voluta_header, VOLUTA_HEADER_SIZE);
	REQUIRE_SIZEOF(struct voluta_uuid, VOLUTA_UUID_SIZE);
	REQUIRE_SIZEOF(struct voluta_name, VOLUTA_NAME_MAX + 1);
	REQUIRE_SIZEOF(struct voluta_ag_rec, 240);
	REQUIRE_SIZEOF(struct voluta_bk_rec, 56);
	REQUIRE_SIZEOF(struct voluta_itable_entry, 16);
	REQUIRE_SIZEOF(struct voluta_dir_entry, 16);
	REQUIRE_SIZEOF(struct voluta_xattr_entry, 8);
	REQUIRE_SIZEOF(struct voluta_dir_ispec, 64);
	REQUIRE_SIZEOF(struct voluta_reg_ispec, 512);
	REQUIRE_SIZEOF(struct voluta_lnk_ispec, 512);
	REQUIRE_SIZEOF(struct voluta_iattr_times, 64);
	REQUIRE_SIZEOF(struct voluta_xattr_ispec, 320);
	REQUIRE_SIZEOF(union voluta_iattr_specific, 512);
	REQUIRE_SIZEOF(struct voluta_inode, VOLUTA_INODE_SIZE);
	REQUIRE_SIZEOF(struct voluta_lnk_value, VOLUTA_SYMLNK_VAL_SIZE);
	REQUIRE_SIZEOF(struct voluta_xattr_node, VOLUTA_XATTR_NODE_SIZE);
	REQUIRE_SIZEOF(struct voluta_radix_tnode, VOLUTA_FILE_RTNODE_SIZE);
	REQUIRE_SIZEOF(struct voluta_itable_tnode, VOLUTA_ITNODE_SIZE);
	REQUIRE_SIZEOF(struct voluta_dir_htnode, VOLUTA_DIR_HTNODE_SIZE);
	REQUIRE_SIZEOF(struct voluta_ioc_query, 2048);
	REQUIRE_SIZEOF_4K(struct voluta_boot_record);
	REQUIRE_SIZEOF_4K(struct voluta_hash_record);
}

static void guarantee_persistent_types_members(void)
{
	REQUIRE_NBITS(struct voluta_header, h_vtype, 8);
	REQUIRE_NBITS(struct voluta_bk_rec, bk_allocated, VOLUTA_NKB_IN_BK);
	REQUIRE_NBITS(struct voluta_bk_rec, bk_unwritten, VOLUTA_NKB_IN_BK);
	REQUIRE_MEMBER_SIZE(struct voluta_itable_tnode, it_child, 1024);
	REQUIRE_NELEMS(struct voluta_radix_tnode,
	               r_child, VOLUTA_FILE_TREE_NCHILDS);
	REQUIRE_NELEMS(struct voluta_dir_htnode,
	               de, VOLUTA_DIR_HTNODE_NENTS);
	REQUIRE_NELEMS(struct voluta_dir_htnode,
	               dh_child, VOLUTA_DIR_HTNODE_NCHILDS);
	REQUIRE_NBITS(struct voluta_bksec_info, bs_mask,
	              VOLUTA_NKB_IN_BK * VOLUTA_NBK_IN_BSEC);
}

static void guarantee_persistent_types_alignment(void)
{
	REQUIRE_AOFFSET64(struct voluta_boot_record, br_magic, 16);
	REQUIRE_AOFFSET64(struct voluta_boot_record, br_version, 24);
	REQUIRE_AOFFSET64(struct voluta_boot_record, br_size, 32);
	REQUIRE_AOFFSET64(struct voluta_boot_record, br_sw_version, 64);
	REQUIRE_AOFFSET64(struct voluta_boot_record, br_kdf_pair, 512);
	REQUIRE_AOFFSET64(struct voluta_super_block, sb_boot_rec, 0);
	REQUIRE_AOFFSET64(struct voluta_super_block, sb_hash_rec, 4096);
	REQUIRE_AOFFSET64(struct voluta_super_block, sb_birth_time, 8192);
	REQUIRE_AOFFSET64(struct voluta_super_block, sb_name, 8448);
	REQUIRE_AOFFSET64(struct voluta_super_block, sb_keys, 16384);
	REQUIRE_AOFFSET64(struct voluta_super_block, sb_usm, 32768);
	REQUIRE_AOFFSET(struct voluta_hspace_map, hs_hdr, 0);
	REQUIRE_AOFFSET64(struct voluta_hspace_map, hs_agr, 4096);
	REQUIRE_AOFFSET(struct voluta_agroup_map, ag_hdr, 0);
	REQUIRE_AOFFSET64(struct voluta_agroup_map, ag_bkr, 8192);
	REQUIRE_AOFFSET64(struct voluta_itable_tnode, ite, 64);
	REQUIRE_AOFFSET64(struct voluta_itable_tnode, it_child, 15360);
	REQUIRE_AOFFSET(struct voluta_inode, i_hdr, 0);
	REQUIRE_AOFFSET(struct voluta_inode, i_ino, 16);
	REQUIRE_AOFFSET(struct voluta_inode, i_parent, 24);
	REQUIRE_AOFFSET(struct voluta_inode, i_uid, 32);
	REQUIRE_AOFFSET(struct voluta_inode, i_gid, 36);
	REQUIRE_AOFFSET(struct voluta_inode, i_mode, 40);
	REQUIRE_AOFFSET(struct voluta_inode, i_flags, 44);
	REQUIRE_AOFFSET(struct voluta_inode, i_size, 48);
	REQUIRE_AOFFSET(struct voluta_inode, i_span, 56);
	REQUIRE_AOFFSET(struct voluta_inode, i_blocks, 64);
	REQUIRE_AOFFSET(struct voluta_inode, i_nlink, 72);
	REQUIRE_AOFFSET(struct voluta_inode, i_attributes, 80);
	REQUIRE_AOFFSET64(struct voluta_inode, i_t, 128);
	REQUIRE_AOFFSET64(struct voluta_inode, i_x, 192);
	REQUIRE_AOFFSET64(struct voluta_inode, i_s, 512);
	REQUIRE_AOFFSET(struct voluta_dir_entry, de_ino, 0);
	REQUIRE_AOFFSET(struct voluta_dir_entry, de_nents, 8);
	REQUIRE_XOFFSET(struct voluta_dir_entry, de_nprev, 10);
	REQUIRE_XOFFSET(struct voluta_dir_entry, de_name_len, 12);
	REQUIRE_XOFFSET(struct voluta_dir_entry, de_dt, 14);
	REQUIRE_AOFFSET(struct voluta_dir_htnode, dh_hdr, 0);
	REQUIRE_AOFFSET64(struct voluta_dir_htnode, de, 64);
	REQUIRE_AOFFSET(struct voluta_radix_tnode, r_hdr, 0);
	REQUIRE_AOFFSET64(struct voluta_radix_tnode, r_zeros, 64);
	REQUIRE_AOFFSET64(struct voluta_radix_tnode, r_child, 1024);
	REQUIRE_AOFFSET(struct voluta_xattr_ispec, xa_nents, 0);
	REQUIRE_AOFFSET(struct voluta_xattr_ispec, xa_vaddr, 8);
	REQUIRE_AOFFSET(struct voluta_xattr_node, xa_hdr, 0);
	REQUIRE_AOFFSET(struct voluta_xattr_node, xe, 64);
	REQUIRE_AOFFSET64(struct voluta_lnk_value, lv_value, 64);
}

static void guarantee_defs_consistency(void)
{
	REQUIRE_EQ(CHAR_BIT, 8);
	REQUIRE_LT(VOLUTA_DIR_HTREE_DEPTH_MAX, VOLUTA_HASH256_LEN);
	REQUIRE_LT(VOLUTA_DIR_HTREE_INDEX_MAX, INT32_MAX);
	REQUIRE_LT(VOLUTA_DIR_HTREE_INDEX_MAX, VOLUTA_DIR_HTREE_INDEX_NULL);
	REQUIRE_GT(VOLUTA_DIR_ENTRIES_MAX, VOLUTA_LINK_MAX);
	REQUIRE_LT(VOLUTA_XATTR_VALUE_MAX, VOLUTA_XATTR_NODE_SIZE);
	REQUIRE_EQ(VOLUTA_FILE_SIZE_MAX, 64 * VOLUTA_TERA - 1);
	REQUIRE_EQ(VOLUTA_BU_SIZE, 256 * VOLUTA_KILO);
	REQUIRE_EQ(VOLUTA_AG_SIZE, 64 * VOLUTA_MEGA);
	REQUIRE_EQ(VOLUTA_HS_SIZE, 16 * VOLUTA_GIGA);
	REQUIRE_EQ(VOLUTA_VOLUME_SIZE_MIN, 2 * VOLUTA_GIGA);
	REQUIRE_EQ(VOLUTA_VOLUME_SIZE_MAX, 8 * VOLUTA_TERA);
	REQUIRE_EQ(VOLUTA_AR_BLOB_SIZE, 16 * VOLUTA_MEGA);

	REQUIRE_EQ(VOLUTA_FILE_HEAD1_LEAF_SIZE * VOLUTA_FILE_HEAD1_NLEAVES,
	           VOLUTA_FILE_HEAD2_LEAF_SIZE);
	REQUIRE_EQ((VOLUTA_FILE_HEAD1_LEAF_SIZE * VOLUTA_FILE_HEAD1_NLEAVES) +
	           (VOLUTA_FILE_HEAD2_LEAF_SIZE * VOLUTA_FILE_HEAD2_NLEAVES),
	           VOLUTA_FILE_TREE_LEAF_SIZE);
}

static void guarantee_external_constants(void)
{
	REQUIRE_EQ(VOLUTA_NAME_MAX, NAME_MAX);
	REQUIRE_EQ(VOLUTA_PATH_MAX, PATH_MAX);
	REQUIRE_GE(VOLUTA_LINK_MAX, LINK_MAX);
	REQUIRE_GE(VOLUTA_NAME_MAX, XATTR_NAME_MAX);
	REQUIRE_GE(VOLUTA_XATTR_VALUE_MAX, XATTR_SIZE_MAX / 16);
	REQUIRE_EQ(VOLUTA_CIPHER_AES256, GCRY_CIPHER_AES256);
	REQUIRE_EQ(VOLUTA_CIPHER_MODE_CBC, GCRY_CIPHER_MODE_CBC);
	REQUIRE_EQ(VOLUTA_CIPHER_MODE_GCM, GCRY_CIPHER_MODE_GCM);
	REQUIRE_EQ(VOLUTA_MD_SHA256, GCRY_MD_SHA256);
	REQUIRE_EQ(VOLUTA_MD_SHA3_256, GCRY_MD_SHA3_256);
	REQUIRE_EQ(VOLUTA_MD_SHA3_512, GCRY_MD_SHA3_512);
	REQUIRE_EQ(VOLUTA_KDF_PBKDF2, GCRY_KDF_PBKDF2);
	REQUIRE_EQ(VOLUTA_KDF_SCRYPT, GCRY_KDF_SCRYPT);
}

static void guarantee_sane(void)
{
	guarantee_fundamental_types_size();
	guarantee_persistent_types_size();
	guarantee_persistent_types_members();
	guarantee_persistent_types_alignment();
	guarantee_defs_consistency();
	guarantee_external_constants();
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int g_libvoluta_init;


static int errno_or_errnum(int errnum)
{
	return (errno > 0) ? -errno : -abs(errnum);
}

static int check_sysconf(void)
{
	long val;
	long page_shift = 0;
	const long page_size_min = VOLUTA_PAGE_SIZE;
	const long page_shift_min = VOLUTA_PAGE_SHIFT;
	const long page_shift_max = VOLUTA_PAGE_SHIFT_MAX;
	const long cl_size_min = VOLUTA_CACHELINE_SIZE;

	errno = 0;
	val = (long)voluta_sc_phys_pages();
	if (val <= 0) {
		return errno_or_errnum(ENOMEM);
	}
	val = (long)voluta_sc_avphys_pages();
	if (val <= 0) {
		return errno_or_errnum(ENOMEM);
	}
	val = (long)voluta_sc_l1_dcache_linesize();
	if ((val != cl_size_min) || (val % cl_size_min)) {
		return errno_or_errnum(EOPNOTSUPP);
	}
	val = (long)voluta_sc_page_size();
	if ((val < page_size_min) || (val % page_size_min)) {
		return errno_or_errnum(EOPNOTSUPP);
	}
	for (long shift = page_shift_min; shift <= page_shift_max; ++shift) {
		if (val == (1L << shift)) {
			page_shift = val;
			break;
		}
	}
	if (page_shift == 0) {
		return -EOPNOTSUPP;
	}
	return 0;
}

static int check_system_page_size(void)
{
	long page_size;
	const size_t page_shift[] = { 12, 13, 14, 16 };

	page_size = voluta_sc_page_size();
	if (page_size > VOLUTA_BK_SIZE) {
		return -EOPNOTSUPP;
	}
	for (size_t i = 0; i < VOLUTA_ARRAY_SIZE(page_shift); ++i) {
		if (page_size == (1L << page_shift[i])) {
			return 0;
		}
	}
	return -EOPNOTSUPP;
}

static int check_proc_rlimits(void)
{
	int err;
	struct rlimit rlim;

	err = voluta_sys_getrlimit(RLIMIT_AS, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < VOLUTA_MEGA) {
		return -ENOMEM;
	}
	err = voluta_sys_getrlimit(RLIMIT_NOFILE, &rlim);
	if (err) {
		return err;
	}
	if (rlim.rlim_cur < 64) {
		return -EMFILE;
	}
	return 0;
}


int voluta_init_lib(void)
{
	int err;

	guarantee_sane();
	if (g_libvoluta_init) {
		return 0;
	}
	err = check_sysconf();
	if (err) {
		return err;
	}
	err = check_system_page_size();
	if (err) {
		return err;
	}
	err = check_proc_rlimits();
	if (err) {
		return err;
	}
	err = voluta_init_gcrypt();
	if (err) {
		return err;
	}
	voluta_burnstack();

	g_libvoluta_init = 1;

	return 0;
}
