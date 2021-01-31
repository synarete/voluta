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
#ifndef VOLUTA_DEFS_H_
#define VOLUTA_DEFS_H_

#include <stdint.h>

/* common power-of-2 sizes */
#define VOLUTA_KILO                     (1L << 10)
#define VOLUTA_MEGA                     (1L << 20)
#define VOLUTA_GIGA                     (1L << 30)
#define VOLUTA_TERA                     (1L << 40)
#define VOLUTA_PETA                     (1L << 50)
#define VOLUTA_UKILO                    (1UL << 10)
#define VOLUTA_UMEGA                    (1UL << 20)
#define VOLUTA_UGIGA                    (1UL << 30)
#define VOLUTA_UTERA                    (1UL << 40)
#define VOLUTA_UPETA                    (1UL << 50)


/* volume's zero-block marker (ASCII: "@voluta@") */
#define VOLUTA_ZB_MARK                  (0x406174756C6F7640L)

/* current on-disk format version number */
#define VOLUTA_FMT_VERSION              (1)

/* file-system fsid magic number (ASCII: '@VLT') */
#define VOLUTA_SUPER_MAGIC              (0x40564C54U)

/* magic numbers at meta-objects start (ASCII: '#VLT') */
#define VOLUTA_VTYPE_MAGIC              (0x23564C54U)

/* max length of encryption pass-phrase */
#define VOLUTA_PASSPHRASE_MAX           (255)

/* max size for names (not including null terminator) */
#define VOLUTA_NAME_MAX                 (255)

/* max size of path (symbolic link value, including null) */
#define VOLUTA_PATH_MAX                 (4096)

/* max size of mount-path (including null) */
#define VOLUTA_MNTPATH_MAX              (1920)

/* max number of hard-links to file or sub-directories */
#define VOLUTA_LINK_MAX                 (32767)

/* number of octets in UUID */
#define VOLUTA_UUID_SIZE                (16)

/* size of common meta-data header */
#define VOLUTA_HEADER_SIZE              (16)


/* bits-shift of small (1K) block-size */
#define VOLUTA_KB_SHIFT                 (10)

/* small ("sector") meta-block size (1K) */
#define VOLUTA_KB_SIZE                  (1 << VOLUTA_KB_SHIFT)

/* number of small blocks in block-octet */
#define VOLUTA_NKB_IN_BK \
	(VOLUTA_BK_SIZE / VOLUTA_KB_SIZE)


/* bits-shift of logical block */
#define VOLUTA_BK_SHIFT                 (16)

/* logical block size (64K) */
#define VOLUTA_BK_SIZE                  (1L << VOLUTA_BK_SHIFT)

/* number of logical blocks within allocation-group */
#define VOLUTA_NBK_IN_AG                (1024L)


/* allocation-group size (64M) */
#define VOLUTA_AG_SIZE \
	(VOLUTA_NBK_IN_AG * VOLUTA_BK_SIZE)


/* number of allocation-groups per hyper-space */
#define VOLUTA_NAG_IN_HS                (1024L)

/* number of leading allocation-groups for super/hyper-space meta-blocks */
#define VOLUTA_NAG_IN_HS_PREFIX         (1)

/* size of single hyper-space (64G) */
#define VOLUTA_HS_SIZE \
	(VOLUTA_NAG_IN_HS * VOLUTA_AG_SIZE)


/* minimal number of allocation-groups in volume */
#define VOLUTA_VOLUME_NAG_MIN           (2)

/* maximal number of allocation-groups in volume */
#define VOLUTA_VOLUME_NAG_MAX \
	((VOLUTA_NAG_IN_HS * VOLUTA_NBK_IN_AG) / 2)

/* minimal bytes-size of underlying volume */
#define VOLUTA_VOLUME_SIZE_MIN \
	(VOLUTA_VOLUME_NAG_MIN * VOLUTA_AG_SIZE)

/* maximal bytes-size of underlying volume (32T) */
#define VOLUTA_VOLUME_SIZE_MAX  \
	(VOLUTA_AG_SIZE * VOLUTA_VOLUME_NAG_MAX)

/* max path-length (including null) of volume-path */
#define VOLUTA_VOLUME_PATH_MAX          (2032)


/* non-valid ("NIL") logical byte address */
#define VOLUTA_OFF_NULL                 ((1L << 56) - 1)

/* non-valid ("NIL") logical block address */
#define VOLUTA_LBA_NULL                 ((1L << 56) - 1)

/* well-known LBA of super-block */
#define VOLUTA_LBA_SB                   (0)

/* "nil" inode number */
#define VOLUTA_INO_NULL                 (0)

/* export ino towards vfs of root inode */
#define VOLUTA_INO_ROOT                 (1)

/* max valid ino number */
#define VOLUTA_INO_MAX                  ((1L << 56) - 1)


/* on-disk size of super-block */
#define VOLUTA_SB_SIZE                  VOLUTA_BK_SIZE

/* maximal number of file-system layers within super-block */
#define VOLUTA_SB_LAYERS_MAX            (64)


/* on-disk size of inode's head */
#define VOLUTA_INODE_SIZE               VOLUTA_KB_SIZE


/* bits-shift for inode-table childs fan-out */
#define VOLUTA_ITNODE_SHIFT             (7)

/* number of children per inode-table node */
#define VOLUTA_ITNODE_NSLOTS            (1 << VOLUTA_ITNODE_SHIFT)

/* number of entries in inode-table node */
#define VOLUTA_ITNODE_NENTS             (953)

/* on-disk size of inode-table node */
#define VOLUTA_ITNODE_SIZE              (16384)


/* height-limit of file-mapping radix-tree */
#define VOLUTA_FILE_HEIGHT_MAX          (4)

/* bits-shift of single file-mapping address-space */
#define VOLUTA_FILE_MAP_SHIFT           (10)

/* file's level1 head-mapping block-sizes (4K) */
#define VOLUTA_FILE_HEAD_LEAF_SIZE     (4 * VOLUTA_KB_SIZE)

/* file's tree-mapping block-sizes */
#define VOLUTA_FILE_TREE_LEAF_SIZE      VOLUTA_BK_SIZE

/* number of 4K leaves in regular-file's head mapping */
#define VOLUTA_FILE_HEAD_NLEAVES       (16)

/* number of mapping-slots per single file tree node */
#define VOLUTA_FILE_TREE_NCHILDS        (1LL << VOLUTA_FILE_MAP_SHIFT)

/* maximum number of data-leafs in regular file */
#define VOLUTA_FILE_LEAVES_MAX \
	(1LL << (VOLUTA_FILE_MAP_SHIFT * (VOLUTA_FILE_HEIGHT_MAX - 1)))

/* maximum size in bytes of regular file */
#define VOLUTA_FILE_SIZE_MAX \
	((VOLUTA_BK_SIZE * VOLUTA_FILE_LEAVES_MAX) - 1)

/* on-disk size of file's radix-tree-node */
#define VOLUTA_FILE_RTNODE_SIZE         (8192)


/* base size of empty directory */
#define VOLUTA_DIR_EMPTY_SIZE           VOLUTA_INODE_SIZE

/* on-disk size of directory htree-node */
#define VOLUTA_DIR_HTNODE_SIZE          (8192)

/* number of directory-entries in dir's internal H-tree mapping node  */
#define VOLUTA_DIR_HTNODE_NENTS         (476)

/* bits-shift of children per dir-htree node */
#define VOLUTA_DIR_HTNODE_SHIFT         (6)

/* number of children per dir-htree node */
#define VOLUTA_DIR_HTNODE_NCHILDS \
	(1 << VOLUTA_DIR_HTNODE_SHIFT)

/* maximum depth of directory htree-mapping */
#define VOLUTA_DIR_HTREE_DEPTH_MAX (4L)

/* max number of dir htree nodes */
#define VOLUTA_DIR_HTREE_INDEX_MAX \
	((1L << (VOLUTA_DIR_HTNODE_SHIFT * VOLUTA_DIR_HTREE_DEPTH_MAX)) - 1)

/* non-valid htree node-index */
#define VOLUTA_DIR_HTREE_INDEX_NULL     (1L << 31)

/* max entries in directory */
#define VOLUTA_DIR_ENTRIES_MAX \
	(VOLUTA_DIR_HTNODE_NENTS * VOLUTA_DIR_HTREE_INDEX_MAX)

/* max value of directory offset */
#define VOLUTA_DIR_OFFSET_MAX           (VOLUTA_DIR_ENTRIES_MAX + 1)


/* max size of symbolic-link value (including null terminator) */
#define VOLUTA_SYMLNK_MAX               VOLUTA_PATH_MAX

/* max size of within-inode symbolic-link value  */
#define VOLUTA_SYMLNK_HEAD_MAX          (472)

/* max size of symbolic-link part  */
#define VOLUTA_SYMLNK_PART_MAX          (960)

/* number of possible symbolic-link parts  */
#define VOLUTA_SYMLNK_NPARTS            (5)

/* on-disk size of symlink tail-value */
#define VOLUTA_SYMLNK_VAL_SIZE          VOLUTA_KB_SIZE


/* number of extended-attributes entries in inode's head */
#define VOLUTA_XATTR_INENTS             (32)

/* number of extended-attributes entries in indirect node */
#define VOLUTA_XATTR_NENTS              (1016)

/* max length of extended attributes value */
#define VOLUTA_XATTR_VALUE_MAX          (4096)

/* on-disk size of xattr node */
#define VOLUTA_XATTR_NODE_SIZE          (8192)


/* max size of single I/O operation */
#define VOLUTA_IO_SIZE_MAX              (4UL * VOLUTA_UMEGA)


/* size in bytes of single archiving blob (16M) */
#define VOLUTA_AR_BLOB_SIZE             (VOLUTA_AG_SIZE / 4)

/* size of archive blob spec entry */
#define VOLUTA_AR_BLOBREF_SIZE          (64)



/* zero-LBA meta-block types */
enum voluta_ztype {
	VOLUTA_ZTYPE_NONE       = 0,
	VOLUTA_ZTYPE_VOLUME     = 1,
	VOLUTA_ZTYPE_ARCHIVE    = 2,
};


/* zero-LBA meta-block control flags */
enum voluta_zbf {
	VOLUTA_ZBF_NONE         = (1 << 0),
	VOLUTA_ZBF_ENCRYPTED    = (1 << 1),
};


/* file-system elements types */
enum voluta_vtype {
	VOLUTA_VTYPE_NONE       = 0,
	VOLUTA_VTYPE_DATA4K     = 4,
	VOLUTA_VTYPE_HSMAP      = 5,
	VOLUTA_VTYPE_AGMAP      = 7,
	VOLUTA_VTYPE_ITNODE     = 11,
	VOLUTA_VTYPE_INODE      = 13,
	VOLUTA_VTYPE_XANODE     = 17,
	VOLUTA_VTYPE_HTNODE     = 19,
	VOLUTA_VTYPE_RTNODE     = 23,
	VOLUTA_VTYPE_SYMVAL     = 29,
	VOLUTA_VTYPE_DATABK     = 64,
};


/* hyper-space flags */
enum voluta_hsf {
	VOLUTA_HSF_HASNEXT      = (1 << 0),
};


/* allocation-groups flags */
enum voluta_agf {
	VOLUTA_AGF_FORMATTED    = (1 << 0),
	VOLUTA_AGF_FRAGMENTED   = (1 << 1),
	VOLUTA_AGF_USERDATA     = (1 << 2),
	VOLUTA_AGF_METADATA     = (1 << 3),
	VOLUTA_AGF_ITABLEROOT   = (1 << 4),
};


/* inode control flags */
enum voluta_inodef {
	VOLUTA_INODEF_ROOTD     = (1 << 0),
};


/* dir-inode control flags */
enum voluta_dirf {
	VOLUTA_DIRF_HASH_SHA256 = (1 << 0),
	VOLUTA_DIRF_NAME_UTF8   = (1 << 1),
};

/* extended attributes known classes */
enum voluta_xattr_ns {
	VOLUTA_XATTR_NONE       = 0,
	VOLUTA_XATTR_SECURITY   = 1,
	VOLUTA_XATTR_SYSTEM     = 2,
	VOLUTA_XATTR_TRUSTED    = 3,
	VOLUTA_XATTR_USER       = 4,
};

/* cryptographic key size */
#define VOLUTA_KEY_SIZE         (32)

/* initialization vector size (for AES256) */
#define VOLUTA_IV_SIZE          (16)

/* cryptographic hash-128-bits bytes-size */
#define VOLUTA_HASH128_LEN      (16)

/* cryptographic hash-256-bits bytes-size */
#define VOLUTA_HASH256_LEN      (32)

/* cryptographic hash-512-bits bytes-size */
#define VOLUTA_HASH512_LEN      (64)

/* salt size for Key-Derivation-Function */
#define VOLUTA_SALT_SIZE        (128)

/* encryption cipher settings (libgcrypt values) */
enum voluta_cipher_type {
	VOLUTA_CIPHER_NONE      = 0,
	VOLUTA_CIPHER_AES256    = 9,
	VOLUTA_CIPHER_MODE_CBC  = 3,
	VOLUTA_CIPHER_MODE_GCM  = 9,
};

/* hash-function type (libgcrypt values) */
enum voluta_md_type {
	VOLUTA_MD_NONE          = 0,
	VOLUTA_MD_SHA256        = 8,
	VOLUTA_MD_SHA3_256      = 313,
	VOLUTA_MD_SHA3_512      = 315
};

/* key-derivation functions (libgcrypt values) */
enum voluta_kdf_algos {
	VOLUTA_KDF_NONE         = 0,
	VOLUTA_KDF_PBKDF2       = 34,
	VOLUTA_KDF_SCRYPT       = 48
};

#define VOLUTA_PAGE_SHIFT       (12)
#define VOLUTA_PAGE_SIZE        (1U << VOLUTA_PAGE_SHIFT)

/* minimal required size for system LEVELx_CACHE_LINESIZE */
#define VOLUTA_CACHELINE_SHIFT  (6)
#define VOLUTA_CACHELINE_SIZE   (1U << VOLUTA_CACHELINE_SHIFT)


/* unix-domain socket for mount daemon */
#define VOLUTA_MNTSOCK_NAME     "voluta-mount"

/* max number of mount-rules */
#define VOLUTA_MNTRULE_MAX      1024



/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define voluta_aligned          __attribute__ ((__aligned__))
#define voluta_aligned8         __attribute__ ((__aligned__(8)))
#define voluta_aligned64        __attribute__ ((__aligned__(64)))
#define voluta_packed           __attribute__ ((__packed__))
#define voluta_packed_aligned   __attribute__ ((__packed__, __aligned__))
#define voluta_packed_aligned4  __attribute__ ((__packed__, __aligned__(4)))
#define voluta_packed_aligned8  __attribute__ ((__packed__, __aligned__(8)))
#define voluta_packed_aligned16 __attribute__ ((__packed__, __aligned__(16)))
#define voluta_packed_aligned32 __attribute__ ((__packed__, __aligned__(32)))
#define voluta_packed_aligned64 __attribute__ ((__packed__, __aligned__(64)))

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_vaddr56 {
	uint32_t lo;
	uint16_t me;
	uint8_t  hi;
} voluta_packed;

struct voluta_vaddr64 {
	uint64_t off_vtype;
} voluta_packed_aligned8;


struct voluta_timespec {
	uint64_t t_sec;
	uint64_t t_nsec;
} voluta_packed_aligned16;


struct voluta_hash128 {
	uint8_t hash[VOLUTA_HASH128_LEN];
} voluta_packed_aligned32;


struct voluta_hash256 {
	uint8_t hash[VOLUTA_HASH256_LEN];
} voluta_packed_aligned32;


struct voluta_hash512 {
	uint8_t hash[VOLUTA_HASH512_LEN];
} voluta_packed_aligned64;


struct voluta_uuid {
	uint8_t uu[VOLUTA_UUID_SIZE];
} voluta_packed_aligned8;


struct voluta_name {
	uint8_t name[VOLUTA_NAME_MAX + 1];
} voluta_packed_aligned8;


struct voluta_key {
	uint8_t key[VOLUTA_KEY_SIZE];
} voluta_packed_aligned32;


struct voluta_iv {
	uint8_t iv[VOLUTA_IV_SIZE];
} voluta_packed_aligned8;


struct voluta_iv_key {
	struct voluta_key key;
	struct voluta_iv  iv;
	uint8_t pad[16];
} voluta_packed_aligned32;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_kdf_desc {
	uint32_t kd_algo;
	uint32_t kd_subalgo;
	uint32_t kd_iterations;
	uint32_t kd_reserved;
} voluta_packed_aligned16;


struct voluta_kdf_pair {
	struct voluta_kdf_desc  kdf_iv;
	struct voluta_kdf_desc  kdf_key;
} voluta_packed_aligned16;


struct voluta_zero_block4 {
	uint64_t                z_marker;
	uint64_t                z_version;
	uint64_t                z_size;
	uint32_t                z_type;
	uint32_t                z_flags;
	struct voluta_kdf_pair  z_kdf_pair;
	uint8_t                 z_sw_version[64];
	struct voluta_uuid      z_uuid;
	uint8_t                 z_reserved2[872];
	uint8_t                 z_reserved3[3072];
} voluta_packed_aligned64;


struct voluta_meta_block4 {
	struct voluta_name      m_name;
	uint64_t                m_birth_time;
	uint64_t                m_ag_count;
	uint64_t                m_ar_nents;
	uint8_t                 m_reserved[3808];
} voluta_packed_aligned64;


struct voluta_ivks_block4 {
	struct voluta_iv_key    ivk[64];
} voluta_packed_aligned64;


struct voluta_rand_block4 {
	struct voluta_hash512   r_hash;
	uint8_t                 r_fill[4032];
} voluta_packed_aligned64;


struct voluta_super_block {
	struct voluta_zero_block4 s_zero;
	struct voluta_meta_block4 s_meta;
	struct voluta_ivks_block4 s_ivks;
	struct voluta_rand_block4 s_rand[13];
} voluta_packed_aligned64;


struct voluta_header {
	uint32_t                h_magic;
	uint8_t                 h_vtype;
	uint8_t                 h_flags;
	uint16_t                h_reserved;
	uint32_t                h_size;
	uint32_t                h_csum;
} voluta_packed_aligned8;


struct voluta_ag_rec {
	struct voluta_iv        ag_iv;
	uint32_t                ag_used_meta;
	uint32_t                ag_used_data;
	uint32_t                ag_nfiles;
	uint16_t                ag_flags;
	uint8_t                 ag_reserved[16];
} voluta_packed_aligned16;


struct voluta_hspace_map {
	struct voluta_header    hs_hdr;
	uint32_t                hs_index;
	uint32_t                hs_flags;
	uint64_t                hs_nused;
	uint64_t                hs_reserved1;
	uint32_t                hs_nags_span;
	uint32_t                hs_nags_form;
	uint8_t                 hs_reserved2[8144];
	struct voluta_key       hs_keys[256];
	struct voluta_ag_rec    hs_agr[VOLUTA_NAG_IN_HS];
} voluta_packed_aligned64;


struct voluta_bk_rec {
	struct voluta_iv        bk_iv;
	uint64_t                bk_allocated;
	uint64_t                bk_unwritten;
	uint32_t                bk_refcnt;
	uint32_t                bk_flags;
	uint8_t                 bk_vtype;
	uint8_t                 bk_reserved[13];
} voluta_packed_aligned8;


struct voluta_agroup_map {
	struct voluta_header    ag_hdr;
	uint64_t                ag_index;
	struct voluta_vaddr64   ag_it_root;
	uint8_t                 ag_reserved[4064];
	struct voluta_key       ag_keys[128];
	struct voluta_bk_rec    ag_bkr[VOLUTA_NBK_IN_AG];
} voluta_packed_aligned64;


struct voluta_itable_entry {
	uint64_t                ino;
	struct voluta_vaddr64   vaddr;
} voluta_packed_aligned16;


struct voluta_itable_tnode {
	struct voluta_header    it_hdr;
	struct voluta_vaddr64   it_parent;
	uint16_t                it_depth;
	uint16_t                it_nents;
	uint16_t                it_nchilds;
	uint16_t                it_pad;
	uint8_t                 it_reserved1[32];
	struct voluta_itable_entry ite[VOLUTA_ITNODE_NENTS];
	uint8_t                 it_reserved2[48];
	struct voluta_vaddr64   it_child[VOLUTA_ITNODE_NSLOTS];
} voluta_packed_aligned64;


struct voluta_iattr_times {
	struct voluta_timespec  btime;
	struct voluta_timespec  atime;
	struct voluta_timespec  ctime;
	struct voluta_timespec  mtime;
} voluta_packed_aligned64;


struct voluta_xattr_entry {
	uint16_t                xe_name_len;
	uint16_t                xe_value_size;
	uint32_t                xe_reserved;
} voluta_packed_aligned8;


struct voluta_xattr_ispec {
	uint16_t                xa_nents;
	uint8_t                 xa_pad[6];
	struct voluta_vaddr64   xa_vaddr[5];
	int64_t                 xa_reserved[2];
	struct voluta_xattr_entry xe[VOLUTA_XATTR_INENTS];
} voluta_packed_aligned64;


struct voluta_xattr_node {
	struct voluta_header    xa_hdr;
	uint64_t                xa_ino;
	uint16_t                xa_nents;
	uint8_t                 xa_reserved[38];
	struct voluta_xattr_entry xe[VOLUTA_XATTR_NENTS];
} voluta_packed_aligned64;


struct voluta_reg_ispec {
	struct voluta_vaddr64   r_head_leaf[VOLUTA_FILE_HEAD_NLEAVES];
	struct voluta_vaddr64   r_tree_root;
	uint8_t                 r_reserved[376];
} voluta_packed_aligned8;


struct voluta_lnk_ispec {
	uint8_t                 l_head[VOLUTA_SYMLNK_HEAD_MAX];
	struct voluta_vaddr64   l_tail[VOLUTA_SYMLNK_NPARTS];
} voluta_packed_aligned64;


struct voluta_dir_ispec {
	int64_t                 d_root;
	uint64_t                d_ndents;
	uint32_t                d_last_index;
	uint32_t                d_flags;
	uint8_t                 d_reserved[40];
} voluta_packed_aligned64;


union voluta_iattr_specific {
	struct voluta_dir_ispec d;
	struct voluta_reg_ispec r;
	struct voluta_lnk_ispec l;
	uint8_t                 b[512];
} voluta_packed_aligned64;


struct voluta_inode {
	struct voluta_header    i_hdr;
	uint64_t                i_ino;
	uint64_t                i_parent;
	uint32_t                i_uid;
	uint32_t                i_gid;
	uint32_t                i_mode;
	uint32_t                i_flags;
	int64_t                 i_size;
	uint64_t                i_blocks;
	uint64_t                i_nlink;
	uint64_t                i_attributes; /* statx */
	uint32_t                i_rdev_major;
	uint32_t                i_rdev_minor;
	uint64_t                i_revision;
	uint64_t                i_reserved[4];
	struct voluta_iattr_times   i_t;
	struct voluta_xattr_ispec   i_x;
	union voluta_iattr_specific i_s;
} voluta_packed_aligned64;


struct voluta_radix_tnode {
	struct voluta_header    r_hdr;
	uint64_t                r_ino;
	int64_t                 r_beg;
	int64_t                 r_end;
	uint8_t                 r_height;
	uint8_t                 r_reserved1[23];
	uint8_t                 r_zeros[960];
	struct voluta_vaddr56   r_child[VOLUTA_FILE_TREE_NCHILDS];
} voluta_packed_aligned64;


struct voluta_lnk_value {
	struct voluta_header    lv_hdr;
	uint64_t                lv_parent;
	uint16_t                lv_length;
	uint8_t                 lv_reserved1[38];
	uint8_t                 lv_value[VOLUTA_SYMLNK_PART_MAX];
} voluta_packed_aligned64;


struct voluta_dir_entry {
	uint64_t                de_ino;
	uint16_t                de_nents;
	uint16_t                de_nprev;
	uint16_t                de_name_len;
	uint8_t                 de_dt;
	uint8_t                 de_reserved;
} voluta_packed_aligned8;


struct voluta_dir_htnode {
	struct voluta_header    dh_hdr;
	uint64_t                dh_ino;
	int64_t                 dh_parent;
	uint32_t                dh_node_index;
	uint32_t                dh_flags;
	uint64_t                dh_reserved[3];
	struct voluta_dir_entry de[VOLUTA_DIR_HTNODE_NENTS];
	struct voluta_vaddr64   dh_child[VOLUTA_DIR_HTNODE_NCHILDS];
} voluta_packed_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* 4K data block */
struct voluta_data_block4 {
	uint8_t dat[4 * VOLUTA_KB_SIZE];
} voluta_packed_aligned64;


/* 64K data block */
struct voluta_data_block {
	uint8_t dat[VOLUTA_BK_SIZE];
} voluta_packed_aligned64;


/* semantic "view" into 64K block */
union voluta_block_u {
	struct voluta_hspace_map        hsm;
	struct voluta_agroup_map        agm;
	struct voluta_data_block        dbk;
	uint8_t bk[VOLUTA_BK_SIZE];
} voluta_packed_aligned64;


struct voluta_block {
	union voluta_block_u u;
} voluta_packed_aligned64;


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* semantic "view" into meta elements */
union voluta_view_u {
	struct voluta_header            hdr;
	struct voluta_hspace_map        hsm;
	struct voluta_agroup_map        agm;
	struct voluta_inode             inode;
	struct voluta_dir_htnode        htn;
	struct voluta_radix_tnode       rtn;
	struct voluta_xattr_node        xan;
	struct voluta_lnk_value         lnv;
	struct voluta_itable_tnode      itn;
	struct voluta_data_block4       db4;
	struct voluta_data_block        db;
} voluta_packed_aligned64;


struct voluta_view {
	union voluta_view_u u;
} voluta_packed_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct voluta_ar_blob {
	uint8_t b[VOLUTA_AR_BLOB_SIZE];
} voluta_packed_aligned64;


struct voluta_ar_blobref {
	uint32_t                br_magic;
	uint32_t                br_flags;
	uint32_t                br_length;
	uint16_t                br_hfunc;
	uint16_t                br_xbin;
	int64_t                 br_voff;
	uint64_t                br_reserved2;
	struct voluta_hash256   br_hash;
} voluta_packed_aligned64;


struct voluta_ar_blobrefs {
	struct voluta_ar_blobref ar_bref[256];
} voluta_packed_aligned64;


struct voluta_ar_spec {
	struct voluta_zero_block4       ar_zero;
	struct voluta_meta_block4       ar_meta;
	struct voluta_rand_block4       ar_rand[2];
	struct voluta_ar_blobrefs       ar_brefs[1];
} voluta_packed_aligned64;

#endif /* VOLUTA_DEFS_H_ */
