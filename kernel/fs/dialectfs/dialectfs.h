/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DialectForge OS — dialectfs internal header
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */
#ifndef _DIALECTFS_H
#define _DIALECTFS_H

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/types.h>
#include <linux/dialectforge.h>

/* Superblock private data */
struct dfs_sb_info {
	char lower_path[PATH_MAX];      /* Backing store root path */
	struct df_seed volume_seed;     /* Volume-level seed derived from system root */
};

/* Inode private data — every inode gets its own seed */
struct dfs_inode_info {
	struct inode vfs_inode;         /* Must be first for container_of */
	struct df_seed file_seed;       /* Per-file/dir seed */
};

/* Accessors */
static inline struct dfs_sb_info *DFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct dfs_inode_info *DFS_INODE(struct inode *inode)
{
	return container_of(inode, struct dfs_inode_info, vfs_inode);
}

/* Operations tables */
extern const struct inode_operations dfs_inode_ops;
extern const struct file_operations dfs_file_ops;
int dfs_file_release(struct inode *inode, struct file *file);
extern const struct file_operations dfs_dir_ops;
extern const struct super_operations dfs_super_ops;

/* Seed derivation (implemented in super.c) */
void dfs_derive_file_seed(struct df_seed *parent, struct df_seed *out,
			  const char *name, int namelen);

/* Crypto operations (implemented in df_crypto.c) */
void dfs_encrypt_page(void *data, size_t len, struct df_seed *seed,
		      u64 page_index);
void dfs_decrypt_page(void *data, size_t len, struct df_seed *seed,
		      u64 page_index);

/* Sector hopping (implemented in df_crypto.c) */
void dfs_sector_hop_permute(u64 *map, int count, struct df_seed *seed);

/* Crypto engine init/cleanup (implemented in df_crypto.c) */
int dfs_crypto_init(void);
void dfs_crypto_cleanup(void);

#endif /* _DIALECTFS_H */
