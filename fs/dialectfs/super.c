// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS — dialectfs superblock operations
 *
 * Mount/unmount, volume seed derivation from system root seed,
 * inode allocation with per-file seed context.
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/statfs.h>
#include <linux/namei.h>
#include "dialectfs.h"

static struct kmem_cache *dfs_inode_cache;

/* Mount option tokens */
enum {
	Opt_lower,
	Opt_err,
};

static const match_table_t tokens = {
	{ Opt_lower, "lower=%s" },
	{ Opt_err, NULL },
};

/*
 * Inode slab allocator — gives us the dfs_inode_info wrapper
 * around every VFS inode. This is how each file gets its own seed.
 */
static struct inode *dfs_alloc_inode(struct super_block *sb)
{
	struct dfs_inode_info *ii;

	ii = alloc_inode_sb(sb, dfs_inode_cache, GFP_KERNEL);
	if (!ii)
		return NULL;

	memset(&ii->file_seed, 0, sizeof(ii->file_seed));
	return &ii->vfs_inode;
}

static void dfs_free_inode(struct inode *inode)
{
	kmem_cache_free(dfs_inode_cache, DFS_INODE(inode));
}

static void dfs_put_super(struct super_block *sb)
{
	struct dfs_sb_info *sbi = DFS_SB(sb);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

static int dfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct dfs_sb_info *sbi = DFS_SB(dentry->d_sb);
	struct path lower_path;
	int err;

	err = kern_path(sbi->lower_path, LOOKUP_FOLLOW, &lower_path);
	if (err)
		return err;

	err = vfs_statfs(&lower_path, buf);
	path_put(&lower_path);

	/* Report ourselves as dialectfs */
	buf->f_type = 0xDF5EC;  /* "DFsec" magic */
	return err;
}

const struct super_operations dfs_super_ops = {
	.alloc_inode	= dfs_alloc_inode,
	.free_inode	= dfs_free_inode,
	.put_super	= dfs_put_super,
	.statfs		= dfs_statfs,
};

/*
 * dfs_derive_file_seed() — hierarchical seed derivation
 *
 * Parent seed + filename → child seed via HKDF-SHA256.
 * Like a family tree where DNA is cryptographic.
 */
void dfs_derive_file_seed(struct df_seed *parent, struct df_seed *out,
			  const char *name, int namelen)
{
	/* Use the kernel DF seed derivation */
	df_seed_derive_labeled(parent, name, namelen, out);
}

/*
 * dfs_fill_super() — set up the superblock on mount
 *
 * Parse mount options, derive volume seed, create root inode.
 */
static int dfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct dfs_sb_info *sbi;
	struct inode *root_inode;
	struct dfs_inode_info *root_ii;
	substring_t args[MAX_OPT_ARGS];
	char *opts = data;
	char *p;
	int token;
	struct path lower_root;
	int err;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;

	/* Parse mount options */
	if (!opts || !*opts) {
		pr_err("dialectfs: missing mount options (need lower=<path>)\n");
		kfree(sbi);
		return -EINVAL;
	}

	while ((p = strsep(&opts, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_lower:
			strscpy(sbi->lower_path, args[0].from,
				sizeof(sbi->lower_path));
			break;
		default:
			pr_err("dialectfs: unknown option: %s\n", p);
			break;
		}
	}

	if (!sbi->lower_path[0]) {
		pr_err("dialectfs: lower= path not specified\n");
		kfree(sbi);
		return -EINVAL;
	}

	/* Verify the lower path exists and is a directory */
	err = kern_path(sbi->lower_path, LOOKUP_FOLLOW, &lower_root);
	if (err) {
		pr_err("dialectfs: lower path '%s' not found (%d)\n",
		       sbi->lower_path, err);
		kfree(sbi);
		return err;
	}
	path_put(&lower_root);

	/* Set up the superblock */
	sb->s_op = &dfs_super_ops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = 0xDF5EC;

	/* Derive volume seed from system root seed */
	df_seed_derive_labeled(&df_get_system()->root_seed, "dialectfs-volume", 16, &sbi->volume_seed);
	pr_info("dialectfs: volume seed derived from system root\n");

	/* Create root inode */
	root_inode = new_inode(sb);
	if (!root_inode) {
		kfree(sbi);
		return -ENOMEM;
	}

	root_inode->i_ino = 1;
	root_inode->i_mode = S_IFDIR | 0755;
	root_inode->i_op = &dfs_inode_ops;
	root_inode->i_fop = &dfs_dir_ops;
	set_nlink(root_inode, 2);
	inode_set_atime_to_ts(root_inode, inode_set_ctime_current(root_inode));
	inode_set_mtime_to_ts(root_inode, inode_get_atime(root_inode));

	/* Root inode gets the volume seed */
	root_ii = DFS_INODE(root_inode);
	memcpy(&root_ii->file_seed, &sbi->volume_seed, sizeof(struct df_seed));

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		kfree(sbi);
		return -ENOMEM;
	}

	pr_info("dialectfs: mounted with lower=%s\n", sbi->lower_path);
	return 0;
}

static struct dentry *dfs_mount(struct file_system_type *fs_type, int flags,
				const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, dfs_fill_super);
}

static void dfs_kill_sb(struct super_block *sb)
{
	kill_anon_super(sb);
}

static struct file_system_type dfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "dialectfs",
	.mount		= dfs_mount,
	.kill_sb	= dfs_kill_sb,
	.fs_flags	= 0,
};

static void dfs_inode_init_once(void *obj)
{
	struct dfs_inode_info *ii = obj;
	inode_init_once(&ii->vfs_inode);
}

int __init dialectfs_init(void)
{
	int err;

	dfs_inode_cache = kmem_cache_create("dfs_inode_cache",
					    sizeof(struct dfs_inode_info),
					    0,
					    SLAB_RECLAIM_ACCOUNT |
					    SLAB_ACCOUNT,
					    dfs_inode_init_once);
	if (!dfs_inode_cache)
		return -ENOMEM;

	err = register_filesystem(&dfs_fs_type);
	if (err) {
		kmem_cache_destroy(dfs_inode_cache);
		return err;
	}

	err = dfs_crypto_init();
	if (err) {
		dfs_crypto_cleanup();
		unregister_filesystem(&dfs_fs_type);
		kmem_cache_destroy(dfs_inode_cache);
		return err;
	}
	pr_info("dialectfs: native VFS filesystem registered\n");
	return 0;
}

void __exit dialectfs_exit(void)
{
	dfs_crypto_cleanup();
		unregister_filesystem(&dfs_fs_type);
	kmem_cache_destroy(dfs_inode_cache);
}

module_init(dialectfs_init);
module_exit(dialectfs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DialectForge encrypted filesystem");
