// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS — dialectfs directory operations
 *
 * Handles mkdir, create, unlink, lookup in the backing store.
 * Each directory operation mirrors to the lower filesystem.
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/file.h>
#include "dialectfs.h"

/*
 * Helper: build full path in backing store for a given name
 * within a directory
 */
static char *dfs_build_lower_child_path(struct dentry *parent_dentry,
					const char *name, int namelen,
					char *buf, int buflen)
{
	struct dfs_sb_info *sbi = DFS_SB(parent_dentry->d_sb);
 (void)sbi; /* suppress unused warning — used in later phases */
	char *parent_path;
	int plen, total;

	parent_path = dentry_path_raw(parent_dentry, buf, buflen);
	if (IS_ERR(parent_path))
		return parent_path;

	plen = strlen(sbi->lower_path) + strlen(parent_path);
	total = plen + 1 + namelen + 1; /* lower + parent + / + name + \0 */

	if (total > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	/* Build the full path */
	snprintf(buf, buflen, "%s%s/%.*s",
		 sbi->lower_path,
		 (strcmp(parent_path, "/") == 0) ? "" : parent_path,
		 namelen, name);

	return buf;
}

/*
 * dfs_create() — create a new file
 *
 * When an app does `touch /mnt/secure/test.txt`, we create
 * the file in the backing store too. The inode gets its own
 * per-file seed derived from the parent directory seed.
 */
static int dfs_create(struct mnt_idmap *idmap, struct inode *dir,
		      struct dentry *dentry, umode_t mode, bool excl)
{
	struct inode *inode;
	struct dfs_inode_info *ii;
	struct dfs_inode_info *parent_ii = DFS_INODE(dir);
	struct dfs_sb_info *sbi = DFS_SB(dir->i_sb);
 (void)sbi; /* suppress unused warning — used in later phases */
	char *pathbuf, *lower_path;
	struct file *lower_file;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = get_next_ino();
	inode_init_owner(idmap, inode, dir, mode);
	inode->i_op = &dfs_inode_ops;
	inode->i_fop = &dfs_file_ops;
	inode_set_atime_to_ts(inode, inode_set_ctime_current(inode));
	inode_set_mtime_to_ts(inode, inode_get_atime(inode));

	/* Derive per-file seed from parent directory seed */
	ii = DFS_INODE(inode);
	dfs_derive_file_seed(&parent_ii->file_seed, &ii->file_seed,
			     dentry->d_name.name, dentry->d_name.len);

	/* Create the backing file */
	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf) {
		iput(inode);
		return -ENOMEM;
	}

	lower_path = dfs_build_lower_child_path(dentry->d_parent,
						dentry->d_name.name,
						dentry->d_name.len,
						pathbuf, PATH_MAX);
	if (IS_ERR(lower_path)) {
		kfree(pathbuf);
		iput(inode);
		return PTR_ERR(lower_path);
	}

	/* Create backing file via filp_open with O_CREAT */
	lower_file = filp_open(lower_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
	kfree(pathbuf);

	if (IS_ERR(lower_file)) {
		iput(inode);
		return PTR_ERR(lower_file);
	}
	fput(lower_file);

	d_instantiate(dentry, inode);
	return 0;
}

/*
 * dfs_mkdir() — create a directory in backing store
 */
static int dfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
		     struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct dfs_inode_info *ii;
	struct dfs_inode_info *parent_ii = DFS_INODE(dir);
	char *pathbuf, *lower_path;
	struct path lower_dir_path;
	int err;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = get_next_ino();
	inode_init_owner(idmap, inode, dir, mode | S_IFDIR);
	inode->i_op = &dfs_inode_ops;
	inode->i_fop = &dfs_dir_ops;
	set_nlink(inode, 2);
	inode_set_atime_to_ts(inode, inode_set_ctime_current(inode));
	inode_set_mtime_to_ts(inode, inode_get_atime(inode));

	/* Derive directory seed from parent */
	ii = DFS_INODE(inode);
	dfs_derive_file_seed(&parent_ii->file_seed, &ii->file_seed,
			     dentry->d_name.name, dentry->d_name.len);

	/* Create backing directory via kern_path + vfs_mkdir */
	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf) {
		iput(inode);
		return -ENOMEM;
	}

	lower_path = dfs_build_lower_child_path(dentry->d_parent,
						dentry->d_name.name,
						dentry->d_name.len,
						pathbuf, PATH_MAX);
	if (IS_ERR(lower_path)) {
		kfree(pathbuf);
		iput(inode);
		return PTR_ERR(lower_path);
	}

	/* Use a simple approach: call ksys helpers aren't exported,
	 * so we use init_mkdir via the backing path */
	err = kern_path(lower_path, 0, &lower_dir_path);
	if (err == -ENOENT) {
		/* Doesn't exist yet — good, create it using vfs */
		struct dentry *lower_parent_dentry;
		struct path lower_parent_path;
		char *parent_pathbuf;
		char *lower_parent_str;

		/* Get the parent path in lower fs */
		parent_pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!parent_pathbuf) {
			kfree(pathbuf);
			iput(inode);
			return -ENOMEM;
		}

		/* Build parent lower path */
		lower_parent_str = dfs_build_lower_child_path(
			dentry->d_parent->d_parent,
			dentry->d_parent->d_name.name,
			dentry->d_parent->d_name.len,
			parent_pathbuf, PATH_MAX);
		
		/* For root parent, just use sbi->lower_path */
		if (IS_ERR(lower_parent_str)) {
			struct dfs_sb_info *sbi = DFS_SB(dir->i_sb);
   (void)sbi; /* suppress unused warning — used in later phases */
			err = kern_path(sbi->lower_path, LOOKUP_DIRECTORY,
					&lower_parent_path);
		} else {
			err = kern_path(lower_parent_str, LOOKUP_DIRECTORY,
					&lower_parent_path);
		}
		kfree(parent_pathbuf);

		if (err) {
			kfree(pathbuf);
			iput(inode);
			return err;
		}

		/* Create the directory using vfs_mkdir */
		lower_parent_dentry = lower_parent_path.dentry;
		inode_lock(d_inode(lower_parent_dentry));
		{
			struct dentry *lower_dentry;
			lower_dentry = lookup_one_len(dentry->d_name.name,
						      lower_parent_dentry,
						      dentry->d_name.len);
			if (IS_ERR(lower_dentry)) {
				err = PTR_ERR(lower_dentry);
			} else {
				err = vfs_mkdir(mnt_idmap(lower_parent_path.mnt),
						d_inode(lower_parent_dentry),
						lower_dentry, mode);
				dput(lower_dentry);
			}
		}
		inode_unlock(d_inode(lower_parent_dentry));
		path_put(&lower_parent_path);

		if (err) {
			kfree(pathbuf);
			iput(inode);
			return err;
		}
	} else if (!err) {
		/* Already exists */
		path_put(&lower_dir_path);
	} else {
		kfree(pathbuf);
		iput(inode);
		return err;
	}

	kfree(pathbuf);
	d_instantiate(dentry, inode);
	inc_nlink(dir);
	return 0;
}

/*
 * dfs_lookup() — find a file/dir by name
 *
 * Check if the name exists in the backing store, and if so,
 * create an inode for it with proper seed derivation.
 */
static struct dentry *dfs_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct dfs_inode_info *parent_ii = DFS_INODE(dir);
	struct dfs_sb_info *sbi = DFS_SB(dir->i_sb);
 (void)sbi; /* suppress unused warning — used in later phases */
	char *pathbuf, *lower_path_str;
	struct path lower_path;
	struct inode *inode = NULL;
	int err;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return ERR_PTR(-ENOMEM);

	lower_path_str = dfs_build_lower_child_path(dentry->d_parent,
						    dentry->d_name.name,
						    dentry->d_name.len,
						    pathbuf, PATH_MAX);
	if (IS_ERR(lower_path_str)) {
		kfree(pathbuf);
		return ERR_CAST(lower_path_str);
	}

	err = kern_path(lower_path_str, 0, &lower_path);
	kfree(pathbuf);

	if (err == -ENOENT) {
		/* File doesn't exist in backing store — negative dentry */
		d_add(dentry, NULL);
		return NULL;
	}
	if (err)
		return ERR_PTR(err);

	/* File exists in backing store — create our inode */
	inode = new_inode(dir->i_sb);
	if (!inode) {
		path_put(&lower_path);
		return ERR_PTR(-ENOMEM);
	}

	inode->i_ino = get_next_ino();

	/* Mirror the lower inode's type and permissions */
	if (d_is_dir(lower_path.dentry)) {
		inode->i_mode = S_IFDIR | 0755;
		inode->i_op = &dfs_inode_ops;
		inode->i_fop = &dfs_dir_ops;
		set_nlink(inode, 2);
	} else {
		struct kstat stat;
		inode->i_mode = S_IFREG | 0644;
		inode->i_op = &dfs_inode_ops;
		inode->i_fop = &dfs_file_ops;
		set_nlink(inode, 1);

		/* Get the size from the backing file */
		err = vfs_getattr(&lower_path, &stat,
				  STATX_SIZE, AT_STATX_SYNC_AS_STAT);
		if (!err)
			i_size_write(inode, stat.size);
	}

	inode_set_atime_to_ts(inode, inode_set_ctime_current(inode));
	inode_set_mtime_to_ts(inode, inode_get_atime(inode));

	/* Derive seed from parent */
	{
		struct dfs_inode_info *ii = DFS_INODE(inode);
		dfs_derive_file_seed(&parent_ii->file_seed, &ii->file_seed,
				     dentry->d_name.name, dentry->d_name.len);
	}

	path_put(&lower_path);
	d_add(dentry, inode);
	return NULL;
}

/*
 * dfs_unlink() — delete a file
 */
static int dfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct dfs_sb_info *sbi = DFS_SB(dir->i_sb);
 (void)sbi; /* suppress unused warning — used in later phases */
	char *pathbuf, *lower_path_str;
	struct path lower_parent_path;
	int err;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return -ENOMEM;

	lower_path_str = dfs_build_lower_child_path(dentry->d_parent,
						    dentry->d_name.name,
						    dentry->d_name.len,
						    pathbuf, PATH_MAX);
	if (IS_ERR(lower_path_str)) {
		kfree(pathbuf);
		return PTR_ERR(lower_path_str);
	}

	/* Get parent dir in lower fs and unlink */
	err = kern_path(sbi->lower_path, LOOKUP_DIRECTORY, &lower_parent_path);
	if (!err) {
		/* Walk to the actual parent if nested */
		struct path target_path;
		err = kern_path(lower_path_str, 0, &target_path);
		if (!err) {
			struct dentry *lower_parent = target_path.dentry->d_parent;
			inode_lock(d_inode(lower_parent));
			err = vfs_unlink(mnt_idmap(target_path.mnt),
					 d_inode(lower_parent),
					 target_path.dentry, NULL);
			inode_unlock(d_inode(lower_parent));
			path_put(&target_path);
		}
		path_put(&lower_parent_path);
	}

	kfree(pathbuf);

	if (!err) {
		drop_nlink(d_inode(dentry));
		d_drop(dentry);
	}

	return err;
}

/*
 * dfs_iterate_shared() — list directory contents
 *
 * Reads the backing directory and returns its entries.
 * Files in the backing store have the same names — only
 * their contents are encrypted.
 */
static int dfs_iterate_shared(struct file *file, struct dir_context *ctx)
{
	struct file *lower_file = file->private_data;

	if (!lower_file)
		return -EIO;

	return iterate_dir(lower_file, ctx);
}

const struct inode_operations dfs_inode_ops = {
	.lookup		= dfs_lookup,
	.create		= dfs_create,
	.mkdir		= dfs_mkdir,
	.unlink		= dfs_unlink,
};

const struct file_operations dfs_dir_ops = {
	.open		= generic_file_open,
	.release	= dfs_file_release,
	.iterate_shared	= dfs_iterate_shared,
	.llseek		= generic_file_llseek,
};
