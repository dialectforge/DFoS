// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS — dialectfs inode operations
 *
 * Inode-level operations that aren't in dir.c or file.c.
 * Getattr for stat() to work properly.
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */

#include <linux/fs.h>
#include "dialectfs.h"

/*
 * dfs_getattr() — return file attributes
 *
 * We report the size we track in our inode, not the backing
 * file's size (which might differ due to padding).
 */
static int __maybe_unused dfs_getattr(struct mnt_idmap *idmap, const struct path *path,
		struct kstat *stat, u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);

	generic_fillattr(idmap, request_mask, inode, stat);
	return 0;
}
