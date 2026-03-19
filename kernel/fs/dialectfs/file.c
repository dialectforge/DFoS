// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS — dialectfs file operations
 * 
 * This is the membrane between applications and the backing store.
 * Every write passes through df_crypto encryption before hitting disk.
 * Every read passes through df_crypto decryption before reaching the app.
 * The backing file only ever contains dialect-encoded noise.
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include <linux/file.h>
#include "dialectfs.h"

/*
 * dfs_lower_path() — construct the backing file path
 *
 * Given a dialectfs dentry, figure out where the corresponding file
 * lives in the backing (lower) filesystem. Like looking up the
 * real address behind a P.O. box.
 */
static char *dfs_lower_path(struct dentry *dentry, char *buf, int buflen)
{
	struct dfs_sb_info *sbi = DFS_SB(dentry->d_sb);
	char *dentry_path;
	int lower_len, dentry_path_len;

	dentry_path = dentry_path_raw(dentry, buf, buflen);
	if (IS_ERR(dentry_path))
		return dentry_path;

	/* Build: <lower_root>/<relative_path> */
	lower_len = strlen(sbi->lower_path);
	dentry_path_len = strlen(dentry_path);

	/* If dentry_path is "/" (root), just return lower_path */
	if (dentry_path_len == 1 && dentry_path[0] == '/') {
		if (lower_len >= buflen)
			return ERR_PTR(-ENAMETOOLONG);
		memcpy(buf, sbi->lower_path, lower_len + 1);
		return buf;
	}

	/* Otherwise concatenate: lower_path + dentry_path */
	if (lower_len + dentry_path_len >= buflen)
		return ERR_PTR(-ENAMETOOLONG);

	/* Shift dentry_path to make room for lower_path prefix */
	memmove(buf + lower_len, dentry_path, dentry_path_len + 1);
	memcpy(buf, sbi->lower_path, lower_len);

	return buf;
}

/*
 * dfs_file_open() — open the backing file
 *
 * When an app opens a file through dialectfs, we open the corresponding
 * file in the backing store. The backing file handle gets stashed in
 * file->private_data so read/write can use it.
 *
 * Think of it as: app opens the P.O. box door, we open the real
 * mailbox behind it.
 */
static int dfs_file_open(struct inode *inode, struct file *file)
{
	char *pathbuf;
	char *lower_path_str;
	struct file *lower_file;
	int flags;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return -ENOMEM;

	lower_path_str = dfs_lower_path(file->f_path.dentry, pathbuf, PATH_MAX);
	if (IS_ERR(lower_path_str)) {
		kfree(pathbuf);
		return PTR_ERR(lower_path_str);
	}

	/*
	 * Open the backing file with matching flags.
	 * O_LARGEFILE is always set in kernel context.
	 * We strip O_APPEND — we manage our own positioning.
	 */
	flags = file->f_flags & ~(O_APPEND | O_DIRECT);
	/* Ensure backing file can be created if needed */
	if (flags & O_CREAT)
		lower_file = filp_open(lower_path_str, flags, 0644);
	else
		lower_file = filp_open(lower_path_str, flags, 0);

	kfree(pathbuf);

	if (IS_ERR(lower_file))
		return PTR_ERR(lower_file);

	file->private_data = lower_file;
	return 0;
}

/*
 * dfs_file_release() — close the backing file
 *
 * App closes the P.O. box, we close the real mailbox.
 */
int dfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file = file->private_data;

	if (lower_file) {
		fput(lower_file);
		file->private_data = NULL;
	}
	return 0;
}

/*
 * dfs_write_iter() — encrypted write to backing store
 *
 * Data flow:
 *   App's plaintext → copy to kernel buffer → df_encrypt_page() →
 *   kernel_write() to backing file → disk sees noise
 *
 * We process in page-sized chunks. Each chunk gets its own
 * encryption pass with the file's per-file seed.
 */
static ssize_t dfs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct file *lower_file = file->private_data;
	struct inode *inode = file_inode(file);
	struct dfs_inode_info *ii = DFS_INODE(inode);
	ssize_t total = 0;
	loff_t pos = iocb->ki_pos;

	if (!lower_file)
		return -EIO;

	while (iov_iter_count(from) > 0) {
		size_t chunk = min_t(size_t, iov_iter_count(from), PAGE_SIZE);
		u8 *plainbuf, *encbuf;
		ssize_t written;

		plainbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		encbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!plainbuf || !encbuf) {
			kfree(plainbuf);
			kfree(encbuf);
			return total ? total : -ENOMEM;
		}

		/* Copy plaintext from userspace */
		if (!copy_from_iter_full(plainbuf, chunk, from)) {
			kfree(plainbuf);
			kfree(encbuf);
			return total ? total : -EFAULT;
		}

		/* Zero-pad remainder of page for consistent encryption */
		if (chunk < PAGE_SIZE)
			memset(plainbuf + chunk, 0, PAGE_SIZE - chunk);

		/* Encrypt: plaintext → noise */
		memcpy(encbuf, plainbuf, PAGE_SIZE);
		dfs_encrypt_page(encbuf, PAGE_SIZE, &ii->file_seed,
				 pos / PAGE_SIZE);

		/* Write encrypted data to backing file */
		written = kernel_write(lower_file, encbuf, chunk, &pos);

		kfree(plainbuf);
		kfree(encbuf);

		if (written < 0)
			return total ? total : written;

		total += written;

		/* Update file size if we extended it */
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
	}

	iocb->ki_pos = pos;

	/* Update timestamps using 6.6+ API */
	inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
	mark_inode_dirty(inode);

	return total;
}

/*
 * dfs_read_iter() — decrypted read from backing store
 *
 * Data flow:
 *   Disk noise → kernel_read() from backing file → df_decrypt_page() →
 *   copy to userspace → App sees plaintext
 */
static ssize_t dfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct file *lower_file = file->private_data;
	struct inode *inode = file_inode(file);
	struct dfs_inode_info *ii = DFS_INODE(inode);
	ssize_t total = 0;
	loff_t pos = iocb->ki_pos;
	loff_t file_size = i_size_read(inode);

	if (!lower_file)
		return -EIO;

	/* Don't read past end of file */
	if (pos >= file_size)
		return 0;

	while (iov_iter_count(to) > 0 && pos < file_size) {
		size_t want = min_t(size_t, iov_iter_count(to), PAGE_SIZE);
		size_t avail = min_t(size_t, want, file_size - pos);
		u8 *encbuf;
		ssize_t nread;

		encbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!encbuf)
			return total ? total : -ENOMEM;

		/* Read encrypted data from backing file */
		nread = kernel_read(lower_file, encbuf, avail, &pos);
		if (nread <= 0) {
			kfree(encbuf);
			return total ? total : (nread ? nread : 0);
		}

		/* Pad to page boundary for decryption if needed */
		if (nread < PAGE_SIZE)
			memset(encbuf + nread, 0, PAGE_SIZE - nread);

		/* Decrypt: noise → plaintext */
		dfs_decrypt_page(encbuf, PAGE_SIZE, &ii->file_seed,
				 (pos - nread) / PAGE_SIZE);

		/* Copy decrypted data to userspace */
		if (copy_to_iter(encbuf, nread, to) != nread) {
			kfree(encbuf);
			return total ? total : -EFAULT;
		}

		kfree(encbuf);
		total += nread;
	}

	iocb->ki_pos = pos;

	/* Update access time */
	inode_set_atime_to_ts(inode, current_time(inode));

	return total;
}

/*
 * dfs_llseek() — standard seek, nothing special needed
 */
static loff_t dfs_llseek(struct file *file, loff_t offset, int whence)
{
	return generic_file_llseek(file, offset, whence);
}

/*
 * dfs_fsync() — sync backing file to disk
 */
static int dfs_fsync(struct file *file, loff_t start, loff_t end,
		     int datasync)
{
	struct file *lower_file = file->private_data;

	if (!lower_file)
		return -EIO;

	return vfs_fsync_range(lower_file, start, end, datasync);
}

const struct file_operations dfs_file_ops = {
	.open		= dfs_file_open,
	.release	= dfs_file_release,
	.read_iter	= dfs_read_iter,
	.write_iter	= dfs_write_iter,
	.llseek		= dfs_llseek,
	.fsync		= dfs_fsync,
};
