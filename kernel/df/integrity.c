// SPDX-License-Identifier: GPL-2.0
/*
 * df/integrity.c — DialectForge Integrity Shield
 * Copyright (c) 2026 John Dean Martin - Patent Pending
 *
 * Three-layer kernel security:
 *   Layer 1: File Attestation — HMAC-SHA256 of protected paths
 *   Layer 2: Anomaly Integration — extended scoring (cron, SUID, etc.)
 *   Layer 3: Service Attestation — runtime binary hash verification
 *
 * Philosophy: Traditional security asks "do you have permission?"
 * DialectForge asks "does the atmosphere recognize you?"
 *
 * A file's attestation hash is derived from the system root seed.
 * If the file changes, the hash won't match. If the seed rotates,
 * all attestations re-derive deterministically. No external DB needed.
 *
 * This isn't IMA/dm-verity. Those check "has this file changed?"
 * We check "does this file belong to this atmosphere?" The seed IS
 * the atmosphere. A file attested on one DFoS instance won't verify
 * on another — the root seeds are different. That's the point.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>   /* crypto_memneq */
#include <linux/dialectforge.h>

/* ================================================================
 * Constants
 * ================================================================ */
#define DF_INTEGRITY_HASH_SIZE   32   /* HMAC-SHA256 output */
#define DF_INTEGRITY_MAX_ENTRIES 2048 /* Max protected paths */
#define DF_INTEGRITY_PATH_MAX   256  /* Max path length stored */
#define DF_INTEGRITY_READ_BUF   4096 /* File read chunk size */

/* Protection levels — what the shield enforces */
#define DF_PROTECT_WRITE    0x01  /* Block writes by non-root */
#define DF_PROTECT_EXEC     0x02  /* Verify hash before exec */
#define DF_PROTECT_IMMUTABLE 0x04 /* Block ALL writes, even root */
#define DF_PROTECT_MONITOR  0x08  /* Log access, don't block */

/* Attestation status */
#define DF_ATTEST_UNKNOWN   0
#define DF_ATTEST_VALID     1
#define DF_ATTEST_TAMPERED  2
#define DF_ATTEST_NEW       3  /* Not yet attested */

/* ================================================================
 * Data Structures
 * ================================================================ */

/*
 * Per-file attestation record.
 * The HMAC is derived from the file content + the system root seed.
 * Same file on different DFoS instances → different HMACs.
 */
struct df_integrity_entry {
	char                path[DF_INTEGRITY_PATH_MAX];
	u8                  hmac[DF_INTEGRITY_HASH_SIZE];
	u32                 protect_flags;   /* DF_PROTECT_* */
	u32                 status;          /* DF_ATTEST_* */
	u64                 attested_ns;     /* When last attested */
	u64                 file_size;       /* Size at attestation time */
	u64                 verify_count;    /* Times verified OK */
	u64                 tamper_count;    /* Times verification failed */
	struct list_head    list;
};

/* ================================================================
 * Module State
 * ================================================================ */
static DEFINE_RWLOCK(integrity_lock);
static LIST_HEAD(integrity_entries);
static int integrity_entry_count;
static bool integrity_initialized;
static bool integrity_enforcing = true;  /* false = audit-only mode */
static struct crypto_shash *integrity_hmac_tfm;

/* Counters for /proc reporting */
static u64 total_verifications;
static u64 total_blocks;
static u64 total_tamper_detections;

/* ================================================================
 * HMAC Computation — file content hashed with root seed as key
 * ================================================================ */

/*
 * Compute HMAC-SHA256 of a file's contents using the system root
 * seed as the key. This ties the attestation to this specific
 * DFoS instance's atmosphere.
 */
static int df_integrity_compute_hmac(const char *path, u8 *hmac_out)
{
	struct file *f;
	SHASH_DESC_ON_STACK(desc, integrity_hmac_tfm);
	struct df_seed *root;
	u8 *buf;
	loff_t pos = 0;
	ssize_t bytes;
	int ret;

	if (!integrity_hmac_tfm)
		return -ENODEV;

	root = df_get_system_root_seed();
	if (!root || !df_seed_is_valid(root))
		return -EKEYREVOKED;

	/* Key the HMAC with the root seed — this is the atmosphere binding */
	desc->tfm = integrity_hmac_tfm;
	ret = crypto_shash_setkey(integrity_hmac_tfm,
	                          root->bytes, DF_SEED_BYTES);
	if (ret)
		return ret;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out_desc;

	/* Also hash the path itself — prevents file-swap attacks */
	ret = crypto_shash_update(desc, (const u8 *)path, strlen(path));
	if (ret)
		goto out_desc;

	/* Open file for kernel reading */
	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	buf = kmalloc(DF_INTEGRITY_READ_BUF, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_file;
	}

	/* Stream the file through HMAC */
	while ((bytes = kernel_read(f, buf, DF_INTEGRITY_READ_BUF, &pos)) > 0) {
		ret = crypto_shash_update(desc, buf, bytes);
		if (ret)
			goto out_buf;
	}
	if (bytes < 0) {
		ret = bytes;
		goto out_buf;
	}

	ret = crypto_shash_final(desc, hmac_out);

out_buf:
	memzero_explicit(buf, DF_INTEGRITY_READ_BUF);
	kfree(buf);
out_file:
	filp_close(f, NULL);
out_desc:
	shash_desc_zero(desc);
	return ret;
}

/* ================================================================
 * Entry Management
 * ================================================================ */

/* Find entry by path — caller must hold integrity_lock (read or write) */
static struct df_integrity_entry *find_entry(const char *path)
{
	struct df_integrity_entry *e;

	list_for_each_entry(e, &integrity_entries, list) {
		if (strncmp(e->path, path, DF_INTEGRITY_PATH_MAX) == 0)
			return e;
	}
	return NULL;
}

/*
 * df_integrity_attest — Compute and store HMAC for a file.
 * Called during system init or via /proc/df_integrity_ctl.
 *
 * This is the "birth certificate" — the file is photographed
 * and the photo signed with the atmosphere's DNA.
 */
int df_integrity_attest(const char *path, u32 protect_flags)
{
	struct df_integrity_entry *entry;
	struct file *f;
	u8 hmac[DF_INTEGRITY_HASH_SIZE];
	int ret;

	if (!integrity_initialized)
		return -ENODEV;
	if (!path || strlen(path) >= DF_INTEGRITY_PATH_MAX)
		return -EINVAL;

	/* Compute HMAC of current file contents */
	ret = df_integrity_compute_hmac(path, hmac);
	if (ret) {
		pr_warn("dialectforge: integrity attest failed for %s: %d\n",
		        path, ret);
		return ret;
	}

	/* Get file size for record */
	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	write_lock(&integrity_lock);

	/* Update existing or create new */
	entry = find_entry(path);
	if (!entry) {
		if (integrity_entry_count >= DF_INTEGRITY_MAX_ENTRIES) {
			write_unlock(&integrity_lock);
			filp_close(f, NULL);
			return -ENOSPC;
		}
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry) {
			write_unlock(&integrity_lock);
			filp_close(f, NULL);
			return -ENOMEM;
		}
		strscpy(entry->path, path, DF_INTEGRITY_PATH_MAX);
		INIT_LIST_HEAD(&entry->list);
		list_add_tail(&entry->list, &integrity_entries);
		integrity_entry_count++;
	}

	memcpy(entry->hmac, hmac, DF_INTEGRITY_HASH_SIZE);
	entry->protect_flags = protect_flags;
	entry->status = DF_ATTEST_VALID;
	entry->attested_ns = ktime_get_ns();
	entry->file_size = i_size_read(file_inode(f));

	write_unlock(&integrity_lock);
	filp_close(f, NULL);

	pr_debug("dialectforge: attested %s [%02x%02x...%02x%02x] flags=0x%x\n",
	        path, hmac[0], hmac[1], hmac[30], hmac[31], protect_flags);

	memzero_explicit(hmac, sizeof(hmac));
	return 0;
}
EXPORT_SYMBOL_GPL(df_integrity_attest);

/*
 * df_integrity_verify — Check a file's current HMAC against stored.
 * Returns: 0 = valid, -EKEYREJECTED = tampered, negative = error
 */
int df_integrity_verify(const char *path)
{
	struct df_integrity_entry *entry;
	u8 current_hmac[DF_INTEGRITY_HASH_SIZE];
	int ret;

	if (!integrity_initialized)
		return -ENODEV;

	read_lock(&integrity_lock);
	entry = find_entry(path);
	if (!entry) {
		read_unlock(&integrity_lock);
		return -ENOENT;  /* Not attested — not our concern */
	}
	read_unlock(&integrity_lock);

	/* Compute current HMAC */
	ret = df_integrity_compute_hmac(path, current_hmac);
	if (ret)
		return ret;

	/* Compare */
	read_lock(&integrity_lock);
	entry = find_entry(path);  /* Re-lookup under lock */
	if (!entry) {
		read_unlock(&integrity_lock);
		memzero_explicit(current_hmac, sizeof(current_hmac));
		return -ENOENT;
	}

	total_verifications++;

	if (crypto_memneq(current_hmac, entry->hmac,
	                  DF_INTEGRITY_HASH_SIZE)) {
		/* TAMPERED */
		entry->status = DF_ATTEST_TAMPERED;
		entry->tamper_count++;
		total_tamper_detections++;
		read_unlock(&integrity_lock);

		pr_warn_ratelimited("dialectforge: INTEGRITY VIOLATION %s "
		        "(expected %02x%02x..., got %02x%02x...)\n",
		        path,
		        entry->hmac[0], entry->hmac[1],
		        current_hmac[0], current_hmac[1]);

		/* Score anomaly against the opener */
		df_anomaly_log_quarantine_event(current->pid,
			"integrity_violation", 15);

		memzero_explicit(current_hmac, sizeof(current_hmac));
		return -EKEYREJECTED;
	}

	entry->verify_count++;
	read_unlock(&integrity_lock);

	memzero_explicit(current_hmac, sizeof(current_hmac));
	return 0;
}
EXPORT_SYMBOL_GPL(df_integrity_verify);

/*
 * df_integrity_check_write — Called from LSM file_open hook.
 * Decides whether a write to a protected path should be blocked.
 *
 * Returns: 0 = allow, -EACCES = block
 */
int df_integrity_check_write(const char *path, struct task_struct *task)
{
	struct df_integrity_entry *entry;
	int ret = 0;

	if (!integrity_initialized)
		return 0;

	read_lock(&integrity_lock);
	entry = find_entry(path);
	if (!entry) {
		read_unlock(&integrity_lock);
		return 0;  /* Not protected */
	}

	if (entry->protect_flags & DF_PROTECT_IMMUTABLE) {
		/* Nobody writes to immutable files, not even root */
		total_blocks++;
		ret = -EACCES;
		pr_warn_ratelimited("dialectforge: BLOCKED write to immutable %s "
		        "by pid %d (uid %u)\n",
		        path, task->pid,
		        from_kuid(&init_user_ns, task_uid(task)));
		df_anomaly_log_quarantine_event(task->pid,
			"write_immutable", 20);
	} else if (entry->protect_flags & DF_PROTECT_WRITE) {
		/* Only root can write to write-protected files */
		if (!uid_eq(task_uid(task), GLOBAL_ROOT_UID)) {
			total_blocks++;
			ret = -EACCES;
			pr_info_ratelimited(
				"dialectforge: BLOCKED non-root write to %s "
				"by pid %d (uid %u)\n",
				path, task->pid,
				from_kuid(&init_user_ns, task_uid(task)));
			df_anomaly_log_quarantine_event(task->pid,
				"write_protected", 10);
		}
	}

	if (entry->protect_flags & DF_PROTECT_MONITOR) {
		pr_info_ratelimited(
			"dialectforge: MONITOR write access to %s "
			"by pid %d (uid %u)\n",
			path, task->pid,
			from_kuid(&init_user_ns, task_uid(task)));
	}

	read_unlock(&integrity_lock);

	if (!integrity_enforcing && ret == -EACCES) {
		pr_info("dialectforge: (audit mode — would block %s)\n", path);
		ret = 0;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(df_integrity_check_write);

/*
 * df_integrity_check_exec — Called before exec of an attested binary.
 * Verifies HMAC matches. If tampered, block execution.
 *
 * Returns: 0 = allow, -EACCES = block
 */
int df_integrity_check_exec(const char *path)
{
	struct df_integrity_entry *entry;
	int ret;

	if (!integrity_initialized)
		return 0;

	read_lock(&integrity_lock);
	entry = find_entry(path);
	if (!entry || !(entry->protect_flags & DF_PROTECT_EXEC)) {
		read_unlock(&integrity_lock);
		return 0;  /* Not attested for exec or not protected */
	}
	read_unlock(&integrity_lock);

	/* Full verification — re-hash the file and compare */
	ret = df_integrity_verify(path);
	if (ret == -EKEYREJECTED) {
		pr_warn_ratelimited("dialectforge: BLOCKED exec of tampered binary %s\n",
		        path);
		df_anomaly_log_quarantine_event(current->pid,
			"exec_tampered", 25);
		if (integrity_enforcing)
			return -EACCES;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(df_integrity_check_exec);

/* ================================================================
 * Default Protected Paths — attested at boot
 *
 * These are the paths that CAI's pentest found vulnerable:
 *   - systemd service units (writable by non-root)
 *   - cron spool entries (cron persistence)
 *   - /etc/shadow, /etc/passwd, /etc/sudoers
 *   - SUID binaries
 * ================================================================ */

static const struct {
	const char *path;
	u32 flags;
} df_default_protected[] = {
	/* Systemd service files — IMMUTABLE (Problem #94) */
	{ "/usr/lib/systemd/system/ssh.service",     DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },
	{ "/usr/lib/systemd/system/cron.service",    DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },
	{ "/usr/lib/systemd/system/networking.service", DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },
	{ "/usr/lib/systemd/system/rsyslog.service", DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },
	{ "/usr/lib/systemd/system/dbus.service",    DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },
	{ "/usr/lib/systemd/system/systemd-logind.service", DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },
	{ "/usr/lib/systemd/system/systemd-journald.service", DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },
	{ "/usr/lib/systemd/system/systemd-udevd.service", DF_PROTECT_IMMUTABLE | DF_PROTECT_EXEC },

	/* Critical system configs (Problem #98 and general hardening) */
	{ "/etc/shadow",            DF_PROTECT_IMMUTABLE },
	{ "/etc/passwd",            DF_PROTECT_WRITE | DF_PROTECT_MONITOR },
	{ "/etc/sudoers",           DF_PROTECT_IMMUTABLE },
	{ "/etc/ssh/sshd_config",   DF_PROTECT_IMMUTABLE },
	{ "/etc/cron.allow",        DF_PROTECT_IMMUTABLE },
	{ "/etc/cron.deny",         DF_PROTECT_IMMUTABLE },

	/* Cron directories — IMMUTABLE (Problem #95) */
	{ "/etc/crontab",           DF_PROTECT_IMMUTABLE },

	/* Shell configs — MONITOR (Problem #98) */
	{ "/etc/profile",           DF_PROTECT_WRITE | DF_PROTECT_MONITOR },
	{ "/etc/bash.bashrc",       DF_PROTECT_WRITE | DF_PROTECT_MONITOR },

	{ NULL, 0 }
};

/*
 * Attest all default paths at boot.
 * Runs during df_init() after root seed is generated.
 * Files that don't exist yet are skipped — they'll be attested
 * when first created (if the admin adds them).
 */
static int df_integrity_attest_defaults(void)
{
	int i, ok = 0, skip = 0;

	for (i = 0; df_default_protected[i].path; i++) {
		int ret = df_integrity_attest(df_default_protected[i].path,
		                              df_default_protected[i].flags);
		if (ret == -ENOENT || ret == -EACCES) {
			skip++;
			continue;  /* File doesn't exist in this image */
		}
		if (ret) {
			pr_warn("dialectforge: failed to attest %s: %d\n",
			        df_default_protected[i].path, ret);
			continue;
		}
		ok++;
	}

	pr_debug("dialectforge: integrity shield attested %d files "
	        "(%d skipped)\n", ok, skip);
	return 0;
}

/* ================================================================
 * /proc Interface
 * ================================================================ */

/* /proc/df_integrity — read-only status (root only) */
static int df_integrity_proc_show(struct seq_file *m, void *v)
{
	struct df_integrity_entry *e;

	seq_puts(m, "=== DialectForge Integrity Shield ===\n");
	seq_printf(m, "Mode:          %s\n",
	           integrity_enforcing ? "ENFORCING" : "AUDIT");
	seq_printf(m, "Entries:       %d / %d\n",
	           integrity_entry_count, DF_INTEGRITY_MAX_ENTRIES);
	seq_printf(m, "Verifications: %llu\n", total_verifications);
	seq_printf(m, "Blocks:        %llu\n", total_blocks);
	seq_printf(m, "Tamper detect: %llu\n\n", total_tamper_detections);

	read_lock(&integrity_lock);
	list_for_each_entry(e, &integrity_entries, list) {
		const char *status_str;
		switch (e->status) {
		case DF_ATTEST_VALID:    status_str = "VALID";    break;
		case DF_ATTEST_TAMPERED: status_str = "TAMPERED"; break;
		case DF_ATTEST_NEW:      status_str = "NEW";      break;
		default:                 status_str = "UNKNOWN";  break;
		}
		seq_printf(m, "%-50s %s  flags=0x%02x  "
		           "verify=%llu tamper=%llu  "
		           "hmac=%02x%02x..%02x%02x\n",
		           e->path, status_str, e->protect_flags,
		           e->verify_count, e->tamper_count,
		           e->hmac[0], e->hmac[1],
		           e->hmac[30], e->hmac[31]);
	}
	read_unlock(&integrity_lock);

	return 0;
}

static int df_integrity_proc_open(struct inode *i, struct file *f)
{
	return single_open(f, df_integrity_proc_show, NULL);
}

static const struct proc_ops df_integrity_proc_ops = {
	.proc_open    = df_integrity_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/*
 * /proc/df_integrity_ctl — write interface for admin operations.
 * Commands:
 *   "attest <path> <flags>"  — Add or re-attest a file
 *   "verify <path>"          — Verify a file's integrity
 *   "enforce"                — Switch to enforcing mode
 *   "audit"                  — Switch to audit-only mode
 *   "verify_all"             — Re-verify all attested files
 *   "attest_defaults"        — Attest all default protected paths
 */
static ssize_t df_integrity_ctl_write(struct file *file,
                                      const char __user *buf,
                                      size_t count, loff_t *ppos)
{
	char *kbuf, *cmd, *arg;
	int ret = 0;

	/* DFoS: Require CAP_SYS_ADMIN for integrity control */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (count > 512)
		return -EINVAL;

	/* Only root can issue commands */
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;

	kbuf = kzalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return -EFAULT;
	}
	kbuf[count] = '\0';

	/* Strip trailing newline */
	if (count > 0 && kbuf[count - 1] == '\n')
		kbuf[count - 1] = '\0';

	cmd = kbuf;
	arg = strchr(kbuf, ' ');
	if (arg) {
		*arg = '\0';
		arg++;
	}

	if (strcmp(cmd, "attest") == 0 && arg) {
		/* "attest /path/to/file 0x05" */
		char *flags_str = strchr(arg, ' ');
		u32 flags = DF_PROTECT_WRITE | DF_PROTECT_EXEC;
		if (flags_str) {
			*flags_str = '\0';
			flags_str++;
			if (kstrtou32(flags_str, 0, &flags))
				flags = DF_PROTECT_WRITE | DF_PROTECT_EXEC;
		}
		ret = df_integrity_attest(arg, flags);
	} else if (strcmp(cmd, "verify") == 0 && arg) {
		ret = df_integrity_verify(arg);
		if (ret == 0)
			pr_debug("dialectforge: %s VERIFIED OK\n", arg);
	} else if (strcmp(cmd, "enforce") == 0) {
		integrity_enforcing = true;
		pr_debug("dialectforge: integrity shield -> ENFORCING\n");
	} else if (strcmp(cmd, "audit") == 0) {
		integrity_enforcing = false;
		pr_debug("dialectforge: integrity shield -> AUDIT\n");
	} else if (strcmp(cmd, "attest_defaults") == 0) {
		/* Triggered via: echo attest_defaults > /proc/df_integrity_ctl */
		df_integrity_attest_defaults();
		pr_debug("dialectforge: attest_defaults triggered via proc\n");
	} else if (strcmp(cmd, "verify_all") == 0) {
		struct df_integrity_entry *e;
		int good = 0, bad = 0;
		read_lock(&integrity_lock);
		list_for_each_entry(e, &integrity_entries, list) {
			int v = df_integrity_verify(e->path);
			if (v == 0)
				good++;
			else
				bad++;
		}
		read_unlock(&integrity_lock);
		pr_debug("dialectforge: verify_all — %d OK, %d FAILED\n",
		        good, bad);
	} else {
		ret = -EINVAL;
	}

	kfree(kbuf);
	return ret ? ret : count;
}

static const struct proc_ops df_integrity_ctl_ops = {
	.proc_write = df_integrity_ctl_write,
};

/* ================================================================
 * Init / Cleanup
 * ================================================================ */

int df_integrity_init(void)
{
	/* Allocate HMAC-SHA256 transform */
	integrity_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(integrity_hmac_tfm)) {
		pr_err("dialectforge: integrity HMAC alloc failed (%ld)\n",
		       PTR_ERR(integrity_hmac_tfm));
		integrity_hmac_tfm = NULL;
		return -ENOMEM;
	}

	/* Create /proc entries (root-only) */
	proc_create("df_integrity", 0400, NULL,
	            &df_integrity_proc_ops);
	proc_create("df_integrity_ctl", 0200, NULL,
	            &df_integrity_ctl_ops);

	integrity_initialized = true;

	/* Default attestation deferred to userspace (root FS not yet mounted) */
	/* Triggered via: echo attest_defaults > /proc/df_integrity_ctl */

	pr_debug("dialectforge: ========================================\n");
	pr_debug("dialectforge:   Integrity Shield ACTIVE\n");
	pr_debug("dialectforge:   Mode: %s\n",
	        integrity_enforcing ? "ENFORCING" : "AUDIT");
	pr_debug("dialectforge:   Protected: %d files\n",
	        integrity_entry_count);
	pr_debug("dialectforge: ========================================\n");

	return 0;
}
EXPORT_SYMBOL_GPL(df_integrity_init);

void df_integrity_cleanup(void)
{
	struct df_integrity_entry *e, *tmp;

	integrity_initialized = false;

	write_lock(&integrity_lock);
	list_for_each_entry_safe(e, tmp, &integrity_entries, list) {
		list_del(&e->list);
		memzero_explicit(e->hmac, DF_INTEGRITY_HASH_SIZE);
		kfree(e);
	}
	integrity_entry_count = 0;
	write_unlock(&integrity_lock);

	remove_proc_entry("df_integrity", NULL);
	remove_proc_entry("df_integrity_ctl", NULL);

	if (integrity_hmac_tfm) {
		crypto_free_shash(integrity_hmac_tfm);
		integrity_hmac_tfm = NULL;
	}
}
EXPORT_SYMBOL_GPL(df_integrity_cleanup);
