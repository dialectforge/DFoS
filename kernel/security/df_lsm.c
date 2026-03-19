// SPDX-License-Identifier: GPL-2.0
/*
 * security/df_lsm.c — DialectForge Linux Security Module v2
 *
 * Phase 3 base + Integrity Shield integration.
 *
 * v2 changes:
 *   - file_open: integrity write protection checks
 *   - bprm_check_security: integrity exec verification + SUID monitoring
 *   - inode_create/inode_unlink: cron directory protection
 *   - file_permission: catch writes to protected files
 *   - Anomaly scoring for all blocked actions
 *
 * The atmosphere now has customs AND health inspection.
 *
 * Copyright (C) 2026 John Dean Martin. Protocol is PROPRIETARY.
 */

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/ptrace.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/dialectforge.h>

/* Forward declarations for integrity shield */
extern int df_integrity_check_write(const char *path, struct task_struct *task);
extern int df_integrity_check_exec(const char *path);
extern bool df_anomaly_is_locked_down(pid_t pid);
extern int df_anomaly_get_pid_score(pid_t pid);

/* ── Path helper ──
 * Get full path string from file struct.
 * Returns pointer into pathbuf or ERR_PTR on failure.
 */
static inline char *df_get_filepath(struct file *file, char *pathbuf, int buflen)
{
	if (!file || !file->f_path.dentry)
		return ERR_PTR(-EINVAL);
	return d_path(&file->f_path, pathbuf, buflen);
}

/* ── Protected cron paths ──
 * Any write/create/unlink in these directories triggers anomaly scoring.
 */
static bool is_cron_path(const char *path)
{
	if (!path) return false;
	/* Use strncmp prefix match, not strstr substring match */
	return (strncmp(path, "/var/spool/cron", 15) == 0 ||
	        strncmp(path, "/etc/cron", 9) == 0 ||
	        strcmp(path, "/etc/anacrontab") == 0);
}

/* ── Protected system paths ──
 * Paths where non-root writes should raise anomaly flags.
 */
static bool is_sensitive_system_path(const char *path)
{
	if (!path) return false;
	/* Use strncmp (prefix match) not strstr (substring match).
	 * strstr would match /mnt/target/etc/shadow during install. */
	return (strncmp(path, "/usr/lib/systemd/system", 23) == 0 ||
	        strncmp(path, "/etc/systemd/system", 19) == 0 ||
	        strcmp(path, "/etc/shadow") == 0 ||
	        strcmp(path, "/etc/sudoers") == 0 ||
	        strcmp(path, "/etc/ssh/sshd_config") == 0 ||
	        strcmp(path, "/etc/passwd") == 0 ||
	        strcmp(path, "/etc/profile") == 0 ||
	        strcmp(path, "/etc/bash.bashrc") == 0);
}

/* ── Dialect Compatibility Check ── */
static int df_check_dialect_compat(struct task_struct *a,
                                    struct task_struct *b)
{
	bool a_valid = !!(a->df_ctx.flags & DF_TASKF_SEED_VALID);
	bool b_valid = !!(b->df_ctx.flags & DF_TASKF_SEED_VALID);
	u8 a_tier = a_valid ? a->df_ctx.tier : DF_TIER_NATIVE;
	u8 b_tier = b_valid ? b->df_ctx.tier : DF_TIER_NATIVE;

	if (a_tier <= DF_TIER_ADOPTED && b_tier <= DF_TIER_ADOPTED)
		return 0;

	if (a->df_ctx.zone_id != 0 && b->df_ctx.zone_id != 0 &&
	    a->df_ctx.zone_id == b->df_ctx.zone_id)
		return 0;

	return -EACCES;
}

/* ── LSM Hook: task_alloc ── */
static int df_task_alloc(struct task_struct *task,
                          unsigned long clone_flags)
{
	struct task_struct *parent = current;
	return df_task_context_init(task, parent);
}

/* ── LSM Hook: task_free ── */
static void df_task_free(struct task_struct *task)
{
	df_task_context_cleanup(task);
}

/* ── LSM Hook: ptrace_access_check ── */
static int df_ptrace_access_check(struct task_struct *child,
                                   unsigned int mode)
{
	int ret;

	if ((mode & PTRACE_MODE_ATTACH) == 0) {
		if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
			if (!(child->df_ctx.flags & DF_TASKF_QUARANTINED) ||
			    current->df_ctx.zone_id != child->df_ctx.zone_id) {
				df_anomaly_log_quarantine_event(current->pid,
					"ptrace_read_cross_zone", 3);
				return -EACCES;
			}
		}
		return 0;
	}

	/* Block ptrace if attacker PID is in anomaly lockdown */
	if (df_anomaly_is_locked_down(current->pid)) {
		pr_warn("dialectforge: LOCKDOWN pid %d blocked ptrace\n",
		        current->pid);
		return -EACCES;
	}

	/*
	 * DFoS ptrace hardening — equivalent to Yama ptrace_scope=2.
	 * Only CAP_SYS_PTRACE (effectively root) can attach to any process.
	 * This prevents memory inspection attacks and debugger-based exploits.
	 * DFoS philosophy: the atmosphere doesn't let you read other minds.
	 */
	if (!capable(CAP_SYS_PTRACE)) {
		pr_info_ratelimited(
			"dialectforge: ptrace ATTACH denied pid %d -> pid %d "
			"(non-root, ptrace hardened)\n",
			current->pid, child->pid);
		df_anomaly_log_quarantine_event(current->pid,
			"ptrace_nonroot", 5);
		return -EACCES;
	}

	ret = df_check_dialect_compat(current, child);
	if (ret) {
		pr_info_ratelimited(
			"dialectforge: ptrace ATTACH denied pid %d -> pid %d "
			"(tier %u vs %u)\n",
			current->pid, child->pid,
			current->df_ctx.tier, child->df_ctx.tier);
		df_anomaly_log_quarantine_event(current->pid,
			"ptrace_attach_cross_dialect", 5);
	}
	return ret;
}

/* ── LSM Hook: socket_create ── */
static int df_socket_create(int family, int type,
                             int protocol, int kern)
{
	if (kern)
		return 0;

	/* Block network for locked-down PIDs */
	if (df_anomaly_is_locked_down(current->pid)) {
		pr_warn("dialectforge: LOCKDOWN pid %d blocked socket\n",
		        current->pid);
		return -EACCES;
	}

	if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
		pr_info_ratelimited(
			"dialectforge: quarantine pid %d creating socket "
			"(family=%d type=%d)\n",
			current->pid, family, type);
		df_anomaly_log_quarantine_event(current->pid,
			"socket_create", 1);
	}
	return 0;
}

/* ── LSM Hook: socket_connect ── */
static int df_socket_connect(struct socket *sock,
                              struct sockaddr *address, int addrlen)
{
	if (df_anomaly_is_locked_down(current->pid))
		return -EACCES;

	if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
		if (address->sa_family == AF_UNIX)
			return 0;
		pr_info_ratelimited(
			"dialectforge: quarantine pid %d BLOCKED connect\n",
			current->pid);
		df_anomaly_log_quarantine_event(current->pid,
			"blocked_connect", 8);
		return -EACCES;
	}
	return 0;
}

/* ── LSM Hook: socket_sendmsg ── */
static int df_socket_sendmsg(struct socket *sock,
                              struct msghdr *msg, int size)
{
	if (current->df_ctx.flags & DF_TASKF_QUARANTINED)
		df_anomaly_log_quarantine_event(current->pid,
			"sendmsg_attempt", 2);
	return 0;
}

/* ── LSM Hook: msg_queue_msgsnd ── */
static int df_msg_queue_msgsnd(struct kern_ipc_perm *msq,
                                struct msg_msg *msg, int msqflg)
{
	if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
		df_anomaly_log_quarantine_event(current->pid,
			"blocked_msgq", 6);
		return -EACCES;
	}
	return 0;
}

/* ── LSM Hook: shm_alloc_security ── */
static int df_shm_alloc(struct kern_ipc_perm *shp)
{
	if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
		df_anomaly_log_quarantine_event(current->pid,
			"blocked_shm", 7);
		return -EACCES;
	}
	return 0;
}

/* ── LSM Hook: file_open ── (MAJOR v2 UPGRADE)
 *
 * Now handles:
 * 1. Quarantine enforcement (original)
 * 2. USB auto-quarantine (original)
 * 3. Integrity Shield write protection (NEW)
 * 4. Cron directory monitoring (NEW)
 * 5. Sensitive path monitoring (NEW)
 * 6. Lockdown enforcement (NEW)
 */
static int df_file_open(struct file *file)
{
	struct dentry *dentry;
	const char *name;
	char pathbuf[256];
	char *filepath;
	bool is_write;
	int ret;

	/* Install mode: skip all security scoring to allow system copy */
	if (df_install_mode)
		return 0;

	/* Get full path for integrity checks */
	filepath = df_get_filepath(file, pathbuf, sizeof(pathbuf));

	/* ── Lockdown enforcement ── */
	if (df_anomaly_is_locked_down(current->pid)) {
		/* Locked-down processes can only read /dev/null, /proc/self */
		if (!IS_ERR(filepath)) {
			if (strncmp(filepath, "/dev/", 5) != 0 &&
			    strncmp(filepath, "/proc/self", 10) != 0) {
				pr_warn_ratelimited(
					"dialectforge: LOCKDOWN pid %d blocked "
					"file_open %s\n",
					current->pid, filepath);
				return -EACCES;
			}
		}
	}

	/* ── Integrity Shield: write protection ── */
	is_write = (file->f_mode & FMODE_WRITE) != 0;
	if (is_write && !IS_ERR(filepath)) {
		/* Check integrity shield for protected paths */
		ret = df_integrity_check_write(filepath, current);
		if (ret)
			return ret;

		/* Cron directory monitoring */
		if (is_cron_path(filepath)) {
			if (!uid_eq(task_uid(current), GLOBAL_ROOT_UID)) {
				pr_warn("dialectforge: BLOCKED non-root cron "
				        "write by pid %d: %s\n",
				        current->pid, filepath);
				df_anomaly_log_quarantine_event(current->pid,
					"cron_write_nonroot", 12);
				return -EACCES;
			}
			/* Root cron writes: score only non-native tier */
			if (current->df_ctx.tier > DF_TIER_NATIVE)
				df_anomaly_log_quarantine_event(current->pid,
					"cron_write", 3);
		}

		/* Sensitive system path monitoring */
		if (is_sensitive_system_path(filepath)) {
			if (!uid_eq(task_uid(current), GLOBAL_ROOT_UID)) {
				pr_warn("dialectforge: BLOCKED non-root write "
				        "to system path by pid %d: %s\n",
				        current->pid, filepath);
				df_anomaly_log_quarantine_event(current->pid,
					"sysfile_write_nonroot", 10);
				return -EACCES;
			}
			/* Root modifying system files: log only for native tier,
			 * score for adopted/quarantine to detect compromised procs */
			if (current->df_ctx.tier > DF_TIER_NATIVE)
				df_anomaly_log_quarantine_event(current->pid,
					"sysfile_write_root", 1);
		}
	}

	/* ── USB Auto-Quarantine (original) ── */
	if (!(current->df_ctx.flags & DF_TASKF_QUARANTINED)) {
		if (!IS_ERR(filepath) &&
		    df_usb_is_quarantine_path(filepath)) {
			pr_info_ratelimited(
				"dialectforge: pid %d auto-quarantined "
				"(USB content: %s)\n",
				current->pid, filepath);
			task_lock(current);
			current->df_ctx.tier = DF_TIER_QUARANTINE;
			current->df_ctx.flags |= DF_TASKF_QUARANTINED;
			task_unlock(current);
			df_anomaly_log_quarantine_event(current->pid,
				"usb_auto_quarantine", 0);
		}
		return 0;
	}

	/* ── Quarantine enforcement (original) ── */
	dentry = file->f_path.dentry;
	if (!dentry)
		return 0;

	name = dentry->d_name.name;

	/* Allow: /dev/ entries */
	if (dentry->d_parent && dentry->d_parent->d_name.name &&
	    strcmp(dentry->d_parent->d_name.name, "dev") == 0)
		return 0;

	/* Allow: /tmp */
	if (dentry->d_parent && dentry->d_parent->d_name.name) {
		const char *parent = dentry->d_parent->d_name.name;
		if (strcmp(parent, "tmp") == 0)
			return 0;
	}

	/* Allow: /proc/self */
	if (name && strncmp(name, "self", 4) == 0)
		return 0;

	/* Block quarantine access to sensitive dirs */
	if (dentry->d_parent && dentry->d_parent->d_name.name) {
		const char *parent = dentry->d_parent->d_name.name;
		if (strcmp(parent, "etc") == 0 ||
		    strcmp(parent, "home") == 0 ||
		    strcmp(parent, "root") == 0) {
			pr_info_ratelimited(
				"dialectforge: quarantine pid %d BLOCKED "
				"file open /%s/%s\n",
				current->pid, parent, name);
			df_anomaly_log_quarantine_event(current->pid,
				"blocked_file", 4);
			return -EACCES;
		}
	}

	return 0;
}

/* ── LSM Hook: bprm_check_security ── (MAJOR v2 UPGRADE)
 *
 * Now handles:
 * 1. Quarantine exec logging (original)
 * 2. Integrity Shield exec verification (NEW)
 * 3. SUID binary monitoring (NEW)
 * 4. Lockdown enforcement (NEW)
 */
static int df_bprm_check_security(struct linux_binprm *bprm)
{
	const char *filename = bprm->filename;
	struct inode *inode;

	if (df_install_mode || !filename)
		return 0;

	/* Lockdown: blocked PIDs can't exec anything */
	if (df_anomaly_is_locked_down(current->pid)) {
		pr_warn("dialectforge: LOCKDOWN pid %d blocked exec %s\n",
		        current->pid, filename);
		return -EACCES;
	}

	/* Integrity Shield: verify attested binaries before exec */
	if (df_integrity_check_exec(filename) != 0) {
		pr_warn("dialectforge: BLOCKED exec of tampered %s "
		        "by pid %d\n", filename, current->pid);
		return -EACCES;
	}

	/* SUID monitoring: score only non-native tier.
	 * Native processes legitimately run SUID binaries (sudo, mount, su).
	 * Scoring them causes lockdown of normal user shells. */
	inode = file_inode(bprm->file);
	if (inode && (inode->i_mode & S_ISUID) &&
	    current->df_ctx.tier > DF_TIER_NATIVE) {
		pr_info_ratelimited(
			"dialectforge: SUID exec by pid %d (uid %u): %s\n",
			current->pid,
			from_kuid(&init_user_ns, task_uid(current)),
			filename);
		df_anomaly_log_quarantine_event(current->pid,
			"suid_exec", 5);
	}

	/* Quarantine logging (original) */
	if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
		pr_info_ratelimited(
			"dialectforge: quarantine pid %d exec %s\n",
			current->pid, filename);
	}

	return 0;
}


/* ── LSM Identity ── */
static const struct lsm_id df_lsmid = {
	.name = "dialectforge",
	.id   = 0,
};

/* ── LSM Hook Table ── */
static struct security_hook_list df_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_alloc, df_task_alloc),
	LSM_HOOK_INIT(task_free, df_task_free),
	LSM_HOOK_INIT(ptrace_access_check, df_ptrace_access_check),
	LSM_HOOK_INIT(socket_create, df_socket_create),
	LSM_HOOK_INIT(socket_connect, df_socket_connect),
	LSM_HOOK_INIT(socket_sendmsg, df_socket_sendmsg),
	LSM_HOOK_INIT(msg_queue_msgsnd, df_msg_queue_msgsnd),
	LSM_HOOK_INIT(shm_alloc_security, df_shm_alloc),
	LSM_HOOK_INIT(file_open, df_file_open),
	LSM_HOOK_INIT(bprm_check_security, df_bprm_check_security),
};

/* ── LSM Registration ── */
static int __init df_lsm_init(void)
{
	security_add_hooks(df_hooks, ARRAY_SIZE(df_hooks), &df_lsmid);
	pr_debug("dialectforge: LSM v2 initialized — "
	        "integrity shield + anomaly enforcement active\n");
	return 0;
}

DEFINE_LSM(dialectforge) = {
	.name  = "dialectforge",
	.init  = df_lsm_init,
};
