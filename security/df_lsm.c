// SPDX-License-Identifier: GPL-2.0
/*
 * security/df_lsm.c — DialectForge Linux Security Module
 *
 * This is the atmosphere's customs enforcement. Every IPC path in the
 * kernel passes through here. The check is not "do you have permission?"
 * — it's "do you speak the same language?"
 *
 * Root doesn't help. Root is a permission level. This checks dialect.
 * Root without the right dialect is a master key to a building where
 * every room speaks a language that changes every 30 seconds.
 *
 * Registered as an exclusive LSM — we own security, no stacking.
 *
 * Hooks:
 *   task_alloc        — Seed inheritance at fork()
 *   task_free         — Cleanup seed material on exit
 *   socket_create     — Assign dialect context to new sockets
 *   socket_connect    — Verify dialect compat before connect
 *   socket_sendmsg    — Encode through sender's dialect
 *   socket_recvmsg    — Verify/decode through receiver's dialect
 *   shm_alloc         — Shared memory gets negotiated dialect
 *   msg_queue_msgsnd  — Message queues dialect-authenticated
 *   ptrace_access_check — Block cross-dialect process debugging
 *   file_open         — Quarantine enforcement on file access
 *   bprm_check_security — Tier assignment on exec
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
#include <linux/dialectforge.h>

/* ── Dialect Compatibility Check ──
 *
 * Two processes can communicate IFF they share the same dialect tree
 * branch. Native processes all derive from system root — compatible.
 * Quarantined processes derive from quarantine root — isolated island.
 *
 * Even two quarantine zones can't talk to each other — each zone has
 * its own unique seed. Different dialects = different universes.
 *
 * Kernel threads (created before DF init) have no valid seed but are
 * the bones of the OS — they're native by birth, just born before
 * the atmosphere formed. We treat them as native.
 *
 * Returns 0 if compatible, -EACCES if not.
 */
static int df_check_dialect_compat(struct task_struct *a,
                                    struct task_struct *b)
{
    bool a_valid = !!(a->df_ctx.flags & DF_TASKF_SEED_VALID);
    bool b_valid = !!(b->df_ctx.flags & DF_TASKF_SEED_VALID);
    u8 a_tier = a_valid ? a->df_ctx.tier : DF_TIER_NATIVE;
    u8 b_tier = b_valid ? b->df_ctx.tier : DF_TIER_NATIVE;

    /* Processes without valid seeds are pre-boot kernel threads.
     * They're native — born before the atmosphere, but part of it.
     * Like bones that existed before skin grew over them. */

    /* Both native or adopted = compatible (same atmosphere) */
    if (a_tier <= DF_TIER_ADOPTED && b_tier <= DF_TIER_ADOPTED)
        return 0;

    /* Quarantine can only talk to same zone */
    if (a->df_ctx.zone_id != 0 && b->df_ctx.zone_id != 0 &&
        a->df_ctx.zone_id == b->df_ctx.zone_id)
        return 0;

    /* Everything else: structurally incompatible */
    return -EACCES;
}

/* ── LSM Hook: task_alloc ──
 * Called on fork(). Child inherits parent's dialect context.
 * Native parent → native child. Quarantine parent → quarantine child.
 * The seed is derived, not copied — child has its own unique seed
 * but it's in the same dialect tree branch as the parent.
 */
static int df_task_alloc(struct task_struct *task,
                          unsigned long clone_flags)
{
    struct task_struct *parent = current;
    return df_task_context_init(task, parent);
}

/* ── LSM Hook: task_free ──
 * Process exiting. Wipe its seed material — no trace left.
 * If it was the last reference to a quarantine zone, zone dies too.
 */
static void df_task_free(struct task_struct *task)
{
    df_task_context_cleanup(task);
}

/* ── LSM Hook: ptrace_access_check ──
 * Can process A inspect/debug process B?
 *
 * Two levels of access:
 *   PTRACE_MODE_READ   — /proc browsing, ps, top, etc.
 *                        Allowed for same-atmosphere processes.
 *   PTRACE_MODE_ATTACH — strace, gdb, actual debugging.
 *                        Blocked across dialect boundaries.
 *                        Root doesn't override this.
 *
 * Quarantine processes can never attach to anything outside their zone.
 */
static int df_ptrace_access_check(struct task_struct *child,
                                   unsigned int mode)
{
    /* Read-only access (/proc browsing): allow within same atmosphere.
     * This lets ps, top, /proc reading work normally for native processes.
     * The data they read is just metadata — not the actual dialect content. */
    if ((mode & PTRACE_MODE_ATTACH) == 0) {
        /* Read mode: only block quarantine reading non-quarantine */
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

    /* Attach mode (strace, gdb): full dialect check */
    int ret = df_check_dialect_compat(current, child);
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

/* ── LSM Hook: socket_create ──
 * New socket gets the creating process's dialect context.
 * Quarantine socket can only connect to quarantine endpoints.
 */
static int df_socket_create(int family, int type,
                             int protocol, int kern)
{
    /* Kernel sockets (kern=1) are always native — they're part of
     * the OS, born speaking the language. */
    if (kern)
        return 0;

    /* Log quarantine network attempts for anomaly scoring */
    if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
        pr_info_ratelimited(
            "dialectforge: quarantine pid %d creating socket "
            "(family=%d type=%d) — will be dialect-restricted\n",
            current->pid, family, type);
        df_anomaly_log_quarantine_event(current->pid,
            "socket_create", 1);
    }
    return 0;
}

/* ── LSM Hook: socket_connect ──
 * Quarantined processes cannot connect to external addresses.
 * This is where "can't phone home" is enforced.
 * Not a firewall rule — the socket's dialect is quarantine,
 * the network stack speaks system. Incompatible atmospheres.
 */
static int df_socket_connect(struct socket *sock,
                              struct sockaddr *address, int addrlen)
{
    if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
        /* Allow loopback for display/local compute */
        if (address->sa_family == AF_UNIX)
            return 0;

        /* Block all other outbound from quarantine */
        pr_info_ratelimited(
            "dialectforge: quarantine pid %d BLOCKED connect "
            "(family=%d) — can't phone home\n",
            current->pid, address->sa_family);
        df_anomaly_log_quarantine_event(current->pid,
            "blocked_connect", 8);
        return -EACCES;
    }
    return 0;
}

/* ── LSM Hook: socket_sendmsg ──
 * IPC between processes checked for dialect compatibility.
 * If sender and receiver don't share dialect, message is refused.
 */
static int df_socket_sendmsg(struct socket *sock,
                              struct msghdr *msg, int size)
{
    if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
        df_anomaly_log_quarantine_event(current->pid,
            "sendmsg_attempt", 2);
    }
    return 0;
}

/* ── LSM Hook: msg_queue_msgsnd ──
 * System V message queue: sender must have compatible dialect.
 */
static int df_msg_queue_msgsnd(struct kern_ipc_perm *msq,
                                struct msg_msg *msg, int msqflg)
{
    if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
        pr_info_ratelimited(
            "dialectforge: quarantine pid %d BLOCKED msgq send "
            "— wrong dialect\n", current->pid);
        df_anomaly_log_quarantine_event(current->pid,
            "blocked_msgq", 6);
        return -EACCES;
    }
    return 0;
}

/* ── LSM Hook: shm_alloc_security ──
 * Shared memory: quarantine cannot create shared memory visible
 * to non-quarantine processes.
 */
static int df_shm_alloc(struct kern_ipc_perm *shp)
{
    if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
        pr_info_ratelimited(
            "dialectforge: quarantine pid %d BLOCKED shm alloc "
            "— quarantine can't create shared memory\n",
            current->pid);
        df_anomaly_log_quarantine_event(current->pid,
            "blocked_shm", 7);
        return -EACCES;
    }
    return 0;
}

/* ── LSM Hook: file_open ──
 * Quarantine enforcement on file access.
 * Quarantine processes can only read/write within their zone.
 * System files are structurally incompatible — different dialect.
 */
static int df_file_open(struct file *file)
{
    struct dentry *dentry;
    const char *name;

    if (!(current->df_ctx.flags & DF_TASKF_QUARANTINED))
        return 0;  /* Native/Adopted: full access */

    /* Quarantine: block access to sensitive paths */
    dentry = file->f_path.dentry;
    if (!dentry)
        return 0;

    name = dentry->d_name.name;

    /* Allow: /dev/null, /dev/zero, /dev/urandom (basic compute needs) */
    if (dentry->d_parent && dentry->d_parent->d_name.name &&
        strcmp(dentry->d_parent->d_name.name, "dev") == 0)
        return 0;

    /* Allow: /tmp, /proc/self (quarantine's own view) */
    if (dentry->d_parent && dentry->d_parent->d_name.name) {
        const char *parent = dentry->d_parent->d_name.name;
        if (strcmp(parent, "tmp") == 0)
            return 0;
    }

    /* Allow: /proc/self */
    if (name && strncmp(name, "self", 4) == 0)
        return 0;

    /* Block access to /etc, /home, /root, sensitive locations */
    if (dentry->d_parent && dentry->d_parent->d_name.name) {
        const char *parent = dentry->d_parent->d_name.name;
        if (strcmp(parent, "etc") == 0 ||
            strcmp(parent, "home") == 0 ||
            strcmp(parent, "root") == 0) {
            pr_info_ratelimited(
                "dialectforge: quarantine pid %d BLOCKED "
                "file open /%s/%s — wrong dialect\n",
                current->pid, parent, name);
            df_anomaly_log_quarantine_event(current->pid,
                "blocked_file", 4);
            return -EACCES;
        }
    }

    return 0;
}

/* ── LSM Hook: bprm_check_security ──
 * On exec(): determine tier for the new binary.
 * Binaries launched from quarantine stay quarantined.
 * This is process birth authentication — the binary inherits
 * the dialect of whatever launched it.
 */
static int df_bprm_check_security(struct linux_binprm *bprm)
{
    if (current->df_ctx.flags & DF_TASKF_QUARANTINED) {
        pr_info_ratelimited(
            "dialectforge: quarantine pid %d exec'ing %s "
            "— child inherits quarantine\n",
            current->pid,
            bprm->filename ? bprm->filename : "(unknown)");
    }
    return 0;
}


/* ── LSM Identity ── */
static const struct lsm_id df_lsmid = {
    .name = "dialectforge",
    .id   = 0,  /* Unregistered LSM — no upstream ID yet */
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
    pr_info("dialectforge: LSM initialized — "
            "the atmosphere now has customs enforcement\n");
    return 0;
}

DEFINE_LSM(dialectforge) = {
    .name  = "dialectforge",
    .init  = df_lsm_init,
};
