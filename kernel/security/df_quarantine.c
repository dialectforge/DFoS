// SPDX-License-Identifier: GPL-2.0
/*
 * security/df_quarantine.c — Tier enforcement helpers for the LSM.
 *
 * Process context init/cleanup, IPC compatibility checks.
 * These are called from the LSM hooks in df_lsm.c.
 *
 * Copyright (C) 2026 John Dean Martin. Protocol is PROPRIETARY.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/dialectforge.h>
#include <linux/sched.h>
#include <linux/ktime.h>

/* Forward decl — from df/seed.c */
extern int df_seed_derive_labeled(const struct df_seed *parent,
                                   const char *label, size_t label_len,
                                   struct df_seed *child);

/*
 * Helper: Build a proper struct df_seed from the raw seed_bytes
 * stored in task_struct's df_ctx. The task_struct only stores the
 * raw 32-byte seed material to save space. But df_seed_derive_labeled
 * needs a full struct df_seed with valid metadata (especially expires=0)
 * or df_seed_is_valid() will read garbage past the 32 bytes and
 * return -EKEYREVOKED.
 *
 * Think of it like this: seed_bytes is the DNA sample in a test tube.
 * struct df_seed is the full medical chart. You can't hand a test tube
 * to a function that expects a chart — it'll read the label wrong.
 */
static void seed_from_task(struct df_seed *out,
                           const struct task_struct *task)
{
	memset(out, 0, sizeof(*out));
	memcpy(out->bytes, task->df_ctx.seed_bytes, DF_SEED_BYTES);
	out->created = ns_to_ktime(task->df_ctx.seed_born_ns);
	out->expires = 0;       /* No expiry — task seeds live with the task */
	out->tier = task->df_ctx.tier;
	out->flags = 0;
	out->revoked = false;
}

static void seed_to_task(struct task_struct *task,
                         const struct df_seed *seed)
{
	memcpy(task->df_ctx.seed_bytes, seed->bytes, DF_SEED_BYTES);
	task->df_ctx.seed_born_ns = ktime_to_ns(seed->created);
}

/*
 * df_task_context_init — Set up DF context for a new process.
 *
 * Called from task_alloc LSM hook (fork path).
 * Child seed is derived from parent seed with "child_PID" label.
 * Child inherits parent's tier — quarantine begets quarantine.
 *
 * CRITICAL: This must NEVER fail the fork. If seed derivation fails,
 * we fall back to copying the parent's seed directly and logging a
 * warning. A process without a unique seed is less ideal but a
 * process that can't be born at all breaks the entire system.
 * The atmosphere must let its citizens breathe.
 */
int df_task_context_init(struct task_struct *task,
                          struct task_struct *parent)
{
    struct df_seed parent_seed, child_seed;
    char label[32];
    int ret;

    memset(&task->df_ctx, 0, sizeof(task->df_ctx));

    if (!parent || !(parent->df_ctx.flags & DF_TASKF_SEED_VALID)) {
        /* Parent has no valid seed — either pre-boot or early init.
         * Derive a native seed from system root so this process
         * is born into the atmosphere, not floating outside it. */
        struct df_seed *sys_root = df_get_system_root_seed();
        if (sys_root) {
            snprintf(label, sizeof(label), "native_%d", task->pid);
            memset(&child_seed, 0, sizeof(child_seed));
            ret = df_seed_derive_labeled(sys_root, label,
                                         strlen(label), &child_seed);
            if (ret == 0) {
                seed_to_task(task, &child_seed);
                task->df_ctx.tier = DF_TIER_NATIVE;
                task->df_ctx.generation = 1;
                task->df_ctx.zone_id = 0;
                task->df_ctx.flags = DF_TASKF_SEED_VALID;
                memzero_explicit(&child_seed, sizeof(child_seed));
                return 0;
            }
        }
        /* Fallback if root seed not ready yet (very early boot) */
        task->df_ctx.tier = DF_TIER_NATIVE;
        task->df_ctx.flags = 0;
        return 0;
    }

    /* Build proper df_seed from parent's raw bytes */
    seed_from_task(&parent_seed, parent);

    /* Derive child seed */
    snprintf(label, sizeof(label), "child_%d", task->pid);
    memset(&child_seed, 0, sizeof(child_seed));
    ret = df_seed_derive_labeled(&parent_seed, label, strlen(label),
                                  &child_seed);
    if (ret) {
        /* FALLBACK: Copy parent's seed context directly.
         * Not ideal (parent and child share seed identity) but
         * vastly better than failing the fork entirely. */
        pr_warn_ratelimited(
            "dialectforge: seed derivation failed for pid %d: %d "
            "— inheriting parent seed (fallback)\n",
            task->pid, ret);
        memcpy(task->df_ctx.seed_bytes, parent->df_ctx.seed_bytes,
               sizeof(task->df_ctx.seed_bytes));
    } else {
        seed_to_task(task, &child_seed);
    }

    task->df_ctx.tier = parent->df_ctx.tier;
    task->df_ctx.generation = parent->df_ctx.generation + 1;
    task->df_ctx.zone_id = parent->df_ctx.zone_id;
    task->df_ctx.seed_born_ns = ktime_get_ns();
    task->df_ctx.flags = parent->df_ctx.flags & (DF_TASKF_SEED_VALID |
                                                   DF_TASKF_QUARANTINED);

    /* Wipe stack secrets */
    memzero_explicit(&parent_seed, sizeof(parent_seed));
    memzero_explicit(&child_seed, sizeof(child_seed));
    return 0;  /* ALWAYS succeed — never kill the fork */
}

/*
 * df_task_context_cleanup — Wipe DF context on process exit.
 *
 * Crypto-zeroes the seed. After this, any data encrypted with
 * this process's dialect is unrecoverable. Clean exit.
 */
void df_task_context_cleanup(struct task_struct *task)
{
    /* Clear anomaly record: PIDs are recycled, stale lockdown records
     * would block innocent new processes that reuse this PID. */
    df_anomaly_clear_pid(task->pid);

    memzero_explicit(task->df_ctx.seed_bytes, sizeof(task->df_ctx.seed_bytes));
    task->df_ctx.flags = 0;
    task->df_ctx.tier = 0;
    task->df_ctx.zone_id = 0;
}

/*
 * df_task_check_ipc_compat — Can two processes communicate?
 *
 * Returns 0 if yes, -EACCES if no.
 * Compatibility = same dialect tree branch.
 * Native ↔ Native: yes
 * Native ↔ Adopted: yes
 * Native ↔ Quarantine: NO
 * Quarantine(A) ↔ Quarantine(B): NO (different zones)
 * Quarantine(A) ↔ Quarantine(A): yes (same zone)
 */
int df_task_check_ipc_compat(struct task_struct *sender,
                              struct task_struct *receiver)
{
    /* Both valid? */
    if (!(sender->df_ctx.flags & DF_TASKF_SEED_VALID) ||
        !(receiver->df_ctx.flags & DF_TASKF_SEED_VALID))
        return -EACCES;

    /* Both in system dialect tree (native or adopted)? */
    if (sender->df_ctx.tier <= DF_TIER_ADOPTED &&
        receiver->df_ctx.tier <= DF_TIER_ADOPTED)
        return 0;

    /* Both in same quarantine zone? */
    if (sender->df_ctx.zone_id != 0 &&
        sender->df_ctx.zone_id == receiver->df_ctx.zone_id)
        return 0;

    return -EACCES;
}
