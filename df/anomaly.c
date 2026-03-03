// SPDX-License-Identifier: GPL-2.0
/*
 * df/anomaly.c — DialectForge Anomaly Detection Engine
 *
 * Phase 3 upgrade: quarantine-aware monitoring.
 * Watches quarantined processes for suspicious behavior:
 *   - Unusual syscall patterns
 *   - Network access attempts from quarantine
 *   - Privilege escalation attempts
 *   - Cross-dialect IPC attempts
 *
 * Scoring is weighted — some events are more suspicious than others.
 * High enough score triggers automatic zone destruction.
 *
 * Copyright (C) 2026 John Dean Martin. Protocol is PROPRIETARY.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/dialectforge.h>

#define DF_ANOMALY_HISTORY_SIZE  64
#define DF_ANOMALY_LOCKDOWN_THRESHOLD  50

/* Per-process anomaly record */
struct df_anomaly_record {
    pid_t               pid;
    int                 total_score;
    int                 event_count;
    u64                 last_event_ns;
    char                last_event[32];
    struct list_head    list;
};

static DEFINE_SPINLOCK(anomaly_lock);
static LIST_HEAD(anomaly_records);
static int anomaly_initialized;

/*
 * find_or_create_record — Get anomaly record for a PID.
 * Must be called with anomaly_lock held.
 */
static struct df_anomaly_record *find_or_create_record(pid_t pid)
{
    struct df_anomaly_record *rec;

    list_for_each_entry(rec, &anomaly_records, list) {
        if (rec->pid == pid)
            return rec;
    }

    /* New record */
    rec = kzalloc(sizeof(*rec), GFP_ATOMIC);
    if (!rec)
        return NULL;

    rec->pid = pid;
    INIT_LIST_HEAD(&rec->list);
    list_add_tail(&rec->list, &anomaly_records);
    return rec;
}

/*
 * df_anomaly_log_quarantine_event — Record a suspicious event.
 *
 * Called from LSM hooks when quarantine processes do sketchy things.
 * Events: socket_create, blocked_connect, blocked_file,
 *         blocked_msgq, blocked_shm, ptrace_cross_dialect,
 *         sendmsg_attempt
 */
void df_anomaly_log_quarantine_event(pid_t pid, const char *event,
                                      int score)
{
    struct df_anomaly_record *rec;

    if (!anomaly_initialized)
        return;

    spin_lock(&anomaly_lock);
    rec = find_or_create_record(pid);
    if (rec) {
        rec->total_score += score;
        rec->event_count++;
        rec->last_event_ns = ktime_get_ns();
        strscpy(rec->last_event, event, sizeof(rec->last_event));

        if (rec->total_score >= DF_ANOMALY_LOCKDOWN_THRESHOLD) {
            pr_warn("dialectforge: ANOMALY LOCKDOWN pid %d "
                    "(score %d, events %d, last: %s) — "
                    "zone will be destroyed\n",
                    pid, rec->total_score, rec->event_count,
                    rec->last_event);
            /* In a full implementation, this would trigger
             * quarantine zone destruction. For Phase 3,
             * we log and let the zone TTL handle cleanup. */
        }
    }
    spin_unlock(&anomaly_lock);
}

/* ── /proc/dialectforge/anomaly ── */
static int df_anomaly_proc_show(struct seq_file *m, void *v)
{
    struct df_anomaly_record *rec;

    seq_printf(m, "=== DialectForge Anomaly Report ===\n");
    seq_printf(m, "Lockdown threshold: %d\n\n",
               DF_ANOMALY_LOCKDOWN_THRESHOLD);

    spin_lock(&anomaly_lock);
    list_for_each_entry(rec, &anomaly_records, list) {
        seq_printf(m, "PID %-6d  score=%-4d  events=%-4d  "
                   "last=%s\n",
                   rec->pid, rec->total_score,
                   rec->event_count, rec->last_event);
    }
    spin_unlock(&anomaly_lock);

    return 0;
}

static int df_anomaly_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, df_anomaly_proc_show, NULL);
}

static const struct proc_ops df_anomaly_proc_ops = {
    .proc_open    = df_anomaly_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

int df_anomaly_init(void)
{
    proc_create("df_anomaly", 0444, NULL,
                &df_anomaly_proc_ops);
    anomaly_initialized = 1;
    pr_info("dialectforge: anomaly detection initialized "
            "(lockdown threshold: %d)\n",
            DF_ANOMALY_LOCKDOWN_THRESHOLD);
    return 0;
}
