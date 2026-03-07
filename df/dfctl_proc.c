// SPDX-License-Identifier: GPL-2.0
/*
 * df/dfctl_proc.c — /proc/dfctl interface for tier management.
 *
 * Read:  Shows tier list of all DF-aware processes.
 * Write: "promote <pid>" to promote from quarantine to adopted.
 *        "quarantine <pid>" to force a process into quarantine.
 *        "status" to show quarantine zone status.
 *
 * This is the early CLI interface. Full dfctl userspace tool in Phase 6.
 *
 * Copyright (C) 2026 John Dean Martin. Protocol is PROPRIETARY.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/dialectforge.h>

static const char *tier_name(u8 tier)
{
    switch (tier) {
    case DF_TIER_NATIVE:     return "native";
    case DF_TIER_ADOPTED:    return "adopted";
    case DF_TIER_QUARANTINE: return "quarantine";
    default:                 return "unknown";
    }
}

/* ── Read: show all process tiers ── */
static int dfctl_show(struct seq_file *m, void *v)
{
    struct task_struct *task;

    seq_printf(m, "=== DialectForge Process Tier List ===\n");
    seq_printf(m, "%-8s %-6s %-12s %-6s %-10s %s\n",
               "PID", "TID", "TIER", "GEN", "ZONE", "COMM");
    seq_printf(m, "%-8s %-6s %-12s %-6s %-10s %s\n",
               "---", "---", "----", "---", "----", "----");

    rcu_read_lock();
    for_each_process(task) {
        if (task->df_ctx.flags & DF_TASKF_SEED_VALID) {
            seq_printf(m, "%-8d %-6d %-12s %-6u %-10u %s\n",
                       task->tgid, task->pid,
                       tier_name(task->df_ctx.tier),
                       task->df_ctx.generation,
                       task->df_ctx.zone_id,
                       task->comm);
        }
    }
    rcu_read_unlock();

    return 0;
}

static int dfctl_open(struct inode *inode, struct file *file)
{
    return single_open(file, dfctl_show, NULL);
}

/* ── Write: tier management commands ── */
static ssize_t dfctl_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos)
{
    char kbuf[64];
    pid_t pid;
    int ret;

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    /* "promote <pid>" */
    if (sscanf(kbuf, "promote %d", &pid) == 1) {
        ret = df_quarantine_promote(pid, DF_TIER_ADOPTED);
        if (ret)
            pr_err("dialectforge: dfctl: promote pid %d failed: %d\n",
                   pid, ret);
        else
            pr_info("dialectforge: dfctl: pid %d promoted to adopted\n",
                    pid);
        return ret ? ret : count;
    }

    /* "quarantine <pid>" */
    if (sscanf(kbuf, "quarantine %d", &pid) == 1) {
        struct task_struct *task;
        struct df_quarantine_zone *zone;

        zone = df_quarantine_zone_create(pid);
        if (IS_ERR(zone))
            return PTR_ERR(zone);

        rcu_read_lock();
        task = find_task_by_vpid(pid);
        if (task) {
            get_task_struct(task);
            rcu_read_unlock();

            memcpy(task->df_ctx.seed_bytes, zone->seed.bytes, 32);
            task->df_ctx.tier = DF_TIER_QUARANTINE;
            task->df_ctx.zone_id = zone->zone_id;
            task->df_ctx.flags |= DF_TASKF_QUARANTINED | DF_TASKF_SEED_VALID;

            pr_info("dialectforge: dfctl: pid %d forced to quarantine "
                    "(zone %u)\n", pid, zone->zone_id);
            put_task_struct(task);
        } else {
            rcu_read_unlock();
            df_quarantine_zone_destroy(zone);
            return -ESRCH;
        }
        return count;
    }

    pr_info("dialectforge: dfctl: unknown command: %s\n", kbuf);
    return -EINVAL;
}

static const struct proc_ops dfctl_proc_ops = {
    .proc_open    = dfctl_open,
    .proc_read    = seq_read,
    .proc_write   = dfctl_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

int df_dfctl_proc_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create("dfctl", 0400, NULL, &dfctl_proc_ops);
    if (!entry)
        return -ENOMEM;

    pr_info("dialectforge: /proc/dfctl interface active\n");
    return 0;
}

void df_dfctl_proc_cleanup(void)
{
    remove_proc_entry("dfctl", NULL);
}
