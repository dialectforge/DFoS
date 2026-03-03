// SPDX-License-Identifier: GPL-2.0
/*
 * df/quarantine.c — DialectForge Quarantine Engine
 *
 * Manages the three-tier software model:
 *   Tier 0 (Native):     Born on DFOS. Seed derived from system root.
 *   Tier 1 (Adopted):    Promoted by user/dfpkg. Scoped seed context.
 *   Tier 2 (Quarantine): Untrusted. Ephemeral seed from quarantine root.
 *                         TTL expires → seed dies → data = noise.
 *
 * Quarantine seeds are derived from a dedicated "quarantine root" seed
 * that is itself a child of the system root. This means:
 *   - Quarantine zones are structurally isolated from native dialect
 *   - Revoking quarantine root kills ALL quarantine zones at once
 *   - Each zone has its own unique derived seed (zone cannot read zone)
 *
 * Copyright (C) 2026 John Dean Martin. Protocol is PROPRIETARY.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/dialectforge.h>

/* ── Global State ── */
static struct df_seed quarantine_root_seed;    /* Child of system root     */
static DEFINE_SPINLOCK(zone_list_lock);
static LIST_HEAD(zone_list);
static atomic_t zone_counter = ATOMIC_INIT(0);
static int quarantine_initialized;

/* Forward decl — defined in crypto/df_seed.c */
extern int df_seed_derive_labeled(const struct df_seed *parent,
                                   const char *label, size_t label_len,
                                   struct df_seed *child);

/* Forward decl — defined in df/core.c */
extern struct df_seed *df_get_system_root_seed(void);

/*
 * df_quarantine_init — Initialize the quarantine subsystem.
 *
 * Derives the quarantine root seed from the system root.
 * Called from df_init() after root seed is generated.
 */
int df_quarantine_init(void)
{
    struct df_seed *sys_root;
    int ret;

    sys_root = df_get_system_root_seed();
    if (!sys_root) {
        pr_err("dialectforge: quarantine: no system root seed\n");
        return -ENOENT;
    }

    ret = df_seed_derive_labeled(sys_root, "quarantine_root", 15,
                                  &quarantine_root_seed);
    if (ret) {
        pr_err("dialectforge: quarantine: seed derivation failed: %d\n", ret);
        return ret;
    }

    quarantine_initialized = 1;
    pr_info("dialectforge: quarantine engine initialized "
            "(root seed derived, max %d zones)\n",
            DF_QUARANTINE_MAX_ZONES);
    return 0;
}

/*
 * df_quarantine_zone_create — Spawn a new quarantine zone for a process.
 *
 * Each zone gets a unique seed derived from quarantine root + zone_id.
 * The zone's seed is structurally incompatible with system dialect —
 * different universe, different language.
 */
struct df_quarantine_zone *df_quarantine_zone_create(pid_t pid)
{
    struct df_quarantine_zone *zone;
    char label[32];
    u32 zid;
    int ret;

    if (!quarantine_initialized)
        return ERR_PTR(-ENODEV);

    zid = atomic_inc_return(&zone_counter);
    if (zid > DF_QUARANTINE_MAX_ZONES) {
        atomic_dec(&zone_counter);
        pr_warn("dialectforge: quarantine: max zones reached (%d)\n",
                DF_QUARANTINE_MAX_ZONES);
        return ERR_PTR(-ENOSPC);
    }

    zone = kzalloc(sizeof(*zone), GFP_KERNEL);
    if (!zone) {
        atomic_dec(&zone_counter);
        return ERR_PTR(-ENOMEM);
    }

    /* Derive per-zone seed: quarantine_root + "zone_NNNN" */
    snprintf(label, sizeof(label), "zone_%u", zid);
    ret = df_seed_derive_labeled(&quarantine_root_seed, label,
                                  strlen(label), &zone->seed);
    if (ret) {
        kfree(zone);
        atomic_dec(&zone_counter);
        return ERR_PTR(ret);
    }

    zone->tier = DF_TIER_QUARANTINE;
    zone->created_ns = ktime_get_ns();
    zone->ttl_ns = (u64)DF_QUARANTINE_TTL_DEFAULT_MS * 1000000ULL;
    zone->zone_id = zid;
    zone->owner_pid = pid;
    atomic_set(&zone->refcount, 1);
    spin_lock_init(&zone->lock);
    INIT_LIST_HEAD(&zone->list);

    spin_lock(&zone_list_lock);
    list_add_tail(&zone->list, &zone_list);
    spin_unlock(&zone_list_lock);

    pr_info("dialectforge: quarantine zone %u created for pid %d "
            "(TTL %llu ms)\n", zid, pid,
            zone->ttl_ns / 1000000ULL);
    return zone;
}

/*
 * df_quarantine_zone_destroy — Tear down a quarantine zone.
 *
 * Zeros the seed material. After this, any data encrypted with
 * this zone's dialect is permanently unreadable — the key is gone.
 */
void df_quarantine_zone_destroy(struct df_quarantine_zone *zone)
{
    if (!zone)
        return;

    spin_lock(&zone_list_lock);
    list_del(&zone->list);
    spin_unlock(&zone_list_lock);

    pr_info("dialectforge: quarantine zone %u destroyed (pid %d) — "
            "dialect is dead\n", zone->zone_id, zone->owner_pid);

    /* Crypto-wipe the seed — this kills the dialect forever */
    memzero_explicit(&zone->seed, sizeof(zone->seed));
    atomic_dec(&zone_counter);
    kfree(zone);
}

/*
 * df_quarantine_zone_find — Look up a zone by ID.
 */
struct df_quarantine_zone *df_quarantine_zone_find(u32 zone_id)
{
    struct df_quarantine_zone *zone;

    spin_lock(&zone_list_lock);
    list_for_each_entry(zone, &zone_list, list) {
        if (zone->zone_id == zone_id) {
            spin_unlock(&zone_list_lock);
            return zone;
        }
    }
    spin_unlock(&zone_list_lock);
    return NULL;
}

/*
 * df_quarantine_check_expiry — Check if a zone's visa has expired.
 *
 * Returns 1 if expired (zone should be destroyed), 0 if still valid.
 * This is called from the cycle timer and from LSM hooks.
 */
int df_quarantine_check_expiry(struct df_quarantine_zone *zone)
{
    u64 now, deadline;

    if (!zone)
        return 1;

    now = ktime_get_ns();
    deadline = zone->created_ns + zone->ttl_ns;

    if (now >= deadline) {
        pr_info("dialectforge: quarantine zone %u expired "
                "(pid %d, lived %llu ms)\n",
                zone->zone_id, zone->owner_pid,
                (now - zone->created_ns) / 1000000ULL);
        return 1;
    }
    return 0;
}

/*
 * df_quarantine_promote — Move a process from quarantine to adopted tier.
 *
 * The process gets a new seed derived from the system tree (not quarantine
 * tree). Its old quarantine data becomes unreadable — it's literally
 * starting fresh in a new dialect. Like getting citizenship: new passport,
 * new language, old tourist phrase book is shredded.
 */
int df_quarantine_promote(pid_t pid, u8 new_tier)
{
    struct task_struct *task;
    struct df_seed *sys_root;
    char label[32];
    int ret = -ESRCH;

    if (new_tier != DF_TIER_ADOPTED && new_tier != DF_TIER_NATIVE)
        return -EINVAL;

    sys_root = df_get_system_root_seed();
    if (!sys_root)
        return -ENOENT;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) {
        get_task_struct(task);
        rcu_read_unlock();

        /* Derive new seed from system root — now part of the real tree */
        snprintf(label, sizeof(label), "promoted_%d", pid);
        ret = df_seed_derive_labeled(sys_root, label, strlen(label),
                                      (struct df_seed *)&task->df_ctx.seed_bytes);
        if (!ret) {
            task->df_ctx.tier = new_tier;
            task->df_ctx.flags = DF_TASKF_SEED_VALID | DF_TASKF_PROMOTED;
            task->df_ctx.zone_id = 0; /* No longer in quarantine */
            task->df_ctx.generation++;
            pr_info("dialectforge: pid %d promoted to tier %u "
                    "— new dialect assigned\n", pid, new_tier);
        }
        put_task_struct(task);
    } else {
        rcu_read_unlock();
    }
    return ret;
}

/*
 * df_quarantine_sweep — Check all zones for expiry. Called from cycle timer.
 */
void df_quarantine_sweep(void)
{
    struct df_quarantine_zone *zone, *tmp;
    struct list_head expired;

    INIT_LIST_HEAD(&expired);

    spin_lock(&zone_list_lock);
    list_for_each_entry_safe(zone, tmp, &zone_list, list) {
        if (df_quarantine_check_expiry(zone)) {
            list_del(&zone->list);
            list_add(&zone->list, &expired);
        }
    }
    spin_unlock(&zone_list_lock);

    /* Destroy outside the lock */
    list_for_each_entry_safe(zone, tmp, &expired, list) {
        list_del(&zone->list);
        df_quarantine_zone_destroy(zone);
    }
}

void df_quarantine_cleanup(void)
{
    struct df_quarantine_zone *zone, *tmp;

    spin_lock(&zone_list_lock);
    list_for_each_entry_safe(zone, tmp, &zone_list, list) {
        list_del(&zone->list);
        memzero_explicit(&zone->seed, sizeof(zone->seed));
        kfree(zone);
    }
    spin_unlock(&zone_list_lock);

    memzero_explicit(&quarantine_root_seed, sizeof(quarantine_root_seed));
    quarantine_initialized = 0;
    pr_info("dialectforge: quarantine engine shut down\n");
}
