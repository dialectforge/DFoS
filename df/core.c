// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS - Core Runtime
 * Copyright (c) 2026 John Dean Martin - Patent Pending
 *
 * df/core.c - System initialization, dialect lifecycle, /proc interface
 *
 * Phase 2: Now wires up cipher engine, HKDF seed manager, sysctl,
 * and anomaly detection during boot.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/dialectforge.h>
#include <linux/sched/task.h>
#include <linux/ktime.h>

/* Phase 3: forward decl */
struct df_seed *df_get_system_root_seed(void);

static struct df_system df_sys;

struct df_system *df_get_system(void)
{
	return &df_sys;
}
EXPORT_SYMBOL_GPL(df_get_system);

/* ==================================================================
 *  Dialect Management (uses cipher engine now)
 * ================================================================== */

int df_dialect_create(struct df_dialect *dialect, const struct df_seed *seed)
{
	int ret;

	if (!dialect || !seed)
		return -EINVAL;
	if (!df_seed_is_valid(seed))
		return -EKEYREVOKED;

	memcpy(&dialect->seed, seed, sizeof(struct df_seed));

	/* Derive cipher keys via HKDF (not raw copy) */
	ret = df_seed_derive_keys(seed, 0, dialect->cipher_key, dialect->cipher_iv);
	if (ret)
		return ret;

	dialect->cipher_mode = DF_CIPHER_XOR_FAST;
	dialect->cycle_count = 0;
	dialect->cycle_start = ktime_get_real();
	dialect->status = DF_STATUS_ACTIVE;
	spin_lock_init(&dialect->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(df_dialect_create);

int df_dialect_derive_keys(struct df_dialect *dialect)
{
	unsigned long flags;
	int ret;

	if (!dialect)
		return -EINVAL;

	spin_lock_irqsave(&dialect->lock, flags);
	dialect->cycle_count++;

	/* Re-derive keys from seed + new cycle count via HKDF */
	ret = df_seed_derive_keys(&dialect->seed, dialect->cycle_count,
	                          dialect->cipher_key, dialect->cipher_iv);
	dialect->cycle_start = ktime_get_real();
	spin_unlock_irqrestore(&dialect->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(df_dialect_derive_keys);

void df_dialect_destroy(struct df_dialect *dialect)
{
	if (!dialect) return;
	memset(dialect->cipher_key, 0, 32);
	memset(dialect->cipher_iv, 0, 16);
	memset(&dialect->seed, 0, sizeof(struct df_seed));
	dialect->status = DF_STATUS_UNINIT;
}
EXPORT_SYMBOL_GPL(df_dialect_destroy);

/* ==================================================================
 *  /proc/dialectforge Interface
 * ================================================================== */

static const char *df_status_str(u32 s)
{
	switch (s) {
	case DF_STATUS_UNINIT:   return "UNINITIALIZED";
	case DF_STATUS_ACTIVE:   return "ACTIVE";
	case DF_STATUS_ROTATING: return "ROTATING";
	case DF_STATUS_LOCKDOWN: return "LOCKDOWN";
	case DF_STATUS_ERROR:    return "ERROR";
	default:                 return "UNKNOWN";
	}
}

static int df_proc_show(struct seq_file *m, void *v)
{
	struct df_system *sys = df_get_system();
	s64 up = ktime_ms_delta(ktime_get_real(), sys->boot_time);

	seq_puts(m, "\n");
	seq_puts(m, "    ============================================\n");
	seq_puts(m, "        DialectForge OS v0.2.0 (Phase 2)\n");
	seq_puts(m, "        The Atmosphere Has Changed.\n");
	seq_puts(m, "    ============================================\n\n");

	seq_printf(m, "  Status:          %s\n", df_status_str(sys->status));
	seq_printf(m, "  Uptime:          %lld.%03lld sec\n",
	           up / 1000, up % 1000);

	seq_puts(m, "\n  -- Root Seed --\n");
	seq_printf(m, "  Fingerprint:     %02x%02x%02x%02x...%02x%02x%02x%02x\n",
	           sys->root_seed.bytes[0], sys->root_seed.bytes[1],
	           sys->root_seed.bytes[2], sys->root_seed.bytes[3],
	           sys->root_seed.bytes[28], sys->root_seed.bytes[29],
	           sys->root_seed.bytes[30], sys->root_seed.bytes[31]);
	seq_printf(m, "  Tier:            %s\n",
	           sys->root_seed.tier == DF_TIER_NATIVE ? "NATIVE" : "OTHER");
	seq_printf(m, "  Valid:           %s\n",
	           df_seed_is_valid(&sys->root_seed) ? "YES" : "NO");

	seq_puts(m, "\n  -- System Dialect --\n");
	seq_printf(m, "  Cipher Mode:     %s\n",
	           sys->system_dialect.cipher_mode == DF_CIPHER_AES_GCM
	           ? "AES-256-GCM" : "XOR_FAST");
	seq_printf(m, "  Cycle Count:     %llu\n",
	           sys->system_dialect.cycle_count);

	seq_puts(m, "\n  -- Engine Stats --\n");
	seq_printf(m, "  Cycle Interval:  %u ms\n", sys->cycle_cfg.interval_ms);
	seq_printf(m, "  Jitter:          %u ms\n", sys->cycle_cfg.jitter_ms);
	seq_printf(m, "  Auto-Rotate:     %s\n",
	           sys->cycle_cfg.auto_rotate ? "ON" : "OFF");
	seq_printf(m, "  Total Rotations: %llu\n", sys->total_rotations);
	seq_printf(m, "  Seeds Generated: %llu\n", sys->total_seeds_generated);

	seq_puts(m, "\n  -- Subsystems --\n");
	seq_puts(m, "  Cipher Engine:   ACTIVE (AES-GCM + HMAC-SHA256)\n");
	seq_puts(m, "  Seed Manager:    ACTIVE (HKDF-SHA256)\n");
	seq_puts(m, "  Anomaly Detect:  ACTIVE\n");
	seq_puts(m, "  Sysctl:          ACTIVE (/proc/sys/dialectforge/)\n");
	seq_puts(m, "\n");

	return 0;
}

static int df_proc_open(struct inode *i, struct file *f)
{
	return single_open(f, df_proc_show, NULL);
}

static const struct proc_ops df_proc_ops = {
	.proc_open    = df_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *df_proc_entry;

static int df_proc_init(void)
{
	df_proc_entry = proc_create("dialectforge", 0400, NULL, &df_proc_ops);
	if (!df_proc_entry) return -ENOMEM;
	pr_info("dialectforge: /proc/dialectforge active\n");


	return 0;
}

static void __maybe_unused df_proc_cleanup(void)
{
	if (df_proc_entry) proc_remove(df_proc_entry);
}

/* ==================================================================
 *  Subsystem Init — Phase 2: wire up all engines
 * ================================================================== */


/*
 * df_get_system_root_seed — Return pointer to system root seed.
 * Used by quarantine engine to derive quarantine root.
 */
struct df_seed *df_get_system_root_seed(void)
{
    return &df_sys.root_seed;
}
EXPORT_SYMBOL_GPL(df_get_system_root_seed);

int __init df_init(void)
{
	int ret;

	pr_info("dialectforge: ========================================\n");
	pr_info("dialectforge:   DialectForge OS v%d.%d.%d\n",
	        DF_VERSION_MAJOR, DF_VERSION_MINOR, DF_VERSION_PATCH);
	pr_info("dialectforge:   Copyright (c) 2026 John Dean Martin\n");
	pr_info("dialectforge:   Patent Pending\n");
	pr_info("dialectforge: ========================================\n");

	memset(&df_sys, 0, sizeof(df_sys));
	spin_lock_init(&df_sys.lock);
	df_sys.boot_time = ktime_get_real();
	df_sys.status = DF_STATUS_UNINIT;

	/* Phase 2: Initialize seed manager FIRST (HKDF) */
	ret = df_seed_init();
	if (ret) {
		pr_err("dialectforge: FATAL - seed manager init failed\n");
		return ret;
	}

	/* Phase 2: Initialize cipher engine */
	ret = df_cipher_init();
	if (ret) {
		pr_err("dialectforge: FATAL - cipher engine init failed\n");
		return ret;
	}

	/* Generate root seed */
	ret = df_seed_generate(&df_sys.root_seed, DF_TIER_NATIVE);
	if (ret) {
		pr_err("dialectforge: FATAL - root seed generation failed\n");
		return ret;
	}
	df_sys.total_seeds_generated = 1;

	/* Create system dialect from root seed (now uses HKDF) */
	ret = df_dialect_create(&df_sys.system_dialect, &df_sys.root_seed);
	if (ret) {
		pr_err("dialectforge: FATAL - system dialect creation failed\n");
		return ret;
	}

	/* Initialize cycle configuration */
	df_sys.cycle_cfg.interval_ms = DF_CYCLE_DEFAULT_MS;
	df_sys.cycle_cfg.jitter_ms = DF_CYCLE_JITTER_MS;
	df_sys.cycle_cfg.emergency_interval_ms = 5000;
	df_sys.cycle_cfg.auto_rotate = false;

	/* Initialize cycle engine */
	ret = df_cycle_init();
	if (ret)
		pr_warn("dialectforge: cycle engine init failed (non-fatal)\n");

	/* Phase 2: Initialize sysctl */
	ret = df_sysctl_init();
	if (ret)
		pr_warn("dialectforge: sysctl init failed (non-fatal)\n");

	/* Phase 2: Initialize anomaly detection */
	ret = df_anomaly_init();
	if (ret)
		pr_warn("dialectforge: anomaly init failed (non-fatal)\n");

	/* Initialize /proc interface */
	ret = df_proc_init();
	if (ret) {
		pr_err("dialectforge: FATAL - /proc init failed\n");
		return ret;
	}

	df_sys.status = DF_STATUS_ACTIVE;

	pr_info("dialectforge: ========================================\n");
	pr_info("dialectforge:   ALL SUBSYSTEMS ACTIVE\n");
	pr_info("dialectforge:   Cipher:  AES-256-GCM + XOR_FAST\n");
	pr_info("dialectforge:   Seeds:   HKDF-SHA256\n");
	pr_info("dialectforge:   Anomaly: scoring active\n");
	pr_info("dialectforge:   Sysctl:  /proc/sys/dialectforge/\n");
	
        /* ── Phase 3: Quarantine & LSM ── */

        /* Initialize quarantine engine */
        ret = df_quarantine_init();
        if (ret)
                pr_warn("dialectforge: quarantine init failed: %d\n", ret);

        /* (anomaly detection already initialized in Phase 2 above) */

        /* Initialize /proc/dfctl interface */
        ret = df_dfctl_proc_init();
        if (ret)
                pr_warn("dialectforge: dfctl proc init failed: %d\n", ret);

        /* Set init process (PID 1) as native tier */
        {
                struct task_struct *init_task_p = &init_task;
                memcpy(init_task_p->df_ctx.seed_bytes,
                       df_sys.root_seed.bytes,
                       sizeof(init_task_p->df_ctx.seed_bytes));
                init_task_p->df_ctx.tier = DF_TIER_NATIVE;
                init_task_p->df_ctx.generation = 0;
                init_task_p->df_ctx.zone_id = 0;
                init_task_p->df_ctx.seed_born_ns = ktime_get_ns();
                init_task_p->df_ctx.flags = DF_TASKF_SEED_VALID;
                pr_info("dialectforge: init_task seeded as native tier 0\n");
        }


	/* Phase 4: Network adapter */
	df_net_init();
        pr_info("dialectforge:   The atmosphere has changed.\n");
	pr_info("dialectforge: ========================================\n");

	
	/* Phase 6: register AF_DIALECTFORGE protocol family */
	ret = df_proto_init();
	if (ret)
		pr_warn("DialectForge: AF_DIALECTFORGE init failed: %d\n", ret);

return 0;
}
subsys_initcall(df_init);
