// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS — cycle engine
 *
 * Timer-based dialect rotation with jitter. When the dialect cycles,
 * all derived parameters rotate: encryption keys, sector maps, etc.
 *
 * Phase 2 addition: notification hook for dialectfs sector hopping.
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */

#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/dialectforge.h>

/* Cycle state */
static struct timer_list df_cycle_timer;
static unsigned long df_cycle_interval_ms = 30000;  /* 30 seconds */
static unsigned long df_cycle_jitter_ms = 5000;     /* ±5 seconds */
static u64 df_cycle_count = 0;
static bool df_cycle_active = false;

/* Notification callbacks — called when dialect rotates */
#define DF_CYCLE_MAX_HOOKS 16
static void (*df_cycle_hooks[DF_CYCLE_MAX_HOOKS])(u64 cycle);
static int df_cycle_hook_count = 0;

/*
 * df_cycle_register_hook() — register a callback for dialect rotation
 *
 * Subsystems like dialectfs register here to get notified when
 * the dialect cycles, so they can update their sector maps.
 */
int df_cycle_register_hook(void (*hook)(u64 cycle))
{
	if (df_cycle_hook_count >= DF_CYCLE_MAX_HOOKS)
		return -ENOSPC;
	df_cycle_hooks[df_cycle_hook_count++] = hook;
	pr_info("dialectforge: cycle hook registered (%d total)\n",
		df_cycle_hook_count);
	return 0;
}
EXPORT_SYMBOL(df_cycle_register_hook);

/*
 * df_cycle_tick() — the heartbeat of the atmosphere
 *
 * Every 30s (±jitter), the dialect rotates. Everything derived
 * from the system seed changes. All registered hooks fire.
 */
static void df_cycle_tick(struct timer_list *t)
{
	unsigned long next_interval;
	u32 jitter;
	int i;

	df_cycle_count++;

	/* Rotate the system dialect */
	df_seed_derive_labeled(&df_get_system()->root_seed, "cycle-rotate", 12, &df_get_system()->root_seed);

	pr_debug("dialectforge: dialect cycled (cycle=%llu)\n", df_cycle_count);

	/* Notify all registered subsystems */
	for (i = 0; i < df_cycle_hook_count; i++) {
		if (df_cycle_hooks[i])
			df_cycle_hooks[i](df_cycle_count);
	}

	/* Schedule next cycle with jitter */
	get_random_bytes(&jitter, sizeof(jitter));
	jitter = jitter % (df_cycle_jitter_ms * 2);
	next_interval = df_cycle_interval_ms - df_cycle_jitter_ms + jitter;

	mod_timer(&df_cycle_timer,
		  jiffies + msecs_to_jiffies(next_interval));
}

/*
 * df_cycle_emergency_rotate() — force immediate rotation
 *
 * Called when anomaly detection triggers. Don't wait for the
 * timer — rotate NOW. Like hitting the fire alarm.
 */
void df_cycle_emergency_rotate(void)
{
	pr_warn("dialectforge: EMERGENCY dialect rotation!\n");
	df_cycle_tick(&df_cycle_timer);
}
EXPORT_SYMBOL(df_cycle_emergency_rotate);

/* Getters for /proc/dialectforge */
u64 df_cycle_get_count(void)
{
	return df_cycle_count;
}

unsigned long df_cycle_get_interval(void)
{
	return df_cycle_interval_ms;
}

int __init df_cycle_init(void)
{
	unsigned long first_interval;
	u32 jitter;

	get_random_bytes(&jitter, sizeof(jitter));
	jitter = jitter % (df_cycle_jitter_ms * 2);
	first_interval = df_cycle_interval_ms - df_cycle_jitter_ms + jitter;

	timer_setup(&df_cycle_timer, df_cycle_tick, 0);
	mod_timer(&df_cycle_timer,
		  jiffies + msecs_to_jiffies(first_interval));
	df_cycle_active = true;

	pr_info("dialectforge: cycle engine initialized (interval=%lums, jitter=%lums)\n",
		df_cycle_interval_ms, df_cycle_jitter_ms);
	return 0;
}
