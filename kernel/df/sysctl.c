// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS - Runtime Tunables
 * Copyright (c) 2026 John Dean Martin - Patent Pending
 *
 * df/sysctl.c - /proc/sys/dialectforge/ parameters
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/dialectforge.h>

static struct ctl_table_header *df_sysctl_header;

/* Tunable values - these are the knobs */
static u32 sysctl_cycle_ms     = DF_CYCLE_DEFAULT_MS;
static u32 sysctl_jitter_ms    = DF_CYCLE_JITTER_MS;
static u32 sysctl_anomaly_thresh = DF_ANOMALY_THRESHOLD;
static u32 sysctl_cipher_mode  = DF_CIPHER_XOR_FAST;
static u32 sysctl_auto_rotate  = 0;
static u32 sysctl_debug_level  = 1;

static struct ctl_table df_sysctl_table[] = {
	{
		.procname   = "cycle_interval_ms",
		.data       = &sysctl_cycle_ms,
		.maxlen     = sizeof(u32),
		.mode       = 0600,
		.proc_handler = proc_douintvec,
	},
	{
		.procname   = "cycle_jitter_ms",
		.data       = &sysctl_jitter_ms,
		.maxlen     = sizeof(u32),
		.mode       = 0600,
		.proc_handler = proc_douintvec,
	},
	{
		.procname   = "anomaly_threshold",
		.data       = &sysctl_anomaly_thresh,
		.maxlen     = sizeof(u32),
		.mode       = 0600,
		.proc_handler = proc_douintvec,
	},
	{
		.procname   = "cipher_mode",
		.data       = &sysctl_cipher_mode,
		.maxlen     = sizeof(u32),
		.mode       = 0600,
		.proc_handler = proc_douintvec,
	},
	{
		.procname   = "auto_rotate",
		.data       = &sysctl_auto_rotate,
		.maxlen     = sizeof(u32),
		.mode       = 0600,
		.proc_handler = proc_douintvec,
	},
	{
		.procname   = "debug_level",
		.data       = &sysctl_debug_level,
		.maxlen     = sizeof(u32),
		.mode       = 0600,
		.proc_handler = proc_douintvec,
	},
};

int df_sysctl_init(void)
{
	df_sysctl_header = register_sysctl("dialectforge", df_sysctl_table);
	if (!df_sysctl_header) {
		pr_err("dialectforge: sysctl registration failed\n");
		return -ENOMEM;
	}
	pr_info("dialectforge: sysctl interface at /proc/sys/dialectforge/\n");
	return 0;
}
EXPORT_SYMBOL_GPL(df_sysctl_init);

void df_sysctl_cleanup(void)
{
	if (df_sysctl_header)
		unregister_sysctl_table(df_sysctl_header);
}
EXPORT_SYMBOL_GPL(df_sysctl_cleanup);

/* Accessors for other DF modules */
u32 df_sysctl_get_cycle_ms(void)     { return sysctl_cycle_ms; }
u32 df_sysctl_get_jitter_ms(void)    { return sysctl_jitter_ms; }
u32 df_sysctl_get_cipher_mode(void)  { return sysctl_cipher_mode; }
u32 df_sysctl_get_debug_level(void)  { return sysctl_debug_level; }
EXPORT_SYMBOL_GPL(df_sysctl_get_cycle_ms);
EXPORT_SYMBOL_GPL(df_sysctl_get_jitter_ms);
EXPORT_SYMBOL_GPL(df_sysctl_get_cipher_mode);
EXPORT_SYMBOL_GPL(df_sysctl_get_debug_level);
