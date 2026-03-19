// SPDX-License-Identifier: GPL-2.0
/*
 * df/anomaly.c — DialectForge Anomaly Detection Engine v2
 * Copyright (C) 2026 John Dean Martin. Protocol is PROPRIETARY.
 *
 * Phase 3 base + Integrity Shield Layer 2 extensions.
 *
 * v2 changes:
 *   - Extended event types: file tampering, cron, SUID, SSH, integrity
 *   - Score decay: old events fade over time (30-min half-life)
 *   - Separate thresholds for quarantine lockdown vs native alert
 *   - /proc/df_anomaly permissions fixed to 0400 (root only)
 *   - SUID execution monitoring
 *   - History ring buffer for forensics
 *
 * The anomaly engine is the immune system. Layer 1 (integrity) detects
 * the virus. Layer 2 (this) decides how sick the patient is.
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
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/dialectforge.h>

/* ================================================================
 * Constants
 * ================================================================ */
#define DF_ANOMALY_LOCKDOWN_THRESHOLD  50  /* Quarantine lockdown */
#define DF_ANOMALY_NATIVE_ALERT        30  /* Native process alert */
#define DF_ANOMALY_HISTORY_SIZE        128 /* Ring buffer for events */
#define DF_ANOMALY_MAX_RECORDS         512 /* Max tracked PIDs */
#define DF_ANOMALY_DECAY_INTERVAL_MS   60000 /* Decay every 60 sec */
#define DF_ANOMALY_DECAY_HALFLIFE_NS   (30ULL * 60 * 1000000000ULL) /* 30 min */

/* Event score weights — tuned from pentest results */
#define DF_SCORE_QUARANTINE_LIGHT   1   /* socket_create, sendmsg */
#define DF_SCORE_QUARANTINE_MEDIUM  4   /* blocked_file */
#define DF_SCORE_QUARANTINE_HEAVY   8   /* blocked_connect, blocked_shm */
#define DF_SCORE_INTEGRITY_WARN     10  /* write to protected file */
#define DF_SCORE_INTEGRITY_TAMPER   15  /* file hash mismatch */
#define DF_SCORE_INTEGRITY_IMMUT    20  /* write to immutable */
#define DF_SCORE_EXEC_TAMPERED      25  /* exec of tampered binary */
#define DF_SCORE_SUID_EXEC          5   /* any SUID execution */
#define DF_SCORE_CRON_WRITE         12  /* cron file modification */
#define DF_SCORE_SSH_FAIL           3   /* SSH auth failure */
#define DF_SCORE_PTRACE_CROSS       5   /* cross-dialect ptrace */

/* ================================================================
 * Data Structures
 * ================================================================ */

/* Per-process anomaly record */
struct df_anomaly_record {
	pid_t               pid;
	int                 total_score;
	int                 peak_score;     /* Highest score ever */
	int                 event_count;
	u64                 first_event_ns;
	u64                 last_event_ns;
	char                last_event[32];
	bool                locked_down;    /* Already triggered lockdown */
	struct list_head    list;
};

/* Event history entry — ring buffer for forensics */
struct df_anomaly_event {
	u64     timestamp_ns;
	pid_t   pid;
	int     score;
	char    event[32];
};

/* ================================================================
 * Module State
 * ================================================================ */
static DEFINE_SPINLOCK(anomaly_lock);
static LIST_HEAD(anomaly_records);
static int anomaly_record_count;
static int anomaly_initialized;

/* Event history ring buffer */
static struct df_anomaly_event event_history[DF_ANOMALY_HISTORY_SIZE];
static int history_head;  /* Next write position */
static u64 total_events;

/* Decay timer */
static struct timer_list decay_timer;

/* ================================================================
 * Score Decay — old events fade
 *
 * Every 60 seconds, all scores decay by factor based on time since
 * last event. 30-minute half-life: a score of 50 becomes 25 after
 * 30 minutes of quiet. This prevents a single bad hour from
 * permanently marking a PID.
 * ================================================================ */

static void df_anomaly_decay_work(struct timer_list *t)
{
	struct df_anomaly_record *rec, *tmp;
	u64 now = ktime_get_ns();

	spin_lock(&anomaly_lock);
	list_for_each_entry_safe(rec, tmp, &anomaly_records, list) {
		u64 age_ns;
		int new_score;

		if (rec->total_score <= 0)
			continue;

		age_ns = now - rec->last_event_ns;

		/* Exponential decay: score * 2^(-age/halflife) */
		if (age_ns >= DF_ANOMALY_DECAY_HALFLIFE_NS * 4) {
			/* More than 2 hours — effectively zero */
			new_score = 0;
		} else if (age_ns >= DF_ANOMALY_DECAY_HALFLIFE_NS) {
			/* Simple integer approximation:
			 * 1 half-life: score/2
			 * 2 half-lives: score/4
			 * 3 half-lives: score/8 */
			int shifts = (int)(age_ns / DF_ANOMALY_DECAY_HALFLIFE_NS);
			if (shifts > 10) shifts = 10;
			new_score = rec->total_score >> shifts;
		} else {
			continue;  /* Not yet one half-life */
		}

		if (new_score != rec->total_score) {
			rec->total_score = new_score;
			if (new_score == 0 && !rec->locked_down) {
				/* Clean record, remove it */
				list_del(&rec->list);
				kfree(rec);
				anomaly_record_count--;
			}
		}
	}
	spin_unlock(&anomaly_lock);

	/* Re-arm timer */
	mod_timer(&decay_timer,
	          jiffies + msecs_to_jiffies(DF_ANOMALY_DECAY_INTERVAL_MS));
}

/* ================================================================
 * Core API
 * ================================================================ */

/* Find or create record — must be called with anomaly_lock held */
static struct df_anomaly_record *find_or_create_record(pid_t pid)
{
	struct df_anomaly_record *rec;

	list_for_each_entry(rec, &anomaly_records, list) {
		if (rec->pid == pid)
			return rec;
	}

	if (anomaly_record_count >= DF_ANOMALY_MAX_RECORDS)
		return NULL;  /* Too many tracked PIDs */

	rec = kzalloc(sizeof(*rec), GFP_ATOMIC);
	if (!rec)
		return NULL;

	rec->pid = pid;
	rec->first_event_ns = ktime_get_ns();
	INIT_LIST_HEAD(&rec->list);
	list_add_tail(&rec->list, &anomaly_records);
	anomaly_record_count++;
	return rec;
}

/*
 * df_anomaly_log_quarantine_event — Record a suspicious event.
 * Called from LSM hooks, integrity checks, and cron/SUID monitors.
 *
 * This is the original Phase 3 API — kept for backward compat.
 * All new event types flow through here.
 */
void df_anomaly_log_quarantine_event(pid_t pid, const char *event,
                                      int score)
{
	struct df_anomaly_record *rec;

	if (!anomaly_initialized)
		return;

	spin_lock(&anomaly_lock);

	/* Record in ring buffer for forensics */
	event_history[history_head].timestamp_ns = ktime_get_ns();
	event_history[history_head].pid = pid;
	event_history[history_head].score = score;
	strscpy(event_history[history_head].event, event,
	        sizeof(event_history[history_head].event));
	history_head = (history_head + 1) % DF_ANOMALY_HISTORY_SIZE;
	total_events++;

	rec = find_or_create_record(pid);
	if (rec) {
		rec->total_score += score;
		rec->event_count++;
		rec->last_event_ns = ktime_get_ns();
		strscpy(rec->last_event, event, sizeof(rec->last_event));

		/* Track peak */
		if (rec->total_score > rec->peak_score)
			rec->peak_score = rec->total_score;

		/* Lockdown check */
		if (!rec->locked_down &&
		    rec->total_score >= DF_ANOMALY_LOCKDOWN_THRESHOLD) {
			rec->locked_down = true;
			pr_warn("dialectforge: ANOMALY LOCKDOWN pid %d "
			        "(score %d, events %d, last: %s)\n",
			        pid, rec->total_score, rec->event_count,
			        rec->last_event);
		}

		/* Native process alert (lower threshold) */
		if (rec->total_score >= DF_ANOMALY_NATIVE_ALERT &&
		    rec->total_score < DF_ANOMALY_LOCKDOWN_THRESHOLD) {
			pr_info_ratelimited(
				"dialectforge: ANOMALY ALERT pid %d "
				"score %d (last: %s)\n",
				pid, rec->total_score, rec->last_event);
		}
	}
	spin_unlock(&anomaly_lock);
}

/*
 * df_anomaly_get_pid_score — Get current score for a PID.
 * Used by LSM hooks to make enforcement decisions.
 */
int df_anomaly_get_pid_score(pid_t pid)
{
	struct df_anomaly_record *rec;
	int score = 0;

	spin_lock(&anomaly_lock);
	list_for_each_entry(rec, &anomaly_records, list) {
		if (rec->pid == pid) {
			score = rec->total_score;
			break;
		}
	}
	spin_unlock(&anomaly_lock);
	return score;
}
EXPORT_SYMBOL_GPL(df_anomaly_get_pid_score);

/*
 * df_anomaly_is_locked_down — Check if PID is in lockdown.
 */
bool df_anomaly_is_locked_down(pid_t pid)
{
	struct df_anomaly_record *rec;
	bool locked = false;

	spin_lock(&anomaly_lock);
	list_for_each_entry(rec, &anomaly_records, list) {
		if (rec->pid == pid) {
			locked = rec->locked_down;
			break;
		}
	}
	spin_unlock(&anomaly_lock);
	return locked;
}
EXPORT_SYMBOL_GPL(df_anomaly_is_locked_down);

/*
 * df_anomaly_clear_pid — Remove anomaly record when process exits.
 *
 * PIDs are recycled by the kernel. Without clearing stale records,
 * a new process that reuses a locked-down PID inherits the lockdown.
 * This caused ext4 journal aborts: jbd2 or journald would reuse a
 * PID from a demo/attack process and be unable to open files.
 */
void df_anomaly_clear_pid(pid_t pid)
{
	struct df_anomaly_record *rec, *tmp;

	if (!anomaly_initialized)
		return;

	spin_lock(&anomaly_lock);
	list_for_each_entry_safe(rec, tmp, &anomaly_records, list) {
		if (rec->pid == pid) {
			list_del(&rec->list);
			kfree(rec);
			anomaly_record_count--;
			break;
		}
	}
	spin_unlock(&anomaly_lock);
}
EXPORT_SYMBOL_GPL(df_anomaly_clear_pid);

/* ================================================================
 * /proc Interface — root only (was 0444, now 0400)
 * ================================================================ */

static int df_anomaly_proc_show(struct seq_file *m, void *v)
{
	struct df_anomaly_record *rec;
	int i, idx;

	seq_puts(m, "=== DialectForge Anomaly Engine v2 ===\n");
	seq_printf(m, "Lockdown threshold: %d\n",
	           DF_ANOMALY_LOCKDOWN_THRESHOLD);
	seq_printf(m, "Native alert:       %d\n",
	           DF_ANOMALY_NATIVE_ALERT);
	seq_printf(m, "Total events:       %llu\n",
	           total_events);
	seq_printf(m, "Active records:     %d / %d\n\n",
	           anomaly_record_count, DF_ANOMALY_MAX_RECORDS);

	seq_puts(m, "--- Active Records ---\n");
	spin_lock(&anomaly_lock);
	list_for_each_entry(rec, &anomaly_records, list) {
		seq_printf(m, "PID %-6d  score=%-4d  peak=%-4d  "
		           "events=%-4d  %s  last=%s\n",
		           rec->pid, rec->total_score,
		           rec->peak_score, rec->event_count,
		           rec->locked_down ? "LOCKDOWN" : "active  ",
		           rec->last_event);
	}

	/* Last 20 events from ring buffer */
	seq_puts(m, "\n--- Recent Events (last 20) ---\n");
	for (i = 0; i < 20 && i < (int)total_events; i++) {
		idx = (history_head - 1 - i + DF_ANOMALY_HISTORY_SIZE)
		      % DF_ANOMALY_HISTORY_SIZE;
		if (event_history[idx].pid == 0)
			break;  /* Empty slot */
		seq_printf(m, "  [%llu] pid=%-6d score=+%-3d %s\n",
		           event_history[idx].timestamp_ns / 1000000,
		           event_history[idx].pid,
		           event_history[idx].score,
		           event_history[idx].event);
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

/* ================================================================
 * Init / Cleanup
 * ================================================================ */

int df_anomaly_init(void)
{
	/* /proc/df_anomaly — ROOT ONLY (0400, not 0444) */
	proc_create("df_anomaly", 0400, NULL,
	            &df_anomaly_proc_ops);

	/* Start decay timer */
	timer_setup(&decay_timer, df_anomaly_decay_work, 0);
	mod_timer(&decay_timer,
	          jiffies + msecs_to_jiffies(DF_ANOMALY_DECAY_INTERVAL_MS));

	anomaly_initialized = 1;
	pr_info("dialectforge: anomaly engine v2 initialized "
	        "(lockdown: %d, alert: %d, decay: 30min)\n",
	        DF_ANOMALY_LOCKDOWN_THRESHOLD,
	        DF_ANOMALY_NATIVE_ALERT);
	return 0;
}

void df_anomaly_cleanup(void)
{
	struct df_anomaly_record *rec, *tmp;

	anomaly_initialized = 0;
	del_timer_sync(&decay_timer);

	spin_lock(&anomaly_lock);
	list_for_each_entry_safe(rec, tmp, &anomaly_records, list) {
		list_del(&rec->list);
		kfree(rec);
	}
	anomaly_record_count = 0;
	spin_unlock(&anomaly_lock);

	remove_proc_entry("df_anomaly", NULL);
}
