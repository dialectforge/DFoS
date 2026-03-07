/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DialectForge OS — Master Header v0.3.1
 *
 * All core DF structures, constants, and API declarations.
 * The nervous system of the atmosphere.
 *
 * v0.3.1: Fixed arg order for df_seed_derive_labeled,
 *         added .expires/.flags to df_seed,
 *         df_cycle_init takes void,
 *         added df_proc_init/cleanup declarations.
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */
#ifndef _LINUX_DIALECTFORGE_H
#define _LINUX_DIALECTFORGE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/dma-direction.h>

struct page;
struct device;
struct vm_fault;

/* ================================================================
 * Constants
 * ================================================================ */
#define DF_SEED_SIZE        32
#define DF_SEED_BYTES       32    /* Alias used by negotiate.c */
#define DF_DIALECT_SIZE     64
#define DF_MAX_PROPOSAL     16
#define DF_MAX_PROPOSALS    16    /* Alias used by negotiate.c */
#define DF_HMAC_SIZE        32
#define DF_GCM_TAG_SIZE     16
#define DF_GCM_IV_SIZE      12
#define DF_GCM_KEY_SIZE     32

#define DF_VERSION_MAJOR    0
#define DF_VERSION_MINOR    3
#define DF_VERSION_PATCH    1
#define DF_VERSION_STRING   "0.3.1"

/* Software tiers */
#define DF_TIER_NATIVE      0
#define DF_TIER_ADOPTED     1
#define DF_TIER_QUARANTINE  2

/* Cipher modes */
#define DF_CIPHER_XOR_FAST  0
#define DF_CIPHER_AES_GCM   1

/* System status codes */
#define DF_STATUS_UNINIT    0
#define DF_STATUS_ACTIVE    1
#define DF_STATUS_ROTATING  2
#define DF_STATUS_LOCKDOWN  3
#define DF_STATUS_ERROR     4

/* Cycle engine defaults */
#define DF_CYCLE_DEFAULT_MS 30000
#define DF_CYCLE_JITTER_MS  5000

/* Anomaly event types */
#define DF_EVENT_INVALID_SEED       0
#define DF_EVENT_TIER_VIOLATION     1
#define DF_EVENT_RAPID_ROTATION     2
#define DF_EVENT_NEGOTIATION_FAIL   3
#define DF_EVENT_CIPHER_FAIL        4
#define DF_EVENT_REPLAY_DETECT      5
#define DF_EVENT_MAX                6

#define DF_ANOMALY_THRESHOLD  200

/* ================================================================
 * Core Structures
 * ================================================================ */

/*
 * 256-bit seed: the atomic unit of DF identity.
 * .bytes[] and .data[] are aliases for the same 32 bytes.
 */
struct df_seed {
        union {
                u8 bytes[DF_SEED_SIZE];
                u8 data[DF_SEED_SIZE];
        };
        u64 generation;
        ktime_t created;        /* When seed was born */
        ktime_t expires;        /* 0 = no expiry, else ktime deadline */
        u32 tier;               /* DF_TIER_* */
        u32 flags;              /* Bit 0 = revoked */
        bool revoked;
};

/*
 * Current dialect state — a living cipher context.
 */
struct df_dialect {
        struct df_seed seed;
        u8 cipher_key[DF_GCM_KEY_SIZE];
        u8 cipher_iv[DF_GCM_IV_SIZE];
        u32 cipher_mode;        /* DF_CIPHER_* */
        u64 cycle_count;
        ktime_t cycle_start;
        u32 status;             /* DF_STATUS_* */
        spinlock_t lock;
};

/* Per-process DF context */
struct df_context {
        struct df_seed seed;
        struct df_dialect dialect;
        u32 tier;
        u64 parent_seed_gen;
};

/* Negotiation state */
struct df_negotiation {
        struct df_seed proposals[DF_MAX_PROPOSALS];
        int proposal_count;
        u32 quorum_required;
        u8 xor_aggregate[DF_SEED_BYTES];
        struct df_seed consensus;
        int status;             /* 0=pending, 1=complete */
        ktime_t started;
        ktime_t deadline;
        bool complete;
};

/* Cycle configuration */
struct df_cycle_config {
        u32 interval_ms;
        u32 jitter_ms;
        u32 emergency_interval_ms;
        bool auto_rotate;
        bool active;
};

/* Anomaly tracking */
struct df_anomaly_entry {
        u64             context_id;
        u64             score;
        u64             event_count;
        ktime_t         last_event;
        struct hlist_node node;
};

/* ================================================================
 * System-wide State
 * ================================================================ */
struct df_system {
        struct df_seed root_seed;
        struct df_dialect system_dialect;
        struct df_cycle_config cycle_cfg;
        u32 status;
        ktime_t boot_time;
        u64 total_rotations;
        u64 total_seeds_generated;
        spinlock_t lock;
};

/* ================================================================
 * Core — df/core.c
 * ================================================================ */
struct df_system *df_get_system(void);
int __init df_init(void);
int df_dialect_create(struct df_dialect *dialect, const struct df_seed *seed);
int df_dialect_derive_keys(struct df_dialect *dialect);
void df_dialect_destroy(struct df_dialect *dialect);

/* ================================================================
 * Seed — df/seed.c
 *
 * IMPORTANT: df_seed_derive_labeled arg order is:
 *   (parent, label, label_len, child)
 * NOT (parent, child, label, label_len)
 * ================================================================ */
int df_seed_init(void);
void df_seed_cleanup(void);
int df_seed_generate(struct df_seed *seed, u32 tier);
int df_seed_derive(const struct df_seed *parent, struct df_seed *child);
int df_seed_derive_labeled(const struct df_seed *parent,
                           const char *label, size_t label_len,
                           struct df_seed *child);
int df_seed_derive_keys(const struct df_seed *seed, u64 cycle,
                        u8 *key_out, u8 *iv_out);
int df_seed_revoke(struct df_seed *seed);
bool df_seed_is_valid(const struct df_seed *seed);

/* ================================================================
 * Cipher — df/cipher.c
 * ================================================================ */
int df_cipher_init(void);
void df_cipher_cleanup(void);
int df_cipher_encrypt(struct df_dialect *d, const u8 *in, size_t in_len,
                      u8 *out, size_t *out_len);
int df_cipher_decrypt(struct df_dialect *d, const u8 *in, size_t in_len,
                      u8 *out, size_t *out_len);
int df_cipher_set_mode(struct df_dialect *d, u32 mode);
void df_cipher_xor_keystream(u8 *data, size_t len,
                             const struct df_seed *seed, u64 counter);

/* ================================================================
 * Cycle — df/cycle.c  (takes void, not config ptr)
 * ================================================================ */
int __init df_cycle_init(void);
u64 df_cycle_get_count(void);
unsigned long df_cycle_get_interval(void);
void df_cycle_emergency_rotate(void);
int df_cycle_register_hook(void (*hook)(u64 cycle));

/* ================================================================
 * Negotiate — df/negotiate.c
 * ================================================================ */
int df_negotiate_begin(struct df_negotiation *neg, u32 quorum);
int df_negotiate_add_proposal(struct df_negotiation *neg,
                              const struct df_seed *proposal);
int df_negotiate_derive_consensus(struct df_negotiation *neg);
bool df_negotiate_is_complete(const struct df_negotiation *neg);

/* ================================================================
 * Anomaly — df/anomaly.c
 * ================================================================ */
int df_anomaly_init(void);
void df_anomaly_cleanup(void);
int df_anomaly_report(u32 event_type, u64 context_id);
u64 df_anomaly_get_score(u64 context_id);
int df_anomaly_reset(u64 context_id);

/* ================================================================
 * Sysctl — df/sysctl.c
 * ================================================================ */
int df_sysctl_init(void);
void df_sysctl_cleanup(void);
u32 df_sysctl_get_cycle_ms(void);
u32 df_sysctl_get_jitter_ms(void);
u32 df_sysctl_get_cipher_mode(void);
u32 df_sysctl_get_debug_level(void);

/* ================================================================
 * Compress — df/compress.c
 * ================================================================ */
int df_compress_init(void);
int df_compress(const u8 *in, size_t in_len, u8 *out, size_t *out_len);
int df_decompress(const u8 *in, size_t in_len, u8 *out, size_t *out_len);

/* ================================================================
 * Filesystem — fs/dialectfs/
 * ================================================================ */
int __init dialectfs_init(void);
void __exit dialectfs_exit(void);


/* ────────────────────────────────────────────────────────────
 * Phase 3: Quarantine & LSM additions
 * ──────────────────────────────────────────────────────────── */

/* Forward declaration — full definition in linux/sched.h.
 * This avoids circular include: sched.h includes us for df_task_context,
 * we need task_struct for function prototypes below. */
struct task_struct;

/* Tier constants — these may already exist from Phase 1/2.
 * If so, the patch_file guard will skip this block.         */
#ifndef DF_TIER_NATIVE
#define DF_TIER_NATIVE      0   /* Born on DFOS, full citizen         */
#define DF_TIER_ADOPTED     1   /* Promoted via dfpkg/dfctl           */
#define DF_TIER_QUARANTINE  2   /* Untrusted, ephemeral visa          */
#endif

/* Quarantine zone descriptor */
struct df_quarantine_zone {
    struct df_seed      seed;           /* Ephemeral quarantine seed      */
    u8                  tier;           /* DF_TIER_*                      */
    u64                 created_ns;     /* ktime_get_ns() at creation     */
    u64                 ttl_ns;         /* Time-to-live in nanoseconds    */
    u32                 zone_id;        /* Unique zone identifier         */
    pid_t               owner_pid;      /* Process that owns this zone    */
    atomic_t            refcount;       /* Active references              */
    struct list_head    list;           /* Global zone list               */
    spinlock_t          lock;
};

/* Per-process DialectForge context.
 * NOTE: The actual field in task_struct is defined inline in sched.h
 * to avoid circular includes. This struct mirrors that layout and is
 * used for stack variables and function parameters. The seed_bytes
 * field maps directly to df_seed.bytes[]. */
struct df_task_context {
    u8                  seed_bytes[32]; /* 256-bit seed material          */
    u8                  tier;           /* DF_TIER_*                      */
    u32                 generation;     /* Seed generation (depth in tree)*/
    u32                 zone_id;        /* Quarantine zone (0 = none)     */
    u64                 seed_born_ns;   /* When this seed was derived     */
    u8                  flags;          /* DF_TASKF_* below               */
};

#define DF_TASKF_SEED_VALID     0x01    /* Seed has been initialized      */
#define DF_TASKF_QUARANTINED    0x02    /* In quarantine zone             */
#define DF_TASKF_PROMOTED       0x04    /* Was quarantine, now adopted    */
#define DF_TASKF_CLEARTEXT      0x08    /* Translator mode: skip XOR      */

/* Quarantine configuration */
#define DF_QUARANTINE_TTL_DEFAULT_MS   300000  /* 5 minutes default TTL  */
#define DF_QUARANTINE_MAX_ZONES        256     /* Max concurrent zones   */

/* ── Quarantine API ── */
int  df_quarantine_init(void);
void df_quarantine_cleanup(void);
void df_quarantine_sweep(void);
struct df_seed *df_get_system_root_seed(void);
struct df_quarantine_zone *df_quarantine_zone_create(pid_t pid);
void df_quarantine_zone_destroy(struct df_quarantine_zone *zone);
struct df_quarantine_zone *df_quarantine_zone_find(u32 zone_id);
int  df_quarantine_check_expiry(struct df_quarantine_zone *zone);
int  df_quarantine_promote(pid_t pid, u8 new_tier);

/* ── LSM API ── */

/* ── Process context API ── */
int  df_task_context_init(struct task_struct *task, struct task_struct *parent);
void df_task_context_cleanup(struct task_struct *task);
int  df_task_check_ipc_compat(struct task_struct *sender,
                               struct task_struct *receiver);

/* ── dfctl proc interface ── */
int  df_dfctl_proc_init(void);
void df_dfctl_proc_cleanup(void);

/* ── Anomaly API additions ── */
void df_anomaly_log_quarantine_event(pid_t pid, const char *event, int score);


/* ══ Phase 4: Network Adapter ══ */
struct df_net_peer;
int  df_net_init(void);
void df_net_exit(void);
struct df_net_peer *df_net_find_peer(__be32 ip);
struct df_net_peer *df_net_handle_proposal(__be32 peer_ip, const u8 *their_seed);
int  df_net_encode(struct df_net_peer *p, u8 *data, u32 len);
int  df_net_decode(struct df_net_peer *p, u8 *data, u32 len);
/* ══ Phase 5: Memory Protection ══ */

#define DF_MEMF_PAGES_ENCODED  (1 << 0)
#define DF_MEMF_DMA_TRACKED    (1 << 1)
#define DF_MEMF_FORK_PENDING   (1 << 2)
#define DF_MEMF_REENCODE_PENDING (1 << 3)

int  df_mem_encode_page(struct page *page, struct task_struct *task,
                        unsigned long vaddr);
int  df_mem_decode_page(struct page *page, struct task_struct *task,
                        unsigned long vaddr);
void df_mem_context_switch(struct task_struct *prev,
                           struct task_struct *next);
void df_mem_schedule_protect(struct task_struct *task);
void df_mem_exec_reset(void);
struct df_active_page;  /* forward decl for pre_fork/post_fork */
struct df_active_page *df_mem_pre_fork(struct mm_struct *mm,
                                       unsigned int *count_out);
void df_mem_post_fork_parent(struct mm_struct *mm,
                             struct df_active_page *snapshot,
                             unsigned int count);
int  df_mem_fork_init(struct task_struct *child,
                      struct task_struct *parent);
int  df_mem_cow_page(struct page *new_page, struct page *old_page,
                     struct task_struct *new_owner,
                     struct task_struct *old_owner,
                     unsigned long vaddr);
void df_mem_exit_cleanup(struct task_struct *task);
int  df_mem_dma_check(struct page *page, enum dma_data_direction dir,
                      struct device *dev);
bool df_mem_has_hw_backend(void);
bool df_mem_is_enabled(void);
int  df_mem_decode_fault(struct vm_fault *vmf);
int  df_mem_pte_decode_fault(struct vm_fault *vmf);
void df_mem_track_active_page(struct mm_struct *mm, struct page *page,
                              unsigned long vaddr);
void df_mem_decode_vma_range(struct mm_struct *mm, unsigned long start,
                             unsigned long end);
void df_mem_proc_read_encode(char *buf, size_t len,
                             const u8 *seed_bytes, unsigned long addr);


/* ── Post-quantum (Kyber-768) ── */
struct df_kyber_keypair;
int  df_kyber_keygen(struct df_kyber_keypair *kp);
int  df_kyber_encaps(u8 *ct, u8 *ss, const u8 *pk);
int  df_kyber_decaps(u8 *ss, const u8 *ct, const u8 *sk);
int  df_kyber_seed_exchange(u8 *our_seed, const u8 *peer_pk,
                            const u8 *our_sk, u8 *ct_out,
                            bool is_initiator);

/* ── AF_DIALECTFORGE protocol ── */
int  df_proto_init(void);
void df_proto_exit(void);

#endif /* _LINUX_DIALECTFORGE_H */
