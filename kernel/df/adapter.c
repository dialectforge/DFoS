// SPDX-License-Identifier: GPL-2.0
/*
 * df/adapter.c — DialectForge Network Adapter
 *
 * Keystream derivation, peer management, XOR consensus handshake.
 * Ported from DialectEngine.swift, extended to full-payload XOR.
 *
 * Wire format for DF-to-DF tunnel:
 *   No headers. No protocol identifiers. Just XOR(payload, keystream).
 *   Observer sees: random bytes. That's it.
 *
 * Handshake:
 *   A -> B: 32 bytes (seed_A, looks random)
 *   B -> A: 32 bytes (seed_B, looks random)
 *   Both compute: shared_seed = seed_A XOR seed_B
 *   Nobody transmits the shared seed. Math handles it.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <crypto/sha2.h>
#include <linux/dialectforge.h>

/* Constants */
#define DF_NET_CYCLE_SEC        30
#define DF_NET_SEED_LEN         32
#define DF_NET_KS_BLOCKS        16
#define DF_NET_KS_LEN           (DF_NET_SEED_LEN * DF_NET_KS_BLOCKS)
#define DF_NET_MAX_PEERS        64

/* Keystream: seed + time_slot + block_index -> SHA256 per block */
struct df_net_keystream {
	u8	key[DF_NET_KS_LEN];
	u32	len;
	u64	time_slot;
};

/* Peer: one connected DF node */
struct df_net_peer {
	u8			peer_seed[DF_NET_SEED_LEN];
	u8			shared_seed[DF_NET_SEED_LEN];
	__be32			peer_ip;
	struct df_net_keystream	ks;
	u64			established_ns;
	u64			last_rx_ns;
	u32			packets_tx;
	u32			packets_rx;
	bool			active;
	spinlock_t		lock;
};

/* Global state */
static struct df_net_peer	df_peers[DF_NET_MAX_PEERS];
static int			df_peer_count;
static DEFINE_SPINLOCK(df_peer_lock);
static u8			df_local_proposal[DF_NET_SEED_LEN];
static bool			df_proposal_ready;

/* Time slot: same concept as DialectEngine's floor(time/interval) */
static u64 df_net_time_slot(void)
{
	return ktime_get_real_seconds() / DF_NET_CYCLE_SEC;
}

/* Derive keystream from seed + slot. 16 blocks of SHA256 = 512 bytes. */
static void df_net_derive_ks(const u8 *seed, u64 slot,
			     struct df_net_keystream *ks)
{
	struct sha256_state ctx;
	__le64 slot_le = cpu_to_le64(slot);
	__le32 blk_le;
	int i;

	for (i = 0; i < DF_NET_KS_BLOCKS; i++) {
		blk_le = cpu_to_le32(i);
		sha256_init(&ctx);
		sha256_update(&ctx, seed, DF_NET_SEED_LEN);
		sha256_update(&ctx, (u8 *)&slot_le, sizeof(slot_le));
		sha256_update(&ctx, (u8 *)&blk_le, sizeof(blk_le));
		sha256_final(&ctx, &ks->key[i * SHA256_DIGEST_SIZE]);
	}
	ks->len = DF_NET_KS_LEN;
	ks->time_slot = slot;
}

/* XOR payload with keystream. Same op for encode and decode. */
static void df_net_xor(u8 *data, u32 len, const struct df_net_keystream *ks)
{
	u32 i;
	for (i = 0; i < len; i++)
		data[i] ^= ks->key[i % ks->len];
}

/* Refresh keystream if time slot changed */
static void df_net_refresh_ks(struct df_net_peer *peer)
{
	u64 slot = df_net_time_slot();
	unsigned long flags;

	if (peer->ks.time_slot == slot)
		return;

	spin_lock_irqsave(&peer->lock, flags);
	if (peer->ks.time_slot != slot) {
		df_net_derive_ks(peer->shared_seed, slot, &peer->ks);
		pr_debug("df_net: keystream cycled for %pI4 slot=%llu\n",
			 &peer->peer_ip, slot);
	}
	spin_unlock_irqrestore(&peer->lock, flags);
}

/* Find peer by IP */
static struct df_net_peer *df_net_find_peer_internal(__be32 ip)
{
	int i;
	for (i = 0; i < df_peer_count; i++) {
		if (df_peers[i].active && df_peers[i].peer_ip == ip)
			return &df_peers[i];
	}
	return NULL;
}

/* Public: find peer */
struct df_net_peer *df_net_find_peer(__be32 ip)
{
	return df_net_find_peer_internal(ip);
}

/* Add peer after handshake */
static struct df_net_peer *df_net_add_peer(__be32 ip, const u8 *shared)
{
	struct df_net_peer *p;
	unsigned long flags;

	spin_lock_irqsave(&df_peer_lock, flags);
	if (df_peer_count >= DF_NET_MAX_PEERS) {
		spin_unlock_irqrestore(&df_peer_lock, flags);
		pr_warn("df_net: peer table full\n");
		return NULL;
	}

	p = &df_peers[df_peer_count];
	memset(p, 0, sizeof(*p));
	spin_lock_init(&p->lock);
	p->peer_ip = ip;
	memcpy(p->shared_seed, shared, DF_NET_SEED_LEN);
	p->established_ns = ktime_get_ns();
	p->active = true;

	df_net_derive_ks(shared, df_net_time_slot(), &p->ks);
	df_peer_count++;
	spin_unlock_irqrestore(&df_peer_lock, flags);

	pr_info("df_net: peer added %pI4 (slot=%llu)\n",
		&ip, p->ks.time_slot);
	return p;
}

/* Generate local proposal at boot */
static int df_net_gen_proposal(void)
{
	get_random_bytes(df_local_proposal, DF_NET_SEED_LEN);
	df_proposal_ready = true;
	pr_info("df_net: local proposal generated\n");
	return 0;
}

/* Handle incoming proposal: XOR consensus */
struct df_net_peer *df_net_handle_proposal(__be32 peer_ip, const u8 *their_seed)
{
	u8 shared[DF_NET_SEED_LEN];
	struct df_net_peer *p;
	int i;

	if (!df_proposal_ready) {
		pr_warn("df_net: proposal received but not ready\n");
		return NULL;
	}

	p = df_net_find_peer_internal(peer_ip);
	if (p && p->active)
		return p;

	/* XOR consensus */
	for (i = 0; i < DF_NET_SEED_LEN; i++)
		shared[i] = df_local_proposal[i] ^ their_seed[i];

	p = df_net_add_peer(peer_ip, shared);
	if (p)
		memcpy(p->peer_seed, their_seed, DF_NET_SEED_LEN);

	pr_info("df_net: handshake complete with %pI4\n", &peer_ip);
	return p;
}

/* Encode packet for tunnel */
int df_net_encode(struct df_net_peer *p, u8 *data, u32 len)
{
	if (!p || !p->active)
		return -ENOENT;
	df_net_refresh_ks(p);
	df_net_xor(data, len, &p->ks);
	p->packets_tx++;
	return 0;
}

/* Decode packet from tunnel */
int df_net_decode(struct df_net_peer *p, u8 *data, u32 len)
{
	if (!p || !p->active)
		return -ENOENT;
	df_net_refresh_ks(p);
	df_net_xor(data, len, &p->ks);
	p->packets_rx++;
	p->last_rx_ns = ktime_get_ns();
	return 0;
}

/* /proc/df_net */
static int df_net_proc_show(struct seq_file *m, void *v)
{
	int i;
	u64 now = ktime_get_ns();

	seq_printf(m, "=== DialectForge Network ===\n");
	seq_printf(m, "time_slot:    %llu\n", df_net_time_slot());
	seq_printf(m, "cycle:        %d sec\n", DF_NET_CYCLE_SEC);
	seq_printf(m, "keystream:    %d bytes\n", DF_NET_KS_LEN);
	seq_printf(m, "peers:        %d / %d\n", df_peer_count, DF_NET_MAX_PEERS);
	seq_printf(m, "proposal:     %s\n", df_proposal_ready ? "ready" : "no");

	for (i = 0; i < df_peer_count; i++) {
		struct df_net_peer *p = &df_peers[i];
		if (!p->active) continue;
		seq_printf(m, "  peer[%d] %pI4 tx=%u rx=%u age=%llus slot=%llu\n",
			   i, &p->peer_ip, p->packets_tx, p->packets_rx,
			   (now - p->established_ns) / 1000000000ULL,
			   p->ks.time_slot);
	}
	return 0;
}

static int df_net_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, df_net_proc_show, NULL);
}

static const struct proc_ops df_net_proc_ops = {
	.proc_open    = df_net_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* Init */
int df_net_init(void)
{
	memset(df_peers, 0, sizeof(df_peers));
	df_peer_count = 0;
	df_proposal_ready = false;

	df_net_gen_proposal();
	proc_create("df_net", 0400, NULL, &df_net_proc_ops);

	pr_debug("df_net: adapter initialized (cycle=%ds ks=%d bytes)\n",
		DF_NET_CYCLE_SEC, DF_NET_KS_LEN);
	return 0;
}

/* Exit */
void df_net_exit(void)
{
	remove_proc_entry("df_net", NULL);
	memzero_explicit(df_peers, sizeof(df_peers));
	memzero_explicit(df_local_proposal, sizeof(df_local_proposal));
	df_peer_count = 0;
	pr_info("df_net: shutdown, keys wiped\n");
}
