// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS - Negotiation Engine
 * Copyright (c) 2026 John Dean Martin - Patent Pending
 *
 * df/negotiate.c - XOR aggregate consensus negotiation
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/dialectforge.h>

int df_negotiate_begin(struct df_negotiation *neg, u32 quorum)
{
	if (!neg || quorum == 0 || quorum > DF_MAX_PROPOSALS)
		return -EINVAL;

	memset(neg, 0, sizeof(*neg));
	neg->quorum_required = quorum;
	neg->started = ktime_get_real();
	neg->deadline = ktime_add_ms(neg->started, 30000);

	pr_info("dialectforge: negotiation started, quorum=%u\n", quorum);
	return 0;
}
EXPORT_SYMBOL_GPL(df_negotiate_begin);

int df_negotiate_add_proposal(struct df_negotiation *neg,
			      const struct df_seed *proposal)
{
	int i;

	if (!neg || !proposal)
		return -EINVAL;
	if (neg->proposal_count >= neg->quorum_required)
		return -ENOSPC;

	memcpy(&neg->proposals[neg->proposal_count], proposal,
	       sizeof(struct df_seed));

	/* XOR aggregate: each proposal folds into consensus */
	for (i = 0; i < DF_SEED_BYTES; i++)
		neg->xor_aggregate[i] ^= proposal->bytes[i];

	neg->proposal_count++;

	pr_info("dialectforge: proposal %u/%u added (gen=%llu)\n",
		neg->proposal_count, neg->quorum_required,
		proposal->generation);
	return 0;
}
EXPORT_SYMBOL_GPL(df_negotiate_add_proposal);

int df_negotiate_derive_consensus(struct df_negotiation *neg)
{
	if (!neg)
		return -EINVAL;
	if (neg->proposal_count < neg->quorum_required)
		return -EAGAIN;

	memcpy(neg->consensus.bytes, neg->xor_aggregate, DF_SEED_BYTES);
	neg->consensus.created = ktime_get_real();
	neg->consensus.tier = DF_TIER_NATIVE;
	neg->status = 1;

	pr_info("dialectforge: consensus reached (%u proposals)\n",
		neg->proposal_count);
	return 0;
}
EXPORT_SYMBOL_GPL(df_negotiate_derive_consensus);

bool df_negotiate_is_complete(const struct df_negotiation *neg)
{
	return neg && neg->status == 1;
}
EXPORT_SYMBOL_GPL(df_negotiate_is_complete);
