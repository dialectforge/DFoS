// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS - Seed Lifecycle Manager
 * Copyright (c) 2026 John Dean Martin - Patent Pending
 *
 * df/seed.c - HKDF-SHA256 hierarchical seed derivation
 *
 * Seeds are DNA. Root seed is the genome. Every child inherits from
 * parent through HKDF with a label describing purpose. Revoking a
 * parent kills the entire bloodline.
 *
 * Hierarchy: root -> volume -> directory -> file
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>
#include <crypto/hash.h>
#include <linux/dialectforge.h>

static struct crypto_shash *df_hkdf_hmac;
static bool seed_initialized;

/* HKDF-Extract: PRK = HMAC-SHA256(salt, IKM) */
static int hkdf_extract(const u8 *salt, size_t salt_len,
                        const u8 *ikm, size_t ikm_len, u8 *prk)
{
	SHASH_DESC_ON_STACK(desc, df_hkdf_hmac);
	int ret;

	desc->tfm = df_hkdf_hmac;
	ret = crypto_shash_setkey(df_hkdf_hmac, salt, salt_len);
	if (ret) return ret;
	ret = crypto_shash_init(desc);
	if (ret) goto out;
	ret = crypto_shash_update(desc, ikm, ikm_len);
	if (ret) goto out;
	ret = crypto_shash_final(desc, prk);
out:
	shash_desc_zero(desc);
	return ret;
}

/* HKDF-Expand: OKM = HMAC-SHA256(PRK, info || counter) */
static int hkdf_expand(const u8 *prk, size_t prk_len,
                       const u8 *info, size_t info_len,
                       u8 *okm, size_t okm_len)
{
	SHASH_DESC_ON_STACK(desc, df_hkdf_hmac);
	u8 block[32];
	u8 counter = 1;
	size_t off = 0, n;
	int ret;

	desc->tfm = df_hkdf_hmac;
	ret = crypto_shash_setkey(df_hkdf_hmac, prk, prk_len);
	if (ret) return ret;

	while (off < okm_len) {
		ret = crypto_shash_init(desc);
		if (ret) goto out;
		if (off > 0) {
			ret = crypto_shash_update(desc, block, 32);
			if (ret) goto out;
		}
		if (info && info_len) {
			ret = crypto_shash_update(desc, info, info_len);
			if (ret) goto out;
		}
		ret = crypto_shash_update(desc, &counter, 1);
		if (ret) goto out;
		ret = crypto_shash_final(desc, block);
		if (ret) goto out;

		n = min_t(size_t, okm_len - off, 32);
		memcpy(okm + off, block, n);
		off += n;
		counter++;
	}
	ret = 0;
out:
	memzero_explicit(block, sizeof(block));
	shash_desc_zero(desc);
	return ret;
}

/* ------------------------------------------------------------------
 *  Public API
 * ------------------------------------------------------------------ */

int df_seed_init(void)
{
	df_hkdf_hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(df_hkdf_hmac)) {
		pr_err("dialectforge: HKDF alloc failed (%ld)\n",
		       PTR_ERR(df_hkdf_hmac));
		df_hkdf_hmac = NULL;
		return -ENOMEM;
	}
	seed_initialized = true;
	pr_info("dialectforge: seed manager ready (HKDF-SHA256)\n");
	return 0;
}
EXPORT_SYMBOL_GPL(df_seed_init);

void df_seed_cleanup(void)
{
	seed_initialized = false;
	if (df_hkdf_hmac) {
		crypto_free_shash(df_hkdf_hmac);
		df_hkdf_hmac = NULL;
	}
}
EXPORT_SYMBOL_GPL(df_seed_cleanup);

int df_seed_generate(struct df_seed *seed, u32 tier)
{
	if (!seed) return -EINVAL;
	get_random_bytes(seed->bytes, DF_SEED_BYTES);
	seed->created = ktime_get_real();
	seed->expires = 0;
	seed->tier = tier;
	seed->flags = 0;
	return 0;
}
EXPORT_SYMBOL_GPL(df_seed_generate);

/*
 * Derive child from parent via HKDF-SHA256.
 * Deterministic: same parent + same label = same child.
 */
int df_seed_derive_labeled(const struct df_seed *parent,
                           const char *label, size_t label_len,
                           struct df_seed *child)
{
	u8 salt[DF_SEED_BYTES];
	u8 prk[32];
	int ret;

	if (!parent || !child || !seed_initialized)
		return -EINVAL;
	if (!df_seed_is_valid(parent))
		return -EKEYREVOKED;

	/* Salt must be deterministic for reproducible derivation.
	 * Derive salt from label so same inputs → same output. */
	memset(salt, 0, DF_SEED_BYTES);
	if (label && label_len > 0)
		memcpy(salt, label, label_len < DF_SEED_BYTES ? label_len : DF_SEED_BYTES);

	ret = hkdf_extract(salt, DF_SEED_BYTES,
	                   parent->bytes, DF_SEED_BYTES, prk);
	if (ret) goto out;

	ret = hkdf_expand(prk, 32, (const u8 *)label, label_len,
	                  child->bytes, DF_SEED_BYTES);
	if (ret) goto out;

	child->created = ktime_get_real();
	child->expires = 0;
	child->tier = parent->tier;
	child->flags = 0;

out:
	memzero_explicit(salt, sizeof(salt));
	memzero_explicit(prk, sizeof(prk));
	return ret;
}
EXPORT_SYMBOL_GPL(df_seed_derive_labeled);

/* Legacy wrapper for Phase 1 compatibility */
int df_seed_derive(const struct df_seed *parent, struct df_seed *child)
{
	return df_seed_derive_labeled(parent, "default", 7, child);
}
EXPORT_SYMBOL_GPL(df_seed_derive);

/*
 * Derive cipher keys + IV from a seed for a given cycle count.
 * Deterministic: same seed + cycle = same keys.
 * Used by both the DF core and dialectfs.
 */
int df_seed_derive_keys(const struct df_seed *seed, u64 cycle,
                        u8 *key_out, u8 *iv_out)
{
	u8 info[48]; /* "cipher-key:" + cycle as bytes */
	int ret;

	if (!seed || !key_out || !iv_out || !seed_initialized)
		return -EINVAL;

	/* Derive 32-byte cipher key */
	memcpy(info, "cipher-key:", 11);
	memcpy(info + 11, &cycle, 8);
	ret = hkdf_expand(seed->bytes, DF_SEED_BYTES, info, 19, key_out, 32);
	if (ret) return ret;

	/* Derive 16-byte IV */
	memcpy(info, "cipher-iv::", 11);
	memcpy(info + 11, &cycle, 8);
	ret = hkdf_expand(seed->bytes, DF_SEED_BYTES, info, 19, iv_out, 16);
	return ret;
}
EXPORT_SYMBOL_GPL(df_seed_derive_keys);

int df_seed_revoke(struct df_seed *seed)
{
	if (!seed) return -EINVAL;
	memset(seed->bytes, 0, DF_SEED_BYTES);
	seed->expires = ktime_get_real();
	seed->flags |= 0x1; /* REVOKED */
	pr_info("dialectforge: seed revoked\n");
	return 0;
}
EXPORT_SYMBOL_GPL(df_seed_revoke);

bool df_seed_is_valid(const struct df_seed *seed)
{
	int i;
	if (!seed) return false;
	for (i = 0; i < DF_SEED_BYTES; i++)
		if (seed->bytes[i] != 0)
			goto not_zero;
	return false;
not_zero:
	if (seed->expires != 0 &&
	    ktime_after(ktime_get_real(), seed->expires))
		return false;
	return true;
}
EXPORT_SYMBOL_GPL(df_seed_is_valid);
