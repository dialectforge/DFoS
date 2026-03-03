// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS — dialectfs crypto operations
 *
 * Page-level encrypt/decrypt using AES-256-CTR keystream derived
 * from per-file HKDF seeds.  Fisher-Yates sector hopping.
 *
 * v2: Replaced homebrew XOR keystream (repeated every 32 bytes)
 *     with proper AES-256-CTR via kernel skcipher API.
 *     Each page gets: HKDF(file_seed, page_index) → 32-byte key,
 *     then AES-256-CTR(key, IV=page_index) → unique keystream.
 *
 * Copyright (C) 2026 John Dean Martin. OS: GPL. Protocol: Proprietary.
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/dialectforge.h>
#include "dialectfs.h"

#define AES_CTR_KEY_SIZE   32   /* AES-256 */
#define AES_CTR_IV_SIZE    16   /* CTR mode IV */

/*
 * Module-level crypto transform — allocated once at mount time
 * (or first use), freed at module exit.
 */
static struct crypto_skcipher *dfs_ctr_tfm;
static bool dfs_crypto_ready;

/*
 * dfs_crypto_init() — allocate the AES-256-CTR transform.
 * Called from dialectfs_init() (super.c) before any I/O.
 */
int dfs_crypto_init(void)
{
	if (dfs_crypto_ready)
		return 0;

	dfs_ctr_tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);
	if (IS_ERR(dfs_ctr_tfm)) {
		pr_err("dialectfs: AES-CTR alloc failed (%ld)\n",
		       PTR_ERR(dfs_ctr_tfm));
		dfs_ctr_tfm = NULL;
		return -ENOMEM;
	}

	dfs_crypto_ready = true;
	pr_info("dialectfs: AES-256-CTR crypto engine ready\n");
	return 0;
}

void dfs_crypto_cleanup(void)
{
	if (dfs_ctr_tfm) {
		crypto_free_skcipher(dfs_ctr_tfm);
		dfs_ctr_tfm = NULL;
	}
	dfs_crypto_ready = false;
}

/*
 * dfs_derive_keystream() — generate a keystream of `len` bytes
 *   using AES-256-CTR.
 *
 * Steps:
 *   1. HKDF-derive a per-page seed from the file seed + page_index
 *      (this part was already correct — unique 256-bit key per page)
 *   2. Use that 32-byte seed as the AES-256 key
 *   3. Build a 16-byte IV from the page_index
 *   4. Encrypt a zero buffer → pure keystream output
 *
 * Unlike the old code (which repeated every 32 bytes), AES-CTR
 * generates a cryptographically unique keystream up to 2^39 bytes
 * per (key, IV) pair.
 */
static int dfs_derive_keystream(u8 *keystream, size_t len,
				struct df_seed *seed, u64 page_index)
{
	struct df_seed page_seed;
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	u8 iv[AES_CTR_IV_SIZE];
	u8 context[32];
	int ret;

	if (unlikely(!dfs_crypto_ready || !dfs_ctr_tfm))
		return -ENODEV;

	/* Step 1: Derive per-page seed via HKDF (this was already good) */
	memcpy(context, "dialectfs-page\0\0", 16);
	memcpy(context + 16, &page_index, 8);
	memset(context + 24, 0, 8);

	ret = df_seed_derive_labeled(seed, (const char *)context, 24,
				     &page_seed);
	if (ret)
		return ret;

	/* Step 2: Set the derived 32-byte seed as AES-256 key */
	ret = crypto_skcipher_setkey(dfs_ctr_tfm, page_seed.data,
				    AES_CTR_KEY_SIZE);
	if (ret)
		goto out_zero;

	/* Step 3: Build IV from page_index (unique per page) */
	memset(iv, 0, AES_CTR_IV_SIZE);
	memcpy(iv, &page_index, sizeof(page_index));

	/* Step 4: Encrypt zeros → keystream
	 * CTR mode: E(key, IV+counter) for each 16-byte block.
	 * Encrypting zeros gives us the raw keystream. */
	memset(keystream, 0, len);
	sg_init_one(&sg, keystream, len);

	req = skcipher_request_alloc(dfs_ctr_tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_zero;
	}

	skcipher_request_set_crypt(req, &sg, &sg, len, iv);
	ret = crypto_skcipher_encrypt(req);
	skcipher_request_free(req);

out_zero:
	memzero_explicit(&page_seed, sizeof(page_seed));
	memzero_explicit(context, sizeof(context));
	return ret;
}

/*
 * dfs_encrypt_page() — encrypt a page of data in place
 *
 * XOR with AES-256-CTR derived keystream.
 * Each page gets a unique keystream via HKDF + AES-CTR.
 */
void dfs_encrypt_page(void *data, size_t len, struct df_seed *seed,
		      u64 page_index)
{
	u8 *keystream;
	unsigned int i;
	u8 *buf = data;
	int ret;

	keystream = kmalloc(len, GFP_KERNEL);
	if (!keystream) {
		pr_warn_ratelimited("dialectfs: keystream alloc failed, "
				    "page %llu unencrypted\n", page_index);
		return;
	}

	ret = dfs_derive_keystream(keystream, len, seed, page_index);
	if (ret) {
		pr_warn_ratelimited("dialectfs: AES-CTR failed (%d), "
				    "page %llu unencrypted\n", ret, page_index);
		kfree(keystream);
		return;
	}

	for (i = 0; i < len; i++)
		buf[i] ^= keystream[i];

	memzero_explicit(keystream, len);
	kfree(keystream);
}

/*
 * dfs_decrypt_page() — decrypt a page of data in place
 *
 * XOR is its own inverse. Same operation as encrypt.
 */
void dfs_decrypt_page(void *data, size_t len, struct df_seed *seed,
		      u64 page_index)
{
	/* XOR is symmetric — encrypt == decrypt */
	dfs_encrypt_page(data, len, seed, page_index);
}

/*
 * dfs_sector_hop_permute() — Fisher-Yates shuffle of sector map
 *
 * Given an array of sector indices, permute them using HKDF-derived
 * randomness from the seed.  Each position gets its own derived
 * 8-byte random value via labeled HKDF, ensuring unbiased shuffling
 * even for large sector counts.
 */
void dfs_sector_hop_permute(u64 *map, int count, struct df_seed *seed)
{
	struct df_seed hop_seed;
	char label[32];
	int i, j;
	u64 tmp, rand_val;

	/* Initialize identity map */
	for (i = 0; i < count; i++)
		map[i] = i;

	/* Fisher-Yates using HKDF-derived randomness per position */
	for (i = count - 1; i > 0; i--) {
		/* Derive unique random value for this swap position */
		snprintf(label, sizeof(label), "hop:%d", i);
		if (df_seed_derive_labeled(seed, label, strlen(label),
					  &hop_seed))
			continue; /* skip on error, don't break the map */

		/* Use first 8 bytes of derived seed as random u64 */
		memcpy(&rand_val, hop_seed.data, sizeof(rand_val));
		j = (int)(rand_val % (u64)(i + 1));

		/* Swap */
		tmp = map[i];
		map[i] = map[j];
		map[j] = tmp;
	}

	memzero_explicit(&hop_seed, sizeof(hop_seed));
}
