// SPDX-License-Identifier: GPL-2.0
/*
 * DialectForge OS - Cipher Engine
 * Copyright (c) 2026 John Dean Martin - Patent Pending
 *
 * df/cipher.c - Dual-mode encryption: XOR fast + AES-256-GCM secure
 *
 * Two roads through the same atmosphere.
 *   XOR_FAST: highway - bulk data, memory-bandwidth speed.
 *   AES_GCM:  armored tunnel - authenticated, tamper-proof.
 *
 * Both derive keys from HKDF. Both rotate every dialect cycle.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/err.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/dialectforge.h>

#define AES_GCM_KEY_SIZE    32
#define AES_GCM_IV_SIZE     12
#define AES_GCM_TAG_SIZE    16
#define XOR_KEYSTREAM_BLOCK 32

static struct crypto_aead  *df_aead_tfm;
static struct crypto_shash *df_hmac_tfm;
static bool cipher_initialized;

/* ------------------------------------------------------------------
 *  XOR Fast Path - HMAC-SHA256 counter-mode keystream
 * ------------------------------------------------------------------ */

static int df_xor_keystream(const u8 *key, u32 key_len,
                            const u8 *iv, u32 iv_len,
                            u8 *stream, size_t len)
{
	SHASH_DESC_ON_STACK(desc, df_hmac_tfm);
	u8 block[XOR_KEYSTREAM_BLOCK];
	u32 counter = 0;
	size_t off = 0, n;
	int ret;

	if (!cipher_initialized || !df_hmac_tfm)
		return -ENODEV;

	desc->tfm = df_hmac_tfm;
	ret = crypto_shash_setkey(df_hmac_tfm, key, key_len);
	if (ret)
		return ret;

	while (off < len) {
		ret = crypto_shash_init(desc);
		if (ret) goto out;
		ret = crypto_shash_update(desc, (u8 *)&counter, 4);
		if (ret) goto out;
		if (iv && iv_len)
			ret = crypto_shash_update(desc, iv, iv_len);
		if (ret) goto out;
		ret = crypto_shash_final(desc, block);
		if (ret) goto out;

		n = min_t(size_t, len - off, XOR_KEYSTREAM_BLOCK);
		memcpy(stream + off, block, n);
		off += n;
		counter++;
	}
	ret = 0;
out:
	memzero_explicit(block, sizeof(block));
	shash_desc_zero(desc);
	return ret;
}

static int df_xor_crypt(struct df_dialect *d, const u8 *in,
                        size_t len, u8 *out)
{
	u8 *ks;
	size_t i;
	int ret;

	if (!d || !in || !out || !len)
		return -EINVAL;

	ks = kmalloc(len, GFP_KERNEL);
	if (!ks)
		return -ENOMEM;

	ret = df_xor_keystream(d->cipher_key, 32, d->cipher_iv, DF_GCM_IV_SIZE, ks, len);
	if (ret) {
		kfree(ks);
		return ret;
	}

	for (i = 0; i < len; i++)
		out[i] = in[i] ^ ks[i];

	memzero_explicit(ks, len);
	kfree(ks);
	return 0;
}

/* ------------------------------------------------------------------
 *  AES-256-GCM Secure Path
 * ------------------------------------------------------------------ */

static int df_aes_encrypt(struct df_dialect *d, const u8 *in,
                          size_t in_len, u8 *out, size_t *out_len)
{
	struct aead_request *req;
	struct scatterlist sg;
	u8 *buf;
	size_t buf_len = in_len + AES_GCM_TAG_SIZE;
	int ret;

	if (!cipher_initialized || !df_aead_tfm)
		return -ENODEV;
	if (*out_len < buf_len)
		return -ENOSPC;

	ret = crypto_aead_setkey(df_aead_tfm, d->cipher_key, AES_GCM_KEY_SIZE);
	if (ret) return ret;
	crypto_aead_setauthsize(df_aead_tfm, AES_GCM_TAG_SIZE);

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) return -ENOMEM;

	memcpy(buf, in, in_len);
	memset(buf + in_len, 0, AES_GCM_TAG_SIZE);
	sg_init_one(&sg, buf, buf_len);

	req = aead_request_alloc(df_aead_tfm, GFP_KERNEL);
	if (!req) { ret = -ENOMEM; goto free_buf; }

	aead_request_set_crypt(req, &sg, &sg, in_len, d->cipher_iv);
	aead_request_set_ad(req, 0);
	ret = crypto_aead_encrypt(req);
	if (!ret) {
		memcpy(out, buf, buf_len);
		*out_len = buf_len;
	}

	aead_request_free(req);
free_buf:
	memzero_explicit(buf, buf_len);
	kfree(buf);
	return ret;
}

static int df_aes_decrypt(struct df_dialect *d, const u8 *in,
                          size_t in_len, u8 *out, size_t *out_len)
{
	struct aead_request *req;
	struct scatterlist sg;
	u8 *buf;
	size_t pt_len;
	int ret;

	if (!cipher_initialized || !df_aead_tfm)
		return -ENODEV;
	if (in_len < AES_GCM_TAG_SIZE)
		return -EINVAL;

	pt_len = in_len - AES_GCM_TAG_SIZE;
	if (*out_len < pt_len)
		return -ENOSPC;

	ret = crypto_aead_setkey(df_aead_tfm, d->cipher_key, AES_GCM_KEY_SIZE);
	if (ret) return ret;
	crypto_aead_setauthsize(df_aead_tfm, AES_GCM_TAG_SIZE);

	buf = kmalloc(in_len, GFP_KERNEL);
	if (!buf) return -ENOMEM;

	memcpy(buf, in, in_len);
	sg_init_one(&sg, buf, in_len);

	req = aead_request_alloc(df_aead_tfm, GFP_KERNEL);
	if (!req) { ret = -ENOMEM; goto free_buf; }

	aead_request_set_crypt(req, &sg, &sg, in_len, d->cipher_iv);
	aead_request_set_ad(req, 0);
	ret = crypto_aead_decrypt(req);
	if (ret == -EBADMSG)
		pr_warn("dialectforge: AES-GCM auth failed - wrong dialect\n");
	if (!ret) {
		memcpy(out, buf, pt_len);
		*out_len = pt_len;
	}

	aead_request_free(req);
free_buf:
	memzero_explicit(buf, in_len);
	kfree(buf);
	return ret;
}

/* ------------------------------------------------------------------
 *  Public API
 * ------------------------------------------------------------------ */

int df_cipher_encrypt(struct df_dialect *d, const u8 *in, size_t in_len,
                      u8 *out, size_t *out_len)
{
	if (!d) return -EINVAL;
	switch (d->cipher_mode) {
	case DF_CIPHER_XOR_FAST:
		if (!out_len || *out_len < in_len) return -ENOSPC;
		*out_len = in_len;
		return df_xor_crypt(d, in, in_len, out);
	case DF_CIPHER_AES_GCM:
		return df_aes_encrypt(d, in, in_len, out, out_len);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(df_cipher_encrypt);

int df_cipher_decrypt(struct df_dialect *d, const u8 *in, size_t in_len,
                      u8 *out, size_t *out_len)
{
	if (!d) return -EINVAL;
	switch (d->cipher_mode) {
	case DF_CIPHER_XOR_FAST:
		if (!out_len || *out_len < in_len) return -ENOSPC;
		*out_len = in_len;
		return df_xor_crypt(d, in, in_len, out);
	case DF_CIPHER_AES_GCM:
		return df_aes_decrypt(d, in, in_len, out, out_len);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(df_cipher_decrypt);

int df_cipher_set_mode(struct df_dialect *d, u32 mode)
{
	unsigned long flags;
	if (!d) return -EINVAL;
	if (mode != DF_CIPHER_XOR_FAST && mode != DF_CIPHER_AES_GCM)
		return -EINVAL;
	spin_lock_irqsave(&d->lock, flags);
	d->cipher_mode = mode;
	spin_unlock_irqrestore(&d->lock, flags);
	pr_info("dialectforge: cipher -> %s\n",
	        mode == DF_CIPHER_XOR_FAST ? "XOR_FAST" : "AES_GCM");
	return 0;
}
EXPORT_SYMBOL_GPL(df_cipher_set_mode);

int df_cipher_init(void)
{
	df_aead_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(df_aead_tfm)) {
		pr_err("dialectforge: AES-GCM alloc failed (%ld)\n",
		       PTR_ERR(df_aead_tfm));
		df_aead_tfm = NULL;
		return -ENOMEM;
	}
	df_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(df_hmac_tfm)) {
		pr_err("dialectforge: HMAC-SHA256 alloc failed (%ld)\n",
		       PTR_ERR(df_hmac_tfm));
		crypto_free_aead(df_aead_tfm);
		df_aead_tfm = NULL;
		df_hmac_tfm = NULL;
		return -ENOMEM;
	}
	cipher_initialized = true;
	pr_info("dialectforge: cipher engine ready (AES-256-GCM + HMAC-SHA256)\n");
	return 0;
}
EXPORT_SYMBOL_GPL(df_cipher_init);

void df_cipher_cleanup(void)
{
	cipher_initialized = false;
	if (df_aead_tfm) { crypto_free_aead(df_aead_tfm); df_aead_tfm = NULL; }
	if (df_hmac_tfm) { crypto_free_shash(df_hmac_tfm); df_hmac_tfm = NULL; }
}
EXPORT_SYMBOL_GPL(df_cipher_cleanup);
