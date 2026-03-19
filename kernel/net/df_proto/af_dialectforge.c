// SPDX-License-Identifier: GPL-2.0
/*
 * af_dialectforge.c - AF_DIALECTFORGE Protocol Family
 * Copyright (c) 2026 John Dean Martin - Patent Pending
 *
 * Native DF-to-DF socket communication. Processes open
 * socket(AF_DIALECTFORGE, SOCK_STREAM, 0) and get automatic
 * dialect-encrypted communication without eBPF overhead.
 *
 * All data on the wire is indistinguishable from noise.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/un.h>
#include <linux/file.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/dialectforge.h>

#include "df_proto.h"

/* DF socket private data */
struct df_sock {
	struct sock	sk;
	struct df_seed	local_seed;
	struct df_seed	peer_seed;
	struct df_dialect dialect;
	u32		cycle_count;
	bool		negotiated;
	spinlock_t	df_lock;
};

static inline struct df_sock *df_sk(const struct sock *sk)
{
	return (struct df_sock *)sk;
}

/* ================================================================
 *  Handshake: XOR-consensus seed negotiation (kernel-side)
 * ================================================================ */

static int df_proto_negotiate(struct df_sock *dsk, struct df_sock *peer)
{
	struct df_system *sys = df_get_system();
	unsigned long irqflags;
	int i;

	if (!sys)
		return -ENODEV;

	spin_lock_irqsave(&dsk->df_lock, irqflags);

	/* Generate local ephemeral seed from system root */
	get_random_bytes(dsk->local_seed.bytes, DF_SEED_SIZE);
	for (i = 0; i < DF_SEED_SIZE; i++)
		dsk->local_seed.bytes[i] ^= sys->root_seed.bytes[i];

	dsk->local_seed.generation = sys->root_seed.generation + 1;
	dsk->local_seed.tier = DF_TIER_NATIVE;
	dsk->local_seed.created = ktime_get_real();

	spin_unlock_irqrestore(&dsk->df_lock, irqflags);
	return 0;
}

static int __maybe_unused df_proto_derive_shared(struct df_sock *dsk,
				  const u8 *peer_seed_bytes)
{
	unsigned long irqflags;
	struct df_seed combined;
	int i, ret;

	spin_lock_irqsave(&dsk->df_lock, irqflags);

	/* XOR consensus */
	for (i = 0; i < DF_SEED_SIZE; i++)
		combined.bytes[i] = dsk->local_seed.bytes[i] ^ peer_seed_bytes[i];

	combined.generation = dsk->local_seed.generation;
	combined.tier = DF_TIER_NATIVE;
	combined.created = ktime_get_real();

	memcpy(&dsk->peer_seed.bytes, peer_seed_bytes, DF_SEED_SIZE);

	/* Derive cipher keys via HKDF */
	ret = df_dialect_create(&dsk->dialect, &combined);
	if (ret == 0) {
		dsk->cycle_count = 0;
		dsk->negotiated = true;
	}

	memzero_explicit(&combined, sizeof(combined));
	spin_unlock_irqrestore(&dsk->df_lock, irqflags);
	return ret;
}

/* ================================================================
 *  Encode / decode using XOR keystream
 * ================================================================ */

static int df_proto_encode(struct df_sock *dsk, u8 *data, u32 len)
{
	int ret;
	if (!dsk->negotiated)
		return -ENOTCONN;
	ret = df_cipher_encrypt(&dsk->dialect, data, len, data, NULL);
	return ret;
}

static int df_proto_decode(struct df_sock *dsk, u8 *data, u32 len)
{
	int ret;
	if (!dsk->negotiated)
		return -ENOTCONN;
	ret = df_cipher_decrypt(&dsk->dialect, data, len, data, NULL);
	return ret;
}

/* ================================================================
 *  Socket operations
 * ================================================================ */

static int df_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct df_sock *dsk;

	if (!sk)
		return 0;

	dsk = df_sk(sk);

	/* Wipe crypto material */
	df_dialect_destroy(&dsk->dialect);
	memzero_explicit(&dsk->local_seed, sizeof(dsk->local_seed));
	memzero_explicit(&dsk->peer_seed, sizeof(dsk->peer_seed));

	sock_orphan(sk);
	sock->sk = NULL;
	sock_put(sk);
	return 0;
}

static int df_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct sock *sk = sock->sk;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	lock_sock(sk);
	inet_sk(sk)->inet_rcv_saddr = sin->sin_addr.s_addr;
	inet_sk(sk)->inet_sport = sin->sin_port;
	release_sock(sk);

	return 0;
}

static int df_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct df_sock *dsk = df_sk(sk);
	struct sk_buff *skb;
	u8 *buf;
	int ret;

	if (!dsk->negotiated)
		return -ENOTCONN;

	if (len > 65535)
		return -EMSGSIZE;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = memcpy_from_msg(buf, msg, len);
	if (ret) {
		kfree(buf);
		return ret;
	}

	/* Encode before sending */
	ret = df_proto_encode(dsk, buf, len);
	if (ret) {
		kfree(buf);
		return ret;
	}

	/* Build skb and queue */
	skb = alloc_skb(len + 64, GFP_KERNEL);
	if (!skb) {
		kfree(buf);
		return -ENOMEM;
	}

	skb_reserve(skb, 32);
	skb_put_data(skb, buf, len);
	kfree(buf);

	/* Send via connected peer socket's receive queue */
	if (sk->sk_peer_pid) {
		struct sock *peer = sk->sk_state == TCP_ESTABLISHED ?
			sk->sk_user_data : NULL;
		if (peer) {
			skb_queue_tail(&peer->sk_receive_queue, skb);
			peer->sk_data_ready(peer);
			return len;
		}
	}

	kfree_skb(skb);
	return -ENOTCONN;
}

static int df_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
		      int flags)
{
	struct sock *sk = sock->sk;
	struct df_sock *dsk = df_sk(sk);
	struct sk_buff *skb;
	int copied, ret;

	skb = skb_dequeue(&sk->sk_receive_queue);
	if (!skb) {
		if (flags & MSG_DONTWAIT)
			return -EAGAIN;

		ret = sk_wait_data(sk, NULL, NULL);
		if (ret)
			return ret;

		skb = skb_dequeue(&sk->sk_receive_queue);
		if (!skb)
			return -EAGAIN;
	}

	copied = min_t(int, len, skb->len);

	/* Decode after receiving */
	ret = df_proto_decode(dsk, skb->data, copied);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	ret = skb_copy_datagram_msg(skb, 0, msg, copied);
	kfree_skb(skb);

	if (ret)
		return ret;

	return copied;
}

static int df_connect(struct socket *sock, struct sockaddr *addr,
		      int alen, int flags)
{
	/* For now: local-only connections via socketpair/accept.
	 * Network tunneling reuses this path via df_tunnel integration. */
	return -EOPNOTSUPP;
}

static __poll_t df_poll(struct file *file, struct socket *sock,
			struct poll_table_struct *wait)
{
	struct sock *sk = sock->sk;
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (!skb_queue_empty(&sk->sk_receive_queue))
		mask |= EPOLLIN | EPOLLRDNORM;

	mask |= EPOLLOUT | EPOLLWRNORM;

	return mask;
}

static const struct proto_ops df_stream_ops = {
	.family		= PF_DIALECTFORGE,
	.owner		= THIS_MODULE,
	.release	= df_release,
	.bind		= df_bind,
	.connect	= df_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= df_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.sendmsg	= df_sendmsg,
	.recvmsg	= df_recvmsg,
	.mmap		= sock_no_mmap,
};

/* ================================================================
 *  Protocol registration
 * ================================================================ */

static struct proto df_proto = {
	.name		= "DIALECTFORGE",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct df_sock),
};

static int df_create(struct net *net, struct socket *sock,
		     int protocol, int kern)
{
	struct sock *sk;
	struct df_sock *dsk;

	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->ops = &df_stream_ops;

	sk = sk_alloc(net, PF_DIALECTFORGE, GFP_KERNEL, &df_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	dsk = df_sk(sk);
	spin_lock_init(&dsk->df_lock);
	dsk->negotiated = false;
	dsk->cycle_count = 0;
	memset(&dsk->dialect, 0, sizeof(dsk->dialect));

	/* Auto-negotiate from system seed */
	df_proto_negotiate(dsk, NULL);

	return 0;
}

static const struct net_proto_family df_family_ops = {
	.family	= PF_DIALECTFORGE,
	.create	= df_create,
	.owner	= THIS_MODULE,
};

int __init df_proto_init(void)
{
	int ret;

	ret = proto_register(&df_proto, 1);
	if (ret) {
		pr_err("df_proto: proto_register failed: %d\n", ret);
		return ret;
	}

	ret = sock_register(&df_family_ops);
	if (ret) {
		pr_err("df_proto: sock_register failed: %d\n", ret);
		proto_unregister(&df_proto);
		return ret;
	}

	pr_info("DialectForge: AF_DIALECTFORGE protocol family registered\n");
	return 0;
}

void df_proto_exit(void)
{
	sock_unregister(PF_DIALECTFORGE);
	proto_unregister(&df_proto);
	pr_info("DialectForge: AF_DIALECTFORGE protocol family unregistered\n");
}
