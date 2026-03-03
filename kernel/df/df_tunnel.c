/*
 * df_tunnel.c — DialectForge Tunnel Daemon
 *
 * Handles DF-to-DF tunnels between DFOS machines.
 *   1. Handshake: 32 bytes each way, XOR consensus
 *   2. Tunnel: TUN device <-> TCP, all XOR-encoded
 *   On the wire: noise. No headers. No protocol.
 *
 * Build:  gcc -O2 -o df_tunnel df_tunnel.c -lpthread -lssl -lcrypto
 * Run:    ./df_tunnel --listen  10.1.0.1
 *         ./df_tunnel --connect 10.1.0.2 10.0.0.1
 *
 * STATIC: gcc -O2 -static -o df_tunnel df_tunnel.c -lpthread -lssl -lcrypto -ldl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <openssl/sha.h>

#define SEED_LEN    32
#define KS_BLOCKS   16
#define KS_LEN      (SEED_LEN * KS_BLOCKS)
#define CYCLE_SEC   30
#define HS_PORT     51830
#define MAX_FRAME   65535
#define TUN_MTU     1400

struct keystream {
	unsigned char key[KS_LEN];
	unsigned long slot;
};

struct tunnel {
	int              tun_fd;
	int              sock_fd;
	unsigned char    shared_seed[SEED_LEN];
	struct keystream ks;
	volatile int     running;
	unsigned long    tx, rx;
};

static struct tunnel T;

static unsigned long time_slot(void)
{
	return (unsigned long)time(NULL) / CYCLE_SEC;
}

static void derive_ks(const unsigned char *seed, unsigned long slot,
		      struct keystream *ks)
{
	unsigned char buf[SEED_LEN + 12];
	int i;
	memcpy(buf, seed, SEED_LEN);
	memcpy(buf + SEED_LEN, &slot, 8);
	for (i = 0; i < KS_BLOCKS; i++) {
		memcpy(buf + SEED_LEN + 8, &i, 4);
		SHA256(buf, sizeof(buf), &ks->key[i * 32]);
	}
	ks->slot = slot;
}

static void xor_buf(unsigned char *data, unsigned int len,
		    const struct keystream *ks)
{
	unsigned int i;
	for (i = 0; i < len; i++)
		data[i] ^= ks->key[i % KS_LEN];
}

static void refresh_ks(void)
{
	unsigned long s = time_slot();
	if (T.ks.slot != s) {
		derive_ks(T.shared_seed, s, &T.ks);
		printf("[CYCLE] Dialect rotated -> slot %lu\n", s);
	}
}

static int tun_open(void)
{
	struct ifreq ifr;
	int fd, flags;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) { perror("open tun"); return -1; }

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, "df0", IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		perror("ioctl tun");
		close(fd);
		return -1;
	}

	/* FIX: Set non-blocking so poll() works properly */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	printf("[TUN] Opened %s (non-blocking)\n", ifr.ifr_name);
	return fd;
}

static void tun_configure(const char *ip, const char *peer_ip)
{
	struct ifreq ifr;
	struct sockaddr_in *sa;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "df0", IFNAMSIZ);

	/* Set local address */
	sa = (struct sockaddr_in *)&ifr.ifr_addr;
	sa->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &sa->sin_addr);
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
		perror("SIOCSIFADDR");

	/* Set netmask */
	sa = (struct sockaddr_in *)&ifr.ifr_netmask;
	sa->sin_family = AF_INET;
	inet_pton(AF_INET, "255.255.255.0", &sa->sin_addr);
	if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0)
		perror("SIOCSIFNETMASK");

	/* Set point-to-point destination (the OTHER end) */
	if (peer_ip) {
		sa = (struct sockaddr_in *)&ifr.ifr_dstaddr;
		sa->sin_family = AF_INET;
		inet_pton(AF_INET, peer_ip, &sa->sin_addr);
		if (ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0)
			perror("SIOCSIFDSTADDR");
		printf("[TUN] P-t-P dest = %s\n", peer_ip);
	}

	/* Bring interface up */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
			perror("SIOCSIFFLAGS");
	}

	close(fd);
	printf("[TUN] df0 = %s/24\n", ip);
}

static void enable_forwarding(void)
{
	int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
	if (fd >= 0) {
		write(fd, "1", 1);
		close(fd);
		printf("[NET] IP forwarding enabled\n");
	} else {
		printf("[NET] Could not enable IP forwarding (non-fatal)\n");
	}
}

static int recv_exact(int fd, void *buf, int n)
{
	int got = 0, r;
	while (got < n) {
		r = recv(fd, (char *)buf + got, n - got, 0);
		if (r <= 0) return r;
		got += r;
	}
	return got;
}

static int do_handshake(int sock)
{
	unsigned char mine[SEED_LEN], theirs[SEED_LEN];
	int fd, i;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0 || read(fd, mine, SEED_LEN) != SEED_LEN) {
		perror("urandom"); if (fd >= 0) close(fd); return -1;
	}
	close(fd);

	if (send(sock, mine, SEED_LEN, 0) != SEED_LEN) {
		perror("send proposal"); return -1;
	}
	if (recv_exact(sock, theirs, SEED_LEN) != SEED_LEN) {
		perror("recv proposal"); return -1;
	}

	for (i = 0; i < SEED_LEN; i++)
		T.shared_seed[i] = mine[i] ^ theirs[i];

	printf("[HANDSHAKE] Done.\n");
	printf("  mine:   %02x%02x%02x%02x...\n",
	       mine[0], mine[1], mine[2], mine[3]);
	printf("  theirs: %02x%02x%02x%02x...\n",
	       theirs[0], theirs[1], theirs[2], theirs[3]);
	printf("  shared: %02x%02x%02x%02x... (never on wire)\n",
	       T.shared_seed[0], T.shared_seed[1],
	       T.shared_seed[2], T.shared_seed[3]);

	memset(mine, 0, SEED_LEN);
	memset(theirs, 0, SEED_LEN);
	return 0;
}

/* TUN -> encode -> TCP */
/* FIX: Use poll() instead of blocking read() */
static void *thread_out(void *arg)
{
	unsigned char pkt[MAX_FRAME], frame[MAX_FRAME + 2];
	struct pollfd pfd;
	int n, ret;
	(void)arg;

	pfd.fd = T.tun_fd;
	pfd.events = POLLIN;

	printf("[THREAD_OUT] TUN reader started (poll mode)\n");

	while (T.running) {
		/* Wait up to 100ms for data on TUN */
		ret = poll(&pfd, 1, 100);
		if (ret < 0) {
			if (errno == EINTR) continue;
			perror("poll tun");
			break;
		}
		if (ret == 0) continue;  /* timeout, loop and check T.running */

		n = read(T.tun_fd, pkt, sizeof(pkt));
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			if (T.running) perror("tun read");
			break;
		}
		if (n == 0) continue;

		refresh_ks();
		xor_buf(pkt, n, &T.ks);

		frame[0] = (n >> 8) & 0xFF;
		frame[1] = n & 0xFF;
		memcpy(frame + 2, pkt, n);

		if (send(T.sock_fd, frame, n + 2, 0) != n + 2) {
			if (T.running) perror("send");
			break;
		}
		T.tx++;
		if (T.tx == 1)
			printf("[THREAD_OUT] First packet sent!\n");
	}
	return NULL;
}

/* TCP -> decode -> TUN */
static void *thread_in(void *arg)
{
	unsigned char hdr[2], pkt[MAX_FRAME];
	int plen;
	(void)arg;

	printf("[THREAD_IN] TCP reader started\n");

	while (T.running) {
		if (recv_exact(T.sock_fd, hdr, 2) != 2) {
			if (T.running) printf("[TUNNEL] Peer gone\n");
			break;
		}
		plen = (hdr[0] << 8) | hdr[1];
		if (plen <= 0 || plen > MAX_FRAME) {
			printf("[TUNNEL] Bad frame: %d\n", plen);
			break;
		}
		if (recv_exact(T.sock_fd, pkt, plen) != plen) {
			printf("[TUNNEL] Short read\n");
			break;
		}

		refresh_ks();
		xor_buf(pkt, plen, &T.ks);

		if (write(T.tun_fd, pkt, plen) != plen) {
			if (T.running) perror("tun write");
		}
		T.rx++;
		if (T.rx == 1)
			printf("[THREAD_IN] First packet received!\n");
	}
	T.running = 0;
	return NULL;
}

static void sig_handler(int s) { (void)s; T.running = 0; }

int main(int argc, char **argv)
{
	int listen_mode, sock;
	const char *local_ip, *peer_ip = NULL;
	const char *tun_local, *tun_remote;
	pthread_t tout, tin;

	if (argc < 3) {
		printf("Usage:\n");
		printf("  %s --listen  <local_tun_ip>\n", argv[0]);
		printf("  %s --connect <local_tun_ip> <peer_eth_ip>\n", argv[0]);
		printf("\nExample:\n");
		printf("  VM-A: %s --listen  10.1.0.1\n", argv[0]);
		printf("  VM-B: %s --connect 10.1.0.2 10.0.0.1\n", argv[0]);
		return 1;
	}

	listen_mode = (strcmp(argv[1], "--listen") == 0);
	local_ip = argv[2];
	peer_ip = (argc > 3) ? argv[3] : NULL;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("========================================\n");
	printf("  DialectForge Tunnel — Phase 4\n");
	printf("  No headers. No protocol. Just noise.\n");
	printf("========================================\n\n");

	/* Open TUN (now non-blocking) */
	T.tun_fd = tun_open();
	if (T.tun_fd < 0) return 1;

	/* Figure out tunnel endpoint IPs */
	tun_local = local_ip;
	if (strcmp(local_ip, "10.1.0.1") == 0)
		tun_remote = "10.1.0.2";
	else
		tun_remote = "10.1.0.1";

	tun_configure(tun_local, tun_remote);

	/* Enable IP forwarding */
	enable_forwarding();

	if (listen_mode) {
		struct sockaddr_in addr, pa;
		socklen_t plen = sizeof(pa);
		int lfd, opt = 1;

		printf("[LISTEN] Port %d...\n", HS_PORT);
		lfd = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(HS_PORT);
		addr.sin_addr.s_addr = INADDR_ANY;
		if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("bind"); return 1;
		}
		listen(lfd, 1);
		printf("[LISTEN] Waiting for peer...\n");
		sock = accept(lfd, (struct sockaddr *)&pa, &plen);
		close(lfd);
		if (sock < 0) { perror("accept"); return 1; }
		printf("[LISTEN] Peer: %s\n", inet_ntoa(pa.sin_addr));
	} else {
		struct sockaddr_in addr;
		printf("[CONNECT] -> %s:%d\n", peer_ip, HS_PORT);
		sock = socket(AF_INET, SOCK_STREAM, 0);
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(HS_PORT);
		inet_pton(AF_INET, peer_ip, &addr.sin_addr);
		if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			perror("connect"); return 1;
		}
		printf("[CONNECT] Connected.\n");
	}

	printf("\n[HANDSHAKE] Exchanging proposals...\n");
	if (do_handshake(sock) != 0) {
		close(sock); return 1;
	}

	derive_ks(T.shared_seed, time_slot(), &T.ks);
	printf("[KEYSTREAM] Ready (slot=%lu, %d bytes)\n\n",
	       T.ks.slot, KS_LEN);

	T.sock_fd = sock;
	T.running = 1;
	T.tx = T.rx = 0;

	printf("=== TUNNEL LIVE === Everything is noise. ===\n\n");

	pthread_create(&tout, NULL, thread_out, NULL);
	pthread_create(&tin, NULL, thread_in, NULL);

	while (T.running) {
		sleep(5);
		printf("[STATS] tx=%lu rx=%lu\n", T.tx, T.rx);
	}

	pthread_join(tin, NULL);
	T.running = 0;
	pthread_join(tout, NULL);

	memset(T.shared_seed, 0, SEED_LEN);
	memset(&T.ks, 0, sizeof(T.ks));
	close(sock);
	close(T.tun_fd);
	printf("[DONE] Keys wiped.\n");
	return 0;
}
