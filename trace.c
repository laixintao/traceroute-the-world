#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ipdb.h"

#ifndef AF_XDP
#define AF_XDP 44
#endif

#define FRAME_SIZE              2048U
#define NUM_FRAMES              4096U
#define RING_SIZE               2048U
#define TX_FRAME_BASE           RING_SIZE
#define TX_NUM_FRAMES           (NUM_FRAMES - TX_FRAME_BASE)
#define DEFAULT_PAYLOAD_LEN     32U
#define DEFAULT_INTERVAL_USEC   1000000U
#define DEFAULT_REPLY_TIMEOUT_MS 3000U
#define DEFAULT_TTL             64U
#define DEFAULT_BPF_OBJ         "icmp_reply_drop_kern.o"
#define DEFAULT_OUTPUT          "replies.bin"
#define MAX_SEEN_IPS            65536

extern unsigned int if_nametoindex(const char *ifname);

/* ── rings ───────────────────────────────────────────────────────────────── */

struct xsk_ring {
	uint32_t *producer;
	uint32_t *consumer;
	uint32_t *flags;
	void     *desc;
	uint32_t  size;
	uint32_t  mask;
};

struct xsk_socket {
	int              fd;
	void            *umem;
	size_t           umem_len;
	struct xsk_ring  rx;
	struct xsk_ring  tx;
	struct xsk_ring  fq;
	struct xsk_ring  cq;
};

/* ── config ──────────────────────────────────────────────────────────────── */

struct app_config {
	const char    *ifname;
	const char    *bpf_obj;
	const char    *output;
	const char    *ignore_from;
	uint32_t       queue_id;
	uint32_t       count;
	uint32_t       interval_usec;
	uint32_t       payload_len;
	uint32_t       ttl;
	uint32_t       reply_timeout_ms;
	bool           busy;
	bool           force_copy;
	bool           force_zerocopy;
	uint8_t        src_mac[ETH_ALEN];
	uint8_t        dst_mac[ETH_ALEN];
	bool           have_src_mac;
	bool           have_dst_mac;
	struct in_addr src_ip;
	struct in_addr dst_ip;
	uint32_t       dst_start;
	uint32_t       dst_end;
	bool           have_src_ip;
	bool           have_dst_ip;
	bool           have_dst_subnet;
};

/* ── global state shared between main and signal handler ─────────────────── */

static volatile int      g_running  = 1;
static struct bpf_object *g_bpf_obj  = NULL;
static int               g_ifindex   = 0;

/* ── seen-IP tracking (only written by reader thread) ────────────────────── */

static uint32_t g_seen_ips[MAX_SEEN_IPS];
static int      g_seen_count = 0;

/* ── signal handler ──────────────────────────────────────────────────────── */

static void sig_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

/* ── usage / arg parsing ─────────────────────────────────────────────────── */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --dev IFACE --dst-mac xx:xx:xx:xx:xx:xx\n"
		"           (--dst-ip A.B.C.D | --dst-subnet CIDR) [options]\n"
		"\n"
		"Options:\n"
		"  --src-ip A.B.C.D         Source IPv4, default: interface IPv4\n"
		"  --src-mac xx:..:xx       Source MAC, default: interface MAC\n"
		"  --queue N                TX queue id, default: 0\n"
		"  --count N                Packets per destination, default: 4\n"
		"  --interval-usec N        Delay between packets (µs), default: 1000000\n"
		"  --payload-len N          ICMP payload bytes, default: 32\n"
		"  --ttl N                  IP TTL, default: 64\n"
		"  --reply-timeout-ms N     Wait after last send (ms), default: 3000\n"
		"  --output PATH            reply bitmap file, default: %s\n"
		"  --ignore-binary-from PATH  skip IPs already set in this ipdb file\n"
		"  --bpf-obj PATH           eBPF object file, default: %s\n"
		"  --copy                   Force XDP copy mode\n"
		"  --zerocopy               Force XDP zero-copy mode\n"
		"  --busy                   Send without sleeping between packets\n",
		prog, DEFAULT_OUTPUT, DEFAULT_BPF_OBJ);
}

static unsigned long parse_ulong(const char *s, const char *name)
{
	char *end = NULL;
	errno = 0;
	unsigned long v = strtoul(s, &end, 0);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	return v;
}

static int parse_mac(const char *s, uint8_t mac[ETH_ALEN])
{
	unsigned int b[ETH_ALEN];
	if (sscanf(s, "%x:%x:%x:%x:%x:%x",
		   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != ETH_ALEN)
		return -1;
	for (int i = 0; i < ETH_ALEN; i++) {
		if (b[i] > 0xff) return -1;
		mac[i] = (uint8_t)b[i];
	}
	return 0;
}

static int parse_cidr(const char *s, uint32_t *start, uint32_t *end)
{
	char buf[INET_ADDRSTRLEN + 4];
	if (strlen(s) >= sizeof(buf)) return -1;
	snprintf(buf, sizeof(buf), "%s", s);

	char *slash = strchr(buf, '/');
	if (!slash || slash == buf || slash[1] == '\0') return -1;
	*slash++ = '\0';

	struct in_addr addr;
	if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

	unsigned long prefix = parse_ulong(slash, "dst-subnet prefix");
	if (prefix > 32) return -1;

	uint32_t ip   = ntohl(addr.s_addr);
	uint32_t mask = prefix == 0 ? 0 : UINT32_MAX << (32 - prefix);
	*start = ip & mask;
	*end   = *start | ~mask;
	return 0;
}

static void parse_args(int argc, char **argv, struct app_config *cfg)
{
	cfg->queue_id          = 0;
	cfg->count             = 4;
	cfg->interval_usec     = DEFAULT_INTERVAL_USEC;
	cfg->payload_len       = DEFAULT_PAYLOAD_LEN;
	cfg->ttl               = DEFAULT_TTL;
	cfg->reply_timeout_ms  = DEFAULT_REPLY_TIMEOUT_MS;
	cfg->output            = DEFAULT_OUTPUT;
	cfg->bpf_obj           = DEFAULT_BPF_OBJ;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dev") && i + 1 < argc) {
			cfg->ifname = argv[++i];
		} else if (!strcmp(argv[i], "--queue") && i + 1 < argc) {
			cfg->queue_id = (uint32_t)parse_ulong(argv[++i], "queue");
		} else if (!strcmp(argv[i], "--count") && i + 1 < argc) {
			cfg->count = (uint32_t)parse_ulong(argv[++i], "count");
		} else if (!strcmp(argv[i], "--interval-usec") && i + 1 < argc) {
			cfg->interval_usec = (uint32_t)parse_ulong(argv[++i], "interval-usec");
		} else if (!strcmp(argv[i], "--payload-len") && i + 1 < argc) {
			cfg->payload_len = (uint32_t)parse_ulong(argv[++i], "payload-len");
		} else if (!strcmp(argv[i], "--ttl") && i + 1 < argc) {
			cfg->ttl = (uint32_t)parse_ulong(argv[++i], "ttl");
		} else if (!strcmp(argv[i], "--reply-timeout-ms") && i + 1 < argc) {
			cfg->reply_timeout_ms = (uint32_t)parse_ulong(argv[++i], "reply-timeout-ms");
		} else if (!strcmp(argv[i], "--output") && i + 1 < argc) {
			cfg->output = argv[++i];
		} else if (!strcmp(argv[i], "--ignore-binary-from") && i + 1 < argc) {
			cfg->ignore_from = argv[++i];
		} else if (!strcmp(argv[i], "--bpf-obj") && i + 1 < argc) {
			cfg->bpf_obj = argv[++i];
		} else if (!strcmp(argv[i], "--src-ip") && i + 1 < argc) {
			if (inet_pton(AF_INET, argv[++i], &cfg->src_ip) != 1) {
				fprintf(stderr, "invalid --src-ip\n"); exit(2);
			}
			cfg->have_src_ip = true;
		} else if (!strcmp(argv[i], "--dst-ip") && i + 1 < argc) {
			if (inet_pton(AF_INET, argv[++i], &cfg->dst_ip) != 1) {
				fprintf(stderr, "invalid --dst-ip\n"); exit(2);
			}
			cfg->have_dst_ip = true;
		} else if (!strcmp(argv[i], "--dst-subnet") && i + 1 < argc) {
			if (parse_cidr(argv[++i], &cfg->dst_start, &cfg->dst_end) != 0) {
				fprintf(stderr, "invalid --dst-subnet\n"); exit(2);
			}
			cfg->have_dst_subnet = true;
		} else if (!strcmp(argv[i], "--src-mac") && i + 1 < argc) {
			if (parse_mac(argv[++i], cfg->src_mac) != 0) {
				fprintf(stderr, "invalid --src-mac\n"); exit(2);
			}
			cfg->have_src_mac = true;
		} else if (!strcmp(argv[i], "--dst-mac") && i + 1 < argc) {
			if (parse_mac(argv[++i], cfg->dst_mac) != 0) {
				fprintf(stderr, "invalid --dst-mac\n"); exit(2);
			}
			cfg->have_dst_mac = true;
		} else if (!strcmp(argv[i], "--copy")) {
			cfg->force_copy = true;
		} else if (!strcmp(argv[i], "--zerocopy")) {
			cfg->force_zerocopy = true;
		} else if (!strcmp(argv[i], "--busy")) {
			cfg->busy = true;
		} else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv[0]); exit(0);
		} else {
			usage(argv[0]); exit(2);
		}
	}

	if (cfg->have_dst_ip) {
		cfg->dst_start = ntohl(cfg->dst_ip.s_addr);
		cfg->dst_end   = cfg->dst_start;
	}

	if (!cfg->ifname || cfg->have_dst_ip == cfg->have_dst_subnet ||
	    !cfg->have_dst_mac || cfg->payload_len > 1400 || cfg->ttl > 255 ||
	    (cfg->force_copy && cfg->force_zerocopy)) {
		usage(argv[0]); exit(2);
	}
}

/* ── interface helpers ───────────────────────────────────────────────────── */

static int get_if_mac(const char *ifname, uint8_t mac[ETH_ALEN])
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	int rc = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (rc < 0) return -1;
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

static int get_if_ipv4(const char *ifname, struct in_addr *addr)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	int rc = ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	if (rc < 0) return -1;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	*addr = sin->sin_addr;
	return 0;
}

/* ── packet builder ──────────────────────────────────────────────────────── */

static uint16_t checksum(const void *data, size_t len)
{
	const uint16_t *p = data;
	uint32_t sum = 0;
	while (len > 1) { sum += *p++; len -= 2; }
	if (len) sum += *(const uint8_t *)p;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static size_t build_icmp_frame(uint8_t *buf, const struct app_config *cfg, uint16_t seq)
{
	struct ethhdr  *eth     = (struct ethhdr *)buf;
	struct iphdr   *ip      = (struct iphdr *)(buf + sizeof(*eth));
	struct icmphdr *icmp    = (struct icmphdr *)(buf + sizeof(*eth) + sizeof(*ip));
	uint8_t        *payload = (uint8_t *)(icmp + 1);

	memcpy(eth->h_dest,   cfg->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, cfg->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	memset(ip, 0, sizeof(*ip));
	ip->version  = 4;
	ip->ihl      = 5;
	ip->ttl      = (uint8_t)cfg->ttl;
	ip->protocol = IPPROTO_ICMP;
	ip->tot_len  = htons((uint16_t)(sizeof(*ip) + sizeof(*icmp) + cfg->payload_len));
	ip->id       = htons(seq);
	ip->saddr    = cfg->src_ip.s_addr;
	ip->daddr    = cfg->dst_ip.s_addr;
	ip->check    = checksum(ip, sizeof(*ip));

	memset(icmp, 0, sizeof(*icmp) + cfg->payload_len);
	icmp->type             = ICMP_ECHO;
	icmp->un.echo.id       = htons((uint16_t)getpid());
	icmp->un.echo.sequence = htons(seq);
	for (uint32_t i = 0; i < cfg->payload_len; i++)
		payload[i] = (uint8_t)i;
	icmp->checksum = checksum(icmp, sizeof(*icmp) + cfg->payload_len);

	return sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) + cfg->payload_len;
}

/* ── AF_XDP ring ops ─────────────────────────────────────────────────────── */

static int ring_needs_wakeup(const struct xsk_ring *r)
{
	return r->flags && (*r->flags & XDP_RING_NEED_WAKEUP);
}

static uint32_t ring_free(const struct xsk_ring *r)
{
	return r->size - (*r->producer - *r->consumer);
}

static void ring_release(struct xsk_ring *r, uint32_t n)
{
	__atomic_store_n(r->consumer, *r->consumer + n, __ATOMIC_RELEASE);
}

static void ring_submit(struct xsk_ring *r, uint32_t n)
{
	__atomic_store_n(r->producer, *r->producer + n, __ATOMIC_RELEASE);
}

static int mmap_ring(int fd, struct xsk_ring *ring, const struct xdp_ring_offset *off,
		     uint32_t ndesc, off_t pgoff, size_t desc_size)
{
	size_t map_sz = off->desc + ndesc * desc_size;
	void  *map    = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
			     MAP_SHARED | MAP_POPULATE, fd, pgoff);
	if (map == MAP_FAILED) return -1;
	ring->producer = map + off->producer;
	ring->consumer = map + off->consumer;
	ring->flags    = off->flags ? map + off->flags : NULL;
	ring->desc     = map + off->desc;
	ring->size     = ndesc;
	ring->mask     = ndesc - 1;
	return 0;
}

static int xsk_open(struct xsk_socket *xsk, const struct app_config *cfg, int ifindex)
{
	memset(xsk, 0, sizeof(*xsk));
	xsk->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (xsk->fd < 0) return -1;

	xsk->umem_len = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&xsk->umem, getpagesize(), xsk->umem_len) != 0) {
		errno = ENOMEM; return -1;
	}
	memset(xsk->umem, 0, xsk->umem_len);

	struct xdp_umem_reg mr = {
		.addr       = (uintptr_t)xsk->umem,
		.len        = xsk->umem_len,
		.chunk_size = FRAME_SIZE,
		.headroom   = 0,
		.flags      = 0,
	};
	if (setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) return -1;
	if (setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING,
		       &(uint32_t){RING_SIZE}, sizeof(uint32_t)) < 0) return -1;
	if (setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING,
		       &(uint32_t){RING_SIZE}, sizeof(uint32_t)) < 0) return -1;
	if (setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_FILL_RING,
		       &(uint32_t){RING_SIZE}, sizeof(uint32_t)) < 0) return -1;
	if (setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
		       &(uint32_t){RING_SIZE}, sizeof(uint32_t)) < 0) return -1;

	struct xdp_mmap_offsets off;
	socklen_t optlen = sizeof(off);
	if (getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) return -1;

	if (mmap_ring(xsk->fd, &xsk->rx, &off.rx, RING_SIZE,
		      XDP_PGOFF_RX_RING, sizeof(struct xdp_desc)) < 0) return -1;
	if (mmap_ring(xsk->fd, &xsk->tx, &off.tx, RING_SIZE,
		      XDP_PGOFF_TX_RING, sizeof(struct xdp_desc)) < 0) return -1;
	if (mmap_ring(xsk->fd, &xsk->fq, &off.fr, RING_SIZE,
		      XDP_UMEM_PGOFF_FILL_RING, sizeof(uint64_t)) < 0) return -1;
	if (mmap_ring(xsk->fd, &xsk->cq, &off.cr, RING_SIZE,
		      XDP_UMEM_PGOFF_COMPLETION_RING, sizeof(uint64_t)) < 0) return -1;

	uint64_t *fq  = xsk->fq.desc;
	uint32_t  prod = *xsk->fq.producer;
	for (uint32_t i = 0; i < RING_SIZE; i++)
		fq[(prod + i) & xsk->fq.mask] = (uint64_t)i * FRAME_SIZE;
	ring_submit(&xsk->fq, RING_SIZE);

	struct sockaddr_xdp sxdp = {
		.sxdp_family   = AF_XDP,
		.sxdp_flags    = XDP_USE_NEED_WAKEUP,
		.sxdp_ifindex  = (uint32_t)ifindex,
		.sxdp_queue_id = cfg->queue_id,
	};
	if (cfg->force_copy)     sxdp.sxdp_flags |= XDP_COPY;
	if (cfg->force_zerocopy) sxdp.sxdp_flags |= XDP_ZEROCOPY;

	return bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
}

static void reap_completions(struct xsk_socket *xsk)
{
	uint32_t prod = __atomic_load_n(xsk->cq.producer, __ATOMIC_ACQUIRE);
	uint32_t cons = *xsk->cq.consumer;
	uint32_t n    = prod - cons;
	if (n) ring_release(&xsk->cq, n);
}

static int send_one(struct xsk_socket *xsk, const struct app_config *cfg,
		    uint32_t frame_idx, uint16_t seq)
{
	while (ring_free(&xsk->tx) == 0) {
		reap_completions(xsk);
		if (ring_free(&xsk->tx) == 0) {
			struct pollfd pfd = {.fd = xsk->fd, .events = POLLOUT};
			(void)poll(&pfd, 1, 10);
		}
	}

	uint32_t  idx  = *xsk->tx.producer & xsk->tx.mask;
	uint64_t  addr = (uint64_t)(TX_FRAME_BASE + (frame_idx % TX_NUM_FRAMES)) * FRAME_SIZE;
	uint8_t  *pkt  = (uint8_t *)xsk->umem + addr;
	size_t    len  = build_icmp_frame(pkt, cfg, seq);

	struct xdp_desc *tx = xsk->tx.desc;
	tx[idx].addr    = addr;
	tx[idx].len     = (uint32_t)len;
	tx[idx].options = 0;
	__atomic_store_n(xsk->tx.producer, *xsk->tx.producer + 1, __ATOMIC_RELEASE);

	if (ring_needs_wakeup(&xsk->tx) || true) {
		if (sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0 &&
		    errno != EBUSY && errno != EAGAIN && errno != ENOBUFS)
			return -1;
	}
	return 0;
}

/* ── XDP program load / unload ───────────────────────────────────────────── */

static int xdp_load(const char *obj_path, int ifindex, int *map_fd_out)
{
	struct bpf_object *obj = bpf_object__open(obj_path);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "bpf_object__open(%s): %s\n", obj_path, strerror(errno));
		return -1;
	}
	if (bpf_object__load(obj) != 0) {
		fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
		bpf_object__close(obj);
		return -1;
	}

	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "xdp_drop_icmp_reply");
	if (!prog) {
		fprintf(stderr, "program 'xdp_drop_icmp_reply' not found in %s\n", obj_path);
		bpf_object__close(obj);
		return -1;
	}

	int prog_fd = bpf_program__fd(prog);
	if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0) {
		perror("bpf_xdp_attach");
		bpf_object__close(obj);
		return -1;
	}

	int map_fd = bpf_object__find_map_fd_by_name(obj, "icmp_reply_ips");
	if (map_fd < 0) {
		fprintf(stderr, "map 'icmp_reply_ips' not found\n");
		bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
		bpf_object__close(obj);
		return -1;
	}

	g_bpf_obj   = obj;
	*map_fd_out = map_fd;
	return 0;
}

static void xdp_unload(void)
{
	if (g_ifindex)
		bpf_xdp_detach(g_ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
	if (g_bpf_obj) {
		bpf_object__close(g_bpf_obj);
		g_bpf_obj = NULL;
	}
}

/* ── reader thread ───────────────────────────────────────────────────────── */

static bool already_seen(uint32_t ip)
{
	for (int i = 0; i < g_seen_count; i++)
		if (g_seen_ips[i] == ip) return true;
	return false;
}

/* Drain whatever is currently in the map, printing newly seen IPs. */
static void poll_map(int map_fd)
{
	uint32_t key = 0, next_key;
	__u64    count;
	char     ip_str[INET_ADDRSTRLEN];
	bool     first = true;

	while (bpf_map_get_next_key(map_fd,
				    first ? NULL : &key,
				    &next_key) == 0) {
		first = false;
		key   = next_key;

		if (bpf_map_lookup_elem(map_fd, &key, &count) != 0)
			continue;

		if (!already_seen(key)) {
			ipdb_mark(ntohl(key));
			inet_ntop(AF_INET, &key, ip_str, sizeof(ip_str));
			printf("[reply] %-20s (%llu packet(s))\n",
			       ip_str, (unsigned long long)count);
			fflush(stdout);
			if (g_seen_count < MAX_SEEN_IPS)
				g_seen_ips[g_seen_count++] = key;
		}
	}
}

static void *reader_thread_fn(void *arg)
{
	int map_fd = *(int *)arg;

	while (g_running) {
		poll_map(map_fd);
		usleep(1000); /* 1 ms */
	}

	/* final drain after g_running is cleared */
	poll_map(map_fd);
	return NULL;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	struct app_config cfg = {0};
	parse_args(argc, argv, &cfg);

	int ifindex = (int)if_nametoindex(cfg.ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface: %s\n", cfg.ifname);
		return 1;
	}
	g_ifindex = ifindex;

	if (!cfg.have_src_mac && get_if_mac(cfg.ifname, cfg.src_mac) != 0) {
		perror("get interface MAC"); return 1;
	}
	if (!cfg.have_src_ip && get_if_ipv4(cfg.ifname, &cfg.src_ip) != 0) {
		perror("get interface IPv4"); return 1;
	}

	/* ① Open reply bitmap */
	if (ipdb_open(cfg.output) != 0)
		return 1;
	fprintf(stderr, "reply bitmap: %s\n", cfg.output);

	/* ① Open ignore bitmap (optional) */
	if (cfg.ignore_from) {
		if (ipdb_ignore_open(cfg.ignore_from) != 0) {
			ipdb_close();
			return 1;
		}
		fprintf(stderr, "ignore bitmap: %s\n", cfg.ignore_from);
	}

	/* ② Load XDP program — intercepts and drops incoming ICMP replies */
	int map_fd;
	if (xdp_load(cfg.bpf_obj, ifindex, &map_fd) != 0) {
		ipdb_ignore_close();
		ipdb_close();
		return 1;
	}
	fprintf(stderr, "XDP program loaded (%s)\n", cfg.bpf_obj);

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	/* ② Start reader thread — polls BPF map and prints new responders */
	pthread_t reader_tid;
	bool      reader_started = false;
	if (pthread_create(&reader_tid, NULL, reader_thread_fn, &map_fd) != 0) {
		perror("pthread_create");
		xdp_unload();
		return 1;
	}
	reader_started = true;

	/* ③ Open AF_XDP socket for TX */
	struct xsk_socket xsk;
	if (xsk_open(&xsk, &cfg, ifindex) != 0) {
		perror("AF_XDP setup");
		g_running = 0;
		pthread_join(reader_tid, NULL);
		xdp_unload();
		return 1;
	}

	/* Print scan summary */
	char src[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &cfg.src_ip, src, sizeof(src));
	uint64_t dst_count    = (uint64_t)cfg.dst_end - cfg.dst_start + 1;
	uint64_t total_frames = dst_count * cfg.count;
	struct in_addr first_a = {.s_addr = htonl(cfg.dst_start)};
	struct in_addr last_a  = {.s_addr = htonl(cfg.dst_end)};
	char first_s[INET_ADDRSTRLEN], last_s[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &first_a, first_s, sizeof(first_s));
	inet_ntop(AF_INET, &last_a,  last_s,  sizeof(last_s));

	fprintf(stderr, "from  : %s\n", first_s);
	fprintf(stderr, "to    : %s\n", last_s);
	fprintf(stderr, "IPs   : %llu\n", (unsigned long long)dst_count);
	if (cfg.ignore_from)
		fprintf(stderr, "ignore: %s (skipping already-seen IPs)\n", cfg.ignore_from);
	fprintf(stderr, "iface : %s  queue %u  src %s\n",
		cfg.ifname, cfg.queue_id, src);
	fprintf(stderr, "starting in 2s, Ctrl-C to cancel...\n");

	uint64_t frame_idx = 0;
	bool     send_ok   = true;

	sleep(2);
	if (!g_running)
		goto cleanup;

	fprintf(stderr, "sending %llu ICMP Echo frame(s)...\n",
		(unsigned long long)total_frames);

	/* ④ Send packets via AF_XDP */
	for (uint32_t dst_ip = cfg.dst_start; g_running && send_ok; dst_ip++) {
		if (ipdb_ignore_check(dst_ip)) {
			if (dst_ip == cfg.dst_end) break;
			continue;
		}

		cfg.dst_ip.s_addr = htonl(dst_ip);
		char dst[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &cfg.dst_ip, dst, sizeof(dst));

		for (uint32_t i = 0; i < cfg.count && g_running; i++) {
			if (send_one(&xsk, &cfg, (uint32_t)frame_idx,
				     (uint16_t)(frame_idx + 1)) != 0) {
				fprintf(stderr, "send to %s: %s\n", dst, strerror(errno));
				send_ok = false;
				break;
			}
			frame_idx++;
			reap_completions(&xsk);
			if (!cfg.busy && cfg.interval_usec)
				usleep(cfg.interval_usec);
		}
		if (dst_ip == cfg.dst_end) break;
	}

	/* Drain TX completions */
	for (int i = 0; i < 100 && *xsk.cq.consumer != *xsk.tx.producer; i++) {
		reap_completions(&xsk);
		struct pollfd pfd = {.fd = xsk.fd, .events = POLLOUT};
		(void)poll(&pfd, 1, 10);
	}

	/* ⑤ Wait for replies */
	fprintf(stderr, "all packets sent, waiting %u ms for replies...\n",
		cfg.reply_timeout_ms);
	uint32_t remaining = cfg.reply_timeout_ms;
	while (g_running && remaining > 0) {
		uint32_t slice = remaining < 100 ? remaining : 100;
		usleep((useconds_t)slice * 1000);
		remaining -= slice;
	}

	g_running = 0;
	if (reader_started)
		pthread_join(reader_tid, NULL);

	fprintf(stderr, "%d unique IP(s) replied.\n", g_seen_count);

cleanup:
	ipdb_ignore_close();
	ipdb_close();
	xdp_unload();
	return 0;
}
