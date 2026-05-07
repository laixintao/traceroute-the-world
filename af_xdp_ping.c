#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <poll.h>
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

#ifndef AF_XDP
#define AF_XDP 44
#endif

#define FRAME_SIZE 2048U
#define NUM_FRAMES 4096U
#define RING_SIZE 2048U
#define DEFAULT_PAYLOAD_LEN 32U
#define DEFAULT_INTERVAL_USEC 1000000U

extern unsigned int if_nametoindex(const char *ifname);

struct xsk_ring {
	uint32_t *producer;
	uint32_t *consumer;
	uint32_t *flags;
	void *desc;
	uint32_t size;
	uint32_t mask;
};

struct app_config {
	const char *ifname;
	uint32_t queue_id;
	uint32_t count;
	uint32_t interval_usec;
	uint32_t payload_len;
	bool busy;
	bool force_copy;
	bool force_zerocopy;
	uint8_t src_mac[ETH_ALEN];
	uint8_t dst_mac[ETH_ALEN];
	bool have_src_mac;
	bool have_dst_mac;
	struct in_addr src_ip;
	struct in_addr dst_ip;
	bool have_src_ip;
	bool have_dst_ip;
};

struct xsk_socket {
	int fd;
	void *umem;
	size_t umem_len;
	struct xsk_ring tx;
	struct xsk_ring cq;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --dev IFACE --dst-ip A.B.C.D --dst-mac xx:xx:xx:xx:xx:xx [options]\n"
		"\n"
		"Options:\n"
		"  --src-ip A.B.C.D       Source IPv4 address, default: interface IPv4\n"
		"  --src-mac xx:..:xx     Source MAC, default: interface MAC\n"
		"  --queue N              TX queue id, default: 0\n"
		"  --count N              Packet count, default: 4\n"
		"  --interval-usec N      Delay between packets, default: 1000000\n"
		"  --payload-len N        ICMP payload length, default: 32\n"
		"  --copy                 Force XDP copy mode\n"
		"  --zerocopy             Force XDP zero-copy mode\n"
		"  --busy                 Send without sleeping between packets\n",
		prog);
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
		if (b[i] > 0xff)
			return -1;
		mac[i] = (uint8_t)b[i];
	}
	return 0;
}

static void parse_args(int argc, char **argv, struct app_config *cfg)
{
	cfg->queue_id = 0;
	cfg->count = 4;
	cfg->interval_usec = DEFAULT_INTERVAL_USEC;
	cfg->payload_len = DEFAULT_PAYLOAD_LEN;

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
		} else if (!strcmp(argv[i], "--src-ip") && i + 1 < argc) {
			if (inet_pton(AF_INET, argv[++i], &cfg->src_ip) != 1) {
				fprintf(stderr, "invalid --src-ip\n");
				exit(2);
			}
			cfg->have_src_ip = true;
		} else if (!strcmp(argv[i], "--dst-ip") && i + 1 < argc) {
			if (inet_pton(AF_INET, argv[++i], &cfg->dst_ip) != 1) {
				fprintf(stderr, "invalid --dst-ip\n");
				exit(2);
			}
			cfg->have_dst_ip = true;
		} else if (!strcmp(argv[i], "--src-mac") && i + 1 < argc) {
			if (parse_mac(argv[++i], cfg->src_mac) != 0) {
				fprintf(stderr, "invalid --src-mac\n");
				exit(2);
			}
			cfg->have_src_mac = true;
		} else if (!strcmp(argv[i], "--dst-mac") && i + 1 < argc) {
			if (parse_mac(argv[++i], cfg->dst_mac) != 0) {
				fprintf(stderr, "invalid --dst-mac\n");
				exit(2);
			}
			cfg->have_dst_mac = true;
		} else if (!strcmp(argv[i], "--copy")) {
			cfg->force_copy = true;
		} else if (!strcmp(argv[i], "--zerocopy")) {
			cfg->force_zerocopy = true;
		} else if (!strcmp(argv[i], "--busy")) {
			cfg->busy = true;
		} else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv[0]);
			exit(0);
		} else {
			usage(argv[0]);
			exit(2);
		}
	}

	if (!cfg->ifname || !cfg->have_dst_ip || !cfg->have_dst_mac ||
	    cfg->payload_len > 1400 || (cfg->force_copy && cfg->force_zerocopy)) {
		usage(argv[0]);
		exit(2);
	}
}

static int get_if_mac(const char *ifname, uint8_t mac[ETH_ALEN])
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	int rc = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (rc < 0)
		return -1;

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

static int get_if_ipv4(const char *ifname, struct in_addr *addr)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	int rc = ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	if (rc < 0)
		return -1;

	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	*addr = sin->sin_addr;
	return 0;
}

static uint16_t checksum(const void *data, size_t len)
{
	const uint16_t *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static size_t build_icmp_frame(uint8_t *buf, const struct app_config *cfg, uint16_t seq)
{
	struct ethhdr *eth = (struct ethhdr *)buf;
	struct iphdr *ip = (struct iphdr *)(buf + sizeof(*eth));
	struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(*eth) + sizeof(*ip));
	uint8_t *payload = (uint8_t *)(icmp + 1);

	memcpy(eth->h_dest, cfg->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, cfg->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);

	memset(ip, 0, sizeof(*ip));
	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;
	ip->tot_len = htons((uint16_t)(sizeof(*ip) + sizeof(*icmp) + cfg->payload_len));
	ip->id = htons(seq);
	ip->saddr = cfg->src_ip.s_addr;
	ip->daddr = cfg->dst_ip.s_addr;
	ip->check = checksum(ip, sizeof(*ip));

	memset(icmp, 0, sizeof(*icmp) + cfg->payload_len);
	icmp->type = ICMP_ECHO;
	icmp->un.echo.id = htons((uint16_t)getpid());
	icmp->un.echo.sequence = htons(seq);
	for (uint32_t i = 0; i < cfg->payload_len; i++)
		payload[i] = (uint8_t)i;
	icmp->checksum = checksum(icmp, sizeof(*icmp) + cfg->payload_len);

	return sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) + cfg->payload_len;
}

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

static int mmap_ring(int fd, struct xsk_ring *ring, const struct xdp_ring_offset *off,
		     uint32_t ndesc, off_t pgoff, size_t desc_size)
{
	size_t map_sz = off->desc + ndesc * desc_size;
	void *map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, pgoff);
	if (map == MAP_FAILED)
		return -1;

	ring->producer = map + off->producer;
	ring->consumer = map + off->consumer;
	ring->flags = off->flags ? map + off->flags : NULL;
	ring->desc = map + off->desc;
	ring->size = ndesc;
	ring->mask = ndesc - 1;
	return 0;
}

static int xsk_open(struct xsk_socket *xsk, const struct app_config *cfg, int ifindex)
{
	memset(xsk, 0, sizeof(*xsk));
	xsk->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (xsk->fd < 0)
		return -1;

	int one = 1;
	setsockopt(xsk->fd, SOL_XDP, XDP_USE_NEED_WAKEUP, &one, sizeof(one));

	xsk->umem_len = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&xsk->umem, getpagesize(), xsk->umem_len) != 0) {
		errno = ENOMEM;
		return -1;
	}
	memset(xsk->umem, 0, xsk->umem_len);

	struct xdp_umem_reg mr = {
		.addr = (uintptr_t)xsk->umem,
		.len = xsk->umem_len,
		.chunk_size = FRAME_SIZE,
		.headroom = 0,
		.flags = 0,
	};
	if (setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0)
		return -1;
	if (setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &(uint32_t){RING_SIZE}, sizeof(uint32_t)) < 0)
		return -1;
	if (setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
		       &(uint32_t){RING_SIZE}, sizeof(uint32_t)) < 0)
		return -1;

	struct xdp_mmap_offsets off;
	socklen_t optlen = sizeof(off);
	if (getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0)
		return -1;

	if (mmap_ring(xsk->fd, &xsk->tx, &off.tx, RING_SIZE,
		      XDP_PGOFF_TX_RING, sizeof(struct xdp_desc)) < 0)
		return -1;
	if (mmap_ring(xsk->fd, &xsk->cq, &off.cr, RING_SIZE,
		      XDP_UMEM_PGOFF_COMPLETION_RING, sizeof(uint64_t)) < 0)
		return -1;

	struct sockaddr_xdp sxdp = {
		.sxdp_family = AF_XDP,
		.sxdp_ifindex = (uint32_t)ifindex,
		.sxdp_queue_id = cfg->queue_id,
	};
	if (cfg->force_copy)
		sxdp.sxdp_flags |= XDP_COPY;
	if (cfg->force_zerocopy)
		sxdp.sxdp_flags |= XDP_ZEROCOPY;

	return bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
}

static void reap_completions(struct xsk_socket *xsk)
{
	uint32_t prod = __atomic_load_n(xsk->cq.producer, __ATOMIC_ACQUIRE);
	uint32_t cons = *xsk->cq.consumer;
	uint32_t n = prod - cons;
	if (n)
		ring_release(&xsk->cq, n);
}

static int send_one(struct xsk_socket *xsk, const struct app_config *cfg, uint32_t frame_idx, uint16_t seq)
{
	while (ring_free(&xsk->tx) == 0) {
		reap_completions(xsk);
		if (ring_free(&xsk->tx) == 0) {
			struct pollfd pfd = {.fd = xsk->fd, .events = POLLOUT};
			(void)poll(&pfd, 1, 10);
		}
	}

	uint32_t idx = *xsk->tx.producer & xsk->tx.mask;
	uint64_t addr = (uint64_t)frame_idx * FRAME_SIZE;
	uint8_t *pkt = (uint8_t *)xsk->umem + addr;
	size_t len = build_icmp_frame(pkt, cfg, seq);

	struct xdp_desc *tx = xsk->tx.desc;
	tx[idx].addr = addr;
	tx[idx].len = (uint32_t)len;
	tx[idx].options = 0;
	__atomic_store_n(xsk->tx.producer, *xsk->tx.producer + 1, __ATOMIC_RELEASE);

	if (ring_needs_wakeup(&xsk->tx) || true) {
		if (sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0 &&
		    errno != EBUSY && errno != EAGAIN && errno != ENOBUFS)
			return -1;
	}
	return 0;
}

static int packet_send_loop(const struct app_config *cfg, int ifindex)
{
	int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IP));
	if (fd < 0)
		return -1;

	uint8_t frame[sizeof(struct ethhdr) + sizeof(struct iphdr) +
		      sizeof(struct icmphdr) + 1400];
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = ifindex,
		.sll_halen = ETH_ALEN,
	};
	memcpy(sa.sll_addr, cfg->dst_mac, ETH_ALEN);

	for (uint32_t i = 0; i < cfg->count; i++) {
		size_t len = build_icmp_frame(frame, cfg, (uint16_t)(i + 1));
		if (sendto(fd, frame, len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			close(fd);
			return -1;
		}
		if (!cfg->busy && cfg->interval_usec)
			usleep(cfg->interval_usec);
	}

	close(fd);
	return 0;
}

static bool af_xdp_unsupported_errno(int err)
{
	return err == EINVAL || err == EOPNOTSUPP || err == ENOTSUP;
}

int main(int argc, char **argv)
{
	struct app_config cfg = {0};
	parse_args(argc, argv, &cfg);

	int ifindex = if_nametoindex(cfg.ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface: %s\n", cfg.ifname);
		return 1;
	}

	if (!cfg.have_src_mac && get_if_mac(cfg.ifname, cfg.src_mac) != 0) {
		perror("get interface MAC");
		return 1;
	}
	if (!cfg.have_src_ip && get_if_ipv4(cfg.ifname, &cfg.src_ip) != 0) {
		perror("get interface IPv4");
		return 1;
	}

	struct xsk_socket xsk;
	if (xsk_open(&xsk, &cfg, ifindex) != 0) {
		int setup_errno = errno;
		if (!cfg.force_zerocopy && af_xdp_unsupported_errno(setup_errno)) {
			char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &cfg.src_ip, src, sizeof(src));
			inet_ntop(AF_INET, &cfg.dst_ip, dst, sizeof(dst));
			fprintf(stderr,
				"AF_XDP setup failed (%s); falling back to AF_PACKET TX on %s: %s -> %s\n",
				strerror(setup_errno), cfg.ifname, src, dst);
			if (packet_send_loop(&cfg, ifindex) != 0) {
				perror("AF_PACKET send");
				return 1;
			}
			fprintf(stderr, "done\n");
			return 0;
		}
		errno = setup_errno;
		perror("AF_XDP setup");
		return 1;
	}

	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &cfg.src_ip, src, sizeof(src));
	inet_ntop(AF_INET, &cfg.dst_ip, dst, sizeof(dst));
	fprintf(stderr, "sending %u ICMP Echo frames on %s queue %u: %s -> %s\n",
		cfg.count, cfg.ifname, cfg.queue_id, src, dst);

	for (uint32_t i = 0; i < cfg.count; i++) {
		if (send_one(&xsk, &cfg, i % NUM_FRAMES, (uint16_t)(i + 1)) != 0) {
			perror("send");
			return 1;
		}
		reap_completions(&xsk);
		if (!cfg.busy && cfg.interval_usec)
			usleep(cfg.interval_usec);
	}

	for (int i = 0; i < 100; i++) {
		reap_completions(&xsk);
		if (*xsk.cq.consumer == *xsk.tx.producer)
			break;
		struct pollfd pfd = {.fd = xsk.fd, .events = POLLOUT};
		(void)poll(&pfd, 1, 10);
	}

	fprintf(stderr, "done\n");
	return 0;
}
