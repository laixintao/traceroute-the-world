// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
/* Inline definitions to avoid userspace headers under -target bpf */
#define IPPROTO_ICMP    1
#define ICMP_ECHOREPLY  0
#define ICMP_ECHO       8
struct icmphdr {
	__u8  type;
	__u8  code;
	__u16 checksum;
	union {
		struct { __u16 id; __u16 sequence; } echo;
		__u32 gateway;
		struct { __u16 __unused; __u16 mtu; } frag;
		__u8  reserved[4];
	} un;
};
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct icmp_event {
	__u32 src_ip; /* IPv4 source address, network byte order */
};

/*
 * Written by user-space after XDP load: g_secret used when encoding
 * cookie = g_secret ^ dst_ip_host in ICMP payload[0..3].
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} icmp_secret SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); /* 4 MiB — if full, events are dropped */
} icmp_reply_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} ringbuf_drops SEC(".maps");

SEC("xdp")
int xdp_drop_icmp_reply(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	if (ip->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	/* ip->ihl is in 32-bit words; mask keeps verifier happy */
	__u32 ip_hdr_len = (__u32)(ip->ihl & 0xf) * 4;
	if (ip_hdr_len < sizeof(struct iphdr))
		return XDP_PASS;

	struct icmphdr *icmp = (struct icmphdr *)((void *)ip + ip_hdr_len);
	if ((void *)(icmp + 1) > data_end)
		return XDP_PASS;

	/* Drop all ICMP that isn't an Echo Reply (unreachable, time-exceeded…)
	 * so the kernel never processes them and they don't pollute the stack. */
	if (icmp->type != ICMP_ECHOREPLY)
		return XDP_DROP;

	/* Verify cookie: payload[0..3] (big-endian) must equal secret ^ src_ip_host.
	 * Replies without a valid cookie are dropped silently — not our packets. */
	__u8 *payload = (__u8 *)(icmp + 1);
	if ((void *)(payload + 4) > data_end)
		return XDP_DROP;

	__u32 map_key = 0;
	__u32 *secret = bpf_map_lookup_elem(&icmp_secret, &map_key);
	if (!secret)
		return XDP_DROP;

	__u32 got_be;
	__builtin_memcpy(&got_be, payload, sizeof(got_be));
	if (bpf_ntohl(got_be) != (*secret ^ bpf_ntohl(ip->saddr)))
		return XDP_DROP;

	struct icmp_event *e = bpf_ringbuf_reserve(&icmp_reply_events,
						    sizeof(*e), 0);
	if (e) {
		e->src_ip = ip->saddr;
		bpf_ringbuf_submit(e, 0);
	} else {
		__u32 k = 0;
		__u64 *cnt = bpf_map_lookup_elem(&ringbuf_drops, &k);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
	}

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
