// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
/* Inline ICMP definitions to avoid linux/if.h -> sys/socket.h under -target bpf */
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);   /* source IPv4 address (network byte order) */
	__type(value, __u64); /* reply count */
} icmp_reply_ips SEC(".maps");

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

	if (icmp->type != ICMP_ECHOREPLY)
		return XDP_PASS;

	__u32 src_ip = ip->saddr;
	__u64 *count = bpf_map_lookup_elem(&icmp_reply_ips, &src_ip);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&icmp_reply_ips, &src_ip, &one, BPF_NOEXIST);
	}

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
