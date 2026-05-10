#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile int running = 1;

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

static void dump_map(int map_fd)
{
	__u32 key = 0, next_key;
	__u64 count;
	char ip_str[INET_ADDRSTRLEN];
	bool first = true;

	while (bpf_map_get_next_key(map_fd, first ? NULL : &key, &next_key) == 0) {
		first = false;
		key = next_key;
		if (bpf_map_lookup_elem(map_fd, &key, &count) == 0) {
			inet_ntop(AF_INET, &key, ip_str, sizeof(ip_str));
			printf("  %-20s %llu\n", ip_str, (unsigned long long)count);
		}
	}
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname> [bpf-obj]\n", argv[0]);
		return 1;
	}

	const char *ifname   = argv[1];
	const char *obj_path = argc >= 3 ? argv[2] : "icmp_reply_drop_kern.o";

	int ifindex = (int)if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface: %s\n", ifname);
		return 1;
	}

	struct bpf_object *obj = bpf_object__open(obj_path);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "failed to open BPF object: %s\n", obj_path);
		return 1;
	}

	if (bpf_object__load(obj) != 0) {
		fprintf(stderr, "failed to load BPF object\n");
		bpf_object__close(obj);
		return 1;
	}

	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "xdp_drop_icmp_reply");
	if (!prog) {
		fprintf(stderr, "BPF program 'xdp_drop_icmp_reply' not found\n");
		bpf_object__close(obj);
		return 1;
	}

	int prog_fd = bpf_program__fd(prog);
	if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0) {
		perror("bpf_xdp_attach");
		bpf_object__close(obj);
		return 1;
	}

	int map_fd = bpf_object__find_map_fd_by_name(obj, "icmp_reply_ips");
	if (map_fd < 0) {
		fprintf(stderr, "BPF map 'icmp_reply_ips' not found\n");
		bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
		bpf_object__close(obj);
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	fprintf(stderr, "XDP loaded on %s — dropping ICMP replies. Ctrl-C to stop.\n", ifname);

	while (running) {
		sleep(1);
		printf("\n--- ICMP reply sources (src_ip, count) ---\n");
		dump_map(map_fd);
	}

	printf("\nFinal ICMP reply sources:\n");
	dump_map(map_fd);

	bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
	bpf_object__close(obj);
	return 0;
}
