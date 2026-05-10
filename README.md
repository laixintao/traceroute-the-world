# trace-route-the-world

High-speed ICMP Echo scanner that uses **AF_XDP** to send packets and an
**eBPF XDP** hook to intercept replies — without letting the kernel process
them at all.

## How it works

```
┌────────────────────────────────────────┐
│  trace (userspace)                     │
│                                        │
│  ① xdp_load()     load eBPF .o, attach │
│     to interface RX path               │
│                                        │
│  ② reader thread  poll BPF map every   │
│     100 ms, print new replying IPs     │
│                                        │
│  ③ xsk_open()     open AF_XDP socket   │
│                                        │
│  ④ send loop      write ICMP Echo      │
│     frames into AF_XDP TX ring         │
│                                        │
│  ⑤ wait           reply-timeout-ms     │
│     then join reader thread, unload    │
└────────────────────────────────────────┘
         │ TX (ICMP Echo)       ▲ RX (ICMP Reply)
         ▼                      │
┌────────────────────────────────────────┐
│  kernel / NIC                          │
│                                        │
│  XDP hook (icmp_reply_drop_kern.o)     │
│    • type == ECHOREPLY?                │
│    • yes → record src IP in BPF map    │
│           → XDP_DROP  (kernel skips)   │
│    • no  → XDP_PASS                    │
└────────────────────────────────────────┘
```

## Build

```sh
# requires: clang, libbpf-dev (>= 0.8), libelf-dev, zlib1g-dev
make
```

This produces two artifacts:

| File | Description |
|---|---|
| `trace` | Userspace binary |
| `icmp_reply_drop_kern.o` | eBPF object loaded at runtime |

Both must be in the same directory (or pass `--bpf-obj` to override the path).

## Usage

You must supply a destination MAC address because the program bypasses ARP.
Run as root (or with `CAP_NET_ADMIN` + `CAP_BPF`).

### Ping a single host

```sh
sudo ./trace \
  --dev eth0 \
  --dst-ip 192.168.1.1 \
  --dst-mac 02:00:00:00:00:01
```

### Scan a subnet

```sh
sudo ./trace \
  --dev eth0 \
  --dst-subnet 192.168.1.0/24 \
  --dst-mac 02:00:00:00:00:01 \
  --count 1 \
  --interval-usec 0 \
  --busy
```

Example output:

```
XDP program loaded (icmp_reply_drop_kern.o)
sending 256 ICMP Echo frame(s) on eth0 queue 0: 10.0.0.2 -> 192.168.1.0-192.168.1.255
[reply] 192.168.1.1          (1 packet(s))
[reply] 192.168.1.10         (1 packet(s))
[reply] 192.168.1.42         (1 packet(s))
all packets sent, waiting 3000 ms for replies...
[reply] 192.168.1.254        (1 packet(s))
4 unique IP(s) replied.
```

### Wait longer for replies (e.g. slow hosts)

```sh
sudo ./trace \
  --dev eth0 \
  --dst-subnet 10.0.0.0/16 \
  --dst-mac 02:00:00:00:00:01 \
  --count 1 \
  --busy \
  --reply-timeout-ms 10000
```

### Use a custom eBPF object path

```sh
sudo ./trace \
  --dev eth0 \
  --dst-ip 192.168.1.1 \
  --dst-mac 02:00:00:00:00:01 \
  --bpf-obj /usr/local/lib/icmp_reply_drop_kern.o
```

## All options

```
--dev IFACE              Network interface (required)
--dst-ip A.B.C.D         Single destination IP
--dst-subnet CIDR        Scan every IP in subnet (mutually exclusive with --dst-ip)
--dst-mac xx:xx:xx:xx:xx:xx  Destination MAC (required; no ARP)
--src-ip A.B.C.D         Source IPv4, default: interface IPv4
--src-mac xx:..:xx       Source MAC, default: interface MAC
--queue N                TX queue id, default: 0
--count N                ICMP Echo packets per destination, default: 4
--interval-usec N        Delay between packets (µs), default: 1000000
--payload-len N          ICMP payload bytes, default: 32
--ttl N                  IP TTL (1-255), default: 64
--reply-timeout-ms N     Time to wait after last send (ms), default: 3000
--output PATH            reply bitmap file, default: replies.bin
--bpf-obj PATH           eBPF object file, default: icmp_reply_drop_kern.o
--copy                   Force XDP copy mode
--zerocopy               Force XDP zero-copy mode
--busy                   Do not sleep between packets
```

## Notes

- The eBPF XDP program attaches with `XDP_FLAGS_UPDATE_IF_NOEXIST`, so it
  will fail if another XDP program is already attached to the interface.
  Detach it first with `ip link set dev eth0 xdp off`.
- AF_XDP in copy mode (`--copy`) works on any driver. Zero-copy requires
  driver support. If `bind(AF_XDP)` fails with `EINVAL`, try `--copy`.
- The scanner sends raw Ethernet frames and does not perform ARP. Make sure
  `--dst-mac` is the MAC of the next hop (gateway) when scanning remote
  subnets, or the target MAC when on the same L2 segment.
- Replies are intercepted and dropped by the XDP hook before the kernel
  sees them, so `ping` or other tools on the same host will not receive
  those replies while `trace` is running.
- The reply bitmap (`replies.bin` by default) is a 4 GiB sparse file.
  Byte at offset `ntohl(src_ip)` is set to `1` when that host replied.
  The file persists across runs (results accumulate); delete it to start
  fresh. To check whether `192.168.1.1` replied:
  ```python
  with open("replies.bin", "rb") as f:
      f.seek(0xC0A80101)   # 192.168.1.1 in host byte order
      print(f.read(1) == b'\x01')
  ```
