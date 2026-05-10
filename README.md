# AF_XDP ICMP sender

This is a minimal AF_XDP ICMP Echo sender. It bypasses the normal kernel
network data path for packet transmission by writing complete Ethernet frames
into an AF_XDP TX ring.

It intentionally does not use libbpf or libxdp, so it only needs Linux UAPI
headers and a C compiler.

## Build

```sh
make
```

## Run

You must provide the destination MAC address because this program bypasses the
kernel data path and does not perform ARP.

```sh
sudo ./af_xdp_ping \
  --dev eth0 \
  --dst-ip 192.0.2.10 \
  --dst-mac 02:00:00:00:00:02
```

To send one ICMP Echo packet to every address in a subnet:

```sh
sudo ./af_xdp_ping \
  --dev eth0 \
  --dst-subnet 192.0.2.0/24 \
  --dst-mac 02:00:00:00:00:02 \
  --count 1 \
  --busy
```

Useful options:

```text
--src-ip A.B.C.D       Source IPv4 address. Defaults to the interface IPv4.
--src-mac xx:..:xx     Source MAC. Defaults to the interface MAC.
--queue N              TX queue id. Default: 0.
--dst-subnet CIDR      Send to every IPv4 address in CIDR instead of --dst-ip.
--count N              Number of ICMP Echo packets per destination. Default: 4.
--interval-usec N      Delay between packets. Default: 1000000.
--payload-len N        ICMP payload length. Default: 32.
--copy                 Force XDP copy mode.
--zerocopy             Force XDP zero-copy mode.
--busy                 Do not sleep between packets.
```

## Notes

AF_XDP support depends on the NIC driver and queue setup. If `bind(AF_XDP)`
fails with `EINVAL`, try `--copy` first. For zero-copy mode, the NIC driver must
support AF_XDP zero-copy on the selected queue. This program does not fall back
to AF_PACKET.

This program sends ICMP Echo packets only. It does not attach an XDP program and
does not receive Echo Replies.
