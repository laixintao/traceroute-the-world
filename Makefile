CC    ?= cc
CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Wextra
LDFLAGS ?=

# Override to point at a custom libbpf install, e.g.:
#   make LIBBPF_CFLAGS="-I/usr/local/include" LIBBPF_LDFLAGS="-L/usr/local/lib -lbpf -lelf -lz"
LIBBPF_CFLAGS  ?=
LIBBPF_LDFLAGS ?= -lbpf -lelf -lz -lpthread

TARGET   := trace
XDP_KERN := icmp_reply_drop_kern.o

.PHONY: all clean

all: $(TARGET) $(XDP_KERN)

$(TARGET): trace.c
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -o $@ $< $(LDFLAGS) $(LIBBPF_LDFLAGS)

$(XDP_KERN): icmp_reply_drop_kern.c
	$(CLANG) -O2 -g -Wall -target bpf $(LIBBPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(XDP_KERN)
