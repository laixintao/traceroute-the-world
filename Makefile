CC    ?= cc
CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Wextra
LDFLAGS ?=

# Override to point at a custom libbpf install, e.g.:
#   make LIBBPF_CFLAGS="-I/usr/local/include" LIBBPF_LDFLAGS="-L/usr/local/lib -lbpf -lelf -lz"
LIBBPF_CFLAGS  ?=
LIBBPF_LDFLAGS ?= -lbpf -lelf -lz -lpthread

TARGET   := trace
DUMP     := ipdump
COUNT    := ipcount
DIFF     := ipdiff
XDP_KERN := icmp_reply_drop_kern.o

.PHONY: all clean

all: $(TARGET) $(DUMP) $(COUNT) $(DIFF) $(XDP_KERN)

$(TARGET): trace.c ipdb.c ipdb.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -o $@ trace.c ipdb.c $(LDFLAGS) $(LIBBPF_LDFLAGS)

$(DUMP): ipdump.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(COUNT): ipcount.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(DIFF): ipdiff.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(XDP_KERN): icmp_reply_drop_kern.c
	$(CLANG) -O2 -g -Wall -target bpf $(LIBBPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(DUMP) $(COUNT) $(DIFF) $(XDP_KERN)
