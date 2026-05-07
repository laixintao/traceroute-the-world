CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra
LDFLAGS ?=

TARGET := af_xdp_ping

.PHONY: all clean

all: $(TARGET)

$(TARGET): af_xdp_ping.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
