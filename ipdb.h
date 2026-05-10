#pragma once

#include <stdint.h>

/*
 * Reply bitmap backed by a 4 GiB sparse mmap file.
 * Byte at index ntohl(src_ip) is set to 1 when that host replied.
 * The file retains results across runs; delete it to start fresh.
 */

int  ipdb_open(const char *path);
void ipdb_mark(uint32_t ip_host_order);
void ipdb_close(void);
