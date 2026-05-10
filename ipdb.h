#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * Reply bitmap backed by a 4 GiB sparse mmap file.
 * Byte at index ntohl(src_ip) is set to 1 when that host replied.
 * The file retains results across runs; delete it to start fresh.
 */

int  ipdb_open(const char *path);
void ipdb_mark(uint32_t ip_host_order);
void ipdb_close(void);

/*
 * Read-only view of an existing ipdb file used to skip already-known IPs.
 * ipdb_ignore_check() returns true if the IP should be skipped.
 */

int  ipdb_ignore_open(const char *path);
bool ipdb_ignore_check(uint32_t ip_host_order);
void ipdb_ignore_close(void);
