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
bool ipdb_check(uint32_t ip_host_order);  /* true if already set */
void ipdb_close(void);

/*
 * Merge an existing ipdb file into the currently open output map.
 * Any IP that is 1 in src_path will also become 1 in the output.
 * Call after ipdb_open().
 */
int ipdb_copy_from(const char *src_path);
