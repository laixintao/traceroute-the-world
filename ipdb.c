#define _GNU_SOURCE

#include "ipdb.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* 2^32 bytes — sparse file; the OS only allocates touched pages */
#define IPDB_SIZE ((uint64_t)1 << 32)

static uint8_t *g_map = NULL;
static int      g_fd  = -1;

int ipdb_open(const char *path)
{
	g_fd = open(path, O_RDWR | O_CREAT, 0644);
	if (g_fd < 0) {
		perror("ipdb: open");
		return -1;
	}
	if (ftruncate(g_fd, (off_t)IPDB_SIZE) < 0) {
		perror("ipdb: ftruncate");
		close(g_fd);
		g_fd = -1;
		return -1;
	}
	g_map = mmap(NULL, (size_t)IPDB_SIZE,
		     PROT_READ | PROT_WRITE, MAP_SHARED, g_fd, 0);
	if (g_map == MAP_FAILED) {
		perror("ipdb: mmap");
		close(g_fd);
		g_fd  = -1;
		g_map = NULL;
		return -1;
	}
	return 0;
}

void ipdb_mark(uint32_t ip)
{
	if (g_map)
		g_map[ip] = 1;
}

void ipdb_close(void)
{
	if (g_map) {
		munmap(g_map, (size_t)IPDB_SIZE);
		g_map = NULL;
	}
	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}
}

/* ── ignore map (read-only) ──────────────────────────────────────────────── */

static const uint8_t *g_ignore_map = NULL;
static int            g_ignore_fd  = -1;

int ipdb_ignore_open(const char *path)
{
	g_ignore_fd = open(path, O_RDONLY);
	if (g_ignore_fd < 0) {
		perror("ipdb_ignore: open");
		return -1;
	}
	struct stat st;
	if (fstat(g_ignore_fd, &st) < 0 || (uint64_t)st.st_size != IPDB_SIZE) {
		fprintf(stderr, "ipdb_ignore: %s is not a valid 4 GiB ipdb file\n", path);
		close(g_ignore_fd);
		g_ignore_fd = -1;
		return -1;
	}
	g_ignore_map = mmap(NULL, (size_t)IPDB_SIZE,
			    PROT_READ, MAP_SHARED, g_ignore_fd, 0);
	if (g_ignore_map == MAP_FAILED) {
		perror("ipdb_ignore: mmap");
		close(g_ignore_fd);
		g_ignore_fd  = -1;
		g_ignore_map = NULL;
		return -1;
	}
	return 0;
}

bool ipdb_ignore_check(uint32_t ip)
{
	return g_ignore_map && g_ignore_map[ip];
}

void ipdb_ignore_close(void)
{
	if (g_ignore_map) {
		munmap((void *)g_ignore_map, (size_t)IPDB_SIZE);
		g_ignore_map = NULL;
	}
	if (g_ignore_fd >= 0) {
		close(g_ignore_fd);
		g_ignore_fd = -1;
	}
}
