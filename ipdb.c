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

bool ipdb_check(uint32_t ip)
{
	return g_map && g_map[ip];
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

int ipdb_copy_from(const char *src_path)
{
	if (!g_map) {
		fprintf(stderr, "ipdb_copy_from: output map not open\n");
		return -1;
	}

	int src_fd = open(src_path, O_RDONLY);
	if (src_fd < 0) {
		perror(src_path);
		return -1;
	}
	struct stat st;
	if (fstat(src_fd, &st) < 0 || (uint64_t)st.st_size != IPDB_SIZE) {
		fprintf(stderr, "%s: expected a %llu-byte ipdb file\n",
			src_path, (unsigned long long)IPDB_SIZE);
		close(src_fd);
		return -1;
	}

	/* Copy only the allocated (non-hole) pages from src into g_map.
	 * Use |= so existing 1s in the output are preserved. */
	uint8_t buf[65536];
	off_t   data = 0;
	int     rc   = 0;

	while ((data = lseek(src_fd, data, SEEK_DATA)) >= 0) {
		off_t hole = lseek(src_fd, data, SEEK_HOLE);
		if (hole < 0)
			hole = (off_t)IPDB_SIZE;

		off_t pos = data;
		while (pos < hole) {
			size_t  want = sizeof(buf);
			off_t   left = hole - pos;
			if ((off_t)want > left)
				want = (size_t)left;
			ssize_t n = pread(src_fd, buf, want, pos);
			if (n <= 0) {
				if (n < 0) { perror("ipdb_copy_from: pread"); rc = -1; }
				goto done;
			}
			for (ssize_t i = 0; i < n; i++)
				g_map[pos + i] |= buf[i];
			pos += n;
		}
		data = hole;
	}

done:
	close(src_fd);
	return rc;
}
