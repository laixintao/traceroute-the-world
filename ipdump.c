#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define IPDB_SIZE  ((uint64_t)1 << 32)   /* 4 GiB */
#define CHUNK_SIZE (4u * 1024u * 1024u)  /* 4 MiB read buffer */

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <replies.bin>\n", argv[0]);
		return 1;
	}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror(argv[1]);
		return 1;
	}

	struct stat st;
	if (fstat(fd, &st) < 0 || (uint64_t)st.st_size != IPDB_SIZE) {
		fprintf(stderr, "%s: expected a %llu-byte ipdb file\n",
			argv[1], (unsigned long long)IPDB_SIZE);
		close(fd);
		return 1;
	}

	posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

	uint8_t *buf = malloc(CHUNK_SIZE);
	if (!buf) {
		perror("malloc");
		close(fd);
		return 1;
	}

	char     ip_str[INET_ADDRSTRLEN];
	uint64_t base  = 0;
	uint64_t found = 0;
	ssize_t  n;

	while ((n = read(fd, buf, CHUNK_SIZE)) > 0) {
		for (ssize_t j = 0; j < n; j++) {
			if (buf[j]) {
				uint32_t ip_net = htonl((uint32_t)(base + (uint64_t)j));
				inet_ntop(AF_INET, &ip_net, ip_str, sizeof(ip_str));
				puts(ip_str);
				found++;
			}
		}
		base += (uint64_t)n;
	}

	free(buf);
	close(fd);

	if (n < 0) {
		perror("read");
		return 1;
	}

	fprintf(stderr, "%llu IP(s) found.\n", (unsigned long long)found);
	return 0;
}
