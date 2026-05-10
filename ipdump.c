#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define IPDB_SIZE  ((uint64_t)1 << 32)
#define CHUNK_SIZE (4u * 1024u * 1024u)

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

	uint8_t *buf = malloc(CHUNK_SIZE);
	if (!buf) {
		perror("malloc");
		close(fd);
		return 1;
	}

	char     ip_str[INET_ADDRSTRLEN];
	uint64_t found = 0;
	off_t    data  = 0;

	while ((data = lseek(fd, data, SEEK_DATA)) >= 0) {
		off_t hole = lseek(fd, data, SEEK_HOLE);
		if (hole < 0)
			hole = (off_t)IPDB_SIZE;

		off_t pos = data;
		while (pos < hole) {
			size_t want = CHUNK_SIZE;
			off_t  left = hole - pos;
			if ((off_t)want > left)
				want = (size_t)left;

			ssize_t n = pread(fd, buf, want, pos);
			if (n <= 0) {
				if (n < 0) perror("pread");
				goto done;
			}
			for (ssize_t j = 0; j < n; j++) {
				if (buf[j]) {
					uint32_t ip_net = htonl((uint32_t)(pos + j));
					inet_ntop(AF_INET, &ip_net, ip_str, sizeof(ip_str));
					puts(ip_str);
					found++;
				}
			}
			pos += n;
		}
		data = hole;
	}

done:
	free(buf);
	close(fd);
	fprintf(stderr, "%llu IP(s) found.\n", (unsigned long long)found);
	return 0;
}
