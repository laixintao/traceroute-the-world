#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define IPDB_SIZE  ((uint64_t)1 << 32)
#define CHUNK_SIZE (4u * 1024u * 1024u)

static const uint8_t *open_excl(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror(path);
		return NULL;
	}
	struct stat st;
	if (fstat(fd, &st) < 0 || (uint64_t)st.st_size != IPDB_SIZE) {
		fprintf(stderr, "%s: expected a %llu-byte ipdb file\n",
			path, (unsigned long long)IPDB_SIZE);
		close(fd);
		return NULL;
	}
	const uint8_t *m = mmap(NULL, (size_t)IPDB_SIZE,
				PROT_READ, MAP_SHARED, fd, 0);
	close(fd); /* fd can be closed after mmap */
	if (m == MAP_FAILED) {
		perror(path);
		return NULL;
	}
	return m;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"Usage: %s <base.bin> <excl1.bin> [excl2.bin ...]\n"
			"\n"
			"Prints IPs that are 1 in base.bin but 0 in every excl file.\n",
			argv[0]);
		return 1;
	}

	/* open base file (iterated with SEEK_DATA/SEEK_HOLE) */
	int base_fd = open(argv[1], O_RDONLY);
	if (base_fd < 0) {
		perror(argv[1]);
		return 1;
	}
	struct stat st;
	if (fstat(base_fd, &st) < 0 || (uint64_t)st.st_size != IPDB_SIZE) {
		fprintf(stderr, "%s: expected a %llu-byte ipdb file\n",
			argv[1], (unsigned long long)IPDB_SIZE);
		close(base_fd);
		return 1;
	}

	/* mmap all exclude files for O(1) random access */
	int n_excl = argc - 2;
	const uint8_t **excl = malloc((size_t)n_excl * sizeof(*excl));
	if (!excl) {
		perror("malloc");
		close(base_fd);
		return 1;
	}
	for (int i = 0; i < n_excl; i++) {
		excl[i] = open_excl(argv[i + 2]);
		if (!excl[i]) {
			close(base_fd);
			free(excl);
			return 1;
		}
	}

	uint8_t *buf = malloc(CHUNK_SIZE);
	if (!buf) {
		perror("malloc");
		close(base_fd);
		free(excl);
		return 1;
	}

	char     ip_str[INET_ADDRSTRLEN];
	uint64_t found = 0;
	off_t    data  = 0;

	while ((data = lseek(base_fd, data, SEEK_DATA)) >= 0) {
		off_t hole = lseek(base_fd, data, SEEK_HOLE);
		if (hole < 0)
			hole = (off_t)IPDB_SIZE;

		off_t pos = data;
		while (pos < hole) {
			size_t want = CHUNK_SIZE;
			off_t  left = hole - pos;
			if ((off_t)want > left)
				want = (size_t)left;

			ssize_t n = pread(base_fd, buf, want, pos);
			if (n <= 0) {
				if (n < 0) perror("pread");
				goto done;
			}
			for (ssize_t j = 0; j < n; j++) {
				if (!buf[j])
					continue;

				uint32_t idx = (uint32_t)(pos + j);

				/* skip if already set in any exclude file */
				int excluded = 0;
				for (int k = 0; k < n_excl; k++) {
					if (excl[k][idx]) {
						excluded = 1;
						break;
					}
				}
				if (excluded)
					continue;

				uint32_t ip_net = htonl(idx);
				inet_ntop(AF_INET, &ip_net, ip_str, sizeof(ip_str));
				puts(ip_str);
				found++;
			}
			pos += n;
		}
		data = hole;
	}

done:
	fprintf(stderr, "%llu IP(s) found.\n", (unsigned long long)found);

	free(buf);
	close(base_fd);
	for (int i = 0; i < n_excl; i++)
		munmap((void *)excl[i], (size_t)IPDB_SIZE);
	free(excl);
	return 0;
}
