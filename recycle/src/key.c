#include "utils.h"

uint64_t gen_key_64(void) {
	int	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	uint64_t key;
	if (read(fd, &key, sizeof(uint64_t)) == -1)
		handle_syscall("read");

	close(fd);
	return key;
}

uint8_t gen_key(void) {
	int	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	uint8_t key;
	if (read(fd, &key, sizeof(uint8_t)) == -1)
		handle_syscall("read");

	close(fd);
	return key;
}

void encrypt(uint8_t *data, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}
