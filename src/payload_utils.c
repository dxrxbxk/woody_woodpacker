#include "woody_woodpacker.h"

void	modify_payload(int64_t value, size_t offset, size_t size) {
	DEBUG_P("value: %lx, %ld, offset: %ld, size: %ld\n", value, value, offset, size);

	for (size_t i = size; i > 0; i--) {
		g_payload[g_payload_size - offset] = value & 0xFF;
		value >>= 8;
		offset--;
	}
}

void	patch_payload(int64_t codecave_diff, int64_t key, int32_t jmp_range) {
#ifdef DEBUG
	print_hex(g_payload, g_payload_size);
#endif
	modify_payload(codecave_diff, ADDR_OFFSET, sizeof(codecave_diff));
	modify_payload(key, KEY_OFFSET, sizeof(key));
	modify_payload(jmp_range, JMP_OFFSET, sizeof(jmp_range));
#ifdef DEBUG
	printf("----------------------\n");
	print_hex(g_payload, g_payload_size);
#endif

}

uint8_t	gen_key(void) {
	int	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	uint8_t key;
	if (read(fd, &key, sizeof(uint8_t)) == -1)
		handle_syscall("read");

	close(fd);
	return key;
}

int64_t	gen_key_64(void) {
	int	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	int64_t key;
	if (read(fd, &key, sizeof(int64_t)) == -1)
		handle_syscall("read");

	close(fd);
	return key;
}

void	encrypt(uint8_t *data, size_t size, uint64_t key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
    }
}
