#include "woody_woodpacker.h"

void modify_payload(int64_t value, size_t offset, size_t size) {
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

int gen_key_64(int64_t* key) {

	if (key == NULL)
		return -1;

	const int fd = open("/dev/urandom", O_RDONLY);

	if (fd == -1) {
		runtime_error("open /dev/urandom");
		return -1;
	}

	if (read(fd, key, sizeof(int64_t)) == -1) {
		close(fd);
		runtime_error("read /dev/urandom");
		return -1;
	}

	close(fd);
	return 0;
}

void encrypt(uint8_t *data, const size_t size, const uint64_t key) {
	for (size_t i = 0; i < size; i++)
		data[i] ^= (key >> (8 * (i % 8))) & 0xFF;
}
