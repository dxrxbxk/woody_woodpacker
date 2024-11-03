#include "utils.h"

extern char	shellcode[];

void	print_payload(payload_t payload) {
	for (size_t i = 0; i < payload._size; i++) {
		printf("%02x", ((unsigned char *)payload._payload)[i]);
		if (i % 4 == 3)
			printf(" ");
	}
	printf("\n");
}

void	print_shellcode(size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%02x", shellcode[i]);
		if (i % 4 == 3)
			printf(" ");
	}
	printf("\n");
}

void	print_hex(void *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)data)[i]);
			printf(" ");
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

void	print_PAYLOAD(void) {

}

void print_data(const uint8_t *data, size_t size) {
	size_t i = 0;
    if (data == NULL || size == 0) {
        printf("No data\n");
        return;
    }

    for (; i < size; i++) {
        printf("%02x ", data[i]);

        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    if (size % 16 != 0) {
        printf("\n");
    }
}
