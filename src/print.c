#include "utils.h"

void	print_hex(void *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)data)[i]);
			printf(" ");
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}
