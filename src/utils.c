#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "utils.h"
#include <bits/stdint-uintn.h>
#include <fcntl.h>

int	ft_strlen(char *str) {
	int i = 0;
	while (str[i]) {
		i++;
	}
	return (i);
}

int handle_syscall(char *msg, int fd) {
	if (fd != -1)
		close(fd);
	perror(msg);
	exit(EXIT_FAILURE);
}

int	handle_error(char *msg) {
	write(2, msg, ft_strlen(msg));
	return (EXIT_FAILURE);
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

void print_shellcode(const char *code) {
	size_t shellcode_length = ft_strlen((char*)code);
	for (size_t i = 0; i < shellcode_length; i++) {
		printf("\\x%02x", (unsigned char)code[i]);
	}
}

uint64_t gen_key_64(void) {
	int	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		handle_syscall("open", fd);

	uint64_t key;
	if (read(fd, &key, sizeof(uint64_t)) == -1)
		handle_syscall("read", fd);

	close(fd);
	return key;
}

uint8_t gen_key(void) {
	int	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		handle_syscall("open", fd);

	uint8_t key;
	if (read(fd, &key, sizeof(uint8_t)) == -1)
		handle_syscall("read", fd);

	close(fd);
	return key;
}

void encrypt(uint8_t *data, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}
