#include "woody_woodpacker.h"

const char*	error_strings(int code) {
	static const char *error_strings[ERROR_CODES_SIZE] = {
		"Success\n",
		"Failure\n",
		"Usage: ./woody_woodpacker <filename>\n",
		"Not an ELF file\n",
		"File architecture not suported. x86_64 only\n",
		"Codecave size too small\n",
		"Codecave not found\n",
		"No section found\n",
		"Failed to copy payload\n",
	};

	return (error_strings[code]);
}

int	ft_strlen(char *str) {
	int i = 0;
	while (str[i]) {
		i++;
	}
	return (i);
}

<<<<<<< HEAD
int handle_syscall(char *msg) {
=======
void	print_hex(void *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)data)[i]);
			printf(" ");
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

int	handle_syscall(char *msg) {
>>>>>>> padding_encryption
	perror(msg);
	free_data();
	exit(EXIT_FAILURE);
}

int	handle_error(int code) {
	write(2, error_strings(code), ft_strlen((char *)error_strings(code)));
	return (code);
}

data_t*	get_data(void) {
	static data_t *data = NULL;

	if (data == NULL) {
		data = malloc(sizeof(data_t));
		if (data == NULL)
			handle_syscall("malloc");

		data->_file_map = NULL;
		data->_file_size = 0;

	}

	return data;
}

void	free_data(void) {
	data_t *data = get_data();

	if (data) {
		if (data->_file_map) {
			munmap(data->_file_map, data->_file_size);
			data->_file_map = NULL;
		}
		free(data);
		data = NULL;
	}
}

void	*ft_memcpy(void *dst, const void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = (uint8_t *)src;

	for (size_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
	return dst;
}

int	ft_memcmp(const void *s1, const void *s2, size_t size) {
	uint8_t *str1 = (uint8_t *)s1;
	uint8_t *str2 = (uint8_t *)s2;

	for (size_t i = 0; i < size; i++) {
		if (str1[i] != str2[i])
			return (str1[i] - str2[i]);
	}
	return (0);
}
