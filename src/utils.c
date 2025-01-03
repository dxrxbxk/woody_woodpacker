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

int	ft_strlen(const char *str) {
	int i = 0;
	while (str[i]) {
		i++;
	}
	return (i);
}

void print_hex(void *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)data)[i]);
			printf(" ");
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

int	print_key(int64_t key) {
	char key_str[5 + sizeof(int64_t) * 3 + 1] = "key: ";
	char *key_ptr = key_str + 5;

	for (size_t i = 0U; i < sizeof(int64_t); ++i) {
		uint8_t byte = (uint8_t)(key >> (i * 8));
		*(key_ptr)     = "0123456789abcdef"[(byte & 0xf0) >> 4];
		*(key_ptr + 1) = "0123456789abcdef"[byte & 0x0f];
		*(key_ptr + 2) = ' ';
		key_ptr += 3;
	}
	*(key_ptr - 1) = '\n';
	*key_ptr = '\0';

	if (write(STDOUT_FILENO, key_str, ft_strlen(key_str)) == -1) {
		perror("write");
		return (EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);
}

void print_error(const char* where) {
	dprintf(STDERR_FILENO, "%s\n", where);
}

void runtime_error(const char* where) {
	perror(where);
}

int	handle_syscall(char *msg) {
	perror(msg);
	free_data();
	exit(FAILURE);
}

int	handle_error(int code) {	
	write(2, error_strings(code), ft_strlen((char *)error_strings(code)));
	g_exit_status = code;
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
		data->_oentry_offset = 0;

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
