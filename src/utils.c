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

int handle_syscall(char *msg) {
	perror(msg);
	free_data();
	exit(EXIT_FAILURE);
}

int	handle_error(char *msg) {
	write(2, msg, ft_strlen(msg));
	return (EXIT_FAILURE);
}

data_t*	get_data(void) {
	static data_t *data = NULL;

	if (data == NULL) {
		data = malloc(sizeof(data_t));
		if (data == NULL)
			handle_error("malloc");

		data->_file_map = NULL;
		data->_file_size = 0;

	}

	return data;
}

void	free_data(void) {
	data_t *data = get_data();

	if (data) {
		if (data->_file_map)
			munmap(data->_file_map, data->_file_size);
		free(data);
	}
}

void	*ft_memcpy(void *dst, const void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = (uint8_t *)src;

	for (size_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
	return (dst);
}

void ft_memset(void *dst, int c, size_t size) {
	uint8_t *d = dst;

	for (size_t i = 0; i < size; i++) {
		d[i] = c;
	}
}

int ft_memcmp(const void *s1, const void *s2, size_t size) {
	uint8_t *str1 = (uint8_t *)s1;
	uint8_t *str2 = (uint8_t *)s2;

	for (size_t i = 0; i < size; i++) {
		if (str1[i] != str2[i])
			return (str1[i] - str2[i]);
	}
	return (0);
}
