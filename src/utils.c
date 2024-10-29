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
		data = NULL;
	}
}

void	ft_memcpy(void *dst, void *src, size_t size) {
	uint8_t *d = dst;
	uint8_t *s = src;

	for (size_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
}

void ft_memset(void *dst, int c, size_t size) {
	uint8_t *d = dst;

	for (size_t i = 0; i < size; i++) {
		d[i] = c;
	}
}

int ft_memcmp(void *s1, void *s2, size_t size) {
	uint8_t *str1 = s1;
	uint8_t *str2 = s2;

	for (size_t i = 0; i < size; i++) {
		if (str1[i] != str2[i])
			return (str1[i] - str2[i]);
	}
	return (0);
}
