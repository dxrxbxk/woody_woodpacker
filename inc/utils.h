#ifndef UTILS_H
#define UTILS_H

#include <bits/stdint-uintn.h>
#include <stddef.h>

int	ft_strlen(char *str);
int	handle_error(char *msg);
int handle_syscall(char *msg, int fd);
void print_data(const uint8_t *data, size_t size);

#endif
