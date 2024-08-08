#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int	ft_strlen(char *str) {
	int i = 0;
	while (str[i]) {
		i++;
	}
	return (i);
}

int handle_syscall(char *msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

int	handle_error(char *msg) {
	write(2, msg, ft_strlen(msg));
	return (EXIT_FAILURE);
}
