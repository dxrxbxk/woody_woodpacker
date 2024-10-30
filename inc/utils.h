#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <bits/stdint-uintn.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <elf.h>
#include <sys/syscall.h>

#define ELF_32 1
#define ELF_64 2
#define PT_LOAD 1

#ifdef VERBOSE
# define PRINT(...) printf(__VA_ARGS__)
#else
# define PRINT(...)
#endif

#ifdef DEBUG_PRINT
# define DEBUG_P(...) printf("DEBUG: "); printf(__VA_ARGS__)
#else
# define DEBUG_P(...)
#endif

#define ERROR(x) handle_error(x)

typedef struct data_s {
	uint8_t					*_file_map;
	size_t					_file_size;
} data_t;

void	*ft_memcpy(void *dest, const void *src, size_t n);
void	*ft_memset(void *s, int c, size_t n);
int		ft_memcmp(const void *s1, const void *s2, size_t n);

int		ft_strlen(char *str);
int		handle_error(char *msg);
int		handle_syscall(char *msg);

void	print_hex(void *data, size_t size);

data_t	*get_data(void);
void	free_data(void);


typedef struct patch_s{
	/* offset from payload to pgm entrypoint */
	uint64_t				entry_offset;
	/* offset from payload to text entrypoint */
	uint64_t				text_offset;
	/* offset from payload to begin of segment */
	uint64_t				segment_offset;
} patch_t;


#endif