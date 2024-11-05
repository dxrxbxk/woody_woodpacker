#ifndef WOODY_WOODPACKER_H
#define WOODY_WOODPACKER_H

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

#ifdef DEBUG
# define DEBUG_P(...) printf("DEBUG: "); printf(__VA_ARGS__)
#else
# define DEBUG_P(...)
#endif

#define ERROR(x) handle_error(x)

#define KEY_OFFSET		8
#define ADDR_OFFSET		16
#define JMP_OFFSET		20

extern	char		g_payload[];
extern	size_t		g_payload_size;
extern	size_t		g_payload_offset;

typedef struct data_s {
	uint8_t					*_file_map;
	size_t					_file_size;
	Elf64_Addr				_oentry_offset;
} data_t;

void		*ft_memcpy(void *dest, const void *src, size_t n);
int			ft_memcmp(const void *s1, const void *s2, size_t n);

int			ft_strlen(char *str);
int			handle_error(int error_code);
int			handle_syscall(char *msg);

void		print_hex(void *data, size_t size);
void	ft_puthex(uint64_t n);

data_t		*get_data(void);
void		free_data(void);

uint8_t		gen_key(void);
int64_t		gen_key_64(void);
void		encrypt(uint8_t *data, size_t size, uint64_t key);

void		modify_payload(int64_t jmp_value, size_t offset, size_t size);
void		patch_payload(int64_t codecave_diff, int64_t key, int32_t jmp_range);

enum e_error_codes {
	SUCCESS = 0,
	FAILURE,
	BAD_ARGS,
	NOT_ELF_FILE,
	NOT_X86_64,
	CODECAVE_SIZE_TOO_SMALL,
	NO_CODECAVE_FOUND,
	NO_SECTION_FOUND,
	COPY_FAILED,
	ERROR_CODES_SIZE
};

#endif
