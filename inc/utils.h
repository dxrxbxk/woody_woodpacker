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

#define ELF_32 1
#define ELF_64 2
#define SH_PROGBITS 1
#define SHF_EXECINSTR 4
#define PT_LOAD 1
#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef uint64_t	Elf64_Addr;

int		ft_strlen(char *str);
int		handle_error(char *msg);
int		handle_syscall(char *msg, int fd);
void	print_data(const uint8_t *data, size_t size);

typedef struct Elf64Hdr_s {
	uint8_t     e_ident[16];			/* Magic number and other info */
	uint16_t    e_type;              	/* Object file type */
	uint16_t    e_machine;           	/* Architecture */
	uint32_t    e_version;           	/* Object file version */
	uint64_t    e_entry;             	/* Entry point virtual address */
	uint64_t    e_phoff;             	/* Program header table file offset */
	uint64_t    e_shoff;             	/* Section header table file offset */
	uint32_t    e_flags;             	/* Processor-specific flags */
	uint16_t    e_ehsize;            	/* ELF header size in bytes */
	uint16_t    e_phentsize;         	/* Program header table entry size */
	uint16_t    e_phnum;             	/* Program header table entry count */
	uint16_t    e_shentsize;         	/* Section header table entry size */
	uint16_t    e_shnum;             	/* Section header table entry count */
	uint16_t    e_shstrndx;		   	/* Section header string table index */
} Elf64Hdr_t;

typedef struct {
	uint32_t	p_type;				/* Segment type */
	uint32_t 	p_flags;   			/* Segment flags */
	uint64_t 	p_offset;  			/* Offset of segment in file */
	uint64_t 	p_vaddr;   			/* Virtual address of segment */
	uint64_t 	p_paddr;   			/* Reserved */
	uint64_t 	p_filesz;  			/* Size of segment in file */
	uint64_t 	p_memsz;   			/* Size of segment in memory */
	uint64_t 	p_align;   			/* Alignment of segment */
} Elf64Phdr_t;

typedef struct {
	uint32_t	sh_name;				/* Section name (string tbl index) */
	uint32_t 	sh_type;       		/* Section type */
	uint64_t 	sh_flags;      		/* Section flags */
	uint64_t 	sh_addr;       		/* Address where section is to be loaded */
	uint64_t 	sh_offset;     		/* File offset of section data */
	uint64_t 	sh_size;       		/* Size of section data */
	uint32_t 	sh_link;       		/* Section index linked to this section */
	uint32_t 	sh_info;       		/* Extra information */
	uint64_t 	sh_addralign;  		/* Section alignment */
	uint64_t 	sh_entsize;			/* Entry size if section holds table */
} Elf64Shdr_t;

typedef struct patch_s{
	/* offset from payload to pgm entrypoint */
	uint64_t				entry_offset;
	/* offset from payload to text entrypoint */
	uint64_t				text_offset;
	/* offset from payload to begin of segment */
	uint64_t				segment_offset;
} patch_t;

typedef struct data_s {
	uint8_t					*_file_map;
	size_t					_file_size;
} data_t;

#endif
