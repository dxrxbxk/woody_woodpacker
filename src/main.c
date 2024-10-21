#include <bits/stdint-uintn.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include "utils.h"

#define ELF_32 1
#define ELF_64 2
#define SH_PROGBITS 1
#define SHF_EXECINSTR 4
#define PT_LOAD 1
#define PF_X 1


typedef struct Elf64Hdr_s {
  uint8_t     e_ident[16];         /* Magic number and other info */
  uint16_t    e_type;              /* Object file type */
  uint16_t    e_machine;           /* Architecture */
  uint32_t    e_version;           /* Object file version */
  uint64_t    e_entry;             /* Entry point virtual address */
  uint64_t    e_phoff;             /* Program header table file offset */
  uint64_t    e_shoff;             /* Section header table file offset */
  uint32_t    e_flags;             /* Processor-specific flags */
  uint16_t    e_ehsize;            /* ELF header size in bytes */
  uint16_t    e_phentsize;         /* Program header table entry size */
  uint16_t    e_phnum;             /* Program header table entry count */
  uint16_t    e_shentsize;         /* Section header table entry size */
  uint16_t    e_shnum;             /* Section header table entry count */
  uint16_t    e_shstrndx;          /* Section header string table index */
} Elf64Hdr_t;


typedef struct {
	uint32_t p_type;    /* Type de segment */
	uint32_t p_flags;   /* Flags du segment */
	uint64_t p_offset;  /* Offset du segment dans le fichier */
	uint64_t p_vaddr;   /* Adresse virtuelle du segment */
	uint64_t p_paddr;   /* Adresse physique du segment */
	uint64_t p_filesz;  /* Taille du segment dans le fichier */
	uint64_t p_memsz;   /* Taille du segment en mémoire */
	uint64_t p_align;   /* Alignement du segment */
} Elf64_Phdr;

typedef struct {
	uint32_t sh_name;       /* Nom de la section */
	uint32_t sh_type;       /* Type de section */
	uint64_t sh_flags;      /* Drapeaux de section */
	uint64_t sh_addr;       /* Adresse de section */
	uint64_t sh_offset;     /* Offset de section */
	uint64_t sh_size;       /* Taille de section */
	uint32_t sh_link;       /* Index de section */
	uint32_t sh_info;       /* Info de section */
	uint64_t sh_addralign;  /* Alignement de section */
	uint64_t sh_entsize;    /* Taille d'entrée de section */
} Elf64_Shdr;

const char shellcode[] = "\x31\xc0\x99\xb2\x0a\xff\xc0\x89\xc7\x48\x8d\x35\x12\x00\x00\x00\x0f\x05\xb2\x2a\x31\xc0\xff\xc0\xf6\xe2\x89\xc7\x31\xc0\xb0\x3c\x0f\x05\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x0a";
size_t shellcode_length = sizeof(shellcode) - 1;

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

int	get_shellcode_size(const char *code) {
	int i = 0;
	int size = 0;
	printf("code: %s\n", code);
	while (code[i] != '\0') {
		if (code[i] == '\\')
			size++;
		i++;
	}
	return size;
}

void print_shellcode(const char *code) {
	for (size_t i = 0; i < shellcode_length; i++) {
		printf("\\x%02x", (unsigned char)shellcode[i]);
	}
}

void *get_section_data(void *file_map, Elf64Hdr_t *header, const char *section_name, size_t *section_size) {
    Elf64_Shdr *sections = (Elf64_Shdr *)((char *)file_map + header->e_shoff);
    Elf64_Shdr *section;
    Elf64_Shdr *strtab = &sections[header->e_shstrndx];
    char *strtab_data = (char *)file_map + strtab->sh_offset;

    for (size_t i = 0; i < header->e_shnum; i++) {
        section = &sections[i];
        const char *name = &strtab_data[section->sh_name];

        if (strcmp(name, section_name) == 0) {
            *section_size = section->sh_size;
			print_data((uint8_t *)file_map + section->sh_offset, section->sh_size);
            return (char *)file_map + section->sh_offset;
        }
    }

    return NULL;
}

void patch_shellcode(void *file_map, Elf64Hdr_t *header, Elf64_Phdr *load_segment, void *section_data, size_t section_size) {
    void *shellcode_addr = (char *)file_map + load_segment->p_vaddr;
    size_t segment_size = load_segment->p_memsz;
	size_t pfile = load_segment->p_filesz;

	printf("shellcode_addr: %p\n", shellcode_addr);
	printf("segment_size: %lu\n", segment_size);
	printf("section_size: %lu\n", section_size);

	section_size += shellcode_length;
	segment_size += shellcode_length;
	pfile += shellcode_length;


	if (section_size > segment_size) {
		handle_error("Shellcode too big\n");
	}

	memmove(&shellcode_addr + shellcode_length, shellcode_addr, section_size);
	memcpy(shellcode_addr, shellcode, shellcode_length);


	print_data((uint8_t *)shellcode_addr, segment_size);

	header->e_entry = load_segment->p_vaddr;
}

int	check_file(char *filename) {

	int	fd = open(filename, O_RDONLY);
	if (fd == -1)
		handle_syscall("open", fd);

	ssize_t	file_size = lseek(fd, 0, SEEK_END);
	if (file_size == -1)
		handle_syscall("lseek", fd);

	lseek(fd, 0, SEEK_SET);

	void *file_map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (file_map == MAP_FAILED)
		handle_syscall("mmap", fd);

	Elf64Hdr_t	*header = (Elf64Hdr_t *)file_map;

	if (memcmp(header->e_ident, "\x7f""ELF", 4) != 0)
		return handle_error("Not an ELF file\n");
	else if (header->e_ident[4] == ELF_32)
		return handle_error("File architecture not suported. x86_64 only\n");
	else if (header->e_ident[4] != ELF_64)
		return handle_error("Unknown ELF format\n");


	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)file_map + header->e_phoff);
	Elf64_Phdr *load_segment = NULL;
	for (size_t i = 0; i < header->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
			load_segment = &phdr[i];
			break;
		}
	}

	if (load_segment == NULL)
		return handle_error("No executable segment found\n");

	size_t section_size;
	void *section_data = get_section_data(file_map, header, ".text", &section_size);
	if (section_data == NULL)
		return handle_error("No .text section found\n");

	patch_shellcode(file_map, header, load_segment, section_data, section_size);

	printf("load_segment->p_vaddr: %lx\n", load_segment->p_vaddr);
	printf("header->e_entry: %lx\n", header->e_entry);

	header->e_entry = load_segment->p_vaddr;

	int fd2 = open("woody", O_CREAT | O_RDWR | O_TRUNC, 0755);
	if (fd2 == -1)
		handle_syscall("open", fd2);

	write(fd2, file_map, file_size);

	if (munmap(file_map, file_size) == -1)
		handle_syscall("munmap", fd);

	close(fd);
	close(fd2);

	return 0;
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
	  if (check_file(argv[1]))
		  return (EXIT_FAILURE);
	  return (EXIT_SUCCESS);
  } else
	  return handle_error("Usage: ./woody_woodpacker <filename>\n");
}

/* 
int	check_file(char *filename) {
	Elf64Hdr_t	header;
	ssize_t		size;
								int fd2;

	int	fd = open(filename, O_RDONLY);
	if (fd == -1)
		handle_syscall("open", fd);
	else {
		if (read(fd, &header, sizeof(Elf64Hdr_t)) == -1)
			handle_syscall("read", fd);
		else {
			if (header.e_ident[0] == 0x7f && header.e_ident[1] == 'E' && header.e_ident[2] == 'L' && header.e_ident[3] == 'F') {
				if (header.e_ident[4] == ELF_32) {
					close(fd);
					return handle_error("File architecture not suported. x86_64 only\n");
				}
				else if (header.e_ident[4] == ELF_64) {

					lseek(fd, 0, SEEK_SET);
					size = lseek(fd, 0, SEEK_END);
					if (size == -1) {
						handle_syscall("lseek", fd);
					}
					else {
						uint8_t	*data = malloc(size);
						if (data == NULL)
							handle_syscall("malloc", fd);
						else {
							lseek(fd, 0, SEEK_SET);
							if (read(fd, data, size) == -1) {
								free(data);
								handle_syscall("read", fd);
							}
							else {
							}
						}
					}
				}
				else
					return handle_error("Unknown ELF format\n");
			} else
				return handle_error("Not an ELF file\n");
		}
	}
	close(fd);
	return (EXIT_SUCCESS);
}*/
