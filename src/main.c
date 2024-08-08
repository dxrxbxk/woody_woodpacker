#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include "utils.h"

#define ELF_32 1
#define ELF_64 2

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

int	check_file(char *filename) {
	Elf64Hdr_t	header;
	int	fd = open(filename, O_RDONLY);
	if (fd == -1)
		handle_syscall("open");
	else {
		if (read(fd, &header, sizeof(Elf64Hdr_t)) == -1)
			handle_syscall("read");
		else {
			if (header.e_ident[0] == 0x7f && header.e_ident[1] == 'E' && header.e_ident[2] == 'L' && header.e_ident[3] == 'F') {
				if (header.e_ident[4] == ELF_32)
					return handle_error("File architecture not suported. x86_64 only\n");
				else if (header.e_ident[4] == ELF_64)
					printf("64 bits\n");
				else
					return handle_error("Unknown ELF format\n");
			} else
				return handle_error("Not an ELF file\n");
		}
	}
	close(fd);
	return (EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
	  if (check_file(argv[1]))
		  return (EXIT_FAILURE);
	  else

	  return (EXIT_SUCCESS);
  } else
	  return handle_error("Usage: ./woody_woodpacker <filename>\n");
}
