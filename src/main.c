#include "utils.h"


const char	shellcode[]			= "\x48\x31\xc0\xb0\x01\xbf\x01\x00\x00\x00\x48\x8d\x35\x13\x00\x00\x00\xba\x0f\x00\x00\x00\x0f\x05\x48\x31\xc0\xb0\x3c\xbf\x2a\x00\x00\x00\x0f\x05\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x0d";
size_t		shellcode_size		= sizeof(shellcode) - 1;

data_t*	data_getter(void) {
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


void	data_destroyer(void) {
	data_t *data = data_getter();

	if (data) {
		if (data->_file_map)
			munmap(data->_file_map, data->_file_size);
		free(data);
	}
}


 //		Map in the umodified target ELF executable and the user-supplied payload, a position-independent blob
 //		Locate the first executable segment by parsing program headers
 //		Locate the last section in the executable segment by parsing section headers
 //		Expand the last section (in the segment) section header's sh_size and program header's p_memsz/p_filesz by the size of the user-supplied payload
 //		Fixup section headers' sh_offset's and program headers' p_offset's (move down sections and segments to make room for the payload and a small "stager stub")
 //		Fix offsets in the ELF header (e_shoff, e_phoff, etc..)
 //		Modify the ELF header e_entry (ELF entrypoint offset) to point to the injected code
 //		Create a new ELF containing the injected code and modified ELF headers

static Elf64Phdr_t*	parse_program_headers(data_t *data) {
	
	Elf64Hdr_t	*header = (Elf64Hdr_t *)data->_file_map;
	Elf64Phdr_t	*program_headers = (Elf64Phdr_t *)(data->_file_map + header->e_phoff);

	for (size_t i = 0; i < header->e_phnum; i++) {
		if (program_headers[i].p_flags & PF_X) {
			printf("Found executable segment at offset 0x%lx, size %li\n", program_headers[i].p_offset, program_headers[i].p_filesz);
			return &program_headers[i];
		}
	}

	return NULL;
}

// make space for the shellcode in the last section of the executable segment
//
void	expand_section(data_t *data, Elf64Shdr_t *shdr, Elf64Phdr_t *phdr)

{
	Elf64Hdr_t	*header = (Elf64Hdr_t *)data->_file_map;
	printf("--------------------\n");
	printf("header->e_shoff: %lx\n", header->e_shoff);
	printf("header->e_phoff: %lx\n", header->e_phoff);
	printf("shdr->sh_offset: %lx\n", shdr->sh_offset);
	printf("shdr->sh_size: %li\n", shdr->sh_size);
	printf("phdr->p_offset: %lx\n", phdr->p_offset);
	printf("phdr->p_filesz: %li\n", phdr->p_filesz);
	printf("phdr->p_memsz: %li\n", phdr->p_memsz);
	printf("header->e_entry: %lx\n", header->e_entry);
	

//	// expand the section
//	shdr->sh_size += shellcode_size;
//
//	// expand the segment
//	phdr->p_filesz += shellcode_size;
//	phdr->p_memsz += shellcode_size;
//
//	// move down sections
//	Elf64Shdr_t	*section_headers = (Elf64Shdr_t *)(data->_file_map + header->e_shoff);
//	for (size_t i = 0; i < header->e_shnum; i++) {
//			section_headers[i].sh_offset += shellcode_size;
//	}
//
//	// move down segments
//	Elf64Phdr_t	*program_headers = (Elf64Phdr_t *)(data->_file_map + header->e_phoff);
//	for (size_t i = 0; i < header->e_phnum; i++) {
//			program_headers[i].p_offset += shellcode_size;
//	}
//
////	 fix offsets in the ELF header
//	header->e_shoff += shellcode_size;
//	header->e_phoff += shellcode_size;
//
//
	// encrypt the shellcode
	//uint8_t key = gen_key();
	//encrypt((uint8_t *)shellcode, shellcode_size, key);

	// append the shellcode to the section
	memcpy(data->_file_map + shdr->sh_offset + shdr->sh_size - shellcode_size, shellcode, shellcode_size);

	header->e_entry = shdr->sh_addr + shdr->sh_size - shellcode_size;

	//printf("Shellcode key: 0x%02x\n", key);
	printf("Shellcode size: %li\n", shellcode_size);
	printf("Shellcode appended at offset 0x%lx\n", shdr->sh_offset + shdr->sh_size - shellcode_size);

}

static Elf64Shdr_t	*parse_section_headers(data_t *data, Elf64Phdr_t *phdr) {

	uint64_t	segment_end			= phdr->p_offset + phdr->p_filesz;
	Elf64Hdr_t	*header				= (Elf64Hdr_t *)data->_file_map;
	Elf64Shdr_t	*section_headers	= (Elf64Shdr_t *)(data->_file_map + header->e_shoff);

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (section_headers[i].sh_offset + section_headers[i].sh_size == segment_end) {
			printf("Found last section in segment at offset 0x%lx, size %li\n", section_headers[i].sh_offset, section_headers[i].sh_size);
			printf("Section name: %s\n", data->_file_map + section_headers[header->e_shstrndx].sh_offset + section_headers[i].sh_name);
			return section_headers + i;
		}
	}
	return NULL;
}

#define MAP_ANONYMOUS 0x20

static int patch_new_file(data_t *data, Elf64Phdr_t *phdr, Elf64Shdr_t *shdr) {

	int fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd == -1)
		handle_syscall("open", fd);

	if (write(fd, data->_file_map, data->_file_size) == -1)
		handle_syscall("write", fd);

	return (EXIT_SUCCESS);
}

static int	inject_shellcode(void) {

	data_t *data = data_getter();


	Elf64Phdr_t	*phdr = parse_program_headers(data);
	if (phdr == NULL)
		return handle_error("No executable segment found\n");

	Elf64Shdr_t	*shdr = parse_section_headers(data, phdr);
	if (shdr == NULL)
		return handle_error("No section found\n");

	if ((shdr + 1)->sh_addr - shdr->sh_addr - shdr->sh_size >= shellcode_size) {
		printf("Shellcode fits in section\n");
		expand_section(data, shdr, phdr);
		patch_new_file(data, phdr, shdr);
	} else {
		return handle_error("Shellcode too big for section\n");
	}

	//check if the shellcode fits in the section
	return (EXIT_SUCCESS);
}

static int	check_file(char *filename) {

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

	data_t *data		= data_getter();
	data->_file_map		= file_map;
	data->_file_size	= file_size;

	return inject_shellcode();
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
	  if (check_file(argv[1])) {
		  data_destroyer();
		  return (EXIT_FAILURE);
	  }
	  return (EXIT_SUCCESS);
  } else
	  return handle_error("Usage: ./woody_woodpacker <filename>\n");
}
