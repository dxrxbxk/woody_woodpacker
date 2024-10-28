#include "utils.h"

//char	shellcode[]			= "\x48\x31\xc0\xb0\x01\xbf\x01\x00\x00\x00\x48\x8d\x35\x13\x00\x00\x00\xba\x0f\x00\x00\x00\x0f\x05\x48\x31\xc0\xb0\x3c\xbf\x2a\x00\x00\x00\x0f\x05\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x0d";
//char shellcode [] ="\x52\xb8\x0a\x00\x00\x00\x50\x48\xb8\x20\x4d\x65\x73\x73\x61\x67\x65\x50\x48\xb8\x49\x6e\x6a\x65\x63\x74\x65\x64\x50\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\xba\x11\x00\x00\x00\x0f\x05\x58\x58\x58\x5a\xe9\x16\x10\x00\x00";
char shellcode[] = "\x52\xb8\x0a\x00\x00\x00\x50\x48\xb8\x20\x4d\x65\x73\x73\x61\x67\x65\x50\x48\xb8\x49\x6e\x6a\x65\x63\x74\x65\x64\x50\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\xba\x11\x00\x00\x00\x0f\x05\x58\x58\x58\x5a\xb8\x50\x10\x00\x00\xff\xe0";

char mov[] = {0x48, 0xc7, 0xc0, 0x50, 0x10, 0x00, 0x00};
char jmp[] = {0xff, 0xe0};

static void patch_jump(char *code, uintptr_t target_address) {
    uintptr_t jump_address = (uintptr_t)code + sizeof(shellcode) - 5; // Address of the jmp instruction
    int32_t offset = target_address - (jump_address + 5); // Calculate offset

    // Patch the jump instruction
    code[sizeof(shellcode) - 1] = (offset & 0xFF);          // Lower byte
    code[sizeof(shellcode) - 2] = (offset >> 8) & 0xFF;     // 2nd byte
    code[sizeof(shellcode) - 3] = (offset >> 16) & 0xFF;    // 3rd byte
    code[sizeof(shellcode) - 4] = (offset >> 24) & 0xFF;    // Higher byte
}


static Elf64_Phdr*	parse_program_headers(data_t *data, size_t *codecave_offset, size_t *codecave_size) {
	
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*program_headers = (Elf64_Phdr *)(data->_file_map + header->e_phoff);

	size_t shellcode_size = sizeof(shellcode) - 1;
	for (size_t i = 0; i < header->e_phnum; i++) {
		if (program_headers[i].p_type == PT_LOAD && program_headers[i].p_flags & PF_X) {
			Elf64_Phdr *next = &program_headers[i + 1];
			size_t end_of_segment = program_headers[i].p_offset + program_headers[i].p_filesz;

			if (i + 1 < header->e_phnum && next->p_type == PT_LOAD) {
				*codecave_offset = end_of_segment;
				*codecave_size = next->p_offset - end_of_segment;
				printf("Found codecave program header.address: %lx, offset: %lx, size: %lx\n", program_headers[i].p_vaddr, *codecave_offset, *codecave_size);

				if (*codecave_size >= shellcode_size) {
					printf("Codecave size: %zu, offset: %zu, shellcode size: %lu\n", *codecave_size, *codecave_offset, shellcode_size);
					return &program_headers[i];
				}
			}

		}
	}
	return NULL;
}

static Elf64_Shdr	*get_section_by_name(data_t *data, const char *name) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*sections = (Elf64_Shdr *)(data->_file_map + header->e_shoff);
	Elf64_Shdr	*strtab = &sections[header->e_shstrndx];
	char		*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (strcmp(strtab_p + sections[i].sh_name, name) == 0) {
			printf("Found section %s at %lx\n", name, sections[i].sh_addr);
			return &sections[i];
		}
	}
	return NULL;
}

static Elf64_Shdr	*get_section_by_address(data_t *data, size_t address) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*sections = (Elf64_Shdr *)(data->_file_map + header->e_shoff);

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (sections[i].sh_addr == address) {
			printf("Found section at %lx\n", address);
			return &sections[i];
		}
	}
	return NULL;
}

static int patch_new_file(data_t *data) {

	int fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd == -1)
		handle_syscall("open", fd);

	if (write(fd, data->_file_map, data->_file_size) == -1)
		handle_syscall("write", fd);

	close(fd);

	return (EXIT_SUCCESS);
}


static int	inject_payload(void) {

	data_t *data = get_data();
	size_t	codecave_offset = 0;
	size_t	codecave_size = 0;
	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)data->_file_map;


	Elf64_Phdr	*phdr = parse_program_headers(data, &codecave_offset, &codecave_size);
	if (phdr == NULL)
		return handle_error("No codecave found\n");


	Elf64_Shdr	*shdr = get_section_by_name(data, ".fini");
	if (shdr == NULL)
		return handle_error("No .text section found\n");

	printf("Shellcode entrypoint: %lx\n", codecave_offset);

	if (codecave_offset + codecave_size > data->_file_size)
		return handle_error("Codecave out of bounds\n");

	size_t shellcode_size = sizeof(shellcode) - 1;
	if (codecave_size < shellcode_size)
		return handle_error("Codecave too small\n");

	uint64_t old_entry = ehdr->e_entry;

	printf("Old entrypoint: %lx\n", old_entry);


	memcpy(data->_file_map + codecave_offset, shellcode, shellcode_size);
	//patch_jump(shellcode, old_entry);

	const uintptr_t page_size = 4096;
	if (mprotect((void *)((uintptr_t)&ehdr->e_entry & ~(uintptr_t)4095), 4096, PROT_READ | PROT_WRITE) == -1)
		handle_syscall("mprotect", -1);
	

	ehdr->e_entry = codecave_offset;
	phdr->p_filesz += shellcode_size;
	phdr->p_memsz += shellcode_size;
	shdr->sh_size += shellcode_size;

	patch_new_file(data);

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


	Elf64_Ehdr	*header = (Elf64_Ehdr *)file_map;

	if (memcmp(header->e_ident, "\x7f""ELF", 4) != 0)
		return handle_error("Not an ELF file\n");
	else if (header->e_ident[4] == ELF_32)
		return handle_error("File architecture not suported. x86_64 only\n");
	else if (header->e_ident[4] != ELF_64)
		return handle_error("Unknown ELF format\n");

	data_t *data		= get_data();
	data->_file_map		= file_map;
	data->_file_size	= file_size;

	return (EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
	  if (check_file(argv[1])) {
		  return (EXIT_FAILURE);
	  } else if (inject_payload()) {
		  return (EXIT_FAILURE);
	  }
	  return (EXIT_SUCCESS);
  } else
	  return handle_error("Usage: ./woody_woodpacker <filename>\n");
}

//patch_t	init_patch(Elf64_Phdr *phdr, Elf64_Shdr *shdr, Elf64_Ehdr *ehdr) {
//	patch_t patch;
//
//	patch.entry_offset = phdr->p_offset + phdr->p_filesz - ehdr->e_entry;
//	patch.text_offset = phdr->p_offset + phdr->p_filesz - shdr->sh_addr;
//	patch.segment_offset =	phdr->p_memsz;
//
//	//printf("entry_offset: %lx\n", patch.entry_offset);
//	//printf("text_offset: %lx\n", patch.text_offset);
//	//printf("segment_offset: %lx\n", patch.segment_offset);
//
//	return patch;
//}

