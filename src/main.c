#include "utils.h"

// woody one with relative jump
//char shellcode[] = "\x52\x50\xb8\x0a\x00\x00\x00\x50\x48\xb8\x44\x59\x2e\x2e\x2e\x2e\x00\x00\x50\x48\xb8\x2e\x2e\x2e\x2e\x57\x4f\x4f\x00\x50\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\xba\x11\x00\x00\x00\x0f\x05\x58\x58\x58\x58\x5a\xe9\xb7\xfe\xff\xff";


// working and we push rax first
//char shellcode[] = "\x52\x50\xb8\x0a\x00\x00\x00\x50\x48\xb8\x44\x59\x2e\x2e\x2e\x2e\x00\x00\x50\x48\xb8\x2e\x2e\x2e\x2e\x57\x4f\x4f\x00\x50\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\xba\x11\x00\x00\x00\x0f\x05\x58\x58\x58\x58\x5a\xe9\xb7\xfe\xff\xff";

// working and dont push rax first
char shellcode[]		= "\x52\xb8\x0a\x00\x00\x00\x50\x48\xb8\x44\x59\x2e\x2e\x2e\x2e\x00\x00\x50\x48\xb8\x2e\x2e\x2e\x2e\x57\x4f\x4f\x00\x50\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\xba\x11\x00\x00\x00\x0f\x05\x58\x58\x58\x5a\xe9\xc6\xff\xff\xff";

size_t shellcode_size	= sizeof(shellcode) - 1;

void patch_jmp_relative(int64_t offset) {
	shellcode[sizeof(shellcode) - 5] = offset & 0xFF;
	shellcode[sizeof(shellcode) - 4] = (offset >> 8) & 0xFF;
	shellcode[sizeof(shellcode) - 3] = (offset >> 16) & 0xFF;
	shellcode[sizeof(shellcode) - 2] = (offset >> 24) & 0xFF;
}

static int		find_codecave(data_t *data, size_t *codecave_offset, size_t *codecave_size) {
	
	Elf64_Ehdr	*ehdr				= (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr				= (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);

	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags & PF_X) {

			Elf64_Phdr *next		= &phdr[i + 1];
			size_t end_of_segment	= phdr[i].p_offset + phdr[i].p_filesz;

			DEBUG_P("offset %lx, and next offset %lx\n", phdr[i].p_offset, next->p_offset);

			if (i + 1 < ehdr->e_phnum && next->p_type == PT_LOAD) {
				*codecave_offset	= end_of_segment;
				*codecave_size		= next->p_offset - end_of_segment;

				if (*codecave_size < shellcode_size) 
					return (handle_error("Codecave too small\n"));
				

				int64_t	old_entry	= ehdr->e_entry;
				DEBUG_P("phdr[i].p_vaddr: %lx, phdr[i].p_filesz: %lx, old_entry: %lx\n", phdr[i].p_vaddr, phdr[i].p_filesz, old_entry);
				phdr[i].p_filesz	+= shellcode_size;
				phdr[i].p_memsz		+= shellcode_size;
				ehdr->e_entry		= *codecave_offset;
				int64_t	jmp_range	= (int64_t)old_entry - ((int64_t)phdr[i].p_vaddr + (int64_t)phdr[i].p_filesz);

				//another way to calculate jmp range ? 

				PRINT("Old entry: %lx, new entry: %lx, jmp range: %li\n", old_entry, ehdr->e_entry, jmp_range);
				patch_jmp_relative(jmp_range);


				PRINT("Found codecave program ehdr.address: %lx, offset: %lx\n", phdr[i].p_vaddr, *codecave_offset);

				return (EXIT_SUCCESS);

			} 
		}
	}

	return (EXIT_FAILURE);
}

static int		find_section(data_t *data, Elf64_Addr addr) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + header->e_shoff);
	Elf64_Shdr	*strtab = &shdr[header->e_shstrndx];
	char		*strtab_p = (char *)data->_file_map + strtab->sh_offset;


	for (size_t i = 0; i < header->e_shnum; i++) {
		if (i + 1 < header->e_shnum && addr >= shdr[i].sh_addr && addr < shdr[i + 1].sh_addr) {
			DEBUG_P("find_section: Found section %s at %lx\n", strtab_p + shdr[i].sh_name, addr);
			shdr[i].sh_size += shellcode_size;
			return (EXIT_SUCCESS);
		}
	}
	return (EXIT_FAILURE);
}

static int patch_new_file(data_t *data) {

	int fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd == -1)
		handle_syscall("open");

	if (write(fd, data->_file_map, data->_file_size) == -1)
		handle_syscall("write");

	close(fd);

	return (EXIT_SUCCESS);
}


static int	inject_payload(void) {

	data_t		*data			= get_data();
	size_t		codecave_offset = 0;
	size_t		codecave_size	= 0;
	Elf64_Ehdr	*ehdr			= (Elf64_Ehdr *)data->_file_map;


	if (find_codecave(data, &codecave_offset, &codecave_size))
		return handle_error("No codecave found\n");

	PRINT("Codecave size: %zu, offset: %lx, shellcode size: %zu\n", codecave_size, codecave_offset, shellcode_size);

	if (find_section(data, codecave_offset))
		return handle_error("No section found\n");

	if (ft_memcpy(data->_file_map + codecave_offset, shellcode, shellcode_size) == NULL)
		handle_error("ft_memcpy");

	//const uintptr_t page_size = 4096;
	//if (mprotect((void *)((uintptr_t)&ehdr->e_entry & ~(uintptr_t)4095), 4096, PROT_READ | PROT_WRITE) == -1)
	//	handle_syscall("mprotect", -1);

	patch_new_file(data);

	return (EXIT_SUCCESS);
}

static int	check_file(char *filename) {

	int	fd = open(filename, O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	ssize_t	file_size = lseek(fd, 0, SEEK_END);
	if (file_size == -1)
		handle_syscall("lseek");

	lseek(fd, 0, SEEK_SET);

	void *file_map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (file_map == MAP_FAILED)
		handle_syscall("mmap");


	Elf64_Ehdr	*header = (Elf64_Ehdr *)file_map;

	if (ft_memcmp(header->e_ident, "\x7f""ELF", 4) != 0)
		return handle_error("Not an ELF file\n");
	else if (header->e_ident[4] == ELF_32)
		return handle_error("File architecture not suported. x86_64 only\n");
	else if (header->e_ident[4] != ELF_64)
		return handle_error("Unknown ELF format\n");

	data_t *data		= get_data();
	data->_file_map		= file_map;
	data->_file_size	= file_size;

	close(fd);
	return (EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
	  if (check_file(argv[1])) {
		  return (EXIT_FAILURE);
	  } else if (inject_payload()) {
		  return (EXIT_FAILURE);
	  }
	  free_data();
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

