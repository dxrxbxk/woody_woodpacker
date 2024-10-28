#include "utils.h"


#define PAGE_SIZE 4096

char shellcode [] = {
	//mov
	0x48, 0xc7, 0xc0, 0x50, 0x10, 0x00, 0x00,
	//jmp
	0xff, 0xe0 };

#define JMP_PATCH_OFFSET 1


/* Algorithm for the Silvio .text infection method
1. Increase ehdr->e_shoff by PAGE_SIZE in the ELF file header.
2. Locate the text segment phdr:
1. Modify the entry point to the parasite location:
ehdr->e_entry = phdr[TEXT].p_vaddr + phdr[TEXT].p_filesz
2. Increase phdr[TEXT].p_filesz by the length of the parasite.
3. Increase phdr[TEXT].p_memsz by the length of the parasite.
3. For each phdr whose segment is after the parasite, increase
phdr[x].p_offset by PAGE_SIZE bytes.
4. Find the last shdr in the text segment and increase shdr[x].sh_size
by the length of the parasite (because this is the section that the parasite
will exist in).
5. For every shdr that exists after the parasite insertion, increase
shdr[x].sh_offset by PAGE_SIZE.
6. Insert the actual parasite code into the text segment at (file_base +
phdr[TEXT].p_filesz). */



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
	Elf64_Phdr	*phdr			= (Elf64_Phdr *)&data->_file_map[ehdr->e_phoff];
	Elf64_Shdr	*shdr			= (Elf64_Shdr *)&data->_file_map[ehdr->e_shoff];

	size_t		shellcode_size	= sizeof(shellcode);

	Elf64_Addr	text_segment_offset = 0;
	size_t		text_segment_size = 0;

	Elf64_Addr	old_entry = ehdr->e_entry;

	// Step 0
	ehdr->e_shoff += PAGE_SIZE;

	// Step 1
	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags & PF_X) {

			ehdr->e_entry = phdr[i].p_vaddr + phdr[i].p_filesz;

			phdr[i].p_filesz += shellcode_size;
			phdr[i].p_memsz += shellcode_size;


			text_segment_offset = phdr[i].p_offset;
			text_segment_size = phdr[i].p_filesz;
		}
	}

	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_offset > text_segment_offset + text_segment_size) {
			phdr[i].p_offset += PAGE_SIZE;
		}
	}

	for (size_t i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_offset >= text_segment_offset && shdr[i].sh_offset < text_segment_offset + text_segment_size) {
			shdr[i].sh_offset += shellcode_size;
		}
	}

	for (size_t i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_addr >= text_segment_offset) {
			shdr[i].sh_size += PAGE_SIZE;
		}
	}

	*(uint32_t *)&shellcode[JMP_PATCH_OFFSET] = old_entry;

	ft_memcpy(data->_file_map + text_segment_offset + text_segment_size, shellcode, shellcode_size);

	patch_new_file(data);

	return (EXIT_SUCCESS);
}

static int	check_file(char *filename) {
	data_t *data		= get_data();

	int	fd = open(filename, O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	ssize_t	file_size = lseek(fd, 0, SEEK_END);
	if (file_size == -1)
		handle_syscall("lseek");

	lseek(fd, 0, SEEK_SET);

	void *file_map = mmap(NULL, file_size + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (file_map == MAP_FAILED)
		handle_syscall("mmap");


	Elf64_Ehdr	*header = (Elf64_Ehdr *)file_map;

	if (ft_memcmp(header->e_ident, "\x7f""ELF", 4) != 0)
		return handle_error("Not an ELF file\n");
	else if (header->e_ident[4] == ELF_32)
		return handle_error("File architecture not suported. x86_64 only\n");
	else if (header->e_ident[4] != ELF_64)
		return handle_error("Unknown ELF format\n");

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

