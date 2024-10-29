#include "utils.h"

//char	shellcode[]			= "\x48\x31\xc0\xb0\x01\xbf\x01\x00\x00\x00\x48\x8d\x35\x13\x00\x00\x00\xba\x0f\x00\x00\x00\x0f\x05\x48\x31\xc0\xb0\x3c\xbf\x2a\x00\x00\x00\x0f\x05\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x0d";
//char shellcode [] ="\x52\xb8\x0a\x00\x00\x00\x50\x48\xb8\x20\x4d\x65\x73\x73\x61\x67\x65\x50\x48\xb8\x49\x6e\x6a\x65\x63\x74\x65\x64\x50\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\xba\x11\x00\x00\x00\x0f\x05\x58\x58\x58\x5a\xe9\x16\x10\x00\x00";
char shellcode[] = "\x52\xb8\x0a\x00\x00\x00\x50\x48\xb8\x20\x4d\x65\x73\x73\x61\x67\x65\x50\x48\xb8\x49\x6e\x6a\x65\x63\x74\x65\x64\x50\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\xba\x11\x00\x00\x00\x0f\x05\x58\x58\x58\x5a\xb8\x50\x10\x00\x00\xff\xe0";

char mov[] = {0x48, 0xc7, 0xc0, 0x50, 0x10, 0x00, 0x00};
char jmp[] = {0xff, 0xe0};

#define PAGE_SIZE 4096  // Typically 4096 bytes for x86 architecture
#define PAGE_ROUND(x) (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))


static Elf64_Phdr*	get_phdr_text(data_t *data) {
	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr = (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);
	Elf64_Addr	original_offset = 0;
	Elf64_Addr	original_vaddr = 0;

	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags & PF_X) {
			printf("Found text segment at %lx\n", phdr[i].p_offset);

			original_vaddr = phdr[i].p_vaddr;
			original_offset = phdr[i].p_offset;

			printf("Original offset: %lx\n", original_offset);

			printf("Original vaddr: %lx\n", original_vaddr);

			phdr[i].p_vaddr -= PAGE_ROUND(sizeof(shellcode));
			phdr[i].p_paddr -= PAGE_ROUND(sizeof(shellcode));

			printf("New vaddr: %lx\n", phdr[i].p_vaddr);

			phdr[i].p_filesz += PAGE_ROUND(sizeof(shellcode));
			phdr[i].p_memsz += PAGE_ROUND(sizeof(shellcode));

			for (size_t j = 0; j < ehdr->e_phnum; j++) {
				if (phdr[j].p_offset > original_offset) {
					phdr[j].p_offset += PAGE_ROUND(sizeof(shellcode));
				}
			}

			printf("old entry: %lx\n", ehdr->e_entry);

			ehdr->e_entry = original_vaddr - PAGE_ROUND(sizeof(shellcode)) + sizeof(Elf64_Ehdr);

			printf("new entry: %lx\n", ehdr->e_entry);

			return &phdr[i];
		}
	}
	return NULL;
}

static int patch_new_file(data_t *data) {

	int fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd == -1)
		handle_syscall("open");

	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr = (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);

	size_t		phdr_size = ehdr->e_phnum * ehdr->e_phentsize;
	size_t		new_size = data->_file_size + PAGE_ROUND(sizeof(shellcode));

	uint8_t	*new_data = malloc(new_size);
	if (new_data == NULL)
		handle_syscall("malloc");

	ft_memcpy(new_data, ehdr, sizeof(Elf64_Ehdr));

	ft_memcpy(new_data + ehdr->e_phoff, phdr, phdr_size);

	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + ehdr->e_shoff);
	size_t		shdr_size = ehdr->e_shnum * ehdr->e_shentsize;

	ft_memcpy(new_data + ehdr->e_shoff, shdr, shdr_size);


	ft_memcpy(new_data + ehdr->e_shoff - PAGE_ROUND(sizeof(shellcode)), shellcode, sizeof(shellcode));

	ssize_t written = write(fd, new_data, new_size);
	if (written == -1)
		handle_syscall("write");

	free(new_data);
	close(fd);

	return (EXIT_SUCCESS);
}


static int	inject_payload(void) {

	data_t *data = get_data();

	Elf64_Addr original_vaddr = 0;
	size_t shellcode_size = sizeof(shellcode) - 1;

	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)data->_file_map;


	printf("Shellcode size: %li\n", shellcode_size);

	printf("e_shoff: %lx\n", ehdr->e_shoff);
	ehdr->e_shoff += PAGE_ROUND(sizeof(shellcode));
	printf("e_shoff: %lx\n", ehdr->e_shoff);



	get_phdr_text(data);

	ehdr->e_phoff += PAGE_ROUND(sizeof(shellcode));
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
	printf("File size: %ld\n", file_size);
	if (file_map == MAP_FAILED)
		handle_syscall("mmap");


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

