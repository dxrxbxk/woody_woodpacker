#include "woody_woodpacker.h"

#define PAGE_SIZE	4096

char	g_payload[]	= "\x52\x48\x8d\x35\xf8\xff\xff\xff\x48\x2b\x35\x58\x00\x00\x00\x48\x8b\x0d\x51\x00\x00\x00\x48\x8d\x3d\x52\x00\x00\x00\x48\x31\xdb\x48\x83\xf9\x00\x74\x23\x8a\x04\x1f\x30\x06\x48\xff\xc6\x48\xff\xc9\x48\xff\xc3\x48\x83\xe3\x07\xeb\xe6\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\xe0\xff\xff\xff\xba\x0f\x00\x00\x00\x0f\x05\x5a\xe9\x99\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
size_t	g_payload_size	= sizeof(g_payload) - 1;
int64_t g_exit_status	= SUCCESS;


static int	find_codecave(data_t *data, size_t *codecave_offset, size_t *codecave_size) {

	Elf64_Ehdr	*ehdr	= (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr	= (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);

	for (size_t i = 0; i < ehdr->e_phnum; ++i) {

		if (phdr[i].p_type != PT_LOAD || (phdr[i].p_flags & PF_X) == 0)
			continue;

		*codecave_offset = phdr[i].p_offset + phdr[i].p_filesz;
		*codecave_size   = phdr[i].p_offset + PAGE_SIZE - *codecave_offset;

		PRINT("phdr[i].p_offset: %lx, phdr[i].p_filesz: %lx, codecave_offset: %lx, codecave_size: %lx\n",
			phdr[i].p_offset, phdr[i].p_filesz, *codecave_offset, *codecave_size);

		if (*codecave_size < g_payload_size) 
			return EXIT_FAILURE;

		ehdr->e_entry     = phdr[i].p_vaddr + phdr[i].p_filesz;
		phdr[i].p_flags  |= PF_W;
		phdr[i].p_filesz += g_payload_size;
		phdr[i].p_memsz  += g_payload_size;

		int32_t	jmp_range = (int64_t)data->_oentry_offset - ((int64_t)phdr[i].p_offset + (int64_t)phdr[i].p_filesz) + ADDR_OFFSET;
		int64_t key;

		if (gen_key_64(&key) == -1)
			return EXIT_FAILURE;

		uint64_t start = *codecave_offset - data->_oentry_offset;

		if (print_key(key))
			return EXIT_FAILURE;


		PRINT("Old entry: %lx, phdr[i].p_vaddr: %lx, phdr[i].p_filesz: %lx\n", data->_oentry_offset, phdr[i].p_vaddr, phdr[i].p_filesz);

		encrypt(data->_file_map + data->_oentry_offset, phdr[i].p_filesz, key);

		patch_payload(start, key, jmp_range);


		PRINT("Found codecave program ehdr.address: %lx, offset: %lx\n", phdr[i].p_vaddr, *codecave_offset);
		PRINT("Old entry: %lx, new entry: %lx, jmp range: %i\n", data->_oentry_offset, ehdr->e_entry, jmp_range);

		return (EXIT_SUCCESS);

	}

	return (EXIT_FAILURE);
}

static int	find_section_by_name(data_t *data, char *name) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + header->e_shoff);
	Elf64_Shdr	*strtab = &shdr[header->e_shstrndx];
	char	*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (ft_memcmp(strtab_p + shdr[i].sh_name, name, ft_strlen(name)) == 0) {
			DEBUG_P("find_section_by_name: Found section %s at %lx\n", name, shdr[i].sh_addr);
			data->_oentry_offset = shdr[i].sh_offset;
			return (SUCCESS);
		}
	}
	return (EXIT_FAILURE);
}

static int	update_section_size(data_t *data, size_t offset) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + header->e_shoff);
	Elf64_Shdr	*strtab = &shdr[header->e_shstrndx];
	char	*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	DEBUG_P("update_section_size: offset: %lx\n", offset);

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (offset >= shdr[i].sh_offset) {
			if (i + 1 < header->e_shnum && offset + g_payload_size <= shdr[i + 1].sh_offset) {
				shdr[i].sh_size += g_payload_size;
				DEBUG_P("update_section_size: Found section %s at %lx\n", strtab_p + shdr[i].sh_name, shdr[i].sh_addr);
				return (EXIT_SUCCESS);
			} else if (i + 1 == header->e_shnum && offset < shdr[i].sh_offset + shdr[i].sh_size) {
				shdr[i].sh_size += g_payload_size;
				DEBUG_P("update_section_size: Found section %s at %lx\n", strtab_p + shdr[i].sh_name, shdr[i].sh_addr);
				return (EXIT_SUCCESS);
			}
		}
	}
	return (EXIT_FAILURE);
}

static int	patch_new_file(data_t *data) {

	int fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd == -1)
		return (EXIT_FAILURE);

	if (write(fd, data->_file_map, data->_file_size) == -1) {
		close(fd);
		return (EXIT_FAILURE);
	}

	close(fd);

	return (EXIT_SUCCESS);
}

static int	inject_payload(data_t* data) {

	size_t	codecave_offset	= 0;
	size_t	codecave_size = 0;
	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)data->_file_map;

	if (find_section_by_name(data, ".text")) {
		write(STDERR_FILENO, "Failed to find section\n", 24);
		return (EXIT_FAILURE); }

	DEBUG_P("Entry offset: %lx\n", data->_oentry_offset);

	if (find_codecave(data, &codecave_offset, &codecave_size)) {
		write(STDERR_FILENO, "Failed to find codecave\n", 25);
		return (EXIT_FAILURE); }

	if (update_section_size(data, codecave_offset)) {
		write(STDERR_FILENO, "Failed to update section size\n", 31);
		return (EXIT_FAILURE); }

	PRINT("codecave size: %zu, offset: %lx, payload size: %zu\n", codecave_size, codecave_offset, g_payload_size);

	if (ft_memcpy(data->_file_map + codecave_offset, g_payload, g_payload_size) == NULL) {
		write(STDERR_FILENO, "Failed to inject payload\n", 26);
		return (EXIT_FAILURE); }

	if (patch_new_file(data)) {
		write(STDERR_FILENO, "Failed to patch new file\n", 26);
		return (EXIT_FAILURE); }

	return (EXIT_SUCCESS);
}

void destroy_data(data_t *data) {

	if (data == NULL)
		return;

	if (data->_file_map != NULL)
		munmap(data->_file_map, data->_file_size);

	data->_file_map = NULL;

	if (data->_fd != -1)
		close(data->_fd);

	data->_fd = -1;
}



int init_data(data_t* data, const char *filename) {

	data->_fd            = -1;
	data->_file_map      = NULL;
	data->_file_size     = 0U;
	data->_oentry_offset = 0U;

	data->_fd = open(filename, O_RDONLY);

	if (data->_fd == -1) {
		runtime_error(filename);
		return -1;
	}

	{
		char ehdr[5U];

		if (read(data->_fd, ehdr, 5U) == -1) {
			runtime_error(filename);
			return -1;
		}

		if (ft_memcmp(ehdr, "\x7f""ELF", 4) != 0) {
			print_error("Not an ELF file");
			return -1;
		}
		else if (ft_memcmp(ehdr + 4, "\x02", 1) != 0) {
			print_error("Not an x86_64 ELF file");
			return -1;
		}
	}


	const ssize_t file_size = lseek(data->_fd, 0, SEEK_END);

	if (file_size == -1) {
		runtime_error("Failed to get file size");
		return -1;
	}

	data->_file_size = (size_t)file_size;

	void *file_map = mmap(NULL, data->_file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, data->_fd, 0);

	if (file_map == MAP_FAILED) {
		runtime_error("Failed to map file");
		return -1;
	}

	data->_file_map = (uint8_t *)file_map;

	return 0;
}


int main(int argc, char *argv[]) {

	if (argc != 2) {
		dprintf(STDERR_FILENO, "Usage: %s <filename>\n", argv[0U]);
		return EXIT_FAILURE; }

	data_t data;

	const int state = init_data(&data, argv[1U]);

	if (state != -1)
		inject_payload(&data);

	destroy_data(&data);

	return EXIT_SUCCESS;
}
