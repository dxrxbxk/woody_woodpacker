#include "woody_woodpacker.h"

#define PAGE_SIZE	4096

//char	g_payload[]	= "\x52\x48\x8d\x35\xf8\xff\xff\xff\x48\x2b\x35\x58\x00\x00\x00\x48\x8b\x0d\x51\x00\x00\x00\x48\x8d\x3d\x52\x00\x00\x00\x48\x31\xdb\x48\x83\xf9\x00\x74\x23\x8a\x04\x1f\x30\x06\x48\xff\xc6\x48\xff\xc9\x48\xff\xc3\x48\x83\xe3\x07\xeb\xe6\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\xe0\xff\xff\xff\xba\x0f\x00\x00\x00\x0f\x05\x5a\xe9\x99\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char	g_payload[] = "\x52\xeb\x0f\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\xe0\xff\xff\xff\xba\x0f\x00\x00\x00\x0f\x05\x5a\xe9\xd0\xff\xff\xff";
size_t	g_payload_size	= sizeof(g_payload) - 1;
int64_t g_exit_status	= SUCCESS;

void	ft_memmove(void *dst, const void *src, size_t n) {
	uint8_t *d = (uint8_t *)dst;
	const uint8_t *s = (const uint8_t *)src;

	if (d < s)
		while (n--)
			*d++ = *s++;
	else {
		d += n;
		s += n;
		while (n--)
			*--d = *--s;
	}
}


static Elf64_Shdr* find_section_by_name(data_t *data, char *name) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + header->e_shoff);
	Elf64_Shdr	*strtab = &shdr[header->e_shstrndx];
	char	*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (ft_memcmp(strtab_p + shdr[i].sh_name, name, ft_strlen(name)) == 0) {
			DEBUG_P("find_section_by_name: Found section %s at %lx\n", name, shdr[i].sh_addr);
			if (ft_memcmp(name, ".text", 5) == 0)
				data->_oentry_offset = shdr[i].sh_addr;
			return (&shdr[i]);
		}
	}
	return (NULL);
}

static Elf64_Shdr* find_section_by_address(data_t *data, size_t address) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + header->e_shoff);
	Elf64_Shdr	*strtab = &shdr[header->e_shstrndx];
	char	*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (address >= shdr[i].sh_addr && address < shdr[i].sh_addr + shdr[i].sh_size) {
			DEBUG_P("find_section_by_address: Found section at %lx, name: %s\n", shdr[i].sh_addr, strtab_p + shdr[i].sh_name);
			return (&shdr[i]);
		}
	}
	return (NULL);
}

static int	find_codecave(data_t *data, size_t *codecave_offset, size_t *codecave_size) {

	Elf64_Ehdr	*ehdr	= (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr	= (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);
	Elf64_Shdr	*shdr	= (Elf64_Shdr *)(data->_file_map + ehdr->e_shoff);

	// data infection, after .data before .bss
	printf("section header offset: %lx\n", ehdr->e_shoff);
	printf("program header offset: %lx\n", ehdr->e_phoff);

	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags & PF_W)
		{
			Elf64_Shdr *codec = find_section_by_address(data, phdr[i].p_vaddr + phdr[i].p_filesz);
			if (codec) {
				//printf("changing section header\n");
				//codec->sh_size += g_payload_size;
				//codec->sh_offset += g_payload_size;
				//ehdr->e_shoff += g_payload_size;
				//codec->sh_addr += g_payload_size;

				//codec->sh_flags |= SHF_EXECINSTR;

			}
			ehdr->e_entry = phdr[i].p_vaddr + phdr[i].p_filesz;
			*codecave_offset = phdr[i].p_offset + phdr[i].p_filesz;


			*codecave_size = g_payload_size;
			phdr[i].p_filesz += g_payload_size;
			phdr[i].p_memsz += g_payload_size;
			phdr[i].p_flags |= PF_X;
			DEBUG_P("find_codecave: Found codecave at %lx\n", *codecave_offset);



			int32_t	jmp_range = (int64_t)data->_oentry_offset - ((int64_t)phdr[i].p_vaddr + (int64_t)phdr[i].p_filesz);
			//int64_t key;
			//
			//if (gen_key_64(&key) == -1)
			//	return EXIT_FAILURE;
			//
			//uint64_t start = *codecave_offset - data->_oentry_offset;
			//
			//if (print_key(key))
			//	return EXIT_FAILURE;


			PRINT("Old entry: %lx, phdr[i].p_vaddr: %lx, phdr[i].p_filesz: %lx, phdr[i].p_offset: %lx\n", data->_oentry_offset, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_offset);
			modify_payload(jmp_range, JMP_OFFSET, sizeof(jmp_range));

			//encrypt(data->_file_map + data->_oentry_offset, phdr[i].p_filesz, key);

			//patch_payload(start, key, jmp_range);

			ft_memcpy(data->_file_map + *codecave_offset, g_payload, g_payload_size);


			PRINT("Found codecave program ehdr.address: %lx, offset: %lx\n", phdr[i].p_vaddr, *codecave_offset);
			PRINT("Old entry: %lx, new entry: %lx, jmp range: %i\n", data->_oentry_offset, ehdr->e_entry, jmp_range);

		}
	}
	return (EXIT_SUCCESS);
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

	if (find_section_by_name(data, ".text") == NULL) {
		write(STDERR_FILENO, "Failed to find section\n", 24);
		return (EXIT_FAILURE); }

	DEBUG_P("Entry offset: %lx\n", data->_oentry_offset);

	if (find_codecave(data, &codecave_offset, &codecave_size)) {
		write(STDERR_FILENO, "Failed to find codecave\n", 25);
		return (EXIT_FAILURE); }

	//if (update_section_size(data, codecave_offset)) {
	//	write(STDERR_FILENO, "Failed to update section size\n", 31);
	//	return (EXIT_FAILURE); }

	PRINT("codecave size: %zu, offset: %lx, payload size: %zu\n", codecave_size, codecave_offset, g_payload_size);



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

	data->_fd = open(filename, O_RDWR);

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

	printf("file size: %zu\n", data->_file_size);
	printf("file size: %zu\n", data->_file_size);


	uint8_t *file_map = mmap(NULL, data->_file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, data->_fd, 0);

	if (file_map == MAP_FAILED) {
		runtime_error("Failed to map file");
		return -1;
	}

	uint8_t *new_map = mmap(NULL, data->_file_size + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (new_map == MAP_FAILED) {
		runtime_error("Failed to map file");
		return -1;
	}

	ft_memcpy(new_map, file_map, data->_file_size);

	munmap(file_map, data->_file_size);

	data->_file_size += PAGE_SIZE;

	data->_file_map = new_map;

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
