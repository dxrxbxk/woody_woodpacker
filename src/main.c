#include "woody_woodpacker.h"

#define PAGE_SIZE	4096

char	g_payload[]	= "\x52\x48\x8d\x35\xf8\xff\xff\xff\x48\x2b\x35\x58\x00\x00\x00\x48\x8b\x0d\x51\x00\x00\x00\x48\x8d\x3d\x52\x00\x00\x00\x48\x31\xdb\x48\x83\xf9\x00\x74\x23\x8a\x04\x1f\x30\x06\x48\xff\xc6\x48\xff\xc9\x48\xff\xc3\x48\x83\xe3\x07\xeb\xe6\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\xe0\xff\xff\xff\xba\x0f\x00\x00\x00\x0f\x05\x5a\xe9\x99\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
size_t	g_payload_size	= sizeof(g_payload) - 1;
int64_t g_exit_status	= SUCCESS;

static int	find_codecave(data_t *data, size_t *codecave_offset, size_t *codecave_size) {

	Elf64_Ehdr	*ehdr	= (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr	= (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);

	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags & PF_X) {

			*codecave_offset	= phdr[i].p_offset + phdr[i].p_filesz;
			*codecave_size		= phdr[i].p_offset + PAGE_SIZE - *codecave_offset;

			PRINT("phdr[i].p_offset: %lx, phdr[i].p_filesz: %lx, codecave_offset: %lx, codecave_size: %lx\n", phdr[i].p_offset, phdr[i].p_filesz, *codecave_offset, *codecave_size);

			if (*codecave_size < g_payload_size) 
				return (ERROR(CODECAVE_SIZE_TOO_SMALL));

			ehdr->e_entry		= phdr[i].p_vaddr + phdr[i].p_filesz;
			phdr[i].p_flags		|= PF_W;
			phdr[i].p_filesz	+= g_payload_size;
			phdr[i].p_memsz		+= g_payload_size;

			int32_t	jmp_range	= (int64_t)data->_oentry_offset - ((int64_t)phdr[i].p_offset + (int64_t)phdr[i].p_filesz) + ADDR_OFFSET;
			int64_t key			= gen_key_64();
			uint64_t start		= *codecave_offset - data->_oentry_offset;

			printf("Key: ");
			print_hex(&key, sizeof(key));


			PRINT("Old entry: %lx, phdr[i].p_vaddr: %lx, phdr[i].p_filesz: %lx\n", data->_oentry_offset, phdr[i].p_vaddr, phdr[i].p_filesz);

			encrypt(data->_file_map + data->_oentry_offset, phdr[i].p_filesz, key);

			patch_payload(start, key, jmp_range);


			PRINT("Found codecave program ehdr.address: %lx, offset: %lx\n", phdr[i].p_vaddr, *codecave_offset);
			PRINT("Old entry: %lx, new entry: %lx, jmp range: %i\n", data->_oentry_offset, ehdr->e_entry, jmp_range);

			return (SUCCESS);

			} 
		}

	return (FAILURE);
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
	return (FAILURE);
}

static int	update_section_size(data_t *data, size_t offset) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + header->e_shoff);
	Elf64_Shdr	*strtab = &shdr[header->e_shstrndx];
	char	*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	printf("update_section_size: offset: %lx\n", offset);

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (offset >= shdr[i].sh_offset) {
			if (i + 1 < header->e_shnum && offset < shdr[i + 1].sh_offset) {
				shdr[i].sh_size += g_payload_size;
				DEBUG_P("update_section_size: Found section %s at %lx\n", strtab_p + shdr[i].sh_name, shdr[i].sh_addr);
				return (SUCCESS);
			} else if (i + 1 == header->e_shnum) {
				shdr[i].sh_size += g_payload_size;
				DEBUG_P("update_section_size: Found section %s at %lx\n", strtab_p + shdr[i].sh_name, shdr[i].sh_addr);
				return (SUCCESS);
			}
		}
	}
	return (FAILURE);
}

static int	patch_new_file(data_t *data) {

	int fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd == -1)
		handle_syscall("open");

	if (write(fd, data->_file_map, data->_file_size) == -1) {
		close(fd);
		handle_syscall("write");
	}

	close(fd);

	return (SUCCESS);
}

static int	inject_payload(void) {

	data_t	*data	= get_data();
	size_t	codecave_offset	= 0;
	size_t	codecave_size	= 0;
	Elf64_Ehdr	*ehdr	= (Elf64_Ehdr *)data->_file_map;

	if (find_section_by_name(data, ".text"))
		return ERROR(NO_SECTION_FOUND);

	DEBUG_P("Entry offset: %lx\n", data->_oentry_offset);

	if (find_codecave(data, &codecave_offset, &codecave_size))
		return ERROR(NO_CODECAVE_FOUND);

	if (update_section_size(data, codecave_offset))
		return ERROR(NO_SECTION_FOUND);

	PRINT("codecave size: %zu, offset: %lx, payload size: %zu\n", codecave_size, codecave_offset, g_payload_size);

	if (ft_memcpy(data->_file_map + codecave_offset, g_payload, g_payload_size) == NULL)
		return ERROR(COPY_FAILED);

	patch_new_file(data);

	return (SUCCESS);
}

static int	check_file(int fd) {
	char	ehdr[5];

	if (read(fd, ehdr, 5) == -1) {
		close(fd);
		handle_syscall("read");
	}

	if (ft_memcmp(ehdr, "\x7f""ELF", 4) != 0) {
		return ERROR(NOT_ELF_FILE);
	} else if (ft_memcmp(ehdr + 4, "\x02", 1) != 0) {
		return ERROR(NOT_X86_64);
	}

	return (SUCCESS);
}

static int	map_file(char *filename) {
	int	fd = open(filename, O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	if (check_file(fd)) {
		close(fd);
		return (FAILURE);
	}

	ssize_t	file_size = lseek(fd, 0, SEEK_END);
	if (file_size == -1) {
		close(fd);
		handle_syscall("lseek");
	}

	lseek(fd, 0, SEEK_SET);

	void *file_map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (file_map == MAP_FAILED) {
		close(fd);
		handle_syscall("mmap");
	}

	data_t *data		= get_data();
	data->_file_map		= file_map;
	data->_file_size	= file_size;

	close(fd);

	return (SUCCESS);
}

static int handle_status(int status) {
    if (status != SUCCESS) {
        free_data();
        return status;
    }
    return (SUCCESS);
}

int main(int argc, char *argv[]) {
	if (argc == 2) {
		if ((handle_status(map_file(argv[1]))) != SUCCESS ||
			(handle_status(inject_payload())) != SUCCESS) {
			return (g_exit_status);
		}
		free_data();
		return (SUCCESS);
	} else
		return ERROR(BAD_ARGS);
}
