#include "woody_woodpacker.h"
#include <sys/stat.h>

#define PAGE_SIZE	4096

//char	g_payload[]	= "\x52\x48\x8d\x35\xf8\xff\xff\xff\x48\x2b\x35\x58\x00\x00\x00\x48\x8b\x0d\x51\x00\x00\x00\x48\x8d\x3d\x52\x00\x00\x00\x48\x31\xdb\x48\x83\xf9\x00\x74\x23\x8a\x04\x1f\x30\x06\x48\xff\xc6\x48\xff\xc9\x48\xff\xc3\x48\x83\xe3\x07\xeb\xe6\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\xe0\xff\xff\xff\xba\x0f\x00\x00\x00\x0f\x05\x5a\xe9\x99\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
char	g_payload[] = "\x52\xeb\x0f\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\xe0\xff\xff\xff\xba\x0f\x00\x00\x00\x0f\x05\x5a\xe9\xd0\xff\xff\xff";
size_t	g_payload_size	= sizeof(g_payload) - 1;
int64_t g_exit_status	= SUCCESS;

#define ALIGN(value, align) (((value) + (align - 1)) & ~(align - 1))


void	print_phdr(data_t *data) {
	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr = (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);

	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		printf("p_type: %x, p_flags: %x, p_offset: %lx, p_vaddr: %lx, p_paddr: %lx, p_filesz: %lx, p_memsz: %lx, p_align: %lx\n",
			phdr[i].p_type, phdr[i].p_flags, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_align);
	}
}

void	print_section(data_t *data) {
	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)data->_file_map;
	Elf64_Shdr	*shdr = (Elf64_Shdr *)(data->_file_map + ehdr->e_shoff);
	Elf64_Shdr	*strtab = &shdr[ehdr->e_shstrndx];
	char	*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	for (size_t i = 0; i < ehdr->e_shnum; i++) {
		printf("sh_name: %s, sh_type: %x, sh_flags: %lx, sh_addr: %lx, sh_offset: %lx, sh_size: %lx, sh_link: %x, sh_info: %x, sh_addralign: %lx, sh_entsize: %lx\n",
			strtab_p + shdr[i].sh_name, shdr[i].sh_type, shdr[i].sh_flags, shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_link, shdr[i].sh_info, shdr[i].sh_addralign, shdr[i].sh_entsize);
	}
}

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
			if (ft_memcmp(name, ".text", 5) == 0) {
				data->_oentry_offset = shdr[i].sh_addr;
			}
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


Elf64_Phdr *get_last_phdr(data_t *data) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr = (Elf64_Phdr *)(data->_file_map + header->e_phoff);

	return (&phdr[header->e_phnum - 1]);
}

Elf64_Phdr *create_segment(data_t *data) {
	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr = (Elf64_Phdr *)(data->_file_map + header->e_phoff);
	Elf64_Phdr	*new_phdr = (Elf64_Phdr *)(data->_file_map + header->e_phoff + header->e_phnum * sizeof(Elf64_Phdr));

	printf("header->e_phoff: %lx, header->e_phnum: %x\n", header->e_phoff, header->e_phnum);
	printf("calcuated pos %lx\n", header->e_phoff + header->e_phnum * sizeof(Elf64_Phdr));

	Elf64_Phdr	*last_phdr = get_last_phdr(data);

	new_phdr->p_type = PT_LOAD;
	new_phdr->p_flags = PF_R | PF_X;
	new_phdr->p_offset = ALIGN(last_phdr->p_offset + last_phdr->p_filesz, PAGE_SIZE);
	new_phdr->p_vaddr = ALIGN(last_phdr->p_vaddr + last_phdr->p_filesz, PAGE_SIZE);
	new_phdr->p_paddr = ALIGN(last_phdr->p_paddr + last_phdr->p_filesz, PAGE_SIZE);
	new_phdr->p_filesz = g_payload_size;
	new_phdr->p_memsz = g_payload_size;
	new_phdr->p_align = PAGE_SIZE;


	printf("data->_file_size: %lx\n", data->_file_size);


	printf("new_phdr->p_offset: %lx, new_phdr->p_vaddr: %lx, new_phdr->p_paddr: %lx\n", new_phdr->p_offset, new_phdr->p_vaddr, new_phdr->p_paddr);

	header->e_phnum++;

	return (new_phdr);
}


static int	find_codecave(data_t *data, size_t *codecave_offset, size_t *codecave_size) {

	Elf64_Ehdr	*ehdr	= (Elf64_Ehdr *)data->_file_map;
	Elf64_Phdr	*phdr	= (Elf64_Phdr *)(data->_file_map + ehdr->e_phoff);
	Elf64_Shdr	*shdr	= (Elf64_Shdr *)(data->_file_map + ehdr->e_shoff);

	Elf64_Phdr	*new_phdr = create_segment(data);


	printf("old entry: %lx\n", data->_oentry_offset);
	ehdr->e_entry = new_phdr->p_vaddr;

	printf("new_phdr->p_vaddr: %lx\n", new_phdr->p_vaddr);
	printf("new_phdr->p_vaddr + new_phdr->p_filesz: %lx\n", new_phdr->p_vaddr + new_phdr->p_filesz);
	printf("new_phdr->p_offset: %lx\n", new_phdr->p_offset);
	printf("new_phdr->p_filesz: %lx\n", new_phdr->p_filesz);

	int32_t jmp_range = (int64_t)data->_oentry_offset - (new_phdr->p_vaddr + new_phdr->p_filesz);

	printf("jmp_range: %i\n", jmp_range);

	modify_payload(jmp_range, JMP_OFFSET, sizeof(jmp_range));

	ft_memcpy((uint8_t *)data->_file_map + new_phdr->p_offset, g_payload, g_payload_size);



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

	if (write(fd, data->_file_map, data->_mapped_size) == -1) {
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
	data->_mapped_size   = 0U;

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
	
	lseek(data->_fd, 0, SEEK_SET);

	struct stat st;

	if (fstat(data->_fd, &st) == -1) {
		runtime_error("Failed to get file size");
		return -1;
	}

	printf("File size: %ld\n", st.st_size);


	void *file_map = mmap(NULL, st.st_size , PROT_READ | PROT_WRITE, MAP_PRIVATE, data->_fd, 0);

	if (file_map == MAP_FAILED) {
		runtime_error("Failed to map file");
		return -1;
	}

	//char buffer[4096];
	//ssize_t bytes_read = 0;
	//
	//void *file_map_start = file_map;
	//while ((bytes_read = read(data->_fd, buffer, 4096)) > 0) {
	//	ft_memmove(file_map, buffer, bytes_read);
	//	file_map = (uint8_t *)file_map + bytes_read;
	//}
	//
	//
	data->_mapped_size = st.st_size + PAGE_SIZE;
	void *file_map_big = mmap(NULL, data->_mapped_size , PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (file_map_big == MAP_FAILED) {
		runtime_error("Failed to map file");
		return -1;
	}

	ft_memmove(file_map_big, file_map, st.st_size);
	memset((uint8_t *)file_map_big + st.st_size, 0, PAGE_SIZE);

	data->_file_map = file_map_big;
	data->_file_size = st.st_size;
	printf("File size: %ld\n", data->_mapped_size);

	munmap(file_map, st.st_size);

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
