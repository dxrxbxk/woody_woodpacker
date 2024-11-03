#include "woody_woodpacker.h"

char	g_payload[]		= "\x52\x48\x8d\x05\xf8\xff\xff\xff\x48\x2b\x05\x4a\x00\x00\x00\x48\x8b\x0d\x43\x00\x00\x00\x8a\x1d\x45\x00\x00\x00\x48\x83\xf9\x00\x74\x19\x30\x18\x48\xff\xc0\x48\xff\xc9\xeb\xf0\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\xe0\xff\xff\xff\xba\x0f\x00\x00\x00\x0f\x05\x5a\xe9\xa7\xff\xff\xff\x5d\x01\x00\x00\x00\x00\x00\x00\x42";
size_t	g_payload_size	= sizeof(g_payload) - 1;
int64_t exit_status		= EXIT_SUCCESS;

		}
	}
	return (EXIT_FAILURE);
}


static int		patch_new_file(data_t *data) {

	int fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd == -1)
		handle_syscall("open");


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

static int		inject_payload(void) {


	PRINT("Codecave size: %zu, offset: %lx, payload size: %zu\n", codecave_size, codecave_offset, g_payload_size);


	ehdr->e_phoff += PAGE_ROUND(sizeof(shellcode));
	patch_new_file(data);

}

static int		map_file(char *filename) {
	int	fd = open(filename, O_RDONLY);
	if (fd == -1)
		handle_syscall("open");

	ssize_t	file_size = lseek(fd, 0, SEEK_END);

	lseek(fd, 0, SEEK_SET);

	void *file_map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	data_t *data		= get_data();
	data->_file_map		= file_map;
	data->_file_size	= file_size;

	close(fd);

	return (EXIT_SUCCESS);
}

static int		check_file(void) {
	data_t		*data = get_data();

	Elf64_Ehdr	*header = (Elf64_Ehdr *)data->_file_map;

	if (ft_memcmp(header->e_ident, "\x7f""ELF", 4) != 0)
		return ERROR(NOT_ELF_FILE);
	else if (header->e_ident[4] != ELF_64)
		return ERROR(NOT_X86_64);

	return (SUCCESS);
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
	  if ((exit_status = map_file(argv[1])) != EXIT_SUCCESS)
		  return (exit_status);
	  if ((exit_status = check_file()) != EXIT_SUCCESS)
		  return (exit_status);
	  if ((exit_status = inject_payload()) != EXIT_SUCCESS)
		  return (exit_status);
	  free_data();
	  return (exit_status);
  } else
	  return ERROR(BAD_ARGS);

