#include "utils.h"

//char	shellcode[]			= "\x48\x31\xc0\xb0\x01\xbf\x01\x00\x00\x00\x48\x8d\x35\x13\x00\x00\x00\xba\x0f\x00\x00\x00\x0f\x05\x48\x31\xc0\xb0\x3c\xbf\x2a\x00\x00\x00\x0f\x05\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x0d";
//char shellcode[] = 
//    "\x48\x52"                         // push   rdx                  ; Push rdx onto the stack
//    "\x48\x31\xc0"                     // xor    rax, rax             ; RAZ de rax
//    "\xb0\x01"                         // mov    al, 1                ; sys_write syscall
//    "\xbf\x01\x00\x00\x00"             // mov    edi, 1               ; Set edi to 1 (stdout)
//    "\x48\x8d\x35\x13\x00\x00\x00"     // lea    rsi, [rip+0x13]      ; Load address of message
//    "\xba\x0f\x00\x00\x00"             // mov    edx, 15              ; Set edx (message length)
//    "\x0f\x05"                         // syscall                     ; Write syscall
//
//    "\x48\x31\xc0"                     // xor    rax, rax             ; RAZ de rax pour prochain appel
//    "\x48\xc7\xc0\x50\x10\x00\x00"     // mov    rax, 0x1050          ; Load the address 0x1050 into rax
//    "\x58"                             // pop    rdx                  ; Restore rdx from the stack
//    "\xff\xe0"                         // jmp    rax                  ; Jump to 0x1050
//
//    "\x2e\x2e\x2e\x2e"                 // "...."                      ; Start of message
//    "\x57\x4f\x4f\x44\x59"             // "WOODY"                     ; Message content
//    "\x2e\x2e\x2e\x2e\x0a\x0d";        // "....\n\r"                  ; End of message
									   //
char shellcode[] = 
    "\x48\x31\xc0"                     // xor    rax, rax           ; RAZ de rax
    "\xb0\x01"                         // mov    al, 1              ; set rax = 1 (sys_write)
    "\xbf\x01\x00\x00\x00"             // mov    edi, 1             ; set rdi = 1 (stdout)
    "\x48\x8d\x35\x13\x00\x00\x00"     // lea    rsi, [rip+0x13]    ; charge l'adresse du message dans rsi
    "\xba\x0f\x00\x00\x00"             // mov    edx, 15            ; set edx = 15 (taille du message)
    "\x0f\x05"                         // syscall                   ; appel système (write)

    "\x48\x31\xc0"                     // xor    rax, rax           ; RAZ de rax pour prochain appel
    "\x48\xc7\xc0\x50\x10\x00\x00"     // mov    rax, 0x1050        ; l'ancien entrypoint à 0x1050
    "\xff\xe0"                         // jmp    rax                ; sauter à l'ancien entrypoint

    // Message à afficher
    "\x2e\x2e\x2e\x2e"                 // "...."                    ; début du message à afficher
    "\x57\x4f\x4f\x44\x59"             // "WOODY"                   ; contenu du message
    "\x2e\x2e\x2e\x2e\x0a\x0d"     ;    // "....\n\r"
     // "....\n\r"               ; fin du message avec retour de ligne

// Déclaration de msg
//char shellcode[] = 
//    "\x48\x31\xc0"                       // xor rax, rax                ; RAZ de rax
//    "\x48\x89\xc2"                       // mov rdx, rax                ; RAZ de rdx (taille du message)
//    "\x48\x8d\x3d\x1a\x00\x00\x00"       // lea rdi, [rip + 0x1a]       ; adresse du message
//    "\xb8\x01\x00\x00\x00"               // mov eax, 1                  ; sys_write
//    "\xba\x0e\x00\x00\x00"               // mov edx, 14                 ; taille du message (14)
//    "\x0f\x05"                           // syscall                     ; appel système (write)
//
//    "\x48\xc7\xc0\x50\x10\x00\x00"       // mov rax, 0x1050            ; adresse de l'entrypoint
//    "\xff\xe0"                           // jmp rax                    ; sauter à l'entrypoint
//
//    // Message à afficher
//    "\x2e\x2e\x2e\x2e"                   // "...."
//    "\x57\x4f\x4f\x44\x59"               // "WOODY"
//    "\x2e\x2e\x2e\x2e\x0a";              // "....\n"
										 //
//char shellcode[] = 
//    "\x52"                                // push rdx
//    "\xbf\x00\x00\x40\x00"                // mov rdi, 0x400000 (adresse)
//    "\xbe\x00\x10\x00\x00"                // mov rsi, 0x1000 (taille)
//    "\xba\x07\x00\x00\x00"                // mov rdx, 0x7 (PROT_READ | PROT_WRITE | PROT_EXEC)
//    "\xb8\x0a\x00\x00\x00"                // mov rax, 0xa (syscall: mprotect)
//    "\x0f\x05"                            // syscall
//
//    "\xbf\x01\x00\x00\x00"                // mov rdi, 1 (stdout)
//    "\x48\xbe\x3c\x00\x00\x00\x00\x00\x00\x00" // mov rsi, msg (adresse du message)
//    "\xba\x0e\x00\x00\x00"                // mov rdx, 0xe (longueur du message)
//    "\xb8\x01\x00\x00\x00"                // mov rax, 1 (syscall: write)
//    "\x0f\x05"                            // syscall
//
//    "\xbf\x50\x10\x00\x00"                // mov rdi, entry_offset (0x1050)
//    "\x5a"                                // pop rdx
//    "\xff\xe7"                            // jmp rdi
//
//    "\x2e\x2e\x2e\x2e"                    // "...."
//    "\x57\x4f\x4f\x44\x59"                // "WOODY"
//    "\x2e\x2e\x2e\x2e\x0a";                // "....\n"
char mov[] = {0x48, 0xc7, 0xc0, 0x50, 0x10, 0x00, 0x00};
char jmp[] = {0xff, 0xe0};

//#define shellcode_size		sizeof(shellcode)
//Map the target in memory (mmap()) and sanitize it (looking for ELF).
//Fetch & sanitize the executable LOAD segment.
//Measure size of cave and compare it to the shellcode size.
//Stop if codecave isn't large enough else continue.
//Fetch & sanitize the text section.
//Patch the shellcode with properties found in the load segment and text section.
//Move target program entrypoint to shellcode entrypoint.
//Writes this memory to a new file named woody.

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

void	print_phdr(Elf64Phdr_t *phdr) {
	printf("p_type: %d\n", phdr->p_type);
	printf("p_offset: %lx\n", phdr->p_offset);
	printf("p_vaddr: %lx\n", phdr->p_vaddr);
	printf("p_paddr: %lx\n", phdr->p_paddr);
	printf("p_filesz: %lx\n", phdr->p_filesz);
	printf("p_memsz: %lx\n", phdr->p_memsz);
	printf("p_align: %lx\n", phdr->p_align);
}

static Elf64Phdr_t*	parse_program_headers(data_t *data, size_t *codecave_offset, size_t *codecave_size) {
	
	Elf64Hdr_t	*header = (Elf64Hdr_t *)data->_file_map;
	Elf64Phdr_t	*program_headers = (Elf64Phdr_t *)(data->_file_map + header->e_phoff);

	size_t shellcode_size = sizeof(shellcode) - 1;
	for (size_t i = 0; i < header->e_phnum; i++) {
		if (program_headers[i].p_type == PT_LOAD && program_headers[i].p_flags & PF_X) {
			Elf64Phdr_t *next = &program_headers[i + 1];
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

Elf64Shdr_t	*get_section_by_name(data_t *data, const char *name) {
	Elf64Hdr_t	*header = (Elf64Hdr_t *)data->_file_map;
	Elf64Shdr_t	*sections = (Elf64Shdr_t *)(data->_file_map + header->e_shoff);
	Elf64Shdr_t	*strtab = &sections[header->e_shstrndx];
	char		*strtab_p = (char *)data->_file_map + strtab->sh_offset;

	for (size_t i = 0; i < header->e_shnum; i++) {
		if (strcmp(strtab_p + sections[i].sh_name, name) == 0) {
			printf("Found section %s at %lx\n", name, sections[i].sh_addr);
			return &sections[i];
		}
	}
	return NULL;
}

Elf64Shdr_t	*get_section_by_address(data_t *data, size_t address) {
	Elf64Hdr_t	*header = (Elf64Hdr_t *)data->_file_map;
	Elf64Shdr_t	*sections = (Elf64Shdr_t *)(data->_file_map + header->e_shoff);

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

patch_t	init_patch(Elf64Phdr_t *phdr, Elf64Shdr_t *shdr, Elf64Hdr_t *ehdr) {
	patch_t patch;

	patch.entry_offset = phdr->p_offset + phdr->p_filesz - ehdr->e_entry;
	patch.text_offset = phdr->p_offset + phdr->p_filesz - shdr->sh_addr;
	patch.segment_offset =	phdr->p_memsz;

	//printf("entry_offset: %lx\n", patch.entry_offset);
	//printf("text_offset: %lx\n", patch.text_offset);
	//printf("segment_offset: %lx\n", patch.segment_offset);

	return patch;
}

void	print_shellcode(void) {
	for (size_t i = 0; i < sizeof(shellcode); i++) {
		printf("%02x", shellcode[i]);
		if (i % 4 == 3)
			printf(" ");
	}
	printf("\n");
}

void	mov_modify(uint64_t old_entry) {
	mov[3] = old_entry & 0xff;
	mov[4] = (old_entry >> 8) & 0xff;
	mov[5] = (old_entry >> 16) & 0xff;
	mov[6] = (old_entry >> 24) & 0xff;
}

void	print_hex(void *data, size_t size) {
	for (size_t i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)data)[i]);
		if (i % 4 == 3)
			printf(" ");
	}
	printf("\n");
}


static int	inject_shellcode(void) {

	data_t *data = data_getter();
	size_t	codecave_offset = 0;
	size_t	codecave_size = 0;
	Elf64Hdr_t	*ehdr = (Elf64Hdr_t *)data->_file_map;


	Elf64Phdr_t	*phdr = parse_program_headers(data, &codecave_offset, &codecave_size);
	if (phdr == NULL)
		return handle_error("No codecave found\n");


	Elf64Shdr_t	*shdr = get_section_by_name(data, ".fini");
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


//(void *)woody->file + payload_off + (PAYLOAD_SIZE - sizeof(t_patch)),
	//memcpy(shellcode + shellcode_size - 8, &old_entry, 8);

	memcpy(data->_file_map + codecave_offset, shellcode, shellcode_size);
	//mov_modify(old_entry);
//	memcpy(data->_file_map + codecave_offset + shellcode_size, mov, sizeof(mov));
//	memcpy(data->_file_map + codecave_offset + shellcode_size + sizeof(mov), jmp, sizeof(jmp));

	print_hex(mov, sizeof(mov));
	print_hex(jmp, sizeof(jmp));


	printf("Shellcode injected at %lx\n", codecave_offset);
	printf("p_filesz: %lx\n", phdr->p_filesz);
	printf("p_memsz: %lx\n", phdr->p_memsz);
	printf("sh_size: %lx\n", shdr->sh_size);

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
