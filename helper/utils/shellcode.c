#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>


//char code[] = "\x31\xc0\x99\xb2\x0c\xff\xc0\x89\xc7\x48\x8d\x35\x12\x00\x00\x00\x0f\x05\xb2\x2a\x31\xc0\xff\xc0\xf6\xe2\x89\xc7\x31\xc0\xb0\x3c\x0f\x05\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0c";
//char code[] = "\x48\x31\xc0\xb0\x01\xbf\x01\x00\x00\x00\x48\x8d\x35\x13\x00\x00\x00\xba\x0f\x00\x00\x00\x0f\x05\x48\x31\xc0\xb0\x3c\xbf\x2a\x00\x00\x00\x0f\x05\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x0d";
//char code[] = "\x31\xed\x49\x89\xd1\x5e\x48\x89\xe2\x48\x83\xe4\xf0\x50\x54\x45\x31\xc0\x31\xc9\x48\x8d\x3d\xce\x00\x00\x00\xff\x15\x4f\x2f\x00\x00\xf4\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x40\x00\x48\x8d\x3d\x91\x2f\x00\x00\x48\x8d\x05\x8a\x2f\x00\x00\x48\x39\xf8\x74\x15\x48\x8b\x05\x2e\x2f\x00\x00\x48\x85\xc0\x74\x09\xff\xe0\x0f\x1f\x80\x00\x00\x00\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00\x48\x8d\x3d\x61\x2f\x00\x00\x48\x8d\x35\x5a\x2f\x00\x00\x48\x29\xfe\x48\x89\xf0\x48\xc1\xee\x3f\x48\xc1\xf8\x03\x48\x01\xc6\x48\xd1\xfe\x74\x14\x48\x8b\x05\xfd\x2e\x00\x00\x48\x85\xc0\x74\x08\xff\xe0\x66\x0f\x1f\x44\x00\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfa\x80\x3d\x1d\x2f\x00\x00\x00\x75\x2b\x55\x48\x83\x3d\xda\x2e\x00\x00\x00\x48\x89\xe5\x74\x0c\x48\x8b\x3d\xfe\x2e\x00\x00\xe8\x29\xff\xff\xff\xe8\x64\xff\xff\xff\xc6\x05\xf5\x2e\x00\x00\x01\x5d\xc3\x0f\x1f\x00\xc3\x0f\x1f\x80\x00\x00\x00\x00\xf3\x0f\x1e\xfa\xe9\x77\xff\xff\xff\x55\x48\x89\xe5\x48\x8d\x05\xc0\x0e\x00\x00\x48\x89\xc7\xe8\xe4\xfe\xff\xff\xb8\x00\x00\x00\x00\x5d\xc3";
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

int main() {
    // Message à afficher
    char msg[] = "Injected Message\n";

    // Shellcode
    char shellcode[] = {
        0x52,                           // push rdx
        0x50,                           // push rax
        0xb8, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1        ; syscall: write
        0xbf, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1        ; STDOUT_FILENO
        0x48, 0x8d, 0x35, 0x0e, 0x00, 0x00, 0x00, // lea rsi, [rip + offset] ; adresse du message
        0xba, 0x16, 0x00, 0x00, 0x00,  // mov rdx, 22      ; longueur du message
        0x0f, 0x05,                    // syscall           ; appel système (write)
        0x58,                           // pop rax           ; restaure rax
        0x5a,                           // pop rdx           ; restaure rdx
        0xb8, 0x3c, 0x00, 0x00, 0x00,  // mov rax, 60      ; syscall: exit
        0x48, 0x31, 0xff,              // xor rdi, rdi     ; code de retour 0
        0x0f, 0x05,                    // syscall           ; appel système (exit)
    };

    // Calculer l'offset du message
    *(unsigned long *)(shellcode + 0x0e) = (unsigned long)(msg);

	if (mprotect((void *)((unsigned long)shellcode & ~0xFFF), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
		perror("mprotect");
		return 1;
	}

    // Exécution du shellcode
    void (*func)() = (void (*)())shellcode;
    func();

    return 0;
}
