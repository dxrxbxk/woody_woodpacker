#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

char code[] = "\x31\xc0\x99\xb2\x0a\xff\xc0\x89\xc7\x48\x8d\x35\x12\x00\x00\x00\x0f\x05\xb2\x2a\x31\xc0\xff\xc0\xf6\xe2\x89\xc7\x31\xc0\xb0\x3c\x0f\x05\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x0a";


int main() {
    if (mprotect((void*)((uintptr_t)code & ~0xFFF), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
        return 1;
    }

    int (*func)();
    func = (int (*)()) code;
    (int)(*func)();
    
    return 0;
}
