
section .text
global _start
_start:
	jmp short ender
	starter:
	xor eax, eax ;zero out eax
	xor ebx, ebx ;zero out ebx
	xor edx, edx ;zero out edx
	xor ecx, ecx ;zero out ecx
	mov al, 4 ;system call write
	mov bl, 1 ;stdout is 1
	pop ecx ;pop out the address of the string from the stack
	mov dl, 18 ;length of the string
	int 0x80 ;call the kernel
	xor eax, eax ;zero out eax
	mov al, 1 ;exit the shellcode
	xor ebx,ebx
	int 0x80
	ender:
	call starter ;put the address of the string on the stack
	db 'Kerala Cyber Force'
