BITS 32

section .data
	msg db "Hello, World!", 0xa
	msglen equ $ - msg

section .text
global _start
_start:
	mov eax, 4
	mov ebx, 1
	mov ecx, msg
	mov edx, msglen
	int 0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
