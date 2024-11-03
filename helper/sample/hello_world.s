BITS 64

section .data
	msg db "Hello, World!", 0

section .text
	global _start

_start:
	mov rax, 1
	mov rdi, 1
	mov rsi, msg
	mov rdx, 13
	syscall

	mov rax, 60
	xor rdi, rdi
	syscall
