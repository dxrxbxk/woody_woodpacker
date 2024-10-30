BITS 64

_payload:
	push rdx

	jmp .print

.string:
	db "....WOODY....", 0x0a, 0

.print:
	mov rax, 1
	mov rdi, 1
	lea rsi, [rel .string]
	mov rdx, 15

	syscall

	pop rdx

	jmp	0x0
