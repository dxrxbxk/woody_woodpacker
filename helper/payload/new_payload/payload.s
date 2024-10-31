BITS 64

_payload:
	push rdx


.decrypt:
	lea rsi, [rel addr_offset]
	add rsi, [rsi]
	mov rcx, 0x1000
	mov al, 0x42

.loop:
	cmp rcx, 0
	je .print

	xor byte [rsi], al
	inc rsi
	dec rcx
	jmp .loop

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

addr_offset: dd 0x0
