BITS 64

_payload:
	push rdx

	lea rax, [rel _payload]
	sub rax, [rel offset]
	mov rcx, [rel offset]

	mov bl, [rel key]

.loop:
	cmp rcx, 0
	je .print

	xor byte [rax], bl
	inc rax
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

	jmp 0x0

offset:
	dq 0x0

key:
	db 0x42
