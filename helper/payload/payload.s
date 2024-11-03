BITS 64

_payload:
	push rdx

	lea rsi, [rel _payload]
	sub rsi, [rel offset]
	mov rcx, [rel offset]

	lea rdi, [rel key]
	xor rbx, rbx

.loop:
	cmp rcx, 0
	je .print

	mov al, byte [rdi + rbx]
	xor byte [rsi], al
	
	inc rsi
	dec rcx
	inc rbx

	and rbx, 0x07

	jmp .loop

.string:
	db "....WOODY....", 0x0a, 0x0

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
	dq 0x0
