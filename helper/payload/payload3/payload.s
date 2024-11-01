BITS 64

_payload:
	push rdx
	push rax
	push rcx
	push rbx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12


	mov rax, 0xa				; syscall mprotect
	lea rdi, [rel _payload]
	sub rdi, 0x15d
	mov rsi, 0x1000
	mov rdx, 0x7				; PROT_READ | PROT_WRITE | PROT_EXEC
	syscall

	lea rax, [rel _payload]
	sub rax, 0x15d
	mov rcx, 0x15d

	mov bl, 0x42

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

	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rbx
	pop rcx
	pop rax
	pop rdx


	jmp 0x0
