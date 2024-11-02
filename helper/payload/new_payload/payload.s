BITS 64

_payload:
	db 0x66
	push rdx

.decrypt:
	
	call get_current_addr
get_current_addr:
	lea rsi, [rel _payload]
	add rsi, 1

	mov rcx, 0x1
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

	; jmp 0x0
	call exit

exit:
	mov rax, 60
	xor rdi, rdi
	syscall


addr_offset: dd 0x9
