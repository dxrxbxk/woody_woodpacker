BITS 64
    push rdx
    ;; Load Message Into the stack
	push rax
	mov rax, 10
    push rax
    mov rax, 'DY....'
    push rax
    mov rax, '....WOO'
    push rax

    mov rax, 1      ;;  write(
    mov rdi, 1      ;;  STDOUT_FILENO,
    mov rsi, rsp    ;;  "Injected Message\n",
    mov rdx, 17     ;;  17
    syscall             ;;  );

    pop rax
    pop rax
    pop rax
	pop rax
    pop rdx

	jmp -269
