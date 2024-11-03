BITS 64
    push rdx
    ;; Load Message Into the stack
    mov rax, 10
    push rax
    mov rax, ' Message'
    push rax
    mov rax, 'Injected'
    push rax

    mov rax, 1      ;;  write(
    mov rdi, 1      ;;  STDOUT_FILENO,
    mov rsi, rsp    ;;  "Injected Message\n",
    mov rdx, 17     ;;  17
    syscall             ;;  );

    pop rax
    pop rax
    pop rax
    pop rdx

	mov rax, 0x1050
	jmp rax

