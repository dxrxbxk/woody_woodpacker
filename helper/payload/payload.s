BITS 64
    push rdx
    ;; Load Message Into the stack
	push rax
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
	pop rax
    pop rdx
	jmp -269		;; -263 is the offset to the next instruction

