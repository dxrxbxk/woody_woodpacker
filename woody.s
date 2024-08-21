global _start
_start:
    xor     rax, rax                ; rax = 0
    mov     al, 1                   ; rax = 1 (syscall numéro pour write)
    xor     rdi, rdi                ; rdi = 0
    inc     rdi                     ; rdi = 1 (stdout)
    lea     rsi, [rel message]      ; Charger l'adresse du message
    mov     dl, 13                  ; rdx = 13 (taille du message)
    syscall                         ; appel système

    xor     rax, rax                ; rax = 0
    mov     al, 60                  ; rax = 60 (syscall numéro pour exit)
	mov		rdi, 42                 ; rdi = 42 (code de retour)
    syscall                         ; appel système

message db "...WOODY...", 0x0A, 0x0D
