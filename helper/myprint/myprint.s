bits 64
global _start

_start:
    push rdx                            ; Sauvegarder rdx

    ; mprotect(0x400000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC)
    mov rdi, 0x400000                   ; Adresse de la région à protéger
    mov rsi, 0x1000                     ; Taille de la région
    mov rdx, 0x7                        ; PROT_READ | PROT_WRITE | PROT_EXEC
    mov rax, 0xa                        ; syscall: mprotect
    syscall

    ; write(1, msg, msg_len)
    mov rdi, 1                          ; File descriptor: 1 (stdout)
    mov rsi, msg                        ; Adresse du message
    mov rdx, msg_len                    ; Longueur du message
    mov rax, 1                          ; syscall: write
    syscall

    ; mov entry_offset and jump
    mov rdi, entry_offset               ; Charger l'offset de l'entrée dans rdi
    pop rdx                             ; Restaurer rdx
    jmp rdi                             ; Sauter à l'offset d'entrée

msg db "....WOODY....", 10             ; Message à afficher, suivi d'un saut de ligne
msg_len equ $ - msg                    ; Longueur du message
entry_offset equ 0x1050                ; Offset d'entrée

