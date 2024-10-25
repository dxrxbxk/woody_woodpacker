bits 64
global _start

_start:
    ; Écrire "WOODY" sur la sortie standard
    mov rax, 1          ; numéro de syscall pour sys_write
    mov rdi, 1          ; file descriptor 1 (stdout)
    lea rsi, [rel msg]  ; adresse du message
    mov rdx, msg_len    ; longueur du message
    syscall             ; appel du syscall pour écrire le message

    ; Terminer le programme
    xor rax, rax        ; numéro de syscall pour sys_exit
    xor rdi, rdi        ; code de retour 0
    syscall             ; appel du syscall pour quitter

msg             db "WOODY", 10 ; Message à afficher, suivi d'un saut de ligne
msg_len        equ $ - msg      ; Longueur du message

entry_offset    dq 0x1a1b2a2b3a3b4a4b ; Ancien point d'entrée (à patcher)
