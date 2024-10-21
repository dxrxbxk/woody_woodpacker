bits 64
default rel
section .text
global _start

_start:
    xor     rax, rax                ; rax = 0
    mov     al, 1                   ; rax = 1 (syscall numéro pour write)
    mov     rdi, 1                   ; rdi = 1 (stdout)
    lea     rsi, [rel message]      ; Charger l'adresse du message
    mov     rdx, 15                  ; rdx = 15 (taille du message)
    syscall                          ; appel système

    xor     rax, rax                ; rax = 0
    mov     al, 60                  ; rax = 60 (syscall numéro pour exit)
    mov     rdi, 42                 ; rdi = 42 (code de retour)
    syscall                          ; appel système

section .data
message db "....WOODY....", 10, 13      ; Chaîne à afficher (15 octets)
