bits 64
default rel
global _start

_start:
     xor     eax, eax
     cdq
     mov     dl, 10         ; 3ème argument (rdx)
     inc     eax            ; eax = 1 (syscall write)
     mov     edi, eax       ; 1er argument rdi = 1 (stdout)
     lea     rsi, [rel msg] ; 2ème argument rsi = adresse du message
     syscall                ; appel système
     mov     dl, 42         ; valeur 42 dans dl
     xor     eax, eax
     inc     eax
     mul     dl             ; multiplier 42 * 1 = 42
     mov     edi, eax       ; rdi = 42
     xor     eax, eax
     mov     al, 60         ; syscall pour exit
     syscall                ; exit(42)

msg db "..WOODY..", 10      ; message à écrire suivi d'un saut de ligne
