BITS 64

global _start

_start:
    ; Sauvegarde des registres utilisés
    push rdx                      ; Sauvegarde rdx
    push rax                      ; Sauvegarde rax (pour nettoyer plus tard)

    ; Préparation des paramètres pour l'appel système (write)
	mov rax, 1                    ; syscall: write
	mov rdi, 1                    ; fd: stdout
	lea rsi, [msg]                ; adresse du message
	mov rdx, msg_len               ; longueur du message
	syscall                       ; appel système

    ; Restauration des registres
    pop rax                       ; restaure rax
    pop rdx                       ; restaure rdx

    ; Terminer proprement le programme
    mov rax, 60                   ; syscall: exit
    xor rdi, rdi                  ; code de retour 0
    syscall                       ; appel système

msg db '....WOODY....', 0x0A
msg_len equ $ - msg
