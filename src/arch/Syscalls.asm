.intel_syntax noprefix
.section .text
.global DirectSyscall

DirectSyscall:
    mov eax, ecx                ; EAX = SSN (wID)
    
    ; Mover argumentos de syscall a registros correctos
    ; Windows x64 syscall convention: R10, RDX, R8, R9 + stack
    mov r10, rdx                ; R10 = p1 (primer argumento real)
    mov rdx, r8                 ; RDX = p2
    mov r8, r9                  ; R8  = p3
    mov r9, [rsp + 40]          ; R9  = p4 (quinto argumento de C, cuarto de syscall)
    
    ; Los argumentos adicionales (p5 en adelante) ya están correctamente posicionados
    ; en la pila desde [rsp+48] en adelante. NO moverlos.
    ; La convención x64 mantiene: retaddr(8) + shadow space(32) = 40 bytes
    ; p5 está en [rsp+48], p6 en [rsp+56], etc.
    
    syscall                     ; Ejecutar syscall
    ret
