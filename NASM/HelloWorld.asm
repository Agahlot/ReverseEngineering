global _main
extern _printf

SECTION .data
helloworld db 'Hello World.',10,'Le diametre de la terre est de %d km.', 0
rayon dw 6371, 0

SECTION .text
_main:
mov eax, [rayon]
add eax, [rayon]
push eax
push helloworld
call _printf
pop ebp
pop ebp
;add esp, 8
ret 0x0
