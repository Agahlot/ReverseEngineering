global _main
extern _printf

SECTION .text
_main:
push 00646c72h
push 6f57206fh
push 6c6c6548h
mov eax, esp ;ASCII "Hello World", 0x00
push eax
call _printf
add esp, 16
ret 0x0
