global _main
extern _printf

SECTION .text
next:
call _printf
add esp, 4
ret 0x0

_main:
call next
db "Hello World", 0
