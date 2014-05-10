global _main
SECTION .text

_main:
jmp GetParamWinExec

CallWinExec:
pop ebx
xor eax, eax

push eax
push ebx

mov ebx, 0xstatic_addr ;kernel32.dll WinExec
call ebx

xor eax, eax
push eax

mov ebx, 0xstatic_addr ;kernel32.dll ExitProcess
call ebx

GetParamWinExec:
call CallWinExec
db "calc.exe", 0x00