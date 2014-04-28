global _main
SECTION .text

_main:
jmp GetParamWinExec

CallWinExec:
pop ebx
xor eax, eax

push eax
push ebx

mov ebx, 0x75ad2ff1 ;kernel32.dll WinExec
call ebx

xor eax, eax
push eax

mov ebx, 0x75a579d8 ;kernel32.dll ExitProcess
call ebx

GetParamWinExec:
call CallWinExec
db "calc.exe", 0x00