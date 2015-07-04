global _start

section .data
shell db '/bin/sh', 0

section .text
_start:

mov rax, 59 ; sys_execve
mov rdi, shell
mov rsi, 0
mov rdx, 0
syscall

mov rax, 60 ; sys_exit
mov rdi, 0
syscall