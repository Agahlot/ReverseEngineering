global _start

section .text
_start:

mov rax, 1 ; sys_write
mov rdi, 1 ; stdout
push 0x0A646C72
push 0x6F57206F
push 0x6c6c6548 ; "Hello World"
mov rsi, rsp
mov rdx, 24 ; lentgh
syscall

mov rax, 60 ; sys_exit
mov rdi, 0
syscall