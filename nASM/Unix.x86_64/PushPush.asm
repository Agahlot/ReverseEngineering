global _start

section .text
_start:

mov rax, 1
mov rdi, 1

push 0x0A646C72
push 0x6F57206F
push 0x6c6c6548

mov rsi, rsp
mov rdx, 24
syscall

mov rax, 60
mov rdi, 0
syscall