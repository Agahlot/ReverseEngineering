#ifndef _MapPE_H
#define _MapPE_H

#include <assert.h>
#include <windows.h>
#include <winternl.h>

#define Magic_DOS 0x00005A4D
#define Magic_NT  0x00004550	

/* Export Address Table
*/
typedef struct EAT{
	PDWORD	function;
	PDWORD	name;
	PDWORD	ordinal;
} EAT, *PEAT;

BOOL isDOS(PIMAGE_DOS_HEADER buffer) {
	return (buffer->e_magic == Magic_DOS);
}

BOOL isNT(PIMAGE_NT_HEADERS buffer) {
	return (buffer->Signature == Magic_NT);
}

PIMAGE_DOS_HEADER MapPE_DOS(HANDLE hProcess, PVOID address) {
	PIMAGE_DOS_HEADER buffer = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));
	ReadProcessMemory(hProcess, address, buffer, sizeof(IMAGE_DOS_HEADER), NULL);
	return buffer;
}

PIMAGE_NT_HEADERS MapPE_NT(HANDLE hProcess, PVOID address) {
	PIMAGE_NT_HEADERS buffer = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));
	ReadProcessMemory(hProcess, address, buffer, sizeof(IMAGE_NT_HEADERS), NULL);
	return buffer;
}

IMAGE_SECTION_HEADER** MapPE_SECTIONS(HANDLE hProcess, PVOID address, UINT nbSection) {
	IMAGE_SECTION_HEADER** arrSection = (IMAGE_SECTION_HEADER**)calloc(nbSection, sizeof(IMAGE_SECTION_HEADER));
	UINT i;
	for (i = 0; i < nbSection; i++) {
		arrSection[i] = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER));
		ReadProcessMemory(hProcess, (PVOID)((DWORD)address + sizeof(IMAGE_SECTION_HEADER)* i), arrSection[i], sizeof(IMAGE_SECTION_HEADER), NULL);
	}
	return arrSection;
}

PIMAGE_EXPORT_DIRECTORY MapPE_DD_EXPORT(HANDLE hProcess, PVOID address) {
	PIMAGE_EXPORT_DIRECTORY buffer = (PIMAGE_EXPORT_DIRECTORY)malloc(sizeof(IMAGE_EXPORT_DIRECTORY));
	ReadProcessMemory(hProcess, address, buffer, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);
	return buffer;
}

HANDLE MapPE_open(WCHAR* file) {
	HANDLE hFile = CreateFile(file,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	HANDLE hFileMapping = CreateFileMapping(hFile,
		NULL,
		PAGE_READWRITE, 0, 0, 0);

	HANDLE hFileMap = MapViewOfFile(hFileMapping,
		FILE_MAP_ALL_ACCESS, 0, 0, 0);

	CloseHandle(hFile);
	CloseHandle(hFileMapping);

	return hFileMap;
}

void MapPE_close(HANDLE hFileMap) {
	UnmapViewOfFile(hFileMap);
}

PIMAGE_DOS_HEADER MapPE_DOS(HANDLE hFileMap) {
	return (PIMAGE_DOS_HEADER)hFileMap;
}

PIMAGE_NT_HEADERS MapPE_NT(HANDLE hFileMap) {
	return (PIMAGE_NT_HEADERS)((DWORD)hFileMap + MapPE_DOS(hFileMap)->e_lfanew);
}

PIMAGE_SECTION_HEADER MapPE_SECTIONS(HANDLE hFileMap, int i) {
	assert(i < MapPE_NT(hFileMap)->FileHeader.NumberOfSections);
	return (PIMAGE_SECTION_HEADER)((DWORD)hFileMap + MapPE_DOS(hFileMap)->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)* i);
}

DWORD RVAtoOFFSET(HANDLE hFileMap, const DWORD RVA) {
	PIMAGE_SECTION_HEADER hSection = (PIMAGE_SECTION_HEADER)MapPE_SECTIONS(hFileMap, 0);
	int i; for (i = 0;
	i < MapPE_NT(hFileMap)->FileHeader.NumberOfSections && (hSection->VirtualAddress + hSection->Misc.VirtualSize) <= RVA; i++, hSection++);
	return RVA - hSection->VirtualAddress + hSection->PointerToRawData;
}


#endif // _MapPE_H
