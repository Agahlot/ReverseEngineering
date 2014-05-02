#ifndef _MapPE_H
#define _MapPE_H
#include<assert.h>

HANDLE MapPE_open(const char *file) {
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
	return (PIMAGE_DOS_HEADER) hFileMap;
}

PIMAGE_NT_HEADERS MapPE_NT(HANDLE hFileMap) {
    return (PIMAGE_NT_HEADERS) (hFileMap + MapPE_DOS(hFileMap)->e_lfanew);
}

PIMAGE_SECTION_HEADER MapPE_SECTIONS(HANDLE hFileMap, int i) {
    assert(i < MapPE_NT(hFileMap)->FileHeader.NumberOfSections);
    return (PIMAGE_SECTION_HEADER) (hFileMap + MapPE_DOS(hFileMap)->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
}

DWORD RVAtoOFFSET(HANDLE hFileMap, const DWORD RVA) {
	PIMAGE_SECTION_HEADER hSection = (PIMAGE_SECTION_HEADER) MapPE_SECTIONS(hFileMap, 0);
	int i; for (i = 0;
	i < MapPE_NT(hFileMap)->FileHeader.NumberOfSections && (hSection->VirtualAddress + hSection->Misc.VirtualSize) <= RVA; i++, hSection++);
	return RVA - hSection->VirtualAddress + hSection->PointerToRawData;
}
#endif // _MapPE_H
