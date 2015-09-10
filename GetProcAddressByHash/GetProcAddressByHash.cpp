#include "stdafx.h"
#include "PE.h"
#include "signature.h"
#include "hash.h"
#include "md5.h"

#define DEBUG FALSE


PDWORD GetProcAddressByHash(WCHAR* dll, ULONGLONG hash) {
	PPEB Peb; UINT i;
	PPEB_LDR_DATA Ldr;
	PLDR_DATA_TABLE_ENTRY Module;
	PLIST_ENTRY ModuleListEntry, ModuleListHead;

	/* get PEB
	*/
	__asm {
		mov eax, FS:[0x30];
		mov Peb, eax
	}

	Ldr = (PPEB_LDR_DATA)Peb->Ldr;
	ModuleListHead = &Ldr->InMemoryOrderModuleList;
	ModuleListEntry = ModuleListHead->Flink;

	while (ModuleListEntry != ModuleListHead)
	{
		Module = (PLDR_DATA_TABLE_ENTRY)ModuleListEntry;
		ModuleListEntry = ModuleListEntry->Flink;
		if (!wcscmp(Module->FullDllName.Buffer, dll))
			break;
	}
	DWORD imageBaseAddr = (DWORD)Module->Reserved2[0];

#if DEBUG
	printf("PEB location : 0x%p\n", Peb);
	printf("Dll: %ls imageBaseAddr: 0x%p\n", Module->FullDllName.Buffer, Module->Reserved2[0]);
#endif // DEBUG

	PIMAGE_DOS_HEADER hDOS = MapPE_DOS(GetCurrentProcess(), (PVOID)imageBaseAddr);
	if (!isDOS(hDOS))
		return NULL;

	PIMAGE_NT_HEADERS hNT = MapPE_NT(GetCurrentProcess(), (PVOID)(imageBaseAddr + hDOS->e_lfanew));
	if (!isNT(hNT))
		return NULL;

	IMAGE_SECTION_HEADER** hSection = MapPE_SECTIONS(
		GetCurrentProcess(),
		(PVOID)(imageBaseAddr + hDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS)),
		hNT->FileHeader.NumberOfSections);

#if DEBUG
	for (i = 0; i < hNT->FileHeader.NumberOfSections; i++)
		printf("%s\n", hSection[i]->Name);
#endif // DEBUG

	PIMAGE_EXPORT_DIRECTORY hExport = MapPE_DD_EXPORT(GetCurrentProcess(), (PVOID)(imageBaseAddr + hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	EAT hEAT;
	hEAT.function = (PDWORD)(imageBaseAddr + hExport->AddressOfFunctions);
	hEAT.name = (PDWORD)(imageBaseAddr + hExport->AddressOfNames);
	hEAT.ordinal = (PDWORD)(imageBaseAddr + hExport->AddressOfNameOrdinals);

#if DEBUG
	printf("Dll: %s\n", imageBaseAddr + hExport->Name);
	for (i = 0; i < hExport->NumberOfNames; i++)
		printf("%s <> 0x%p\n", (char*)(imageBaseAddr + hEAT.name[i]), (PDWORD)(imageBaseAddr + hEAT.function[i]));
#endif // DEBUG

	for (i = 0; i < hExport->NumberOfNames; i++) {
		if (hashkey((PCHAR)(imageBaseAddr + hEAT.name[i])) == hash)
			break;
	}

	free(hSection);
	free(hExport);
	free(hNT);
	free(hDOS);

	return (PDWORD)(imageBaseAddr + hEAT.function[i]);
}


int main(int argc, char* argv[])
{
	// "Sleep": 3675000
	pLambda0 lambda0 = (pLambda0)GetProcAddressByHash(L"kernel32.dll", 3675000);
	lambda0(10000);

	return 0;
}
