#include "stdafx.h"
#include <windows.h>
#include <winternl.h>

int _tmain(int argc, _TCHAR* argv[])
{
	// Init
	PMEMORY_BASIC_INFORMATION basicInfo = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(MEMORY_BASIC_INFORMATION));
	PMEMORY_BASIC_INFORMATION basicInfoEnum = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(MEMORY_BASIC_INFORMATION));
	LPSYSTEM_INFO sysInfo = (LPSYSTEM_INFO)malloc(sizeof(SYSTEM_INFO));
	SIZE_T i = 0, j = 0, szbuffer = 0;
	PBYTE hDump = 0;

	// Pattern Signature
	BYTE pattern[] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
	BYTE offset_pointer = 0;

	if (argc != 2)
		return 0;

	GetNativeSystemInfo(sysInfo);
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, _tstoi(argv[1]));

	//printf("Dump from %p to %p\n", sysInfo->lpMinimumApplicationAddress, sysInfo->lpMaximumApplicationAddress);
	for (i = (SIZE_T)sysInfo->lpMinimumApplicationAddress; i < (SIZE_T)sysInfo->lpMaximumApplicationAddress; i += basicInfoEnum->RegionSize) {
		VirtualQueryEx(hProcess, (LPCVOID)i, basicInfoEnum, sizeof(MEMORY_BASIC_INFORMATION));

		if (memcmp(basicInfoEnum, basicInfo, sizeof(MEMORY_BASIC_INFORMATION)) && basicInfoEnum->AllocationBase != 0) {
			if (basicInfoEnum->AllocationBase == basicInfo->AllocationBase) {
				printf("%24s [+] BaseAddress: %p RegionSize: %p Protect: %x\t\n", " ", basicInfoEnum->BaseAddress, basicInfoEnum->RegionSize, basicInfoEnum->Protect);
			}
			else {
				printf("[-] AllocationBase: %p BaseAddress: %p RegionSize: %p Protect: %x\t\n", basicInfoEnum->AllocationBase, basicInfoEnum->BaseAddress, basicInfoEnum->RegionSize, basicInfoEnum->Protect);
			}
			memcpy(basicInfo, basicInfoEnum, sizeof(MEMORY_BASIC_INFORMATION));
		}

		if (basicInfoEnum->RegionSize != -1) {
			hDump = (PBYTE)malloc(basicInfoEnum->RegionSize);
			ReadProcessMemory(hProcess, basicInfoEnum->BaseAddress, hDump, basicInfoEnum->RegionSize, &szbuffer);
			if (hDump && szbuffer != 0) {
				for (j = 0; j < basicInfoEnum->RegionSize; j++) {
					if (!memcmp(&hDump[j], &pattern, sizeof(pattern))) {
						printf("Pattern over here, Captain! Addr: %x\n", (DWORD)basicInfoEnum->BaseAddress + (j + offset_pointer));
						/*
						SIZE_T k = j;
						for (; k < j + 16; k++)  {
						printf("%x", hDump[k]);
						}
						break;
						*/
					}
				}
			}
		}
		i += 1000;
	}
	printf("FIN\n");
	free(hDump);
	free(basicInfo);
	free(basicInfoEnum);
	free(sysInfo);
	CloseHandle(hProcess);
	return 0;
}
