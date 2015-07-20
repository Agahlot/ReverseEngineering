
#include "stdafx.h"
#include <Windows.h>
#include <winternl.h>

int _tmain(int argc, _TCHAR* argv[])
{
	SIZE_T i = 0, j = 0, szbuffer = 0;
	LPSYSTEM_INFO sysInfo = (LPSYSTEM_INFO)malloc(sizeof(SYSTEM_INFO));
	GetNativeSystemInfo(sysInfo);
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, _tstoi(argv[1]));
	PMEMORY_BASIC_INFORMATION basicInfo = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(MEMORY_BASIC_INFORMATION));
	PMEMORY_BASIC_INFORMATION basicInfoEnum = (PMEMORY_BASIC_INFORMATION)malloc(sizeof(MEMORY_BASIC_INFORMATION));
	PBYTE hDump = 0;

	//printf("Dump de %x à %x\n", sysInfo->lpMinimumApplicationAddress, sysInfo->lpMaximumApplicationAddress);
	for (i = (SIZE_T)sysInfo->lpMinimumApplicationAddress; i < (SIZE_T)sysInfo->lpMaximumApplicationAddress; i += basicInfoEnum->RegionSize) {
		VirtualQueryEx(hProcess, (LPCVOID)i, basicInfoEnum, sizeof(MEMORY_BASIC_INFORMATION));

		if (memcmp(basicInfoEnum, basicInfo, sizeof(MEMORY_BASIC_INFORMATION)) && basicInfoEnum->AllocationBase != 0) {
			if (basicInfoEnum->AllocationBase == basicInfo->AllocationBase) {
				printf("%29s BaseAddress : %p RegionSize %p Protect : %x\t\n\n", " ", basicInfoEnum->BaseAddress, basicInfoEnum->RegionSize, basicInfoEnum->Protect);
			}
			else {
				printf("[+] AllocationBase : %p BaseAddress : %p RegionSize %p Protect : %x\t\n\n", basicInfoEnum->AllocationBase, basicInfoEnum->BaseAddress, basicInfoEnum->RegionSize, basicInfoEnum->Protect);
			}
			memcpy(basicInfo, basicInfoEnum, sizeof(MEMORY_BASIC_INFORMATION));
		}

		// Looking for pattern "password"
		BYTE pattern[] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };
		hDump = (PBYTE)malloc(basicInfoEnum->RegionSize);
		ReadProcessMemory(hProcess, basicInfoEnum->BaseAddress, hDump, basicInfoEnum->RegionSize, &szbuffer);
		if (hDump && szbuffer != 0) {
			for (j = 0; j < basicInfoEnum->RegionSize; j++) {
				if (!memcmp(&hDump[j], &pattern, sizeof(pattern))) {
					printf("Pattern over here, Captain!\n");
					/*
					SIZE_T k = j;
					for (; k < j + 16; k++)  {
						printf("%c", hDump[k]);
					}
					break;
					*/
				}
			}

		}
	}
	printf("FIN\n");
	free(hDump);
	free(basicInfo);
	free(basicInfoEnum);
	free(sysInfo);
	CloseHandle(hProcess);
	return 0;
}

