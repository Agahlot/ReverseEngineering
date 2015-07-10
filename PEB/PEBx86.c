#include "stdafx.h"
#include<stdio.h>
#include<windows.h>
#include<winternl.h>

/*
*NTSTATUS WINAPI NtQueryInformationProcess(
*_In_       HANDLE ProcessHandle,
*_In_       PROCESSINFOCLASS ProcessInformationClass,
*_Out_      PVOID ProcessInformation,
*_In_       ULONG ProcessInformationLength,
*_Out_opt_  PULONG ReturnLength
*);
*/
typedef NTSTATUS(WINAPI*pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
// OR
typedef PPEB(*pRtlGetCurrentPeb)(void);

int main() {
	PROCESS_BASIC_INFORMATION ProcessInformation;
	PPEB Peb;
	PPEB_LDR_DATA PedLdrData;
	PLDR_DATA_TABLE_ENTRY LdrDataEntry;
	PLIST_ENTRY ModuleListEntry, ModuleListHead;

	pRtlGetCurrentPeb RtlGetCurrentPeb =
		(pRtlGetCurrentPeb)GetProcAddress(
		LoadLibraryA("Ntdll.dll"), "RtlGetCurrentPeb");

	pNtQueryInformationProcess NtQueryInformationProcess =
		(pNtQueryInformationProcess)GetProcAddress(
		LoadLibraryA("Ntdll.dll"), "NtQueryInformationProcess");

	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation,
		&ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	Peb = (PPEB)ProcessInformation.PebBaseAddress;
	// Peb = (PPEB)RtlGetCurrentPeb();
	PedLdrData = (PPEB_LDR_DATA)Peb->Ldr;

	printf("PEB location : %p\n", Peb);

	ModuleListHead = &PedLdrData->InMemoryOrderModuleList;
	ModuleListEntry = ModuleListHead->Flink;

	while (ModuleListEntry != ModuleListHead)
	{
		LdrDataEntry = (PLDR_DATA_TABLE_ENTRY)ModuleListEntry;
		printf("%ls\n", LdrDataEntry->FullDllName.Buffer);
		ModuleListEntry = ModuleListEntry->Flink;
	}

	return 0;
}
