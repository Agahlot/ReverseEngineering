// PEB.x64.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI*pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
pNtQueryInformationProcess fNtQueryInformationProcess =
(pNtQueryInformationProcess)GetProcAddress(
LoadLibrary(L"Ntdll.dll"), "NtQueryInformationProcess");

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, _tstoi(argv[1]));

	PROCESS_BASIC_INFORMATION processInformations;
	PEB peb;

	LPVOID pProcessInformation, pPeb;
	ULONG szBuffer, szInfos;
	szBuffer = sizeof(processInformations);
	pProcessInformation = &processInformations;

	ULONG szPeb;
	szPeb = sizeof(peb);
	pPeb = &peb;

	if (NT_SUCCESS(fNtQueryInformationProcess(hProcess, ProcessBasicInformation, pProcessInformation, szBuffer, &szInfos)) && (szBuffer == szInfos) && processInformations.PebBaseAddress)
	{
		ReadProcessMemory(hProcess, processInformations.PebBaseAddress, &peb, szPeb, NULL);
		printf("ImageBaseAddress : %p\n", peb.ImageBaseAddress);
	}

	CloseHandle(hProcess);
	return 0;
}

