#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>


BOOL is64(int pid) {
	typedef BOOL(*pIsWow64Process)(HANDLE, PBOOL);
	BOOL is64;
	pIsWow64Process IsWow64Process = (pIsWow64Process)GetProcAddress(
		GetModuleHandleA("kernel32"),
		"IsWow64Process");
	IsWow64Process(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), &is64);
	return is64;
}


int ps(WCHAR* name) {
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE Snapshot32Process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Snapshot32Process == INVALID_HANDLE_VALUE)
		exit(EXIT_FAILURE);

	if (!Process32First(Snapshot32Process, &processEntry)) {
		CloseHandle(Snapshot32Process);
		exit(EXIT_FAILURE);
	}

	do {
		if (!wcscmp(name, processEntry.szExeFile)) {
			CloseHandle(Snapshot32Process);
			return processEntry.th32ProcessID;
		}
	} while (Process32Next(Snapshot32Process, &processEntry));
	CloseHandle(Snapshot32Process);
	return -1;
}


void ms(int pid) {
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	HANDLE Snapshot32Module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (Snapshot32Module == INVALID_HANDLE_VALUE)
		exit(EXIT_FAILURE);

	if (!Module32First(Snapshot32Module, &moduleEntry)) {
		CloseHandle(Snapshot32Module);
		exit(EXIT_FAILURE);
	}

	do {
		printf("[+] %-16ls : 0x%p\n", moduleEntry.szModule, moduleEntry.modBaseAddr);
	} while (Module32Next(Snapshot32Module, &moduleEntry));
	CloseHandle(Snapshot32Module);
}


void wmain(int argc, WCHAR* argv[]) {
	ms(ps(argv[1]));
}
