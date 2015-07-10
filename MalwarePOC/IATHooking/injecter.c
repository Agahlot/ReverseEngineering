#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

HANDLE GetHandleDll(char *dll, int pid) {
	MODULEENTRY32 ModuleEntry;
	ModuleEntry.dwSize = sizeof(MODULEENTRY32);
	HANDLE Snapshot32Module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	Module32First(Snapshot32Module, &ModuleEntry);

	while (Module32Next(Snapshot32Module, &ModuleEntry))
		if (!strstr(ModuleEntry.szModule, dll)) {
			CloseHandle(Snapshot32Module);
			return ModuleEntry.hModule;
		}
	CloseHandle(Snapshot32Module);
	return INVALID_HANDLE_VALUE ;
}

int main(int argc, char *argv[]) {
	printf("[#] InjectDLL into Win*32 Process RING 3 ~ follow @tfairane\n");
	if (argc != 3) {
		printf("[~] Usage : %s <PID> <Full Path DLL>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
	if (!hProcess) {
		printf("[-] OpenProcess() : Error");
		exit(EXIT_FAILURE);
	}

	LPVOID addrAlloc = VirtualAllocEx(hProcess, NULL, strlen(argv[2]) + 1,
	MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!WriteProcessMemory(hProcess, addrAlloc, argv[2], strlen(argv[2]) + 1,
			0)) {
		printf("[-] WriteProcessMemory() : Error");
		exit(EXIT_FAILURE);
	}

	LPTHREAD_START_ROUTINE addrLoadLibrary =
			(LPTHREAD_START_ROUTINE) GetProcAddress(
			GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	HANDLE RemoteFunction = CreateRemoteThread(hProcess, NULL, 0,
			addrLoadLibrary, addrAlloc, 0, 0);
	if (!RemoteFunction) {
		printf("[-] CreateRemoteThread() : Error");
		exit(EXIT_FAILURE);
	}

	printf("[+] DLL Injected ! :o\n");
	WaitForSingleObject(RemoteFunction, 1000);
	VirtualFreeEx(hProcess, addrAlloc, 0, MEM_DECOMMIT);
	CloseHandle(RemoteFunction);
	CloseHandle(hProcess);

	return 0;
}
