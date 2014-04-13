#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

int GetProcessPidByName(char *nProcess);
HANDLE GetHandleDll(char *PathDll, int pid);

int main(int argc, char *argv[]) {
	printf("InjectDLL into Win*32 Process RING 3 ~ follow @tfairane");
	if (argc != 3) {
		printf("Usage : %s <process name> <full path DLL>", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *PathDll = argv[2]; // Specifie FULL Path to DLL !!!!
	int sPathDll = strlen(PathDll);
	int pid = GetProcessPidByName(argv[1]);

	printf("[~] Target Process Name : %s PID : %d", argv[1], pid);

	HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("[#] OpenProcess() : Error"), exit(EXIT_FAILURE);
	}

	LPVOID AddrAlloc = VirtualAllocEx(hProcess, NULL, sPathDll, MEM_COMMIT,
	PAGE_EXECUTE_READWRITE);
	if (AddrAlloc == NULL) {
		printf("[#] VirtualAllocEx() : Error");
		exit(EXIT_FAILURE);
	}

	if (WriteProcessMemory(hProcess, AddrAlloc, PathDll, sPathDll, 0) == 0) {
		printf("[#] WriteProcessMemory() : Error");
		exit(EXIT_FAILURE);
	}

	LPTHREAD_START_ROUTINE addrLoadLibrary =
			(LPTHREAD_START_ROUTINE) GetProcAddress(
			GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (addrLoadLibrary == NULL) {
		printf(
				"[#] GetProcAddress(\"kernel32.dll\", \"LoadLibraryA\") : Error");
		exit(EXIT_FAILURE);
	}

	HANDLE RemoteFunction = CreateRemoteThread(hProcess, NULL, 0,
			addrLoadLibrary, AddrAlloc, 0, 0);
	if (RemoteFunction == NULL) {
		printf("[#] CreateRemoteThread() : Error");
		exit(EXIT_FAILURE);
	}

	printf("[~] DLL Injected ! :o");
	WaitForSingleObject(RemoteFunction, 1000);
	VirtualFreeEx(hProcess, AddrAlloc, 0, MEM_DECOMMIT);
	CloseHandle(RemoteFunction);

	LPTHREAD_START_ROUTINE addrFreeLibrary =
			(LPTHREAD_START_ROUTINE) GetProcAddress(
			GetModuleHandle("kernel32.dll"), "FreeLibrary");
	if (addrFreeLibrary == NULL) {
		printf("[#] GetProcAddress(\"kernel32.dll\", \"FreeLibrary\") : Error");
		exit(EXIT_FAILURE);
	}

	RemoteFunction = CreateRemoteThread(hProcess, NULL, 0, addrFreeLibrary,
			GetHandleDll(PathDll, pid), 0, 0);
	if (RemoteFunction == NULL) {
		printf("[#] CreateRemoteThread() : Error");
		exit(EXIT_FAILURE);
	}
	printf("[~] DLL Free ! ;)");
	CloseHandle(RemoteFunction);
	CloseHandle(hProcess);

	return 0;
}

int GetProcessPidByName(char *nProcess) {
	PROCESSENTRY32 ProcessEntry = { 0 };
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE Snapshot32Process = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0);
	Process32First(Snapshot32Process, &ProcessEntry);
	while (Process32Next(Snapshot32Process, &ProcessEntry)
			&& strcmp(ProcessEntry.szExeFile, nProcess) != 0)
		;
	CloseHandle(Snapshot32Process);

	if (!strcmp(ProcessEntry.szExeFile, nProcess))
		return ProcessEntry.th32ProcessID;
	else
		return -1;
}

HANDLE GetHandleDll(char *PathDll, int pid) {
	MODULEENTRY32 ModuleEntry = { 0 };
	ModuleEntry.dwSize = sizeof(MODULEENTRY32);
	HANDLE Snapshot32Module = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid);
	Module32First(Snapshot32Module, &ModuleEntry);

	while (Module32Next(Snapshot32Module, &ModuleEntry))
		;
	CloseHandle(Snapshot32Module);
	if (!strstr(ModuleEntry.szModule, PathDll))
		return ModuleEntry.hModule;
	else
		return INVALID_HANDLE_VALUE ;
}
