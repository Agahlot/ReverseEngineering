#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#define C_EOL "\n"
#define NOTICE "Usage : %s <PID> - list modules"

void ms(int pid) {
	MODULEENTRY32 ModuleEntry;
	ModuleEntry.dwSize = sizeof(MODULEENTRY32);
	HANDLE Snapshot32Module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	if (Snapshot32Module == INVALID_HANDLE_VALUE)
		exit(EXIT_FAILURE);

	if (!Module32First(Snapshot32Module, &ModuleEntry)) {
		CloseHandle(Snapshot32Module);
		exit(EXIT_FAILURE);
	}

	while (Module32Next(Snapshot32Module, &ModuleEntry))
		printf("[+] %-32s" C_EOL, ModuleEntry.szModule);
	CloseHandle(Snapshot32Module);
}

void main(int argc, char* argv[]) {
    if(argc!=2)
        printf(NOTICE);
    else
        ms(atoi(argv[1]));
}
