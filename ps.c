#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#define C_EOL "\n"

typedef enum bool bool;
enum bool {
	false,
	true
};

bool is64(int pid) {
	typedef bool (*pis64)(HANDLE, bool);
	bool is64;
	pis64 fis64;
	fis64 = (pis64) GetProcAddress(GetModuleHandle("kernel32"),
			"IsWow64Process");
	fis64(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (bool) &is64);
	return is64;
}

void ps() {
	PROCESSENTRY32 ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE Snapshot32Process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Snapshot32Process == INVALID_HANDLE_VALUE)
		exit(EXIT_FAILURE);

	if (!Process32First(Snapshot32Process, &ProcessEntry)) {
		CloseHandle(Snapshot32Process);
		exit(EXIT_FAILURE);
	}

	printf("%-4s%-32s%8s%2c%8s%8s" C_EOL C_EOL, "[~]", "Process Name", "PID", '-',
			"PPID", "Version");
	while (Process32Next(Snapshot32Process, &ProcessEntry))
		printf("%-4s%-32s%8d%2c%8d%8s" C_EOL, "[+]", ProcessEntry.szExeFile,
				ProcessEntry.th32ProcessID, '-',
				ProcessEntry.th32ParentProcessID,
				is64(ProcessEntry.th32ProcessID) ? "*32" : "*64");
	CloseHandle(Snapshot32Process);
}

void main() {
	ps();
}
