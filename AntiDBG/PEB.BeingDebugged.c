#include<stdio.h>
#include<PEB.h>

typedef DWORD (*pNtQueryInformationProcess)(HANDLE, enum PROCESSINFOCLASS,
		PVOID, ULONG, PULONG);

int main(int argc, char *argv[]) {

	PPEB PEB;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	DWORD sReturn;
	pNtQueryInformationProcess NtQueryInformationProcess =
			(pNtQueryInformationProcess) GetProcAddress(
					LoadLibrary("Ntdll.dll"), "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation,
			&ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), &sReturn);
	PEB = (PPEB) ProcessInformation.PebBaseAddress;

	printf("Is there a debugger ? %s !", PEB->BeingDebugged ? "Yes" : "No");
	return 0x0;
}
