#include<stdio.h>
#include<MapPE/PEB.h>

typedef DWORD (*pNtQueryInformationProcess)(HANDLE, enum PROCESSINFOCLASS,
		PVOID, ULONG, PULONG);

int main(int argc, char *argv[]) {

	DWORD sReturn;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	PPEB PEB;
	PRTL_USER_PROCESS_PARAMETERS UPP;
	PPEB_LDR_DATA LDR;

	pNtQueryInformationProcess NtQueryInformationProcess =
			(pNtQueryInformationProcess) GetProcAddress(
			LoadLibrary("Ntdll.dll"), "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation,
			&ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), &sReturn);

	PEB = (PPEB) ProcessInformation.PebBaseAddress;
	UPP = (PRTL_USER_PROCESS_PARAMETERS) PEB->ProcessParameters;
	LDR = (PPEB_LDR_DATA) PEB->Ldr;

	return 0x0;
}
