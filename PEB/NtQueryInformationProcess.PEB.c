#include<stdio.h>
#include<windows.h>
#include<PEB.h>

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
typedef PPEB (*pRtlGetCurrentPeb)(void);

int main() {
	PROCESS_BASIC_INFORMATION ProcessInformation;
	PPEB PEB;
	PRTL_USER_PROCESS_PARAMETERS UPP;
	PPEB_LDR_DATA LDR;

	pRtlGetCurrentPeb RtlGetCurrentPeb =
            (pRtlGetCurrentPeb) GetProcAddress(
            LoadLibrary("Ntdll.dll"), "RtlGetCurrentPeb");

	pNtQueryInformationProcess NtQueryInformationProcess =
			(pNtQueryInformationProcess) GetProcAddress(
			LoadLibrary("Ntdll.dll"), "NtQueryInformationProcess");

	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation,
			&ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	PEB = (PPEB) ProcessInformation.PebBaseAddress;
	UPP = (PRTL_USER_PROCESS_PARAMETERS) PEB->ProcessParameters;
	LDR = (PPEB_LDR_DATA) PEB->Ldr;

	printf("PEB location : %08x", PEB);
	return 0;
}
