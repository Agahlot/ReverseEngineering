#include<stdio.h>
#include<windows.h>

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved4[104];
	PVOID Reserved5[52];
	PVOID PostProcessInitRoutine;
	BYTE Reserved6[128];
	PVOID Reserved7[1];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

enum PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information2 = 6,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
};

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
