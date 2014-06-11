#include<stdio.h>
#include<windows.h>
#include<PEB.h>

typedef PPEB (*pRtlGetCurrentPeb)(void);

int main() {
	PPEB PEB;

	pRtlGetCurrentPeb RtlGetCurrentPeb =
            (pRtlGetCurrentPeb) GetProcAddress(
            LoadLibrary("Ntdll.dll"), "RtlGetCurrentPeb");

    PEB = RtlGetCurrentPeb();

	printf("PEB location : %08x", PEB);
	return 0;
}
