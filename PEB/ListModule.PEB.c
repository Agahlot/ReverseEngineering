#include<stdio.h>
#include<windows.h>
#include<PEB.h>

typedef PPEB (*pRtlGetCurrentPeb)(void);

int main() {
	PPEB Peb;
	PPEB_LDR_DATA PedLdrData;
	PLDR_DATA_TABLE_ENTRY LdrDataEntry;
	PLIST_ENTRY ModuleListEntry, ModuleListHead;
	PLIST_ENTRY LdrpHashTable, ListEntry, ListHead;

	Peb=(PPEB) RtlGetCurrentPeb();
	PedLdrData=Peb->Ldr;

	ModuleListHead=&PedLdrData->InMemoryOrderModuleList;
	ModuleListEntry=ModuleListHead->Flink;

	while(ModuleListEntry!=ModuleListHead)
	{
		LdrDataEntry = (PLDR_DATA_TABLE_ENTRY) ModuleListEntry;

		printf("%s", LdrDataEntry->FullDllName.Buffer);

		ModuleListEntry=ModuleListEntry->Flink;
	}
	return 0;
}
