#include <ntddk.h>
#include <wdf.h>
#include<winapifamily.h>
#define UniqueProcessId 0x180
#define ActiveProcessLinks 0x188
#define ImageFileName 0x2e0

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

VOID ExploreEPROCESS() {

	PEPROCESS cEProcess = (PEPROCESS)PsGetCurrentProcess(), origEProcess = cEProcess;
	PLIST_ENTRY cActiveProcessLinks;
	PUCHAR cImageFileName;
	PUINT32 cPid;

	do {
		cImageFileName = (PUCHAR)((DWORD64)cEProcess + ImageFileName);
		cPid = (PUINT32)((DWORD64)cEProcess + UniqueProcessId);
		cActiveProcessLinks = (PLIST_ENTRY)((DWORD64)cEProcess + ActiveProcessLinks);

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "cImageFileName : %s\n", cImageFileName));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "cPid : %d\n", *cPid));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "cActiveProcessLinks->Flink : %x\n", cActiveProcessLinks->Flink));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "cActiveProcessLinks->Blink : %x\n", cActiveProcessLinks->Blink));

		cEProcess = (PEPROCESS)((DWORD64)cActiveProcessLinks->Flink - ActiveProcessLinks);
	} while ((DWORD64)origEProcess != (DWORD64)cEProcess);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Loaded\n"));
	// Initialize the driver config structure
	WDF_DRIVER_CONFIG_INIT(&config, NULL);
	// Indicate that this is a non-PNP driver
	config.DriverInitFlags = WdfDriverInitNonPnpDriver;
	// Specify the callout driver's Unload function
	config.EvtDriverUnload = EvtDriverUnload;
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

	ExploreEPROCESS();

	return status;
}

VOID EvtDriverUnload(_In_ WDFDRIVER DriverObject) {
	DriverObject;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Unloaded\n"));
}
