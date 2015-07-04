#include "stdafx.h"
#include <Windows.h>

int _tmain(int argc, _TCHAR* argv[])
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;
	
	printf("Load W7 driver unsigned/signed\nhigh privileged required\n");

	// get Service Control Manager
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (hSCManager) {

		// Create Service
		hService = CreateService(
			hSCManager,
			TEXT("POC.DKOM.W7.rootkit"),
			TEXT("POC.DKOM.W7.rootkit"),
			SERVICE_START | DELETE | SERVICE_STOP,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE,
			TEXT("C:\\\\Users\\Airane\\Documents\\Visual Studio 2013\\Projects\\rootkit\\x64\\Win7Debug\\rootkit.sys"),
			NULL, NULL, NULL, NULL, NULL);

		// if service does not exist, open it 
		if (!hService) {
			hService = OpenService(
				hSCManager,
				TEXT("POC.DKOM.W7.rootkit"),
				SERVICE_START | DELETE | SERVICE_STOP);
		}

		// if service exist, start it
		if (hService) {

			StartService(hService, 0, NULL);

			printf("Please, press any key to unload driver\n");
			getchar();

			ControlService(hService, SERVICE_CONTROL_STOP, &ss);
			DeleteService(hService);
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCManager);
	} else {
		// if "5 : ERROR_ACCESS_DENIED" : check permission
		printf("Error : %d", GetLastError());
		return 1;
	}

	return 0;
}

