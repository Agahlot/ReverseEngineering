#include "stdafx.h"
#include <Windows.h>

int _tmain(int argc, _TCHAR* argv[])
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if(hSCManager) {

		hService = CreateService(
			hSCManager,
			TEXT("DriverTestService"),
			TEXT("DriverTestService"),
			SERVICE_START | DELETE | SERVICE_STOP,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE,
			TEXT(""),
			NULL, NULL, NULL, NULL, NULL);

		if(!hService) {

			hService = OpenService(
				hSCManager,
				TEXT("DriverTestService"),
				SERVICE_START | DELETE | SERVICE_STOP);
		}

		if(hService) {

			StartService(hService, 0, NULL);

			printf("Press Enter to close service\r\n");
			getchar();

			ControlService(hService, SERVICE_CONTROL_STOP, &ss);
			DeleteService(hService);
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCManager);
	}

	return 0;
}

