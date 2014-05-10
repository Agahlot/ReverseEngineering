#include <windows.h>

LPDWORD getAddr(char *f) {
	HMODULE hFileMap = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER hDOS = (PIMAGE_DOS_HEADER) (hFileMap);
	PIMAGE_NT_HEADERS hNT = (PIMAGE_NT_HEADERS) ((DWORD) hFileMap
			+ hDOS->e_lfanew);

	DWORD EntryExportVA =
			hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR hEntryImport =
			(PIMAGE_IMPORT_DESCRIPTOR) ((DWORD) hFileMap + EntryExportVA);

	while (hEntryImport->FirstThunk) {
		PIMAGE_THUNK_DATA hOriginalFirstThunk =
				(PIMAGE_THUNK_DATA) ((DWORD) hFileMap
						+ hEntryImport->OriginalFirstThunk);
		PIMAGE_THUNK_DATA hFirstThunk = (PIMAGE_THUNK_DATA) ((DWORD) hFileMap
				+ hEntryImport->FirstThunk);

		while (hOriginalFirstThunk->u1.AddressOfData) {
			PIMAGE_IMPORT_BY_NAME API =
					(PIMAGE_IMPORT_BY_NAME) ((DWORD) hFileMap
							+ hOriginalFirstThunk->u1.AddressOfData);
			if (!strcmp((char*) API->Name, f))
				return &(hFirstThunk->u1.Function);

			hOriginalFirstThunk++;
			hFirstThunk++;
		}
		hEntryImport++;
	}
	return NULL;
}

BOOL HookAPI(char *f, DWORD addrHook) {
	DWORD dwProtect;
	LPDWORD addrOrig = getAddr(f);

	if (VirtualProtect(addrOrig, sizeof(LPDWORD), PAGE_EXECUTE_READWRITE,
			&dwProtect)) {

		*addrOrig = (DWORD) addrHook;

		if (!VirtualProtect(addrOrig, sizeof(LPDWORD), dwProtect, &dwProtect)) {
			MessageBox(NULL, "VirtualProtect() 1: Error",
					"VirtualProtect() : Error", 0);
			return FALSE;
		}
	} else {
		MessageBox(NULL, "VirtualProtect() 2 : Error",
				"VirtualProtect() : Error", 0);
		return FALSE;
	}
	return TRUE;
}

// Hook "printf" Prototype
int hookprintf(const char* format) {
	MessageBoxA(NULL, "Hook Success ;)", "Hook Success ;)", 0);
	return 0;
}

extern "C" __declspec(dllexport) BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {

	if (fdwReason == DLL_PROCESS_ATTACH)
	if(!HookAPI((char*) "printf", (DWORD) &hookprintf))
	MessageBox(NULL, "Hook Failed :(", "Hook Failed :(", 0);

	return TRUE;
}
