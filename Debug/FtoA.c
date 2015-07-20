#include<stdio.h>
#include<windows.h>

int main(int argc, char *argv[]) {
	if (argc != 3) {
		printf("[~] %s <dll> <function>", argv[0]);
		return 0x1;
	}

	HMODULE hDll;
	hDll = LoadLibrary(argv[1]);
	if (!hDll) {
		printf("[-] LoadLibrary() : Error");
		return 0x1;
	}

	FARPROC hFunc;
	hFunc = GetProcAddress(hDll, argv[2]);
	if (!hFunc) {
		printf("[-] GetProcAddress() : Error");
		FreeLibrary(hDll);
		return 0x1;
	}

	printf("[+] %s 0x%08x", argv[2], hFunc);
	FreeLibrary(hDll);
	return 0x0;
}
