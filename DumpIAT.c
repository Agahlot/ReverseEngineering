/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane@github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | DumpIAT.c
\ / Language        | C
/ \ Brief           | DUMP Import Address Table
\ /
/ \ Licence         | Ce code est totalement libre de droit.
\ /                 | Je vous encourage à le partager et/ou le modifier.
/ \                 | Son utilisation engage votre entière responsabilité.
\*/

	#include<stdio.h>
	#include<stdlib.h>
	#include<windows.h>
    #define C_EOL "\n"

	int main(int argc, char * argv[])
	{

	PIMAGE_DOS_HEADER EnTeteDOS;
	PIMAGE_NT_HEADERS EnTeteNT;

	DWORD ImportDirectory;
	DWORD ImageSizeDirectory;

	PIMAGE_IMPORT_DESCRIPTOR IATBase;
	PIMAGE_THUNK_DATA OrigThunk;
	PIMAGE_THUNK_DATA FirstThunk;

	HANDLE hFileMapView =   GetModuleHandle(NULL); // CURRENT HANDLE
	EnTeteDOS           =   (PIMAGE_DOS_HEADER)hFileMapView;
	EnTeteNT            =   (PIMAGE_NT_HEADERS)(hFileMapView + EnTeteDOS->e_lfanew);

	if(EnTeteNT->Signature == IMAGE_NT_SIGNATURE) {

	DWORD ImportDirectory;
	DWORD ImageSizeDirectory;
	PIMAGE_THUNK_DATA OrigThunk;
	PIMAGE_THUNK_DATA FirstThunk;

    ImportDirectory     =   (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ImageSizeDirectory  =   (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("<~> DUMP Import Address Table" C_EOL );
	printf("<~> Address : 0x%08x and Size : %d" C_EOL C_EOL, ImportDirectory, ImageSizeDirectory);
	PIMAGE_IMPORT_DESCRIPTOR IATBase = (PIMAGE_IMPORT_DESCRIPTOR)(hFileMapView + (DWORD)ImportDirectory);

			while(IATBase->Name)
			{
				printf("> DLL Name : %s - ", hFileMapView + IATBase->Name);
				printf("OriginalThunk : %08x - ", IATBase->OriginalFirstThunk);
				printf("FirstThunk : %08x" C_EOL C_EOL, IATBase->FirstThunk);

				PIMAGE_THUNK_DATA OrigThunk     =   (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->OriginalFirstThunk);
				PIMAGE_THUNK_DATA FirstThunk    =   (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->FirstThunk);
				while(OrigThunk->u1.AddressOfData)
				{
						PIMAGE_IMPORT_BY_NAME APIName = (PIMAGE_IMPORT_BY_NAME)(hFileMapView + OrigThunk->u1.AddressOfData);
                        printf("-> API Name : %-32s Address : 0x%08x" C_EOL, APIName->Name, GetProcAddress(GetModuleHandle(hFileMapView + IATBase->Name), APIName->Name));
						OrigThunk++;
				}
				printf(C_EOL);
				IATBase++;
			}
	}
	return 0;
	}
