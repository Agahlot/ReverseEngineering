//**//**//**//**|---------------------------------------------------------------------------
//	Author  // From     :	Toufik Airane // Paris
//	GitHub              :	toufikairane@github.io
//	Mail to 	        :	tf.airane@gmail.com
//* * * * * * * * * * * |
//	Source file         :	DumpIAT.c
//	Brief		        :	Dump IAT from an "Handle"
//	Language	        :	C
//  Compilation option  :   no
//* * * * * * * * * * * |
//	Licence		        :	Cette oeuvre est totalement libre de droit.
//	*******		        |	Je vous encourage à la partager et/ou la modifier.
//	*******		        |	En revanche son utilisation engage votre entière responsabilité.
//**//**//**//**|---------------------------------------------------------------------------

	#include<stdio.h>
	#include<stdlib.h>
	#include<windows.h>

	int main(int argc, char * argv[])
	{
	PIMAGE_DOS_HEADER EnTeteDOS;
	PIMAGE_NT_HEADERS EnTeteNT;

	DWORD ImportDirectory;
	DWORD ImageSizeDirectory;

	PIMAGE_IMPORT_DESCRIPTOR IATBase;
	PIMAGE_THUNK_DATA OrigThunk;
	PIMAGE_THUNK_DATA FirstThunk;

	//HANDLE hFile = CreateFile(argv[0], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//HANDLE hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
	//HANDLE hFileMapView = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);

    //HANDLE hFileMapView = GetModuleHandle("kernel32"); // Dump any IAT from DLL attached
	HANDLE hFileMapView = GetModuleHandle(NULL);    // Current Handle

	EnTeteDOS = (PIMAGE_DOS_HEADER)hFileMapView;
	EnTeteNT = (PIMAGE_NT_HEADERS)(hFileMapView + EnTeteDOS->e_lfanew);

	if(EnTeteNT->Signature == IMAGE_NT_SIGNATURE) {	//#define	IMAGE_NT_SIGNATURE	0x00004550  // PE00

	DWORD ImportDirectory;
	DWORD ImageSizeDirectory;

	PIMAGE_THUNK_DATA OrigThunk;
	PIMAGE_THUNK_DATA FirstThunk;

		ImportDirectory = (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		ImageSizeDirectory = (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
		printf("[~] VIEW Import Address Tables [~]\n");
		printf("[#] Import table address %08x and size %08x [#]\n", ImportDirectory, ImageSizeDirectory);
		PIMAGE_IMPORT_DESCRIPTOR IATBase = (PIMAGE_IMPORT_DESCRIPTOR)(hFileMapView + (DWORD)ImportDirectory);

			while(IATBase->Name)
			{
				printf("DLL/LIB : %s\n", hFileMapView + IATBase->Name);
				printf("OriginalThunk : %08x\n", IATBase->OriginalFirstThunk);
				printf("FirstThunk : %08x\n", IATBase->FirstThunk);

				PIMAGE_THUNK_DATA OrigThunk = (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->OriginalFirstThunk);
				PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->FirstThunk);
				while(OrigThunk->u1.AddressOfData)
				{
						PIMAGE_IMPORT_BY_NAME APIName = (PIMAGE_IMPORT_BY_NAME)(hFileMapView + OrigThunk->u1.AddressOfData);
							printf("[~] API Name : %32s\n", APIName->Name);
						OrigThunk++;
				}
				IATBase++;
			}
	}
	return 0;
	}
