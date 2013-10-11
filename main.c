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

HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
HANDLE hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
HANDLE hFileMapView = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);


EnTeteDOS = (PIMAGE_DOS_HEADER)hFileMapView;
EnTeteNT = (PIMAGE_NT_HEADERS)(hFileMapView + EnTeteDOS->e_lfanew);

if(EnTeteNT->Signature == IMAGE_NT_SIGNATURE) { //#define IMAGE_NT_SIGNATURE              0x00004550  // PE00

    ImportDirectory = (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ImageSizeDirectory = (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    printf("[~ VIEW Import Address Tables ~]\n\n");
    printf("[#]Import table address %08x and size %08x\n\n", ImportDirectory, ImageSizeDirectory);

    PIMAGE_IMPORT_DESCRIPTOR IATBase = (PIMAGE_IMPORT_DESCRIPTOR)(hFileMapView + (DWORD)ImportDirectory);

        while(IATBase->Name)
        {
            printf("DLL/LIB : %08x\n", IATBase->Name);
            printf("OriginalThunk : %08x\n", IATBase->OriginalFirstThunk);
            printf("FirstThunk : %08x\n", IATBase->FirstThunk);

            PIMAGE_THUNK_DATA OrigThunk = (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->OriginalFirstThunk);
            PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->FirstThunk);
            do
            {
                PIMAGE_IMPORT_BY_NAME APIName = (PIMAGE_IMPORT_BY_NAME)(hFileMapView + OrigThunk->u1.AddressOfData);
                    if (!((DWORD)APIName & IMAGE_ORDINAL_FLAG)) // IMAGE ORDINAL FLAG IL EST FUMER CE TRUC !!! FAUT VOIR
                       printf("%s\n", APIName->Name);

                OrigThunk++;

            } while(OrigThunk->u1.AddressOfData != 0);
            IATBase++;
        }
    }

CloseHandle(hFile);
CloseHandle(hFileMap);
CloseHandle(hFileMapView);

return 0;
}
