

    /*//
    //@Name     :   PE ANALYSE
    //@Author   :   Toufik Airane
    //*/

    #include<stdio.h>
    #include<stdlib.h>
    #include<windows.h>

    int main(int argc, char * argv[])
    {
    HANDLE hFile = CreateFile("main.exe", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    HANDLE hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
    HANDLE hFileMapView = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);

    if(hFile==INVALID_HANDLE_VALUE || hFileMap==INVALID_HANDLE_VALUE || hFileMapView==INVALID_HANDLE_VALUE)
        exit(EXIT_FAILURE);

    PIMAGE_DOS_HEADER EnTeteDOS = (PIMAGE_DOS_HEADER)hFileMapView;
    PIMAGE_NT_HEADERS EnTeteNT = (PIMAGE_NT_HEADERS)(hFileMapView + EnTeteDOS->e_lfanew);

    if(EnTeteNT->Signature == IMAGE_NT_SIGNATURE && EnTeteDOS->e_magic == IMAGE_DOS_SIGNATURE) {
        //#define IMAGE_NT_SIGNATURE    0x4550    "PE"
        //#define IMAGE_DOS_SIGNATURE   0x5A4D    "MZ"
        printf("[#] PE ANALYSE [#]\n");
        printf("[~] Entry Point : %08x\n", EnTeteNT->OptionalHeader.AddressOfEntryPoint);
        printf("[~] ImageBase : %08x\n", EnTeteNT->OptionalHeader.ImageBase);
        printf("[~] Number of sections : %ld\n", EnTeteNT->FileHeader.NumberOfSections);


        int i;
        for( i=0; i < EnTeteNT->FileHeader.NumberOfSections; i++ ) {
            PIMAGE_SECTION_HEADER EnTeteSection = (PIMAGE_SECTION_HEADER) (hFileMapView + EnTeteDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i*sizeof(IMAGE_SECTION_HEADER));
            printf("Section name : %-10s Relative Virtual Address : %08x\n", (char *)EnTeteSection->Name ,  (char *)EnTeteSection->VirtualAddress);
        }

    }

    DWORD ImportDirectory;
    DWORD ImageSizeDirectory;

    PIMAGE_THUNK_DATA OrigThunk;
    PIMAGE_THUNK_DATA FirstThunk;

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
            printf("----------------------\n");
            IATBase++;
        }
    return 0;
    }
