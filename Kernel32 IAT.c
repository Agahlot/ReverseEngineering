    
    
    /**
    * @file Kernel32 IAT.c
    * @author Airane Toufik
    **/
    
    #include<stdio.h>
    #include<stdlib.h>
    #include<windows.h>

    int main()
    {
    DWORD hFileMapView = GetModuleHandle("kernel32");
    PIMAGE_DOS_HEADER EnTeteDOS = (PIMAGE_DOS_HEADER)hFileMapView;
    PIMAGE_NT_HEADERS EnTeteNT = (PIMAGE_NT_HEADERS)(hFileMapView + EnTeteDOS->e_lfanew);

    DWORD ImportDirectory;
    DWORD ImageSizeDirectory;

    PIMAGE_IMPORT_DESCRIPTOR IATBase;
    PIMAGE_THUNK_DATA OrigThunk;
    PIMAGE_THUNK_DATA FirstThunk;

    ImportDirectory = (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ImageSizeDirectory = (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    printf("[~] VIEW Import Address Tables KERNEL32 [~]\n");
    printf("[#] Import table address %08x and size %08x [#]\n", ImportDirectory, ImageSizeDirectory);
    IATBase = (PIMAGE_IMPORT_DESCRIPTOR)(hFileMapView + (DWORD)ImportDirectory);

        while(IATBase->Name)
        {
            printf("DLL/LIB : %08x\n", IATBase->Name);
            printf("OriginalThunk : %08x\n", IATBase->OriginalFirstThunk);
            printf("FirstThunk : %08x\n", IATBase->FirstThunk);

            PIMAGE_THUNK_DATA OrigThunk = (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->OriginalFirstThunk);
            PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)(hFileMapView + IATBase->FirstThunk);
            while(OrigThunk->u1.AddressOfData != 0)
            {
                    PIMAGE_IMPORT_BY_NAME APIName = (PIMAGE_IMPORT_BY_NAME)(hFileMapView + OrigThunk->u1.AddressOfData);
                        printf("[~] API Name %32s\n", APIName->Name);
                    OrigThunk++;
            }
            IATBase++;
        }
        
	return 0;
	}
