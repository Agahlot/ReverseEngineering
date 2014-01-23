/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane.github.com
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

    FILE* hLog          =   fopen("DumpIAT.log.txt", "w+");
    HANDLE hFile        =   GetModuleHandle(NULL);// Current Handle
    EnTeteDOS           =   (PIMAGE_DOS_HEADER)hFile;
    EnTeteNT            =   (PIMAGE_NT_HEADERS)(hFile + EnTeteDOS->e_lfanew);

    ImportDirectory     =   (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ImageSizeDirectory  =   (DWORD)(EnTeteNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    IATBase = (PIMAGE_IMPORT_DESCRIPTOR)(hFile + (DWORD)ImportDirectory);

    fprintf(hLog, "[ DUMP Import Address Table ]"C_EOL);
    fprintf(hLog, "[Address] : 0x%08x"C_EOL"[Size] : %d"C_EOL C_EOL, ImportDirectory, ImageSizeDirectory);

        while(IATBase->Name)
        {
            fprintf(hLog, "[DLL Name] : %s"C_EOL, hFile + IATBase->Name);
            fprintf(hLog, "[OriginalThunk] : %08x"C_EOL, IATBase->OriginalFirstThunk);
            fprintf(hLog, "[FirstThunk] : %08x"C_EOL C_EOL, IATBase->FirstThunk);

            PIMAGE_THUNK_DATA OrigThunk     =   (PIMAGE_THUNK_DATA)(hFile + IATBase->OriginalFirstThunk);
            PIMAGE_THUNK_DATA FirstThunk    =   (PIMAGE_THUNK_DATA)(hFile + IATBase->FirstThunk);

                while(OrigThunk->u1.AddressOfData)
                {
                    PIMAGE_IMPORT_BY_NAME APIName = (PIMAGE_IMPORT_BY_NAME)(hFile + OrigThunk->u1.AddressOfData);
                    fprintf(hLog, "[API Name] : %-32s [Address] : 0x%08x"C_EOL, APIName->Name, FirstThunk->u1.Function);

                    OrigThunk++;
                    FirstThunk++;
                }
                fprintf(hLog,C_EOL);
                IATBase++;
        }

    fclose(hLog);
    return 0;
	}
