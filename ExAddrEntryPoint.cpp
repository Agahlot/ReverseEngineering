/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane.github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | EntryPointRedirection.cpp
\ / Language        | C++
/ \ Brief           | AddressOfEntryPoint Rewritting
\ /
/ \ Licence         | Ce code est totalement libre.
\ /                 | Je vous encourage à le partager et/ou le modifier.
/ \                 | Un grand pouvoir implique de grandes responsabilités.
\*/

    #include <iostream>
    #include <cstdlib>
    #include <windows.h>
    using namespace std;

    int main(int argc, char *argv[])
    {
        if(argc!=3)
            exit(EXIT_FAILURE);

        HANDLE hFile = CreateFile( argv[1],
                                   GENERIC_WRITE|GENERIC_READ,
                                   FILE_SHARE_WRITE|FILE_SHARE_READ,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL,
                                   NULL );

        DWORD dwTaille = 0;
        IMAGE_DOS_HEADER hDOS;
        IMAGE_NT_HEADERS hNT;

        SetFilePointer(hFile, 0, 0, FILE_BEGIN);
        ReadFile(hFile, &hDOS, sizeof(IMAGE_DOS_HEADER), &dwTaille, NULL);// DOS HEADER

        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        ReadFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);// NT HEADER

        cout << hex << "Ex AddressOfEntryPoint Offset : " << hNT.OptionalHeader.AddressOfEntryPoint << endl;
        hNT.OptionalHeader.AddressOfEntryPoint = (DWORD) strtoul(argv[2], NULL, 16);
        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        WriteFile(hFile, &hNT, sizeof(hNT), &dwTaille, NULL);// Patch NT HEADER
        cout << hex << "New  AddressOfEntryPoint Offset : " << hNT.OptionalHeader.AddressOfEntryPoint << endl;

        CloseHandle(hFile);
        return 0;
    }
