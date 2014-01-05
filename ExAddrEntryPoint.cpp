/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | toufikairane@github.io
\ / Mail to         | tf.airane@gmail.com
/ \ Twitter         | @toufikairane
\ /
/ \ Source file     | ExAddrEntryPoint.cpp
\ / Language        | C++ ~ Windows API
/ \ Brief           | Rewrite AddressOfEntryPoint
\ /
/ \ Licence :   	| Cette oeuvre est totalement libre de droit.
\ /      			| Je vous encourage � la partager et/ou la modifier.
/ \    				| Son utilisation engage votre enti�re responsabilit�.
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
        ReadFile(hFile, &hDOS, sizeof(IMAGE_DOS_HEADER), &dwTaille, NULL);  // DOS HEADER

        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        ReadFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);   // NT HEADER

        cout << hex << "Ex AddressOfEntryPoint Offset : " << hNT.OptionalHeader.AddressOfEntryPoint << endl;
        hNT.OptionalHeader.AddressOfEntryPoint = (DWORD) strtoul(argv[2], NULL, 16);
        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        WriteFile(hFile, &hNT, sizeof(hNT), &dwTaille, NULL);               // Patch NT HEADER
        cout << hex << "New  AddressOfEntryPoint Offset : " << hNT.OptionalHeader.AddressOfEntryPoint << endl;

        CloseHandle(hFile);
        return 0;
    }
