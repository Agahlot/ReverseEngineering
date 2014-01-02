/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | toufikairane@github.io
\ / Mail to         | tf.airane@gmail.com
/ \ Twitter         | @toufikairane
\ /
/ \ Source file     | inject.cpp
\ / Language        | C++
/ \ Brief           | inject dll to process
\ /
/ \ Licence :   	| Cette oeuvre est totalement libre de droit.
\ /      			| Je vous encourage à la partager et/ou la modifier.
/ \    				| Son utilisation engage votre entière responsabilité.
\*/

    #include <iostream>
    #include <cstring>
    #include <windows.h>
    #include <TlHelp32.h>

    using namespace std;

    int GetProcessPidByName( char *nProcess);
    HANDLE GetHandleDll( char *PathDll, int pid);

    int main( int argc, char *argv[])
    {
        if(argc!=3)
            exit(EXIT_FAILURE);

        char *PathDll   =   argv[2];    // Specifie FULL Path to DLL !
        int sPathDll    =   strlen(PathDll);
        int pid         =   GetProcessPidByName( argv[1]);

        HANDLE hProcess     =   OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid);
        LPVOID AddrAlloc    =   VirtualAllocEx( hProcess, NULL, sPathDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory( hProcess, AddrAlloc, PathDll, sPathDll, 0);
        LPTHREAD_START_ROUTINE addrLoadLibrary  =   (LPTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        HANDLE RemoteFunction   =   CreateRemoteThread( hProcess, NULL, 0, addrLoadLibrary, AddrAlloc, 0, 0);
        WaitForSingleObject( RemoteFunction, 1000);
        VirtualFreeEx( hProcess, AddrAlloc, 0, MEM_DECOMMIT);
        CloseHandle( RemoteFunction);

        LPTHREAD_START_ROUTINE addrFreeLibrary = (LPTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("kernel32.dll"), "FreeLibrary");
        RemoteFunction = CreateRemoteThread( hProcess, NULL, 0, addrFreeLibrary, GetHandleDll("DLL.dll", pid), 0 , 0);
        CloseHandle( RemoteFunction);
        CloseHandle( hProcess);
    }

    int GetProcessPidByName( char *nProcess) {
        PROCESSENTRY32 ProcessEntry = { 0 };
        ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE Snapshot32Process = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0);
        Process32First( Snapshot32Process, &ProcessEntry);

        while(Process32Next( Snapshot32Process, &ProcessEntry) && strcmp( ProcessEntry.szExeFile, nProcess)!=0);
        CloseHandle( Snapshot32Process);

        if(!strcmp( ProcessEntry.szExeFile, nProcess))
            return ProcessEntry.th32ProcessID;
        else
            return -1;
    }

    HANDLE GetHandleDll( char *PathDll, int pid) {
        MODULEENTRY32 ModuleEntry = { 0 };
        ModuleEntry.dwSize = sizeof(MODULEENTRY32);
        HANDLE Snapshot32Module = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid);
        Module32First( Snapshot32Module, &ModuleEntry);

        while(Module32Next( Snapshot32Module, &ModuleEntry));
        CloseHandle( Snapshot32Module);

        if(!strncmp(PathDll, ModuleEntry.szModule, 4))
            return ModuleEntry.hModule;
        else
            return INVALID_HANDLE_VALUE;
    }
