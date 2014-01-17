/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane@github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | injectDLL.cpp
\ / Language        | C++
/ \ Brief           | InjectDLL into Process RING 3
\ /
/ \ Licence         | Ce code est totalement libre de droit.
\ /      			| Je vous encourage à le partager et/ou le modifier.
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
        cout << "InjectDLL into Process RING 3 | follow @tfairane" << endl;
        if(argc!=3) {
            cout << "[NOTICE] " << argv[0] << " <Process Name> <FULL Path DLL>" << endl;
            exit(EXIT_FAILURE);
        }

        char *PathDll   =   argv[2];// Specifie FULL Path to DLL !!!!
        int sPathDll    =   strlen(PathDll);
        int pid         =   GetProcessPidByName(argv[1]);

        cout << "[Target]" << endl << " Name : " << argv[1] << endl << " PID : " << pid << endl;

        HANDLE hProcess     =   OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid);
        if(hProcess == NULL) {
            cout << "[#] OpenProcess() : Error (" << GetLastError() << ")" << endl;
            exit( EXIT_FAILURE);
        }

        LPVOID AddrAlloc    =   VirtualAllocEx( hProcess, NULL, sPathDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(AddrAlloc == NULL) {
            cout << "[#] VirtualAllocEx() : Error (" << GetLastError() << ")" << endl;
            exit( EXIT_FAILURE);
        }

        if(WriteProcessMemory( hProcess, AddrAlloc, PathDll, sPathDll, 0) == 0) {
            cout << "[#] WriteProcessMemory() : Error (" << GetLastError() << ")" << endl;
            exit( EXIT_FAILURE);
        }

        LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        if(addrLoadLibrary == NULL) {
            cout << "[#] GetProcAddress(\"kernel32.dll\", \"LoadLibraryA\") : Error (" << GetLastError() << ")" << endl;
            exit( EXIT_FAILURE);
        }

        HANDLE RemoteFunction   =   CreateRemoteThread( hProcess, NULL, 0, addrLoadLibrary, AddrAlloc, 0, 0);
        if(RemoteFunction == NULL) {
            cout << "[#] CreateRemoteThread() : Error (" << GetLastError() << ")" << endl;
            exit( EXIT_FAILURE);
        }

        cout << "[~] DLL Injected ! :o" << endl;
        WaitForSingleObject( RemoteFunction, 1000);
        VirtualFreeEx( hProcess, AddrAlloc, 0, MEM_DECOMMIT);
        CloseHandle( RemoteFunction);

        LPTHREAD_START_ROUTINE addrFreeLibrary = (LPTHREAD_START_ROUTINE) GetProcAddress( GetModuleHandle("kernel32.dll"), "FreeLibrary");
        if(addrFreeLibrary == NULL) {
            cout << "[#] GetProcAddress(\"kernel32.dll\", \"FreeLibrary\") : Error (" << GetLastError() << ")" << endl;
            exit( EXIT_FAILURE);
        }

        RemoteFunction = CreateRemoteThread( hProcess, NULL, 0, addrFreeLibrary, GetHandleDll(PathDll, pid), 0 , 0);
        if(RemoteFunction == NULL) {
            cout << "[#] CreateRemoteThread() : Error (" << GetLastError() << ")" << endl;
            exit( EXIT_FAILURE);
        }

        cout << "[~] DLL Free ! ;)" << endl;
        CloseHandle( RemoteFunction);
        CloseHandle( hProcess);

        return 0;
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
        if(!strstr( ModuleEntry.szModule, PathDll))
            return ModuleEntry.hModule;
        else
            return INVALID_HANDLE_VALUE;
    }
