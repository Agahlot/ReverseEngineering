/*\
\ / Author ~ From | Toufik Airane ~ Paris
/ \ GitHub        | tfairane.github.com
\ / Mail          | tf.airane@gmail.com
/ \ Twitter       | @tfairane
\ /
/ \ File          | ps.c
\ / Language      | C
/ \ Brief         | Report Process Status
\ /
/ \ Licence       | Ce code est totalement libre de droit.
\ /               | Je vous encourage à le partager et/ou le modifier.
/ \               | Son utilisation engage votre entière responsabilité.
\*/

    #include <stdio.h>
    #include <windows.h>
    #include <TlHelp32.h>
    #define C_EOL "\n"
    #define NOTICE "Usage : %s [OPTION] [PID] || follow @tfairane" C_EOL\
                    "-p : list all process" C_EOL\
                    "-m [PID] : retrieve all current handle",argv[0]
    typedef int bool;

    void ps();//Report Process Status
    void ms(int pid);// Report Module Status
    bool is64(int pid);// Is 64 or 32 bits ?

    int main(int argc, char* argv[])
    {
        switch (argc) {
            default:
            case 1:
                printf(NOTICE);
                break;

            case 2:
                if(!strcmp(argv[1],"-p"))
                    ps();
                break;

            case 3:
                if(!strcmp(argv[1],"-m"))
                    ms(atoi(argv[2]));
                break;
        };

        return EXIT_SUCCESS;
    }

    void ps() {
        PROCESSENTRY32 ProcessEntry = { 0 };
        ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE Snapshot32Process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if(Snapshot32Process == INVALID_HANDLE_VALUE)
            exit(EXIT_FAILURE);

        if(!Process32First(Snapshot32Process, &ProcessEntry)) {
                CloseHandle(Snapshot32Process);
                exit(EXIT_FAILURE);
        }

        printf(" %-32s %8s %2c %8s %8s" C_EOL C_EOL, "** Process Name **", "** PID **", '-', "** PPID **", "** Version **");
        while (Process32Next(Snapshot32Process, &ProcessEntry))
                printf("[+] %-32s %8d %2c %8d %8s" C_EOL, ProcessEntry.szExeFile, ProcessEntry.th32ProcessID , '-', ProcessEntry.th32ParentProcessID, is64(ProcessEntry.th32ProcessID)?"*32":"*64");
        CloseHandle(Snapshot32Process);
    }

    void ms(int pid) {
        MODULEENTRY32 ModuleEntry = { 0 };
        ModuleEntry.dwSize = sizeof(MODULEENTRY32);
        HANDLE Snapshot32Module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

        if(Snapshot32Module == INVALID_HANDLE_VALUE)
            exit(EXIT_FAILURE);

        if(!Module32First(Snapshot32Module, &ModuleEntry)) {
            CloseHandle(Snapshot32Module);
            exit(EXIT_FAILURE);
        }

        while(Module32Next(Snapshot32Module, &ModuleEntry))
            printf("%[+] %-32s" C_EOL, ModuleEntry.szModule);
        CloseHandle(Snapshot32Module);
    }

    bool is64(int pid) {
        bool is64;
        typedef bool(*pis64)(HANDLE, bool);
        pis64 fis64;
        fis64 = (pis64)GetProcAddress(GetModuleHandle("kernel32"),"IsWow64Process");
        fis64(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), (bool)&is64);
    return is64;
    }
