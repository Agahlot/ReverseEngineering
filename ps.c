/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane@github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | ps.c
\ / Language        | C
/ \ Brief           | Report Process Status CLI
\ /
/ \ Licence         | Ce code est totalement libre de droit.
\ /                 | Je vous encourage à le partager et/ou le modifier.
/ \                 | Son utilisation engage votre entière responsabilité.
\*/

    #include <stdio.h>
    #include <windows.h>
    #include <TlHelp32.h>
    #define C_EOL "\n"

    int main()
    {
        PROCESSENTRY32 ProcessEntry = { 0 };
        ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE Snapshot32Process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if(Snapshot32Process == INVALID_HANDLE_VALUE)
            exit(EXIT_FAILURE);

        if(!Process32First(Snapshot32Process, &ProcessEntry)) {
                CloseHandle(Snapshot32Process);
                exit(EXIT_FAILURE);
        }

        printf(" %-32s %8s %2c %8s" C_EOL C_EOL, "** Process Name **", "** PID **", '-', "** PPID **");
        while (Process32Next(Snapshot32Process, &ProcessEntry)) {
                printf(" %-32s %8d %2c %8d" C_EOL, ProcessEntry.szExeFile, ProcessEntry.th32ProcessID , '-', ProcessEntry.th32ParentProcessID);
        }

        CloseHandle(Snapshot32Process);
        return EXIT_SUCCESS;
    }
