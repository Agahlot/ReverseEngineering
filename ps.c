/*\
\ / Author ~ From   Toufik Airane ~ Paris
/ \ GitHub          toufikairane@github.io
\ / Mail to         tf.airane@gmail.com
/ \ Twitter         @toufikairane
\ /
/ \ Source file     ps.c
\ / Language        C
/ \ Brief           Simple report process status in cmdline interface
\ /
/ \ Licence         Cette oeuvre est totalement libre de droit.
\ /                 Je vous encourage à la partager et/ou la modifier.
/ \                 Son utilisation engage votre entière responsabilité.
\*/

    #include <stdio.h>
    #include <stdlib.h>
    #include <windows.h>
    #include <TlHelp32.h>
    #define C_EOL "\n"
	
    int main(int argc, char *argv[])
    {
        PROCESSENTRY32 ProcessEntry={0};
        ProcessEntry.dwSize=sizeof(PROCESSENTRY32);
        HANDLE Snapshot32Process = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);

        if(Snapshot32Process==INVALID_HANDLE_VALUE)
            exit(EXIT_FAILURE);

        if(!Process32First(Snapshot32Process, &ProcessEntry)) {
                CloseHandle(Snapshot32Process);
                exit(EXIT_FAILURE);
        }

        printf("%8s %6c %8s %64s"C_EOL C_EOL, "PPID", '-', "PID", "Process Name");
        while (Process32Next(Snapshot32Process, &ProcessEntry)) {
                printf("%8s %6c %8s %64s"C_EOL, ProcessEntry.th32ParentProcessID, '-', ProcessEntry.th32ProcessID, ProcessEntry.szExeFile);
        }

        CloseHandle(Snapshot32Process);
        return 0;
    }
