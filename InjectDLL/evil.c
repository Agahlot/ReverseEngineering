/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane.github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | evil.c ~ compile to evil.dll
\ / Language        | C
/ \ Brief           | poc evil dll can be injected in process
\ /
/ \ Licence         | Ce code est totalement libre de droit.
\ /      			| Je vous encourage à le partager et/ou le modifier.
/ \    				| Son utilisation engage votre entière responsabilité.
\*/

    #include <windows.h>
    #include <stdio.h>

    extern "C" void __declspec(dllexport) evil(void)
    {
        char name[128], buffer[164];
        int pid = GetCurrentProcessId();
        GetModuleFileName(NULL, name, 127);
        sprintf(buffer, "PID : %d\nName : %s", pid, name);
        MessageBoxA(0, buffer, "EVIL DLL", MB_OK);
    }

    extern "C" __declspec(dllexport) BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
    {
        if(fdwReason == DLL_PROCESS_ATTACH)
            evil();

        return TRUE;
    }
