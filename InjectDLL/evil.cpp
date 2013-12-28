/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | toufikairane@github.io
\ / Mail to         | tf.airane@gmail.com
/ \ Twitter         | @toufikairane
\ /
/ \ Source file     | evil.cpp ~ compile to evil.dll
\ / Language        | C++
/ \ Brief           | poc evil dll can be injected in process
\ /
/ \ Licence :   	| Cette oeuvre est totalement libre de droit.
\ /      			| Je vous encourage à la partager et/ou la modifier.
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
