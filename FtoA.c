//**//**//**//**|---------------------------------------------------------------------------
//	Author  // From     :	Toufik Airane // Paris
//	GitHub              :	toufikairane@github.io
//	Mail to 	        :	tf.airane@gmail.com
//* * * * * * * * * * * |
//	Source file         :	FtoA.c
//	Brief		        :	Convert Function Name to Offset Address from DLL
//	Language	        :	C
//  Compilation option  :   no
//* * * * * * * * * * * |
//	Licence		        :	Cette oeuvre est totalement libre de droit.
//	*******		        |	Je vous encourage à la partager et/ou la modifier.
//	*******		        |	En revanche son utilisation engage votre entière responsabilité.
//**//**//**//**|---------------------------------------------------------------------------

    #include<stdio.h>
    #include<stdlib.h>
    #include<windows.h>

    int main(int argc, char *argv[]) {
        if(argc!=3) {
                printf("[#] %s <DLL> <FUNCTION>", argv[0]);
                return 1;
    }

        HMODULE hDll;
        hDll = LoadLibrary(argv[1]);
        if(!hDll) {
                printf("[#] LoadLibrary : Error");
                return 1;
        }

        FARPROC hFunc;
        hFunc = GetProcAddress(hDll, argv[2]);
        if(!hFunc) {
                printf("[#] GetProcAddress : Error");
                FreeLibrary(hDll);
                return 1;
        }

        printf("[#]\t%s\t0x%08x",argv[2], hFunc);
        FreeLibrary(hDll);
        return 0;
    }
