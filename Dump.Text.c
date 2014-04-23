#include<stdio.h>
#include<windows.h>
#include<MapPE/MapPE.h>

int main() {
    HANDLE PE = MapPE_open("foo.exe");
    PIMAGE_DOS_HEADER DOS = MapPE_DOS(PE);
    PIMAGE_NT_HEADERS NT = MapPE_NT(PE);
    PIMAGE_SECTION_HEADER SECTION = MapPE_SECTIONS(PE);

    printf("Dump of : %s ", SECTION->Name);
    int i; for(i=0; i < RVAtoOFFSET(PE,SECTION->Misc.VirtualSize); i++)
    printf("\\x%x", *((BYTE*)PE + RVAtoOFFSET(PE, SECTION->VirtualAddress) + i));

    return 0;
}
