#include<stdio.h>
#include<windows.h>
#include<MapPE.h>

int main(int argc, char* argv[]) {
    HANDLE PE = MapPE_open(argv[1]);
    PIMAGE_DOS_HEADER DOS = MapPE_DOS(PE);
    PIMAGE_NT_HEADERS NT = MapPE_NT(PE);
    PIMAGE_SECTION_HEADER SECTION = NULL;

    int i; for(i=0; i < MapPE_NT(PE)->FileHeader.NumberOfSections; i++)
    if(!strcmp(MapPE_SECTIONS(PE, i)->Name, argv[2]))
        SECTION = MapPE_SECTIONS(PE, i);

    if(!SECTION)
        exit(EXIT_FAILURE);

    printf("Dump of : %s ", SECTION->Name);
    for(i=0; i < RVAtoOFFSET(PE, SECTION->Misc.VirtualSize); i++)
    printf("\\x%02x", *(BYTE*)(PE + RVAtoOFFSET(PE, SECTION->VirtualAddress) + i));

    return 0;
}
