/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane.github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | addsectionPE.c
\ / Language        | C
/ \ Brief           | Add Section into PE Format MS Windows
\ /
/ \ Licence         | Ce code est totalement libre.
\ /                 | Je vous encourage à le partager et/ou le modifier.
/ \                 | L'usage de ce programme relève de votre entière responsabilité.
\*/

    #include<stdio.h>
    #include <windows.h>
    #define C_EOL "\n"

    DWORD alignment(DWORD base, DWORD address);
    int main(int argc, char *argv[])
    {
        if(argc!=2)
            exit(EXIT_FAILURE);

        HANDLE hFile = CreateFile( argv[1],
                                   GENERIC_WRITE|GENERIC_READ,
                                   FILE_SHARE_WRITE|FILE_SHARE_READ,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL,
                                   NULL );

        if(hFile == INVALID_HANDLE_VALUE)
            exit(EXIT_FAILURE);

        char pattern = 0x90;//PATTERN
        char shellcode[] = "\xE9";//JMP
        DWORD sizeofshellcode = strlen(shellcode) * sizeof(char);

        DWORD dwTaille = 0;
        IMAGE_DOS_HEADER hDOS;
        IMAGE_NT_HEADERS hNT;
        IMAGE_SECTION_HEADER hSection;
        IMAGE_SECTION_HEADER ownSection;

        SetFilePointer(hFile, 0, 0, FILE_BEGIN);
        ReadFile(hFile, &hDOS, sizeof(IMAGE_DOS_HEADER), &dwTaille, NULL);// DOS HEADER
        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        ReadFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);// NT HEADER

        int i;
        for(i=0; i < hNT.FileHeader.NumberOfSections; i++)
            ReadFile(hFile, &hSection, sizeof(IMAGE_SECTION_HEADER), &dwTaille, NULL);

        ownSection = hSection;

        memcpy(ownSection.Name, "FOOBAR", 8);
        ownSection.Misc.VirtualSize = alignment(hNT.OptionalHeader.SectionAlignment, sizeofshellcode);
        ownSection.VirtualAddress = alignment(hNT.OptionalHeader.SectionAlignment, hSection.VirtualAddress + hSection.Misc.VirtualSize);;
        ownSection.SizeOfRawData = alignment(hNT.OptionalHeader.FileAlignment, sizeofshellcode);
        ownSection.PointerToRawData = alignment(hNT.OptionalHeader.FileAlignment, hSection.PointerToRawData + hSection.SizeOfRawData);
        ownSection.Characteristics = IMAGE_SCN_MEM_WRITE + IMAGE_SCN_MEM_READ + IMAGE_SCN_MEM_EXECUTE + IMAGE_SCN_MEM_SHARED + IMAGE_SCN_CNT_CODE;
        ownSection.Misc.PhysicalAddress;
        ownSection.PointerToRelocations = 0x0;
        ownSection.PointerToLinenumbers = 0x0;
        ownSection.NumberOfRelocations = 0x0;
        ownSection.NumberOfLinenumbers = 0x0;
        WriteFile(hFile, &ownSection, sizeof(IMAGE_SECTION_HEADER), &dwTaille, NULL);//ADD SECTION HEADER

        SetFilePointer(hFile, ownSection.PointerToRawData, 0, FILE_BEGIN);
        WriteFile(hFile, &shellcode, sizeofshellcode, &dwTaille, NULL);//WRITE SHELLCODE

        for(i=0; i<hNT.OptionalHeader.FileAlignment-sizeofshellcode; i++)
        WriteFile(hFile, &pattern, sizeof(char), &dwTaille, NULL);//PATTERN

        hNT.FileHeader.NumberOfSections++;
        hNT.OptionalHeader.SizeOfImage += hNT.OptionalHeader.FileAlignment;
        hNT.OptionalHeader.AddressOfEntryPoint = ownSection.VirtualAddress;//PATCH ADDR OF ENTRYPOINT
        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        WriteFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);//PATCH NT HEADER

        CloseHandle(hFile);
        return 0;
    }

    DWORD alignment(DWORD base, DWORD address) {
    return (address % base == 0) ? address : (((address / base) + 1) * base);
    }
