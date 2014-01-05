/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | toufikairane@github.io
\ / Mail to         | tf.airane@gmail.com
/ \ Twitter         | @toufikairane
\ /
/ \ Source file     | PE.c
\ / Language        | C
/ \ Brief           | PE Analyse
\ /
/ \ Licence         | Cette oeuvre est totalement libre de droit.
\ /                 | Je vous encourage à la partager et/ou la modifier.
/ \                 | Son utilisation engage votre entière responsabilité.
\*/
    #include <stdio.h>
    #include <stdlib.h>
    #include <windows.h>
    #define C_EOL "\n"
    /*/
    typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
    } IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;
    /*/

    /*/
    typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32,*PIMAGE_NT_HEADERS32;
    /*/

    /*/
    typedef struct _IMAGE_FILE_HEADER {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    /*/

    /*/
    typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;
    /*/

    /*/
    typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics;
    } IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;
    /*/

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

        DWORD dwTaille = 0;
        IMAGE_DOS_HEADER hDOS;
        IMAGE_NT_HEADERS hNT;
        IMAGE_SECTION_HEADER hSection;

        SetFilePointer(hFile, 0, 0, FILE_BEGIN);
        ReadFile(hFile, &hDOS, sizeof(IMAGE_DOS_HEADER), &dwTaille, NULL);// DOS HEADER
        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        ReadFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);// NT HEADER

        printf(C_EOL"%32s"C_EOL C_EOL, "[ IMAGE_DOS_HEADER ]");
        printf("%32s : 0x%08x"C_EOL, "e_magic",     hDOS.e_magic);//#define IMAGE_DOS_SIGNATURE 0x5A4D
        printf("%32s : 0x%08x"C_EOL, "e_cblp",      hDOS.e_cblp);
        printf("%32s : 0x%08x"C_EOL, "e_cp",        hDOS.e_cp);
        printf("%32s : 0x%08x"C_EOL, "e_crlc",      hDOS.e_crlc);
        printf("%32s : 0x%08x"C_EOL, "e_cparhdr",   hDOS.e_cparhdr);
        printf("%32s : 0x%08x"C_EOL, "e_minalloc",  hDOS.e_minalloc);
        printf("%32s : 0x%08x"C_EOL, "e_maxalloc",  hDOS.e_maxalloc);
        printf("%32s : 0x%08x"C_EOL, "e_ss",        hDOS.e_ss);
        printf("%32s : 0x%08x"C_EOL, "e_sp",        hDOS.e_sp);
        printf("%32s : 0x%08x"C_EOL, "e_csum",      hDOS.e_csum);
        printf("%32s : 0x%08x"C_EOL, "e_ip",        hDOS.e_ip);
        printf("%32s : 0x%08x"C_EOL, "e_cs",        hDOS.e_cs);
        printf("%32s : 0x%08x"C_EOL, "e_lfarlc",    hDOS.e_lfarlc);
        printf("%32s : 0x%08x"C_EOL, "e_ovno",      hDOS.e_ovno);
        printf("%32s : 0x%08x"C_EOL, "e_res",       hDOS.e_res);
        printf("%32s : 0x%08x"C_EOL, "e_oemid",     hDOS.e_oemid);
        printf("%32s : 0x%08x"C_EOL, "e_oeminfo",   hDOS.e_oeminfo);
        printf("%32s : 0x%08x"C_EOL, "e_res2",      hDOS.e_res2);
        printf("%32s : 0x%08x"C_EOL, "e_lfanew",    hDOS.e_lfanew);

        printf(C_EOL"%32s"C_EOL C_EOL, "[ IMAGE_NT_HEADERS ]");
        printf("%32s : 0x%08x"C_EOL, "Signature",   hNT.Signature);//#define IMAGE_NT_SIGNATURE 0x00004550

        printf(C_EOL"%32s"C_EOL C_EOL, "[ IMAGE_FILE_HEADER ]");
        printf("%32s : 0x%08x"C_EOL, "Machine",                 hNT.FileHeader.Machine);
        printf("%32s : 0x%08x"C_EOL, "NumberOfSections",        hNT.FileHeader.NumberOfSections);
        printf("%32s : 0x%08x"C_EOL, "TimeDateStamp",           hNT.FileHeader.TimeDateStamp);
        printf("%32s : 0x%08x"C_EOL, "PointerToSymbolTable",    hNT.FileHeader.PointerToSymbolTable);
        printf("%32s : 0x%08x"C_EOL, "NumberOfSymbols",         hNT.FileHeader.NumberOfSymbols);
        printf("%32s : 0x%08x"C_EOL, "SizeOfOptionalHeader",    hNT.FileHeader.SizeOfOptionalHeader);
        printf("%32s : 0x%08x"C_EOL, "Characteristics",         hNT.FileHeader.Characteristics);

        printf(C_EOL"%32s"C_EOL C_EOL, "[ IMAGE_OPTIONAL_HEADER ]");
        printf("%32s : 0x%08x"C_EOL, "Magic",                       hNT.OptionalHeader.Magic);
        printf("%32s : 0x%08x"C_EOL, "MajorLinkerVersion",          hNT.OptionalHeader.MajorLinkerVersion);
        printf("%32s : 0x%08x"C_EOL, "MinorLinkerVersion",          hNT.OptionalHeader.MinorLinkerVersion);
        printf("%32s : 0x%08x"C_EOL, "SizeOfCode",                  hNT.OptionalHeader.SizeOfCode);
        printf("%32s : 0x%08x"C_EOL, "SizeOfInitializedData",       hNT.OptionalHeader.SizeOfInitializedData);
        printf("%32s : 0x%08x"C_EOL, "SizeOfUninitializedData",     hNT.OptionalHeader.SizeOfUninitializedData);
        printf("%32s : 0x%08x"C_EOL, "AddressOfEntryPoint",         hNT.OptionalHeader.AddressOfEntryPoint);
        printf("%32s : 0x%08x"C_EOL, "BaseOfCode",                  hNT.OptionalHeader.BaseOfCode);
        printf("%32s : 0x%08x"C_EOL, "BaseOfData",                  hNT.OptionalHeader.BaseOfData);
        printf("%32s : 0x%08x"C_EOL, "ImageBase",                   hNT.OptionalHeader.ImageBase);
        printf("%32s : 0x%08x"C_EOL, "SectionAlignment",            hNT.OptionalHeader.SectionAlignment);
        printf("%32s : 0x%08x"C_EOL, "FileAlignment",               hNT.OptionalHeader.FileAlignment);
        printf("%32s : 0x%08x"C_EOL, "MajorOperatingSystemVersion", hNT.OptionalHeader.MajorOperatingSystemVersion);
        printf("%32s : 0x%08x"C_EOL, "MinorOperatingSystemVersion", hNT.OptionalHeader.MinorOperatingSystemVersion);
        printf("%32s : 0x%08x"C_EOL, "MajorImageVersion",           hNT.OptionalHeader.MajorImageVersion);
        printf("%32s : 0x%08x"C_EOL, "MinorImageVersion",           hNT.OptionalHeader.MinorImageVersion);
        printf("%32s : 0x%08x"C_EOL, "MajorSubsystemVersion",       hNT.OptionalHeader.MajorSubsystemVersion);
        printf("%32s : 0x%08x"C_EOL, "MinorSubsystemVersion",       hNT.OptionalHeader.MinorSubsystemVersion);
        printf("%32s : 0x%08x"C_EOL, "Win32VersionValue",           hNT.OptionalHeader.Win32VersionValue);
        printf("%32s : 0x%08x"C_EOL, "SizeOfImage",                 hNT.OptionalHeader.SizeOfImage);
        printf("%32s : 0x%08x"C_EOL, "SizeOfHeaders",               hNT.OptionalHeader.SizeOfHeaders);
        printf("%32s : 0x%08x"C_EOL, "CheckSum",                    hNT.OptionalHeader.CheckSum);
        printf("%32s : 0x%08x"C_EOL, "Subsystem",                   hNT.OptionalHeader.Subsystem);
        printf("%32s : 0x%08x"C_EOL, "DllCharacteristics",          hNT.OptionalHeader.DllCharacteristics);
        printf("%32s : 0x%08x"C_EOL, "SizeOfStackReserve",          hNT.OptionalHeader.SizeOfStackReserve);
        printf("%32s : 0x%08x"C_EOL, "SizeOfStackCommit",           hNT.OptionalHeader.SizeOfStackCommit);
        printf("%32s : 0x%08x"C_EOL, "SizeOfHeapReserve",           hNT.OptionalHeader.SizeOfHeapReserve);
        printf("%32s : 0x%08x"C_EOL, "SizeOfHeapCommit",            hNT.OptionalHeader.SizeOfHeapCommit);
        printf("%32s : 0x%08x"C_EOL, "LoaderFlags",                 hNT.OptionalHeader.LoaderFlags);
        printf("%32s : 0x%08x"C_EOL, "NumberOfRvaAndSizes",         hNT.OptionalHeader.NumberOfRvaAndSizes);

        printf(C_EOL"%32s * %d"C_EOL C_EOL, "[ IMAGE_SECTION_HEADER ]", hNT.FileHeader.NumberOfSections );
        int i;
        for(i=0; i< hNT.FileHeader.NumberOfSections; i++) {
        ReadFile(hFile, &hSection, sizeof(IMAGE_SECTION_HEADER), &dwTaille, NULL);
        printf("%32s : %s"C_EOL, "Name",                        hSection.Name);
        printf("%32s : 0x%08x"C_EOL, "VirtualAddress",          hSection.VirtualAddress);
        printf("%32s : 0x%08x"C_EOL, "SizeOfRawData",           hSection.SizeOfRawData);
        printf("%32s : 0x%08x"C_EOL, "PointerToRawData",        hSection.PointerToRawData);
        printf("%32s : 0x%08x"C_EOL, "PointerToRelocations",    hSection.PointerToRelocations);
        printf("%32s : 0x%08x"C_EOL, "PointerToLinenumbers",    hSection.PointerToLinenumbers);
        printf("%32s : 0x%08x"C_EOL, "NumberOfRelocations",     hSection.NumberOfRelocations);
        printf("%32s : 0x%08x"C_EOL, "NumberOfLinenumbers",     hSection.NumberOfLinenumbers);
        printf("%32s : 0x%08x"C_EOL C_EOL, "Characteristics",   hSection.Characteristics);
        }
        CloseHandle(hFile);
        return 0;
    }
