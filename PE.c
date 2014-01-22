/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane@github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | PE.c
\ / Language        | C
/ \ Brief           | PE HEADERS DUMP
\ /
/ \ Licence         | Ce code est totalement libre de droit.
\ /                 | Je vous encourage à le partager et/ou le modifier.
/ \                 | Son utilisation engage votre entière responsabilité.
\*/

    #include <stdio.h>
    #include <stdlib.h>
    #include <windows.h>
    #define C_EOL "\n"
    #define print(x,y) printf("%32s : 0x%08x\n", x, y);
    #define printv0(x) printf("\n\n%50s\n\n", x);
    #define printv1(x,y) printf("\n%32s : %s\n", x, y);
    #define printv2(x,y) printf("%-64s : 0x%08x\n", x, y);
    #define NOTICE "PE HEADERS DUMP 1.1 ( follow @tfairane )\n"\
                    "Usage: %s [File]"

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
    #define IMAGE_DIRECTORY_ENTRY_EXPORT            0
    #define IMAGE_DIRECTORY_ENTRY_IMPORT            1
    #define IMAGE_DIRECTORY_ENTRY_RESOURCE          2
    #define IMAGE_DIRECTORY_ENTRY_EXCEPTION         3
    #define IMAGE_DIRECTORY_ENTRY_SECURITY          4
    #define IMAGE_DIRECTORY_ENTRY_BASERELOC         5
    #define IMAGE_DIRECTORY_ENTRY_DEBUG             6
    #define IMAGE_DIRECTORY_ENTRY_COPYRIGHT         7
    #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      7
    #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR         8
    #define IMAGE_DIRECTORY_ENTRY_TLS               9
    #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10
    #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11
    #define IMAGE_DIRECTORY_ENTRY_IAT               12
    #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13
    #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14
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

    /*/
    typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	_ANONYMOUS_UNION union {
		DWORD Characteristics;
		DWORD OriginalFirstThunk;
	} DUMMYUNIONNAME;
	DWORD TimeDateStamp;
	DWORD ForwarderChain;
	DWORD Name;
	DWORD FirstThunk;
    } IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;
    /*/

    int main(int argc, char *argv[])
    {
        if(argc!=2) {
            printf(NOTICE, argv[0]);
            exit(EXIT_FAILURE);
        }

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
        IMAGE_IMPORT_DESCRIPTOR hEntryImport;
        IMAGE_THUNK_DATA hOriginalFirstThunk;
        IMAGE_THUNK_DATA hFirstThunk;
        IMAGE_IMPORT_BY_NAME API;

        SetFilePointer(hFile, 0, 0, FILE_BEGIN);
        ReadFile(hFile, &hDOS, sizeof(IMAGE_DOS_HEADER), &dwTaille, NULL);// DOS HEADER
        SetFilePointer(hFile, hDOS.e_lfanew, 0, FILE_BEGIN);
        ReadFile(hFile, &hNT, sizeof(IMAGE_NT_HEADERS), &dwTaille, NULL);// NT HEADER

        printv0("** IMAGE_DOS_HEADER **");
        print("e_magic",    hDOS.e_magic);//#define IMAGE_DOS_SIGNATURE 0x5A4D
        print("e_cblp",     hDOS.e_cblp);
        print("e_cp",       hDOS.e_cp);
        print("e_crlc",     hDOS.e_crlc);
        print("e_cparhdr",  hDOS.e_cparhdr);
        print("e_minalloc", hDOS.e_minalloc);
        print("e_maxalloc", hDOS.e_maxalloc);
        print("e_ss",       hDOS.e_ss);
        print("e_sp",       hDOS.e_sp);
        print("e_csum",     hDOS.e_csum);
        print("e_ip",       hDOS.e_ip);
        print("e_cs",       hDOS.e_cs);
        print("e_lfarlc",   hDOS.e_lfarlc);
        print("e_ovno",     hDOS.e_ovno);
        print("e_res",      hDOS.e_res);
        print("e_oemid",    hDOS.e_oemid);
        print("e_oeminfo",  hDOS.e_oeminfo);
        print("e_res2",     hDOS.e_res2);
        print("e_lfanew",   hDOS.e_lfanew);

        printv0("** IMAGE_NT_HEADERS **");
        print("Signature",  hNT.Signature);//#define IMAGE_NT_SIGNATURE 0x00004550

        printv0("** IMAGE_FILE_HEADER **");
        print("Machine",                hNT.FileHeader.Machine);
        print("NumberOfSections",       hNT.FileHeader.NumberOfSections);
        print("TimeDateStamp",          hNT.FileHeader.TimeDateStamp);
        print("PointerToSymbolTable",   hNT.FileHeader.PointerToSymbolTable);
        print("NumberOfSymbols",        hNT.FileHeader.NumberOfSymbols);
        print("SizeOfOptionalHeader",   hNT.FileHeader.SizeOfOptionalHeader);
        print("Characteristics",        hNT.FileHeader.Characteristics);

        printv0("** IMAGE_OPTIONAL_HEADER **");
        print("Magic",                       hNT.OptionalHeader.Magic);
        print("MajorLinkerVersion",          hNT.OptionalHeader.MajorLinkerVersion);
        print("MinorLinkerVersion",          hNT.OptionalHeader.MinorLinkerVersion);
        print("SizeOfCode",                  hNT.OptionalHeader.SizeOfCode);
        print("SizeOfInitializedData",       hNT.OptionalHeader.SizeOfInitializedData);
        print("SizeOfUninitializedData",     hNT.OptionalHeader.SizeOfUninitializedData);
        print("AddressOfEntryPoint",         hNT.OptionalHeader.AddressOfEntryPoint);
        print("BaseOfCode",                  hNT.OptionalHeader.BaseOfCode);
        print("BaseOfData",                  hNT.OptionalHeader.BaseOfData);
        print("ImageBase",                   hNT.OptionalHeader.ImageBase);
        print("SectionAlignment",            hNT.OptionalHeader.SectionAlignment);
        print("FileAlignment",               hNT.OptionalHeader.FileAlignment);
        print("MajorOperatingSystemVersion", hNT.OptionalHeader.MajorOperatingSystemVersion);
        print("MinorOperatingSystemVersion", hNT.OptionalHeader.MinorOperatingSystemVersion);
        print("MajorImageVersion",           hNT.OptionalHeader.MajorImageVersion);
        print("MinorImageVersion",           hNT.OptionalHeader.MinorImageVersion);
        print("MajorSubsystemVersion",       hNT.OptionalHeader.MajorSubsystemVersion);
        print("MinorSubsystemVersion",       hNT.OptionalHeader.MinorSubsystemVersion);
        print("Win32VersionValue",           hNT.OptionalHeader.Win32VersionValue);
        print("SizeOfImage",                 hNT.OptionalHeader.SizeOfImage);
        print("SizeOfHeaders",               hNT.OptionalHeader.SizeOfHeaders);
        print("CheckSum",                    hNT.OptionalHeader.CheckSum);
        print("Subsystem",                   hNT.OptionalHeader.Subsystem);
        print("DllCharacteristics",          hNT.OptionalHeader.DllCharacteristics);
        print("SizeOfStackReserve",          hNT.OptionalHeader.SizeOfStackReserve);
        print("SizeOfStackCommit",           hNT.OptionalHeader.SizeOfStackCommit);
        print("SizeOfHeapReserve",           hNT.OptionalHeader.SizeOfHeapReserve);
        print("SizeOfHeapCommit",            hNT.OptionalHeader.SizeOfHeapCommit);
        print("LoaderFlags",                 hNT.OptionalHeader.LoaderFlags);
        print("NumberOfRvaAndSizes",         hNT.OptionalHeader.NumberOfRvaAndSizes);

        printv0("** DataDirectory **");
        printv2("[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_EXPORT].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_IMPORT].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_SECURITY].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_DEBUG].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_TLS].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_IAT].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
        printv2("[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
        printv2("[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size", hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);

        DWORD EntryExportRAWOffset  =       0;
        DWORD EntryExportVA         =       hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD EntryExportSize       =       hNT.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        printv0("** IMAGE_SECTION_HEADER **");
        int i;
        for(i=0; i< hNT.FileHeader.NumberOfSections; i++) {
            ReadFile(hFile, &hSection, sizeof(IMAGE_SECTION_HEADER), &dwTaille, NULL);// SECTION HEADER
            printv1("Name",                     hSection.Name);
            print("Misc.PhysicalAddress",       hSection.Misc.PhysicalAddress);
            print("Misc.VirtualSize",           hSection.Misc.VirtualSize);
            print("VirtualAddress",             hSection.VirtualAddress);
            print("SizeOfRawData",              hSection.SizeOfRawData);
            print("PointerToRawData",           hSection.PointerToRawData);
            print("PointerToRelocations",       hSection.PointerToRelocations);
            print("PointerToLinenumbers",       hSection.PointerToLinenumbers);
            print("NumberOfRelocations",        hSection.NumberOfRelocations);
            print("NumberOfLinenumbers",        hSection.NumberOfLinenumbers);
            print("Characteristics",            hSection.Characteristics);

            if(hSection.VirtualAddress <= EntryExportVA)// SAVE IMAGE_DIRECTORY_ENTRY_IMPORT RAW OFFSET
                EntryExportRAWOffset = EntryExportVA - hSection.VirtualAddress + hSection.PointerToRawData;
        }

        SetFilePointer(hFile, EntryExportRAWOffset, 0, FILE_BEGIN);// IMAGE_DIRECTORY_ENTRY_IMPORT DUMP
        ReadFile(hFile, &hEntryImport, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwTaille, NULL);

        printv0("** IMAGE_DIRECTORY_ENTRY_IMPORT **");
        while(hEntryImport.OriginalFirstThunk) {
        print("Name",             hEntryImport.Name);
        print("OriginalFirstThunk", hEntryImport.OriginalFirstThunk);
        print("FirstThunk",         hEntryImport.FirstThunk);
        print("Characteristics",    hEntryImport.Characteristics);
        print("TimeDateStamp",      hEntryImport.TimeDateStamp);
        print("ForwarderChain",     hEntryImport.ForwarderChain);
        ReadFile(hFile, &hEntryImport, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwTaille, NULL);
        }

        CloseHandle(hFile);
        return 0;
    }
