/*\
\ / Author ~ From   | Toufik Airane ~ Paris
/ \ GitHub          | tfairane.github.com
\ / Mail            | tf.airane@gmail.com
/ \ Twitter         | @tfairane
\ /
/ \ File            | PEDump.c
\ / Language        | C
/ \ Brief           | Analyse PE File Header && IAT dump
\ /
/ \ Licence         | Ce code est totalement libre de droit.
\ /                 | Je vous encourage à le partager et/ou le modifier.
/ \                 | Son utilisation engage votre entière responsabilité.
\*/

    #include <stdio.h>
    #include <stdlib.h>
    #include <windows.h>
    #define C_EOL "\n"
    #define printx(x,y) printf("%s : 0x%08x" C_EOL , x, y);
    #define print_dd(x,y) printf("%s : %08x" C_EOL , x, y);

    #define print_title(x) printf( C_EOL C_EOL "*** %s ***" C_EOL C_EOL , x);
    #define print_subtitle(x,y) printf( C_EOL "[+] %s : %s" C_EOL , x, y);

    #define NOTICE "PEDump ~ follow @tfairane" C_EOL\
    "Usage: %s [File]"

    DWORD RVAtoOFFSET(HANDLE hFileMap, const DWORD RVA);

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

        HANDLE hFileMapping = CreateFileMapping( hFile,
                                             NULL,
                                             PAGE_READWRITE,
                                             0,
                                             0,
                                             0 );

        HANDLE hFileMap = MapViewOfFile( hFileMapping,
                                         FILE_MAP_ALL_ACCESS,
                                         0,
                                         0,
                                         0 );

        PIMAGE_DOS_HEADER hDOS;
        PIMAGE_NT_HEADERS hNT;
        PIMAGE_SECTION_HEADER hSection;
        PIMAGE_IMPORT_DESCRIPTOR hEntryImport;
        PIMAGE_THUNK_DATA hOriginalFirstThunk;
        PIMAGE_THUNK_DATA hFirstThunk;
        PIMAGE_IMPORT_BY_NAME API;

        hDOS = (PIMAGE_DOS_HEADER)hFileMap;// DOS HEADER
        hNT = (PIMAGE_NT_HEADERS)(hFileMap + hDOS->e_lfanew);// NT HEADER

        print_title("IMAGE_DOS_HEADER");
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
        printx("e_magic",    hDOS->e_magic);//#define IMAGE_DOS_SIGNATURE 0x5A4D
        printx("e_cblp",     hDOS->e_cblp);
        printx("e_cp",       hDOS->e_cp);
        printx("e_crlc",     hDOS->e_crlc);
        printx("e_cparhdr",  hDOS->e_cparhdr);
        printx("e_minalloc", hDOS->e_minalloc);
        printx("e_maxalloc", hDOS->e_maxalloc);
        printx("e_ss",       hDOS->e_ss);
        printx("e_sp",       hDOS->e_sp);
        printx("e_csum",     hDOS->e_csum);
        printx("e_ip",       hDOS->e_ip);
        printx("e_cs",       hDOS->e_cs);
        printx("e_lfarlc",   hDOS->e_lfarlc);
        printx("e_ovno",     hDOS->e_ovno);
        printx("e_res",      hDOS->e_res);
        printx("e_oemid",    hDOS->e_oemid);
        printx("e_oeminfo",  hDOS->e_oeminfo);
        printx("e_res2",     hDOS->e_res2);
        printx("e_lfanew",   hDOS->e_lfanew);

        print_title("IMAGE_NT_HEADERS");
        /*/
        typedef struct _IMAGE_NT_HEADERS {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32,*PIMAGE_NT_HEADERS32;
        /*/
        printx("Signature",  hNT->Signature);//#define IMAGE_NT_SIGNATURE 0x00004550

        print_title("IMAGE_FILE_HEADER");
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
        printx("Machine",                hNT->FileHeader.Machine);
        printx("NumberOfSections",       hNT->FileHeader.NumberOfSections);
        printx("TimeDateStamp",          hNT->FileHeader.TimeDateStamp);
        printx("PointerToSymbolTable",   hNT->FileHeader.PointerToSymbolTable);
        printx("NumberOfSymbols",        hNT->FileHeader.NumberOfSymbols);
        printx("SizeOfOptionalHeader",   hNT->FileHeader.SizeOfOptionalHeader);
        printx("Characteristics",        hNT->FileHeader.Characteristics);

        print_title("IMAGE_OPTIONAL_HEADER");
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
        printx("Magic",                       hNT->OptionalHeader.Magic);
        printx("MajorLinkerVersion",          hNT->OptionalHeader.MajorLinkerVersion);
        printx("MinorLinkerVersion",          hNT->OptionalHeader.MinorLinkerVersion);
        printx("SizeOfCode",                  hNT->OptionalHeader.SizeOfCode);
        printx("SizeOfInitializedData",       hNT->OptionalHeader.SizeOfInitializedData);
        printx("SizeOfUninitializedData",     hNT->OptionalHeader.SizeOfUninitializedData);
        printx("AddressOfEntryPoint",         hNT->OptionalHeader.AddressOfEntryPoint);
        printx("BaseOfCode",                  hNT->OptionalHeader.BaseOfCode);
        printx("BaseOfData",                  hNT->OptionalHeader.BaseOfData);
        printx("ImageBase",                   hNT->OptionalHeader.ImageBase);
        printx("SectionAlignment",            hNT->OptionalHeader.SectionAlignment);
        printx("FileAlignment",               hNT->OptionalHeader.FileAlignment);
        printx("MajorOperatingSystemVersion", hNT->OptionalHeader.MajorOperatingSystemVersion);
        printx("MinorOperatingSystemVersion", hNT->OptionalHeader.MinorOperatingSystemVersion);
        printx("MajorImageVersion",           hNT->OptionalHeader.MajorImageVersion);
        printx("MinorImageVersion",           hNT->OptionalHeader.MinorImageVersion);
        printx("MajorSubsystemVersion",       hNT->OptionalHeader.MajorSubsystemVersion);
        printx("MinorSubsystemVersion",       hNT->OptionalHeader.MinorSubsystemVersion);
        printx("Win32VersionValue",           hNT->OptionalHeader.Win32VersionValue);
        printx("SizeOfImage",                 hNT->OptionalHeader.SizeOfImage);
        printx("SizeOfHeaders",               hNT->OptionalHeader.SizeOfHeaders);
        printx("CheckSum",                    hNT->OptionalHeader.CheckSum);
        printx("Subsystem",                   hNT->OptionalHeader.Subsystem);
        printx("DllCharacteristics",          hNT->OptionalHeader.DllCharacteristics);
        printx("SizeOfStackReserve",          hNT->OptionalHeader.SizeOfStackReserve);
        printx("SizeOfStackCommit",           hNT->OptionalHeader.SizeOfStackCommit);
        printx("SizeOfHeapReserve",           hNT->OptionalHeader.SizeOfHeapReserve);
        printx("SizeOfHeapCommit",            hNT->OptionalHeader.SizeOfHeapCommit);
        printx("LoaderFlags",                 hNT->OptionalHeader.LoaderFlags);
        printx("NumberOfRvaAndSizes",         hNT->OptionalHeader.NumberOfRvaAndSizes);

        print_title("DataDirectory");
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
        print_dd("[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_EXPORT].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_IMPORT].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_SECURITY].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_DEBUG].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COPYRIGHT].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_TLS].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_IAT].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
        print_dd("[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
        print_dd("[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size", hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);

        print_title("IMAGE_SECTION_HEADER");
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
        int i;
        for(i=0; i < hNT->FileHeader.NumberOfSections; i++) {
            hSection = (PIMAGE_SECTION_HEADER) (hFileMap + hDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i*sizeof(IMAGE_SECTION_HEADER));// SECTION HEADER
            print_subtitle("Name",          hSection->Name);
            printx("Misc.PhysicalAddress",  hSection->Misc.PhysicalAddress);
            printx("Misc.VirtualSize",      hSection->Misc.VirtualSize);
            printx("VirtualAddress",        hSection->VirtualAddress);
            printx("SizeOfRawData",         hSection->SizeOfRawData);
            printx("PointerToRawData",      hSection->PointerToRawData);
            printx("PointerToRelocations",  hSection->PointerToRelocations);
            printx("PointerToLinenumbers",  hSection->PointerToLinenumbers);
            printx("NumberOfRelocations",   hSection->NumberOfRelocations);
            printx("NumberOfLinenumbers",   hSection->NumberOfLinenumbers);
            printx("Characteristics",       hSection->Characteristics);
        }

        print_title("IMAGE_DIRECTORY_ENTRY_IMPORT");
        DWORD EntryExportVA = hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD EntryExportSize = hNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
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
        hEntryImport = (PIMAGE_IMPORT_DESCRIPTOR)(hFileMap + RVAtoOFFSET(hFileMap, EntryExportVA));//IMAGE_DIRECTORY_ENTRY_IMPORT

        while(hEntryImport->FirstThunk) {
        print_subtitle("Name",          hFileMap + RVAtoOFFSET(hFileMap, hEntryImport->Name));
        printx("OriginalFirstThunk",    hEntryImport->OriginalFirstThunk);
        printx("FirstThunk",            hEntryImport->FirstThunk);
        printx("Characteristics",       hEntryImport->Characteristics);
        printx("TimeDateStamp",         hEntryImport->TimeDateStamp);
        printx("ForwarderChain",        hEntryImport->ForwarderChain);
        /*/
        typedef struct _IMAGE_THUNK_DATA {
        union {
            DWORD ForwarderString;
            DWORD Function;
            DWORD Ordinal;
            DWORD AddressOfData;
        } u1;
    } IMAGE_THUNK_DATA,*PIMAGE_THUNK_DATA;
        /*/
        hOriginalFirstThunk = (PIMAGE_THUNK_DATA)(hFileMap + RVAtoOFFSET(hFileMap, hEntryImport->OriginalFirstThunk));
        hFirstThunk = (PIMAGE_THUNK_DATA)(hFileMap + RVAtoOFFSET(hFileMap, hEntryImport->FirstThunk));
            while(hOriginalFirstThunk->u1.AddressOfData)
            {
            /*/
            typedef struct _IMAGE_IMPORT_BY_NAME {
            WORD Hint;
            BYTE Name[1];
        } IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;
            /*/
            API = (PIMAGE_IMPORT_BY_NAME)(hFileMap + RVAtoOFFSET(hFileMap, hOriginalFirstThunk->u1.AddressOfData));
            print_subtitle("Name", API->Name);
            printx("Hint", API->Hint);
            printx("Function", hOriginalFirstThunk->u1.Function);
            hOriginalFirstThunk++;
            hFirstThunk++;
            }
        hEntryImport++;
        }
        UnmapViewOfFile(hFileMap);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);

        return 0;
    }

DWORD RVAtoOFFSET(HANDLE hFileMap, const DWORD RVA) {
        PIMAGE_DOS_HEADER hDOS = (PIMAGE_DOS_HEADER)hFileMap;
        PIMAGE_NT_HEADERS hNT = (PIMAGE_NT_HEADERS)(hFileMap + hDOS->e_lfanew);
        PIMAGE_SECTION_HEADER hSection = (PIMAGE_SECTION_HEADER)(hFileMap + hDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS));
        int i;
        for(i=0; i < hNT->FileHeader.NumberOfSections && (hSection->VirtualAddress + hSection->Misc.VirtualSize) <= RVA; i++, hSection++);
        return RVA - hSection->VirtualAddress + hSection->PointerToRawData;
}
