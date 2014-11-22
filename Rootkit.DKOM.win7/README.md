```
               _   _   _ _
  _ _ ___  ___| |_| |_(_) |_
 | '_/ _ \/ _ \  _| / / |  _|
 |_| \___/\___/\__|_\_\_|\__|DKOM

 Direct Kernel Object Manipulationon on EPROCESS opaque struct
 Toufik Airane @tfairane
```
> don't forget to :
  * sign driver
  * compile in 64 bits mode

Tested on : win7sp1
```
lkd> lm v m nt
start             end                 module name
fffff800`02e4d000 fffff800`03432000   nt         (export symbols)       ntkrnlmp.exe
    Loaded symbol image file: ntkrnlmp.exe
    Image path: ntkrnlmp.exe
    Image name: ntkrnlmp.exe
    Timestamp:        Tue Mar 04 09:38:19 2014 (531590FB)
    CheckSum:         00554C03
    ImageSize:        005E5000
    File version:     6.1.7601.18409
    Product version:  6.1.7601.18409
    File flags:       0 (Mask 3F)
    File OS:          40004 NT Win32
    File type:        1.0 App
    File date:        00000000.00000000
    Translations:     0409.04b0
    CompanyName:      Microsoft Corporation
    ProductName:      Microsoft® Windows® Operating System
    InternalName:     ntkrnlmp.exe
    OriginalFilename: ntkrnlmp.exe
    ProductVersion:   6.1.7601.18409
    FileVersion:      6.1.7601.18409 (win7sp1_gdr.140303-2144)
    FileDescription:  NT Kernel & System
    LegalCopyright:   © Microsoft Corporation. All rights reserved.
```

![Alt text](/Rootkit.DKOM.win7/rootkitban.png?raw=true)
![Alt text](/Rootkit.DKOM.win7/rootkit1.png?raw=true)
![Alt text](/Rootkit.DKOM.win7/rootkit2.png?raw=true)
![Alt text](/Rootkit.DKOM.win7/rootkitban.png?raw=true)