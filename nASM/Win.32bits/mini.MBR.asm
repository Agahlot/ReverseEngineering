[BITS 16]    ;16 bit code generation
[ORG 0x7C00] ;Origin location

mov ah, 0x05 ;Select active display page
mov al, 0x01 ;Page Number
int 0x10

msg db 'READY FOR BOOTING ...'
mov bp, msg  ;Message
mov al, 0x01 ;Write mode
mov bh, 0x01 ;Page Number
mov bl, 0x04 ;Color
mov cx, 0x15 ;String length
mov dh, 0x00 ;Row
mov dl, 0x00 ;Column
mov ah, 0x13 ;Write string
int 0x10

jmp $
times 510-($-$$) db 0 ;520 KB
dw 0xAA55 ;Magic Boot