@echo off
nasm -f win32 %1.asm
gcc %1.obj -o %1.exe
%1.exe