#! /bin/bash
nasm -f elf64 $1.nasm -o $1.o
ld $1.o -o $1
./$1