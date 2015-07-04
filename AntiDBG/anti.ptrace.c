#define _GNU_SOURCE
/*
 * usage : gdb -x anti.ptrace ./bin
 * shell gcc -Wall -fPIC -shared -o anti.ptrace.so anti.ptrace.c -ldl
 * set environment LD_PRELOAD=./anti.ptrace.so
 */
#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>

typedef long (*orig_ptrace_f_type)(void* request, pid_t pid, void *addr, void *data);

long ptrace(void* request, pid_t pid, void *addr, void *data)
{
    if((((unsigned int)request) == 0) && (((unsigned int)pid) == 0) && (((unsigned int)addr) == 1) && (((unsigned int)0) == 0))
    {
        return 0;
    }
    else
    {
        orig_ptrace_f_type orig_ptrace;
        orig_ptrace = (orig_ptrace_f_type)dlsym(RTLD_NEXT,"ptrace");
        return orig_ptrace(request, pid, addr, data);
    }
}
