#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/syscalls.h>
#include<linux/string.h>

#define DISABLE_WRITE_PROTECTION (write_cr0(read_cr0() & (~ 0x10000)))
#define ACTIVE_WRITE_PROTECTION (write_cr0(read_cr0() | 0x10000))

static unsigned long **find_sys_call_table(void);
static unsigned long **find_sys_call_table() {
    unsigned long offset;
    unsigned long **iter;
    printk("sys_call_table addr : ");
    for(offset=PAGE_OFFSET; offset < 0xD0000000; offset += sizeof(void*)) {
        iter = (unsigned long**) offset;
        if(iter[__NR_close] == (unsigned long *) sys_close) {
            printk("%08x\n", iter);
            return iter;
        }
    }
    return NULL;
}

static int __init __init__hook(void) {
    find_sys_call_table();
    return 0;
}

static void __exit __cleanup__hook(void) {
    printk("good bye\n");
}

module_init(__init__hook);
module_exit(__cleanup__hook);
