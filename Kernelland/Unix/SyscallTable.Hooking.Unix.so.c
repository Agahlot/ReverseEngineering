#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>

MODULE_LICENSE("F****** FREE");
MODULE_AUTHOR("Toufik Airane");
MODULE_DESCRIPTION("sys_call_table Hooking");

/*
 * Voodoo shit !
 */ 
#define DISABLE_WRITE_PROTECTION (write_cr0(read_cr0() & (~ 0x10000)))
#define ENABLE_WRITE_PROTECTION (write_cr0(read_cr0() | 0x10000))

static unsigned long **find_sys_call_table(void);
asmlinkage ssize_t hook_sys_read(int, void*, size_t);
asmlinkage ssize_t (*original_sys_read)(int, void*, size_t);
asmlinkage unsigned long **sys_call_table;

static int __init _init(void) {
    /*
     * find sys_call_table
     */
    sys_call_table = find_sys_call_table();
    if(!sys_call_table) {
	printk(KERN_ERR "Couldn't find sys_call_table.\n");
	return -EPERM;
    }

    DISABLE_WRITE_PROTECTION;
    /*
     * save orig sys_read
     */
    original_sys_read = (void *) sys_call_table[__NR_read];
    /*
     * hook sys_read
     */
    sys_call_table[__NR_read] = (unsigned long *) hook_sys_read;
    ENABLE_WRITE_PROTECTION;
    return 0;
}

asmlinkage ssize_t hook_sys_read(int fd, void* buf, size_t count) {
    return (*original_sys_read)(fd, buf, count);
}

static void __exit _cleanup(void) {
    printk(KERN_INFO "bye bye from baby hook\n");

    DISABLE_WRITE_PROTECTION;
    sys_call_table[__NR_read] = (unsigned long *) original_sys_read;
    ENABLE_WRITE_PROTECTION;
}

static unsigned long **find_sys_call_table() {
    unsigned long offset;
    unsigned long **sct;

    for(offset = PAGE_OFFSET; offset < 0xD0000000; offset += sizeof(void *)) {
	sct = (unsigned long **) offset;

	if(sct[__NR_close] == (unsigned long *) sys_close)
	    return sct;
    }

    return NULL;
}

module_init(_init);
module_exit(_cleanup);
