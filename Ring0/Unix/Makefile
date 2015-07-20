obj-m		:= rootkit.o

KBUILD_DIR	:= /lib/modules/$(shell uname -r)/build

default:s
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd)
clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean