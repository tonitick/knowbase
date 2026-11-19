# Kbuild part: read by the kernel build system (KERNELRELEASE is set there)
ifneq ($(KERNELRELEASE),)
obj-m := toygpu.o
ifeq ($(VULN),1)
ccflags-y += -DTOYGPU_VULNERABLE
endif

else
# Normal make invocation
KDIR ?= /lib/modules/$(shell uname -r)/build

all: module toygpu_test

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

# sparse static analysis (needs the 'sparse' package): checks __user / __iomem misuse
check:
	$(MAKE) -C $(KDIR) M=$(CURDIR) C=2 modules

toygpu_test: toygpu_test.c toygpu_uapi.h
	$(CC) -O2 -Wall -Wextra -pthread -o $@ toygpu_test.c

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -f toygpu_test

.PHONY: all module check clean
endif
