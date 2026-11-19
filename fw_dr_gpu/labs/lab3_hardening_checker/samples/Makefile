# Builds sample artifacts with good and bad hardening so the checker has something to find.
CC ?= gcc

HARDENED_CFLAGS  := -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection \
                    -fcf-protection=full -fPIE
HARDENED_LDFLAGS := -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# Everything turned off explicitly (distro compilers enable much of this by default).
WEAK_CFLAGS  := -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector -fcf-protection=none -fno-pie
WEAK_LDFLAGS := -no-pie -Wl,-z,norelro -Wl,-z,lazy -Wl,-z,execstack -Wl,-rpath,./plugins

ARCH := $(shell uname -m)
TARGETS := build/demo_hardened build/demo_weak build/libdemo.so
ifeq ($(ARCH),x86_64)
TARGETS += build/demo_asm build/legacy_asm.o
endif

all: $(TARGETS)

build:
	mkdir -p build

build/demo_hardened: demo.c | build
	$(CC) $(HARDENED_CFLAGS) $< -o $@ $(HARDENED_LDFLAGS)

build/demo_weak: demo.c | build
	$(CC) $(WEAK_CFLAGS) $< -o $@ $(WEAK_LDFLAGS)

# Hardened flags, but one unmarked assembly file and no explicit -z noexecstack.
build/demo_asm: demo.c legacy_asm.S | build
	$(CC) $(HARDENED_CFLAGS) -DUSE_ASM demo.c legacy_asm.S -o $@ -pie -Wl,-z,relro -Wl,-z,now

build/legacy_asm.o: legacy_asm.S | build
	$(CC) -c $< -o $@

build/libdemo.so: libdemo.c | build
	$(CC) -O2 -fPIC -shared $< -o $@ -Wl,-z,relro -Wl,-z,lazy -Wl,-rpath,'$$ORIGIN/../lib:plugins'

clean:
	rm -rf build

.PHONY: all clean
