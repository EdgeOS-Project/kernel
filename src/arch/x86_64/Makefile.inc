# x86-64 mechanisms only. Linux-visible subsystem policy belongs in common code.
X86_ARCH_SRCS := \
	$(SRC)/arch/x86_64/kernel/gdt.c \
	$(SRC)/arch/x86_64/kernel/idt.c \
	$(SRC)/arch/x86_64/kernel/isr.c \
	$(SRC)/arch/x86_64/kernel/pic.c \
	$(SRC)/arch/x86_64/kernel/io_ports.c \
	$(SRC)/arch/x86_64/kernel/cache.c \
	$(SRC)/arch/x86_64/kernel/syscall.c \
	$(SRC)/arch/x86_64/kernel/runtime.c \
	$(SRC)/arch/x86_64/kernel/smp.c

ifeq ($(CONFIG_INITRAMFS),y)
X86_ARCH_SRCS += $(SRC)/arch/x86_64/boot/initramfs_multiboot.c
endif

X86_ARCH_ASM_SRCS := $(shell find $(SRC)/arch/x86_64 -name '*.asm')
