# ARM64 mechanisms. Linux-visible subsystem policy comes from Makefile.common.
include $(SRC)/Makefile.common

ARM64_UEFI_SRCS = \
	$(SRC)/arch/arm64/boot/uefi.c \
	$(SRC)/arch/arm64/boot/kernel_entry.c \
	$(SRC)/arch/arm64/mm/mmu.c \
	$(SRC)/arch/arm64/mm/address_space.c \
	$(SRC)/arch/arm64/entry/syscall.c \
	$(SRC)/arch/arm64/entry/signal.c \
	$(SRC)/arch/arm64/entry/runtime.c \
	$(SRC)/arch/arm64/mm/elf_vm.c \
	$(SRC)/arch/arm64/entry/user_enter.S \
	$(SRC)/arch/arm64/compiler_runtime.c \
	$(SRC)/arch/arm64/kernel/interrupt.c \
	$(SRC)/arch/arm64/kernel/platform.c \
	$(SRC)/arch/arm64/kernel/smp.c \
	$(SRC)/arch/arm64/kernel/console_input.c \
	$(SRC)/arch/arm64/kernel/runtime.c \
	$(SRC)/arch/arm64/kernel/bootstrap_runtime.c \
	$(SRC)/arch/arm64/kernel/time.c \
	$(SRC)/arch/arm64/entry/context.c \
	$(SRC)/arch/arm64/entry/exceptions.S \
	$(SRC)/arch/arm64/entry/switch.S \
	$(SRC)/arch/arm64/entry/entry.S \
	$(EDGE_RUNTIME_SRCS)
