ASM = nasm
HOST_CC ?= cc
X86_64_CROSS_PREFIX ?= $(if $(shell command -v x86_64-elf-gcc 2>/dev/null),x86_64-elf-,)
CC  = $(if $(X86_64_CROSS_PREFIX),$(X86_64_CROSS_PREFIX)gcc,gcc)
LD  = $(if $(X86_64_CROSS_PREFIX),$(X86_64_CROSS_PREFIX)ld,ld)
NM  = $(if $(X86_64_CROSS_PREFIX),$(X86_64_CROSS_PREFIX)nm,nm)
GRUB = grub-mkrescue
X86_64_UEFI_CODE ?= $(firstword \
	$(wildcard /opt/homebrew/share/qemu/edk2-x86_64-code.fd) \
	$(wildcard /usr/local/share/qemu/edk2-x86_64-code.fd) \
	$(wildcard /usr/share/qemu/edk2-x86_64-code.fd) \
	$(wildcard /usr/share/OVMF/OVMF_CODE.fd) \
	$(wildcard /usr/share/edk2/x64/OVMF_CODE.fd))
AARCH64_CC ?= aarch64-elf-gcc
AARCH64_LD ?= aarch64-elf-ld
AARCH64_OBJCOPY ?= aarch64-elf-objcopy
ARM64_EFI_CC ?= /opt/homebrew/opt/llvm/bin/clang
VDSO_CC ?= /opt/homebrew/opt/llvm/bin/clang
LLVM_NM ?= /opt/homebrew/opt/llvm/bin/llvm-nm
LLVM_LINK ?= /opt/homebrew/opt/llvm/bin/llvm-link
QEMU_AARCH64 ?= qemu-system-aarch64
LWIP_DIR ?= third_party/lwip

.DEFAULT_GOAL := kernel
export PATH := /opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/e2fsprogs/sbin:/opt/homebrew/opt/e2fsprogs/bin:/opt/homebrew/bin:/usr/sbin:/sbin:$(PATH)

DOT_CONFIG ?= .config
ARCH ?= x86
SRCARCH ?= x86
KCONFIG ?= Kconfig
KCONFIG_DEFCONFIG ?= arch/$(SRCARCH)/configs/x86_64_defconfig
KCONFIG_SCRIPT := scripts/kconfig/conf.py
KCONFIG_DEPS := $(KCONFIG_SCRIPT) $(KCONFIG) \
	$(shell find arch -type f \( -name 'Kconfig' -o -name 'Kconfig.*' \)) \
	$(wildcard scripts/kconfig/vendor/kconfiglib/*.py)

-include $(DOT_CONFIG)

SRC    = src
OBJ    = obj
OUT    = out
INC    = include
AUTOCONF_H := $(INC)/generated/autoconf.h
VDSO_OUT := $(OUT)/vdso
VDSO_GENERATED := $(OUT)/generated
VDSO_ARM64_SO := $(VDSO_OUT)/linux-vdso-arm64.so
VDSO_X86_64_SO := $(VDSO_OUT)/linux-vdso-x86_64.so
VDSO_ARM64_IMAGE := $(VDSO_GENERATED)/linux-vdso-arm64-image.inc
VDSO_X86_64_IMAGE := $(VDSO_GENERATED)/linux-vdso-x86_64-image.inc
ARM64_DOT_CONFIG ?= .config.arm64
ARM64_AUTOCONF_H := $(INC)/generated/autoconf-arm64.h
ARM64_CONFIG_MK := $(INC)/generated/autoconf-arm64.mk
ARM64_KCONFIG_DEFCONFIG ?= arch/arm64/configs/arm64_defconfig
ifeq ($(strip $(MAKECMDGOALS)),)
-include $(ARM64_CONFIG_MK)
else ifneq ($(strip $(filter-out clean distclean,$(MAKECMDGOALS))),)
-include $(ARM64_CONFIG_MK)
endif
CONFIG = config

COMPILE_TIME := $(shell date +"%a %b %d %H:%M:%S %Z %Y")
strip_quotes = $(patsubst "%",%,$(1))
KERNEL_VERSION := $(call strip_quotes,$(strip $(CONFIG_KERNEL_VERSION)))
KERNEL_VERSION_APPEND := $(call strip_quotes,$(strip $(CONFIG_KERNEL_VERSION_APPEND)))
KERNEL_RELEASE := $(KERNEL_VERSION)$(KERNEL_VERSION_APPEND)
KERNEL_OPT ?= -O2

# Kernel C code must not touch x87/MMX/XMM state.  Exceptions and IRQs may
# interrupt userspace between an SIMD load and a faulting store; compiler-used
# vector registers would then corrupt the retried userspace instruction unless
# every entry path eagerly saved the complete FPU state.
CFLAGS = -I$(INC) -I$(SRC) -I$(VDSO_GENERATED) \
	-DCOMPILE_TIME="\"$(COMPILE_TIME)\"" \
	-include $(AUTOCONF_H) \
	-m64 -mno-red-zone -mcmodel=kernel \
	-mno-mmx -mno-sse -mno-sse2 -msoft-float \
	-std=gnu99 $(KERNEL_OPT) -ffreestanding -fno-pie \
	-fno-builtin -fno-stack-protector -fno-strict-aliasing \
	-fno-delete-null-pointer-checks -fno-omit-frame-pointer \
	-fno-optimize-sibling-calls \
	-Wall -Wextra -MMD -MP

LDFLAGS  = -m elf_x86_64 -T $(CONFIG)/linker.ld -nostdlib
ASMFLAGS = -f elf64

DRIVER_SRCS :=
ifeq ($(CONFIG_ACPI),y)
DRIVER_SRCS += $(SRC)/drivers/acpi/acpi.c
endif
ifeq ($(CONFIG_VIRTIO_BLK),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_blk.c
endif
ifeq ($(CONFIG_VIRTIO_SCSI),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_scsi.c
endif
ifeq ($(CONFIG_NVME),y)
DRIVER_SRCS += $(SRC)/drivers/nvme/nvme.c
endif
ifeq ($(CONFIG_AHCI),y)
DRIVER_SRCS += $(SRC)/drivers/ahci/ahci.c
endif
ifeq ($(CONFIG_ATA),y)
DRIVER_SRCS += $(SRC)/drivers/ata/ata.c
endif
ifeq ($(CONFIG_RTC),y)
DRIVER_SRCS += $(SRC)/drivers/rtc/rtc.c
endif
ifeq ($(CONFIG_HPET),y)
DRIVER_SRCS += $(SRC)/drivers/hpet/hpet.c
endif
ifeq ($(CONFIG_APIC),y)
DRIVER_SRCS += $(SRC)/drivers/interrupt/apic.c
endif
ifeq ($(CONFIG_PCI),y)
DRIVER_SRCS += $(SRC)/drivers/pci/pci.c
ifeq ($(CONFIG_PCI_DRIVER_PROBE),y)
DRIVER_SRCS += $(SRC)/drivers/pci/pci_probe.c
endif
endif
ifeq ($(CONFIG_NET),y)
ifeq ($(CONFIG_E1000),y)
DRIVER_SRCS += $(SRC)/drivers/e1000/e1000.c
else ifeq ($(CONFIG_VIRTIO_NET),y)
DRIVER_SRCS += $(SRC)/drivers/net/virtio_net_frontend.c
else
DRIVER_SRCS += $(SRC)/drivers/net/net_stub.c
endif
ifeq ($(CONFIG_VIRTIO_NET),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_net.c
endif
ifeq ($(CONFIG_NET_REALTEK_R8169),y)
DRIVER_SRCS += $(SRC)/drivers/realtek/r8169.c
endif
ifeq ($(CONFIG_WIFI_INTEL_IWLWIFI),y)
DRIVER_SRCS += $(SRC)/drivers/wifi/iwlwifi.c
endif
ifeq ($(CONFIG_VMWARE_VMXNET3),y)
DRIVER_SRCS += $(SRC)/drivers/vmware/vmxnet3_probe.c
endif
ifeq ($(CONFIG_VMWARE_PVSCSI),y)
DRIVER_SRCS += $(SRC)/drivers/vmware/pvscsi.c
endif
ifeq ($(CONFIG_HYPERV_NETVSC),y)
DRIVER_SRCS += $(SRC)/drivers/hyperv/hyperv_probe.c
endif
endif
ifneq ($(filter y,$(CONFIG_USB) $(CONFIG_BSD_DRIVER_BRIDGE)),)
DRIVER_SRCS += $(SRC)/drivers/usb/handoff.c
endif
ifeq ($(CONFIG_USB),y)
DRIVER_SRCS += $(SRC)/drivers/usb/usb.c $(SRC)/drivers/usb/usb_dma.c $(SRC)/drivers/usb/usb_dma_layout.c
ifeq ($(CONFIG_USB_UHCI),y)
DRIVER_SRCS += $(SRC)/drivers/usb/uhci.c
endif
ifeq ($(CONFIG_USB_EHCI),y)
DRIVER_SRCS += $(SRC)/drivers/usb/ehci.c
endif
ifeq ($(CONFIG_USB_OHCI),y)
DRIVER_SRCS += $(SRC)/drivers/usb/ohci.c
endif
ifeq ($(CONFIG_USB_XHCI),y)
DRIVER_SRCS += $(SRC)/drivers/usb/xhci.c $(SRC)/drivers/usb/xhci_capability.c $(SRC)/drivers/usb/xhci_transfer.c
endif
endif
ifeq ($(CONFIG_SMBUS),y)
DRIVER_SRCS += $(SRC)/drivers/smbus/ichsmb.c
endif
ifeq ($(CONFIG_I2C),y)
DRIVER_SRCS += $(SRC)/drivers/i2c/i2c.c
endif
ifeq ($(CONFIG_TPM2),y)
DRIVER_SRCS += $(SRC)/drivers/tpm/tpm2.c
endif
ifeq ($(CONFIG_WATCHDOG),y)
DRIVER_SRCS += $(SRC)/drivers/watchdog/i6300esbwd.c
endif
ifeq ($(CONFIG_CPUFREQ_INTEL_PSTATE),y)
DRIVER_SRCS += $(SRC)/drivers/cpufreq/intel_pstate.c
endif
ifneq ($(filter y,$(CONFIG_AUDIO_AC97) $(CONFIG_AUDIO_HDA) $(CONFIG_USB_AUDIO)),)
DRIVER_SRCS += $(SRC)/drivers/audio/audio.c
endif
ifeq ($(CONFIG_AUDIO_AC97),y)
DRIVER_SRCS += $(SRC)/drivers/audio/ac97.c
endif
ifeq ($(CONFIG_AUDIO_HDA),y)
DRIVER_SRCS += $(SRC)/drivers/audio/hda.c
endif
ifeq ($(CONFIG_GRAPHICS_BGA),y)
DRIVER_SRCS += $(SRC)/drivers/video/bga.c
endif
ifeq ($(CONFIG_VMWARE_SVGA),y)
DRIVER_SRCS += $(SRC)/drivers/video/vmware_svga.c
endif
ifeq ($(CONFIG_GRAPHICS_INTEL),y)
DRIVER_SRCS += $(SRC)/drivers/video/intel_graphics_probe.c
endif
ifeq ($(CONFIG_VIRTIO_GPU),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_gpu.c \
	$(SRC)/drivers/virtio/virtio_gpu_damage.c
endif
ifeq ($(CONFIG_VIRTIO_RNG),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_rng.c
endif
ifeq ($(CONFIG_VIRTIO_BALLOON),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_balloon.c
endif
ifeq ($(CONFIG_VIRTIO_CONSOLE),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_console.c
endif
ifeq ($(CONFIG_VIRTIO_INPUT),y)
DRIVER_SRCS += $(SRC)/drivers/virtio/virtio_input.c
endif

FS_SRCS := $(SRC)/fs/sysfs.c
ifeq ($(CONFIG_FS_SWAP),y)
FS_SRCS += $(SRC)/fs/swap.c
endif

ifeq ($(CONFIG_INITRAMFS),y)
FS_SRCS += $(SRC)/fs/initramfs.c
endif
ifeq ($(CONFIG_OVERLAY_FS),y)
FS_SRCS += $(SRC)/fs/overlayfs.c
endif
ifeq ($(CONFIG_FS_EXT2),y)
FS_SRCS += $(SRC)/fs/ext2/ext2.c
endif
ifeq ($(CONFIG_FS_EXT4),y)
FS_SRCS += $(SRC)/fs/ext4/ext4.c
endif
ifeq ($(CONFIG_FS_FAT32),y)
FS_SRCS += $(SRC)/fs/fat32.c $(SRC)/fs/fat32/fat32_vfs.c
endif
ifeq ($(CONFIG_FS_EXFAT),y)
FS_SRCS += $(SRC)/fs/exfat/exfat.c
endif
ifeq ($(CONFIG_FS_NTFS),y)
FS_SRCS += $(SRC)/fs/ntfs/ntfs.c
endif
ifeq ($(CONFIG_FS_ISO9660),y)
FS_SRCS += $(SRC)/fs/iso9660/iso9660.c
endif
ifeq ($(CONFIG_FS_UDF),y)
FS_SRCS += $(SRC)/fs/udf/udf.c
endif

C_SRCS  := $(shell find $(SRC) \
	-path '$(SRC)/arch' -prune -o \
	-path '$(SRC)/shell' -prune -o \
	-path '$(SRC)/compat/freebsd' -prune -o \
	-path '$(SRC)/sys/syscall_parts' -prune -o \
	-path '$(SRC)/kernel/user_stack.c' -prune -o \
	-path '$(SRC)/mm/fbdev_sync.c' -prune -o \
	-path '$(SRC)/elf/elf_image.c' -prune -o \
	-path '$(SRC)/drivers' -prune -o \
	-path '$(SRC)/fs/swap.c' -prune -o \
	-path '$(SRC)/fs/initramfs.c' -prune -o \
	-path '$(SRC)/fs/overlayfs.c' -prune -o \
	-path '$(SRC)/fs/vfs_early.c' -prune -o \
	-path '$(SRC)/fs/sysfs.c' -prune -o \
	-path '$(SRC)/fs/ext2' -prune -o \
	-path '$(SRC)/fs/ext4' -prune -o \
	-path '$(SRC)/fs/exfat' -prune -o \
	-path '$(SRC)/fs/ntfs' -prune -o \
	-path '$(SRC)/fs/iso9660' -prune -o \
	-path '$(SRC)/fs/udf' -prune -o \
	-path '$(SRC)/fs/squashfs' -prune -o \
	-path '$(SRC)/fs/erofs' -prune -o \
	-path '$(SRC)/fs/fat32' -prune -o \
	-path '$(SRC)/fs/fat32.c' -prune -o \
	-path '$(SRC)/lib/gzip.c' -prune -o \
	-path '$(SRC)/lib/zlib' -prune -o \
	-name '*.c' -print)
include $(SRC)/arch/x86_64/Makefile.inc
C_SRCS += $(X86_ARCH_SRCS) $(DRIVER_SRCS) $(FS_SRCS)
ASM_SRCS := $(X86_ARCH_ASM_SRCS)
LWIP_SRCS := \
	$(LWIP_DIR)/src/core/def.c \
	$(LWIP_DIR)/src/core/dns.c \
	$(LWIP_DIR)/src/core/init.c \
	$(LWIP_DIR)/src/core/inet_chksum.c \
	$(LWIP_DIR)/src/core/ip.c \
	$(LWIP_DIR)/src/core/mem.c \
	$(LWIP_DIR)/src/core/memp.c \
	$(LWIP_DIR)/src/core/netif.c \
	$(LWIP_DIR)/src/core/pbuf.c \
	$(LWIP_DIR)/src/core/raw.c \
	$(LWIP_DIR)/src/core/stats.c \
	$(LWIP_DIR)/src/core/sys.c \
	$(LWIP_DIR)/src/core/tcp.c \
	$(LWIP_DIR)/src/core/tcp_in.c \
	$(LWIP_DIR)/src/core/tcp_out.c \
	$(LWIP_DIR)/src/core/timeouts.c \
	$(LWIP_DIR)/src/core/udp.c \
	$(LWIP_DIR)/src/core/ipv4/ip4.c \
	$(LWIP_DIR)/src/core/ipv4/ip4_addr.c \
	$(LWIP_DIR)/src/core/ipv4/ip4_frag.c \
	$(LWIP_DIR)/src/core/ipv4/icmp.c \
	$(LWIP_DIR)/src/core/ipv4/igmp.c \
	$(LWIP_DIR)/src/core/ipv6/ip6.c \
	$(LWIP_DIR)/src/core/ipv6/ip6_addr.c \
	$(LWIP_DIR)/src/core/ipv6/icmp6.c \
	$(LWIP_DIR)/src/core/ipv6/inet6.c \
	$(LWIP_DIR)/src/core/ipv6/ip6_frag.c \
	$(LWIP_DIR)/src/core/ipv6/nd6.c \
	$(LWIP_DIR)/src/core/ipv6/mld6.c \
	$(LWIP_DIR)/src/core/ipv6/ethip6.c \
	$(LWIP_DIR)/src/netif/ethernet.c

include $(SRC)/Makefile.common
# Select architecture-independent policy from the same explicit manifest as
# ARM64. The find-based legacy list is filtered first to avoid duplicate
# objects while the remaining x86 subsystems are migrated incrementally.
C_SRCS := $(filter-out $(EDGE_SHARED_SRCS),$(C_SRCS))
C_SRCS += $(EDGE_SHARED_SRCS)

C_OBJS  := $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(C_SRCS))
ASM_OBJS := $(patsubst $(SRC)/%.asm,$(OBJ)/%.o,$(ASM_SRCS))
LWIP_OBJS := $(patsubst $(LWIP_DIR)/src/%.c,$(OBJ)/lwip/%.o,$(LWIP_SRCS))
OBJS := $(C_OBJS) $(ASM_OBJS) $(LWIP_OBJS)
# Keep this recursive because BSD bridge objects are appended after the
# generated package plan is loaded below.  An immediate expansion silently
# omitted imported-source header dependencies from incremental builds.
DEPS = $(OBJS:.o=.d)

TARGET = $(OUT)/edgeos.bin
X86_INITRAMFS = $(OUT)/x86_64/initramfs.img
X86_INITRAMFS_ISO_DIR = $(OUT)/x86_64-initramfs-isodir
X86_INITRAMFS_ISO = $(OUT)/edgeos-x86_64-initramfs.iso
ARM64_OUT = $(OUT)/arm64
ARM64_UEFI_ELF = $(ARM64_OUT)/edgeos-arm64-uefi.elf
ARM64_UEFI_OBJ = $(OBJ)/arch/arm64/uefi_entry.o
ARM64_UEFI_EFI = $(ARM64_OUT)/BOOTAA64.EFI
include $(SRC)/arch/arm64/Makefile.inc
ARM64_UEFI_HEADERS := $(shell find $(INC) $(SRC) -type f -name '*.h')
ARM64_UEFI_INCLUDED_SRCS := $(wildcard $(SRC)/sys/syscall_parts/*.c)
ARM64_UEFI_GENERATED_INCLUDES := $(SRC)/kernel/linux_syscall_tables.inc
ARM64_INITRAMFS = $(ARM64_OUT)/initramfs.img
ARM64_INITRAMFS_ESP = $(OUT)/edgeos-arm64-initramfs.img
ARM64_INITRAMFS_ESP_SIZE_MB ?= 224
ARM64_RPI4_ESP = $(OUT)/edgeos-arm64-rpi4.img
ARM64_RPI4_ESP_SIZE_MB ?= 256
ARM64_RPI5_ESP = $(OUT)/edgeos-arm64-rpi5.img
ARM64_RPI5_ESP_SIZE_MB ?= 512
ARM64_KERNEL_VERSION_APPEND ?= +arm64
ARM64_KERNEL_RELEASE ?= $(KERNEL_VERSION)$(ARM64_KERNEL_VERSION_APPEND)
ARM64_VERSION_CFLAGS = \
	-DCOMPILE_TIME="\"$(COMPILE_TIME)\"" \
	-include $(ARM64_AUTOCONF_H)
INITRAMFS_TOOL = tools/initramfs/mkinitramfs.py
INITRAMFS_BASE_MANIFEST = config/initramfs-base.list
INITRAMFS_CONFIG_SOURCE = $(call strip_quotes,$(strip $(CONFIG_INITRAMFS_SOURCE)))
INITRAMFS_SOURCE_DIR ?= $(INITRAMFS_CONFIG_SOURCE)
INITRAMFS_OVERLAYS ?=
INITRAMFS_IMAGE ?= $(OUT)/initramfs.img
INITRAMFS_OWNER ?= 0:0
INITRAMFS_MTIME ?= 0
INITRAMFS_FORMAT_ARG = $(if $(filter y,$(CONFIG_INITRAMFS_CRC)),--format crc,)
INITRAMFS_COMPRESSION = $(if $(filter y,$(CONFIG_INITRAMFS_COMPRESSION_GZIP)),gzip,none)
CFLAGS += -I$(LWIP_DIR)/src/include

.PHONY: all clean run-x86-initramfs run-arm64-initramfs-uefi run-arm64-rpi4 x86-initramfs-iso arm64-initramfs-uefi arm64-rpi4 arm64-rpi5 arm64-rpi5-fdt-acceptance initramfs initramfs-tool-unit gzip-unit aes-unit defconfig x86_64_defconfig arm64_defconfig olddefconfig arm64-olddefconfig menuconfig arm64-menuconfig kconfig-check syscall-inventory-check cross-arch-unity-check abi-service-dispatch-unit directory-runtime-unit vfs-path-cache-unit vfs-filesystem-registry-unit vfs-mount-table-unit overlayfs-capacity-unit vfs-mount-snapshot-unit vfs-mount-topology-unit mount-api-unit vfs-read-exact-unit vfs-readahead-state-unit vfs-seek-data-hole-unit vfs-readlink-unit vfs-metadata-unit vfs-open-unit loop-device-unit device-mapper-unit squashfs-reader-unit erofs-reader-unit xfs-reader-unit btrfs-reader-unit nfsd-protocol-unit process-clone-unit process-exec-unit wait-runtime-unit process-commit-unit process-native-view-unit proc-task-unit mm-runtime-unit event-dispatch-policy-unit inotify-readiness-sequence-unit io-dispatch-policy-unit proc-maps-unit scheduler-policy-unit scheduler-runtime-unit deferred-work-unit smp-unit x86-scheduler-context-unit syslog-runtime-unit task-scratch-current-unit vfs-context-unit vfs-descriptor-policy-unit vfs-writeback-unit file-description-runtime-unit pipe-runtime-unit fd-runtime-unit fd-table-runtime-unit descriptor-factory-runtime-unit socket-runtime-unit socket-message-unit socket-rights-unit socket-rights-delivery-unit socket-accept-queue-unit network-core-unit linux-netlink-netfilter-unit linux-genetlink-unit linux-ethtool-unit namespace-ioctl-runtime-unit kernelrelease prepare syncconfig arm64-syncconfig arm64-kernel kernel FORCE

BSD_DRIVER_MANIFEST_DIR := config/bsd_drivers/manifests
BSD_DRIVER_CAPABILITY_DIR := config/bsd_drivers/capabilities
BSD_DRIVER_MANIFESTS := $(sort $(wildcard $(BSD_DRIVER_MANIFEST_DIR)/*.json))
BSD_DRIVER_CAPABILITY_REGISTRIES := \
	$(sort $(wildcard $(BSD_DRIVER_CAPABILITY_DIR)/*.json))
BSD_BRIDGE_GENERATED := $(OUT)/bsd_bridge/generated
BSD_BRIDGE_ACPICA_INCLUDE := $(OUT)/bsd_bridge/acpica_include
BSD_BRIDGE_ACPICA_INCLUDE_STAMP := \
	$(BSD_BRIDGE_ACPICA_INCLUDE)/.stamp
BSD_BRIDGE_ACPICA_UPSTREAM_INCLUDE = \
	$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/dev/acpica/include
BSD_BRIDGE_ACPICA_RUNTIME_SRCS = \
	$(sort $(shell find \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/dev/acpica/components \
		-type f -name '*.c' 2>/dev/null))
BSD_BRIDGE_X86_ACPICA_CORE_OBJS = \
	$(patsubst \
	$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/dev/acpica/components/%.c,\
	$(OBJ)/compat/freebsd/acpica/%.o,\
	$(BSD_BRIDGE_ACPICA_RUNTIME_SRCS))
BSD_BRIDGE_X86_ACPICA_OS_OBJS := \
	$(OBJ)/compat/freebsd/acpica/acpica_osl.o \
	$(OBJ)/compat/freebsd/acpica/acpica_runtime.o
BSD_BRIDGE_ARM64_ACPICA_CORE_BCS = \
	$(patsubst \
	$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/dev/acpica/components/%.c,\
	$(OBJ)/arm64-bsd/acpica/%.bc,\
	$(BSD_BRIDGE_ACPICA_RUNTIME_SRCS))
BSD_BRIDGE_ARM64_ACPICA_CORE_OBJS = \
	$(BSD_BRIDGE_ARM64_ACPICA_CORE_BCS:.bc=.obj)
BSD_BRIDGE_ARM64_ACPICA_OS_BCS := \
	$(OBJ)/arm64-bsd/acpica/acpica_osl.bc \
	$(OBJ)/arm64-bsd/acpica/acpica_runtime.bc
BSD_BRIDGE_ARM64_ACPICA_OS_OBJS := \
	$(BSD_BRIDGE_ARM64_ACPICA_OS_BCS:.bc=.obj)
BSD_BRIDGE_BUILD_PLAN := $(OUT)/bsd_bridge/packages.mk
BSD_BRIDGE_PACKAGE_REGISTRY := \
	$(BSD_BRIDGE_GENERATED)/bsd_package_registry.c
ifneq ($(MAKECMDGOALS),clean)
-include $(BSD_BRIDGE_BUILD_PLAN)
endif
BSD_BRIDGE_SOURCE_WARNINGS := \
	-Wno-sign-compare -Wno-unused-parameter -Wno-pointer-sign \
	-Wno-missing-field-initializers -Wno-misleading-indentation \
	-Wno-ignored-qualifiers \
	-Wno-format -Wno-type-limits -Wno-unused-function \
	-Wno-empty-body -Wno-return-type -Wno-implicit-fallthrough \
	-Wno-unused-but-set-variable -Wno-unused-but-set-parameter \
	-Wno-address-of-packed-member -Wno-cast-function-type
BSD_BRIDGE_GCC_SOURCE_WARNINGS := \
	-Wno-old-style-declaration -Wno-maybe-uninitialized \
	-Wno-unknown-pragmas
BSD_BRIDGE_CLANG_SOURCE_WARNINGS := \
	-Wno-microsoft-enum-forward-reference \
	-Wno-macro-redefined \
	-Wno-gnu-null-pointer-arithmetic \
	-Wno-null-pointer-subtraction \
	-Wno-bitfield-constant-conversion \
	-Wno-unused-const-variable \
	-Wno-cast-function-type-mismatch
BSD_BRIDGE_VTNET_GCC_WARNINGS := -Wno-error=maybe-uninitialized
BSD_BRIDGE_E1000_GCC_WARNINGS := -Wno-error=maybe-uninitialized
BSD_BRIDGE_VMXNET3_GCC_WARNINGS := -Wno-error=maybe-uninitialized
BSD_BRIDGE_IGC_GCC_WARNINGS := -Wno-error=maybe-uninitialized
BSD_BRIDGE_QSORT_GCC_WARNINGS := -Wno-error=sign-compare
BSD_BRIDGE_QSORT_CLANG_WARNINGS := \
	-Wno-error=null-pointer-subtraction -Wno-error=sign-compare
BSD_BRIDGE_COFF_SOURCE_WARNINGS := \
	$(BSD_BRIDGE_SOURCE_WARNINGS) -Wno-unused-function
BSD_BRIDGE_RUNTIME_SRCS := \
	$(SRC)/compat/freebsd/kern/acpi_ioctl.c \
	$(SRC)/compat/freebsd/kern/acpi_power.c \
	$(SRC)/compat/freebsd/kern/acpi_tables.c \
	$(SRC)/compat/freebsd/kern/allocator.c \
	$(SRC)/compat/freebsd/kern/audio.c \
	$(SRC)/compat/freebsd/kern/block.c \
	$(SRC)/compat/freebsd/kern/bootstrap.c \
	$(SRC)/compat/freebsd/kern/bpf.c \
	$(SRC)/compat/freebsd/kern/bus_dma.c \
	$(SRC)/compat/freebsd/kern/bus_space.c \
	$(SRC)/compat/freebsd/kern/callout.c \
	$(SRC)/compat/freebsd/kern/cam.c \
	$(SRC)/compat/freebsd/kern/cdev.c \
	$(SRC)/compat/freebsd/kern/clock_fixed.c \
	$(SRC)/compat/freebsd/kern/compiler_runtime.c \
	$(SRC)/compat/freebsd/kern/contigmalloc.c \
	$(SRC)/compat/freebsd/kern/config_intrhook.c \
	$(SRC)/compat/freebsd/kern/console.c \
	$(SRC)/compat/freebsd/kern/counter.c \
	$(SRC)/compat/freebsd/kern/cpu.c \
	$(SRC)/compat/freebsd/kern/devctl.c \
	$(SRC)/compat/freebsd/kern/device_property.c \
	$(SRC)/compat/freebsd/kern/devicestat.c \
	$(SRC)/compat/freebsd/kern/driver_loader.c \
	$(SRC)/compat/freebsd/kern/driver_path.c \
	$(SRC)/compat/freebsd/kern/driver_symbols.c \
	$(SRC)/compat/freebsd/kern/environment.c \
	$(SRC)/compat/freebsd/kern/epoch.c \
	$(SRC)/compat/freebsd/kern/efi_runtime.c \
	$(SRC)/compat/freebsd/kern/eventtimer.c \
	$(SRC)/compat/freebsd/kern/evdev.c \
	$(SRC)/compat/freebsd/drivers/adapters.c \
	$(SRC)/compat/freebsd/drivers/iwm_firmware.c \
	$(SRC)/compat/freebsd/drivers/wireless_firmware.c \
	$(SRC)/compat/freebsd/kern/eventhandler.c \
	$(SRC)/compat/freebsd/kern/fdt_inventory.c \
	$(SRC)/compat/freebsd/kern/firmware.c \
	$(SRC)/compat/freebsd/kern/firmware_metadata.c \
	$(SRC)/compat/freebsd/kern/framebuffer.c \
	$(SRC)/compat/freebsd/kern/gtaskqueue.c \
	$(SRC)/compat/freebsd/kern/handoff.c \
	$(SRC)/compat/freebsd/kern/hash.c \
	$(SRC)/compat/freebsd/kern/hypervisor.c \
	$(SRC)/compat/freebsd/kern/hwreset.c \
	$(SRC)/compat/freebsd/kern/interrupt.c \
	$(SRC)/compat/freebsd/kern/intrng.c \
	$(SRC)/compat/freebsd/kern/isa.c \
	$(SRC)/compat/freebsd/kern/if_clone.c \
	$(SRC)/compat/freebsd/kern/ifnet.c \
	$(SRC)/compat/freebsd/kern/in.c \
	$(SRC)/compat/freebsd/kern/in_cksum.c \
	$(SRC)/compat/freebsd/kern/ip6.c \
	$(SRC)/compat/freebsd/kern/kobj.c \
	$(SRC)/compat/freebsd/kern/kthread.c \
	$(SRC)/compat/freebsd/kern/led.c \
	$(SRC)/compat/freebsd/kern/linker.c \
	$(SRC)/compat/freebsd/kern/malloc.c \
	$(SRC)/compat/freebsd/kern/mbuf.c \
	$(SRC)/compat/freebsd/kern/module.c \
	$(SRC)/compat/freebsd/kern/mutex_pool.c \
	$(SRC)/compat/freebsd/kern/newbus.c \
	$(SRC)/compat/freebsd/kern/newbus_generic.c \
	$(SRC)/compat/freebsd/kern/netisr.c \
	$(SRC)/compat/freebsd/kern/ofw.c \
	$(SRC)/compat/freebsd/kern/ofw_bus.c \
	$(SRC)/compat/freebsd/kern/ofw_bus_map.c \
	$(SRC)/compat/freebsd/kern/ofw_subr.c \
	$(SRC)/compat/freebsd/kern/package.c \
	$(SRC)/compat/freebsd/kern/platform.c \
	$(SRC)/compat/freebsd/kern/pci.c \
	$(SRC)/compat/freebsd/kern/physio.c \
	$(SRC)/compat/freebsd/kern/priv.c \
	$(SRC)/compat/freebsd/kern/pps.c \
	$(SRC)/compat/freebsd/kern/random.c \
	$(SRC)/compat/freebsd/kern/resource.c \
	$(SRC)/compat/freebsd/kern/resource_rman.c \
	$(SRC)/compat/freebsd/kern/route_notify.c \
	$(SRC)/compat/freebsd/kern/rss.c \
	$(SRC)/compat/freebsd/kern/root_mount.c \
	$(SRC)/compat/freebsd/kern/rtc.c \
	$(SRC)/compat/freebsd/kern/sbuf.c \
	$(SRC)/compat/freebsd/kern/selinfo.c \
	$(SRC)/compat/freebsd/kern/sglist.c \
	$(SRC)/compat/freebsd/kern/sigio.c \
	$(SRC)/compat/freebsd/kern/slicer.c \
	$(SRC)/compat/freebsd/kern/sleep.c \
	$(SRC)/compat/freebsd/kern/socket.c \
	$(SRC)/compat/freebsd/kern/sync.c \
	$(SRC)/compat/freebsd/kern/syscon.c \
	$(SRC)/compat/freebsd/kern/sysctl.c \
	$(SRC)/compat/freebsd/kern/systm.c \
	$(SRC)/compat/freebsd/kern/taskqueue.c \
	$(SRC)/compat/freebsd/kern/tcp_lro.c \
	$(SRC)/compat/freebsd/kern/time.c \
	$(SRC)/compat/freebsd/kern/tty.c \
	$(SRC)/compat/freebsd/kern/uio.c \
	$(SRC)/compat/freebsd/kern/uma.c \
	$(SRC)/compat/freebsd/kern/uuid.c \
	$(SRC)/compat/freebsd/kern/vm_page.c \
	$(SRC)/compat/freebsd/kern/vm_kern.c \
	$(SRC)/compat/freebsd/kern/vmem.c \
	$(SRC)/compat/freebsd/kern/watchdog.c \
	$(SRC)/compat/freebsd/kern/builtin_module_metadata.c \
	$(SRC)/compat/freebsd/drivers/virtio_mmio.c
BSD_BRIDGE_X86_ARCH_SRCS := \
	$(SRC)/compat/freebsd/arch/x86_64/fpu.c \
	$(SRC)/compat/freebsd/arch/x86_64/handoff.c \
	$(SRC)/compat/freebsd/arch/x86_64/interrupt.c \
	$(SRC)/compat/freebsd/arch/x86_64/pci.c \
	$(SRC)/compat/freebsd/arch/x86_64/rtc.c \
	$(SRC)/compat/freebsd/kern/iommu_platform.c \
	$(SRC)/compat/freebsd/kern/pvclock.c
BSD_BRIDGE_ARM64_ARCH_SRCS := \
	$(SRC)/compat/freebsd/arch/arm64/bcm2712_sdhci.c \
	$(SRC)/compat/freebsd/arch/arm64/fpu.c \
	$(SRC)/compat/freebsd/arch/arm64/handoff.c \
	$(SRC)/compat/freebsd/arch/arm64/interrupt.c \
	$(SRC)/compat/freebsd/arch/arm64/pci.c \
	$(SRC)/compat/freebsd/arch/arm64/psci_platform.c \
	$(SRC)/compat/freebsd/arch/arm64/smccc.c
BSD_BRIDGE_CORE_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_CORE_SRCS)
BSD_BRIDGE_PCI_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_PCI_SRCS)
BSD_BRIDGE_MMIO_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_MMIO_SRCS)
BSD_BRIDGE_MMIO_FIRMWARE_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_MMIO_ACPI_SRCS) \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_MMIO_FDT_SRCS)
BSD_BRIDGE_HOST_TEST_INCLUDE := \
	tools/tests/bsd_bridge_host_include
BSD_BRIDGE_RANDOM_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_RANDOM_SRCS)
BSD_BRIDGE_GPU_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_GPU_SRCS)
BSD_BRIDGE_SCMI_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_SCMI_SRCS)
BSD_BRIDGE_BALLOON_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_BALLOON_SRCS)
BSD_BRIDGE_CONSOLE_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_CONSOLE_SRCS)
BSD_BRIDGE_BLOCK_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_BLOCK_SRCS)
BSD_BRIDGE_NETWORK_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_NETWORK_SRCS)
BSD_BRIDGE_SCSI_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_VIRTIO_SCSI_SRCS)
BSD_BRIDGE_FRAMEBUFFER_SRCS = \
	$(BSD_BRIDGE_MODULE_FREEBSD_VIRTIO_FREEBSD_VT_FRAMEBUFFER_SRCS)
BSD_BRIDGE_SUPPORT_SRCS := \
	$(SRC)/compat/freebsd/kern/sbuf.c \
	$(SRC)/compat/freebsd/kern/sysctl.c \
	$(SRC)/compat/freebsd/kern/newbus_generic.c
BSD_BRIDGE_X86_RUNTIME_OBJS := \
	$(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(BSD_BRIDGE_RUNTIME_SRCS) \
	$(BSD_BRIDGE_X86_ARCH_SRCS))
BSD_BRIDGE_X86_GENERATED_OBJS := \
	$(addprefix $(OBJ)/compat/freebsd/generated/,\
	$(BSD_BRIDGE_X86_64_GENERATED_SRCS:.c=.o))
BSD_BRIDGE_X86_UPSTREAM_C_REL_SRCS := \
	$(filter %.c,$(BSD_BRIDGE_X86_64_UPSTREAM_REL_SRCS))
BSD_BRIDGE_X86_UPSTREAM_ASM_REL_SRCS := \
	$(filter %.S,$(BSD_BRIDGE_X86_64_UPSTREAM_REL_SRCS))
BSD_BRIDGE_X86_UPSTREAM_OBJS := \
	$(addprefix $(OBJ)/compat/freebsd/upstream/,\
	$(BSD_BRIDGE_X86_UPSTREAM_C_REL_SRCS:.c=.o) \
	$(BSD_BRIDGE_X86_UPSTREAM_ASM_REL_SRCS:.S=.o))
BSD_BRIDGE_ARM64_RUNTIME_OBJS := \
	$(patsubst $(SRC)/%.c,$(OBJ)/arm64-bsd/%.obj,\
	$(BSD_BRIDGE_RUNTIME_SRCS) $(BSD_BRIDGE_ARM64_ARCH_SRCS))
BSD_BRIDGE_ARM64_RUNTIME_BCS := \
	$(patsubst $(SRC)/%.c,$(OBJ)/arm64-bsd/%.bc,\
	$(BSD_BRIDGE_RUNTIME_SRCS) $(BSD_BRIDGE_ARM64_ARCH_SRCS))
BSD_BRIDGE_ARM64_GENERATED_OBJS := \
	$(addprefix $(OBJ)/arm64-bsd/generated/,\
	$(BSD_BRIDGE_ARM64_GENERATED_SRCS:.c=.obj))
BSD_BRIDGE_ARM64_GENERATED_BCS := \
	$(addprefix $(OBJ)/arm64-bsd/generated/,\
	$(BSD_BRIDGE_ARM64_GENERATED_SRCS:.c=.bc))
BSD_BRIDGE_ARM64_UPSTREAM_C_REL_SRCS := \
	$(filter %.c,$(BSD_BRIDGE_ARM64_UPSTREAM_REL_SRCS))
BSD_BRIDGE_ARM64_UPSTREAM_ASM_REL_SRCS := \
	$(filter %.S,$(BSD_BRIDGE_ARM64_UPSTREAM_REL_SRCS))
BSD_BRIDGE_ARM64_UPSTREAM_OBJS := \
	$(addprefix $(OBJ)/arm64-bsd/upstream/,\
	$(BSD_BRIDGE_ARM64_UPSTREAM_C_REL_SRCS:.c=.obj) \
	$(BSD_BRIDGE_ARM64_UPSTREAM_ASM_REL_SRCS:.S=.obj))
BSD_BRIDGE_ARM64_UPSTREAM_BCS := \
	$(addprefix $(OBJ)/arm64-bsd/upstream/,\
	$(BSD_BRIDGE_ARM64_UPSTREAM_C_REL_SRCS:.c=.bc))
BSD_BRIDGE_ARM64_DEPS := \
	$(BSD_BRIDGE_ARM64_RUNTIME_BCS:.bc=.d) \
	$(BSD_BRIDGE_ARM64_GENERATED_BCS:.bc=.d) \
	$(BSD_BRIDGE_ARM64_UPSTREAM_BCS:.bc=.d) \
	$(BSD_BRIDGE_ARM64_ACPICA_CORE_BCS:.bc=.d) \
	$(BSD_BRIDGE_ARM64_ACPICA_OS_BCS:.bc=.d)
.SECONDARY: $(BSD_BRIDGE_ARM64_RUNTIME_BCS) \
	$(BSD_BRIDGE_ARM64_GENERATED_BCS) $(BSD_BRIDGE_ARM64_UPSTREAM_BCS) \
	$(BSD_BRIDGE_ARM64_ACPICA_CORE_BCS) $(BSD_BRIDGE_ARM64_ACPICA_OS_BCS)
.PRECIOUS: $(BSD_BRIDGE_ARM64_RUNTIME_BCS) \
	$(BSD_BRIDGE_ARM64_GENERATED_BCS) $(BSD_BRIDGE_ARM64_UPSTREAM_BCS) \
	$(BSD_BRIDGE_ARM64_ACPICA_CORE_BCS) $(BSD_BRIDGE_ARM64_ACPICA_OS_BCS)
BSD_BRIDGE_GENERATED_STAMP := $(BSD_BRIDGE_GENERATED)/.stamp
# The bridge is a FreeBSD kernel target even when GCC itself runs on Linux.
# Host OS macros select incompatible ACPICA and libc-facing header branches.
BSD_BRIDGE_X86_COMPILE_FLAGS = \
	$(BSD_BRIDGE_SOURCE_INCLUDE_FLAGS) \
	-U__linux__ \
	-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
	-I$(BSD_BRIDGE_UPSTREAM_SYS) \
	-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib \
	-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/device-tree/include \
	-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt \
	-I$(SRC)/lib/zlib/upstream $(CFLAGS) \
	-Werror $(BSD_BRIDGE_SOURCE_WARNINGS) \
	$(BSD_BRIDGE_GCC_SOURCE_WARNINGS) \
	-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS)
BSD_BRIDGE_ARM64_COMMON_SOURCE_FLAGS = \
	$(BSD_BRIDGE_SOURCE_INCLUDE_FLAGS) \
	-std=gnu11 -O2 -ffreestanding -fshort-wchar \
	-fno-builtin -fno-stack-protector -fno-strict-aliasing \
	-mgeneral-regs-only -mno-outline-atomics \
	-ffunction-sections -fdata-sections \
	-MMD -MP \
	-Wall -Wextra -Werror $(BSD_BRIDGE_COFF_SOURCE_WARNINGS) \
	$(BSD_BRIDGE_CLANG_SOURCE_WARNINGS) \
	-D_KERNEL -DEDGEOS_BSD_BRIDGE -DEDGEOS_BSD_COFF_TARGET=1 \
	-DEDGEOS_BSD_ARM64=1 \
	$(BSD_BRIDGE_SOURCE_CPPFLAGS) \
	-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
	-I$(BSD_BRIDGE_UPSTREAM_SYS) \
	-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib \
	-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/device-tree/include \
	-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt \
	-I$(SRC)/lib/zlib/upstream -I$(INC) -I$(SRC) \
	-include $(ARM64_AUTOCONF_H)
# Direct COFF flags remain available for isolated ABI compile checks.
# Production FreeBSD sources are compiled with the FreeBSD LP64/AAPCS
# frontend and then lowered to the COFF object format required by UEFI.
BSD_BRIDGE_ARM64_COMPILE_FLAGS = \
	-target aarch64-unknown-windows -D__STDC__=1 \
	$(BSD_BRIDGE_ARM64_COMMON_SOURCE_FLAGS) \
	$(BSD_BRIDGE_ARM64_TARGET_FLAGS)
BSD_BRIDGE_ARM64_FRONTEND_FLAGS = \
	-target aarch64-unknown-freebsd \
	-include $(INC)/compat/freebsd/edgeos/arm64_coff_varargs.h \
	$(BSD_BRIDGE_ARM64_COMMON_SOURCE_FLAGS) \
	$(BSD_BRIDGE_ARM64_TARGET_FLAGS)
BSD_BRIDGE_X86_MODULE_COMPILE_FLAGS = \
	$(BSD_BRIDGE_X86_COMPILE_FLAGS) -mcmodel=large \
	-DEDGEOS_BSD_LOADABLE_MODULE=1
BSD_BRIDGE_ARM64_MODULE_COMPILE_FLAGS = \
	$(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) \
	-DEDGEOS_BSD_LOADABLE_MODULE=1
BSD_BRIDGE_ARM64_MODULE_FINAL_FLAGS = \
	-target aarch64-unknown-windows -O2 -ffreestanding -fshort-wchar \
	-fno-builtin -fno-stack-protector -fno-strict-aliasing \
	-mgeneral-regs-only -ffunction-sections -fdata-sections \
	-Wno-override-module

ifeq ($(CONFIG_BSD_DRIVER_BRIDGE),y)
CFLAGS += -DCONFIG_BSD_DRIVER_BRIDGE=1
OBJS += $(BSD_BRIDGE_X86_RUNTIME_OBJS) \
	$(BSD_BRIDGE_X86_GENERATED_OBJS) $(BSD_BRIDGE_X86_UPSTREAM_OBJS)
endif

ifeq ($(CONFIG_BSD_DRIVER_ACPICA),y)
CFLAGS += -DCONFIG_BSD_DRIVER_ACPICA=1
OBJS += $(BSD_BRIDGE_X86_ACPICA_CORE_OBJS) \
	$(BSD_BRIDGE_X86_ACPICA_OS_OBJS)
endif

ifeq ($(ARM64_CONFIG_BSD_DRIVER_BRIDGE),y)
ARM64_VERSION_CFLAGS += -DCONFIG_BSD_DRIVER_BRIDGE=1
ARM64_UEFI_SRCS += $(BSD_BRIDGE_ARM64_RUNTIME_OBJS) \
	$(BSD_BRIDGE_ARM64_GENERATED_OBJS) $(BSD_BRIDGE_ARM64_UPSTREAM_OBJS)
endif

ifeq ($(ARM64_CONFIG_BSD_DRIVER_ACPICA),y)
ARM64_VERSION_CFLAGS += -DCONFIG_BSD_DRIVER_ACPICA=1
ARM64_UEFI_SRCS += $(BSD_BRIDGE_ARM64_ACPICA_CORE_OBJS) \
	$(BSD_BRIDGE_ARM64_ACPICA_OS_OBJS)
endif

# This translation unit contains the bridge startup call. Recompile it when a
# command-line Kconfig override changes so an object from the opposite mode
# can never be reused.
$(OBJ)/kernel.o: FORCE

$(BSD_BRIDGE_BUILD_PLAN): $(BSD_DRIVER_MANIFESTS) \
		$(BSD_DRIVER_CAPABILITY_REGISTRIES) \
		tools/bsd_bridge/catalog.py \
		tools/bsd_bridge/generate_build_plan.py \
		tools/bsd_bridge/manifest.py
	@mkdir -p $(dir $@)
	@python3 tools/bsd_bridge/generate_build_plan.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--capability-dir $(BSD_DRIVER_CAPABILITY_DIR) \
		--output $@

$(BSD_BRIDGE_GENERATED_STAMP): $(BSD_DRIVER_MANIFESTS) \
		$(BSD_DRIVER_CAPABILITY_REGISTRIES) $(BSD_BRIDGE_BUILD_PLAN) \
		tools/bsd_bridge/generate_interfaces.py \
		tools/bsd_bridge/generate_miidevs.py \
		tools/bsd_bridge/generate_usbdevs.py \
		tools/bsd_bridge/generate_package_registry.py | \
		bsd-bridge-source-gate
	@mkdir -p $(BSD_BRIDGE_GENERATED)
	@python3 tools/bsd_bridge/generate_interfaces.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--output $(BSD_BRIDGE_GENERATED)
	@python3 tools/bsd_bridge/generate_package_registry.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--capability-dir $(BSD_DRIVER_CAPABILITY_DIR) \
		--output $(BSD_BRIDGE_PACKAGE_REGISTRY)
	@touch $@

$(BSD_BRIDGE_GENERATED)/%.c $(BSD_BRIDGE_GENERATED)/%.h: \
		| $(BSD_BRIDGE_GENERATED_STAMP)
	@if [ ! -f "$@" ]; then \
		python3 tools/bsd_bridge/generate_interfaces.py \
			--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
			--output $(BSD_BRIDGE_GENERATED); \
	fi

$(BSD_BRIDGE_PACKAGE_REGISTRY): $(BSD_DRIVER_MANIFESTS) \
		$(BSD_DRIVER_CAPABILITY_REGISTRIES) \
		tools/bsd_bridge/catalog.py \
		tools/bsd_bridge/generate_package_registry.py \
		tools/bsd_bridge/manifest.py
	@mkdir -p $(dir $@)
	@python3 tools/bsd_bridge/generate_package_registry.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--capability-dir $(BSD_DRIVER_CAPABILITY_DIR) \
		--output $@

$(OBJ)/compat/freebsd/acpica/%.o: \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/dev/acpica/components/%.c \
		$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP) \
		$(BSD_BRIDGE_GENERATED_STAMP) $(AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_X86_COMPILE_FLAGS) -Wa,--noexecstack \
		-D__FreeBSD__=14 -DEDGEOS_BSD_FULL_ACPICA \
		-c $< -o $@

$(OBJ)/compat/freebsd/acpica/acpica_osl.o: \
		$(SRC)/compat/freebsd/kern/acpica_osl.c \
		$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP) \
		$(BSD_BRIDGE_GENERATED_STAMP) $(AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_X86_COMPILE_FLAGS) -Wa,--noexecstack \
		-D__FreeBSD__=14 -DEDGEOS_BSD_FULL_ACPICA \
		-c $< -o $@

$(OBJ)/compat/freebsd/acpica/acpica_runtime.o: \
		$(SRC)/compat/freebsd/kern/acpica_runtime.c \
		$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP) \
		$(BSD_BRIDGE_GENERATED_STAMP) $(AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_X86_COMPILE_FLAGS) -Wa,--noexecstack \
		-D__FreeBSD__=14 -DEDGEOS_BSD_FULL_ACPICA \
		-c $< -o $@

$(OBJ)/arm64-bsd/acpica/%.bc: \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/dev/acpica/components/%.c \
		$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP) \
		$(BSD_BRIDGE_GENERATED_STAMP) $(ARM64_AUTOCONF_H) Makefile | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) -U_MSC_VER \
		-D__GNUC__=4 -D__LP64__=1 -D__FreeBSD__=14 \
		-DEDGEOS_BSD_FULL_ACPICA -emit-llvm -c $< -o $@

$(OBJ)/arm64-bsd/acpica/acpica_osl.bc: \
		$(SRC)/compat/freebsd/kern/acpica_osl.c \
		$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP) \
		$(BSD_BRIDGE_GENERATED_STAMP) $(ARM64_AUTOCONF_H) Makefile | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) -U_MSC_VER \
		-D__GNUC__=4 -D__LP64__=1 -D__FreeBSD__=14 \
		-DEDGEOS_BSD_FULL_ACPICA -emit-llvm -c $< -o $@

$(OBJ)/arm64-bsd/acpica/acpica_runtime.bc: \
		$(SRC)/compat/freebsd/kern/acpica_runtime.c \
		$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP) \
		$(BSD_BRIDGE_GENERATED_STAMP) $(ARM64_AUTOCONF_H) Makefile | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) -U_MSC_VER \
		-D__GNUC__=4 -D__LP64__=1 -D__FreeBSD__=14 \
		-DEDGEOS_BSD_FULL_ACPICA -emit-llvm -c $< -o $@

$(OBJ)/compat/freebsd/%.o: $(SRC)/compat/freebsd/%.c \
		$(BSD_BRIDGE_GENERATED_STAMP) $(AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) -c $< -o $@

$(OBJ)/compat/freebsd/generated/%.o: $(BSD_BRIDGE_GENERATED)/%.c \
		$(BSD_BRIDGE_GENERATED_STAMP) $(AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) -c $< -o $@

$(OBJ)/compat/freebsd/upstream/%.o: \
		$(BSD_BRIDGE_UPSTREAM_SYS)/%.c $(BSD_BRIDGE_GENERATED_STAMP) \
		$(AUTOCONF_H) | bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) -c $< -o $@

$(OBJ)/compat/freebsd/upstream/%.o: \
		$(BSD_BRIDGE_UPSTREAM_SYS)/%.S $(BSD_BRIDGE_GENERATED_STAMP) \
		$(AUTOCONF_H) | bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) -Wa,--noexecstack \
		-DLOCORE -x assembler-with-cpp -c $< -o $@

$(OBJ)/compat/freebsd/upstream/dev/virtio/network/if_vtnet.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += $(BSD_BRIDGE_VTNET_GCC_WARNINGS)
$(OBJ)/compat/freebsd/upstream/dev/e1000/e1000_phy.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += $(BSD_BRIDGE_E1000_GCC_WARNINGS)
$(OBJ)/compat/freebsd/upstream/dev/e1000/if_em.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += \
		$(BSD_BRIDGE_E1000_GCC_WARNINGS) -Wno-unused-but-set-variable
$(OBJ)/compat/freebsd/upstream/dev/vmware/vmxnet3/if_vmx.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += $(BSD_BRIDGE_VMXNET3_GCC_WARNINGS)
$(OBJ)/compat/freebsd/upstream/dev/igc/if_igc.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += \
		$(BSD_BRIDGE_IGC_GCC_WARNINGS) -Wno-unused-but-set-variable
$(OBJ)/compat/freebsd/upstream/dev/mpr/mpr.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-array-bounds
$(OBJ)/compat/freebsd/upstream/dev/mpr/mpr_sas.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-array-bounds
$(OBJ)/compat/freebsd/upstream/dev/mpr/mpr_user.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-aggressive-loop-optimizations
$(OBJ)/compat/freebsd/upstream/dev/mps/mps_sas.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-array-bounds
$(OBJ)/compat/freebsd/upstream/libkern/qsort.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += $(BSD_BRIDGE_QSORT_GCC_WARNINGS)
$(OBJ)/compat/freebsd/upstream/net/iflib.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-unused-but-set-variable
$(OBJ)/compat/freebsd/upstream/dev/oce/oce_sysctl.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += \
		-Wno-unterminated-string-initialization
$(OBJ)/compat/freebsd/upstream/dev/sound/pci/emu10kx.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += \
		-Wno-unterminated-string-initialization
$(OBJ)/compat/freebsd/upstream/dev/hyperv/netvsc/hn_nvs.o \
$(OBJ)/compat/freebsd/upstream/dev/hyperv/netvsc/hn_rndis.o \
$(OBJ)/compat/freebsd/upstream/dev/hyperv/netvsc/if_hn.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -include sys/rmlock.h
$(OBJ)/compat/freebsd/upstream/dev/hyperv/vmbus/vmbus.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -DEDGEOS_BSD_FULL_ACPICA
# The HWT implementation relies on the kernel compilation environment to
# provide these core declarations before its private headers are parsed.
# Keep that environment explicit while preserving the imported sources.
$(OBJ)/compat/freebsd/upstream/dev/hwt/%.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -include sys/queue.h \
		-include sys/cpuset.h -include sys/systm.h -include sys/proc.h \
		-include sys/conf.h -include vm/vm_object.h
$(OBJ)/compat/freebsd/upstream/dev/oce/oce_mbox.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-array-bounds
$(OBJ)/compat/freebsd/upstream/dev/usb/net/if_usie.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-packed-not-aligned
$(OBJ)/compat/freebsd/upstream/dev/bxe/bxe_elink.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-cast-function-type
$(OBJ)/compat/freebsd/upstream/isa/isa_common.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -Wno-error=shift-negative-value
$(OBJ)/compat/freebsd/upstream/dev/liquidio/%.o: \
		BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/dev/liquidio \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/dev/liquidio/base \
		-include sys/malloc.h
$(OBJ)/compat/freebsd/upstream/dev/liquidio/%.o: \
		BSD_BRIDGE_SOURCE_CPPFLAGS += -DSMP

$(OBJ)/arm64-bsd/upstream/libkern/qsort.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += $(BSD_BRIDGE_QSORT_CLANG_WARNINGS)
$(OBJ)/arm64-bsd/upstream/dev/iavf/iavf_osdep.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += -Dinline=
$(OBJ)/arm64-bsd/upstream/dev/ixl/ixl_pf_main.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += -Dinline=
$(OBJ)/arm64-bsd/upstream/dev/oce/oce_sysctl.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += \
		-Wno-unterminated-string-initialization
$(OBJ)/arm64-bsd/upstream/dev/sound/pci/emu10kx.bc: \
		BSD_BRIDGE_ARM64_FRONTEND_FLAGS += \
		-Wno-unterminated-string-initialization
$(OBJ)/arm64-bsd/upstream/dev/hyperv/netvsc/hn_nvs.bc \
$(OBJ)/arm64-bsd/upstream/dev/hyperv/netvsc/hn_rndis.bc \
$(OBJ)/arm64-bsd/upstream/dev/hyperv/netvsc/if_hn.bc: \
		BSD_BRIDGE_ARM64_FRONTEND_FLAGS += -include sys/rmlock.h
$(OBJ)/arm64-bsd/upstream/dev/hyperv/vmbus/vmbus.bc: \
		BSD_BRIDGE_ARM64_FRONTEND_FLAGS += -DEDGEOS_BSD_FULL_ACPICA
$(OBJ)/arm64-bsd/upstream/dev/oce/oce_mbox.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += -Wno-array-bounds
$(OBJ)/arm64-bsd/upstream/dev/bxe/bxe_elink.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += \
		-Wno-cast-function-type-mismatch
$(OBJ)/arm64-bsd/upstream/dev/bwi/%.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += -Wno-shift-count-overflow
$(OBJ)/arm64-bsd/upstream/contrib/ena-com/%.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += \
		-Wno-void-pointer-to-int-cast -Wno-int-to-void-pointer-cast
$(OBJ)/arm64-bsd/upstream/dev/ena/%.obj: \
		BSD_BRIDGE_ARM64_TARGET_FLAGS += \
		-Wno-void-pointer-to-int-cast -Wno-int-to-void-pointer-cast
$(OBJ)/arm64-bsd/upstream/dev/liquidio/%.obj: \
		BSD_BRIDGE_SOURCE_INCLUDE_FLAGS += \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/dev/liquidio \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/dev/liquidio/base \
		-include sys/malloc.h
$(OBJ)/arm64-bsd/upstream/dev/liquidio/%.obj: \
		BSD_BRIDGE_SOURCE_CPPFLAGS += -DSMP

$(OBJ)/compat/freebsd/kern/hwreset.o \
$(OBJ)/compat/freebsd/generated/hwreset_if.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -DFDT
$(OBJ)/compat/freebsd/kern/syscon.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -DFDT
$(OBJ)/arm64-bsd/compat/freebsd/kern/hwreset.bc \
$(OBJ)/arm64-bsd/generated/hwreset_if.bc: \
		BSD_BRIDGE_ARM64_FRONTEND_FLAGS += -DFDT
$(OBJ)/arm64-bsd/compat/freebsd/kern/syscon.bc: \
		BSD_BRIDGE_ARM64_FRONTEND_FLAGS += -DFDT

$(OBJ)/compat/freebsd/upstream/dev/regulator/regulator_fixed.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -include sys/malloc.h
$(OBJ)/arm64-bsd/upstream/dev/regulator/regulator_fixed.bc: \
		BSD_BRIDGE_ARM64_FRONTEND_FLAGS += -include sys/malloc.h
$(OBJ)/compat/freebsd/upstream/dev/sdhci/sdhci_fdt.o \
$(OBJ)/compat/freebsd/upstream/dev/sdhci/sdhci_fdt_gpio.o \
$(OBJ)/compat/freebsd/upstream/dev/sdhci/sdhci_xenon_acpi.o \
$(OBJ)/compat/freebsd/upstream/dev/sdhci/sdhci_xenon_fdt.o: \
		BSD_BRIDGE_X86_COMPILE_FLAGS += -include sys/malloc.h
$(OBJ)/arm64-bsd/upstream/dev/sdhci/sdhci_fdt.bc \
$(OBJ)/arm64-bsd/upstream/dev/sdhci/sdhci_fdt_gpio.bc \
$(OBJ)/arm64-bsd/upstream/dev/sdhci/sdhci_xenon_acpi.bc \
$(OBJ)/arm64-bsd/upstream/dev/sdhci/sdhci_xenon_fdt.bc: \
	BSD_BRIDGE_ARM64_FRONTEND_FLAGS += -include sys/malloc.h

# FreeBSD's ThunderX FDT frontend obtains the MIDR helpers through the
# platform kernel include environment. Make that implicit dependency explicit
# for the standalone bridge frontend while keeping the imported source intact.
$(OBJ)/arm64-bsd/upstream/arm64/cavium/thunder_pcie_fdt.bc: \
	BSD_BRIDGE_ARM64_FRONTEND_FLAGS += -include machine/cpu.h

# The firmware runtime context helper intentionally reads and writes the
# complete floating-point state. Keep the general-register-only policy for all
# other bridge objects while allowing this translation unit to emit FP/SIMD.
$(OBJ)/arm64-bsd/compat/freebsd/arch/arm64/fpu.bc: \
		BSD_BRIDGE_ARM64_FRONTEND_FLAGS := \
		$(filter-out -mgeneral-regs-only,$(BSD_BRIDGE_ARM64_FRONTEND_FLAGS))
$(OBJ)/arm64-bsd/compat/freebsd/arch/arm64/fpu.obj: \
		BSD_BRIDGE_ARM64_MODULE_FINAL_FLAGS := \
		$(filter-out -mgeneral-regs-only,$(BSD_BRIDGE_ARM64_MODULE_FINAL_FLAGS))

$(OBJ)/arm64-bsd/%.bc: $(SRC)/%.c Makefile \
		$(BSD_BRIDGE_GENERATED_STAMP) \
		$(ARM64_AUTOCONF_H) | bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) \
		-emit-llvm -c $< -o $@

$(OBJ)/arm64-bsd/generated/%.bc: $(BSD_BRIDGE_GENERATED)/%.c Makefile \
		$(BSD_BRIDGE_GENERATED_STAMP) $(ARM64_AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) \
		-emit-llvm -c $< -o $@

$(OBJ)/arm64-bsd/upstream/%.bc: $(BSD_BRIDGE_UPSTREAM_SYS)/%.c Makefile \
		$(BSD_BRIDGE_GENERATED_STAMP) $(ARM64_AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) \
		-emit-llvm -c $< -o $@

$(OBJ)/arm64-bsd/%.obj: $(OBJ)/arm64-bsd/%.bc
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_MODULE_FINAL_FLAGS) \
		-c $< -o $@

$(OBJ)/arm64-bsd/upstream/%.obj: \
		$(BSD_BRIDGE_UPSTREAM_SYS)/%.S Makefile \
		$(BSD_BRIDGE_GENERATED_STAMP) $(ARM64_AUTOCONF_H) | \
		bsd-bridge-source-gate
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-DLOCORE -x assembler-with-cpp -c $< -o $@

.PHONY: display-backend-unit drm-runtime-unit virtgpu-runtime-unit virtio-gpu-damage-unit pty-runtime-unit tty-session-unit
.PHONY: xhci-transfer-unit usb-dma-layout-unit
.PHONY: block-registry-unit netdev-registry-unit native-netdev-unit usb-handoff-unit xhci-capability-unit bsd-driver-build-plan-check bsd-driver-package-registry-check bsd-driver-manifest-check bsd-driver-dependency-report bsd-driver-interface-check bsd-driver-modules bsd-driver-modules-x86_64 bsd-driver-modules-arm64 bsd-bridge-acpica-runtime-compile bsd-bridge-arm64-abi-layout-unit bsd-bridge-arm64-handoff-unit bsd-bridge-x86_64-handoff-unit bsd-bridge-audio-unit bsd-bridge-base-headers-unit bsd-bridge-atomic-unit bsd-bridge-allocator-unit bsd-bridge-block-unit bsd-bridge-bootstrap-unit bsd-bridge-bus-dma-unit bsd-bridge-bus-space-unit bsd-bridge-callout-unit bsd-bridge-cam-unit bsd-bridge-cdev-unit bsd-bridge-config-intrhook-unit bsd-bridge-contigmalloc-unit bsd-bridge-device-property-unit bsd-bridge-driver-adapters-unit bsd-bridge-dwc-hdmi-compile bsd-bridge-environment-unit bsd-bridge-epoch-unit bsd-bridge-evdev-unit bsd-bridge-eventhandler-unit bsd-bridge-fdt-inventory-unit bsd-bridge-firmware-frontends-unit bsd-bridge-firmware-metadata-unit bsd-bridge-framebuffer-unit bsd-bridge-gtaskqueue-unit bsd-bridge-handoff-unit bsd-bridge-hash-unit bsd-bridge-interrupt-unit bsd-bridge-intrng-unit bsd-bridge-kernel-link bsd-bridge-kobj-unit bsd-bridge-kthread-unit bsd-bridge-led-unit bsd-bridge-libkern-sort-unit bsd-bridge-linker-unit bsd-bridge-malloc-unit bsd-bridge-module-unit bsd-bridge-network-unit bsd-bridge-newbus-unit bsd-bridge-ofw-unit bsd-bridge-package-unit bsd-bridge-pci-unit bsd-bridge-platform-unit bsd-bridge-pps-unit bsd-bridge-random-unit bsd-bridge-resource-unit bsd-bridge-rss-unit bsd-bridge-sbuf-sysctl-unit bsd-bridge-selinfo-unit bsd-bridge-sglist-unit bsd-bridge-source-gate bsd-bridge-systm-unit bsd-bridge-sync-unit bsd-bridge-taskqueue-unit bsd-bridge-time-unit bsd-bridge-tty-unit bsd-bridge-videomode-unit bsd-bridge-vmem-unit bsd-bridge-watchdog-unit bsd-bridge-virtio-balloon-compile bsd-bridge-virtio-block-compile bsd-bridge-virtio-console-compile bsd-bridge-virtio-core-compile bsd-bridge-virtio-gpu-compile bsd-bridge-virtio-network-compile bsd-bridge-virtio-pci-compile bsd-bridge-virtio-random-compile bsd-bridge-virtio-scmi-compile bsd-bridge-virtio-transport-compile bsd-bridge-virtqueue-compile bsd-bridge-vm-page-unit
.PHONY: bsd-bridge-bitstring-unit

display-backend-unit: tools/tests/display_backend_unit.c $(SRC)/display.c \
		$(SRC)/display_edid.c include/display.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-iquote $(INC) \
		tools/tests/display_backend_unit.c $(SRC)/display.c \
		$(SRC)/display_edid.c \
		-o $(OUT)/tests/display_backend_unit
	@$(OUT)/tests/display_backend_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/display_backend_unit.c $(SRC)/display.c \
		$(SRC)/display_edid.c \
		-o $(OUT)/tests/display_backend_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/display_backend_sanitize

bsd-bridge-arm64-abi-layout-unit: \
		tools/tests/bsd_bridge_arm64_layout_unit.c arm64-syncconfig
	@mkdir -p $(OUT)/tests
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) \
		-emit-llvm -c $< \
		-o $(OUT)/tests/bsd_bridge_arm64_layout.bc
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_MODULE_FINAL_FLAGS) \
		-c $(OUT)/tests/bsd_bridge_arm64_layout.bc \
		-o $(OUT)/tests/bsd_bridge_arm64_layout.obj
	@llvm-readobj --file-headers \
		$(OUT)/tests/bsd_bridge_arm64_layout.obj | \
		rg -q '^Format: COFF-ARM64$$'
	@printf 'bsd_bridge_arm64_abi_layout_unit: PASS\n'

drm-runtime-unit: tools/tests/drm_runtime_unit.c \
		$(SRC)/kernel/drm_runtime.c $(SRC)/kernel/virtgpu_runtime.c \
		$(SRC)/kernel/deferred_work.c \
		$(SRC)/display.c $(SRC)/display_edid.c \
		include/kernel/drm_runtime.h \
		include/kernel/virtgpu_runtime.h include/display.h include/fb.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-D_POSIX_C_SOURCE=200112L \
		-iquote $(INC) \
		tools/tests/drm_runtime_unit.c \
		$(SRC)/kernel/drm_runtime.c $(SRC)/kernel/virtgpu_runtime.c \
		$(SRC)/kernel/deferred_work.c \
		$(SRC)/display.c $(SRC)/display_edid.c \
		-o $(OUT)/tests/drm_runtime_unit
	@$(OUT)/tests/drm_runtime_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-D_POSIX_C_SOURCE=200112L \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/drm_runtime_unit.c \
		$(SRC)/kernel/drm_runtime.c $(SRC)/kernel/virtgpu_runtime.c \
		$(SRC)/kernel/deferred_work.c \
		$(SRC)/display.c $(SRC)/display_edid.c \
		-o $(OUT)/tests/drm_runtime_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/drm_runtime_sanitize

virtgpu-runtime-unit: tools/tests/virtgpu_runtime_unit.c \
		$(SRC)/kernel/virtgpu_runtime.c \
		include/kernel/virtgpu_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-D_POSIX_C_SOURCE=200112L \
		-iquote $(INC) \
		tools/tests/virtgpu_runtime_unit.c \
		$(SRC)/kernel/virtgpu_runtime.c \
		-o $(OUT)/tests/virtgpu_runtime_unit
	@$(OUT)/tests/virtgpu_runtime_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-D_POSIX_C_SOURCE=200112L \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/virtgpu_runtime_unit.c \
		$(SRC)/kernel/virtgpu_runtime.c \
		-o $(OUT)/tests/virtgpu_runtime_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/virtgpu_runtime_sanitize

virtio-gpu-damage-unit: tools/tests/virtio_gpu_damage_unit.c \
		$(SRC)/drivers/virtio/virtio_gpu_damage.c \
		include/drivers/virtio_gpu_damage.h include/display.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-iquote $(INC) \
		tools/tests/virtio_gpu_damage_unit.c \
		$(SRC)/drivers/virtio/virtio_gpu_damage.c \
		-o $(OUT)/tests/virtio_gpu_damage_unit
	@$(OUT)/tests/virtio_gpu_damage_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/virtio_gpu_damage_unit.c \
		$(SRC)/drivers/virtio/virtio_gpu_damage.c \
		-o $(OUT)/tests/virtio_gpu_damage_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/virtio_gpu_damage_sanitize

bsd-bridge-ofw-unit: tools/tests/bsd_bridge_ofw_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/ofw_bus_map.c \
		$(SRC)/compat/freebsd/kern/systm.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-Wno-sign-compare \
		-D_POSIX_C_SOURCE=200112L \
		-DBSD_BRIDGE_HOST_TEST -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_ofw_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/ofw_bus_map.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_ro.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_addresses.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_strerror.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_sw.c \
		-o $(OUT)/tests/bsd_bridge_ofw_unit
	@$(OUT)/tests/bsd_bridge_ofw_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-Wno-sign-compare \
		-D_POSIX_C_SOURCE=200112L \
		-DBSD_BRIDGE_HOST_TEST -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_ofw_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/ofw_bus_map.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_ro.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_addresses.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_strerror.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_sw.c \
		-o $(OUT)/tests/bsd_bridge_ofw_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_ofw_sanitize

arm64-rpi5-fdt-acceptance: tools/tests/rpi5_fdt_acceptance.c \
		$(SRC)/arch/arm64/kernel/platform.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/ofw_bus_map.c \
		$(SRC)/compat/freebsd/kern/systm.c
	@if [ -z "$$EDGEOS_RPI5_DTB" ] || [ ! -f "$$EDGEOS_RPI5_DTB" ]; then \
		echo "[arm64] set EDGEOS_RPI5_DTB to bcm2712-rpi-5-b.dtb"; exit 1; \
	fi
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-Wno-sign-compare -D_POSIX_C_SOURCE=200112L \
		-DBSD_BRIDGE_HOST_TEST -DEDGEOS_BSD_BRIDGE \
		-DCONFIG_BSD_DRIVER_BRIDGE -DCONFIG_DEVICE_TREE \
		-I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		tools/tests/rpi5_fdt_acceptance.c \
		$(SRC)/arch/arm64/kernel/platform.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/ofw_bus_map.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_ro.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_rw.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_wip.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_addresses.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_strerror.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_sw.c \
		-o $(OUT)/tests/rpi5_fdt_acceptance
	@$(OUT)/tests/rpi5_fdt_acceptance "$$EDGEOS_RPI5_DTB"

bsd-bridge-device-property-unit: \
		tools/tests/bsd_bridge_device_property_unit.c \
		$(SRC)/compat/freebsd/kern/device_property.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -Wno-unused-parameter \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include stddef.h \
		-include sys/queue.h \
		tools/tests/bsd_bridge_device_property_unit.c \
		$(SRC)/compat/freebsd/kern/device_property.c \
		-o $(OUT)/tests/bsd_bridge_device_property_unit
	@$(OUT)/tests/bsd_bridge_device_property_unit
	@$(HOST_CC) -std=c11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -Wno-unused-parameter \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include stddef.h \
		-include sys/queue.h \
		tools/tests/bsd_bridge_device_property_unit.c \
		$(SRC)/compat/freebsd/kern/device_property.c \
		-o $(OUT)/tests/bsd_bridge_device_property_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_device_property_sanitize

bsd-bridge-fdt-inventory-unit: bsd-driver-interface-check \
		tools/tests/bsd_bridge_fdt_inventory_unit.c \
		$(SRC)/compat/freebsd/kern/fdt_inventory.c \
		$(SRC)/compat/freebsd/kern/firmware.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/platform.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-Wno-sign-compare -D_POSIX_C_SOURCE=200112L \
		-DBSD_BRIDGE_HOST_TEST -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt \
		-iquote $(INC) -idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_fdt_inventory_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/fdt_inventory.c \
		$(SRC)/compat/freebsd/kern/firmware.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/platform.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_ro.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_addresses.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_strerror.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_sw.c \
		-o $(OUT)/tests/bsd_bridge_fdt_inventory_unit
	@$(OUT)/tests/bsd_bridge_fdt_inventory_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-Wno-sign-compare -D_POSIX_C_SOURCE=200112L \
		-DBSD_BRIDGE_HOST_TEST -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt \
		-iquote $(INC) -idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_fdt_inventory_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/fdt_inventory.c \
		$(SRC)/compat/freebsd/kern/firmware.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/ofw.c \
		$(SRC)/compat/freebsd/kern/platform.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_ro.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_addresses.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_strerror.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/contrib/libfdt/fdt_sw.c \
		-o $(OUT)/tests/bsd_bridge_fdt_inventory_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_fdt_inventory_sanitize

bsd-driver-modules: bsd-driver-modules-x86_64 bsd-driver-modules-arm64 \
		tools/bsd_bridge/check_module_symbols.py \
		$(SRC)/compat/freebsd/kern/driver_symbols.c
	@python3 tools/bsd_bridge/check_module_symbols.py \
		--nm $(LLVM_NM) \
		--exports $(SRC)/compat/freebsd/kern/driver_symbols.c \
		$(foreach module,$(BSD_BRIDGE_LOADABLE_X86_MODULES),\
			--module x86_64=$(module)) \
		$(foreach module,$(BSD_BRIDGE_LOADABLE_ARM64_MODULES),\
			--module arm64=$(module))

bsd-driver-modules-x86_64: $(BSD_BRIDGE_LOADABLE_X86_MODULES)

bsd-driver-modules-arm64: $(BSD_BRIDGE_LOADABLE_ARM64_MODULES)

bsd-bridge-driver-path-unit: \
		tools/tests/bsd_bridge_driver_path_unit.c \
		$(SRC)/compat/freebsd/kern/driver_path.c \
		include/compat/freebsd/edgeos/driver_loader.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DCONFIG_BSD_DRIVER_MODULE_DIRECTORY=\"/opt/edgeos/modules///\" \
		-iquote $(INC) \
		tools/tests/bsd_bridge_driver_path_unit.c \
		$(SRC)/compat/freebsd/kern/driver_path.c \
		-o $(OUT)/tests/bsd_bridge_driver_path_unit
	@$(OUT)/tests/bsd_bridge_driver_path_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-DCONFIG_BSD_DRIVER_MODULE_DIRECTORY=\"/opt/edgeos/modules///\" \
		-iquote $(INC) \
		tools/tests/bsd_bridge_driver_path_unit.c \
		$(SRC)/compat/freebsd/kern/driver_path.c \
		-o $(OUT)/tests/bsd_bridge_driver_path_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_driver_path_sanitize

bsd-bridge-arm64-fdt-fallback-compile: \
		$(SRC)/arch/arm64/kernel/interrupt.c \
		$(SRC)/drivers/virtio/virtio_net_mmio.c
	@mkdir -p $(OUT)/tests
	@$(ARM64_EFI_CC) -I$(INC) -I$(SRC) \
		-target aarch64-unknown-windows -std=gnu11 -O2 \
		-ffreestanding -fshort-wchar -fno-stack-protector -fno-builtin \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		-DCONFIG_BSD_DRIVER_BRIDGE=1 \
		-c $(SRC)/arch/arm64/kernel/interrupt.c \
		-o $(OUT)/tests/arm64_interrupt_fdt_fallback.obj
	@$(ARM64_EFI_CC) -I$(INC) -I$(SRC) \
		-target aarch64-unknown-windows -std=gnu11 -O2 \
		-ffreestanding -fshort-wchar -fno-stack-protector -fno-builtin \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		-DCONFIG_BSD_DRIVER_BRIDGE=1 \
		-c $(SRC)/drivers/virtio/virtio_net_mmio.c \
		-o $(OUT)/tests/arm64_virtio_net_fdt_fallback.obj

bsd-bridge-virtio-balloon-compile \
bsd-bridge-virtio-block-compile \
bsd-bridge-virtio-console-compile \
bsd-bridge-virtio-core-compile \
bsd-bridge-virtio-gpu-compile \
bsd-bridge-virtio-network-compile \
bsd-bridge-virtio-pci-compile \
bsd-bridge-virtio-random-compile \
bsd-bridge-virtio-scmi-compile \
bsd-bridge-virtio-scsi-compile \
bsd-bridge-virtio-transport-compile \
bsd-bridge-virtqueue-compile: BSD_BRIDGE_SOURCE_CPPFLAGS += \
	$(BSD_BRIDGE_PACKAGE_FREEBSD_VIRTIO_CPPFLAGS)

netdev-registry-unit: tools/tests/netdev_registry_unit.c $(SRC)/net/netdev.c include/net/netdev.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/netdev_registry_unit.c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/netdev_registry_unit
	@$(OUT)/tests/netdev_registry_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/netdev_registry_unit.c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/netdev_registry_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/netdev_registry_sanitize
	@$(CC) -std=c11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror -I$(INC) \
		-c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/netdev_registry_x86_64.o
	@$(AARCH64_CC) -std=c11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror -I$(INC) \
		-c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/netdev_registry_arm64.o

native-netdev-unit: netdev-registry-unit tools/tests/native_netdev_unit.c $(SRC)/net/native_netdev.c include/net/native_netdev.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/native_netdev_unit.c $(SRC)/net/native_netdev.c \
		$(SRC)/net/netdev.c -o $(OUT)/tests/native_netdev_unit
	@$(OUT)/tests/native_netdev_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/native_netdev_unit.c $(SRC)/net/native_netdev.c \
		$(SRC)/net/netdev.c -o $(OUT)/tests/native_netdev_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/native_netdev_sanitize

bsd-bridge-network-unit: native-netdev-unit tools/tests/bsd_bridge_network_unit.c $(SRC)/compat/freebsd/kern/bpf.c $(SRC)/compat/freebsd/kern/counter.c $(SRC)/compat/freebsd/kern/ifnet.c $(SRC)/compat/freebsd/kern/in.c $(SRC)/compat/freebsd/kern/ip6.c $(SRC)/compat/freebsd/kern/mbuf.c $(SRC)/compat/freebsd/kern/netisr.c $(SRC)/compat/freebsd/kern/random.c $(SRC)/compat/freebsd/kern/uma.c include/compat/freebsd/net/bpf.h include/compat/freebsd/sys/counter.h include/compat/freebsd/sys/mbuf.h include/compat/freebsd/net/if_var.h include/compat/freebsd/net/ethernet.h include/compat/freebsd/vm/uma.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_network_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bpf.c \
		$(SRC)/compat/freebsd/kern/counter.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/mbuf.c \
		$(SRC)/compat/freebsd/kern/random.c \
		$(SRC)/compat/freebsd/kern/tcp_lro.c \
		$(SRC)/compat/freebsd/kern/uma.c \
		$(SRC)/compat/freebsd/kern/ifnet.c \
		$(SRC)/compat/freebsd/kern/in.c \
		$(SRC)/compat/freebsd/kern/in_cksum.c \
		$(SRC)/compat/freebsd/kern/ip6.c \
		$(SRC)/compat/freebsd/kern/netisr.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/net/netdev.c \
		-o $(OUT)/tests/bsd_bridge_network_unit
	@$(OUT)/tests/bsd_bridge_network_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_network_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bpf.c \
		$(SRC)/compat/freebsd/kern/counter.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/mbuf.c \
		$(SRC)/compat/freebsd/kern/random.c \
		$(SRC)/compat/freebsd/kern/tcp_lro.c \
		$(SRC)/compat/freebsd/kern/uma.c \
		$(SRC)/compat/freebsd/kern/ifnet.c \
		$(SRC)/compat/freebsd/kern/in.c \
		$(SRC)/compat/freebsd/kern/in_cksum.c \
		$(SRC)/compat/freebsd/kern/ip6.c \
		$(SRC)/compat/freebsd/kern/netisr.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/net/netdev.c \
		-o $(OUT)/tests/bsd_bridge_network_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_network_sanitize
	@$(CC) $(CFLAGS) -Werror \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c $(SRC)/compat/freebsd/kern/ifnet.c \
		-o $(OUT)/tests/bsd_bridge_ifnet_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -I$(INC)/compat/freebsd \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include $(AUTOCONF_H) \
		-std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/ifnet.c \
		-o $(OUT)/tests/bsd_bridge_ifnet_arm64.o

bsd-bridge-rss-unit: tools/tests/bsd_bridge_rss_unit.c \
		$(SRC)/compat/freebsd/kern/rss.c \
		include/compat/freebsd/net/rss_config.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_rss_unit.c \
		$(SRC)/compat/freebsd/kern/rss.c \
		-o $(OUT)/tests/bsd_bridge_rss_unit
	@$(OUT)/tests/bsd_bridge_rss_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_rss_unit.c \
		$(SRC)/compat/freebsd/kern/rss.c \
		-o $(OUT)/tests/bsd_bridge_rss_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_rss_sanitize
	@$(CC) $(CFLAGS) -Werror -I$(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-c $(SRC)/compat/freebsd/kern/rss.c \
		-o $(OUT)/tests/bsd_bridge_rss_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -I$(INC)/compat/freebsd \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/rss.c \
		-o $(OUT)/tests/bsd_bridge_rss_arm64.o

bsd-bridge-cam-unit: tools/tests/bsd_bridge_cam_unit.c $(SRC)/compat/freebsd/kern/cam.c include/compat/freebsd/edgeos/cam.h include/compat/freebsd/cam/cam_ccb.h include/compat/freebsd/cam/cam_sim.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_cam_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/block.c \
		$(SRC)/compat/freebsd/kern/cam.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_cam_unit
	@$(OUT)/tests/bsd_bridge_cam_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_cam_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/block.c \
		$(SRC)/compat/freebsd/kern/cam.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_cam_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_cam_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/cam.c \
		-o $(OUT)/tests/bsd_bridge_cam_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/cam.c \
		-o $(OUT)/tests/bsd_bridge_cam_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/cam.c \
		-o $(OUT)/tests/bsd_bridge_cam_arm64_coff.obj

block-registry-unit: tools/tests/block_registry_unit.c $(SRC)/block/block.c include/block/block.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -ffreestanding -fno-builtin \
		-Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/block_registry_unit.c $(SRC)/block/block.c \
		-o $(OUT)/tests/block_registry_unit
	@$(OUT)/tests/block_registry_unit
	@$(HOST_CC) -std=c11 -O1 -g -ffreestanding -fno-builtin \
		-Wall -Wextra -Werror -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/block_registry_unit.c $(SRC)/block/block.c \
		-o $(OUT)/tests/block_registry_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/block_registry_sanitize

bsd-bridge-block-unit: block-registry-unit tools/tests/bsd_bridge_block_unit.c $(SRC)/compat/freebsd/kern/block.c $(SRC)/compat/freebsd/kern/slicer.c include/compat/freebsd/edgeos/block.h include/compat/freebsd/edgeos/slicer.h include/compat/freebsd/sys/bio.h include/compat/freebsd/geom/geom.h include/compat/freebsd/geom/geom_disk.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) \
		tools/tests/bsd_bridge_block_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/block.c \
		$(SRC)/compat/freebsd/kern/slicer.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_block_unit
	@$(OUT)/tests/bsd_bridge_block_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_block_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/block.c \
		$(SRC)/compat/freebsd/kern/slicer.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_block_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_block_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/block.c \
		-o $(OUT)/tests/bsd_bridge_block_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/block.c \
		-o $(OUT)/tests/bsd_bridge_block_arm64.o

bsd-bridge-source-gate: $(BSD_BRIDGE_BUILD_PLAN)
	@python3 tools/bsd_bridge/verify_sources.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR)

bsd-driver-build-plan-check: $(BSD_BRIDGE_BUILD_PLAN)
	python3 tools/bsd_bridge/generate_build_plan.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--capability-dir $(BSD_DRIVER_CAPABILITY_DIR) \
		--check $(BSD_BRIDGE_BUILD_PLAN)

bsd-driver-package-registry-check: $(BSD_BRIDGE_GENERATED_STAMP)
	python3 tools/bsd_bridge/generate_package_registry.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--capability-dir $(BSD_DRIVER_CAPABILITY_DIR) \
		--check $(BSD_BRIDGE_PACKAGE_REGISTRY)

bsd-driver-manifest-check: bsd-driver-build-plan-check \
		bsd-driver-package-registry-check
	python3 tools/bsd_bridge/verify_sources.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR)
	python3 tools/tests/bsd_bridge_manifest_test.py

bsd-driver-dependency-report:
	python3 tools/bsd_bridge/scan_dependencies.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR)

bsd-driver-interface-check:
	python3 tools/bsd_bridge/generate_interfaces.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR)

bsd-bridge-kernel-link: bsd-bridge-bootstrap-unit bsd-bridge-config-intrhook-unit bsd-bridge-driver-adapters-unit bsd-bridge-dwc-hdmi-compile bsd-bridge-environment-unit bsd-bridge-evdev-unit bsd-bridge-handoff-unit bsd-bridge-arm64-abi-layout-unit bsd-bridge-arm64-handoff-unit bsd-bridge-x86_64-handoff-unit usb-handoff-unit bsd-bridge-platform-unit bsd-bridge-fdt-inventory-unit bsd-bridge-firmware-frontends-unit bsd-bridge-driver-path-unit bsd-bridge-arm64-fdt-fallback-compile bsd-bridge-audio-unit bsd-bridge-block-unit bsd-bridge-cam-unit bsd-bridge-network-unit bsd-bridge-rss-unit bsd-bridge-sglist-unit bsd-bridge-contigmalloc-unit bsd-bridge-eventhandler-unit bsd-bridge-watchdog-unit bsd-bridge-framebuffer-unit bsd-bridge-videomode-unit bsd-bridge-random-unit bsd-bridge-kthread-unit bsd-bridge-taskqueue-unit bsd-bridge-gtaskqueue-unit bsd-bridge-callout-unit bsd-bridge-led-unit bsd-bridge-selinfo-unit bsd-bridge-cdev-unit bsd-bridge-time-unit bsd-bridge-tty-unit bsd-bridge-vm-page-unit bsd-bridge-package-unit bsd-bridge-pci-unit bsd-bridge-arm64-pci-unit bsd-bridge-libkern-sort-unit bsd-bridge-virtio-random-compile bsd-bridge-virtio-gpu-compile bsd-bridge-virtio-scmi-compile bsd-bridge-virtio-balloon-compile bsd-bridge-virtio-console-compile bsd-bridge-virtio-block-compile bsd-bridge-virtio-network-compile bsd-bridge-virtio-scsi-compile
bsd-bridge-kernel-link: bsd-bridge-bitstring-unit
	$(MAKE) CONFIG_BSD_DRIVER_BRIDGE=y $(TARGET)
	$(MAKE) ARM64_CONFIG_BSD_DRIVER_BRIDGE=y $(ARM64_UEFI_EFI)
	@strings $(TARGET) | \
		rg -Fq '[bsd-bridge] runtime ready; device handoff disabled'
	@strings $(ARM64_UEFI_EFI) | \
		rg -Fq 'arm64: BSD driver bridge runtime ready'
	@set -e; for package in $(BSD_BRIDGE_PACKAGE_IDS); do \
		strings $(TARGET) | rg -Fq "$$package"; \
		strings $(ARM64_UEFI_EFI) | rg -Fq "$$package"; \
	done

bsd-bridge-audio-unit: bsd-driver-interface-check tools/tests/bsd_bridge_audio_unit.c $(SRC)/compat/freebsd/kern/audio.c $(SRC)/compat/freebsd/kern/bus_dma.c $(SRC)/dev/alsa.c $(SRC)/drivers/audio/audio.c include/compat/freebsd/edgeos/audio.h include/compat/freebsd/edgeos/bus_dma.h include/dev/alsa.h include/drivers/audio.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -ffreestanding -fno-builtin -nostdinc \
		-Wall -Wextra -Werror -Wno-unused-parameter \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-DCONFIG_BSD_DRIVER_BRIDGE=1 \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(SRC) \
		-include stddef.h -include sys/queue.h \
		tools/tests/bsd_bridge_audio_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/audio.c \
		$(SRC)/compat/freebsd/kern/bus_dma.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/dev/alsa.c \
		$(SRC)/drivers/audio/audio.c \
		$(BSD_BRIDGE_GENERATED)/channel_if.c \
		$(BSD_BRIDGE_GENERATED)/mixer_if.c \
		-o $(OUT)/tests/bsd_bridge_audio_unit
	@$(OUT)/tests/bsd_bridge_audio_unit
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/audio.c \
		-o $(OUT)/tests/bsd_bridge_audio_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/audio.c \
		-o $(OUT)/tests/bsd_bridge_audio_arm64_coff.obj

bsd-bridge-bootstrap-unit: tools/tests/bsd_bridge_bootstrap_unit.c $(SRC)/compat/freebsd/kern/bootstrap.c include/compat/freebsd/edgeos/audio.h include/compat/freebsd/edgeos/bootstrap.h include/compat/freebsd/edgeos/driver_adapters.h include/compat/freebsd/edgeos/keyboard.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_bootstrap_unit.c \
		$(SRC)/compat/freebsd/kern/bootstrap.c \
		-o $(OUT)/tests/bsd_bridge_bootstrap_unit
	@$(OUT)/tests/bsd_bridge_bootstrap_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_bootstrap_unit.c \
		$(SRC)/compat/freebsd/kern/bootstrap.c \
		-o $(OUT)/tests/bsd_bridge_bootstrap_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_bootstrap_sanitize

bsd-bridge-driver-adapters-unit: \
		tools/tests/bsd_bridge_driver_adapters_unit.c \
		$(SRC)/compat/freebsd/drivers/adapters.c \
		include/compat/freebsd/edgeos/driver_adapters.h \
		include/compat/freebsd/edgeos/driver_hooks.h \
		include/compat/freebsd/edgeos/bus_dma.h \
		include/compat/freebsd/edgeos/bus_space.h \
		include/compat/freebsd/edgeos/mfi_adapter.h \
		include/compat/freebsd/edgeos/pci.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_driver_adapters_unit.c \
		$(SRC)/compat/freebsd/drivers/adapters.c \
		-o $(OUT)/tests/bsd_bridge_driver_adapters_unit
	@$(OUT)/tests/bsd_bridge_driver_adapters_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_driver_adapters_unit.c \
		$(SRC)/compat/freebsd/drivers/adapters.c \
		-o $(OUT)/tests/bsd_bridge_driver_adapters_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_driver_adapters_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/drivers/adapters.c \
		-o $(OUT)/tests/bsd_bridge_driver_adapters_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/drivers/adapters.c \
		-o $(OUT)/tests/bsd_bridge_driver_adapters_arm64.obj

bsd-bridge-handoff-unit: tools/tests/bsd_bridge_handoff_unit.c $(SRC)/compat/freebsd/kern/handoff.c include/compat/freebsd/edgeos/handoff.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-DCONFIG_NET=1 \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_handoff_unit.c \
		$(SRC)/compat/freebsd/kern/handoff.c \
		-o $(OUT)/tests/bsd_bridge_handoff_unit
	@$(OUT)/tests/bsd_bridge_handoff_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-DCONFIG_NET=1 \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_handoff_unit.c \
		$(SRC)/compat/freebsd/kern/handoff.c \
		-o $(OUT)/tests/bsd_bridge_handoff_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_handoff_sanitize
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/kern/handoff.c \
		-o $(OUT)/tests/bsd_bridge_handoff_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/handoff.c \
		-o $(OUT)/tests/bsd_bridge_handoff_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-I$(INC) -I$(SRC) -DCONFIG_NET=1 \
		-std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/handoff.c \
		-o $(OUT)/tests/bsd_bridge_handoff_arm64_coff.o

bsd-bridge-arm64-handoff-unit: native-netdev-unit tools/tests/bsd_bridge_arm64_handoff_unit.c $(SRC)/compat/freebsd/arch/arm64/handoff.c include/compat/freebsd/edgeos/arm64_handoff.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_arm64_handoff_unit.c \
		$(SRC)/compat/freebsd/arch/arm64/handoff.c \
		$(SRC)/net/native_netdev.c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/bsd_bridge_arm64_handoff_unit
	@$(OUT)/tests/bsd_bridge_arm64_handoff_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_arm64_handoff_unit.c \
		$(SRC)/compat/freebsd/arch/arm64/handoff.c \
		$(SRC)/net/native_netdev.c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/bsd_bridge_arm64_handoff_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_arm64_handoff_sanitize

bsd-bridge-x86_64-handoff-unit: native-netdev-unit tools/tests/bsd_bridge_x86_64_handoff_unit.c $(SRC)/compat/freebsd/arch/x86_64/handoff.c include/compat/freebsd/edgeos/x86_64_handoff.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_x86_64_handoff_unit.c \
		$(SRC)/compat/freebsd/arch/x86_64/handoff.c \
		$(SRC)/net/native_netdev.c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/bsd_bridge_x86_64_handoff_unit
	@$(OUT)/tests/bsd_bridge_x86_64_handoff_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_x86_64_handoff_unit.c \
		$(SRC)/compat/freebsd/arch/x86_64/handoff.c \
		$(SRC)/net/native_netdev.c $(SRC)/net/netdev.c \
		-o $(OUT)/tests/bsd_bridge_x86_64_handoff_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_x86_64_handoff_sanitize

usb-handoff-unit: tools/tests/usb_handoff_unit.c $(SRC)/drivers/usb/handoff.c include/drivers/usb_handoff.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/usb_handoff_unit.c \
		$(SRC)/drivers/usb/handoff.c \
		-o $(OUT)/tests/usb_handoff_unit
	@$(OUT)/tests/usb_handoff_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/usb_handoff_unit.c \
		$(SRC)/drivers/usb/handoff.c \
		-o $(OUT)/tests/usb_handoff_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/usb_handoff_sanitize

xhci-capability-unit: tools/tests/xhci_capability_unit.c $(SRC)/drivers/usb/xhci_capability.c include/drivers/xhci_capability.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/xhci_capability_unit.c \
		$(SRC)/drivers/usb/xhci_capability.c \
		-o $(OUT)/tests/xhci_capability_unit
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/xhci_capability_unit

xhci-transfer-unit: tools/tests/xhci_transfer_unit.c $(SRC)/drivers/usb/xhci_transfer.c include/drivers/xhci_transfer.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/xhci_transfer_unit.c \
		$(SRC)/drivers/usb/xhci_transfer.c \
		-o $(OUT)/tests/xhci_transfer_unit
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/xhci_transfer_unit

usb-dma-layout-unit: tools/tests/usb_dma_layout_unit.c $(SRC)/drivers/usb/usb_dma_layout.c include/drivers/usb_dma_layout.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/usb_dma_layout_unit.c \
		$(SRC)/drivers/usb/usb_dma_layout.c \
		-o $(OUT)/tests/usb_dma_layout_unit
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/usb_dma_layout_unit

bsd-bridge-virtqueue-compile: bsd-bridge-virtio-core-compile

bsd-bridge-sbuf-sysctl-unit:
	@mkdir -p $(BSD_BRIDGE_GENERATED) $(OUT)/tests
	@python3 tools/bsd_bridge/generate_interfaces.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--output $(BSD_BRIDGE_GENERATED)
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -iquote $(INC) -iquote $(SRC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_sbuf_sysctl_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/counter.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_sbuf_sysctl_unit
	@$(OUT)/tests/bsd_bridge_sbuf_sysctl_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer -iquote $(INC) -iquote $(SRC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_sbuf_sysctl_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/counter.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_sbuf_sysctl_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_sbuf_sysctl_sanitize
	@set -e; for source in $(BSD_BRIDGE_SUPPORT_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(CC) -I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) \
			$(CFLAGS) -Werror $(BSD_BRIDGE_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-c "$$source" \
			-o "$(OUT)/tests/bsd_bridge_$${name}_x86_64.o"; \
	done
	@set -e; for source in $(BSD_BRIDGE_SUPPORT_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
			-fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) \
			-c "$$source" \
			-o "$(OUT)/tests/bsd_bridge_$${name}_arm64.o"; \
	done
	@set -e; for source in $(BSD_BRIDGE_SUPPORT_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(ARM64_EFI_CC) -target aarch64-unknown-windows \
			-D__STDC__=1 -std=gnu11 -O2 -ffreestanding \
			-fno-builtin -fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_COFF_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) \
			-c "$$source" \
			-o "$(OUT)/tests/bsd_bridge_$${name}_arm64_coff.obj"; \
	done

bsd-bridge-virtio-core-compile: bsd-bridge-sbuf-sysctl-unit
	@mkdir -p $(BSD_BRIDGE_GENERATED) $(OUT)/tests
	@python3 tools/bsd_bridge/generate_interfaces.py \
		--manifest-dir $(BSD_DRIVER_MANIFEST_DIR) \
		--output $(BSD_BRIDGE_GENERATED)
	@set -e; for source in \
		$(addprefix $(BSD_BRIDGE_GENERATED)/,$(BSD_BRIDGE_X86_64_GENERATED_SRCS)) \
		$(BSD_BRIDGE_CORE_SRCS); do \
		name=$$(basename "$$source" .c); \
		extra_flags=; \
		for mapping in $(BSD_BRIDGE_X86_64_GENERATED_COMPILE_MAPPINGS); do \
			case "$$mapping" in \
			"$$name="*) extra_flags="$$extra_flags $${mapping#*=}";; \
			esac; \
		done; \
		$(CC) $$extra_flags $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_x86_64.o"; \
	done
	@set -e; for source in \
		$(addprefix $(BSD_BRIDGE_GENERATED)/,$(BSD_BRIDGE_ARM64_GENERATED_SRCS)) \
		$(BSD_BRIDGE_CORE_SRCS); do \
		name=$$(basename "$$source" .c); \
		extra_flags=; \
		for mapping in $(BSD_BRIDGE_ARM64_GENERATED_COMPILE_MAPPINGS); do \
			case "$$mapping" in \
			"$$name="*) extra_flags="$$extra_flags $${mapping#*=}";; \
			esac; \
		done; \
		$(AARCH64_CC) $$extra_flags \
			-std=gnu11 -O2 -ffreestanding -fno-builtin \
			-fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64.o"; \
	done
	@set -e; for source in \
		$(addprefix $(BSD_BRIDGE_GENERATED)/,$(BSD_BRIDGE_ARM64_GENERATED_SRCS)) \
		$(BSD_BRIDGE_CORE_SRCS); do \
		name=$$(basename "$$source" .c); \
		extra_flags=; \
		for mapping in $(BSD_BRIDGE_ARM64_GENERATED_COMPILE_MAPPINGS); do \
			case "$$mapping" in \
			"$$name="*) extra_flags="$$extra_flags $${mapping#*=}";; \
			esac; \
		done; \
		$(ARM64_EFI_CC) $$extra_flags \
			-target aarch64-unknown-windows \
			-D__STDC__=1 -std=gnu11 -O2 -ffreestanding \
			-fno-builtin -fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_COFF_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64_coff.obj"; \
	done
	@llvm-readobj --sections \
		$(OUT)/tests/freebsd_virtio_arm64_coff.obj | \
		rg -q '.bsdsi[$$]m'
	@llvm-readobj --sections \
		$(OUT)/tests/freebsd_virtio_arm64_coff.obj | \
		rg -q '.bsdmm[$$]m'

bsd-bridge-virtio-pci-compile: bsd-bridge-virtio-core-compile
	@set -e; for source in $(BSD_BRIDGE_PCI_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_x86_64.o"; \
	done
	@set -e; for source in $(BSD_BRIDGE_PCI_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
			-fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64.o"; \
	done
	@set -e; for source in $(BSD_BRIDGE_PCI_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(ARM64_EFI_CC) -target aarch64-unknown-windows \
			-D__STDC__=1 -std=gnu11 -O2 -ffreestanding \
			-fno-builtin -fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_COFF_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64_coff.obj"; \
	done

bsd-bridge-virtio-transport-compile: bsd-bridge-virtio-pci-compile
	@set -e; for source in \
		$(BSD_BRIDGE_MMIO_SRCS) $(BSD_BRIDGE_MMIO_FIRMWARE_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) -c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_x86_64.o"; \
	done
	@set -e; for source in \
		$(BSD_BRIDGE_MMIO_SRCS) $(BSD_BRIDGE_MMIO_FIRMWARE_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
			-fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			$(BSD_BRIDGE_SOURCE_CPPFLAGS) \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) -c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64.o"; \
	done
	@set -e; for source in \
		$(BSD_BRIDGE_MMIO_SRCS) $(BSD_BRIDGE_MMIO_FIRMWARE_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64_coff.obj"; \
	done

bsd-bridge-virtio-random-compile: bsd-bridge-virtio-transport-compile
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_RANDOM_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_random_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_RANDOM_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_random_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-D__STDC__=1 -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_COFF_SOURCE_WARNINGS) \
		-Wno-missing-field-initializers \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_RANDOM_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_random_arm64_coff.obj

bsd-bridge-virtio-gpu-compile: bsd-bridge-virtio-random-compile
	@set -e; for source in \
		$(BSD_BRIDGE_GPU_SRCS) $(BSD_BRIDGE_FRAMEBUFFER_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_x86_64.o"; \
	done
	@set -e; for source in \
		$(BSD_BRIDGE_GPU_SRCS) $(BSD_BRIDGE_FRAMEBUFFER_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
			-fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64.o"; \
	done
	@set -e; for source in \
		$(BSD_BRIDGE_GPU_SRCS) $(BSD_BRIDGE_FRAMEBUFFER_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
			-c "$$source" \
			-o "$(OUT)/tests/freebsd_$${name}_arm64_coff.obj"; \
	done

bsd-bridge-virtio-scmi-compile: bsd-bridge-virtio-gpu-compile
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_SCMI_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_scmi_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_SCMI_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_scmi_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_SCMI_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_scmi_arm64_coff.obj

bsd-bridge-virtio-balloon-compile: bsd-bridge-virtio-scmi-compile
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_BALLOON_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_balloon_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_BALLOON_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_balloon_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_BALLOON_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_balloon_arm64_coff.obj

bsd-bridge-virtio-console-compile: bsd-bridge-virtio-balloon-compile
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_CONSOLE_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_console_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_CONSOLE_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_console_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_CONSOLE_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_console_arm64_coff.obj

bsd-bridge-virtio-block-compile: bsd-bridge-block-unit bsd-bridge-virtio-core-compile
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_BLOCK_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_block_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_BLOCK_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_block_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_BLOCK_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_block_arm64_coff.obj

bsd-bridge-virtio-network-compile: bsd-bridge-network-unit bsd-bridge-virtio-core-compile
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		$(BSD_BRIDGE_VTNET_GCC_WARNINGS) \
		-c $(BSD_BRIDGE_NETWORK_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_network_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		$(BSD_BRIDGE_VTNET_GCC_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_NETWORK_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_network_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_NETWORK_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_network_arm64_coff.obj

bsd-bridge-virtio-scsi-compile: bsd-bridge-cam-unit bsd-bridge-virtio-core-compile
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_SCSI_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_scsi_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(BSD_BRIDGE_SCSI_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_scsi_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(BSD_BRIDGE_SCSI_SRCS) \
		-o $(OUT)/tests/freebsd_virtio_scsi_arm64_coff.obj

bsd-bridge-base-headers-unit: tools/tests/bsd_bridge_base_headers_unit.c include/compat/freebsd/machine/_limits.h include/compat/freebsd/machine/_types.h include/compat/freebsd/machine/_stdint.h include/compat/freebsd/machine/endian.h include/compat/freebsd/machine/param.h include/compat/freebsd/machine/cpufunc.h include/compat/freebsd/machine/cpu.h include/compat/freebsd/net/netmap.h include/compat/freebsd/dev/netmap/netmap_kern.h include/compat/freebsd/sys/bus_dma.h include/compat/freebsd/sys/libkern.h include/compat/freebsd/sys/mbuf.h include/compat/freebsd/contrib/zlib/zlib.h src/lib/zlib/upstream/zlib.h src/lib/zlib/upstream/zconf.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_KERNEL -I$(INC)/compat/freebsd \
		-I$(SRC)/lib/zlib/upstream \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_base_headers_unit.c \
		-o $(OUT)/tests/bsd_bridge_base_headers_unit
	@$(OUT)/tests/bsd_bridge_base_headers_unit
	@$(CC) -std=c11 -Wall -Wextra -Werror -ffreestanding \
		-D_KERNEL -I$(INC)/compat/freebsd \
		-I$(SRC)/lib/zlib/upstream \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c tools/tests/bsd_bridge_base_headers_unit.c \
		-o $(OUT)/tests/bsd_bridge_base_headers_x86_64.o
	@$(AARCH64_CC) -std=c11 -Wall -Wextra -Werror -ffreestanding \
		-D_KERNEL -I$(INC)/compat/freebsd \
		-I$(SRC)/lib/zlib/upstream \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c tools/tests/bsd_bridge_base_headers_unit.c \
		-o $(OUT)/tests/bsd_bridge_base_headers_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-D__STDC__=1 -std=c11 -Wall -Wextra -Werror \
		-Wno-unused-function -ffreestanding -D_KERNEL \
		-I$(INC)/compat/freebsd \
		-I$(SRC)/lib/zlib/upstream \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c tools/tests/bsd_bridge_base_headers_unit.c \
		-o $(OUT)/tests/bsd_bridge_base_headers_arm64_coff.o

bsd-bridge-bitstring-unit: tools/tests/bsd_bridge_bitstring_unit.c \
		include/compat/freebsd/sys/bitstring.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_bitstring_unit.c \
		-o $(OUT)/tests/bsd_bridge_bitstring_unit
	@$(OUT)/tests/bsd_bridge_bitstring_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_bitstring_unit.c \
		-o $(OUT)/tests/bsd_bridge_bitstring_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_bitstring_sanitize

bsd-bridge-atomic-unit: tools/tests/bsd_bridge_atomic_unit.c include/compat/freebsd/machine/atomic.h include/compat/freebsd/sys/refcount.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread \
		-D_KERNEL -idirafter $(INC)/compat/freebsd -iquote . \
		tools/tests/bsd_bridge_atomic_unit.c \
		-o $(OUT)/tests/bsd_bridge_atomic_unit
	@$(OUT)/tests/bsd_bridge_atomic_unit
	@$(CC) -std=c11 -Wall -Wextra -Werror -ffreestanding \
		-D_KERNEL -DBSD_BRIDGE_TARGET_COMPILE \
		-I$(INC)/compat/freebsd \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c tools/tests/bsd_bridge_atomic_unit.c \
		-o $(OUT)/tests/bsd_bridge_atomic_x86_64.o
	@$(AARCH64_CC) -std=c11 -Wall -Wextra -Werror -ffreestanding \
		-D_KERNEL -DBSD_BRIDGE_TARGET_COMPILE \
		-I$(INC)/compat/freebsd \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c tools/tests/bsd_bridge_atomic_unit.c \
		-o $(OUT)/tests/bsd_bridge_atomic_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-D__STDC__=1 -std=c11 -Wall -Wextra -Werror \
		-Wno-unused-function -ffreestanding \
		-D_KERNEL -DBSD_BRIDGE_TARGET_COMPILE \
		-I$(INC)/compat/freebsd \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c tools/tests/bsd_bridge_atomic_unit.c \
		-o $(OUT)/tests/bsd_bridge_atomic_arm64_coff.obj

bsd-bridge-allocator-unit: tools/tests/bsd_bridge_allocator_unit.c $(SRC)/compat/freebsd/kern/allocator.c include/compat/freebsd/edgeos/allocator.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_allocator_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		-o $(OUT)/tests/bsd_bridge_allocator_unit
	@$(OUT)/tests/bsd_bridge_allocator_unit

bsd-bridge-hash-unit: tools/tests/bsd_bridge_hash_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/hash.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		include/compat/freebsd/edgeos/hash.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) \
		tools/tests/bsd_bridge_hash_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/hash.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		-o $(OUT)/tests/bsd_bridge_hash_unit
	@$(OUT)/tests/bsd_bridge_hash_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/bsd_bridge_hash_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/hash.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		-o $(OUT)/tests/bsd_bridge_hash_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_hash_sanitize

bsd-bridge-bus-dma-unit: tools/tests/bsd_bridge_bus_dma_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/malloc.c $(SRC)/compat/freebsd/kern/bus_dma.c $(SRC)/compat/freebsd/kern/sync.c $(SRC)/compat/freebsd/kern/systm.c include/compat/freebsd/edgeos/bus_dma.h include/compat/freebsd/machine/bus.h include/compat/freebsd/machine/resource.h $(BSD_BRIDGE_UPSTREAM_SYS)/sys/memdesc.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_bus_dma_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/bus_dma.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_bus_dma_unit
	@$(OUT)/tests/bsd_bridge_bus_dma_unit
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_bus_dma_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/bus_dma.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_bus_dma_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_bus_dma_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/bus_dma.c \
		-o $(OUT)/tests/bsd_bridge_bus_dma_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/bus_dma.c \
		-o $(OUT)/tests/bsd_bridge_bus_dma_arm64.o

bsd-bridge-acpi-tables-unit: tools/tests/bsd_bridge_acpi_tables_unit.c $(SRC)/compat/freebsd/kern/acpi_tables.c include/compat/freebsd/edgeos/acpi_tables.h include/compat/freebsd/machine/acpica_machdep.h include/compat/freebsd/dev/acpica/acpivar.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -DEDGEOS_BSD_ARM64=1 \
		-iquote $(INC) -I$(BSD_BRIDGE_GENERATED) \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_acpi_tables_unit.c \
		$(SRC)/compat/freebsd/kern/acpi_tables.c \
		-o $(OUT)/tests/bsd_bridge_acpi_tables_unit
	@$(OUT)/tests/bsd_bridge_acpi_tables_unit

bsd-bridge-bus-space-unit: tools/tests/bsd_bridge_bus_space_unit.c $(SRC)/compat/freebsd/kern/bus_space.c include/compat/freebsd/edgeos/bus_space.h include/compat/freebsd/machine/bus.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_bus_space_unit.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		-o $(OUT)/tests/bsd_bridge_bus_space_unit
	@$(OUT)/tests/bsd_bridge_bus_space_unit
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_bus_space_unit.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		-o $(OUT)/tests/bsd_bridge_bus_space_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_bus_space_sanitize
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/kern/bus_space.c \
		-o $(OUT)/tests/bsd_bridge_bus_space_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/bus_space.c \
		-o $(OUT)/tests/bsd_bridge_bus_space_arm64.o

bsd-bridge-interrupt-unit: tools/tests/bsd_bridge_interrupt_unit.c tools/tests/bsd_bridge_arm64_interrupt_unit.c tools/tests/bsd_bridge_x86_interrupt_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/interrupt.c $(SRC)/compat/freebsd/kern/malloc.c $(SRC)/compat/freebsd/kern/resource.c $(SRC)/compat/freebsd/kern/systm.c include/compat/freebsd/edgeos/interrupt.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_interrupt_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/interrupt.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_interrupt_unit
	@$(OUT)/tests/bsd_bridge_interrupt_unit
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_arm64_interrupt_unit.c \
		$(SRC)/compat/freebsd/arch/arm64/interrupt.c \
		-o $(OUT)/tests/bsd_bridge_arm64_interrupt_unit
	@$(OUT)/tests/bsd_bridge_arm64_interrupt_unit
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_x86_interrupt_unit.c \
		$(SRC)/compat/freebsd/arch/x86_64/interrupt.c \
		-o $(OUT)/tests/bsd_bridge_x86_interrupt_unit
	@$(OUT)/tests/bsd_bridge_x86_interrupt_unit
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/interrupt.c \
		-o $(OUT)/tests/bsd_bridge_interrupt_x86_64.o
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/arch/x86_64/interrupt.c \
		-o $(OUT)/tests/bsd_bridge_interrupt_backend_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/interrupt.c \
		-o $(OUT)/tests/bsd_bridge_interrupt_arm64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/arch/arm64/interrupt.c \
		-o $(OUT)/tests/bsd_bridge_interrupt_backend_arm64.o

bsd-bridge-intrng-unit: bsd-driver-interface-check \
		tools/tests/bsd_bridge_intrng_unit.c \
		$(SRC)/compat/freebsd/kern/intrng.c \
		$(BSD_BRIDGE_GENERATED)/msi_if.c \
		$(BSD_BRIDGE_GENERATED)/pic_if.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -Wno-unused-parameter \
		-DBSD_BRIDGE_HOST_TEST -DBSD_BRIDGE_INTRNG_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -DINTRNG \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) -include stddef.h \
		-include sys/queue.h \
		tools/tests/bsd_bridge_intrng_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/intrng.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(BSD_BRIDGE_GENERATED)/msi_if.c \
		$(BSD_BRIDGE_GENERATED)/pic_if.c \
		-o $(OUT)/tests/bsd_bridge_intrng_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_intrng_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) -DINTRNG \
		-c $(SRC)/compat/freebsd/kern/intrng.c \
		-o $(OUT)/tests/bsd_bridge_intrng_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) -DINTRNG \
		-c $(SRC)/compat/freebsd/kern/intrng.c \
		-o $(OUT)/tests/bsd_bridge_intrng_arm64.obj

bsd-bridge-eventhandler-unit: tools/tests/bsd_bridge_eventhandler_unit.c $(SRC)/compat/freebsd/kern/eventhandler.c include/compat/freebsd/sys/eventhandler.h include/compat/freebsd/sys/_eventhandler.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) \
		tools/tests/bsd_bridge_eventhandler_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/eventhandler.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_eventhandler_unit
	@$(OUT)/tests/bsd_bridge_eventhandler_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_eventhandler_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/eventhandler.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_eventhandler_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_eventhandler_sanitize

bsd-bridge-watchdog-unit: tools/tests/bsd_bridge_watchdog_unit.c \
		tools/tests/bsd_bridge_watchdog_include/sys/watchdog.h \
		$(SRC)/compat/freebsd/kern/watchdog.c \
		$(SRC)/compat/freebsd/kern/eventhandler.c \
		include/compat/freebsd/edgeos/watchdog.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-Itools/tests/bsd_bridge_watchdog_include -iquote $(INC) \
		tools/tests/bsd_bridge_watchdog_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/eventhandler.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/watchdog.c \
		-o $(OUT)/tests/bsd_bridge_watchdog_unit
	@$(OUT)/tests/bsd_bridge_watchdog_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-Itools/tests/bsd_bridge_watchdog_include -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_watchdog_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/eventhandler.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/watchdog.c \
		-o $(OUT)/tests/bsd_bridge_watchdog_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_watchdog_sanitize

bsd-bridge-videomode-unit: tools/tests/bsd_bridge_videomode_unit.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/edid.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/pickmode.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/vesagtf.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/videomode.c \
		include/compat/freebsd/opt_videomode.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -O2 -Wall -Wextra -Werror \
		-Wno-missing-field-initializers -Wno-pointer-sign \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -D_KERNEL \
		-Itools/tests/bsd_bridge_videomode_include \
		tools/tests/bsd_bridge_videomode_unit.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/edid.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/pickmode.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/vesagtf.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/videomode.c \
		-o $(OUT)/tests/bsd_bridge_videomode_unit
	@$(OUT)/tests/bsd_bridge_videomode_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-Wno-missing-field-initializers -Wno-pointer-sign \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -D_KERNEL \
		-Itools/tests/bsd_bridge_videomode_include \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_videomode_unit.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/edid.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/pickmode.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/vesagtf.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/videomode/videomode.c \
		-o $(OUT)/tests/bsd_bridge_videomode_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_videomode_sanitize

bsd-bridge-dwc-hdmi-compile: bsd-driver-interface-check \
		$(OBJ)/compat/freebsd/generated/crtc_if.o \
		$(OBJ)/compat/freebsd/upstream/dev/hdmi/dwc_hdmi.o \
		$(OBJ)/compat/freebsd/upstream/dev/hdmi/dwc_hdmi_fdt.o \
		$(OBJ)/arm64-bsd/generated/crtc_if.obj \
		$(OBJ)/arm64-bsd/upstream/dev/hdmi/dwc_hdmi.obj \
		$(OBJ)/arm64-bsd/upstream/dev/hdmi/dwc_hdmi_fdt.obj

bsd-bridge-framebuffer-unit: bsd-bridge-eventhandler-unit tools/tests/bsd_bridge_framebuffer_unit.c $(SRC)/compat/freebsd/kern/framebuffer.c $(SRC)/display.c include/compat/freebsd/edgeos/framebuffer.h include/compat/freebsd/sys/fbio.h include/compat/freebsd/dev/vt/vt.h include/compat/freebsd/dev/vt/hw/fb/vt_fb.h include/compat/freebsd/dev/vt/colors/vt_termcolors.h include/display.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DSC_NO_CUTPASTE -iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_framebuffer_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/eventhandler.c \
		$(SRC)/compat/freebsd/kern/framebuffer.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/display.c \
		-o $(OUT)/tests/bsd_bridge_framebuffer_unit
	@$(OUT)/tests/bsd_bridge_framebuffer_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DSC_NO_CUTPASTE -iquote $(INC) \
		-idirafter $(INC)/compat/freebsd \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_framebuffer_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/eventhandler.c \
		$(SRC)/compat/freebsd/kern/framebuffer.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/display.c \
		-o $(OUT)/tests/bsd_bridge_framebuffer_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_framebuffer_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/framebuffer.c \
		-o $(OUT)/tests/bsd_bridge_framebuffer_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE $(BSD_BRIDGE_SOURCE_CPPFLAGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/framebuffer.c \
		-o $(OUT)/tests/bsd_bridge_framebuffer_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/framebuffer.c \
		-o $(OUT)/tests/bsd_bridge_framebuffer_arm64_coff.obj

bsd-bridge-kobj-unit: tools/tests/bsd_bridge_kobj_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/malloc.c $(SRC)/compat/freebsd/kern/kobj.c include/compat/freebsd/sys/kobj.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_kobj_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_kobj_unit
	@$(OUT)/tests/bsd_bridge_kobj_unit
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/kern/kobj.c \
		-o $(OUT)/tests/bsd_bridge_kobj_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/kobj.c \
		-o $(OUT)/tests/bsd_bridge_kobj_arm64.o

bsd-bridge-newbus-unit: bsd-bridge-sbuf-sysctl-unit bsd-driver-interface-check tools/tests/bsd_bridge_newbus_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/bus_space.c $(SRC)/compat/freebsd/kern/environment.c $(SRC)/compat/freebsd/kern/kobj.c $(SRC)/compat/freebsd/kern/malloc.c $(SRC)/compat/freebsd/kern/newbus.c $(SRC)/compat/freebsd/kern/newbus_generic.c $(SRC)/compat/freebsd/kern/resource.c $(SRC)/compat/freebsd/kern/resource_rman.c $(SRC)/compat/freebsd/kern/sbuf.c $(SRC)/compat/freebsd/kern/sysctl.c $(SRC)/compat/freebsd/kern/systm.c include/compat/freebsd/edgeos/newbus.h include/compat/freebsd/edgeos/driver_hooks.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -Wno-unused-parameter \
		-DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include stddef.h \
		-include sys/queue.h \
		tools/tests/bsd_bridge_newbus_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/environment.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/newbus_generic.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/resource_rman.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(BSD_BRIDGE_GENERATED)/bus_if.c \
		-o $(OUT)/tests/bsd_bridge_newbus_unit
	@$(OUT)/tests/bsd_bridge_newbus_unit
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/newbus.c \
		-o $(OUT)/tests/bsd_bridge_newbus_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/newbus.c \
		-o $(OUT)/tests/bsd_bridge_newbus_arm64.obj

bsd-bridge-platform-unit: bsd-bridge-newbus-unit bsd-driver-interface-check tools/tests/bsd_bridge_platform_unit.c $(SRC)/compat/freebsd/kern/firmware.c $(SRC)/compat/freebsd/kern/platform.c include/compat/freebsd/edgeos/firmware.h include/compat/freebsd/edgeos/platform.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-I$(BSD_BRIDGE_GENERATED) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_platform_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/firmware.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/platform.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_platform_unit
	@$(OUT)/tests/bsd_bridge_platform_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-I$(BSD_BRIDGE_GENERATED) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_platform_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/firmware.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/platform.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_platform_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_platform_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/drivers/virtio_mmio.c \
		-o $(OUT)/tests/bsd_bridge_virtio_mmio_frontend_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/drivers/virtio_mmio.c \
		-o $(OUT)/tests/bsd_bridge_virtio_mmio_frontend_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-D__STDC__=1 -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_COFF_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/drivers/virtio_mmio.c \
		-o $(OUT)/tests/bsd_bridge_virtio_mmio_frontend_arm64_coff.obj

bsd-bridge-firmware-frontends-unit: bsd-bridge-sbuf-sysctl-unit tools/tests/bsd_bridge_firmware_frontends_unit.c $(SRC)/compat/freebsd/kern/environment.c $(SRC)/compat/freebsd/kern/firmware.c $(SRC)/compat/freebsd/kern/package.c $(SRC)/compat/freebsd/kern/platform.c $(SRC)/compat/freebsd/drivers/virtio_mmio.c include/compat/freebsd/edgeos/firmware.h include/compat/freebsd/edgeos/package.h include/compat/freebsd/edgeos/virtio_mmio.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include sys/queue.h \
		tools/tests/bsd_bridge_firmware_frontends_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/environment.c \
		$(SRC)/compat/freebsd/kern/firmware.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/module.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/package.c \
		$(SRC)/compat/freebsd/kern/platform.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/drivers/virtio_mmio.c \
		$(BSD_BRIDGE_MMIO_FIRMWARE_SRCS) \
		-o $(OUT)/tests/bsd_bridge_firmware_frontends_unit
	@$(OUT)/tests/bsd_bridge_firmware_frontends_unit
	@$(HOST_CC) -std=c11 -O1 -g -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include sys/queue.h \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_firmware_frontends_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/environment.c \
		$(SRC)/compat/freebsd/kern/firmware.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/module.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/package.c \
		$(SRC)/compat/freebsd/kern/platform.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/drivers/virtio_mmio.c \
		$(BSD_BRIDGE_MMIO_FIRMWARE_SRCS) \
		-o $(OUT)/tests/bsd_bridge_firmware_frontends_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_firmware_frontends_sanitize

bsd-bridge-firmware-metadata-unit: \
		tools/tests/bsd_bridge_firmware_metadata_unit.c \
		$(SRC)/compat/freebsd/kern/firmware_metadata.c \
		include/compat/freebsd/edgeos/firmware_metadata.h \
		include/compat/freebsd/machine/metadata.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -DBSD_BRIDGE_FIRMWARE_METADATA_TEST_X86 \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_firmware_metadata_unit.c \
		$(SRC)/compat/freebsd/kern/firmware_metadata.c \
		-o $(OUT)/tests/bsd_bridge_firmware_metadata_unit
	@$(OUT)/tests/bsd_bridge_firmware_metadata_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -DBSD_BRIDGE_FIRMWARE_METADATA_TEST_X86 \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_firmware_metadata_unit.c \
		$(SRC)/compat/freebsd/kern/firmware_metadata.c \
		-o $(OUT)/tests/bsd_bridge_firmware_metadata_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_firmware_metadata_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/firmware_metadata.c \
		-o $(OUT)/tests/bsd_bridge_firmware_metadata_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/firmware_metadata.c \
		-o $(OUT)/tests/bsd_bridge_firmware_metadata_arm64.obj

bsd-bridge-pci-unit: bsd-bridge-sbuf-sysctl-unit tools/tests/bsd_bridge_pci_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/bus_space.c $(SRC)/compat/freebsd/kern/interrupt.c $(SRC)/compat/freebsd/kern/kobj.c $(SRC)/compat/freebsd/kern/malloc.c $(SRC)/compat/freebsd/kern/newbus.c $(SRC)/compat/freebsd/kern/pci.c $(SRC)/compat/freebsd/kern/resource.c $(SRC)/compat/freebsd/kern/sbuf.c $(SRC)/compat/freebsd/kern/sysctl.c $(SRC)/compat/freebsd/kern/systm.c include/compat/freebsd/edgeos/pci.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_pci_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/interrupt.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/pci.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_pci_unit
	@$(OUT)/tests/bsd_bridge_pci_unit
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/pci.c \
		-o $(OUT)/tests/bsd_bridge_pci_x86_64.o
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/arch/x86_64/pci.c \
		-o $(OUT)/tests/bsd_bridge_pci_backend_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/pci.c \
		-o $(OUT)/tests/bsd_bridge_pci_arm64.obj
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/arch/arm64/pci.c \
		-o $(OUT)/tests/bsd_bridge_pci_backend_arm64.o

bsd-bridge-arm64-pci-unit: tools/tests/bsd_bridge_arm64_pci_unit.c \
		$(SRC)/compat/freebsd/arch/arm64/pci.c \
		include/compat/freebsd/edgeos/pci.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_arm64_pci_unit.c \
		$(SRC)/compat/freebsd/arch/arm64/pci.c \
		-o $(OUT)/tests/bsd_bridge_arm64_pci_unit
	@$(OUT)/tests/bsd_bridge_arm64_pci_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/bsd_bridge_arm64_pci_unit.c \
		$(SRC)/compat/freebsd/arch/arm64/pci.c \
		-o $(OUT)/tests/bsd_bridge_arm64_pci_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_arm64_pci_sanitize

bsd-bridge-package-unit: tools/tests/bsd_bridge_package_unit.c \
		$(SRC)/compat/freebsd/kern/package.c \
		include/compat/freebsd/edgeos/package.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -DBSD_BRIDGE_PACKAGE_TEST_REGISTRY \
		-iquote $(INC) \
		tools/tests/bsd_bridge_package_unit.c \
		$(SRC)/compat/freebsd/kern/package.c \
		-o $(OUT)/tests/bsd_bridge_package_unit
	@$(OUT)/tests/bsd_bridge_package_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -DBSD_BRIDGE_PACKAGE_TEST_REGISTRY \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/bsd_bridge_package_unit.c \
		$(SRC)/compat/freebsd/kern/package.c \
		-o $(OUT)/tests/bsd_bridge_package_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_package_sanitize
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/kern/package.c \
		-o $(OUT)/tests/bsd_bridge_package_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/package.c \
		-o $(OUT)/tests/bsd_bridge_package_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-I$(INC) -I$(SRC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/package.c \
		-o $(OUT)/tests/bsd_bridge_package_arm64_coff.o

bsd-bridge-linker-unit: tools/tests/bsd_linker_module_fixture.c \
		tools/tests/bsd_linker_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/linker.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		include/compat/freebsd/edgeos/linker.h
	@mkdir -p $(OUT)/tests
	@$(CC) -std=gnu11 -O2 -ffreestanding -fno-pie -fno-builtin \
		-fno-stack-protector -m64 -mno-red-zone -mcmodel=large \
		-Wall -Wextra -Werror \
		-c tools/tests/bsd_linker_module_fixture.c \
		-o $(OUT)/tests/bsd_linker_fixture_x86_64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -ffunction-sections -fdata-sections \
		-Wall -Wextra -Werror \
		-c tools/tests/bsd_linker_module_fixture.c \
		-o $(OUT)/tests/bsd_linker_fixture_arm64.obj
	@$(HOST_CC) -DBSD_BRIDGE_HOST_TEST -std=c11 \
		-Wall -Wextra -Werror -iquote $(INC) -iquote $(SRC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_linker_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/linker.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_linker_unit
	@$(OUT)/tests/bsd_linker_unit \
		$(OUT)/tests/bsd_linker_fixture_x86_64.o \
		$(OUT)/tests/bsd_linker_fixture_arm64.obj
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/linker.c \
		-o $(OUT)/tests/bsd_linker_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/linker.c \
		-o $(OUT)/tests/bsd_linker_arm64.obj

bsd-bridge-module-unit: bsd-bridge-virtio-core-compile bsd-bridge-package-unit tools/tests/bsd_bridge_module_unit.c tools/tests/bsd_bridge_module_failure_unit.c tools/tests/bsd_bridge_module_target_compile.c tools/tests/bsd_bridge_arm64_varargs_compile.c tools/tests/bsd_module_linker_test_adapter.c tools/tests/bsd_module_linker_test_adapter.h $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/bus_space.c $(SRC)/compat/freebsd/kern/builtin_module_metadata.c $(SRC)/compat/freebsd/kern/kobj.c $(SRC)/compat/freebsd/kern/malloc.c $(SRC)/compat/freebsd/kern/module.c $(SRC)/compat/freebsd/kern/newbus.c $(SRC)/compat/freebsd/kern/package.c $(SRC)/compat/freebsd/kern/resource.c $(SRC)/compat/freebsd/kern/sbuf.c $(SRC)/compat/freebsd/kern/slicer.c $(SRC)/compat/freebsd/kern/sysctl.c $(SRC)/compat/freebsd/kern/systm.c include/compat/freebsd/edgeos/arm64_coff_varargs.h include/compat/freebsd/edgeos/linker.h include/compat/freebsd/edgeos/module.h include/compat/freebsd/edgeos/package.h include/compat/freebsd/edgeos/slicer.h include/compat/freebsd/sys/kernel.h include/compat/freebsd/sys/module.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-DBSD_BRIDGE_PACKAGE_TEST_REGISTRY -iquote $(INC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_module_unit.c \
		tools/tests/bsd_module_linker_test_adapter.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/module.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/package.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/slicer.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/builtin_module_metadata.c \
		-o $(OUT)/tests/bsd_bridge_module_unit
	@$(OUT)/tests/bsd_bridge_module_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-DBSD_BRIDGE_PACKAGE_TEST_REGISTRY \
		-iquote $(INC) -idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_module_unit.c \
		tools/tests/bsd_module_linker_test_adapter.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/kobj.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/module.c \
		$(SRC)/compat/freebsd/kern/newbus.c \
		$(SRC)/compat/freebsd/kern/package.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/sbuf.c \
		$(SRC)/compat/freebsd/kern/slicer.c \
		$(SRC)/compat/freebsd/kern/sysctl.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/builtin_module_metadata.c \
		-o $(OUT)/tests/bsd_bridge_module_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_module_sanitize
	@set -e; for mode in missing version callback unavailable rollback cycle; do \
		definition=; \
		if [ "$$mode" = version ]; then \
			definition=-DBSD_MODULE_VERSION_FAILURE; \
		elif [ "$$mode" = callback ]; then \
			definition=-DBSD_MODULE_CALLBACK_FAILURE; \
		elif [ "$$mode" = unavailable ]; then \
			definition=-DBSD_MODULE_UNAVAILABLE; \
		elif [ "$$mode" = rollback ]; then \
			definition=-DBSD_MODULE_DEPENDENCY_ROLLBACK; \
		elif [ "$$mode" = cycle ]; then \
			definition=-DBSD_MODULE_DEPENDENCY_CYCLE; \
		fi; \
		$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
			-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
			$$definition -iquote $(INC) \
			-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			tools/tests/bsd_bridge_module_failure_unit.c \
			tools/tests/bsd_module_linker_test_adapter.c \
			$(SRC)/compat/freebsd/kern/allocator.c \
			$(SRC)/compat/freebsd/kern/malloc.c \
			$(SRC)/compat/freebsd/kern/module.c \
			$(SRC)/compat/freebsd/kern/package.c \
			$(SRC)/compat/freebsd/kern/systm.c \
			-o "$(OUT)/tests/bsd_bridge_module_$${mode}_unit"; \
		ASAN_OPTIONS=detect_leaks=0 \
			"$(OUT)/tests/bsd_bridge_module_$${mode}_unit"; \
	done
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/kern/module.c \
		-o $(OUT)/tests/bsd_bridge_module_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/module.c \
		-o $(OUT)/tests/bsd_bridge_module_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-I$(INC) -I$(SRC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/module.c \
		-o $(OUT)/tests/bsd_bridge_module_arm64_coff.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-freebsd \
		-DEDGEOS_BSD_COFF_TARGET=1 \
		-I$(INC) -I$(SRC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/module.c \
		-o $(OUT)/tests/bsd_bridge_module_arm64_coff_pipeline.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-I$(INC) -I$(SRC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c tools/tests/bsd_bridge_module_target_compile.c \
		-o $(OUT)/tests/bsd_bridge_module_target_arm64_coff.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_FRONTEND_FLAGS) -O0 \
		-S -emit-llvm tools/tests/bsd_bridge_arm64_varargs_compile.c \
		-o $(OUT)/tests/bsd_bridge_arm64_varargs.ll
	@rg -q 'llvm.memset' $(OUT)/tests/bsd_bridge_arm64_varargs.ll
	@rg -q 'llvm.va_start' $(OUT)/tests/bsd_bridge_arm64_varargs.ll
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_MODULE_FINAL_FLAGS) \
		-c $(OUT)/tests/bsd_bridge_arm64_varargs.ll \
		-o $(OUT)/tests/bsd_bridge_arm64_varargs.obj
	@llvm-readobj --symbols \
		$(OUT)/tests/bsd_bridge_arm64_varargs.obj | \
		rg -q 'bsd_bridge_arm64_varargs_probe'
	@$(X86_64_CROSS_PREFIX)readelf -W -S \
		$(OUT)/tests/freebsd_virtio_x86_64.o | rg -q 'bsd_sysinit'
	@$(X86_64_CROSS_PREFIX)readelf -W -S \
		$(OUT)/tests/freebsd_virtio_x86_64.o | rg -q 'bsd_module_metadata'
	@aarch64-elf-readelf -W -S \
		$(OUT)/tests/freebsd_virtio_arm64.o | rg -q 'bsd_sysinit'
	@aarch64-elf-readelf -W -S \
		$(OUT)/tests/freebsd_virtio_arm64.o | rg -q 'bsd_module_metadata'
	@llvm-readobj --sections \
		$(OUT)/tests/bsd_bridge_module_arm64_coff.o | rg -q '.bsdsi[$$]a'
	@llvm-readobj --sections \
		$(OUT)/tests/bsd_bridge_module_arm64_coff.o | rg -q '.bsdmm[$$]z'
	@llvm-readobj --sections \
		$(OUT)/tests/bsd_bridge_module_arm64_coff_pipeline.o | \
		rg -q '.bsdsi[$$]a'
	@llvm-readobj --sections \
		$(OUT)/tests/bsd_bridge_module_arm64_coff_pipeline.o | \
		rg -q '.bsdmm[$$]z'
	@llvm-readobj --sections \
		$(OUT)/tests/bsd_bridge_module_target_arm64_coff.o | \
		rg -q '.bsdsi[$$]m'
	@llvm-readobj --sections \
		$(OUT)/tests/bsd_bridge_module_target_arm64_coff.o | \
		rg -q '.bsdsu[$$]m'
	@llvm-readobj --sections \
		$(OUT)/tests/bsd_bridge_module_target_arm64_coff.o | \
		rg -q '.bsdmm[$$]m'

bsd-bridge-resource-unit: tools/tests/bsd_bridge_resource_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/bus_space.c $(SRC)/compat/freebsd/kern/malloc.c $(SRC)/compat/freebsd/kern/resource.c $(SRC)/compat/freebsd/kern/systm.c include/compat/freebsd/edgeos/resource.h include/compat/freebsd/sys/rman.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		tools/tests/bsd_bridge_resource_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_space.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/resource.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_resource_unit
	@$(OUT)/tests/bsd_bridge_resource_unit
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/resource.c \
		-o $(OUT)/tests/bsd_bridge_resource_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/resource.c \
		-o $(OUT)/tests/bsd_bridge_resource_arm64.obj

bsd-bridge-malloc-unit: tools/tests/bsd_bridge_malloc_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/malloc.c include/compat/freebsd/edgeos/allocator.h include/compat/freebsd/edgeos/malloc.h include/compat/freebsd/sys/malloc.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_malloc_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		-o $(OUT)/tests/bsd_bridge_malloc_unit
	@$(OUT)/tests/bsd_bridge_malloc_unit
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/kern/malloc.c \
		-o $(OUT)/tests/bsd_bridge_malloc_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/malloc.c \
		-o $(OUT)/tests/bsd_bridge_malloc_arm64.o

bsd-bridge-contigmalloc-unit: bsd-bridge-malloc-unit tools/tests/bsd_bridge_contigmalloc_unit.c $(SRC)/compat/freebsd/kern/contigmalloc.c include/compat/freebsd/edgeos/malloc.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_contigmalloc_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_dma.c \
		$(SRC)/compat/freebsd/kern/contigmalloc.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_contigmalloc_unit
	@$(OUT)/tests/bsd_bridge_contigmalloc_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) -idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_contigmalloc_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_dma.c \
		$(SRC)/compat/freebsd/kern/contigmalloc.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_contigmalloc_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_contigmalloc_sanitize
	@$(CC) $(CFLAGS) -Werror \
		-c $(SRC)/compat/freebsd/kern/contigmalloc.c \
		-o $(OUT)/tests/bsd_bridge_contigmalloc_x86_64.o
	@$(AARCH64_CC) -I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/contigmalloc.c \
		-o $(OUT)/tests/bsd_bridge_contigmalloc_arm64.o

bsd-bridge-sglist-unit: bsd-bridge-malloc-unit tools/tests/bsd_bridge_sglist_unit.c $(SRC)/compat/freebsd/kern/sglist.c include/compat/freebsd/sys/sglist.h include/compat/freebsd/sys/uio.h include/compat/freebsd/sys/_iovec.h include/compat/freebsd/sys/_uio.h include/compat/freebsd/vm/vm_page.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) -iquote $(INC) \
		tools/tests/bsd_bridge_sglist_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_dma.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sglist.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_sglist_unit
	@$(OUT)/tests/bsd_bridge_sglist_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_sglist_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/bus_dma.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sglist.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_sglist_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_sglist_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/sglist.c \
		-o $(OUT)/tests/bsd_bridge_sglist_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/sglist.c \
		-o $(OUT)/tests/bsd_bridge_sglist_arm64.o

bsd-bridge-environment-unit: tools/tests/bsd_bridge_environment_unit.c \
		$(SRC)/compat/freebsd/kern/environment.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -DBSD_BRIDGE_HOST_TEST \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-I$(INC) -I$(SRC) \
		tools/tests/bsd_bridge_environment_unit.c \
		$(SRC)/compat/freebsd/kern/environment.c \
		-o $(OUT)/tests/bsd_bridge_environment_unit
	@$(OUT)/tests/bsd_bridge_environment_unit
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/environment.c \
		-o $(OUT)/tests/bsd_bridge_environment_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/environment.c \
		-o $(OUT)/tests/bsd_bridge_environment_arm64.o

bsd-bridge-evdev-unit: tools/tests/bsd_bridge_evdev_unit.c \
		$(SRC)/compat/freebsd/kern/evdev.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/evdev/evdev_utils.c \
		include/compat/freebsd/dev/evdev/evdev_private.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -Wno-unused-parameter \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -DBSD_BRIDGE_HOST_TEST \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include sys/queue.h -include sys/errno.h -include sys/mutex.h \
		tools/tests/bsd_bridge_evdev_unit.c \
		$(SRC)/compat/freebsd/kern/evdev.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/dev/evdev/evdev_utils.c \
		-o $(OUT)/tests/bsd_bridge_evdev_unit
	@$(OUT)/tests/bsd_bridge_evdev_unit
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/evdev.c \
		-o $(OUT)/tests/bsd_bridge_evdev_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/evdev.c \
		-o $(OUT)/tests/bsd_bridge_evdev_arm64.o

bsd-bridge-random-unit: tools/tests/bsd_bridge_random_unit.c $(SRC)/compat/freebsd/kern/random.c include/compat/freebsd/edgeos/random.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_KERNEL -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) \
		tools/tests/bsd_bridge_random_unit.c \
		$(SRC)/compat/freebsd/kern/random.c \
		-o $(OUT)/tests/bsd_bridge_random_unit
	@$(OUT)/tests/bsd_bridge_random_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_KERNEL -DBSD_BRIDGE_HOST_TEST \
		-iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_random_unit.c \
		$(SRC)/compat/freebsd/kern/random.c \
		-o $(OUT)/tests/bsd_bridge_random_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_random_sanitize

bsd-bridge-time-unit: tools/tests/bsd_bridge_time_unit.c \
		$(SRC)/compat/freebsd/kern/time.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -DCLOCK_MONOTONIC_FAST=12 -iquote $(INC) \
		tools/tests/bsd_bridge_time_unit.c \
		$(SRC)/compat/freebsd/kern/time.c \
		-o $(OUT)/tests/bsd_bridge_time_unit
	@$(OUT)/tests/bsd_bridge_time_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -DCLOCK_MONOTONIC_FAST=12 -iquote $(INC) \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_time_unit.c \
		$(SRC)/compat/freebsd/kern/time.c \
		-o $(OUT)/tests/bsd_bridge_time_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_time_sanitize

bsd-bridge-systm-unit: tools/tests/bsd_bridge_systm_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/systm.c include/compat/freebsd/edgeos/allocator.h include/compat/freebsd/edgeos/systm.h include/compat/freebsd/sys/systm.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -iquote $(INC) \
		tools/tests/bsd_bridge_systm_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_systm_unit
	@$(OUT)/tests/bsd_bridge_systm_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST -fsanitize=address,undefined \
		-fno-omit-frame-pointer -iquote $(INC) \
		tools/tests/bsd_bridge_systm_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_systm_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_systm_sanitize
	@$(CC) $(CFLAGS) -Werror -I$(INC)/compat/freebsd \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-c $(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_systm_x86_64.o
	@$(AARCH64_CC) -I$(INC)/compat/freebsd \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-std=gnu99 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		-c $(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_systm_arm64.o
	@$(ARM64_EFI_CC) -target aarch64-unknown-windows \
		-D__STDC__=1 -std=gnu11 -O2 -ffreestanding \
		-fno-builtin -fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_COFF_SOURCE_WARNINGS) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-I$(INC) -I$(SRC) -include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_systm_arm64_coff.obj

bsd-bridge-libkern-sort-unit: tools/tests/bsd_bridge_libkern_sort_unit.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/libkern/qsort.c \
		include/compat/freebsd/sys/libkern.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		$(BSD_BRIDGE_QSORT_CLANG_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-I$(INC) -I$(SRC) \
		tools/tests/bsd_bridge_libkern_sort_unit.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/libkern/qsort.c \
		-o $(OUT)/tests/bsd_bridge_libkern_sort_unit
	@$(OUT)/tests/bsd_bridge_libkern_sort_unit

bsd-bridge-kthread-unit: tools/tests/bsd_bridge_kthread_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/kthread.c $(SRC)/compat/freebsd/kern/sleep.c include/compat/freebsd/edgeos/kthread.h include/compat/freebsd/edgeos/sleep.h include/compat/freebsd/sys/kthread.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -idirafter $(INC)/compat/freebsd \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_kthread_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_kthread_unit
	@$(OUT)/tests/bsd_bridge_kthread_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer -idirafter $(INC)/compat/freebsd \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_kthread_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_kthread_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_kthread_sanitize
	@set -e; for source in \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c; do \
		name=$$(basename "$$source" .c); \
		$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) -c "$$source" \
			-o "$(OUT)/tests/bsd_bridge_$${name}_x86_64.o"; \
	done
	@set -e; for source in \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c; do \
		name=$$(basename "$$source" .c); \
		$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
			-fno-stack-protector -fno-strict-aliasing \
			-mgeneral-regs-only -Wall -Wextra -Werror \
			$(BSD_BRIDGE_SOURCE_WARNINGS) \
			-D_KERNEL -DEDGEOS_BSD_BRIDGE \
			-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
			-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
			-include $(AUTOCONF_H) -c "$$source" \
			-o "$(OUT)/tests/bsd_bridge_$${name}_arm64.o"; \
	done
	@set -e; for source in \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c; do \
		name=$$(basename "$$source" .c); \
		$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
			-c "$$source" \
			-o "$(OUT)/tests/bsd_bridge_$${name}_arm64_coff.obj"; \
	done

bsd-bridge-taskqueue-unit: tools/tests/bsd_bridge_taskqueue_unit.c $(SRC)/compat/freebsd/kern/callout.c $(SRC)/compat/freebsd/kern/taskqueue.c include/compat/freebsd/edgeos/taskqueue.h include/compat/freebsd/sys/taskqueue.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_taskqueue_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/callout.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/taskqueue.c \
		-o $(OUT)/tests/bsd_bridge_taskqueue_unit
	@$(OUT)/tests/bsd_bridge_taskqueue_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer -iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_taskqueue_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/callout.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/taskqueue.c \
		-o $(OUT)/tests/bsd_bridge_taskqueue_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_taskqueue_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/taskqueue.c \
		-o $(OUT)/tests/bsd_bridge_taskqueue_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/taskqueue.c \
		-o $(OUT)/tests/bsd_bridge_taskqueue_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/taskqueue.c \
		-o $(OUT)/tests/bsd_bridge_taskqueue_arm64_coff.obj

bsd-bridge-gtaskqueue-unit: tools/tests/bsd_bridge_gtaskqueue_unit.c $(SRC)/compat/freebsd/kern/gtaskqueue.c include/compat/freebsd/sys/gtaskqueue.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_gtaskqueue_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/gtaskqueue.c \
		-o $(OUT)/tests/bsd_bridge_gtaskqueue_unit
	@$(OUT)/tests/bsd_bridge_gtaskqueue_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_gtaskqueue_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/gtaskqueue.c \
		-o $(OUT)/tests/bsd_bridge_gtaskqueue_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_gtaskqueue_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/gtaskqueue.c \
		-o $(OUT)/tests/bsd_bridge_gtaskqueue_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/gtaskqueue.c \
		-o $(OUT)/tests/bsd_bridge_gtaskqueue_arm64_coff.obj

bsd-bridge-led-unit: tools/tests/bsd_bridge_led_unit.c $(SRC)/compat/freebsd/kern/led.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_led_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/led.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_led_unit
	@$(OUT)/tests/bsd_bridge_led_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		tools/tests/bsd_bridge_led_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/led.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_led_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_led_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/led.c \
		-o $(OUT)/tests/bsd_bridge_led_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/led.c \
		-o $(OUT)/tests/bsd_bridge_led_arm64_coff.obj

bsd-bridge-callout-unit: tools/tests/bsd_bridge_callout_unit.c $(SRC)/compat/freebsd/kern/allocator.c $(SRC)/compat/freebsd/kern/callout.c include/compat/freebsd/edgeos/callout.h include/compat/freebsd/sys/_callout.h include/compat/freebsd/sys/callout.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_callout_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/callout.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_callout_unit
	@$(OUT)/tests/bsd_bridge_callout_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer -iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_callout_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/callout.c \
		$(SRC)/compat/freebsd/kern/kthread.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_callout_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_callout_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/callout.c \
		-o $(OUT)/tests/bsd_bridge_callout_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/callout.c \
		-o $(OUT)/tests/bsd_bridge_callout_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/callout.c \
		-o $(OUT)/tests/bsd_bridge_callout_arm64_coff.obj

bsd-bridge-config-intrhook-unit: tools/tests/bsd_bridge_config_intrhook_unit.c $(SRC)/compat/freebsd/kern/config_intrhook.c include/compat/freebsd/sys/kernel.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include sys/queue.h \
		tools/tests/bsd_bridge_config_intrhook_unit.c \
		-o $(OUT)/tests/bsd_bridge_config_intrhook_unit
	@$(OUT)/tests/bsd_bridge_config_intrhook_unit
	@$(HOST_CC) -std=c11 -O1 -g -ffreestanding -nostdinc \
		-Wall -Wextra -Werror -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) -iquote $(INC) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -include sys/queue.h \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		tools/tests/bsd_bridge_config_intrhook_unit.c \
		-o $(OUT)/tests/bsd_bridge_config_intrhook_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_config_intrhook_sanitize

bsd-bridge-cdev-unit: tools/tests/bsd_bridge_cdev_unit.c $(SRC)/compat/freebsd/kern/tty.c $(SRC)/compat/freebsd/kern/cdev.c $(SRC)/compat/freebsd/kern/kthread.c $(SRC)/compat/freebsd/kern/selinfo.c include/compat/freebsd/edgeos/cdev.h include/compat/freebsd/sys/conf.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-DBSD_BRIDGE_FORCE_LLP64_V4L2_ABI \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_cdev_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/uio.c \
			$(SRC)/compat/freebsd/kern/cdev.c \
			$(SRC)/compat/freebsd/kern/kthread.c \
			$(SRC)/compat/freebsd/kern/selinfo.c \
			$(SRC)/compat/freebsd/kern/tty.c \
		-o $(OUT)/tests/bsd_bridge_cdev_unit
	@$(OUT)/tests/bsd_bridge_cdev_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-DBSD_BRIDGE_FORCE_LLP64_V4L2_ABI \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_cdev_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
		$(SRC)/compat/freebsd/kern/uio.c \
			$(SRC)/compat/freebsd/kern/cdev.c \
			$(SRC)/compat/freebsd/kern/kthread.c \
			$(SRC)/compat/freebsd/kern/selinfo.c \
			$(SRC)/compat/freebsd/kern/tty.c \
		-o $(OUT)/tests/bsd_bridge_cdev_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_cdev_sanitize

bsd-bridge-selinfo-unit: tools/tests/bsd_bridge_selinfo_unit.c $(SRC)/compat/freebsd/kern/selinfo.c include/compat/freebsd/sys/event.h include/compat/freebsd/sys/selinfo.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror \
		-iquote $(INC) \
		tools/tests/bsd_bridge_selinfo_unit.c \
		$(SRC)/compat/freebsd/kern/selinfo.c \
		-o $(OUT)/tests/bsd_bridge_selinfo_unit
	@$(OUT)/tests/bsd_bridge_selinfo_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/bsd_bridge_selinfo_unit.c \
		$(SRC)/compat/freebsd/kern/selinfo.c \
		-o $(OUT)/tests/bsd_bridge_selinfo_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_selinfo_sanitize

bsd-bridge-pps-unit: tools/tests/bsd_bridge_pps_unit.c $(SRC)/compat/freebsd/kern/pps.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -ffreestanding -nostdinc \
		-Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_pps_unit.c \
		$(SRC)/compat/freebsd/kern/pps.c \
		-o $(OUT)/tests/bsd_bridge_pps_unit
	@$(OUT)/tests/bsd_bridge_pps_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -ffreestanding -nostdinc \
		-Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer \
		-I$(BSD_BRIDGE_HOST_TEST_INCLUDE) \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_pps_unit.c \
		$(SRC)/compat/freebsd/kern/pps.c \
		-o $(OUT)/tests/bsd_bridge_pps_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_pps_sanitize

bsd-bridge-tty-unit: bsd-bridge-pps-unit tools/tests/bsd_bridge_tty_unit.c $(SRC)/compat/freebsd/kern/tty.c $(SRC)/compat/freebsd/kern/cdev.c $(SRC)/compat/freebsd/kern/kthread.c $(SRC)/compat/freebsd/kern/selinfo.c include/compat/freebsd/edgeos/cdev.h include/compat/freebsd/sys/conf.h include/compat/freebsd/sys/tty.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_tty_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
			$(SRC)/compat/freebsd/kern/cdev.c \
			$(SRC)/compat/freebsd/kern/kthread.c \
			$(SRC)/compat/freebsd/kern/selinfo.c \
			$(SRC)/compat/freebsd/kern/tty.c \
		-o $(OUT)/tests/bsd_bridge_tty_unit
	@$(OUT)/tests/bsd_bridge_tty_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_tty_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/sleep.c \
			$(SRC)/compat/freebsd/kern/cdev.c \
			$(SRC)/compat/freebsd/kern/kthread.c \
			$(SRC)/compat/freebsd/kern/selinfo.c \
			$(SRC)/compat/freebsd/kern/tty.c \
		-o $(OUT)/tests/bsd_bridge_tty_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_tty_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/tty.c \
		-o $(OUT)/tests/bsd_bridge_tty_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/tty.c \
		-o $(OUT)/tests/bsd_bridge_tty_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/tty.c \
		-o $(OUT)/tests/bsd_bridge_tty_arm64_coff.obj

bsd-bridge-vm-page-unit: tools/tests/bsd_bridge_vm_page_unit.c $(SRC)/compat/freebsd/kern/vm_page.c include/compat/freebsd/edgeos/vm_page.h include/compat/freebsd/vm/vm.h include/compat/freebsd/vm/vm_page.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_vm_page_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/vm_page.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_vm_page_unit
	@$(OUT)/tests/bsd_bridge_vm_page_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200112L -DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE -fsanitize=address,undefined \
		-fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_vm_page_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/vm_page.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		-o $(OUT)/tests/bsd_bridge_vm_page_sanitize
	@ASAN_OPTIONS=detect_leaks=0 \
		$(OUT)/tests/bsd_bridge_vm_page_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/vm_page.c \
		-o $(OUT)/tests/bsd_bridge_vm_page_x86_64.o
	@$(AARCH64_CC) -std=gnu11 -O2 -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-strict-aliasing \
		-mgeneral-regs-only -Wall -Wextra -Werror \
		$(BSD_BRIDGE_SOURCE_WARNINGS) \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-I$(INC)/compat/freebsd -I$(BSD_BRIDGE_GENERATED) \
		-I$(BSD_BRIDGE_UPSTREAM_SYS) -I$(INC) -I$(SRC) \
		-include $(AUTOCONF_H) \
		-c $(SRC)/compat/freebsd/kern/vm_page.c \
		-o $(OUT)/tests/bsd_bridge_vm_page_arm64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/vm_page.c \
		-o $(OUT)/tests/bsd_bridge_vm_page_arm64_coff.obj

bsd-bridge-vmem-unit: tools/tests/bsd_bridge_vmem_unit.c \
		$(SRC)/compat/freebsd/kern/vmem.c \
		$(BSD_BRIDGE_UPSTREAM_SYS)/sys/vmem.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=gnu11 -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_vmem_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/vmem.c \
		-o $(OUT)/tests/bsd_bridge_vmem_unit
	@$(OUT)/tests/bsd_bridge_vmem_unit
	@$(HOST_CC) -std=gnu11 -O1 -g -Wall -Wextra -Werror \
		-DBSD_BRIDGE_HOST_TEST \
		-D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd \
		-idirafter $(BSD_BRIDGE_UPSTREAM_SYS) \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/bsd_bridge_vmem_unit.c \
		$(SRC)/compat/freebsd/kern/allocator.c \
		$(SRC)/compat/freebsd/kern/malloc.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		$(SRC)/compat/freebsd/kern/systm.c \
		$(SRC)/compat/freebsd/kern/vmem.c \
		-o $(OUT)/tests/bsd_bridge_vmem_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_vmem_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/vmem.c \
		-o $(OUT)/tests/bsd_bridge_vmem_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/vmem.c \
		-o $(OUT)/tests/bsd_bridge_vmem_arm64.obj

bsd-bridge-sync-unit: tools/tests/bsd_bridge_sync_unit.c $(SRC)/compat/freebsd/kern/sync.c include/compat/freebsd/edgeos/sync.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread \
		-DBSD_BRIDGE_HOST_TEST -idirafter $(INC)/compat/freebsd -iquote $(INC) \
		tools/tests/bsd_bridge_sync_unit.c \
		$(SRC)/compat/freebsd/kern/sync.c \
		-o $(OUT)/tests/bsd_bridge_sync_unit
	@$(OUT)/tests/bsd_bridge_sync_unit

bsd-bridge-epoch-unit: tools/tests/bsd_bridge_epoch_unit.c \
		$(SRC)/compat/freebsd/kern/epoch.c \
		include/compat/freebsd/sys/epoch.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -pthread \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) \
		tools/tests/bsd_bridge_epoch_unit.c \
		$(SRC)/compat/freebsd/kern/epoch.c \
		-o $(OUT)/tests/bsd_bridge_epoch_unit
	@$(OUT)/tests/bsd_bridge_epoch_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -pthread \
		-DBSD_BRIDGE_HOST_TEST -D_KERNEL -DEDGEOS_BSD_BRIDGE \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-idirafter $(INC)/compat/freebsd -iquote $(INC) \
		tools/tests/bsd_bridge_epoch_unit.c \
		$(SRC)/compat/freebsd/kern/epoch.c \
		-o $(OUT)/tests/bsd_bridge_epoch_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/bsd_bridge_epoch_sanitize
	@$(CC) $(BSD_BRIDGE_X86_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/epoch.c \
		-o $(OUT)/tests/bsd_bridge_epoch_x86_64.o
	@$(ARM64_EFI_CC) $(BSD_BRIDGE_ARM64_COMPILE_FLAGS) \
		-c $(SRC)/compat/freebsd/kern/epoch.c \
		-o $(OUT)/tests/bsd_bridge_epoch_arm64.obj

$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP): \
		$(shell find $(BSD_BRIDGE_ACPICA_UPSTREAM_INCLUDE) -type f 2>/dev/null)
	@mkdir -p \
		$(BSD_BRIDGE_ACPICA_INCLUDE)/contrib/dev/acpica/include
	@cp -R $(BSD_BRIDGE_ACPICA_UPSTREAM_INCLUDE)/. \
		$(BSD_BRIDGE_ACPICA_INCLUDE)/contrib/dev/acpica/include/
	@touch $@

bsd-bridge-acpica-runtime-compile: \
		$(BSD_BRIDGE_ACPICA_INCLUDE_STAMP) arm64-syncconfig
	@mkdir -p $(OUT)/tests/acpica/x86_64 $(OUT)/tests/acpica/arm64
	@set -e; for source in $(BSD_BRIDGE_ACPICA_RUNTIME_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
			$(BSD_BRIDGE_X86_COMPILE_FLAGS) -D__FreeBSD__=14 \
			-DEDGEOS_BSD_FULL_ACPICA \
			-c "$$source" \
			-o "$(OUT)/tests/acpica/x86_64/$${name}.o"; \
	done
	@set -e; for source in $(BSD_BRIDGE_ACPICA_RUNTIME_SRCS); do \
		name=$$(basename "$$source" .c); \
		$(ARM64_EFI_CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
			$(BSD_BRIDGE_ARM64_COMPILE_FLAGS) -U_MSC_VER \
			-D__GNUC__=4 -D__LP64__=1 -D__FreeBSD__=14 \
			-DEDGEOS_BSD_FULL_ACPICA \
			-c "$$source" \
			-o "$(OUT)/tests/acpica/arm64/$${name}.obj"; \
	done
	@$(CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_X86_COMPILE_FLAGS) -D__FreeBSD__=14 \
		-DEDGEOS_BSD_FULL_ACPICA \
		-c $(SRC)/compat/freebsd/kern/acpica_osl.c \
		-o $(OUT)/tests/acpica/x86_64/acpica_osl.o
	@$(CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_X86_COMPILE_FLAGS) -D__FreeBSD__=14 \
		-DEDGEOS_BSD_FULL_ACPICA \
		-c $(SRC)/compat/freebsd/kern/acpica_runtime.c \
		-o $(OUT)/tests/acpica/x86_64/acpica_runtime.o
	@$(ARM64_EFI_CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_ARM64_COMPILE_FLAGS) -U_MSC_VER \
		-D__GNUC__=4 -D__LP64__=1 -D__FreeBSD__=14 \
		-DEDGEOS_BSD_FULL_ACPICA \
		-c $(SRC)/compat/freebsd/kern/acpica_osl.c \
		-o $(OUT)/tests/acpica/arm64/acpica_osl.obj
	@$(ARM64_EFI_CC) -I$(BSD_BRIDGE_ACPICA_INCLUDE) \
		$(BSD_BRIDGE_ARM64_COMPILE_FLAGS) -U_MSC_VER \
		-D__GNUC__=4 -D__LP64__=1 -D__FreeBSD__=14 \
		-DEDGEOS_BSD_FULL_ACPICA \
		-c $(SRC)/compat/freebsd/kern/acpica_runtime.c \
		-o $(OUT)/tests/acpica/arm64/acpica_runtime.obj
	@$(LD) -r $(OUT)/tests/acpica/x86_64/*.o \
		-o $(OUT)/tests/acpica/acpica-runtime-complete-x86_64.o
	@if $(NM) -u $(OUT)/tests/acpica/acpica-runtime-complete-x86_64.o | \
		awk '{print $$NF}' | rg -q '^AcpiOs'; then \
		echo 'bsd-acpica-runtime: unresolved operating-system service'; \
		exit 1; \
	fi
	@printf 'bsd-acpica-runtime: PASS: %s core sources plus complete OSL on x86_64 and arm64\n' \
		"$(words $(BSD_BRIDGE_ACPICA_RUNTIME_SRCS))"

# -------------------------
# Build
# -------------------------

all: kernel

kernel: prepare $(TARGET)

prepare: syncconfig syscall-inventory-check cross-arch-unity-check

syncconfig: $(KCONFIG_DEPS) $(DOT_CONFIG)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(DOT_CONFIG) --syncconfig --autoconf $(AUTOCONF_H)

$(ARM64_DOT_CONFIG): $(KCONFIG_DEPS) $(ARM64_KCONFIG_DEFCONFIG)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(ARM64_DOT_CONFIG) --defconfig $(ARM64_KCONFIG_DEFCONFIG) --autoconf $(ARM64_AUTOCONF_H) --makefile $(ARM64_CONFIG_MK) --make-prefix ARM64_
	@touch $(ARM64_DOT_CONFIG)
	@printf '[config] wrote %s from %s\n' "$(ARM64_DOT_CONFIG)" "$(ARM64_KCONFIG_DEFCONFIG)"

$(ARM64_CONFIG_MK): $(KCONFIG_DEPS) $(ARM64_DOT_CONFIG)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(ARM64_DOT_CONFIG) --syncconfig --autoconf $(ARM64_AUTOCONF_H) --makefile $(ARM64_CONFIG_MK) --make-prefix ARM64_

$(ARM64_AUTOCONF_H): $(ARM64_CONFIG_MK)
	@test -f $@ || \
		python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(ARM64_DOT_CONFIG) --syncconfig --autoconf $(ARM64_AUTOCONF_H) --makefile $(ARM64_CONFIG_MK) --make-prefix ARM64_

arm64-syncconfig: $(ARM64_CONFIG_MK) $(ARM64_AUTOCONF_H)

defconfig: x86_64_defconfig

x86_64_defconfig: $(KCONFIG_DEPS) $(KCONFIG_DEFCONFIG)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(DOT_CONFIG) --defconfig $(KCONFIG_DEFCONFIG) --autoconf $(AUTOCONF_H)
	@printf '[config] wrote %s from %s\n' "$(DOT_CONFIG)" "$(KCONFIG_DEFCONFIG)"

arm64_defconfig: $(KCONFIG_DEPS) $(ARM64_KCONFIG_DEFCONFIG)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(ARM64_DOT_CONFIG) --defconfig $(ARM64_KCONFIG_DEFCONFIG) --autoconf $(ARM64_AUTOCONF_H) --makefile $(ARM64_CONFIG_MK) --make-prefix ARM64_
	@printf '[config] wrote %s from %s\n' "$(ARM64_DOT_CONFIG)" "$(ARM64_KCONFIG_DEFCONFIG)"

olddefconfig: $(KCONFIG_DEPS)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(DOT_CONFIG) --olddefconfig --autoconf $(AUTOCONF_H)
	@printf '[config] updated %s from %s defaults\n' "$(DOT_CONFIG)" "$(KCONFIG)"

arm64-olddefconfig: $(KCONFIG_DEPS)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(ARM64_DOT_CONFIG) --olddefconfig --autoconf $(ARM64_AUTOCONF_H) --makefile $(ARM64_CONFIG_MK) --make-prefix ARM64_
	@printf '[config] updated %s from %s defaults\n' "$(ARM64_DOT_CONFIG)" "$(KCONFIG)"

menuconfig: $(KCONFIG_DEPS)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(DOT_CONFIG) --menuconfig --autoconf $(AUTOCONF_H)
	@printf '[config] updated %s from interactive menu\n' "$(DOT_CONFIG)"

arm64-menuconfig: $(KCONFIG_DEPS)
	@python3 $(KCONFIG_SCRIPT) --kconfig $(KCONFIG) --config $(ARM64_DOT_CONFIG) --menuconfig --autoconf $(ARM64_AUTOCONF_H) --makefile $(ARM64_CONFIG_MK) --make-prefix ARM64_
	@printf '[config] updated %s from interactive menu\n' "$(ARM64_DOT_CONFIG)"

kconfig-check: $(KCONFIG_DEPS)
	@python3 -m unittest scripts.kconfig.tests.test_edgeos_kconfig

initramfs-tool-unit: tools/tests/test_mkinitramfs.py $(INITRAMFS_TOOL)
	@python3 -m unittest tools.tests.test_mkinitramfs

gzip-unit: tools/tests/gzip_unit.c $(SRC)/lib/gzip.c $(wildcard $(SRC)/lib/zlib/*.c)
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/gzip_unit.c \
		$(SRC)/lib/gzip.c \
		$(SRC)/lib/zlib/adler32.c \
		$(SRC)/lib/zlib/crc32.c \
		$(SRC)/lib/zlib/inffast.c \
		$(SRC)/lib/zlib/inflate.c \
		$(SRC)/lib/zlib/inftrees.c \
		$(SRC)/lib/zlib/zutil.c \
		-o $(OUT)/tests/gzip_unit
	@$(OUT)/tests/gzip_unit

.PHONY: boot-command-line-unit
boot-command-line-unit: tools/tests/boot_command_line_unit.c $(SRC)/kernel/boot_command_line.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/boot_command_line_unit.c \
		$(SRC)/kernel/boot_command_line.c \
		-o $(OUT)/tests/boot_command_line_unit
	@$(OUT)/tests/boot_command_line_unit

.PHONY: boot-log-policy-unit
boot-log-policy-unit: tools/tests/boot_log_policy_unit.c \
		$(SRC)/kernel/boot_command_line.c $(SRC)/kernel/boot_log_policy.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/boot_log_policy_unit.c \
		$(SRC)/kernel/boot_command_line.c \
		$(SRC)/kernel/boot_log_policy.c \
		-o $(OUT)/tests/boot_log_policy_unit
	@$(OUT)/tests/boot_log_policy_unit

.PHONY: boot-logfile-unit
boot-logfile-unit: tools/tests/boot_logfile_unit.c \
		$(SRC)/kernel/boot_command_line.c \
		$(SRC)/kernel/boot_log_policy.c \
		$(SRC)/kernel/boot_logfile.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/boot_logfile_unit.c \
		$(SRC)/kernel/boot_command_line.c \
		$(SRC)/kernel/boot_log_policy.c \
		$(SRC)/kernel/boot_logfile.c \
		-o $(OUT)/tests/boot_logfile_unit
	@$(OUT)/tests/boot_logfile_unit

.PHONY: xhci-device-policy-unit
xhci-device-policy-unit: tools/tests/xhci_device_policy_unit.c \
		$(SRC)/drivers/usb/xhci_device_policy.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/xhci_device_policy_unit.c \
		$(SRC)/drivers/usb/xhci_device_policy.c \
		-o $(OUT)/tests/xhci_device_policy_unit
	@$(OUT)/tests/xhci_device_policy_unit

.PHONY: boot-root-unit
boot-root-unit: tools/tests/boot_root_unit.c \
		$(SRC)/kernel/boot_command_line.c $(SRC)/kernel/boot_root.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) -iquote $(SRC) \
		tools/tests/boot_root_unit.c \
		$(SRC)/kernel/boot_command_line.c \
		$(SRC)/kernel/boot_root.c \
		-o $(OUT)/tests/boot_root_unit
	@$(OUT)/tests/boot_root_unit

syscall-inventory-check: tools/syscalls/linux_syscall_inventory.json tools/syscalls/generate_linux_syscall_tables.py tools/tests/arch_syscall_parity.py tools/tests/test_arch_syscall_parity.py tools/tests/test_validate_syscall_inventory.py tools/tests/validate_syscall_inventory.py
	@python3 -m unittest tools.tests.test_arch_syscall_parity tools.tests.test_validate_syscall_inventory
	@python3 tools/tests/validate_syscall_inventory.py
	@python3 tools/syscalls/generate_linux_syscall_tables.py --check

cross-arch-unity-check: tools/tests/cross_arch_unity.py tools/tests/cross_arch_unity_inventory.json tools/tests/test_cross_arch_unity.py
	@python3 -m unittest tools.tests.test_cross_arch_unity
	@python3 tools/tests/cross_arch_unity.py

wait-runtime-unit: tools/tests/wait_runtime_unit.c $(SRC)/kernel/wait_runtime.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -I$(INC) \
		tools/tests/wait_runtime_unit.c $(SRC)/kernel/wait_runtime.c \
		-o $(OUT)/tests/wait_runtime_unit
	@$(OUT)/tests/wait_runtime_unit

futex-runtime-unit: tools/tests/futex_runtime_unit.c \
		$(SRC)/kernel/futex_runtime.c include/kernel/futex_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/futex_runtime_unit.c $(SRC)/kernel/futex_runtime.c \
		-o $(OUT)/tests/futex_runtime_unit
	@$(OUT)/tests/futex_runtime_unit

pty-runtime-unit: tools/tests/pty_runtime_unit.c $(SRC)/kernel/pty_runtime.c include/kernel/pty_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/pty_runtime_unit.c $(SRC)/kernel/pty_runtime.c \
		-o $(OUT)/tests/pty_runtime_unit
	@$(OUT)/tests/pty_runtime_unit

tty-session-unit: tools/tests/tty_session_unit.c $(SRC)/kernel/tty_session.c include/kernel/tty_session.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/tty_session_unit.c $(SRC)/kernel/tty_session.c \
		-o $(OUT)/tests/tty_session_unit
	@$(OUT)/tests/tty_session_unit

process-commit-unit: tools/tests/process_commit_unit.c $(SRC)/kernel/process_commit.c include/kernel/process_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/process_commit_unit.c $(SRC)/kernel/process_commit.c \
		-o $(OUT)/tests/process_commit_unit
	@$(OUT)/tests/process_commit_unit

process-native-view-unit: tools/tests/process_native_view_unit.c $(SRC)/kernel/process_native_view.c include/kernel/process_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/process_native_view_unit.c \
		$(SRC)/kernel/process_native_view.c \
		-o $(OUT)/tests/process_native_view_unit
	@$(OUT)/tests/process_native_view_unit

proc-task-unit: tools/tests/proc_task_unit.c $(SRC)/kernel/proc_task.c include/kernel/process_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/proc_task_unit.c $(SRC)/kernel/proc_task.c \
		-o $(OUT)/tests/proc_task_unit
	@$(OUT)/tests/proc_task_unit

mm-runtime-unit: tools/tests/mm_runtime_unit.c $(SRC)/kernel/mm_runtime.c include/kernel/mm_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/mm_runtime_unit.c $(SRC)/kernel/mm_runtime.c \
		-o $(OUT)/tests/mm_runtime_unit
	@$(OUT)/tests/mm_runtime_unit

proc-memory-unit: tools/tests/proc_memory_unit.c $(SRC)/kernel/proc_memory.c $(SRC)/mm/statistics.c include/kernel/proc_memory.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/proc_memory_unit.c $(SRC)/kernel/proc_memory.c \
		$(SRC)/mm/statistics.c \
		-o $(OUT)/tests/proc_memory_unit
	@$(OUT)/tests/proc_memory_unit

page-allocator-unit: tools/tests/page_allocator_unit.c $(SRC)/mm/page_allocator.c include/mm/page_allocator.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/page_allocator_unit.c $(SRC)/mm/page_allocator.c \
		-o $(OUT)/tests/page_allocator_unit
	@$(OUT)/tests/page_allocator_unit

	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/page_allocator_unit.c $(SRC)/mm/page_allocator.c \
		-o $(OUT)/tests/page_allocator_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/page_allocator_sanitize

.PHONY: swap-storage-unit
swap-storage-unit: tools/tests/swap_storage_unit.c $(SRC)/fs/swap.c include/fs/swap.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -iquote tools/tests/host_include -iquote $(INC) \
		-DCONFIG_FS_SWAP=1 \
		-std=gnu99 -O2 -fno-builtin -fno-stack-protector \
		-Wall -Wextra -Werror \
		tools/tests/swap_storage_unit.c $(SRC)/fs/swap.c \
		-o $(OUT)/tests/swap_storage_unit
	@$(OUT)/tests/swap_storage_unit

.PHONY: swap-map-unit
swap-map-unit: tools/tests/swap_map_unit.c $(SRC)/mm/swap_map.c include/mm/swap_map.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -iquote tools/tests/host_include -iquote $(INC) \
		-DCONFIG_FS_SWAP=1 -std=gnu99 -O2 -fno-builtin \
		-fno-stack-protector -Wall -Wextra -Werror \
		tools/tests/swap_map_unit.c $(SRC)/mm/swap_map.c \
		-o $(OUT)/tests/swap_map_unit
	@$(OUT)/tests/swap_map_unit

proc-maps-unit: tools/tests/proc_maps_unit.c $(SRC)/kernel/proc_maps.c include/kernel/proc_maps.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/proc_maps_unit.c $(SRC)/kernel/proc_maps.c \
		-o $(OUT)/tests/proc_maps_unit
	@$(OUT)/tests/proc_maps_unit

scheduler-policy-unit: tools/tests/scheduler_policy_unit.c $(SRC)/kernel/scheduler_policy.c include/kernel/scheduler_policy.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/scheduler_policy_unit.c \
		$(SRC)/kernel/scheduler_policy.c \
		-o $(OUT)/tests/scheduler_policy_unit
	@$(OUT)/tests/scheduler_policy_unit

scheduler-runtime-unit: tools/tests/scheduler_runtime_unit.c $(SRC)/kernel/scheduler_runtime.c $(SRC)/kernel/scheduler_policy.c include/kernel/process_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/scheduler_runtime_unit.c \
		$(SRC)/kernel/scheduler_runtime.c $(SRC)/kernel/scheduler_policy.c \
		-o $(OUT)/tests/scheduler_runtime_unit
	@$(OUT)/tests/scheduler_runtime_unit

deferred-work-unit: tools/tests/deferred_work_unit.c \
		$(SRC)/kernel/deferred_work.c include/kernel/deferred_work.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/deferred_work_unit.c \
		$(SRC)/kernel/deferred_work.c \
		-pthread \
		-o $(OUT)/tests/deferred_work_unit
	@$(OUT)/tests/deferred_work_unit

smp-unit: tools/tests/smp_unit.c $(SRC)/kernel/smp.c include/kernel/smp.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/smp_unit.c $(SRC)/kernel/smp.c \
		-o $(OUT)/tests/smp_unit
	@$(OUT)/tests/smp_unit

x86-scheduler-context-unit: tools/tests/x86_scheduler_context_unit.c include/arch/x86_64/task.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/x86_scheduler_context_unit.c \
		-o $(OUT)/tests/x86_scheduler_context_unit
	@$(OUT)/tests/x86_scheduler_context_unit

syslog-runtime-unit: tools/tests/syslog_runtime_unit.c $(SRC)/kernel/syslog_runtime.c include/kernel/syslog_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/syslog_runtime_unit.c \
		$(SRC)/kernel/syslog_runtime.c \
		-o $(OUT)/tests/syslog_runtime_unit
	@$(OUT)/tests/syslog_runtime_unit

task-scratch-current-unit: tools/tests/task_scratch_current_unit.c $(SRC)/kernel/task_scratch.c include/kernel/task_scratch.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/task_scratch_current_unit.c \
		$(SRC)/kernel/task_scratch.c \
		-o $(OUT)/tests/task_scratch_current_unit
	@$(OUT)/tests/task_scratch_current_unit

event-dispatch-policy-unit: tools/tests/event_dispatch_policy_unit.c $(SRC)/kernel/event_dispatch_policy.c include/kernel/event_runtime.h include/kernel/inotify_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/event_dispatch_policy_unit.c \
		$(SRC)/kernel/event_dispatch_policy.c \
		-o $(OUT)/tests/event_dispatch_policy_unit
	@$(OUT)/tests/event_dispatch_policy_unit

inotify-readiness-sequence-unit: tools/tests/inotify_readiness_sequence_unit.c $(SRC)/kernel/inotify.c include/kernel/inotify.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/inotify_readiness_sequence_unit.c \
		$(SRC)/kernel/inotify.c \
		-o $(OUT)/tests/inotify_readiness_sequence_unit
	@$(OUT)/tests/inotify_readiness_sequence_unit

abi-service-dispatch-unit: tools/tests/abi_service_dispatch_unit.c $(SRC)/kernel/abi_service_dispatch.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/abi_service_dispatch_unit.c \
		$(SRC)/kernel/abi_service_dispatch.c \
		-o $(OUT)/tests/abi_service_dispatch_unit
	@$(OUT)/tests/abi_service_dispatch_unit

directory-runtime-unit: tools/tests/directory_runtime_unit.c $(SRC)/kernel/directory.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/directory_runtime_unit.c \
		$(SRC)/kernel/directory.c \
		-o $(OUT)/tests/directory_runtime_unit
	@$(OUT)/tests/directory_runtime_unit

vfs-path-cache-unit: tools/tests/vfs_path_cache_unit.c $(SRC)/vfs/path_cache.c include/vfs/path_cache.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_path_cache_unit.c \
		-o $(OUT)/tests/vfs_path_cache_unit
	@$(OUT)/tests/vfs_path_cache_unit

vfs-mount-topology-unit: tools/tests/vfs_mount_topology_unit.c $(SRC)/vfs/mount_topology.c include/vfs/vfs.h include/vfs/mount_namespace.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_mount_topology_unit.c \
		-o $(OUT)/tests/vfs_mount_topology_unit
	@$(OUT)/tests/vfs_mount_topology_unit

vfs-mount-table-unit: tools/tests/vfs_mount_table_unit.c $(SRC)/vfs/mount_namespace.c include/vfs/mount_namespace.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_mount_table_unit.c \
		$(SRC)/vfs/mount_namespace.c \
		-o $(OUT)/tests/vfs_mount_table_unit
	@$(OUT)/tests/vfs_mount_table_unit

vfs-filesystem-registry-unit: tools/tests/vfs_filesystem_registry_unit.c $(SRC)/vfs/filesystem_registry.c include/vfs/filesystem_registry.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_filesystem_registry_unit.c \
		$(SRC)/vfs/filesystem_registry.c \
		-o $(OUT)/tests/vfs_filesystem_registry_unit
	@$(OUT)/tests/vfs_filesystem_registry_unit

overlayfs-capacity-unit: tools/tests/overlayfs_capacity_unit.c $(SRC)/fs/overlayfs.c include/vfs/vfs.h
	@mkdir -p $(OUT)/tests
	@strip_flag='-Wl,--gc-sections'; \
	if [ "$$(uname -s)" = Darwin ]; then strip_flag='-Wl,-dead_strip'; fi; \
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-ffunction-sections -fdata-sections -iquote $(INC) \
		tools/tests/overlayfs_capacity_unit.c $$strip_flag \
		-o $(OUT)/tests/overlayfs_capacity_unit
	@$(OUT)/tests/overlayfs_capacity_unit

vfs-mount-snapshot-unit: tools/tests/vfs_mount_snapshot_unit.c $(SRC)/vfs/mount_snapshot.c include/vfs/mount_namespace.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_mount_snapshot_unit.c \
		$(SRC)/vfs/mount_snapshot.c \
		-o $(OUT)/tests/vfs_mount_snapshot_unit
	@$(OUT)/tests/vfs_mount_snapshot_unit

mount-api-unit: tools/tests/mount_api_unit.c $(SRC)/kernel/mount_api.c include/kernel/mount_api.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/mount_api_unit.c $(SRC)/kernel/mount_api.c \
		-o $(OUT)/tests/mount_api_unit
	@$(OUT)/tests/mount_api_unit

vfs-read-exact-unit: tools/tests/vfs_read_exact_unit.c $(SRC)/vfs/readahead.c include/vfs/vfs.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_read_exact_unit.c \
		$(SRC)/vfs/readahead.c \
		-o $(OUT)/tests/vfs_read_exact_unit
	@$(OUT)/tests/vfs_read_exact_unit

loop-device-unit: tools/tests/loop_device_unit.c $(SRC)/block/loop.c $(SRC)/block/block.c $(SRC)/vfs/readahead.c include/block/loop.h include/block/block.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-DCONFIG_LOOP_DEVICE \
		-iquote $(INC) tools/tests/loop_device_unit.c \
		$(SRC)/block/loop.c $(SRC)/block/block.c $(SRC)/vfs/readahead.c \
		-o $(OUT)/tests/loop_device_unit
	@$(OUT)/tests/loop_device_unit

SQUASHFS_TEST_IMAGE ?= work/squashfs-runtime.sqfs
$(SQUASHFS_TEST_IMAGE): tools/tests/make_squashfs_test_image.sh
	@tools/tests/make_squashfs_test_image.sh "$@"

squashfs-reader-unit: tools/tests/squashfs_reader_unit.c $(SQUASHFS_TEST_IMAGE)
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -D_DARWIN_C_SOURCE -DEDGEOS_SQFS_HOST_TEST=1 \
		-Wall -Wextra -Werror -Wno-unused-parameter -Wno-sign-compare \
		-Isrc -iquote $(INC) tools/tests/squashfs_reader_unit.c \
		$(SRC)/fs/squashfs/upstream/cache.c \
		$(SRC)/fs/squashfs/upstream/decompress.c \
		$(SRC)/fs/squashfs/upstream/dir.c \
		$(SRC)/fs/squashfs/upstream/file.c \
		$(SRC)/fs/squashfs/upstream/fs.c \
		$(SRC)/fs/squashfs/upstream/swap.c \
		$(SRC)/fs/squashfs/upstream/table.c \
		$(SRC)/fs/squashfs/upstream/xattr.c \
		$(SRC)/lib/zlib/adler32.c $(SRC)/lib/zlib/crc32.c \
		$(SRC)/lib/zlib/inffast.c $(SRC)/lib/zlib/inflate.c \
		$(SRC)/lib/zlib/inftrees.c $(SRC)/lib/zlib/zutil.c \
		-o $(OUT)/tests/squashfs_reader_unit
	@$(OUT)/tests/squashfs_reader_unit "$(SQUASHFS_TEST_IMAGE)"

EROFS_TEST_IMAGE ?= work/erofs-runtime.erofs
EROFS_LZ4_TEST_IMAGE ?= work/erofs-lz4-runtime.erofs
EROFS_LZ4_LEGACY_TEST_IMAGE ?= work/erofs-lz4-legacy-runtime.erofs
EROFS_LZ4_BIG_TEST_IMAGE ?= work/erofs-lz4-big-runtime.erofs
$(EROFS_TEST_IMAGE): tools/tests/make_erofs_test_image.sh
	@tools/tests/make_erofs_test_image.sh "$@"

$(EROFS_LZ4_TEST_IMAGE): tools/tests/make_erofs_test_image.sh
	@EROFS_COMPRESSION=lz4 tools/tests/make_erofs_test_image.sh "$@"

$(EROFS_LZ4_LEGACY_TEST_IMAGE): tools/tests/make_erofs_test_image.sh
	@EROFS_COMPRESSION=lz4-legacy tools/tests/make_erofs_test_image.sh "$@"

$(EROFS_LZ4_BIG_TEST_IMAGE): tools/tests/make_erofs_test_image.sh
	@EROFS_COMPRESSION=lz4-big tools/tests/make_erofs_test_image.sh "$@"

erofs-reader-unit: tools/tests/erofs_reader_unit.c $(EROFS_TEST_IMAGE) $(EROFS_LZ4_TEST_IMAGE) $(EROFS_LZ4_LEGACY_TEST_IMAGE) $(EROFS_LZ4_BIG_TEST_IMAGE)
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -D_DARWIN_C_SOURCE -DEDGEOS_EROFS_HOST_TEST=1 \
		-Wall -Wextra -Werror \
		-Isrc -iquote $(INC) tools/tests/erofs_reader_unit.c \
		$(SRC)/fs/erofs/erofs_reader.c \
		$(SRC)/fs/erofs/lz4_decode.c \
		-o $(OUT)/tests/erofs_reader_unit
	@$(OUT)/tests/erofs_reader_unit "$(EROFS_TEST_IMAGE)"
	@$(OUT)/tests/erofs_reader_unit "$(EROFS_LZ4_TEST_IMAGE)"
	@$(OUT)/tests/erofs_reader_unit "$(EROFS_LZ4_LEGACY_TEST_IMAGE)"
	@$(OUT)/tests/erofs_reader_unit "$(EROFS_LZ4_BIG_TEST_IMAGE)"

XFS_TEST_IMAGE ?= work/xfs-runtime.xfs
$(XFS_TEST_IMAGE): tools/tests/make_xfs_test_image.sh
	@tools/tests/make_xfs_test_image.sh "$@"

xfs-reader-unit: tools/tests/xfs_reader_unit.c $(XFS_TEST_IMAGE)
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -D_DARWIN_C_SOURCE -DEDGEOS_XFS_HOST_TEST=1 \
		-D_FILE_OFFSET_BITS=64 -Wall -Wextra -Werror \
		-Isrc -iquote $(INC) tools/tests/xfs_reader_unit.c \
		$(SRC)/fs/xfs/xfs_reader.c -o $(OUT)/tests/xfs_reader_unit
	@$(OUT)/tests/xfs_reader_unit "$(XFS_TEST_IMAGE)"

BTRFS_TEST_IMAGE ?= work/btrfs-runtime.btrfs
$(BTRFS_TEST_IMAGE): tools/tests/make_btrfs_test_image.sh
	@tools/tests/make_btrfs_test_image.sh "$@"

btrfs-reader-unit: tools/tests/btrfs_reader_unit.c $(BTRFS_TEST_IMAGE)
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -D_DARWIN_C_SOURCE -D_FILE_OFFSET_BITS=64 \
		-fno-builtin \
		-Wall -Wextra -Werror -Isrc -iquote $(INC) \
		tools/tests/btrfs_reader_unit.c $(SRC)/fs/btrfs/btrfs_reader.c \
		-o $(OUT)/tests/btrfs_reader_unit
	@$(OUT)/tests/btrfs_reader_unit "$(BTRFS_TEST_IMAGE)"

nfsd-protocol-unit: tools/tests/nfsd_protocol_unit.c $(SRC)/fs/nfsd/nfsd_protocol.c include/fs/nfsd.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) tools/tests/nfsd_protocol_unit.c \
		$(SRC)/fs/nfsd/nfsd_protocol.c \
		-o $(OUT)/tests/nfsd_protocol_unit
	@$(OUT)/tests/nfsd_protocol_unit

device-mapper-unit: tools/tests/device_mapper_unit.c $(SRC)/block/device_mapper.c $(SRC)/block/block.c $(SRC)/vfs/readahead.c $(SRC)/lib/aes.c include/block/device_mapper.h include/block/block.h include/lib/aes.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-DCONFIG_DEVICE_MAPPER \
		-iquote $(INC) tools/tests/device_mapper_unit.c \
		$(SRC)/block/device_mapper.c $(SRC)/block/block.c $(SRC)/vfs/readahead.c $(SRC)/lib/aes.c \
		-o $(OUT)/tests/device_mapper_unit
	@$(OUT)/tests/device_mapper_unit

aes-unit: tools/tests/aes_unit.c $(SRC)/lib/aes.c include/lib/aes.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) tools/tests/aes_unit.c $(SRC)/lib/aes.c \
		-o $(OUT)/tests/aes_unit
	@$(OUT)/tests/aes_unit

vfs-readahead-state-unit: tools/tests/vfs_readahead_state_unit.c $(SRC)/vfs/readahead_state.c include/vfs/readahead.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_readahead_state_unit.c \
		-o $(OUT)/tests/vfs_readahead_state_unit
	@$(OUT)/tests/vfs_readahead_state_unit

vfs-seek-data-hole-unit: tools/tests/vfs_seek_data_hole_unit.c $(SRC)/vfs/seek.c $(SRC)/kernel/linux_seek.c include/kernel/linux_seek.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_seek_data_hole_unit.c \
		$(SRC)/vfs/seek.c $(SRC)/kernel/linux_seek.c \
		-o $(OUT)/tests/vfs_seek_data_hole_unit
	@$(OUT)/tests/vfs_seek_data_hole_unit

vfs-fiemap-unit: tools/tests/vfs_fiemap_unit.c $(SRC)/vfs/fiemap.c $(SRC)/kernel/linux_fiemap.c include/kernel/linux_fiemap.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_fiemap_unit.c \
		$(SRC)/vfs/fiemap.c $(SRC)/kernel/linux_fiemap.c \
		-o $(OUT)/tests/vfs_fiemap_unit
	@$(OUT)/tests/vfs_fiemap_unit

vfs-readlink-unit: tools/tests/vfs_readlink_unit.c $(SRC)/kernel/vfs_readlink.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_readlink_unit.c \
		$(SRC)/kernel/vfs_readlink.c \
		-o $(OUT)/tests/vfs_readlink_unit
	@$(OUT)/tests/vfs_readlink_unit

vfs-metadata-unit: tools/tests/vfs_metadata_unit.c $(SRC)/kernel/vfs_metadata.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_metadata_unit.c \
		$(SRC)/kernel/vfs_metadata.c \
		-o $(OUT)/tests/vfs_metadata_unit
	@$(OUT)/tests/vfs_metadata_unit

vfs-open-unit: tools/tests/vfs_open_unit.c $(SRC)/kernel/vfs_open.c $(SRC)/kernel/vfs_result.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_open_unit.c \
		$(SRC)/kernel/vfs_open.c \
		$(SRC)/kernel/vfs_result.c \
		-o $(OUT)/tests/vfs_open_unit
	@$(OUT)/tests/vfs_open_unit

process-clone-unit: tools/tests/process_clone_unit.c $(SRC)/kernel/process_clone.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/process_clone_unit.c \
		$(SRC)/kernel/process_clone.c \
		-o $(OUT)/tests/process_clone_unit
	@$(OUT)/tests/process_clone_unit

process-exec-unit: tools/tests/process_exec_unit.c $(SRC)/kernel/process_exec.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/process_exec_unit.c \
		$(SRC)/kernel/process_exec.c \
		-o $(OUT)/tests/process_exec_unit
	@$(OUT)/tests/process_exec_unit

socket-netlink-delivery-unit: tools/tests/socket_netlink_delivery_unit.c $(SRC)/kernel/netlink_delivery_policy.c include/kernel/socket_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/socket_netlink_delivery_unit.c \
		$(SRC)/kernel/netlink_delivery_policy.c \
		-o $(OUT)/tests/socket_netlink_delivery_unit
	@$(OUT)/tests/socket_netlink_delivery_unit

network-core-unit: tools/tests/network_core_unit.c $(SRC)/net/network_core.c include/net/network_core.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/network_core_unit.c \
		$(SRC)/net/network_core.c \
		-o $(OUT)/tests/network_core_unit
	@$(OUT)/tests/network_core_unit
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/network_core_unit.c \
		$(SRC)/net/network_core.c \
		-o $(OUT)/tests/network_core_sanitize
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/network_core_sanitize

linux-netlink-netfilter-unit: tools/tests/linux_netlink_netfilter_unit.c $(SRC)/kernel/linux_netlink.c $(SRC)/net/network_core.c $(SRC)/net/linux_tun.c include/kernel/linux_netlink.h include/kernel/linux_tun.h include/net/network_core.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/linux_netlink_netfilter_unit.c \
		$(SRC)/kernel/linux_netlink.c \
		$(SRC)/net/network_core.c \
		$(SRC)/net/linux_tun.c \
		-o $(OUT)/tests/linux_netlink_netfilter_unit
	@$(OUT)/tests/linux_netlink_netfilter_unit

linux-sock-diag-unit: tools/tests/linux_sock_diag_unit.c $(SRC)/kernel/linux_sock_diag.c include/kernel/linux_sock_diag.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/linux_sock_diag_unit.c \
		$(SRC)/kernel/linux_sock_diag.c \
		-o $(OUT)/tests/linux_sock_diag_unit
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/linux_sock_diag_unit

linux-genetlink-unit: tools/tests/linux_genetlink_unit.c $(SRC)/kernel/linux_genetlink.c $(SRC)/kernel/linux_ethtool.c $(SRC)/net/network_core.c include/kernel/linux_genetlink.h include/kernel/linux_ethtool.h include/net/network_core.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/linux_genetlink_unit.c \
		$(SRC)/kernel/linux_genetlink.c \
		$(SRC)/kernel/linux_ethtool.c \
		$(SRC)/net/network_core.c \
		-o $(OUT)/tests/linux_genetlink_unit
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/linux_genetlink_unit

linux-ethtool-unit: tools/tests/linux_ethtool_unit.c $(SRC)/kernel/linux_ethtool.c $(SRC)/net/network_core.c include/kernel/linux_ethtool.h include/net/network_core.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -O1 -g -Wall -Wextra -Werror -fno-builtin \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		-iquote $(INC) \
		tools/tests/linux_ethtool_unit.c \
		$(SRC)/kernel/linux_ethtool.c \
		$(SRC)/net/network_core.c \
		-o $(OUT)/tests/linux_ethtool_unit
	@ASAN_OPTIONS=detect_leaks=0 $(OUT)/tests/linux_ethtool_unit

io-dispatch-policy-unit: tools/tests/io_dispatch_policy_unit.c $(SRC)/kernel/io_dispatch_policy.c include/kernel/io_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/io_dispatch_policy_unit.c \
		$(SRC)/kernel/io_dispatch_policy.c \
		-o $(OUT)/tests/io_dispatch_policy_unit
	@$(OUT)/tests/io_dispatch_policy_unit

vfs-context-unit: tools/tests/vfs_context_unit.c $(SRC)/kernel/vfs_context.c $(SRC)/kernel/vfs_result.c include/kernel/vfs_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_context_unit.c $(SRC)/kernel/vfs_context.c \
		$(SRC)/kernel/vfs_result.c \
		-o $(OUT)/tests/vfs_context_unit
	@$(OUT)/tests/vfs_context_unit

vfs-descriptor-policy-unit: tools/tests/vfs_descriptor_policy_unit.c $(SRC)/kernel/vfs_descriptor_policy.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_descriptor_policy_unit.c \
		$(SRC)/kernel/vfs_descriptor_policy.c \
		-o $(OUT)/tests/vfs_descriptor_policy_unit
	@$(OUT)/tests/vfs_descriptor_policy_unit

vfs-writeback-unit: tools/tests/vfs_writeback_unit.c $(SRC)/vfs/writeback.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -I$(INC) \
		tools/tests/vfs_writeback_unit.c $(SRC)/vfs/writeback.c \
		-o $(OUT)/tests/vfs_writeback_unit
	@$(OUT)/tests/vfs_writeback_unit

.PHONY: vfs-page-writeback-unit
vfs-page-writeback-unit: tools/tests/vfs_page_writeback_unit.c $(SRC)/vfs/page_writeback.c include/vfs/page_writeback.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -fno-builtin \
		-iquote $(INC) \
		tools/tests/vfs_page_writeback_unit.c \
		-o $(OUT)/tests/vfs_page_writeback_unit
	@$(OUT)/tests/vfs_page_writeback_unit

file-description-runtime-unit: tools/tests/file_description_runtime_unit.c $(SRC)/kernel/file_description_runtime.c include/kernel/file_description_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -iquote $(INC) \
		tools/tests/file_description_runtime_unit.c \
		-o $(OUT)/tests/file_description_runtime_unit
	@$(OUT)/tests/file_description_runtime_unit

pipe-runtime-unit: tools/tests/pipe_runtime_unit.c $(SRC)/kernel/pipe_runtime.c include/kernel/pipe_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -iquote $(INC) \
		tools/tests/pipe_runtime_unit.c $(SRC)/kernel/pipe_runtime.c \
		-o $(OUT)/tests/pipe_runtime_unit
	@$(OUT)/tests/pipe_runtime_unit

fd-runtime-unit: tools/tests/fd_runtime_unit.c $(SRC)/kernel/fd_runtime.c include/kernel/fd_runtime.h include/kernel/io_runtime.h include/kernel/socket_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/fd_runtime_unit.c $(SRC)/kernel/fd_runtime.c \
		-o $(OUT)/tests/fd_runtime_unit
	@$(OUT)/tests/fd_runtime_unit

fd-table-runtime-unit: tools/tests/fd_table_runtime_unit.c $(SRC)/kernel/fd_table_runtime.c include/kernel/fd_table_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -iquote $(INC) \
		tools/tests/fd_table_runtime_unit.c \
		-o $(OUT)/tests/fd_table_runtime_unit
	@$(OUT)/tests/fd_table_runtime_unit

descriptor-factory-runtime-unit: tools/tests/descriptor_factory_runtime_unit.c $(SRC)/kernel/descriptor_factory_runtime.c $(SRC)/kernel/socket_factory_runtime.c
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/descriptor_factory_runtime_unit.c \
		$(SRC)/kernel/descriptor_factory_runtime.c \
		$(SRC)/kernel/socket_factory_runtime.c \
		-o $(OUT)/tests/descriptor_factory_runtime_unit
	@$(OUT)/tests/descriptor_factory_runtime_unit

socket-runtime-unit: tools/tests/socket_poll_runtime_unit.c $(SRC)/kernel/socket_poll.c $(SRC)/kernel/socket_option_state.c $(SRC)/kernel/socket_unix_policy.c include/kernel/socket_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -iquote $(INC) \
		tools/tests/socket_poll_runtime_unit.c \
		$(SRC)/kernel/socket_poll.c \
		$(SRC)/kernel/socket_option_state.c \
		$(SRC)/kernel/socket_unix_policy.c \
		-o $(OUT)/tests/socket_runtime_unit
	@$(OUT)/tests/socket_runtime_unit

socket-message-unit: tools/tests/socket_message_unit.c $(SRC)/kernel/socket_message.c include/kernel/socket_message.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/socket_message_unit.c \
		$(SRC)/kernel/socket_message.c \
		-o $(OUT)/tests/socket_message_unit
	@$(OUT)/tests/socket_message_unit

socket-rights-unit: tools/tests/socket_rights_unit.c $(SRC)/kernel/socket_rights.c include/kernel/socket_rights.h $(SRC)/kernel/socket_message.c include/kernel/socket_message.h $(SRC)/kernel/fd_runtime.c include/kernel/fd_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -iquote $(INC) \
		tools/tests/socket_rights_unit.c \
		-o $(OUT)/tests/socket_rights_unit
	@$(OUT)/tests/socket_rights_unit

socket-rights-delivery-unit: tools/tests/socket_rights_delivery_unit.c $(SRC)/kernel/socket_rights.c include/kernel/socket_rights.h $(SRC)/kernel/socket_message.c include/kernel/socket_message.h $(SRC)/kernel/fd_runtime.c include/kernel/fd_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -iquote $(INC) \
		tools/tests/socket_rights_delivery_unit.c \
		-o $(OUT)/tests/socket_rights_delivery_unit
	@$(OUT)/tests/socket_rights_delivery_unit

socket-accept-queue-unit: tools/tests/socket_accept_queue_unit.c $(SRC)/kernel/socket_accept_queue.c include/kernel/socket_accept_queue.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -pthread -iquote $(INC) \
		tools/tests/socket_accept_queue_unit.c \
		-o $(OUT)/tests/socket_accept_queue_unit
	@$(OUT)/tests/socket_accept_queue_unit

namespace-ioctl-runtime-unit: tools/tests/namespace_ioctl_runtime_unit.c include/kernel/namespace_runtime.h
	@mkdir -p $(OUT)/tests
	@$(HOST_CC) -std=c11 -Wall -Wextra -Werror -iquote $(INC) \
		tools/tests/namespace_ioctl_runtime_unit.c \
		-o $(OUT)/tests/namespace_ioctl_runtime_unit
	@$(OUT)/tests/namespace_ioctl_runtime_unit

kernelrelease:
	@printf '%s\n' "$(KERNEL_RELEASE)"

$(INITRAMFS_IMAGE): $(INITRAMFS_TOOL) $(INITRAMFS_BASE_MANIFEST) FORCE
	@if [ -z "$(INITRAMFS_SOURCE_DIR)" ]; then \
		echo "[initramfs] CONFIG_INITRAMFS_SOURCE or INITRAMFS_SOURCE_DIR is required"; \
		exit 1; \
	fi
	python3 $(INITRAMFS_TOOL) \
		--source "$(INITRAMFS_SOURCE_DIR)" \
		$(foreach overlay,$(INITRAMFS_OVERLAYS),--overlay "$(overlay)") \
		--manifest $(INITRAMFS_BASE_MANIFEST) \
		--output $@ \
		--owner $(INITRAMFS_OWNER) \
		--mtime $(INITRAMFS_MTIME) \
		--exclude .DS_Store \
		--exclude '*/.DS_Store' \
		--compression $(INITRAMFS_COMPRESSION) \
		$(INITRAMFS_FORMAT_ARG)

initramfs: syncconfig $(INITRAMFS_IMAGE)
	@echo "[initramfs] built $(INITRAMFS_IMAGE)"

$(X86_INITRAMFS): $(INITRAMFS_TOOL) $(INITRAMFS_BASE_MANIFEST) FORCE
	@if [ -z "$(INITRAMFS_SOURCE_DIR)" ]; then \
		echo "[initramfs] CONFIG_INITRAMFS_SOURCE or INITRAMFS_SOURCE_DIR is required"; \
		exit 1; \
	fi
	@mkdir -p $(dir $@)
	python3 $(INITRAMFS_TOOL) \
		--source "$(INITRAMFS_SOURCE_DIR)" \
		$(foreach overlay,$(INITRAMFS_OVERLAYS),--overlay "$(overlay)") \
		--manifest $(INITRAMFS_BASE_MANIFEST) \
		--output $@ \
		--owner 0:0 \
		--mtime 0 \
		--exclude .DS_Store \
		--exclude '*/.DS_Store' \
		--compression $(INITRAMFS_COMPRESSION)

$(TARGET): syscall-inventory-check $(OBJS)
	@mkdir -p $(OUT)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

$(X86_INITRAMFS_ISO): $(TARGET) $(X86_INITRAMFS) $(CONFIG)/grub-initramfs.cfg
	@mkdir -p $(X86_INITRAMFS_ISO_DIR)/boot/grub
	cp -f $(TARGET) $(X86_INITRAMFS_ISO_DIR)/boot/edgeos.bin
	cp -f $(X86_INITRAMFS) $(X86_INITRAMFS_ISO_DIR)/boot/initramfs.img
	cp -f $(CONFIG)/grub-initramfs.cfg $(X86_INITRAMFS_ISO_DIR)/boot/grub/grub.cfg
	$(GRUB) -o $@ $(X86_INITRAMFS_ISO_DIR)

x86-initramfs-iso: $(X86_INITRAMFS_ISO)
	@echo "[x86_64] built $(X86_INITRAMFS_ISO)"

$(ARM64_UEFI_OBJ): $(SRC)/arch/arm64/boot/uefi.c
	@mkdir -p $(dir $@)
	$(AARCH64_CC) -I$(INC) -I$(SRC) -std=gnu11 -ffreestanding -fpic -fshort-wchar -fno-stack-protector -fno-builtin -Wall -Wextra -MMD -MP -c $< -o $@

$(ARM64_UEFI_ELF): $(ARM64_UEFI_OBJ) $(CONFIG)/linker-arm64-uefi.ld
	@mkdir -p $(ARM64_OUT)
	$(AARCH64_LD) -nostdlib -shared -Bsymbolic -z notext -T $(CONFIG)/linker-arm64-uefi.ld -o $@ $(ARM64_UEFI_OBJ)

ARM64_EDGE_C_SRCS := $(filter $(SRC)/%.c,$(ARM64_UEFI_SRCS))
ARM64_EDGE_ASM_SRCS := $(filter $(SRC)/%.S,$(ARM64_UEFI_SRCS))
ARM64_EDGE_LWIP_C_SRCS := $(filter $(LWIP_DIR)/src/%.c,$(ARM64_UEFI_SRCS))
ARM64_EDGE_PREBUILT_OBJS := $(filter %.obj,$(ARM64_UEFI_SRCS))
ARM64_EDGE_C_OBJS := \
	$(patsubst $(SRC)/%.c,$(OBJ)/arm64-edge/src/%.obj,$(ARM64_EDGE_C_SRCS))
ARM64_EDGE_ASM_OBJS := \
	$(patsubst $(SRC)/%.S,$(OBJ)/arm64-edge/src/%.obj,$(ARM64_EDGE_ASM_SRCS))
ARM64_EDGE_LWIP_C_OBJS := \
	$(patsubst $(LWIP_DIR)/src/%.c,$(OBJ)/arm64-edge/lwip/%.obj,$(ARM64_EDGE_LWIP_C_SRCS))
ARM64_EDGE_OBJS := \
	$(ARM64_EDGE_C_OBJS) $(ARM64_EDGE_ASM_OBJS) $(ARM64_EDGE_LWIP_C_OBJS)
ARM64_UEFI_LINK_OBJS := $(ARM64_EDGE_OBJS) $(ARM64_EDGE_PREBUILT_OBJS)
ARM64_EDGE_DEPS := $(ARM64_EDGE_OBJS:.obj=.d)
ARM64_UEFI_COMPILE_FLAGS = \
	-I$(INC) -I$(SRC) -I$(LWIP_DIR)/src/include -I$(VDSO_GENERATED) \
	$(ARM64_VERSION_CFLAGS) -target aarch64-unknown-windows \
	-O2 -ffreestanding -fshort-wchar -fno-stack-protector -fno-builtin \
	-mgeneral-regs-only -ffunction-sections -fdata-sections \
	-Wall -Wextra -Wframe-larger-than=2048 -MMD -MP
ARM64_UEFI_LINK_FLAGS = \
	-target aarch64-unknown-windows -fuse-ld=lld \
	-Wl,/entry:efi_main -Wl,/subsystem:efi_application -Wl,/base:0 \
	-Wl,/opt:ref -Wl,/map:$(ARM64_OUT)/BOOTAA64.map -nostdlib

$(OBJ)/arm64-edge/src/%.obj: $(SRC)/%.c $(ARM64_AUTOCONF_H)
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(ARM64_UEFI_COMPILE_FLAGS) -c $< -o $@

$(OBJ)/arm64-edge/src/kernel/linux_vdso_image.obj: $(VDSO_ARM64_IMAGE)

$(OBJ)/arm64-edge/src/%.obj: $(SRC)/%.S $(ARM64_AUTOCONF_H)
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(ARM64_UEFI_COMPILE_FLAGS) -c $< -o $@

$(OBJ)/arm64-edge/lwip/%.obj: $(LWIP_DIR)/src/%.c $(ARM64_AUTOCONF_H)
	@mkdir -p $(dir $@)
	$(ARM64_EFI_CC) $(ARM64_UEFI_COMPILE_FLAGS) -c $< -o $@

-include $(ARM64_EDGE_DEPS)

$(ARM64_UEFI_EFI): $(ARM64_AUTOCONF_H) $(ARM64_UEFI_LINK_OBJS) tools/arm64/materialize_pe_data.py | syscall-inventory-check
	@mkdir -p $(ARM64_OUT)
	$(ARM64_EFI_CC) $(ARM64_UEFI_LINK_FLAGS) $(ARM64_UEFI_LINK_OBJS) -o $@
	python3 tools/arm64/materialize_pe_data.py --objcopy $(AARCH64_OBJCOPY) $@

$(ARM64_INITRAMFS): $(INITRAMFS_TOOL) $(INITRAMFS_BASE_MANIFEST) FORCE
	@if [ -z "$(INITRAMFS_SOURCE_DIR)" ]; then \
		echo "[initramfs] CONFIG_INITRAMFS_SOURCE or INITRAMFS_SOURCE_DIR is required"; \
		exit 1; \
	fi
	@mkdir -p $(ARM64_OUT)
	python3 $(INITRAMFS_TOOL) \
		--source "$(INITRAMFS_SOURCE_DIR)" \
		$(foreach overlay,$(INITRAMFS_OVERLAYS),--overlay "$(overlay)") \
		--manifest $(INITRAMFS_BASE_MANIFEST) \
		--output $@ \
		--owner 0:0 \
		--mtime 0 \
		--exclude .DS_Store \
		--exclude '*/.DS_Store' \
		--compression $(INITRAMFS_COMPRESSION)

$(ARM64_INITRAMFS_ESP): $(ARM64_UEFI_EFI) $(ARM64_INITRAMFS) config/startup-arm64-initramfs.nsh config/cmdline-arm64-initramfs
	@mkdir -p $(ARM64_OUT)
	@rm -f $@
	@dd if=/dev/zero of=$@ bs=1048576 count=0 seek=$(ARM64_INITRAMFS_ESP_SIZE_MB) >/dev/null 2>&1
	mformat -i $@ -F -v EDGEOSINIT ::
	mmd -i $@ ::/EFI ::/EFI/BOOT ::/boot
	mcopy -i $@ $(ARM64_UEFI_EFI) ::/EFI/BOOT/BOOTAA64.EFI
	mcopy -i $@ config/startup-arm64-initramfs.nsh ::/startup.nsh
	mcopy -i $@ config/cmdline-arm64-initramfs ::/boot/cmdline
	mcopy -i $@ $(ARM64_INITRAMFS) ::/boot/initramfs.img

# QEMU's Raspberry Pi SD controller requires a power-of-two card capacity.
# Keep the board DTB and U-Boot external so their upstream licenses and update
# cadence remain independent from the EdgeOS image.
$(ARM64_RPI4_ESP): $(ARM64_UEFI_EFI) $(ARM64_INITRAMFS) config/startup-arm64-initramfs.nsh config/cmdline-arm64-initramfs
	@mkdir -p $(ARM64_OUT)
	@rm -f $@
	@dd if=/dev/zero of=$@ bs=1048576 count=0 seek=$(ARM64_RPI4_ESP_SIZE_MB) >/dev/null 2>&1
	mformat -i $@ -F -v EDGEOSRPI4 ::
	mmd -i $@ ::/EFI ::/EFI/BOOT ::/boot
	mcopy -i $@ $(ARM64_UEFI_EFI) ::/EFI/BOOT/BOOTAA64.EFI
	mcopy -i $@ config/startup-arm64-initramfs.nsh ::/startup.nsh
	mcopy -i $@ config/cmdline-arm64-initramfs ::/boot/cmdline
	mcopy -i $@ $(ARM64_INITRAMFS) ::/boot/initramfs.img

arm64-kernel: arm64-syncconfig $(ARM64_UEFI_EFI)
	@echo "[arm64] built $(ARM64_UEFI_EFI)"

arm64-initramfs-uefi: $(ARM64_INITRAMFS_ESP)
	@echo "[arm64] built $(ARM64_UEFI_EFI)"
	@echo "[arm64] built $(ARM64_INITRAMFS_ESP)"

arm64-rpi4: $(ARM64_RPI4_ESP)
	@echo "[arm64] built Raspberry Pi 4 SD image $(ARM64_RPI4_ESP)"

# This image contains the EdgeOS EFI payload and initramfs. A bootable physical
# card additionally needs current Raspberry Pi boot files, a Pi 5 U-Boot binary
# named u-boot.bin, and bcm2712-rpi-5-b.dtb copied into the FAT filesystem.
$(ARM64_RPI5_ESP): $(ARM64_UEFI_EFI) $(ARM64_INITRAMFS) config/startup-arm64-initramfs.nsh config/cmdline-arm64-initramfs
	@mkdir -p $(ARM64_OUT)
	@rm -f $@
	@dd if=/dev/zero of=$@ bs=1048576 count=0 seek=$(ARM64_RPI5_ESP_SIZE_MB) >/dev/null 2>&1
	mformat -i $@ -F -v EDGEOSRPI5 ::
	mmd -i $@ ::/EFI ::/EFI/BOOT ::/boot
	mcopy -i $@ $(ARM64_UEFI_EFI) ::/EFI/BOOT/BOOTAA64.EFI
	mcopy -i $@ config/startup-arm64-initramfs.nsh ::/startup.nsh
	mcopy -i $@ config/cmdline-arm64-initramfs ::/boot/cmdline
	@if [ -n "$$EDGEOS_RPI5_CONFIG" ]; then \
		test -f "$$EDGEOS_RPI5_CONFIG" || { echo "[arm64] missing $$EDGEOS_RPI5_CONFIG"; exit 1; }; \
		mcopy -o -i $@ "$$EDGEOS_RPI5_CONFIG" ::/config.txt; \
	fi
	mcopy -i $@ $(ARM64_INITRAMFS) ::/boot/initramfs.img
	@if [ -n "$$EDGEOS_RPI5_UBOOT" ]; then \
		test -f "$$EDGEOS_RPI5_UBOOT" || { echo "[arm64] missing $$EDGEOS_RPI5_UBOOT"; exit 1; }; \
		mcopy -o -i $@ "$$EDGEOS_RPI5_UBOOT" ::/u-boot.bin; \
	fi
	@if [ -n "$$EDGEOS_RPI5_DTB" ]; then \
		test -f "$$EDGEOS_RPI5_DTB" || { echo "[arm64] missing $$EDGEOS_RPI5_DTB"; exit 1; }; \
		mcopy -o -i $@ "$$EDGEOS_RPI5_DTB" ::/bcm2712-rpi-5-b.dtb; \
	fi

arm64-rpi5: $(ARM64_RPI5_ESP)
	@echo "[arm64] built Raspberry Pi 5 EFI payload image $(ARM64_RPI5_ESP)"
	@echo "[arm64] populate Raspberry Pi boot firmware and u-boot.bin before physical boot"

# -------------------------
# Kernel build
# -------------------------

$(OBJ)/%.o: $(SRC)/%.c $(AUTOCONF_H)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/kernel/linux_vdso_image.o: $(VDSO_X86_64_IMAGE)

$(VDSO_ARM64_SO): $(SRC)/kernel/vdso/vdso.c \
		$(SRC)/kernel/vdso/vdso.lds $(SRC)/kernel/vdso/vdso-arm64.map
	@mkdir -p $(dir $@)
	$(VDSO_CC) -target aarch64-linux-gnu -fuse-ld=lld -O2 -fPIC \
		-ffreestanding -fno-builtin -fno-stack-protector -nostdlib -shared \
		-Wl,-soname=linux-vdso.so.1 -Wl,--hash-style=both \
		-Wl,--version-script=$(SRC)/kernel/vdso/vdso-arm64.map \
		-Wl,-T,$(SRC)/kernel/vdso/vdso.lds $< -o $@

$(VDSO_X86_64_SO): $(SRC)/kernel/vdso/vdso.c \
		$(SRC)/kernel/vdso/vdso.lds $(SRC)/kernel/vdso/vdso-x86_64.map
	@mkdir -p $(dir $@)
	$(VDSO_CC) -target x86_64-linux-gnu -fuse-ld=lld -O2 -fPIC \
		-ffreestanding -fno-builtin -fno-stack-protector -nostdlib -shared \
		-Wl,-soname=linux-vdso.so.1 -Wl,--hash-style=both \
		-Wl,--version-script=$(SRC)/kernel/vdso/vdso-x86_64.map \
		-Wl,-T,$(SRC)/kernel/vdso/vdso.lds $< -o $@

$(VDSO_ARM64_IMAGE): $(VDSO_ARM64_SO) tools/build/embed_binary.py
	python3 tools/build/embed_binary.py --input $< --output $@ --size 8192

$(VDSO_X86_64_IMAGE): $(VDSO_X86_64_SO) tools/build/embed_binary.py
	python3 tools/build/embed_binary.py --input $< --output $@ --size 8192

$(OBJ)/%.o: $(SRC)/%.asm
	@mkdir -p $(dir $@)
	$(ASM) $(ASMFLAGS) $< -o $@

$(OBJ)/lwip/%.o: $(LWIP_DIR)/src/%.c $(AUTOCONF_H)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

run-x86-initramfs: x86-initramfs-iso
	@ACCEL=$${EDGEOS_QEMU_ACCEL:-kvm}; \
	FIRMWARE=$${EDGEOS_X86_UEFI_CODE:-$(X86_64_UEFI_CODE)}; \
	if [ -z "$$FIRMWARE" ] || [ ! -f "$$FIRMWARE" ]; then \
		echo "[error] x86_64 UEFI firmware is required; set EDGEOS_X86_UEFI_CODE"; \
		exit 1; \
	fi; \
	if [ "$$ACCEL" = "kvm" ]; then CPU=host; else CPU=max; fi; \
	qemu-system-x86_64 \
		-machine q35,accel=$$ACCEL \
		-cpu $$CPU \
		-smp 2 \
		-m $${EDGEOS_QEMU_MEM:-2048M} \
		-drive if=pflash,format=raw,readonly=on,file="$$FIRMWARE" \
		-nographic \
		-netdev user,id=net0 \
		-device e1000,netdev=net0 \
		-cdrom $(X86_INITRAMFS_ISO) \
		-boot d \
		-no-reboot

run-arm64-initramfs-uefi: arm64-initramfs-uefi
	@FW=$${EDGEOS_AARCH64_EFI:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}; \
	if [ ! -f "$$FW" ]; then FW="/opt/homebrew/Cellar/qemu/11.0.2/share/qemu/edk2-aarch64-code.fd"; fi; \
	if [ ! -f "$$FW" ]; then echo "[arm64] missing EDK2 AArch64 firmware; set EDGEOS_AARCH64_EFI=/path/to/edk2-aarch64-code.fd"; exit 1; fi; \
	ACCEL=$${EDGEOS_QEMU_ACCEL:-hvf}; \
	if [ "$$ACCEL" = "hvf" ]; then CPU=host; else CPU=cortex-a72; fi; \
	$(QEMU_AARCH64) \
		-machine virt,gic-version=3,acpi=off \
		-accel "$$ACCEL" \
		-global virtio-mmio.force-legacy=false \
		-cpu "$$CPU" \
		-smp 2 \
		-m $${EDGEOS_QEMU_MEM:-2048M} \
		-bios "$$FW" \
		-serial mon:stdio \
		-display none \
		-device ramfb \
		-drive if=none,file=$(ARM64_INITRAMFS_ESP),format=raw,id=esp \
		-device virtio-blk-device,drive=esp \
		-netdev user,id=net0 \
		-device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
		-device virtio-tablet-device,serial=edgeos-virtio-input-config-alignment-0000000000000000000000000000 \
		-device virtio-keyboard-device,serial=edgeos-virtio-input-config-alignment-0000000000000000000000000000 \
		-no-reboot

run-arm64-rpi4: arm64-rpi4
	@if [ -z "$$EDGEOS_RPI4_UBOOT" ] || [ ! -f "$$EDGEOS_RPI4_UBOOT" ]; then \
		echo "[arm64] set EDGEOS_RPI4_UBOOT to an AArch64 Raspberry Pi U-Boot binary"; exit 1; \
	fi; \
	if [ -z "$$EDGEOS_RPI4_DTB" ] || [ ! -f "$$EDGEOS_RPI4_DTB" ]; then \
		echo "[arm64] set EDGEOS_RPI4_DTB to bcm2711-rpi-4-b.dtb"; exit 1; \
	fi; \
	$(QEMU_AARCH64) \
		-machine raspi4b \
		-accel tcg,thread=multi \
		-smp 4 \
		-m 2G \
		-kernel "$$EDGEOS_RPI4_UBOOT" \
		-dtb "$$EDGEOS_RPI4_DTB" \
		-drive file=$(ARM64_RPI4_ESP),if=sd,format=raw \
		-serial mon:stdio \
		-display none \
		-no-reboot

clean:
	rm -rf $(OBJ) $(OUT) $(INC)/generated

# Compiler-generated dependency files are side effects of object compilation.
# Declaring them explicitly prevents GNU make from applying a built-in
# .d -> .d.o -> .d.c implicit chain when generated bridge inputs change.
$(DEPS): ;
-include $(wildcard $(DEPS))

$(BSD_BRIDGE_ARM64_DEPS): ;
-include $(wildcard $(BSD_BRIDGE_ARM64_DEPS))
