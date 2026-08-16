/*
 * Original EdgeOS code, licensed under MPL-2.0.
 *
 * ARM64 Generic UEFI boot handoff ABI.  The UEFI loader owns firmware calls;
 * the kernel owns all post-ExitBootServices execution.  Keep this structure
 * architecture-visible rather than hiding UEFI details in the generic kernel:
 * ARM64 needs the firmware memory map to build MAIR/TCR/SCTLR-compatible page
 * tables, and framebuffer/rootfs descriptions must feed the same EdgeOS
 * fbdev and block-device paths used after x86_64 Multiboot boot.
 */
#ifndef EDGEOS_ARCH_ARM64_BOOTINFO_H
#define EDGEOS_ARCH_ARM64_BOOTINFO_H

#include <stdint.h>

#define EDGEOS_ARM64_BOOTINFO_MAGIC 0x4544474541363442ULL /* "EDGEA64B" */
#define EDGEOS_ARM64_BOOTINFO_VERSION 2u
#define EDGEOS_ARM64_BOOTINFO_FLAG_GOP_FB   (1u << 0)
#define EDGEOS_ARM64_BOOTINFO_FLAG_ROOTFS   (1u << 1)
#define EDGEOS_ARM64_BOOTINFO_FLAG_EFI_MMAP (1u << 2)
#define EDGEOS_ARM64_BOOTINFO_FLAG_FDT      (1u << 3)
#define EDGEOS_ARM64_BOOTINFO_FLAG_ACPI     (1u << 4)
#define EDGEOS_ARM64_BOOTINFO_FLAG_INITRAMFS (1u << 5)

typedef struct edgeos_arm64_efi_mmap_info {
    uint64_t map;
    uint64_t size;
    uint64_t descriptor_size;
    uint32_t descriptor_version;
    uint32_t reserved;
} edgeos_arm64_efi_mmap_info_t;

typedef struct edgeos_arm64_fb_info {
    uint64_t base;
    uint64_t size;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t r_mask;
    uint32_t g_mask;
    uint32_t b_mask;
    uint32_t r_pos;
    uint32_t g_pos;
    uint32_t b_pos;
} edgeos_arm64_fb_info_t;

typedef struct edgeos_arm64_module_info {
    uint64_t base;
    uint64_t size;
    uint32_t type;
    uint32_t reserved;
} edgeos_arm64_module_info_t;

typedef struct edgeos_arm64_bootinfo {
    uint64_t magic;
    uint32_t version;
    uint32_t flags;
    edgeos_arm64_efi_mmap_info_t efi_mmap;
    edgeos_arm64_fb_info_t fb;
    edgeos_arm64_module_info_t rootfs;
    edgeos_arm64_module_info_t initramfs;
    edgeos_arm64_module_info_t kernel_image;
    uint64_t fdt_base;
    uint64_t fdt_size;
    uint64_t acpi_rsdp;
    uint64_t efi_system_table;
} edgeos_arm64_bootinfo_t;

#endif /* EDGEOS_ARCH_ARM64_BOOTINFO_H */
