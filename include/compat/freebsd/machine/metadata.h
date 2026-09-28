/* SPDX-License-Identifier: MPL-2.0 */
/* Shared boot metadata definitions used by imported firmware drivers. */

#ifndef EDGEOS_COMPAT_FREEBSD_MACHINE_METADATA_H
#define EDGEOS_COMPAT_FREEBSD_MACHINE_METADATA_H

#include <sys/types.h>

#if defined(__x86_64__) || defined(BSD_BRIDGE_FIRMWARE_METADATA_TEST_X86)
#define MODINFOMD_SMAP 0x1001
#define MODINFOMD_SMAP_XATTR 0x1002
#define MODINFOMD_EFI_MAP 0x1004
#define MODINFOMD_VBE_FB 0x1104
#else
#define MODINFOMD_EFI_MAP 0x1001
#endif
#define MODINFOMD_DTBP 0x1102
#define MODINFOMD_EFI_FB 0x1103

struct efi_map_header {
    size_t memory_size;
    size_t descriptor_size;
    uint32_t descriptor_version;
};

struct efi_fb {
    uint64_t fb_addr;
    uint64_t fb_size;
    uint32_t fb_height;
    uint32_t fb_width;
    uint32_t fb_stride;
    uint32_t fb_mask_red;
    uint32_t fb_mask_green;
    uint32_t fb_mask_blue;
    uint32_t fb_mask_reserved;
};

#if defined(__x86_64__) || defined(BSD_BRIDGE_FIRMWARE_METADATA_TEST_X86)
struct vbe_fb {
    uint64_t fb_addr;
    uint64_t fb_size;
    uint32_t fb_height;
    uint32_t fb_width;
    uint32_t fb_stride;
    uint32_t fb_mask_red;
    uint32_t fb_mask_green;
    uint32_t fb_mask_blue;
    uint32_t fb_mask_reserved;
    uint32_t fb_bpp;
};
#endif

#endif
