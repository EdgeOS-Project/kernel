/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS ARM64 EL1 translation setup.
 * Copyright (c) EdgeOS Contributors.
 *
 * The UEFI memory map is the authoritative physical-memory inventory at the
 * handoff boundary.  We build an identity mapping from it before attempting
 * any allocator, interrupt, or process setup.  This avoids retaining the
 * firmware's translation tables after ExitBootServices and keeps MMIO and GOP
 * scanout mappings distinct from ordinary cacheable RAM.
 */

#include <stdint.h>
#include "arch/arm64/mmu.h"
#include "arch/arm64/interrupt.h"
#include "arch/arm64/platform.h"
#include "drivers/virtio_net_mmio.h"
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
#include "compat/freebsd/edgeos/ofw.h"
#endif

#define ARM64_PAGE_SIZE          4096ULL
#define ARM64_L2_BLOCK_SIZE      (2ULL * 1024ULL * 1024ULL)
#define ARM64_L1_REGION_SIZE     (1024ULL * 1024ULL * 1024ULL)
#define ARM64_L0_REGION_SIZE     (512ULL * 1024ULL * 1024ULL * 1024ULL)
#define ARM64_TABLE_ENTRIES      512u
#define ARM64_MAX_L0_TABLES      16u
#define ARM64_MAX_L2_TABLES      128u
#define ARM64_PCI_EARLY_CELLS    128u
#define ARM64_PCI_EARLY_MAP_MAX  (4ULL * 1024ULL * 1024ULL * 1024ULL)
#define ARM64_PCI_EARLY_64_WINDOW ARM64_L1_REGION_SIZE

#define ARM64_DESC_VALID         (1ULL << 0)
#define ARM64_DESC_TABLE         (1ULL << 1)
#define ARM64_DESC_AF            (1ULL << 10)
#define ARM64_DESC_NG            (1ULL << 11)
#define ARM64_DESC_SH_INNER      (3ULL << 8)
#define ARM64_DESC_ATTRIDX(n)    ((uint64_t)(n) << 2)

#define EFI_MEMORY_MAPPED_IO     11u
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12u

typedef struct {
    uint32_t type;
    uint32_t pad;
    uint64_t physical_start;
    uint64_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} efi_memory_descriptor_t;

static uint64_t g_l0[ARM64_TABLE_ENTRIES] __attribute__((aligned(ARM64_PAGE_SIZE)));
static uint64_t g_l1[ARM64_MAX_L0_TABLES][ARM64_TABLE_ENTRIES]
    __attribute__((aligned(ARM64_PAGE_SIZE)));
static uint64_t g_l2[ARM64_MAX_L2_TABLES][ARM64_TABLE_ENTRIES]
    __attribute__((aligned(ARM64_PAGE_SIZE)));
static uint16_t g_l0_slot[ARM64_TABLE_ENTRIES];
static uint16_t g_l2_slot[ARM64_MAX_L0_TABLES][ARM64_TABLE_ENTRIES];
static uint32_t g_l1_count;
static uint32_t g_l2_count;
static int g_translation_tables_initialized;
static volatile unsigned int g_device_map_lock;

static uint64_t arm64_cache_line_size(void) {
    uint64_t ctr;

    __asm__ __volatile__("mrs %0, ctr_el0" : "=r"(ctr));
    return 4ULL << ((ctr >> 16) & 0xfu);
}

static void arm64_clean_range(const void *address, uint64_t length) {
    uint64_t line;
    uint64_t cursor;
    uint64_t end;

    if (!address || !length) return;
    line = arm64_cache_line_size();
    cursor = (uint64_t)(uintptr_t)address & ~(line - 1u);
    end = ((uint64_t)(uintptr_t)address + length + line - 1u) &
          ~(line - 1u);
    for (; cursor < end; cursor += line)
        __asm__ __volatile__("dc cvac, %0" :: "r"(cursor) : "memory");
}

static void arm64_clean_invalidate_range(const void *address,
                                         uint64_t length) {
    uint64_t line;
    uint64_t cursor;
    uint64_t end;

    if (!address || !length) return;
    line = arm64_cache_line_size();
    cursor = (uint64_t)(uintptr_t)address & ~(line - 1u);
    end = ((uint64_t)(uintptr_t)address + length + line - 1u) &
          ~(line - 1u);
    for (; cursor < end; cursor += line)
        __asm__ __volatile__("dc civac, %0" :: "r"(cursor) : "memory");
}

static void edgeos_memset(void *dst, uint8_t value, uint64_t size) {
    uint8_t *p = (uint8_t *)dst;
    while (size--) *p++ = value;
}

static uint64_t align_down(uint64_t value, uint64_t align) {
    return value & ~(align - 1ULL);
}

static uint64_t align_up(uint64_t value, uint64_t align) {
    if (value > UINT64_MAX - (align - 1ULL)) return 0;
    return (value + align - 1ULL) & ~(align - 1ULL);
}

static int ensure_l1(uint32_t l0_index, uint64_t **table_out, uint32_t *slot_out) {
    uint16_t slot;

    if (l0_index >= ARM64_TABLE_ENTRIES) return -1;
    slot = g_l0_slot[l0_index];
    if (!slot) {
        if (g_l1_count >= ARM64_MAX_L0_TABLES) return -1;
        slot = (uint16_t)(++g_l1_count);
        g_l0_slot[l0_index] = slot;
        g_l0[l0_index] = ((uint64_t)(uintptr_t)g_l1[slot - 1u]) |
                         ARM64_DESC_VALID | ARM64_DESC_TABLE;
    }
    *table_out = g_l1[slot - 1u];
    *slot_out = (uint32_t)(slot - 1u);
    return 0;
}

static int ensure_l2(uint32_t l0_index, uint32_t l1_index, uint64_t **table_out) {
    uint64_t *l1;
    uint32_t l1_slot;
    uint16_t slot;

    if (ensure_l1(l0_index, &l1, &l1_slot) < 0) return -1;
    slot = g_l2_slot[l1_slot][l1_index];
    if (!slot) {
        if (g_l2_count >= ARM64_MAX_L2_TABLES) return -1;
        slot = (uint16_t)(++g_l2_count);
        g_l2_slot[l1_slot][l1_index] = slot;
        l1[l1_index] = ((uint64_t)(uintptr_t)g_l2[slot - 1u]) |
                       ARM64_DESC_VALID | ARM64_DESC_TABLE;
    }
    *table_out = g_l2[slot - 1u];
    return 0;
}

static int map_range(uint64_t start, uint64_t size, uint32_t attr_index) {
    uint64_t addr;
    uint64_t end;

    if (!size || start >= (1ULL << 48)) return 0;
    end = align_up(start + size, ARM64_L2_BLOCK_SIZE);
    if (!end || end > (1ULL << 48)) return -1;
    addr = align_down(start, ARM64_L2_BLOCK_SIZE);

    while (addr < end) {
        uint32_t l0_index = (uint32_t)(addr / ARM64_L0_REGION_SIZE);
        uint32_t l1_index = (uint32_t)((addr / ARM64_L1_REGION_SIZE) & 0x1ffULL);
        uint32_t l2_index = (uint32_t)((addr / ARM64_L2_BLOCK_SIZE) & 0x1ffULL);
        uint64_t *l2;

        if (ensure_l2(l0_index, l1_index, &l2) < 0) return -1;
        l2[l2_index] = addr | ARM64_DESC_VALID | ARM64_DESC_AF |
                       ARM64_DESC_NG | ARM64_DESC_SH_INNER |
                       ARM64_DESC_ATTRIDX(attr_index);
        addr += ARM64_L2_BLOCK_SIZE;
    }
    return 0;
}

static uint64_t *lookup_l2_entry(uint64_t address) {
    uint32_t l0_index = (uint32_t)(address / ARM64_L0_REGION_SIZE);
    uint32_t l1_index =
        (uint32_t)((address / ARM64_L1_REGION_SIZE) & 0x1ffULL);
    uint32_t l2_index =
        (uint32_t)((address / ARM64_L2_BLOCK_SIZE) & 0x1ffULL);
    uint16_t l1_slot;
    uint16_t l2_slot;

    if (l0_index >= ARM64_TABLE_ENTRIES)
        return 0;
    l1_slot = g_l0_slot[l0_index];
    if (l1_slot == 0)
        return 0;
    l2_slot = g_l2_slot[l1_slot - 1u][l1_index];
    if (l2_slot == 0)
        return 0;
    return &g_l2[l2_slot - 1u][l2_index];
}

int edgeos_arm64_mmu_map_device_range(uint64_t start, uint64_t size) {
    uint64_t first;
    uint64_t end;
    int result = -1;

    if (!g_translation_tables_initialized || size == 0 ||
        start >= (UINT64_C(1) << 48) ||
        size - 1u > UINT64_MAX - start ||
        start + size > (UINT64_C(1) << 48))
        return -1;
    first = align_down(start, ARM64_L2_BLOCK_SIZE);
    end = align_up(start + size, ARM64_L2_BLOCK_SIZE);
    if (end == 0)
        return -1;

    while (__atomic_test_and_set(&g_device_map_lock, __ATOMIC_ACQUIRE))
        __asm__ __volatile__("yield");
    for (uint64_t address = first; address < end;
         address += ARM64_L2_BLOCK_SIZE) {
        uint64_t *entry = lookup_l2_entry(address);
        uint64_t descriptor;

        if (!entry || !((*entry) & ARM64_DESC_VALID))
            continue;
        descriptor = *entry;
        if ((descriptor &
                UINT64_C(0x0000fffffffff000) &
                ~(ARM64_L2_BLOCK_SIZE - 1u)) != address ||
            ((descriptor >> 2) & 7u) != 1u)
            goto out;
    }
    if (map_range(start, size, 1u) < 0)
        goto out;
    arm64_clean_range(g_l0, sizeof(g_l0));
    arm64_clean_range(g_l1, sizeof(g_l1));
    arm64_clean_range(g_l2, sizeof(g_l2));
    __asm__ __volatile__(
        "dsb ishst\n\t"
        "tlbi vmalle1is\n\t"
        "dsb ish\n\t"
        "isb"
        ::: "memory");
    result = 0;
out:
    __atomic_clear(&g_device_map_lock, __ATOMIC_RELEASE);
    return result;
}

static int map_efi_descriptors(const edgeos_arm64_bootinfo_t *bootinfo, int mmio_only) {
    uint64_t off;

    for (off = 0; off + bootinfo->efi_mmap.descriptor_size <= bootinfo->efi_mmap.size;
         off += bootinfo->efi_mmap.descriptor_size) {
        const efi_memory_descriptor_t *d =
            (const efi_memory_descriptor_t *)(uintptr_t)(bootinfo->efi_mmap.map + off);
        uint64_t bytes;
        int is_mmio = d->type == EFI_MEMORY_MAPPED_IO ||
                      d->type == EFI_MEMORY_MAPPED_IO_PORT_SPACE;

        if ((mmio_only && !is_mmio) || (!mmio_only && is_mmio)) continue;
        if (d->number_of_pages > UINT64_MAX / ARM64_PAGE_SIZE) return -1;
        bytes = d->number_of_pages * ARM64_PAGE_SIZE;
        if (map_range(d->physical_start, bytes, is_mmio ? 1u : 0u) < 0) return -1;
    }
    return 0;
}

#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_DEVICE_TREE)
static int decode_fdt_cells(const pcell_t *cells, uint32_t count,
                            uint64_t *value) {
    uint64_t decoded = 0;

    if (!cells || !value || count == 0 || count > 2) return -1;
    for (uint32_t index = 0; index < count; ++index)
        decoded = (decoded << 32) | cells[index];
    *value = decoded;
    return 0;
}

static uint32_t fdt_cell_count(phandle_t node, const char *property,
                               uint32_t fallback) {
    pcell_t value;

    return OF_getencprop(node, property, &value, sizeof(value)) ==
        (ssize_t)sizeof(value) ? value : fallback;
}

static int map_fdt_device_node(phandle_t node) {
    size_t register_count;

    if (bsd_ofw_fdt_node_status_okay(node) &&
        OF_hasprop(node, "compatible") &&
        !bsd_ofw_fdt_node_is_compatible(node, "shared-dma-pool") &&
        !bsd_ofw_fdt_node_is_compatible(node, "simple-framebuffer") &&
        bsd_ofw_fdt_get_reg_count(node, &register_count) == 0) {
        for (size_t index = 0; index < register_count; ++index) {
            uint64_t address;
            uint64_t size;

            if (bsd_ofw_fdt_get_reg(node, (unsigned int)index,
                    &address, &size) == 0 && size != 0 &&
                map_range(address, size, 1u) < 0)
                return -1;
        }
    }
    for (phandle_t child = OF_child(node); child != 0;
         child = OF_peer(child)) {
        if (map_fdt_device_node(child) < 0)
            return -1;
    }
    return 0;
}

static int map_fdt_device_registers(void) {
    phandle_t root = OF_peer(0);

    return root == 0 ? 0 : map_fdt_device_node(root);
}

static int map_pci_host_windows(void) {
    phandle_t node = bsd_ofw_fdt_find_compatible(
        "pci-host-ecam-generic", 0);
    phandle_t parent;
    pcell_t cells[ARM64_PCI_EARLY_CELLS];
    uint64_t ecam_base;
    uint64_t ecam_size;
    uint32_t child_address_cells;
    uint32_t parent_address_cells;
    uint32_t size_cells;
    uint32_t stride;
    ssize_t length;

    if (node == 0) return 0;
    if (bsd_ofw_fdt_get_reg(node, 0, &ecam_base, &ecam_size) != 0 ||
        map_range(ecam_base, ecam_size, 1u) < 0) return -1;
    parent = OF_parent(node);
    if (parent == 0) return -1;
    child_address_cells = fdt_cell_count(node, "#address-cells", 3);
    parent_address_cells =
        fdt_cell_count(parent, "#address-cells", 2);
    size_cells = fdt_cell_count(node, "#size-cells", 2);
    if (child_address_cells != 3 ||
        parent_address_cells == 0 || parent_address_cells > 2 ||
        size_cells == 0 || size_cells > 2) return -1;
    stride = child_address_cells + parent_address_cells + size_cells;
    length = OF_getencprop(node, "ranges", cells, sizeof(cells));
    if (length < 0 || length % (ssize_t)sizeof(cells[0]) != 0 ||
        (uint32_t)(length / (ssize_t)sizeof(cells[0])) % stride != 0)
        return -1;
    for (uint32_t offset = 0;
         offset < (uint32_t)(length / (ssize_t)sizeof(cells[0]));
         offset += stride) {
        uint64_t host_base;
        uint64_t range_size;

        if (decode_fdt_cells(&cells[offset + child_address_cells],
                parent_address_cells, &host_base) < 0 ||
            decode_fdt_cells(&cells[offset + child_address_cells +
                parent_address_cells], size_cells, &range_size) < 0)
            return -1;
        /*
         * The low PCI windows are mapped in full.  Firmware commonly places
         * early 64-bit BARs at the start of a much larger aperture, so map its
         * first GiB without consuming tables for the entire advertised range.
         */
        if (range_size > ARM64_PCI_EARLY_MAP_MAX)
            range_size = ARM64_PCI_EARLY_64_WINDOW;
        if (range_size != 0 &&
            map_range(host_base, range_size, 1u) < 0) return -1;
    }
    return 0;
}
#else
static int map_fdt_device_registers(void) {
    return 0;
}

static int map_pci_host_windows(void) {
    return 0;
}
#endif

static void arm64_install_translation(
    const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t mmfr0;
    uint64_t pa_range;
    uint64_t cpacr;
    uint64_t sctlr;
    const uint64_t mair = 0x00000000004404ffULL;
    uint64_t tcr;

    __asm__ __volatile__("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    pa_range = mmfr0 & 0xfu;
    if (pa_range > 5u) pa_range = 5u;
    tcr = 16ULL | (1ULL << 8) | (1ULL << 10) |
          (3ULL << 12) | (1ULL << 23) | (pa_range << 32);
    if (((mmfr0 >> 4) & 0xfu) >= 2u)
        tcr |= 1ULL << 36; /* TCR_EL1.AS: use all 16 implemented ASID bits. */

    /*
     * U-Boot leaves the Raspberry Pi framebuffer and these newly-created page
     * tables in write-back mappings.  Publish page-table entries before the
     * hardware walker uses them, and remove framebuffer cache lines before
     * changing that aperture to Normal Non-Cacheable memory.  Keeping stale
     * write-back lines across the attribute transition produces striped or
     * torn scanout on real BCM2712 hardware even though emulators tolerate it.
     */
    arm64_clean_range(g_l0, sizeof(g_l0));
    arm64_clean_range(g_l1, sizeof(g_l1));
    arm64_clean_range(g_l2, sizeof(g_l2));
    if (bootinfo &&
        (bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_GOP_FB) &&
        bootinfo->fb.base && bootinfo->fb.size)
        arm64_clean_invalidate_range(
            (const void *)(uintptr_t)bootinfo->fb.base,
            bootinfo->fb.size);
    __asm__ __volatile__("dsb sy\n\tisb" ::: "memory");
    __asm__ __volatile__("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr &= ~1ULL;
    __asm__ __volatile__("msr sctlr_el1, %0\n\tisb" :: "r"(sctlr) : "memory");
    __asm__ __volatile__("msr mair_el1, %0" :: "r"(mair));
    __asm__ __volatile__("msr tcr_el1, %0" :: "r"(tcr));
    __asm__ __volatile__("msr ttbr0_el1, %0" :: "r"((uint64_t)(uintptr_t)g_l0));
    __asm__ __volatile__("dsb ishst\n\ttlbi vmalle1\n\tdsb ish\n\tisb" ::: "memory");
    /*
     * Linux AArch64 permits ordinary unaligned EL0 loads and stores.  UEFI is
     * allowed to leave SCTLR_EL1.A set, so do not inherit that firmware policy
     * into Linux userspace; libraries and Xorg legitimately use unaligned data.
     * Stack-pointer alignment checking remains controlled independently by
     * SA/SA0.
     */
    sctlr &= ~(1ULL << 1);
    /* Linux AArch64 permits EL0 cache-ID reads, DC ZVA, and user cache maintenance. */
    sctlr |= 1ULL | (1ULL << 14) | (1ULL << 15) | (1ULL << 26);
    __asm__ __volatile__("msr sctlr_el1, %0\n\tisb" :: "r"(sctlr) : "memory");

    /* Firmware policy must not determine whether Linux userspace can use FP/SIMD. */
    __asm__ __volatile__("mrs %0, cpacr_el1" : "=r"(cpacr));
    cpacr |= 3ULL << 20;
    __asm__ __volatile__("msr cpacr_el1, %0\n\tisb" :: "r"(cpacr) : "memory");
}

int edgeos_arm64_mmu_init(const edgeos_arm64_bootinfo_t *bootinfo) {
    uint64_t gicd;
    uint64_t gicr;
    uint64_t virtio_mmio;
    if (!bootinfo || !bootinfo->efi_mmap.map || !bootinfo->efi_mmap.descriptor_size) return -1;

    /*
     * U-Boot can start the EFI payload at EL2.  In that case UEFI prepares
     * these EL1 tables before eret, then EL1 calls this function again after
     * installing the firmware Device Tree.  Never clear a table that EL1 is
     * already executing through.  Retaining the table allocation metadata
     * also lets the second pass add platform MMIO mappings atomically before
     * the final translation-register refresh.
     */
    if (!g_translation_tables_initialized) {
        edgeos_memset(g_l0, 0, sizeof(g_l0));
        edgeos_memset(g_l1, 0, sizeof(g_l1));
        edgeos_memset(g_l2, 0, sizeof(g_l2));
        edgeos_memset(g_l0_slot, 0, sizeof(g_l0_slot));
        edgeos_memset(g_l2_slot, 0, sizeof(g_l2_slot));
        g_l1_count = 0;
        g_l2_count = 0;
    }

    if (map_efi_descriptors(bootinfo, 0) < 0 || map_efi_descriptors(bootinfo, 1) < 0) return -1;
    if (bootinfo->kernel_image.base && bootinfo->kernel_image.size &&
        map_range(bootinfo->kernel_image.base, bootinfo->kernel_image.size, 0u) < 0)
        return -1;
    /*
     * Raspberry Pi firmware and U-Boot expose the scanout as write-back
     * memory and require explicit cache cleaning after drawing.  Preserve
     * that proven attribute across the EL1 handoff; changing the live BCM2712
     * aperture to Normal Non-Cacheable produces striped scanout on hardware.
     */
    if ((bootinfo->flags & EDGEOS_ARM64_BOOTINFO_FLAG_GOP_FB) &&
        map_range(bootinfo->fb.base, bootinfo->fb.size, 0u) < 0) return -1;
    /*
     * QEMU EDK2 does not describe the GIC MMIO aperture in every EFI memory
     * map.  The platform table is authoritative for this device region, so
     * map it explicitly before replacing firmware translations.
     */
    if (edgeos_arm64_gic_discover(bootinfo, &gicd, &gicr) == 0) {
        if (map_range(gicd, ARM64_L2_BLOCK_SIZE, 1u) < 0 ||
            map_range(gicr, ARM64_L2_BLOCK_SIZE, 1u) < 0) return -1;
    }
    if (edgeos_arm64_platform_serial_base() != 0 &&
        map_range(edgeos_arm64_platform_serial_base(),
                  ARM64_PAGE_SIZE, 1u) < 0)
        return -1;
    if (edgeos_arm64_virtio_mmio_aperture(bootinfo, &virtio_mmio) == 0 &&
        map_range(virtio_mmio, ARM64_L2_BLOCK_SIZE, 1u) < 0) return -1;
    if (map_fdt_device_registers() < 0) return -1;
    if (map_pci_host_windows() < 0) return -1;

    arm64_install_translation(bootinfo);
    g_translation_tables_initialized = 1;
    return 0;
}
