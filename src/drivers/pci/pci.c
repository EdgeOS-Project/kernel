/* SPDX-License-Identifier: MPL-2.0 */
/*
 * PCI configuration-space helpers for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This is original EdgeOS code.  It implements PCI config access through
 * ACPI MCFG/PCIe ECAM when firmware publishes a usable window, and falls
 * back to conventional 0xcf8/0xcfc I/O on legacy machines.
 *
 * Red flags:
 * - Do not enable MSI/MSI-X from this common helper.  Interrupt routing has to
 *   be owned by the device driver and coordinated with IOAPIC/APIC support.
 * - Do not trust firmware/device capability lists without loop bounds; broken
 *   hardware can create cycles or unaligned next pointers.
 * - Do not copy Linux PCI implementation code; public PCI register layouts are
 *   enough for this small helper.
 */

#include "drivers/pci.h"
#ifdef CONFIG_ACPI
#include "drivers/acpi.h"
#endif
#include "arch/x86_64/io_ports.h"
#include "string.h"
#include "sys/mmio.h"

#define PCI_CFG_ADDR_PORT 0xCF8u
#define PCI_CFG_DATA_PORT 0xCFCu

#define PCI_COMMAND_STATUS       0x04u
#define PCI_STATUS_CAP_LIST      0x0010u
#define PCI_HEADER_TYPE          0x0Eu
#define PCI_CAP_PTR_TYPE0        0x34u
#define PCI_INTERRUPT_LINE_REG   0x3Cu

#define PCI_BUS_COUNT       256u
#define PCI_SLOT_COUNT       32u
#define PCI_FUNCTION_COUNT    8u
#define PCI_BDF_COUNT \
    (PCI_BUS_COUNT * PCI_SLOT_COUNT * PCI_FUNCTION_COUNT)

static uint32_t g_pci_function_ids[PCI_BDF_COUNT];
static uint32_t g_pci_present_functions;
static int g_pci_inventory_ready;

static uint32_t pci_bdf_index(uint8_t bus, uint8_t slot, uint8_t func) {
    return ((uint32_t)bus * PCI_SLOT_COUNT + (uint32_t)slot) *
           PCI_FUNCTION_COUNT + (uint32_t)func;
}

static int pci_ecam_addr(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off,
                         uint64_t *addr) {
#ifdef CONFIG_ACPI
    struct acpi_mcfg_window mcfg;
    uint32_t count;

    if (!addr || slot >= 32u || func >= 8u) return 0;
    count = acpi_mcfg_count();
    for (uint32_t i = 0; i < count; ++i) {
        if (acpi_get_mcfg(i, &mcfg) < 0) continue;
        if (mcfg.segment != 0) continue;
        if (bus < mcfg.start_bus || bus > mcfg.end_bus) continue;
        /*
         * PCIe ECAM reserves 4 KiB per function, 32 functions per bus slot,
         * and 1 MiB per bus.  Per ACPI MCFG, base_address corresponds to bus
         * 0 of the segment, not to start_bus.  Keep segment filtering strict
         * until EdgeOS exposes non-zero PCI domains in Linux sysfs names.
         */
        *addr = mcfg.base_address +
                (((uint64_t)bus << 20) |
                 ((uint64_t)slot << 15) |
                 ((uint64_t)func << 12) |
                 ((uint64_t)off & 0xFFFu));
        return 1;
    }
#else
    (void)bus;
    (void)slot;
    (void)func;
    (void)off;
    (void)addr;
#endif
    return 0;
}

static uint32_t pci_cfg_addr(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off) {
    return 0x80000000u |
           ((uint32_t)bus << 16) |
           ((uint32_t)slot << 11) |
           ((uint32_t)func << 8) |
           ((uint32_t)off & 0xFCu);
}

static uint32_t pci_cfg_read32_raw(uint8_t bus, uint8_t slot, uint8_t func,
                                   uint8_t off) {
    uint64_t ecam;

    if (pci_ecam_addr(bus, slot, func, (uint8_t)(off & 0xFCu), &ecam)) {
        return *(volatile uint32_t *)edge_mmio_low_alias(ecam);
    }
    outportl(PCI_CFG_ADDR_PORT, pci_cfg_addr(bus, slot, func, off));
    return inportl(PCI_CFG_DATA_PORT);
}

void pci_inventory_refresh(void) {
    uint32_t present = 0;

    /*
     * Keep a direct BDF-indexed identity table.  Drivers commonly scan for a
     * class or vendor independently, and making offset-zero reads O(1) lets
     * existing complete driver probes share this inventory without coupling
     * them to a central driver registry.
     */
    __atomic_store_n(&g_pci_inventory_ready, 0, __ATOMIC_RELEASE);
    memset(g_pci_function_ids, (char)0xFF, sizeof(g_pci_function_ids));
    for (uint32_t bus = 0; bus < PCI_BUS_COUNT; ++bus) {
        for (uint32_t slot = 0; slot < PCI_SLOT_COUNT; ++slot) {
            uint8_t bus8 = (uint8_t)bus;
            uint8_t slot8 = (uint8_t)slot;
            uint32_t id0 = pci_cfg_read32_raw(bus8, slot8, 0, 0);
            uint32_t functions;

            g_pci_function_ids[pci_bdf_index(bus8, slot8, 0)] = id0;
            if ((id0 & 0xFFFFu) == PCI_VENDOR_INVALID) continue;
            present++;
            functions =
                (pci_cfg_read32_raw(bus8, slot8, 0, PCI_HEADER_TYPE) &
                 0x00800000u) ? PCI_FUNCTION_COUNT : 1u;
            for (uint32_t function = 1; function < functions; ++function) {
                uint8_t function8 = (uint8_t)function;
                uint32_t id =
                    pci_cfg_read32_raw(bus8, slot8, function8, 0);
                g_pci_function_ids[
                    pci_bdf_index(bus8, slot8, function8)] = id;
                if ((id & 0xFFFFu) != PCI_VENDOR_INVALID) present++;
            }
        }
    }
    g_pci_present_functions = present;
    __atomic_store_n(&g_pci_inventory_ready, 1, __ATOMIC_RELEASE);
}

void pci_inventory_init(void) {
    if (__atomic_load_n(&g_pci_inventory_ready, __ATOMIC_ACQUIRE)) return;
    pci_inventory_refresh();
}

uint32_t pci_function_count(void) {
    pci_inventory_init();
    return g_pci_present_functions;
}

int pci_function_at(uint32_t index, uint8_t *bus, uint8_t *slot,
                    uint8_t *function) {
    uint32_t seen = 0;

    if (!bus || !slot || !function) return -1;
    pci_inventory_init();
    for (uint32_t current_bus = 0; current_bus < PCI_BUS_COUNT;
         ++current_bus) {
        for (uint32_t current_slot = 0; current_slot < PCI_SLOT_COUNT;
             ++current_slot) {
            for (uint32_t current_function = 0;
                 current_function < PCI_FUNCTION_COUNT;
                 ++current_function) {
                uint32_t identity = g_pci_function_ids[pci_bdf_index(
                    (uint8_t)current_bus, (uint8_t)current_slot,
                    (uint8_t)current_function)];

                if ((identity & 0xffffu) == PCI_VENDOR_INVALID) continue;
                if (seen++ != index) continue;
                *bus = (uint8_t)current_bus;
                *slot = (uint8_t)current_slot;
                *function = (uint8_t)current_function;
                return 0;
            }
        }
    }
    return -1;
}

uint32_t pci_cfg_read32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off) {
    if ((off & 0xFCu) == 0 &&
        __atomic_load_n(&g_pci_inventory_ready, __ATOMIC_ACQUIRE)) {
        return g_pci_function_ids[pci_bdf_index(bus, slot, func)];
    }
    return pci_cfg_read32_raw(bus, slot, func, off);
}

void pci_cfg_write32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint32_t v) {
    uint64_t ecam;

    if (pci_ecam_addr(bus, slot, func, (uint8_t)(off & 0xFCu), &ecam)) {
        *(volatile uint32_t *)edge_mmio_low_alias(ecam) = v;
        return;
    }
    outportl(PCI_CFG_ADDR_PORT, pci_cfg_addr(bus, slot, func, off));
    outportl(PCI_CFG_DATA_PORT, v);
}

uint16_t pci_cfg_read16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off) {
    uint32_t v = pci_cfg_read32(bus, slot, func, (uint8_t)(off & 0xFCu));
    uint8_t sh = (uint8_t)((off & 2u) * 8u);
    return (uint16_t)((v >> sh) & 0xFFFFu);
}

void pci_cfg_write16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint16_t v) {
    uint32_t cur = pci_cfg_read32(bus, slot, func, (uint8_t)(off & 0xFCu));
    uint32_t sh = (uint32_t)(off & 2u) * 8u;
    cur = (cur & ~(0xFFFFu << sh)) | ((uint32_t)v << sh);
    pci_cfg_write32(bus, slot, func, (uint8_t)(off & 0xFCu), cur);
}

uint8_t pci_cfg_read8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off) {
    uint32_t v = pci_cfg_read32(bus, slot, func, (uint8_t)(off & 0xFCu));
    uint8_t sh = (uint8_t)((off & 3u) * 8u);
    return (uint8_t)((v >> sh) & 0xFFu);
}

void pci_cfg_write8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t off, uint8_t v) {
    uint32_t cur = pci_cfg_read32(bus, slot, func, (uint8_t)(off & 0xFCu));
    uint32_t sh = (uint32_t)(off & 3u) * 8u;
    cur = (cur & ~(0xFFu << sh)) | ((uint32_t)v << sh);
    pci_cfg_write32(bus, slot, func, (uint8_t)(off & 0xFCu), cur);
}

uint8_t pci_header_type(uint8_t bus, uint8_t slot, uint8_t func) {
    return pci_cfg_read8(bus, slot, func, PCI_HEADER_TYPE);
}

uint8_t pci_interrupt_line(uint8_t bus, uint8_t slot, uint8_t func) {
    return pci_cfg_read8(bus, slot, func, PCI_INTERRUPT_LINE_REG);
}

uint32_t pci_read_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar_index) {
    if (bar_index >= 6) return 0;
    return pci_cfg_read32(bus, slot, func, (uint8_t)(0x10u + ((uint32_t)bar_index * 4u)));
}

int pci_find_capability(uint8_t bus, uint8_t slot, uint8_t func, uint8_t cap_id) {
    uint16_t status;
    uint8_t cap;

    status = pci_cfg_read16(bus, slot, func, PCI_COMMAND_STATUS + 2u);
    if ((status & PCI_STATUS_CAP_LIST) == 0) return 0;

    cap = (uint8_t)(pci_cfg_read8(bus, slot, func, PCI_CAP_PTR_TYPE0) & 0xFCu);
    for (uint32_t guard = 0; guard < 48u && cap >= 0x40u; ++guard) {
        uint8_t id = pci_cfg_read8(bus, slot, func, cap);
        uint8_t next = (uint8_t)(pci_cfg_read8(bus, slot, func, (uint8_t)(cap + 1u)) & 0xFCu);

        if (id == cap_id) return (int)cap;
        if (next == cap) break;
        cap = next;
    }
    return 0;
}

int pci_has_msi(uint8_t bus, uint8_t slot, uint8_t func) {
    return pci_find_capability(bus, slot, func, PCI_CAP_ID_MSI) != 0;
}

int pci_has_msix(uint8_t bus, uint8_t slot, uint8_t func) {
    return pci_find_capability(bus, slot, func, PCI_CAP_ID_MSIX) != 0;
}

int pci_has_pcie(uint8_t bus, uint8_t slot, uint8_t func) {
    return pci_find_capability(bus, slot, func, PCI_CAP_ID_PCIE) != 0;
}

static int pci_snap_append_char(char *buf, uint32_t max, uint32_t *off, char c) {
    if (!buf || !off || *off + 1u >= max) return -1;
    buf[(*off)++] = c;
    buf[*off] = 0;
    return 0;
}

static int pci_snap_append_lit(char *buf, uint32_t max, uint32_t *off, const char *s) {
    if (!s) return -1;
    while (*s) {
        if (pci_snap_append_char(buf, max, off, *s++) < 0) return -1;
    }
    return 0;
}

static int pci_snap_append_u32(char *buf, uint32_t max, uint32_t *off, uint32_t v) {
    char tmp[11];
    int n = 0;

    if (v == 0) return pci_snap_append_char(buf, max, off, '0');
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        if (pci_snap_append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int pci_snap_append_hex(char *buf, uint32_t max, uint32_t *off, uint32_t v, uint32_t digits) {
    static const char hx[] = "0123456789abcdef";

    if (digits > 8) digits = 8;
    for (int i = (int)digits - 1; i >= 0; --i) {
        if (pci_snap_append_char(buf, max, off, hx[(v >> ((uint32_t)i * 4u)) & 0xFu]) < 0) return -1;
    }
    return 0;
}

static int pci_snap_space(char *buf, uint32_t max, uint32_t *off) {
    return pci_snap_append_char(buf, max, off, ' ');
}

static int pci_snapshot_function(char *buf, uint32_t max, uint32_t *off,
                                 uint8_t bus, uint8_t slot, uint8_t func) {
    uint16_t vendor = pci_cfg_read16(bus, slot, func, 0x00);
    uint16_t device;
    uint8_t revision;
    uint8_t prog_if;
    uint8_t subclass;
    uint8_t class_code;

    if (vendor == PCI_VENDOR_INVALID) return 0;
    device = pci_cfg_read16(bus, slot, func, 0x02);
    revision = pci_cfg_read8(bus, slot, func, 0x08);
    prog_if = pci_cfg_read8(bus, slot, func, 0x09);
    subclass = pci_cfg_read8(bus, slot, func, 0x0A);
    class_code = pci_cfg_read8(bus, slot, func, 0x0B);

    if (pci_snap_append_lit(buf, max, off, "bdf ") < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, bus, 2) < 0) return -1;
    if (pci_snap_append_char(buf, max, off, ':') < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, slot, 2) < 0) return -1;
    if (pci_snap_append_char(buf, max, off, '.') < 0) return -1;
    if (pci_snap_append_u32(buf, max, off, func) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " vendor 0x") < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, vendor, 4) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " device 0x") < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, device, 4) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " class 0x") < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, class_code, 2) < 0) return -1;
    if (pci_snap_append_char(buf, max, off, '/') < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, subclass, 2) < 0) return -1;
    if (pci_snap_append_char(buf, max, off, '/') < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, prog_if, 2) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " rev 0x") < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, revision, 2) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " irq ") < 0) return -1;
    if (pci_snap_append_u32(buf, max, off, pci_interrupt_line(bus, slot, func)) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " pcie ") < 0) return -1;
    if (pci_snap_append_u32(buf, max, off, pci_has_pcie(bus, slot, func) ? 1u : 0u) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " msi ") < 0) return -1;
    if (pci_snap_append_u32(buf, max, off, pci_has_msi(bus, slot, func) ? 1u : 0u) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " msix ") < 0) return -1;
    if (pci_snap_append_u32(buf, max, off, pci_has_msix(bus, slot, func) ? 1u : 0u) < 0) return -1;
    if (pci_snap_append_lit(buf, max, off, " bars") < 0) return -1;
    for (uint8_t bar = 0; bar < 6; ++bar) {
        if (pci_snap_space(buf, max, off) < 0) return -1;
        if (pci_snap_append_lit(buf, max, off, "0x") < 0) return -1;
        if (pci_snap_append_hex(buf, max, off, pci_read_bar(bus, slot, func, bar), 8) < 0) return -1;
    }
    return pci_snap_append_char(buf, max, off, '\n');
}

int pci_inventory_snapshot(char *buf, uint32_t max) {
    uint32_t off = 0;
    uint32_t functions = 0;

    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (pci_snap_append_lit(buf, max, &off, "pci: yes\n") < 0) return -1;
    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint32_t slot = 0; slot < 32u; ++slot) {
            uint16_t vendor0 = pci_cfg_read16((uint8_t)bus, (uint8_t)slot, 0, 0x00);
            uint8_t header_type;
            uint32_t max_func;

            if (vendor0 == PCI_VENDOR_INVALID) continue;
            header_type = pci_header_type((uint8_t)bus, (uint8_t)slot, 0);
            max_func = (header_type & 0x80u) ? 8u : 1u;
            for (uint32_t func = 0; func < max_func; ++func) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x00);
                if (vendor == PCI_VENDOR_INVALID) continue;
                if (pci_snapshot_function(buf, max, &off, (uint8_t)bus, (uint8_t)slot, (uint8_t)func) < 0) return -1;
                functions++;
            }
        }
    }
    if (pci_snap_append_lit(buf, max, &off, "functions: ") < 0) return -1;
    if (pci_snap_append_u32(buf, max, &off, functions) < 0) return -1;
    if (pci_snap_append_char(buf, max, &off, '\n') < 0) return -1;
    return (int)off;
}

static int pci_append_bdf_name(char *buf, uint32_t max, uint32_t *off,
                               uint8_t bus, uint8_t slot, uint8_t func) {
    if (pci_snap_append_lit(buf, max, off, "0000:") < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, bus, 2) < 0) return -1;
    if (pci_snap_append_char(buf, max, off, ':') < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, slot, 2) < 0) return -1;
    if (pci_snap_append_char(buf, max, off, '.') < 0) return -1;
    return pci_snap_append_u32(buf, max, off, func);
}

int pci_device_name_by_index(uint32_t index, char *out, uint32_t out_sz) {
    uint32_t seen = 0;

    if (!out || out_sz == 0) return -1;
    out[0] = 0;
    for (uint32_t bus = 0; bus < 256u; ++bus) {
        for (uint32_t slot = 0; slot < 32u; ++slot) {
            uint16_t vendor0 = pci_cfg_read16((uint8_t)bus, (uint8_t)slot, 0, 0x00);
            uint8_t header_type;
            uint32_t max_func;

            if (vendor0 == PCI_VENDOR_INVALID) continue;
            header_type = pci_header_type((uint8_t)bus, (uint8_t)slot, 0);
            max_func = (header_type & 0x80u) ? 8u : 1u;
            for (uint32_t func = 0; func < max_func; ++func) {
                uint16_t vendor = pci_cfg_read16((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x00);
                uint32_t off = 0;

                if (vendor == PCI_VENDOR_INVALID) continue;
                if (seen++ != index) continue;
                if (pci_append_bdf_name(out, out_sz, &off, (uint8_t)bus, (uint8_t)slot, (uint8_t)func) < 0) return -1;
                return 0;
            }
        }
    }
    return -1;
}

static int pci_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int pci_parse_hex2(const char *s, uint8_t *out) {
    int hi;
    int lo;
    if (!s || !out) return -1;
    hi = pci_hex_nibble(s[0]);
    lo = pci_hex_nibble(s[1]);
    if (hi < 0 || lo < 0) return -1;
    *out = (uint8_t)((hi << 4) | lo);
    return 0;
}

static int pci_parse_bdf_name(const char *name, uint8_t *bus, uint8_t *slot, uint8_t *func) {
    uint8_t parsed_bus;
    uint8_t parsed_slot;
    int parsed_func;

    if (!name || !bus || !slot || !func) return -1;
    if (pci_hex_nibble(name[0]) < 0 || pci_hex_nibble(name[1]) < 0 ||
        pci_hex_nibble(name[2]) < 0 || pci_hex_nibble(name[3]) < 0 ||
        name[4] != ':' || name[7] != ':' || name[10] != '.' || name[12] != 0) {
        return -1;
    }
    /*
     * EdgeOS currently exposes domain 0000 only.  Keep the parser strict so
     * future PCIe segment support does not accidentally alias different Linux
     * sysfs device names onto the same config-space access.
     */
    if (name[0] != '0' || name[1] != '0' || name[2] != '0' || name[3] != '0') return -1;
    if (pci_parse_hex2(name + 5, &parsed_bus) < 0) return -1;
    if (pci_parse_hex2(name + 8, &parsed_slot) < 0) return -1;
    if (name[11] < '0' || name[11] > '7') return -1;
    parsed_func = name[11] - '0';
    if (parsed_slot >= 32u) return -1;
    if (pci_cfg_read16(parsed_bus, parsed_slot, (uint8_t)parsed_func, 0x00) == PCI_VENDOR_INVALID) return -1;
    *bus = parsed_bus;
    *slot = parsed_slot;
    *func = (uint8_t)parsed_func;
    return 0;
}

static int pci_sysfs_split_device_path(const char *path, char *name, uint32_t name_sz,
                                       const char **file_out,
                                       uint8_t *bus, uint8_t *slot, uint8_t *func) {
    static const char prefix[] = "/sys/bus/pci/devices/";
    const char *rest;
    uint32_t i = 0;

    if (!path || !name || name_sz == 0 || !file_out || !bus || !slot || !func) return -1;
    if (strncmp(path, prefix, sizeof(prefix) - 1u) != 0) return -1;
    rest = path + sizeof(prefix) - 1u;
    while (rest[i] && rest[i] != '/' && i + 1u < name_sz) {
        name[i] = rest[i];
        ++i;
    }
    name[i] = 0;
    if (rest[i] && rest[i] != '/') return -1;
    if (pci_parse_bdf_name(name, bus, slot, func) < 0) return -1;
    *file_out = rest[i] == '/' ? rest + i + 1u : rest + i;
    return 0;
}

static int pci_sysfs_device_file_known(const char *file, int *is_link) {
    static const char *files[] = {
        "vendor", "device", "subsystem_vendor", "subsystem_device", "class",
        "revision", "irq", "resource", "modalias", "uevent"
    };

    if (!file || !is_link) return 0;
    *is_link = 0;
    if (strcmp(file, "subsystem") == 0) {
        *is_link = 1;
        return 1;
    }
    for (uint32_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        if (strcmp(file, files[i]) == 0) return 1;
    }
    return 0;
}

int pci_sysfs_path_kind(const char *path) {
    char name[16];
    const char *file;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    int is_link = 0;

    if (!path) return PCI_SYSFS_PATH_NONE;
    if (strcmp(path, "/sys/bus") == 0 ||
        strcmp(path, "/sys/bus/pci") == 0 ||
        strcmp(path, "/sys/bus/pci/devices") == 0) {
        return PCI_SYSFS_PATH_DIR;
    }
    if (pci_sysfs_split_device_path(path, name, sizeof(name), &file, &bus, &slot, &func) < 0) {
        return PCI_SYSFS_PATH_NONE;
    }
    if (!file[0]) return PCI_SYSFS_PATH_DIR;
    if (!pci_sysfs_device_file_known(file, &is_link)) return PCI_SYSFS_PATH_NONE;
    return is_link ? PCI_SYSFS_PATH_LINK : PCI_SYSFS_PATH_FILE;
}

static int pci_sysfs_append_hex_upper(char *buf, uint32_t max, uint32_t *off,
                                      uint32_t v, uint32_t digits) {
    static const char hx[] = "0123456789ABCDEF";

    if (digits > 8) digits = 8;
    for (int i = (int)digits - 1; i >= 0; --i) {
        if (pci_snap_append_char(buf, max, off, hx[(v >> ((uint32_t)i * 4u)) & 0xFu]) < 0) return -1;
    }
    return 0;
}

static int pci_sysfs_append_prefixed_hex(char *buf, uint32_t max, uint32_t *off,
                                         uint32_t v, uint32_t digits) {
    if (pci_snap_append_lit(buf, max, off, "0x") < 0) return -1;
    if (pci_snap_append_hex(buf, max, off, v, digits) < 0) return -1;
    if (pci_snap_append_char(buf, max, off, '\n') < 0) return -1;
    return (int)*off;
}

static int pci_sysfs_resource(char *buf, uint32_t max, uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t off = 0;

    if (!buf || max == 0) return -1;
    buf[0] = 0;
    for (uint8_t bar = 0; bar < 6u; ++bar) {
        uint32_t raw = pci_read_bar(bus, slot, func, bar);
        uint32_t start = 0;
        uint32_t end = 0;
        uint32_t flags = 0;

        if (raw != 0) {
            if (raw & 1u) {
                start = raw & ~3u;
                end = start;
                flags = 0x00000100u;
            } else {
                start = raw & ~0xFu;
                end = start;
                flags = 0x00000200u;
            }
        }
        if (pci_snap_append_lit(buf, max, &off, "0x") < 0) return -1;
        if (pci_snap_append_hex(buf, max, &off, start, 8) < 0) return -1;
        if (pci_snap_append_char(buf, max, &off, ' ') < 0) return -1;
        if (pci_snap_append_lit(buf, max, &off, "0x") < 0) return -1;
        if (pci_snap_append_hex(buf, max, &off, end, 8) < 0) return -1;
        if (pci_snap_append_char(buf, max, &off, ' ') < 0) return -1;
        if (pci_snap_append_lit(buf, max, &off, "0x") < 0) return -1;
        if (pci_snap_append_hex(buf, max, &off, flags, 8) < 0) return -1;
        if (pci_snap_append_char(buf, max, &off, '\n') < 0) return -1;
    }
    return (int)off;
}

static int pci_sysfs_modalias(char *buf, uint32_t max, uint8_t bus, uint8_t slot, uint8_t func, int newline) {
    uint32_t off = 0;
    uint16_t vendor = pci_cfg_read16(bus, slot, func, 0x00);
    uint16_t device = pci_cfg_read16(bus, slot, func, 0x02);
    uint16_t subsys_vendor = pci_cfg_read16(bus, slot, func, 0x2C);
    uint16_t subsys_device = pci_cfg_read16(bus, slot, func, 0x2E);
    uint8_t prog_if = pci_cfg_read8(bus, slot, func, 0x09);
    uint8_t subclass = pci_cfg_read8(bus, slot, func, 0x0A);
    uint8_t class_code = pci_cfg_read8(bus, slot, func, 0x0B);

    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (pci_snap_append_lit(buf, max, &off, "pci:v0000") < 0) return -1;
    if (pci_sysfs_append_hex_upper(buf, max, &off, vendor, 4) < 0) return -1;
    if (pci_snap_append_lit(buf, max, &off, "d0000") < 0) return -1;
    if (pci_sysfs_append_hex_upper(buf, max, &off, device, 4) < 0) return -1;
    if (pci_snap_append_lit(buf, max, &off, "sv0000") < 0) return -1;
    if (pci_sysfs_append_hex_upper(buf, max, &off, subsys_vendor, 4) < 0) return -1;
    if (pci_snap_append_lit(buf, max, &off, "sd0000") < 0) return -1;
    if (pci_sysfs_append_hex_upper(buf, max, &off, subsys_device, 4) < 0) return -1;
    if (pci_snap_append_lit(buf, max, &off, "bc") < 0) return -1;
    if (pci_sysfs_append_hex_upper(buf, max, &off, class_code, 2) < 0) return -1;
    if (pci_snap_append_lit(buf, max, &off, "sc") < 0) return -1;
    if (pci_sysfs_append_hex_upper(buf, max, &off, subclass, 2) < 0) return -1;
    if (pci_snap_append_lit(buf, max, &off, "i") < 0) return -1;
    if (pci_sysfs_append_hex_upper(buf, max, &off, prog_if, 2) < 0) return -1;
    if (newline && pci_snap_append_char(buf, max, &off, '\n') < 0) return -1;
    return (int)off;
}

int pci_sysfs_read_file(const char *path, char *out, uint32_t max) {
    char name[16];
    const char *file;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint32_t off = 0;
    uint16_t vendor;
    uint16_t device;
    uint16_t subsys_vendor;
    uint16_t subsys_device;
    uint8_t revision;
    uint8_t prog_if;
    uint8_t subclass;
    uint8_t class_code;
    char modalias[96];

    if (!out || max == 0) return -1;
    out[0] = 0;
    if (pci_sysfs_split_device_path(path, name, sizeof(name), &file, &bus, &slot, &func) < 0) return -1;
    if (!file[0]) return -1;

    vendor = pci_cfg_read16(bus, slot, func, 0x00);
    device = pci_cfg_read16(bus, slot, func, 0x02);
    revision = pci_cfg_read8(bus, slot, func, 0x08);
    prog_if = pci_cfg_read8(bus, slot, func, 0x09);
    subclass = pci_cfg_read8(bus, slot, func, 0x0A);
    class_code = pci_cfg_read8(bus, slot, func, 0x0B);
    subsys_vendor = pci_cfg_read16(bus, slot, func, 0x2C);
    subsys_device = pci_cfg_read16(bus, slot, func, 0x2E);

    if (strcmp(file, "vendor") == 0) return pci_sysfs_append_prefixed_hex(out, max, &off, vendor, 4);
    if (strcmp(file, "device") == 0) return pci_sysfs_append_prefixed_hex(out, max, &off, device, 4);
    if (strcmp(file, "subsystem_vendor") == 0) return pci_sysfs_append_prefixed_hex(out, max, &off, subsys_vendor, 4);
    if (strcmp(file, "subsystem_device") == 0) return pci_sysfs_append_prefixed_hex(out, max, &off, subsys_device, 4);
    if (strcmp(file, "revision") == 0) return pci_sysfs_append_prefixed_hex(out, max, &off, revision, 2);
    if (strcmp(file, "irq") == 0) {
        if (pci_snap_append_u32(out, max, &off, pci_interrupt_line(bus, slot, func)) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, '\n') < 0) return -1;
        return (int)off;
    }
    if (strcmp(file, "class") == 0) {
        if (pci_snap_append_lit(out, max, &off, "0x") < 0) return -1;
        if (pci_snap_append_hex(out, max, &off,
                                ((uint32_t)class_code << 16) |
                                ((uint32_t)subclass << 8) |
                                (uint32_t)prog_if, 6) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, '\n') < 0) return -1;
        return (int)off;
    }
    if (strcmp(file, "resource") == 0) return pci_sysfs_resource(out, max, bus, slot, func);
    if (strcmp(file, "modalias") == 0) return pci_sysfs_modalias(out, max, bus, slot, func, 1);
    if (strcmp(file, "uevent") == 0) {
        if (pci_sysfs_modalias(modalias, sizeof(modalias), bus, slot, func, 0) < 0) return -1;
        if (pci_snap_append_lit(out, max, &off, "PCI_CLASS=") < 0) return -1;
        if (pci_sysfs_append_hex_upper(out, max, &off,
                                       ((uint32_t)class_code << 16) |
                                       ((uint32_t)subclass << 8) |
                                       (uint32_t)prog_if, 6) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, '\n') < 0) return -1;
        if (pci_snap_append_lit(out, max, &off, "PCI_ID=") < 0) return -1;
        if (pci_sysfs_append_hex_upper(out, max, &off, vendor, 4) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, ':') < 0) return -1;
        if (pci_sysfs_append_hex_upper(out, max, &off, device, 4) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, '\n') < 0) return -1;
        if (pci_snap_append_lit(out, max, &off, "PCI_SUBSYS_ID=") < 0) return -1;
        if (pci_sysfs_append_hex_upper(out, max, &off, subsys_vendor, 4) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, ':') < 0) return -1;
        if (pci_sysfs_append_hex_upper(out, max, &off, subsys_device, 4) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, '\n') < 0) return -1;
        if (pci_snap_append_lit(out, max, &off, "PCI_SLOT_NAME=") < 0) return -1;
        if (pci_snap_append_lit(out, max, &off, name) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, '\n') < 0) return -1;
        if (pci_snap_append_lit(out, max, &off, "MODALIAS=") < 0) return -1;
        if (pci_snap_append_lit(out, max, &off, modalias) < 0) return -1;
        if (pci_snap_append_char(out, max, &off, '\n') < 0) return -1;
        return (int)off;
    }
    return -1;
}

int pci_sysfs_readlink(const char *path, char *out, uint32_t max) {
    char name[16];
    const char *file;
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    const char *target = "../../../bus/pci";
    uint32_t n;

    if (!path || !out || max == 0) return -1;
    if (pci_sysfs_split_device_path(path, name, sizeof(name), &file, &bus, &slot, &func) < 0) return -1;
    if (strcmp(file, "subsystem") != 0) return -1;
    n = (uint32_t)strlen(target);
    if (n > max) n = max;
    memcpy(out, target, n);
    return (int)n;
}
