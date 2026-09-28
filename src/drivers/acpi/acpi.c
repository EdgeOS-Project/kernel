// SPDX-License-Identifier: MPL-2.0
/*
 * ACPI firmware table discovery for EdgeOS.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This file intentionally performs read-only discovery: do not enable ACPI
 * control methods, interrupt remapping, power resources, or timer switching
 * here.  Those require dedicated drivers and must be wired only after their
 * Linux-visible behavior is understood.
 *
 * Red flags:
 * - Never trust firmware pointers before validating the owning table checksum.
 * - Do not treat discovery logs as driver support.  Device drivers must opt in
 *   to the parsed topology and preserve Linux ABI behavior at user/kernel APIs.
 * - Do not copy Linux ACPI implementation code.  Linux UAPI/docs are reference
 *   material only under this repository's licensing rules.
 */

#include "drivers/acpi.h"
#include "arch/x86_64/io_ports.h"
#include "stdio.h"
#include "string.h"

#include <stdint.h>

#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_BSD_DRIVER_ACPICA)
#include "compat/freebsd/edgeos/acpi_power.h"
#endif

#define MULTIBOOT2_BOOTLOADER_MAGIC 0x36d76289u
#define MB2_TAG_TYPE_END 0u
#define MB2_TAG_TYPE_ACPI_OLD 14u
#define MB2_TAG_TYPE_ACPI_NEW 15u

#define ACPI_RSDP_SIG "RSD PTR "
#define ACPI_RSDT_SIG "RSDT"
#define ACPI_XSDT_SIG "XSDT"
#define ACPI_FADT_SIG "FACP"
#define ACPI_DSDT_SIG "DSDT"
#define ACPI_MADT_SIG "APIC"
#define ACPI_HPET_SIG "HPET"
#define ACPI_MCFG_SIG "MCFG"
#define ACPI_FACS_SIG "FACS"

#define ACPI_MAX_TABLES 64u
#define ACPI_MAX_HPET 8u
#define ACPI_MAX_MCFG 16u
#define ACPI_MAX_IOAPIC 8u
#define ACPI_MAX_IRQ_OVERRIDE 16u
#define ACPI_MAX_PROCESSORS 256u
#define ACPI_TABLE_STORAGE_SIZE (4u * 1024u * 1024u)

struct mb2_tag {
    uint32_t type;
    uint32_t size;
};

struct acpi_rsdp {
    char signature[8];
    uint8_t checksum;
    char oemid[6];
    uint8_t revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed));

struct acpi_sdt_header {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oemid[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

struct acpi_facs_min {
    char signature[4];
    uint32_t length;
} __attribute__((packed));

struct acpi_madt {
    struct acpi_sdt_header hdr;
    uint32_t local_apic_address;
    uint32_t flags;
    uint8_t entries[];
} __attribute__((packed));

struct acpi_gas {
    uint8_t address_space_id;
    uint8_t register_bit_width;
    uint8_t register_bit_offset;
    uint8_t access_size;
    uint64_t address;
} __attribute__((packed));

struct acpi_hpet {
    struct acpi_sdt_header hdr;
    uint32_t event_timer_block_id;
    struct acpi_gas address;
    uint8_t hpet_number;
    uint16_t minimum_tick;
    uint8_t page_protection;
} __attribute__((packed));

struct acpi_mcfg_allocation {
    uint64_t base_address;
    uint16_t pci_segment;
    uint8_t start_bus_number;
    uint8_t end_bus_number;
    uint32_t reserved;
} __attribute__((packed));

struct acpi_fadt_min {
    struct acpi_sdt_header hdr;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t reserved0;
    uint8_t preferred_pm_profile;
    uint16_t sci_interrupt;
    uint32_t smi_command_port;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_control;
    uint32_t pm1a_event_block;
    uint32_t pm1b_event_block;
    uint32_t pm1a_control_block;
    uint32_t pm1b_control_block;
    uint32_t pm2_control_block;
    uint32_t pm_timer_block;
    uint32_t gpe0_block;
    uint32_t gpe1_block;
    uint8_t pm1_event_length;
    uint8_t pm1_control_length;
    uint8_t pm2_control_length;
    uint8_t pm_timer_length;
    uint8_t gpe0_block_length;
    uint8_t gpe1_block_length;
    uint8_t gpe1_base;
    uint8_t cst_control;
    uint16_t c2_latency;
    uint16_t c3_latency;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alarm;
    uint8_t month_alarm;
    uint8_t century;
    uint16_t boot_flags;
    uint8_t reserved1;
    uint32_t flags;
} __attribute__((packed));

struct acpi_fadt_extended_prefix {
    struct acpi_fadt_min v1;
    struct acpi_gas reset_register;
    uint8_t reset_value;
    uint16_t arm_boot_flags;
    uint8_t minor_revision;
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
} __attribute__((packed));

struct acpi_table_slot {
    char signature[5];
    uint64_t address;
    uint64_t firmware_address;
    uint32_t length;
    uint8_t revision;
};

struct acpi_madt_ioapic_entry {
    uint8_t type;
    uint8_t length;
    uint8_t ioapic_id;
    uint8_t reserved;
    uint32_t address;
    uint32_t global_irq_base;
} __attribute__((packed));

struct acpi_madt_irq_override_entry {
    uint8_t type;
    uint8_t length;
    uint8_t bus;
    uint8_t source_irq;
    uint32_t global_irq;
    uint16_t flags;
} __attribute__((packed));

struct acpi_madt_local_apic_entry {
    uint8_t type;
    uint8_t length;
    uint8_t processor_uid;
    uint8_t apic_id;
    uint32_t flags;
} __attribute__((packed));

struct acpi_madt_local_x2apic_entry {
    uint8_t type;
    uint8_t length;
    uint16_t reserved;
    uint32_t x2apic_id;
    uint32_t flags;
    uint32_t processor_uid;
} __attribute__((packed));

struct acpi_state {
    int available;
    uint64_t rsdp_phys;
    uint32_t rsdp_len;
    uint8_t rsdp_copy[4096];
    uint64_t rsdt_phys;
    uint64_t xsdt_phys;
    uint32_t table_count;
    struct acpi_table_slot tables[ACPI_MAX_TABLES];
    uint64_t fadt_phys;
    uint64_t facs_phys;
    uint64_t dsdt_phys;
    uint32_t fadt_profile;
    uint32_t sci_interrupt;
    uint32_t pm_timer_block;
    uint32_t pm1a_event_block;
    uint32_t pm1a_control_block;
    uint32_t pm1b_control_block;
    uint32_t gpe0_block;
    uint32_t fadt_flags;
    uint32_t lapic_address;
    uint32_t local_apics;
    uint32_t x2apics;
    uint32_t ioapics;
    uint32_t interrupt_overrides;
    uint32_t processors;
    struct acpi_processor_info processor_info[ACPI_MAX_PROCESSORS];
    struct acpi_ioapic_info ioapic_info[ACPI_MAX_IOAPIC];
    struct acpi_irq_override_info irq_overrides[ACPI_MAX_IRQ_OVERRIDE];
    uint32_t hpet_count;
    struct acpi_hpet_info hpets[ACPI_MAX_HPET];
    uint32_t mcfg_count;
    struct acpi_mcfg_window mcfgs[ACPI_MAX_MCFG];
    uint8_t has_ac_adapter;
    uint8_t has_battery;
    uint8_t has_power_button;
    uint8_t has_sleep_button;
    uint8_t has_lid_switch;
    uint8_t has_thermal_zone;
};

static struct acpi_state g_acpi;
/*
 * Firmware may place ACPI reclaim tables in ordinary physical memory.  The
 * bootstrap mapping can read that memory, but it is not guaranteed to remain
 * mapped in every process address space after userspace starts.  Keep stable
 * validated copies for runtime drivers, sysfs, and the shutdown path.
 *
 * Four MiB is deliberately larger than the complete table set on normal PC
 * firmware while still imposing a hard kernel resource limit.  Exhaustion is
 * reported and the affected table is rejected; retaining a transient firmware
 * pointer would turn a later sysfs read or poweroff into a kernel fault.
 */
static uint8_t g_acpi_table_storage[ACPI_TABLE_STORAGE_SIZE]
    __attribute__((aligned(8)));
static uint32_t g_acpi_table_storage_used;

static int acpi_facs_is_valid(const struct acpi_facs_min *facs);

static int sig_eq(const char *a, const char *b, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static uint8_t checksum8(const void *ptr, uint32_t len) {
    const uint8_t *p = (const uint8_t *)ptr;
    uint8_t sum = 0;

    for (uint32_t i = 0; i < len; ++i) sum = (uint8_t)(sum + p[i]);
    return sum;
}

static int rsdp_is_valid(const struct acpi_rsdp *rsdp, uint32_t available_len) {
    if (!rsdp) return 0;
    if (available_len < 20) return 0;
    if (!sig_eq(rsdp->signature, ACPI_RSDP_SIG, 8)) return 0;
    if (checksum8(rsdp, 20) != 0) return 0;
    if (rsdp->revision >= 2) {
        if (available_len < 36) return 0;
        if (rsdp->length < 36 || rsdp->length > 4096) return 0;
        if (available_len < rsdp->length) return 0;
        if (checksum8(rsdp, rsdp->length) != 0) return 0;
    }
    return 1;
}

static int sdt_is_valid(const struct acpi_sdt_header *hdr) {
    if (!hdr) return 0;
    if (hdr->length < sizeof(*hdr) || hdr->length > (1024u * 1024u)) return 0;
    return checksum8(hdr, hdr->length) == 0;
}

static void copy_fixed_string(char *dst, uint32_t dst_len, const char *src, uint32_t src_len) {
    uint32_t out = 0;

    if (!dst || dst_len == 0) return;
    for (uint32_t i = 0; i < src_len && out + 1 < dst_len; ++i) {
        char c = src[i];
        if (c == 0) break;
        dst[out++] = c;
    }
    dst[out] = 0;
}

static const void *copy_firmware_table(const void *source, uint32_t length,
                                       const char signature[4]) {
    uint32_t offset;

    if (!source || length == 0) return 0;
    offset = (g_acpi_table_storage_used + 7u) & ~7u;
    if (offset > ACPI_TABLE_STORAGE_SIZE ||
        length > ACPI_TABLE_STORAGE_SIZE - offset) {
        printf("[acpi] stable table storage exhausted for %.4s len=%u used=%u\n",
               signature ? signature : "????", length,
               g_acpi_table_storage_used);
        return 0;
    }
    memcpy(g_acpi_table_storage + offset, source, length);
    g_acpi_table_storage_used = offset + length;
    return g_acpi_table_storage + offset;
}

static const struct acpi_sdt_header *store_table(
    const struct acpi_sdt_header *hdr) {
    struct acpi_table_slot *slot;
    const struct acpi_sdt_header *copy;

    for (uint32_t i = 0; i < g_acpi.table_count; ++i) {
        if (g_acpi.tables[i].firmware_address ==
            (uint64_t)(uintptr_t)hdr) {
            return (const struct acpi_sdt_header *)(uintptr_t)
                g_acpi.tables[i].address;
        }
    }

    if (g_acpi.table_count >= ACPI_MAX_TABLES) {
        printf("[acpi] table registry full, dropping %.4s addr=0x%llx\n",
               hdr->signature, (unsigned long long)(uintptr_t)hdr);
        return 0;
    }
    copy = (const struct acpi_sdt_header *)copy_firmware_table(
        hdr, hdr->length, hdr->signature);
    if (!copy) return 0;

    slot = &g_acpi.tables[g_acpi.table_count++];
    copy_fixed_string(slot->signature, sizeof(slot->signature),
                      copy->signature, 4);
    slot->address = (uint64_t)(uintptr_t)copy;
    slot->firmware_address = (uint64_t)(uintptr_t)hdr;
    slot->length = copy->length;
    slot->revision = copy->revision;
    return copy;
}

static int acpi_blob_contains(const uint8_t *base, uint32_t len, const char *needle) {
    uint32_t nlen;

    if (!base || !needle) return 0;
    nlen = (uint32_t)strlen(needle);
    if (nlen == 0 || len < nlen) return 0;
    for (uint32_t i = 0; i + nlen <= len; ++i) {
        uint32_t j;
        for (j = 0; j < nlen; ++j) {
            if ((char)base[i + j] != needle[j]) break;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static void scan_dsdt_platform_devices(const struct acpi_sdt_header *hdr) {
    const uint8_t *aml;
    uint32_t aml_len;

    if (!hdr || hdr->length <= sizeof(*hdr)) return;
    aml = (const uint8_t *)hdr + sizeof(*hdr);
    aml_len = hdr->length - (uint32_t)sizeof(*hdr);

    /*
     * This is discovery only, not AML execution.  Linux-visible power_supply,
     * input, and thermal behavior must be implemented by real drivers later;
     * for now only publish devices that firmware clearly names through common
     * PNP/ACPI hardware IDs or thermal-zone method names.
     *
     * Red flags:
     * - Do not infer a battery or lid from VM profile names.
     * - Do not hardcode QEMU/rootfs assumptions in the kernel.
     * - Do not parse Linux driver source for this; ACPI IDs are public ABI.
     */
    if (acpi_blob_contains(aml, aml_len, "ACPI0003")) g_acpi.has_ac_adapter = 1;
    if (acpi_blob_contains(aml, aml_len, "PNP0C0A")) g_acpi.has_battery = 1;
    if (acpi_blob_contains(aml, aml_len, "PNP0C0C")) g_acpi.has_power_button = 1;
    if (acpi_blob_contains(aml, aml_len, "PNP0C0E")) g_acpi.has_sleep_button = 1;
    if (acpi_blob_contains(aml, aml_len, "PNP0C0D")) g_acpi.has_lid_switch = 1;
    if (acpi_blob_contains(aml, aml_len, "_TZ_") ||
        acpi_blob_contains(aml, aml_len, "_TMP") ||
        acpi_blob_contains(aml, aml_len, "TZ00") ||
        acpi_blob_contains(aml, aml_len, "THRM")) {
        g_acpi.has_thermal_zone = 1;
    }
}

static int try_register_dsdt(uint64_t dsdt) {
    const struct acpi_sdt_header *hdr;
    const struct acpi_sdt_header *copy;

    if (!dsdt) return 0;
    hdr = (const struct acpi_sdt_header *)(uintptr_t)dsdt;
    if (!sdt_is_valid(hdr)) {
        printf("[acpi][fadt] invalid DSDT addr=0x%llx\n", (unsigned long long)dsdt);
        return 0;
    }
    if (!sig_eq(hdr->signature, ACPI_DSDT_SIG, 4)) {
        printf("[acpi][fadt] DSDT pointer has unexpected signature %.4s addr=0x%llx\n",
               hdr->signature, (unsigned long long)dsdt);
        return 0;
    }
    copy = store_table(hdr);
    if (!copy) return 0;
    g_acpi.dsdt_phys = (uint64_t)(uintptr_t)copy;
    scan_dsdt_platform_devices(copy);
    printf("[acpi][dsdt] firmware=0x%llx copy=0x%llx len=%u rev=%u\n",
           (unsigned long long)dsdt,
           (unsigned long long)(uintptr_t)copy, copy->length,
           (uint32_t)copy->revision);
    return 1;
}

static int try_register_facs(uint64_t facs_address) {
    const struct acpi_facs_min *facs;
    const struct acpi_facs_min *copy;

    if (!facs_address) return 0;
    facs = (const struct acpi_facs_min *)(uintptr_t)facs_address;
    if (!acpi_facs_is_valid(facs)) {
        printf("[acpi][fadt] invalid FACS addr=0x%llx\n",
               (unsigned long long)facs_address);
        return 0;
    }
    copy = (const struct acpi_facs_min *)copy_firmware_table(
        facs, facs->length, ACPI_FACS_SIG);
    if (!copy) return 0;
    g_acpi.facs_phys = (uint64_t)(uintptr_t)copy;
    printf("[acpi][facs] firmware=0x%llx copy=0x%llx len=%u\n",
           (unsigned long long)facs_address,
           (unsigned long long)(uintptr_t)copy, copy->length);
    return 1;
}

static int aml_pkg_length(const uint8_t *p, const uint8_t *end, uint32_t *len_out,
                          const uint8_t **next_out) {
    uint8_t first;
    uint32_t len;
    uint32_t follow;

    if (!p || p >= end || !len_out || !next_out) return -1;
    first = *p++;
    follow = (uint32_t)(first >> 6);
    len = follow ? (uint32_t)(first & 0x0fu) : (uint32_t)(first & 0x3fu);
    for (uint32_t i = 0; i < follow; ++i) {
        if (p >= end) return -1;
        len |= ((uint32_t)(*p++)) << (4u + (i * 8u));
    }
    *len_out = len;
    *next_out = p;
    return 0;
}

static int aml_integer(const uint8_t **pp, const uint8_t *end, uint8_t *out) {
    const uint8_t *p;
    uint32_t val = 0;

    if (!pp || !*pp || !out) return -1;
    p = *pp;
    if (p >= end) return -1;
    switch (*p++) {
        case 0x00: val = 0; break;              /* ZeroOp */
        case 0x01: val = 1; break;              /* OneOp */
        case 0x0a:                              /* ByteConst */
            if (p >= end) return -1;
            val = *p++;
            break;
        case 0x0b:                              /* WordConst */
            if (p + 2 > end) return -1;
            val = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
            p += 2;
            break;
        case 0x0c:                              /* DWordConst */
            if (p + 4 > end) return -1;
            val = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                  ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            p += 4;
            break;
        default:
            return -1;
    }
    if (val > 7) return -1;
    *pp = p;
    *out = (uint8_t)val;
    return 0;
}

static int acpi_decode_s5(uint8_t *slp_typa, uint8_t *slp_typb) {
    const struct acpi_sdt_header *dsdt;
    const uint8_t *base;
    const uint8_t *end;

    if (!slp_typa || !slp_typb || !g_acpi.dsdt_phys) return -1;
    dsdt = (const struct acpi_sdt_header *)(uintptr_t)g_acpi.dsdt_phys;
    if (!sdt_is_valid(dsdt) || !sig_eq(dsdt->signature, ACPI_DSDT_SIG, 4)) return -1;
    base = (const uint8_t *)dsdt + sizeof(*dsdt);
    end = (const uint8_t *)dsdt + dsdt->length;

    for (const uint8_t *p = base; p + 7 < end; ++p) {
        const uint8_t *q;
        const uint8_t *pkg_start;
        const uint8_t *pkg_end;
        uint32_t pkg_len;
        uint8_t count;
        uint8_t a;
        uint8_t b;

        if (p[0] != 0x08 || p[1] != '_' || p[2] != 'S' || p[3] != '5' || p[4] != '_') continue;
        q = p + 5;
        if (q >= end || *q++ != 0x12) continue; /* PackageOp */
        pkg_start = q;
        if (aml_pkg_length(q, end, &pkg_len, &q) < 0) continue;
        if (pkg_len == 0 || pkg_start + pkg_len > end) continue;
        pkg_end = pkg_start + pkg_len;
        if (q >= pkg_end) continue;
        count = *q++;
        if (count < 2) continue;
        if (aml_integer(&q, pkg_end, &a) < 0) continue;
        if (aml_integer(&q, pkg_end, &b) < 0) b = a;
        *slp_typa = a;
        *slp_typb = b;
        return 0;
    }
    return -1;
}

static const struct acpi_rsdp *find_rsdp_multiboot2(void *boot_info) {
    uint8_t *base = (uint8_t *)boot_info;
    uint32_t total_size;
    uint8_t *p;
    uint8_t *end;

    if (!boot_info) return 0;
    total_size = *(uint32_t *)base;
    if (total_size < 16 || total_size > (4u * 1024u * 1024u)) return 0;

    p = base + 8;
    end = base + total_size;
    while (p + sizeof(struct mb2_tag) <= end) {
        struct mb2_tag *tag = (struct mb2_tag *)p;
        uint32_t aligned;

        if (tag->type == MB2_TAG_TYPE_END) break;
        if (tag->size < sizeof(*tag)) break;
        if (p + tag->size > end) break;
        if ((tag->type == MB2_TAG_TYPE_ACPI_NEW || tag->type == MB2_TAG_TYPE_ACPI_OLD) &&
            tag->size >= sizeof(*tag) + 20) {
            const struct acpi_rsdp *rsdp = (const struct acpi_rsdp *)(tag + 1);
            if (rsdp_is_valid(rsdp, tag->size - sizeof(*tag))) return rsdp;
        }
        aligned = (tag->size + 7u) & ~7u;
        if (aligned == 0) break;
        p += aligned;
    }
    return 0;
}

static const struct acpi_rsdp *scan_rsdp_range(uintptr_t start, uintptr_t end) {
    uintptr_t p;

    for (p = start; p + 20 <= end; p += 16) {
        const struct acpi_rsdp *rsdp = (const struct acpi_rsdp *)p;
        if (rsdp_is_valid(rsdp, (uint32_t)(end - p))) return rsdp;
    }
    return 0;
}

static const struct acpi_rsdp *find_rsdp_bios(void) {
    uint16_t ebda_seg = *(const uint16_t *)(uintptr_t)0x40e;
    uintptr_t ebda = ((uintptr_t)ebda_seg) << 4;
    const struct acpi_rsdp *rsdp;

    if (ebda >= 0x80000u && ebda < 0xa0000u) {
        rsdp = scan_rsdp_range(ebda, ebda + 1024u);
        if (rsdp) return rsdp;
    }
    return scan_rsdp_range(0xe0000u, 0x100000u);
}

static void log_table(const struct acpi_sdt_header *hdr) {
    char sig[5];
    char oem[7];
    char table[9];

    copy_fixed_string(sig, sizeof(sig), hdr->signature, 4);
    copy_fixed_string(oem, sizeof(oem), hdr->oemid, 6);
    copy_fixed_string(table, sizeof(table), hdr->oem_table_id, 8);
    printf("[acpi] table %s addr=0x%llx len=%u rev=%u oem=%s/%s\n",
           sig, (unsigned long long)(uintptr_t)hdr, hdr->length,
           (uint32_t)hdr->revision, oem, table);
}

static void parse_fadt(const struct acpi_sdt_header *hdr) {
    const struct acpi_fadt_min *fadt = (const struct acpi_fadt_min *)hdr;
    uint64_t facs = 0;
    uint64_t dsdt = 0;
    int have_extended = 0;

    if (hdr->length < sizeof(struct acpi_fadt_min)) {
        printf("[acpi][fadt] short table len=%u\n", hdr->length);
        return;
    }
    facs = fadt->firmware_ctrl;
    dsdt = fadt->dsdt;
    if (hdr->length >= sizeof(struct acpi_fadt_extended_prefix)) {
        const struct acpi_fadt_extended_prefix *ext =
            (const struct acpi_fadt_extended_prefix *)hdr;

        /*
         * ACPI firmware in the field frequently advertises the wrong FADT
         * revision.  ACPICA/FreeBSD treat table length as authoritative, so
         * EdgeOS follows that rule and uses X_FACS/X_DSDT when present.
         */
        have_extended = 1;
        if (ext->x_firmware_ctrl) facs = ext->x_firmware_ctrl;
        if (ext->x_dsdt) dsdt = ext->x_dsdt;
    }
    g_acpi.fadt_phys = (uint64_t)(uintptr_t)hdr;
    g_acpi.facs_phys = 0;
    g_acpi.fadt_profile = fadt->preferred_pm_profile;
    g_acpi.sci_interrupt = fadt->sci_interrupt;
    g_acpi.pm_timer_block = fadt->pm_timer_block;
    g_acpi.pm1a_event_block = fadt->pm1a_event_block;
    g_acpi.pm1a_control_block = fadt->pm1a_control_block;
    g_acpi.pm1b_control_block = fadt->pm1b_control_block;
    g_acpi.gpe0_block = fadt->gpe0_block;
    g_acpi.fadt_flags = fadt->flags;
    printf("[acpi][fadt] sci=%u profile=%u pm_tmr=0x%x pm1a_evt=0x%x pm1a_cnt=0x%x gpe0=0x%x\n",
           (uint32_t)fadt->sci_interrupt,
           (uint32_t)fadt->preferred_pm_profile,
           fadt->pm_timer_block,
           fadt->pm1a_event_block,
           fadt->pm1a_control_block,
           fadt->gpe0_block);
    printf("[acpi][fadt] facs=0x%llx dsdt=0x%llx flags=0x%x extended=%s\n",
           (unsigned long long)facs, (unsigned long long)dsdt, fadt->flags,
           have_extended ? "yes" : "no");
    (void)try_register_facs(facs);
    (void)try_register_dsdt(dsdt);
}

static void parse_madt(const struct acpi_sdt_header *hdr) {
    const struct acpi_madt *madt = (const struct acpi_madt *)hdr;
    const uint8_t *p;
    const uint8_t *end;
    uint32_t local_apics = 0;
    uint32_t x2apics = 0;
    uint32_t ioapics = 0;
    uint32_t overrides = 0;

    if (hdr->length < sizeof(*madt)) {
        printf("[acpi][madt] short table len=%u\n", hdr->length);
        return;
    }

    p = madt->entries;
    end = ((const uint8_t *)hdr) + hdr->length;
    while (p + 2 <= end) {
        uint8_t type = p[0];
        uint8_t len = p[1];

        if (len < 2 || p + len > end) break;
        switch (type) {
        case 0:
            if (len >= sizeof(struct acpi_madt_local_apic_entry) &&
                g_acpi.processors < ACPI_MAX_PROCESSORS) {
                const struct acpi_madt_local_apic_entry *e =
                    (const struct acpi_madt_local_apic_entry *)(const void *)p;
                struct acpi_processor_info *slot =
                    &g_acpi.processor_info[g_acpi.processors++];

                slot->processor_uid = e->processor_uid;
                slot->apic_id = e->apic_id;
                slot->flags = e->flags;
                slot->x2apic = 0;
            }
            local_apics++;
            break;
        case 1:
            if (len >= sizeof(struct acpi_madt_ioapic_entry) &&
                g_acpi.ioapics + ioapics < ACPI_MAX_IOAPIC) {
                const struct acpi_madt_ioapic_entry *e =
                    (const struct acpi_madt_ioapic_entry *)(const void *)p;
                struct acpi_ioapic_info *slot =
                    &g_acpi.ioapic_info[g_acpi.ioapics + ioapics];
                slot->id = e->ioapic_id;
                slot->address = e->address;
                slot->global_irq_base = e->global_irq_base;
            }
            ioapics++;
            break;
        case 2:
            if (len >= sizeof(struct acpi_madt_irq_override_entry) &&
                g_acpi.interrupt_overrides + overrides < ACPI_MAX_IRQ_OVERRIDE) {
                const struct acpi_madt_irq_override_entry *e =
                    (const struct acpi_madt_irq_override_entry *)(const void *)p;
                struct acpi_irq_override_info *slot =
                    &g_acpi.irq_overrides[g_acpi.interrupt_overrides + overrides];
                slot->bus = e->bus;
                slot->source_irq = e->source_irq;
                slot->global_irq = e->global_irq;
                slot->flags = e->flags;
            }
            overrides++;
            break;
        case 9:
            if (len >= sizeof(struct acpi_madt_local_x2apic_entry) &&
                g_acpi.processors < ACPI_MAX_PROCESSORS) {
                const struct acpi_madt_local_x2apic_entry *e =
                    (const struct acpi_madt_local_x2apic_entry *)(const void *)p;
                struct acpi_processor_info *slot =
                    &g_acpi.processor_info[g_acpi.processors++];

                slot->processor_uid = e->processor_uid;
                slot->apic_id = e->x2apic_id;
                slot->flags = e->flags;
                slot->x2apic = 1;
            }
            x2apics++;
            break;
        default:
            break;
        }
        p += len;
    }

    g_acpi.lapic_address = madt->local_apic_address;
    g_acpi.local_apics += local_apics;
    g_acpi.x2apics += x2apics;
    g_acpi.ioapics += ioapics;
    g_acpi.interrupt_overrides += overrides;

    printf("[acpi][madt] lapic=0x%x flags=0x%x local_apic=%u ioapic=%u iso=%u x2apic=%u\n",
           madt->local_apic_address, madt->flags, local_apics, ioapics,
           overrides, x2apics);
}

static void parse_hpet(const struct acpi_sdt_header *hdr) {
    const struct acpi_hpet *hpet = (const struct acpi_hpet *)hdr;

    if (hdr->length < sizeof(*hpet)) {
        printf("[acpi][hpet] short table len=%u\n", hdr->length);
        return;
    }
    if (g_acpi.hpet_count < ACPI_MAX_HPET) {
        struct acpi_hpet_info *slot = &g_acpi.hpets[g_acpi.hpet_count];
        slot->event_timer_block_id = hpet->event_timer_block_id;
        slot->address = hpet->address.address;
        slot->address_space_id = hpet->address.address_space_id;
        slot->hpet_number = hpet->hpet_number;
        slot->minimum_tick = hpet->minimum_tick;
        slot->page_protection = hpet->page_protection;
    }
    g_acpi.hpet_count++;
    printf("[acpi][hpet] id=0x%x addr_space=%u addr=0x%llx number=%u min_tick=%u\n",
           hpet->event_timer_block_id,
           (uint32_t)hpet->address.address_space_id,
           (unsigned long long)hpet->address.address,
           (uint32_t)hpet->hpet_number,
           (uint32_t)hpet->minimum_tick);
}

static void parse_mcfg(const struct acpi_sdt_header *hdr) {
    const uint8_t *payload;
    uint32_t payload_len;
    uint32_t entries;

    if (hdr->length < sizeof(*hdr) + 8u) {
        printf("[acpi][mcfg] short table len=%u\n", hdr->length);
        return;
    }
    payload = (const uint8_t *)hdr + sizeof(*hdr) + 8u;
    payload_len = hdr->length - (uint32_t)sizeof(*hdr) - 8u;
    entries = payload_len / (uint32_t)sizeof(struct acpi_mcfg_allocation);
    if (payload_len % (uint32_t)sizeof(struct acpi_mcfg_allocation)) {
        printf("[acpi][mcfg] ignoring %u trailing byte(s) in table len=%u\n",
               payload_len % (uint32_t)sizeof(struct acpi_mcfg_allocation), hdr->length);
    }

    for (uint32_t i = 0; i < entries; ++i) {
        const struct acpi_mcfg_allocation *alloc =
            (const struct acpi_mcfg_allocation *)(const void *)(payload + (i * sizeof(*alloc)));
        struct acpi_mcfg_window *slot;

        if (!alloc->base_address) {
            printf("[acpi][mcfg] skip entry %u with null ECAM base\n", i);
            continue;
        }
        if (alloc->end_bus_number < alloc->start_bus_number) {
            printf("[acpi][mcfg] skip entry %u segment=%u invalid bus range %u-%u\n",
                   i, (uint32_t)alloc->pci_segment,
                   (uint32_t)alloc->start_bus_number,
                   (uint32_t)alloc->end_bus_number);
            continue;
        }
        if (g_acpi.mcfg_count >= ACPI_MAX_MCFG) {
            printf("[acpi][mcfg] table has more than %u usable ECAM window(s), dropping entry %u\n",
                   ACPI_MAX_MCFG, i);
            continue;
        }

        slot = &g_acpi.mcfgs[g_acpi.mcfg_count++];
        slot->base_address = alloc->base_address;
        slot->segment = alloc->pci_segment;
        slot->start_bus = alloc->start_bus_number;
        slot->end_bus = alloc->end_bus_number;
        /*
         * ACPI MCFG publishes the ECAM base for bus 0 of the PCI segment.
         * Consumers must still include the absolute bus number in the ECAM
         * offset.  Treating start_bus as the base would alias Linux-visible
         * PCI BDFs on systems whose segment does not begin at bus 0.
         */
        printf("[acpi][mcfg] segment=%u bus=%u-%u ecam_base=0x%llx\n",
               (uint32_t)slot->segment,
               (uint32_t)slot->start_bus,
               (uint32_t)slot->end_bus,
               (unsigned long long)slot->base_address);
    }
}

static void parse_table(const struct acpi_sdt_header *hdr) {
    const struct acpi_sdt_header *copy;

    if (!sdt_is_valid(hdr)) {
        printf("[acpi] rejected table addr=0x%llx invalid checksum/length\n",
               (unsigned long long)(uintptr_t)hdr);
        return;
    }

    copy = store_table(hdr);
    if (!copy) return;
    log_table(copy);

    if (sig_eq(copy->signature, ACPI_FADT_SIG, 4)) parse_fadt(copy);
    else if (sig_eq(copy->signature, ACPI_MADT_SIG, 4)) parse_madt(copy);
    else if (sig_eq(copy->signature, ACPI_HPET_SIG, 4)) parse_hpet(copy);
    else if (sig_eq(copy->signature, ACPI_MCFG_SIG, 4)) parse_mcfg(copy);
}

static void parse_rsdt(const struct acpi_sdt_header *rsdt) {
    const struct acpi_sdt_header *copy;
    uint32_t entries;
    const uint32_t *table;

    if (!sdt_is_valid(rsdt) || !sig_eq(rsdt->signature, ACPI_RSDT_SIG, 4)) {
        printf("[acpi] invalid RSDT at 0x%llx\n", (unsigned long long)(uintptr_t)rsdt);
        return;
    }
    copy = (const struct acpi_sdt_header *)copy_firmware_table(
        rsdt, rsdt->length, ACPI_RSDT_SIG);
    if (!copy) return;
    g_acpi.rsdt_phys = (uint64_t)(uintptr_t)copy;
    entries = (copy->length - sizeof(*copy)) / 4u;
    if (entries > ACPI_MAX_TABLES) entries = ACPI_MAX_TABLES;
    printf("[acpi] using RSDT firmware=0x%llx copy=0x%llx entries=%u\n",
           (unsigned long long)(uintptr_t)rsdt,
           (unsigned long long)(uintptr_t)copy, entries);

    table = (const uint32_t *)((const uint8_t *)copy + sizeof(*copy));
    for (uint32_t i = 0; i < entries; ++i) {
        if (!table[i]) continue;
        parse_table((const struct acpi_sdt_header *)(uintptr_t)table[i]);
    }
}

static void parse_xsdt(const struct acpi_sdt_header *xsdt) {
    const struct acpi_sdt_header *copy;
    uint32_t entries;
    const uint64_t *table;

    if (!sdt_is_valid(xsdt) || !sig_eq(xsdt->signature, ACPI_XSDT_SIG, 4)) {
        printf("[acpi] invalid XSDT at 0x%llx\n", (unsigned long long)(uintptr_t)xsdt);
        return;
    }
    copy = (const struct acpi_sdt_header *)copy_firmware_table(
        xsdt, xsdt->length, ACPI_XSDT_SIG);
    if (!copy) return;
    g_acpi.xsdt_phys = (uint64_t)(uintptr_t)copy;
    entries = (copy->length - sizeof(*copy)) / 8u;
    if (entries > ACPI_MAX_TABLES) entries = ACPI_MAX_TABLES;
    printf("[acpi] using XSDT firmware=0x%llx copy=0x%llx entries=%u\n",
           (unsigned long long)(uintptr_t)xsdt,
           (unsigned long long)(uintptr_t)copy, entries);

    table = (const uint64_t *)((const uint8_t *)copy + sizeof(*copy));
    for (uint32_t i = 0; i < entries; ++i) {
        if (!table[i]) continue;
        parse_table((const struct acpi_sdt_header *)(uintptr_t)table[i]);
    }
}

void acpi_init(uint32_t boot_magic, void *boot_info) {
    const struct acpi_rsdp *rsdp = 0;
    char oem[7];

    memset(&g_acpi, 0, sizeof(g_acpi));
    g_acpi_table_storage_used = 0;

    if (boot_magic == MULTIBOOT2_BOOTLOADER_MAGIC) {
        rsdp = find_rsdp_multiboot2(boot_info);
    }
    if (!rsdp) rsdp = find_rsdp_bios();
    if (!rsdp) {
        printf("[acpi] RSDP not found; ACPI-dependent drivers disabled\n");
        return;
    }

    copy_fixed_string(oem, sizeof(oem), rsdp->oemid, 6);
    g_acpi.available = 1;
    g_acpi.rsdp_phys = (uint64_t)(uintptr_t)rsdp;
    g_acpi.rsdp_len = 20u;
    if (rsdp->revision >= 2 && rsdp->length >= 36u &&
        rsdp->length <= sizeof(g_acpi.rsdp_copy) &&
        checksum8(rsdp, rsdp->length) == 0) {
        g_acpi.rsdp_len = rsdp->length;
    }
    /*
     * Linux exposes the RSDP as a raw sysfs table.  Multiboot can provide the
     * RSDP inside boot handoff memory that is not part of the normal ACPI SDT
     * registry, so sysfs must serve a stable copy instead of a pointer that
     * later boot code may overwrite.
     */
    memcpy(g_acpi.rsdp_copy, rsdp, g_acpi.rsdp_len);

    printf("[acpi] RSDP addr=0x%llx rev=%u oem=%s rsdt=0x%x xsdt=0x%llx\n",
           (unsigned long long)g_acpi.rsdp_phys,
           (uint32_t)rsdp->revision,
           oem,
           rsdp->rsdt_address,
           (unsigned long long)((rsdp->revision >= 2) ? rsdp->xsdt_address : 0));

    if (rsdp->revision >= 2 && rsdp->xsdt_address) {
        parse_xsdt((const struct acpi_sdt_header *)(uintptr_t)rsdp->xsdt_address);
    } else if (rsdp->rsdt_address) {
        parse_rsdt((const struct acpi_sdt_header *)(uintptr_t)rsdp->rsdt_address);
    }

    if (g_acpi.table_count == 0 && rsdp->rsdt_address) {
        /*
         * Some boot paths provide a revision-2 RSDP with a bad or unmapped
         * XSDT while the legacy RSDT remains usable.  Falling back keeps boot
         * robust without pretending the XSDT contents are valid.
         */
        parse_rsdt((const struct acpi_sdt_header *)(uintptr_t)rsdp->rsdt_address);
    }

    printf("[acpi] summary tables=%u lapic=0x%x local_apic=%u ioapic=%u hpet=%u mcfg=%u\n",
           g_acpi.table_count,
           g_acpi.lapic_address,
           g_acpi.local_apics + g_acpi.x2apics,
           g_acpi.ioapics,
           g_acpi.hpet_count,
           g_acpi.mcfg_count);
}

int acpi_available(void) {
    return g_acpi.available;
}

uint64_t acpi_rsdp_address(void) {
    if (!g_acpi.available || !g_acpi.rsdp_len) return 0;
    return (uint64_t)(uintptr_t)g_acpi.rsdp_copy;
}

uint64_t acpi_rsdt_address(void) {
    return g_acpi.rsdt_phys;
}

uint64_t acpi_xsdt_address(void) {
    return g_acpi.xsdt_phys;
}

uint32_t acpi_table_count(void) {
    return g_acpi.table_count;
}

int acpi_get_table(uint32_t index, struct acpi_table_info *out) {
    const struct acpi_table_slot *slot;

    if (!out || index >= g_acpi.table_count) return -1;
    slot = &g_acpi.tables[index];
    for (uint32_t i = 0; i < sizeof(out->signature); ++i) {
        out->signature[i] = slot->signature[i];
    }
    out->address = slot->address;
    out->length = slot->length;
    out->revision = slot->revision;
    return 0;
}

uint64_t acpi_find_table(const char signature[4], uint32_t index) {
    uint32_t seen = 0;

    if (!signature) return 0;
    for (uint32_t i = 0; i < g_acpi.table_count; ++i) {
        if (!sig_eq(g_acpi.tables[i].signature, signature, 4)) continue;
        if (seen == index) return g_acpi.tables[i].address;
        seen++;
    }
    return 0;
}

static uint32_t acpi_rsdp_length(void) {
    if (!g_acpi.available || !g_acpi.rsdp_phys) return 0;
    return g_acpi.rsdp_len ? g_acpi.rsdp_len : 20u;
}

static int acpi_facs_is_valid(const struct acpi_facs_min *facs) {
    if (!facs) return 0;
    if (!sig_eq(facs->signature, ACPI_FACS_SIG, 4)) return 0;
    /*
     * FACS has no normal SDT checksum/header.  Expose it only when a
     * validated FADT pointed at a plausible FACS payload.  Do not fabricate
     * a table for Linux userspace tools when firmware does not provide one.
     */
    if (facs->length < 64u || facs->length > 4096u) return 0;
    return 1;
}

static uint32_t acpi_sysfs_root_count(void) {
    uint32_t n = 0;

    if (acpi_rsdp_length() > 0) n++;
    if (g_acpi.rsdt_phys) {
        const struct acpi_sdt_header *hdr = (const struct acpi_sdt_header *)(uintptr_t)g_acpi.rsdt_phys;
        if (sdt_is_valid(hdr) && sig_eq(hdr->signature, ACPI_RSDT_SIG, 4)) n++;
    }
    if (g_acpi.xsdt_phys) {
        const struct acpi_sdt_header *hdr = (const struct acpi_sdt_header *)(uintptr_t)g_acpi.xsdt_phys;
        if (sdt_is_valid(hdr) && sig_eq(hdr->signature, ACPI_XSDT_SIG, 4)) n++;
    }
    if (g_acpi.facs_phys &&
        acpi_facs_is_valid((const struct acpi_facs_min *)(uintptr_t)g_acpi.facs_phys)) {
        n++;
    }
    return n;
}

static int acpi_sysfs_root_slot(uint32_t slot, char sig[5], uint64_t *addr, uint32_t *len) {
    uint32_t cur = 0;

    if (!sig || !addr || !len) return -1;
    if (acpi_rsdp_length() > 0) {
        if (cur == slot) {
            strcpy(sig, "RSDP");
            *addr = (uint64_t)(uintptr_t)g_acpi.rsdp_copy;
            *len = acpi_rsdp_length();
            return 0;
        }
        cur++;
    }
    if (g_acpi.rsdt_phys) {
        const struct acpi_sdt_header *hdr = (const struct acpi_sdt_header *)(uintptr_t)g_acpi.rsdt_phys;
        if (sdt_is_valid(hdr) && sig_eq(hdr->signature, ACPI_RSDT_SIG, 4)) {
            if (cur == slot) {
                strcpy(sig, "RSDT");
                *addr = g_acpi.rsdt_phys;
                *len = hdr->length;
                return 0;
            }
            cur++;
        }
    }
    if (g_acpi.xsdt_phys) {
        const struct acpi_sdt_header *hdr = (const struct acpi_sdt_header *)(uintptr_t)g_acpi.xsdt_phys;
        if (sdt_is_valid(hdr) && sig_eq(hdr->signature, ACPI_XSDT_SIG, 4)) {
            if (cur == slot) {
                strcpy(sig, "XSDT");
                *addr = g_acpi.xsdt_phys;
                *len = hdr->length;
                return 0;
            }
            cur++;
        }
    }
    if (g_acpi.facs_phys) {
        const struct acpi_facs_min *facs = (const struct acpi_facs_min *)(uintptr_t)g_acpi.facs_phys;
        if (cur == slot && acpi_facs_is_valid(facs)) {
            strcpy(sig, "FACS");
            *addr = g_acpi.facs_phys;
            *len = facs->length;
            return 0;
        }
    }
    return -1;
}

static void acpi_sysfs_format_table_name(const char sig[5], uint32_t instance,
                                         char *out, uint32_t out_len) {
    uint32_t off = 0;
    char tmp[10];
    uint32_t n = 0;

    if (!out || out_len == 0) return;
    out[0] = 0;
    for (uint32_t i = 0; i < 4 && sig[i] && off + 1 < out_len; ++i) {
        out[off++] = sig[i];
    }
    if (instance == 0) {
        out[off] = 0;
        return;
    }
    while (instance > 0 && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (instance % 10u));
        instance /= 10u;
    }
    while (n > 0 && off + 1 < out_len) out[off++] = tmp[--n];
    out[off] = 0;
}

static int acpi_sysfs_table_slot(uint32_t index, char name[16], uint64_t *addr, uint32_t *len) {
    uint32_t root_count = acpi_sysfs_root_count();

    if (!name || !addr || !len || !g_acpi.available) return -1;
    if (index < root_count) {
        char sig[5];
        uint32_t instance = 0;
        if (acpi_sysfs_root_slot(index, sig, addr, len) < 0) return -1;
        for (uint32_t i = 0; i < index; ++i) {
            char psig[5];
            uint64_t paddr;
            uint32_t plen;
            if (acpi_sysfs_root_slot(i, psig, &paddr, &plen) == 0 &&
                sig_eq(psig, sig, 4)) {
                instance++;
            }
        }
        acpi_sysfs_format_table_name(sig, instance, name, 16);
        return 0;
    }

    index -= root_count;
    if (index >= g_acpi.table_count) return -1;
    {
        const struct acpi_table_slot *slot = &g_acpi.tables[index];
        uint32_t instance = 0;

        for (uint32_t i = 0; i < root_count; ++i) {
            char psig[5];
            uint64_t paddr;
            uint32_t plen;
            if (acpi_sysfs_root_slot(i, psig, &paddr, &plen) == 0 &&
                sig_eq(psig, slot->signature, 4)) {
                instance++;
            }
        }
        for (uint32_t i = 0; i < index; ++i) {
            if (sig_eq(g_acpi.tables[i].signature, slot->signature, 4)) instance++;
        }
        acpi_sysfs_format_table_name(slot->signature, instance, name, 16);
        *addr = slot->address;
        *len = slot->length;
        return 0;
    }
}

uint32_t acpi_sysfs_table_count(void) {
    if (!g_acpi.available) return 0;
    return acpi_sysfs_root_count() + g_acpi.table_count;
}

int acpi_sysfs_table_name(uint32_t index, char *out, uint32_t out_len) {
    char name[16];
    uint64_t addr;
    uint32_t len;

    if (!out || out_len == 0) return -1;
    if (acpi_sysfs_table_slot(index, name, &addr, &len) < 0) return -1;
    (void)addr;
    (void)len;
    strncpy(out, name, out_len - 1);
    out[out_len - 1] = 0;
    return 0;
}

int acpi_sysfs_table_size(const char *name, uint32_t *out_len) {
    char cur[16];
    uint64_t addr;
    uint32_t len;

    if (!name || !out_len) return -1;
    for (uint32_t i = 0; acpi_sysfs_table_slot(i, cur, &addr, &len) == 0; ++i) {
        if (strcmp(cur, name) == 0) {
            (void)addr;
            *out_len = len;
            return 0;
        }
    }
    return -1;
}

int acpi_sysfs_table_read(const char *name, uint32_t offset, char *out,
                          uint32_t max) {
    char cur[16];
    uint64_t addr;
    uint32_t len;

    if (!name || !out) return -1;
    for (uint32_t i = 0; acpi_sysfs_table_slot(i, cur, &addr, &len) == 0; ++i) {
        if (strcmp(cur, name) != 0) continue;
        if (offset >= len) return 0;
        len -= offset;
        if (len > max) len = max;
        memcpy(out, (const uint8_t *)(uintptr_t)addr + offset, len);
        return (int)len;
    }
    return -1;
}

uint64_t acpi_fadt_address(void) {
    return g_acpi.fadt_phys;
}

uint64_t acpi_dsdt_address(void) {
    return g_acpi.dsdt_phys;
}

uint64_t acpi_facs_address(void) {
    return g_acpi.facs_phys;
}

uint32_t acpi_lapic_address(void) {
    return g_acpi.lapic_address;
}

uint32_t acpi_ioapic_count(void) {
    return g_acpi.ioapics;
}

int acpi_get_ioapic(uint32_t index, struct acpi_ioapic_info *out) {
    if (!out) return -1;
    if (index >= g_acpi.ioapics || index >= ACPI_MAX_IOAPIC) return -1;
    *out = g_acpi.ioapic_info[index];
    return 0;
}

uint32_t acpi_hpet_count(void) {
    return g_acpi.hpet_count;
}

int acpi_get_hpet(uint32_t index, struct acpi_hpet_info *out) {
    if (!out) return -1;
    if (index >= g_acpi.hpet_count || index >= ACPI_MAX_HPET) return -1;
    *out = g_acpi.hpets[index];
    return 0;
}

uint32_t acpi_local_apic_count(void) {
    return g_acpi.local_apics + g_acpi.x2apics;
}

uint32_t acpi_processor_count(void) {
    return g_acpi.processors;
}

int acpi_get_processor(uint32_t index, struct acpi_processor_info *out) {
    if (!out || index >= g_acpi.processors || index >= ACPI_MAX_PROCESSORS)
        return -1;
    *out = g_acpi.processor_info[index];
    return 0;
}

uint32_t acpi_interrupt_override_count(void) {
    return g_acpi.interrupt_overrides;
}

int acpi_get_interrupt_override(uint32_t index, struct acpi_irq_override_info *out) {
    if (!out) return -1;
    if (index >= g_acpi.interrupt_overrides || index >= ACPI_MAX_IRQ_OVERRIDE) return -1;
    *out = g_acpi.irq_overrides[index];
    return 0;
}

uint32_t acpi_mcfg_count(void) {
    return g_acpi.mcfg_count;
}

int acpi_get_mcfg(uint32_t index, struct acpi_mcfg_window *out) {
    if (!out) return -1;
    if (index >= g_acpi.mcfg_count || index >= ACPI_MAX_MCFG) return -1;
    *out = g_acpi.mcfgs[index];
    return 0;
}

uint32_t acpi_has_ac_adapter(void) {
    int online;

    return acpi_get_ac_adapter_online(&online) == 0;
}

uint32_t acpi_has_battery(void) {
    struct edge_acpi_battery_info information;

    return acpi_get_battery_info(0, &information) == 0;
}

int acpi_get_ac_adapter_online(int *online) {
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_BSD_DRIVER_ACPICA)
    return bsd_acpi_ac_adapter_snapshot(online);
#else
    (void)online;
    return -1;
#endif
}

int acpi_get_battery_info(uint32_t unit,
                          struct edge_acpi_battery_info *information) {
#if defined(CONFIG_BSD_DRIVER_BRIDGE) && defined(CONFIG_BSD_DRIVER_ACPICA)
    bsd_acpi_battery_snapshot_t snapshot;

    if (!information ||
        bsd_acpi_battery_snapshot((size_t)unit, &snapshot) != 0)
        return -1;
    memset(information, 0, sizeof(*information));
    information->present = snapshot.present;
    information->state = snapshot.state;
    information->units = snapshot.units;
    information->design_capacity = snapshot.design_capacity;
    information->full_capacity = snapshot.full_capacity;
    information->remaining_capacity = snapshot.remaining_capacity;
    information->rate = snapshot.rate;
    information->voltage = snapshot.voltage;
    information->design_voltage = snapshot.design_voltage;
    information->cycle_count = snapshot.cycle_count;
    information->capacity_percent = snapshot.capacity_percent;
    information->remaining_minutes = snapshot.remaining_minutes;
    memcpy(information->model, snapshot.model, sizeof(information->model));
    memcpy(information->serial, snapshot.serial, sizeof(information->serial));
    memcpy(information->technology, snapshot.technology,
           sizeof(information->technology));
    memcpy(information->manufacturer, snapshot.manufacturer,
           sizeof(information->manufacturer));
    return 0;
#else
    (void)unit;
    (void)information;
    return -1;
#endif
}

uint32_t acpi_battery_attribute_mask(
    const struct edge_acpi_battery_info *information) {
    uint32_t mask = 0;

    if (!information)
        return 0;
    if (information->capacity_percent >= 0 &&
        information->capacity_percent <= 100)
        mask |= EDGE_ACPI_BATTERY_ATTR_CAPACITY;
    if (information->technology[0])
        mask |= EDGE_ACPI_BATTERY_ATTR_TECHNOLOGY;
    if (information->serial[0])
        mask |= EDGE_ACPI_BATTERY_ATTR_SERIAL;
    if (information->cycle_count != EDGE_ACPI_BATTERY_VALUE_UNKNOWN)
        mask |= EDGE_ACPI_BATTERY_ATTR_CYCLE_COUNT;
    if (information->voltage != EDGE_ACPI_BATTERY_VALUE_UNKNOWN)
        mask |= EDGE_ACPI_BATTERY_ATTR_VOLTAGE_NOW;
    if (information->design_voltage != EDGE_ACPI_BATTERY_VALUE_UNKNOWN)
        mask |= EDGE_ACPI_BATTERY_ATTR_VOLTAGE_DESIGN;
    if (information->units <= 1 &&
        information->design_capacity != EDGE_ACPI_BATTERY_VALUE_UNKNOWN &&
        information->full_capacity != EDGE_ACPI_BATTERY_VALUE_UNKNOWN &&
        information->remaining_capacity != EDGE_ACPI_BATTERY_VALUE_UNKNOWN)
        mask |= EDGE_ACPI_BATTERY_ATTR_STORAGE;
    if (information->units <= 1 &&
        information->rate != EDGE_ACPI_BATTERY_VALUE_UNKNOWN)
        mask |= EDGE_ACPI_BATTERY_ATTR_RATE;
    if (information->remaining_minutes >= 0)
        mask |= EDGE_ACPI_BATTERY_ATTR_TIME_TO_EMPTY;
    return mask;
}

uint32_t acpi_has_power_button(void) {
    /*
     * Button/lid devices need ACPI event delivery before they can be exposed
     * as working input devices.  String discovery remains available through
     * acpi_platform_snapshot(), but runtime support is not claimed here.
     */
    return 0;
}

uint32_t acpi_has_sleep_button(void) {
    return 0;
}

uint32_t acpi_has_lid_switch(void) {
    return 0;
}

uint32_t acpi_has_thermal_zone(void) {
    /*
     * Thermal zones require AML _TMP/_CRT/_PSV evaluation and trip-point
     * policy.  Do not expose thermal support until ACPICA is integrated.
     */
    return 0;
}

uint32_t acpi_pm_profile(void) {
    return g_acpi.fadt_profile;
}

static int snap_append_char(char *buf, uint32_t max, uint32_t *off, char c) {
    if (!buf || !off || *off + 1u >= max) return -1;
    buf[(*off)++] = c;
    buf[*off] = 0;
    return 0;
}

static int snap_append_lit(char *buf, uint32_t max, uint32_t *off, const char *s) {
    if (!s) return -1;
    while (*s) {
        if (snap_append_char(buf, max, off, *s++) < 0) return -1;
    }
    return 0;
}

static int snap_append_u32(char *buf, uint32_t max, uint32_t *off, uint32_t v) {
    char tmp[11];
    int n = 0;

    if (v == 0) return snap_append_char(buf, max, off, '0');
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        if (snap_append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int snap_append_hex64(char *buf, uint32_t max, uint32_t *off, uint64_t v) {
    static const char hx[] = "0123456789abcdef";
    int started = 0;

    if (snap_append_lit(buf, max, off, "0x") < 0) return -1;
    for (int i = 15; i >= 0; --i) {
        uint8_t nib = (uint8_t)((v >> (i * 4)) & 0xfu);
        if (nib || started || i == 0) {
            started = 1;
            if (snap_append_char(buf, max, off, hx[nib]) < 0) return -1;
        }
    }
    return 0;
}

static int snap_line_u32(char *buf, uint32_t max, uint32_t *off, const char *name, uint32_t v) {
    if (snap_append_lit(buf, max, off, name) < 0) return -1;
    if (snap_append_lit(buf, max, off, ": ") < 0) return -1;
    if (snap_append_u32(buf, max, off, v) < 0) return -1;
    return snap_append_char(buf, max, off, '\n');
}

static int snap_line_hex64(char *buf, uint32_t max, uint32_t *off, const char *name, uint64_t v) {
    if (snap_append_lit(buf, max, off, name) < 0) return -1;
    if (snap_append_lit(buf, max, off, ": ") < 0) return -1;
    if (snap_append_hex64(buf, max, off, v) < 0) return -1;
    return snap_append_char(buf, max, off, '\n');
}

static int snap_line_mcfg(char *buf, uint32_t max, uint32_t *off, uint32_t index,
                          const struct acpi_mcfg_window *mcfg) {
    if (!mcfg) return -1;
    if (snap_append_lit(buf, max, off, "mcfg") < 0) return -1;
    if (snap_append_u32(buf, max, off, index) < 0) return -1;
    if (snap_append_lit(buf, max, off, ": segment ") < 0) return -1;
    if (snap_append_u32(buf, max, off, mcfg->segment) < 0) return -1;
    if (snap_append_lit(buf, max, off, " bus ") < 0) return -1;
    if (snap_append_u32(buf, max, off, mcfg->start_bus) < 0) return -1;
    if (snap_append_char(buf, max, off, '-') < 0) return -1;
    if (snap_append_u32(buf, max, off, mcfg->end_bus) < 0) return -1;
    if (snap_append_lit(buf, max, off, " base ") < 0) return -1;
    if (snap_append_hex64(buf, max, off, mcfg->base_address) < 0) return -1;
    return snap_append_char(buf, max, off, '\n');
}

static int snap_line_present(char *buf, uint32_t max, uint32_t *off, const char *name, uint32_t yes) {
    if (snap_append_lit(buf, max, off, name) < 0) return -1;
    if (snap_append_lit(buf, max, off, ": ") < 0) return -1;
    if (snap_append_lit(buf, max, off, yes ? "present" : "absent") < 0) return -1;
    return snap_append_char(buf, max, off, '\n');
}

int acpi_platform_snapshot(char *buf, uint32_t max) {
    uint32_t off = 0;

    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (!g_acpi.available) {
        if (snap_append_lit(buf, max, &off, "acpi: no\n") < 0) return -1;
        return (int)off;
    }
    if (snap_append_lit(buf, max, &off, "acpi: yes\n") < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "rsdp", g_acpi.rsdp_phys) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "rsdt", g_acpi.rsdt_phys) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "xsdt", g_acpi.xsdt_phys) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "fadt", g_acpi.fadt_phys) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "dsdt", g_acpi.dsdt_phys) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "facs", g_acpi.facs_phys) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "tables", g_acpi.table_count) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "fadt_profile", g_acpi.fadt_profile) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "sci_irq", g_acpi.sci_interrupt) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "pm_timer_block", g_acpi.pm_timer_block) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "pm1a_event_block", g_acpi.pm1a_event_block) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "pm1a_control_block", g_acpi.pm1a_control_block) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "pm1b_control_block", g_acpi.pm1b_control_block) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "gpe0_block", g_acpi.gpe0_block) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "fadt_flags", g_acpi.fadt_flags) < 0) return -1;
    if (snap_line_hex64(buf, max, &off, "lapic_address", g_acpi.lapic_address) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "local_apic", acpi_local_apic_count()) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "ioapic", g_acpi.ioapics) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "interrupt_overrides", g_acpi.interrupt_overrides) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "hpet", g_acpi.hpet_count) < 0) return -1;
    if (snap_line_u32(buf, max, &off, "mcfg", g_acpi.mcfg_count) < 0) return -1;
    for (uint32_t i = 0; i < g_acpi.mcfg_count && i < ACPI_MAX_MCFG; ++i) {
        if (snap_line_mcfg(buf, max, &off, i, &g_acpi.mcfgs[i]) < 0) return -1;
    }
    if (snap_line_present(buf, max, &off, "ac_adapter", g_acpi.has_ac_adapter) < 0) return -1;
    if (snap_line_present(buf, max, &off, "battery", g_acpi.has_battery) < 0) return -1;
    if (snap_line_present(buf, max, &off, "power_button", g_acpi.has_power_button) < 0) return -1;
    if (snap_line_present(buf, max, &off, "sleep_button", g_acpi.has_sleep_button) < 0) return -1;
    if (snap_line_present(buf, max, &off, "lid_switch", g_acpi.has_lid_switch) < 0) return -1;
    if (snap_line_present(buf, max, &off, "thermal_zone", g_acpi.has_thermal_zone) < 0) return -1;
    return (int)off;
}

int acpi_poweroff(void) {
    uint8_t slp_typa = 0;
    uint8_t slp_typb = 0;
    uint16_t value;

    if (!g_acpi.available || !g_acpi.pm1a_control_block) return -1;
    if (acpi_decode_s5(&slp_typa, &slp_typb) < 0) {
        printf("[acpi][power] _S5_ not found; firmware poweroff unavailable\n");
        return -1;
    }

    printf("[acpi][power] S5 pm1a=0x%x pm1b=0x%x typ=%u/%u\n",
           g_acpi.pm1a_control_block, g_acpi.pm1b_control_block,
           (uint32_t)slp_typa, (uint32_t)slp_typb);
    value = (uint16_t)((1u << 13) | ((uint16_t)slp_typa << 10));
    outports((uint16_t)g_acpi.pm1a_control_block, value);
    if (g_acpi.pm1b_control_block) {
        value = (uint16_t)((1u << 13) | ((uint16_t)slp_typb << 10));
        outports((uint16_t)g_acpi.pm1b_control_block, value);
    }
    return 0;
}
