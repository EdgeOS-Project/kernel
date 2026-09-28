/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS HPET driver.
 *
 * Copyright (c) EdgeOS Contributors.
 *
 * This driver deliberately limits itself to ACPI discovery, MMIO capability
 * validation, and the HPET main counter.  Do not route scheduler ticks or
 * enable comparator interrupts here until APIC/IOAPIC/MSI ownership and the
 * Linux clockevent/clocksource ABI surface are implemented together.
 */

#include "drivers/acpi.h"
#include "drivers/hpet.h"
#include "stdio.h"
#include "string.h"
#include "sys/mmio.h"
#include "sys/boottime.h"

#include <stdint.h>

#define HPET_ADDRESS_SPACE_SYSTEM_MEMORY 0u

#define HPET_REG_CAPABILITIES 0x000u
#define HPET_REG_CONFIGURATION 0x010u
#define HPET_REG_MAIN_COUNTER 0x0F0u

#define HPET_CFG_ENABLE 0x1u
#define HPET_CFG_LEGACY_REPLACEMENT 0x2u

struct hpet_state {
    uint8_t present;
    uint8_t counter_enabled;
    uint8_t legacy_capable;
    uint8_t counter_64bit;
    uint8_t revision;
    uint8_t timer_count;
    uint8_t hpet_number;
    uint16_t minimum_tick;
    uint32_t period_fs;
    uint32_t vendor_id;
    uint64_t phys;
    volatile uint8_t *base;
};

static struct hpet_state g_hpet;

static uint64_t hpet_rdtsc(void) {
    uint32_t lo;
    uint32_t hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static uint64_t hpet_scale_u64(uint64_t value, uint64_t multiplier,
                               uint64_t divisor) {
    uint64_t quotient;
    uint64_t remainder;
    if (divisor == 0) return 0;
    quotient = value / divisor;
    remainder = value % divisor;
    if (quotient > UINT64_MAX / multiplier) return UINT64_MAX;
    return quotient * multiplier + (remainder * multiplier) / divisor;
}

static void hpet_refine_tsc_clocksource(void) {
    uint64_t target_ticks;
    uint64_t start_counter;
    uint64_t end_counter;
    uint64_t start_tsc;
    uint64_t end_tsc;
    uint64_t elapsed_us;
    uint64_t tsc_hz;
    uint32_t spins = 0;

    if (!g_hpet.present || !g_hpet.counter_enabled || g_hpet.period_fs == 0) return;
    target_ticks = (20000ull * 1000000000ull) / g_hpet.period_fs;
    if (target_ticks == 0) target_ticks = 1;
    start_counter = hpet_read_counter();
    start_tsc = hpet_rdtsc();
    do {
        end_counter = hpet_read_counter();
        if (++spins > 100000000u) return;
        __asm__ __volatile__("pause");
    } while (end_counter - start_counter < target_ticks);
    end_tsc = hpet_rdtsc();
    if (end_tsc <= start_tsc || end_counter <= start_counter) return;
    elapsed_us = hpet_scale_u64(end_counter - start_counter,
                                g_hpet.period_fs, 1000000000ull);
    if (elapsed_us == 0) return;
    tsc_hz = hpet_scale_u64(end_tsc - start_tsc, 1000000ull, elapsed_us);
    if (boottime_refine_tsc(tsc_hz) == 0) {
        printf("[hpet] clocksource=%s tsc_hz=%llu sample_us=%llu\n",
               boottime_clocksource_name(),
               (unsigned long long)boottime_clocksource_hz(),
               (unsigned long long)elapsed_us);
    }
}

static uint32_t hpet_mmio_read32(uint32_t off) {
    return *(volatile uint32_t *)(g_hpet.base + off);
}

static void hpet_mmio_write32(uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(g_hpet.base + off) = v;
    __asm__ __volatile__("" ::: "memory");
}

static uint64_t hpet_mmio_read64(uint32_t off) {
    uint32_t lo1;
    uint32_t hi;
    uint32_t lo2;

    if (g_hpet.counter_64bit) {
        return *(volatile uint64_t *)(g_hpet.base + off);
    }

    /*
     * Some 32-bit HPET counters can tick between low and high reads.  Sample
     * low/high/low and retry with the second high value if low wrapped.
     */
    lo1 = hpet_mmio_read32(off);
    hi = hpet_mmio_read32(off + 4u);
    lo2 = hpet_mmio_read32(off);
    if (lo2 < lo1) hi = hpet_mmio_read32(off + 4u);
    return ((uint64_t)hi << 32) | (uint64_t)lo2;
}

static int append_char(char *buf, uint32_t max, uint32_t *off, char c) {
    if (!buf || !off || *off + 1u >= max) return -1;
    buf[(*off)++] = c;
    buf[*off] = 0;
    return 0;
}

static int append_lit(char *buf, uint32_t max, uint32_t *off, const char *s) {
    if (!s) return -1;
    while (*s) {
        if (append_char(buf, max, off, *s++) < 0) return -1;
    }
    return 0;
}

static int append_u64(char *buf, uint32_t max, uint32_t *off, uint64_t v) {
    char tmp[21];
    int n = 0;
    if (v == 0) return append_char(buf, max, off, '0');
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10ull));
        v /= 10ull;
    }
    while (n > 0) {
        if (append_char(buf, max, off, tmp[--n]) < 0) return -1;
    }
    return 0;
}

static int append_hex64(char *buf, uint32_t max, uint32_t *off, uint64_t v) {
    static const char hx[] = "0123456789abcdef";
    int started = 0;
    if (append_lit(buf, max, off, "0x") < 0) return -1;
    for (int i = 15; i >= 0; --i) {
        uint8_t nib = (uint8_t)((v >> ((uint32_t)i * 4u)) & 0xFu);
        if (nib || started || i == 0) {
            if (append_char(buf, max, off, hx[nib]) < 0) return -1;
            started = 1;
        }
    }
    return 0;
}

static int append_line_u64(char *buf, uint32_t max, uint32_t *off,
                           const char *name, uint64_t value) {
    if (append_lit(buf, max, off, name) < 0) return -1;
    if (append_lit(buf, max, off, ": ") < 0) return -1;
    if (append_u64(buf, max, off, value) < 0) return -1;
    return append_char(buf, max, off, '\n');
}

static int append_line_hex(char *buf, uint32_t max, uint32_t *off,
                           const char *name, uint64_t value) {
    if (append_lit(buf, max, off, name) < 0) return -1;
    if (append_lit(buf, max, off, ": ") < 0) return -1;
    if (append_hex64(buf, max, off, value) < 0) return -1;
    return append_char(buf, max, off, '\n');
}

void hpet_init(void) {
    struct acpi_hpet_info info;
    uint64_t cap;
    uint32_t cfg;

    memset(&g_hpet, 0, sizeof(g_hpet));
    if (!acpi_available() || acpi_get_hpet(0, &info) < 0) {
        printf("[hpet] no ACPI HPET table\n");
        return;
    }
    if (info.address_space_id != HPET_ADDRESS_SPACE_SYSTEM_MEMORY || info.address == 0) {
        printf("[hpet] unsupported address space=%u addr=0x%llx\n",
               (uint32_t)info.address_space_id, (unsigned long long)info.address);
        return;
    }

    g_hpet.phys = info.address;
    g_hpet.base = (volatile uint8_t *)edge_mmio_low_alias(info.address);
    g_hpet.hpet_number = info.hpet_number;
    g_hpet.minimum_tick = info.minimum_tick;

    cap = hpet_mmio_read64(HPET_REG_CAPABILITIES);
    if (cap == 0 || cap == UINT64_MAX) {
        printf("[hpet] invalid capabilities=0x%llx addr=0x%llx\n",
               (unsigned long long)cap, (unsigned long long)info.address);
        memset(&g_hpet, 0, sizeof(g_hpet));
        return;
    }

    g_hpet.revision = (uint8_t)(cap & 0xffu);
    g_hpet.timer_count = (uint8_t)(((cap >> 8) & 0x1fu) + 1u);
    g_hpet.counter_64bit = (cap & (1ull << 13)) ? 1 : 0;
    g_hpet.legacy_capable = (cap & (1ull << 15)) ? 1 : 0;
    g_hpet.vendor_id = (uint32_t)((cap >> 16) & 0xffffu);
    g_hpet.period_fs = (uint32_t)(cap >> 32);
    if (g_hpet.period_fs == 0 || g_hpet.period_fs > 100000000u) {
        printf("[hpet] invalid counter period=%u fs\n", g_hpet.period_fs);
        memset(&g_hpet, 0, sizeof(g_hpet));
        return;
    }

    cfg = hpet_mmio_read32(HPET_REG_CONFIGURATION);
    cfg &= ~HPET_CFG_LEGACY_REPLACEMENT;
    cfg |= HPET_CFG_ENABLE;
    hpet_mmio_write32(HPET_REG_CONFIGURATION, cfg);
    g_hpet.counter_enabled = (hpet_mmio_read32(HPET_REG_CONFIGURATION) & HPET_CFG_ENABLE) ? 1 : 0;
    g_hpet.present = 1;

    printf("[hpet] ready addr=0x%llx period=%u fs timers=%u 64bit=%u legacy_capable=%u counter=%s\n",
           (unsigned long long)g_hpet.phys,
           g_hpet.period_fs,
           (uint32_t)g_hpet.timer_count,
           (uint32_t)g_hpet.counter_64bit,
           (uint32_t)g_hpet.legacy_capable,
           g_hpet.counter_enabled ? "enabled" : "disabled");
    hpet_refine_tsc_clocksource();
}

int hpet_is_available(void) {
    return g_hpet.present;
}

uint64_t hpet_read_counter(void) {
    if (!g_hpet.present) return 0;
    return hpet_mmio_read64(HPET_REG_MAIN_COUNTER);
}

int hpet_snapshot(char *buf, uint32_t max) {
    uint32_t off = 0;

    if (!buf || max == 0) return -1;
    buf[0] = 0;
    if (!g_hpet.present) {
        if (append_lit(buf, max, &off, "hpet: absent\n") < 0) return -1;
        return (int)off;
    }
    if (append_lit(buf, max, &off, "hpet: present\n") < 0) return -1;
    if (append_line_hex(buf, max, &off, "address", g_hpet.phys) < 0) return -1;
    if (append_line_hex(buf, max, &off, "vendor_id", g_hpet.vendor_id) < 0) return -1;
    if (append_line_u64(buf, max, &off, "revision", g_hpet.revision) < 0) return -1;
    if (append_line_u64(buf, max, &off, "hpet_number", g_hpet.hpet_number) < 0) return -1;
    if (append_line_u64(buf, max, &off, "timers", g_hpet.timer_count) < 0) return -1;
    if (append_line_u64(buf, max, &off, "counter_64bit", g_hpet.counter_64bit) < 0) return -1;
    if (append_line_u64(buf, max, &off, "legacy_replacement_capable", g_hpet.legacy_capable) < 0) return -1;
    if (append_line_u64(buf, max, &off, "period_fs", g_hpet.period_fs) < 0) return -1;
    if (append_line_u64(buf, max, &off, "minimum_tick", g_hpet.minimum_tick) < 0) return -1;
    if (append_line_u64(buf, max, &off, "counter_enabled", g_hpet.counter_enabled) < 0) return -1;
    if (append_line_u64(buf, max, &off, "counter", hpet_read_counter()) < 0) return -1;
    return (int)off;
}
