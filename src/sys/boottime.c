#include "sys/boottime.h"
#include "arch/x86_64/io_ports.h"
#include "kernel/boottime_arch.h"

#define PIT_CMD_PORT 0x43
#define PIT_CH0_PORT 0x40
#define PIT_HZ_NUM 1193182ull
#define TSC_HZ_MIN 1000000ull
#define TSC_HZ_MAX 20000000000ull
static volatile uint64_t g_fallback_tick_us;
static uint64_t g_boot_tsc;
static uint64_t g_tsc_base_us;
static uint64_t g_tsc_hz;
static int g_tsc_ready;
static const char *g_clocksource_name = "timer-tick";

static uint64_t rdtsc_read(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static uint16_t pit_read_ch0_counter(void) {
    outportb(PIT_CMD_PORT, 0x00);
    uint8_t lo = inportb(PIT_CH0_PORT);
    uint8_t hi = inportb(PIT_CH0_PORT);
    return (uint16_t)(((uint16_t)hi << 8) | lo);
}

static uint64_t scale_u64(uint64_t value, uint64_t multiplier, uint64_t divisor) {
    uint64_t quotient;
    uint64_t remainder;
    if (divisor == 0) return 0;
    quotient = value / divisor;
    remainder = value % divisor;
    if (quotient > UINT64_MAX / multiplier) return UINT64_MAX;
    return quotient * multiplier + (remainder * multiplier) / divisor;
}

static void cpuid_leaf(uint32_t leaf, uint32_t subleaf,
                       uint32_t *eax, uint32_t *ebx,
                       uint32_t *ecx, uint32_t *edx) {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(leaf), "c"(subleaf));
    if (eax) *eax = a;
    if (ebx) *ebx = b;
    if (ecx) *ecx = c;
    if (edx) *edx = d;
}

static int tsc_hz_valid(uint64_t hz) {
    return hz >= TSC_HZ_MIN && hz <= TSC_HZ_MAX;
}

static uint64_t tsc_hz_from_cpuid(void) {
    uint32_t max_leaf;
    uint32_t denominator;
    uint32_t numerator;
    uint32_t crystal_hz;
    uint32_t base_mhz;
    uint64_t hz;

    cpuid_leaf(0, 0, &max_leaf, 0, 0, 0);
    if (max_leaf >= 0x15u) {
        cpuid_leaf(0x15u, 0, &denominator, &numerator, &crystal_hz, 0);
        if (denominator != 0 && numerator != 0 && crystal_hz != 0) {
            hz = scale_u64(crystal_hz, numerator, denominator);
            if (tsc_hz_valid(hz)) return hz;
        }
    }
    if (max_leaf >= 0x16u) {
        cpuid_leaf(0x16u, 0, &base_mhz, 0, 0, 0);
        hz = (uint64_t)base_mhz * 1000000ull;
        if (tsc_hz_valid(hz)) return hz;
    }
    return 0;
}

static int rtc_updating(void) {
    outportb(0x70, 0x0A);
    return (inportb(0x71) & 0x80) != 0;
}

static uint8_t rtc_read_reg(uint8_t reg) {
    outportb(0x70, reg);
    return inportb(0x71);
}

static uint8_t bcd_to_bin(uint8_t v) {
    return (uint8_t)((v & 0x0F) + ((v >> 4) * 10));
}

static int is_leap(int y) {
    return ((y % 4) == 0 && (y % 100) != 0) || ((y % 400) == 0);
}

static uint64_t ymd_hms_to_unix(int y, int mon, int day, int h, int m, int s) {
    static const int mdays[12] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
    uint64_t days = 0;
    for (int yy = 1970; yy < y; ++yy) days += (uint64_t)(is_leap(yy) ? 366 : 365);
    for (int mm = 1; mm < mon; ++mm) {
        days += (uint64_t)mdays[mm - 1];
        if (mm == 2 && is_leap(y)) days++;
    }
    days += (uint64_t)(day - 1);
    return days * 86400ull + (uint64_t)h * 3600ull + (uint64_t)m * 60ull + (uint64_t)s;
}

static uint64_t rtc_unix_seconds(void) {
    uint8_t sec, min, hour, day, mon, year, regb;
    do { } while (rtc_updating());
    sec = rtc_read_reg(0x00);
    min = rtc_read_reg(0x02);
    hour = rtc_read_reg(0x04);
    day = rtc_read_reg(0x07);
    mon = rtc_read_reg(0x08);
    year = rtc_read_reg(0x09);
    regb = rtc_read_reg(0x0B);

    if ((regb & 0x04) == 0) {
        sec = bcd_to_bin(sec);
        min = bcd_to_bin(min);
        hour = bcd_to_bin(hour & 0x7F);
        day = bcd_to_bin(day);
        mon = bcd_to_bin(mon);
        year = bcd_to_bin(year);
    } else {
        hour &= 0x7F;
    }

    int full_year = 2000 + (int)year;
    if (full_year < 1970) full_year = 1970;
    return ymd_hms_to_unix(full_year, mon ? mon : 1, day ? day : 1, hour, min, sec);
}

static int boottime_calibrate_tsc(void) {
    uint64_t start_tsc;
    uint64_t end_tsc;
    uint32_t elapsed_counts;
    const uint32_t target_counts = 40000u; /* ~33.5ms */
    uint32_t spins = 0;

    /*
     * Firmware does not promise a particular channel-0 mode or divisor.  A
     * calibration that merely samples the inherited PIT state can therefore
     * mistake a periodic reload for a 16-bit wrap and report a wildly low TSC
     * frequency.  Program a one-shot counter so every observed decrement has
     * an unambiguous duration.  The scheduler installs its periodic mode later.
     */
    outportb(PIT_CMD_PORT, 0x30); /* ch0, lobyte/hibyte, mode 0 */
    outportb(PIT_CH0_PORT, 0xffu);
    outportb(PIT_CH0_PORT, 0xffu);
    start_tsc = rdtsc_read();

    for (;;) {
        uint16_t now = pit_read_ch0_counter();
        elapsed_counts = 0xffffu - (uint32_t)now;
        if (elapsed_counts >= target_counts) break;
        if (++spins > 10000000u) return -1;
        __asm__ __volatile__("pause");
    }

    end_tsc = rdtsc_read();
    if (end_tsc <= start_tsc || elapsed_counts == 0) return -1;
    g_tsc_hz = scale_u64(end_tsc - start_tsc, PIT_HZ_NUM, elapsed_counts);
    if (!tsc_hz_valid(g_tsc_hz)) return -1;
    return 0;
}

uint64_t kernel_arch_boottime_initialize(void) {
    uint64_t realtime_us = rtc_unix_seconds() * 1000000ull;

    g_fallback_tick_us = 0;
    g_tsc_base_us = 0;
    g_tsc_ready = 0;
    g_tsc_hz = tsc_hz_from_cpuid();
    if (tsc_hz_valid(g_tsc_hz)) {
        g_clocksource_name = "cpuid-tsc";
        g_boot_tsc = rdtsc_read();
        g_tsc_ready = 1;
    } else if (boottime_calibrate_tsc() == 0) {
        g_clocksource_name = "pit-calibrated-tsc";
        g_boot_tsc = rdtsc_read();
        g_tsc_ready = 1;
    } else {
        g_tsc_hz = 0;
        g_clocksource_name = "timer-tick";
    }
    return realtime_us;
}

void kernel_arch_boottime_timer_tick(uint32_t hz) {
    if (g_tsc_ready || hz == 0) return;
    __sync_fetch_and_add(&g_fallback_tick_us, 1000000ull / (uint64_t)hz);
}

int kernel_arch_boottime_refine(uint64_t hz,
                                uint64_t monotonic_floor_us) {
    uint64_t flags;
    uint64_t now_tsc;
    uint64_t base_us;

    if (!tsc_hz_valid(hz)) return -1;
    __asm__ __volatile__("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    now_tsc = rdtsc_read();
    if (g_tsc_ready && g_tsc_hz != 0) {
        base_us = g_tsc_base_us +
                  scale_u64(now_tsc - g_boot_tsc, 1000000ull, g_tsc_hz);
    } else {
        base_us = g_fallback_tick_us;
    }
    if (base_us < monotonic_floor_us) base_us = monotonic_floor_us;
    g_tsc_base_us = base_us;
    g_boot_tsc = now_tsc;
    g_tsc_hz = hz;
    g_tsc_ready = 1;
    g_clocksource_name = "hpet-calibrated-tsc";
    if (flags & (1ull << 9)) __asm__ __volatile__("sti" ::: "memory");
    return 0;
}

uint64_t kernel_arch_boottime_source_hz(void) {
    return g_tsc_hz;
}

const char *kernel_arch_boottime_source_name(void) {
    return g_clocksource_name;
}

uint64_t kernel_arch_boottime_monotonic_us(void) {
    uint64_t now_us;
    if (g_tsc_ready && g_tsc_hz > 0) {
        uint64_t now_tsc = rdtsc_read();
        uint64_t delta = now_tsc - g_boot_tsc;
        now_us = g_tsc_base_us + scale_u64(delta, 1000000ull, g_tsc_hz);
    } else {
        now_us = g_fallback_tick_us;
    }

    return now_us;
}

void kernel_arch_boottime_vdso_snapshot(uint64_t *cycle_last,
                                        uint64_t *monotonic_base_us,
                                        uint64_t *frequency) {
    if (cycle_last) *cycle_last = g_boot_tsc;
    if (monotonic_base_us) *monotonic_base_us = g_tsc_base_us;
    if (frequency) *frequency = g_tsc_ready ? g_tsc_hz : 0;
}
