/* SPDX-License-Identifier: MPL-2.0 */
/* Linux-compatible vDSO time entry points for EdgeOS user processes. */

typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

struct edge_vdso_timespec {
    s64 tv_sec;
    s64 tv_nsec;
};

struct edge_vdso_timeval {
    s64 tv_sec;
    s64 tv_usec;
};

struct edge_vdso_data {
    volatile u32 sequence;
    u32 clock_mode;
    u64 cycle_last;
    u64 monotonic_base_us;
    u64 realtime_offset_us;
    u64 frequency;
};

__attribute__((section(".vdso_data"), visibility("hidden")))
struct edge_vdso_data edge_vdso_data;

enum {
    EDGE_CLOCK_REALTIME = 0,
    EDGE_CLOCK_MONOTONIC = 1,
    EDGE_CLOCK_MONOTONIC_RAW = 4,
    EDGE_CLOCK_REALTIME_COARSE = 5,
    EDGE_CLOCK_MONOTONIC_COARSE = 6,
    EDGE_CLOCK_BOOTTIME = 7,
};

static __attribute__((always_inline)) inline u64 edge_cycle_now(void) {
#if defined(__aarch64__)
    u64 value;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
    return value;
#elif defined(__x86_64__)
    u32 low;
    u32 high;
    __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
    return ((u64)high << 32) | low;
#else
#error Unsupported vDSO architecture
#endif
}

static __attribute__((always_inline)) inline int edge_clock_supported(int id) {
    return id == EDGE_CLOCK_REALTIME || id == EDGE_CLOCK_MONOTONIC ||
           id == EDGE_CLOCK_MONOTONIC_RAW ||
           id == EDGE_CLOCK_REALTIME_COARSE ||
           id == EDGE_CLOCK_MONOTONIC_COARSE ||
           id == EDGE_CLOCK_BOOTTIME;
}

static __attribute__((always_inline)) inline u64 edge_scale_cycles(
    u64 cycles, u64 frequency) {
    u64 quotient = cycles / frequency;
    u64 remainder = cycles % frequency;
    return quotient * 1000000u + (remainder * 1000000u) / frequency;
}

static int edge_fast_time(int clock_id, u64 *microseconds) {
    u32 before;
    u32 after;
    u64 cycle_last;
    u64 monotonic_base;
    u64 realtime_offset;
    u64 frequency;
    u64 now;

    if (!microseconds || !edge_clock_supported(clock_id)) return -1;
    do {
        before = __atomic_load_n(&edge_vdso_data.sequence, __ATOMIC_ACQUIRE);
        if (before & 1u) continue;
        cycle_last = edge_vdso_data.cycle_last;
        monotonic_base = edge_vdso_data.monotonic_base_us;
        realtime_offset = edge_vdso_data.realtime_offset_us;
        frequency = edge_vdso_data.frequency;
        now = edge_cycle_now();
        after = __atomic_load_n(&edge_vdso_data.sequence, __ATOMIC_ACQUIRE);
    } while (before != after || (after & 1u));
    if (!frequency) return -1;
    *microseconds = monotonic_base +
                    edge_scale_cycles(now - cycle_last, frequency);
    if (clock_id == EDGE_CLOCK_REALTIME ||
        clock_id == EDGE_CLOCK_REALTIME_COARSE)
        *microseconds += realtime_offset;
    if (clock_id == EDGE_CLOCK_REALTIME_COARSE ||
        clock_id == EDGE_CLOCK_MONOTONIC_COARSE)
        *microseconds -= *microseconds % 1000u;
    return 0;
}

static int edge_clock_gettime_fallback(int clock_id,
                                       struct edge_vdso_timespec *value) {
#if defined(__aarch64__)
    register long result __asm__("x0") = clock_id;
    register void *argument __asm__("x1") = value;
    register long number __asm__("x8") = 113;
    __asm__ __volatile__("svc #0" : "+r"(result) : "r"(argument), "r"(number)
                         : "memory");
    return (int)result;
#elif defined(__x86_64__)
    register long result __asm__("rax") = 228;
    register long argument0 __asm__("rdi") = clock_id;
    register void *argument1 __asm__("rsi") = value;
    __asm__ __volatile__("syscall" : "+r"(result)
                         : "r"(argument0), "r"(argument1)
                         : "rcx", "r11", "memory");
    return (int)result;
#endif
}

int __vdso_clock_gettime(int clock_id, struct edge_vdso_timespec *value) {
    u64 microseconds;
    if (!value || edge_fast_time(clock_id, &microseconds) < 0)
        return edge_clock_gettime_fallback(clock_id, value);
    value->tv_sec = (s64)(microseconds / 1000000u);
    value->tv_nsec = (s64)((microseconds % 1000000u) * 1000u);
    return 0;
}

int clock_gettime(int clock_id, struct edge_vdso_timespec *value)
    __attribute__((alias("__vdso_clock_gettime")));

#if defined(__aarch64__)
int __kernel_clock_gettime(int clock_id, struct edge_vdso_timespec *value)
    __attribute__((alias("__vdso_clock_gettime")));
#endif

int __vdso_gettimeofday(struct edge_vdso_timeval *value, void *timezone) {
    u64 microseconds;
    (void)timezone;
    if (!value) return 0;
    if (edge_fast_time(EDGE_CLOCK_REALTIME, &microseconds) < 0) return -1;
    value->tv_sec = (s64)(microseconds / 1000000u);
    value->tv_usec = (s64)(microseconds % 1000000u);
    return 0;
}

int gettimeofday(struct edge_vdso_timeval *value, void *timezone)
    __attribute__((alias("__vdso_gettimeofday")));

#if defined(__aarch64__)
int __kernel_gettimeofday(struct edge_vdso_timeval *value, void *timezone)
    __attribute__((alias("__vdso_gettimeofday")));
#endif

int __vdso_clock_getres(int clock_id, struct edge_vdso_timespec *value) {
    if (!edge_clock_supported(clock_id)) return -1;
    if (value) {
        value->tv_sec = 0;
        value->tv_nsec =
            (clock_id == EDGE_CLOCK_REALTIME_COARSE ||
             clock_id == EDGE_CLOCK_MONOTONIC_COARSE) ? 1000000 : 1000;
    }
    return 0;
}

#if defined(__aarch64__)
int __kernel_clock_getres(int clock_id, struct edge_vdso_timespec *value)
    __attribute__((alias("__vdso_clock_getres")));
#endif

s64 __vdso_time(s64 *result) {
    u64 microseconds;
    s64 seconds;
    if (edge_fast_time(EDGE_CLOCK_REALTIME, &microseconds) < 0) return -1;
    seconds = (s64)(microseconds / 1000000u);
    if (result) *result = seconds;
    return seconds;
}

s64 time(s64 *result) __attribute__((alias("__vdso_time")));
