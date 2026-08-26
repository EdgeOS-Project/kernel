/* SPDX-License-Identifier: MPL-2.0 */
/* Linux cachestat ABI probe for native and EdgeOS guest parity. */

#include <stdint.h>

#if defined(__x86_64__)
#define EDGE_ENTRY_ALIGN __attribute__((force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_msync 26
#define SYS_madvise 28
#define SYS_exit 60
#define SYS_ftruncate 77
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_memfd_create 319
#elif defined(__aarch64__)
#define EDGE_ENTRY_ALIGN
#define SYS_ftruncate 46
#define SYS_openat 56
#define SYS_unlinkat 35
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_msync 227
#define SYS_madvise 233
#define SYS_mmap 222
#define SYS_memfd_create 279
#else
#error "cachestat_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_cachestat 451
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 64
#define O_TRUNC 512
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MS_SYNC 4
#define MADV_PAGEOUT 21
#define PAGE_SIZE 4096u
#define EBADF 9
#define EFAULT 14
#define EINVAL 22

struct edge_cachestat_range {
    uint64_t offset;
    uint64_t length;
};

struct edge_cachestat {
    uint64_t cached_pages;
    uint64_t dirty_pages;
    uint64_t writeback_pages;
    uint64_t evicted_pages;
    uint64_t recently_evicted_pages;
};

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

static uint64_t string_length(const char *text) {
    uint64_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)string_length(text), 0, 0, 0);
}

static void print_number(uint64_t value) {
    char digits[24];
    uint32_t position = sizeof(digits);

    do {
        digits[--position] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && position);
    (void)raw_syscall6(
        SYS_write, 1, (long)&digits[position],
        sizeof(digits) - position, 0, 0, 0);
}

static long run_cachestat(long descriptor,
                          struct edge_cachestat_range *range,
                          struct edge_cachestat *statistics,
                          unsigned int flags) {
    return raw_syscall6(SYS_cachestat, descriptor, (long)range,
                        (long)statistics, flags, 0, 0);
}

static int test_errors(void) {
    static const char name[] = "edgeos-cachestat-errors";
    struct edge_cachestat_range range = {0, 0};
    struct edge_cachestat statistics = {0};
    long descriptor;

    if (run_cachestat(-1, 0, 0, 0) != -EBADF) return 1;
    descriptor = raw_syscall6(
        SYS_memfd_create, (long)name, 0, 0, 0, 0, 0);
    if (descriptor < 0) return 2;
    if (run_cachestat(descriptor, 0, &statistics, 0) != -EFAULT)
        return 3;
    if (run_cachestat(descriptor, &range, &statistics, 1) != -EINVAL)
        return 4;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0)
        return 5;
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return 0;
}

static int test_memfd(void) {
    static const char name[] = "edgeos-cachestat";
    struct edge_cachestat_range range = {0, PAGE_SIZE * 3u};
    struct edge_cachestat statistics = {0};
    volatile uint8_t *mapping;
    long descriptor;
    long address;

    descriptor = raw_syscall6(
        SYS_memfd_create, (long)name, 0, 0, 0, 0, 0);
    if (descriptor < 0) return 10;
    if (raw_syscall6(
            SYS_ftruncate, descriptor, PAGE_SIZE * 3u, 0, 0, 0, 0) < 0)
        return 11;
    address = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE * 3u, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, 0);
    if ((uint64_t)address >= UINT64_MAX - 4095u) return 12;
    mapping = (volatile uint8_t *)(uintptr_t)address;
    mapping[0] = 1u;
    mapping[PAGE_SIZE * 2u] = 2u;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.cached_pages != 2u ||
        statistics.dirty_pages != 0u ||
        statistics.writeback_pages != 0u)
        return 13;
    range.offset = PAGE_SIZE;
    range.length = PAGE_SIZE;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.cached_pages != 0u)
        return 14;
    range.offset = PAGE_SIZE * 2u;
    range.length = 0;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.cached_pages != 1u)
        return 15;
    (void)raw_syscall6(
        SYS_munmap, address, PAGE_SIZE * 3u, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return 0;
}

static int test_file_eviction(void) {
    static const char path[] = "/tmp/edgeos-cachestat-probe";
    struct edge_cachestat_range range = {0, PAGE_SIZE};
    struct edge_cachestat statistics = {0};
    volatile uint8_t *mapping;
    long descriptor;
    long address;

    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path,
        O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
    if (descriptor < 0) return 20;
    if (raw_syscall6(
            SYS_ftruncate, descriptor, PAGE_SIZE, 0, 0, 0, 0) < 0)
        return 21;
    address = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, 0);
    if ((uint64_t)address >= UINT64_MAX - 4095u) return 22;
    mapping = (volatile uint8_t *)(uintptr_t)address;
    mapping[0] = 0x5au;
    if (raw_syscall6(
            SYS_msync, address, PAGE_SIZE, MS_SYNC, 0, 0, 0) < 0)
        return 23;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.cached_pages != 1u ||
        statistics.dirty_pages != 0u) {
        print_text("CACHESTAT_FILE_CACHED=");
        print_number(statistics.cached_pages);
        print_text(" DIRTY=");
        print_number(statistics.dirty_pages);
        print_text(" WRITEBACK=");
        print_number(statistics.writeback_pages);
        print_text("\n");
        return 24;
    }
    mapping[1] = 0x3cu;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.cached_pages != 1u ||
        statistics.dirty_pages != 0u) {
        print_text("CACHESTAT_FILE_REDIRTY_CACHED=");
        print_number(statistics.cached_pages);
        print_text(" DIRTY=");
        print_number(statistics.dirty_pages);
        print_text("\n");
        return 29;
    }
    if (raw_syscall6(
            SYS_msync, address, PAGE_SIZE, MS_SYNC, 0, 0, 0) < 0 ||
        run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.dirty_pages != 0u) {
        print_text("CACHESTAT_FILE_RESYNC_DIRTY=");
        print_number(statistics.dirty_pages);
        print_text("\n");
        return 30;
    }
    if (raw_syscall6(
            SYS_madvise, address, PAGE_SIZE, MADV_PAGEOUT,
            0, 0, 0) < 0)
        return 25;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.cached_pages > 1u ||
        statistics.evicted_pages > 1u ||
        statistics.recently_evicted_pages >
            statistics.evicted_pages) {
        print_text("CACHESTAT_FILE_AFTER_PAGEOUT_CACHED=");
        print_number(statistics.cached_pages);
        print_text(" EVICTED=");
        print_number(statistics.evicted_pages);
        print_text(" RECENT=");
        print_number(statistics.recently_evicted_pages);
        print_text("\n");
        return 26;
    }
    if (mapping[0] != 0x5au) return 27;
    if (run_cachestat(descriptor, &range, &statistics, 0) != 0 ||
        statistics.cached_pages != 1u ||
        statistics.evicted_pages != 0u)
        return 28;
    (void)raw_syscall6(SYS_munmap, address, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    return 0;
}

EDGE_ENTRY_ALIGN void _start(void) {
    int result = test_errors();
    if (!result) result = test_memfd();
    if (!result) result = test_file_eviction();
    if (result) {
        print_text("CACHESTAT_ABI_PROBE_FAIL code=");
        print_number((uint64_t)result);
        print_text("\n");
    } else {
        print_text("CACHESTAT_ABI_PROBE_PASS\n");
    }
    raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
    for (;;) { }
}
