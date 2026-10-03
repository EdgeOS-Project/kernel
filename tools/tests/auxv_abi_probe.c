/* SPDX-License-Identifier: MPL-2.0 */
/* Compare saved auxv with the ELF entry stack, procfs, and fork inheritance. */
#include <stdint.h>
#if defined(__x86_64__)
#define SYS_prctl 157
#define SYS_openat 257
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_clone 56
#define SYS_wait4 61
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_prctl 167
#define SYS_openat 56
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit 93
#endif
#define PR_GET_AUXV 0x41555856u
static long raw_syscall6(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4,
                         long argument5) {
    long result;
#if defined(__x86_64__)
    register long r10 __asm__("r10") = argument3;
    register long r8 __asm__("r8") = argument4;
    register long r9 __asm__("r9") = argument5;
    __asm__ __volatile__(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument0), "S"(argument1), "d"(argument2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = argument0;
    register long x1 __asm__("x1") = argument1;
    register long x2 __asm__("x2") = argument2;
    register long x3 __asm__("x3") = argument3;
    register long x4 __asm__("x4") = argument4;
    register long x5 __asm__("x5") = argument5;
    __asm__ __volatile__(
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory");
    result = x0;
#endif
    return result;
}

static long raw_syscall5(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, argument4, 0);
}


static uint8_t expected[512], actual[512];
static long full_size;
static int equal(const uint8_t *a, const uint8_t *b, uint32_t size) {
    for (uint32_t i = 0; i < size; ++i) if (a[i] != b[i]) return 0;
    return 1;
}
static int check_auxv(uint32_t size) {
    long result = raw_syscall6(SYS_prctl, PR_GET_AUXV, (long)actual, 512, 0, 0, 0);
    return result >= size && result <= 512 && equal(expected, actual, size);
}
__attribute__((noreturn)) void auxv_probe_start(uint64_t *stack) {
    uint64_t *cursor = stack + stack[0] + 2u;
    uint32_t size = 0;
    int failures = 0, status = -1;
    while (*cursor) ++cursor;
    ++cursor;
    uint64_t *initial = cursor;
    for (;;) {
        if (size + 16u > sizeof(expected)) { failures++; break; }
        uint64_t type = cursor[0];
        for (uint32_t i = 0; i < 16; ++i) expected[size + i] = ((uint8_t *)cursor)[i];
        size += 16u;
        cursor += 2u;
        if (!type) break;
    }
    full_size = raw_syscall6(SYS_prctl, PR_GET_AUXV, (long)actual, 512, 0, 0, 0);
    failures += !check_auxv(size);
    failures += raw_syscall6(SYS_prctl, PR_GET_AUXV, 0, 0, 0, 0, 0) != full_size;
    failures += raw_syscall6(SYS_prctl, PR_GET_AUXV, (long)actual, 7, 0, 0, 0) != full_size;
    failures += !equal(expected, actual, 7);
    failures += raw_syscall6(SYS_prctl, PR_GET_AUXV, (long)actual, 512, 1, 0, 0) != -22;
    failures += raw_syscall6(SYS_prctl, PR_GET_AUXV, 1, 512, 0, 0, 0) != -14;
    initial[1] ^= 1u;
    failures += !check_auxv(size);
    long fd = raw_syscall6(SYS_openat, -100, (long)"/proc/self/auxv", 0, 0, 0, 0);
    if (fd < 0) failures++;
    else {
        long bytes = raw_syscall6(SYS_read, fd, (long)actual, 512, 0, 0, 0);
        failures += bytes != size || !equal(expected, actual, size);
        raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    }
    long child = raw_syscall6(SYS_clone, 17, 0, 0, 0, 0, 0);
    if (!child) {
        raw_syscall6(SYS_exit, !check_auxv(size), 0, 0, 0, 0, 0);
        for (;;) {}
    }
    if (child < 0) failures++;
    else {
        failures += raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child;
        failures += status != 0;
    }
    const char *message = failures ? "AUXV_ABI_PROBE_FAIL\n" : "AUXV_ABI_PROBE_PASS\n";
    raw_syscall6(SYS_write, 1, (long)message, 20, 0, 0, 0);
    raw_syscall6(SYS_exit, failures != 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
#if defined(__aarch64__)
__asm__(".global _start\n_start:\nmov x0, sp\nbl auxv_probe_start\n");
#else
__asm__(".global _start\n_start:\nmov %rsp, %rdi\nand $-16, %rsp\ncall auxv_probe_start\n");
#endif
