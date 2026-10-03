/* SPDX-License-Identifier: MPL-2.0 */
/* Validate transport ancestry and aliases using public sysfs interfaces. */
#include <stdint.h>
#if defined(__aarch64__)
#define SYS_write 64
#define SYS_openat 56
#define SYS_close 57
#define SYS_readlinkat 78
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_exit 93
#else
#define SYS_write 1
#define SYS_openat 257
#define SYS_close 3
#define SYS_readlinkat 267
#define SYS_mkdirat 258
#define SYS_mount 165
#define SYS_exit 60
#endif
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
static unsigned length(const char *s) { unsigned n = 0; while(s[n]) ++n; return n; }
static int same(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static void print(const char *s) { raw_syscall6(SYS_write, 1, (long)s, length(s), 0, 0, 0); }
static int link(const char *path, char *out) {
    long n = raw_syscall6(SYS_readlinkat, -100, (long)path, (long)out, 255, 0, 0);
    if (n < 0) { print(path); print(" FAIL readlink\n"); return 1; }
    out[n] = 0; print(path); print(" -> "); print(out); print("\n"); return 0;
}
void _start(void) {
    char card[256], alias[256], parent[256], driver[256];
    int failed = 0;
    raw_syscall6(SYS_mkdirat, -100, (long)"/sys", 0755, 0, 0, 0);
    raw_syscall6(SYS_mount, (long)"sysfs", (long)"/sys", (long)"sysfs", 0, 0, 0);
    failed |= link("/sys/class/drm/card0", card);
    failed |= link("/sys/dev/char/226:0", alias);
    failed |= link("/sys/class/drm/card0/device/subsystem", parent);
    failed |= link("/sys/class/drm/card0/device/driver", driver);
    if (!failed) {
        failed |= !same(card, alias);
#if defined(__aarch64__)
        failed |= !same(parent, "../../../bus/platform");
        failed |= !same(driver, "../../../bus/platform/drivers/virtio-mmio");
#endif
    }
    long fd = raw_syscall6(SYS_openat, -100, (long)"/sys/class/drm/card0/device/uevent", 0, 0, 0, 0);
    if (fd < 0) failed = 1;
    else raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    print(failed ? "GPU_TOPOLOGY_FAIL\n" : "GPU_TOPOLOGY_PASS\n");
    raw_syscall6(SYS_exit, failed, 0, 0, 0, 0, 0);
    for (;;) {}
}
