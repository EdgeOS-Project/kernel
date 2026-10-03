/* SPDX-License-Identifier: MPL-2.0 */
/* Check that a detached tmpfs root exists and survives mount attachment. */
#include <stdint.h>
#if defined(__x86_64__)
#define SYS_openat 257
#define SYS_close 3
#define SYS_write 1
#define SYS_exit 60
#define SYS_mkdirat 258
#define SYS_unlinkat 263
#define SYS_umount2 166
#define SYS_fchmod 91
#define SYS_statx 332
#define O_DIRECTORY 65536
#elif defined(__aarch64__)
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_umount2 39
#define SYS_fchmod 52
#define SYS_statx 291
#define O_DIRECTORY 16384
#endif
#define SYS_move_mount 429
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
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



static uint64_t metadata[32];
static int mode_matches(long fd, uint16_t expected) {
    if (raw_syscall6(SYS_statx, fd, (long)"", 0x1000, 0x7ff, (long)metadata, 0) < 0) return 0;
    return *(uint16_t *)((uint8_t *)metadata + 28) == (uint16_t)(040000u | expected);
}
#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    const char *target = "/tmp/edgeos-detached-mount-probe";
    long context = raw_syscall6(SYS_fsopen, (long)"tmpfs", 1, 0, 0, 0, 0);
    int failures = context < 0;
    long mount_fd = -1, root_fd = -1, visible = -1;
    if (!failures) {
        failures += raw_syscall6(SYS_fsconfig, context, 1, (long)"mode", (long)"0710", 0, 0) != 0;
        failures += raw_syscall6(SYS_fsconfig, context, 1, (long)"size", (long)"1048576", 0, 0) != 0;
        failures += raw_syscall6(SYS_fsconfig, context, 1, (long)"nr_inodes", (long)"1024", 0, 0) != 0;
        failures += raw_syscall6(SYS_fsconfig, context, 0, (long)"noswap", 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_fsconfig, context, 6, 0, 0, 0, 0) != 0;
        mount_fd = raw_syscall6(SYS_fsmount, context, 1, 8, 0, 0, 0);
        failures += mount_fd < 0;
    }
    if (mount_fd >= 0) {
        failures += !mode_matches(mount_fd, 0710);
        root_fd = raw_syscall6(SYS_openat, mount_fd, (long)".", O_DIRECTORY | 0x80000, 0, 0, 0);
        failures += root_fd < 0;
    }
    if (root_fd >= 0) {
        failures += !mode_matches(root_fd, 0710);
        failures += raw_syscall6(SYS_fchmod, root_fd, 0750, 0, 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_fsconfig, context, 0, (long)"noswap", 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_fsconfig, context, 0, (long)"ro", 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_fsconfig, context, 7, 0, 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_fchmod, root_fd, 0700, 0, 0, 0, 0) != -30;
        long created = raw_syscall6(SYS_mkdirat, -100, (long)target, 0700, 0, 0, 0);
        failures += created != 0 && created != -17;
        failures += raw_syscall6(SYS_move_mount, mount_fd, (long)"", -100, (long)target, 4, 0) != 0;
        visible = raw_syscall6(SYS_openat, -100, (long)target, O_DIRECTORY, 0, 0, 0);
        failures += visible < 0 || !mode_matches(visible, 0750);
        if (visible >= 0) raw_syscall6(SYS_close, visible, 0, 0, 0, 0, 0);
        raw_syscall6(SYS_close, mount_fd, 0, 0, 0, 0, 0);
        mount_fd = -1;
        failures += !mode_matches(root_fd, 0750);
        failures += raw_syscall6(SYS_umount2, (long)target, 2, 0, 0, 0, 0) != 0;
        failures += !mode_matches(root_fd, 0750);
        raw_syscall6(SYS_close, root_fd, 0, 0, 0, 0, 0);
        raw_syscall6(SYS_unlinkat, -100, (long)target, 0x200, 0, 0, 0);
    }
    if (mount_fd >= 0) raw_syscall6(SYS_close, mount_fd, 0, 0, 0, 0, 0);
    if (context >= 0) raw_syscall6(SYS_close, context, 0, 0, 0, 0, 0);
    const char *message = failures ? "DETACHED_TMPFS_PROBE_FAIL\n" : "DETACHED_TMPFS_PROBE_PASS\n";
    uint32_t length = 0;
    while (message[length]) ++length;
    raw_syscall6(SYS_write, 1, (long)message, length, 0, 0, 0);
    raw_syscall6(SYS_exit, failures != 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
