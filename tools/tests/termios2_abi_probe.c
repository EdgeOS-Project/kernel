/* SPDX-License-Identifier: MPL-2.0 */
/* Verify the legacy and extended terminal parameter ABIs on one PTY. */
#include <stdint.h>
#include "kernel/tty_termios.h"
#if defined(__x86_64__)
#define SYS_ioctl 16
#define SYS_openat 257
#define SYS_close 3
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_ioctl 29
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
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

static long raw_syscall5(long number, long argument0, long argument1,
                         long argument2, long argument3, long argument4) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, argument4, 0);
}



#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    edge_linux_termios2_t original, changed, result;
    int failures = 0;
    long fd = raw_syscall6(SYS_openat, -100, (long)"/dev/ptmx", 258, 0, 0, 0);
    if (fd < 0) failures++;
    else if (raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCGETS2, (long)&original, 0, 0, 0) != 0) failures++;
    else {
        changed = original;
        changed.c_cflag = (changed.c_cflag & ~0x100f100fu) | 0x10001000u;
        changed.c_ispeed = 654321;
        changed.c_ospeed = 123456;
        failures += raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCSETS2, (long)&changed, 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCGETS2, (long)&result, 0, 0, 0) != 0;
        failures += result.c_ispeed != 654321 || result.c_ospeed != 123456;
        changed.c_cflag = (changed.c_cflag & ~0x100f100fu) | 0x1002u;
        failures += raw_syscall6(SYS_ioctl, fd, 0x5402, (long)&changed, 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCGETS2, (long)&result, 0, 0, 0) != 0;
        failures += result.c_ispeed != 115200 || result.c_ospeed != 115200;
        failures += raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCGETS2, 1, 0, 0, 0) != -14;
        failures += raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCSETSW2, (long)&original, 0, 0, 0) != 0;
        failures += raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCSETSF2, (long)&original, 0, 0, 0) != 0;
    }
    if (fd >= 0) raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    fd = raw_syscall6(SYS_openat, -100, (long)"/dev/null", 2, 0, 0, 0);
    failures += fd < 0 || raw_syscall6(SYS_ioctl, fd, EDGE_LINUX_TCGETS2, (long)&result, 0, 0, 0) != -25;
    const char *message = failures ? "TERMIOS2_ABI_PROBE_FAIL\n" : "TERMIOS2_ABI_PROBE_PASS\n";
    uint32_t length = 0;
    while (message[length]) ++length;
    raw_syscall6(SYS_write, 1, (long)message, length, 0, 0, 0);
    raw_syscall6(SYS_exit, failures != 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
