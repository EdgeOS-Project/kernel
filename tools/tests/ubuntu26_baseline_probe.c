/* SPDX-License-Identifier: MPL-2.0 */
/* Report Ubuntu 26.04 interface availability without requiring a libc. */
#include <stdint.h>
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



static void report(const char *label, long value) {
    char line[128]; unsigned n = 0, digits = 0; char reversed[24];
    while (label[n]) { line[n] = label[n]; ++n; }
    line[n++] = '=';
    unsigned long magnitude = value < 0 ? (unsigned long)(-value) : (unsigned long)value;
    if (value < 0) line[n++] = '-';
    do { reversed[digits++] = (char)('0' + magnitude % 10); magnitude /= 10; } while (magnitude);
    while (digits) line[n++] = reversed[--digits];
    line[n++] = '\n'; raw_syscall6(64, 1, (long)line, n, 0, 0, 0);
}
void _start(void) {
    uint64_t buffer[64];
    report("BASELINE_PR_GET_AUXV", raw_syscall6(167, 0x41555856, (long)buffer, sizeof(buffer), 0, 0, 0));
    report("BASELINE_PROC_AUXV", raw_syscall6(56, -100, (long)"/proc/self/auxv", 0, 0, 0, 0));
    report("BASELINE_TCGETS2", raw_syscall6(29, 1, 0x802c542a, (long)buffer, 0, 0, 0));
    long context = raw_syscall6(430, (long)"tmpfs", 1, 0, 0, 0, 0);
    report("BASELINE_FSOPEN", context);
    if (context >= 0) {
        report("BASELINE_FSCONFIG", raw_syscall6(431, context, 6, 0, 0, 0, 0));
        long mount = raw_syscall6(432, context, 1, 0, 0, 0, 0);
        report("BASELINE_FSMOUNT", mount);
        if (mount >= 0) {
            report("BASELINE_MOUNT_ROOT_OPEN", raw_syscall6(56, mount, (long)".", 16384, 0, 0, 0));
            long status = raw_syscall6(291, mount, (long)"", 0x1000, 0x7ff, (long)buffer, 0);
            report("BASELINE_MOUNT_STATX", status);
            if (!status) report("BASELINE_MOUNT_TYPE", *(uint16_t *)((uint8_t *)buffer + 28) & 0170000);
        }
    }
    report("BASELINE_DONE", 1);
    raw_syscall6(142, 0xfee1dead, 0x28121969, 0x4321fedc, 0, 0, 0);
    for (;;) {}
}
