/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 generic ioctl compatibility probe. */

#include <stdint.h>

#define SYS_write 1
#define SYS_close 3
#define SYS_fcntl 72
#define SYS_exit 60
#define SYS_pipe2 293
#define X32_BIT UINT64_C(0x40000000)
#define X32_ioctl 514

#define EBADF 9
#define EFAULT 14
#define ENOTTY 25
#define F_GETFD 1
#define F_GETFL 3
#define FD_CLOEXEC 1
#define O_NONBLOCK 0x800
#define FIONCLEX 0x5450
#define FIOCLEX 0x5451
#define FIONBIO 0x5421

static int descriptors[2] = {-1, -1};
static int enabled = 1;
static int disabled;

static long call(long number, long a0, long a1, long a2,
                 long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a0),
                     "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static long x32_ioctl(long descriptor, long command, long argument) {
    return call((long)(X32_BIT | X32_ioctl), descriptor, command,
                argument, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call(SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_hex(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char buffer[18];
    buffer[0] = '0';
    buffer[1] = 'x';
    for (int index = 0; index < 16; ++index)
        buffer[index + 2] = digits[(value >> ((15 - index) * 4)) & 15u];
    call(SYS_write, 1, (long)buffer, sizeof(buffer), 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text(name);
    print_text(" actual=");
    print_hex((uint64_t)actual);
    print_text(" expected=");
    print_hex((uint64_t)expected);
    print_text("\n");
    return 1;
}

__attribute__((noreturn, force_align_arg_pointer)) void _start(void) {
    int failures = 0;
    uint64_t enabled_alias;

    failures += expect("bad descriptor", x32_ioctl(-1, FIONBIO, 1), -EBADF);
    failures += expect("pipe2", call(
        SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0), 0);
    if (descriptors[0] >= 0) {
        failures += expect("fioclex", x32_ioctl(
            descriptors[0], FIOCLEX, 0), 0);
        failures += expect("getfd set", call(
            SYS_fcntl, descriptors[0], F_GETFD, 0, 0, 0, 0), FD_CLOEXEC);
        failures += expect("fionclex", x32_ioctl(
            descriptors[0], FIONCLEX, 0), 0);
        failures += expect("getfd clear", call(
            SYS_fcntl, descriptors[0], F_GETFD, 0, 0, 0, 0), 0);
        failures += expect("fionbio null", x32_ioctl(
            descriptors[0], FIONBIO, 0), -EFAULT);
        enabled_alias = (UINT64_C(1) << 32) |
            (uint32_t)(uintptr_t)&enabled;
        failures += expect("fionbio alias", x32_ioctl(
            descriptors[0], FIONBIO, (long)enabled_alias), 0);
        failures += expect("getfl set", call(
            SYS_fcntl, descriptors[0], F_GETFL, 0, 0, 0, 0) & O_NONBLOCK,
            O_NONBLOCK);
        failures += expect("fionbio clear", x32_ioctl(
            descriptors[0], FIONBIO, (long)&disabled), 0);
        failures += expect("getfl clear", call(
            SYS_fcntl, descriptors[0], F_GETFL, 0, 0, 0, 0) & O_NONBLOCK, 0);
        failures += expect("unknown", x32_ioctl(
            descriptors[0], UINT64_C(0x1234567812345678), 0), -ENOTTY);
    }
    if (descriptors[0] >= 0)
        call(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    if (descriptors[1] >= 0)
        call(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    print_text(failures ? "X32_IOCTL_ABI_PROBE_FAIL\n" :
                          "X32_IOCTL_ABI_PROBE_PASS\n");
    call(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
