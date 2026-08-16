/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux ABI probe for /proc/self/oom_score_adj policy. */

#include <stdint.h>

#if defined(__aarch64__)
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_CLOSE 57
#define SYS_OPENAT 56
#define SYS_CAPGET 90
#define SYS_CAPSET 91
#define SYS_EXIT 93
#elif defined(__x86_64__)
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_OPENAT 257
#define SYS_CAPGET 125
#define SYS_CAPSET 126
#define SYS_EXIT 60
#else
#error Unsupported architecture
#endif

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define LINUX_CAPABILITY_VERSION_3 0x20080522u
#define CAP_SYS_RESOURCE 24u

struct capability_header {
    uint32_t version;
    int32_t pid;
};

struct capability_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static long raw_syscall6(long nr, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__aarch64__)
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                     "r"(x4), "r"(x5), "r"(x8) : "memory");
    return x0;
#else
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a0),
                     "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
#endif
}

static long syscall3(long nr, long a0, long a1, long a2) {
    return raw_syscall6(nr, a0, a1, a2, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print(const char *text) {
    syscall3(SYS_WRITE, 1, (long)text, (long)text_length(text));
}

static int write_adjustment(const char *text) {
    static const char path[] = "/proc/self/oom_score_adj";
    long fd = raw_syscall6(SYS_OPENAT, AT_FDCWD, (long)path, O_WRONLY,
                           0, 0, 0);
    long result;
    if (fd < 0) return (int)fd;
    result = syscall3(SYS_WRITE, fd, (long)text, (long)text_length(text));
    raw_syscall6(SYS_CLOSE, fd, 0, 0, 0, 0, 0);
    return (int)result;
}

static int read_adjustment(void) {
    static const char path[] = "/proc/self/oom_score_adj";
    char buffer[32];
    long fd = raw_syscall6(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY,
                           0, 0, 0);
    long length;
    int sign = 1;
    int value = 0;
    int index = 0;
    if (fd < 0) return 2001;
    length = syscall3(SYS_READ, fd, (long)buffer, sizeof(buffer));
    raw_syscall6(SYS_CLOSE, fd, 0, 0, 0, 0, 0);
    if (length <= 0) return 2002;
    if (buffer[index] == '-') {
        sign = -1;
        ++index;
    }
    for (; index < length && buffer[index] >= '0' && buffer[index] <= '9';
         ++index)
        value = value * 10 + buffer[index] - '0';
    return sign * value;
}

static int run_probe(void) {
    struct capability_header header = {
        LINUX_CAPABILITY_VERSION_3, 0
    };
    struct capability_data original[2];
    struct capability_data reduced[2];
    int original_adjustment;

    original_adjustment = read_adjustment();
    if (original_adjustment < -1000 || original_adjustment > 1000) return 1;
    if (write_adjustment("-100\n") < 0 || read_adjustment() != -100) return 2;
    if (syscall3(SYS_CAPGET, (long)&header, (long)original, 0) < 0) return 3;
    reduced[0] = original[0];
    reduced[1] = original[1];
    reduced[0].effective &= ~(1u << CAP_SYS_RESOURCE);
    if (syscall3(SYS_CAPSET, (long)&header, (long)reduced, 0) < 0) return 4;
    if (write_adjustment("-101\n") >= 0) return 5;
    if (write_adjustment("200\n") < 0 || read_adjustment() != 200) return 6;
    if (write_adjustment("-100\n") < 0 || read_adjustment() != -100) return 7;
    if (write_adjustment("-101\n") >= 0) return 8;
    if (syscall3(SYS_CAPSET, (long)&header, (long)original, 0) < 0) return 9;
    if (original_adjustment == 0) {
        if (write_adjustment("0\n") < 0 || read_adjustment() != 0) return 10;
    }
    return 0;
}

void _start(void) {
    int result = run_probe();
    if (result == 0)
        print("oom_score_adj_abi_probe: OK\n");
    else
        print("oom_score_adj_abi_probe: FAIL\n");
    raw_syscall6(SYS_EXIT, result, 0, 0, 0, 0, 0);
    for (;;) { }
}
