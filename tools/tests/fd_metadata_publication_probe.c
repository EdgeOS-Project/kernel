/* SPDX-License-Identifier: MPL-2.0 */
/* Verify metadata and status publication across copied and shared FD tables. */
#include <stdint.h>
#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_openat 257
#define SYS_close 3
#define SYS_dup 32
#define SYS_clone 56
#define SYS_wait4 61
#define SYS_exit 60
#define SYS_pipe2 293
#define SYS_fcntl 72
#define SYS_ftruncate 77
#define SYS_statx 332
#define SYS_lseek 8
#else
#define SYS_read 63
#define SYS_write 64
#define SYS_openat 56
#define SYS_close 57
#define SYS_dup 23
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_exit 93
#define SYS_pipe2 59
#define SYS_fcntl 25
#define SYS_ftruncate 46
#define SYS_statx 291
#define SYS_lseek 62
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

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2, argument3,
                        0, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static void putdec(long value) {
    char buffer[24];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        putstr("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    if (!magnitude) {
        putstr("0");
        return;
    }
    while (magnitude && position) {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    }
    (void)raw_syscall3(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned)position));
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": result=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}


static int check_size(long descriptor, uint64_t expected) {
    uint64_t status[32] = {0};
    long result = raw_syscall6(SYS_statx, descriptor, (long)"", 0x1000,
                               0x200, (long)status, 0);
    return expect_result("statx", result, 0) +
           expect_result("size", status[5], expected);
}

static int run_probe(void) {
    long file = raw_syscall4(SYS_openat, -100, (long)"/tmp/fd-metadata-probe",
                             2 | 64 | 512, 0600);
    long duplicate = raw_syscall1(SYS_dup, file);
    int pipe[2];
    int failures = 0;
    char byte = 'x';
    if (file < 0 || duplicate < 0 ||
        raw_syscall3(SYS_pipe2, (long)pipe, 0, 0) < 0) return 1;
    for (int iteration = 0; iteration < 32; ++iteration) {
        long child = raw_syscall6(SYS_clone,
            17 | ((iteration & 1) ? 0x400 : 0), 0, 0, 0, 0, 0);
        if (child < 0) return 1;
        if (!child) {
            int failed = expect_result("child_barrier",
                raw_syscall3(SYS_read, pipe[0], (long)&byte, 1), 1);
            failed += check_size(duplicate, 7);
            failed += expect_result("shared_append_flag",
                raw_syscall3(SYS_fcntl, duplicate, 3, 0) & 1024, 1024);
            failed += expect_result("append_write",
                raw_syscall3(SYS_write, duplicate, (long)&byte, 1), 1);
            failed += expect_result("clear_shared_flag",
                raw_syscall3(SYS_fcntl, duplicate, 4, 0), 0);
            raw_syscall1(SYS_exit, failed ? 1 : 0);
            for (;;) {}
        }
        failures += expect_result("truncate",
            raw_syscall3(SYS_ftruncate, file, 7, 0), 0);
        failures += expect_result("rewind",
            raw_syscall3(SYS_lseek, file, 0, 0), 0);
        failures += expect_result("set_shared_flag",
            raw_syscall3(SYS_fcntl, file, 4, 1024), 0);
        failures += expect_result("release_child",
            raw_syscall3(SYS_write, pipe[1], (long)&byte, 1), 1);
        int status = -1;
        failures += expect_result("wait_child",
            raw_syscall4(SYS_wait4, child, (long)&status, 0, 0), child);
        failures += expect_result("child_status", status, 0);
        failures += check_size(file, 8);
        failures += expect_result("parent_shared_flag",
            raw_syscall3(SYS_fcntl, file, 3, 0) & 1024, 0);
        failures += expect_result("shared_position",
            raw_syscall3(SYS_lseek, duplicate, 0, 1), 8);
    }
    return failures;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    int result = run_probe();
    putstr(result ? "FD_METADATA_FAIL\n" : "FD_METADATA_PASS\n");
    raw_syscall1(SYS_exit, result ? 1 : 0);
    for (;;) {}
}
#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ __volatile__("andq $-16, %rsp\ncall probe_entry\n");
}
#else
void _start(void) { probe_entry(); }
#endif
