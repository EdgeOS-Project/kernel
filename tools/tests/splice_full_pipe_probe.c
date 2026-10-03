/* SPDX-License-Identifier: MPL-2.0 */
/* A blocked splice must let another process drain a completely full pipe. */
#include <stdint.h>
#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_nanosleep 35
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_fcntl 72
#define SYS_openat 257
#define SYS_splice 275
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_nanosleep 101
#define SYS_clone 220
#define SYS_exit 93
#define SYS_wait4 260
#define SYS_fcntl 25
#define SYS_openat 56
#define SYS_splice 76
#define SYS_pipe2 59
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



static uint8_t bytes[4096];
static void say(const char *s) {
    uint32_t n = 0;
    while (s[n]) ++n;
    raw_syscall6(SYS_write, 1, (long)s, n, 0, 0, 0);
}
__attribute__((noreturn)) static void finish(int status) {
    say(status ? "SPLICE_FULL_PIPE_FAIL\n" : "SPLICE_FULL_PIPE_PASS\n");
    raw_syscall6(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {}
}
#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int pipe[2], status = -1;
    uint64_t filled = 0, offset = 0;
    long file, result, child;
    if (raw_syscall6(SYS_pipe2, (long)pipe, 2048, 0, 0, 0, 0) < 0) finish(1);
    while (filled < 1048576u) {
        result = raw_syscall6(SYS_write, pipe[1], (long)bytes, sizeof(bytes), 0, 0, 0);
        if (result == -11) break;
        if (result <= 0) finish(2);
        filled += (uint64_t)result;
    }
    if (!filled || filled >= 1048576u) finish(3);
    if (raw_syscall6(SYS_fcntl, pipe[0], 4, 0, 0, 0, 0) < 0 ||
        raw_syscall6(SYS_fcntl, pipe[1], 4, 0, 0, 0, 0) < 0) finish(4);
    file = raw_syscall6(SYS_openat, -100, (long)"/tmp/splice-full-pipe-source", 578, 0600, 0, 0);
    if (file < 0 || raw_syscall6(SYS_write, file, (long)"Z", 1, 0, 0, 0) != 1) finish(5);
    child = raw_syscall6(SYS_clone, 17, 0, 0, 0, 0, 0);
    if (!child) {
        const int64_t delay[2] = {0, 100000000};
        uint64_t remaining = filled;
        raw_syscall6(SYS_close, pipe[1], 0, 0, 0, 0, 0);
        raw_syscall6(SYS_nanosleep, (long)delay, 0, 0, 0, 0, 0);
        while (remaining) {
            uint32_t count = remaining < sizeof(bytes) ? (uint32_t)remaining : sizeof(bytes);
            result = raw_syscall6(SYS_read, pipe[0], (long)bytes, count, 0, 0, 0);
            if (result <= 0) finish(6);
            for (long i = 0; i < result; ++i) if (bytes[i]) finish(7);
            remaining -= (uint64_t)result;
        }
        result = raw_syscall6(SYS_read, pipe[0], (long)bytes, 1, 0, 0, 0);
        raw_syscall6(SYS_exit, result == 1 && bytes[0] == 'Z' ? 0 : 8, 0, 0, 0, 0, 0);
        for (;;) {}
    }
    if (child < 0) finish(9);
    say("SPLICE_FULL_PIPE_WAIT_BEGIN\n");
    result = raw_syscall6(SYS_splice, file, (long)&offset, pipe[1], 0, 1, 0);
    if (result != 1 || offset != 1) finish(10);
    raw_syscall6(SYS_close, pipe[1], 0, 0, 0, 0, 0);
    if (raw_syscall6(SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child || status) finish(11);
    finish(0);
}
