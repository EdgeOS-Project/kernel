/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 execve and execveat pointer-vector probe. */

#include <stdint.h>

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_BIT UINT64_C(0x40000000)
#define SYS_write 1
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define X32_execve 520
#define X32_execveat 545
#define AT_FDCWD -100

static const char child_path[] = "/child";
static uint32_t arguments[4];
static uint32_t environment[2];

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

static long x32(long number, long a0, long a1, long a2,
                long a3, long a4, long a5) {
    return call((long)(X32_BIT | (uint64_t)number),
                a0, a1, a2, a3, a4, a5);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call(SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int run_child(int use_execveat) {
    int32_t status = -1;
    long child = x32(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (child < 0) return -1;
    if (child == 0) {
        long result = use_execveat ?
            x32(X32_execveat, AT_FDCWD, (long)child_path,
                (long)arguments, (long)environment, 0, 0) :
            x32(X32_execve, (long)child_path, (long)arguments,
                (long)environment, 0, 0, 0);
        call(SYS_exit, result < 0 ? 111 : 112, 0, 0, 0, 0, 0);
    }
    if (x32(SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child)
        return -1;
    return status == 0 ? 0 : -1;
}

START_ATTRIBUTES void _start(void) {
    arguments[0] = (uint32_t)(uintptr_t)child_path;
    arguments[1] = 0;
    arguments[2] = UINT32_C(0xdeadbeef);
    environment[0] = 0;
    environment[1] = UINT32_C(0xdeadbeef);

    if (run_child(0) < 0) {
        print_text("FAIL execve\nX32_EXEC_ABI_PROBE_FAIL\n");
        call(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    if (run_child(1) < 0) {
        print_text("FAIL execveat\nX32_EXEC_ABI_PROBE_FAIL\n");
        call(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_EXEC_ABI_PROBE_PASS\n");
    call(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
