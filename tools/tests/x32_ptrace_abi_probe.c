/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 ptrace word-width compatibility probe. */

#include <stdint.h>

#define SYS_write 1
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define X32_BIT UINT64_C(0x40000000)
#define X32_ptrace 521

#define PTRACE_TRACEME 0
#define PTRACE_PEEKDATA 2
#define PTRACE_POKEDATA 5
#define PTRACE_CONT 7
#define SIGSTOP 19

static volatile uint64_t trace_word = UINT64_C(0x1122334455667788);
static uint64_t peeked = UINT64_C(0xaabbccddeeff0011);
static int32_t child_status = -1;

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

static long x32_ptrace(long request, long pid, long address, long data) {
    return call((long)(X32_BIT | X32_ptrace), request, pid,
                address, data, 0, 0);
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

static int expect(const char *name, uint64_t actual, uint64_t expected) {
    if (actual == expected) return 0;
    print_text(name);
    print_text(" actual=");
    print_hex(actual);
    print_text(" expected=");
    print_hex(expected);
    print_text("\n");
    return 1;
}

static int stopped(int status) {
    return (status & 0xff) == 0x7f && ((status >> 8) & 0xff) == SIGSTOP;
}

__attribute__((noreturn, force_align_arg_pointer)) void _start(void) {
    int failures = 0;
    long child = call(SYS_fork, 0, 0, 0, 0, 0, 0);

    if (child == 0) {
        if (x32_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            call(SYS_exit, 20, 0, 0, 0, 0, 0);
        call(SYS_kill, call(SYS_getpid, 0, 0, 0, 0, 0, 0),
             SIGSTOP, 0, 0, 0, 0);
        call(SYS_exit,
             trace_word == UINT64_C(0x1122334412345678) ? 0 : 21,
             0, 0, 0, 0, 0);
    }
    if (child < 0 || call(SYS_wait4, child, (long)&child_status,
                          0, 0, 0, 0) != child || !stopped(child_status)) {
        failures++;
    } else {
        failures += expect("peek result", (uint64_t)x32_ptrace(
            PTRACE_PEEKDATA, child, (long)&trace_word, (long)&peeked), 0);
        failures += expect("peek value", peeked,
                           UINT64_C(0xaabbccdd55667788));
        failures += expect("poke result", (uint64_t)x32_ptrace(
            PTRACE_POKEDATA, child, (long)&trace_word, 0x12345678), 0);
        failures += expect("continue result", (uint64_t)x32_ptrace(
            PTRACE_CONT, child, 0, 0), 0);
        child_status = -1;
        failures += expect("wait result", (uint64_t)call(
            SYS_wait4, child, (long)&child_status, 0, 0, 0, 0),
            (uint64_t)child);
        failures += expect("child status", (uint32_t)child_status, 0);
    }
    print_text(failures ? "X32_PTRACE_ABI_PROBE_FAIL\n" :
                          "X32_PTRACE_ABI_PROBE_PASS\n");
    call(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
