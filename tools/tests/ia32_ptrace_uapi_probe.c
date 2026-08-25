/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 ptrace compatibility ABI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_fork 2
#define SYS_write 4
#define SYS_getpid 20
#define SYS_kill 37
#define SYS_ptrace 26
#define SYS_wait4 114

#define PTRACE_TRACEME 0
#define PTRACE_PEEKDATA 2
#define PTRACE_PEEKUSER 3
#define PTRACE_POKEDATA 5
#define PTRACE_POKEUSER 6
#define PTRACE_CONT 7
#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#define PTRACE_GETFPREGS 14
#define PTRACE_SETFPREGS 15
#define PTRACE_GETFPXREGS 18
#define PTRACE_SETFPXREGS 19
#define PTRACE_GET_THREAD_AREA 25
#define PTRACE_SET_THREAD_AREA 26
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SETSIGINFO 0x4203
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205

#define NT_PRSTATUS 1
#define SIGSTOP 19

struct user_regs32 {
    uint32_t bx;
    uint32_t cx;
    uint32_t dx;
    uint32_t si;
    uint32_t di;
    uint32_t bp;
    uint32_t ax;
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;
    uint32_t orig_ax;
    uint32_t ip;
    uint32_t cs;
    uint32_t flags;
    uint32_t sp;
    uint32_t ss;
};

struct compat_iovec {
    uint32_t base;
    uint32_t length;
};

struct user_desc {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t flags;
};

static volatile uint32_t trace_word = UINT32_C(0x55667788);
static uint32_t peeked_word;
static uint32_t peeked_user;
static uint32_t saved_ax;
static int32_t child_status;
static struct user_regs32 registers;
static struct user_regs32 regset_registers;
static uint8_t fpregs[108];
static uint8_t fpxregs[512];
static uint8_t signal_info[128];
static struct user_desc thread_area;
static struct compat_iovec register_iovec;

__attribute__((naked)) static long raw_call6(
        long number, long a0, long a1, long a2,
        long a3, long a4, long a5) {
    __asm__ volatile(
        "pushl %ebp\n"
        "pushl %edi\n"
        "pushl %esi\n"
        "pushl %ebx\n"
        "movl 20(%esp), %eax\n"
        "movl 24(%esp), %ebx\n"
        "movl 28(%esp), %ecx\n"
        "movl 32(%esp), %edx\n"
        "movl 36(%esp), %esi\n"
        "movl 40(%esp), %edi\n"
        "movl 44(%esp), %ebp\n"
        "int $0x80\n"
        "popl %ebx\n"
        "popl %esi\n"
        "popl %edi\n"
        "popl %ebp\n"
        "ret\n");
}

#define call6(number, a0, a1, a2, a3, a4, a5) \
    raw_call6((number), \
              (long)(uintptr_t)(a0), (long)(uintptr_t)(a1), \
              (long)(uintptr_t)(a2), (long)(uintptr_t)(a3), \
              (long)(uintptr_t)(a4), (long)(uintptr_t)(a5))

#define ptrace_call(request, pid, address, data) \
    call6(SYS_ptrace, (request), (pid), (address), (data), 0, 0)

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void fail(const char *name) {
    static const char prefix[] = "IA32_PTRACE_UAPI_PROBE_FAIL ";
    static const char newline[] = "\n";
    call6(SYS_write, 1, prefix, sizeof(prefix) - 1u, 0, 0, 0);
    call6(SYS_write, 1, name, text_length(name), 0, 0, 0);
    call6(SYS_write, 1, newline, 1, 0, 0, 0);
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static int stopped(int32_t status) {
    return (status & 0xff) == 0x7f &&
           ((status >> 8) & 0xff) == SIGSTOP;
}

static void trace_child(long child) {
    if (call6(SYS_wait4, child, &child_status, 0, 0, 0, 0) != child ||
        !stopped(child_status))
        fail("wait-stop");
    if (ptrace_call(PTRACE_PEEKDATA, child, &trace_word, &peeked_word) != 0 ||
        peeked_word != UINT32_C(0x55667788))
        fail("peekdata");
    if (ptrace_call(PTRACE_POKEDATA, child, &trace_word,
                    UINT32_C(0x12345678)) != 0)
        fail("pokedata");
    if (ptrace_call(PTRACE_GETREGS, child, 0, &registers) != 0 ||
        registers.ip == 0 || registers.sp == 0 ||
        (registers.cs & 3u) != 3u || (registers.ss & 3u) != 3u)
        fail("getregs");
    if (ptrace_call(PTRACE_PEEKUSER, child, 0, &peeked_user) != 0 ||
        peeked_user != registers.bx)
        fail("peekuser");
    saved_ax = registers.ax;
    if (ptrace_call(PTRACE_POKEUSER, child, 24,
                    UINT32_C(0x31415926)) != 0 ||
        ptrace_call(PTRACE_GETREGS, child, 0, &registers) != 0 ||
        registers.ax != UINT32_C(0x31415926))
        fail("pokeuser");
    if (ptrace_call(PTRACE_POKEUSER, child, 24, saved_ax) != 0)
        fail("restore-user");
    register_iovec.base = (uint32_t)(uintptr_t)&regset_registers;
    register_iovec.length = sizeof(regset_registers);
    if (ptrace_call(PTRACE_GETREGSET, child, NT_PRSTATUS,
                    &register_iovec) != 0 ||
        register_iovec.length != sizeof(regset_registers) ||
        regset_registers.ip != registers.ip)
        fail("getregset");
    if (ptrace_call(PTRACE_SETREGS, child, 0, &registers) != 0)
        fail("setregs");
    register_iovec.length = sizeof(regset_registers);
    if (ptrace_call(PTRACE_SETREGSET, child, NT_PRSTATUS,
                    &register_iovec) != 0)
        fail("setregset");
    if (ptrace_call(PTRACE_GETFPREGS, child, 0, fpregs) != 0)
        fail("getfpregs");
    if (ptrace_call(PTRACE_SETFPREGS, child, 0, fpregs) != 0)
        fail("setfpregs");
    if (ptrace_call(PTRACE_GETFPXREGS, child, 0, fpxregs) != 0)
        fail("getfpxregs");
    if (ptrace_call(PTRACE_SETFPXREGS, child, 0, fpxregs) != 0)
        fail("setfpxregs");
    if (ptrace_call(PTRACE_GETSIGINFO, child, 0, signal_info) != 0 ||
        ptrace_call(PTRACE_SETSIGINFO, child, 0, signal_info) != 0)
        fail("siginfo");
    thread_area.entry_number = 12;
    if (ptrace_call(PTRACE_GET_THREAD_AREA, child, 12, &thread_area) != 0 ||
        thread_area.entry_number != 12)
        fail("get-thread-area");
    if (ptrace_call(PTRACE_SET_THREAD_AREA, child, 12, &thread_area) != 0)
        fail("set-thread-area");
    if (ptrace_call(PTRACE_CONT, child, 0, 0) != 0)
        fail("continue");
    child_status = -1;
    if (call6(SYS_wait4, child, &child_status, 0, 0, 0, 0) != child ||
        child_status != 0)
        fail("wait-exit");
}

__attribute__((noreturn)) void _start(void) {
    static const char pass[] = "IA32_PTRACE_UAPI_PROBE_PASS\n";
    long child = call6(SYS_fork, 0, 0, 0, 0, 0, 0);

    if (child == 0) {
        long pid;
        if (ptrace_call(PTRACE_TRACEME, 0, 0, 0) != 0)
            call6(SYS_exit, 20, 0, 0, 0, 0, 0);
        pid = call6(SYS_getpid, 0, 0, 0, 0, 0, 0);
        if (pid <= 0 || call6(SYS_kill, pid, SIGSTOP, 0, 0, 0, 0) != 0)
            call6(SYS_exit, 21, 0, 0, 0, 0, 0);
        call6(SYS_exit,
              trace_word == UINT32_C(0x12345678) ? 0 : 22,
              0, 0, 0, 0, 0);
    }
    if (child < 0) fail("fork");
    trace_child(child);
    call6(SYS_write, 1, pass, sizeof(pass) - 1u, 0, 0, 0);
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
