/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code, licensed under MPL-2.0.
 *
 * Validate Linux CLONE_FS sharing and unshare(CLONE_FS) isolation without a
 * libc dependency so the same binary can run in both Alpine guests.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_getcwd 79
#define SYS_chdir 80
#define SYS_umask 95
#define SYS_sched_yield 24
#define SYS_unshare 272
#elif defined(__aarch64__)
#define SYS_getcwd 17
#define SYS_chdir 49
#define SYS_write 64
#define SYS_exit 93
#define SYS_unshare 97
#define SYS_sched_yield 124
#define SYS_umask 166
#define SYS_clone 220
#define SYS_wait4 260
#else
#error "fs_context_state_runtime_probe requires a Linux 64-bit architecture"
#endif

#define CLONE_VM 0x00000100ul
#define CLONE_FS 0x00000200ul
#define SIGCHLD 17ul

static unsigned char child_stack[65536] __attribute__((aligned(16)));
static volatile int child_phase;
static volatile int child_done;

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
    return raw_syscall4(number, argument0, argument1, argument2, 0);
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall3(number, argument0, argument1, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall2(number, argument0, 0);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text, (long)text_length(text));
}

static int text_equal(const char *left, const char *right) {
    unsigned long index = 0;
    while (left[index] && right[index] && left[index] == right[index])
        ++index;
    return left[index] == right[index];
}

typedef int (*child_entry_t)(void *argument);
extern long clone_shared(unsigned long flags, void *stack,
                         child_entry_t entry, void *argument);

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".global clone_shared\n"
    ".type clone_shared,@function\n"
    "clone_shared:\n"
    "push %r12\n"
    "push %r13\n"
    "mov %rdx,%r12\n"
    "mov %rcx,%r13\n"
    "xor %rdx,%rdx\n"
    "xor %r10,%r10\n"
    "xor %r8,%r8\n"
    "mov $56,%rax\n"
    "syscall\n"
    "test %rax,%rax\n"
    "jnz 1f\n"
    "mov %r13,%rdi\n"
    "call *%r12\n"
    "mov %rax,%rdi\n"
    "mov $60,%rax\n"
    "syscall\n"
    "ud2\n"
    "1:\n"
    "pop %r13\n"
    "pop %r12\n"
    "ret\n");
#else
__asm__(
    ".text\n"
    ".global clone_shared\n"
    ".type clone_shared,%function\n"
    "clone_shared:\n"
    "stp x19,x20,[sp,#-16]!\n"
    "mov x19,x2\n"
    "mov x20,x3\n"
    "mov x2,xzr\n"
    "mov x3,xzr\n"
    "mov x4,xzr\n"
    "mov x8,#220\n"
    "svc #0\n"
    "cbnz x0,1f\n"
    "mov x0,x20\n"
    "blr x19\n"
    "mov x8,#93\n"
    "svc #0\n"
    "brk #0\n"
    "1:\n"
    "ldp x19,x20,[sp],#16\n"
    "ret\n");
#endif

static int shared_child(void *argument) {
    (void)argument;
    if (raw_syscall1(SYS_umask, 0077) != 0022) return 1;
    if (raw_syscall1(SYS_chdir, (long)"/tmp") != 0) return 2;
    __atomic_store_n(&child_done, 1, __ATOMIC_RELEASE);
    return 0;
}

static int isolated_child(void *argument) {
    (void)argument;
    while (!__atomic_load_n(&child_phase, __ATOMIC_ACQUIRE))
        (void)raw_syscall1(SYS_sched_yield, 0);
    if (raw_syscall1(SYS_umask, 0077) != 0022) return 3;
    if (raw_syscall1(SYS_chdir, (long)"/") != 0) return 4;
    __atomic_store_n(&child_done, 1, __ATOMIC_RELEASE);
    return 0;
}

static int wait_for_child(long pid) {
    int status = -1;
    long result = raw_syscall4(SYS_wait4, pid, (long)&status, 0, 0);
    return result == pid && status == 0 ? 0 : 1;
}

static int wait_for_flag(void) {
    unsigned long spins = 0;
    while (!__atomic_load_n(&child_done, __ATOMIC_ACQUIRE)) {
        if (++spins == 10000000ul) return 1;
        (void)raw_syscall1(SYS_sched_yield, 0);
    }
    return 0;
}

static int cwd_is(const char *expected) {
    char buffer[64];
    long result = raw_syscall2(SYS_getcwd, (long)buffer, sizeof(buffer));
    return result > 0 && text_equal(buffer, expected);
}

static long start_child(child_entry_t entry) {
    void *stack = child_stack + sizeof(child_stack);
    child_done = 0;
    return clone_shared(CLONE_VM | CLONE_FS | SIGCHLD, stack, entry, 0);
}

static int run_probe(void) {
    int failures = 0;
    long child;

    (void)raw_syscall1(SYS_umask, 0022);
    if (raw_syscall1(SYS_chdir, (long)"/") != 0) return 1;
    child = start_child(shared_child);
    if (child <= 0 || wait_for_flag()) ++failures;
    if (raw_syscall1(SYS_umask, 0022) != 0077) ++failures;
    if (!cwd_is("/tmp")) ++failures;
    if (child > 0 && wait_for_child(child)) ++failures;

    (void)raw_syscall1(SYS_umask, 0022);
    if (raw_syscall1(SYS_chdir, (long)"/tmp") != 0) ++failures;
    child_phase = 0;
    child = start_child(isolated_child);
    if (child <= 0 || raw_syscall1(SYS_unshare, CLONE_FS) != 0)
        ++failures;
    __atomic_store_n(&child_phase, 1, __ATOMIC_RELEASE);
    if (child > 0 && wait_for_flag()) ++failures;
    if (raw_syscall1(SYS_umask, 0022) != 0022) ++failures;
    if (!cwd_is("/tmp")) ++failures;
    if (child > 0 && wait_for_child(child)) ++failures;

    putstr("fs_context_state_runtime_probe: ");
    putstr(failures ? "FAIL\n" : "OK\n");
    return failures ? 1 : 0;
}

void _start(void) {
    int result = run_probe();
    (void)raw_syscall1(SYS_exit, result);
    for (;;) {}
}
