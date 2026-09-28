/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux clone and clone3 policy probe for both supported ABIs.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_rt_sigaction 13
#define SYS_clone 56
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_pipe2 293
#define SYS_clone3 435
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_rt_sigaction 134
#define SYS_clone 220
#define SYS_execve 221
#define SYS_wait4 260
#define SYS_clone3 435
#else
#error "clone_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define ECHILD 10
#define EFAULT 14
#define EINVAL 22

#define O_CLOEXEC 0x00080000
#define SIGCHLD 17
#define CLONE_VM 0x00000100ULL
#define CLONE_SIGHAND 0x00000800ULL
#define CLONE_PIDFD 0x00001000ULL
#define CLONE_VFORK 0x00004000ULL
#define CLONE_PARENT 0x00008000ULL
#define CLONE_PARENT_SETTID 0x00100000ULL
#define CLONE_CHILD_SETTID 0x01000000ULL
#define CLONE_THREAD 0x00010000ULL
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#define CLONE_INTO_CGROUP 0x200000000ULL

struct clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

struct linux_sigaction {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

static volatile uint64_t g_sighand_phase;
static volatile uint64_t g_sighand_seen;
static uint8_t g_sighand_child_stack[16384] __attribute__((aligned(16)));
static uint8_t g_vfork_child_stack[16384] __attribute__((aligned(16)));
static int g_exec_pipe[2];
static int g_exec_pidfd;
static long g_exec_error;
static char g_exec_path[] = "/bin/true";
static char *g_exec_argv[] = {g_exec_path, 0};
static char *g_exec_env[] = {0};

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
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, 0, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
}

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall6(number, argument0, argument1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static long raw_clone(uint64_t flags, uint64_t stack, uint64_t parent_tid,
                      uint64_t child_tid, uint64_t tls) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_clone, (long)flags, (long)stack,
                        (long)parent_tid, (long)child_tid, (long)tls, 0);
#else
    return raw_syscall6(SYS_clone, (long)flags, (long)stack,
                        (long)parent_tid, (long)tls, (long)child_tid, 0);
#endif
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

static __attribute__((noreturn)) void exit_now(int status) {
    (void)raw_syscall1(SYS_exit, status);
    for (;;) {}
}

static __attribute__((noreturn, noinline, used))
void sighand_child_entry(void) {
    struct linux_sigaction action;
    while (!g_sighand_phase)
        __asm__ __volatile__("" ::: "memory");
    action.handler = 0;
    action.flags = 0;
    action.restorer = 0;
    action.mask = 0;
    if (raw_syscall4(SYS_rt_sigaction, 10, 0, (long)&action, 8) < 0)
        exit_now(2);
    g_sighand_seen = action.handler;
    __asm__ __volatile__("" ::: "memory");
    exit_now(0);
}

#if defined(__x86_64__)
static __attribute__((naked, noinline)) long
spawn_sighand_child(uint64_t flags __attribute__((unused)),
                    uint64_t stack __attribute__((unused))) {
    __asm__ __volatile__(
        "mov $56, %rax\n"
        "syscall\n"
        "test %rax, %rax\n"
        "jnz 1f\n"
        "xor %ebp, %ebp\n"
        "call sighand_child_entry\n"
        "ud2\n"
        "1: ret\n");
}
#else
static __attribute__((noinline)) long
spawn_sighand_child(uint64_t flags, uint64_t stack) {
    register uint64_t x0 __asm__("x0") = flags;
    register uint64_t x1 __asm__("x1") = stack;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    register uint64_t x4 __asm__("x4") = 0;
    register uint64_t x8 __asm__("x8") = SYS_clone;
    __asm__ __volatile__(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "mov x29, xzr\n"
        "bl sighand_child_entry\n"
        "brk #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x29", "x30", "memory", "cc");
    return (long)x0;
}
#endif

/*
 * A clone child using a replacement stack cannot return through the caller's
 * C frame. Keep the child exit path entirely in registers while the parent
 * returns normally after vfork releases it.
 */
#if defined(__x86_64__)
static __attribute__((naked, noinline)) long
spawn_vfork_child(uint64_t flags __attribute__((unused)),
                  uint64_t stack __attribute__((unused))) {
    __asm__ __volatile__(
        "mov $56, %rax\n"
        "syscall\n"
        "test %rax, %rax\n"
        "jnz 1f\n"
        "mov $60, %rax\n"
        "xor %edi, %edi\n"
        "syscall\n"
        "ud2\n"
        "1: ret\n");
}
#else
static __attribute__((noinline)) long
spawn_vfork_child(uint64_t flags, uint64_t stack) {
    register uint64_t x0 __asm__("x0") = flags;
    register uint64_t x1 __asm__("x1") = stack;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    register uint64_t x4 __asm__("x4") = 0;
    register uint64_t x8 __asm__("x8") = SYS_clone;
    __asm__ __volatile__(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "mov x8, %6\n"
        "mov x0, xzr\n"
        "svc #0\n"
        "brk #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8),
          "i"(SYS_exit)
        : "x29", "x30", "memory", "cc");
    return (long)x0;
}
#endif

static void clone_args_clear(struct clone_args *arguments) {
    uint64_t *words = (uint64_t *)arguments;
    for (uint32_t index = 0; index < sizeof(*arguments) / sizeof(*words);
         ++index)
        words[index] = 0;
}

static int wait_for_success(const char *name, long child) {
    int status = -1;
    long waited;
    if (child < 0) return expect_result(name, child, 0);
    waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    if (waited != child) return expect_result(name, waited, child);
    return expect_result(name, status, 0);
}

static int test_clone_success(void) {
    long child = raw_clone(SIGCHLD, 0, 0, 0, 0);
    if (!child) exit_now(0);
    return wait_for_success("clone_success", child);
}

static int test_vfork_success(void) {
    uint64_t stack_top = (uint64_t)(uintptr_t)
        &g_vfork_child_stack[sizeof(g_vfork_child_stack)];
    long child = spawn_vfork_child(
        CLONE_VM | CLONE_VFORK | SIGCHLD, stack_top);
    return wait_for_success("vfork_success", child);
}

static int test_vfork_exec_cloexec(void) {
    long child;
    long bytes;
    int failures = 0;

    g_exec_pipe[0] = -1;
    g_exec_pipe[1] = -1;
    g_exec_pidfd = -1;
    g_exec_error = 0;
    if (raw_syscall2(SYS_pipe2, (long)g_exec_pipe, O_CLOEXEC) < 0)
        return expect_result("vfork_exec_pipe2", -1, 0);

    child = raw_clone(CLONE_VM | CLONE_VFORK | CLONE_PIDFD | SIGCHLD,
                      0, (uint64_t)(uintptr_t)&g_exec_pidfd, 0, 0);
    if (!child) {
        (void)raw_syscall1(SYS_close, g_exec_pipe[0]);
        g_exec_error = raw_syscall3(
            SYS_execve, (long)g_exec_path, (long)g_exec_argv,
            (long)g_exec_env);
        (void)raw_syscall3(SYS_write, g_exec_pipe[1],
                           (long)&g_exec_error, sizeof(g_exec_error));
        exit_now(253);
    }
    if (child < 0) {
        (void)raw_syscall1(SYS_close, g_exec_pipe[0]);
        (void)raw_syscall1(SYS_close, g_exec_pipe[1]);
        return expect_result("vfork_exec_clone", child, 0);
    }

    (void)raw_syscall1(SYS_close, g_exec_pipe[1]);
    bytes = raw_syscall3(SYS_read, g_exec_pipe[0],
                         (long)&g_exec_error, sizeof(g_exec_error));
    (void)raw_syscall1(SYS_close, g_exec_pipe[0]);
    failures += expect_result("vfork_exec_error_pipe_eof", bytes, 0);
    failures += expect_result("vfork_exec_pidfd", g_exec_pidfd >= 0, 1);
    failures += wait_for_success("vfork_exec_wait", child);
    if (g_exec_pidfd >= 0)
        (void)raw_syscall1(SYS_close, g_exec_pidfd);
    return failures;
}

static int test_clone_high_bits_ignored(void) {
    long child = raw_clone(SIGCHLD | (1ULL << 63) |
                           CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP,
                           0, 0, 0, 0);
    if (!child) exit_now(0);
    return wait_for_success("clone_high_bits_ignored", child);
}

static int test_clone3_success(void) {
    struct clone_args arguments;
    long child;
    clone_args_clear(&arguments);
    arguments.exit_signal = SIGCHLD;
    child = raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments));
    if (!child) exit_now(0);
    return wait_for_success("clone3_success", child);
}

static int test_clone3_unused_cgroup(void) {
    struct clone_args arguments;
    long child;
    clone_args_clear(&arguments);
    arguments.exit_signal = SIGCHLD;
    arguments.cgroup = 0xffffffffffffffffULL;
    child = raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments));
    if (!child) exit_now(0);
    return wait_for_success("clone3_unused_cgroup", child);
}

static int test_clone3_pidfd_and_parent_tid(void) {
    struct clone_args arguments;
    int pidfd = -1;
    int parent_tid = -1;
    long child;
    int failures = 0;
    clone_args_clear(&arguments);
    arguments.flags = CLONE_PIDFD | CLONE_PARENT_SETTID;
    arguments.pidfd = (uint64_t)(uintptr_t)&pidfd;
    arguments.parent_tid = (uint64_t)(uintptr_t)&parent_tid;
    arguments.exit_signal = SIGCHLD;
    child = raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments));
    if (!child) exit_now(0);
    if (child < 0) return expect_result("clone3_pidfd_parent_tid", child, 0);
    failures += expect_result("clone3_parent_tid_value", parent_tid, child);
    if (pidfd < 0) failures += expect_result("clone3_pidfd_value", pidfd, 0);
    failures += wait_for_success("clone3_pidfd_wait", child);
    if (pidfd >= 0) (void)raw_syscall1(SYS_close, pidfd);
    return failures;
}

static int test_clone_parent(void) {
    long worker = raw_clone(SIGCHLD, 0, 0, 0, 0);
    int status = -1;
    long waited;
    int failures = 0;

    if (!worker) {
        long sibling = raw_clone(SIGCHLD | CLONE_PARENT, 0, 0, 0, 0);
        if (!sibling) exit_now(0);
        if (sibling < 0) exit_now(2);
        waited = raw_syscall4(SYS_wait4, sibling, (long)&status, 0, 0);
        exit_now(waited == -ECHILD ? 0 : 3);
    }
    if (worker < 0) return expect_result("clone_parent_worker", worker, 0);
    waited = raw_syscall4(SYS_wait4, worker, (long)&status, 0, 0);
    failures += expect_result("clone_parent_worker_wait", waited, worker);
    failures += expect_result("clone_parent_worker_status", status, 0);
    status = -1;
    waited = raw_syscall4(SYS_wait4, -1, (long)&status, 0, 0);
    if (waited <= 0)
        failures += expect_result("clone_parent_sibling_wait", waited, 1);
    failures += expect_result("clone_parent_sibling_status", status, 0);
    return failures;
}

static int test_clone_sighand_shared(void) {
    struct linux_sigaction original;
    struct linux_sigaction initial;
    struct linux_sigaction updated;
    uint64_t stack_top = (uint64_t)(uintptr_t)
        &g_sighand_child_stack[sizeof(g_sighand_child_stack)];
    long child;
    int failures = 0;

    original.handler = 0;
    original.flags = 0;
    original.restorer = 0;
    original.mask = 0;
    if (raw_syscall4(SYS_rt_sigaction, 10, 0, (long)&original, 8) < 0)
        return expect_result("clone_sighand_get_original", -1, 0);
    initial.handler = 0x10000;
    initial.flags = 0;
    initial.restorer = 0;
    initial.mask = 0;
    if (raw_syscall4(SYS_rt_sigaction, 10, (long)&initial, 0, 8) < 0)
        return expect_result("clone_sighand_set_initial", -1, 0);

    g_sighand_phase = 0;
    g_sighand_seen = 0;
    child = spawn_sighand_child(CLONE_VM | CLONE_SIGHAND | SIGCHLD,
                                stack_top);
    if (child < 0) {
        (void)raw_syscall4(SYS_rt_sigaction, 10, (long)&original, 0, 8);
        return expect_result("clone_sighand_spawn", child, 0);
    }
    updated.handler = 0x20000;
    updated.flags = 0;
    updated.restorer = 0;
    updated.mask = 0;
    if (raw_syscall4(SYS_rt_sigaction, 10, (long)&updated, 0, 8) < 0)
        failures += expect_result("clone_sighand_set_updated", -1, 0);
    __asm__ __volatile__("" ::: "memory");
    g_sighand_phase = 1;
    failures += wait_for_success("clone_sighand_wait", child);
    failures += expect_result("clone_sighand_shared_value",
                              (long)g_sighand_seen,
                              (long)updated.handler);
    (void)raw_syscall4(SYS_rt_sigaction, 10, (long)&original, 0, 8);
    return failures;
}

static int test_clone3_clear_sighand(void) {
    struct clone_args arguments;
    struct linux_sigaction original_ignored;
    struct linux_sigaction original_caught;
    struct linux_sigaction ignored;
    struct linux_sigaction caught;
    struct linux_sigaction observed_ignored;
    struct linux_sigaction observed_caught;
    long child;
    int failures = 0;

    if (raw_syscall4(SYS_rt_sigaction, 10, 0,
                     (long)&original_ignored, 8) < 0 ||
        raw_syscall4(SYS_rt_sigaction, 12, 0,
                     (long)&original_caught, 8) < 0)
        return expect_result("clone_clear_get_original", -1, 0);
    ignored.handler = 1;
    ignored.flags = 0;
    ignored.restorer = 0;
    ignored.mask = 0;
    caught.handler = 0x30000;
    caught.flags = 0;
    caught.restorer = 0;
    caught.mask = 0;
    (void)raw_syscall4(SYS_rt_sigaction, 10, (long)&ignored, 0, 8);
    (void)raw_syscall4(SYS_rt_sigaction, 12, (long)&caught, 0, 8);

    clone_args_clear(&arguments);
    arguments.flags = CLONE_CLEAR_SIGHAND;
    arguments.exit_signal = SIGCHLD;
    child = raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments));
    if (!child) {
        if (raw_syscall4(SYS_rt_sigaction, 10, 0,
                         (long)&observed_ignored, 8) < 0 ||
            raw_syscall4(SYS_rt_sigaction, 12, 0,
                         (long)&observed_caught, 8) < 0)
            exit_now(2);
        exit_now(observed_ignored.handler == 1 &&
                 observed_caught.handler == 0 ? 0 : 3);
    }
    if (child < 0) {
        failures += expect_result("clone3_clear_sighand_spawn", child, 0);
    } else {
        failures += wait_for_success("clone3_clear_sighand_wait", child);
    }
    (void)raw_syscall4(SYS_rt_sigaction, 10,
                       (long)&original_ignored, 0, 8);
    (void)raw_syscall4(SYS_rt_sigaction, 12,
                       (long)&original_caught, 0, 8);
    return failures;
}

static int run_probe(void) {
    struct clone_args arguments;
    int failures = 0;

    failures += expect_result("clone_sighand_without_vm",
        raw_clone(CLONE_SIGHAND, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("clone_thread_without_sighand",
        raw_clone(CLONE_THREAD, 0, 0, 0, 0), -EINVAL);
    failures += expect_result("clone_pidfd_parent_tid_conflict",
        raw_clone(SIGCHLD | CLONE_PIDFD | CLONE_PARENT_SETTID,
                  0, 1, 0, 0), -EINVAL);
    failures += expect_result("clone_pidfd_null",
        raw_clone(SIGCHLD | CLONE_PIDFD, 0, 0, 0, 0), -EFAULT);

    failures += expect_result("clone3_null",
        raw_syscall2(SYS_clone3, 0, sizeof(arguments)), -EFAULT);
    clone_args_clear(&arguments);
    failures += expect_result("clone3_short",
        raw_syscall2(SYS_clone3, (long)&arguments, 63), -EINVAL);
    arguments.flags = 1ULL << 63;
    failures += expect_result("clone3_unknown_flags",
        raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments)),
        -EINVAL);
    clone_args_clear(&arguments);
    arguments.stack = 0x10000;
    failures += expect_result("clone3_stack_without_size",
        raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments)),
        -EINVAL);
    clone_args_clear(&arguments);
    arguments.stack_size = 0x1000;
    failures += expect_result("clone3_size_without_stack",
        raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments)),
        -EINVAL);
    clone_args_clear(&arguments);
    arguments.stack = 0xfffffffffffff000ULL;
    arguments.stack_size = 0x2000;
    failures += expect_result("clone3_stack_overflow",
        raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments)),
        -EINVAL);
    clone_args_clear(&arguments);
    arguments.exit_signal = 65;
    failures += expect_result("clone3_bad_exit_signal",
        raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments)),
        -EINVAL);
    clone_args_clear(&arguments);
    arguments.flags = CLONE_PIDFD;
    failures += expect_result("clone3_pidfd_null",
        raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments)),
        -EFAULT);
    clone_args_clear(&arguments);
    arguments.flags = CLONE_INTO_CGROUP;
    arguments.cgroup = 999999;
    failures += expect_result("clone3_bad_cgroup_fd",
        raw_syscall2(SYS_clone3, (long)&arguments, sizeof(arguments)),
        -EBADF);

    failures += test_clone_success();
    failures += test_vfork_success();
    failures += test_vfork_exec_cloexec();
    failures += test_clone_high_bits_ignored();
    failures += test_clone3_success();
    failures += test_clone3_unused_cgroup();
    failures += test_clone3_pidfd_and_parent_tid();
    failures += test_clone_parent();
    failures += test_clone_sighand_shared();
    failures += test_clone3_clear_sighand();

    putstr(failures ? "CLONE_ABI_PROBE_FAIL failures: " :
                      "CLONE_ABI_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    exit_now(run_probe());
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ __volatile__(
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
