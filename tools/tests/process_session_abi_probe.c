/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code, licensed under MPL-2.0.
 *
 * This freestanding probe validates Linux process-group and session behavior
 * without relying on libc wrappers or architecture-specific errno handling.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_sched_yield 24
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_setpgid 109
#define SYS_setsid 112
#define SYS_getpgid 121
#define SYS_getsid 124
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_sched_yield 124
#define SYS_kill 129
#define SYS_setpgid 154
#define SYS_getpgid 155
#define SYS_getsid 156
#define SYS_setsid 157
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_execve 221
#define SYS_wait4 260
#else
#error "process_session_abi_probe requires a Linux 64-bit architecture"
#endif

#define EPERM 1
#define ESRCH 3
#define EACCES 13
#define EINTR 4
#define EINVAL 22
#define SIGKILL 9
#define SIGCHLD 17
#define O_CLOEXEC 0x80000

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
#elif defined(__aarch64__)
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

static long raw_syscall2(long number, long argument0, long argument1) {
    return raw_syscall6(number, argument0, argument1, 0, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static long raw_syscall0(long number) {
    return raw_syscall6(number, 0, 0, 0, 0, 0, 0);
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
    char buffer[32];
    unsigned long magnitude;
    int index = 31;
    buffer[index] = 0;
    if (value < 0) magnitude = (unsigned long)(-(value + 1)) + 1u;
    else magnitude = (unsigned long)value;
    do {
        buffer[--index] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    if (value < 0) buffer[--index] = '-';
    putstr(&buffer[index]);
}

static int expect_ret(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    putstr(name);
    putstr(": got=");
    putdec(actual);
    putstr(" expected=");
    putdec(expected);
    putstr("\n");
    return 1;
}

__attribute__((noreturn)) static void child_exit(int status) {
    (void)raw_syscall1(SYS_exit, status);
    for (;;) {}
}

static long fork_process(void) {
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
}

static int pipe_create(int descriptors[2], int flags) {
    return (int)raw_syscall2(SYS_pipe2, (long)descriptors, flags);
}

static int wait_child(long pid, int *exit_status) {
    int status = 0;
    long result;
    do {
        result = raw_syscall4(SYS_wait4, pid, (long)&status, 0, 0);
    } while (result == -EINTR);
    if (result != pid) return -1;
    if (exit_status) *exit_status = (status >> 8) & 0xff;
    return 0;
}

static int read_byte(int descriptor, char *byte) {
    long result;
    do {
        result = raw_syscall3(SYS_read, descriptor, (long)byte, 1);
    } while (result == -EINTR);
    return (int)result;
}

static int write_byte(int descriptor, char byte) {
    long result;
    do {
        result = raw_syscall3(SYS_write, descriptor, (long)&byte, 1);
    } while (result == -EINTR);
    return result == 1 ? 0 : -1;
}

static int test_child_process_group(void) {
    int descriptors[2];
    int child_status = 0;
    long parent_group = raw_syscall1(SYS_getpgid, 0);
    long child;
    char release;

    if (parent_group <= 0 || pipe_create(descriptors, 0) < 0) return 1;
    child = fork_process();
    if (child < 0) return 1;
    if (!child) {
        (void)raw_syscall1(SYS_close, descriptors[1]);
        child_exit(read_byte(descriptors[0], &release) == 1 ? 0 : 1);
    }
    (void)raw_syscall1(SYS_close, descriptors[0]);
    if (expect_ret("setpgid_child_new_group",
                   raw_syscall2(SYS_setpgid, child, child), 0) ||
        expect_ret("getpgid_child_new_group",
                   raw_syscall1(SYS_getpgid, child), child) ||
        expect_ret("setpgid_child_parent_group",
                   raw_syscall2(SYS_setpgid, child, parent_group), 0) ||
        expect_ret("getpgid_child_parent_group",
                   raw_syscall1(SYS_getpgid, child), parent_group)) {
        (void)raw_syscall2(SYS_kill, child, SIGKILL);
        (void)wait_child(child, 0);
        return 1;
    }
    if (write_byte(descriptors[1], 'x') < 0 ||
        wait_child(child, &child_status) < 0 || child_status)
        return 1;
    (void)raw_syscall1(SYS_close, descriptors[1]);
    return 0;
}

static int test_child_session(void) {
    int child_status = 0;
    long child = fork_process();
    if (child < 0) return 1;
    if (!child) {
        long pid = raw_syscall0(SYS_getpid);
        long sid = raw_syscall0(SYS_setsid);
        if (sid != pid || raw_syscall1(SYS_getsid, 0) != pid ||
            raw_syscall1(SYS_getpgid, 0) != pid ||
            raw_syscall0(SYS_setsid) != -EPERM)
            child_exit(1);
        child_exit(0);
    }
    if (wait_child(child, &child_status) < 0) return 1;
    if (child_status) {
        putstr("child_setsid_semantics: status=");
        putdec(child_status);
        putstr("\n");
        return 1;
    }
    return 0;
}

static int test_parent_rejects_other_session(void) {
    int ready_pipe[2];
    int release_pipe[2];
    int child_status = 0;
    long child;
    char byte;

    if (pipe_create(ready_pipe, 0) < 0 ||
        pipe_create(release_pipe, 0) < 0)
        return 1;
    child = fork_process();
    if (child < 0) return 1;
    if (!child) {
        long pid = raw_syscall0(SYS_getpid);
        (void)raw_syscall1(SYS_close, ready_pipe[0]);
        (void)raw_syscall1(SYS_close, release_pipe[1]);
        if (raw_syscall0(SYS_setsid) != pid ||
            write_byte(ready_pipe[1], 'r') < 0 ||
            read_byte(release_pipe[0], &byte) != 1)
            child_exit(1);
        child_exit(0);
    }
    (void)raw_syscall1(SYS_close, ready_pipe[1]);
    (void)raw_syscall1(SYS_close, release_pipe[0]);
    if (read_byte(ready_pipe[0], &byte) != 1 ||
        expect_ret("setpgid_child_other_session",
                   raw_syscall2(SYS_setpgid, child, child), -EPERM)) {
        (void)raw_syscall2(SYS_kill, child, SIGKILL);
        (void)wait_child(child, 0);
        return 1;
    }
    if (write_byte(release_pipe[1], 'x') < 0 ||
        wait_child(child, &child_status) < 0 || child_status)
        return 1;
    return 0;
}

static int test_execed_child(void) {
    static char path[] = "/probes/process_session_exec_helper";
    static char argument0[] = "process_session_exec_helper";
    static char environment0[] = "PATH=/usr/bin:/bin";
    static char *arguments[] = {argument0, 0};
    static char *environment[] = {environment0, 0};
    int descriptors[2];
    long child;
    char byte;
    int result;

    if (pipe_create(descriptors, O_CLOEXEC) < 0) return 1;
    child = fork_process();
    if (child < 0) return 1;
    if (!child) {
        (void)raw_syscall1(SYS_close, descriptors[0]);
        if (write_byte(descriptors[1], 'e') < 0) child_exit(1);
        (void)raw_syscall3(SYS_execve, (long)path, (long)arguments,
                           (long)environment);
        child_exit(2);
    }
    (void)raw_syscall1(SYS_close, descriptors[1]);
    if (read_byte(descriptors[0], &byte) != 1 ||
        read_byte(descriptors[0], &byte) != 0) {
        (void)raw_syscall2(SYS_kill, child, SIGKILL);
        (void)wait_child(child, 0);
        return 1;
    }
    result = expect_ret("setpgid_execed_child",
                        raw_syscall2(SYS_setpgid, child, child), -EACCES);
    (void)raw_syscall2(SYS_kill, child, SIGKILL);
    (void)wait_child(child, 0);
    return result;
}

static int run_probe(void) {
    int failures = 0;

    failures += expect_ret("setpgid_self",
                           raw_syscall2(SYS_setpgid, 0, 0), 0);
    failures += expect_ret("setpgid_negative_pid",
                           raw_syscall2(SYS_setpgid, -1, 0), -EINVAL);
    failures += expect_ret("setpgid_negative_group",
                           raw_syscall2(SYS_setpgid, 0, -1), -EINVAL);
    failures += expect_ret("setpgid_missing_process",
                           raw_syscall2(SYS_setpgid, 0x7fffffff, 0), -ESRCH);
    failures += expect_ret("getpgid_negative",
                           raw_syscall1(SYS_getpgid, -1), -ESRCH);
    failures += expect_ret("getsid_negative",
                           raw_syscall1(SYS_getsid, -1), -ESRCH);
    failures += test_child_process_group();
    failures += test_child_session();
    failures += test_parent_rejects_other_session();
    failures += test_execed_child();
    putstr("process_session_abi_probe: ");
    putstr(failures ? "FAIL\n" : "OK\n");
    return failures ? 1 : 0;
}

void _start(void) {
    int result = run_probe();
    child_exit(result);
}
