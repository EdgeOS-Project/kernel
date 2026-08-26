/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 *
 * Freestanding Linux exec policy probe. It validates pathname and flag error
 * ordering plus successful execve and execveat replacement on both supported
 * 64-bit architectures.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_clone 56
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_fcntl 72
#define SYS_getuid 102
#define SYS_getgid 104
#define SYS_geteuid 107
#define SYS_getegid 108
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_symlinkat 266
#define SYS_readlinkat 267
#define SYS_execveat 322
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#define SYS_symlinkat 36
#define SYS_openat 56
#define SYS_close 57
#define SYS_fcntl 25
#define SYS_write 64
#define SYS_exit 93
#define SYS_getuid 174
#define SYS_geteuid 175
#define SYS_getgid 176
#define SYS_getegid 177
#define SYS_clone 220
#define SYS_execve 221
#define SYS_wait4 260
#define SYS_readlinkat 78
#define SYS_execveat 281
#else
#error "exec_abi_probe requires a Linux 64-bit architecture"
#endif

#define EBADF 9
#define EFAULT 14
#define EINVAL 22
#define ENOENT 2
#define ENAMETOOLONG 36

#define AT_FDCWD (-100)
#define AT_EMPTY_PATH 0x1000
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0x10000
#define O_CLOEXEC 0x80000
#define F_GETFD 1
#define F_SETFD 2
#define FD_CLOEXEC 1
#define CLONE_FILES 0x00000400
#define SIGCHLD 17
#define MANY_ARGUMENT_COUNT 1024
#define AT_NULL 0
#define AT_UID 11
#define AT_EUID 12
#define AT_GID 13
#define AT_EGID 14
#define AT_SECURE 23

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

static long raw_syscall4(long number, long argument0, long argument1,
                         long argument2, long argument3) {
    return raw_syscall6(number, argument0, argument1, argument2,
                        argument3, 0, 0);
}

static long raw_syscall3(long number, long argument0, long argument1,
                         long argument2) {
    return raw_syscall6(number, argument0, argument1, argument2, 0, 0, 0);
}

static long raw_syscall1(long number, long argument0) {
    return raw_syscall6(number, argument0, 0, 0, 0, 0, 0);
}

static int append_decimal(char *buffer, unsigned long capacity,
                          unsigned long *length, unsigned long value) {
    char digits[24];
    unsigned long count = 0;
    if (!buffer || !length) return -1;
    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count) {
        if (*length + 1u >= capacity) return -1;
        buffer[(*length)++] = digits[--count];
    }
    buffer[*length] = 0;
    return 0;
}

static int text_equal(const char *left, const char *right) {
    unsigned long index = 0;
    if (!left || !right) return 0;
    while (left[index] && left[index] == right[index]) ++index;
    return left[index] == right[index];
}

static int parse_decimal(const char *text, long *value) {
    unsigned long parsed = 0;
    unsigned long index = 0;
    if (!text || !text[0] || !value) return -1;
    while (text[index]) {
        if (text[index] < '0' || text[index] > '9') return -1;
        parsed = parsed * 10u + (unsigned long)(text[index] - '0');
        ++index;
    }
    *value = (long)parsed;
    return 0;
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

static int wait_for_success(const char *name, long child) {
    int status = -1;
    long waited;
    if (child < 0) return expect_result(name, child, 0);
    waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    if (waited != child) return expect_result(name, waited, child);
    return expect_result(name, status, 0);
}

static long initial_auxv_value(uintptr_t *initial_stack,
                               uintptr_t requested_type, int *found) {
    uintptr_t *cursor;
    uintptr_t argc;

    if (found) *found = 0;
    if (!initial_stack) return 0;
    argc = initial_stack[0];
    if (argc > 4096u) return 0;
    cursor = initial_stack + argc + 2u;
    for (uint32_t index = 0; index < 4096u && *cursor; ++index)
        ++cursor;
    if (*cursor) return 0;
    ++cursor;
    for (uint32_t index = 0; index < 256u; ++index, cursor += 2u) {
        if (cursor[0] == AT_NULL) return 0;
        if (cursor[0] != requested_type) continue;
        if (found) *found = 1;
        return (long)cursor[1];
    }
    return 0;
}

static int test_initial_auxv(uintptr_t *initial_stack) {
    long uid = raw_syscall1(SYS_getuid, 0);
    long euid = raw_syscall1(SYS_geteuid, 0);
    long gid = raw_syscall1(SYS_getgid, 0);
    long egid = raw_syscall1(SYS_getegid, 0);
    long expected_secure = uid != euid || gid != egid;
    int found;
    int failures = 0;
    long value;

#define CHECK_AUXV(name, type, expected) \
    do { \
        value = initial_auxv_value(initial_stack, type, &found); \
        failures += expect_result(name "_present", found, 1); \
        if (found) failures += expect_result(name, value, expected); \
    } while (0)
    CHECK_AUXV("auxv_uid", AT_UID, uid);
    CHECK_AUXV("auxv_euid", AT_EUID, euid);
    CHECK_AUXV("auxv_gid", AT_GID, gid);
    CHECK_AUXV("auxv_egid", AT_EGID, egid);
    CHECK_AUXV("auxv_secure", AT_SECURE, expected_secure);
#undef CHECK_AUXV
    return failures;
}

static int test_execve_success(void) {
    char *arguments[] = {(char *)"true", 0};
    char *environment[] = {(char *)"PATH=/bin:/usr/bin", 0};
    long child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (!child) {
        (void)raw_syscall3(SYS_execve, (long)"/bin/true",
                           (long)arguments, (long)environment);
        exit_now(111);
    }
    return wait_for_success("execve_success", child);
}

static int test_execve_many_arguments(void) {
    static char *arguments[MANY_ARGUMENT_COUNT + 1];
    char *environment[] = {(char *)"PATH=/bin:/usr/bin", 0};
    long child;

    arguments[0] = (char *)"true";
    for (uint32_t index = 1; index < MANY_ARGUMENT_COUNT; ++index)
        arguments[index] = (char *)"argument";
    arguments[MANY_ARGUMENT_COUNT] = 0;

    child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (!child) {
        (void)raw_syscall3(SYS_execve, (long)"/bin/true",
                           (long)arguments, (long)environment);
        exit_now(111);
    }
    return wait_for_success("execve_many_arguments", child);
}

static int test_exec_unshares_files(void) {
    static char descriptor_text[24];
    static char executable_path[256];
    char *arguments[] = {
        (char *)"exec_abi_probe",
        (char *)"--cloexec-child",
        descriptor_text,
        executable_path,
        0
    };
    char *environment[] = {(char *)"PATH=/bin:/usr/bin", 0};
    unsigned long descriptor_text_length = 0;
    long descriptor;
    long stdin_flags;
    long descriptor_flags;
    long child;
    int failures = 0;

    {
        long length = raw_syscall4(
            SYS_readlinkat, AT_FDCWD, (long)"/proc/self/exe",
            (long)executable_path, sizeof(executable_path) - 1u);
        if (length <= 0 || length >= (long)sizeof(executable_path))
            return expect_result("exec_identity_parent", length, 1);
        executable_path[length] = 0;
    }

    descriptor = raw_syscall4(
        SYS_openat, AT_FDCWD, (long)"/dev/null",
        O_WRONLY | O_CLOEXEC, 0);
    if (descriptor < 0)
        return expect_result(
            "exec_files_open_cloexec", descriptor, 0);

    stdin_flags = raw_syscall3(SYS_fcntl, 0, F_GETFD, 0);
    if (stdin_flags >= 0) {
        failures += expect_result(
            "exec_files_mark_stdin_cloexec",
            raw_syscall3(
                SYS_fcntl, 0, F_SETFD,
                stdin_flags | FD_CLOEXEC),
            0);
    }

    if (append_decimal(
            descriptor_text, sizeof(descriptor_text),
            &descriptor_text_length,
            (unsigned long)descriptor) < 0) {
        failures += expect_result(
            "exec_files_descriptor_format", -1, 0);
        goto out;
    }

    child = raw_syscall5(
        SYS_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if (!child) {
        (void)raw_syscall3(
            SYS_execve, (long)"/proc/self/exe",
            (long)arguments, (long)environment);
        exit_now(111);
    }
    failures += wait_for_success("exec_files_child_cloexec", child);

    descriptor_flags =
        raw_syscall3(SYS_fcntl, descriptor, F_GETFD, 0);
    failures += expect_result(
        "exec_files_parent_descriptor",
        descriptor_flags, FD_CLOEXEC);
    if (stdin_flags >= 0) {
        failures += expect_result(
            "exec_files_parent_stdin",
            raw_syscall3(SYS_fcntl, 0, F_GETFD, 0),
            stdin_flags | FD_CLOEXEC);
    }

out:
    if (stdin_flags >= 0)
        failures += expect_result(
            "exec_files_restore_stdin",
            raw_syscall3(SYS_fcntl, 0, F_SETFD, stdin_flags),
            0);
    failures += expect_result(
        "exec_files_close_parent",
        raw_syscall1(SYS_close, descriptor), 0);
    return failures;
}

static int run_cloexec_child(const char *descriptor_text,
                             const char *expected_executable_path) {
    char executable_path[256];
    long descriptor;
    long length;

    if (parse_decimal(descriptor_text, &descriptor) < 0)
        return 92;
    if (raw_syscall3(SYS_fcntl, 0, F_GETFD, 0) != -EBADF)
        return 90;
    if (raw_syscall3(SYS_fcntl, descriptor, F_GETFD, 0) != -EBADF)
        return 91;
    length = raw_syscall4(
        SYS_readlinkat, AT_FDCWD, (long)"/proc/self/exe",
        (long)executable_path, sizeof(executable_path) - 1u);
    if (length <= 0 || length >= (long)sizeof(executable_path))
        return 93;
    executable_path[length] = 0;
    if (!text_equal(executable_path, expected_executable_path))
        return 94;
    return 0;
}

static int run_cloexec_probe(void) {
    int failures = test_exec_unshares_files();
    putstr(failures ?
        "EXEC_CLOEXEC_UNSHARE_PROBE_FAIL failures: " :
        "EXEC_CLOEXEC_UNSHARE_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static int test_shebang_symlink_path(void) {
    static const char target[] = "/tmp/edgeos-exec-script";
    static const char alias[] = "/tmp/edgeos-exec-script-alias";
    static const char script[] = "#!/probes/exec_script_helper\n";
    char *arguments[] = {(char *)"ignored-argv0", 0};
    char *environment[] = {(char *)"PATH=/bin:/usr/bin", 0};
    long descriptor;
    long child;
    int failures = 0;

    (void)raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)alias, 0);
    (void)raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)target, 0);
    descriptor = raw_syscall4(
        SYS_openat, AT_FDCWD, (long)target,
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (descriptor < 0)
        return expect_result("shebang_create", descriptor, 0);
    failures += expect_result(
        "shebang_write",
        raw_syscall3(SYS_write, descriptor, (long)script,
                     (long)(sizeof(script) - 1u)),
        (long)(sizeof(script) - 1u));
    failures += expect_result(
        "shebang_close", raw_syscall1(SYS_close, descriptor), 0);
    failures += expect_result(
        "shebang_symlink",
        raw_syscall3(SYS_symlinkat, (long)target, AT_FDCWD, (long)alias), 0);
    if (!failures) {
        child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
        if (!child) {
            (void)raw_syscall3(SYS_execve, (long)alias,
                               (long)arguments, (long)environment);
            exit_now(111);
        }
        failures += wait_for_success("shebang_symlink_path", child);
    }
    (void)raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)alias, 0);
    (void)raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)target, 0);
    return failures;
}

static int test_execveat_success(int empty_path) {
    const char *opened_path = empty_path ? "/bin/true" : "/bin";
    const char *exec_path = empty_path ? "" : "true";
    int open_flags = O_RDONLY | O_CLOEXEC;
    char *arguments[] = {(char *)"true", 0};
    char *environment[] = {(char *)"PATH=/bin:/usr/bin", 0};
    long descriptor;
    long child;
    int failures;

    if (!empty_path) open_flags |= O_DIRECTORY;
    descriptor = raw_syscall4(
        SYS_openat, AT_FDCWD, (long)opened_path, open_flags, 0);
    if (descriptor < 0)
        return expect_result(empty_path ? "open_exec" : "open_bin",
                             descriptor, 0);
    child = raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (!child) {
        (void)raw_syscall5(
            SYS_execveat, descriptor, (long)exec_path, (long)arguments,
            (long)environment, empty_path ? AT_EMPTY_PATH : 0);
        exit_now(111);
    }
    failures = wait_for_success(
        empty_path ? "execveat_empty_success" :
                     "execveat_relative_success",
        child);
    (void)raw_syscall1(SYS_close, descriptor);
    return failures;
}

static int run_probe(uintptr_t *initial_stack) {
    static char long_path[4096];
    int failures = test_initial_auxv(initial_stack);

    for (uint32_t index = 0; index < sizeof(long_path); ++index)
        long_path[index] = 'x';
    failures += expect_result("execve_null",
        raw_syscall3(SYS_execve, 0, 0, 0), -EFAULT);
    failures += expect_result("execve_long_path",
        raw_syscall3(SYS_execve, (long)long_path, 0, 0),
        -ENAMETOOLONG);
    failures += expect_result("execveat_null",
        raw_syscall5(SYS_execveat, AT_FDCWD, 0, 0, 0, 0), -EFAULT);
    failures += expect_result("execveat_null_bad_flags",
        raw_syscall5(SYS_execveat, AT_FDCWD, 0, 0, 0,
                     0x80000000u), -EINVAL);
    failures += expect_result("execveat_empty_without_flag",
        raw_syscall5(SYS_execveat, -1, (long)"", 0, 0, 0), -ENOENT);
    failures += expect_result("execveat_empty_bad_descriptor",
        raw_syscall5(SYS_execveat, -1, (long)"", 0, 0,
                     AT_EMPTY_PATH), -EBADF);
    failures += expect_result("execveat_bad_flags_before_descriptor",
        raw_syscall5(SYS_execveat, -1, (long)"missing", 0, 0,
                     0x80000000u), -EINVAL);
    failures += expect_result("execveat_relative_bad_descriptor",
        raw_syscall5(SYS_execveat, -1, (long)"missing", 0, 0, 0),
        -EBADF);
    failures += expect_result("execveat_absolute_ignores_descriptor",
        raw_syscall5(SYS_execveat, -1, (long)"/edgeos-missing-exec",
                     0, 0, 0), -ENOENT);
    failures += expect_result("execveat_high_flag_bits_ignored",
        raw_syscall5(SYS_execveat, -1, (long)"missing", 0, 0,
                     (long)1 << 32), -EBADF);
    failures += test_execve_success();
    failures += test_execve_many_arguments();
    failures += test_exec_unshares_files();
    failures += test_shebang_symlink_path();
    failures += test_execveat_success(0);
    failures += test_execveat_success(1);

    putstr(failures ? "EXEC_ABI_PROBE_FAIL failures: " :
                      "EXEC_ABI_PROBE_PASS failures: ");
    putdec(failures);
    putstr("\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used))
void probe_entry(uintptr_t *initial_stack) {
    long argc = initial_stack ? (long)initial_stack[0] : 0;
    char **arguments = initial_stack ?
        (char **)&initial_stack[1] : (char **)0;

    if (argc >= 4 && arguments &&
        text_equal(arguments[1], "--cloexec-child"))
        exit_now(run_cloexec_child(arguments[2], arguments[3]));
    if (argc >= 2 && arguments &&
        text_equal(arguments[1], "--cloexec-only"))
        exit_now(run_cloexec_probe());
    exit_now(run_probe(initial_stack));
}

#if defined(__x86_64__)
__asm__(
    ".global _start\n"
    ".type _start, @function\n"
    "_start:\n"
    "movq %rsp, %rdi\n"
    "andq $-16, %rsp\n"
    "call probe_entry\n");
#else
__asm__(
    ".global _start\n"
    ".type _start, %function\n"
    "_start:\n"
    "mov x0, sp\n"
    "bl probe_entry\n");
#endif
