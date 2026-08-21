/* SPDX-License-Identifier: MPL-2.0 */
/* Initramfs runner for a batch of standalone Linux UAPI probes. */

#include <stdint.h>

#if defined(__x86_64__)
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#define SYS_write 1
#define SYS_fork 57
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#elif defined(__aarch64__)
#define ENTRY_ALIGNMENT
#define SYS_write 64
#define SYS_exit 93
#define SYS_wait4 260
#define SYS_execve 221
#define SYS_clone 220
#else
#error "uapi_batch_init requires a supported 64-bit architecture"
#endif

#define SIGCHLD 17

void *memcpy(void *destination, const void *source, unsigned long length) {
    unsigned char *output = destination;
    const unsigned char *input = source;

    for (unsigned long index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

static long raw_syscall1(long number, long a0) {
#if defined(__x86_64__)
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
#endif
}

static long raw_syscall3(long number, long a0, long a1, long a2) {
#if defined(__x86_64__)
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2)
                     : "memory", "cc");
    return x0;
#endif
}

static long raw_syscall4(long number, long a0, long a1, long a2, long a3) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall3(SYS_write, 1, (long)text,
                       (long)text_length(text));
}

static long spawn(void) {
#if defined(__x86_64__)
    return raw_syscall1(SYS_fork, 0);
#else
    return raw_syscall4(SYS_clone, SIGCHLD, 0, 0, 0);
#endif
}

static int run_probe(const char *name) {
    char path[96] = "/probes/";
    char *arguments[2];
    char *environment[1] = {0};
    unsigned long offset = text_length(path);
    long child;
    int status = -1;

    for (unsigned long index = 0; name[index] && offset + 1 < sizeof(path);
         ++index)
        path[offset++] = name[index];
    path[offset] = 0;
    child = spawn();
    if (child < 0) return 1;
    if (child == 0) {
        arguments[0] = path;
        arguments[1] = 0;
        (void)raw_syscall3(
            SYS_execve, (long)path, (long)arguments, (long)environment);
        (void)raw_syscall1(SYS_exit, 127);
        for (;;) { }
    }
    if (raw_syscall4(SYS_wait4, child, (long)&status, 0, 0) != child)
        return 1;
    return status != 0;
}

__attribute__((noreturn)) ENTRY_ALIGNMENT void _start(void) {
    static const char *const probes[] = {
#ifndef UAPI_BATCH_FREESTANDING_ONLY
        "restart_syscall_abi_probe",
#endif
        "futex_abi_probe",
        "futex_pi_abi_probe",
#ifndef UAPI_BATCH_FREESTANDING_ONLY
        "futex_pi_requeue_abi_probe",
#endif
        "sysv_sem_abi_probe",
        "sysv_msg_abi_probe",
        "posix_mq_abi_probe",
        "fanotify_abi_probe",
        "userfaultfd_abi_probe",
        "keyring_abi_probe",
        "quota_abi_probe",
        "perf_event_abi_probe",
        "bpf_abi_probe",
        "seccomp_abi_probe",
        "memfd_secret_abi_probe",
#ifndef UAPI_BATCH_FREESTANDING_ONLY
        "clock_adjust_abi_probe",
        "module_abi_probe",
        "vhangup_abi_probe",
#endif
    };
    int failures = 0;

    for (unsigned long index = 0;
         index < sizeof(probes) / sizeof(probes[0]); ++index) {
        int failed;
        print_text("UAPI_BATCH_BEGIN ");
        print_text(probes[index]);
        print_text("\n");
        failed = run_probe(probes[index]);
        failures += failed;
        print_text(failed ? "UAPI_BATCH_FAIL " : "UAPI_BATCH_PASS ");
        print_text(probes[index]);
        print_text("\n");
    }
    print_text(failures ? "UAPI_BATCH_RESULT_FAIL\n" :
                          "UAPI_BATCH_RESULT_PASS\n");
    (void)raw_syscall1(SYS_exit, failures ? 1 : 0);
    for (;;) { }
}
