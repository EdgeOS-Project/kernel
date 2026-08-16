/* SPDX-License-Identifier: MPL-2.0 */
/* Linux process_mrelease ABI probe for native and EdgeOS guest parity. */

#include <stdint.h>

#if defined(__x86_64__)
#define EDGE_ENTRY_ALIGN __attribute__((force_align_arg_pointer))
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define EDGE_ENTRY_ALIGN
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_kill 129
#define SYS_getpid 172
#define SYS_munmap 215
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_wait4 260
#else
#error "process_mrelease_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_pidfd_open 434
#define SYS_process_mrelease 448

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define SIGKILL 9
#define SIGCHLD 17
#define EBADF 9
#define EINVAL 22
#define EAGAIN 11
#define ESRCH 3
#define PAGE_SIZE 4096u
#define MAX_ALLOCATION (64u * 1024u * 1024u)

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a0), "S"(a1), "d"(a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#endif
}

static uint64_t text_length(const char *text) {
    uint64_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_unsigned(uint32_t value) {
    char digits[10];
    uint32_t count = 0;

    do {
        digits[count++] = (char)('0' + (value % 10u));
        value /= 10u;
    } while (value && count < sizeof(digits));
    while (count)
        (void)raw_syscall6(SYS_write, 1, (long)&digits[--count], 1,
                           0, 0, 0);
}

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static int child_main(int write_descriptor, uint64_t allocation) {
    volatile uint8_t *mapping;
    char ready = 'R';
    long address = raw_syscall6(
        SYS_mmap, 0, (long)allocation, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (address < 0) return 20;
    mapping = (volatile uint8_t *)(uintptr_t)address;
    for (uint64_t offset = 0; offset < allocation; offset += PAGE_SIZE)
        mapping[offset] = (uint8_t)(offset / PAGE_SIZE);
    if (raw_syscall6(
            SYS_write, write_descriptor, (long)&ready, 1, 0, 0, 0) != 1)
        return 21;
    for (;;) __asm__ volatile("" ::: "memory");
}

static int run_attempt(uint64_t allocation, int run_negative_tests) {
    int descriptors[2] = {-1, -1};
    int status = 0;
    char ready = 0;
    long child;
    long pidfd;
    long result;

    if (raw_syscall6(
            SYS_pipe2, (long)descriptors, 0, 0, 0, 0, 0) != 0)
        return 30;
    child = create_child();
    if (child < 0) return 31;
    if (child == 0) {
        int child_result;
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
        child_result = child_main(descriptors[1], allocation);
        raw_syscall6(SYS_exit, child_result, 0, 0, 0, 0, 0);
        for (;;) {}
    }

    (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    if (raw_syscall6(
            SYS_read, descriptors[0], (long)&ready, 1, 0, 0, 0) != 1 ||
        ready != 'R')
        return 32;
    (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    pidfd = raw_syscall6(SYS_pidfd_open, child, 0, 0, 0, 0, 0);
    if (pidfd < 0) return 33;

    if (run_negative_tests) {
        if (raw_syscall6(
                SYS_process_mrelease, -1, 0, 0, 0, 0, 0) != -EBADF)
            return 34;
        if (raw_syscall6(
                SYS_process_mrelease, pidfd, 1, 0, 0, 0, 0) != -EINVAL)
            return 35;
        if (raw_syscall6(
                SYS_process_mrelease, pidfd, 0, 0, 0, 0, 0) != -EINVAL)
            return 36;
    }

    if (raw_syscall6(SYS_kill, child, SIGKILL, 0, 0, 0, 0) != 0)
        return 37;
    result = raw_syscall6(
        SYS_process_mrelease, pidfd, 0, 0, 0, 0, 0);
    for (uint32_t retry = 0; result == -EAGAIN && retry < 8u; ++retry)
        result = raw_syscall6(
            SYS_process_mrelease, pidfd, 0, 0, 0, 0, 0);
    if (raw_syscall6(
            SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child)
        return 38;
    (void)raw_syscall6(SYS_close, pidfd, 0, 0, 0, 0, 0);
    if (result == 0) return 0;
    if (result == -ESRCH) return 1;
    return 39;
}

static int run_probe(void) {
    uint64_t allocation = 1u * 1024u * 1024u;
    int first = 1;

    while (allocation <= MAX_ALLOCATION) {
        int result = run_attempt(allocation, first);
        first = 0;
        if (result == 0) return 0;
        if (result != 1) return result;
        allocation *= 2u;
    }
    return 40;
}

EDGE_ENTRY_ALIGN __attribute__((noreturn)) void _start(void) {
    int result = run_probe();
    if (!result)
        print_text("PROCESS_MRELEASE_ABI_PROBE_PASS\n");
    else {
        print_text("PROCESS_MRELEASE_ABI_PROBE_FAIL stage=");
        print_unsigned((uint32_t)result);
        print_text("\n");
    }
    raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
    for (;;) {}
}
