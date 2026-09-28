/* SPDX-License-Identifier: MPL-2.0 */
/* Keep a fork-shared working set alive for procfs PSS acceptance tests. */

#include <stdint.h>

#if defined(__x86_64__)
#define EDGE_ENTRY_ALIGN __attribute__((force_align_arg_pointer))
#define SYS_write 1
#define SYS_mmap 9
#define SYS_mlock 149
#define SYS_nanosleep 35
#define SYS_getpid 39
#define SYS_fork 57
#define SYS_exit 60
#define SYS_getppid 110
#elif defined(__aarch64__)
#define EDGE_ENTRY_ALIGN
#define SYS_write 64
#define SYS_exit 93
#define SYS_nanosleep 101
#define SYS_getpid 172
#define SYS_getppid 173
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_mlock 228
#else
#error "pss_share_probe requires a Linux 64-bit architecture"
#endif

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define SIGCHLD 17
#define PAGE_SIZE 4096u
#define WORKING_SET_SIZE (32u * 1024u * 1024u)

typedef struct edge_timespec {
    int64_t seconds;
    int64_t nanoseconds;
} edge_timespec_t;

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

static long create_child(void) {
#if defined(__x86_64__)
    return raw_syscall6(SYS_fork, 0, 0, 0, 0, 0, 0);
#else
    return raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
#endif
}

static void pause_briefly(void) {
    const edge_timespec_t duration = {0, 10000000};
    (void)raw_syscall6(SYS_nanosleep, (long)&duration, 0, 0, 0, 0, 0);
}

EDGE_ENTRY_ALIGN __attribute__((noreturn)) void _start(void) {
    volatile uint8_t *mapping;
    long parent;
    long child;
    long address = raw_syscall6(
        SYS_mmap, 0, WORKING_SET_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (address < 0)
        raw_syscall6(SYS_exit, 2, 0, 0, 0, 0, 0);
    mapping = (volatile uint8_t *)(uintptr_t)address;
    for (uint64_t offset = 0; offset < WORKING_SET_SIZE; offset += PAGE_SIZE)
        mapping[offset] = (uint8_t)(offset / PAGE_SIZE);
    parent = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    child = create_child();
    if (child < 0)
        raw_syscall6(SYS_exit, 3, 0, 0, 0, 0, 0);
    if (child == 0) {
        long owner = parent;
        for (;;) {
            long current = raw_syscall6(SYS_getppid, 0, 0, 0, 0, 0, 0);
            if (current != owner) break;
            pause_briefly();
        }
        raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    }
    if (raw_syscall6(SYS_mlock, address, PAGE_SIZE, 0, 0, 0, 0) < 0)
        raw_syscall6(SYS_exit, 4, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_write, 1, (long)"READY\n", 6, 0, 0, 0);
    for (;;) pause_briefly();
}
