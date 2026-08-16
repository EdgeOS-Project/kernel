/* SPDX-License-Identifier: MPL-2.0 */
/* Trigger a cgroup v2 group OOM from an unreclaimable anonymous mapping. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_mlock 149
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_openat 257
#define SYS_close 3
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_mmap 222
#define SYS_mlock 228
#define SYS_getpid 172
#define SYS_exit 93
#define SYS_openat 56
#define SYS_close 57
#else
#error "memory_oom_group_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD -100
#define O_WRONLY 1
#define O_CLOEXEC 02000000
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PAGE_SIZE 4096u
#define MAPPING_BYTES (8u * 1024u * 1024u)

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

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static int join_test_group(void) {
    static const char path[] =
        "/sys/fs/cgroup/edgeos-oom-group-test/cgroup.procs";
    char pid_text[24];
    unsigned long pid = (unsigned long)raw_syscall6(
        SYS_getpid, 0, 0, 0, 0, 0, 0);
    unsigned long position = sizeof(pid_text) - 2u;
    long fd;
    long written;

    pid_text[sizeof(pid_text) - 1u] = 0;
    pid_text[sizeof(pid_text) - 2u] = '\n';
    do {
        pid_text[--position] = (char)('0' + pid % 10u);
        pid /= 10u;
    } while (pid);
    fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                      O_WRONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return -1;
    written = raw_syscall6(
        SYS_write, fd, (long)&pid_text[position],
        (long)(sizeof(pid_text) - 1u - position), 0, 0, 0);
    (void)raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    return written == (long)(sizeof(pid_text) - 1u - position) ? 0 : -1;
}

void _start(void) {
    long mapping;

    if (join_test_group() < 0) {
        print_text("MEMORY_OOM_GROUP_ABI_FAIL join\n");
        raw_syscall6(SYS_exit, 2, 0, 0, 0, 0, 0);
    }
    mapping = raw_syscall6(
        SYS_mmap, 0, MAPPING_BYTES, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping <= 0) {
        print_text("MEMORY_OOM_GROUP_ABI_FAIL mapping\n");
        raw_syscall6(SYS_exit, 3, 0, 0, 0, 0, 0);
    }
    (void)raw_syscall6(SYS_mlock, mapping, MAPPING_BYTES, 0, 0, 0, 0);
    for (uint32_t offset = 0; offset < MAPPING_BYTES; offset += PAGE_SIZE)
        *(volatile uint8_t *)(uintptr_t)(mapping + offset) =
            (uint8_t)(offset >> 12);
    print_text("MEMORY_OOM_GROUP_ABI_FAIL survived\n");
    raw_syscall6(SYS_exit, 4, 0, 0, 0, 0, 0);
    for (;;) { }
}
