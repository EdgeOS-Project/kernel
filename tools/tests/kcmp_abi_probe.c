/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux kcmp ABI regression probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define ENTRY_ALIGNMENT __attribute__((force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_dup 32
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_openat 257
#define SYS_kcmp 312
#elif defined(__aarch64__)
#define ENTRY_ALIGNMENT
#define SYS_dup 23
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_kcmp 272
#else
#error "kcmp_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define KCMP_FILE 0
#define KCMP_VM 1
#define KCMP_FILES 2
#define KCMP_FS 3
#define KCMP_SIGHAND 4
#define EBADF 9
#define EINVAL 22

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

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static long compare(long first, long second, unsigned int type,
                    unsigned long first_index,
                    unsigned long second_index) {
    return raw_syscall6(SYS_kcmp, first, second, type,
                        (long)first_index, (long)second_index, 0);
}

static int run_tests(void) {
    static const char null_path[] = "/dev/null";
    long self = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    long descriptor = raw_syscall6(SYS_openat, AT_FDCWD, (long)null_path,
                                   O_RDONLY, 0, 0, 0);
    long duplicate;
    int failures = 0;

    if (descriptor < 0) return 1;
    duplicate = raw_syscall6(SYS_dup, descriptor, 0, 0, 0, 0, 0);
    if (duplicate < 0) return 1;
    failures += compare(self, self, KCMP_FILE, descriptor, duplicate) != 0;
    failures += compare(self, self, KCMP_VM, 0, 0) != 0;
    failures += compare(self, self, KCMP_FILES, 0, 0) != 0;
    failures += compare(self, self, KCMP_FS, 0, 0) != 0;
    failures += compare(self, self, KCMP_SIGHAND, 0, 0) != 0;
    failures += compare(self, self, KCMP_FILE, (unsigned long)-1,
                        descriptor) != -EBADF;
    failures += compare(self, self, UINT32_MAX, 0, 0) != -EINVAL;
    (void)raw_syscall6(SYS_close, duplicate, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

__attribute__((noreturn)) ENTRY_ALIGNMENT void _start(void) {
    int failures = run_tests();
    print_text(failures ? "KCMP_ABI_PROBE_FAIL\n" :
                          "KCMP_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
