/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux PI futex ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_futex 202
#define SYS_gettid 186
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_futex 98
#define SYS_gettid 178
#define SYS_exit 93
#else
#error "futex_pi_abi_probe requires a Linux 64-bit architecture"
#endif

#define EAGAIN 11
#define EDEADLK 35
#define EPERM 1
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_TID_MASK 0x3fffffffU

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

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int run_tests(void) {
    volatile uint32_t word = 0;
    long tid = raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    int failures = 0;

    failures += expect("lock",
        raw_syscall6(SYS_futex, (long)&word,
                     FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG,
                     0, 0, 0, 0), 0);
    failures += expect("owner tid", word & FUTEX_TID_MASK, tid);
    failures += expect("recursive deadlock",
        raw_syscall6(SYS_futex, (long)&word,
                     FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG,
                     0, 0, 0, 0), -EDEADLK);
    failures += expect("unlock",
        raw_syscall6(SYS_futex, (long)&word,
                     FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG,
                     0, 0, 0, 0), 0);
    failures += expect("unlock clears owner", word, 0);
    failures += expect("unowned unlock",
        raw_syscall6(SYS_futex, (long)&word,
                     FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG,
                     0, 0, 0, 0), -EPERM);
    failures += expect("trylock",
        raw_syscall6(SYS_futex, (long)&word,
                     FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG,
                     0, 0, 0, 0), 0);
    failures += expect("trylock recursive",
        raw_syscall6(SYS_futex, (long)&word,
                     FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG,
                     0, 0, 0, 0), -EDEADLK);
    failures += expect("final unlock",
        raw_syscall6(SYS_futex, (long)&word,
                     FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG,
                     0, 0, 0, 0), 0);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    print_text(failures ? "futex-pi-abi: FAIL\n" :
                          "futex-pi-abi: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
