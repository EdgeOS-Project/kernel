/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise private mappings while independent processes clone and exit. */

#if !defined(__aarch64__)
#error "This probe targets AArch64"
#endif

#define SYS_write 64
#define SYS_exit 93
#define SYS_sched_yield 124
#define SYS_munmap 215
#define SYS_clone 220
#define SYS_mmap 222
#define SYS_wait4 260
#define SIGCHLD 17
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 32
#define PAGE_SIZE 4096
#define WORKERS 4
#define ROUNDS 64

static long call(long number, long a0, long a1, long a2,
                 long a3, long a4, long a5) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}

static void say(const char *message) {
    unsigned long length = 0;
    while (message[length]) ++length;
    (void)call(SYS_write, 1, (long)message, length, 0, 0, 0);
}

static __attribute__((noreturn)) void leave(int status) {
    (void)call(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) {}
}

static long map_page(void) {
    return call(SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static int worker(int id) {
    long base = map_page();
    if (base < 0) return 1;
    volatile unsigned char *shared = (volatile unsigned char *)base;
    shared[0] = (unsigned char)(id + 1);
    for (int round = 0; round < ROUNDS; ++round) {
        int status = -1;
        long child = call(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (child < 0) return 2;
        if (child == 0) {
            long page = map_page();
            if (page < 0) leave(3);
            volatile unsigned char *private_page = (volatile unsigned char *)page;
            private_page[0] = (unsigned char)round;
            private_page[PAGE_SIZE - 1] = (unsigned char)(round + 1);
            shared[0] = (unsigned char)(round + 10);
            if (call(SYS_munmap, page, PAGE_SIZE, 0, 0, 0, 0) != 0) leave(4);
            leave(0);
        }
        if (call(SYS_wait4, child, (long)&status, 0, 0, 0, 0) != child ||
            status != 0 || shared[0] != (unsigned char)(id + 1)) return 5;
        (void)call(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    if (call(SYS_munmap, base, PAGE_SIZE, 0, 0, 0, 0) != 0) return 6;
    return 0;
}

void _start(void) {
    long children[WORKERS];
    int launched = 0;
    int failed = 0;
    say("LIFETIME_START\n");
    for (int index = 0; index < WORKERS; ++index) {
        long child = call(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
        if (child < 0) {
            failed = 1;
            break;
        }
        if (child == 0) leave(worker(index));
        children[launched++] = child;
    }
    for (int index = 0; index < launched; ++index) {
        int status = -1;
        if (call(SYS_wait4, children[index], (long)&status, 0, 0, 0, 0) !=
                children[index] || status != 0) failed = 1;
    }
    say(failed ? "LIFETIME_FAIL\n" : "LIFETIME_PASS\n");
    for (;;) (void)call(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
}
