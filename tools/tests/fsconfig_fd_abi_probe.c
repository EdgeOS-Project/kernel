/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux ABI probe; creates contexts but never mounts them. */
#if defined(__x86_64__)
#define NR_WRITE 1
#define NR_CLOSE 3
#define NR_FCNTL 72
#define NR_OPENAT 257
#define NR_EXIT 60
static long call(long nr, long a, long b, long c, long d, long e) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory");
    return result;
}
#elif defined(__aarch64__)
#define NR_WRITE 64
#define NR_CLOSE 57
#define NR_FCNTL 25
#define NR_OPENAT 56
#define NR_EXIT 93
static long call(long nr, long a, long b, long c, long d, long e) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    __asm__ volatile("svc #0" : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory");
    return x0;
}
#else
#error Unsupported architecture
#endif

static int failures;
static void print(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    (void)call(NR_WRITE, 1, (long)text, (long)length, 0, 0);
}
static void number(long value) {
    char text[24];
    unsigned int count = 0;
    if (value < 0) { print("-"); value = -value; }
    do { text[count++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (count) (void)call(NR_WRITE, 1, (long)&text[--count], 1, 0, 0);
}
static void expect(const char *label, long result, long wanted) {
    print(result == wanted ? "PASS " : "FAIL "); print(label);
    print(" result="); number(result); print(" expected="); number(wanted); print("\n");
    if (result != wanted) ++failures;
}
static long set_fd(long context, const char *key, long fd) {
    return call(431, context, 5, (long)key, 0, fd);
}
static void filesystem(const char *type, long pathfd) {
    static const char unknown[] = "adefinitelynotexistingmountoption";
    long fd = call(430, (long)type, 1, 0, 0, 0);
    print("filesystem="); print(type); print("\n");
    if (fd < 0) { expect("fsopen", fd, 0); return; }
    expect("context FD unknown key", set_fd(fd, unknown, fd), -22);
    expect("O_PATH FD unknown key", set_fd(fd, unknown, pathfd), -22);
    expect("negative auxiliary FD", set_fd(fd, unknown, -1), -22);
    long duplicate = call(NR_FCNTL, pathfd, 1030, 0, 0, 0);
    if (duplicate < 0) expect("duplicate O_PATH", duplicate, 0);
    else {
        expect("duplicate O_PATH unknown key", set_fd(fd, unknown, duplicate), -22);
        (void)call(NR_CLOSE, duplicate, 0, 0, 0, 0);
        expect("closed auxiliary FD", set_fd(fd, unknown, duplicate), -9);
    }
    expect("file-typed source rejected", set_fd(fd, "source", pathfd), -22);
    (void)call(NR_CLOSE, fd, 0, 0, 0, 0);
}
static void overlay_option(const char *key, long pathfd) {
    long fd = call(430, (long)"overlay", 1, 0, 0, 0);
    if (fd < 0) { expect("overlay fsopen", fd, 0); return; }
    expect(key, set_fd(fd, key, pathfd), 0);
    (void)call(NR_CLOSE, fd, 0, 0, 0, 0);
}
void probe_main(void) {
    long pathfd = call(NR_OPENAT, -100, (long)"/tmp", 0x280000, 0, 0);
    if (pathfd < 0) expect("open /tmp O_PATH", pathfd, 0);
    else {
        filesystem("tmpfs", pathfd);
        filesystem("cgroup2", pathfd);
        overlay_option("upperdir", pathfd);
        overlay_option("workdir", pathfd);
        (void)call(NR_CLOSE, pathfd, 0, 0, 0, 0);
    }
    print(failures ? "fsconfig_fd_abi_probe: FAIL\n" : "fsconfig_fd_abi_probe: PASS\n");
    (void)call(NR_EXIT, failures ? 1 : 0, 0, 0, 0, 0);
    for (;;) { }
}

#if defined(__x86_64__)
__asm__(".global _start\n_start:\n andq $-16, %rsp\n call probe_main\n ud2\n");
#else
__asm__(".global _start\n_start:\n bl probe_main\n brk #0\n");
#endif
