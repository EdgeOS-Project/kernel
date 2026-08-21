/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux remap_file_pages ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_pwrite64 18
#define SYS_mincore 27
#define SYS_exit 60
#define SYS_ftruncate 77
#define SYS_remap_file_pages 216
#define SYS_memfd_create 319
#elif defined(__aarch64__)
#define SYS_ftruncate 46
#define SYS_write 64
#define SYS_pwrite64 68
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_mincore 232
#define SYS_remap_file_pages 234
#define SYS_memfd_create 279
#else
#error "remap_file_pages_abi_probe requires x86_64 or AArch64"
#endif

#define PAGE_SIZE 4096ul
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
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
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                       "r"(x8)
                     : "memory");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int run_tests(void) {
    static const char name[] = "remap-pages";
    static const char values[] = { 'A', 'B', 'C' };
    long descriptor;
    long shared_address;
    long private_address;
    volatile char *shared;
    uint8_t residency = 0;
    int failures = 0;

    descriptor = raw_syscall6(SYS_memfd_create, (long)name, 0, 0, 0, 0, 0);
    if (descriptor < 0) return failures + expect("memfd_create", descriptor, 0);
    failures += expect(
        "ftruncate", raw_syscall6(
            SYS_ftruncate, descriptor, 4 * PAGE_SIZE, 0, 0, 0, 0), 0);
    for (long index = 0; index < 3; ++index)
        failures += expect(
            "pwrite64", raw_syscall6(
                SYS_pwrite64, descriptor, (long)&values[index], 1,
                index * PAGE_SIZE, 0, 0), 1);

    shared_address = raw_syscall6(
        SYS_mmap, 0, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, 0);
    if (shared_address < 0)
        return failures + expect("shared mmap", shared_address, 0);
    shared = (volatile char *)shared_address;
    failures += expect("initial page zero", shared[0], 'A');
    failures += expect("initial page one", shared[PAGE_SIZE], 'B');
    failures += expect(
        "remap page two", raw_syscall6(
            SYS_remap_file_pages, shared_address, PAGE_SIZE,
            0, 2, 0, 0), 0);
    failures += expect(
        "populated remap", raw_syscall6(
            SYS_mincore, shared_address, PAGE_SIZE,
            (long)&residency, 0, 0, 0), 0);
    failures += expect("resident remap page", residency & 1u, 1);
    failures += expect("remapped content", shared[0], 'C');
    failures += expect("adjacent content", shared[PAGE_SIZE], 'B');
    failures += expect(
        "nonzero protection", raw_syscall6(
            SYS_remap_file_pages, shared_address, PAGE_SIZE,
            1, 0, 0, 0), -EINVAL);
    failures += expect(
        "short size", raw_syscall6(
            SYS_remap_file_pages, shared_address, PAGE_SIZE - 1,
            0, 0, 0, 0), -EINVAL);
    failures += expect(
        "unaligned start and ignored flags", raw_syscall6(
            SYS_remap_file_pages, shared_address + 17, PAGE_SIZE + 17,
            0, 0, -1, 0), 0);
    failures += expect("restored content", shared[0], 'A');

    private_address = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ, MAP_PRIVATE, descriptor, 0);
    if (private_address < 0)
        failures += expect("private mmap", private_address, 0);
    else {
        failures += expect(
            "private mapping", raw_syscall6(
                SYS_remap_file_pages, private_address, PAGE_SIZE,
                0, 1, 0, 0), -EINVAL);
        (void)raw_syscall6(
            SYS_munmap, private_address, PAGE_SIZE, 0, 0, 0, 0);
    }
    (void)raw_syscall6(
        SYS_munmap, shared_address, 2 * PAGE_SIZE, 0, 0, 0, 0);
    return failures;
}

__attribute__((noreturn)) void _start(void) {
    int failures = run_tests();
    print_text(failures ? "REMAP_FILE_PAGES_ABI_PROBE_FAIL\n" :
                          "REMAP_FILE_PAGES_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
