/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 descriptor and memory-layout UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_unlink 10
#define SYS_fcntl 55
#define SYS_old_select 82
#define SYS_old_mmap 90
#define SYS_munmap 91
#define SYS_llseek 140
#define SYS_pread64 180
#define SYS_pwrite64 181
#define SYS_mmap2 192
#define SYS_fcntl64 221

#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define SEEK_SET 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define F_GETLK 5
#define F_SETLK 6
#define F_GETLK64 12
#define F_SETLK64 13
#define F_UNLCK 2
#define F_WRLCK 1

struct compat_flock {
    int16_t type;
    int16_t whence;
    int32_t start;
    int32_t length;
    int32_t pid;
};

struct __attribute__((packed)) compat_flock64 {
    int16_t type;
    int16_t whence;
    int64_t start;
    int64_t length;
    int32_t pid;
};

struct timeval32 {
    int32_t seconds;
    int32_t microseconds;
};

struct old_select_arguments {
    uint32_t count;
    uint32_t read_set;
    uint32_t write_set;
    uint32_t except_set;
    uint32_t timeout;
};

struct old_mmap_arguments {
    uint32_t address;
    uint32_t length;
    uint32_t protection;
    uint32_t flags;
    uint32_t descriptor;
    uint32_t offset;
};

_Static_assert(sizeof(struct compat_flock) == 16,
               "i386 flock layout mismatch");
_Static_assert(sizeof(struct compat_flock64) == 24,
               "i386 flock64 layout mismatch");
_Static_assert(sizeof(struct old_select_arguments) == 20,
               "i386 old select layout mismatch");
_Static_assert(sizeof(struct old_mmap_arguments) == 24,
               "i386 old mmap layout mismatch");

__attribute__((naked)) static long raw_call6(
        long number, long a0, long a1, long a2,
        long a3, long a4, long a5) {
    __asm__ volatile(
        "pushl %ebp\n"
        "pushl %edi\n"
        "pushl %esi\n"
        "pushl %ebx\n"
        "movl 20(%esp), %eax\n"
        "movl 24(%esp), %ebx\n"
        "movl 28(%esp), %ecx\n"
        "movl 32(%esp), %edx\n"
        "movl 36(%esp), %esi\n"
        "movl 40(%esp), %edi\n"
        "movl 44(%esp), %ebp\n"
        "int $0x80\n"
        "popl %ebx\n"
        "popl %esi\n"
        "popl %edi\n"
        "popl %ebp\n"
        "ret\n");
}

#define call6(number, a0, a1, a2, a3, a4, a5) \
    raw_call6((number), \
              (long)(uintptr_t)(a0), (long)(uintptr_t)(a1), \
              (long)(uintptr_t)(a2), (long)(uintptr_t)(a3), \
              (long)(uintptr_t)(a4), (long)(uintptr_t)(a5))

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call6(SYS_write, 1, text, text_length(text), 0, 0, 0);
}

static void print_hex(uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    char text[11];
    uint32_t index;
    text[0] = '0';
    text[1] = 'x';
    for (index = 0; index < 8; ++index)
        text[2 + index] = digits[(value >> (28 - index * 4)) & 15u];
    text[10] = '\0';
    print_text(text);
}

static void fail(const char *name) {
    print_text("IA32_FD_MM_UAPI_PROBE_FAIL ");
    print_text(name);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void fail_result(const char *name, long result) {
    print_text("IA32_FD_MM_UAPI_PROBE_FAIL ");
    print_text(name);
    print_text(" result=");
    print_hex((uint32_t)result);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

__attribute__((noreturn)) void _start(void) {
    static const char path[] = "/ia32-fd-mm";
    static const char zero_page_data[] = "zero-page";
    static const char page_data[] = "page-offset";
    struct compat_flock lock32 = {F_WRLCK, SEEK_SET, 0, 1, 0};
    struct compat_flock64 lock64 = {F_WRLCK, SEEK_SET, 4096, 1, 0};
    struct timeval32 timeout = {0, 0};
    struct old_select_arguments select_arguments;
    struct old_mmap_arguments mmap_arguments;
    int64_t seek_result = -1;
    char read_data[sizeof(page_data)] = {0};
    long descriptor;
    long mapping;

    descriptor = call6(SYS_open, path, O_CREAT | O_TRUNC | O_RDWR,
                       0600, 0, 0, 0);
    if (descriptor < 0) fail("open");
    if (call6(SYS_pwrite64, descriptor, zero_page_data,
              sizeof(zero_page_data), 0, 0, 0) !=
        sizeof(zero_page_data))
        fail("pwrite64-zero-page");
    if (call6(SYS_pwrite64, descriptor, page_data,
              sizeof(page_data), 4096, 0, 0) != sizeof(page_data))
        fail("pwrite64");
    if (call6(SYS_pread64, descriptor, read_data,
              sizeof(read_data), 4096, 0, 0) != sizeof(read_data))
        fail("pread64");
    if (read_data[0] != page_data[0] || read_data[4] != page_data[4])
        fail_result("pread64-data", *(const uint32_t *)read_data);

    if (call6(SYS_fcntl, descriptor, F_SETLK, &lock32, 0, 0, 0) != 0)
        fail("fcntl-setlk");
    lock32.type = F_WRLCK;
    if (call6(SYS_fcntl, descriptor, F_GETLK, &lock32, 0, 0, 0) != 0 ||
        lock32.type != F_UNLCK)
        fail("fcntl-getlk");
    if (call6(SYS_fcntl, descriptor, F_GETLK64,
              &lock64, 0, 0, 0) != 0 || lock64.type != F_UNLCK)
        fail("fcntl-wide-getlk");

    if (call6(SYS_fcntl64, descriptor, F_SETLK64,
              &lock64, 0, 0, 0) != 0)
        fail("fcntl64-setlk");
    lock64.type = F_WRLCK;
    if (call6(SYS_fcntl64, descriptor, F_GETLK64,
              &lock64, 0, 0, 0) != 0 || lock64.type != F_UNLCK)
        fail("fcntl64-getlk");

    if (call6(SYS_llseek, descriptor, 0, 4096,
              &seek_result, SEEK_SET, 0) != 0 || seek_result != 4096)
        fail("llseek");

    select_arguments.count = 0;
    select_arguments.read_set = 0;
    select_arguments.write_set = 0;
    select_arguments.except_set = 0;
    select_arguments.timeout = (uint32_t)(uintptr_t)&timeout;
    if (call6(SYS_old_select, &select_arguments, 0, 0, 0, 0, 0) != 0)
        fail("old-select");

    mmap_arguments.address = 0;
    mmap_arguments.length = 4096;
    mmap_arguments.protection = PROT_READ | PROT_WRITE;
    mmap_arguments.flags = MAP_PRIVATE | MAP_ANONYMOUS;
    mmap_arguments.descriptor = (uint32_t)-1;
    mmap_arguments.offset = 0;
    mapping = call6(SYS_old_mmap, &mmap_arguments, 0, 0, 0, 0, 0);
    if ((uint32_t)mapping >= 0xfffff001u)
        fail_result("old-mmap", mapping);
    *(volatile uint32_t *)(uintptr_t)mapping = 0x45444745u;
    if (*(volatile uint32_t *)(uintptr_t)mapping != 0x45444745u ||
        call6(SYS_munmap, mapping, 4096, 0, 0, 0, 0) != 0)
        fail("old-mmap-access");

    mapping = call6(SYS_mmap2, 0, 4096, PROT_READ,
                    MAP_SHARED, descriptor, 1);
    if ((uint32_t)mapping >= 0xfffff001u)
        fail_result("mmap2-page-offset", mapping);
    if (((const char *)(uintptr_t)mapping)[0] != page_data[0] ||
        ((const char *)(uintptr_t)mapping)[4] != page_data[4])
        fail_result("mmap2-data",
                    *(const uint32_t *)(uintptr_t)mapping);
    if (call6(SYS_munmap, mapping, 4096, 0, 0, 0, 0) != 0)
        fail("mmap2-unmap");

    if (call6(SYS_close, descriptor, 0, 0, 0, 0, 0) != 0 ||
        call6(SYS_unlink, path, 0, 0, 0, 0, 0) != 0)
        fail("cleanup");
    print_text("IA32_FD_MM_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
