/* SPDX-License-Identifier: MPL-2.0 */
/* Linux ia32 and x32 io_uring fixed-buffer compatibility ABI probe. */

#include <stdint.h>

#if defined(__i386__)
#define PROBE_NAME "IA32_IO_URING_IOVEC_UAPI_PROBE"
#define SYS_exit 1
#define SYS_write 4
#define SYS_close 6
#define SYS_mprotect 125
#define SYS_mmap 192
#elif defined(__x86_64__) && defined(__ILP32__)
#define PROBE_NAME "X32_IO_URING_IOVEC_UAPI_PROBE"
#define X32_SYSCALL_BIT UINT32_C(0x40000000)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_exit 60
#else
#error "compat_io_uring_iovec_uapi_probe requires ia32 or x32"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_register 427

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

#define IORING_REGISTER_BUFFERS 0
#define IORING_UNREGISTER_BUFFERS 1

struct compat_iovec {
    uint32_t base;
    uint32_t length;
};

struct io_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t reserved1;
    uint64_t user_address;
};

struct io_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t flags;
    uint32_t reserved1;
    uint64_t user_address;
};

struct io_uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t workqueue_fd;
    uint32_t reserved[3];
    struct io_sqring_offsets sq_offsets;
    struct io_cqring_offsets cq_offsets;
};

_Static_assert(sizeof(struct compat_iovec) == 8u,
               "compat iovec must be eight bytes");
_Static_assert(sizeof(struct io_uring_params) == 120u,
               "io_uring parameters must match Linux UAPI");

static struct io_uring_params ring_parameters;
static unsigned char fixed_buffer;

#if defined(__i386__)
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
#else
static long raw_call6(long number, long a0, long a1, long a2,
                      long a3, long a4, long a5) {
    register uint64_t r10 __asm__("r10") = (uint32_t)a3;
    register uint64_t r8 __asm__("r8") = (uint32_t)a4;
    register uint64_t r9 __asm__("r9") = (uint32_t)a5;
    int64_t result;

    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"((uint64_t)X32_SYSCALL_BIT +
                           (uint32_t)number),
                       "D"((uint64_t)(uint32_t)a0),
                       "S"((uint64_t)(uint32_t)a1),
                       "d"((uint64_t)(uint32_t)a2),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return (long)result;
}
#endif

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

static void fail(const char *reason) {
    print_text(PROBE_NAME "_FAIL ");
    print_text(reason);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
}

static int syscall_failed(long result) {
    return (uint32_t)result >= UINT32_C(0xfffff001);
}

static void require_result(long actual, long expected, const char *name) {
    if (actual != expected) fail(name);
}

__attribute__((noreturn)) void _start(void) {
    const uint32_t page_size = 4096u;
    unsigned char *mapping;
    struct compat_iovec *vector;
    long ring;
    long result;

    ring = call6(SYS_io_uring_setup, 2, &ring_parameters, 0, 0, 0, 0);
    if (ring < 0) fail("setup");

    result = call6(SYS_mmap, 0, page_size * 2u,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_failed(result)) fail("mmap");
    mapping = (unsigned char *)(uintptr_t)(uint32_t)result;
    require_result(call6(SYS_mprotect, mapping + page_size, page_size,
                         PROT_NONE, 0, 0, 0), 0, "mprotect");

    vector = (struct compat_iovec *)(mapping + page_size - sizeof(*vector));
    vector->base = (uint32_t)(uintptr_t)&fixed_buffer;
    vector->length = 1;
    require_result(call6(SYS_io_uring_register, ring,
                         IORING_REGISTER_BUFFERS, vector, 1, 0, 0),
                   0, "register-buffers-layout");
    require_result(call6(SYS_io_uring_register, ring,
                         IORING_UNREGISTER_BUFFERS, 0, 0, 0, 0),
                   0, "unregister-buffers");
    require_result(call6(SYS_close, ring, 0, 0, 0, 0, 0), 0, "close");

    print_text(PROBE_NAME "_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
