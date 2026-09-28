/* SPDX-License-Identifier: MPL-2.0 */
/* Linux ia32 and x32 userfaultfd compatibility ABI probe. */

#include <stdint.h>

#if defined(__i386__)
#define PROBE_NAME "IA32_USERFAULTFD_UAPI_PROBE"
#define SYS_exit 1
#define SYS_write 4
#define SYS_close 6
#define SYS_ioctl 54
#define SYS_mprotect 125
#define SYS_mmap 192
#define SYS_userfaultfd 374
#elif defined(__x86_64__) && defined(__ILP32__)
#define PROBE_NAME "X32_USERFAULTFD_UAPI_PROBE"
#define X32_SYSCALL_BIT UINT32_C(0x40000000)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_ioctl 514
#define SYS_exit 60
#define SYS_userfaultfd 323
#else
#error "compat_userfaultfd_uapi_probe requires ia32 or x32"
#endif

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

#define UFFD_USER_MODE_ONLY 1
#define UFFD_API UINT64_C(0xaa)
#define UFFDIO_REGISTER_MODE_MISSING UINT64_C(1)
#define UFFDIO_API UINT32_C(0xc018aa3f)
#define UFFDIO_REGISTER UINT32_C(0xc020aa00)
#define UFFDIO_UNREGISTER UINT32_C(0x8010aa01)
#define UFFDIO_COPY_NUMBER 3

struct uffdio_api {
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
};

struct uffdio_range {
    uint64_t start;
    uint64_t length;
};

struct uffdio_register {
    struct uffdio_range range;
    uint64_t mode;
    uint64_t ioctls;
};

_Static_assert(sizeof(struct uffdio_api) == 24u,
               "uffdio_api must match Linux UAPI");
_Static_assert(sizeof(struct uffdio_range) == 16u,
               "uffdio_range must match Linux UAPI");
_Static_assert(sizeof(struct uffdio_register) == 32u,
               "uffdio_register must match Linux UAPI");

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

static void print_number(long value) {
    char output[24];
    uint32_t count = 0;
    uint32_t magnitude;

    if (value < 0) {
        print_text("-");
        magnitude = (uint32_t)(-(value + 1)) + 1u;
    } else {
        magnitude = (uint32_t)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (uint32_t left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];

        output[left] = output[right];
        output[right] = temporary;
    }
    call6(SYS_write, 1, output, count, 0, 0, 0);
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
    if (actual != expected) {
        print_text(PROBE_NAME "_FAIL ");
        print_text(name);
        print_text(" result=");
        print_number(actual);
        print_text(" expected=");
        print_number(expected);
        print_text("\n");
        call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
}

__attribute__((noreturn)) void _start(void) {
    const uint32_t page_size = 4096u;
    unsigned char *boundary_mapping;
    unsigned char *target_mapping;
    struct uffdio_api *api;
    struct uffdio_register *registration;
    long descriptor;
    long result;

    descriptor = call6(SYS_userfaultfd, UFFD_USER_MODE_ONLY,
                       0, 0, 0, 0, 0);
    if (descriptor < 0) fail("userfaultfd");

    result = call6(SYS_mmap, 0, page_size * 2u,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_failed(result)) fail("mmap-boundary");
    boundary_mapping = (unsigned char *)(uintptr_t)(uint32_t)result;
    require_result(call6(SYS_mprotect, boundary_mapping + page_size,
                         page_size, PROT_NONE, 0, 0, 0),
                   0, "mprotect");

    api = (struct uffdio_api *)(
        boundary_mapping + page_size - sizeof(*api));
    api->api = UFFD_API;
    api->features = 0;
    api->ioctls = 0;
    require_result(call6(SYS_ioctl, descriptor, UFFDIO_API,
                         api, 0, 0, 0),
                   0, "api-layout");
    if (api->api != UFFD_API || !api->ioctls)
        fail("api-result");

    result = call6(SYS_mmap, 0, page_size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall_failed(result)) fail("mmap-target");
    target_mapping = (unsigned char *)(uintptr_t)(uint32_t)result;
    registration = (struct uffdio_register *)(
        boundary_mapping + page_size - sizeof(*registration));
    registration->range.start = (uint32_t)(uintptr_t)target_mapping;
    registration->range.length = page_size;
    registration->mode = UFFDIO_REGISTER_MODE_MISSING;
    registration->ioctls = 0;
    require_result(call6(SYS_ioctl, descriptor, UFFDIO_REGISTER,
                         registration, 0, 0, 0),
                   0, "register-layout");
    if (!(registration->ioctls &
          (UINT64_C(1) << UFFDIO_COPY_NUMBER)))
        fail("register-ioctls");
    require_result(call6(SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
                         &registration->range, 0, 0, 0),
                   0, "unregister-layout");
    require_result(call6(SYS_close, descriptor, 0, 0, 0, 0, 0),
                   0, "close");

    print_text(PROBE_NAME "_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
