/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 userfaultfd ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_madvise 28
#define SYS_mremap 25
#define SYS_ioctl 16
#define SYS_close 3
#define SYS_clone 56
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_ftruncate 77
#define SYS_memfd_create 319
#define SYS_sched_yield 24
#define SYS_exit 60
#define SYS_userfaultfd 323
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_madvise 233
#define SYS_mremap 216
#define SYS_ioctl 29
#define SYS_close 57
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_kill 129
#define SYS_ftruncate 46
#define SYS_memfd_create 279
#define SYS_sched_yield 124
#define SYS_exit 93
#define SYS_userfaultfd 282
#else
#error "userfaultfd_abi_probe requires a Linux 64-bit architecture"
#endif

#define PAGE_SIZE 4096u
#define HUGE_PAGE_SIZE (2u * 1024u * 1024u)
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x2
#define MAP_SHARED 0x1
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MREMAP_MAYMOVE 0x1
#define MREMAP_FIXED 0x2
#define MFD_CLOEXEC 0x0001u
#define MFD_ALLOW_SEALING 0x0002u
#define MFD_HUGETLB 0x0004u
#define MFD_HUGE_SHIFT 26u
#define MFD_HUGE_2MB (21u << MFD_HUGE_SHIFT)
#define O_NONBLOCK 0x800
#define O_CLOEXEC 0x80000
#define UFFD_USER_MODE_ONLY 0x1
#define UFFD_API 0xAAu
#define UFFD_FEATURE_PAGEFAULT_FLAG_WP (1ULL << 0)
#define UFFD_FEATURE_EVENT_FORK (1ULL << 1)
#define UFFD_FEATURE_EVENT_REMAP (1ULL << 2)
#define UFFD_FEATURE_EVENT_REMOVE (1ULL << 3)
#define UFFD_FEATURE_MISSING_HUGETLBFS (1ULL << 4)
#define UFFD_FEATURE_MISSING_SHMEM (1ULL << 5)
#define UFFD_FEATURE_EVENT_UNMAP (1ULL << 6)
#define UFFD_FEATURE_SIGBUS (1ULL << 7)
#define UFFD_FEATURE_THREAD_ID (1ULL << 8)
#define UFFD_FEATURE_MINOR_HUGETLBFS (1ULL << 9)
#define UFFD_FEATURE_MINOR_SHMEM (1ULL << 10)
#define UFFD_FEATURE_EXACT_ADDRESS (1ULL << 11)
#define UFFD_FEATURE_WP_UNPOPULATED (1ULL << 13)
#define UFFD_FEATURE_POISON (1ULL << 14)
#define UFFD_FEATURE_WP_ASYNC (1ULL << 15)
#define UFFD_FEATURE_MOVE (1ULL << 16)
#define UFFDIO_REGISTER_MODE_MISSING 0x1u
#define UFFDIO_REGISTER_MODE_WP 0x2u
#define UFFDIO_REGISTER_MODE_MINOR 0x4u
#define UFFDIO_COPY_MODE_WP 0x2u
#define UFFDIO_WRITEPROTECT_MODE_WP 0x1u
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE 0x2u
#define UFFDIO_POISON_MODE_DONTWAKE 0x1u
#define UFFDIO_API 0xc018aa3fu
#define UFFDIO_REGISTER 0xc020aa00u
#define UFFDIO_UNREGISTER 0x8010aa01u
#define UFFDIO_COPY 0xc028aa03u
#define UFFDIO_ZEROPAGE 0xc020aa04u
#define UFFDIO_MOVE 0xc028aa05u
#define UFFDIO_WRITEPROTECT 0xc018aa06u
#define UFFDIO_CONTINUE 0xc020aa07u
#define UFFDIO_POISON 0xc020aa08u
#define UFFD_EVENT_PAGEFAULT 0x12u
#define UFFD_EVENT_FORK 0x13u
#define UFFD_EVENT_REMAP 0x14u
#define UFFD_EVENT_REMOVE 0x15u
#define UFFD_EVENT_UNMAP 0x16u
#define UFFD_PAGEFAULT_FLAG_WRITE (1ULL << 0)
#define UFFD_PAGEFAULT_FLAG_WP (1ULL << 1)
#define UFFD_PAGEFAULT_FLAG_MINOR (1ULL << 2)
#define CLONE_VM 0x00000100u
#define SIGCHLD 17
#define SIGKILL 9
#define SIGBUS 7
#define WNOHANG 1
#define EAGAIN 11
#define EEXIST 17
#define EINVAL 22
#define ENOENT 2
#define MADV_DONTNEED 4

struct uffdio_api {
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
};

struct uffdio_range {
    uint64_t start;
    uint64_t len;
};

struct uffdio_register {
    struct uffdio_range range;
    uint64_t mode;
    uint64_t ioctls;
};

struct uffdio_copy {
    uint64_t dst;
    uint64_t src;
    uint64_t len;
    uint64_t mode;
    int64_t copy;
};

struct uffdio_zeropage {
    struct uffdio_range range;
    uint64_t mode;
    int64_t zeropage;
};

struct uffdio_move {
    uint64_t dst;
    uint64_t src;
    uint64_t len;
    uint64_t mode;
    int64_t move;
};

struct uffdio_writeprotect {
    struct uffdio_range range;
    uint64_t mode;
};

struct uffdio_continue {
    struct uffdio_range range;
    uint64_t mode;
    int64_t mapped;
};

struct uffdio_poison {
    struct uffdio_range range;
    uint64_t mode;
    int64_t updated;
};

struct uffd_msg {
    uint8_t event;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    union {
        struct {
            uint64_t flags;
            uint64_t address;
            union {
                struct {
                    uint32_t thread_id;
                    uint32_t reserved4;
                };
                uint64_t length;
            };
        };
        struct {
            uint32_t fork_ufd;
            uint32_t fork_reserved;
            uint64_t fork_reserved2;
            uint64_t fork_reserved3;
        };
    };
};

static unsigned char g_fault_stack[16384] __attribute__((aligned(16)));
static unsigned char g_fork_handler_stack[16384]
    __attribute__((aligned(16)));
static unsigned char g_fork_child_stack[16384]
    __attribute__((aligned(16)));
static volatile unsigned char *g_fault_address;
static volatile unsigned char g_fault_value;
static volatile unsigned char g_fault_write;
static volatile unsigned long g_child_operation;
static volatile unsigned long g_child_length;
static volatile unsigned long g_child_target;
static volatile long g_child_result;
static volatile unsigned char *g_fork_area;
static volatile long g_fork_parent_descriptor;
static volatile long g_fork_child_descriptor;
static volatile long g_fork_handler_ready;
static volatile long g_fork_event_result;
static volatile long g_fork_fault_result;
static volatile long g_fork_fault_received;
static volatile long g_fork_fault_event;
static volatile uint64_t g_fork_fault_address;
static const char g_fork_event_failure[] = "FAIL fork-handler-event\n";

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

static __attribute__((noreturn)) void exit_now(int status) {
    (void)raw_syscall6(SYS_exit, status, 0, 0, 0, 0, 0);
    for (;;) { }
}

static __attribute__((noreturn, noinline, used))
void fault_child_entry(void) {
    if (g_child_operation == 1u) {
        g_child_result = raw_syscall6(
            SYS_madvise, (long)g_fault_address,
            (long)g_child_length, MADV_DONTNEED, 0, 0, 0);
        exit_now(0);
    }
    if (g_child_operation == 2u) {
        g_child_result = raw_syscall6(
            SYS_munmap, (long)g_fault_address,
            (long)g_child_length, 0, 0, 0, 0);
        exit_now(0);
    }
    if (g_child_operation == 3u) {
        g_child_result = raw_syscall6(
            SYS_mremap, (long)g_fault_address,
            (long)g_child_length, (long)g_child_length,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            (long)g_child_target, 0);
        exit_now(0);
    }
    if (g_fault_write)
        *g_fault_address = g_fault_write;
    else
        g_fault_value = *g_fault_address;
    __asm__ volatile("" ::: "memory");
    exit_now(0);
}

static __attribute__((noreturn, noinline, used))
void fork_handler_entry(void) {
    struct uffd_msg event;
    struct uffdio_zeropage zero;
    long received = -EAGAIN;

    g_fork_handler_ready = 1;
    for (unsigned long attempt = 0; attempt < 1000000u; ++attempt) {
        received = raw_syscall6(
            SYS_read, g_fork_parent_descriptor, (long)&event,
            sizeof(event), 0, 0, 0);
        if (received != -EAGAIN) break;
        (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    if (received != (long)sizeof(event) ||
        event.event != UFFD_EVENT_FORK || (int32_t)event.fork_ufd < 0) {
        g_fork_event_result = -1;
        (void)raw_syscall6(
            SYS_write, 1, (long)g_fork_event_failure,
            sizeof(g_fork_event_failure) - 1u, 0, 0, 0);
        exit_now(1);
    }
    g_fork_child_descriptor = (long)(int32_t)event.fork_ufd;
    g_fork_event_result = 1;
    received = -EAGAIN;
    for (unsigned long attempt = 0; attempt < 1000000u; ++attempt) {
        received = raw_syscall6(
            SYS_read, g_fork_child_descriptor, (long)&event,
            sizeof(event), 0, 0, 0);
        if (received != -EAGAIN) break;
        (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    g_fork_fault_received = received;
    g_fork_fault_event = event.event;
    g_fork_fault_address = event.address;
    if (received != (long)sizeof(event) ||
        event.event != UFFD_EVENT_PAGEFAULT ||
        event.address != (uint64_t)(uintptr_t)g_fork_area) {
        g_fork_fault_result = -1;
        exit_now(2);
    }
    zero.range.start = (uint64_t)(uintptr_t)g_fork_area;
    zero.range.len = PAGE_SIZE;
    zero.mode = 0;
    zero.zeropage = 0;
    if (raw_syscall6(
            SYS_ioctl, g_fork_child_descriptor, UFFDIO_ZEROPAGE,
            (long)&zero, 0, 0, 0) != 0 ||
        zero.zeropage != PAGE_SIZE) {
        g_fork_fault_result = -2;
        exit_now(3);
    }
    g_fork_fault_result = 1;
    exit_now(0);
}

static __attribute__((noreturn, noinline, used))
void fork_fault_child_entry(void) {
    unsigned char value = *g_fork_area;
    __asm__ volatile("" ::: "memory");
    exit_now(value == 0 ? 0 : 4);
}

#if defined(__x86_64__)
static __attribute__((naked, noinline)) long
spawn_fault_child(unsigned long flags __attribute__((unused)),
                  void *stack __attribute__((unused))) {
    __asm__ volatile(
        "mov $56, %rax\n"
        "syscall\n"
        "test %rax, %rax\n"
        "jnz 1f\n"
        "xor %ebp, %ebp\n"
        "call fault_child_entry\n"
        "ud2\n"
        "1: ret\n");
}

static __attribute__((naked, noinline)) long
spawn_fork_handler(unsigned long flags __attribute__((unused)),
                   void *stack __attribute__((unused))) {
    __asm__ volatile(
        "mov $56, %rax\n"
        "syscall\n"
        "test %rax, %rax\n"
        "jnz 1f\n"
        "xor %ebp, %ebp\n"
        "call fork_handler_entry\n"
        "ud2\n"
        "1: ret\n");
}

static __attribute__((naked, noinline)) long
spawn_fork_fault_child(unsigned long flags __attribute__((unused)),
                       void *stack __attribute__((unused))) {
    __asm__ volatile(
        "mov $56, %rax\n"
        "syscall\n"
        "test %rax, %rax\n"
        "jnz 1f\n"
        "xor %ebp, %ebp\n"
        "call fork_fault_child_entry\n"
        "ud2\n"
        "1: ret\n");
}
#else
static __attribute__((noinline)) long
spawn_fault_child(unsigned long flags, void *stack) {
    register unsigned long x0 __asm__("x0") = flags;
    register void *x1 __asm__("x1") = stack;
    register unsigned long x2 __asm__("x2") = 0;
    register unsigned long x3 __asm__("x3") = 0;
    register unsigned long x4 __asm__("x4") = 0;
    register unsigned long x8 __asm__("x8") = SYS_clone;
    __asm__ volatile(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "bl fault_child_entry\n"
        "brk #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x30", "memory", "cc");
    return (long)x0;
}

static __attribute__((noinline)) long
spawn_fork_handler(unsigned long flags, void *stack) {
    register unsigned long x0 __asm__("x0") = flags;
    register void *x1 __asm__("x1") = stack;
    register unsigned long x2 __asm__("x2") = 0;
    register unsigned long x3 __asm__("x3") = 0;
    register unsigned long x4 __asm__("x4") = 0;
    register unsigned long x8 __asm__("x8") = SYS_clone;
    __asm__ volatile(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "bl fork_handler_entry\n"
        "brk #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x30", "memory", "cc");
    return (long)x0;
}

static __attribute__((noinline)) long
spawn_fork_fault_child(unsigned long flags, void *stack) {
    register unsigned long x0 __asm__("x0") = flags;
    register void *x1 __asm__("x1") = stack;
    register unsigned long x2 __asm__("x2") = 0;
    register unsigned long x3 __asm__("x3") = 0;
    register unsigned long x4 __asm__("x4") = 0;
    register unsigned long x8 __asm__("x8") = SYS_clone;
    __asm__ volatile(
        "svc #0\n"
        "cbnz x0, 1f\n"
        "bl fork_fault_child_entry\n"
        "brk #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x30", "memory", "cc");
    return (long)x0;
}
#endif

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(
        SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

#if defined(__x86_64__)
#define START_ATTRIBUTES \
    __attribute__((noreturn, force_align_arg_pointer))
#else
#define START_ATTRIBUTES __attribute__((noreturn))
#endif

START_ATTRIBUTES void _start(void) {
    struct uffdio_api api = {
        .api = UFFD_API,
        .features = UFFD_FEATURE_THREAD_ID |
                    UFFD_FEATURE_PAGEFAULT_FLAG_WP |
                    UFFD_FEATURE_MISSING_HUGETLBFS |
                    UFFD_FEATURE_MISSING_SHMEM |
                    UFFD_FEATURE_MINOR_HUGETLBFS |
                    UFFD_FEATURE_MINOR_SHMEM |
                    UFFD_FEATURE_EXACT_ADDRESS |
                    UFFD_FEATURE_POISON |
                    UFFD_FEATURE_MOVE,
    };
    struct uffdio_register registration;
    struct uffdio_copy copy;
    struct uffdio_zeropage zero;
    struct uffdio_move move;
    struct uffdio_writeprotect writeprotect;
    struct uffdio_poison poison;
    struct uffd_msg message;
    unsigned char *source;
    unsigned char *destination;
    unsigned char *move_area;
    unsigned char *poison_area;
    long descriptor;
    int failures = 0;

    failures += expect_result(
        "invalid-flags",
        raw_syscall6(
            SYS_userfaultfd,
            0x40000000u | UFFD_USER_MODE_ONLY, 0, 0, 0, 0, 0),
        -EINVAL);
    source = (unsigned char *)raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    destination = (unsigned char *)raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE * 3u, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    move_area = (unsigned char *)raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE * 3u, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    poison_area = (unsigned char *)raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE * 2u, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)source < 0 || (long)destination < 0 ||
        (long)move_area < 0 || (long)poison_area < 0) {
        print_text("FAIL mmap\n");
        ++failures;
        goto out;
    }
    for (unsigned long index = 0; index < PAGE_SIZE; ++index)
        source[index] = (unsigned char)(index * 37u + 11u);
    move_area[0] = 0x6du;

    descriptor = raw_syscall6(
        SYS_userfaultfd,
        O_NONBLOCK | O_CLOEXEC | UFFD_USER_MODE_ONLY, 0, 0, 0, 0, 0);
    if (descriptor < 0) {
        failures += expect_result("create", descriptor, 0);
        goto out;
    }
    failures += expect_result(
        "api", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_API, (long)&api, 0, 0, 0), 0);
    if (api.api != UFFD_API || !api.ioctls ||
        !(api.features & UFFD_FEATURE_THREAD_ID) ||
        !(api.features & UFFD_FEATURE_MISSING_HUGETLBFS) ||
        !(api.features & UFFD_FEATURE_MISSING_SHMEM) ||
        !(api.features & UFFD_FEATURE_MINOR_HUGETLBFS) ||
        !(api.features & UFFD_FEATURE_MINOR_SHMEM) ||
        !(api.features & UFFD_FEATURE_SIGBUS) ||
        !(api.features & UFFD_FEATURE_EXACT_ADDRESS) ||
        !(api.features & UFFD_FEATURE_WP_UNPOPULATED) ||
        !(api.features & UFFD_FEATURE_POISON) ||
        !(api.features & UFFD_FEATURE_WP_ASYNC) ||
        !(api.features & UFFD_FEATURE_MOVE)) {
        print_text("FAIL api-result\n");
        ++failures;
    }

    registration.range.start = (uint64_t)(uintptr_t)destination;
    registration.range.len = PAGE_SIZE * 3u;
    registration.mode = UFFDIO_REGISTER_MODE_MISSING;
    registration.ioctls = 0;
    failures += expect_result(
        "register", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_REGISTER,
            (long)&registration, 0, 0, 0), 0);
    if (!registration.ioctls) {
        print_text("FAIL register-ioctls\n");
        ++failures;
    }

    copy.dst = (uint64_t)(uintptr_t)destination;
    copy.src = (uint64_t)(uintptr_t)source;
    copy.len = PAGE_SIZE;
    copy.mode = UFFDIO_COPY_MODE_WP;
    copy.copy = 0;
    failures += expect_result(
        "copy-wp-without-registration", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_COPY, (long)&copy, 0, 0, 0),
        -EINVAL);
    copy.mode = 0;
    copy.copy = 0;
    failures += expect_result(
        "copy", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_COPY, (long)&copy, 0, 0, 0), 0);
    failures += expect_result("copy-count", copy.copy, PAGE_SIZE);
    for (unsigned long index = 0; index < PAGE_SIZE; ++index) {
        if (destination[index] != source[index]) {
            print_text("FAIL copy-data\n");
            ++failures;
            break;
        }
    }

    zero.range.start = (uint64_t)(uintptr_t)(destination + PAGE_SIZE);
    zero.range.len = PAGE_SIZE;
    zero.mode = 0;
    zero.zeropage = 0;
    failures += expect_result(
        "zeropage", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_ZEROPAGE,
            (long)&zero, 0, 0, 0), 0);
    failures += expect_result("zero-count", zero.zeropage, PAGE_SIZE);
    for (unsigned long index = PAGE_SIZE; index < PAGE_SIZE * 2u; ++index) {
        if (destination[index] != 0) {
            print_text("FAIL zero-data\n");
            ++failures;
            break;
        }
    }

    g_fault_address = destination + PAGE_SIZE * 2u + 37u;
    g_fault_value = 0;
    {
        long child = spawn_fault_child(
            CLONE_VM | SIGCHLD,
            &g_fault_stack[sizeof(g_fault_stack)]);
        long received = -EAGAIN;
        int child_status = -1;

        if (child < 0) {
            failures += expect_result("fault-child", child, 0);
        } else {
            for (unsigned long attempt = 0; attempt < 100000u; ++attempt) {
                received = raw_syscall6(
                    SYS_read, descriptor, (long)&message,
                    sizeof(message), 0, 0, 0);
                if (received != -EAGAIN) break;
                (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
            }
            failures += expect_result(
                "fault-event-size", received, sizeof(message));
            if (received == (long)sizeof(message) &&
                (message.event != UFFD_EVENT_PAGEFAULT ||
                 message.flags != 0 ||
                 message.thread_id != (uint32_t)child ||
                 message.address !=
                    (uint64_t)(uintptr_t)g_fault_address)) {
                print_text("FAIL fault-event-data\n");
                ++failures;
            }
            if (received == (long)sizeof(message)) {
                copy.dst = (uint64_t)(uintptr_t)g_fault_address &
                           ~(uint64_t)(PAGE_SIZE - 1u);
                copy.src = (uint64_t)(uintptr_t)source;
                copy.len = PAGE_SIZE;
                copy.mode = 0;
                copy.copy = 0;
                failures += expect_result(
                    "fault-copy", raw_syscall6(
                        SYS_ioctl, descriptor, UFFDIO_COPY,
                        (long)&copy, 0, 0, 0), 0);
                failures += expect_result(
                    "fault-copy-count", copy.copy, PAGE_SIZE);
            } else {
                (void)raw_syscall6(
                    SYS_kill, child, SIGKILL, 0, 0, 0, 0);
            }
            failures += expect_result(
                "fault-wait", raw_syscall6(
                    SYS_wait4, child, (long)&child_status,
                    0, 0, 0, 0), child);
            failures += expect_result("fault-child-status", child_status, 0);
            failures += expect_result(
                "fault-child-value", g_fault_value, source[37]);
        }
    }
    failures += expect_result(
        "empty-read", raw_syscall6(
            SYS_read, descriptor, (long)&message,
            sizeof(message), 0, 0, 0), -EAGAIN);
    failures += expect_result(
        "unregister", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
            (long)&registration.range, 0, 0, 0), 0);

    {
        static const char shmem_name[] = "uffd-shmem";
        long shmem_descriptor = raw_syscall6(
            SYS_memfd_create, (long)shmem_name, 0, 0, 0, 0, 0);
        unsigned char *shmem_area = (unsigned char *)(uintptr_t)-1;
        unsigned char *shmem_minor_area =
            (unsigned char *)(uintptr_t)-1;

        failures += expect_result(
            "shmem-create", shmem_descriptor < 0 ? shmem_descriptor : 0,
            0);
        if (shmem_descriptor >= 0) {
            failures += expect_result(
                "shmem-size", raw_syscall6(
                    SYS_ftruncate, shmem_descriptor, PAGE_SIZE,
                    0, 0, 0, 0), 0);
            shmem_area = (unsigned char *)raw_syscall6(
                SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED, shmem_descriptor, 0);
            failures += expect_result(
                "shmem-map", (long)shmem_area < 0 ? (long)shmem_area : 0,
                0);
            shmem_minor_area = (unsigned char *)raw_syscall6(
                SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED, shmem_descriptor, 0);
            failures += expect_result(
                "shmem-minor-map",
                (long)shmem_minor_area < 0 ?
                    (long)shmem_minor_area : 0,
                0);
        }
        if ((long)shmem_area >= 0) {
            registration.range.start =
                (uint64_t)(uintptr_t)shmem_area;
            registration.range.len = PAGE_SIZE;
            registration.mode = UFFDIO_REGISTER_MODE_MISSING;
            registration.ioctls = 0;
            failures += expect_result(
                "shmem-register", raw_syscall6(
                    SYS_ioctl, descriptor, UFFDIO_REGISTER,
                    (long)&registration, 0, 0, 0), 0);
            g_fault_address = shmem_area + 83u;
            g_fault_value = 0;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                long received = -EAGAIN;
                int child_status = -1;

                failures += expect_result(
                    "shmem-child", child < 0 ? child : 0, 0);
                if (child >= 0) {
                    for (unsigned long attempt = 0;
                         attempt < 100000u; ++attempt) {
                        received = raw_syscall6(
                            SYS_read, descriptor, (long)&message,
                            sizeof(message), 0, 0, 0);
                        if (received != -EAGAIN) break;
                        (void)raw_syscall6(
                            SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                    }
                    failures += expect_result(
                        "shmem-event-size", received, sizeof(message));
                    if (received == (long)sizeof(message) &&
                        (message.event != UFFD_EVENT_PAGEFAULT ||
                         message.flags != 0 ||
                         message.thread_id != (uint32_t)child ||
                         message.address !=
                            (uint64_t)(uintptr_t)g_fault_address)) {
                        print_text("FAIL shmem-event-data\n");
                        ++failures;
                    }
                    if (received == (long)sizeof(message)) {
                        copy.dst = (uint64_t)(uintptr_t)shmem_area;
                        copy.src = (uint64_t)(uintptr_t)source;
                        copy.len = PAGE_SIZE;
                        copy.mode = 0;
                        copy.copy = 0;
                        failures += expect_result(
                            "shmem-copy", raw_syscall6(
                                SYS_ioctl, descriptor, UFFDIO_COPY,
                                (long)&copy, 0, 0, 0), 0);
                        failures += expect_result(
                            "shmem-copy-count", copy.copy, PAGE_SIZE);
                    } else {
                        (void)raw_syscall6(
                            SYS_kill, child, SIGKILL, 0, 0, 0, 0);
                    }
                    failures += expect_result(
                        "shmem-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "shmem-child-status", child_status, 0);
                    failures += expect_result(
                        "shmem-child-value", g_fault_value, source[83]);
                }
            }
            failures += expect_result(
                "shmem-empty-read", raw_syscall6(
                    SYS_read, descriptor, (long)&message,
                    sizeof(message), 0, 0, 0), -EAGAIN);
            failures += expect_result(
                "shmem-unregister", raw_syscall6(
                    SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
                    (long)&registration.range, 0, 0, 0), 0);
            if ((long)shmem_minor_area >= 0) {
                struct uffdio_continue continuation;

                registration.range.start =
                    (uint64_t)(uintptr_t)shmem_minor_area;
                registration.range.len = PAGE_SIZE;
                registration.mode = UFFDIO_REGISTER_MODE_MINOR;
                registration.ioctls = 0;
                failures += expect_result(
                    "shmem-minor-register", raw_syscall6(
                        SYS_ioctl, descriptor, UFFDIO_REGISTER,
                        (long)&registration, 0, 0, 0), 0);
                if (!(registration.ioctls & (1ULL << 7))) {
                    print_text("FAIL shmem-minor-register-ioctls\n");
                    ++failures;
                }
                g_fault_address = shmem_minor_area + 83u;
                g_fault_value = 0;
                {
                    long child = spawn_fault_child(
                        CLONE_VM | SIGCHLD,
                        &g_fault_stack[sizeof(g_fault_stack)]);
                    long received = -EAGAIN;
                    int child_status = -1;

                    failures += expect_result(
                        "shmem-minor-child", child < 0 ? child : 0, 0);
                    if (child >= 0) {
                        for (unsigned long attempt = 0;
                             attempt < 100000u; ++attempt) {
                            received = raw_syscall6(
                                SYS_read, descriptor, (long)&message,
                                sizeof(message), 0, 0, 0);
                            if (received != -EAGAIN) break;
                            (void)raw_syscall6(
                                SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                        }
                        failures += expect_result(
                            "shmem-minor-event-size", received,
                            sizeof(message));
                        if (received == (long)sizeof(message) &&
                            (message.event != UFFD_EVENT_PAGEFAULT ||
                             message.flags != UFFD_PAGEFAULT_FLAG_MINOR ||
                             message.thread_id != (uint32_t)child ||
                             message.address !=
                                (uint64_t)(uintptr_t)g_fault_address)) {
                            print_text("FAIL shmem-minor-event-data\n");
                            ++failures;
                        }
                        if (received == (long)sizeof(message)) {
                            continuation.range = registration.range;
                            continuation.mode = 0;
                            continuation.mapped = 0;
                            failures += expect_result(
                                "shmem-minor-continue", raw_syscall6(
                                    SYS_ioctl, descriptor,
                                    UFFDIO_CONTINUE,
                                    (long)&continuation,
                                    0, 0, 0), 0);
                            failures += expect_result(
                                "shmem-minor-continue-count",
                                continuation.mapped, PAGE_SIZE);
                            continuation.mapped = 0;
                            failures += expect_result(
                                "shmem-minor-continue-existing",
                                raw_syscall6(
                                    SYS_ioctl, descriptor,
                                    UFFDIO_CONTINUE,
                                    (long)&continuation,
                                    0, 0, 0), -EEXIST);
                            failures += expect_result(
                                "shmem-minor-continue-existing-count",
                                continuation.mapped, -EEXIST);
                        } else {
                            (void)raw_syscall6(
                                SYS_kill, child, SIGKILL, 0, 0, 0, 0);
                        }
                        failures += expect_result(
                            "shmem-minor-wait", raw_syscall6(
                                SYS_wait4, child, (long)&child_status,
                                0, 0, 0, 0), child);
                        failures += expect_result(
                            "shmem-minor-child-status", child_status, 0);
                        failures += expect_result(
                            "shmem-minor-child-value",
                            g_fault_value, source[83]);
                    }
                }
                failures += expect_result(
                    "shmem-minor-unregister", raw_syscall6(
                        SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
                        (long)&registration.range, 0, 0, 0), 0);
                (void)raw_syscall6(
                    SYS_munmap, (long)shmem_minor_area,
                    PAGE_SIZE, 0, 0, 0, 0);
            }
            (void)raw_syscall6(
                SYS_munmap, (long)shmem_area, PAGE_SIZE, 0, 0, 0, 0);
        }
        if (shmem_descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, shmem_descriptor, 0, 0, 0, 0, 0);
    }

    {
        static const char huge_name[] = "uffd-hugetlb";
        long huge_descriptor;
        unsigned char *huge_source =
            (unsigned char *)(uintptr_t)-1;
        unsigned char *huge_minor =
            (unsigned char *)(uintptr_t)-1;
        unsigned char *huge_copy_source =
            (unsigned char *)(uintptr_t)-1;

        failures += expect_result(
            "hugetlb-selector-without-flag",
            raw_syscall6(
                SYS_memfd_create, (long)huge_name,
                MFD_HUGE_2MB, 0, 0, 0, 0),
            -EINVAL);
        huge_descriptor = raw_syscall6(
            SYS_memfd_create, (long)huge_name,
            MFD_CLOEXEC | MFD_ALLOW_SEALING |
                MFD_HUGETLB | MFD_HUGE_2MB,
            0, 0, 0, 0);
        failures += expect_result(
            "hugetlb-create",
            huge_descriptor < 0 ? huge_descriptor : 0, 0);
        if (huge_descriptor >= 0) {
            failures += expect_result(
                "hugetlb-unaligned-size", raw_syscall6(
                    SYS_ftruncate, huge_descriptor, PAGE_SIZE,
                    0, 0, 0, 0), -EINVAL);
            failures += expect_result(
                "hugetlb-size", raw_syscall6(
                    SYS_ftruncate, huge_descriptor, HUGE_PAGE_SIZE,
                    0, 0, 0, 0), 0);
            huge_source = (unsigned char *)raw_syscall6(
                SYS_mmap, 0, HUGE_PAGE_SIZE,
                PROT_READ | PROT_WRITE, MAP_SHARED,
                huge_descriptor, 0);
            failures += expect_result(
                "hugetlb-source-map",
                (long)huge_source < 0 ? (long)huge_source : 0, 0);
            huge_minor = (unsigned char *)raw_syscall6(
                SYS_mmap, 0, HUGE_PAGE_SIZE,
                PROT_READ | PROT_WRITE, MAP_SHARED,
                huge_descriptor, 0);
            failures += expect_result(
                "hugetlb-minor-map",
                (long)huge_minor < 0 ? (long)huge_minor : 0, 0);
        }
        if ((long)huge_source >= 0 && (long)huge_minor >= 0) {
            struct uffdio_continue continuation;

            if (((uintptr_t)huge_source | (uintptr_t)huge_minor) &
                (HUGE_PAGE_SIZE - 1u)) {
                print_text("FAIL hugetlb-map-alignment\n");
                ++failures;
            }
            huge_source[83] = 0x7bu;
            registration.range.start =
                (uint64_t)(uintptr_t)huge_minor;
            registration.range.len = HUGE_PAGE_SIZE;
            registration.mode = UFFDIO_REGISTER_MODE_MINOR;
            registration.ioctls = 0;
            failures += expect_result(
                "hugetlb-minor-register", raw_syscall6(
                    SYS_ioctl, descriptor, UFFDIO_REGISTER,
                    (long)&registration, 0, 0, 0), 0);
            if (!(registration.ioctls & (1ULL << 7)) ||
                (registration.ioctls & (1ULL << 4))) {
                print_text("FAIL hugetlb-minor-register-ioctls\n");
                ++failures;
            }
            g_fault_address = huge_minor + 83u;
            g_fault_value = 0;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                long received = -EAGAIN;
                int child_status = -1;

                failures += expect_result(
                    "hugetlb-minor-child", child < 0 ? child : 0, 0);
                if (child >= 0) {
                    for (unsigned long attempt = 0;
                         attempt < 100000u; ++attempt) {
                        received = raw_syscall6(
                            SYS_read, descriptor, (long)&message,
                            sizeof(message), 0, 0, 0);
                        if (received != -EAGAIN) break;
                        (void)raw_syscall6(
                            SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                    }
                    failures += expect_result(
                        "hugetlb-minor-event-size", received,
                        sizeof(message));
                    if (received == (long)sizeof(message) &&
                        (message.event != UFFD_EVENT_PAGEFAULT ||
                         message.flags != UFFD_PAGEFAULT_FLAG_MINOR ||
                         message.thread_id != (uint32_t)child ||
                         message.address !=
                            (uint64_t)(uintptr_t)g_fault_address)) {
                        print_text("FAIL hugetlb-minor-event-data\n");
                        ++failures;
                    }
                    if (received == (long)sizeof(message)) {
                        continuation.range = registration.range;
                        continuation.mode = 0;
                        continuation.mapped = 0;
                        failures += expect_result(
                            "hugetlb-minor-continue", raw_syscall6(
                                SYS_ioctl, descriptor, UFFDIO_CONTINUE,
                                (long)&continuation, 0, 0, 0), 0);
                        failures += expect_result(
                            "hugetlb-minor-continue-count",
                            continuation.mapped, HUGE_PAGE_SIZE);
                        continuation.mapped = 0;
                        failures += expect_result(
                            "hugetlb-minor-continue-existing",
                            raw_syscall6(
                                SYS_ioctl, descriptor, UFFDIO_CONTINUE,
                                (long)&continuation, 0, 0, 0),
                            -EEXIST);
                        failures += expect_result(
                            "hugetlb-minor-continue-existing-count",
                            continuation.mapped, -EEXIST);
                    } else {
                        (void)raw_syscall6(
                            SYS_kill, child, SIGKILL, 0, 0, 0, 0);
                    }
                    failures += expect_result(
                        "hugetlb-minor-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "hugetlb-minor-child-status", child_status, 0);
                    failures += expect_result(
                        "hugetlb-minor-child-value",
                        g_fault_value, 0x7b);
                }
            }
            failures += expect_result(
                "hugetlb-minor-unregister", raw_syscall6(
                    SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
                    (long)&registration.range, 0, 0, 0), 0);
        }
        if (huge_descriptor >= 0) {
            static const char huge_missing_name[] =
                "uffd-hugetlb-missing";
            long missing_descriptor = raw_syscall6(
                SYS_memfd_create, (long)huge_missing_name,
                MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_2MB,
                0, 0, 0, 0);
            unsigned char *huge_missing =
                (unsigned char *)(uintptr_t)-1;

            failures += expect_result(
                "hugetlb-missing-create",
                missing_descriptor < 0 ? missing_descriptor : 0, 0);
            if (missing_descriptor >= 0) {
                failures += expect_result(
                    "hugetlb-missing-size", raw_syscall6(
                        SYS_ftruncate, missing_descriptor,
                        HUGE_PAGE_SIZE, 0, 0, 0, 0), 0);
                huge_missing = (unsigned char *)raw_syscall6(
                    SYS_mmap, 0, HUGE_PAGE_SIZE,
                    PROT_READ | PROT_WRITE, MAP_SHARED,
                    missing_descriptor, 0);
                failures += expect_result(
                    "hugetlb-missing-map",
                    (long)huge_missing < 0 ?
                        (long)huge_missing : 0, 0);
            }
            huge_copy_source = (unsigned char *)raw_syscall6(
                SYS_mmap, 0, HUGE_PAGE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            failures += expect_result(
                "hugetlb-copy-source-map",
                (long)huge_copy_source < 0 ?
                    (long)huge_copy_source : 0, 0);
            if ((long)huge_missing >= 0 &&
                (long)huge_copy_source >= 0) {
                huge_copy_source[91] = 0x5au;
                registration.range.start =
                    (uint64_t)(uintptr_t)huge_missing;
                registration.range.len = HUGE_PAGE_SIZE;
                registration.mode = UFFDIO_REGISTER_MODE_MISSING;
                registration.ioctls = 0;
                failures += expect_result(
                    "hugetlb-missing-register", raw_syscall6(
                        SYS_ioctl, descriptor, UFFDIO_REGISTER,
                        (long)&registration, 0, 0, 0), 0);
                if (!(registration.ioctls & (1ULL << 3)) ||
                    (registration.ioctls & (1ULL << 4))) {
                    print_text(
                        "FAIL hugetlb-missing-register-ioctls\n");
                    ++failures;
                }
                g_fault_address = huge_missing + 91u;
                g_fault_value = 0;
                {
                    long child = spawn_fault_child(
                        CLONE_VM | SIGCHLD,
                        &g_fault_stack[sizeof(g_fault_stack)]);
                    long received = -EAGAIN;
                    int child_status = -1;

                    failures += expect_result(
                        "hugetlb-missing-child",
                        child < 0 ? child : 0, 0);
                    if (child >= 0) {
                        for (unsigned long attempt = 0;
                             attempt < 100000u; ++attempt) {
                            received = raw_syscall6(
                                SYS_read, descriptor, (long)&message,
                                sizeof(message), 0, 0, 0);
                            if (received != -EAGAIN) break;
                            (void)raw_syscall6(
                                SYS_sched_yield,
                                0, 0, 0, 0, 0, 0);
                        }
                        failures += expect_result(
                            "hugetlb-missing-event-size", received,
                            sizeof(message));
                        if (received == (long)sizeof(message) &&
                            (message.event != UFFD_EVENT_PAGEFAULT ||
                             message.flags != 0 ||
                             message.thread_id != (uint32_t)child ||
                             message.address !=
                                (uint64_t)(uintptr_t)g_fault_address)) {
                            print_text(
                                "FAIL hugetlb-missing-event-data\n");
                            ++failures;
                        }
                        if (received == (long)sizeof(message)) {
                            copy.dst = registration.range.start;
                            copy.src =
                                (uint64_t)(uintptr_t)huge_copy_source;
                            copy.len = HUGE_PAGE_SIZE;
                            copy.mode = 0;
                            copy.copy = 0;
                            failures += expect_result(
                                "hugetlb-missing-copy", raw_syscall6(
                                    SYS_ioctl, descriptor, UFFDIO_COPY,
                                    (long)&copy, 0, 0, 0), 0);
                            failures += expect_result(
                                "hugetlb-missing-copy-count",
                                copy.copy, HUGE_PAGE_SIZE);
                        } else {
                            (void)raw_syscall6(
                                SYS_kill, child, SIGKILL,
                                0, 0, 0, 0);
                        }
                        failures += expect_result(
                            "hugetlb-missing-wait", raw_syscall6(
                                SYS_wait4, child,
                                (long)&child_status,
                                0, 0, 0, 0), child);
                        failures += expect_result(
                            "hugetlb-missing-child-status",
                            child_status, 0);
                        failures += expect_result(
                            "hugetlb-missing-child-value",
                            g_fault_value, 0x5a);
                    }
                }
                failures += expect_result(
                    "hugetlb-missing-unregister", raw_syscall6(
                        SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
                        (long)&registration.range, 0, 0, 0), 0);
            }
            if ((long)huge_missing >= 0)
                (void)raw_syscall6(
                    SYS_munmap, (long)huge_missing,
                    HUGE_PAGE_SIZE, 0, 0, 0, 0);
            if (missing_descriptor >= 0)
                (void)raw_syscall6(
                    SYS_close, missing_descriptor,
                    0, 0, 0, 0, 0);
        }
        if ((long)huge_source >= 0)
            (void)raw_syscall6(
                SYS_munmap, (long)huge_source, HUGE_PAGE_SIZE,
                0, 0, 0, 0);
        if ((long)huge_minor >= 0)
            (void)raw_syscall6(
                SYS_munmap, (long)huge_minor, HUGE_PAGE_SIZE,
                0, 0, 0, 0);
        if ((long)huge_copy_source >= 0)
            (void)raw_syscall6(
                SYS_munmap, (long)huge_copy_source,
                HUGE_PAGE_SIZE, 0, 0, 0, 0);
        if (huge_descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, huge_descriptor, 0, 0, 0, 0, 0);
    }

    registration.range.start =
        (uint64_t)(uintptr_t)(move_area + PAGE_SIZE);
    registration.range.len = PAGE_SIZE * 2u;
    registration.mode = UFFDIO_REGISTER_MODE_MISSING;
    registration.ioctls = 0;
    failures += expect_result(
        "move-register", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_REGISTER,
            (long)&registration, 0, 0, 0), 0);
    if (!(registration.ioctls & (1ULL << 5))) {
        print_text("FAIL move-register-ioctls\n");
        ++failures;
    }
    move.dst = (uint64_t)(uintptr_t)(move_area + PAGE_SIZE);
    move.src = (uint64_t)(uintptr_t)(move_area + 1u);
    move.len = PAGE_SIZE;
    move.mode = 0;
    move.move = 0;
    failures += expect_result(
        "move-unaligned-source", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_MOVE,
            (long)&move, 0, 0, 0), -EINVAL);
    move.dst = (uint64_t)(uintptr_t)(move_area + PAGE_SIZE);
    move.src = (uint64_t)(uintptr_t)move_area;
    move.len = PAGE_SIZE;
    move.mode = 0;
    move.move = 0;
    failures += expect_result(
        "move", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_MOVE,
            (long)&move, 0, 0, 0), 0);
    failures += expect_result("move-count", move.move, PAGE_SIZE);
    failures += expect_result(
        "move-data", move_area[PAGE_SIZE], 0x6d);
    move.dst = (uint64_t)(uintptr_t)(move_area + PAGE_SIZE * 2u);
    move.src = (uint64_t)(uintptr_t)move_area;
    move.move = 0;
    failures += expect_result(
        "move-source-hole", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_MOVE,
            (long)&move, 0, 0, 0), -ENOENT);
    failures += expect_result("move-source-hole-result", move.move, -ENOENT);
    failures += expect_result(
        "move-unregister", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
            (long)&registration.range, 0, 0, 0), 0);

    registration.range.start = (uint64_t)(uintptr_t)poison_area;
    registration.range.len = PAGE_SIZE * 2u;
    registration.mode = UFFDIO_REGISTER_MODE_MISSING;
    registration.ioctls = 0;
    failures += expect_result(
        "poison-register", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_REGISTER,
            (long)&registration, 0, 0, 0), 0);
    if (!(registration.ioctls & (1ULL << 8))) {
        print_text("FAIL poison-register-ioctls\n");
        ++failures;
    }
    poison.range.start = (uint64_t)(uintptr_t)poison_area;
    poison.range.len = PAGE_SIZE;
    poison.mode = 2u;
    poison.updated = 123;
    failures += expect_result(
        "poison-invalid-mode", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_POISON,
            (long)&poison, 0, 0, 0), -EINVAL);
    poison.mode = UFFDIO_POISON_MODE_DONTWAKE;
    poison.updated = 0;
    failures += expect_result(
        "poison", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_POISON,
            (long)&poison, 0, 0, 0), 0);
    failures += expect_result("poison-count", poison.updated, PAGE_SIZE);
    poison.updated = 0;
    failures += expect_result(
        "poison-existing", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_POISON,
            (long)&poison, 0, 0, 0), -EEXIST);
    failures += expect_result(
        "poison-existing-result", poison.updated, -EEXIST);
    failures += expect_result(
        "poison-unregister", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
            (long)&registration.range, 0, 0, 0), 0);
    g_fault_address = poison_area;
    g_fault_write = 0;
    {
        long child = spawn_fault_child(
            CLONE_VM | SIGCHLD,
            &g_fault_stack[sizeof(g_fault_stack)]);
        int child_status = -1;

        if (child < 0) {
            failures += expect_result("poison-child", child, 0);
        } else {
            failures += expect_result(
                "poison-wait", raw_syscall6(
                    SYS_wait4, child, (long)&child_status,
                    0, 0, 0, 0), child);
            if ((child_status & 0x7f) != SIGBUS) {
                print_text("FAIL poison-child-signal expected=");
                print_number(SIGBUS);
                print_text(" actual=");
                print_number(child_status & 0x7f);
                print_text("\n");
                ++failures;
            }
        }
    }
    {
        long child = spawn_fault_child(
            SIGCHLD, &g_fault_stack[sizeof(g_fault_stack)]);
        int child_status = -1;

        if (child < 0) {
            failures += expect_result("poison-fork-child", child, 0);
        } else {
            failures += expect_result(
                "poison-fork-wait", raw_syscall6(
                    SYS_wait4, child, (long)&child_status,
                    0, 0, 0, 0), child);
            if ((child_status & 0x7f) != SIGBUS) {
                print_text("FAIL poison-fork-signal expected=");
                print_number(SIGBUS);
                print_text(" actual=");
                print_number(child_status & 0x7f);
                print_text("\n");
                ++failures;
            }
        }
    }
    failures += expect_result(
        "poison-empty-read", raw_syscall6(
            SYS_read, descriptor, (long)&message,
            sizeof(message), 0, 0, 0), -EAGAIN);
    failures += expect_result(
        "poison-munmap", raw_syscall6(
            SYS_munmap, (long)poison_area, PAGE_SIZE * 2u,
            0, 0, 0, 0), 0);
    {
        long remapped = raw_syscall6(
            SYS_mmap, (long)poison_area, PAGE_SIZE * 2u,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        failures += expect_result(
            "poison-remap", remapped, (long)poison_area);
        if (remapped == (long)poison_area) {
            poison_area[0] = 0x39u;
            failures += expect_result(
                "poison-remap-data", poison_area[0], 0x39u);
        }
    }

    registration.range.start = (uint64_t)(uintptr_t)destination;
    registration.range.len = PAGE_SIZE;
    registration.mode = UFFDIO_REGISTER_MODE_WP;
    registration.ioctls = 0;
    failures += expect_result(
        "wp-register", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_REGISTER,
            (long)&registration, 0, 0, 0), 0);
    if (!(registration.ioctls & (1ULL << 6))) {
        print_text("FAIL wp-register-ioctls\n");
        ++failures;
    }
    writeprotect.range = registration.range;
    writeprotect.mode = UFFDIO_WRITEPROTECT_MODE_WP |
                        UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
    failures += expect_result(
        "writeprotect-enable-dontwake", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_WRITEPROTECT,
            (long)&writeprotect, 0, 0, 0), -EINVAL);
    writeprotect.mode = UFFDIO_WRITEPROTECT_MODE_WP;
    failures += expect_result(
        "writeprotect-enable", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_WRITEPROTECT,
            (long)&writeprotect, 0, 0, 0), 0);
    g_fault_address = destination;
    g_fault_write = 0x5au;
    {
        long child = spawn_fault_child(
            CLONE_VM | SIGCHLD,
            &g_fault_stack[sizeof(g_fault_stack)]);
        long received = -EAGAIN;
        int child_status = -1;

        if (child < 0) {
            failures += expect_result("wp-child", child, 0);
        } else {
            for (unsigned long attempt = 0; attempt < 100000u; ++attempt) {
                received = raw_syscall6(
                    SYS_read, descriptor, (long)&message,
                    sizeof(message), 0, 0, 0);
                if (received != -EAGAIN) break;
                (void)raw_syscall6(
                    SYS_sched_yield, 0, 0, 0, 0, 0, 0);
            }
            failures += expect_result(
                "wp-event-size", received, sizeof(message));
            if (received == (long)sizeof(message) &&
                (message.event != UFFD_EVENT_PAGEFAULT ||
                 message.flags !=
                    (UFFD_PAGEFAULT_FLAG_WRITE |
                     UFFD_PAGEFAULT_FLAG_WP) ||
                 message.thread_id != (uint32_t)child ||
                 message.address !=
                    ((uint64_t)(uintptr_t)g_fault_address &
                     ~(uint64_t)(PAGE_SIZE - 1u)))) {
                print_text("FAIL wp-event-data\n");
                ++failures;
            }
            writeprotect.mode = 0;
            failures += expect_result(
                "writeprotect-disable", raw_syscall6(
                    SYS_ioctl, descriptor, UFFDIO_WRITEPROTECT,
                    (long)&writeprotect, 0, 0, 0), 0);
            if (received != (long)sizeof(message))
                (void)raw_syscall6(
                    SYS_kill, child, SIGKILL, 0, 0, 0, 0);
            failures += expect_result(
                "wp-wait", raw_syscall6(
                    SYS_wait4, child, (long)&child_status,
                    0, 0, 0, 0), child);
            failures += expect_result("wp-child-status", child_status, 0);
            failures += expect_result("wp-write", destination[0], 0x5a);
        }
    }
    g_fault_write = 0;
    failures += expect_result(
        "wp-unregister", raw_syscall6(
            SYS_ioctl, descriptor, UFFDIO_UNREGISTER,
            (long)&registration.range, 0, 0, 0), 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

    {
        unsigned char *async_area = (unsigned char *)raw_syscall6(
            SYS_mmap, 0, PAGE_SIZE * 2u, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        long async_descriptor = raw_syscall6(
            SYS_userfaultfd,
            O_NONBLOCK | O_CLOEXEC | UFFD_USER_MODE_ONLY,
            0, 0, 0, 0, 0);
        struct uffdio_api async_api = {
            .api = UFFD_API,
            .features = UFFD_FEATURE_WP_ASYNC,
        };

        if ((long)async_area < 0 || async_descriptor < 0) {
            print_text("FAIL wp-async-setup\n");
            ++failures;
        } else {
            async_area[0] = 0x11u;
            failures += expect_result(
                "wp-async-api", raw_syscall6(
                    SYS_ioctl, async_descriptor, UFFDIO_API,
                    (long)&async_api, 0, 0, 0), 0);
            if ((async_api.features &
                 (UFFD_FEATURE_WP_ASYNC |
                  UFFD_FEATURE_WP_UNPOPULATED)) !=
                (UFFD_FEATURE_WP_ASYNC |
                 UFFD_FEATURE_WP_UNPOPULATED)) {
                print_text("FAIL wp-async-features\n");
                ++failures;
            }
            registration.range.start =
                (uint64_t)(uintptr_t)async_area;
            registration.range.len = PAGE_SIZE * 2u;
            registration.mode = UFFDIO_REGISTER_MODE_WP;
            registration.ioctls = 0;
            failures += expect_result(
                "wp-async-register", raw_syscall6(
                    SYS_ioctl, async_descriptor, UFFDIO_REGISTER,
                    (long)&registration, 0, 0, 0), 0);
            writeprotect.range = registration.range;
            writeprotect.mode = UFFDIO_WRITEPROTECT_MODE_WP;
            failures += expect_result(
                "wp-async-enable", raw_syscall6(
                    SYS_ioctl, async_descriptor, UFFDIO_WRITEPROTECT,
                    (long)&writeprotect, 0, 0, 0), 0);
            g_fault_address = async_area;
            g_fault_write = 0x62u;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                int child_status = -1;
                failures += expect_result(
                    "wp-async-resident-child", child < 0 ? child : 0, 0);
                if (child >= 0) {
                    failures += expect_result(
                        "wp-async-resident-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "wp-async-resident-status", child_status, 0);
                    failures += expect_result(
                        "wp-async-resident-value", async_area[0], 0x62);
                }
            }
            failures += expect_result(
                "wp-async-resident-event", raw_syscall6(
                    SYS_read, async_descriptor, (long)&message,
                    sizeof(message), 0, 0, 0), -EAGAIN);
            g_fault_address = async_area + PAGE_SIZE + 17u;
            g_fault_write = 0x73u;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                int child_status = -1;
                failures += expect_result(
                    "wp-async-unpopulated-child",
                    child < 0 ? child : 0, 0);
                if (child >= 0) {
                    failures += expect_result(
                        "wp-async-unpopulated-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "wp-async-unpopulated-status", child_status, 0);
                    failures += expect_result(
                        "wp-async-unpopulated-value",
                        async_area[PAGE_SIZE + 17u], 0x73);
                }
            }
            failures += expect_result(
                "wp-async-unpopulated-event", raw_syscall6(
                    SYS_read, async_descriptor, (long)&message,
                    sizeof(message), 0, 0, 0), -EAGAIN);
            g_fault_write = 0;
        }
        if (async_descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, async_descriptor, 0, 0, 0, 0, 0);
        if ((long)async_area > 0)
            (void)raw_syscall6(
                SYS_munmap, (long)async_area, PAGE_SIZE * 2u,
                0, 0, 0, 0);
    }

    {
        unsigned char *sigbus_area = (unsigned char *)raw_syscall6(
            SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        long sigbus_descriptor = raw_syscall6(
            SYS_userfaultfd,
            O_NONBLOCK | O_CLOEXEC | UFFD_USER_MODE_ONLY,
            0, 0, 0, 0, 0);
        struct uffdio_api sigbus_api = {
            .api = UFFD_API,
            .features = UFFD_FEATURE_SIGBUS,
        };

        if ((long)sigbus_area < 0 || sigbus_descriptor < 0) {
            print_text("FAIL sigbus-setup\n");
            ++failures;
            if (sigbus_descriptor >= 0)
                (void)raw_syscall6(
                    SYS_close, sigbus_descriptor, 0, 0, 0, 0, 0);
        } else {
            failures += expect_result(
                "sigbus-api", raw_syscall6(
                    SYS_ioctl, sigbus_descriptor, UFFDIO_API,
                    (long)&sigbus_api, 0, 0, 0), 0);
            registration.range.start =
                (uint64_t)(uintptr_t)sigbus_area;
            registration.range.len = PAGE_SIZE;
            registration.mode = UFFDIO_REGISTER_MODE_MISSING;
            registration.ioctls = 0;
            failures += expect_result(
                "sigbus-register", raw_syscall6(
                    SYS_ioctl, sigbus_descriptor, UFFDIO_REGISTER,
                    (long)&registration, 0, 0, 0), 0);
            g_fault_address = sigbus_area + 91u;
            g_fault_write = 0;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                int child_status = -1;

                if (child < 0) {
                    failures += expect_result(
                        "sigbus-child", child, 0);
                } else {
                    failures += expect_result(
                        "sigbus-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    if ((child_status & 0x7f) != SIGBUS) {
                        print_text("FAIL sigbus-child-signal expected=");
                        print_number(SIGBUS);
                        print_text(" actual=");
                        print_number(child_status & 0x7f);
                        print_text("\n");
                        ++failures;
                    }
                }
            }
            failures += expect_result(
                "sigbus-empty-read", raw_syscall6(
                    SYS_read, sigbus_descriptor, (long)&message,
                    sizeof(message), 0, 0, 0), -EAGAIN);
            failures += expect_result(
                "sigbus-map-fixed", raw_syscall6(
                    SYS_mmap, (long)sigbus_area, PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1, 0), (long)sigbus_area);
            g_fault_address = sigbus_area + 91u;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                int child_status = -1;
                failures += expect_result(
                    "sigbus-map-fixed-child", child < 0 ? child : 0, 0);
                if (child >= 0) {
                    failures += expect_result(
                        "sigbus-map-fixed-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "sigbus-map-fixed-status", child_status, 0);
                }
            }
            registration.range.start =
                (uint64_t)(uintptr_t)sigbus_area;
            registration.range.len = PAGE_SIZE;
            registration.mode = UFFDIO_REGISTER_MODE_MISSING;
            registration.ioctls = 0;
            failures += expect_result(
                "sigbus-reregister", raw_syscall6(
                    SYS_ioctl, sigbus_descriptor, UFFDIO_REGISTER,
                    (long)&registration, 0, 0, 0), 0);
            failures += expect_result(
                "sigbus-munmap", raw_syscall6(
                    SYS_munmap, (long)sigbus_area, PAGE_SIZE,
                    0, 0, 0, 0), 0);
            failures += expect_result(
                "sigbus-remap-same", raw_syscall6(
                    SYS_mmap, (long)sigbus_area, PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1, 0), (long)sigbus_area);
            g_fault_address = sigbus_area + 91u;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                int child_status = -1;
                failures += expect_result(
                    "sigbus-unmap-child", child < 0 ? child : 0, 0);
                if (child >= 0) {
                    failures += expect_result(
                        "sigbus-unmap-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "sigbus-unmap-status", child_status, 0);
                }
            }
            {
                unsigned char *remap_target =
                    (unsigned char *)raw_syscall6(
                        SYS_mmap, 0, PAGE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if ((long)remap_target < 0) {
                    print_text("FAIL sigbus-mremap-target\n");
                    ++failures;
                } else {
                    registration.range.start =
                        (uint64_t)(uintptr_t)sigbus_area;
                    registration.range.len = PAGE_SIZE;
                    registration.mode = UFFDIO_REGISTER_MODE_MISSING;
                    registration.ioctls = 0;
                    failures += expect_result(
                        "sigbus-mremap-register", raw_syscall6(
                            SYS_ioctl, sigbus_descriptor,
                            UFFDIO_REGISTER, (long)&registration,
                            0, 0, 0), 0);
                    failures += expect_result(
                        "sigbus-mremap", raw_syscall6(
                            SYS_mremap, (long)sigbus_area, PAGE_SIZE,
                            PAGE_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED,
                            (long)remap_target, 0),
                        (long)remap_target);
                    sigbus_area = remap_target;
                    g_fault_address = sigbus_area + 91u;
                    {
                        long child = spawn_fault_child(
                            CLONE_VM | SIGCHLD,
                            &g_fault_stack[sizeof(g_fault_stack)]);
                        int child_status = -1;
                        failures += expect_result(
                            "sigbus-mremap-child",
                            child < 0 ? child : 0, 0);
                        if (child >= 0) {
                            failures += expect_result(
                                "sigbus-mremap-wait", raw_syscall6(
                                    SYS_wait4, child,
                                    (long)&child_status,
                                    0, 0, 0, 0), child);
                            failures += expect_result(
                                "sigbus-mremap-status",
                                child_status, 0);
                        }
                    }
                }
            }
            (void)raw_syscall6(
                SYS_close, sigbus_descriptor, 0, 0, 0, 0, 0);
        }
        if ((long)sigbus_area > 0)
            (void)raw_syscall6(
                SYS_munmap, (long)sigbus_area, PAGE_SIZE,
                0, 0, 0, 0);
    }

    {
        unsigned char *event_area = (unsigned char *)raw_syscall6(
            SYS_mmap, 0, PAGE_SIZE * 2u, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        long event_descriptor = raw_syscall6(
            SYS_userfaultfd,
            O_NONBLOCK | O_CLOEXEC | UFFD_USER_MODE_ONLY,
            0, 0, 0, 0, 0);
        struct uffdio_api event_api = {
            .api = UFFD_API,
            .features = UFFD_FEATURE_EVENT_REMAP |
                        UFFD_FEATURE_EVENT_REMOVE |
                        UFFD_FEATURE_EVENT_UNMAP,
        };

        if ((long)event_area < 0 || event_descriptor < 0) {
            print_text("FAIL mapping-event-setup\n");
            ++failures;
        } else {
            failures += expect_result(
                "mapping-event-api", raw_syscall6(
                    SYS_ioctl, event_descriptor, UFFDIO_API,
                    (long)&event_api, 0, 0, 0), 0);
            if ((event_api.features &
                 (UFFD_FEATURE_EVENT_REMAP |
                  UFFD_FEATURE_EVENT_REMOVE |
                  UFFD_FEATURE_EVENT_UNMAP)) !=
                (UFFD_FEATURE_EVENT_REMAP |
                 UFFD_FEATURE_EVENT_REMOVE |
                 UFFD_FEATURE_EVENT_UNMAP)) {
                print_text("FAIL mapping-event-features\n");
                ++failures;
            }
            registration.range.start =
                (uint64_t)(uintptr_t)event_area;
            registration.range.len = PAGE_SIZE * 2u;
            registration.mode = UFFDIO_REGISTER_MODE_MISSING;
            registration.ioctls = 0;
            failures += expect_result(
                "mapping-event-register", raw_syscall6(
                    SYS_ioctl, event_descriptor, UFFDIO_REGISTER,
                    (long)&registration, 0, 0, 0), 0);
            {
                unsigned char *remap_source = event_area;
                unsigned char *remap_target =
                    (unsigned char *)raw_syscall6(
                        SYS_mmap, 0, PAGE_SIZE * 3u,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                long target_unmap = (long)remap_target < 0 ?
                    (long)remap_target : raw_syscall6(
                        SYS_munmap, (long)remap_target,
                        PAGE_SIZE * 3u, 0, 0, 0, 0);

                failures += expect_result(
                    "mapping-event-remap-target", target_unmap, 0);
                if ((long)remap_target >= 0 && target_unmap == 0) {
                    long child;
                    long received = -EAGAIN;
                    int child_status = -1;

                    g_fault_address = remap_source;
                    g_child_length = PAGE_SIZE * 2u;
                    g_child_target = (unsigned long)remap_target;
                    g_child_result = -EAGAIN;
                    g_child_operation = 3u;
                    child = spawn_fault_child(
                        CLONE_VM | SIGCHLD,
                        &g_fault_stack[sizeof(g_fault_stack)]);
                    failures += expect_result(
                        "mapping-event-remap-child",
                        child < 0 ? child : 0, 0);
                    if (child >= 0) {
                        failures += expect_result(
                            "mapping-event-remap-blocked", raw_syscall6(
                                SYS_wait4, child, (long)&child_status,
                                WNOHANG, 0, 0, 0), 0);
                        for (unsigned long attempt = 0;
                             attempt < 100000u; ++attempt) {
                            received = raw_syscall6(
                                SYS_read, event_descriptor,
                                (long)&message, sizeof(message),
                                0, 0, 0);
                            if (received != -EAGAIN) break;
                            (void)raw_syscall6(
                                SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                        }
                        failures += expect_result(
                            "mapping-event-remap-read", received,
                            sizeof(message));
                        if (received == (long)sizeof(message) &&
                            (message.event != UFFD_EVENT_REMAP ||
                             message.flags !=
                                (uint64_t)(uintptr_t)remap_source ||
                             message.address !=
                                (uint64_t)(uintptr_t)remap_target ||
                             message.length != PAGE_SIZE * 2u)) {
                            print_text("FAIL mapping-event-remap-data\n");
                            ++failures;
                        }
                        received = -EAGAIN;
                        for (unsigned long attempt = 0;
                             attempt < 100000u; ++attempt) {
                            received = raw_syscall6(
                                SYS_read, event_descriptor,
                                (long)&message, sizeof(message),
                                0, 0, 0);
                            if (received != -EAGAIN) break;
                            (void)raw_syscall6(
                                SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                        }
                        failures += expect_result(
                            "mapping-event-remap-unmap-read", received,
                            sizeof(message));
                        if (received == (long)sizeof(message) &&
                            (message.event != UFFD_EVENT_UNMAP ||
                             message.flags !=
                                (uint64_t)(uintptr_t)remap_source ||
                             message.address !=
                                (uint64_t)(uintptr_t)
                                    (remap_source + PAGE_SIZE * 2u))) {
                            print_text(
                                "FAIL mapping-event-remap-unmap-data\n");
                            ++failures;
                        }
                        failures += expect_result(
                            "mapping-event-remap-wait", raw_syscall6(
                                SYS_wait4, child, (long)&child_status,
                                0, 0, 0, 0), child);
                        failures += expect_result(
                            "mapping-event-remap-status", child_status, 0);
                        failures += expect_result(
                            "mapping-event-remap-result",
                            g_child_result, (long)remap_target);
                    }
                    g_child_operation = 0;
                    g_child_target = 0;
                    if (g_child_result == (long)remap_target)
                        event_area = remap_target;
                }
            }
            if (g_child_result == (long)event_area) {
                long expanded = raw_syscall6(
                    SYS_mremap, (long)event_area,
                    PAGE_SIZE * 2u, PAGE_SIZE * 3u,
                    0, 0, 0);

                failures += expect_result(
                    "mapping-event-expand", expanded, (long)event_area);
                failures += expect_result(
                    "mapping-event-expand-empty", raw_syscall6(
                        SYS_read, event_descriptor, (long)&message,
                        sizeof(message), 0, 0, 0), -EAGAIN);
                if (expanded == (long)event_area) {
                    long child;
                    long received = -EAGAIN;
                    int child_status = -1;

                    g_fault_address = event_area + PAGE_SIZE * 2u;
                    g_child_operation = 0;
                    child = spawn_fault_child(
                        CLONE_VM | SIGCHLD,
                        &g_fault_stack[sizeof(g_fault_stack)]);
                    failures += expect_result(
                        "mapping-event-expand-child",
                        child < 0 ? child : 0, 0);
                    if (child >= 0) {
                        for (unsigned long attempt = 0;
                             attempt < 100000u; ++attempt) {
                            received = raw_syscall6(
                                SYS_read, event_descriptor,
                                (long)&message, sizeof(message),
                                0, 0, 0);
                            if (received != -EAGAIN) break;
                            (void)raw_syscall6(
                                SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                        }
                        failures += expect_result(
                            "mapping-event-expand-read", received,
                            sizeof(message));
                        if (received == (long)sizeof(message) &&
                            (message.event != UFFD_EVENT_PAGEFAULT ||
                             message.address !=
                                (uint64_t)(uintptr_t)g_fault_address)) {
                            print_text(
                                "FAIL mapping-event-expand-data\n");
                            ++failures;
                        }
                        zero.range.start =
                            (uint64_t)(uintptr_t)g_fault_address;
                        zero.range.len = PAGE_SIZE;
                        zero.mode = 0;
                        zero.zeropage = 0;
                        failures += expect_result(
                            "mapping-event-expand-zero", raw_syscall6(
                                SYS_ioctl, event_descriptor,
                                UFFDIO_ZEROPAGE, (long)&zero,
                                0, 0, 0), 0);
                        failures += expect_result(
                            "mapping-event-expand-zero-count",
                            zero.zeropage, PAGE_SIZE);
                        failures += expect_result(
                            "mapping-event-expand-wait", raw_syscall6(
                                SYS_wait4, child, (long)&child_status,
                                0, 0, 0, 0), child);
                        failures += expect_result(
                            "mapping-event-expand-status",
                            child_status, 0);
                    }
                }
            }
            g_fault_address = event_area;
            g_child_length = PAGE_SIZE;
            g_child_result = -EAGAIN;
            g_child_operation = 1u;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                long received = -EAGAIN;
                int child_status = -1;

                failures += expect_result(
                    "mapping-event-remove-child",
                    child < 0 ? child : 0, 0);
                if (child >= 0) {
                    failures += expect_result(
                        "mapping-event-remove-blocked", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            WNOHANG, 0, 0, 0), 0);
                    for (unsigned long attempt = 0;
                         attempt < 100000u; ++attempt) {
                        received = raw_syscall6(
                            SYS_read, event_descriptor, (long)&message,
                            sizeof(message), 0, 0, 0);
                        if (received != -EAGAIN) break;
                        (void)raw_syscall6(
                            SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                    }
                    failures += expect_result(
                        "mapping-event-remove-read", received,
                        sizeof(message));
                    failures += expect_result(
                        "mapping-event-remove-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "mapping-event-remove-status", child_status, 0);
                    failures += expect_result(
                        "mapping-event-remove-result",
                        g_child_result, 0);
                }
            }
            g_child_operation = 0;
            if (message.event != UFFD_EVENT_REMOVE ||
                message.flags != (uint64_t)(uintptr_t)event_area ||
                message.address !=
                    (uint64_t)(uintptr_t)(event_area + PAGE_SIZE)) {
                print_text("FAIL mapping-event-remove-data\n");
                ++failures;
            }
            g_fault_address = event_area + PAGE_SIZE;
            g_child_length = PAGE_SIZE;
            g_child_result = -EAGAIN;
            g_child_operation = 2u;
            {
                long child = spawn_fault_child(
                    CLONE_VM | SIGCHLD,
                    &g_fault_stack[sizeof(g_fault_stack)]);
                long received = -EAGAIN;
                int child_status = -1;

                failures += expect_result(
                    "mapping-event-unmap-child",
                    child < 0 ? child : 0, 0);
                if (child >= 0) {
                    failures += expect_result(
                        "mapping-event-unmap-blocked", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            WNOHANG, 0, 0, 0), 0);
                    for (unsigned long attempt = 0;
                         attempt < 100000u; ++attempt) {
                        received = raw_syscall6(
                            SYS_read, event_descriptor, (long)&message,
                            sizeof(message), 0, 0, 0);
                        if (received != -EAGAIN) break;
                        (void)raw_syscall6(
                            SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                    }
                    failures += expect_result(
                        "mapping-event-unmap-read", received,
                        sizeof(message));
                    failures += expect_result(
                        "mapping-event-unmap-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "mapping-event-unmap-status", child_status, 0);
                    failures += expect_result(
                        "mapping-event-unmap-result",
                        g_child_result, 0);
                }
            }
            g_child_operation = 0;
            if (message.event != UFFD_EVENT_UNMAP ||
                message.flags !=
                    (uint64_t)(uintptr_t)(event_area + PAGE_SIZE) ||
                message.address !=
                    (uint64_t)(uintptr_t)(event_area + PAGE_SIZE * 2u)) {
                print_text("FAIL mapping-event-unmap-data\n");
                print_text("  event expected=");
                print_number(UFFD_EVENT_UNMAP);
                print_text(" actual=");
                print_number(message.event);
                print_text("\n  start expected=");
                print_number((long)(uintptr_t)(event_area + PAGE_SIZE));
                print_text(" actual=");
                print_number((long)message.flags);
                print_text("\n  end expected=");
                print_number((long)(uintptr_t)(event_area + PAGE_SIZE * 2u));
                print_text(" actual=");
                print_number((long)message.address);
                print_text("\n");
                ++failures;
            }
        }
        if (event_descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, event_descriptor, 0, 0, 0, 0, 0);
        if ((long)event_area > 0)
            (void)raw_syscall6(
                SYS_munmap, (long)event_area,
                event_descriptor >= 0 ? PAGE_SIZE * 3u : PAGE_SIZE * 2u,
                0, 0, 0, 0);
    }

    {
        unsigned char *fork_area = (unsigned char *)raw_syscall6(
            SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        long fork_descriptor = raw_syscall6(
            SYS_userfaultfd,
            O_NONBLOCK | O_CLOEXEC | UFFD_USER_MODE_ONLY,
            0, 0, 0, 0, 0);
        struct uffdio_api fork_api = {
            .api = UFFD_API,
            .features = UFFD_FEATURE_EVENT_FORK,
        };
        long handler = -1;
        long child = -1;
        int handler_status = -1;
        int child_status = -1;

        if ((long)fork_area < 0 || fork_descriptor < 0) {
            print_text("FAIL fork-event-setup\n");
            ++failures;
        } else {
            failures += expect_result(
                "fork-event-api", raw_syscall6(
                    SYS_ioctl, fork_descriptor, UFFDIO_API,
                    (long)&fork_api, 0, 0, 0), 0);
            if (!(fork_api.features & UFFD_FEATURE_EVENT_FORK)) {
                print_text("FAIL fork-event-feature\n");
                ++failures;
            }
            registration.range.start =
                (uint64_t)(uintptr_t)fork_area;
            registration.range.len = PAGE_SIZE;
            registration.mode = UFFDIO_REGISTER_MODE_MISSING;
            registration.ioctls = 0;
            failures += expect_result(
                "fork-event-register", raw_syscall6(
                    SYS_ioctl, fork_descriptor, UFFDIO_REGISTER,
                    (long)&registration, 0, 0, 0), 0);
            g_fork_area = fork_area;
            g_fork_parent_descriptor = fork_descriptor;
            g_fork_child_descriptor = -1;
            g_fork_handler_ready = 0;
            g_fork_event_result = 0;
            g_fork_fault_result = 0;
            g_fork_fault_received = 0;
            g_fork_fault_event = 0;
            g_fork_fault_address = 0;
            handler = spawn_fork_handler(
                CLONE_VM | SIGCHLD,
                &g_fork_handler_stack[sizeof(g_fork_handler_stack)]);
            failures += expect_result(
                "fork-event-handler", handler < 0 ? handler : 0, 0);
            if (handler >= 0) {
                for (unsigned long attempt = 0;
                     attempt < 1000000u && !g_fork_handler_ready;
                     ++attempt)
                    (void)raw_syscall6(
                        SYS_sched_yield, 0, 0, 0, 0, 0, 0);
                failures += expect_result(
                    "fork-event-handler-ready",
                    g_fork_handler_ready, 1);
                child = spawn_fork_fault_child(
                    SIGCHLD,
                    &g_fork_child_stack[sizeof(g_fork_child_stack)]);
                failures += expect_result(
                    "fork-event-child", child < 0 ? child : 0, 0);
                if (child >= 0) {
                    failures += expect_result(
                        "fork-event-handler-wait", raw_syscall6(
                            SYS_wait4, handler, (long)&handler_status,
                            0, 0, 0, 0), handler);
                    if (handler_status != 0)
                        (void)raw_syscall6(
                            SYS_kill, child, SIGKILL, 0, 0, 0, 0);
                    failures += expect_result(
                        "fork-event-child-wait", raw_syscall6(
                            SYS_wait4, child, (long)&child_status,
                            0, 0, 0, 0), child);
                    failures += expect_result(
                        "fork-event-child-status", child_status, 0);
                } else {
                    (void)raw_syscall6(
                        SYS_kill, handler, SIGKILL, 0, 0, 0, 0);
                    (void)raw_syscall6(
                        SYS_wait4, handler, (long)&handler_status,
                        0, 0, 0, 0);
                }
                failures += expect_result(
                    "fork-event-handler-status", handler_status, 0);
                failures += expect_result(
                    "fork-event-received", g_fork_event_result, 1);
                failures += expect_result(
                    "fork-event-child-fault", g_fork_fault_result, 1);
                failures += expect_result(
                    "fork-event-fault-size", g_fork_fault_received,
                    sizeof(message));
                failures += expect_result(
                    "fork-event-fault-kind", g_fork_fault_event,
                    UFFD_EVENT_PAGEFAULT);
                failures += expect_result(
                    "fork-event-fault-address",
                    (long)g_fork_fault_address,
                    (long)(uintptr_t)fork_area);
            }
        }
        if (g_fork_child_descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, g_fork_child_descriptor, 0, 0, 0, 0, 0);
        if (fork_descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, fork_descriptor, 0, 0, 0, 0, 0);
        if ((long)fork_area > 0)
            (void)raw_syscall6(
                SYS_munmap, (long)fork_area, PAGE_SIZE,
                0, 0, 0, 0);
    }

out:
    if ((long)source > 0)
        (void)raw_syscall6(SYS_munmap, (long)source, PAGE_SIZE, 0, 0, 0, 0);
    if ((long)destination > 0)
        (void)raw_syscall6(
            SYS_munmap, (long)destination, PAGE_SIZE * 3u, 0, 0, 0, 0);
    if ((long)move_area > 0)
        (void)raw_syscall6(
            SYS_munmap, (long)move_area, PAGE_SIZE * 3u, 0, 0, 0, 0);
    if ((long)poison_area > 0)
        (void)raw_syscall6(
            SYS_munmap, (long)poison_area, PAGE_SIZE * 2u, 0, 0, 0, 0);
    if (!failures) print_text("USERFAULTFD_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
