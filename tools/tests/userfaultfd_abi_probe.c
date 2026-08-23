/* SPDX-License-Identifier: MPL-2.0 */
/* Linux userfaultfd missing-page and write-protect ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mremap 25
#define SYS_ioctl 16
#define SYS_close 3
#define SYS_clone 56
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_sched_yield 24
#define SYS_exit 60
#define SYS_userfaultfd 323
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_mremap 216
#define SYS_ioctl 29
#define SYS_close 57
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_kill 129
#define SYS_sched_yield 124
#define SYS_exit 93
#define SYS_userfaultfd 282
#else
#error "userfaultfd_abi_probe requires a Linux 64-bit architecture"
#endif

#define PAGE_SIZE 4096u
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MREMAP_MAYMOVE 0x1
#define MREMAP_FIXED 0x2
#define O_NONBLOCK 0x800
#define O_CLOEXEC 0x80000
#define UFFD_USER_MODE_ONLY 0x1
#define UFFD_API 0xAAu
#define UFFD_FEATURE_PAGEFAULT_FLAG_WP (1ULL << 0)
#define UFFD_FEATURE_SIGBUS (1ULL << 7)
#define UFFD_FEATURE_THREAD_ID (1ULL << 8)
#define UFFD_FEATURE_EXACT_ADDRESS (1ULL << 11)
#define UFFD_FEATURE_WP_UNPOPULATED (1ULL << 13)
#define UFFD_FEATURE_POISON (1ULL << 14)
#define UFFD_FEATURE_WP_ASYNC (1ULL << 15)
#define UFFD_FEATURE_MOVE (1ULL << 16)
#define UFFDIO_REGISTER_MODE_MISSING 0x1u
#define UFFDIO_REGISTER_MODE_WP 0x2u
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
#define UFFDIO_POISON 0xc020aa08u
#define UFFD_EVENT_PAGEFAULT 0x12u
#define UFFD_PAGEFAULT_FLAG_WRITE (1ULL << 0)
#define UFFD_PAGEFAULT_FLAG_WP (1ULL << 1)
#define CLONE_VM 0x00000100u
#define SIGCHLD 17
#define SIGKILL 9
#define SIGBUS 7
#define EAGAIN 11
#define EEXIST 17
#define EINVAL 22
#define ENOENT 2

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
    uint64_t flags;
    uint64_t address;
    uint32_t thread_id;
    uint32_t reserved4;
};

static unsigned char g_fault_stack[16384] __attribute__((aligned(16)));
static volatile unsigned char *g_fault_address;
static volatile unsigned char g_fault_value;
static volatile unsigned char g_fault_write;

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
    if (g_fault_write)
        *g_fault_address = g_fault_write;
    else
        g_fault_value = *g_fault_address;
    __asm__ volatile("" ::: "memory");
    exit_now(0);
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
        "mov x29, xzr\n"
        "bl fault_child_entry\n"
        "brk #0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x29", "x30", "memory", "cc");
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
