/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 user-provided io_uring parameter-region ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_write 1
#define SYS_mmap 9
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_mmap 222
#define SYS_exit 93
#else
#error "io_uring_user_region_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define EBUSY 16
#define EBADFD 77
#define EINVAL 22
#define ETIME 62

#define PAGE_SIZE 4096u
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1

#define IORING_SETUP_R_DISABLED (1u << 6)
#define IORING_ENTER_GETEVENTS (1u << 0)
#define IORING_ENTER_EXT_ARG (1u << 3)
#define IORING_ENTER_EXT_ARG_REG (1u << 6)
#define IORING_REGISTER_ENABLE_RINGS 12u
#define IORING_REGISTER_MEM_REGION 34u
#define IORING_MEM_REGION_REG_WAIT_ARG (1u << 0)
#define IORING_MEM_REGION_TYPE_USER (1u << 0)
#define IORING_MAP_OFF_PARAM_REGION 0x20000000ull
#define IORING_REG_WAIT_TS (1u << 0)

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
    uint32_t workqueue_descriptor;
    uint32_t reserved[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};

struct io_uring_region_desc {
    uint64_t user_address;
    uint64_t size;
    uint32_t flags;
    uint32_t id;
    uint64_t mmap_offset;
    uint64_t reserved[4];
};

struct io_uring_mem_region_reg {
    uint64_t region;
    uint64_t flags;
    uint64_t reserved[2];
};

struct io_uring_reg_wait {
    int64_t timeout_seconds;
    int64_t timeout_nanoseconds;
    uint32_t minimum_wait_microseconds;
    uint32_t flags;
    uint64_t signal_mask;
    uint32_t signal_mask_size;
    uint32_t padding[3];
    uint64_t padding2[2];
};

static uint8_t g_wait_page[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static int failures;

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

static void bytes_zero(void *destination, uint32_t size) {
    uint8_t *bytes = destination;
    for (uint32_t index = 0; index < size; ++index) bytes[index] = 0u;
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0u;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[32];
    uint32_t used = 0u;
    unsigned long magnitude;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[used++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    while (used) {
        char character = buffer[--used];
        (void)raw_syscall6(SYS_write, 1, (long)&character, 1, 0, 0, 0);
    }
}

static void check(const char *name, int condition) {
    if (condition) return;
    ++failures;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
}

static void check_result(const char *name, long result, long expected) {
    if (result == expected) return;
    ++failures;
    print_text("FAIL ");
    print_text(name);
    print_text(" result=");
    print_number(result);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
}

static void run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_region_desc region;
    struct io_uring_mem_region_reg registration;
    struct io_uring_reg_wait *wait =
        (struct io_uring_reg_wait *)(void *)g_wait_page;
    long descriptor;
    long mapping;

    bytes_zero(&parameters, sizeof(parameters));
    parameters.flags = IORING_SETUP_R_DISABLED;
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 2, (long)&parameters, 0, 0, 0, 0);
    check("setup", descriptor >= 0);
    if (descriptor < 0) return;

    bytes_zero(g_wait_page, PAGE_SIZE);
    bytes_zero(&region, sizeof(region));
    region.user_address = (uint64_t)(uintptr_t)g_wait_page;
    region.size = PAGE_SIZE;
    region.flags = IORING_MEM_REGION_TYPE_USER;
    bytes_zero(&registration, sizeof(registration));
    registration.region = (uint64_t)(uintptr_t)&region;
    registration.flags = IORING_MEM_REGION_REG_WAIT_ARG;
    check_result("register user region", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_MEM_REGION,
        (long)&registration, 1, 0, 0), 0);
    check("user region handback",
          region.user_address == (uint64_t)(uintptr_t)g_wait_page &&
          region.size == PAGE_SIZE &&
          region.flags == IORING_MEM_REGION_TYPE_USER &&
          region.mmap_offset == 0u);
    check_result("duplicate user region", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_MEM_REGION,
        (long)&registration, 1, 0, 0), -EBUSY);
    mapping = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, IORING_MAP_OFF_PARAM_REGION);
    check("user region cannot mmap", mapping == -EINVAL);

    bytes_zero(wait, sizeof(*wait));
    wait->timeout_nanoseconds = 1000000;
    wait->flags = IORING_REG_WAIT_TS;
    check_result("disabled enter", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 1,
        IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
            IORING_ENTER_EXT_ARG_REG,
        0, sizeof(*wait)), -EBADFD);
    check("enable", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_ENABLE_RINGS,
        0, 0, 0, 0) == 0);
    check_result("registered user wait", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 1,
        IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
            IORING_ENTER_EXT_ARG_REG,
        0, sizeof(*wait)), -ETIME);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    run_probe();
    if (!failures) print_text("IO_URING_USER_REGION_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
