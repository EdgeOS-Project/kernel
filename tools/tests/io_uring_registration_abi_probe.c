/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring per-ring registration ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_exit 60
#define SYS_write 1
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#else
#error "io_uring_registration_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_register 427

#define EFAULT 14
#define EINVAL 22
#define EOVERFLOW 75

#define IORING_REGISTER_FILES2 13u
#define IORING_UNREGISTER_FILES 3u
#define IORING_REGISTER_FILE_ALLOC_RANGE 25u
#define IORING_REGISTER_CLOCK 29u
#define IORING_RESOURCE_SPARSE (1u << 0)
#define CLOCK_MONOTONIC 1u
#define CLOCK_BOOTTIME 7u

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

struct io_uring_resource_register {
    uint32_t count;
    uint32_t flags;
    uint64_t reserved;
    uint64_t data;
    uint64_t tags;
};

struct io_uring_file_index_range {
    uint32_t offset;
    uint32_t length;
    uint64_t reserved;
};

struct io_uring_clock_register {
    uint32_t clock_id;
    uint32_t reserved[3];
};

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
    for (uint32_t index = 0; index < size; ++index) bytes[index] = 0;
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static int expect(long actual, long expected) {
    return actual == expected ? 0 : 1;
}

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_resource_register files;
    struct io_uring_file_index_range range;
    struct io_uring_clock_register clock;
    long ring;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 2, (long)&parameters, 0, 0, 0, 0);
    if (ring < 0) return 1;

    bytes_zero(&files, sizeof(files));
    files.count = 8u;
    files.flags = IORING_RESOURCE_SPARSE;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES2,
        (long)&files, sizeof(files), 0, 0), 0);

    bytes_zero(&range, sizeof(range));
    range.offset = 2u;
    range.length = 3u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILE_ALLOC_RANGE,
        (long)&range, 0, 0, 0), 0);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILE_ALLOC_RANGE,
        (long)&range, 1, 0, 0), -EINVAL);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILE_ALLOC_RANGE,
        0, 0, 0, 0), -EINVAL);
    range.offset = UINT32_MAX;
    range.length = 2u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILE_ALLOC_RANGE,
        (long)&range, 0, 0, 0), -EOVERFLOW);
    range.offset = 7u;
    range.length = 2u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILE_ALLOC_RANGE,
        (long)&range, 0, 0, 0), -EINVAL);
    range.offset = 1u;
    range.length = 1u;
    range.reserved = 1u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILE_ALLOC_RANGE,
        (long)&range, 0, 0, 0), -EINVAL);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILE_ALLOC_RANGE,
        1, 0, 0, 0), -EFAULT);

    bytes_zero(&clock, sizeof(clock));
    clock.clock_id = CLOCK_MONOTONIC;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_CLOCK,
        (long)&clock, 0, 0, 0), 0);
    clock.clock_id = CLOCK_BOOTTIME;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_CLOCK,
        (long)&clock, 0, 0, 0), 0);
    clock.clock_id = 0u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_CLOCK,
        (long)&clock, 0, 0, 0), -EINVAL);
    clock.clock_id = CLOCK_MONOTONIC;
    clock.reserved[1] = 1u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_CLOCK,
        (long)&clock, 0, 0, 0), -EINVAL);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_CLOCK,
        (long)&clock, 1, 0, 0), -EINVAL);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_CLOCK,
        0, 0, 0, 0), -EINVAL);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_CLOCK,
        1, 0, 0, 0), -EFAULT);

    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_FILES,
        0, 0, 0, 0), 0);
    (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int failures = run_probe();
    print_text(failures ?
        "IO_URING_REGISTRATION_ABI_PROBE_FAIL\n" :
        "IO_URING_REGISTRATION_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
