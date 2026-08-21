/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring registered-ring descriptor ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_exit 60
#define SYS_write 1
#define SYS_eventfd2 290
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_eventfd2 19
#else
#error "io_uring_registered_rings_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define EBADF 9
#define EBUSY 16
#define EINVAL 22
#define EOPNOTSUPP 95

#define IORING_ENTER_REGISTERED_RING (1u << 4)
#define IORING_REGISTER_PROBE 8u
#define IORING_REGISTER_RING_FDS 20u
#define IORING_UNREGISTER_RING_FDS 21u
#define IORING_REGISTER_USE_REGISTERED_RING (1u << 31)
#define IO_RINGFD_REG_MAX 16u

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

struct io_uring_resource_update {
    uint32_t offset;
    uint32_t reserved;
    uint64_t data;
};

struct io_uring_probe_op {
    uint8_t opcode;
    uint8_t reserved;
    uint16_t flags;
    uint32_t reserved2;
};

struct io_uring_probe {
    uint8_t last_opcode;
    uint8_t operation_count;
    uint16_t reserved;
    uint32_t reserved2[3];
    struct io_uring_probe_op operation;
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

static long print_text(const char *text) {
    return raw_syscall6(
        SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static void settle_console_output(void) {
    for (volatile uint32_t index = 0; index < 1000000u; ++index) {
#if defined(__x86_64__)
        __asm__ volatile("pause");
#else
        __asm__ volatile("yield");
#endif
    }
}

static int expect(long actual, long expected) {
    return actual == expected ? 0 : 1;
}

static long create_ring(void) {
    struct io_uring_params parameters;
    bytes_zero(&parameters, sizeof(parameters));
    return raw_syscall6(
        SYS_io_uring_setup, 2, (long)&parameters, 0, 0, 0, 0);
}

static int run_probe(void) {
    struct io_uring_resource_update update[2];
    struct io_uring_probe probe;
    long control_ring = create_ring();
    long target_ring = create_ring();
    long second_ring = -1;
    long eventfd = -1;
    uint32_t slot;
    int failures = 0;

    if (control_ring < 0 || target_ring < 0) return 1;

    bytes_zero(update, sizeof(update));
    update[0].offset = UINT32_MAX;
    update[0].data = (uint64_t)target_ring;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_REGISTER_RING_FDS,
        (long)update, 1, 0, 0), 1);
    slot = update[0].offset;
    failures += expect(slot < IO_RINGFD_REG_MAX, 1);
    (void)raw_syscall6(SYS_close, target_ring, 0, 0, 0, 0, 0);
    target_ring = -1;

    failures += expect(raw_syscall6(
        SYS_io_uring_enter, slot, 0, 0,
        IORING_ENTER_REGISTERED_RING, 0, 0), 0);
    bytes_zero(&probe, sizeof(probe));
    failures += expect(raw_syscall6(
        SYS_io_uring_register, slot,
        IORING_REGISTER_PROBE | IORING_REGISTER_USE_REGISTERED_RING,
        (long)&probe, 1, 0, 0), 0);

    update[0].offset = slot;
    update[0].data = 0u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_UNREGISTER_RING_FDS,
        (long)update, 1, 0, 0), 1);
    failures += expect(raw_syscall6(
        SYS_io_uring_enter, slot, 0, 0,
        IORING_ENTER_REGISTERED_RING, 0, 0), -EBADF);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_UNREGISTER_RING_FDS,
        (long)update, 1, 0, 0), 1);

    second_ring = create_ring();
    if (second_ring < 0) {
        failures = 1;
        goto close_descriptors;
    }
    update[0].offset = 7u;
    update[0].data = (uint64_t)second_ring;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_REGISTER_RING_FDS,
        (long)update, 1, 0, 0), 1);
    failures += expect(update[0].offset, 7u);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_REGISTER_RING_FDS,
        (long)update, 1, 0, 0), -EBUSY);

    update[0].offset = IO_RINGFD_REG_MAX;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_REGISTER_RING_FDS,
        (long)update, 1, 0, 0), -EINVAL);
    eventfd = raw_syscall6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    if (eventfd < 0) {
        failures = 1;
        goto unregister_second;
    }
    update[0].offset = UINT32_MAX;
    update[0].data = (uint64_t)eventfd;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_REGISTER_RING_FDS,
        (long)update, 1, 0, 0), -EOPNOTSUPP);

    update[0].offset = 8u;
    update[0].data = (uint64_t)second_ring;
    update[1].offset = 9u;
    update[1].reserved = 1u;
    update[1].data = (uint64_t)second_ring;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_REGISTER_RING_FDS,
        (long)update, 2, 0, 0), 1);
    update[0].data = 0u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_UNREGISTER_RING_FDS,
        (long)update, 1, 0, 0), 1);
    update[0].offset = 8u;
    update[0].reserved = 0u;
    update[0].data = 0u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_UNREGISTER_RING_FDS,
        (long)update, IO_RINGFD_REG_MAX + 1u, 0, 0), -EINVAL);

unregister_second:
    update[0].offset = 7u;
    update[0].reserved = 0u;
    update[0].data = 0u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, control_ring, IORING_UNREGISTER_RING_FDS,
        (long)update, 1, 0, 0), 1);

close_descriptors:
    if (eventfd >= 0)
        (void)raw_syscall6(SYS_close, eventfd, 0, 0, 0, 0, 0);
    if (second_ring >= 0)
        (void)raw_syscall6(SYS_close, second_ring, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, control_ring, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_probe();
    const char *result = failures ?
        "IO_URING_REGISTERED_RINGS_ABI_PROBE_FAIL\n" :
        "IO_URING_REGISTERED_RINGS_ABI_PROBE_PASS\n";
    settle_console_output();
    if (print_text(result) != (long)text_length(result)) ++failures;
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
