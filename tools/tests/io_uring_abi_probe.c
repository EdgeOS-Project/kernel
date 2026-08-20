/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux io_uring ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define EINVAL 22
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_PROBE 8u
#define IO_URING_OP_SUPPORTED 1u
#define IORING_OP_NOP 0u
#define IORING_OP_READ 22u
#define IORING_OP_WRITE 23u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define PROBE_OPERATION_COUNT 65u

struct io_uring_sqe {
    uint8_t opcode;
    uint8_t flags;
    uint16_t ioprio;
    int32_t descriptor;
    uint64_t offset;
    uint64_t address;
    uint32_t length;
    uint32_t operation_flags;
    uint64_t user_data;
    uint16_t buffer_index;
    uint16_t personality;
    int32_t splice_descriptor;
    uint64_t address3;
    uint64_t reserved2;
};

struct io_uring_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
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
    uint32_t workqueue_descriptor;
    uint32_t reserved[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
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
    struct io_uring_probe_op operations[PROBE_OPERATION_COUNT];
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

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int run_tests(void) {
    struct io_uring_probe probe;
    struct io_uring_params parameters;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    volatile uint32_t *sq_head;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    void *sq_ring;
    void *cq_ring;
    long descriptor;
    int failures = 0;

    memset(&parameters, 0, sizeof(parameters));
    parameters.reserved[0] = 1;
    failures += expect("reject reserved setup field", raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0),
        -EINVAL);

    memset(&parameters, 0, sizeof(parameters));
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    failures += expect_true("setup", descriptor >= 0);
    if (descriptor < 0) return failures;
    failures += expect_true("ring entries",
        parameters.sq_entries >= 8 && parameters.cq_entries >= 8);
    failures += expect_true("ring offsets",
        parameters.sq_off.array >= 24 && parameters.cq_off.cqes >= 24);

    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    failures += expect_true("map SQ ring", sq_ring != 0);
    failures += expect_true("map CQ ring", cq_ring != 0);
    failures += expect_true("map SQEs", sqes != 0);
    if (!sq_ring || !cq_ring || !sqes) goto close_ring;

    sq_head = (volatile uint32_t *)((uint8_t *)sq_ring +
                                    parameters.sq_off.head);
    sq_tail = (volatile uint32_t *)((uint8_t *)sq_ring +
                                    parameters.sq_off.tail);
    sq_array = (volatile uint32_t *)((uint8_t *)sq_ring +
                                     parameters.sq_off.array);
    cq_head = (volatile uint32_t *)((uint8_t *)cq_ring +
                                    parameters.cq_off.head);
    cq_tail = (volatile uint32_t *)((uint8_t *)cq_ring +
                                    parameters.cq_off.tail);
    cqes = (struct io_uring_cqe *)((uint8_t *)cq_ring +
                                   parameters.cq_off.cqes);
    memset(&sqes[0], 0, sizeof(sqes[0]));
    sqes[0].opcode = IORING_OP_NOP;
    sqes[0].user_data = 0x454447454f535552ull;
    sq_array[0] = 0;
    __atomic_store_n(sq_tail, 1u, __ATOMIC_RELEASE);
    failures += expect("submit NOP", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("consume submission",
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE) == 1u);
    failures += expect_true("publish completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 1u);
    failures += expect_true("NOP completion",
        cqes[0].user_data == 0x454447454f535552ull &&
        cqes[0].result == 0 && cqes[0].flags == 0);
    __atomic_store_n(cq_head, 1u, __ATOMIC_RELEASE);

    memset(&probe, 0, sizeof(probe));
    failures += expect("register probe", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_PROBE,
        (long)&probe, PROBE_OPERATION_COUNT, 0, 0), 0);
    failures += expect_true("probe extent",
        probe.last_opcode >= IORING_OP_WRITE &&
        probe.operation_count == PROBE_OPERATION_COUNT);
    failures += expect_true("probe NOP",
        probe.operations[IORING_OP_NOP].opcode == IORING_OP_NOP &&
        (probe.operations[IORING_OP_NOP].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe read/write",
        (probe.operations[IORING_OP_READ].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_WRITE].flags &
         IO_URING_OP_SUPPORTED) != 0);

    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    print_text(failures ? "io-uring-abi: FAIL\n" :
                          "io-uring-abi: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
