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
#if defined(__x86_64__)
#define SYS_read 0
#define SYS_eventfd2 290
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_eventfd2 19
#endif

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define EINVAL 22
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_PROBE 8u
#define IORING_REGISTER_EVENTFD 4u
#define IORING_UNREGISTER_EVENTFD 5u
#define IO_URING_OP_SUPPORTED 1u
#define IORING_OP_NOP 0u
#define IORING_OP_READ 22u
#define IORING_OP_WRITE 23u
#define IORING_OP_POLL_ADD 6u
#define IORING_OP_TIMEOUT 11u
#define IORING_OP_TIMEOUT_REMOVE 12u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define PROBE_OPERATION_COUNT 65u
#define POLLIN 0x0001u
#define ETIME 62
#define ECANCELED 125

struct kernel_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

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

static void print_integer(int64_t value) {
    char buffer[32];
    unsigned long length = 0;
    uint64_t magnitude;
    if (value < 0) {
        buffer[length++] = '-';
        magnitude = (uint64_t)(-(value + 1)) + 1u;
    } else {
        magnitude = (uint64_t)value;
    }
    {
        char digits[24];
        unsigned long count = 0;
        do {
            digits[count++] = (char)('0' + magnitude % 10u);
            magnitude /= 10u;
        } while (magnitude);
        while (count) buffer[length++] = digits[--count];
    }
    buffer[length++] = '\n';
    (void)raw_syscall6(SYS_write, 1, (long)buffer, (long)length,
                       0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    print_text("actual/expected\n");
    print_integer(actual);
    print_integer(expected);
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
    long event_descriptor;
    uint64_t event_value = 0;
    struct kernel_timespec short_timeout = {0, 1000000};
    struct kernel_timespec long_timeout = {60, 0};
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

    event_descriptor = raw_syscall6(
        SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    failures += expect_true("eventfd", event_descriptor >= 0);
    if (event_descriptor >= 0) {
        uint32_t event_fd_argument = (uint32_t)event_descriptor;
        failures += expect("register eventfd", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_REGISTER_EVENTFD,
            (long)&event_fd_argument, 1, 0, 0), 0);
        memset(&sqes[1], 0, sizeof(sqes[1]));
        sqes[1].opcode = IORING_OP_NOP;
        sqes[1].user_data = 0x4556454e544644ull;
        sq_array[1] = 1;
        __atomic_store_n(sq_tail, 2u, __ATOMIC_RELEASE);
        failures += expect("submit eventfd NOP", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect("read eventfd", raw_syscall6(
            SYS_read, event_descriptor, (long)&event_value,
            sizeof(event_value), 0, 0, 0), sizeof(event_value));
        failures += expect_true("eventfd count", event_value == 1);
        failures += expect("unregister eventfd", raw_syscall6(
            SYS_io_uring_register, descriptor,
            IORING_UNREGISTER_EVENTFD, 0, 0, 0, 0), 0);
        event_value = 1;
        failures += expect("prime poll eventfd", raw_syscall6(
            SYS_write, event_descriptor, (long)&event_value,
            sizeof(event_value), 0, 0, 0), sizeof(event_value));
        memset(&sqes[2], 0, sizeof(sqes[2]));
        sqes[2].opcode = IORING_OP_POLL_ADD;
        sqes[2].descriptor = (int32_t)event_descriptor;
        sqes[2].operation_flags = POLLIN;
        sqes[2].user_data = 0x504f4c4c52454144ull;
        sq_array[2] = 2;
        __atomic_store_n(sq_tail, 3u, __ATOMIC_RELEASE);
        failures += expect("submit poll", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("poll completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 3u &&
            cqes[2].user_data == 0x504f4c4c52454144ull &&
            (cqes[2].result & POLLIN) != 0);
        __atomic_store_n(cq_head, 3u, __ATOMIC_RELEASE);
        (void)raw_syscall6(SYS_close, event_descriptor, 0, 0, 0, 0, 0);
    }

    memset(&sqes[3], 0, sizeof(sqes[3]));
    print_text("io-uring-abi: testing timeout\n");
    sqes[3].opcode = IORING_OP_TIMEOUT;
    sqes[3].descriptor = -1;
    sqes[3].address = (uint64_t)(uintptr_t)&short_timeout;
    sqes[3].length = 1;
    sqes[3].user_data = 0x54494d454f555431ull;
    sq_array[3] = 3;
    __atomic_store_n(sq_tail, 4u, __ATOMIC_RELEASE);
    failures += expect("submit timeout", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("timeout completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 4u &&
        cqes[3].user_data == 0x54494d454f555431ull &&
        cqes[3].result == -ETIME);
    __atomic_store_n(cq_head, 4u, __ATOMIC_RELEASE);

    memset(&sqes[4], 0, sizeof(sqes[4]));
    print_text("io-uring-abi: testing cancellation\n");
    sqes[4].opcode = IORING_OP_TIMEOUT;
    sqes[4].descriptor = -1;
    sqes[4].address = (uint64_t)(uintptr_t)&long_timeout;
    sqes[4].length = 1;
    sqes[4].user_data = 0x43414e43454c4d45ull;
    memset(&sqes[5], 0, sizeof(sqes[5]));
    sqes[5].opcode = IORING_OP_TIMEOUT_REMOVE;
    sqes[5].descriptor = -1;
    sqes[5].address = 0x43414e43454c4d45ull;
    sqes[5].user_data = 0x52454d4f56454f50ull;
    sq_array[4] = 4;
    sq_array[5] = 5;
    __atomic_store_n(sq_tail, 6u, __ATOMIC_RELEASE);
    failures += expect("submit cancel pair", raw_syscall6(
        SYS_io_uring_enter, descriptor, 2, 2,
        IORING_ENTER_GETEVENTS, 0, 0), 2);
    failures += expect_true("canceled timeout completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 6u &&
        cqes[5].user_data == 0x43414e43454c4d45ull &&
        cqes[5].result == -ECANCELED);
    failures += expect_true("timeout remove completion",
        cqes[4].user_data == 0x52454d4f56454f50ull &&
        cqes[4].result == 0);
    if (cqes[5].user_data != 0x43414e43454c4d45ull ||
        cqes[5].result != -ECANCELED ||
        cqes[4].user_data != 0x52454d4f56454f50ull ||
        cqes[4].result != 0) {
        print_text("io-uring-abi: cancellation CQ tail/results\n");
        print_integer(*cq_tail);
        print_integer((int64_t)cqes[4].user_data);
        print_integer(cqes[4].result);
        print_integer((int64_t)cqes[5].user_data);
        print_integer(cqes[5].result);
    }
    __atomic_store_n(cq_head, 6u, __ATOMIC_RELEASE);

    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_tests();
    print_text(failures ? "io-uring-abi: FAIL\n" :
                          "io-uring-abi: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
