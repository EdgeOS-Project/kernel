/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring synchronous-cancel ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_exit 60
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_write 1
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_write 64
#else
#error "io_uring_sync_cancel_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_SYNC_CANCEL 24u
#define IORING_OP_TIMEOUT 11u
#define IORING_OP_ASYNC_CANCEL 14u
#define IORING_ASYNC_CANCEL_ALL (1u << 0)
#define IORING_ASYNC_CANCEL_ANY (1u << 2)
#define IORING_ASYNC_CANCEL_OP (1u << 5)
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define EINVAL 22
#define ENOENT 2
#define ECANCELED 125

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

struct linux_timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

struct io_uring_sync_cancel_reg {
    uint64_t address;
    int32_t descriptor;
    uint32_t flags;
    struct linux_timespec64 timeout;
    uint8_t opcode;
    uint8_t padding[7];
    uint64_t padding2[3];
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

void *memset(void *destination, int value, unsigned long size) {
    uint8_t *bytes = destination;
    for (unsigned long index = 0; index < size; ++index)
        bytes[index] = (uint8_t)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned long size) {
    uint8_t *output = destination;
    const uint8_t *input = source;
    for (unsigned long index = 0; index < size; ++index)
        output[index] = input[index];
    return destination;
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

static int failures;

static void check(const char *name, int condition) {
    if (condition) return;
    ++failures;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static long submit(long descriptor, volatile uint32_t *sq_tail,
                   volatile uint32_t *sq_mask,
                   volatile uint32_t *sq_array,
                   struct io_uring_sqe *sqes,
                   const struct io_uring_sqe *requests,
                   uint32_t count) {
    uint32_t tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);

    for (uint32_t index = 0; index < count; ++index) {
        uint32_t slot = (tail + index) & *sq_mask;
        sqes[slot] = requests[index];
        sq_array[slot] = slot;
    }
    __atomic_store_n(sq_tail, tail + count, __ATOMIC_RELEASE);
    return raw_syscall6(
        SYS_io_uring_enter, descriptor, count, 0, 0, 0, 0);
}

static int find_completion(const struct io_uring_cqe *cqes,
                           uint32_t mask, uint32_t first,
                           uint32_t last, uint64_t user_data,
                           int32_t expected_result) {
    for (uint32_t index = first; index < last; ++index) {
        const struct io_uring_cqe *completion = &cqes[index & mask];
        if (completion->user_data == user_data &&
            completion->result == expected_result)
            return 1;
    }
    return 0;
}

static int run_probe(void) {
    const uint64_t targets[] = {
        0x53434e43454c3031ull, 0x53434e43454c3032ull,
        0x53434e43454c3033ull, 0x41434e43454c3031ull,
        0x41434e43454c3032ull
    };
    const uint64_t cancel_user_data = 0x41434e43454c4f50ull;
    struct io_uring_params parameters;
    struct io_uring_sqe request[3];
    struct io_uring_sync_cancel_reg cancellation;
    struct linux_timespec64 timeout = {60, 0};
    void *sq_ring;
    void *cq_ring;
    struct io_uring_sqe *sqes;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    struct io_uring_cqe *cqes;
    uint32_t first;
    uint32_t last;
    long descriptor;

    bytes_zero(&parameters, sizeof(parameters));
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    check("setup", descriptor >= 0);
    if (descriptor < 0) return failures;
    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    check("map", sq_ring && cq_ring && sqes);
    if (!sq_ring || !cq_ring || !sqes) goto out;
    sq_tail = (volatile uint32_t *)((uint8_t *)sq_ring +
                                    parameters.sq_off.tail);
    sq_mask = (volatile uint32_t *)((uint8_t *)sq_ring +
                                    parameters.sq_off.ring_mask);
    sq_array = (volatile uint32_t *)((uint8_t *)sq_ring +
                                     parameters.sq_off.array);
    cq_head = (volatile uint32_t *)((uint8_t *)cq_ring +
                                    parameters.cq_off.head);
    cq_tail = (volatile uint32_t *)((uint8_t *)cq_ring +
                                    parameters.cq_off.tail);
    cq_mask = (volatile uint32_t *)((uint8_t *)cq_ring +
                                    parameters.cq_off.ring_mask);
    cqes = (struct io_uring_cqe *)((uint8_t *)cq_ring +
                                   parameters.cq_off.cqes);

    bytes_zero(request, sizeof(request));
    for (uint32_t index = 0; index < 3u; ++index) {
        request[index].opcode = IORING_OP_TIMEOUT;
        request[index].descriptor = -1;
        request[index].address = (uint64_t)(uintptr_t)&timeout;
        request[index].length = 1u;
        request[index].user_data = targets[index];
    }
    check("submit sync targets", submit(
        descriptor, sq_tail, sq_mask, sq_array, sqes, request, 3u) == 3);

    bytes_zero(&cancellation, sizeof(cancellation));
    cancellation.address = targets[0];
    cancellation.timeout.seconds = -1;
    cancellation.timeout.nanoseconds = -1;
    check("sync cancel user data", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_SYNC_CANCEL,
        (long)&cancellation, 1, 0, 0) == 0);
    cancellation.flags = IORING_ASYNC_CANCEL_ALL |
                         IORING_ASYNC_CANCEL_OP;
    cancellation.opcode = IORING_OP_TIMEOUT;
    check("sync cancel all opcode", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_SYNC_CANCEL,
        (long)&cancellation, 1, 0, 0) == 2);
    check("wait sync completions", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 3,
        IORING_ENTER_GETEVENTS, 0, 0) == 0);
    first = __atomic_load_n(cq_head, __ATOMIC_ACQUIRE);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    check("sync completion count", last - first == 3u);
    for (uint32_t index = 0; index < 3u; ++index)
        check("sync canceled target", find_completion(
            cqes, *cq_mask, first, last, targets[index], -ECANCELED));
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    bytes_zero(request, sizeof(request));
    for (uint32_t index = 0; index < 2u; ++index) {
        request[index].opcode = IORING_OP_TIMEOUT;
        request[index].descriptor = -1;
        request[index].address = (uint64_t)(uintptr_t)&timeout;
        request[index].length = 1u;
        request[index].user_data = targets[index + 3u];
    }
    request[2].opcode = IORING_OP_ASYNC_CANCEL;
    request[2].descriptor = -1;
    request[2].length = IORING_OP_TIMEOUT;
    request[2].operation_flags = IORING_ASYNC_CANCEL_ALL |
                                 IORING_ASYNC_CANCEL_OP;
    request[2].user_data = cancel_user_data;
    check("submit async cancel", submit(
        descriptor, sq_tail, sq_mask, sq_array, sqes, request, 3u) == 3);
    check("wait async completions", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 3,
        IORING_ENTER_GETEVENTS, 0, 0) == 0);
    first = __atomic_load_n(cq_head, __ATOMIC_ACQUIRE);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    check("async completion count", last - first == 3u);
    check("async cancel result", find_completion(
        cqes, *cq_mask, first, last, cancel_user_data, 2));
    for (uint32_t index = 3u; index < 5u; ++index)
        check("async canceled target", find_completion(
            cqes, *cq_mask, first, last, targets[index], -ECANCELED));
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    bytes_zero(&cancellation, sizeof(cancellation));
    cancellation.timeout.seconds = -1;
    cancellation.timeout.nanoseconds = -1;
    cancellation.flags = IORING_ASYNC_CANCEL_ANY;
    check("empty cancel all", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_SYNC_CANCEL,
        (long)&cancellation, 1, 0, 0) == 0);
    cancellation.flags = 1u << 31;
    check("invalid flags", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_SYNC_CANCEL,
        (long)&cancellation, 1, 0, 0) == -EINVAL);
    cancellation.flags = 0u;
    cancellation.padding[3] = 1u;
    check("reserved bytes", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_SYNC_CANCEL,
        (long)&cancellation, 1, 0, 0) == -EINVAL);
    check("argument count", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_SYNC_CANCEL,
        (long)&cancellation, 0, 0, 0) == -EINVAL);

out:
    if (sq_ring) (void)raw_syscall6(
        SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring) (void)raw_syscall6(
        SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sqes) (void)raw_syscall6(
        SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_SYNC_CANCEL_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
