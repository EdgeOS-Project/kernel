/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring linked-timeout ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_eventfd2 290
#define SYS_exit 60
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_read 0
#define SYS_write 1
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_eventfd2 19
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_read 63
#define SYS_write 64
#else
#error "io_uring_link_timeout_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define IORING_ENTER_GETEVENTS 1u
#define IOSQE_IO_LINK (1u << 2)
#define IORING_OP_POLL_ADD 6u
#define IORING_OP_LINK_TIMEOUT 15u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define POLLIN 1u
#define EINVAL 22
#define ETIME 62
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

static int first_failure;
static int check_index;

static int check(const char *name, int condition) {
    ++check_index;
    if (condition) return 0;
    if (!first_failure) first_failure = check_index;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
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

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int submit_requests(long descriptor,
                           volatile uint32_t *sq_tail,
                           volatile uint32_t *sq_mask,
                           volatile uint32_t *sq_array,
                           struct io_uring_sqe *sqes,
                           const struct io_uring_sqe *requests,
                           uint32_t count,
                           uint32_t minimum_completions) {
    uint32_t tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);

    for (uint32_t index = 0; index < count; ++index) {
        uint32_t slot = (tail + index) & *sq_mask;
        sqes[slot] = requests[index];
        sq_array[slot] = slot;
    }
    __atomic_store_n(sq_tail, tail + count, __ATOMIC_RELEASE);
    return (int)raw_syscall6(
        SYS_io_uring_enter, descriptor, count, minimum_completions,
        minimum_completions ? IORING_ENTER_GETEVENTS : 0, 0, 0);
}

static int find_result(const struct io_uring_cqe *cqes, uint32_t mask,
                       uint32_t first, uint32_t last,
                       uint64_t user_data, int32_t *result) {
    for (uint32_t index = first; index < last; ++index) {
        const struct io_uring_cqe *completion = &cqes[index & mask];
        if (completion->user_data != user_data) continue;
        *result = completion->result;
        return 1;
    }
    return 0;
}

static int run_probe(void) {
    const uint64_t ready_target = 0x4c54415247455431ull;
    const uint64_t ready_timer = 0x4c54494d45523131ull;
    const uint64_t expired_target = 0x4c54415247455432ull;
    const uint64_t expired_timer = 0x4c54494d45523232ull;
    const uint64_t invalid_timer = 0x4c54494d45523333ull;
    struct io_uring_params parameters;
    struct io_uring_sqe requests[2];
    struct linux_timespec64 timeout;
    void *sq_ring = 0;
    void *cq_ring = 0;
    struct io_uring_sqe *sqes = 0;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    struct io_uring_cqe *cqes;
    uint64_t event_value = 1u;
    long ring_descriptor;
    long event_descriptor = -1;
    uint32_t first;
    uint32_t last;
    int32_t result = 0;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    ring_descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (check("setup ring", ring_descriptor >= 0)) return 100;
    sq_ring = map_ring(ring_descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring_descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(ring_descriptor, IORING_OFF_SQES);
    if (check("map ring", sq_ring && cq_ring && sqes)) goto close_ring;
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

    event_descriptor = raw_syscall6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    failures += check("create eventfd", event_descriptor >= 0);
    if (event_descriptor < 0) goto unmap_ring;

    timeout.seconds = 1;
    timeout.nanoseconds = 0;
    bytes_zero(requests, sizeof(requests));
    requests[0].opcode = IORING_OP_POLL_ADD;
    requests[0].flags = IOSQE_IO_LINK;
    requests[0].descriptor = (int32_t)event_descriptor;
    requests[0].operation_flags = POLLIN;
    requests[0].user_data = ready_target;
    requests[1].opcode = IORING_OP_LINK_TIMEOUT;
    requests[1].descriptor = -1;
    requests[1].address = (uint64_t)(uintptr_t)&timeout;
    requests[1].length = 1u;
    requests[1].user_data = ready_timer;
    first = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("submit ready chain", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 2u, 0u) == 2);
    failures += check("signal eventfd", raw_syscall6(
        SYS_write, event_descriptor, (long)&event_value,
        sizeof(event_value), 0, 0, 0) == (long)sizeof(event_value));
    failures += check("wait ready chain", raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 0, 2,
        IORING_ENTER_GETEVENTS, 0, 0) == 0);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("ready chain completion count", last - first == 2u);
    failures += check("ready target result", find_result(
        cqes, *cq_mask, first, last, ready_target, &result) &&
        (result & POLLIN));
    failures += check("ready timer canceled", find_result(
        cqes, *cq_mask, first, last, ready_timer, &result) &&
        result == -ECANCELED);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);
    failures += check("drain eventfd", raw_syscall6(
        SYS_read, event_descriptor, (long)&event_value,
        sizeof(event_value), 0, 0, 0) == (long)sizeof(event_value));

    timeout.seconds = 0;
    timeout.nanoseconds = 1000000;
    requests[0].user_data = expired_target;
    requests[1].user_data = expired_timer;
    first = last;
    failures += check("wait expired chain", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 2u, 2u) == 2);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("expired chain completion count", last - first == 2u);
    failures += check("expired target canceled", find_result(
        cqes, *cq_mask, first, last, expired_target, &result) &&
        result == -ECANCELED);
    failures += check("expired timer result", find_result(
        cqes, *cq_mask, first, last, expired_timer, &result) &&
        result == -ETIME);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    bytes_zero(requests, sizeof(requests));
    requests[0].opcode = IORING_OP_LINK_TIMEOUT;
    requests[0].descriptor = -1;
    requests[0].address = (uint64_t)(uintptr_t)&timeout;
    requests[0].length = 1u;
    requests[0].user_data = invalid_timer;
    first = last;
    failures += check("submit unlinked timeout", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 1u) == 1);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("unlinked timeout completion", last - first == 1u);
    failures += check("unlinked timeout invalid", find_result(
        cqes, *cq_mask, first, last, invalid_timer, &result) &&
        result == -EINVAL);

    if (!failures)
        print_text("IO_URING_LINK_TIMEOUT_ABI_PROBE_PASS\n");

    (void)raw_syscall6(SYS_close, event_descriptor, 0, 0, 0, 0, 0);
unmap_ring:
    if (sqes) (void)raw_syscall6(
        SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring) (void)raw_syscall6(
        SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sq_ring) (void)raw_syscall6(
        SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(SYS_close, ring_descriptor, 0, 0, 0, 0, 0);
    settle_console_output();
    return failures ? first_failure : 0;
}

__attribute__((noreturn)) void _start(void) {
    int result = run_probe();
    raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
