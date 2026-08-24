/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring futex wait ABI probe. */

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
#error "io_uring_futex_wait_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_FUTEX_WAIT 51u
#define IORING_OP_FUTEX_WAKE 52u
#define IORING_OP_FUTEX_WAITV 53u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define FUTEX_32 2u
#define FUTEX_PRIVATE_FLAG 128u
#define EAGAIN 11
#define EINVAL 22

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

struct futex_waitv {
    uint64_t value;
    uint64_t address;
    uint32_t flags;
    uint32_t reserved;
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
                           uint32_t count, uint32_t minimum) {
    uint32_t tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);

    for (uint32_t index = 0; index < count; ++index) {
        uint32_t slot = (tail + index) & *sq_mask;
        sqes[slot] = requests[index];
        sq_array[slot] = slot;
    }
    __atomic_store_n(sq_tail, tail + count, __ATOMIC_RELEASE);
    return (int)raw_syscall6(
        SYS_io_uring_enter, descriptor, count, minimum,
        minimum ? IORING_ENTER_GETEVENTS : 0, 0, 0);
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
    const uint32_t futex_flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
    const uint64_t single_wait = 0x4655544558574149ull;
    const uint64_t single_wake = 0x465554455857414bull;
    const uint64_t vector_wait = 0x4655544558564543ull;
    const uint64_t vector_wake = 0x465554455856574bull;
    const uint64_t mismatch_wait = 0x46555445584d4953ull;
    const uint64_t invalid_wait = 0x4655544558494e56ull;
    struct io_uring_params parameters;
    struct io_uring_sqe requests[2];
    struct futex_waitv waiters[2];
    uint32_t words[2] = {7u, 9u};
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
    long ring_descriptor;
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

    bytes_zero(requests, sizeof(requests));
    requests[0].opcode = IORING_OP_FUTEX_WAIT;
    requests[0].descriptor = (int32_t)futex_flags;
    requests[0].offset = words[0];
    requests[0].address = (uint64_t)(uintptr_t)&words[0];
    requests[0].user_data = single_wait;
    requests[0].address3 = UINT32_MAX;
    requests[1].opcode = IORING_OP_FUTEX_WAKE;
    requests[1].descriptor = (int32_t)futex_flags;
    requests[1].offset = 1u;
    requests[1].address = (uint64_t)(uintptr_t)&words[0];
    requests[1].user_data = single_wake;
    requests[1].address3 = UINT32_MAX;
    first = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("submit single wait and wake", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 2u, 2u) == 2);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("single completion count", last - first == 2u);
    failures += check("single wait result", find_result(
        cqes, *cq_mask, first, last, single_wait, &result) && result == 0);
    failures += check("single wake result", find_result(
        cqes, *cq_mask, first, last, single_wake, &result) && result == 1);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    waiters[0].value = words[0];
    waiters[0].address = (uint64_t)(uintptr_t)&words[0];
    waiters[0].flags = futex_flags;
    waiters[0].reserved = 0u;
    waiters[1].value = words[1];
    waiters[1].address = (uint64_t)(uintptr_t)&words[1];
    waiters[1].flags = futex_flags;
    waiters[1].reserved = 0u;
    bytes_zero(requests, sizeof(requests));
    requests[0].opcode = IORING_OP_FUTEX_WAITV;
    requests[0].address = (uint64_t)(uintptr_t)waiters;
    requests[0].length = 2u;
    requests[0].user_data = vector_wait;
    requests[1].opcode = IORING_OP_FUTEX_WAKE;
    requests[1].descriptor = (int32_t)futex_flags;
    requests[1].offset = 1u;
    requests[1].address = (uint64_t)(uintptr_t)&words[1];
    requests[1].user_data = vector_wake;
    requests[1].address3 = UINT32_MAX;
    first = last;
    failures += check("submit vector wait and wake", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 2u, 2u) == 2);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("vector completion count", last - first == 2u);
    failures += check("vector wait result", find_result(
        cqes, *cq_mask, first, last, vector_wait, &result) && result == 1);
    failures += check("vector wake result", find_result(
        cqes, *cq_mask, first, last, vector_wake, &result) && result == 1);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    bytes_zero(requests, sizeof(requests));
    requests[0].opcode = IORING_OP_FUTEX_WAIT;
    requests[0].descriptor = (int32_t)futex_flags;
    requests[0].offset = words[0] + 1u;
    requests[0].address = (uint64_t)(uintptr_t)&words[0];
    requests[0].user_data = mismatch_wait;
    requests[0].address3 = UINT32_MAX;
    first = last;
    failures += check("submit mismatch wait", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 1u) == 1);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("mismatch result", find_result(
        cqes, *cq_mask, first, last, mismatch_wait, &result) &&
        result == -EAGAIN);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    requests[0].offset = words[0];
    requests[0].user_data = invalid_wait;
    requests[0].address3 = 0u;
    first = last;
    failures += check("submit zero mask wait", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 1u) == 1);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("zero mask result", find_result(
        cqes, *cq_mask, first, last, invalid_wait, &result) &&
        result == -EINVAL);

    if (!failures) print_text("IO_URING_FUTEX_WAIT_ABI_PROBE_PASS\n");

    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
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
