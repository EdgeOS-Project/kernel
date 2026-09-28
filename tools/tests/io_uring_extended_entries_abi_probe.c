/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring 128-byte SQE and 32-byte CQE ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_write 1
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_extended_entries_abi_probe requires a 64-bit Linux ABI"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u

#define IORING_SETUP_SQE128 (1u << 10)
#define IORING_SETUP_CQE32 (1u << 11)
#define IORING_SETUP_CQSIZE (1u << 3)
#define IORING_SETUP_CQE_MIXED (1u << 18)
#define IORING_SETUP_SQE_MIXED (1u << 19)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_NOP 0u
#define IORING_OP_NOP128 63u
#define IORING_NOP_INJECT_RESULT (1u << 0)
#define IORING_NOP_FILE (1u << 1)
#define IORING_NOP_FIXED_FILE (1u << 2)
#define IORING_NOP_FIXED_BUFFER (1u << 3)
#define IORING_NOP_TASK_WORK (1u << 4)
#define IORING_NOP_CQE32 (1u << 5)
#define IORING_CQE_F_SKIP (1u << 5)
#define IORING_CQE_F_32 (1u << 15)
#define IORING_REGISTER_BUFFERS 0u
#define IORING_REGISTER_FILES 2u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull

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

struct io_uring_cqe32 {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
    uint64_t extra1;
    uint64_t extra2;
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

struct linux_iovec {
    uint64_t base;
    uint64_t length;
};

#ifndef EDGE_PROBE_LAYOUT_ONLY
static uint8_t g_fixed_buffer[16];
#endif

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

static void bytes_copy(void *destination, const void *source,
                       uint32_t size) {
    uint8_t *output = destination;
    const uint8_t *input = source;
    for (uint32_t index = 0; index < size; ++index)
        output[index] = input[index];
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

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int submit_one(long descriptor,
                      struct io_uring_params *parameters,
                      void *sq_ring, void *cq_ring, void *sqes,
                      uint32_t sqe_slot,
                      const struct io_uring_sqe *request,
                      int32_t expected_result,
                      uint64_t expected_extra1,
                      uint64_t expected_extra2) {
    volatile uint32_t *sq_head = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.head);
    volatile uint32_t *sq_tail = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.tail);
    volatile uint32_t *sq_mask = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.ring_mask);
    volatile uint32_t *sq_array = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.array);
    volatile uint32_t *cq_head = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters->cq_off.head);
    volatile uint32_t *cq_tail = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters->cq_off.tail);
    volatile uint32_t *cq_mask = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters->cq_off.ring_mask);
    struct io_uring_cqe32 *cqes = (struct io_uring_cqe32 *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    struct io_uring_sqe *slot = (struct io_uring_sqe *)(
        (uint8_t *)sqes + (uint64_t)sqe_slot * 128u);
    struct io_uring_cqe32 *cqe;

    bytes_zero(slot, 128u);
    bytes_copy(slot, request, sizeof(*request));
    sq_array[submission & *sq_mask] = sqe_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    if (raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0) != 1)
        return 1;
    if (__atomic_load_n(sq_head, __ATOMIC_ACQUIRE) != submission + 1u ||
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != completion + 1u)
        return 1;
    cqe = &cqes[completion & *cq_mask];
    if (cqe->user_data != request->user_data ||
        cqe->result != expected_result || cqe->flags != 0u ||
        cqe->extra1 != expected_extra1 ||
        cqe->extra2 != expected_extra2)
        return 1;
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return 0;
}

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *sqes = 0;
    long descriptor;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    parameters.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (descriptor < 0) return 1;
    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        failures = 1;
        goto done;
    }

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_NOP;
    request.user_data = 0x4558544e4f503031ull;
    failures += submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes,
        1u, &request, 0, 0u, 0u);

#ifndef EDGE_PROBE_LAYOUT_ONLY
    {
        int32_t fixed_file = 1;
        struct linux_iovec fixed_buffer = {
            .base = (uint64_t)(uintptr_t)g_fixed_buffer,
            .length = sizeof(g_fixed_buffer),
        };

        if (raw_syscall6(
                SYS_io_uring_register, descriptor,
                IORING_REGISTER_FILES, (long)&fixed_file,
                1, 0, 0) != 0)
            ++failures;
        if (raw_syscall6(
                SYS_io_uring_register, descriptor,
                IORING_REGISTER_BUFFERS, (long)&fixed_buffer,
                1, 0, 0) != 0)
            ++failures;
    }
    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_NOP128;
    request.offset = 0x1111222233334444ull;
    request.address = 0x5555666677778888ull;
    request.length = 7u;
    request.operation_flags =
        IORING_NOP_INJECT_RESULT | IORING_NOP_FILE |
        IORING_NOP_FIXED_FILE | IORING_NOP_FIXED_BUFFER |
        IORING_NOP_TASK_WORK | IORING_NOP_CQE32;
    request.user_data = 0x4558544e4f503032ull;
    failures += submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes,
        2u, &request, 7,
        request.offset, request.address);
#endif

done:
    if (sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

#ifndef EDGE_PROBE_LAYOUT_ONLY
static int mixed_expect(int condition, const char *failure) {
    if (condition) return 0;
    print_text(failure);
    return 1;
}

static int submit_mixed(long descriptor,
                        struct io_uring_params *parameters,
                        void *sq_ring, void *sqes,
                        uint32_t physical_slot,
                        const struct io_uring_sqe *request,
                        uint32_t submission_entries,
                        long expected_enter_result) {
    volatile uint32_t *sq_tail = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.tail);
    volatile uint32_t *sq_mask = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.ring_mask);
    volatile uint32_t *sq_array = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.array);
    uint32_t tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    struct io_uring_sqe *slot = (struct io_uring_sqe *)(
        (uint8_t *)sqes + (uint64_t)physical_slot * 64u);

    bytes_zero(slot, submission_entries * 64u);
    bytes_copy(slot, request, sizeof(*request));
    sq_array[tail & *sq_mask] = physical_slot;
    if (submission_entries == 2u)
        sq_array[(tail + 1u) & *sq_mask] = physical_slot + 1u;
    __atomic_store_n(
        sq_tail, tail + submission_entries, __ATOMIC_RELEASE);
    return raw_syscall6(
               SYS_io_uring_enter, descriptor, submission_entries,
               0, 0, 0, 0) == expected_enter_result ? 0 : 1;
}

static int run_mixed_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    struct io_uring_cqe32 *completion;
    uint8_t *cqes;
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *sqes = 0;
    long descriptor;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    parameters.flags = IORING_SETUP_SQE128 | IORING_SETUP_SQE_MIXED;
    failures += mixed_expect(raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters,
        0, 0, 0, 0) == -22, "MIXED_FAIL_SETUP_SQE_CONFLICT\n");
    bytes_zero(&parameters, sizeof(parameters));
    parameters.flags = IORING_SETUP_CQE32 | IORING_SETUP_CQE_MIXED;
    failures += mixed_expect(raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters,
        0, 0, 0, 0) == -22, "MIXED_FAIL_SETUP_CQE_CONFLICT\n");

    bytes_zero(&parameters, sizeof(parameters));
    parameters.flags = IORING_SETUP_CQSIZE |
        IORING_SETUP_SQE_MIXED | IORING_SETUP_CQE_MIXED;
    parameters.cq_entries = 8u;
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (descriptor < 0) {
        print_text("MIXED_FAIL_SETUP\n");
        return failures + 1;
    }
    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        ++failures;
        goto done;
    }
    cq_head = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters.cq_off.head);
    cq_tail = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters.cq_off.tail);
    cq_mask = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters.cq_off.ring_mask);
    cqes = (uint8_t *)cq_ring + parameters.cq_off.cqes;

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_NOP;
    request.user_data = 0x4d495845444e4f50ull;
    failures += mixed_expect(submit_mixed(
        descriptor, &parameters, sq_ring, sqes,
        0u, &request, 1u, 1) == 0, "MIXED_FAIL_NOP_ENTER\n");
    failures += mixed_expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 1u,
        "MIXED_FAIL_NOP_TAIL\n");
    completion = (struct io_uring_cqe32 *)(void *)cqes;
    failures += mixed_expect(
        completion->user_data == request.user_data &&
        completion->result == 0 && completion->flags == 0u,
        "MIXED_FAIL_NOP_CQE\n");

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_NOP128;
    request.offset = 0x1111222233334444ull;
    request.address = 0x5555666677778888ull;
    request.operation_flags = IORING_NOP_CQE32;
    request.user_data = 0x4d49584544313238ull;
    failures += mixed_expect(submit_mixed(
        descriptor, &parameters, sq_ring, sqes,
        2u, &request, 2u, 2) == 0, "MIXED_FAIL_NOP128_ENTER\n");
    failures += mixed_expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 3u,
        "MIXED_FAIL_NOP128_TAIL\n");
    completion = (struct io_uring_cqe32 *)(void *)(cqes + 16u);
    failures += mixed_expect(
        completion->user_data == request.user_data &&
        completion->result == 0 &&
        completion->flags == IORING_CQE_F_32 &&
        completion->extra1 == request.offset &&
        completion->extra2 == request.address,
        "MIXED_FAIL_NOP128_CQE\n");

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_NOP128;
    request.user_data = 0x4d49584544424144ull;
    failures += mixed_expect(submit_mixed(
        descriptor, &parameters, sq_ring, sqes,
        4u, &request, 1u, 1) == 0, "MIXED_FAIL_SHORT_ENTER\n");
    failures += mixed_expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 4u,
        "MIXED_FAIL_SHORT_TAIL\n");
    completion = (struct io_uring_cqe32 *)(void *)(cqes + 3u * 16u);
    failures += mixed_expect(
        completion->user_data == request.user_data &&
        completion->result == -22 && completion->flags == 0u,
        "MIXED_FAIL_SHORT_CQE\n");

    for (uint32_t index = 0u; index < 3u; ++index) {
        bytes_zero(&request, sizeof(request));
        request.opcode = IORING_OP_NOP;
        request.user_data = 0x4d4958454446494cull + index;
        failures += mixed_expect(submit_mixed(
            descriptor, &parameters, sq_ring, sqes,
            index, &request, 1u, 1) == 0, "MIXED_FAIL_FILL_ENTER\n");
    }
    failures += mixed_expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 7u,
        "MIXED_FAIL_FILL_TAIL\n");
    __atomic_store_n(cq_head, 7u, __ATOMIC_RELEASE);

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_NOP128;
    request.offset = 9u;
    request.address = 10u;
    request.operation_flags = IORING_NOP_CQE32;
    request.user_data = 0x4d49584544575250ull;
    failures += mixed_expect(submit_mixed(
        descriptor, &parameters, sq_ring, sqes,
        5u, &request, 2u, 2) == 0, "MIXED_FAIL_WRAP_ENTER\n");
    failures += mixed_expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 10u,
        "MIXED_FAIL_WRAP_TAIL\n");
    completion = (struct io_uring_cqe32 *)(void *)(
        cqes + ((*cq_mask) * 16u));
    failures += mixed_expect(
        completion->user_data == 0u && completion->result == 0 &&
        completion->flags == IORING_CQE_F_SKIP,
        "MIXED_FAIL_WRAP_SKIP\n");
    completion = (struct io_uring_cqe32 *)(void *)cqes;
    failures += mixed_expect(
        completion->user_data == request.user_data &&
        completion->result == 0 &&
        completion->flags == IORING_CQE_F_32 &&
        completion->extra1 == 9u && completion->extra2 == 10u,
        "MIXED_FAIL_WRAP_CQE\n");

done:
    if (sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}
#endif

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_probe();
#ifndef EDGE_PROBE_LAYOUT_ONLY
    failures += run_mixed_probe();
#endif
    print_text(failures ?
        "IO_URING_EXTENDED_ENTRIES_ABI_PROBE_FAIL\n" :
        "IO_URING_EXTENDED_ENTRIES_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
