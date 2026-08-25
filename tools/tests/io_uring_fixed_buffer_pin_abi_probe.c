/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring fixed-buffer lifetime ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_fixed_buffer_pin_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define MAP_PRIVATE 2u
#define MAP_ANONYMOUS 0x20u
#define PAGE_SIZE 4096u
#define FIXED_BUFFER_PAGES 66u
#define FIXED_BUFFER_SIZE (FIXED_BUFFER_PAGES * PAGE_SIZE)
#define FIRST_OFFSET (64u * PAGE_SIZE - 8u)
#define SECOND_OFFSET (65u * PAGE_SIZE + 128u)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_BUFFERS 0u
#define IORING_UNREGISTER_BUFFERS 1u
#define IORING_OP_READ_FIXED 4u
#define IORING_OP_WRITE_FIXED 5u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull

struct linux_iovec {
    uint64_t base;
    uint64_t length;
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
    uint32_t length = 0u;
    while (text[length]) ++length;
    return length;
}

static int bytes_equal(const void *left, const void *right,
                       uint32_t length) {
    const uint8_t *a = left;
    const uint8_t *b = right;
    for (uint32_t index = 0; index < length; ++index)
        if (a[index] != b[index]) return 0;
    return 1;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ?
        0 : (void *)(uintptr_t)result;
}

static int submit(
        long ring, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        uint8_t opcode, int32_t descriptor, uint64_t address,
        uint32_t length, uint64_t user_data) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(void *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t sq_index = *sq_tail & *sq_mask;
    uint32_t cq_index;
    long entered;

    bytes_zero(&sqes[sq_index], sizeof(sqes[sq_index]));
    sqes[sq_index].opcode = opcode;
    sqes[sq_index].descriptor = descriptor;
    sqes[sq_index].offset = UINT64_MAX;
    sqes[sq_index].address = address;
    sqes[sq_index].length = length;
    sqes[sq_index].user_data = user_data;
    sqes[sq_index].buffer_index = 0u;
    sq_array[sq_index] = sq_index;
    __atomic_store_n(sq_tail, *sq_tail + 1u, __ATOMIC_RELEASE);
    entered = raw_syscall6(
        SYS_io_uring_enter, ring, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0);
    if (entered != 1 || *sq_head != *sq_tail || *cq_head == *cq_tail)
        return -1;
    cq_index = *cq_head & *cq_mask;
    if (cqes[cq_index].user_data != user_data) return -1;
    entered = cqes[cq_index].result;
    __atomic_store_n(cq_head, *cq_head + 1u, __ATOMIC_RELEASE);
    return (int)entered;
}

static int run_probe(void) {
    static const char first[] = "registered-before-unmap";
    static const char second[] = "read-after-unmap";
    struct io_uring_params parameters;
    struct linux_iovec buffer;
    int32_t input_pipe[2] = {-1, -1};
    int32_t output_pipe[2] = {-1, -1};
    uint8_t observed[64];
    struct io_uring_sqe *sqes = 0;
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *page = 0;
    long ring;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 4, (long)&parameters, 0, 0, 0, 0);
    if (ring < 0) return 1;
    sq_ring = map_ring(ring, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring, IORING_OFF_CQ_RING);
    sqes = map_ring(ring, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        failures = 1;
        goto cleanup;
    }
    page = (void *)(uintptr_t)raw_syscall6(
        SYS_mmap, 0, FIXED_BUFFER_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)(uintptr_t)page < 0 &&
        (long)(uintptr_t)page >= -4095) {
        page = 0;
        failures = 1;
        goto cleanup;
    }
    bytes_zero(page, FIXED_BUFFER_SIZE);
    for (uint32_t index = 0; index < sizeof(first); ++index)
        ((uint8_t *)page)[FIRST_OFFSET + index] = (uint8_t)first[index];
    buffer.base = (uint64_t)(uintptr_t)page;
    buffer.length = FIXED_BUFFER_SIZE;
    if (raw_syscall6(
            SYS_io_uring_register, ring, IORING_REGISTER_BUFFERS,
            (long)&buffer, 1, 0, 0) != 0) {
        failures = 1;
        goto cleanup;
    }
    if (raw_syscall6(
            SYS_munmap, (long)page, FIXED_BUFFER_SIZE, 0, 0, 0, 0) != 0) {
        failures = 1;
        goto cleanup;
    }
    page = 0;
    if (raw_syscall6(
            SYS_pipe2, (long)input_pipe, 0, 0, 0, 0, 0) != 0 ||
        raw_syscall6(
            SYS_pipe2, (long)output_pipe, 0, 0, 0, 0, 0) != 0) {
        failures = 1;
        goto cleanup;
    }

    failures += submit(
        ring, &parameters, sq_ring, cq_ring, sqes,
        IORING_OP_WRITE_FIXED, output_pipe[1],
        buffer.base + FIRST_OFFSET, sizeof(first), 0x5752495445ull) !=
        (int)sizeof(first);
    bytes_zero(observed, sizeof(observed));
    failures += raw_syscall6(
        SYS_read, output_pipe[0], (long)observed,
        sizeof(first), 0, 0, 0) != (long)sizeof(first);
    failures += !bytes_equal(observed, first, sizeof(first));

    failures += raw_syscall6(
        SYS_write, input_pipe[1], (long)second,
        sizeof(second), 0, 0, 0) != (long)sizeof(second);
    failures += submit(
        ring, &parameters, sq_ring, cq_ring, sqes,
        IORING_OP_READ_FIXED, input_pipe[0],
        buffer.base + SECOND_OFFSET, sizeof(second), 0x52454144ull) !=
        (int)sizeof(second);
    failures += submit(
        ring, &parameters, sq_ring, cq_ring, sqes,
        IORING_OP_WRITE_FIXED, output_pipe[1],
        buffer.base + SECOND_OFFSET, sizeof(second), 0x564552494659ull) !=
        (int)sizeof(second);
    bytes_zero(observed, sizeof(observed));
    failures += raw_syscall6(
        SYS_read, output_pipe[0], (long)observed,
        sizeof(second), 0, 0, 0) != (long)sizeof(second);
    failures += !bytes_equal(observed, second, sizeof(second));
    failures += raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_BUFFERS,
        0, 0, 0, 0) != 0;

cleanup:
    if (input_pipe[0] >= 0)
        (void)raw_syscall6(SYS_close, input_pipe[0], 0, 0, 0, 0, 0);
    if (input_pipe[1] >= 0)
        (void)raw_syscall6(SYS_close, input_pipe[1], 0, 0, 0, 0, 0);
    if (output_pipe[0] >= 0)
        (void)raw_syscall6(SYS_close, output_pipe[0], 0, 0, 0, 0, 0);
    if (output_pipe[1] >= 0)
        (void)raw_syscall6(SYS_close, output_pipe[1], 0, 0, 0, 0, 0);
    if (page)
        (void)raw_syscall6(
            SYS_munmap, (long)page, FIXED_BUFFER_SIZE, 0, 0, 0, 0);
    if (sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    static const char pass[] =
        "IO_URING_FIXED_BUFFER_PIN_ABI_PROBE_PASS\n";
    static const char fail[] =
        "IO_URING_FIXED_BUFFER_PIN_ABI_PROBE_FAIL\n";
    int failures = run_probe();
    const char *result = failures ? fail : pass;

    (void)raw_syscall6(
        SYS_write, 1, (long)result, text_length(result), 0, 0, 0);
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
