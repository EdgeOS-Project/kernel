/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 synchronous io_uring message-ring registration ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_mmap 9
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_mmap 222
#else
#error "io_uring_send_msg_ring_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_register 427
#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define EBADF 9
#define EINVAL 22
#define IORING_REGISTER_SEND_MSG_RING 31u
#define IORING_OP_NOP 0u
#define IORING_OP_MSG_RING 40u
#define IORING_MSG_DATA 0u
#define IORING_MSG_SEND_FD 1u
#define IORING_MSG_RING_CQE_SKIP (1u << 0)
#define IORING_MSG_RING_FLAGS_PASS (1u << 1)
#define IORING_CQE_F_MORE (1u << 1)
#define IORING_OFF_CQ_RING 0x08000000ull

struct io_sqring_offsets {
    uint32_t head, tail, ring_mask, ring_entries;
    uint32_t flags, dropped, array, reserved1;
    uint64_t user_address;
};
struct io_cqring_offsets {
    uint32_t head, tail, ring_mask, ring_entries;
    uint32_t overflow, cqes, flags, reserved1;
    uint64_t user_address;
};
struct io_uring_params {
    uint32_t sq_entries, cq_entries, flags;
    uint32_t sq_thread_cpu, sq_thread_idle, features;
    uint32_t workqueue_descriptor, reserved[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};
struct io_uring_sqe {
    uint8_t opcode, flags;
    uint16_t ioprio;
    int32_t descriptor;
    uint64_t offset, address;
    uint32_t length, operation_flags;
    uint64_t user_data;
    uint16_t buffer_index, personality;
    int32_t splice_descriptor;
    uint64_t address3, reserved2;
};
struct io_uring_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
};

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
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
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3),
                       "r"(x4), "r"(x5) : "memory", "cc");
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
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       text_length(text), 0, 0, 0);
}
static int failures;
static void check(const char *name, int condition) {
    if (condition) return;
    ++failures;
    print_text("FAIL "); print_text(name); print_text("\n");
}

struct target_ring {
    long descriptor;
    struct io_uring_params parameters;
    uint8_t *cq;
};

static int ring_create(struct target_ring *ring) {
    long mapping;

    bytes_zero(ring, sizeof(*ring));
    ring->descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&ring->parameters, 0, 0, 0, 0);
    if (ring->descriptor < 0) return -1;
    mapping = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
        ring->descriptor, IORING_OFF_CQ_RING);
    if (mapping < 0) return -1;
    ring->cq = (uint8_t *)(uintptr_t)mapping;
    return 0;
}

static int consume_completion(struct target_ring *ring, uint64_t user_data,
                              int32_t result, uint32_t flags) {
    volatile uint32_t *head = (volatile uint32_t *)(
        ring->cq + ring->parameters.cq_off.head);
    volatile uint32_t *tail = (volatile uint32_t *)(
        ring->cq + ring->parameters.cq_off.tail);
    volatile uint32_t *mask = (volatile uint32_t *)(
        ring->cq + ring->parameters.cq_off.ring_mask);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        ring->cq + ring->parameters.cq_off.cqes);
    struct io_uring_cqe *completion;

    if (*head == *tail) return 0;
    completion = &cqes[*head & *mask];
    if (completion->user_data != user_data ||
        completion->result != result || completion->flags != flags)
        return 0;
    *head = *head + 1u;
    return 1;
}

static long send_blind(struct io_uring_sqe *submission, uint32_t count) {
    return raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_SEND_MSG_RING,
        (long)submission, count, 0, 0);
}

static int run_probe(void) {
    struct target_ring target;
    struct io_uring_sqe submission;

    check("target setup", ring_create(&target) == 0);
    if (target.descriptor < 0 || !target.cq) return failures;

    bytes_zero(&submission, sizeof(submission));
    submission.opcode = IORING_OP_MSG_RING;
    submission.descriptor = (int32_t)target.descriptor;
    submission.offset = 0x53594e4344415441ull;
    submission.length = 321u;
    submission.ioprio = 7u;
    check("data send", send_blind(&submission, 1u) == 0);
    check("data completion", consume_completion(
        &target, submission.offset, 321, 0u));

    submission.offset = 0x53594e43464c4147ull;
    submission.length = 654u;
    submission.operation_flags = IORING_MSG_RING_FLAGS_PASS;
    submission.splice_descriptor = IORING_CQE_F_MORE;
    check("flag send", send_blind(&submission, 1u) == 0);
    check("flag completion", consume_completion(
        &target, submission.offset, 654, IORING_CQE_F_MORE));

    submission.operation_flags = IORING_MSG_RING_CQE_SKIP;
    submission.splice_descriptor = 0;
    check("reject source completion skip", send_blind(
        &submission, 1u) == -EINVAL);
    submission.operation_flags = 0u;
    submission.address = IORING_MSG_SEND_FD;
    check("reject file transfer", send_blind(&submission, 1u) == -EINVAL);
    submission.address = IORING_MSG_DATA;
    submission.flags = 1u;
    check("reject SQE flags", send_blind(&submission, 1u) == -EINVAL);
    submission.flags = 0u;
    submission.opcode = IORING_OP_NOP;
    check("reject wrong opcode", send_blind(&submission, 1u) == -EINVAL);
    submission.opcode = IORING_OP_MSG_RING;
    check("reject argument count", send_blind(&submission, 0u) == -EINVAL);
    check("reject null argument", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_SEND_MSG_RING,
        0, 1, 0, 0) == -EINVAL);
    submission.descriptor = -1;
    check("reject invalid target", send_blind(&submission, 1u) == -EBADF);

    (void)raw_syscall6(SYS_close, target.descriptor, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_SEND_MSG_RING_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
