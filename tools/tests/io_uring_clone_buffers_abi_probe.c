/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring fixed-buffer cloning ABI probe. */

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
#error "io_uring_clone_buffers_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define EBUSY 16
#define EFAULT 14
#define EINVAL 22
#define IORING_REGISTER_BUFFERS 0u
#define IORING_UNREGISTER_BUFFERS 1u
#define IORING_REGISTER_RING_FDS 20u
#define IORING_REGISTER_CLONE_BUFFERS 30u
#define IORING_REGISTER_SRC_REGISTERED (1u << 0)
#define IORING_REGISTER_DST_REPLACE (1u << 1)
#define IORING_OP_NOP 0u
#define IORING_NOP_FIXED_BUFFER (1u << 3)
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull

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
struct user_iovec {
    uint64_t base;
    uint64_t length;
};
struct io_uring_resource_update {
    uint32_t offset;
    uint32_t reserved;
    uint64_t data;
};
struct io_uring_clone_buffers {
    uint32_t source_descriptor;
    uint32_t flags;
    uint32_t source_offset;
    uint32_t destination_offset;
    uint32_t count;
    uint32_t padding[3];
};
struct mapped_ring {
    long descriptor;
    struct io_uring_params parameters;
    uint8_t *sq;
    uint8_t *cq;
    struct io_uring_sqe *sqes;
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
static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(SYS_mmap, 0, PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, (long)offset);
    return result < 0 ? (void *)0 : (void *)(uintptr_t)result;
}
static int ring_create(struct mapped_ring *ring) {
    bytes_zero(ring, sizeof(*ring));
    ring->descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&ring->parameters, 0, 0, 0, 0);
    if (ring->descriptor < 0) return -1;
    ring->sq = map_ring(ring->descriptor, IORING_OFF_SQ_RING);
    ring->cq = map_ring(ring->descriptor, IORING_OFF_CQ_RING);
    ring->sqes = map_ring(ring->descriptor, IORING_OFF_SQES);
    return ring->sq && ring->cq && ring->sqes ? 0 : -1;
}
static int32_t submit_buffer_nop(struct mapped_ring *ring,
                                 uint16_t buffer_index,
                                 uint64_t user_data) {
    volatile uint32_t *sq_tail = (volatile uint32_t *)(
        ring->sq + ring->parameters.sq_off.tail);
    volatile uint32_t *sq_array = (volatile uint32_t *)(
        ring->sq + ring->parameters.sq_off.array);
    volatile uint32_t *cq_head = (volatile uint32_t *)(
        ring->cq + ring->parameters.cq_off.head);
    volatile uint32_t *cq_tail = (volatile uint32_t *)(
        ring->cq + ring->parameters.cq_off.tail);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        ring->cq + ring->parameters.cq_off.cqes);
    uint32_t tail = *sq_tail;
    struct io_uring_sqe *sqe =
        &ring->sqes[tail & (ring->parameters.sq_entries - 1u)];
    bytes_zero(sqe, sizeof(*sqe));
    sqe->opcode = IORING_OP_NOP;
    sqe->operation_flags = IORING_NOP_FIXED_BUFFER;
    sqe->buffer_index = buffer_index;
    sqe->user_data = user_data;
    sq_array[tail & (ring->parameters.sq_entries - 1u)] =
        tail & (ring->parameters.sq_entries - 1u);
    *sq_tail = tail + 1u;
    if (raw_syscall6(SYS_io_uring_enter, ring->descriptor,
                     1, 0, 0, 0, 0) != 1 || *cq_head == *cq_tail)
        return -1000;
    {
        struct io_uring_cqe *cqe =
            &cqes[*cq_head & (ring->parameters.cq_entries - 1u)];
        int32_t result = cqe->result;
        check("completion identity", cqe->user_data == user_data);
        *cq_head = *cq_head + 1u;
        return result;
    }
}

static int run_probe(void) {
    static uint8_t first_buffer[64];
    static uint8_t second_buffer[128];
    struct user_iovec buffers[2];
    struct mapped_ring source, destination;
    struct io_uring_resource_update update;
    struct io_uring_clone_buffers clone;
    uint32_t source_slot;

    check("source setup", ring_create(&source) == 0);
    check("destination setup", ring_create(&destination) == 0);
    if (source.descriptor < 0 || destination.descriptor < 0)
        return failures;
    buffers[0].base = (uint64_t)(uintptr_t)first_buffer;
    buffers[0].length = sizeof(first_buffer);
    buffers[1].base = (uint64_t)(uintptr_t)second_buffer;
    buffers[1].length = sizeof(second_buffer);
    check("register source buffers", raw_syscall6(
        SYS_io_uring_register, source.descriptor,
        IORING_REGISTER_BUFFERS, (long)buffers, 2, 0, 0) == 0);

    bytes_zero(&update, sizeof(update));
    update.offset = UINT32_MAX;
    update.data = (uint64_t)source.descriptor;
    check("register source ring", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_REGISTER_RING_FDS, (long)&update, 1, 0, 0) == 1);
    source_slot = update.offset;

    bytes_zero(&clone, sizeof(clone));
    clone.source_descriptor = source_slot;
    clone.flags = IORING_REGISTER_SRC_REGISTERED;
    clone.source_offset = 1u;
    clone.count = 1u;
    check("clone registered source", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_REGISTER_CLONE_BUFFERS, (long)&clone, 1, 0, 0) == 0);
    check("cloned buffer usable", submit_buffer_nop(
        &destination, 0u, 0x434c4f4e45u) == 0);
    check("destination busy", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_REGISTER_CLONE_BUFFERS, (long)&clone, 1, 0, 0) == -EBUSY);

    clone.source_descriptor = (uint32_t)source.descriptor;
    clone.flags = IORING_REGISTER_DST_REPLACE;
    clone.source_offset = 0u;
    check("replace destination", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_REGISTER_CLONE_BUFFERS, (long)&clone, 1, 0, 0) == 0);
    check("replacement usable", submit_buffer_nop(
        &destination, 0u, 0x5245504c41u) == 0);
    clone.padding[0] = 1u;
    check("reserved validation", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_REGISTER_CLONE_BUFFERS, (long)&clone, 1, 0, 0) == -EINVAL);
    clone.padding[0] = 0u;
    clone.flags = 4u;
    check("flags validation", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_REGISTER_CLONE_BUFFERS, (long)&clone, 1, 0, 0) == -EINVAL);
    check("argument count", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_REGISTER_CLONE_BUFFERS, (long)&clone, 0, 0, 0) == -EINVAL);
    check("unregister cloned buffers", raw_syscall6(
        SYS_io_uring_register, destination.descriptor,
        IORING_UNREGISTER_BUFFERS, 0, 0, 0, 0) == 0);
    check("unregister source buffers", raw_syscall6(
        SYS_io_uring_register, source.descriptor,
        IORING_UNREGISTER_BUFFERS, 0, 0, 0, 0) == 0);
    (void)raw_syscall6(SYS_close, destination.descriptor, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, source.descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_CLONE_BUFFERS_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
