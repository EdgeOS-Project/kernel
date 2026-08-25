/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring ring-resize ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mincore 27
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_mincore 232
#else
#error "io_uring_resize_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define ENOMEM 12
#define EINVAL 22
#define EOVERFLOW 75

#define IORING_SETUP_CQSIZE (1u << 3)
#define IORING_SETUP_SINGLE_ISSUER (1u << 12)
#define IORING_SETUP_DEFER_TASKRUN (1u << 13)
#define IORING_REGISTER_RESIZE_RINGS 33u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_OP_NOP 0u

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

struct mapped_ring {
    uint8_t *sq;
    uint8_t *cq;
    struct io_uring_sqe *sqes;
    volatile uint32_t *sq_head;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_entries;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    volatile uint32_t *cq_entries;
    struct io_uring_cqe *cqes;
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

static void *map_region(long ring, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, ring, (long)offset);
    return result < 0 ? (void *)0 : (void *)(uintptr_t)result;
}

static int map_ring(long ring, const struct io_uring_params *parameters,
                    struct mapped_ring *mapping) {
    bytes_zero(mapping, sizeof(*mapping));
    mapping->sq = map_region(ring, IORING_OFF_SQ_RING);
    mapping->cq = map_region(ring, IORING_OFF_CQ_RING);
    mapping->sqes = map_region(ring, IORING_OFF_SQES);
    if (!mapping->sq || !mapping->cq || !mapping->sqes) return -1;
    mapping->sq_head = (volatile uint32_t *)(
        mapping->sq + parameters->sq_off.head);
    mapping->sq_tail = (volatile uint32_t *)(
        mapping->sq + parameters->sq_off.tail);
    mapping->sq_mask = (volatile uint32_t *)(
        mapping->sq + parameters->sq_off.ring_mask);
    mapping->sq_entries = (volatile uint32_t *)(
        mapping->sq + parameters->sq_off.ring_entries);
    mapping->sq_array = (volatile uint32_t *)(
        mapping->sq + parameters->sq_off.array);
    mapping->cq_head = (volatile uint32_t *)(
        mapping->cq + parameters->cq_off.head);
    mapping->cq_tail = (volatile uint32_t *)(
        mapping->cq + parameters->cq_off.tail);
    mapping->cq_mask = (volatile uint32_t *)(
        mapping->cq + parameters->cq_off.ring_mask);
    mapping->cq_entries = (volatile uint32_t *)(
        mapping->cq + parameters->cq_off.ring_entries);
    mapping->cqes = (struct io_uring_cqe *)(
        mapping->cq + parameters->cq_off.cqes);
    return 0;
}

static void queue_nop(struct mapped_ring *ring, uint64_t user_data) {
    uint32_t tail = *ring->sq_tail;
    uint32_t index = tail & *ring->sq_mask;
    struct io_uring_sqe *sqe = &ring->sqes[index];
    bytes_zero(sqe, sizeof(*sqe));
    sqe->opcode = IORING_OP_NOP;
    sqe->user_data = user_data;
    ring->sq_array[index] = index;
    __atomic_store_n(ring->sq_tail, tail + 1u, __ATOMIC_RELEASE);
}

static int mapping_is_present(void *address) {
    uint8_t residency = 0u;
    return raw_syscall6(
        SYS_mincore, (long)address, PAGE_SIZE,
        (long)&residency, 0, 0, 0) != -ENOMEM;
}

static int run_probe(void) {
    struct io_uring_params ordinary;
    struct io_uring_params parameters;
    struct io_uring_params resize;
    struct mapped_ring old_mapping;
    struct mapped_ring new_mapping;
    long ordinary_ring;
    long ring;

    bytes_zero(&ordinary, sizeof(ordinary));
    ordinary_ring = raw_syscall6(
        SYS_io_uring_setup, 4, (long)&ordinary, 0, 0, 0, 0);
    check("ordinary setup", ordinary_ring >= 0);
    if (ordinary_ring >= 0) {
        bytes_zero(&resize, sizeof(resize));
        resize.sq_entries = 8u;
        check("defer requirement", raw_syscall6(
            SYS_io_uring_register, ordinary_ring,
            IORING_REGISTER_RESIZE_RINGS, (long)&resize,
            1, 0, 0) == -EINVAL);
        (void)raw_syscall6(SYS_close, ordinary_ring, 0, 0, 0, 0, 0);
    }

    bytes_zero(&parameters, sizeof(parameters));
    parameters.flags =
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
    ring = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    check("deferred setup", ring >= 0);
    if (ring < 0) return failures;

    check("null argument", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESIZE_RINGS,
        0, 1, 0, 0) == -EINVAL);
    bytes_zero(&resize, sizeof(resize));
    resize.sq_entries = 16u;
    check("argument count", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESIZE_RINGS,
        (long)&resize, 0, 0, 0) == -EINVAL);

    check("initial mappings", map_ring(ring, &parameters, &old_mapping) == 0);
    if (!old_mapping.sq || !old_mapping.cq || !old_mapping.sqes)
        goto close_ring;

    queue_nop(&old_mapping, 0x1111u);
    queue_nop(&old_mapping, 0x2222u);
    check("initial submit", raw_syscall6(
        SYS_io_uring_enter, ring, 2, 0, 0, 0, 0) == 2);
    check("initial completions", *old_mapping.cq_tail -
        *old_mapping.cq_head == 2u);
    queue_nop(&old_mapping, 0x3333u);
    queue_nop(&old_mapping, 0x4444u);

    bytes_zero(&resize, sizeof(resize));
    resize.sq_entries = 16u;
    resize.cq_entries = 32u;
    resize.flags = IORING_SETUP_CQSIZE;
    check("grow rings", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESIZE_RINGS,
        (long)&resize, 1, 0, 0) == 0);
    check("returned sizes", resize.sq_entries == 16u &&
        resize.cq_entries == 32u);
    check("old sq retained", mapping_is_present(old_mapping.sq));
    check("old cq retained", mapping_is_present(old_mapping.cq));
    check("old sqes retained", mapping_is_present(old_mapping.sqes));
    check("old mapping readable", *old_mapping.sq_entries == 8u &&
        *old_mapping.sq_tail == 4u &&
        old_mapping.cqes[*old_mapping.cq_head &
                         *old_mapping.cq_mask].user_data == 0x1111u);

    check("replacement mappings", map_ring(ring, &resize, &new_mapping) == 0);
    if (!new_mapping.sq || !new_mapping.cq || !new_mapping.sqes)
        goto close_ring;
    check("ring geometry", *new_mapping.sq_entries == 16u &&
        *new_mapping.cq_entries == 32u &&
        *new_mapping.sq_mask == 15u && *new_mapping.cq_mask == 31u);
    check("pending sq preserved", *new_mapping.sq_tail -
        *new_mapping.sq_head == 2u);
    check("pending sq payload", new_mapping.sqes[
        new_mapping.sq_array[*new_mapping.sq_head &
                             *new_mapping.sq_mask]].user_data == 0x3333u);
    check("pending cq preserved", *new_mapping.cq_tail -
        *new_mapping.cq_head == 2u);
    check("pending cq payload", new_mapping.cqes[
        *new_mapping.cq_head & *new_mapping.cq_mask].user_data == 0x1111u);

    bytes_zero(&parameters, sizeof(parameters));
    parameters.sq_entries = 1u;
    parameters.cq_entries = 1u;
    parameters.flags = IORING_SETUP_CQSIZE;
    check("shrink overflow", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESIZE_RINGS,
        (long)&parameters, 1, 0, 0) == -EOVERFLOW);
    check("failed resize keeps mappings", mapping_is_present(new_mapping.sq));

close_ring:
    (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_RESIZE_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
