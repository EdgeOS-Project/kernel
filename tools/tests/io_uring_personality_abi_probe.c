/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring personality ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_getuid 102
#define SYS_setuid 105
#define SYS_openat 257
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_setuid 146
#define SYS_getuid 174
#define SYS_mmap 222
#else
#error "io_uring_personality_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define EACCES 13
#define EINVAL 22
#define AT_FDCWD (-100)
#define O_RDONLY 0u
#define O_WRONLY 1u
#define O_CREAT 64u
#define O_TRUNC 512u
#define IORING_REGISTER_PERSONALITY 9u
#define IORING_UNREGISTER_PERSONALITY 10u
#define IORING_OP_NOP 0u
#define IORING_OP_OPENAT 18u
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

struct mapped_ring {
    struct io_uring_params parameters;
    long descriptor;
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

static void *map_ring(long ring, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, ring, (long)offset);
    return result < 0 ? (void *)0 : (void *)(uintptr_t)result;
}

static int ring_initialize(struct mapped_ring *ring) {
    bytes_zero(ring, sizeof(*ring));
    ring->descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&ring->parameters, 0, 0, 0, 0);
    if (ring->descriptor < 0) return -1;
    ring->sq = map_ring(ring->descriptor, IORING_OFF_SQ_RING);
    ring->cq = map_ring(ring->descriptor, IORING_OFF_CQ_RING);
    ring->sqes = map_ring(ring->descriptor, IORING_OFF_SQES);
    return ring->sq && ring->cq && ring->sqes ? 0 : -1;
}

static int32_t ring_submit(struct mapped_ring *ring, uint8_t opcode,
                           uint16_t personality, const char *path,
                           uint64_t user_data) {
    volatile uint32_t *sq_tail =
        (volatile uint32_t *)(ring->sq + ring->parameters.sq_off.tail);
    volatile uint32_t *sq_array =
        (volatile uint32_t *)(ring->sq + ring->parameters.sq_off.array);
    volatile uint32_t *cq_head =
        (volatile uint32_t *)(ring->cq + ring->parameters.cq_off.head);
    volatile uint32_t *cq_tail =
        (volatile uint32_t *)(ring->cq + ring->parameters.cq_off.tail);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        ring->cq + ring->parameters.cq_off.cqes);
    uint32_t tail = *sq_tail;
    struct io_uring_sqe *submission =
        &ring->sqes[tail & (ring->parameters.sq_entries - 1u)];

    bytes_zero(submission, sizeof(*submission));
    submission->opcode = opcode;
    submission->descriptor = AT_FDCWD;
    submission->address = (uint64_t)(uintptr_t)path;
    submission->operation_flags = O_RDONLY;
    submission->user_data = user_data;
    submission->personality = personality;
    sq_array[tail & (ring->parameters.sq_entries - 1u)] =
        tail & (ring->parameters.sq_entries - 1u);
    *sq_tail = tail + 1u;
    if (raw_syscall6(SYS_io_uring_enter, ring->descriptor,
                     1, 0, 0, 0, 0) != 1)
        return -1000;
    if (*cq_head == *cq_tail) return -1001;
    {
        struct io_uring_cqe *completion =
            &cqes[*cq_head & (ring->parameters.cq_entries - 1u)];
        int32_t result = completion->result;
        check("completion identity", completion->user_data == user_data);
        *cq_head = *cq_head + 1u;
        return result;
    }
}

static int run_probe(void) {
    static const char secret_path[] = "/personality-secret";
    struct mapped_ring ring;
    long secret;
    long personality;
    int32_t result;

    secret = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)secret_path,
        O_WRONLY | O_CREAT | O_TRUNC, 0600, 0, 0);
    check("create secret", secret >= 0);
    if (secret >= 0)
        (void)raw_syscall6(SYS_close, secret, 0, 0, 0, 0, 0);
    check("ring setup", ring_initialize(&ring) == 0);
    if (ring.descriptor < 0) return failures;

    check("register argument validation", raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PERSONALITY, 1, 0, 0, 0) == -EINVAL);
    personality = raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PERSONALITY, 0, 0, 0, 0);
    check("register personality", personality > 0 && personality <= 65535);
    check("drop credentials", raw_syscall6(
        SYS_setuid, 1000, 0, 0, 0, 0, 0) == 0);
    check("credentials dropped", raw_syscall6(
        SYS_getuid, 0, 0, 0, 0, 0, 0) == 1000);

    result = ring_submit(
        &ring, IORING_OP_OPENAT, 0u, secret_path, 0x5001u);
    check("default credentials denied", result == -EACCES);
    result = ring_submit(
        &ring, IORING_OP_OPENAT, (uint16_t)personality,
        secret_path, 0x5002u);
    check("registered credentials applied", result >= 0);
    if (result >= 0)
        (void)raw_syscall6(SYS_close, result, 0, 0, 0, 0, 0);
    check("credentials restored", raw_syscall6(
        SYS_getuid, 0, 0, 0, 0, 0, 0) == 1000);

    check("unregister personality", raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_UNREGISTER_PERSONALITY, 0, personality, 0, 0) == 0);
    check("repeat unregister", raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_UNREGISTER_PERSONALITY, 0, personality, 0, 0) == -EINVAL);
    result = ring_submit(
        &ring, IORING_OP_NOP, (uint16_t)personality, 0, 0x5003u);
    check("unregistered personality rejected", result == -EINVAL);
    (void)raw_syscall6(SYS_close, ring.descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_PERSONALITY_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
