/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring restrictions ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_mmap 9
#define SYS_prctl 157
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_prctl 167
#define SYS_mmap 222
#else
#error "io_uring_restrictions_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define EACCES 13
#define EPERM 1
#define EINVAL 22
#define EBUSY 16
#define EBADFD 77

#define IORING_SETUP_R_DISABLED (1u << 6)
#define IORING_REGISTER_PROBE 8u
#define IORING_REGISTER_RESTRICTIONS 11u
#define IORING_REGISTER_ENABLE_RINGS 12u
#define IORING_UNREGISTER_EVENTFD 5u
#define IORING_RESTRICTION_REGISTER_OP 0u
#define IORING_RESTRICTION_SQE_OP 1u
#define IORING_RESTRICTION_SQE_FLAGS_ALLOWED 2u
#define IORING_OP_NOP 0u
#define IORING_OP_READ 22u
#define IOSQE_ASYNC (1u << 4)
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define PR_SET_NO_NEW_PRIVS 38u

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

struct io_uring_restriction {
    uint16_t opcode;
    uint8_t operation;
    uint8_t reserved;
    uint32_t reserved2[3];
};

struct io_uring_task_restriction {
    uint16_t flags;
    uint16_t restriction_count;
    uint32_t reserved[3];
};

struct task_restriction_packet {
    struct io_uring_task_restriction header;
    struct io_uring_restriction restrictions[3];
};

struct io_uring_probe {
    uint8_t last_operation;
    uint8_t operation_count;
    uint16_t reserved;
    uint32_t reserved2[3];
    uint8_t operation[8];
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

static void *map_ring(long ring, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, ring, (long)offset);
    return result < 0 ? (void *)0 : (void *)(uintptr_t)result;
}

static void submit_one(long ring, struct io_uring_params *parameters,
                       uint8_t opcode, uint8_t flags, uint64_t user_data,
                       int32_t expected) {
    uint8_t *sq = map_ring(ring, IORING_OFF_SQ_RING);
    uint8_t *cq = map_ring(ring, IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = map_ring(ring, IORING_OFF_SQES);
    volatile uint32_t *sq_head;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    struct io_uring_cqe *cqes;
    uint32_t tail;

    check("map rings", sq && cq && sqes);
    if (!sq || !cq || !sqes) return;
    sq_head = (volatile uint32_t *)(sq + parameters->sq_off.head);
    sq_tail = (volatile uint32_t *)(sq + parameters->sq_off.tail);
    sq_array = (volatile uint32_t *)(sq + parameters->sq_off.array);
    cq_head = (volatile uint32_t *)(cq + parameters->cq_off.head);
    cq_tail = (volatile uint32_t *)(cq + parameters->cq_off.tail);
    cqes = (struct io_uring_cqe *)(cq + parameters->cq_off.cqes);
    tail = *sq_tail;
    bytes_zero(&sqes[tail & (parameters->sq_entries - 1u)],
               sizeof(struct io_uring_sqe));
    sqes[tail & (parameters->sq_entries - 1u)].opcode = opcode;
    sqes[tail & (parameters->sq_entries - 1u)].flags = flags;
    sqes[tail & (parameters->sq_entries - 1u)].user_data = user_data;
    sq_array[tail & (parameters->sq_entries - 1u)] =
        tail & (parameters->sq_entries - 1u);
    *sq_tail = tail + 1u;
    check("enter", raw_syscall6(
        SYS_io_uring_enter, ring, 1, 0, 0, 0, 0) == 1);
    check("completion available", *cq_tail != *cq_head);
    if (*cq_tail != *cq_head) {
        struct io_uring_cqe *completion =
            &cqes[*cq_head & (parameters->cq_entries - 1u)];
        check("completion identity", completion->user_data == user_data);
        check("completion result", completion->result == expected);
        *cq_head = *cq_head + 1u;
    }
    (void)sq_head;
}

static int run_probe(void) {
    struct io_uring_params normal_parameters;
    struct io_uring_params parameters;
    struct io_uring_restriction restrictions[4];
    struct io_uring_probe probe;
    struct task_restriction_packet task_packet;
    struct io_uring_params task_parameters;
    long normal_ring;
    long ring;

    bytes_zero(&normal_parameters, sizeof(normal_parameters));
    normal_ring = raw_syscall6(
        SYS_io_uring_setup, 4, (long)&normal_parameters, 0, 0, 0, 0);
    check("normal setup", normal_ring >= 0);
    bytes_zero(restrictions, sizeof(restrictions));
    restrictions[0].opcode = IORING_RESTRICTION_SQE_OP;
    restrictions[0].operation = IORING_OP_NOP;
    check("requires disabled setup", raw_syscall6(
        SYS_io_uring_register, normal_ring, IORING_REGISTER_RESTRICTIONS,
        (long)restrictions, 1, 0, 0) == -EBADFD);
    (void)raw_syscall6(SYS_close, normal_ring, 0, 0, 0, 0, 0);

    bytes_zero(&parameters, sizeof(parameters));
    parameters.flags = IORING_SETUP_R_DISABLED;
    ring = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    check("disabled setup", ring >= 0);
    if (ring < 0) return failures;

    bytes_zero(restrictions, sizeof(restrictions));
    restrictions[0].opcode = IORING_RESTRICTION_REGISTER_OP;
    restrictions[0].operation = IORING_REGISTER_ENABLE_RINGS;
    restrictions[1].opcode = IORING_RESTRICTION_REGISTER_OP;
    restrictions[1].operation = IORING_REGISTER_PROBE;
    restrictions[2].opcode = IORING_RESTRICTION_SQE_OP;
    restrictions[2].operation = IORING_OP_NOP;
    restrictions[3].opcode = IORING_RESTRICTION_SQE_FLAGS_ALLOWED;
    restrictions[3].operation = 0u;
    check("register restrictions", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESTRICTIONS,
        (long)restrictions, 4, 0, 0) == 0);
    check("single registration", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESTRICTIONS,
        (long)restrictions, 4, 0, 0) == -EBUSY);
    check("enable", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_ENABLE_RINGS,
        0, 0, 0, 0) == 0);

    bytes_zero(&probe, sizeof(probe));
    check("allowed register", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_PROBE,
        (long)&probe, 1, 0, 0) == 0);
    check("denied register", raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_EVENTFD,
        0, 0, 0, 0) == -EACCES);
    submit_one(ring, &parameters, IORING_OP_NOP, 0u, 0x1001u, 0);
    submit_one(ring, &parameters, IORING_OP_READ, 0u, 0x1002u, -EACCES);
    submit_one(ring, &parameters, IORING_OP_NOP, IOSQE_ASYNC,
               0x1003u, -EACCES);

    restrictions[0].reserved = 1u;
    check("reserved validation", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESTRICTIONS,
        (long)restrictions, 1, 0, 0) == -EACCES);
    check("null restrictions", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_RESTRICTIONS,
        0, 0, 0, 0) == -EACCES);
    (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);

    check("set no new privileges", raw_syscall6(
        SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) == 0);
    bytes_zero(&task_packet, sizeof(task_packet));
    task_packet.header.restriction_count = 3u;
    task_packet.restrictions[0].opcode =
        IORING_RESTRICTION_REGISTER_OP;
    task_packet.restrictions[0].operation = IORING_REGISTER_PROBE;
    task_packet.restrictions[1].opcode = IORING_RESTRICTION_SQE_OP;
    task_packet.restrictions[1].operation = IORING_OP_NOP;
    task_packet.restrictions[2].opcode =
        IORING_RESTRICTION_SQE_FLAGS_ALLOWED;
    check("task restriction count", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_RESTRICTIONS,
        (long)&task_packet, 0, 0, 0) == -EINVAL);
    task_packet.header.flags = 1u;
    check("task restriction flags", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_RESTRICTIONS,
        (long)&task_packet, 1, 0, 0) == -EINVAL);
    task_packet.header.flags = 0u;
    check("task restrictions", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_RESTRICTIONS,
        (long)&task_packet, 1, 0, 0) == 0);
    check("task restrictions single registration", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_RESTRICTIONS,
        0, 0, 0, 0) == -EPERM);

    bytes_zero(&task_parameters, sizeof(task_parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 4, (long)&task_parameters, 0, 0, 0, 0);
    check("task-restricted setup", ring >= 0);
    if (ring >= 0) {
        bytes_zero(&probe, sizeof(probe));
        check("task allowed register", raw_syscall6(
            SYS_io_uring_register, ring, IORING_REGISTER_PROBE,
            (long)&probe, 1, 0, 0) == 0);
        check("task denied register", raw_syscall6(
            SYS_io_uring_register, ring, IORING_UNREGISTER_EVENTFD,
            0, 0, 0, 0) == -EACCES);
        submit_one(ring, &task_parameters, IORING_OP_NOP, 0u,
                   0x2001u, 0);
        submit_one(ring, &task_parameters, IORING_OP_READ, 0u,
                   0x2002u, -EACCES);
        (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
    }
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_RESTRICTIONS_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
