/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring capability-query ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#else
#error "io_uring_query_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_register 427

#define EINVAL 22
#define EOPNOTSUPP 95

#define IORING_REGISTER_QUERY 35u
#define IORING_OP_LAST 65u
#define IORING_REGISTER_LAST 38u

#define IORING_SETUP_CQSIZE (1u << 3)
#define IORING_SETUP_CLAMP (1u << 4)
#define IORING_SETUP_R_DISABLED (1u << 6)
#define IORING_SETUP_SUBMIT_ALL (1u << 7)
#define IORING_SETUP_COOP_TASKRUN (1u << 8)
#define IORING_SETUP_TASKRUN_FLAG (1u << 9)
#define IORING_SETUP_SQE128 (1u << 10)
#define IORING_SETUP_CQE32 (1u << 11)
#define IORING_SETUP_SINGLE_ISSUER (1u << 12)
#define IORING_SETUP_DEFER_TASKRUN (1u << 13)
#define IORING_SETUP_NO_SQARRAY (1u << 16)
#define IORING_SETUP_CQE_MIXED (1u << 18)
#define IORING_SETUP_SQE_MIXED (1u << 19)
#define IORING_SETUP_SQ_REWIND (1u << 20)
#define EXPECTED_SETUP_FLAGS \
    (IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | \
     IORING_SETUP_R_DISABLED | IORING_SETUP_SUBMIT_ALL | \
     IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG | \
     IORING_SETUP_SQE128 | IORING_SETUP_CQE32 | \
     IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | \
     IORING_SETUP_NO_SQARRAY | IORING_SETUP_CQE_MIXED | \
     IORING_SETUP_SQE_MIXED | IORING_SETUP_SQ_REWIND)
#define FROZEN_LINUX_SETUP_FLAGS 0x1fffffu

#define EXPECTED_ENTER_FLAGS 0xfbu
#define FROZEN_LINUX_ENTER_FLAGS 0xffu
#define EXPECTED_SQE_FLAGS 0x7fu

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

struct io_uring_query_header {
    uint64_t next_entry;
    uint64_t query_data;
    uint32_t query_opcode;
    uint32_t size;
    int32_t result;
    uint32_t reserved[3];
};

struct io_uring_query_opcodes {
    uint32_t request_opcode_count;
    uint32_t register_opcode_count;
    uint64_t feature_flags;
    uint64_t setup_flags;
    uint64_t enter_flags;
    uint64_t sqe_flags;
    uint32_t query_opcode_count;
    uint32_t padding;
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

static void bytes_fill(void *destination, uint8_t value, uint32_t size) {
    uint8_t *bytes = destination;
    for (uint32_t index = 0; index < size; ++index) bytes[index] = value;
}

static void bytes_zero(void *destination, uint32_t size) {
    bytes_fill(destination, 0u, size);
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

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_query_header first_header;
    struct io_uring_query_header second_header;
    struct io_uring_query_header invalid_header;
    union {
        struct io_uring_query_opcodes query;
        uint8_t bytes[64];
    } first_data;
    uint8_t second_data[16];
    long descriptor;

    bytes_zero(&parameters, sizeof(parameters));
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 4, (long)&parameters, 0, 0, 0, 0);
    check("setup", descriptor >= 0);
    if (descriptor < 0) return failures;

    bytes_zero(&first_header, sizeof(first_header));
    bytes_zero(&second_header, sizeof(second_header));
    bytes_fill(&first_data, 0xa5u, sizeof(first_data));
    bytes_fill(second_data, 0xa5u, sizeof(second_data));
    first_header.next_entry = (uint64_t)(uintptr_t)&second_header;
    first_header.query_data = (uint64_t)(uintptr_t)&first_data;
    first_header.query_opcode = 0u;
    first_header.size = sizeof(first_data);
    second_header.query_data = (uint64_t)(uintptr_t)second_data;
    second_header.query_opcode = 0xffffffffu;
    second_header.size = sizeof(second_data);
    check("linked query", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_QUERY,
        (long)&first_header, 0, 0, 0) == 0);
    check("opcode query result",
          first_header.result == 0 &&
          first_header.size == sizeof(first_data.query));
    check("opcode extents",
          first_data.query.request_opcode_count == IORING_OP_LAST &&
          first_data.query.register_opcode_count == IORING_REGISTER_LAST &&
          first_data.query.query_opcode_count >= 1u);
    check("feature query",
          first_data.query.feature_flags == parameters.features);
    check("setup query",
          first_data.query.setup_flags == EXPECTED_SETUP_FLAGS ||
          first_data.query.setup_flags == FROZEN_LINUX_SETUP_FLAGS);
    check("enter query",
          first_data.query.enter_flags == EXPECTED_ENTER_FLAGS ||
          first_data.query.enter_flags == FROZEN_LINUX_ENTER_FLAGS);
    check("sqe query", first_data.query.sqe_flags == EXPECTED_SQE_FLAGS);
    for (uint32_t index = sizeof(first_data.query);
         index < sizeof(first_data.bytes); ++index)
        check("query zero tail", first_data.bytes[index] == 0u);
    check("unknown query result",
          second_header.result == -EOPNOTSUPP && second_header.size == 0u);
    for (uint32_t index = 0; index < sizeof(second_data); ++index)
        check("unknown query zero data", second_data[index] == 0u);

    check("query count validation", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_QUERY,
        (long)&first_header, 1, 0, 0) == -EINVAL);
    check("empty query list", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_QUERY,
        0, 0, 0, 0) == 0);

    bytes_zero(&invalid_header, sizeof(invalid_header));
    invalid_header.query_opcode = 0u;
    check("zero-size entry", raw_syscall6(
        SYS_io_uring_register, -1, IORING_REGISTER_QUERY,
        (long)&invalid_header, 0, 0, 0) == 0 &&
        invalid_header.result == -EINVAL && invalid_header.size == 0u);

    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_QUERY_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
