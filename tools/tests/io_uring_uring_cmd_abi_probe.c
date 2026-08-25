/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring URING_CMD socket ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_socket 41
#define SYS_bind 49
#define SYS_socketpair 53
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_uring_cmd_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define AF_UNIX 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1u
#define SO_TYPE 3u
#define SO_REUSEADDR 2u
#define EINVAL 22
#define EOPNOTSUPP 95

#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_SETUP_SQE128 (1u << 10)
#define IORING_OP_URING_CMD 46u
#define IORING_OP_URING_CMD128 64u
#define SOCKET_URING_OP_GETSOCKOPT 2u
#define SOCKET_URING_OP_SETSOCKOPT 3u
#define SOCKET_URING_OP_GETSOCKNAME 5u

struct user_sockaddr {
    uint16_t family;
    uint8_t data[14];
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

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int record_failure(int failed, const char *label) {
    if (failed) print_text(label);
    return failed;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int submit_one(
        long descriptor, const struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, void *sqes,
        uint32_t sqe_stride, const struct io_uring_sqe *request,
        int32_t expected) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t tail = *sq_tail;
    uint32_t index = tail & *sq_mask;

    memset((uint8_t *)sqes + (uint64_t)index * sqe_stride, 0, sqe_stride);
    *(struct io_uring_sqe *)((uint8_t *)sqes +
        (uint64_t)index * sqe_stride) = *request;
    sq_array[index] = index;
    __atomic_store_n(sq_tail, tail + 1u, __ATOMIC_RELEASE);
    if (raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1, 1, 0, 0) != 1)
        return 1;
    if (*cq_head == *cq_tail) return 1;
    index = *cq_head & parameters->cq_entries - 1u;
    if (cqes[index].user_data != request->user_data ||
        cqes[index].result != expected)
        return 1;
    __atomic_store_n(cq_head, *cq_head + 1u, __ATOMIC_RELEASE);
    return 0;
}

static int run_ring(long socket_descriptor, uint32_t setup_flags,
                    uint8_t opcode) {
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    struct user_sockaddr name;
    void *sq_ring;
    void *cq_ring;
    void *sqes;
    uint32_t name_length;
    uint32_t option_value;
    uint32_t stride = setup_flags & IORING_SETUP_SQE128 ? 128u : 64u;
    long descriptor;
    int failures = 0;

    memset(&parameters, 0, sizeof(parameters));
    parameters.flags = setup_flags;
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (descriptor < 0) {
        print_text(opcode == IORING_OP_URING_CMD128 ?
            "URING_CMD128_SETUP_FAIL\n" : "URING_CMD_SETUP_FAIL\n");
        return 1;
    }
    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        print_text(opcode == IORING_OP_URING_CMD128 ?
            "URING_CMD128_MMAP_FAIL\n" : "URING_CMD_MMAP_FAIL\n");
        return 1;
    }

    memset(&request, 0, sizeof(request));
    option_value = 0u;
    request.opcode = opcode;
    request.descriptor = (int32_t)socket_descriptor;
    request.offset = SOCKET_URING_OP_GETSOCKOPT;
    request.address = SOL_SOCKET | ((uint64_t)SO_TYPE << 32u);
    request.splice_descriptor = sizeof(option_value);
    request.address3 = (uint64_t)(uintptr_t)&option_value;
    request.user_data = 1u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, sizeof(option_value)), "GETSOCKOPT_RESULT_FAIL\n");
    failures += record_failure(
        option_value != SOCK_DGRAM, "GETSOCKOPT_VALUE_FAIL\n");

    option_value = 1u;
    request.offset = SOCKET_URING_OP_SETSOCKOPT;
    request.address = SOL_SOCKET | ((uint64_t)SO_REUSEADDR << 32u);
    request.address3 = (uint64_t)(uintptr_t)&option_value;
    request.user_data = 2u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, 0), "SETSOCKOPT_FAIL\n");

    memset(&name, 0, sizeof(name));
    name_length = sizeof(name);
    request.offset = SOCKET_URING_OP_GETSOCKNAME;
    request.address = (uint64_t)(uintptr_t)&name;
    request.length = 0u;
    request.operation_flags = 0u;
    request.splice_descriptor = 0;
    request.address3 = (uint64_t)(uintptr_t)&name_length;
    request.user_data = 3u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, 0), "GETSOCKNAME_RESULT_FAIL\n");
    failures += record_failure(
        name.family != AF_UNIX || name_length < sizeof(name.family),
        "GETSOCKNAME_VALUE_FAIL\n");

    request.offset = SOCKET_URING_OP_GETSOCKOPT | (1ull << 32u);
    request.address = SOL_SOCKET | ((uint64_t)SO_TYPE << 32u);
    request.splice_descriptor = sizeof(option_value);
    request.address3 = (uint64_t)(uintptr_t)&option_value;
    request.user_data = 4u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, -EINVAL), "PAD1_VALIDATION_FAIL\n");

    request.offset = 99u;
    request.user_data = 5u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, -EOPNOTSUPP), "UNKNOWN_COMMAND_FAIL\n");

    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int32_t sockets[2] = {-1, -1};
    long socket_descriptor = -1;
    int failures = 0;

    if (raw_syscall6(
            SYS_socketpair, AF_UNIX, SOCK_DGRAM, 0,
            (long)sockets, 0, 0) < 0) {
        print_text("SOCKETPAIR_FAIL\n");
        failures = 1;
    } else {
        socket_descriptor = sockets[0];
    }
    if (!failures)
        failures += run_ring(socket_descriptor, 0u, IORING_OP_URING_CMD);
    if (!failures)
        failures += run_ring(
            socket_descriptor, IORING_SETUP_SQE128,
            IORING_OP_URING_CMD128);
    if (socket_descriptor >= 0)
        (void)raw_syscall6(SYS_close, socket_descriptor, 0, 0, 0, 0, 0);
    if (sockets[1] >= 0)
        (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
    print_text(failures ? "io-uring-uring-cmd: FAIL\n" :
                          "io-uring-uring-cmd: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
