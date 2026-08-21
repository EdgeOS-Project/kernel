/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux io_uring ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_fsetxattr 190
#define SYS_fgetxattr 193
#define SYS_flistxattr 196
#define SYS_fremovexattr 199
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_fsetxattr 7
#define SYS_fgetxattr 10
#define SYS_flistxattr 13
#define SYS_fremovexattr 16
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#if defined(__x86_64__)
#define SYS_read 0
#define SYS_eventfd2 290
#define SYS_socket 41
#define SYS_socketpair 53
#define SYS_bind 49
#define SYS_listen 50
#define SYS_epoll_create1 291
#define SYS_pipe2 293
struct linux_epoll_event {
    uint32_t events;
    uint64_t data;
} __attribute__((packed));
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_eventfd2 19
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_listen 201
#define SYS_epoll_create1 20
#define SYS_pipe2 59
struct linux_epoll_event {
    uint32_t events;
    uint64_t data;
};
#endif

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define PAGE_SIZE 4096u
#define ENXIO 6
#define EBADF 9
#define ESPIPE 29
#define EBUSY 16
#define EEXIST 17
#define EINVAL 22
#define ERANGE 34
#define ENODATA 61
#define EOVERFLOW 75
#define EBADFD 77
#define AT_FDCWD (-100)
#define O_RDWR 2u
#define O_CREAT 64u
#define O_TRUNC 512u
#define IORING_ENTER_GETEVENTS 1u
#define IORING_ENTER_EXT_ARG (1u << 3)
#define IORING_SETUP_R_DISABLED (1u << 6)
#define IOSQE_FIXED_FILE (1u << 0)
#define IOSQE_IO_LINK (1u << 2)
#define IORING_REGISTER_FILES 2u
#define IORING_UNREGISTER_FILES 3u
#define IORING_REGISTER_PROBE 8u
#define IORING_REGISTER_EVENTFD 4u
#define IORING_UNREGISTER_EVENTFD 5u
#define IO_URING_OP_SUPPORTED 1u
#define IORING_OP_NOP 0u
#define IORING_OP_SYNC_FILE_RANGE 8u
#define IORING_OP_READ 22u
#define IORING_OP_WRITE 23u
#define IORING_OP_FADVISE 24u
#define IORING_OP_MADVISE 25u
#define IORING_OP_POLL_ADD 6u
#define IORING_OP_SENDMSG 9u
#define IORING_OP_RECVMSG 10u
#define IORING_OP_TIMEOUT 11u
#define IORING_OP_TIMEOUT_REMOVE 12u
#define IORING_OP_ACCEPT 13u
#define IORING_OP_CONNECT 16u
#define IORING_OP_FALLOCATE 17u
#define IORING_OP_OPENAT 18u
#define IORING_OP_CLOSE 19u
#define IORING_OP_STATX 21u
#define IORING_OP_OPENAT2 28u
#define IORING_OP_EPOLL_CTL 29u
#define IORING_OP_SPLICE 30u
#define IORING_OP_SEND 26u
#define IORING_OP_RECV 27u
#define IORING_OP_TEE 33u
#define IORING_OP_SHUTDOWN 34u
#define IORING_OP_RENAMEAT 35u
#define IORING_OP_UNLINKAT 36u
#define IORING_OP_MKDIRAT 37u
#define IORING_OP_SYMLINKAT 38u
#define IORING_OP_LINKAT 39u
#define IORING_OP_MSG_RING 40u
#define IORING_OP_FSETXATTR 41u
#define IORING_OP_SETXATTR 42u
#define IORING_OP_FGETXATTR 43u
#define IORING_OP_GETXATTR 44u
#define IORING_OP_SOCKET 45u
#define IORING_OP_FUTEX_WAKE 52u
#define IORING_OP_FTRUNCATE 55u
#define IORING_OP_BIND 56u
#define IORING_OP_LISTEN 57u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define PROBE_OPERATION_COUNT 65u
#define POLLIN 0x0001u
#define ETIME 62
#define ECANCELED 125
#define AF_UNIX 1
#define SOCK_STREAM 1
#define EPOLLIN 1u
#define EPOLL_CTL_ADD 1u
#define MADV_DONTNEED 4u
#define POSIX_FADV_NORMAL 0u
#define AT_REMOVEDIR 0x200u
#define XATTR_CREATE 1u
#define XATTR_REPLACE 2u
#define SYNC_FILE_RANGE_WRITE 2u
#define SYNC_FILE_RANGE_WAIT_AFTER 4u
#define FUTEX2_SIZE_U32 2u
#define SPLICE_F_FD_IN_FIXED (1u << 31)
#define IORING_MSG_RING_CQE_SKIP (1u << 0)
#define IORING_MSG_RING_FLAGS_PASS (1u << 1)
#define IORING_MSG_DATA 0u
#define IORING_MSG_SEND_FD 1u
#define IORING_FILE_INDEX_ALLOC UINT32_MAX
#define IORING_SQ_CQ_OVERFLOW (1u << 1)

struct kernel_timespec {
    int64_t seconds;
    int64_t nanoseconds;
};

struct io_uring_getevents_arg {
    uint64_t signal_mask;
    uint32_t signal_mask_size;
    uint32_t minimum_wait_microseconds;
    uint64_t timeout;
};

struct open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct user_iovec {
    uint64_t base;
    uint64_t length;
};

struct user_msghdr {
    uint64_t name;
    uint32_t name_length;
    uint32_t padding1;
    uint64_t vectors;
    uint64_t vector_count;
    uint64_t control;
    uint64_t control_length;
    uint32_t flags;
    uint32_t padding2;
};

struct user_sockaddr_un {
    uint16_t family;
    char path[108];
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

struct io_uring_probe_op {
    uint8_t opcode;
    uint8_t reserved;
    uint16_t flags;
    uint32_t reserved2;
};

struct io_uring_probe {
    uint8_t last_opcode;
    uint8_t operation_count;
    uint16_t reserved;
    uint32_t reserved2[3];
    struct io_uring_probe_op operations[PROBE_OPERATION_COUNT];
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

void *memcpy(void *destination, const void *source, unsigned long length) {
    unsigned char *output = destination;
    const unsigned char *input = source;
    for (unsigned long index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static void print_integer(int64_t value) {
    char buffer[32];
    unsigned long length = 0;
    uint64_t magnitude;
    if (value < 0) {
        buffer[length++] = '-';
        magnitude = (uint64_t)(-(value + 1)) + 1u;
    } else {
        magnitude = (uint64_t)value;
    }
    {
        char digits[24];
        unsigned long count = 0;
        do {
            digits[count++] = (char)('0' + magnitude % 10u);
            magnitude /= 10u;
        } while (magnitude);
        while (count) buffer[length++] = digits[--count];
    }
    buffer[length++] = '\n';
    (void)raw_syscall6(SYS_write, 1, (long)buffer, (long)length,
                       0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    print_text("actual/expected\n");
    print_integer(actual);
    print_integer(expected);
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int submit_one(
        long ring_descriptor, volatile uint32_t *sq_tail,
        volatile uint32_t *sq_mask, volatile uint32_t *sq_array,
        struct io_uring_sqe *sqes, volatile uint32_t *cq_head,
        volatile uint32_t *cq_tail, volatile uint32_t *cq_mask,
        struct io_uring_cqe *cqes, const struct io_uring_sqe *request,
        uint64_t user_data, const char *name, int32_t *result) {
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t submission_slot = submission & *sq_mask;
    uint32_t completion_slot = completion & *cq_mask;
    int failures = 0;

    sqes[submission_slot] = *request;
    sqes[submission_slot].user_data = user_data;
    sq_array[submission_slot] = submission_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    failures += expect(name, raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true(name,
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == completion + 1u &&
        cqes[completion_slot].user_data == user_data);
    if (result)
        *result = cqes[completion_slot].result;
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return failures;
}

static int run_splice_only(
        long ring_descriptor, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    static const char data[] = "splice!";
    char output[sizeof(data)] = {0};
    int32_t input_pipe[2] = {-1, -1};
    int32_t output_pipe[2] = {-1, -1};
    int32_t fixed_files[2];
    struct io_uring_sqe request;
    int32_t result = -1;
    int files_registered = 0;
    int failures = 0;

    failures += expect("splice-only input pipe", raw_syscall6(
        SYS_pipe2, (long)input_pipe, 0, 0, 0, 0, 0), 0);
    failures += expect("splice-only output pipe", raw_syscall6(
        SYS_pipe2, (long)output_pipe, 0, 0, 0, 0, 0), 0);
    if (input_pipe[0] < 0 || input_pipe[1] < 0 ||
        output_pipe[0] < 0 || output_pipe[1] < 0)
        goto cleanup;
    failures += expect("splice-only input write", raw_syscall6(
        SYS_write, input_pipe[1], (long)data, sizeof(data), 0, 0, 0),
        sizeof(data));
    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SPLICE;
    request.descriptor = output_pipe[1];
    request.offset = UINT64_MAX;
    request.address = UINT64_MAX;
    request.length = sizeof(data);
    request.splice_descriptor = input_pipe[0];
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x53504c4943454e4full, "splice-only submit", &result);
    failures += expect("splice-only completion", result, sizeof(data));
    failures += expect("splice-only output read", raw_syscall6(
        SYS_read, output_pipe[0], (long)output, sizeof(output), 0, 0, 0),
        sizeof(data));
    for (uint32_t index = 0; index < sizeof(data); ++index)
        failures += expect_true("splice-only output data",
                                output[index] == data[index]);

    request.address = 0;
    request.length = 1u;
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x53504c4943454552ull, "splice-only pipe offset", &result);
    failures += expect("splice-only pipe offset completion",
                       result, -ESPIPE);

    for (uint32_t index = 0; index < 2u; ++index) {
        (void)raw_syscall6(SYS_close, input_pipe[index], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, output_pipe[index], 0, 0, 0, 0, 0);
        input_pipe[index] = -1;
        output_pipe[index] = -1;
    }
    failures += expect("splice-only fixed input pipe", raw_syscall6(
        SYS_pipe2, (long)input_pipe, 0, 0, 0, 0, 0), 0);
    failures += expect("splice-only fixed output pipe", raw_syscall6(
        SYS_pipe2, (long)output_pipe, 0, 0, 0, 0, 0), 0);
    if (input_pipe[0] < 0 || input_pipe[1] < 0 ||
        output_pipe[0] < 0 || output_pipe[1] < 0)
        goto cleanup;
    failures += expect("splice-only fixed input write", raw_syscall6(
        SYS_write, input_pipe[1], (long)data, sizeof(data), 0, 0, 0),
        sizeof(data));
    fixed_files[0] = input_pipe[0];
    fixed_files[1] = output_pipe[1];
    failures += expect("splice-only register files", raw_syscall6(
        SYS_io_uring_register, ring_descriptor, IORING_REGISTER_FILES,
        (long)fixed_files, 2, 0, 0), 0);
    files_registered = 1;
    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SPLICE;
    request.flags = IOSQE_FIXED_FILE;
    request.descriptor = 1;
    request.offset = UINT64_MAX;
    request.address = UINT64_MAX;
    request.length = sizeof(data);
    request.operation_flags = SPLICE_F_FD_IN_FIXED;
    request.splice_descriptor = 0;
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x53504c4943454658ull, "splice-only fixed submit", &result);
    failures += expect("splice-only fixed completion", result, sizeof(data));
    memset(output, 0, sizeof(output));
    failures += expect("splice-only fixed output read", raw_syscall6(
        SYS_read, output_pipe[0], (long)output, sizeof(output), 0, 0, 0),
        sizeof(data));
    for (uint32_t index = 0; index < sizeof(data); ++index)
        failures += expect_true("splice-only fixed output data",
                                output[index] == data[index]);
    request.splice_descriptor = 2;
    request.length = 0;
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x53504c4943454244ull, "splice-only bad fixed input", &result);
    failures += expect("splice-only bad fixed completion", result, -EBADF);

cleanup:
    if (files_registered)
        failures += expect("splice-only unregister files", raw_syscall6(
            SYS_io_uring_register, ring_descriptor, IORING_UNREGISTER_FILES,
            0, 0, 0, 0), 0);
    for (uint32_t index = 0; index < 2u; ++index) {
        if (input_pipe[index] >= 0)
            (void)raw_syscall6(
                SYS_close, input_pipe[index], 0, 0, 0, 0, 0);
        if (output_pipe[index] >= 0)
            (void)raw_syscall6(
                SYS_close, output_pipe[index], 0, 0, 0, 0, 0);
    }
    return failures;
}

static int run_msg_ring_only(
        long ring_descriptor, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    struct io_uring_params target_parameters;
    struct io_uring_params disabled_parameters;
    volatile uint32_t *target_cq_head;
    volatile uint32_t *target_cq_tail;
    volatile uint32_t *target_cq_mask;
    volatile uint32_t *target_cq_overflow;
    volatile uint32_t *target_sq_flags;
    volatile uint32_t *target_sq_tail;
    volatile uint32_t *target_sq_mask;
    volatile uint32_t *target_sq_array;
    struct io_uring_cqe *target_cqes;
    struct io_uring_sqe *target_sqes = 0;
    struct io_uring_sqe request;
    void *target_cq_ring = 0;
    void *target_sq_ring = 0;
    void *target_sqe_ring = 0;
    long target_descriptor = -1;
    long disabled_descriptor = -1;
    int32_t transfer_pipe[2] = {-1, -1};
    int source_files_registered = 0;
    int target_files_registered = 0;
    int32_t result = -1;
    int32_t allocated_index = -1;
    int failures = 0;
    uint32_t position;
    static const char transfer_data[] = "msg-ring-fixed";
    char transfer_output[sizeof(transfer_data)] = {0};

    memset(&target_parameters, 0, sizeof(target_parameters));
    target_descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&target_parameters, 0, 0, 0, 0);
    failures += expect_true("msg-ring target setup", target_descriptor >= 0);
    if (target_descriptor < 0)
        goto cleanup;
    target_cq_ring = map_ring(target_descriptor, IORING_OFF_CQ_RING);
    target_sq_ring = map_ring(target_descriptor, IORING_OFF_SQ_RING);
    target_sqe_ring = map_ring(target_descriptor, IORING_OFF_SQES);
    failures += expect_true("msg-ring target CQ map", target_cq_ring != 0);
    failures += expect_true("msg-ring target SQ map", target_sq_ring != 0);
    failures += expect_true("msg-ring target SQE map", target_sqe_ring != 0);
    if (!target_cq_ring || !target_sq_ring || !target_sqe_ring)
        goto cleanup;
    target_sqes = (struct io_uring_sqe *)target_sqe_ring;
    target_sq_flags = (volatile uint32_t *)((uint8_t *)target_sq_ring +
                                            target_parameters.sq_off.flags);
    target_sq_tail = (volatile uint32_t *)((uint8_t *)target_sq_ring +
                                           target_parameters.sq_off.tail);
    target_sq_mask = (volatile uint32_t *)((uint8_t *)target_sq_ring +
                                           target_parameters.sq_off.ring_mask);
    target_sq_array = (volatile uint32_t *)((uint8_t *)target_sq_ring +
                                            target_parameters.sq_off.array);
    target_cq_head = (volatile uint32_t *)((uint8_t *)target_cq_ring +
                                           target_parameters.cq_off.head);
    target_cq_tail = (volatile uint32_t *)((uint8_t *)target_cq_ring +
                                           target_parameters.cq_off.tail);
    target_cq_mask = (volatile uint32_t *)((uint8_t *)target_cq_ring +
                                           target_parameters.cq_off.ring_mask);
    target_cq_overflow = (volatile uint32_t *)((uint8_t *)target_cq_ring +
                                               target_parameters.cq_off.overflow);
    target_cqes = (struct io_uring_cqe *)((uint8_t *)target_cq_ring +
                                          target_parameters.cq_off.cqes);

    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_MSG_RING;
    request.descriptor = (int32_t)target_descriptor;
    request.offset = 0x4d53474441544131ull;
    request.length = 123u;
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x4d5347534f555243ull, "msg-ring data submit", &result);
    failures += expect("msg-ring data source completion", result, 0);
    position = __atomic_load_n(target_cq_head, __ATOMIC_ACQUIRE);
    failures += expect_true("msg-ring data target completion",
        __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE) == position + 1u &&
        target_cqes[position & *target_cq_mask].user_data == request.offset &&
        target_cqes[position & *target_cq_mask].result == 123 &&
        target_cqes[position & *target_cq_mask].flags == 0u);
    __atomic_store_n(target_cq_head, position + 1u, __ATOMIC_RELEASE);

    {
        int32_t target_file = (int32_t)target_descriptor;
        failures += expect("msg-ring reject registered ring", raw_syscall6(
            SYS_io_uring_register, ring_descriptor, IORING_REGISTER_FILES,
            (long)&target_file, 1, 0, 0), -EBADF);
    }
    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_MSG_RING;
    request.descriptor = (int32_t)target_descriptor;
    request.offset = 0x4d5347464c414753ull;
    request.length = 456u;
    request.operation_flags = IORING_MSG_RING_FLAGS_PASS;
    request.splice_descriptor = 0x1234;
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x4d53474653524345ull, "msg-ring flags submit", &result);
    failures += expect("msg-ring flags source completion", result, 0);
    position = __atomic_load_n(target_cq_head, __ATOMIC_ACQUIRE);
    failures += expect_true("msg-ring flags target completion",
        __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE) == position + 1u &&
        target_cqes[position & *target_cq_mask].user_data == request.offset &&
        target_cqes[position & *target_cq_mask].result == 456 &&
        target_cqes[position & *target_cq_mask].flags == 0x1234u);
    __atomic_store_n(target_cq_head, position + 1u, __ATOMIC_RELEASE);

    request.flags = 0;
    request.descriptor = (int32_t)target_descriptor;
    request.operation_flags = IORING_MSG_RING_CQE_SKIP;
    request.splice_descriptor = 0;
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x4d5347494e56414cull, "msg-ring invalid flags", &result);
    failures += expect("msg-ring invalid flags completion", result, -EINVAL);

    failures += expect("msg-ring transfer pipe", raw_syscall6(
        SYS_pipe2, (long)transfer_pipe, 0, 0, 0, 0, 0), 0);
    if (transfer_pipe[0] >= 0 && transfer_pipe[1] >= 0) {
        int32_t source_files[] = {transfer_pipe[1]};
        int32_t target_files[] = {-1, -1, -1};

        failures += expect("msg-ring register source file", raw_syscall6(
            SYS_io_uring_register, ring_descriptor, IORING_REGISTER_FILES,
            (long)source_files, 1, 0, 0), 0);
        source_files_registered = 1;
        failures += expect("msg-ring register target files", raw_syscall6(
            SYS_io_uring_register, target_descriptor, IORING_REGISTER_FILES,
            (long)target_files, 3, 0, 0), 0);
        target_files_registered = 1;

        memset(&request, 0, sizeof(request));
        request.opcode = IORING_OP_MSG_RING;
        request.descriptor = (int32_t)target_descriptor;
        request.offset = 0x4d53474644544131ull;
        request.address = IORING_MSG_SEND_FD;
        request.splice_descriptor = 2;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474644535231ull, "msg-ring send-fd explicit", &result);
        failures += expect("msg-ring send-fd explicit completion", result, 0);
        position = __atomic_load_n(target_cq_head, __ATOMIC_ACQUIRE);
        failures += expect_true("msg-ring send-fd target completion",
            __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE) ==
                position + 1u &&
            target_cqes[position & *target_cq_mask].user_data ==
                request.offset &&
            target_cqes[position & *target_cq_mask].result == 0 &&
            target_cqes[position & *target_cq_mask].flags == 0u);
        __atomic_store_n(target_cq_head, position + 1u, __ATOMIC_RELEASE);

        request.offset = 0x4d53474644414c4cull;
        request.operation_flags = IORING_MSG_RING_CQE_SKIP;
        request.splice_descriptor = (int32_t)IORING_FILE_INDEX_ALLOC;
        position = __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE);
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474644535232ull, "msg-ring send-fd allocated", &result);
        failures += expect_true("msg-ring send-fd allocated completion",
                                result >= 0 && result < 3 && result != 1);
        allocated_index = result;
        failures += expect_true("msg-ring send-fd skipped target CQE",
            __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE) == position);

        request.operation_flags = 0;
        request.splice_descriptor = 0;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474644425a52ull, "msg-ring send-fd zero slot", &result);
        failures += expect("msg-ring send-fd zero slot completion",
                           result, -EINVAL);
        request.splice_descriptor = 3;
        request.address3 = 1u;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474644424144ull, "msg-ring send-fd bad source", &result);
        failures += expect("msg-ring send-fd bad source completion",
                           result, -EBADF);
        request.splice_descriptor = 0;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474644424f52ull,
            "msg-ring send-fd error ordering", &result);
        failures += expect("msg-ring send-fd error ordering completion",
                           result, -EBADF);
        request.descriptor = (int32_t)ring_descriptor;
        request.address3 = 0u;
        request.splice_descriptor = 1;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d5347464453414dull, "msg-ring send-fd same ring", &result);
        failures += expect("msg-ring send-fd same ring completion",
                           result, -EINVAL);

        failures += expect("msg-ring unregister source file", raw_syscall6(
            SYS_io_uring_register, ring_descriptor,
            IORING_UNREGISTER_FILES, 0, 0, 0, 0), 0);
        source_files_registered = 0;
        failures += expect("msg-ring close original write end", raw_syscall6(
            SYS_close, transfer_pipe[1], 0, 0, 0, 0, 0), 0);
        transfer_pipe[1] = -1;

        memset(&request, 0, sizeof(request));
        request.opcode = IORING_OP_WRITE;
        request.flags = IOSQE_FIXED_FILE;
        request.descriptor = 1;
        request.offset = UINT64_MAX;
        request.address = (uint64_t)(uintptr_t)transfer_data;
        request.length = sizeof(transfer_data);
        failures += submit_one(
            target_descriptor, target_sq_tail, target_sq_mask,
            target_sq_array, target_sqes,
            target_cq_head, target_cq_tail, target_cq_mask, target_cqes,
            &request, 0x4d53474644575231ull,
            "msg-ring target fixed write", &result);
        failures += expect("msg-ring target fixed write completion",
                           result, sizeof(transfer_data));
        failures += expect("msg-ring transferred pipe read", raw_syscall6(
            SYS_read, transfer_pipe[0], (long)transfer_output,
            sizeof(transfer_output), 0, 0, 0), sizeof(transfer_data));
        failures += expect_true("msg-ring transferred pipe data",
            transfer_output[0] == transfer_data[0] &&
            transfer_output[sizeof(transfer_output) - 1u] == 0);

        memset(transfer_output, 0, sizeof(transfer_output));
        request.descriptor = allocated_index;
        failures += submit_one(
            target_descriptor, target_sq_tail, target_sq_mask,
            target_sq_array, target_sqes,
            target_cq_head, target_cq_tail, target_cq_mask, target_cqes,
            &request, 0x4d53474644575232ull,
            "msg-ring allocated fixed write", &result);
        failures += expect("msg-ring allocated fixed write completion",
                           result, sizeof(transfer_data));
        failures += expect("msg-ring allocated pipe read", raw_syscall6(
            SYS_read, transfer_pipe[0], (long)transfer_output,
            sizeof(transfer_output), 0, 0, 0), sizeof(transfer_data));

        failures += expect("msg-ring unregister target files", raw_syscall6(
            SYS_io_uring_register, target_descriptor,
            IORING_UNREGISTER_FILES, 0, 0, 0, 0), 0);
        target_files_registered = 0;
    }

    memset(&disabled_parameters, 0, sizeof(disabled_parameters));
    disabled_parameters.flags = IORING_SETUP_R_DISABLED;
    disabled_descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&disabled_parameters, 0, 0, 0, 0);
    failures += expect_true("msg-ring disabled target setup",
                            disabled_descriptor >= 0);
    if (disabled_descriptor >= 0) {
        memset(&request, 0, sizeof(request));
        request.opcode = IORING_OP_MSG_RING;
        request.descriptor = (int32_t)disabled_descriptor;
        request.offset = 0x4d53474449534142ull;
        request.length = 1u;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474453524345ull, "msg-ring disabled submit", &result);
        failures += expect("msg-ring disabled completion", result, -EBADFD);

        request.address = IORING_MSG_SEND_FD;
        request.length = 0u;
        request.address3 = 0u;
        request.splice_descriptor = 1;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474644445342ull, "msg-ring disabled send-fd", &result);
        failures += expect("msg-ring disabled send-fd completion",
                           result, -EBADFD);
    }

    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_MSG_RING;
    request.descriptor = (int32_t)target_descriptor;
    request.length = 1u;
    position = __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE);
    for (uint32_t index = 0; index < target_parameters.cq_entries; ++index) {
        request.offset = 0x4d534746554c4c00ull + index;
        failures += submit_one(
            ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &request,
            0x4d53474653524300ull + index, "msg-ring fill target", &result);
        failures += expect("msg-ring fill completion", result, 0);
    }
    failures += expect_true("msg-ring target full",
        __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE) ==
        position + target_parameters.cq_entries);
    request.offset = 0x4d53474f56455246ull;
    failures += submit_one(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &request,
        0x4d53474f56535243ull, "msg-ring overflow submit", &result);
    failures += expect("msg-ring buffered overflow completion", result, 0);
    failures += expect("msg-ring no dropped completions",
                       *target_cq_overflow, 0);
    failures += expect_true("msg-ring overflow pending flag",
        (*target_sq_flags & IORING_SQ_CQ_OVERFLOW) != 0u);
    __atomic_store_n(target_cq_head,
                     __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE),
                     __ATOMIC_RELEASE);
    position = __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE);
    failures += expect("msg-ring flush overflow", raw_syscall6(
        SYS_io_uring_enter, target_descriptor, 0, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 0);
    failures += expect_true("msg-ring flushed target completion",
        __atomic_load_n(target_cq_tail, __ATOMIC_ACQUIRE) == position + 1u &&
        target_cqes[position & *target_cq_mask].user_data == request.offset &&
        target_cqes[position & *target_cq_mask].result == 1);
    failures += expect_true("msg-ring overflow pending flag cleared",
        (*target_sq_flags & IORING_SQ_CQ_OVERFLOW) == 0u);
    __atomic_store_n(target_cq_head, position + 1u, __ATOMIC_RELEASE);

cleanup:
    if (source_files_registered)
        (void)raw_syscall6(
            SYS_io_uring_register, ring_descriptor,
            IORING_UNREGISTER_FILES, 0, 0, 0, 0);
    if (target_files_registered && target_descriptor >= 0)
        (void)raw_syscall6(
            SYS_io_uring_register, target_descriptor,
            IORING_UNREGISTER_FILES, 0, 0, 0, 0);
    for (uint32_t index = 0; index < 2u; ++index)
        if (transfer_pipe[index] >= 0)
            (void)raw_syscall6(
                SYS_close, transfer_pipe[index], 0, 0, 0, 0, 0);
    if (disabled_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, disabled_descriptor, 0, 0, 0, 0, 0);
    if (target_cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)target_cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (target_sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)target_sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (target_sqe_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)target_sqe_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (target_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, target_descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int run_tests(void) {
    struct io_uring_probe probe;
    struct io_uring_params parameters;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    volatile uint32_t *sq_head;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    void *sq_ring;
    void *cq_ring;
    long descriptor;
    long event_descriptor;
    uint64_t event_value = 0;
    struct kernel_timespec short_timeout = {0, 1000000};
    struct kernel_timespec long_timeout = {60, 0};
    struct io_uring_getevents_arg extended_argument = {0};
    struct open_how open_how = {0};
    uint8_t statx_buffer[256];
    static const char null_path[] = "/dev/null";
    static const char data_path[] = "/tmp/edgeos-io-uring-probe";
    static const char send_data[] = "edgeos-send";
    static const char message_data[] = "edgeos-message";
    char receive_data[sizeof(send_data)] = {0};
    char receive_message_data[sizeof(message_data)] = {0};
    struct user_iovec send_vector = {
        (uint64_t)(uintptr_t)message_data, sizeof(message_data),
    };
    struct user_iovec receive_vector = {
        (uint64_t)(uintptr_t)receive_message_data, sizeof(message_data),
    };
    struct user_msghdr send_message = {0};
    struct user_msghdr receive_message = {0};
    int32_t socket_descriptors[2] = {-1, -1};
    int32_t listener_descriptor = -1;
    int32_t client_descriptor = -1;
    int32_t accepted_descriptor = -1;
    int32_t ring_listener_descriptor = -1;
    int32_t xattr_descriptor = -1;
    int32_t advice_descriptor = -1;
    int32_t epoll_descriptor = -1;
    int32_t control_event_descriptor = -1;
    int32_t tee_input[2] = {-1, -1};
    int32_t tee_output[2] = {-1, -1};
    int32_t splice_input[2] = {-1, -1};
    int32_t splice_output[2] = {-1, -1};
    uint64_t advice_address = 0;
    char tee_buffer[5] = {0};
    static const char tee_data[] = "tee!";
    char splice_buffer[8] = {0};
    static const char splice_data[] = "splice!";
    static const char path_directory[] = "/tmp/edgeos-uring-path";
    static const char path_source[] = "/tmp/edgeos-uring-path/source";
    static const char path_renamed[] = "/tmp/edgeos-uring-path/renamed";
    static const char path_hardlink[] = "/tmp/edgeos-uring-path/hard";
    static const char path_symlink[] = "/tmp/edgeos-uring-path/symbolic";
    static const char symlink_target[] = "source";
    static const char xattr_path[] = "/tmp/edgeos-io-uring-xattr";
    static const char xattr_name[] = "user.edgeos";
    static const char xattr_fd_value[] = "descriptor-value";
    static const char xattr_path_value[] = "path-value";
    char xattr_buffer[sizeof(xattr_fd_value)] = {0};
    char xattr_list[64] = {0};
    struct io_uring_sqe path_request;
    int32_t path_result = -1;
    struct linux_epoll_event epoll_event = {
        EPOLLIN, 0x45504f4c4c444154ull,
    };
    uint32_t submission_position;
    uint32_t completion_position;
    static const struct user_sockaddr_un listen_address = {
        AF_UNIX, "\0edgeos-io-uring-probe",
    };
    static const struct user_sockaddr_un ring_listen_address = {
        AF_UNIX, "\0edgeos-io-uring-created",
    };
    uint64_t temporary_signal_mask = 0;
    uint32_t futex_word = 0;
    int32_t fixed_files[2] = {-1, -1};
    int failures = 0;

    memset(&parameters, 0, sizeof(parameters));
    parameters.reserved[0] = 1;
    failures += expect("reject reserved setup field", raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0),
        -EINVAL);

    memset(&parameters, 0, sizeof(parameters));
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    failures += expect_true("setup", descriptor >= 0);
    if (descriptor < 0) return failures;
    failures += expect_true("ring entries",
        parameters.sq_entries >= 8 && parameters.cq_entries >= 8);
    failures += expect_true("ring offsets",
        parameters.sq_off.array >= 24 && parameters.cq_off.cqes >= 24);
    failures += expect("extended enter arguments", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 0,
        IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
        (long)&extended_argument,
        sizeof(extended_argument)), 0);
    failures += expect("reject extended argument size", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 0,
        IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
        (long)&extended_argument,
        sizeof(extended_argument) - 1u), -EINVAL);
    failures += expect("temporary signal mask", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 0,
        IORING_ENTER_GETEVENTS, (long)&temporary_signal_mask,
        sizeof(temporary_signal_mask)), 0);

    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    failures += expect_true("map SQ ring", sq_ring != 0);
    failures += expect_true("map CQ ring", cq_ring != 0);
    failures += expect_true("map SQEs", sqes != 0);
    if (!sq_ring || !cq_ring || !sqes) goto close_ring;

    sq_head = (volatile uint32_t *)((uint8_t *)sq_ring +
                                    parameters.sq_off.head);
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
    memset(&sqes[0], 0, sizeof(sqes[0]));
    sqes[0].opcode = IORING_OP_NOP;
    sqes[0].user_data = 0x454447454f535552ull;
    sq_array[0] = 0;
    __atomic_store_n(sq_tail, 1u, __ATOMIC_RELEASE);
    failures += expect("submit NOP", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("consume submission",
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE) == 1u);
    failures += expect_true("publish completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 1u);
    failures += expect_true("NOP completion",
        cqes[0].user_data == 0x454447454f535552ull &&
        cqes[0].result == 0 && cqes[0].flags == 0);
    __atomic_store_n(cq_head, 1u, __ATOMIC_RELEASE);

    memset(&probe, 0, sizeof(probe));
    failures += expect("register probe", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_PROBE,
        (long)&probe, PROBE_OPERATION_COUNT, 0, 0), 0);
    failures += expect_true("probe extent",
        probe.last_opcode >= IORING_OP_WRITE &&
        probe.operation_count > IORING_OP_FUTEX_WAKE &&
        probe.operation_count <= PROBE_OPERATION_COUNT);
    failures += expect_true("probe NOP",
        probe.operations[IORING_OP_NOP].opcode == IORING_OP_NOP &&
        (probe.operations[IORING_OP_NOP].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe read/write",
        (probe.operations[IORING_OP_READ].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_WRITE].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe VFS operations",
        (probe.operations[IORING_OP_OPENAT].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_OPENAT2].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_CLOSE].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_STATX].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_FALLOCATE].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe socket operations",
        (probe.operations[IORING_OP_SEND].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_RECV].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_SENDMSG].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_RECVMSG].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_SHUTDOWN].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe socket connection operations",
        (probe.operations[IORING_OP_ACCEPT].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_CONNECT].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe advice event and pipe operations",
        (probe.operations[IORING_OP_FADVISE].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_MADVISE].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_EPOLL_CTL].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_SPLICE].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_MSG_RING].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_TEE].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe path operations",
        (probe.operations[IORING_OP_RENAMEAT].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_UNLINKAT].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_MKDIRAT].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_SYMLINKAT].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_LINKAT].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe socket setup operations",
        (probe.operations[IORING_OP_SOCKET].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_BIND].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_LISTEN].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe xattr and truncate operations",
        (probe.operations[IORING_OP_FSETXATTR].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_SETXATTR].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_FGETXATTR].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_GETXATTR].flags &
         IO_URING_OP_SUPPORTED) != 0 &&
        (probe.operations[IORING_OP_FTRUNCATE].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe sync file range",
        (probe.operations[IORING_OP_SYNC_FILE_RANGE].flags &
         IO_URING_OP_SUPPORTED) != 0);
    failures += expect_true("probe futex wake",
        (probe.operations[IORING_OP_FUTEX_WAKE].flags &
         IO_URING_OP_SUPPORTED) != 0);

#ifdef EDGEOS_IO_URING_SPLICE_ONLY
    failures += run_splice_only(
        descriptor, &parameters, sq_ring, cq_ring, sqes);
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
#endif

#ifdef EDGEOS_IO_URING_MSG_RING_ONLY
    failures += run_msg_ring_only(
        descriptor, &parameters, sq_ring, cq_ring, sqes);
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
#endif

    event_descriptor = raw_syscall6(
        SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    failures += expect_true("eventfd", event_descriptor >= 0);
    if (event_descriptor >= 0) {
        uint32_t event_fd_argument = (uint32_t)event_descriptor;
        failures += expect("register eventfd", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_REGISTER_EVENTFD,
            (long)&event_fd_argument, 1, 0, 0), 0);
        memset(&sqes[1], 0, sizeof(sqes[1]));
        sqes[1].opcode = IORING_OP_NOP;
        sqes[1].user_data = 0x4556454e544644ull;
        sq_array[1] = 1;
        __atomic_store_n(sq_tail, 2u, __ATOMIC_RELEASE);
        failures += expect("submit eventfd NOP", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect("read eventfd", raw_syscall6(
            SYS_read, event_descriptor, (long)&event_value,
            sizeof(event_value), 0, 0, 0), sizeof(event_value));
        failures += expect_true("eventfd count", event_value == 1);
        failures += expect("unregister eventfd", raw_syscall6(
            SYS_io_uring_register, descriptor,
            IORING_UNREGISTER_EVENTFD, 0, 0, 0, 0), 0);
        event_value = 1;
        failures += expect("prime poll eventfd", raw_syscall6(
            SYS_write, event_descriptor, (long)&event_value,
            sizeof(event_value), 0, 0, 0), sizeof(event_value));
        memset(&sqes[2], 0, sizeof(sqes[2]));
        sqes[2].opcode = IORING_OP_POLL_ADD;
        sqes[2].descriptor = (int32_t)event_descriptor;
        sqes[2].operation_flags = POLLIN;
        sqes[2].user_data = 0x504f4c4c52454144ull;
        sq_array[2] = 2;
        __atomic_store_n(sq_tail, 3u, __ATOMIC_RELEASE);
        failures += expect("submit poll", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("poll completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 3u &&
            cqes[2].user_data == 0x504f4c4c52454144ull &&
            (cqes[2].result & POLLIN) != 0);
        __atomic_store_n(cq_head, 3u, __ATOMIC_RELEASE);
        (void)raw_syscall6(SYS_close, event_descriptor, 0, 0, 0, 0, 0);
    }

    memset(&sqes[3], 0, sizeof(sqes[3]));
    print_text("io-uring-abi: testing timeout\n");
    sqes[3].opcode = IORING_OP_TIMEOUT;
    sqes[3].descriptor = -1;
    sqes[3].address = (uint64_t)(uintptr_t)&short_timeout;
    sqes[3].length = 1;
    sqes[3].user_data = 0x54494d454f555431ull;
    sq_array[3] = 3;
    __atomic_store_n(sq_tail, 4u, __ATOMIC_RELEASE);
    failures += expect("submit timeout", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("timeout completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 4u &&
        cqes[3].user_data == 0x54494d454f555431ull &&
        cqes[3].result == -ETIME);
    __atomic_store_n(cq_head, 4u, __ATOMIC_RELEASE);

    memset(&sqes[4], 0, sizeof(sqes[4]));
    print_text("io-uring-abi: testing cancellation\n");
    sqes[4].opcode = IORING_OP_TIMEOUT;
    sqes[4].descriptor = -1;
    sqes[4].address = (uint64_t)(uintptr_t)&long_timeout;
    sqes[4].length = 1;
    sqes[4].user_data = 0x43414e43454c4d45ull;
    memset(&sqes[5], 0, sizeof(sqes[5]));
    sqes[5].opcode = IORING_OP_TIMEOUT_REMOVE;
    sqes[5].descriptor = -1;
    sqes[5].address = 0x43414e43454c4d45ull;
    sqes[5].user_data = 0x52454d4f56454f50ull;
    sq_array[4] = 4;
    sq_array[5] = 5;
    __atomic_store_n(sq_tail, 6u, __ATOMIC_RELEASE);
    failures += expect("submit cancel pair", raw_syscall6(
        SYS_io_uring_enter, descriptor, 2, 2,
        IORING_ENTER_GETEVENTS, 0, 0), 2);
    failures += expect_true("canceled timeout completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 6u &&
        cqes[5].user_data == 0x43414e43454c4d45ull &&
        cqes[5].result == -ECANCELED);
    failures += expect_true("timeout remove completion",
        cqes[4].user_data == 0x52454d4f56454f50ull &&
        cqes[4].result == 0);
    if (cqes[5].user_data != 0x43414e43454c4d45ull ||
        cqes[5].result != -ECANCELED ||
        cqes[4].user_data != 0x52454d4f56454f50ull ||
        cqes[4].result != 0) {
        print_text("io-uring-abi: cancellation CQ tail/results\n");
        print_integer(*cq_tail);
        print_integer((int64_t)cqes[4].user_data);
        print_integer(cqes[4].result);
        print_integer((int64_t)cqes[5].user_data);
        print_integer(cqes[5].result);
    }
    __atomic_store_n(cq_head, 6u, __ATOMIC_RELEASE);

    memset(&sqes[6], 0, sizeof(sqes[6]));
    sqes[6].opcode = IORING_OP_OPENAT;
    sqes[6].descriptor = AT_FDCWD;
    sqes[6].address = (uint64_t)(uintptr_t)null_path;
    sqes[6].operation_flags = O_RDWR;
    sqes[6].user_data = 0x4f50454e41543031ull;
    sq_array[6] = 6;
    __atomic_store_n(sq_tail, 7u, __ATOMIC_RELEASE);
    failures += expect("submit openat", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("openat completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 7u &&
        cqes[6].user_data == 0x4f50454e41543031ull &&
        cqes[6].result >= 0);
    if (cqes[6].result >= 0) {
        memset(&sqes[7], 0, sizeof(sqes[7]));
        sqes[7].opcode = IORING_OP_CLOSE;
        sqes[7].descriptor = cqes[6].result;
        sqes[7].user_data = 0x434c4f5345303031ull;
        sq_array[7] = 7;
        __atomic_store_n(sq_tail, 8u, __ATOMIC_RELEASE);
        failures += expect("submit close", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("close completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 8u &&
            cqes[7].user_data == 0x434c4f5345303031ull &&
            cqes[7].result == 0);
    }
    __atomic_store_n(cq_head, 8u, __ATOMIC_RELEASE);

    open_how.flags = O_RDWR;
    memset(&sqes[0], 0, sizeof(sqes[0]));
    sqes[0].opcode = IORING_OP_OPENAT2;
    sqes[0].descriptor = AT_FDCWD;
    sqes[0].offset = (uint64_t)(uintptr_t)&open_how;
    sqes[0].address = (uint64_t)(uintptr_t)null_path;
    sqes[0].length = sizeof(open_how);
    sqes[0].user_data = 0x4f50454e41543231ull;
    sq_array[0] = 0;
    __atomic_store_n(sq_tail, 9u, __ATOMIC_RELEASE);
    failures += expect("submit openat2", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("openat2 completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 9u &&
        cqes[8u & *cq_mask].user_data == 0x4f50454e41543231ull &&
        cqes[8u & *cq_mask].result >= 0);
    if (cqes[8u & *cq_mask].result >= 0) {
        memset(&sqes[1], 0, sizeof(sqes[1]));
        sqes[1].opcode = IORING_OP_CLOSE;
        sqes[1].descriptor = cqes[8u & *cq_mask].result;
        sqes[1].user_data = 0x434c4f5345303032ull;
        sq_array[1] = 1;
        __atomic_store_n(sq_tail, 10u, __ATOMIC_RELEASE);
        failures += expect("submit openat2 close", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("openat2 close completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 10u &&
            cqes[9u & *cq_mask].user_data == 0x434c4f5345303032ull &&
            cqes[9u & *cq_mask].result == 0);
    }
    __atomic_store_n(cq_head, 10u, __ATOMIC_RELEASE);

    memset(statx_buffer, 0, sizeof(statx_buffer));
    memset(&sqes[2], 0, sizeof(sqes[2]));
    sqes[2].opcode = IORING_OP_STATX;
    sqes[2].descriptor = AT_FDCWD;
    sqes[2].offset = (uint64_t)(uintptr_t)statx_buffer;
    sqes[2].address = (uint64_t)(uintptr_t)null_path;
    sqes[2].length = 0x7ffu;
    sqes[2].user_data = 0x5354415458303031ull;
    sq_array[2] = 2;
    __atomic_store_n(sq_tail, 11u, __ATOMIC_RELEASE);
    failures += expect("submit statx", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("statx completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 11u &&
        cqes[10u & *cq_mask].user_data == 0x5354415458303031ull &&
        cqes[10u & *cq_mask].result == 0);
    __atomic_store_n(cq_head, 11u, __ATOMIC_RELEASE);

    memset(&sqes[3], 0, sizeof(sqes[3]));
    sqes[3].opcode = IORING_OP_CLOSE;
    sqes[3].descriptor = (int32_t)descriptor;
    sqes[3].user_data = 0x434c4f534552494eull;
    sq_array[3] = 3;
    __atomic_store_n(sq_tail, 12u, __ATOMIC_RELEASE);
    failures += expect("submit ring close", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("reject ring close",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 12u &&
        cqes[11u & *cq_mask].user_data == 0x434c4f534552494eull &&
        cqes[11u & *cq_mask].result == -EBADF);
    __atomic_store_n(cq_head, 12u, __ATOMIC_RELEASE);

    memset(&sqes[4], 0, sizeof(sqes[4]));
    sqes[4].opcode = IORING_OP_OPENAT;
    sqes[4].descriptor = AT_FDCWD;
    sqes[4].address = (uint64_t)(uintptr_t)data_path;
    sqes[4].length = 0600u;
    sqes[4].operation_flags = O_RDWR | O_CREAT | O_TRUNC;
    sqes[4].user_data = 0x4352454154453031ull;
    sq_array[4] = 4;
    __atomic_store_n(sq_tail, 13u, __ATOMIC_RELEASE);
    failures += expect("submit create", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("create completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 13u &&
        cqes[12u & *cq_mask].user_data == 0x4352454154453031ull &&
        cqes[12u & *cq_mask].result >= 0);
    if (cqes[12u & *cq_mask].result >= 0) {
        int32_t data_descriptor = cqes[12u & *cq_mask].result;
        memset(&sqes[5], 0, sizeof(sqes[5]));
        sqes[5].opcode = IORING_OP_FALLOCATE;
        sqes[5].flags = IOSQE_IO_LINK;
        sqes[5].descriptor = data_descriptor;
        sqes[5].address = PAGE_SIZE;
        sqes[5].user_data = 0x46414c4c4f433031ull;
        memset(&sqes[6], 0, sizeof(sqes[6]));
        sqes[6].opcode = IORING_OP_CLOSE;
        sqes[6].descriptor = data_descriptor;
        sqes[6].user_data = 0x434c4f5345303033ull;
        sq_array[5] = 5;
        sq_array[6] = 6;
        __atomic_store_n(sq_tail, 15u, __ATOMIC_RELEASE);
        failures += expect("submit fallocate close", raw_syscall6(
            SYS_io_uring_enter, descriptor, 2, 2,
            IORING_ENTER_GETEVENTS, 0, 0), 2);
        failures += expect_true("fallocate completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 15u &&
            cqes[13u & *cq_mask].user_data == 0x46414c4c4f433031ull &&
            cqes[13u & *cq_mask].result == 0);
        failures += expect_true("fallocate close completion",
            cqes[14u & *cq_mask].user_data == 0x434c4f5345303033ull &&
            cqes[14u & *cq_mask].result == 0);
    }
    __atomic_store_n(cq_head, 15u, __ATOMIC_RELEASE);

    failures += expect("socketpair", raw_syscall6(
        SYS_socketpair, 1, 1, 0, (long)socket_descriptors, 0, 0), 0);
    if (socket_descriptors[0] >= 0 && socket_descriptors[1] >= 0) {
        memset(&sqes[7], 0, sizeof(sqes[7]));
        sqes[7].opcode = IORING_OP_SEND;
        sqes[7].descriptor = socket_descriptors[0];
        sqes[7].address = (uint64_t)(uintptr_t)send_data;
        sqes[7].length = sizeof(send_data);
        sqes[7].user_data = 0x53454e4430303031ull;
        memset(&sqes[0], 0, sizeof(sqes[0]));
        sqes[0].opcode = IORING_OP_RECV;
        sqes[0].descriptor = socket_descriptors[1];
        sqes[0].address = (uint64_t)(uintptr_t)receive_data;
        sqes[0].length = sizeof(receive_data);
        sqes[0].user_data = 0x5245435630303031ull;
        sq_array[7] = 7;
        sq_array[0] = 0;
        __atomic_store_n(sq_tail, 17u, __ATOMIC_RELEASE);
        failures += expect("submit send receive", raw_syscall6(
            SYS_io_uring_enter, descriptor, 2, 2,
            IORING_ENTER_GETEVENTS, 0, 0), 2);
        failures += expect_true("send completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 17u &&
            cqes[15u & *cq_mask].user_data == 0x53454e4430303031ull &&
            cqes[15u & *cq_mask].result == (int32_t)sizeof(send_data));
        failures += expect_true("receive completion",
            cqes[16u & *cq_mask].user_data == 0x5245435630303031ull &&
            cqes[16u & *cq_mask].result == (int32_t)sizeof(receive_data) &&
            receive_data[0] == send_data[0] &&
            receive_data[sizeof(receive_data) - 1u] == 0);
        __atomic_store_n(cq_head, 17u, __ATOMIC_RELEASE);

        send_message.vectors = (uint64_t)(uintptr_t)&send_vector;
        send_message.vector_count = 1;
        receive_message.vectors = (uint64_t)(uintptr_t)&receive_vector;
        receive_message.vector_count = 1;
        memset(&sqes[1], 0, sizeof(sqes[1]));
        sqes[1].opcode = IORING_OP_SENDMSG;
        sqes[1].descriptor = socket_descriptors[0];
        sqes[1].address = (uint64_t)(uintptr_t)&send_message;
        sqes[1].length = 1;
        sqes[1].user_data = 0x53454e444d534731ull;
        memset(&sqes[2], 0, sizeof(sqes[2]));
        sqes[2].opcode = IORING_OP_RECVMSG;
        sqes[2].descriptor = socket_descriptors[1];
        sqes[2].address = (uint64_t)(uintptr_t)&receive_message;
        sqes[2].length = 1;
        sqes[2].user_data = 0x524543564d534731ull;
        sq_array[1] = 1;
        sq_array[2] = 2;
        __atomic_store_n(sq_tail, 19u, __ATOMIC_RELEASE);
        failures += expect("submit sendmsg recvmsg", raw_syscall6(
            SYS_io_uring_enter, descriptor, 2, 2,
            IORING_ENTER_GETEVENTS, 0, 0), 2);
        failures += expect_true("sendmsg completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 19u &&
            cqes[17u & *cq_mask].user_data == 0x53454e444d534731ull &&
            cqes[17u & *cq_mask].result == (int32_t)sizeof(message_data));
        failures += expect_true("recvmsg completion",
            cqes[18u & *cq_mask].user_data == 0x524543564d534731ull &&
            cqes[18u & *cq_mask].result ==
                (int32_t)sizeof(receive_message_data) &&
            receive_message_data[0] == message_data[0] &&
            receive_message_data[sizeof(receive_message_data) - 1u] == 0);
        __atomic_store_n(cq_head, 19u, __ATOMIC_RELEASE);

        memset(&sqes[3], 0, sizeof(sqes[3]));
        sqes[3].opcode = IORING_OP_SHUTDOWN;
        sqes[3].descriptor = socket_descriptors[0];
        sqes[3].length = 2;
        sqes[3].user_data = 0x53485554444f574eull;
        sq_array[3] = 3;
        __atomic_store_n(sq_tail, 20u, __ATOMIC_RELEASE);
        failures += expect("submit shutdown", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("shutdown completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 20u &&
            cqes[19u & *cq_mask].user_data == 0x53485554444f574eull &&
            cqes[19u & *cq_mask].result == 0);
        __atomic_store_n(cq_head, 20u, __ATOMIC_RELEASE);
        (void)raw_syscall6(
            SYS_close, socket_descriptors[0], 0, 0, 0, 0, 0);
        (void)raw_syscall6(
            SYS_close, socket_descriptors[1], 0, 0, 0, 0, 0);
    }

    listener_descriptor = (int32_t)raw_syscall6(
        SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
    failures += expect_true("listener socket", listener_descriptor >= 0);
    if (listener_descriptor >= 0) {
        failures += expect("listener bind", raw_syscall6(
            SYS_bind, listener_descriptor, (long)&listen_address,
            sizeof(uint16_t) + sizeof("edgeos-io-uring-probe"), 0, 0, 0), 0);
        failures += expect("listener listen", raw_syscall6(
            SYS_listen, listener_descriptor, 1, 0, 0, 0, 0), 0);
        client_descriptor = (int32_t)raw_syscall6(
            SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
        failures += expect_true("client socket", client_descriptor >= 0);
    }
    if (listener_descriptor >= 0 && client_descriptor >= 0) {
        memset(&sqes[4], 0, sizeof(sqes[4]));
        sqes[4].opcode = IORING_OP_CONNECT;
        sqes[4].descriptor = client_descriptor;
        sqes[4].offset = sizeof(uint16_t) +
            sizeof("edgeos-io-uring-probe");
        sqes[4].address = (uint64_t)(uintptr_t)&listen_address;
        sqes[4].user_data = 0x434f4e4e45435431ull;
        sq_array[4] = 4;
        __atomic_store_n(sq_tail, 21u, __ATOMIC_RELEASE);
        failures += expect("submit connect", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("connect completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 21u &&
            cqes[20u & *cq_mask].user_data == 0x434f4e4e45435431ull &&
            cqes[20u & *cq_mask].result == 0);
        __atomic_store_n(cq_head, 21u, __ATOMIC_RELEASE);

        memset(&sqes[5], 0, sizeof(sqes[5]));
        sqes[5].opcode = IORING_OP_ACCEPT;
        sqes[5].descriptor = listener_descriptor;
        sqes[5].user_data = 0x4143434550543031ull;
        sq_array[5] = 5;
        __atomic_store_n(sq_tail, 22u, __ATOMIC_RELEASE);
        failures += expect("submit accept", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("accept completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 22u &&
            cqes[21u & *cq_mask].user_data == 0x4143434550543031ull &&
            cqes[21u & *cq_mask].result >= 0);
        accepted_descriptor = cqes[21u & *cq_mask].result;
        __atomic_store_n(cq_head, 22u, __ATOMIC_RELEASE);
    }
    if (accepted_descriptor >= 0)
        (void)raw_syscall6(SYS_close, accepted_descriptor, 0, 0, 0, 0, 0);
    if (client_descriptor >= 0)
        (void)raw_syscall6(SYS_close, client_descriptor, 0, 0, 0, 0, 0);
    if (listener_descriptor >= 0)
        (void)raw_syscall6(SYS_close, listener_descriptor, 0, 0, 0, 0, 0);

    submission_position = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    completion_position = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    memset(&sqes[submission_position & *sq_mask], 0,
           sizeof(sqes[submission_position & *sq_mask]));
    sqes[submission_position & *sq_mask].opcode = IORING_OP_OPENAT;
    sqes[submission_position & *sq_mask].descriptor = AT_FDCWD;
    sqes[submission_position & *sq_mask].address =
        (uint64_t)(uintptr_t)data_path;
    sqes[submission_position & *sq_mask].operation_flags = O_RDWR;
    sqes[submission_position & *sq_mask].user_data = 0x4144564f50454e31ull;
    sq_array[submission_position & *sq_mask] = submission_position & *sq_mask;
    __atomic_store_n(sq_tail, submission_position + 1u, __ATOMIC_RELEASE);
    failures += expect("submit advice open", raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect_true("advice open completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) ==
            completion_position + 1u &&
        cqes[completion_position & *cq_mask].user_data ==
            0x4144564f50454e31ull &&
        cqes[completion_position & *cq_mask].result >= 0);
    advice_descriptor = cqes[completion_position & *cq_mask].result;
    completion_position++;
    __atomic_store_n(cq_head, completion_position, __ATOMIC_RELEASE);
    if (advice_descriptor >= 0) {
        submission_position = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
        memset(&sqes[submission_position & *sq_mask], 0,
               sizeof(sqes[submission_position & *sq_mask]));
        sqes[submission_position & *sq_mask].opcode = IORING_OP_FADVISE;
        sqes[submission_position & *sq_mask].descriptor = advice_descriptor;
        sqes[submission_position & *sq_mask].address = PAGE_SIZE;
        sqes[submission_position & *sq_mask].operation_flags =
            POSIX_FADV_NORMAL;
        sqes[submission_position & *sq_mask].user_data =
            0x4641445649534531ull;
        sq_array[submission_position & *sq_mask] =
            submission_position & *sq_mask;
        memset(&sqes[(submission_position + 1u) & *sq_mask], 0,
               sizeof(sqes[(submission_position + 1u) & *sq_mask]));
        sqes[(submission_position + 1u) & *sq_mask].opcode = IORING_OP_CLOSE;
        sqes[(submission_position + 1u) & *sq_mask].descriptor =
            advice_descriptor;
        sqes[(submission_position + 1u) & *sq_mask].user_data =
            0x414456434c4f5345ull;
        sq_array[(submission_position + 1u) & *sq_mask] =
            (submission_position + 1u) & *sq_mask;
        __atomic_store_n(sq_tail, submission_position + 2u, __ATOMIC_RELEASE);
        failures += expect("submit fadvise close", raw_syscall6(
            SYS_io_uring_enter, descriptor, 2, 2,
            IORING_ENTER_GETEVENTS, 0, 0), 2);
        failures += expect_true("fadvise completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) ==
                completion_position + 2u &&
            cqes[completion_position & *cq_mask].user_data ==
                0x4641445649534531ull &&
            cqes[completion_position & *cq_mask].result == 0);
        failures += expect_true("advice close completion",
            cqes[(completion_position + 1u) & *cq_mask].user_data ==
                0x414456434c4f5345ull &&
            cqes[(completion_position + 1u) & *cq_mask].result == 0);
        completion_position += 2u;
        __atomic_store_n(cq_head, completion_position, __ATOMIC_RELEASE);
        advice_descriptor = -1;
    }

    advice_address = (uint64_t)raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    failures += expect_true("advice mapping", (int64_t)advice_address > 0);
    if ((int64_t)advice_address > 0) {
        submission_position = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
        completion_position = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
        memset(&sqes[submission_position & *sq_mask], 0,
               sizeof(sqes[submission_position & *sq_mask]));
        sqes[submission_position & *sq_mask].opcode = IORING_OP_MADVISE;
        sqes[submission_position & *sq_mask].descriptor = -1;
        sqes[submission_position & *sq_mask].offset = PAGE_SIZE;
        sqes[submission_position & *sq_mask].address = advice_address;
        sqes[submission_position & *sq_mask].operation_flags = MADV_DONTNEED;
        sqes[submission_position & *sq_mask].user_data =
            0x4d41445649534531ull;
        sq_array[submission_position & *sq_mask] =
            submission_position & *sq_mask;
        __atomic_store_n(sq_tail, submission_position + 1u, __ATOMIC_RELEASE);
        failures += expect("submit madvise", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("madvise completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) ==
                completion_position + 1u &&
            cqes[completion_position & *cq_mask].user_data ==
                0x4d41445649534531ull &&
            cqes[completion_position & *cq_mask].result == 0);
        __atomic_store_n(cq_head, completion_position + 1u, __ATOMIC_RELEASE);
    }

    epoll_descriptor = (int32_t)raw_syscall6(
        SYS_epoll_create1, 0, 0, 0, 0, 0, 0);
    control_event_descriptor = (int32_t)raw_syscall6(
        SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    failures += expect_true("epoll control descriptors",
        epoll_descriptor >= 0 && control_event_descriptor >= 0);
    if (epoll_descriptor >= 0 && control_event_descriptor >= 0) {
        submission_position = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
        completion_position = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
        memset(&sqes[submission_position & *sq_mask], 0,
               sizeof(sqes[submission_position & *sq_mask]));
        sqes[submission_position & *sq_mask].opcode = IORING_OP_EPOLL_CTL;
        sqes[submission_position & *sq_mask].descriptor = epoll_descriptor;
        sqes[submission_position & *sq_mask].offset =
            (uint32_t)control_event_descriptor;
        sqes[submission_position & *sq_mask].address =
            (uint64_t)(uintptr_t)&epoll_event;
        sqes[submission_position & *sq_mask].length = EPOLL_CTL_ADD;
        sqes[submission_position & *sq_mask].user_data =
            0x45504f4c4c43544cull;
        sq_array[submission_position & *sq_mask] =
            submission_position & *sq_mask;
        __atomic_store_n(sq_tail, submission_position + 1u, __ATOMIC_RELEASE);
        failures += expect("submit epoll ctl", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("epoll ctl completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) ==
                completion_position + 1u &&
            cqes[completion_position & *cq_mask].user_data ==
                0x45504f4c4c43544cull &&
            cqes[completion_position & *cq_mask].result == 0);
        __atomic_store_n(cq_head, completion_position + 1u, __ATOMIC_RELEASE);
    }

    failures += expect("tee input pipe", raw_syscall6(
        SYS_pipe2, (long)tee_input, 0, 0, 0, 0, 0), 0);
    failures += expect("tee output pipe", raw_syscall6(
        SYS_pipe2, (long)tee_output, 0, 0, 0, 0, 0), 0);
    if (tee_input[0] >= 0 && tee_input[1] >= 0 &&
        tee_output[0] >= 0 && tee_output[1] >= 0) {
        failures += expect("tee input write", raw_syscall6(
            SYS_write, tee_input[1], (long)tee_data,
            sizeof(tee_data), 0, 0, 0), sizeof(tee_data));
        submission_position = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
        completion_position = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
        memset(&sqes[submission_position & *sq_mask], 0,
               sizeof(sqes[submission_position & *sq_mask]));
        sqes[submission_position & *sq_mask].opcode = IORING_OP_TEE;
        sqes[submission_position & *sq_mask].descriptor = tee_output[1];
        sqes[submission_position & *sq_mask].length = sizeof(tee_data);
        sqes[submission_position & *sq_mask].splice_descriptor = tee_input[0];
        sqes[submission_position & *sq_mask].user_data =
            0x5445455049504531ull;
        sq_array[submission_position & *sq_mask] =
            submission_position & *sq_mask;
        __atomic_store_n(sq_tail, submission_position + 1u, __ATOMIC_RELEASE);
        failures += expect("submit tee", raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0), 1);
        failures += expect_true("tee completion",
            __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) ==
                completion_position + 1u &&
            cqes[completion_position & *cq_mask].user_data ==
                0x5445455049504531ull &&
            cqes[completion_position & *cq_mask].result ==
                (int32_t)sizeof(tee_data));
        __atomic_store_n(cq_head, completion_position + 1u, __ATOMIC_RELEASE);
        failures += expect("tee output read", raw_syscall6(
            SYS_read, tee_output[0], (long)tee_buffer,
            sizeof(tee_buffer), 0, 0, 0), sizeof(tee_buffer));
        failures += expect_true("tee output data",
            tee_buffer[0] == tee_data[0] &&
            tee_buffer[sizeof(tee_buffer) - 1u] == 0);
    }
    failures += expect("splice input pipe", raw_syscall6(
        SYS_pipe2, (long)splice_input, 0, 0, 0, 0, 0), 0);
    failures += expect("splice output pipe", raw_syscall6(
        SYS_pipe2, (long)splice_output, 0, 0, 0, 0, 0), 0);
    if (splice_input[0] >= 0 && splice_input[1] >= 0 &&
        splice_output[0] >= 0 && splice_output[1] >= 0) {
        failures += expect("splice input write", raw_syscall6(
            SYS_write, splice_input[1], (long)splice_data,
            sizeof(splice_data), 0, 0, 0), sizeof(splice_data));
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_SPLICE;
        path_request.descriptor = splice_output[1];
        path_request.offset = UINT64_MAX;
        path_request.address = UINT64_MAX;
        path_request.length = sizeof(splice_data);
        path_request.splice_descriptor = splice_input[0];
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x53504c4943453031ull, "submit splice", &path_result);
        failures += expect("splice completion", path_result,
                           sizeof(splice_data));
        failures += expect("splice output read", raw_syscall6(
            SYS_read, splice_output[0], (long)splice_buffer,
            sizeof(splice_buffer), 0, 0, 0), sizeof(splice_data));
        failures += expect_true("splice output data",
            splice_buffer[0] == splice_data[0] &&
            splice_buffer[sizeof(splice_data) - 1u] == 0);

        path_request.address = 0;
        path_request.length = 1u;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x53504c4943454552ull, "submit splice pipe offset",
            &path_result);
        failures += expect("splice pipe offset completion",
                           path_result, -ESPIPE);
    }
    if ((int64_t)advice_address > 0)
        (void)raw_syscall6(SYS_munmap, (long)advice_address,
                           PAGE_SIZE, 0, 0, 0, 0);
    if (control_event_descriptor >= 0)
        (void)raw_syscall6(SYS_close, control_event_descriptor, 0, 0, 0, 0, 0);
    if (epoll_descriptor >= 0)
        (void)raw_syscall6(SYS_close, epoll_descriptor, 0, 0, 0, 0, 0);
    for (uint32_t index = 0; index < 2u; ++index) {
        if (tee_input[index] >= 0)
            (void)raw_syscall6(SYS_close, tee_input[index], 0, 0, 0, 0, 0);
        if (tee_output[index] >= 0)
            (void)raw_syscall6(SYS_close, tee_output[index], 0, 0, 0, 0, 0);
        if (splice_input[index] >= 0) {
            (void)raw_syscall6(SYS_close, splice_input[index], 0, 0, 0, 0, 0);
            splice_input[index] = -1;
        }
        if (splice_output[index] >= 0) {
            (void)raw_syscall6(SYS_close, splice_output[index], 0, 0, 0, 0, 0);
            splice_output[index] = -1;
        }
    }

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_MKDIRAT;
    path_request.descriptor = AT_FDCWD;
    path_request.address = (uint64_t)(uintptr_t)path_directory;
    path_request.length = 0700u;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x4d4b444952415431ull, "submit mkdirat", &path_result);
    failures += expect("mkdirat completion", path_result, 0);

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_OPENAT;
    path_request.descriptor = AT_FDCWD;
    path_request.address = (uint64_t)(uintptr_t)path_source;
    path_request.length = 0600u;
    path_request.operation_flags = O_RDWR | O_CREAT | O_TRUNC;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x504154484f50454eull, "submit path open", &path_result);
    failures += expect_true("path open completion", path_result >= 0);
    if (path_result >= 0)
        (void)raw_syscall6(SYS_close, path_result, 0, 0, 0, 0, 0);

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_LINKAT;
    path_request.descriptor = AT_FDCWD;
    path_request.address = (uint64_t)(uintptr_t)path_source;
    path_request.offset = (uint64_t)(uintptr_t)path_hardlink;
    path_request.length = (uint32_t)AT_FDCWD;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x4c494e4b41543031ull, "submit linkat", &path_result);
    failures += expect("linkat completion", path_result, 0);

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_SYMLINKAT;
    path_request.descriptor = AT_FDCWD;
    path_request.address = (uint64_t)(uintptr_t)symlink_target;
    path_request.offset = (uint64_t)(uintptr_t)path_symlink;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x53594d4c494e4b31ull, "submit symlinkat", &path_result);
    failures += expect("symlinkat completion", path_result, 0);

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_RENAMEAT;
    path_request.descriptor = AT_FDCWD;
    path_request.address = (uint64_t)(uintptr_t)path_source;
    path_request.offset = (uint64_t)(uintptr_t)path_renamed;
    path_request.length = (uint32_t)AT_FDCWD;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x52454e414d454154ull, "submit renameat", &path_result);
    failures += expect("renameat completion", path_result, 0);

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_UNLINKAT;
    path_request.descriptor = AT_FDCWD;
    path_request.address = (uint64_t)(uintptr_t)path_hardlink;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x554e4c494e4b3031ull, "submit unlink hardlink", &path_result);
    failures += expect("unlink hardlink completion", path_result, 0);

    path_request.address = (uint64_t)(uintptr_t)path_symlink;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x554e4c494e4b3032ull, "submit unlink symlink", &path_result);
    failures += expect("unlink symlink completion", path_result, 0);

    path_request.address = (uint64_t)(uintptr_t)path_renamed;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x554e4c494e4b3033ull, "submit unlink renamed", &path_result);
    failures += expect("unlink renamed completion", path_result, 0);

    path_request.address = (uint64_t)(uintptr_t)path_directory;
    path_request.operation_flags = AT_REMOVEDIR;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x554e4c494e4b4449ull, "submit unlink directory", &path_result);
    failures += expect("unlink directory completion", path_result, 0);

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_SOCKET;
    path_request.descriptor = AF_UNIX;
    path_request.offset = SOCK_STREAM;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x534f434b45543031ull, "submit socket", &path_result);
    failures += expect_true("socket completion", path_result >= 0);
    ring_listener_descriptor = path_result;
    if (ring_listener_descriptor >= 0) {
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_BIND;
        path_request.descriptor = ring_listener_descriptor;
        path_request.address =
            (uint64_t)(uintptr_t)&ring_listen_address;
        path_request.offset = sizeof(uint16_t) +
            sizeof("edgeos-io-uring-created");
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x42494e4452494e47ull, "submit bind", &path_result);
        failures += expect("bind completion", path_result, 0);

        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_LISTEN;
        path_request.descriptor = ring_listener_descriptor;
        path_request.length = 1u;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x4c495354454e3031ull, "submit listen", &path_result);
        failures += expect("listen completion", path_result, 0);
        (void)raw_syscall6(
            SYS_close, ring_listener_descriptor, 0, 0, 0, 0, 0);
    }

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_OPENAT;
    path_request.descriptor = AT_FDCWD;
    path_request.address = (uint64_t)(uintptr_t)xattr_path;
    path_request.length = 0600u;
    path_request.operation_flags = O_RDWR | O_CREAT | O_TRUNC;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x58415454524f504eull, "submit xattr open", &path_result);
    failures += expect_true("xattr open completion", path_result >= 0);
    xattr_descriptor = path_result;
    if (xattr_descriptor >= 0) {
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_FSETXATTR;
        path_request.descriptor = xattr_descriptor;
        path_request.address = (uint64_t)(uintptr_t)xattr_name;
        path_request.offset = (uint64_t)(uintptr_t)xattr_fd_value;
        path_request.length = sizeof(xattr_fd_value);
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x4653455458415454ull, "submit fsetxattr", &path_result);
        failures += expect("fsetxattr completion", path_result, 0);

        memset(xattr_buffer, 0, sizeof(xattr_buffer));
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_FGETXATTR;
        path_request.descriptor = xattr_descriptor;
        path_request.address = (uint64_t)(uintptr_t)xattr_name;
        path_request.offset = (uint64_t)(uintptr_t)xattr_buffer;
        path_request.length = sizeof(xattr_buffer);
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x4647455458415454ull, "submit fgetxattr", &path_result);
        failures += expect(
            "fgetxattr completion", path_result, sizeof(xattr_fd_value));
        failures += expect_true("fgetxattr data",
            xattr_buffer[0] == xattr_fd_value[0] &&
            xattr_buffer[sizeof(xattr_fd_value) - 1u] == 0);

        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_SETXATTR;
        path_request.descriptor = -1;
        path_request.address = (uint64_t)(uintptr_t)xattr_name;
        path_request.offset = (uint64_t)(uintptr_t)xattr_path_value;
        path_request.length = sizeof(xattr_path_value);
        path_request.address3 = (uint64_t)(uintptr_t)xattr_path;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x5345545841545452ull, "submit setxattr", &path_result);
        failures += expect("setxattr completion", path_result, 0);

        memset(xattr_buffer, 0, sizeof(xattr_buffer));
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_GETXATTR;
        path_request.descriptor = -1;
        path_request.address = (uint64_t)(uintptr_t)xattr_name;
        path_request.offset = (uint64_t)(uintptr_t)xattr_buffer;
        path_request.length = sizeof(xattr_buffer);
        path_request.address3 = (uint64_t)(uintptr_t)xattr_path;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x4745545841545452ull, "submit getxattr", &path_result);
        failures += expect(
            "getxattr completion", path_result, sizeof(xattr_path_value));
        failures += expect_true("getxattr data",
            xattr_buffer[0] == xattr_path_value[0] &&
            xattr_buffer[sizeof(xattr_path_value) - 1u] == 0);

        failures += expect("fsetxattr create existing", raw_syscall6(
            SYS_fsetxattr, xattr_descriptor,
            (long)(uintptr_t)xattr_name,
            (long)(uintptr_t)xattr_fd_value, sizeof(xattr_fd_value),
            XATTR_CREATE, 0), -EEXIST);
        failures += expect("fsetxattr replace", raw_syscall6(
            SYS_fsetxattr, xattr_descriptor,
            (long)(uintptr_t)xattr_name,
            (long)(uintptr_t)xattr_fd_value, sizeof(xattr_fd_value),
            XATTR_REPLACE, 0), 0);
        failures += expect("fgetxattr query", raw_syscall6(
            SYS_fgetxattr, xattr_descriptor,
            (long)(uintptr_t)xattr_name, 0, 0, 0, 0),
            sizeof(xattr_fd_value));
        failures += expect("fgetxattr short", raw_syscall6(
            SYS_fgetxattr, xattr_descriptor,
            (long)(uintptr_t)xattr_name,
            (long)(uintptr_t)xattr_buffer,
            sizeof(xattr_fd_value) - 1u, 0, 0), -ERANGE);
        memset(xattr_list, 0, sizeof(xattr_list));
        failures += expect("flistxattr", raw_syscall6(
            SYS_flistxattr, xattr_descriptor,
            (long)(uintptr_t)xattr_list, sizeof(xattr_list), 0, 0, 0),
            sizeof(xattr_name));
        failures += expect_true("flistxattr data",
            xattr_list[0] == xattr_name[0] &&
            xattr_list[sizeof(xattr_name) - 1u] == 0);
        failures += expect("fremovexattr", raw_syscall6(
            SYS_fremovexattr, xattr_descriptor,
            (long)(uintptr_t)xattr_name, 0, 0, 0, 0), 0);
        failures += expect("fgetxattr removed", raw_syscall6(
            SYS_fgetxattr, xattr_descriptor,
            (long)(uintptr_t)xattr_name, 0, 0, 0, 0), -ENODATA);

        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_FTRUNCATE;
        path_request.descriptor = xattr_descriptor;
        path_request.offset = 123u;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x465452554e433031ull, "submit ftruncate", &path_result);
        failures += expect("ftruncate completion", path_result, 0);

        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_SYNC_FILE_RANGE;
        path_request.descriptor = xattr_descriptor;
        path_request.offset = 1u;
        path_request.length = 64u;
        path_request.operation_flags =
            SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x53594e4352414e47ull, "submit sync file range", &path_result);
        failures += expect("sync file range completion", path_result, 0);

        path_request.operation_flags = 8u;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x53594e4342414446ull, "submit invalid sync range", &path_result);
        failures += expect("invalid sync range completion",
                           path_result, -EINVAL);

        memset(statx_buffer, 0, sizeof(statx_buffer));
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_STATX;
        path_request.descriptor = AT_FDCWD;
        path_request.address = (uint64_t)(uintptr_t)xattr_path;
        path_request.offset = (uint64_t)(uintptr_t)statx_buffer;
        path_request.length = 0x7ffu;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x535441545853495aull, "submit size statx", &path_result);
        failures += expect("size statx completion", path_result, 0);
        failures += expect_true("ftruncate size",
            statx_buffer[40] == 123u && statx_buffer[41] == 0u &&
            statx_buffer[47] == 0u);
        (void)raw_syscall6(
            SYS_close, xattr_descriptor, 0, 0, 0, 0, 0);

        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_UNLINKAT;
        path_request.descriptor = AT_FDCWD;
        path_request.address = (uint64_t)(uintptr_t)xattr_path;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x554e4c494e4b5841ull, "submit xattr unlink", &path_result);
        failures += expect("xattr unlink completion", path_result, 0);
    }

    memset(&path_request, 0, sizeof(path_request));
    path_request.opcode = IORING_OP_FUTEX_WAKE;
    path_request.descriptor = FUTEX2_SIZE_U32;
    path_request.address = (uint64_t)(uintptr_t)&futex_word;
    path_request.address3 = UINT32_MAX;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x465554455857414bull, "submit futex wake", &path_result);
    failures += expect("futex wake completion", path_result, 0);

    path_request.address3 = 0;
    failures += submit_one(
        descriptor, sq_tail, sq_mask, sq_array, sqes,
        cq_head, cq_tail, cq_mask, cqes, &path_request,
        0x4655544558424144ull, "submit invalid futex wake", &path_result);
    failures += expect("invalid futex wake completion", path_result,
                       -EINVAL);

    failures += expect("fixed splice input pipe", raw_syscall6(
        SYS_pipe2, (long)splice_input, 0, 0, 0, 0, 0), 0);
    failures += expect("fixed splice output pipe", raw_syscall6(
        SYS_pipe2, (long)splice_output, 0, 0, 0, 0, 0), 0);
    if (splice_input[0] >= 0 && splice_input[1] >= 0 &&
        splice_output[0] >= 0 && splice_output[1] >= 0) {
        failures += expect("fixed splice input write", raw_syscall6(
            SYS_write, splice_input[1], (long)splice_data,
            sizeof(splice_data), 0, 0, 0), sizeof(splice_data));
        fixed_files[0] = splice_input[0];
        fixed_files[1] = splice_output[1];
        failures += expect("register fixed splice files", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_REGISTER_FILES,
            (long)fixed_files, 2, 0, 0), 0);
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_SPLICE;
        path_request.flags = IOSQE_FIXED_FILE;
        path_request.descriptor = 1;
        path_request.offset = UINT64_MAX;
        path_request.address = UINT64_MAX;
        path_request.length = sizeof(splice_data);
        path_request.operation_flags = SPLICE_F_FD_IN_FIXED;
        path_request.splice_descriptor = 0;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x53504c4943454658ull, "submit fixed splice", &path_result);
        failures += expect("fixed splice completion", path_result,
                           sizeof(splice_data));
        memset(splice_buffer, 0, sizeof(splice_buffer));
        failures += expect("fixed splice output read", raw_syscall6(
            SYS_read, splice_output[0], (long)splice_buffer,
            sizeof(splice_buffer), 0, 0, 0), sizeof(splice_data));
        failures += expect_true("fixed splice output data",
            splice_buffer[0] == splice_data[0] &&
            splice_buffer[sizeof(splice_data) - 1u] == 0);
        failures += expect("unregister fixed splice files", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_UNREGISTER_FILES,
            0, 0, 0, 0), 0);
    }
    for (uint32_t index = 0; index < 2u; ++index) {
        if (splice_input[index] >= 0) {
            (void)raw_syscall6(
                SYS_close, splice_input[index], 0, 0, 0, 0, 0);
            splice_input[index] = -1;
        }
        if (splice_output[index] >= 0) {
            (void)raw_syscall6(
                SYS_close, splice_output[index], 0, 0, 0, 0, 0);
            splice_output[index] = -1;
        }
    }

    fixed_files[0] = (int32_t)descriptor;
    failures += expect("reject ring as fixed file", raw_syscall6(
        SYS_io_uring_register, descriptor, IORING_REGISTER_FILES,
        (long)fixed_files, 1, 0, 0), -EBADF);
    event_descriptor = raw_syscall6(
        SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    failures += expect_true("fixed file eventfd", event_descriptor >= 0);
    if (event_descriptor >= 0) {
        fixed_files[0] = (int32_t)event_descriptor;
        fixed_files[1] = -1;
        failures += expect("register fixed files", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_REGISTER_FILES,
            (long)fixed_files, 2, 0, 0), 0);
        failures += expect("reject duplicate fixed files", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_REGISTER_FILES,
            (long)fixed_files, 2, 0, 0), -EBUSY);
        (void)raw_syscall6(
            SYS_close, event_descriptor, 0, 0, 0, 0, 0);
        event_descriptor = -1;
        event_value = 1u;
        memset(&path_request, 0, sizeof(path_request));
        path_request.opcode = IORING_OP_WRITE;
        path_request.flags = IOSQE_FIXED_FILE;
        path_request.descriptor = 0;
        path_request.offset = UINT64_MAX;
        path_request.address = (uint64_t)(uintptr_t)&event_value;
        path_request.length = sizeof(event_value);
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x464958454446494cull, "submit fixed file write", &path_result);
        failures += expect("fixed file write completion", path_result,
                           sizeof(event_value));
        path_request.descriptor = 1;
        failures += submit_one(
            descriptor, sq_tail, sq_mask, sq_array, sqes,
            cq_head, cq_tail, cq_mask, cqes, &path_request,
            0x4649584544535041ull, "submit sparse fixed file", &path_result);
        failures += expect("sparse fixed file completion", path_result,
                           -EBADF);
        failures += expect("unregister fixed files", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_UNREGISTER_FILES,
            0, 0, 0, 0), 0);
        failures += expect("repeat unregister fixed files", raw_syscall6(
            SYS_io_uring_register, descriptor, IORING_UNREGISTER_FILES,
            0, 0, 0, 0), -ENXIO);
    }

    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_tests();
    print_text(failures ? "io-uring-abi: FAIL\n" :
                          "io-uring-abi: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
