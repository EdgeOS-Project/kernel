/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring SEND_ZC and SENDMSG_ZC ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_socket 41
#define SYS_connect 42
#define SYS_recvfrom 45
#define SYS_bind 49
#define SYS_socketpair 53
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_connect 203
#define SYS_recvfrom 207
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_send_zc_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define EINVAL 22
#define EOPNOTSUPP 95
#define MSG_DONTWAIT 0x40u

#define IORING_ENTER_GETEVENTS (1u << 0)
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_OP_SEND_ZC 47u
#define IORING_OP_SENDMSG_ZC 48u
#define IOSQE_FIXED_FILE (1u << 0)
#define IOSQE_CQE_SKIP_SUCCESS (1u << 6)
#define IORING_RECVSEND_FIXED_BUF (1u << 2)
#define IORING_SEND_ZC_REPORT_USAGE (1u << 3)
#define IORING_SEND_VECTORIZED (1u << 5)
#define IORING_CQE_F_MORE (1u << 1)
#define IORING_CQE_F_NOTIF (1u << 3)
#define IORING_NOTIF_USAGE_ZC_COPIED (1u << 31)
#define IORING_REGISTER_BUFFERS 0u
#define IORING_UNREGISTER_BUFFERS 1u
#define IORING_REGISTER_FILES 2u
#define IORING_UNREGISTER_FILES 3u

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

struct user_sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t zero[8];
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

void *memcpy(void *destination, const void *source, unsigned long length) {
    unsigned char *output = destination;
    const unsigned char *input = source;
    for (unsigned long index = 0; index < length; ++index)
        output[index] = input[index];
    return destination;
}

unsigned long strlen(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)strlen(text), 0, 0, 0);
}

static int record_failure(int result, const char *label) {
    if (result) print_text(label);
    return result;
}

static uint16_t big_endian16(uint16_t value) {
    return (uint16_t)((value << 8) | (value >> 8));
}

static uint32_t big_endian32(uint32_t value) {
    return ((value & 0x000000ffu) << 24) |
           ((value & 0x0000ff00u) << 8) |
           ((value & 0x00ff0000u) >> 8) |
           ((value & 0xff000000u) >> 24);
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int submit_and_expect(
        long descriptor, const struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        const struct io_uring_sqe *request,
        int32_t main_result, uint32_t main_flags,
        uint64_t notification_data, int32_t notification_result,
        uint32_t completion_count) {
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
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t slot = submission & *sq_mask;

    memset(&sqes[slot], 0, sizeof(sqes[slot]));
    memcpy(&sqes[slot], request, sizeof(*request));
    sq_array[slot] = slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    if (raw_syscall6(
            SYS_io_uring_enter, descriptor, 1, completion_count,
            IORING_ENTER_GETEVENTS, 0, 0) != 1)
        return 1;
    if (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) !=
        completion + completion_count)
        return 1;
    if (cqes[completion & *cq_mask].user_data != request->user_data ||
        cqes[completion & *cq_mask].result != main_result ||
        cqes[completion & *cq_mask].flags != main_flags)
        return 1;
    if (completion_count == 2u &&
        (cqes[(completion + 1u) & *cq_mask].user_data !=
             notification_data ||
         cqes[(completion + 1u) & *cq_mask].result !=
             notification_result ||
         cqes[(completion + 1u) & *cq_mask].flags !=
             IORING_CQE_F_NOTIF))
        return 1;
    __atomic_store_n(
        cq_head, completion + completion_count, __ATOMIC_RELEASE);
    return 0;
}

static int receive_exact(int descriptor, const char *expected,
                         uint32_t length) {
    char received[64];
    long result;

    if (length > sizeof(received)) return 1;
    memset(received, 0, sizeof(received));
    result = raw_syscall6(
        SYS_recvfrom, descriptor, (long)received, length,
        MSG_DONTWAIT, 0, 0);
    if (result != length) return 1;
    for (uint32_t index = 0; index < length; ++index)
        if (received[index] != expected[index]) return 1;
    return 0;
}

static int run_probe(void) {
    static char payload[] = "edge-zc";
    static const char first[] = "edge-";
    static const char second[] = "vector";
    struct user_iovec vectors[2] = {
        {(uint64_t)(uintptr_t)first, sizeof(first) - 1u},
        {(uint64_t)(uintptr_t)second, sizeof(second)},
    };
    struct user_msghdr message = {
        .vectors = (uint64_t)(uintptr_t)vectors,
        .vector_count = 2u,
    };
    struct user_iovec fixed_buffer = {
        (uint64_t)(uintptr_t)payload, sizeof(payload),
    };
    struct user_sockaddr_in address = {
        .family = AF_INET,
        .port = 0,
        .address = 0,
    };
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    int32_t fixed_file;
    int32_t internet_sender = -1;
    int32_t internet_receiver = -1;
    int32_t unix_sockets[2] = {-1, -1};
    void *sq_ring = 0;
    void *cq_ring = 0;
    struct io_uring_sqe *sqes = 0;
    long ring;
    int failures = 0;

    memset(&parameters, 0, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (ring < 0) return 1;
    sq_ring = map_ring(ring, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring, IORING_OFF_CQ_RING);
    sqes = map_ring(ring, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        failures = 1;
        goto done;
    }

    internet_receiver = (int32_t)raw_syscall6(
        SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    internet_sender = (int32_t)raw_syscall6(
        SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    address.port = big_endian16(39491u);
    address.address = big_endian32(0x7f000001u);
    if (internet_receiver < 0 || internet_sender < 0 ||
        raw_syscall6(SYS_bind, internet_receiver, (long)&address,
                     sizeof(address), 0, 0, 0) != 0 ||
        raw_syscall6(SYS_connect, internet_sender, (long)&address,
                     sizeof(address), 0, 0, 0) != 0) {
        failures = 1;
        goto done;
    }

    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SEND_ZC;
    request.ioprio = IORING_SEND_ZC_REPORT_USAGE;
    request.descriptor = internet_sender;
    request.address = (uint64_t)(uintptr_t)payload;
    request.length = sizeof(payload);
    request.user_data = 0x53454e445a433031ull;
    request.address3 = 0x4e4f5449465a4331ull;
    failures += record_failure(submit_and_expect(
        ring, &parameters, sq_ring, cq_ring, sqes, &request,
        sizeof(payload), IORING_CQE_F_MORE, request.address3,
        (int32_t)IORING_NOTIF_USAGE_ZC_COPIED, 2u),
        "SEND_ZC_REPORT_FAIL\n");
    failures += record_failure(receive_exact(
        internet_receiver, payload, sizeof(payload)),
        "SEND_ZC_REPORT_DATA_FAIL\n");

    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SEND_ZC;
    request.ioprio = IORING_SEND_VECTORIZED;
    request.descriptor = internet_sender;
    request.address = (uint64_t)(uintptr_t)vectors;
    request.length = 2u;
    request.user_data = 0x53454e445a433032ull;
    failures += record_failure(submit_and_expect(
        ring, &parameters, sq_ring, cq_ring, sqes, &request,
        (int32_t)(sizeof(first) + sizeof(second) - 1u),
        IORING_CQE_F_MORE, request.user_data, 0, 2u),
        "SEND_ZC_VECTOR_FAIL\n");
    failures += record_failure(receive_exact(
        internet_receiver, "edge-vector",
        sizeof(first) + sizeof(second) - 1u),
        "SEND_ZC_VECTOR_DATA_FAIL\n");

    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SENDMSG_ZC;
    request.descriptor = internet_sender;
    request.address = (uint64_t)(uintptr_t)&message;
    request.length = 1u;
    request.user_data = 0x53454e444d5a4331ull;
    failures += record_failure(submit_and_expect(
        ring, &parameters, sq_ring, cq_ring, sqes, &request,
        (int32_t)(sizeof(first) + sizeof(second) - 1u),
        IORING_CQE_F_MORE, request.user_data, 0, 2u),
        "SENDMSG_ZC_FAIL\n");
    failures += record_failure(receive_exact(
        internet_receiver, "edge-vector",
        sizeof(first) + sizeof(second) - 1u),
        "SENDMSG_ZC_DATA_FAIL\n");

    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_BUFFERS,
        (long)&fixed_buffer, 1, 0, 0) != 0,
        "SEND_ZC_REGISTER_BUFFER_FAIL\n");
    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SEND_ZC;
    request.ioprio = IORING_RECVSEND_FIXED_BUF;
    request.descriptor = internet_sender;
    request.address = (uint64_t)(uintptr_t)payload;
    request.length = sizeof(payload);
    request.user_data = 0x53454e4446495842ull;
    failures += record_failure(submit_and_expect(
        ring, &parameters, sq_ring, cq_ring, sqes, &request,
        sizeof(payload), IORING_CQE_F_MORE, request.user_data, 0, 2u),
        "SEND_ZC_FIXED_BUFFER_FAIL\n");
    failures += record_failure(receive_exact(
        internet_receiver, payload, sizeof(payload)),
        "SEND_ZC_FIXED_BUFFER_DATA_FAIL\n");
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_BUFFERS,
        0, 0, 0, 0) != 0, "SEND_ZC_UNREGISTER_BUFFER_FAIL\n");

    fixed_file = internet_sender;
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES,
        (long)&fixed_file, 1, 0, 0) != 0,
        "SEND_ZC_REGISTER_FILE_FAIL\n");
    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SEND_ZC;
    request.flags = IOSQE_FIXED_FILE;
    request.descriptor = 0;
    request.address = (uint64_t)(uintptr_t)payload;
    request.length = sizeof(payload);
    request.user_data = 0x53454e4446495846ull;
    failures += record_failure(submit_and_expect(
        ring, &parameters, sq_ring, cq_ring, sqes, &request,
        sizeof(payload), IORING_CQE_F_MORE, request.user_data, 0, 2u),
        "SEND_ZC_FIXED_FILE_FAIL\n");
    failures += record_failure(receive_exact(
        internet_receiver, payload, sizeof(payload)),
        "SEND_ZC_FIXED_FILE_DATA_FAIL\n");
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_FILES,
        0, 0, 0, 0) != 0, "SEND_ZC_UNREGISTER_FILE_FAIL\n");

    memset(&request, 0, sizeof(request));
    request.opcode = IORING_OP_SEND_ZC;
    request.ioprio = 0x8000u;
    request.descriptor = internet_sender;
    request.user_data = 0x53454e4442414446ull;
    failures += record_failure(submit_and_expect(
        ring, &parameters, sq_ring, cq_ring, sqes, &request,
        -EINVAL, IORING_CQE_F_MORE, request.user_data, 0, 2u),
        "SEND_ZC_INVALID_FLAG_FAIL\n");

    request.ioprio = 0;
    request.flags = IOSQE_CQE_SKIP_SUCCESS;
    request.user_data = 0x53454e44534b4950ull;
    failures += record_failure(submit_and_expect(
        ring, &parameters, sq_ring, cq_ring, sqes, &request,
        -EINVAL, 0u, 0u, 0, 1u), "SEND_ZC_SKIP_FAIL\n");

    if (raw_syscall6(
            SYS_socketpair, AF_UNIX, SOCK_STREAM, 0,
            (long)unix_sockets, 0, 0) != 0) {
        ++failures;
    } else {
        memset(&request, 0, sizeof(request));
        request.opcode = IORING_OP_SEND_ZC;
        request.descriptor = unix_sockets[0];
        request.address = (uint64_t)(uintptr_t)payload;
        request.length = sizeof(payload);
        request.user_data = 0x53454e44554e4958ull;
        failures += record_failure(submit_and_expect(
            ring, &parameters, sq_ring, cq_ring, sqes, &request,
            -EOPNOTSUPP, IORING_CQE_F_MORE,
            request.user_data, 0, 2u), "SEND_ZC_UNIX_FAIL\n");
    }

done:
    if (internet_sender >= 0)
        (void)raw_syscall6(
            SYS_close, internet_sender, 0, 0, 0, 0, 0);
    if (internet_receiver >= 0)
        (void)raw_syscall6(
            SYS_close, internet_receiver, 0, 0, 0, 0, 0);
    for (uint32_t index = 0; index < 2u; ++index)
        if (unix_sockets[index] >= 0)
            (void)raw_syscall6(
                SYS_close, unix_sockets[index], 0, 0, 0, 0, 0);
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

void _start(void) {
    int failures = run_probe();
    print_text(failures ? "IO_URING_SEND_ZC_FAIL\n" :
                          "IO_URING_SEND_ZC_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
