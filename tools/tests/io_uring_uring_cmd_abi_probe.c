/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring URING_CMD socket ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_pread64 17
#define SYS_pwrite64 18
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_ioctl 16
#define SYS_openat 257
#define SYS_socket 41
#define SYS_sendto 44
#define SYS_bind 49
#define SYS_socketpair 53
#define SYS_setsockopt 54
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_pread64 67
#define SYS_pwrite64 68
#define SYS_exit 93
#define SYS_socket 198
#define SYS_socketpair 199
#define SYS_bind 200
#define SYS_sendto 206
#define SYS_setsockopt 208
#define SYS_ioctl 29
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_openat 56
#else
#error "io_uring_uring_cmd_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define AT_FDCWD -100
#define O_RDWR 2u
#define PAGE_SIZE 4096u
#define AF_UNIX 1
#define AF_INET 2
#define SOCK_DGRAM 2
#define SOL_SOCKET 1u
#define SO_TYPE 3u
#define SO_REUSEADDR 2u
#define SO_TIMESTAMPING 37u
#define EINVAL 22
#define EBADF 9
#define EOPNOTSUPP 95
#define SIOCGIFFLAGS 0x8913u
#define SIOCSIFFLAGS 0x8914u
#define IFF_UP 1u

#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_SETUP_SQE128 (1u << 10)
#define IORING_SETUP_CQE32 (1u << 11)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_URING_CMD 46u
#define IORING_OP_URING_CMD128 64u
#define SOCKET_URING_OP_SIOCINQ 0u
#define SOCKET_URING_OP_SIOCOUTQ 1u
#define SOCKET_URING_OP_GETSOCKOPT 2u
#define SOCKET_URING_OP_SETSOCKOPT 3u
#define SOCKET_URING_OP_TX_TIMESTAMP 4u
#define SOCKET_URING_OP_GETSOCKNAME 5u
#define IORING_CQE_F_MORE (1u << 1)
#define SOF_TIMESTAMPING_TX_SOFTWARE (1u << 1)
#define SOF_TIMESTAMPING_SOFTWARE (1u << 4)
#define SOF_TIMESTAMPING_OPT_ID (1u << 7)
#define SOF_TIMESTAMPING_OPT_TSONLY (1u << 11)
#define BLKGETSIZE64 0x80081272u
#define BLOCK_URING_CMD_DISCARD 0x1200u

struct user_sockaddr {
    uint16_t family;
    uint8_t data[14];
};

struct user_sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t zero[8];
};

struct user_ifreq {
    char name[16];
    uint8_t value[24];
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

static int bring_loopback_up(long descriptor) {
    struct user_ifreq request;
    uint16_t flags;

    memset(&request, 0, sizeof(request));
    request.name[0] = 'l';
    request.name[1] = 'o';
    if (raw_syscall6(
            SYS_ioctl, descriptor, SIOCGIFFLAGS,
            (long)&request, 0, 0, 0) != 0)
        return 1;
    flags = (uint16_t)request.value[0] |
        ((uint16_t)request.value[1] << 8u);
    flags |= IFF_UP;
    request.value[0] = (uint8_t)flags;
    request.value[1] = (uint8_t)(flags >> 8u);
    return raw_syscall6(
        SYS_ioctl, descriptor, SIOCSIFFLAGS,
        (long)&request, 0, 0, 0) != 0;
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

static int run_ring(long socket_descriptor, long queue_descriptor,
                    long queue_sender,
                    const struct user_sockaddr_in *queue_address,
                    uint32_t setup_flags, uint8_t opcode) {
    static const uint8_t payload[] = {'q', 'u', 'e', 'u', 'e'};
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    struct user_sockaddr name;
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *sqes = 0;
    uint32_t name_length;
    uint32_t option_value;
    uint8_t receive_buffer[sizeof(payload)];
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

    memset(&request, 0, sizeof(request));
    request.opcode = opcode;
    request.descriptor = (int32_t)socket_descriptor;
    request.offset = SOCKET_URING_OP_SIOCINQ;
    request.user_data = 6u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, -EOPNOTSUPP), "SIOCINQ_UNSUPPORTED_PROTOCOL_FAIL\n");

    failures += record_failure(raw_syscall6(
        SYS_sendto, queue_sender, (long)payload, sizeof(payload), 0,
        (long)queue_address, sizeof(*queue_address)) !=
        (long)sizeof(payload),
        "SOCKET_QUEUE_WRITE_FAIL\n");
    memset(&request, 0, sizeof(request));
    request.opcode = opcode;
    request.descriptor = (int32_t)queue_descriptor;
    request.offset = SOCKET_URING_OP_SIOCINQ;
    request.user_data = 7u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, sizeof(payload)), "SIOCINQ_RESULT_FAIL\n");

    request.offset = SOCKET_URING_OP_SIOCOUTQ;
    request.user_data = 8u;
    failures += record_failure(submit_one(
        descriptor, &parameters, sq_ring, cq_ring, sqes, stride,
        &request, 0), "SIOCOUTQ_RESULT_FAIL\n");
    failures += record_failure(raw_syscall6(
        SYS_read, queue_descriptor, (long)receive_buffer,
        sizeof(payload), 0, 0, 0) != (long)sizeof(payload),
        "SOCKET_QUEUE_READ_FAIL\n");

    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int run_null_ring(uint32_t setup_flags, uint8_t opcode) {
    static const char null_path[] = "/dev/null";
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *sqes = 0;
    uint32_t stride = setup_flags & IORING_SETUP_SQE128 ? 128u : 64u;
    long null_descriptor;
    long ring_descriptor;
    int failures = 0;

    null_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)null_path, O_RDWR, 0, 0, 0);
    if (null_descriptor < 0) {
        print_text("NULL_OPEN_FAIL\n");
        return 1;
    }
    memset(&parameters, 0, sizeof(parameters));
    parameters.flags = setup_flags;
    ring_descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (ring_descriptor < 0) {
        print_text("NULL_URING_SETUP_FAIL\n");
        (void)raw_syscall6(
            SYS_close, null_descriptor, 0, 0, 0, 0, 0);
        return 1;
    }
    sq_ring = map_ring(ring_descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring_descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(ring_descriptor, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        print_text("NULL_URING_MMAP_FAIL\n");
        failures = 1;
    } else {
        memset(&request, 0, sizeof(request));
        request.opcode = opcode;
        request.descriptor = (int32_t)null_descriptor;
        request.offset = 0x4e554c4cu;
        request.address = 0x1111222233334444ull;
        request.length = 0x55667788u;
        request.user_data = 0x4e554c4c434d44ull;
        failures += record_failure(submit_one(
            ring_descriptor, &parameters, sq_ring, cq_ring, sqes,
            stride, &request, 0), "NULL_URING_CMD_FAIL\n");
    }
    if (sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_close, ring_descriptor, 0, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_close, null_descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int run_block_discard_ring(uint32_t setup_flags, uint8_t opcode) {
    static const char *const paths[] = {
        "/dev/sda", "/dev/vda", "/dev/ram0", "/dev/b252",
        "/dev/b253", "/dev/b254", "/dev/b255", "/dev/b256",
        "/dev/b257", "/dev/b258", "/dev/b259"
    };
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    uint8_t original[512];
    uint8_t pattern[512];
    uint8_t result[512];
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *sqes = 0;
    uint64_t device_size = 0u;
    uint64_t offset;
    const char *block_path = 0;
    uint32_t stride = setup_flags & IORING_SETUP_SQE128 ? 128u : 64u;
    long block_descriptor = -1;
    long ring_descriptor;
    int failures = 0;

    for (uint32_t index = 0;
         index < sizeof(paths) / sizeof(paths[0]); ++index) {
        block_descriptor = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)paths[index], O_RDWR,
            0, 0, 0);
        if (block_descriptor >= 0) {
            block_path = paths[index];
            break;
        }
    }
    if (block_descriptor < 0) {
        print_text("BLOCK_DISCARD_OPEN_FAIL\n");
        return 1;
    }
    if (raw_syscall6(
            SYS_ioctl, block_descriptor, BLKGETSIZE64,
            (long)&device_size, 0, 0, 0) != 0 || device_size < 4096u) {
        print_text("BLOCK_DISCARD_SIZE_FAIL\n");
        (void)raw_syscall6(
            SYS_close, block_descriptor, 0, 0, 0, 0, 0);
        return 1;
    }
    offset = (device_size - 4096u) & ~511ull;
    memset(pattern, 0x5a, sizeof(pattern));
    if (raw_syscall6(
            SYS_pread64, block_descriptor, (long)original,
            sizeof(original), (long)offset, 0, 0) !=
        (long)sizeof(original)) {
        print_text("BLOCK_DISCARD_BACKUP_FAIL\n");
        (void)raw_syscall6(
            SYS_close, block_descriptor, 0, 0, 0, 0, 0);
        return 1;
    }
    failures += record_failure(raw_syscall6(
        SYS_pwrite64, block_descriptor, (long)pattern,
        sizeof(pattern), (long)offset, 0, 0) != (long)sizeof(pattern),
        "BLOCK_DISCARD_PREPARE_FAIL\n");
    if (failures) goto block_discard_restore;

    memset(&parameters, 0, sizeof(parameters));
    parameters.flags = setup_flags;
    ring_descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (ring_descriptor < 0) {
        print_text("BLOCK_DISCARD_SETUP_FAIL\n");
        failures = 1;
        goto block_discard_restore;
    }
    sq_ring = map_ring(ring_descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring_descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(ring_descriptor, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        print_text("BLOCK_DISCARD_MMAP_FAIL\n");
        failures = 1;
    } else {
        memset(&request, 0, sizeof(request));
        request.opcode = opcode;
        request.descriptor = (int32_t)block_descriptor;
        request.offset = BLOCK_URING_CMD_DISCARD;
        request.address = offset;
        request.address3 = sizeof(pattern);
        request.user_data = 0x424c4b44495343ull;
        failures += record_failure(submit_one(
            ring_descriptor, &parameters, sq_ring, cq_ring, sqes,
            stride, &request, 0), "BLOCK_DISCARD_CMD_FAIL\n");
        request.address = offset + 1u;
        request.user_data++;
        failures += record_failure(submit_one(
            ring_descriptor, &parameters, sq_ring, cq_ring, sqes,
            stride, &request, -EINVAL),
            "BLOCK_DISCARD_ALIGNMENT_FAIL\n");
        request.address = offset;
        request.address3 = 0u;
        request.user_data++;
        failures += record_failure(submit_one(
            ring_descriptor, &parameters, sq_ring, cq_ring, sqes,
            stride, &request, -EINVAL),
            "BLOCK_DISCARD_ZERO_LENGTH_FAIL\n");
        request.address3 = sizeof(pattern);
        request.offset = BLOCK_URING_CMD_DISCARD + 1u;
        request.user_data++;
        failures += record_failure(submit_one(
            ring_descriptor, &parameters, sq_ring, cq_ring, sqes,
            stride, &request, -EINVAL),
            "BLOCK_DISCARD_UNKNOWN_COMMAND_FAIL\n");
        request.offset = BLOCK_URING_CMD_DISCARD;
        request.length = 1u;
        request.user_data++;
        failures += record_failure(submit_one(
            ring_descriptor, &parameters, sq_ring, cq_ring, sqes,
            stride, &request, -EINVAL),
            "BLOCK_DISCARD_RESERVED_FAIL\n");
        request.length = 0u;
        {
            long read_only_descriptor = raw_syscall6(
                SYS_openat, AT_FDCWD, (long)block_path, 0u,
                0, 0, 0);
            failures += record_failure(
                read_only_descriptor < 0,
                "BLOCK_DISCARD_READ_ONLY_OPEN_FAIL\n");
            if (read_only_descriptor >= 0) {
                request.descriptor = (int32_t)read_only_descriptor;
                request.user_data++;
                failures += record_failure(submit_one(
                    ring_descriptor, &parameters, sq_ring, cq_ring,
                    sqes, stride, &request, -EBADF),
                    "BLOCK_DISCARD_READ_ONLY_FAIL\n");
                (void)raw_syscall6(
                    SYS_close, read_only_descriptor, 0, 0, 0, 0, 0);
                request.descriptor = (int32_t)block_descriptor;
            }
        }
        memset(result, 0xa5, sizeof(result));
        failures += record_failure(raw_syscall6(
            SYS_pread64, block_descriptor, (long)result,
            sizeof(result), (long)offset, 0, 0) != (long)sizeof(result),
            "BLOCK_DISCARD_READBACK_FAIL\n");
        for (uint32_t index = 0; index < sizeof(result); ++index) {
            if (result[index] != 0u) {
                failures += record_failure(
                    1, "BLOCK_DISCARD_CONTENT_FAIL\n");
                break;
            }
        }
    }
    if (sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_close, ring_descriptor, 0, 0, 0, 0, 0);

block_discard_restore:
    if (raw_syscall6(
            SYS_pwrite64, block_descriptor, (long)original,
            sizeof(original), (long)offset, 0, 0) != (long)sizeof(original))
        failures += record_failure(1, "BLOCK_DISCARD_RESTORE_FAIL\n");
    (void)raw_syscall6(
        SYS_close, block_descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int run_timestamp_ring(
        long sender, long receiver,
        const struct user_sockaddr_in *receiver_address,
        uint32_t setup_flags, uint8_t opcode) {
    static const uint8_t payload[] = {'t', 'i', 'm', 'e'};
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    struct io_uring_cqe *completion;
    uint64_t *extra;
    void *sq_ring;
    void *cq_ring;
    void *sqes;
    uint32_t timestamping =
        SOF_TIMESTAMPING_TX_SOFTWARE |
        SOF_TIMESTAMPING_SOFTWARE |
        SOF_TIMESTAMPING_OPT_ID |
        SOF_TIMESTAMPING_OPT_TSONLY;
    uint32_t stride = setup_flags & IORING_SETUP_SQE128 ? 128u : 64u;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    uint8_t receive_buffer[sizeof(payload)];
    long descriptor;
    int failures = 0;

    failures += record_failure(raw_syscall6(
        SYS_setsockopt, sender, SOL_SOCKET, SO_TIMESTAMPING,
        (long)&timestamping, sizeof(timestamping), 0) != 0,
        "TX_TIMESTAMP_OPTION_FAIL\n");
    if (failures) return failures;
    memset(&parameters, 0, sizeof(parameters));
    parameters.flags = setup_flags | IORING_SETUP_CQE32;
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (descriptor < 0) {
        print_text("TX_TIMESTAMP_SETUP_FAIL\n");
        return 1;
    }
    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        print_text("TX_TIMESTAMP_MMAP_FAIL\n");
        return 1;
    }

    sq_tail = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters.sq_off.tail);
    sq_mask = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters.sq_off.ring_mask);
    sq_array = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters.sq_off.array);
    cq_head = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters.cq_off.head);
    cq_tail = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters.cq_off.tail);
    memset(&request, 0, sizeof(request));
    request.opcode = opcode;
    request.descriptor = (int32_t)sender;
    request.offset = SOCKET_URING_OP_TX_TIMESTAMP;
    request.user_data = 0x545354414d50ull;
    memset(sqes, 0, stride);
    *(struct io_uring_sqe *)sqes = request;
    sq_array[*sq_tail & *sq_mask] = *sq_tail & *sq_mask;
    __atomic_store_n(sq_tail, *sq_tail + 1u, __ATOMIC_RELEASE);
    failures += record_failure(raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 0, 0, 0, 0) != 1,
        "TX_TIMESTAMP_SUBMIT_FAIL\n");
    failures += record_failure(*cq_head != *cq_tail,
                               "TX_TIMESTAMP_EARLY_CQE_FAIL\n");
    failures += record_failure(raw_syscall6(
        SYS_sendto, sender, (long)payload, sizeof(payload), 0,
        (long)receiver_address, sizeof(*receiver_address)) !=
        (long)sizeof(payload), "TX_TIMESTAMP_SEND_FAIL\n");
    if (!failures)
        failures += record_failure(raw_syscall6(
            SYS_io_uring_enter, descriptor, 0, 1,
            IORING_ENTER_GETEVENTS, 0, 0) < 0,
            "TX_TIMESTAMP_WAIT_FAIL\n");
    failures += record_failure(*cq_head == *cq_tail,
                               "TX_TIMESTAMP_CQE_MISSING\n");
    if (*cq_head != *cq_tail) {
        completion = (struct io_uring_cqe *)(void *)(
            (uint8_t *)cq_ring + parameters.cq_off.cqes +
            (uint64_t)(*cq_head & (parameters.cq_entries - 1u)) * 32u);
        extra = (uint64_t *)(void *)(completion + 1);
        failures += record_failure(
            completion->user_data != request.user_data ||
            completion->result < 0 ||
            !(completion->flags & IORING_CQE_F_MORE),
            "TX_TIMESTAMP_CQE_VALUE_FAIL\n");
        failures += record_failure(
            !extra[0] || extra[1] >= 1000000000u,
            "TX_TIMESTAMP_TIME_FAIL\n");
        __atomic_store_n(cq_head, *cq_head + 1u, __ATOMIC_RELEASE);
    }
    failures += record_failure(raw_syscall6(
        SYS_read, receiver, (long)receive_buffer,
        sizeof(receive_buffer), 0, 0, 0) != (long)sizeof(payload),
        "TX_TIMESTAMP_RECEIVE_FAIL\n");

    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int32_t sockets[2] = {-1, -1};
    struct user_sockaddr_in queue_address;
    long queue_receiver = -1;
    long queue_sender = -1;
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
    memset(&queue_address, 0, sizeof(queue_address));
    queue_address.family = AF_INET;
    queue_address.port = 0xc29bu;
    queue_address.address = 0x0100007fu;
    if (!failures) {
        queue_receiver = raw_syscall6(
            SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
        queue_sender = raw_syscall6(
            SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
        failures += record_failure(
            queue_receiver < 0 || queue_sender < 0,
            "QUEUE_SOCKET_CREATE_FAIL\n");
    }
    if (!failures)
        failures += record_failure(
            bring_loopback_up(queue_receiver),
            "LOOPBACK_ENABLE_FAIL\n");
    if (!failures)
        failures += record_failure(raw_syscall6(
            SYS_bind, queue_receiver, (long)&queue_address,
            sizeof(queue_address), 0, 0, 0) != 0,
            "QUEUE_SOCKET_BIND_FAIL\n");
    if (!failures)
        failures += run_ring(
            socket_descriptor, queue_receiver, queue_sender,
            &queue_address, 0u, IORING_OP_URING_CMD);
    if (!failures)
        failures += run_ring(
            socket_descriptor, queue_receiver, queue_sender,
            &queue_address, IORING_SETUP_SQE128,
            IORING_OP_URING_CMD128);
    if (!failures)
        failures += run_timestamp_ring(
            queue_sender, queue_receiver, &queue_address,
            0u, IORING_OP_URING_CMD);
    if (!failures)
        failures += run_timestamp_ring(
            queue_sender, queue_receiver, &queue_address,
            IORING_SETUP_SQE128, IORING_OP_URING_CMD128);
    if (!failures)
        failures += run_null_ring(0u, IORING_OP_URING_CMD);
    if (!failures)
        failures += run_null_ring(
            IORING_SETUP_SQE128, IORING_OP_URING_CMD128);
    if (!failures)
        failures += run_block_discard_ring(
            0u, IORING_OP_URING_CMD);
    if (!failures)
        failures += run_block_discard_ring(
            IORING_SETUP_SQE128, IORING_OP_URING_CMD128);
    if (socket_descriptor >= 0)
        (void)raw_syscall6(SYS_close, socket_descriptor, 0, 0, 0, 0, 0);
    if (sockets[1] >= 0)
        (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
    if (queue_receiver >= 0)
        (void)raw_syscall6(SYS_close, queue_receiver, 0, 0, 0, 0, 0);
    if (queue_sender >= 0)
        (void)raw_syscall6(SYS_close, queue_sender, 0, 0, 0, 0, 0);
    print_text(failures ? "io-uring-uring-cmd: FAIL\n" :
                          "io-uring-uring-cmd: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
