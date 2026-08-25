/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring fixed-buffer lifetime ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_ioctl 16
#define SYS_sched_yield 24
#define SYS_exit 60
#define SYS_socketpair 53
#define SYS_mount 165
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_mknodat 259
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_ioctl 29
#define SYS_mknodat 33
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_openat 56
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_sched_yield 124
#define SYS_socketpair 199
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_fixed_buffer_pin_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define MAP_PRIVATE 2u
#define MAP_ANONYMOUS 0x20u
#define PAGE_SIZE 4096u
#define FIXED_BUFFER_PAGES 66u
#define FIXED_BUFFER_SIZE (FIXED_BUFFER_PAGES * PAGE_SIZE)
#define FIRST_OFFSET (64u * PAGE_SIZE - 8u)
#define SECOND_OFFSET (65u * PAGE_SIZE + 128u)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_BUFFERS 0u
#define IORING_UNREGISTER_BUFFERS 1u
#define IORING_OP_READ_FIXED 4u
#define IORING_OP_WRITE_FIXED 5u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define AF_UNIX 1
#define SOCK_STREAM 1
#define AT_FDCWD -100
#define O_RDWR 2
#define O_NOCTTY 0x100
#define S_IFCHR 0020000
#define TIOCGPTN 0x80045430u
#define TIOCSPTLCK 0x40045431u

struct linux_iovec {
    uint64_t base;
    uint64_t length;
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

static void bytes_zero(void *destination, uint32_t size) {
    uint8_t *bytes = destination;
    for (uint32_t index = 0; index < size; ++index) bytes[index] = 0;
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0u;
    while (text[length]) ++length;
    return length;
}

static int require_result(long actual, long expected, const char *failure) {
    if (actual == expected) return 0;
    (void)raw_syscall6(
        SYS_write, 1, (long)failure, text_length(failure), 0, 0, 0);
    return 1;
}

static int result_is_error(long result) {
    return result < 0 && result >= -4095;
}

static void append_decimal(char *text, uint32_t *length, uint32_t value) {
    char digits[10];
    uint32_t count = 0u;

    do {
        digits[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    while (count) text[(*length)++] = digits[--count];
    text[*length] = '\0';
}

#ifdef IO_URING_FIXED_BUFFER_TTY_PROBE
static void report_long(const char *prefix, long value) {
    char message[96];
    uint32_t length = 0u;
    uint32_t magnitude;

    while (prefix[length] && length + 16u < sizeof(message)) {
        message[length] = prefix[length];
        ++length;
    }
    if (value < 0) {
        message[length++] = '-';
        magnitude = (uint32_t)(-(value + 1)) + 1u;
    } else {
        magnitude = (uint32_t)value;
    }
    append_decimal(message, &length, magnitude);
    message[length++] = '\n';
    (void)raw_syscall6(
        SYS_write, 1, (long)message, length, 0, 0, 0);
}
#endif

static long open_character_device(const char *path, uint32_t device,
                                  uint32_t flags) {
    static const char dev[] = "/dev";
    long descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path, flags, 0, 0, 0);

    if (!result_is_error(descriptor)) return descriptor;
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)dev, 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mknodat, AT_FDCWD, (long)path,
        S_IFCHR | 0666, device, 0, 0);
    return raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path, flags, 0, 0, 0);
}

static long open_pty_pair(int32_t descriptors[2]) {
    static const char dev[] = "/dev";
    static const char pts[] = "/dev/pts";
    static const char ptmx[] = "/dev/ptmx";
    static const char devpts[] = "devpts";
    char slave_path[32] = "/dev/pts/";
    uint32_t path_length = 9u;
    uint32_t number = 0u;
    int32_t unlocked = 0;
    long master;
    long slave;

    master = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)ptmx,
        O_RDWR | O_NOCTTY, 0, 0, 0);
    if (result_is_error(master)) {
        (void)raw_syscall6(
            SYS_mkdirat, AT_FDCWD, (long)dev, 0755, 0, 0, 0);
        (void)raw_syscall6(
            SYS_mkdirat, AT_FDCWD, (long)pts, 0755, 0, 0, 0);
        (void)raw_syscall6(
            SYS_mknodat, AT_FDCWD, (long)ptmx,
            S_IFCHR | 0666, 0x502, 0, 0);
        (void)raw_syscall6(
            SYS_mount, (long)devpts, (long)pts,
            (long)devpts, 0, 0, 0);
        master = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)ptmx,
            O_RDWR | O_NOCTTY, 0, 0, 0);
    }
    if (result_is_error(master)) return master;
    if (raw_syscall6(
            SYS_ioctl, master, TIOCSPTLCK,
            (long)&unlocked, 0, 0, 0) != 0 ||
        raw_syscall6(
            SYS_ioctl, master, TIOCGPTN,
            (long)&number, 0, 0, 0) != 0) {
        (void)raw_syscall6(SYS_close, master, 0, 0, 0, 0, 0);
        return -1;
    }
    append_decimal(slave_path, &path_length, number);
    slave = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)slave_path,
        O_RDWR | O_NOCTTY, 0, 0, 0);
    if (result_is_error(slave)) {
        (void)raw_syscall6(SYS_close, master, 0, 0, 0, 0, 0);
        return slave;
    }
    descriptors[0] = (int32_t)master;
    descriptors[1] = (int32_t)slave;
    return 0;
}

static int bytes_equal(const void *left, const void *right,
                       uint32_t length) {
    const uint8_t *a = left;
    const uint8_t *b = right;
    for (uint32_t index = 0; index < length; ++index)
        if (a[index] != b[index]) return 0;
    return 1;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ?
        0 : (void *)(uintptr_t)result;
}

static int submit(
        long ring, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        uint8_t opcode, int32_t descriptor, uint64_t address,
        uint32_t length, uint64_t user_data) {
    volatile uint32_t *sq_head = (volatile uint32_t *)(
        (uint8_t *)sq_ring + parameters->sq_off.head);
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(void *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t sq_index = *sq_tail & *sq_mask;
    uint32_t cq_index;
    long entered;

    bytes_zero(&sqes[sq_index], sizeof(sqes[sq_index]));
    sqes[sq_index].opcode = opcode;
    sqes[sq_index].descriptor = descriptor;
    sqes[sq_index].offset = UINT64_MAX;
    sqes[sq_index].address = address;
    sqes[sq_index].length = length;
    sqes[sq_index].user_data = user_data;
    sqes[sq_index].buffer_index = 0u;
    sq_array[sq_index] = sq_index;
    __atomic_store_n(sq_tail, *sq_tail + 1u, __ATOMIC_RELEASE);
    entered = raw_syscall6(
        SYS_io_uring_enter, ring, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0);
    if (entered != 1 || *sq_head != *sq_tail || *cq_head == *cq_tail)
        return -1;
    cq_index = *cq_head & *cq_mask;
    if (cqes[cq_index].user_data != user_data) return -1;
    entered = cqes[cq_index].result;
    __atomic_store_n(cq_head, *cq_head + 1u, __ATOMIC_RELEASE);
    return (int)entered;
}

static int run_probe(void) {
    static const char first[] = "registered-before-unmap\n";
    static const char second[] = "read-after-unmap\n";
    struct io_uring_params parameters;
    struct linux_iovec buffer;
    int32_t input_pipe[2] = {-1, -1};
    int32_t output_pipe[2] = {-1, -1};
    int32_t sockets[2] = {-1, -1};
    int32_t pty[2] = {-1, -1};
    int32_t null_descriptor = -1;
    int32_t zero_descriptor = -1;
#ifdef IO_URING_FIXED_BUFFER_TTY_PROBE
    int32_t tty_descriptor = -1;
#endif
    uint8_t observed[64];
    struct io_uring_sqe *sqes = 0;
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *page = 0;
    long ring;
    long result;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 4, (long)&parameters, 0, 0, 0, 0);
    if (ring < 0) return 1;
    sq_ring = map_ring(ring, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring, IORING_OFF_CQ_RING);
    sqes = map_ring(ring, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        failures = 1;
        goto cleanup;
    }
    page = (void *)(uintptr_t)raw_syscall6(
        SYS_mmap, 0, FIXED_BUFFER_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)(uintptr_t)page < 0 &&
        (long)(uintptr_t)page >= -4095) {
        page = 0;
        failures = 1;
        goto cleanup;
    }
    bytes_zero(page, FIXED_BUFFER_SIZE);
    for (uint32_t index = 0; index < sizeof(first); ++index)
        ((uint8_t *)page)[FIRST_OFFSET + index] = (uint8_t)first[index];
    buffer.base = (uint64_t)(uintptr_t)page;
    buffer.length = FIXED_BUFFER_SIZE;
    if (raw_syscall6(
            SYS_io_uring_register, ring, IORING_REGISTER_BUFFERS,
            (long)&buffer, 1, 0, 0) != 0) {
        failures = 1;
        goto cleanup;
    }
    if (raw_syscall6(
            SYS_munmap, (long)page, FIXED_BUFFER_SIZE, 0, 0, 0, 0) != 0) {
        failures = 1;
        goto cleanup;
    }
    page = 0;
    if (raw_syscall6(
            SYS_pipe2, (long)input_pipe, 0, 0, 0, 0, 0) != 0 ||
        raw_syscall6(
            SYS_pipe2, (long)output_pipe, 0, 0, 0, 0, 0) != 0) {
        failures = 1;
        goto cleanup;
    }

    failures += submit(
        ring, &parameters, sq_ring, cq_ring, sqes,
        IORING_OP_WRITE_FIXED, output_pipe[1],
        buffer.base + FIRST_OFFSET, sizeof(first), 0x5752495445ull) !=
        (int)sizeof(first);
    bytes_zero(observed, sizeof(observed));
    failures += raw_syscall6(
        SYS_read, output_pipe[0], (long)observed,
        sizeof(first), 0, 0, 0) != (long)sizeof(first);
    failures += !bytes_equal(observed, first, sizeof(first));

    failures += raw_syscall6(
        SYS_write, input_pipe[1], (long)second,
        sizeof(second), 0, 0, 0) != (long)sizeof(second);
    failures += submit(
        ring, &parameters, sq_ring, cq_ring, sqes,
        IORING_OP_READ_FIXED, input_pipe[0],
        buffer.base + SECOND_OFFSET, sizeof(second), 0x52454144ull) !=
        (int)sizeof(second);
    failures += submit(
        ring, &parameters, sq_ring, cq_ring, sqes,
        IORING_OP_WRITE_FIXED, output_pipe[1],
        buffer.base + SECOND_OFFSET, sizeof(second), 0x564552494659ull) !=
        (int)sizeof(second);
    bytes_zero(observed, sizeof(observed));
    failures += raw_syscall6(
        SYS_read, output_pipe[0], (long)observed,
        sizeof(second), 0, 0, 0) != (long)sizeof(second);
    failures += !bytes_equal(observed, second, sizeof(second));

    result = raw_syscall6(
        SYS_socketpair, AF_UNIX, SOCK_STREAM, 0,
        (long)sockets, 0, 0);
    failures += require_result(
        result, 0, "IO_URING_FIXED_BUFFER_PIN_SOCKETPAIR_FAIL\n");
    if (!failures) {
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_WRITE_FIXED, sockets[0],
            buffer.base + FIRST_OFFSET, sizeof(first),
            0x534f434b57524954ull);
        failures += require_result(
            result, sizeof(first),
            "IO_URING_FIXED_BUFFER_PIN_SOCKET_FIXED_WRITE_FAIL\n");
        bytes_zero(observed, sizeof(observed));
        result = raw_syscall6(
            SYS_read, sockets[1], (long)observed,
            sizeof(first), 0, 0, 0);
        failures += require_result(
            result, sizeof(first),
            "IO_URING_FIXED_BUFFER_PIN_SOCKET_READ_FAIL\n");
        if (!bytes_equal(observed, first, sizeof(first))) {
            static const char mismatch[] =
                "IO_URING_FIXED_BUFFER_PIN_SOCKET_WRITE_DATA_FAIL\n";
            (void)raw_syscall6(
                SYS_write, 1, (long)mismatch, text_length(mismatch),
                0, 0, 0);
            ++failures;
        }
        result = raw_syscall6(
            SYS_write, sockets[1], (long)second,
            sizeof(second), 0, 0, 0);
        failures += require_result(
            result, sizeof(second),
            "IO_URING_FIXED_BUFFER_PIN_SOCKET_WRITE_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_READ_FIXED, sockets[0],
            buffer.base + SECOND_OFFSET, sizeof(second),
            0x534f434b52454144ull);
        failures += require_result(
            result, sizeof(second),
            "IO_URING_FIXED_BUFFER_PIN_SOCKET_FIXED_READ_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_WRITE_FIXED, sockets[0],
            buffer.base + SECOND_OFFSET, sizeof(second),
            0x534f434b56455249ull);
        failures += require_result(
            result, sizeof(second),
            "IO_URING_FIXED_BUFFER_PIN_SOCKET_VERIFY_WRITE_FAIL\n");
        bytes_zero(observed, sizeof(observed));
        result = raw_syscall6(
            SYS_read, sockets[1], (long)observed,
            sizeof(second), 0, 0, 0);
        failures += require_result(
            result, sizeof(second),
            "IO_URING_FIXED_BUFFER_PIN_SOCKET_VERIFY_READ_FAIL\n");
        if (!bytes_equal(observed, second, sizeof(second))) {
            static const char mismatch[] =
                "IO_URING_FIXED_BUFFER_PIN_SOCKET_READ_DATA_FAIL\n";
            (void)raw_syscall6(
                SYS_write, 1, (long)mismatch, text_length(mismatch),
                0, 0, 0);
            ++failures;
        }
    }
    result = open_character_device("/dev/null", 0x103u, O_RDWR);
    if (!result_is_error(result)) null_descriptor = (int32_t)result;
    failures += require_result(
        result_is_error(result), 0,
        "IO_URING_FIXED_BUFFER_PIN_NULL_OPEN_FAIL\n");
    result = open_character_device("/dev/zero", 0x105u, O_RDWR);
    if (!result_is_error(result)) zero_descriptor = (int32_t)result;
    failures += require_result(
        result_is_error(result), 0,
        "IO_URING_FIXED_BUFFER_PIN_ZERO_OPEN_FAIL\n");
    if (!failures) {
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_WRITE_FIXED, null_descriptor,
            buffer.base + FIRST_OFFSET, sizeof(first),
            0x4e554c4c57524954ull);
        failures += require_result(
            result, sizeof(first),
            "IO_URING_FIXED_BUFFER_PIN_NULL_WRITE_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_READ_FIXED, null_descriptor,
            buffer.base + SECOND_OFFSET, sizeof(second),
            0x4e554c4c52454144ull);
        failures += require_result(
            result, 0,
            "IO_URING_FIXED_BUFFER_PIN_NULL_READ_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_READ_FIXED, zero_descriptor,
            buffer.base + SECOND_OFFSET, sizeof(observed),
            0x5a45524f52454144ull);
        failures += require_result(
            result, sizeof(observed),
            "IO_URING_FIXED_BUFFER_PIN_ZERO_READ_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_WRITE_FIXED, output_pipe[1],
            buffer.base + SECOND_OFFSET, sizeof(observed),
            0x5a45524f56455249ull);
        failures += require_result(
            result, sizeof(observed),
            "IO_URING_FIXED_BUFFER_PIN_ZERO_VERIFY_WRITE_FAIL\n");
        for (uint32_t index = 0; index < sizeof(observed); ++index)
            observed[index] = 0xffu;
        result = raw_syscall6(
            SYS_read, output_pipe[0], (long)observed,
            sizeof(observed), 0, 0, 0);
        failures += require_result(
            result, sizeof(observed),
            "IO_URING_FIXED_BUFFER_PIN_ZERO_VERIFY_READ_FAIL\n");
        for (uint32_t index = 0; index < sizeof(observed); ++index) {
            if (!observed[index]) continue;
            {
                static const char mismatch[] =
                    "IO_URING_FIXED_BUFFER_PIN_ZERO_DATA_FAIL\n";
                (void)raw_syscall6(
                    SYS_write, 1, (long)mismatch,
                    text_length(mismatch), 0, 0, 0);
            }
            ++failures;
            break;
        }
    }
    result = open_pty_pair(pty);
    failures += require_result(
        result, 0, "IO_URING_FIXED_BUFFER_PIN_PTY_OPEN_FAIL\n");
    if (!failures) {
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_WRITE_FIXED, pty[0],
            buffer.base + FIRST_OFFSET, sizeof(first) - 1u,
            0x5054595752495445ull);
        failures += require_result(
            result, sizeof(first) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_PTY_FIXED_WRITE_FAIL\n");
        bytes_zero(observed, sizeof(observed));
        result = raw_syscall6(
            SYS_read, pty[1], (long)observed,
            sizeof(first) - 1u, 0, 0, 0);
        failures += require_result(
            result, sizeof(first) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_PTY_READ_FAIL\n");
        if (!bytes_equal(observed, first, sizeof(first) - 1u)) {
            static const char mismatch[] =
                "IO_URING_FIXED_BUFFER_PIN_PTY_WRITE_DATA_FAIL\n";
            (void)raw_syscall6(
                SYS_write, 1, (long)mismatch, text_length(mismatch),
                0, 0, 0);
            ++failures;
        }
        result = raw_syscall6(
            SYS_write, pty[0], (long)second,
            sizeof(second) - 1u, 0, 0, 0);
        failures += require_result(
            result, sizeof(second) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_PTY_WRITE_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_READ_FIXED, pty[1],
            buffer.base + SECOND_OFFSET, sizeof(second) - 1u,
            0x50545952454144ull);
        failures += require_result(
            result, sizeof(second) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_PTY_FIXED_READ_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_WRITE_FIXED, output_pipe[1],
            buffer.base + SECOND_OFFSET, sizeof(second) - 1u,
            0x5054595645524946ull);
        failures += require_result(
            result, sizeof(second) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_PTY_VERIFY_WRITE_FAIL\n");
        bytes_zero(observed, sizeof(observed));
        result = raw_syscall6(
            SYS_read, output_pipe[0], (long)observed,
            sizeof(second) - 1u, 0, 0, 0);
        failures += require_result(
            result, sizeof(second) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_PTY_VERIFY_READ_FAIL\n");
        if (!bytes_equal(observed, second, sizeof(second) - 1u)) {
            static const char mismatch[] =
                "IO_URING_FIXED_BUFFER_PIN_PTY_READ_DATA_FAIL\n";
            (void)raw_syscall6(
                SYS_write, 1, (long)mismatch, text_length(mismatch),
                0, 0, 0);
            ++failures;
        }
    }
#ifdef IO_URING_FIXED_BUFFER_TTY_PROBE
    if (!failures) {
        static const char ready[] =
            "IO_URING_FIXED_BUFFER_PIN_TTY_READY\n";
        static const char expected[] = "tty\n";
#if defined(__aarch64__)
        static const char tty_path[] = "/dev/ttyAMA0";
        const uint32_t tty_device = 0xcc40u;
#else
        static const char tty_path[] = "/dev/ttyS0";
        const uint32_t tty_device = 0x440u;
#endif

        result = open_character_device(
            tty_path, tty_device, O_RDWR | O_NOCTTY);
        if (!result_is_error(result)) tty_descriptor = (int32_t)result;
        failures += require_result(
            result_is_error(result), 0,
            "IO_URING_FIXED_BUFFER_PIN_TTY_OPEN_FAIL\n");
        if (failures) goto tty_done;

        (void)raw_syscall6(
            SYS_write, 1, (long)ready, text_length(ready), 0, 0, 0);
        for (uint32_t attempt = 0u; attempt < 50000u; ++attempt)
            (void)raw_syscall6(
                SYS_sched_yield, 0, 0, 0, 0, 0, 0);
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_READ_FIXED, tty_descriptor,
            buffer.base + SECOND_OFFSET, sizeof(expected) - 1u,
            0x54545952454144ull);
        if (result != (long)(sizeof(expected) - 1u))
            report_long("IO_URING_FIXED_BUFFER_PIN_TTY_RESULT=", result);
        failures += require_result(
            result, sizeof(expected) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_TTY_READ_FAIL\n");
        result = submit(
            ring, &parameters, sq_ring, cq_ring, sqes,
            IORING_OP_WRITE_FIXED, output_pipe[1],
            buffer.base + SECOND_OFFSET, sizeof(expected) - 1u,
            0x5454595645524946ull);
        failures += require_result(
            result, sizeof(expected) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_TTY_VERIFY_WRITE_FAIL\n");
        bytes_zero(observed, sizeof(observed));
        result = raw_syscall6(
            SYS_read, output_pipe[0], (long)observed,
            sizeof(expected) - 1u, 0, 0, 0);
        failures += require_result(
            result, sizeof(expected) - 1u,
            "IO_URING_FIXED_BUFFER_PIN_TTY_VERIFY_READ_FAIL\n");
        if (!bytes_equal(observed, expected, sizeof(expected) - 1u)) {
            static const char mismatch[] =
                "IO_URING_FIXED_BUFFER_PIN_TTY_DATA_FAIL\n";
            (void)raw_syscall6(
                SYS_write, 1, (long)mismatch, text_length(mismatch),
                0, 0, 0);
            ++failures;
        }
tty_done:
        if (tty_descriptor >= 0) {
            (void)raw_syscall6(
                SYS_close, tty_descriptor, 0, 0, 0, 0, 0);
            tty_descriptor = -1;
        }
    }
#endif
    failures += raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_BUFFERS,
        0, 0, 0, 0) != 0;

cleanup:
    if (input_pipe[0] >= 0)
        (void)raw_syscall6(SYS_close, input_pipe[0], 0, 0, 0, 0, 0);
    if (input_pipe[1] >= 0)
        (void)raw_syscall6(SYS_close, input_pipe[1], 0, 0, 0, 0, 0);
    if (output_pipe[0] >= 0)
        (void)raw_syscall6(SYS_close, output_pipe[0], 0, 0, 0, 0, 0);
    if (output_pipe[1] >= 0)
        (void)raw_syscall6(SYS_close, output_pipe[1], 0, 0, 0, 0, 0);
    if (sockets[0] >= 0)
        (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
    if (sockets[1] >= 0)
        (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
    if (pty[0] >= 0)
        (void)raw_syscall6(SYS_close, pty[0], 0, 0, 0, 0, 0);
    if (pty[1] >= 0)
        (void)raw_syscall6(SYS_close, pty[1], 0, 0, 0, 0, 0);
    if (null_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, null_descriptor, 0, 0, 0, 0, 0);
    if (zero_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, zero_descriptor, 0, 0, 0, 0, 0);
#ifdef IO_URING_FIXED_BUFFER_TTY_PROBE
    if (tty_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, tty_descriptor, 0, 0, 0, 0, 0);
#endif
    if (page)
        (void)raw_syscall6(
            SYS_munmap, (long)page, FIXED_BUFFER_SIZE, 0, 0, 0, 0);
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

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    static const char pass[] =
        "IO_URING_FIXED_BUFFER_PIN_ABI_PROBE_PASS\n";
    static const char fail[] =
        "IO_URING_FIXED_BUFFER_PIN_ABI_PROBE_FAIL\n";
    int failures = run_probe();
    const char *result = failures ? fail : pass;

    (void)raw_syscall6(
        SYS_write, 1, (long)result, text_length(result), 0, 0, 0);
#ifdef IO_URING_FIXED_BUFFER_TTY_PROBE
    for (uint32_t attempt = 0u; attempt < 50000u; ++attempt)
        (void)raw_syscall6(
            SYS_sched_yield, 0, 0, 0, 0, 0, 0);
#endif
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
