/* SPDX-License-Identifier: MPL-2.0 */
/* Linux BSG SCSI io_uring URING_CMD ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_openat 257
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#define SYS_openat 56
#else
#error "io_uring_bsg_uring_cmd_abi_probe requires a 64-bit Linux ABI"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define AT_FDCWD -100
#define O_RDWR 2u
#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define ENOENT 2
#define EINVAL 22
#define EOPNOTSUPP 95

#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_SETUP_SQE128 (1u << 10)
#define IORING_SETUP_CQE32 (1u << 11)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_BUFFERS 0u
#define IORING_OP_URING_CMD 46u
#define IORING_URING_CMD_FIXED (1u << 0)
#define IOSQE_ASYNC (1u << 4)

struct user_iovec {
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

struct bsg_uring_cmd {
    uint64_t request;
    uint32_t request_length;
    uint32_t protocol;
    uint32_t subprotocol;
    uint32_t maximum_response_length;
    uint64_t response;
    uint64_t data_out;
    uint32_t data_out_length;
    uint32_t data_out_vector_count;
    uint64_t data_in;
    uint32_t data_in_length;
    uint32_t data_in_vector_count;
    uint32_t timeout_milliseconds;
    uint8_t reserved[12];
};

struct io_uring_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
    uint64_t extra1;
    uint64_t extra2;
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

struct ring {
    long descriptor;
    struct io_uring_params parameters;
    void *sq_ring;
    void *cq_ring;
    void *sqes;
    uint32_t sqe_stride;
    uint32_t cqe_stride;
};

static uint8_t inquiry_data[96] __attribute__((aligned(PAGE_SIZE)));
static uint8_t fixed_data[96] __attribute__((aligned(PAGE_SIZE)));
static uint8_t sense_data[96] __attribute__((aligned(PAGE_SIZE)));

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
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;

    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int record_failure(int failed, const char *label) {
    if (failed) print_text(label);
    return failed;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 :
        (void *)(uintptr_t)result;
}

static int ring_open(struct ring *ring, uint32_t flags) {
    memset(ring, 0, sizeof(*ring));
    ring->descriptor = -1;
    ring->parameters.flags = flags;
    ring->descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&ring->parameters, 0, 0, 0, 0);
    if (ring->descriptor < 0) return 1;
    ring->sq_ring = map_ring(ring->descriptor, IORING_OFF_SQ_RING);
    ring->cq_ring = map_ring(ring->descriptor, IORING_OFF_CQ_RING);
    ring->sqes = map_ring(ring->descriptor, IORING_OFF_SQES);
    ring->sqe_stride = flags & IORING_SETUP_SQE128 ? 128u : 64u;
    ring->cqe_stride = flags & IORING_SETUP_CQE32 ? 32u : 16u;
    return !ring->sq_ring || !ring->cq_ring || !ring->sqes;
}

static void ring_close(struct ring *ring) {
    if (ring->sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)ring->sqes, PAGE_SIZE, 0, 0, 0, 0);
    if (ring->cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)ring->cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (ring->sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)ring->sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (ring->descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, ring->descriptor, 0, 0, 0, 0, 0);
}

static int ring_submit(struct ring *ring, const uint8_t request[128],
                       struct io_uring_cqe *completion) {
    volatile uint32_t *sq_tail = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.tail);
    volatile uint32_t *sq_mask = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.ring_mask);
    volatile uint32_t *sq_array = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.array);
    volatile uint32_t *cq_head = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.head);
    volatile uint32_t *cq_tail = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.tail);
    uint32_t tail = *sq_tail;
    uint32_t index = tail & *sq_mask;
    struct io_uring_cqe *source;

    memset((uint8_t *)ring->sqes +
        (uint64_t)index * ring->sqe_stride, 0, ring->sqe_stride);
    memcpy((uint8_t *)ring->sqes +
        (uint64_t)index * ring->sqe_stride, request, ring->sqe_stride);
    sq_array[index] = index;
    __atomic_store_n(sq_tail, tail + 1u, __ATOMIC_RELEASE);
    if (raw_syscall6(
            SYS_io_uring_enter, ring->descriptor, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0) != 1)
        return 1;
    if (*cq_head == *cq_tail) return 1;
    index = *cq_head & (ring->parameters.cq_entries - 1u);
    source = (struct io_uring_cqe *)(void *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.cqes +
        (uint64_t)index * ring->cqe_stride);
    memset(completion, 0, sizeof(*completion));
    memcpy(completion, source, ring->cqe_stride);
    __atomic_store_n(cq_head, *cq_head + 1u, __ATOMIC_RELEASE);
    return 0;
}

static void prepare_request(
        uint8_t request[128], int32_t descriptor,
        const struct bsg_uring_cmd *command, uint64_t user_data,
        uint32_t command_flags, uint16_t buffer_index) {
    struct io_uring_sqe *sqe;

    memset(request, 0, 128u);
    sqe = (struct io_uring_sqe *)(void *)request;
    sqe->opcode = IORING_OP_URING_CMD;
    sqe->descriptor = descriptor;
    sqe->operation_flags = command_flags;
    sqe->user_data = user_data;
    sqe->buffer_index = buffer_index;
    memcpy(request + 48u, command, sizeof(*command));
}

static int submit_expect(struct ring *ring, uint8_t request[128],
                         int32_t expected, const char *label,
                         struct io_uring_cqe *completion) {
    if (ring_submit(ring, request, completion))
        return record_failure(1, "BSG_SUBMIT_FAIL\n");
    if (completion->result != expected) {
        print_text(label);
        print_text("BSG_RESULT actual=");
        print_number(completion->result);
        print_text(" expected=");
        print_number(expected);
        print_text("\n");
        return 1;
    }
    return 0;
}

static int inquiry_valid(const uint8_t *data) {
    int vendor_present = 0;

    if ((data[0] & 0x1fu) != 0u || data[4] < 31u) return 0;
    for (uint32_t index = 8u; index < 16u; ++index)
        vendor_present |= data[index] != 0u && data[index] != ' ';
    return vendor_present;
}

void _start(void) {
    static const char path[] = "/dev/bsg/0:0:0:0";
    static const uint8_t inquiry_cdb[6] = {0x12u, 0u, 0u, 0u, 96u, 0u};
    static const uint8_t invalid_cdb[6] = {0xffu, 0u, 0u, 0u, 0u, 0u};
    struct bsg_uring_cmd command;
    struct io_uring_cqe completion;
    struct user_iovec registration;
    struct ring ring;
    uint8_t request[128];
    long descriptor;
    int failures = 0;

    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path, O_RDWR, 0, 0, 0);
#ifdef BSG_EXPECT_DISABLED
    failures += record_failure(
        descriptor != -ENOENT, "BSG_DISABLED_VISIBILITY_FAIL\n");
    goto finish;
#else
    failures += record_failure(descriptor < 0, "BSG_OPEN_FAIL\n");
    if (failures) goto finish;

    memset(&command, 0, sizeof(command));
    command.request = (uint64_t)(uintptr_t)inquiry_cdb;
    command.request_length = sizeof(inquiry_cdb);
    command.maximum_response_length = sizeof(sense_data);
    command.response = (uint64_t)(uintptr_t)sense_data;
    command.data_in = (uint64_t)(uintptr_t)inquiry_data;
    command.data_in_length = sizeof(inquiry_data);
    command.timeout_milliseconds = 2000u;

    if (ring_open(&ring, 0u)) {
        failures += record_failure(1, "BSG_SMALL_RING_OPEN_FAIL\n");
        goto finish;
    }
    prepare_request(request, (int32_t)descriptor, &command, 1u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EOPNOTSUPP,
        "BSG_SQE128_REQUIRED_FAIL\n", &completion);
    ring_close(&ring);

    if (ring_open(&ring, IORING_SETUP_SQE128)) {
        failures += record_failure(1, "BSG_CQE_RING_OPEN_FAIL\n");
        goto finish;
    }
    prepare_request(request, (int32_t)descriptor, &command, 2u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EOPNOTSUPP,
        "BSG_CQE32_REQUIRED_FAIL\n", &completion);
    ring_close(&ring);

    if (ring_open(&ring, IORING_SETUP_SQE128 | IORING_SETUP_CQE32)) {
        failures += record_failure(1, "BSG_FULL_RING_OPEN_FAIL\n");
        goto finish;
    }

    command.protocol = 1u;
    prepare_request(request, (int32_t)descriptor, &command, 3u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EINVAL, "BSG_PROTOCOL_FAIL\n", &completion);
    command.protocol = 0u;

    command.request = 0u;
    prepare_request(request, (int32_t)descriptor, &command, 4u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EINVAL, "BSG_REQUEST_FAIL\n", &completion);
    command.request = (uint64_t)(uintptr_t)inquiry_cdb;

    command.data_out_length = 1u;
    command.data_out = (uint64_t)(uintptr_t)inquiry_data;
    prepare_request(request, (int32_t)descriptor, &command, 5u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EOPNOTSUPP,
        "BSG_BIDIRECTIONAL_FAIL\n", &completion);
    command.data_out_length = 0u;
    command.data_out = 0u;

    command.data_in_vector_count = 1u;
    prepare_request(request, (int32_t)descriptor, &command, 6u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EOPNOTSUPP,
        "BSG_VECTOR_REJECTION_FAIL\n", &completion);
    command.data_in_vector_count = 0u;

    command.request_length = 33u;
    prepare_request(request, (int32_t)descriptor, &command, 7u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EINVAL,
        "BSG_CDB_LENGTH_FAIL\n", &completion);
    command.request_length = sizeof(inquiry_cdb);

    memset(inquiry_data, 0, sizeof(inquiry_data));
    memset(sense_data, 0, sizeof(sense_data));
    prepare_request(request, (int32_t)descriptor, &command, 8u, 0u, 0u);
    ((struct io_uring_sqe *)(void *)request)->flags = IOSQE_ASYNC;
    failures += submit_expect(
        &ring, request, 0, "BSG_INQUIRY_STATUS_FAIL\n", &completion);
    failures += record_failure(
        completion.user_data != 8u || completion.flags != 0u ||
        completion.extra1 != 0u || completion.extra2 != 0u,
        "BSG_INQUIRY_CQE32_FAIL\n");
    failures += record_failure(
        !inquiry_valid(inquiry_data), "BSG_INQUIRY_DATA_FAIL\n");

    registration.base = (uint64_t)(uintptr_t)fixed_data;
    registration.length = sizeof(fixed_data);
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_BUFFERS, (long)&registration, 1u, 0, 0) != 0,
        "BSG_FIXED_REGISTER_FAIL\n");
    memset(fixed_data, 0, sizeof(fixed_data));
    command.data_in = (uint64_t)(uintptr_t)fixed_data;
    prepare_request(request, (int32_t)descriptor, &command, 9u,
                    IORING_URING_CMD_FIXED, 0u);
    failures += submit_expect(
        &ring, request, 0, "BSG_FIXED_STATUS_FAIL\n", &completion);
    failures += record_failure(
        completion.extra1 != 0u || completion.extra2 != 0u,
        "BSG_FIXED_CQE32_FAIL\n");
    failures += record_failure(
        !inquiry_valid(fixed_data), "BSG_FIXED_DATA_FAIL\n");

    memset(sense_data, 0, sizeof(sense_data));
    memset(&command, 0, sizeof(command));
    command.request = (uint64_t)(uintptr_t)invalid_cdb;
    command.request_length = sizeof(invalid_cdb);
    command.maximum_response_length = sizeof(sense_data);
    command.response = (uint64_t)(uintptr_t)sense_data;
    command.timeout_milliseconds = 2000u;
    prepare_request(request, (int32_t)descriptor, &command, 10u, 0u, 0u);
    failures += submit_expect(
        &ring, request, 0, "BSG_SENSE_STATUS_FAIL\n", &completion);
    failures += record_failure(
        (completion.extra1 & 0xffu) != 0x02u ||
        ((completion.extra1 >> 8u) & 0xffu) != 0x08u ||
        ((completion.extra1 >> 16u) & 0xffu) != 0u ||
        ((completion.extra1 >> 24u) & 0xffu) == 0u ||
        (completion.extra1 >> 32u) != 0u || completion.extra2 != 0u,
        "BSG_SENSE_CQE32_FAIL\n");
    failures += record_failure(
        !sense_data[0], "BSG_SENSE_DATA_FAIL\n");
    ring_close(&ring);
#endif

finish:
    if (descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, descriptor, 0, 0, 0, 0, 0);
    print_text(failures ? "io-uring-bsg-cmd: FAIL\n" :
                          "io-uring-bsg-cmd: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
