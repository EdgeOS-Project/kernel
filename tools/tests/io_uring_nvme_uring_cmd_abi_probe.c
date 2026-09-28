/* SPDX-License-Identifier: MPL-2.0 */
/* Linux NVMe io_uring URING_CMD ABI probe. */

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
#error "io_uring_nvme_uring_cmd_abi_probe requires a 64-bit Linux ABI"
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
#define EINVAL 22
#define ENOTTY 25
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

#define NVME_URING_CMD_IO 0xc0484e80u
#define NVME_URING_CMD_IO_VEC 0xc0484e81u
#define NVME_URING_CMD_ADMIN 0xc0484e82u
#define NVME_URING_CMD_ADMIN_VEC 0xc0484e83u
#define NVME_ADMIN_IDENTIFY 0x06u
#define NVME_NVM_READ 0x02u

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

struct nvme_uring_cmd {
    uint8_t opcode;
    uint8_t flags;
    uint16_t reserved1;
    uint32_t namespace_id;
    uint32_t command_dword2;
    uint32_t command_dword3;
    uint64_t metadata;
    uint64_t address;
    uint32_t metadata_length;
    uint32_t data_length;
    uint32_t command_dword10;
    uint32_t command_dword11;
    uint32_t command_dword12;
    uint32_t command_dword13;
    uint32_t command_dword14;
    uint32_t command_dword15;
    uint32_t timeout_milliseconds;
    uint32_t reserved2;
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

static uint8_t identify_scalar[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t identify_vector[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t identify_fixed[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t namespace_data[512]
    __attribute__((aligned(PAGE_SIZE)));

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
        uint8_t request[128], int32_t descriptor, uint32_t operation,
        const struct nvme_uring_cmd *command, uint64_t user_data,
        uint32_t command_flags, uint16_t buffer_index) {
    struct io_uring_sqe *sqe;

    memset(request, 0, 128u);
    sqe = (struct io_uring_sqe *)(void *)request;
    sqe->opcode = IORING_OP_URING_CMD;
    sqe->descriptor = descriptor;
    sqe->offset = operation;
    sqe->operation_flags = command_flags;
    sqe->user_data = user_data;
    sqe->buffer_index = buffer_index;
    memcpy(request + 48u, command, sizeof(*command));
}

static int buffer_has_data(const uint8_t *buffer, uint32_t length) {
    for (uint32_t index = 0; index < length; ++index) {
        if (buffer[index]) return 1;
    }
    return 0;
}

static int submit_expect(struct ring *ring, uint8_t request[128],
                         int32_t expected, const char *label,
                         struct io_uring_cqe *completion) {
    if (ring_submit(ring, request, completion))
        return record_failure(1, "NVME_SUBMIT_FAIL\n");
    return record_failure(completion->result != expected, label);
}

void _start(void) {
    static const char controller_path[] = "/dev/nvme0";
    static const char namespace_path[] = "/dev/ng0n1";
    struct nvme_uring_cmd command;
    struct io_uring_cqe completion;
    struct user_iovec vectors[2];
    struct user_iovec registration;
    struct ring ring;
    uint8_t request[128];
    long controller;
    long namespace_descriptor;
    int failures = 0;

    controller = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)controller_path, O_RDWR, 0, 0, 0);
    namespace_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)namespace_path, O_RDWR, 0, 0, 0);
    failures += record_failure(
        controller < 0, "NVME_CONTROLLER_OPEN_FAIL\n");
    failures += record_failure(
        namespace_descriptor < 0, "NVME_NAMESPACE_OPEN_FAIL\n");
    if (failures) goto finish;

    memset(&command, 0, sizeof(command));
    command.opcode = NVME_ADMIN_IDENTIFY;
    command.address = (uint64_t)(uintptr_t)identify_scalar;
    command.data_length = sizeof(identify_scalar);
    command.command_dword10 = 1u;
    command.timeout_milliseconds = 2000u;

    if (ring_open(&ring, 0u)) {
        failures += record_failure(1, "NVME_SMALL_RING_OPEN_FAIL\n");
        goto finish;
    }
    prepare_request(request, (int32_t)controller,
                    NVME_URING_CMD_ADMIN, &command, 1u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EOPNOTSUPP,
        "NVME_SQE128_REQUIRED_FAIL\n", &completion);
    ring_close(&ring);

    if (ring_open(&ring, IORING_SETUP_SQE128)) {
        failures += record_failure(1, "NVME_CQE_RING_OPEN_FAIL\n");
        goto finish;
    }
    prepare_request(request, (int32_t)controller,
                    NVME_URING_CMD_ADMIN, &command, 2u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EOPNOTSUPP,
        "NVME_CQE32_REQUIRED_FAIL\n", &completion);
    ring_close(&ring);

    if (ring_open(&ring, IORING_SETUP_SQE128 | IORING_SETUP_CQE32)) {
        failures += record_failure(1, "NVME_FULL_RING_OPEN_FAIL\n");
        goto finish;
    }
    memset(identify_scalar, 0, sizeof(identify_scalar));
    prepare_request(request, (int32_t)controller,
                    NVME_URING_CMD_ADMIN, &command, 3u, 0u, 0u);
    failures += submit_expect(
        &ring, request, 0, "NVME_IDENTIFY_STATUS_FAIL\n", &completion);
    failures += record_failure(
        completion.user_data != 3u || completion.flags != 0u ||
        completion.extra2 != 0u,
        "NVME_IDENTIFY_CQE32_FAIL\n");
    failures += record_failure(
        !buffer_has_data(identify_scalar, sizeof(identify_scalar)),
        "NVME_IDENTIFY_DATA_FAIL\n");

    memset(identify_vector, 0, sizeof(identify_vector));
    vectors[0].base = (uint64_t)(uintptr_t)identify_vector;
    vectors[0].length = sizeof(identify_vector) / 2u;
    vectors[1].base = (uint64_t)(uintptr_t)(
        identify_vector + sizeof(identify_vector) / 2u);
    vectors[1].length = sizeof(identify_vector) / 2u;
    command.address = (uint64_t)(uintptr_t)vectors;
    command.data_length = 2u;
    prepare_request(request, (int32_t)controller,
                    NVME_URING_CMD_ADMIN_VEC, &command, 4u, 0u, 0u);
    failures += submit_expect(
        &ring, request, 0, "NVME_IDENTIFY_VEC_STATUS_FAIL\n",
        &completion);
    failures += record_failure(
        !buffer_has_data(identify_vector, sizeof(identify_vector)),
        "NVME_IDENTIFY_VEC_DATA_FAIL\n");

    command.address = (uint64_t)(uintptr_t)identify_scalar;
    command.data_length = sizeof(identify_scalar);
    prepare_request(request, (int32_t)controller,
                    NVME_URING_CMD_IO, &command, 5u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -ENOTTY,
        "NVME_CONTROLLER_COMMAND_CLASS_FAIL\n", &completion);

    command.flags = 1u;
    prepare_request(request, (int32_t)controller,
                    NVME_URING_CMD_ADMIN, &command, 6u, 0u, 0u);
    failures += submit_expect(
        &ring, request, -EINVAL,
        "NVME_COMMAND_FLAGS_FAIL\n", &completion);
    command.flags = 0u;

    registration.base = (uint64_t)(uintptr_t)identify_fixed;
    registration.length = sizeof(identify_fixed);
    failures += record_failure(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_BUFFERS, (long)&registration, 1u, 0, 0) != 0,
        "NVME_FIXED_REGISTER_FAIL\n");
    memset(identify_fixed, 0, sizeof(identify_fixed));
    command.address = (uint64_t)(uintptr_t)identify_fixed;
    command.data_length = sizeof(identify_fixed);
    prepare_request(request, (int32_t)controller,
                    NVME_URING_CMD_ADMIN, &command, 7u,
                    IORING_URING_CMD_FIXED, 0u);
    failures += submit_expect(
        &ring, request, 0, "NVME_FIXED_STATUS_FAIL\n", &completion);
    failures += record_failure(
        !buffer_has_data(identify_fixed, sizeof(identify_fixed)),
        "NVME_FIXED_DATA_FAIL\n");

    memset(namespace_data, 0xa5, sizeof(namespace_data));
    memset(&command, 0, sizeof(command));
    command.opcode = NVME_NVM_READ;
    command.namespace_id = 1u;
    command.address = (uint64_t)(uintptr_t)namespace_data;
    command.data_length = sizeof(namespace_data);
    command.timeout_milliseconds = 2000u;
    prepare_request(request, (int32_t)namespace_descriptor,
                    NVME_URING_CMD_IO, &command, 8u, 0u, 0u);
    failures += submit_expect(
        &ring, request, 0, "NVME_NAMESPACE_READ_STATUS_FAIL\n",
        &completion);
    for (uint32_t index = 0; index < sizeof(namespace_data); ++index) {
        if (namespace_data[index] != 0u) {
            failures += record_failure(
                1, "NVME_NAMESPACE_READ_DATA_FAIL\n");
            break;
        }
    }
    ring_close(&ring);

finish:
    if (namespace_descriptor >= 0)
        (void)raw_syscall6(
            SYS_close, namespace_descriptor, 0, 0, 0, 0, 0);
    if (controller >= 0)
        (void)raw_syscall6(
            SYS_close, controller, 0, 0, 0, 0, 0);
    print_text(failures ? "io-uring-nvme-cmd: FAIL\n" :
                          "io-uring-nvme-cmd: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
