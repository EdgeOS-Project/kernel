/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring user-provided buffer-ring ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_write 1
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_pipe2 59
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_pbuf_ring_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define ENOENT 2
#define EBADF 9
#define ENOBUFS 105
#define IOSQE_BUFFER_SELECT (1u << 5)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_READV 1u
#define IORING_OP_READ 22u
#define IORING_OP_PROVIDE_BUFFERS 31u
#define IORING_CQE_F_BUFFER 1u
#define IORING_CQE_F_BUF_MORE (1u << 4)
#define IORING_CQE_BUFFER_SHIFT 16u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_REGISTER_PBUF_RING 22u
#define IORING_UNREGISTER_PBUF_RING 23u
#define IORING_REGISTER_PBUF_STATUS 26u
#define IOU_PBUF_RING_MMAP 1u
#define IOU_PBUF_RING_INC 2u
#define IORING_OFF_PBUF_RING 0x80000000ull
#define IORING_OFF_PBUF_SHIFT 16u

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

struct io_uring_buf {
    uint64_t address;
    uint32_t length;
    uint16_t id;
    uint16_t reserved;
};

struct io_uring_buf_reg {
    uint64_t ring_address;
    uint32_t ring_entries;
    uint16_t buffer_group;
    uint16_t flags;
    uint32_t minimum_left;
    uint32_t reserved[5];
};

struct io_uring_buf_status {
    uint32_t buffer_group;
    uint32_t head;
    uint32_t reserved[8];
};

struct linux_iovec {
    uint64_t base;
    uint64_t length;
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

typedef struct probe_ring {
    long descriptor;
    struct io_uring_params parameters;
    void *sq_ring;
    void *cq_ring;
    struct io_uring_sqe *sqes;
} probe_ring_t;

static uint8_t g_buffer_ring[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
static uint8_t g_incremental_ring[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t g_first_buffer[16];
static uint8_t g_second_buffer[16];
static uint8_t g_third_buffer[16];

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

static void bytes_copy(void *destination, const void *source,
                       uint32_t size) {
    uint8_t *output = destination;
    const uint8_t *input = source;
    for (uint32_t index = 0; index < size; ++index)
        output[index] = input[index];
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0u;
    while (text[length]) ++length;
    return length;
}

static long print_text(const char *text) {
    return raw_syscall6(
        SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static void settle_console_output(void) {
    for (volatile uint32_t index = 0; index < 1000000u; ++index) {
#if defined(__x86_64__)
        __asm__ volatile("pause");
#else
        __asm__ volatile("yield");
#endif
    }
}

static uint32_t g_expect_index;

static int expect(long actual, long expected) {
    char message[] = "EXPECT_000_FAIL\n";
    uint32_t index = ++g_expect_index;

    if (actual == expected) return 0;
    message[7] = (char)('0' + (index / 100u) % 10u);
    message[8] = (char)('0' + (index / 10u) % 10u);
    message[9] = (char)('0' + index % 10u);
    (void)raw_syscall6(
        SYS_write, 1, (long)message, sizeof(message) - 1u, 0, 0, 0);
    return 1;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static void *map_anonymous_page(void) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return result < 0 && result >= -4095 ? 0 :
        (void *)(uintptr_t)result;
}

static int submit(probe_ring_t *ring, const struct io_uring_sqe *request,
                  int32_t expected_result, uint32_t expected_flags) {
    volatile uint32_t *sq_head = (volatile uint32_t *)(
        (uint8_t *)ring->sq_ring + ring->parameters.sq_off.head);
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
    volatile uint32_t *cq_mask = (volatile uint32_t *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.ring_mask);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)ring->cq_ring + ring->parameters.cq_off.cqes);
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t submission_slot = submission & *sq_mask;
    uint32_t completion_slot = completion & *cq_mask;
    int failures = 0;

    bytes_copy(&ring->sqes[submission_slot], request, sizeof(*request));
    sq_array[submission_slot] = submission_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    failures += expect(raw_syscall6(
        SYS_io_uring_enter, ring->descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect(
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE), submission + 1u);
    failures += expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE), completion + 1u);
    failures += expect(cqes[completion_slot].user_data,
                       request->user_data);
    failures += expect(cqes[completion_slot].result, expected_result);
    failures += expect(cqes[completion_slot].flags, expected_flags);
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return failures;
}

static void publish_buffer(uint8_t *ring_memory, uint32_t index, void *address,
                           uint32_t length, uint16_t id,
                           uint16_t tail) {
    struct io_uring_buf *buffers = (struct io_uring_buf *)ring_memory;
    buffers[index].address = (uint64_t)(uintptr_t)address;
    buffers[index].length = length;
    buffers[index].id = id;
    __atomic_store_n((uint16_t *)&ring_memory[14], tail, __ATOMIC_RELEASE);
}

static int run_probe(void) {
    static const char first[] = "pbuf";
    static const char second[] = "ring";
    static const char third[] = "keep";
    static const char mapped_data[] = "mmap";
    static const char incremental_first[] = "abc";
    static const char incremental_second[] = "def";
    struct io_uring_buf_reg registration;
    struct io_uring_buf_status status;
    struct linux_iovec selected_vector = {0u, 16u};
    int32_t pipes[2] = {-1, -1};
    struct io_uring_sqe request;
    probe_ring_t ring;
    int failures = 0;

    bytes_zero(&ring, sizeof(ring));
    bytes_zero(g_buffer_ring, sizeof(g_buffer_ring));
    bytes_zero(g_incremental_ring, sizeof(g_incremental_ring));
    bytes_zero(g_first_buffer, sizeof(g_first_buffer));
    bytes_zero(g_second_buffer, sizeof(g_second_buffer));
    bytes_zero(g_third_buffer, sizeof(g_third_buffer));
    ring.descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&ring.parameters, 0, 0, 0, 0);
    if (ring.descriptor < 0) return 1;
    ring.sq_ring = map_ring(ring.descriptor, IORING_OFF_SQ_RING);
    ring.cq_ring = map_ring(ring.descriptor, IORING_OFF_CQ_RING);
    ring.sqes = map_ring(ring.descriptor, IORING_OFF_SQES);
    if (!ring.sq_ring || !ring.cq_ring || !ring.sqes) {
        failures = 1;
        goto close_ring;
    }

    bytes_zero(&registration, sizeof(registration));
    registration.ring_address = (uint64_t)(uintptr_t)g_buffer_ring;
    registration.ring_entries = 8u;
    registration.buffer_group = 9u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_RING, (long)&registration, 1, 0, 0), 0);
    failures += expect(raw_syscall6(
        SYS_pipe2, (long)pipes, 0, 0, 0, 0, 0), 0);
    if (pipes[0] < 0 || pipes[1] < 0) {
        ++failures;
        goto unregister_ring;
    }

    publish_buffer(
        g_buffer_ring, 0u, g_first_buffer,
        sizeof(g_first_buffer), 40u, 1u);
    failures += expect(raw_syscall6(
        SYS_write, pipes[1], (long)first, sizeof(first) - 1u,
        0, 0, 0), sizeof(first) - 1u);
    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_READ;
    request.flags = IOSQE_BUFFER_SELECT;
    request.descriptor = pipes[0];
    request.offset = UINT64_MAX;
    request.length = sizeof(g_first_buffer);
    request.buffer_index = 9u;
    request.user_data = 1u;
    failures += submit(
        &ring, &request, sizeof(first) - 1u,
        IORING_CQE_F_BUFFER | (40u << IORING_CQE_BUFFER_SHIFT));
    failures += expect(g_first_buffer[0], 'p');
    failures += expect(g_first_buffer[1], 'b');
    failures += expect(g_first_buffer[2], 'u');
    failures += expect(g_first_buffer[3], 'f');

    bytes_zero(&status, sizeof(status));
    status.buffer_group = 9u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_STATUS, (long)&status, 1, 0, 0), 0);
    failures += expect(status.head, 1u);

    publish_buffer(
        g_buffer_ring, 1u, g_second_buffer,
        sizeof(g_second_buffer), 41u, 2u);
    failures += expect(raw_syscall6(
        SYS_write, pipes[1], (long)second, sizeof(second) - 1u,
        0, 0, 0), sizeof(second) - 1u);
    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_READV;
    request.flags = IOSQE_BUFFER_SELECT;
    request.descriptor = pipes[0];
    request.offset = UINT64_MAX;
    request.address = (uint64_t)(uintptr_t)&selected_vector;
    request.length = 1u;
    request.buffer_index = 9u;
    request.user_data = 2u;
    failures += submit(
        &ring, &request, sizeof(second) - 1u,
        IORING_CQE_F_BUFFER | (41u << IORING_CQE_BUFFER_SHIFT));
    failures += expect(g_second_buffer[0], 'r');
    failures += expect(g_second_buffer[1], 'i');
    failures += expect(g_second_buffer[2], 'n');
    failures += expect(g_second_buffer[3], 'g');

    bytes_zero(&status, sizeof(status));
    status.buffer_group = 9u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_STATUS, (long)&status, 1, 0, 0), 0);
    failures += expect(status.head, 2u);

    publish_buffer(
        g_buffer_ring, 2u, g_third_buffer,
        sizeof(g_third_buffer), 42u, 3u);
    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_READ;
    request.flags = IOSQE_BUFFER_SELECT;
    request.descriptor = pipes[1];
    request.offset = UINT64_MAX;
    request.length = sizeof(g_third_buffer);
    request.buffer_index = 9u;
    request.user_data = 3u;
    failures += submit(&ring, &request, -EBADF, 0u);
    bytes_zero(&status, sizeof(status));
    status.buffer_group = 9u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_STATUS, (long)&status, 1, 0, 0), 0);
    failures += expect(status.head, 2u);

    failures += expect(raw_syscall6(
        SYS_write, pipes[1], (long)third, sizeof(third) - 1u,
        0, 0, 0), sizeof(third) - 1u);
    request.descriptor = pipes[0];
    request.user_data = 4u;
    failures += submit(
        &ring, &request, sizeof(third) - 1u,
        IORING_CQE_F_BUFFER | (42u << IORING_CQE_BUFFER_SHIFT));
    failures += expect(g_third_buffer[0], 'k');
    failures += expect(g_third_buffer[1], 'e');
    failures += expect(g_third_buffer[2], 'e');
    failures += expect(g_third_buffer[3], 'p');
    bytes_zero(&status, sizeof(status));
    status.buffer_group = 9u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_STATUS, (long)&status, 1, 0, 0), 0);
    failures += expect(status.head, 3u);

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_PROVIDE_BUFFERS;
    request.descriptor = 1;
    request.offset = 50u;
    request.address = (uint64_t)(uintptr_t)g_third_buffer;
    request.length = sizeof(g_third_buffer);
    request.buffer_index = 11u;
    request.user_data = 5u;
    failures += submit(&ring, &request, 0, 0u);
    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_READ;
    request.flags = IOSQE_BUFFER_SELECT;
    request.descriptor = pipes[1];
    request.offset = UINT64_MAX;
    request.length = sizeof(g_third_buffer);
    request.buffer_index = 11u;
    request.user_data = 6u;
    failures += submit(
        &ring, &request, -EBADF,
        IORING_CQE_F_BUFFER | (50u << IORING_CQE_BUFFER_SHIFT));
    request.descriptor = pipes[0];
    request.user_data = 7u;
    failures += submit(&ring, &request, -ENOBUFS, 0u);

    bytes_zero(&registration, sizeof(registration));
    registration.ring_entries = 8u;
    registration.buffer_group = 10u;
    registration.flags = IOU_PBUF_RING_MMAP;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_RING, (long)&registration, 1, 0, 0), 0);
    {
        uint8_t *mapped_buffer_ring = map_ring(
            ring.descriptor,
            IORING_OFF_PBUF_RING |
                (10ull << IORING_OFF_PBUF_SHIFT));

        failures += expect(mapped_buffer_ring != 0, 1);
        if (mapped_buffer_ring) {
            bytes_zero(g_third_buffer, sizeof(g_third_buffer));
            publish_buffer(
                mapped_buffer_ring, 0u, g_third_buffer,
                sizeof(g_third_buffer), 60u, 1u);
            failures += expect(raw_syscall6(
                SYS_write, pipes[1], (long)mapped_data,
                sizeof(mapped_data) - 1u, 0, 0, 0),
                sizeof(mapped_data) - 1u);
            bytes_zero(&request, sizeof(request));
            request.opcode = IORING_OP_READ;
            request.flags = IOSQE_BUFFER_SELECT;
            request.descriptor = pipes[0];
            request.offset = UINT64_MAX;
            request.length = sizeof(g_third_buffer);
            request.buffer_index = 10u;
            request.user_data = 8u;
            failures += submit(
                &ring, &request, sizeof(mapped_data) - 1u,
                IORING_CQE_F_BUFFER |
                    (60u << IORING_CQE_BUFFER_SHIFT));
            failures += expect(g_third_buffer[0], 'm');
            failures += expect(g_third_buffer[1], 'm');
            failures += expect(g_third_buffer[2], 'a');
            failures += expect(g_third_buffer[3], 'p');
            bytes_zero(&status, sizeof(status));
            status.buffer_group = 10u;
            failures += expect(raw_syscall6(
                SYS_io_uring_register, ring.descriptor,
                IORING_REGISTER_PBUF_STATUS,
                (long)&status, 1, 0, 0), 0);
            failures += expect(status.head, 1u);
            (void)raw_syscall6(
                SYS_munmap, (long)mapped_buffer_ring,
                PAGE_SIZE, 0, 0, 0, 0);
        }
    }
    bytes_zero(&registration, sizeof(registration));
    registration.buffer_group = 10u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_UNREGISTER_PBUF_RING,
        (long)&registration, 1, 0, 0), 0);

    bytes_zero(&registration, sizeof(registration));
    registration.ring_entries = 8u;
    registration.buffer_group = 12u;
    registration.flags = IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC;
    registration.minimum_left = 4u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_RING, (long)&registration, 1, 0, 0), 0);
    {
        uint8_t *mapped_buffer_ring = map_ring(
            ring.descriptor,
            IORING_OFF_PBUF_RING |
                (12ull << IORING_OFF_PBUF_SHIFT));
        struct io_uring_buf *buffers =
            (struct io_uring_buf *)mapped_buffer_ring;
        uint64_t original_address =
            (uint64_t)(uintptr_t)g_third_buffer;

        failures += expect(mapped_buffer_ring != 0, 1);
        if (mapped_buffer_ring) {
            bytes_zero(g_third_buffer, sizeof(g_third_buffer));
            publish_buffer(
                mapped_buffer_ring, 0u, g_third_buffer,
                8u, 70u, 1u);
            failures += expect(raw_syscall6(
                SYS_write, pipes[1], (long)incremental_first,
                sizeof(incremental_first) - 1u, 0, 0, 0),
                sizeof(incremental_first) - 1u);
            bytes_zero(&request, sizeof(request));
            request.opcode = IORING_OP_READ;
            request.flags = IOSQE_BUFFER_SELECT;
            request.descriptor = pipes[0];
            request.offset = UINT64_MAX;
            request.length = sizeof(incremental_first) - 1u;
            request.buffer_index = 12u;
            request.user_data = 9u;
            failures += submit(
                &ring, &request, sizeof(incremental_first) - 1u,
                IORING_CQE_F_BUFFER | IORING_CQE_F_BUF_MORE |
                    (70u << IORING_CQE_BUFFER_SHIFT));
            failures += expect(buffers[0].address,
                               original_address + 3u);
            failures += expect(buffers[0].length, 5u);
            bytes_zero(&status, sizeof(status));
            status.buffer_group = 12u;
            failures += expect(raw_syscall6(
                SYS_io_uring_register, ring.descriptor,
                IORING_REGISTER_PBUF_STATUS,
                (long)&status, 1, 0, 0), 0);
            failures += expect(status.head, 0u);

            failures += expect(raw_syscall6(
                SYS_write, pipes[1], (long)incremental_second,
                sizeof(incremental_second) - 1u, 0, 0, 0),
                sizeof(incremental_second) - 1u);
            request.user_data = 10u;
            failures += submit(
                &ring, &request, sizeof(incremental_second) - 1u,
                IORING_CQE_F_BUFFER |
                    (70u << IORING_CQE_BUFFER_SHIFT));
            failures += expect(buffers[0].address,
                               original_address + 3u);
            failures += expect(buffers[0].length, 0u);
            failures += expect(g_third_buffer[0], 'a');
            failures += expect(g_third_buffer[1], 'b');
            failures += expect(g_third_buffer[2], 'c');
            failures += expect(g_third_buffer[3], 'd');
            failures += expect(g_third_buffer[4], 'e');
            failures += expect(g_third_buffer[5], 'f');
            bytes_zero(&status, sizeof(status));
            status.buffer_group = 12u;
            failures += expect(raw_syscall6(
                SYS_io_uring_register, ring.descriptor,
                IORING_REGISTER_PBUF_STATUS,
                (long)&status, 1, 0, 0), 0);
            failures += expect(status.head, 1u);
            (void)raw_syscall6(
                SYS_munmap, (long)mapped_buffer_ring,
                PAGE_SIZE, 0, 0, 0, 0);
        }
    }
    bytes_zero(&registration, sizeof(registration));
    registration.buffer_group = 12u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_UNREGISTER_PBUF_RING,
        (long)&registration, 1, 0, 0), 0);

    bytes_zero(&registration, sizeof(registration));
    registration.ring_address =
        (uint64_t)(uintptr_t)g_incremental_ring;
    registration.ring_entries = 8u;
    registration.buffer_group = 13u;
    registration.flags = IOU_PBUF_RING_INC;
    registration.minimum_left = 4u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_RING, (long)&registration, 1, 0, 0), 0);
    {
        struct io_uring_buf *buffers =
            (struct io_uring_buf *)g_incremental_ring;
        uint64_t original_address =
            (uint64_t)(uintptr_t)g_third_buffer;

        bytes_zero(g_third_buffer, sizeof(g_third_buffer));
        publish_buffer(
            g_incremental_ring, 0u, g_third_buffer,
            8u, 80u, 1u);
        failures += expect(raw_syscall6(
            SYS_write, pipes[1], (long)incremental_first,
            sizeof(incremental_first) - 1u, 0, 0, 0),
            sizeof(incremental_first) - 1u);
        bytes_zero(&request, sizeof(request));
        request.opcode = IORING_OP_READ;
        request.flags = IOSQE_BUFFER_SELECT;
        request.descriptor = pipes[0];
        request.offset = UINT64_MAX;
        request.length = sizeof(incremental_first) - 1u;
        request.buffer_index = 13u;
        request.user_data = 11u;
        failures += submit(
            &ring, &request, sizeof(incremental_first) - 1u,
            IORING_CQE_F_BUFFER | IORING_CQE_F_BUF_MORE |
                (80u << IORING_CQE_BUFFER_SHIFT));
        failures += expect(buffers[0].address,
                           original_address + 3u);
        failures += expect(buffers[0].length, 5u);
        bytes_zero(&status, sizeof(status));
        status.buffer_group = 13u;
        failures += expect(raw_syscall6(
            SYS_io_uring_register, ring.descriptor,
            IORING_REGISTER_PBUF_STATUS,
            (long)&status, 1, 0, 0), 0);
        failures += expect(status.head, 0u);

        failures += expect(raw_syscall6(
            SYS_write, pipes[1], (long)incremental_second,
            sizeof(incremental_second) - 1u, 0, 0, 0),
            sizeof(incremental_second) - 1u);
        request.user_data = 12u;
        failures += submit(
            &ring, &request, sizeof(incremental_second) - 1u,
            IORING_CQE_F_BUFFER |
                (80u << IORING_CQE_BUFFER_SHIFT));
        failures += expect(buffers[0].address,
                           original_address + 3u);
        failures += expect(buffers[0].length, 0u);
        failures += expect(g_third_buffer[0], 'a');
        failures += expect(g_third_buffer[1], 'b');
        failures += expect(g_third_buffer[2], 'c');
        failures += expect(g_third_buffer[3], 'd');
        failures += expect(g_third_buffer[4], 'e');
        failures += expect(g_third_buffer[5], 'f');
        bytes_zero(&status, sizeof(status));
        status.buffer_group = 13u;
        failures += expect(raw_syscall6(
            SYS_io_uring_register, ring.descriptor,
            IORING_REGISTER_PBUF_STATUS,
            (long)&status, 1, 0, 0), 0);
        failures += expect(status.head, 1u);
    }
    bytes_zero(&registration, sizeof(registration));
    registration.buffer_group = 13u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_UNREGISTER_PBUF_RING,
        (long)&registration, 1, 0, 0), 0);

    {
        uint8_t *detached_ring = map_anonymous_page();

        failures += expect(detached_ring != 0, 1);
        if (detached_ring) {
            bytes_zero(detached_ring, PAGE_SIZE);
            bytes_zero(g_first_buffer, sizeof(g_first_buffer));
            publish_buffer(
                detached_ring, 0u, g_first_buffer,
                sizeof(g_first_buffer), 90u, 1u);
            bytes_zero(&registration, sizeof(registration));
            registration.ring_address =
                (uint64_t)(uintptr_t)detached_ring;
            registration.ring_entries = 8u;
            registration.buffer_group = 14u;
            failures += expect(raw_syscall6(
                SYS_io_uring_register, ring.descriptor,
                IORING_REGISTER_PBUF_RING,
                (long)&registration, 1, 0, 0), 0);
            failures += expect(raw_syscall6(
                SYS_munmap, (long)detached_ring,
                PAGE_SIZE, 0, 0, 0, 0), 0);
            failures += expect(raw_syscall6(
                SYS_write, pipes[1], (long)first,
                sizeof(first) - 1u, 0, 0, 0),
                sizeof(first) - 1u);
            bytes_zero(&request, sizeof(request));
            request.opcode = IORING_OP_READ;
            request.flags = IOSQE_BUFFER_SELECT;
            request.descriptor = pipes[0];
            request.offset = UINT64_MAX;
            request.length = sizeof(g_first_buffer);
            request.buffer_index = 14u;
            request.user_data = 13u;
            failures += submit(
                &ring, &request, sizeof(first) - 1u,
                IORING_CQE_F_BUFFER |
                    (90u << IORING_CQE_BUFFER_SHIFT));
            failures += expect(g_first_buffer[0], 'p');
            failures += expect(g_first_buffer[1], 'b');
            failures += expect(g_first_buffer[2], 'u');
            failures += expect(g_first_buffer[3], 'f');
            bytes_zero(&status, sizeof(status));
            status.buffer_group = 14u;
            failures += expect(raw_syscall6(
                SYS_io_uring_register, ring.descriptor,
                IORING_REGISTER_PBUF_STATUS,
                (long)&status, 1, 0, 0), 0);
            failures += expect(status.head, 1u);
            bytes_zero(&registration, sizeof(registration));
            registration.buffer_group = 14u;
            failures += expect(raw_syscall6(
                SYS_io_uring_register, ring.descriptor,
                IORING_UNREGISTER_PBUF_RING,
                (long)&registration, 1, 0, 0), 0);
        }
    }

    (void)raw_syscall6(SYS_close, pipes[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, pipes[1], 0, 0, 0, 0, 0);
unregister_ring:
    bytes_zero(&registration, sizeof(registration));
    registration.buffer_group = 9u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_UNREGISTER_PBUF_RING, (long)&registration, 1, 0, 0), 0);
    bytes_zero(&status, sizeof(status));
    status.buffer_group = 9u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring.descriptor,
        IORING_REGISTER_PBUF_STATUS, (long)&status, 1, 0, 0), -ENOENT);
    (void)raw_syscall6(
        SYS_munmap, (long)ring.sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_munmap, (long)ring.cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_munmap, (long)ring.sqes, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(
        SYS_close, ring.descriptor, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_probe();
    const char *result = failures ?
        "IO_URING_PBUF_RING_ABI_PROBE_FAIL\n" :
        "IO_URING_PBUF_RING_ABI_PROBE_PASS\n";
    settle_console_output();
    if (print_text(result) != (long)text_length(result)) ++failures;
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
