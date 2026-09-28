/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring multishot read ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_read_multishot_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define IOSQE_BUFFER_SELECT (1u << 5)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_ASYNC_CANCEL 14u
#define IORING_OP_PROVIDE_BUFFERS 31u
#define IORING_OP_READ_MULTISHOT 49u
#define IORING_CQE_F_BUFFER (1u << 0)
#define IORING_CQE_F_MORE (1u << 1)
#define IORING_CQE_F_BUF_MORE (1u << 4)
#define IORING_CQE_BUFFER_SHIFT 16u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define IORING_REGISTER_PBUF_RING 22u
#define IORING_UNREGISTER_PBUF_RING 23u
#define IORING_REGISTER_PBUF_STATUS 26u
#define IOU_PBUF_RING_INC 2u
#define EINVAL 22
#define EBADF 9
#define EBADFD 77
#define ENOBUFS 105
#define ECANCELED 125

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

void *memcpy(void *destination, const void *source, unsigned long size) {
    uint8_t *output = destination;
    const uint8_t *input = source;

    for (unsigned long index = 0; index < size; ++index)
        output[index] = input[index];
    return destination;
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
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

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

struct ring_view {
    long descriptor;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
};

static uint8_t g_incremental_ring[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t g_incremental_buffer[16];

static int submit(struct ring_view *ring,
                  const struct io_uring_sqe *requests,
                  uint32_t count, uint32_t minimum) {
    uint32_t tail = __atomic_load_n(ring->sq_tail, __ATOMIC_ACQUIRE);

    for (uint32_t index = 0; index < count; ++index) {
        uint32_t slot = (tail + index) & *ring->sq_mask;
        ring->sqes[slot] = requests[index];
        ring->sq_array[slot] = slot;
    }
    __atomic_store_n(ring->sq_tail, tail + count, __ATOMIC_RELEASE);
    return (int)raw_syscall6(
        SYS_io_uring_enter, ring->descriptor, count, minimum,
        minimum ? IORING_ENTER_GETEVENTS : 0, 0, 0);
}

static int wait_one(struct ring_view *ring) {
    return (int)raw_syscall6(
        SYS_io_uring_enter, ring->descriptor, 0, 1,
        IORING_ENTER_GETEVENTS, 0, 0);
}

static struct io_uring_cqe *next_completion(struct ring_view *ring) {
    uint32_t head = __atomic_load_n(ring->cq_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE);
    struct io_uring_cqe *completion;

    if (head == tail) return 0;
    completion = &ring->cqes[head & *ring->cq_mask];
    __atomic_store_n(ring->cq_head, head + 1u, __ATOMIC_RELEASE);
    return completion;
}

static void prepare_buffers(struct io_uring_sqe *request,
                            void *address, uint16_t group,
                            uint16_t first_id, uint32_t count) {
    bytes_zero(request, sizeof(*request));
    request->opcode = IORING_OP_PROVIDE_BUFFERS;
    request->descriptor = (int32_t)count;
    request->offset = first_id;
    request->address = (uint64_t)(uintptr_t)address;
    request->length = 32u;
    request->buffer_index = group;
}

static void prepare_multishot(struct io_uring_sqe *request,
                              int descriptor, uint16_t group,
                              uint64_t user_data) {
    bytes_zero(request, sizeof(*request));
    request->opcode = IORING_OP_READ_MULTISHOT;
    request->flags = IOSQE_BUFFER_SELECT;
    request->descriptor = descriptor;
    request->offset = UINT64_MAX;
    request->buffer_index = group;
    request->user_data = user_data;
}

static void publish_buffer(void *ring_address, uint32_t index,
                           void *buffer_address, uint32_t length,
                           uint16_t id, uint16_t tail) {
    struct io_uring_buf *buffers = ring_address;
    volatile uint16_t *ring_tail = (volatile uint16_t *)(
        (uint8_t *)ring_address + 14u);

    buffers[index].address = (uint64_t)(uintptr_t)buffer_address;
    buffers[index].length = length;
    buffers[index].id = id;
    __atomic_store_n(ring_tail, tail, __ATOMIC_RELEASE);
}

static int run_probe(void) {
    struct io_uring_params parameters;
    struct ring_view ring;
    struct io_uring_sqe requests[2];
    struct io_uring_cqe *completion;
    uint8_t buffers[4][32];
    const uint8_t first[] = {'o', 'n', 'e'};
    const uint8_t second[] = {'t', 'w', 'o'};
    const uint8_t third[] = {'x'};
    const uint8_t incremental_first[] = {'a', 'b', 'c'};
    const uint8_t incremental_second[] = {'d', 'e', 'f'};
    int pipes[2] = {-1, -1};
    void *sq_ring = 0;
    void *cq_ring = 0;
    void *sqes = 0;

    bytes_zero(&parameters, sizeof(parameters));
    bytes_zero(&ring, sizeof(ring));
    bytes_zero(buffers, sizeof(buffers));
    ring.descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    check("setup", ring.descriptor >= 0);
    if (ring.descriptor < 0) return failures;
    sq_ring = map_ring(ring.descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring.descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(ring.descriptor, IORING_OFF_SQES);
    check("map rings", sq_ring && cq_ring && sqes);
    if (!sq_ring || !cq_ring || !sqes) goto out;
    ring.sq_tail = (volatile uint32_t *)((uint8_t *)sq_ring +
                                         parameters.sq_off.tail);
    ring.sq_mask = (volatile uint32_t *)((uint8_t *)sq_ring +
                                         parameters.sq_off.ring_mask);
    ring.sq_array = (volatile uint32_t *)((uint8_t *)sq_ring +
                                          parameters.sq_off.array);
    ring.cq_head = (volatile uint32_t *)((uint8_t *)cq_ring +
                                         parameters.cq_off.head);
    ring.cq_tail = (volatile uint32_t *)((uint8_t *)cq_ring +
                                         parameters.cq_off.tail);
    ring.cq_mask = (volatile uint32_t *)((uint8_t *)cq_ring +
                                         parameters.cq_off.ring_mask);
    ring.sqes = (struct io_uring_sqe *)sqes;
    ring.cqes = (struct io_uring_cqe *)((uint8_t *)cq_ring +
                                        parameters.cq_off.cqes);
    check("pipe", raw_syscall6(
        SYS_pipe2, (long)pipes, 0, 0, 0, 0, 0) == 0);
    if (pipes[0] < 0 || pipes[1] < 0) goto out;

    prepare_buffers(&requests[0], buffers, 11u, 20u, 2u);
    requests[0].user_data = 1u;
    check("provide buffers", submit(&ring, requests, 1u, 1u) == 1);
    completion = next_completion(&ring);
    check("provide result", completion && completion->result == 0);

    prepare_multishot(&requests[0], pipes[0], 11u,
                      0x4d53484f54524541ull);
    check("arm multishot", submit(&ring, requests, 1u, 0u) == 1);
    check("no early completion", next_completion(&ring) == 0);
    check("write first", raw_syscall6(
        SYS_write, pipes[1], (long)first, sizeof(first), 0, 0, 0) ==
        (long)sizeof(first));
    check("wait first", wait_one(&ring) == 0);
    completion = next_completion(&ring);
    check("first completion", completion &&
        completion->user_data == 0x4d53484f54524541ull &&
        completion->result == (int32_t)sizeof(first) &&
        (completion->flags & (IORING_CQE_F_BUFFER |
                              IORING_CQE_F_MORE)) ==
            (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE) &&
        (completion->flags >> IORING_CQE_BUFFER_SHIFT) == 20u &&
        buffers[0][0] == 'o' && buffers[0][1] == 'n' &&
        buffers[0][2] == 'e');

    check("write second", raw_syscall6(
        SYS_write, pipes[1], (long)second, sizeof(second), 0, 0, 0) ==
        (long)sizeof(second));
    check("wait second", wait_one(&ring) == 0);
    completion = next_completion(&ring);
    check("second completion", completion &&
        completion->result == (int32_t)sizeof(second) &&
        (completion->flags & IORING_CQE_F_MORE) != 0 &&
        (completion->flags >> IORING_CQE_BUFFER_SHIFT) == 21u &&
        buffers[1][0] == 't' && buffers[1][1] == 'w' &&
        buffers[1][2] == 'o');

    check("write without buffer", raw_syscall6(
        SYS_write, pipes[1], (long)third, sizeof(third), 0, 0, 0) ==
        (long)sizeof(third));
    check("wait no buffer", wait_one(&ring) == 0);
    completion = next_completion(&ring);
    check("no buffer terminates", completion &&
        completion->result == -ENOBUFS && completion->flags == 0u);
    buffers[3][0] = 0u;
    check("drain unread byte", raw_syscall6(
        SYS_read, pipes[0], (long)&buffers[3][0], 1u, 0, 0, 0) == 1 &&
        buffers[3][0] == 'x');

    prepare_multishot(&requests[0], pipes[0], 12u, 4u);
    requests[0].flags = 0u;
    check("missing buffer-select", submit(&ring, requests, 1u, 1u) == 1);
    completion = next_completion(&ring);
    check("missing buffer-select result", completion &&
        completion->result == -EINVAL);

    prepare_buffers(&requests[0], &buffers[2][0], 13u, 30u, 1u);
    requests[0].user_data = 5u;
    check("provide cancel buffer", submit(&ring, requests, 1u, 1u) == 1);
    (void)next_completion(&ring);
    prepare_multishot(&requests[0], pipes[0], 13u,
                      0x4d53484f5443414eull);
    check("arm cancel target", submit(&ring, requests, 1u, 0u) == 1);
    bytes_zero(&requests[0], sizeof(requests[0]));
    requests[0].opcode = IORING_OP_ASYNC_CANCEL;
    requests[0].descriptor = -1;
    requests[0].address = 0x4d53484f5443414eull;
    requests[0].user_data = 0x43414e43454c4d53ull;
    check("cancel submit", submit(&ring, requests, 1u, 2u) == 1);
    {
        struct io_uring_cqe *first_cancel = next_completion(&ring);
        struct io_uring_cqe *second_cancel = next_completion(&ring);
        int cancel_ok = first_cancel && second_cancel &&
            ((first_cancel->user_data == 0x43414e43454c4d53ull &&
              first_cancel->result == 0 &&
              second_cancel->user_data == 0x4d53484f5443414eull &&
              second_cancel->result == -ECANCELED) ||
             (second_cancel->user_data == 0x43414e43454c4d53ull &&
              second_cancel->result == 0 &&
              first_cancel->user_data == 0x4d53484f5443414eull &&
              first_cancel->result == -ECANCELED));
        check("cancel results", cancel_ok);
    }

    {
        struct io_uring_buf_reg registration;
        struct io_uring_buf_status status;
        struct io_uring_buf *incremental_buffers =
            (struct io_uring_buf *)g_incremental_ring;
        uint64_t original_address =
            (uint64_t)(uintptr_t)g_incremental_buffer;

        bytes_zero(g_incremental_ring, sizeof(g_incremental_ring));
        bytes_zero(g_incremental_buffer, sizeof(g_incremental_buffer));
        bytes_zero(&registration, sizeof(registration));
        registration.ring_address =
            (uint64_t)(uintptr_t)g_incremental_ring;
        registration.ring_entries = 8u;
        registration.buffer_group = 15u;
        registration.flags = IOU_PBUF_RING_INC;
        registration.minimum_left = 4u;
        check("register incremental ring", raw_syscall6(
            SYS_io_uring_register, ring.descriptor,
            IORING_REGISTER_PBUF_RING,
            (long)&registration, 1, 0, 0) == 0);
        publish_buffer(g_incremental_ring, 0u,
                       g_incremental_buffer, 8u, 50u, 1u);
        prepare_multishot(&requests[0], pipes[0], 15u,
                          0x494e43524d53484full);
        check("arm incremental multishot",
              submit(&ring, requests, 1u, 0u) == 1);
        check("write incremental first", raw_syscall6(
            SYS_write, pipes[1], (long)incremental_first,
            sizeof(incremental_first), 0, 0, 0) ==
            (long)sizeof(incremental_first));
        check("wait incremental first", wait_one(&ring) == 0);
        completion = next_completion(&ring);
        check("incremental first completion", completion &&
            completion->result == (int32_t)sizeof(incremental_first) &&
            (completion->flags & (IORING_CQE_F_BUFFER |
                                  IORING_CQE_F_MORE |
                                  IORING_CQE_F_BUF_MORE)) ==
                (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE |
                 IORING_CQE_F_BUF_MORE) &&
            (completion->flags >> IORING_CQE_BUFFER_SHIFT) == 50u &&
            incremental_buffers[0].address == original_address + 3u &&
            incremental_buffers[0].length == 5u &&
            g_incremental_buffer[0] == 'a' &&
            g_incremental_buffer[1] == 'b' &&
            g_incremental_buffer[2] == 'c');
        bytes_zero(&status, sizeof(status));
        status.buffer_group = 15u;
        check("incremental first status", raw_syscall6(
            SYS_io_uring_register, ring.descriptor,
            IORING_REGISTER_PBUF_STATUS,
            (long)&status, 1, 0, 0) == 0 && status.head == 0u);
        check("write incremental second", raw_syscall6(
            SYS_write, pipes[1], (long)incremental_second,
            sizeof(incremental_second), 0, 0, 0) ==
            (long)sizeof(incremental_second));
        check("wait incremental second", wait_one(&ring) == 0);
        completion = next_completion(&ring);
        check("incremental second completion", completion &&
            completion->result == (int32_t)sizeof(incremental_second) &&
            (completion->flags & (IORING_CQE_F_BUFFER |
                                  IORING_CQE_F_MORE)) ==
                (IORING_CQE_F_BUFFER | IORING_CQE_F_MORE) &&
            (completion->flags & IORING_CQE_F_BUF_MORE) == 0u &&
            (completion->flags >> IORING_CQE_BUFFER_SHIFT) == 50u &&
            incremental_buffers[0].address == original_address + 3u &&
            incremental_buffers[0].length == 0u &&
            g_incremental_buffer[3] == 'd' &&
            g_incremental_buffer[4] == 'e' &&
            g_incremental_buffer[5] == 'f');
        bytes_zero(&status, sizeof(status));
        status.buffer_group = 15u;
        check("incremental second status", raw_syscall6(
            SYS_io_uring_register, ring.descriptor,
            IORING_REGISTER_PBUF_STATUS,
            (long)&status, 1, 0, 0) == 0 && status.head == 1u);
        bytes_zero(&registration, sizeof(registration));
        registration.buffer_group = 15u;
        check("unregister incremental ring", raw_syscall6(
            SYS_io_uring_register, ring.descriptor,
            IORING_UNREGISTER_PBUF_RING,
            (long)&registration, 1, 0, 0) == 0);
    }

    prepare_buffers(&requests[0], &buffers[3][0], 14u, 40u, 1u);
    requests[0].user_data = 7u;
    check("provide write-end buffer", submit(&ring, requests, 1u, 1u) == 1);
    (void)next_completion(&ring);
    prepare_multishot(&requests[0], pipes[1], 14u, 8u);
    check("write-end submit", submit(&ring, requests, 1u, 1u) == 1);
    completion = next_completion(&ring);
    check("write-end result", completion && completion->result == -EBADF);

out:
    if (pipes[0] >= 0) (void)raw_syscall6(SYS_close, pipes[0], 0, 0, 0, 0, 0);
    if (pipes[1] >= 0) (void)raw_syscall6(SYS_close, pipes[1], 0, 0, 0, 0, 0);
    if (sq_ring) (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring) (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sqes) (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, ring.descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_READ_MULTISHOT_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
