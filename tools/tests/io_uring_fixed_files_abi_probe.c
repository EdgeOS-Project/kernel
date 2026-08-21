/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring fixed-file registration ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_close 3
#define SYS_fcntl 72
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_write 1
#define SYS_eventfd2 290
#define SYS_pipe2 293
#define O_DIRECT 0x4000u
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_close 57
#define SYS_fcntl 25
#define SYS_write 64
#define SYS_exit 93
#define SYS_eventfd2 19
#define SYS_pipe2 59
#define SYS_munmap 215
#define SYS_mmap 222
#define O_DIRECT 0x10000u
#else
#error "io_uring_fixed_files_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define ENXIO 6
#define EBADF 9
#define EBUSY 16
#define EINVAL 22
#define F_GETFD 1
#define FD_CLOEXEC 1
#define IOSQE_FIXED_FILE (1u << 0)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_FILES 2u
#define IORING_UNREGISTER_FILES 3u
#define IORING_REGISTER_FILES_UPDATE 6u
#define IORING_REGISTER_PROBE 8u
#define IORING_REGISTER_FILES2 13u
#define IORING_REGISTER_FILES_UPDATE2 14u
#define IORING_RESOURCE_SPARSE (1u << 0)
#define IO_URING_OP_SUPPORTED 1u
#define IORING_OP_FILES_UPDATE 20u
#define IORING_OP_FIXED_FD_INSTALL 54u
#define IORING_OP_PIPE 60u
#define IORING_OP_LAST 63u
#define IORING_OP_READ 22u
#define IORING_OP_WRITE 23u
#define IORING_FILE_INDEX_ALLOC UINT32_MAX
#define IORING_FIXED_FD_NO_CLOEXEC (1u << 0)
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull

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

struct io_uring_files_update {
    uint32_t offset;
    uint32_t reserved;
    uint64_t descriptors;
};

struct io_uring_resource_register {
    uint32_t count;
    uint32_t flags;
    uint64_t reserved;
    uint64_t data;
    uint64_t tags;
};

struct io_uring_resource_update2 {
    uint32_t offset;
    uint32_t reserved;
    uint64_t data;
    uint64_t tags;
    uint32_t count;
    uint32_t reserved2;
};

struct io_uring_probe_op {
    uint8_t opcode;
    uint8_t reserved;
    uint16_t flags;
    uint32_t reserved2;
};

struct io_uring_probe_document {
    uint8_t last_opcode;
    uint8_t operation_count;
    uint16_t reserved;
    uint32_t reserved2[3];
    struct io_uring_probe_op operations[IORING_OP_LAST];
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
    uint32_t length = 0;
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

static int expect(long actual, long expected) {
    return actual == expected ? 0 : 1;
}

static int test_pipe2_packet_mode(void) {
    static const char first_packet[] = "abcdef";
    static const char second_packet[] = "WXYZ";
    int32_t descriptors[2] = {-1, -1};
    char output[8];
    int failures = 0;

    bytes_zero(output, sizeof(output));
    failures += expect(raw_syscall6(
        SYS_pipe2, (long)descriptors, O_DIRECT, 0, 0, 0, 0), 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) return failures + 1;
    failures += expect(raw_syscall6(
        SYS_write, descriptors[1], (long)first_packet,
        sizeof(first_packet) - 1u, 0, 0, 0),
        sizeof(first_packet) - 1u);
    failures += expect(raw_syscall6(
        SYS_write, descriptors[1], (long)second_packet,
        sizeof(second_packet) - 1u, 0, 0, 0),
        sizeof(second_packet) - 1u);
    failures += expect(raw_syscall6(
        SYS_read, descriptors[0], (long)output, 3u, 0, 0, 0), 3);
    failures += expect(output[0], 'a');
    failures += expect(output[1], 'b');
    failures += expect(output[2], 'c');
    bytes_zero(output, sizeof(output));
    failures += expect(raw_syscall6(
        SYS_read, descriptors[0], (long)output, sizeof(output),
        0, 0, 0), sizeof(second_packet) - 1u);
    failures += expect(output[0], 'W');
    failures += expect(output[1], 'X');
    failures += expect(output[2], 'Y');
    failures += expect(output[3], 'Z');
    (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    return failures;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int submit_fixed_write(
        long ring_descriptor, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        int32_t fixed_index, uint64_t *value, int32_t expected) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t submission_slot = submission & *sq_mask;
    uint32_t completion_slot = completion & *cq_mask;
    int failures = 0;

    bytes_zero(&sqes[submission_slot], sizeof(sqes[submission_slot]));
    sqes[submission_slot].opcode = IORING_OP_WRITE;
    sqes[submission_slot].flags = IOSQE_FIXED_FILE;
    sqes[submission_slot].descriptor = fixed_index;
    sqes[submission_slot].offset = UINT64_MAX;
    sqes[submission_slot].address = (uint64_t)(uintptr_t)value;
    sqes[submission_slot].length = sizeof(*value);
    sqes[submission_slot].user_data = 0x464958454446494cull;
    sq_array[submission_slot] = submission_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    failures += expect(raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect(
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE), submission + 1u);
    failures += expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE), completion + 1u);
    failures += expect(cqes[completion_slot].result, expected);
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return failures;
}

static int submit_fixed_read(
        long ring_descriptor, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        int32_t fixed_index, uint64_t *value, uint32_t length,
        int32_t expected) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t submission_slot = submission & *sq_mask;
    uint32_t completion_slot = completion & *cq_mask;
    int failures = 0;

    bytes_zero(&sqes[submission_slot], sizeof(sqes[submission_slot]));
    sqes[submission_slot].opcode = IORING_OP_READ;
    sqes[submission_slot].flags = IOSQE_FIXED_FILE;
    sqes[submission_slot].descriptor = fixed_index;
    sqes[submission_slot].offset = UINT64_MAX;
    sqes[submission_slot].address = (uint64_t)(uintptr_t)value;
    sqes[submission_slot].length = length;
    sqes[submission_slot].user_data = 0x4649584544524541ull;
    sq_array[submission_slot] = submission_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    failures += expect(raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect(
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE), submission + 1u);
    failures += expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE), completion + 1u);
    failures += expect(cqes[completion_slot].result, expected);
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return failures;
}

static int32_t submit_pipe(
        long ring_descriptor, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        uint32_t file_index, uint32_t pipe_flags,
        int32_t descriptors[2], int *failures) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t submission_slot = submission & *sq_mask;
    uint32_t completion_slot = completion & *cq_mask;
    int32_t result;

    descriptors[0] = -1;
    descriptors[1] = -1;
    bytes_zero(&sqes[submission_slot], sizeof(sqes[submission_slot]));
    sqes[submission_slot].opcode = IORING_OP_PIPE;
    sqes[submission_slot].address =
        (uint64_t)(uintptr_t)descriptors;
    sqes[submission_slot].operation_flags = pipe_flags;
    sqes[submission_slot].splice_descriptor = (int32_t)file_index;
    sqes[submission_slot].user_data = 0x504950455f4f5045ull;
    sq_array[submission_slot] = submission_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    *failures += expect(raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    *failures += expect(
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE), submission + 1u);
    *failures += expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE), completion + 1u);
    result = cqes[completion_slot].result;
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return result;
}

static int submit_files_update(
        long ring_descriptor, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        uint32_t offset, int32_t *descriptors, uint32_t count,
        int32_t expected) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t submission_slot = submission & *sq_mask;
    uint32_t completion_slot = completion & *cq_mask;
    int failures = 0;

    bytes_zero(&sqes[submission_slot], sizeof(sqes[submission_slot]));
    sqes[submission_slot].opcode = IORING_OP_FILES_UPDATE;
    sqes[submission_slot].offset = offset;
    sqes[submission_slot].address = (uint64_t)(uintptr_t)descriptors;
    sqes[submission_slot].length = count;
    sqes[submission_slot].user_data = 0x46494c4553555044ull;
    sq_array[submission_slot] = submission_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    failures += expect(raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    failures += expect(
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE), submission + 1u);
    failures += expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE), completion + 1u);
    failures += expect(cqes[completion_slot].result, expected);
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return failures;
}

static int32_t submit_fixed_install(
        long ring_descriptor, struct io_uring_params *parameters,
        void *sq_ring, void *cq_ring, struct io_uring_sqe *sqes,
        int32_t fixed_index, uint8_t submission_flags,
        uint32_t install_flags, int *failures) {
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
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t submission = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    uint32_t submission_slot = submission & *sq_mask;
    uint32_t completion_slot = completion & *cq_mask;
    int32_t result;

    bytes_zero(&sqes[submission_slot], sizeof(sqes[submission_slot]));
    sqes[submission_slot].opcode = IORING_OP_FIXED_FD_INSTALL;
    sqes[submission_slot].flags = submission_flags;
    sqes[submission_slot].descriptor = fixed_index;
    sqes[submission_slot].operation_flags = install_flags;
    sqes[submission_slot].user_data = 0x4649584544494e53ull;
    sq_array[submission_slot] = submission_slot;
    __atomic_store_n(sq_tail, submission + 1u, __ATOMIC_RELEASE);
    *failures += expect(raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0), 1);
    *failures += expect(
        __atomic_load_n(sq_head, __ATOMIC_ACQUIRE), submission + 1u);
    *failures += expect(
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE), completion + 1u);
    result = cqes[completion_slot].result;
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);
    return result;
}

static int consume_tag_completion(
        struct io_uring_params *parameters, void *cq_ring,
        uint64_t expected_tag) {
    volatile uint32_t *cq_head = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters->cq_off.head);
    volatile uint32_t *cq_tail = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters->cq_off.tail);
    volatile uint32_t *cq_mask = (volatile uint32_t *)(
        (uint8_t *)cq_ring + parameters->cq_off.ring_mask);
    struct io_uring_cqe *cqes = (struct io_uring_cqe *)(
        (uint8_t *)cq_ring + parameters->cq_off.cqes);
    uint32_t head = __atomic_load_n(cq_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    struct io_uring_cqe *completion;
    int failures = 0;

    failures += expect(tail, head + 1u);
    if (tail == head) return failures;
    completion = &cqes[head & *cq_mask];
    failures += expect((long)completion->user_data, (long)expected_tag);
    failures += expect(completion->result, 0);
    failures += expect(completion->flags, 0);
    __atomic_store_n(cq_head, head + 1u, __ATOMIC_RELEASE);
    return failures;
}

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_sqe *sqes;
    void *sq_ring;
    void *cq_ring;
    int32_t fixed_files[2];
    int32_t update_descriptor;
    int32_t update_descriptors[2];
    struct io_uring_files_update update;
    struct io_uring_resource_register registration2;
    struct io_uring_resource_update2 update2;
    uint64_t value = 1u;
    uint64_t pipe_value = 0u;
    uint64_t second_pipe_value = 2u;
    uint64_t tag;
    long ring;
    long eventfd;
    long second_eventfd;
    long installed;
    int32_t installed_result;
    int failures = 0;

    failures += test_pipe2_packet_mode();

    bytes_zero(&parameters, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (ring < 0) return 1;
#ifdef EDGEOS_EXPECT_FROZEN_IO_URING_OPS
    {
        struct io_uring_probe_document probe;

        bytes_zero(&probe, sizeof(probe));
        failures += expect(raw_syscall6(
            SYS_io_uring_register, ring, IORING_REGISTER_PROBE,
            (long)&probe, IORING_OP_LAST, 0, 0), 0);
        failures += expect(probe.last_opcode, IORING_OP_LAST - 1u);
        failures += expect(probe.operation_count, IORING_OP_LAST);
        failures += expect(
            probe.operations[IORING_OP_FILES_UPDATE].flags,
            IO_URING_OP_SUPPORTED);
        failures += expect(
            probe.operations[IORING_OP_FIXED_FD_INSTALL].flags,
            IO_URING_OP_SUPPORTED);
        failures += expect(
            probe.operations[IORING_OP_PIPE].flags,
            IO_URING_OP_SUPPORTED);
    }
#endif
    sq_ring = map_ring(ring, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring, IORING_OFF_CQ_RING);
    sqes = map_ring(ring, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        failures = 1;
        goto close_ring;
    }

    fixed_files[0] = (int32_t)ring;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES,
        (long)fixed_files, 1, 0, 0), -EBADF);
    eventfd = raw_syscall6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    if (eventfd < 0) {
        failures = 1;
        goto unmap;
    }
    fixed_files[0] = (int32_t)eventfd;
    fixed_files[1] = -1;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES,
        (long)fixed_files, 2, 0, 0), 0);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES,
        (long)fixed_files, 2, 0, 0), -EBUSY);
    second_eventfd = raw_syscall6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    if (second_eventfd < 0) {
        failures = 1;
        goto close_eventfd;
    }
    update_descriptor = (int32_t)second_eventfd;
    update.offset = 1u;
    update.reserved = 0u;
    update.descriptors = (uint64_t)(uintptr_t)&update_descriptor;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 1, 0, 0), 1);
    update_descriptor = (int32_t)second_eventfd;
    failures += submit_files_update(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0u, &update_descriptor, 1u, 1);
    (void)raw_syscall6(SYS_close, eventfd, 0, 0, 0, 0, 0);
    eventfd = -1;
    (void)raw_syscall6(SYS_close, second_eventfd, 0, 0, 0, 0, 0);
    second_eventfd = -1;
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, &value, (int32_t)sizeof(value));
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        1, &value, (int32_t)sizeof(value));
    installed = submit_fixed_install(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, IOSQE_FIXED_FILE, 0u, &failures);
    if (installed < 0) {
        ++failures;
    } else {
        failures += expect(raw_syscall6(
            SYS_fcntl, installed, F_GETFD, 0, 0, 0, 0), FD_CLOEXEC);
        (void)raw_syscall6(SYS_close, installed, 0, 0, 0, 0, 0);
    }
    installed = submit_fixed_install(
        ring, &parameters, sq_ring, cq_ring, sqes,
        1, IOSQE_FIXED_FILE, IORING_FIXED_FD_NO_CLOEXEC, &failures);
    if (installed < 0) {
        ++failures;
    } else {
        failures += expect(raw_syscall6(
            SYS_fcntl, installed, F_GETFD, 0, 0, 0, 0), 0);
        (void)raw_syscall6(SYS_close, installed, 0, 0, 0, 0, 0);
    }
    installed_result = submit_fixed_install(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, 0u, 0u, &failures);
    failures += expect(installed_result, -EBADF);
    installed_result = submit_fixed_install(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, IOSQE_FIXED_FILE, 2u, &failures);
    failures += expect(installed_result, -EINVAL);
    update_descriptors[0] = -2;
    update_descriptors[1] = (int32_t)ring;
    update.offset = 0u;
    update.descriptors = (uint64_t)(uintptr_t)update_descriptors;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 2, 0, 0), 1);
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, &value, (int32_t)sizeof(value));
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        1, &value, -EBADF);
    update_descriptor = -1;
    update.offset = 0u;
    update.descriptors = (uint64_t)(uintptr_t)&update_descriptor;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 1, 0, 0), 1);
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, &value, -EBADF);
    update_descriptor = -2;
    update.offset = 2u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 1, 0, 0), -EINVAL);
    update.offset = 0u;
    update.reserved = 1u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 1, 0, 0), -EINVAL);
    update.reserved = 0u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 0, 0, 0), -EINVAL);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_FILES,
        0, 0, 0, 0), 0);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_FILES,
        0, 0, 0, 0), -ENXIO);
    bytes_zero(&registration2, sizeof(registration2));
    registration2.count = 2u;
    registration2.flags = IORING_RESOURCE_SPARSE;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES2,
        (long)&registration2, sizeof(registration2), 0, 0), 0);
    installed_result = submit_pipe(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0u, 0u, update_descriptors, &failures);
    failures += expect(installed_result, 0);
    if (update_descriptors[0] >= 0)
        (void)raw_syscall6(
            SYS_close, update_descriptors[0], 0, 0, 0, 0, 0);
    if (update_descriptors[1] >= 0)
        (void)raw_syscall6(
            SYS_close, update_descriptors[1], 0, 0, 0, 0, 0);

    installed_result = submit_pipe(
        ring, &parameters, sq_ring, cq_ring, sqes,
        IORING_FILE_INDEX_ALLOC, O_DIRECT,
        update_descriptors, &failures);
    failures += expect(installed_result, 0);
    failures += expect(update_descriptors[0], 0);
    failures += expect(update_descriptors[1], 1);
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        1, &value, (int32_t)sizeof(value));
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        1, &second_pipe_value,
        (int32_t)sizeof(second_pipe_value));
    failures += submit_fixed_read(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, &pipe_value, 4u, 4);
    failures += expect((long)pipe_value, (long)value);
    pipe_value = 0u;
    failures += submit_fixed_read(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, &pipe_value, sizeof(pipe_value),
        (int32_t)sizeof(pipe_value));
    failures += expect((long)pipe_value, (long)second_pipe_value);
    update_descriptors[0] = -1;
    update_descriptors[1] = -1;
    update.offset = 0u;
    update.reserved = 0u;
    update.descriptors = (uint64_t)(uintptr_t)update_descriptors;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 2, 0, 0), 2);

    installed_result = submit_pipe(
        ring, &parameters, sq_ring, cq_ring, sqes,
        1u, 0u, update_descriptors, &failures);
    failures += expect(installed_result, 0);
    failures += expect(update_descriptors[0], 0);
    failures += expect(update_descriptors[1], 1);
    update_descriptors[0] = -1;
    update_descriptors[1] = -1;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE,
        (long)&update, 2, 0, 0), 2);
    eventfd = raw_syscall6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    if (eventfd < 0) {
        failures = 1;
        goto close_eventfd;
    }
    update_descriptor = (int32_t)eventfd;
    bytes_zero(&update2, sizeof(update2));
    update2.data = (uint64_t)(uintptr_t)&update_descriptor;
    tag = 0x5441475f46494c45ull;
    update2.tags = (uint64_t)(uintptr_t)&tag;
    update2.count = 1u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE2,
        (long)&update2, sizeof(update2), 0, 0), 1);
    (void)raw_syscall6(SYS_close, eventfd, 0, 0, 0, 0, 0);
    eventfd = -1;
    second_eventfd = raw_syscall6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    if (second_eventfd < 0) {
        failures = 1;
        goto close_eventfd;
    }
    update_descriptor = (int32_t)second_eventfd;
    tag = 0x5441475f4e455854ull;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE2,
        (long)&update2, sizeof(update2), 0, 0), 1);
    failures += consume_tag_completion(
        &parameters, cq_ring, 0x5441475f46494c45ull);
    (void)raw_syscall6(SYS_close, second_eventfd, 0, 0, 0, 0, 0);
    second_eventfd = -1;
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, &value, (int32_t)sizeof(value));
    update_descriptor = -1;
    tag = 0u;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES_UPDATE2,
        (long)&update2, sizeof(update2), 0, 0), 1);
    failures += consume_tag_completion(
        &parameters, cq_ring, 0x5441475f4e455854ull);
    failures += submit_fixed_write(
        ring, &parameters, sq_ring, cq_ring, sqes,
        0, &value, -EBADF);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_FILES,
        0, 0, 0, 0), 0);
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES2,
        (long)&registration2, sizeof(registration2) - 1u, 0, 0), -EINVAL);
    registration2.data = (uint64_t)(uintptr_t)fixed_files;
    failures += expect(raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_FILES2,
        (long)&registration2, sizeof(registration2), 0, 0), -EINVAL);

close_eventfd:
    if (second_eventfd >= 0)
        (void)raw_syscall6(SYS_close, second_eventfd, 0, 0, 0, 0, 0);
    if (eventfd >= 0)
        (void)raw_syscall6(SYS_close, eventfd, 0, 0, 0, 0, 0);

unmap:
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_probe();
    const char *result = failures ?
        "IO_URING_FIXED_FILES_ABI_PROBE_FAIL\n" :
        "IO_URING_FIXED_FILES_ABI_PROBE_PASS\n";
    settle_console_output();
    if (print_text(result) != (long)text_length(result)) ++failures;
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
