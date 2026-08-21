/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring fixed-file registration ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#define SYS_write 1
#define SYS_eventfd2 290
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_eventfd2 19
#define SYS_munmap 215
#define SYS_mmap 222
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
#define IOSQE_FIXED_FILE (1u << 0)
#define IORING_ENTER_GETEVENTS 1u
#define IORING_REGISTER_FILES 2u
#define IORING_UNREGISTER_FILES 3u
#define IORING_REGISTER_FILES_UPDATE 6u
#define IORING_OP_WRITE 23u
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

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static int expect(long actual, long expected) {
    return actual == expected ? 0 : 1;
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

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_sqe *sqes;
    void *sq_ring;
    void *cq_ring;
    int32_t fixed_files[2];
    int32_t update_descriptor;
    int32_t update_descriptors[2];
    struct io_uring_files_update update;
    uint64_t value = 1u;
    long ring;
    long eventfd;
    long second_eventfd;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (ring < 0) return 1;
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
    print_text(failures ? "IO_URING_FIXED_FILES_ABI_PROBE_FAIL\n" :
                          "IO_URING_FIXED_FILES_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
