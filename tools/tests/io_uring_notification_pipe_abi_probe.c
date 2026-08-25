/* SPDX-License-Identifier: MPL-2.0 */
/* Linux IORING_OP_PIPE notification-pipe ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_ioctl 29
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_write 64
#define SYS_exit 93
#else
#error "io_uring_notification_pipe_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_PIPE 62u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define O_NOTIFICATION_PIPE 0x80u
#define IOC_WATCH_QUEUE_SET_SIZE 0x5760u

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

static unsigned long text_length(const char *text) {
    unsigned long length = 0u;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void bytes_zero(void *destination, unsigned long length) {
    uint8_t *bytes = (uint8_t *)destination;
    while (length) bytes[--length] = 0u;
}

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 :
        (void *)(uintptr_t)result;
}

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    volatile uint32_t *sq_head;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    void *sq_ring;
    void *cq_ring;
    int32_t descriptors[2] = {-1, -1};
    long ring;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 2, (long)&parameters, 0, 0, 0, 0);
    if (ring < 0) return 1;
    sq_ring = map_ring(ring, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring, IORING_OFF_CQ_RING);
    sqes = (struct io_uring_sqe *)map_ring(ring, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        failures = 1;
        goto out_close_ring;
    }
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
    cqes = (struct io_uring_cqe *)((uint8_t *)cq_ring +
                                   parameters.cq_off.cqes);

    bytes_zero(&sqes[0], sizeof(sqes[0]));
    sqes[0].opcode = IORING_OP_PIPE;
    sqes[0].address = (uint64_t)(uintptr_t)descriptors;
    sqes[0].operation_flags = O_NOTIFICATION_PIPE;
    sqes[0].user_data = 0x4e4f544946595049ull;
    sq_array[0u & *sq_mask] = 0u;
    __atomic_store_n(sq_tail, 1u, __ATOMIC_RELEASE);
    if (raw_syscall6(
            SYS_io_uring_enter, ring, 1, 1,
            IORING_ENTER_GETEVENTS, 0, 0) != 1)
        ++failures;
    if (__atomic_load_n(sq_head, __ATOMIC_ACQUIRE) != 1u ||
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) != 1u ||
        cqes[0].result != 0 || descriptors[0] < 0 || descriptors[1] < 0)
        ++failures;
    if (!failures && raw_syscall6(
            SYS_ioctl, descriptors[0], IOC_WATCH_QUEUE_SET_SIZE,
            1, 0, 0, 0) != 0)
        ++failures;
    __atomic_store_n(cq_head, 1u, __ATOMIC_RELEASE);
    if (descriptors[0] >= 0)
        (void)raw_syscall6(SYS_close, descriptors[0], 0, 0, 0, 0, 0);
    if (descriptors[1] >= 0)
        (void)raw_syscall6(SYS_close, descriptors[1], 0, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
out_close_ring:
    (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_probe();
    print_text(failures ?
        "IO_URING_NOTIFICATION_PIPE_ABI_PROBE_FAIL\n" :
        "IO_URING_NOTIFICATION_PIPE_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
