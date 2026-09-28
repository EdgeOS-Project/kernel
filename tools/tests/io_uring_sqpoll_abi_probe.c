/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring SQPOLL and SQ_WAIT ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_sqpoll_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426

#define PROT_READ 1u
#define PROT_WRITE 2u
#define MAP_SHARED 1u
#define PAGE_SIZE 4096u
#define EINVAL 22

#define IORING_SETUP_SQPOLL (1u << 1)
#define IORING_SETUP_SQ_AFF (1u << 2)
#define IORING_SETUP_SINGLE_ISSUER (1u << 12)
#define IORING_SETUP_DEFER_TASKRUN (1u << 13)
#define IORING_FEAT_SQPOLL_NONFIXED (1u << 7)
#define IORING_ENTER_GETEVENTS (1u << 0)
#define IORING_ENTER_SQ_WAKEUP (1u << 1)
#define IORING_ENTER_SQ_WAIT (1u << 2)
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
    uint8_t *bytes = destination;
    while (length) bytes[--length] = (uint8_t)value;
    return destination;
}

unsigned long strlen(const char *text) {
    unsigned long length = 0u;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)strlen(text), 0, 0, 0);
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

static long setup_with_flags(uint32_t flags, uint32_t cpu) {
    struct io_uring_params parameters;

    memset(&parameters, 0, sizeof(parameters));
    parameters.flags = flags;
    parameters.sq_thread_cpu = cpu;
    parameters.sq_thread_idle = 1u;
    return raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
}

static int test_sqpoll(void) {
    struct io_uring_params parameters;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
    void *sq_ring;
    void *cq_ring;
    volatile uint32_t *sq_head;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    long descriptor;
    long enter_result;
    uint32_t index;
    int failures = 0;

    memset(&parameters, 0, sizeof(parameters));
    parameters.flags = IORING_SETUP_SQPOLL;
    parameters.sq_thread_idle = 1u;
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (descriptor < 0) {
        print_text("SQPOLL_SETUP_FAIL\n");
        return 1;
    }
    failures += record_failure(
        !(parameters.features & IORING_FEAT_SQPOLL_NONFIXED),
        "SQPOLL_FEATURE_FAIL\n");
    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    failures += record_failure(
        !sq_ring || !cq_ring || !sqes, "SQPOLL_MMAP_FAIL\n");
    if (failures) goto done;

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

    index = *sq_tail & *sq_mask;
    memset(&sqes[index], 0, sizeof(sqes[index]));
    sqes[index].user_data = 0x5351504fu;
    sq_array[index] = index;
    __atomic_store_n(sq_tail, *sq_tail + 1u, __ATOMIC_RELEASE);
    enter_result = raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP |
            IORING_ENTER_SQ_WAIT,
        0, 0);
    failures += record_failure(
        enter_result != 1, "SQPOLL_ENTER_RESULT_FAIL\n");
    failures += record_failure(
        *sq_head != *sq_tail, "SQPOLL_SQ_WAIT_FAIL\n");
    failures += record_failure(
        *cq_head == *cq_tail, "SQPOLL_CQE_MISSING\n");
    if (*cq_head != *cq_tail) {
        index = *cq_head & (parameters.cq_entries - 1u);
        failures += record_failure(
            cqes[index].user_data != 0x5351504fu ||
            cqes[index].result != 0 || cqes[index].flags != 0u,
            "SQPOLL_CQE_VALUE_FAIL\n");
    }

done:
    if (sqes)
        (void)raw_syscall6(
            SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sq_ring)
        (void)raw_syscall6(
            SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    long descriptor;
    int failures = 0;

    descriptor = setup_with_flags(IORING_SETUP_SQ_AFF, 0u);
    failures += record_failure(
        descriptor != -EINVAL, "SQ_AFF_WITHOUT_SQPOLL_FAIL\n");
    if (descriptor >= 0)
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

    descriptor = setup_with_flags(
        IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER |
            IORING_SETUP_DEFER_TASKRUN,
        0u);
    failures += record_failure(
        descriptor != -EINVAL, "SQPOLL_DEFER_VALIDATION_FAIL\n");
    if (descriptor >= 0)
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

    descriptor = setup_with_flags(
        IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF, 0u);
    failures += record_failure(
        descriptor < 0, "SQPOLL_AFF_SETUP_FAIL\n");
    if (descriptor >= 0)
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

    failures += test_sqpoll();
    print_text(failures ? "io-uring-sqpoll: FAIL\n" :
                          "io-uring-sqpoll: PASS\n");
    (void)raw_syscall6(
        SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
