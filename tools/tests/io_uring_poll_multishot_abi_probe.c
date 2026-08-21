/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring poll update and multishot ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_eventfd2 290
#define SYS_exit 60
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_read 0
#define SYS_write 1
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_eventfd2 19
#define SYS_exit 93
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_read 63
#define SYS_write 64
#else
#error "io_uring_poll_multishot_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_POLL_ADD 6u
#define IORING_OP_POLL_REMOVE 7u
#define IORING_POLL_ADD_MULTI (1u << 0)
#define IORING_POLL_UPDATE_USER_DATA (1u << 2)
#define IORING_CQE_F_MORE (1u << 1)
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define POLLIN 1u
#define ENOENT 2
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
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static long print_text(const char *text) {
    return raw_syscall6(
        SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[32];
    uint32_t position = sizeof(buffer);
    unsigned long magnitude;

    buffer[--position] = '\n';
    magnitude = value < 0 ? (unsigned long)(-value) : (unsigned long)value;
    do {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    if (value < 0) buffer[--position] = '-';
    (void)raw_syscall6(
        SYS_write, 1, (long)&buffer[position], sizeof(buffer) - position,
        0, 0, 0);
}

static int first_failure;
static int check_index;

static int check(const char *name, int condition) {
    ++check_index;
    if (condition) return 0;
    if (!first_failure) first_failure = check_index;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
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

static void *map_ring(long descriptor, uint64_t offset) {
    long result = raw_syscall6(
        SYS_mmap, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED, descriptor, (long)offset);
    return result < 0 && result >= -4095 ? 0 : (void *)(uintptr_t)result;
}

static int submit(long descriptor, volatile uint32_t *sq_tail,
                  volatile uint32_t *sq_mask, volatile uint32_t *sq_array,
                  struct io_uring_sqe *sqes,
                  const struct io_uring_sqe *request,
                  uint32_t minimum_completions) {
    uint32_t tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
    uint32_t slot = tail & *sq_mask;
    sqes[slot] = *request;
    sq_array[slot] = slot;
    __atomic_store_n(sq_tail, tail + 1u, __ATOMIC_RELEASE);
    return (int)raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, minimum_completions,
        minimum_completions ? IORING_ENTER_GETEVENTS : 0, 0, 0);
}

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_sqe request;
    void *sq_ring;
    void *cq_ring;
    struct io_uring_sqe *sqes;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    struct io_uring_cqe *cqes;
    uint64_t event_value = 1u;
    long descriptor;
    long event_descriptor = -1;
    uint32_t completion;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (check("setup ring", descriptor >= 0)) {
        print_number(descriptor);
        settle_console_output();
        return descriptor >= -155 ? 100 - (int)descriptor : 255;
    }
    sq_ring = map_ring(descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(descriptor, IORING_OFF_SQES);
    if (!sq_ring || !cq_ring || !sqes) {
        failures += check("map ring", 0);
        goto close_ring;
    }
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
    cq_mask = (volatile uint32_t *)((uint8_t *)cq_ring +
                                    parameters.cq_off.ring_mask);
    cqes = (struct io_uring_cqe *)((uint8_t *)cq_ring +
                                   parameters.cq_off.cqes);

    event_descriptor = raw_syscall6(
        SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    failures += check("create eventfd", event_descriptor >= 0);
    if (event_descriptor < 0) goto unmap_ring;

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_POLL_ADD;
    request.descriptor = (int32_t)event_descriptor;
    request.length = IORING_POLL_ADD_MULTI;
    request.operation_flags = POLLIN;
    request.user_data = 0x504f4c4c4f4c4431ull;
    failures += check("prime eventfd", raw_syscall6(
        SYS_write, event_descriptor, (long)&event_value,
        sizeof(event_value), 0, 0, 0) == sizeof(event_value));
    completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("submit multishot poll", submit(
        descriptor, sq_tail, sq_mask, sq_array, sqes, &request, 1) == 1);
    failures += check("first poll count",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == completion + 1u);
    failures += check("first poll result",
        cqes[completion & *cq_mask].user_data == request.user_data &&
        (cqes[completion & *cq_mask].result & POLLIN) != 0 &&
        (cqes[completion & *cq_mask].flags & IORING_CQE_F_MORE) != 0);
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);

    completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("collect latched poll", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 0, 0, 0, 0) == 0);
    failures += check("no duplicate poll",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == completion);
    failures += check("drain eventfd", raw_syscall6(
        SYS_read, event_descriptor, (long)&event_value,
        sizeof(event_value), 0, 0, 0) == sizeof(event_value));
    failures += check("rearm poll edge", raw_syscall6(
        SYS_io_uring_enter, descriptor, 0, 0, 0, 0, 0) == 0);

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_POLL_REMOVE;
    request.descriptor = -1;
    request.address = 0x504f4c4c4f4c4431ull;
    request.offset = 0x504f4c4c4e455731ull;
    request.length = IORING_POLL_UPDATE_USER_DATA |
                     IORING_POLL_ADD_MULTI;
    request.user_data = 0x504f4c4c55504431ull;
    completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("submit poll update", submit(
        descriptor, sq_tail, sq_mask, sq_array, sqes, &request, 1) == 1);
    failures += check("poll update completion",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == completion + 1u &&
        cqes[completion & *cq_mask].user_data == request.user_data &&
        cqes[completion & *cq_mask].result == 0);
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);

    bytes_zero(&request, sizeof(request));
    request.opcode = IORING_OP_POLL_REMOVE;
    request.descriptor = -1;
    request.address = 0x504f4c4c4e455731ull;
    request.user_data = 0x504f4c4c524d5631ull;
    completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("remove multishot poll", submit(
        descriptor, sq_tail, sq_mask, sq_array, sqes, &request, 2) == 1);
    failures += check("poll removal completion count",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == completion + 2u);
    {
        struct io_uring_cqe *first = &cqes[completion & *cq_mask];
        struct io_uring_cqe *second =
            &cqes[(completion + 1u) & *cq_mask];
        int removal_ok =
            (first->user_data == request.user_data && first->result == 0) ||
            (second->user_data == request.user_data && second->result == 0);
        int target_ok =
            (first->user_data == 0x504f4c4c4e455731ull &&
             first->result == -ECANCELED) ||
            (second->user_data == 0x504f4c4c4e455731ull &&
             second->result == -ECANCELED);
        failures += check("poll removal results", removal_ok && target_ok);
    }
    __atomic_store_n(cq_head, completion + 2u, __ATOMIC_RELEASE);

    request.address = 0x504f4c4c4e455731ull;
    request.offset = 0x504f4c4c4d495353ull;
    request.length = IORING_POLL_UPDATE_USER_DATA |
                     IORING_POLL_ADD_MULTI;
    request.user_data = 0x504f4c4c55504432ull;
    completion = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("submit missing poll update", submit(
        descriptor, sq_tail, sq_mask, sq_array, sqes, &request, 1) == 1);
    failures += check("missing poll update result",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == completion + 1u &&
        cqes[completion & *cq_mask].user_data == request.user_data &&
        cqes[completion & *cq_mask].result == -ENOENT);
    __atomic_store_n(cq_head, completion + 1u, __ATOMIC_RELEASE);

    (void)raw_syscall6(
        SYS_close, event_descriptor, 0, 0, 0, 0, 0);
unmap_ring:
    (void)raw_syscall6(SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures ? first_failure : 0;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_probe();
    const char *result = failures ?
        "IO_URING_POLL_MULTISHOT_ABI_PROBE_FAIL\n" :
        "IO_URING_POLL_MULTISHOT_ABI_PROBE_PASS\n";
    if (print_text(result) != (long)text_length(result)) ++failures;
    settle_console_output();
    raw_syscall6(SYS_exit, failures, 0, 0, 0, 0, 0);
    for (;;) { }
}
