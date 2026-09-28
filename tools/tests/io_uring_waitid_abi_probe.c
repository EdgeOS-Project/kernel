/* SPDX-License-Identifier: MPL-2.0 */
/* Linux io_uring waitid ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_clone 56
#define SYS_exit 60
#define SYS_waitid 247
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_waitid 95
#define SYS_clone 220
#define SYS_munmap 215
#define SYS_mmap 222
#else
#error "io_uring_waitid_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define PAGE_SIZE 4096u
#define IORING_ENTER_GETEVENTS 1u
#define IORING_OP_ASYNC_CANCEL 14u
#define IORING_OP_WAITID 50u
#define IORING_OFF_SQ_RING 0x00000000ull
#define IORING_OFF_CQ_RING 0x08000000ull
#define IORING_OFF_SQES 0x10000000ull
#define SIGCHLD 17
#define CLD_EXITED 1
#define P_PID 1u
#define WNOHANG 0x00000001u
#define WEXITED 0x00000004u
#define WNOWAIT 0x01000000u
#define EINVAL 22
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

struct linux_siginfo_child {
    int32_t signal_number;
    int32_t error;
    int32_t code;
    uint32_t padding;
    int32_t pid;
    uint32_t uid;
    int32_t status;
    uint32_t child_padding;
    int64_t user_time;
    int64_t system_time;
    uint8_t reserved[80];
};

_Static_assert(sizeof(struct linux_siginfo_child) == 128,
               "Linux siginfo layout mismatch");

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

static void bytes_fill(void *destination, uint8_t value, uint32_t size) {
    uint8_t *bytes = destination;
    for (uint32_t index = 0; index < size; ++index) bytes[index] = value;
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

static int submit_requests(long descriptor,
                           volatile uint32_t *sq_tail,
                           volatile uint32_t *sq_mask,
                           volatile uint32_t *sq_array,
                           struct io_uring_sqe *sqes,
                           const struct io_uring_sqe *requests,
                           uint32_t count, uint32_t minimum) {
    uint32_t tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);

    for (uint32_t index = 0; index < count; ++index) {
        uint32_t slot = (tail + index) & *sq_mask;
        sqes[slot] = requests[index];
        sq_array[slot] = slot;
    }
    __atomic_store_n(sq_tail, tail + count, __ATOMIC_RELEASE);
    return (int)raw_syscall6(
        SYS_io_uring_enter, descriptor, count, minimum,
        minimum ? IORING_ENTER_GETEVENTS : 0, 0, 0);
}

static int find_result(const struct io_uring_cqe *cqes, uint32_t mask,
                       uint32_t first, uint32_t last,
                       uint64_t user_data, int32_t *result) {
    for (uint32_t index = first; index < last; ++index) {
        const struct io_uring_cqe *completion = &cqes[index & mask];
        if (completion->user_data != user_data) continue;
        *result = completion->result;
        return 1;
    }
    return 0;
}

static long spawn_blocked_child(int pipes[2], int status) {
    long child;

    pipes[0] = -1;
    pipes[1] = -1;
    if (raw_syscall6(SYS_pipe2, (long)pipes, 0, 0, 0, 0, 0) < 0)
        return -1;
    child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (!child) {
        uint8_t value = 0;
        (void)raw_syscall6(SYS_close, pipes[1], 0, 0, 0, 0, 0);
        (void)raw_syscall6(
            SYS_read, pipes[0], (long)&value, sizeof(value), 0, 0, 0);
        (void)raw_syscall6(SYS_exit, status, 0, 0, 0, 0, 0);
        for (;;) {}
    }
    (void)raw_syscall6(SYS_close, pipes[0], 0, 0, 0, 0, 0);
    pipes[0] = -1;
    return child;
}

static void release_child(int pipes[2]) {
    const uint8_t value = 1u;
    if (pipes[1] >= 0) {
        (void)raw_syscall6(
            SYS_write, pipes[1], (long)&value, sizeof(value), 0, 0, 0);
        (void)raw_syscall6(SYS_close, pipes[1], 0, 0, 0, 0, 0);
        pipes[1] = -1;
    }
}

static void prepare_waitid(struct io_uring_sqe *request, long child,
                           struct linux_siginfo_child *information,
                           uint32_t options, uint64_t user_data) {
    bytes_zero(request, sizeof(*request));
    request->opcode = IORING_OP_WAITID;
    request->descriptor = (int32_t)child;
    request->offset = (uint64_t)(uintptr_t)information;
    request->length = P_PID;
    request->user_data = user_data;
    request->splice_descriptor = (int32_t)options;
}

static int run_probe(void) {
    const uint64_t nohang_data = 0x574149544e4f4841ull;
    const uint64_t async_data = 0x574149544153594eull;
    const uint64_t invalid_data = 0x57414954494e5641ull;
    const uint64_t cancel_target_data = 0x5741495443414e54ull;
    const uint64_t cancel_data = 0x5741495443414e43ull;
    struct io_uring_params parameters;
    struct io_uring_sqe requests[2];
    struct linux_siginfo_child nohang_information;
    struct linux_siginfo_child async_information;
    struct linux_siginfo_child canceled_information;
    struct linux_siginfo_child reap_information;
    int child_pipes[2] = {-1, -1};
    int cancel_pipes[2] = {-1, -1};
    void *sq_ring = 0;
    void *cq_ring = 0;
    struct io_uring_sqe *sqes = 0;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_mask;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    volatile uint32_t *cq_mask;
    struct io_uring_cqe *cqes;
    long ring_descriptor;
    long child = -1;
    long cancel_child = -1;
    uint32_t first;
    uint32_t last;
    int32_t result = 0;
    int failures = 0;

    bytes_zero(&parameters, sizeof(parameters));
    ring_descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    if (check("setup ring", ring_descriptor >= 0)) return 100;
    sq_ring = map_ring(ring_descriptor, IORING_OFF_SQ_RING);
    cq_ring = map_ring(ring_descriptor, IORING_OFF_CQ_RING);
    sqes = map_ring(ring_descriptor, IORING_OFF_SQES);
    if (check("map ring", sq_ring && cq_ring && sqes)) goto close_ring;
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

    child = spawn_blocked_child(child_pipes, 42);
    failures += check("spawn async child", child > 0);
    if (child <= 0) goto unmap_ring;

    bytes_zero(&nohang_information, sizeof(nohang_information));
    prepare_waitid(&requests[0], child, &nohang_information,
                   WEXITED | WNOHANG, nohang_data);
    first = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("submit nohang wait", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 1u) == 1);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("nohang completion count", last - first == 1u);
    failures += check("nohang result", find_result(
        cqes, *cq_mask, first, last, nohang_data, &result) && result == 0);
    failures += check("nohang zero siginfo",
        nohang_information.signal_number == 0 &&
        nohang_information.pid == 0 && nohang_information.code == 0);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    bytes_fill(&async_information, 0x5a, sizeof(async_information));
    prepare_waitid(&requests[0], child, &async_information,
                   WEXITED, async_data);
    first = last;
    failures += check("submit asynchronous wait", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 0u) == 1);
    failures += check("asynchronous wait remains pending",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == first);

    prepare_waitid(&requests[0], child, &reap_information,
                   WEXITED, invalid_data);
    requests[0].operation_flags = 1u;
    failures += check("submit invalid wait", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 1u) == 1);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("invalid wait result", find_result(
        cqes, *cq_mask, first, last, invalid_data, &result) &&
        result == -EINVAL);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    release_child(child_pipes);
    first = last;
    failures += check("wait for asynchronous child", raw_syscall6(
        SYS_io_uring_enter, ring_descriptor, 0, 1,
        IORING_ENTER_GETEVENTS, 0, 0) == 0);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("asynchronous completion count", last - first == 1u);
    failures += check("asynchronous wait result", find_result(
        cqes, *cq_mask, first, last, async_data, &result) && result == 0);
    failures += check("asynchronous siginfo",
        async_information.signal_number == SIGCHLD &&
        async_information.code == CLD_EXITED &&
        async_information.pid == child && async_information.status == 42);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);
    child = -1;

    cancel_child = spawn_blocked_child(cancel_pipes, 43);
    failures += check("spawn cancellation child", cancel_child > 0);
    if (cancel_child <= 0) goto unmap_ring;
    bytes_fill(&canceled_information, 0x5a,
               sizeof(canceled_information));
    prepare_waitid(&requests[0], cancel_child, &canceled_information,
                   WEXITED, cancel_target_data);
    first = last;
    failures += check("submit cancellation target", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 0u) == 1);
    failures += check("cancellation target remains pending",
        __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == first);

    bytes_zero(&requests[0], sizeof(requests[0]));
    requests[0].opcode = IORING_OP_ASYNC_CANCEL;
    requests[0].descriptor = -1;
    requests[0].address = cancel_target_data;
    requests[0].user_data = cancel_data;
    failures += check("submit wait cancellation", submit_requests(
        ring_descriptor, sq_tail, sq_mask, sq_array, sqes,
        requests, 1u, 2u) == 1);
    last = __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE);
    failures += check("cancellation completion count", last - first == 2u);
    failures += check("cancellation request result", find_result(
        cqes, *cq_mask, first, last, cancel_data, &result) && result == 1);
    failures += check("canceled wait result", find_result(
        cqes, *cq_mask, first, last, cancel_target_data, &result) &&
        result == -ECANCELED);
    __atomic_store_n(cq_head, last, __ATOMIC_RELEASE);

    release_child(cancel_pipes);
    bytes_zero(&reap_information, sizeof(reap_information));
    failures += check("reap cancellation child", raw_syscall6(
        SYS_waitid, P_PID, cancel_child, (long)&reap_information,
        WEXITED, 0, 0) == 0);
    failures += check("cancellation child status",
        reap_information.pid == cancel_child &&
        reap_information.status == 43);
    cancel_child = -1;

    if (!failures) print_text("IO_URING_WAITID_ABI_PROBE_PASS\n");

unmap_ring:
    release_child(child_pipes);
    release_child(cancel_pipes);
    if (child > 0) {
        bytes_zero(&reap_information, sizeof(reap_information));
        (void)raw_syscall6(
            SYS_waitid, P_PID, child, (long)&reap_information,
            WEXITED, 0, 0);
    }
    if (cancel_child > 0) {
        bytes_zero(&reap_information, sizeof(reap_information));
        (void)raw_syscall6(
            SYS_waitid, P_PID, cancel_child, (long)&reap_information,
            WEXITED, 0, 0);
    }
    if (sqes) (void)raw_syscall6(
        SYS_munmap, (long)sqes, PAGE_SIZE, 0, 0, 0, 0);
    if (cq_ring) (void)raw_syscall6(
        SYS_munmap, (long)cq_ring, PAGE_SIZE, 0, 0, 0, 0);
    if (sq_ring) (void)raw_syscall6(
        SYS_munmap, (long)sq_ring, PAGE_SIZE, 0, 0, 0, 0);
close_ring:
    (void)raw_syscall6(SYS_close, ring_descriptor, 0, 0, 0, 0, 0);
    settle_console_output();
    return failures ? first_failure : 0;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
__attribute__((noreturn)) void _start(void) {
    int result = run_probe();
    raw_syscall6(SYS_exit, result, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
