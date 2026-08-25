/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring user-backed ring-memory ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_close 3
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#else
#error "io_uring_no_mmap_abi_probe requires a 64-bit Linux ABI"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427

#define PAGE_SIZE 4096u
#define EFAULT 14
#define EINVAL 22
#define IORING_SETUP_NO_MMAP (1u << 14)
#define IORING_SETUP_SINGLE_ISSUER (1u << 12)
#define IORING_SETUP_DEFER_TASKRUN (1u << 13)
#define IORING_ENTER_GETEVENTS (1u << 0)
#define IORING_REGISTER_RESIZE_RINGS 33u
#define IORING_OP_NOP 0u

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

struct io_uring_sqe {
    uint8_t opcode;
    uint8_t flags;
    uint16_t priority;
    int32_t descriptor;
    uint64_t offset;
    uint64_t address;
    uint32_t length;
    uint32_t operation_flags;
    uint64_t user_data;
    uint16_t buffer_index;
    uint16_t personality;
    int32_t splice_descriptor;
    uint64_t extra[2];
};

struct io_uring_cqe {
    uint64_t user_data;
    int32_t result;
    uint32_t flags;
};

static uint8_t g_ring_memory[PAGE_SIZE * 4u]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t g_sqe_memory[PAGE_SIZE * 2u]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t g_resized_ring_memory[PAGE_SIZE * 4u]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t g_resized_sqe_memory[PAGE_SIZE * 2u]
    __attribute__((aligned(PAGE_SIZE)));
static int failures;

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
    for (uint32_t index = 0; index < size; ++index) bytes[index] = 0u;
}

static uint32_t text_length(const char *text) {
    uint32_t length = 0u;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, text_length(text), 0, 0, 0);
}

static void check(const char *name, int condition) {
    if (condition) return;
    ++failures;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
}

static void check_result(const char *name, long result, long expected) {
    check(name, result == expected);
}

static void prepare_parameters(struct io_uring_params *parameters) {
    bytes_zero(parameters, sizeof(*parameters));
    parameters->flags = IORING_SETUP_NO_MMAP |
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
    parameters->cq_off.user_address =
        (uint64_t)(uintptr_t)g_ring_memory;
    parameters->sq_off.user_address =
        (uint64_t)(uintptr_t)g_sqe_memory;
}

static void run_error_order_checks(void) {
    struct io_uring_params parameters;

    prepare_parameters(&parameters);
    parameters.cq_off.user_address = 0u;
    check_result("missing-ring-address",
                 raw_syscall6(SYS_io_uring_setup, 8,
                              (long)&parameters, 0, 0, 0, 0),
                 -EFAULT);

    prepare_parameters(&parameters);
    parameters.sq_off.user_address = 0u;
    check_result("missing-sqe-address",
                 raw_syscall6(SYS_io_uring_setup, 8,
                              (long)&parameters, 0, 0, 0, 0),
                 -EFAULT);

    prepare_parameters(&parameters);
    parameters.cq_off.user_address += 1u;
    check_result("misaligned-ring-address",
                 raw_syscall6(SYS_io_uring_setup, 8,
                              (long)&parameters, 0, 0, 0, 0),
                 -EINVAL);

    prepare_parameters(&parameters);
    parameters.sq_off.user_address += 1u;
    check_result("misaligned-sqe-address",
                 raw_syscall6(SYS_io_uring_setup, 8,
                              (long)&parameters, 0, 0, 0, 0),
                 -EINVAL);
}

static void run_nop_check(void) {
    struct io_uring_params parameters;
    struct io_uring_params resize;
    struct io_uring_sqe *sqes = (void *)g_sqe_memory;
    struct io_uring_cqe *cqes;
    volatile uint32_t *sq_tail;
    volatile uint32_t *sq_array;
    volatile uint32_t *cq_head;
    volatile uint32_t *cq_tail;
    long descriptor;
    long result;

    bytes_zero(g_ring_memory, sizeof(g_ring_memory));
    bytes_zero(g_sqe_memory, sizeof(g_sqe_memory));
    prepare_parameters(&parameters);
    descriptor = raw_syscall6(
        SYS_io_uring_setup, 8, (long)&parameters, 0, 0, 0, 0);
    check("setup", descriptor >= 0);
    if (descriptor < 0) return;

    check("ring-address-preserved",
          parameters.cq_off.user_address ==
          (uint64_t)(uintptr_t)g_ring_memory);
    check("sqe-address-preserved",
          parameters.sq_off.user_address ==
          (uint64_t)(uintptr_t)g_sqe_memory);
    check("sq-head-offset", parameters.sq_off.head == 0u);
    check("sq-tail-offset", parameters.sq_off.tail == 4u);
    check("cq-head-offset", parameters.cq_off.head == 8u);
    check("cq-tail-offset", parameters.cq_off.tail == 12u);
    check("sq-mask-offset", parameters.sq_off.ring_mask == 16u);
    check("cq-mask-offset", parameters.cq_off.ring_mask == 20u);
    check("sq-entries-offset", parameters.sq_off.ring_entries == 24u);
    check("cq-entries-offset", parameters.cq_off.ring_entries == 28u);
    check("sq-dropped-offset", parameters.sq_off.dropped == 32u);
    check("sq-flags-offset", parameters.sq_off.flags == 36u);
    check("cq-flags-offset", parameters.cq_off.flags == 40u);
    check("cq-overflow-offset", parameters.cq_off.overflow == 44u);
    check("cqes-offset", parameters.cq_off.cqes == 64u);
    check("sq-array-after-cqes",
          parameters.sq_off.array >=
          parameters.cq_off.cqes +
          parameters.cq_entries * sizeof(struct io_uring_cqe));

    sq_tail = (volatile uint32_t *)(void *)(
        g_ring_memory + parameters.sq_off.tail);
    sq_array = (volatile uint32_t *)(void *)(
        g_ring_memory + parameters.sq_off.array);
    cq_head = (volatile uint32_t *)(void *)(
        g_ring_memory + parameters.cq_off.head);
    cq_tail = (volatile uint32_t *)(void *)(
        g_ring_memory + parameters.cq_off.tail);
    cqes = (struct io_uring_cqe *)(void *)(
        g_ring_memory + parameters.cq_off.cqes);

    sqes[0].opcode = IORING_OP_NOP;
    sqes[0].descriptor = -1;
    sqes[0].user_data = UINT64_C(0x4e4f4d4d4150);
    sq_array[0] = 0u;
    __atomic_store_n(sq_tail, 1u, __ATOMIC_RELEASE);
    result = raw_syscall6(
        SYS_io_uring_enter, descriptor, 1, 1,
        IORING_ENTER_GETEVENTS, 0, 0);
    check_result("enter", result, 1);
    check("completion-ready",
          __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 1u);
    check("completion-user-data",
          cqes[0].user_data == UINT64_C(0x4e4f4d4d4150));
    check("completion-result", cqes[0].result == 0);
    __atomic_store_n(cq_head, 1u, __ATOMIC_RELEASE);

    bytes_zero(g_resized_ring_memory, sizeof(g_resized_ring_memory));
    bytes_zero(g_resized_sqe_memory, sizeof(g_resized_sqe_memory));
    bytes_zero(&resize, sizeof(resize));
    resize.sq_entries = 16u;
    resize.cq_off.user_address =
        (uint64_t)(uintptr_t)g_resized_ring_memory;
    resize.sq_off.user_address =
        (uint64_t)(uintptr_t)g_resized_sqe_memory;
    check_result("resize", raw_syscall6(
                     SYS_io_uring_register, descriptor,
                     IORING_REGISTER_RESIZE_RINGS,
                     (long)&resize, 1, 0, 0), 0);
    check("resize-ring-address-preserved",
          resize.cq_off.user_address ==
          (uint64_t)(uintptr_t)g_resized_ring_memory);
    check("resize-sqe-address-preserved",
          resize.sq_off.user_address ==
          (uint64_t)(uintptr_t)g_resized_sqe_memory);
    check("resize-entries",
          resize.sq_entries == 16u && resize.cq_entries == 32u);
    check("resize-array-offset", resize.sq_off.array == 576u);

    sqes = (struct io_uring_sqe *)(void *)g_resized_sqe_memory;
    sq_tail = (volatile uint32_t *)(void *)(
        g_resized_ring_memory + resize.sq_off.tail);
    sq_array = (volatile uint32_t *)(void *)(
        g_resized_ring_memory + resize.sq_off.array);
    cq_head = (volatile uint32_t *)(void *)(
        g_resized_ring_memory + resize.cq_off.head);
    cq_tail = (volatile uint32_t *)(void *)(
        g_resized_ring_memory + resize.cq_off.tail);
    cqes = (struct io_uring_cqe *)(void *)(
        g_resized_ring_memory + resize.cq_off.cqes);
    sqes[1].opcode = IORING_OP_NOP;
    sqes[1].descriptor = -1;
    sqes[1].user_data = UINT64_C(0x524553495a45);
    sq_array[1] = 1u;
    __atomic_store_n(sq_tail, 2u, __ATOMIC_RELEASE);
    check_result("enter-after-resize", raw_syscall6(
                     SYS_io_uring_enter, descriptor, 1, 1,
                     IORING_ENTER_GETEVENTS, 0, 0), 1);
    check("resized-completion-ready",
          __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) == 2u);
    check("resized-completion-user-data",
          cqes[1].user_data == UINT64_C(0x524553495a45));
    check("resized-completion-result", cqes[1].result == 0);
    __atomic_store_n(cq_head, 2u, __ATOMIC_RELEASE);
    check_result("close", raw_syscall6(
                     SYS_close, descriptor, 0, 0, 0, 0, 0), 0);
}

__attribute__((noreturn)) void _start(void) {
    run_error_order_checks();
    run_nop_check();
    if (!failures) print_text("IO_URING_NO_MMAP_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
