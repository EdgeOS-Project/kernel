/* SPDX-License-Identifier: MPL-2.0 */
/* Linux 7.2 io_uring NAPI registration ABI probe. */

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
#error "io_uring_napi_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_register 427

#define EOPNOTSUPP 95
#define EINVAL 22
#define EEXIST 17
#define ENOENT 2

#define IORING_REGISTER_NAPI 27u
#define IORING_UNREGISTER_NAPI 28u
#define IO_URING_NAPI_REGISTER_OP 0u
#define IO_URING_NAPI_STATIC_ADD_ID 1u
#define IO_URING_NAPI_STATIC_DEL_ID 2u
#define IO_URING_NAPI_TRACKING_DYNAMIC 0u
#define IO_URING_NAPI_TRACKING_STATIC 1u
#define IO_URING_NAPI_TRACKING_INACTIVE 255u

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

struct io_uring_napi {
    uint32_t busy_poll_to;
    uint8_t prefer_busy_poll;
    uint8_t opcode;
    uint8_t padding[2];
    uint32_t operation_parameter;
    uint32_t reserved;
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

static int failures;

static void check(const char *name, int condition) {
    if (condition) return;
    ++failures;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
}

static int run_probe(void) {
    struct io_uring_params parameters;
    struct io_uring_napi napi;
    long result;
    long ring;

    bytes_zero(&parameters, sizeof(parameters));
    ring = raw_syscall6(
        SYS_io_uring_setup, 4, (long)&parameters, 0, 0, 0, 0);
    check("setup", ring >= 0);
    if (ring < 0) return failures;

    bytes_zero(&napi, sizeof(napi));
    napi.busy_poll_to = 15000u;
    napi.prefer_busy_poll = 2u;
    napi.operation_parameter = IO_URING_NAPI_TRACKING_DYNAMIC;
    result = raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0);
    if (result == -EOPNOTSUPP) {
        check("disabled unregister", raw_syscall6(
            SYS_io_uring_register, ring, IORING_UNREGISTER_NAPI,
            (long)&napi, 1, 0, 0) == -EOPNOTSUPP);
        print_text("IO_URING_NAPI_ABI_PROBE_DISABLED\n");
        (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
        return failures;
    }
    check("dynamic registration", result == 0);
    check("initial state returned",
          napi.prefer_busy_poll == 0u &&
          napi.operation_parameter == IO_URING_NAPI_TRACKING_INACTIVE);

    bytes_zero(&napi, sizeof(napi));
    napi.busy_poll_to = 127u;
    napi.prefer_busy_poll = 1u;
    napi.operation_parameter = IO_URING_NAPI_TRACKING_STATIC;
    check("static registration", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == 0);
    check("previous state returned",
          napi.busy_poll_to == 10000u &&
          napi.prefer_busy_poll == 1u &&
          napi.operation_parameter == IO_URING_NAPI_TRACKING_DYNAMIC);

    bytes_zero(&napi, sizeof(napi));
    napi.opcode = IO_URING_NAPI_STATIC_ADD_ID;
    napi.operation_parameter = 2u;
    check("live receive context", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == 0);
    bytes_zero(&napi, sizeof(napi));
    napi.opcode = IO_URING_NAPI_STATIC_ADD_ID;
    napi.operation_parameter = 2u;
    check("duplicate receive context", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == -EEXIST);
    bytes_zero(&napi, sizeof(napi));
    napi.opcode = IO_URING_NAPI_STATIC_DEL_ID;
    napi.operation_parameter = 2u;
    check("delete receive context", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == 0);
    bytes_zero(&napi, sizeof(napi));
    napi.opcode = IO_URING_NAPI_STATIC_DEL_ID;
    napi.operation_parameter = 2u;
    check("missing receive context", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == -ENOENT);

    bytes_zero(&napi, sizeof(napi));
    napi.opcode = IO_URING_NAPI_STATIC_ADD_ID;
    check("invalid static id", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == -EINVAL);
    check("state returned before operation error",
          napi.busy_poll_to == 127u && napi.prefer_busy_poll == 1u &&
          napi.operation_parameter == IO_URING_NAPI_TRACKING_STATIC);

    bytes_zero(&napi, sizeof(napi));
    napi.padding[0] = 1u;
    check("reserved input", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == -EINVAL);
    check("reserved failure keeps input", napi.padding[0] == 1u);
    check("register null", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        0, 1, 0, 0) == -EINVAL);
    check("register count", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 0, 0, 0) == -EINVAL);

    bytes_zero(&napi, sizeof(napi));
    check("unregister output", raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_NAPI,
        (long)&napi, 1, 0, 0) == 0);
    check("unregister returned state",
          napi.busy_poll_to == 127u && napi.prefer_busy_poll == 1u &&
          napi.opcode == 0u && napi.operation_parameter == 0u);
    check("unregister null", raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_NAPI,
        0, 1, 0, 0) == 0);
    check("unregister count", raw_syscall6(
        SYS_io_uring_register, ring, IORING_UNREGISTER_NAPI,
        0, 0, 0, 0) == -EINVAL);

    bytes_zero(&napi, sizeof(napi));
    napi.operation_parameter = IO_URING_NAPI_TRACKING_DYNAMIC;
    check("registration after unregister", raw_syscall6(
        SYS_io_uring_register, ring, IORING_REGISTER_NAPI,
        (long)&napi, 1, 0, 0) == 0);
    check("inactive state restored",
          napi.busy_poll_to == 0u && napi.prefer_busy_poll == 0u &&
          napi.operation_parameter == IO_URING_NAPI_TRACKING_INACTIVE);

    (void)raw_syscall6(SYS_close, ring, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int result = run_probe();
    if (!result) print_text("IO_URING_NAPI_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, result ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
