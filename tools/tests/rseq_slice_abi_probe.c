/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux rseq v2 and time-slice extension ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#define SYS_clone 56
#define SYS_prctl 157
#define SYS_rseq 334
#define START_ATTRIBUTES __attribute__((naked, noreturn))
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_clone 220
#define SYS_prctl 167
#define SYS_rseq 293
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "rseq_slice_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_rseq_slice_yield 471

#define ENXIO 6
#define EINVAL 22
#define EOPNOTSUPP 95

#define RSEQ_FLAG_UNREGISTER 1u
#define RSEQ_FLAG_SLICE_EXT_DEFAULT_ON 2u
#define RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE (1u << 4)
#define RSEQ_CS_FLAG_SLICE_EXT_ENABLED (1u << 5)
#define RSEQ_SIGNATURE 0x53053053u

#define PR_RSEQ_SLICE_EXTENSION 79u
#define PR_RSEQ_SLICE_EXTENSION_GET 1u
#define PR_RSEQ_SLICE_EXTENSION_SET 2u
#define PR_RSEQ_SLICE_EXT_ENABLE 1u

struct linux_rseq_v2 {
    uint32_t cpu_id_start;
    uint32_t cpu_id;
    uint64_t rseq_cs;
    uint32_t flags;
    uint32_t node_id;
    uint32_t mm_cid;
    uint32_t slice_ctrl;
    uint8_t reserved;
} __attribute__((aligned(32)));

static struct linux_rseq_v2 rseq_area;

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
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[24];
    unsigned long magnitude;
    unsigned long count = 0;
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    for (unsigned long left = 0, right = count - 1u; left < right;
         ++left, --right) {
        char temporary = output[left];
        output[left] = output[right];
        output[right] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static void clear_area(void) {
    uint8_t *bytes = (uint8_t *)(void *)&rseq_area;
    for (unsigned long index = 0; index < sizeof(rseq_area); ++index)
        bytes[index] = 0;
}

static long rseq_call(uint32_t length, uint32_t flags) {
    return raw_syscall6(SYS_rseq, (long)&rseq_area, length, flags,
                        RSEQ_SIGNATURE, 0, 0);
}

static long slice_prctl(uint64_t operation, uint64_t value) {
    return raw_syscall6(SYS_prctl, PR_RSEQ_SLICE_EXTENSION,
                        operation, value, 0, 0, 0);
}

static int run_probe(void) {
    int failures = 0;
    long child;

    failures += expect_result(
        "yield without grant",
        raw_syscall6(SYS_rseq_slice_yield, 0, 0, 0, 0, 0, 0), 0);
    failures += expect_result(
        "get extra argument",
        slice_prctl(PR_RSEQ_SLICE_EXTENSION_GET, 1), -EINVAL);
    failures += expect_result(
        "get trailing argument",
        raw_syscall6(SYS_prctl, PR_RSEQ_SLICE_EXTENSION,
                     PR_RSEQ_SLICE_EXTENSION_GET, 0, 1, 0, 0), -EINVAL);
    failures += expect_result(
        "set before registration",
        slice_prctl(PR_RSEQ_SLICE_EXTENSION_SET,
                    PR_RSEQ_SLICE_EXT_ENABLE), -ENXIO);

    clear_area();
    failures += expect_result("legacy register", rseq_call(32, 0), 0);
    failures += expect_result(
        "legacy set unsupported",
        slice_prctl(PR_RSEQ_SLICE_EXTENSION_SET,
                    PR_RSEQ_SLICE_EXT_ENABLE), -EOPNOTSUPP);
    failures += expect_result(
        "legacy unregister", rseq_call(32, RSEQ_FLAG_UNREGISTER), 0);

    clear_area();
    failures += expect_result(
        "v2 register default enabled",
        rseq_call(33, RSEQ_FLAG_SLICE_EXT_DEFAULT_ON), 0);
    failures += expect_true(
        "v2 flags advertised",
        (rseq_area.flags &
         (RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE |
          RSEQ_CS_FLAG_SLICE_EXT_ENABLED)) ==
        (RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE |
         RSEQ_CS_FLAG_SLICE_EXT_ENABLED));
    failures += expect_result("v2 control initialized", rseq_area.slice_ctrl, 0);
    failures += expect_result(
        "get enabled", slice_prctl(PR_RSEQ_SLICE_EXTENSION_GET, 0), 1);
    failures += expect_result(
        "disable", slice_prctl(PR_RSEQ_SLICE_EXTENSION_SET, 0), 0);
    failures += expect_result(
        "get disabled", slice_prctl(PR_RSEQ_SLICE_EXTENSION_GET, 0), 0);
    failures += expect_true(
        "enabled flag cleared",
        (rseq_area.flags & RSEQ_CS_FLAG_SLICE_EXT_ENABLED) == 0);
    failures += expect_result(
        "set unknown flag",
        slice_prctl(PR_RSEQ_SLICE_EXTENSION_SET, 2), -EINVAL);
    failures += expect_result(
        "enable",
        slice_prctl(PR_RSEQ_SLICE_EXTENSION_SET,
                    PR_RSEQ_SLICE_EXT_ENABLE), 0);
    failures += expect_result(
        "yield without request",
        raw_syscall6(SYS_rseq_slice_yield, 0, 0, 0, 0, 0, 0), 0);

    child = raw_syscall6(SYS_clone, 17, 0, 0, 0, 0, 0);
    if (child == 0) {
        volatile uint64_t spin = 0;
        for (;;) ++spin;
    }
    failures += expect_true("clone competitor", child > 0);
    if (child > 0) {
        uint64_t polls = 0;
        rseq_area.slice_ctrl = 1u;
        __asm__ volatile("" ::: "memory");
        while (rseq_area.slice_ctrl != 0x100u &&
               polls++ < 200000000u)
            __asm__ volatile("" ::: "memory");
        failures += expect_result(
            "slice granted", rseq_area.slice_ctrl, 0x100u);
        if (rseq_area.slice_ctrl == 0x100u)
            failures += expect_result(
                "yield granted slice",
                raw_syscall6(SYS_rseq_slice_yield, 0, 0, 0, 0, 0, 0), 1);

        polls = 0;
        rseq_area.slice_ctrl = 1u;
        __asm__ volatile("" ::: "memory");
        while (rseq_area.slice_ctrl != 0x100u &&
               polls++ < 200000000u)
            __asm__ volatile("" ::: "memory");
        failures += expect_result(
            "second slice granted", rseq_area.slice_ctrl, 0x100u);
        polls = 0;
        while (rseq_area.slice_ctrl == 0x100u &&
               polls++ < 200000000u)
            __asm__ volatile("" ::: "memory");
        failures += expect_result(
            "expired slice revoked", rseq_area.slice_ctrl, 0);
        failures += expect_result(
            "yield expired slice",
            raw_syscall6(SYS_rseq_slice_yield, 0, 0, 0, 0, 0, 0), 0);
    }
    failures += expect_result(
        "v2 unregister", rseq_call(33, RSEQ_FLAG_UNREGISTER), 0);

    clear_area();
    failures += expect_result(
        "unknown registration flag", rseq_call(33, 4), -EINVAL);

    print_text(failures ? "RSEQ_SLICE_ABI_PROBE_FAILED\n" :
                          "RSEQ_SLICE_ABI_PROBE_PASS\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall6(SYS_exit, run_probe(), 0, 0, 0, 0, 0);
    for (;;) {}
}

#if defined(__x86_64__)
START_ATTRIBUTES void _start(void) {
    __asm__ volatile("andq $-16, %rsp\ncall probe_entry");
}
#else
START_ATTRIBUTES void _start(void) {
    probe_entry();
}
#endif
