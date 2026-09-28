/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux LSM UAPI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#else
#error "lsm_uapi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_lsm_get_self_attr 459
#define SYS_lsm_set_self_attr 460
#define SYS_lsm_list_modules 461

#define LSM_ID_CAPABILITY 100u
#define LSM_ID_LANDLOCK 110u
#define LSM_ATTR_CURRENT 100u
#define LSM_FLAG_SINGLE 0x0001u

#define E2BIG 7
#define EFAULT 14
#define EINVAL 22
#define EOPNOTSUPP 95

struct lsm_ctx {
    uint64_t id;
    uint64_t flags;
    uint64_t len;
    uint64_t ctx_len;
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
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
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

static int contains_id(const uint64_t *ids, uint32_t count, uint64_t id) {
    uint32_t index;
    for (index = 0; index < count; ++index)
        if (ids[index] == id) return 1;
    return 0;
}

static int run_tests(void) {
    uint64_t ids[32];
    struct lsm_ctx context = {
        .id = LSM_ID_LANDLOCK,
        .flags = 0,
        .len = sizeof(struct lsm_ctx),
        .ctx_len = 0,
    };
    uint32_t size = 0;
    long count;
    int failures = 0;

    failures += expect(
        "list sizing",
        raw_syscall6(SYS_lsm_list_modules, 0, (long)&size, 0, 0, 0, 0),
        -E2BIG);
    failures += expect_true(
        "list required size", size >= 2u * sizeof(uint64_t) &&
                              size <= sizeof(ids) &&
                              size % sizeof(uint64_t) == 0);
    size = sizeof(ids);
    count = raw_syscall6(
        SYS_lsm_list_modules, (long)ids, (long)&size, 0, 0, 0, 0);
    failures += expect_true("list count", count >= 2 &&
                            size == (uint32_t)count * sizeof(uint64_t));
    if (count > 0 && count <= 32) {
        failures += expect_true(
            "capability module", contains_id(ids, (uint32_t)count,
                                              LSM_ID_CAPABILITY));
        failures += expect_true(
            "landlock module", contains_id(ids, (uint32_t)count,
                                            LSM_ID_LANDLOCK));
    }
    failures += expect(
        "list flags",
        raw_syscall6(
            SYS_lsm_list_modules, (long)ids, (long)&size, 1, 0, 0, 0),
        -EINVAL);
    failures += expect(
        "list missing size",
        raw_syscall6(SYS_lsm_list_modules, (long)ids, 0, 0, 0, 0, 0),
        -EFAULT);

    size = sizeof(context);
    failures += expect(
        "landlock get attribute",
        raw_syscall6(
            SYS_lsm_get_self_attr, LSM_ATTR_CURRENT, (long)&context,
            (long)&size, LSM_FLAG_SINGLE, 0, 0),
        -EOPNOTSUPP);
    failures += expect("landlock get size", size, 0);
    failures += expect(
        "get undefined attribute",
        raw_syscall6(
            SYS_lsm_get_self_attr, 0, (long)&context,
            (long)&size, LSM_FLAG_SINGLE, 0, 0),
        -EINVAL);
    failures += expect(
        "get missing size",
        raw_syscall6(
            SYS_lsm_get_self_attr, LSM_ATTR_CURRENT,
            (long)&context, 0, LSM_FLAG_SINGLE, 0, 0),
        -EINVAL);

    failures += expect(
        "landlock set attribute",
        raw_syscall6(
            SYS_lsm_set_self_attr, LSM_ATTR_CURRENT, (long)&context,
            sizeof(context), 0, 0, 0),
        -EOPNOTSUPP);
    failures += expect(
        "set flags",
        raw_syscall6(
            SYS_lsm_set_self_attr, LSM_ATTR_CURRENT, (long)&context,
            sizeof(context), 1, 0, 0),
        -EINVAL);
    failures += expect(
        "set short context",
        raw_syscall6(
            SYS_lsm_set_self_attr, LSM_ATTR_CURRENT, (long)&context,
            sizeof(context) - 1u, 0, 0, 0),
        -EINVAL);
    failures += expect(
        "set oversized context",
        raw_syscall6(
            SYS_lsm_set_self_attr, LSM_ATTR_CURRENT, (long)&context,
            4097, 0, 0, 0),
        -E2BIG);
    failures += expect(
        "set missing context",
        raw_syscall6(
            SYS_lsm_set_self_attr, LSM_ATTR_CURRENT, 0,
            sizeof(context), 0, 0, 0),
        -EFAULT);
    context.len = sizeof(context) - 1u;
    failures += expect(
        "set invalid context length",
        raw_syscall6(
            SYS_lsm_set_self_attr, LSM_ATTR_CURRENT, (long)&context,
            sizeof(context), 0, 0, 0),
        -EINVAL);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    print_text(failures ? "LSM_UAPI_PROBE_FAIL\n" :
                          "LSM_UAPI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
