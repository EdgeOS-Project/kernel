/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux listns ABI and namespace-ID consistency probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_exit 60
#define SYS_setuid 105
#define SYS_openat 257
#define SYS_unshare 272
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_unshare 97
#define SYS_setuid 146
#define SYS_ioctl 29
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "listns_abi_probe requires a Linux 64-bit architecture"
#endif

#define SYS_listns 470

#define AT_FDCWD (-100)
#define O_RDONLY 0u
#define O_CLOEXEC 0x80000u

#define E2BIG 7
#define EFAULT 14
#define EINVAL 22
#define EOVERFLOW 75
#define ENOENT 2
#define EOPNOTSUPP 95

#define CLONE_NEWTIME 0x00000080u
#define CLONE_NEWNS 0x00020000u
#define CLONE_NEWUTS 0x04000000u
#define LISTNS_CURRENT_USER UINT64_MAX
#define NS_GET_ID 0x8008b70du

struct ns_id_req {
    uint32_t size;
    uint32_t spare;
    uint64_t ns_id;
    uint32_t ns_type;
    uint32_t spare2;
    uint64_t user_ns_id;
};

struct extended_ns_id_req {
    struct ns_id_req request;
    uint64_t extension;
};

_Static_assert(sizeof(struct ns_id_req) == 32,
               "Linux ns_id_req ABI size");

static uint64_t g_namespace_ids[32];

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
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
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
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count,
                       0, 0, 0);
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

static long list_namespaces(struct ns_id_req *request,
                            uint64_t *ids, unsigned long count,
                            unsigned int flags) {
    return raw_syscall6(SYS_listns, (long)request, (long)ids,
                        (long)count, flags, 0, 0);
}

static int test_validation(void) {
    struct extended_ns_id_req extended;
    int failures = 0;

    memset(&extended, 0, sizeof(extended));
    extended.request.size = sizeof(extended.request);
    failures += expect_result(
        "flags precede count",
        list_namespaces(0, 0, 1000001u, 1), -EINVAL);
    failures += expect_result(
        "maximum count", list_namespaces(0, 0, 1000001u, 0),
        -EOVERFLOW);
    failures += expect_result(
        "output precedes request",
        list_namespaces(0, 0, 1, 0), -EFAULT);
    failures += expect_result(
        "null request", list_namespaces(0, 0, 0, 0), -EFAULT);

    extended.request.size = 4097;
    failures += expect_result(
        "oversize request",
        list_namespaces(&extended.request, g_namespace_ids, 1, 0),
        -E2BIG);
    extended.request.size = 31;
    failures += expect_result(
        "undersize request",
        list_namespaces(&extended.request, g_namespace_ids, 1, 0),
        -EINVAL);
    extended.request.size = sizeof(extended);
    extended.extension = 1;
    failures += expect_result(
        "nonzero extension",
        list_namespaces(&extended.request, g_namespace_ids, 1, 0),
        -E2BIG);
    extended.extension = 0;
    extended.request.spare = 1;
    failures += expect_result(
        "nonzero spare",
        list_namespaces(&extended.request, g_namespace_ids, 1, 0),
        -EINVAL);
    extended.request.spare = 0;
    extended.request.ns_type = 1;
    failures += expect_result(
        "unknown namespace type",
        list_namespaces(&extended.request, g_namespace_ids, 1, 0),
        -EOPNOTSUPP);
    extended.request.ns_type = 0;
    extended.request.spare2 = 1;
    failures += expect_true(
        "spare2 ignored",
        list_namespaces(&extended.request, g_namespace_ids, 1, 0) == 1);
    return failures;
}

static int test_initial_tree(void) {
    struct ns_id_req request;
    long listed;
    int failures = 0;

    memset(&request, 0, sizeof(request));
    request.size = sizeof(request);
    listed = list_namespaces(&request, g_namespace_ids, 32, 0);
    failures += expect_result("initial namespace count", listed, 8);
    if (listed == 8) {
        for (long index = 0; index < listed; ++index)
            failures += expect_true(
                "initial namespace order",
                g_namespace_ids[index] == (uint64_t)index + 1u);
    }

    request.ns_type = CLONE_NEWUTS;
    listed = list_namespaces(&request, g_namespace_ids, 32, 0);
    failures += expect_result("UTS namespace count", listed, 1);
    failures += expect_true("UTS namespace ID",
                            listed == 1 && g_namespace_ids[0] == 2);
    request.ns_type = CLONE_NEWUTS | CLONE_NEWNS;
    listed = list_namespaces(&request, g_namespace_ids, 32, 0);
    failures += expect_result("multi-type namespace count", listed, 2);
    failures += expect_true(
        "multi-type namespace IDs",
        listed == 2 && g_namespace_ids[0] == 2 &&
        g_namespace_ids[1] == 8);

    request.ns_type = 0;
    request.ns_id = 7;
    listed = list_namespaces(&request, g_namespace_ids, 1, 0);
    failures += expect_result("pagination count", listed, 1);
    failures += expect_true("pagination ID",
                            listed == 1 && g_namespace_ids[0] == 8);
    request.ns_id = 8;
    failures += expect_result(
        "pagination end",
        list_namespaces(&request, g_namespace_ids, 1, 0), -ENOENT);
    failures += expect_result(
        "zero capacity at end", list_namespaces(&request, 0, 0, 0),
        -ENOENT);
    request.ns_id = 0;
    failures += expect_result(
        "zero capacity at root", list_namespaces(&request, 0, 0, 0), 0);

    request.user_ns_id = LISTNS_CURRENT_USER;
    listed = list_namespaces(&request, g_namespace_ids, 32, 0);
    failures += expect_result("current owner count", listed, 7);
    if (listed == 7) {
        failures += expect_true(
            "initial user namespace has no owner",
            g_namespace_ids[0] == 1 && g_namespace_ids[1] == 2 &&
            g_namespace_ids[2] == 4 && g_namespace_ids[6] == 8);
    }
    request.user_ns_id = UINT64_C(0x7fffffffffffffff);
    failures += expect_result(
        "invalid owner namespace",
        list_namespaces(&request, g_namespace_ids, 1, 0), -EINVAL);
    return failures;
}

static int test_dynamic_namespace(void) {
    static const char uts_path[] = "/proc/self/ns/uts";
    struct ns_id_req request;
    uint64_t old_id = 0;
    uint64_t current_id = 0;
    uint64_t dynamic_id = 0;
    long old_fd;
    long current_fd;
    long listed;
    int failures = 0;

    old_fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)uts_path,
                          O_RDONLY | O_CLOEXEC, 0, 0, 0);
    failures += expect_true("open initial UTS namespace", old_fd >= 0);
    if (old_fd >= 0) {
        failures += expect_result(
            "initial NS_GET_ID",
            raw_syscall6(SYS_ioctl, old_fd, NS_GET_ID,
                         (long)&old_id, 0, 0, 0), 0);
        failures += expect_true("initial ioctl namespace ID", old_id == 2);
    }

    failures += expect_result(
        "unshare UTS namespace",
        raw_syscall6(SYS_unshare, CLONE_NEWUTS, 0, 0, 0, 0, 0), 0);
    memset(&request, 0, sizeof(request));
    request.size = sizeof(request);
    request.ns_type = CLONE_NEWUTS;
    listed = list_namespaces(&request, g_namespace_ids, 32, 0);
    failures += expect_result("dynamic UTS count", listed, 2);
    if (listed == 2) {
        failures += expect_true(
            "dynamic UTS ordering",
            g_namespace_ids[0] == 2 && g_namespace_ids[1] > 8);
        dynamic_id = g_namespace_ids[1];
    }

    current_fd = raw_syscall6(SYS_openat, AT_FDCWD, (long)uts_path,
                              O_RDONLY | O_CLOEXEC, 0, 0, 0);
    failures += expect_true("open dynamic UTS namespace", current_fd >= 0);
    if (current_fd >= 0) {
        failures += expect_result(
            "dynamic NS_GET_ID",
            raw_syscall6(SYS_ioctl, current_fd, NS_GET_ID,
                         (long)&current_id, 0, 0, 0), 0);
        failures += expect_true(
            "listns and ioctl use the same ID",
            dynamic_id > 8 && current_id == dynamic_id);
        (void)raw_syscall6(SYS_close, current_fd, 0, 0, 0, 0, 0);
    }
    failures += expect_result(
        "drop namespace privilege",
        raw_syscall6(SYS_setuid, 65534, 0, 0, 0, 0, 0), 0);
    listed = list_namespaces(&request, g_namespace_ids, 32, 0);
    failures += expect_result(
        "unprivileged UTS visibility", listed, 1);
    failures += expect_true(
        "unprivileged list exposes only current namespace",
        listed == 1 && g_namespace_ids[0] == dynamic_id);
    if (old_fd >= 0)
        (void)raw_syscall6(SYS_close, old_fd, 0, 0, 0, 0, 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = 0;
    failures += test_validation();
    failures += test_initial_tree();
    failures += test_dynamic_namespace();
    print_text(failures ? "LISTNS_ABI_PROBE_FAILED\n" :
                          "LISTNS_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
