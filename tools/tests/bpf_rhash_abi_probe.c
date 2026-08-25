/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF resizable-hash syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_bpf 321
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_bpf 280
#else
#error "bpf_rhash_abi_probe requires a Linux 64-bit architecture"
#endif

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM 21
#define BPF_MAP_FREEZE 22
#define BPF_MAP_LOOKUP_BATCH 24
#define BPF_MAP_TYPE_RHASH 35
#define BPF_F_NO_PREALLOC (1u << 0)
#define BPF_F_ZERO_SEED (1u << 6)
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define EPERM 1
#define ENOENT 2
#define E2BIG 7
#define EEXIST 17
#define EINVAL 22

struct bpf_map_create_attribute {
    uint32_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_fd;
    uint32_t numa_node;
    char map_name[16];
    uint32_t map_ifindex;
    uint32_t btf_fd;
    uint32_t btf_key_type_id;
    uint32_t btf_value_type_id;
    uint32_t btf_vmlinux_value_type_id;
    uint64_t map_extra;
    uint32_t value_type_btf_obj_fd;
    int32_t map_token_fd;
};

struct bpf_map_element_attribute {
    uint32_t map_fd;
    uint32_t padding;
    uint64_t key;
    uint64_t value;
    uint64_t flags;
};

struct bpf_map_batch_attribute {
    uint64_t input_batch;
    uint64_t output_batch;
    uint64_t keys;
    uint64_t values;
    uint32_t count;
    uint32_t map_fd;
    uint64_t element_flags;
    uint64_t flags;
};

void *memset(void *destination, int value, unsigned long length) {
    volatile unsigned char *bytes = destination;

    while (length--) *bytes++ = (unsigned char)value;
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;

    while (text[length]) ++length;
    return length;
}

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

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
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
    (void)raw_syscall6(
        SYS_write, 1, (long)output, (long)count, 0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected=");
    print_number(expected);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static long create_map(uint32_t max_entries, uint32_t flags,
                       uint64_t map_extra) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = BPF_MAP_TYPE_RHASH;
    attribute.key_size = sizeof(uint32_t);
    attribute.value_size = sizeof(uint64_t);
    attribute.max_entries = max_entries;
    attribute.map_flags = flags;
    attribute.map_extra = map_extra;
    attribute.map_name[0] = 'r';
    attribute.map_name[1] = 'h';
    attribute.map_name[2] = 'a';
    attribute.map_name[3] = 's';
    attribute.map_name[4] = 'h';
    return raw_syscall6(
        SYS_bpf, BPF_MAP_CREATE, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long map_element(long command, int map_fd, uint32_t *key,
                        void *value, uint64_t flags) {
    struct bpf_map_element_attribute attribute = {0};

    attribute.map_fd = (uint32_t)map_fd;
    attribute.key = (uint64_t)(uintptr_t)key;
    attribute.value = (uint64_t)(uintptr_t)value;
    attribute.flags = flags;
    return raw_syscall6(
        SYS_bpf, command, (long)&attribute, sizeof(attribute), 0, 0, 0);
}

static long freeze_map(int map_fd) {
    struct bpf_map_element_attribute attribute = {0};

    attribute.map_fd = (uint32_t)map_fd;
    return raw_syscall6(
        SYS_bpf, BPF_MAP_FREEZE, (long)&attribute,
        sizeof(uint32_t), 0, 0, 0);
}

static long lookup_batch(int map_fd, uint32_t *keys, uint64_t *values,
                         uint32_t *count) {
    struct bpf_map_batch_attribute attribute = {0};
    uint32_t output_batch = 0u;
    long status;

    attribute.output_batch = (uint64_t)(uintptr_t)&output_batch;
    attribute.keys = (uint64_t)(uintptr_t)keys;
    attribute.values = (uint64_t)(uintptr_t)values;
    attribute.count = *count;
    attribute.map_fd = (uint32_t)map_fd;
    status = raw_syscall6(
        SYS_bpf, BPF_MAP_LOOKUP_BATCH, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
    *count = attribute.count;
    return status;
}

static int test_resizable_hash(void) {
    uint32_t keys[] = {10u, 20u, 30u};
    uint64_t values[] = {100u, 200u, 300u};
    uint32_t batch_keys[2] = {0u};
    uint64_t batch_values[2] = {0u};
    uint64_t output = 0u;
    uint32_t next = 0u;
    uint32_t count = 2u;
    long descriptor;
    int failures = 0;

    failures += expect_result(
        "missing-no-prealloc", create_map(2u, 0u, 0u), -EINVAL);
    failures += expect_result(
        "zero-seed", create_map(
            2u, BPF_F_NO_PREALLOC | BPF_F_ZERO_SEED, 0u), -EINVAL);
    failures += expect_result(
        "hint-over-max", create_map(2u, BPF_F_NO_PREALLOC, 3u),
        -EINVAL);
    failures += expect_result(
        "hint-too-large", create_map(
            65536u, BPF_F_NO_PREALLOC, 65536u), -E2BIG);
    failures += expect_result(
        "hint-high-bits", create_map(
            2u, BPF_F_NO_PREALLOC, 1ull << 32u), -EINVAL);
    descriptor = create_map(2u, BPF_F_NO_PREALLOC, 1u);
    if (descriptor < 0)
        return failures + expect_result("create", descriptor, 0);

    failures += expect_result(
        "insert", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                               &keys[0], &values[0], BPF_NOEXIST), 0);
    failures += expect_result(
        "duplicate", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                  &keys[0], &values[0], BPF_NOEXIST),
        -EEXIST);
    failures += expect_result(
        "exist-missing", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                      &keys[1], &values[1], BPF_EXIST),
        -ENOENT);
    failures += expect_result(
        "second", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                               &keys[1], &values[1], BPF_ANY), 0);
    failures += expect_result(
        "full", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                             &keys[2], &values[2], BPF_ANY), -E2BIG);
    failures += expect_result(
        "lookup", map_element(BPF_MAP_LOOKUP_ELEM, descriptor,
                               &keys[0], &output, 0u), 0);
    failures += expect_result("lookup-value", output, values[0]);
    failures += expect_result(
        "next-null", map_element(BPF_MAP_GET_NEXT_KEY, descriptor,
                                  0, &next, 0u), 0);
    failures += expect_result(
        "batch-end", lookup_batch(
            descriptor, batch_keys, batch_values, &count), -ENOENT);
    failures += expect_result("batch-count", count, 2);
    if (!((batch_keys[0] == keys[0] && batch_values[0] == values[0] &&
           batch_keys[1] == keys[1] && batch_values[1] == values[1]) ||
          (batch_keys[0] == keys[1] && batch_values[0] == values[1] &&
           batch_keys[1] == keys[0] && batch_values[1] == values[0]))) {
        print_text("FAIL batch-content\n");
        ++failures;
    }
    failures += expect_result(
        "lookup-delete", map_element(
            BPF_MAP_LOOKUP_AND_DELETE_ELEM, descriptor,
            &keys[0], &output, 0u), 0);
    failures += expect_result("lookup-delete-value", output, values[0]);
    failures += expect_result(
        "delete", map_element(BPF_MAP_DELETE_ELEM, descriptor,
                               &keys[1], 0, 0u), 0);
    failures += expect_result("freeze", freeze_map(descriptor), 0);
    failures += expect_result(
        "frozen-update", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                      &keys[0], &values[0], BPF_ANY),
        -EPERM);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = test_resizable_hash();

    if (failures) {
        print_text("bpf-rhash: FAIL\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("bpf-rhash: PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
