/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF device-map syscall ABI probe. */

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
#error "bpf_devmap_abi_probe requires a Linux 64-bit architecture"
#endif

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_PROG_LOAD 5
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM 21
#define BPF_MAP_FREEZE 22
#define BPF_MAP_LOOKUP_BATCH 24
#define BPF_MAP_TYPE_DEVMAP 14
#define BPF_MAP_TYPE_DEVMAP_HASH 25
#define BPF_PROG_TYPE_CGROUP_DEVICE 15
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define EPERM 1
#define ENOENT 2
#define E2BIG 7
#define EEXIST 17
#define EINVAL 22
#define ENOTSUPP 524

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

struct devmap_value {
    uint32_t ifindex;
    int32_t program_fd;
};

struct bpf_instruction {
    uint8_t code;
    uint8_t registers;
    int16_t offset;
    int32_t immediate;
};

struct bpf_program_load_attribute {
    uint32_t program_type;
    uint32_t instruction_count;
    uint64_t instructions;
    uint64_t license;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buffer;
    uint32_t kernel_version;
    uint32_t program_flags;
    char program_name[16];
    uint32_t program_ifindex;
    uint32_t expected_attach_type;
};

void *memset(void *destination, int value, unsigned long length) {
    volatile unsigned char *bytes =
        (volatile unsigned char *)destination;

    while (length--) *bytes++ = (unsigned char)value;
    return destination;
}

unsigned long strlen(const char *text) {
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
        SYS_write, 1, (long)text, (long)strlen(text), 0, 0, 0);
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

static long create_map(uint32_t type, uint32_t key_size,
                       uint32_t value_size, uint32_t max_entries,
                       uint32_t flags) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = type;
    attribute.key_size = key_size;
    attribute.value_size = value_size;
    attribute.max_entries = max_entries;
    attribute.map_flags = flags;
    attribute.map_name[0] = 'd';
    attribute.map_name[1] = 'e';
    attribute.map_name[2] = 'v';
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
        SYS_bpf, command, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long map_batch(int map_fd, uint32_t *output_batch,
                      uint32_t *keys, uint32_t *values,
                      uint32_t *count) {
    struct bpf_map_batch_attribute attribute = {0};
    long result;

    attribute.output_batch = (uint64_t)(uintptr_t)output_batch;
    attribute.keys = (uint64_t)(uintptr_t)keys;
    attribute.values = (uint64_t)(uintptr_t)values;
    attribute.count = *count;
    attribute.map_fd = (uint32_t)map_fd;
    result = raw_syscall6(
        SYS_bpf, BPF_MAP_LOOKUP_BATCH, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
    *count = attribute.count;
    return result;
}

static int test_array_devmap(void) {
    static const struct bpf_instruction instructions[] = {
        {0xb7u, 0u, 0, 1},
        {0x95u, 0u, 0, 0},
    };
    static const char license[] = "GPL";
    struct devmap_value extended = {1u, -1};
    uint32_t value = 1u;
    uint32_t key = 0u;
    uint32_t next = UINT32_MAX;
    uint32_t cursor = UINT32_MAX;
    uint32_t keys[2] = {UINT32_MAX, UINT32_MAX};
    uint32_t values[2] = {0u, 0u};
    uint32_t count = 2u;
    long descriptor;
    long extended_descriptor;
    long program_descriptor;
    int failures = 0;

    failures += expect_result(
        "array-bad-key", create_map(BPF_MAP_TYPE_DEVMAP, 8u, 4u, 2u, 0u),
        -EINVAL);
    failures += expect_result(
        "array-bad-value", create_map(BPF_MAP_TYPE_DEVMAP, 4u, 16u, 2u, 0u),
        -EINVAL);
    descriptor = create_map(BPF_MAP_TYPE_DEVMAP, 4u, 4u, 2u, 0u);
    if (descriptor < 0) return failures +
        expect_result("array-create", descriptor, 0);
    failures += expect_result(
        "array-empty", map_element(BPF_MAP_LOOKUP_ELEM, descriptor,
                                    &key, &value, 0u), -ENOENT);
    failures += expect_result(
        "array-noexist", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                      &key, &value, BPF_NOEXIST), -EEXIST);
    failures += expect_result(
        "array-update-lo", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                        &key, &value, BPF_ANY), 0);
    value = 0u;
    failures += expect_result(
        "array-lookup-lo", map_element(BPF_MAP_LOOKUP_ELEM, descriptor,
                                        &key, &value, 0u), 0);
    failures += expect_result("array-value-lo", value, 1);
    value = UINT32_MAX;
    failures += expect_result(
        "array-bad-ifindex", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                          &key, &value, BPF_ANY), -EINVAL);
    key = 2u;
    value = 1u;
    failures += expect_result(
        "array-outside-update", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                             &key, &value, BPF_ANY), -E2BIG);
    failures += expect_result(
        "array-outside-delete", map_element(BPF_MAP_DELETE_ELEM, descriptor,
                                             &key, 0, 0u), -EINVAL);
    key = 0u;
    value = 0u;
    failures += expect_result(
        "array-zero-clears", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                          &key, &value, BPF_ANY), 0);
    failures += expect_result(
        "array-delete-empty", map_element(BPF_MAP_DELETE_ELEM, descriptor,
                                           &key, 0, 0u), 0);
    failures += expect_result(
        "array-next-null", map_element(BPF_MAP_GET_NEXT_KEY, descriptor,
                                        0, &next, 0u), 0);
    failures += expect_result("array-next-zero", next, 0);
    key = 1u;
    failures += expect_result(
        "array-next-last", map_element(BPF_MAP_GET_NEXT_KEY, descriptor,
                                        &key, &next, 0u), -ENOENT);
    failures += expect_result(
        "array-lookup-delete", map_element(
            BPF_MAP_LOOKUP_AND_DELETE_ELEM, descriptor, &key, &value, 0u),
        -ENOTSUPP);
    failures += expect_result(
        "array-batch", map_batch(descriptor, &cursor, keys, values, &count),
        -ENOTSUPP);
    {
        struct bpf_map_element_attribute freeze = {0};
        freeze.map_fd = (uint32_t)descriptor;
        failures += expect_result(
            "array-freeze", raw_syscall6(SYS_bpf, BPF_MAP_FREEZE,
                                          (long)&freeze, sizeof(freeze),
                                          0, 0, 0), 0);
    }
    key = 2u;
    value = UINT32_MAX;
    failures += expect_result(
        "array-frozen-order", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                           &key, &value, BPF_ANY), -EPERM);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

    extended_descriptor = create_map(
        BPF_MAP_TYPE_DEVMAP, 4u, sizeof(extended), 2u, 0u);
    if (extended_descriptor < 0) return failures +
        expect_result("array-extended-create", extended_descriptor, 0);
    key = 0u;
    failures += expect_result(
        "array-negative-program", map_element(
            BPF_MAP_UPDATE_ELEM, extended_descriptor, &key, &extended,
            BPF_ANY), 0);
    memset(&extended, 0xff, sizeof(extended));
    failures += expect_result(
        "array-extended-lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, extended_descriptor, &key, &extended, 0u),
        0);
    failures += expect_result("array-program-id", extended.program_fd, 0);
    extended.ifindex = 1u;
    extended.program_fd = 9999;
    failures += expect_result(
        "array-bad-program", map_element(
            BPF_MAP_UPDATE_ELEM, extended_descriptor, &key, &extended,
            BPF_ANY), -EINVAL);
    {
        struct bpf_program_load_attribute program = {0};

        program.program_type = BPF_PROG_TYPE_CGROUP_DEVICE;
        program.instruction_count =
            sizeof(instructions) / sizeof(instructions[0]);
        program.instructions = (uint64_t)(uintptr_t)instructions;
        program.license = (uint64_t)(uintptr_t)license;
        program.program_name[0] = 'd';
        program.program_name[1] = 'e';
        program.program_name[2] = 'v';
        program_descriptor = raw_syscall6(
            SYS_bpf, BPF_PROG_LOAD, (long)&program,
            sizeof(program), 0, 0, 0);
    }
    if (program_descriptor < 0) {
        failures += expect_result(
            "array-program-load", program_descriptor, 0);
    } else {
        extended.program_fd = (int32_t)program_descriptor;
        failures += expect_result(
            "array-wrong-program", map_element(
                BPF_MAP_UPDATE_ELEM, extended_descriptor, &key,
                &extended, BPF_ANY), -EINVAL);
        (void)raw_syscall6(
            SYS_close, program_descriptor, 0, 0, 0, 0, 0);
    }
    extended.ifindex = 0u;
    extended.program_fd = 9999;
    failures += expect_result(
        "array-zero-with-program", map_element(
            BPF_MAP_UPDATE_ELEM, extended_descriptor, &key, &extended,
            BPF_ANY), -EINVAL);
    (void)raw_syscall6(
        SYS_close, extended_descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int test_hash_devmap(void) {
    uint32_t value = 1u;
    uint32_t key = 42u;
    uint32_t next = UINT32_MAX;
    long descriptor;
    int failures = 0;

    descriptor = create_map(BPF_MAP_TYPE_DEVMAP_HASH, 4u, 4u, 1u, 0u);
    if (descriptor < 0) return expect_result("hash-create", descriptor, 0);
    failures += expect_result(
        "hash-insert", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                    &key, &value, BPF_NOEXIST), 0);
    failures += expect_result(
        "hash-noexist-existing", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                              &key, &value, BPF_NOEXIST),
        -EEXIST);
    key = 43u;
    failures += expect_result(
        "hash-full", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                  &key, &value, BPF_ANY), -E2BIG);
    key = 42u;
    failures += expect_result(
        "hash-next-null", map_element(BPF_MAP_GET_NEXT_KEY, descriptor,
                                       0, &next, 0u), 0);
    failures += expect_result("hash-next-key", next, 42);
    failures += expect_result(
        "hash-exist-replace", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                           &key, &value, BPF_EXIST), 0);
    failures += expect_result(
        "hash-delete", map_element(BPF_MAP_DELETE_ELEM, descriptor,
                                    &key, 0, 0u), 0);
    failures += expect_result(
        "hash-delete-empty", map_element(BPF_MAP_DELETE_ELEM, descriptor,
                                          &key, 0, 0u), -ENOENT);
    value = 0u;
    failures += expect_result(
        "hash-zero-ifindex", map_element(BPF_MAP_UPDATE_ELEM, descriptor,
                                          &key, &value, BPF_ANY), -EINVAL);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = test_array_devmap() + test_hash_devmap();

    if (failures) {
        print_text("bpf-devmap: FAIL\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("bpf-devmap: PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
