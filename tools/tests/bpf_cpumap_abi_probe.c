/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF CPU-map syscall ABI probe. */

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
#error "bpf_cpumap_abi_probe requires a Linux 64-bit architecture"
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
#define BPF_MAP_LOOKUP_AND_DELETE_BATCH 25
#define BPF_MAP_TYPE_CPUMAP 16
#define BPF_PROG_TYPE_CGROUP_DEVICE 15
#define BPF_ANY 0
#define BPF_NOEXIST 1

#define ENOENT 2
#define EPERM 1
#define E2BIG 7
#define EBADF 9
#define EEXIST 17
#define ENODEV 19
#define EINVAL 22
#define EOVERFLOW 75
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

struct cpumap_value {
    uint32_t qsize;
    int32_t program_fd;
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

static long create_map(uint32_t key_size, uint32_t value_size,
                       uint32_t max_entries) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = BPF_MAP_TYPE_CPUMAP;
    attribute.key_size = key_size;
    attribute.value_size = value_size;
    attribute.max_entries = max_entries;
    attribute.map_name[0] = 'c';
    attribute.map_name[1] = 'p';
    attribute.map_name[2] = 'u';
    return raw_syscall6(
        SYS_bpf, BPF_MAP_CREATE, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long map_element(long command, int map_fd, uint32_t *key,
                        void *value, uint64_t flags) {
    struct bpf_map_element_attribute attribute = {0};

    attribute.map_fd = (uint32_t)map_fd;
    attribute.key = (uint64_t)(uintptr_t)key;
    if (command == BPF_MAP_LOOKUP_ELEM || command == BPF_MAP_UPDATE_ELEM ||
        command == BPF_MAP_GET_NEXT_KEY ||
        command == BPF_MAP_LOOKUP_AND_DELETE_ELEM)
        attribute.value = (uint64_t)(uintptr_t)value;
    if (command == BPF_MAP_UPDATE_ELEM) attribute.flags = flags;
    return raw_syscall6(
        SYS_bpf, command, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long map_batch(long command, int map_fd, uint32_t *output_batch,
                      uint32_t *keys, uint32_t *values, uint32_t *count) {
    struct bpf_map_batch_attribute attribute = {0};
    long result;

    attribute.output_batch = (uint64_t)(uintptr_t)output_batch;
    attribute.keys = (uint64_t)(uintptr_t)keys;
    attribute.values = (uint64_t)(uintptr_t)values;
    attribute.count = *count;
    attribute.map_fd = (uint32_t)map_fd;
    result = raw_syscall6(
        SYS_bpf, command, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
    *count = attribute.count;
    return result;
}

START_ATTRIBUTES void _start(void) {
    static const struct bpf_instruction instructions[] = {
        {0xb7u, 0u, 0, 1},
        {0x95u, 0u, 0, 0},
    };
    static const char license[] = "GPL";
    struct cpumap_value extended = {1u, 9999};
    uint32_t value = 0u;
    uint32_t key = 0u;
    uint32_t next = UINT32_MAX;
    uint32_t batch_cursor = UINT32_MAX;
    uint32_t batch_keys[2] = {UINT32_MAX, UINT32_MAX};
    uint32_t batch_values[2] = {0u, 0u};
    uint32_t batch_count;
    long descriptor;
    long extended_descriptor;
    long program_descriptor;
    int failures = 0;

    failures += expect_result(
        "bad-key-size", create_map(8u, 4u, 4u), -EINVAL);
    failures += expect_result(
        "bad-value-size", create_map(4u, 16u, 4u), -EINVAL);
    failures += expect_result(
        "too-many-entries", create_map(4u, 4u, 65u), -E2BIG);

    descriptor = create_map(4u, 4u, 4u);
    if (descriptor < 0) {
        failures += expect_result("create", descriptor, 0);
    } else {
        failures += expect_result(
            "lookup-empty",
            map_element(BPF_MAP_LOOKUP_ELEM, (int)descriptor,
                        &key, &value, 0u),
            -ENOENT);
        value = 1u;
        failures += expect_result(
            "update-cpu0",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor,
                        &key, &value, BPF_ANY),
            0);
        value = 0u;
        failures += expect_result(
            "lookup-cpu0",
            map_element(BPF_MAP_LOOKUP_ELEM, (int)descriptor,
                        &key, &value, 0u),
            0);
        failures += expect_result("lookup-qsize", value, 1);
        failures += expect_result(
            "lookup-delete-unsupported",
            map_element(BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                        (int)descriptor, &key, &value, 0u),
            -ENOTSUPP);
        batch_count = 2u;
        failures += expect_result(
            "lookup-batch-unsupported",
            map_batch(BPF_MAP_LOOKUP_BATCH, (int)descriptor,
                      &batch_cursor, batch_keys, batch_values,
                      &batch_count),
            -ENOTSUPP);
        batch_count = 2u;
        failures += expect_result(
            "lookup-delete-batch-unsupported",
            map_batch(BPF_MAP_LOOKUP_AND_DELETE_BATCH,
                      (int)descriptor, &batch_cursor, batch_keys,
                      batch_values, &batch_count),
            -ENOTSUPP);
        failures += expect_result(
            "noexist-rejected",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor,
                        &key, &value, BPF_NOEXIST),
            -EEXIST);
        value = 16385u;
        failures += expect_result(
            "qsize-overflow",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor,
                        &key, &value, BPF_ANY),
            -EOVERFLOW);
        key = 4u;
        value = 1u;
        failures += expect_result(
            "update-outside-map",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor,
                        &key, &value, BPF_ANY),
            -E2BIG);
        failures += expect_result(
            "delete-outside-map",
            map_element(BPF_MAP_DELETE_ELEM, (int)descriptor,
                        &key, 0, 0u),
            -EINVAL);
        key = 3u;
        failures += expect_result(
            "update-impossible-cpu",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor,
                        &key, &value, BPF_ANY),
            -ENODEV);
        key = 0u;
        value = 0u;
        failures += expect_result(
            "zero-qsize-deletes",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor,
                        &key, &value, BPF_ANY),
            0);
        failures += expect_result(
            "lookup-after-delete",
            map_element(BPF_MAP_LOOKUP_ELEM, (int)descriptor,
                        &key, &value, 0u),
            -ENOENT);
        failures += expect_result(
            "delete-empty",
            map_element(BPF_MAP_DELETE_ELEM, (int)descriptor,
                        &key, 0, 0u),
            0);
        failures += expect_result(
            "next-null",
            map_element(BPF_MAP_GET_NEXT_KEY, (int)descriptor,
                        0, &next, 0u),
            0);
        failures += expect_result("next-null-key", next, 0);
        key = 3u;
        failures += expect_result(
            "next-last",
            map_element(BPF_MAP_GET_NEXT_KEY, (int)descriptor,
                        &key, &next, 0u),
            -ENOENT);
        key = 4u;
        failures += expect_result(
            "next-invalid-restarts",
            map_element(BPF_MAP_GET_NEXT_KEY, (int)descriptor,
                        &key, &next, 0u),
            0);
        failures += expect_result("next-restart-key", next, 0);
        {
            struct bpf_map_element_attribute freeze = {0};

            freeze.map_fd = (uint32_t)descriptor;
            failures += expect_result(
                "freeze",
                raw_syscall6(SYS_bpf, BPF_MAP_FREEZE,
                             (long)&freeze, sizeof(freeze), 0, 0, 0),
                0);
        }
        key = 4u;
        value = 16385u;
        failures += expect_result(
            "frozen-update-order",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor,
                        &key, &value, BPF_ANY),
            -EPERM);
        failures += expect_result(
            "frozen-delete-order",
            map_element(BPF_MAP_DELETE_ELEM, (int)descriptor,
                        &key, 0, 0u),
            -EPERM);
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    }

    extended_descriptor = create_map(4u, sizeof(extended), 4u);
    if (extended_descriptor < 0) {
        failures += expect_result(
            "extended-create", extended_descriptor, 0);
    } else {
        key = 0u;
        failures += expect_result(
            "bad-program-fd",
            map_element(BPF_MAP_UPDATE_ELEM, (int)extended_descriptor,
                        &key, &extended, BPF_ANY),
            -EBADF);
        extended.qsize = 0u;
        failures += expect_result(
            "zero-qsize-ignores-program-fd",
            map_element(BPF_MAP_UPDATE_ELEM, (int)extended_descriptor,
                        &key, &extended, BPF_ANY),
            0);
        extended.qsize = 1u;
        extended.program_fd = -1;
        failures += expect_result(
            "negative-program-fd",
            map_element(BPF_MAP_UPDATE_ELEM, (int)extended_descriptor,
                        &key, &extended, BPF_ANY),
            0);
        extended.qsize = UINT32_MAX;
        extended.program_fd = -1;
        failures += expect_result(
            "extended-lookup",
            map_element(BPF_MAP_LOOKUP_ELEM, (int)extended_descriptor,
                        &key, &extended, 0u),
            0);
        failures += expect_result(
            "extended-lookup-qsize", extended.qsize, 1);
        failures += expect_result(
            "extended-lookup-program-id", extended.program_fd, 0);
        {
            struct bpf_program_load_attribute program = {0};

            program.program_type = BPF_PROG_TYPE_CGROUP_DEVICE;
            program.instruction_count =
                sizeof(instructions) / sizeof(instructions[0]);
            program.instructions =
                (uint64_t)(uintptr_t)instructions;
            program.license = (uint64_t)(uintptr_t)license;
            program.program_name[0] = 'c';
            program.program_name[1] = 'p';
            program.program_name[2] = 'u';
            program_descriptor = raw_syscall6(
                SYS_bpf, BPF_PROG_LOAD, (long)&program,
                sizeof(program), 0, 0, 0);
        }
        if (program_descriptor < 0) {
            failures += expect_result(
                "program-load", program_descriptor, 0);
        } else {
            extended.qsize = 1u;
            extended.program_fd = (int32_t)program_descriptor;
            failures += expect_result(
                "wrong-program-type",
                map_element(BPF_MAP_UPDATE_ELEM,
                            (int)extended_descriptor, &key,
                            &extended, BPF_ANY),
                -EINVAL);
            (void)raw_syscall6(
                SYS_close, program_descriptor, 0, 0, 0, 0, 0);
        }
        (void)raw_syscall6(
            SYS_close, extended_descriptor, 0, 0, 0, 0, 0);
    }

    if (failures) {
        print_text("bpf-cpumap: FAIL\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("bpf-cpumap: PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
