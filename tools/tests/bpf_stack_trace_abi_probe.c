/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF stack-trace map syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_bpf 321
#define SYS_getpid 39
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_bpf 280
#define SYS_getpid 172
#else
#error "bpf_stack_trace_abi_probe requires a Linux 64-bit architecture"
#endif

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_PROG_LOAD 5
#define BPF_RAW_TRACEPOINT_OPEN 17
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM 21
#define BPF_MAP_TYPE_STACK_TRACE 7
#define BPF_PROG_TYPE_RAW_TRACEPOINT 17
#define BPF_F_STACK_BUILD_ID (1u << 5)
#define BPF_ANY 0

#define ENOENT 2
#define E2BIG 7
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
    uint32_t interface_index;
    uint32_t expected_attach_type;
};

struct bpf_raw_tracepoint_attribute {
    uint64_t name;
    uint32_t program_descriptor;
    uint32_t padding;
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

static unsigned long text_length(const char *text) {
    return strlen(text);
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

static long create_map_with_entries(uint32_t value_size, uint32_t flags,
                                    uint32_t max_entries) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = BPF_MAP_TYPE_STACK_TRACE;
    attribute.key_size = sizeof(uint32_t);
    attribute.value_size = value_size;
    attribute.max_entries = max_entries;
    attribute.map_flags = flags;
    attribute.map_name[0] = 's';
    attribute.map_name[1] = 't';
    return raw_syscall6(
        SYS_bpf, BPF_MAP_CREATE, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long create_map(uint32_t value_size, uint32_t flags) {
    return create_map_with_entries(value_size, flags, 3u);
}

static long map_element(long command, int map_fd, uint32_t *key,
                        uint64_t *value) {
    struct bpf_map_element_attribute attribute = {0};

    attribute.map_fd = (uint32_t)map_fd;
    attribute.key = (uint64_t)(uintptr_t)key;
    if (command != BPF_MAP_DELETE_ELEM &&
        command != BPF_MAP_GET_NEXT_KEY)
        attribute.value = (uint64_t)(uintptr_t)value;
    if (command == BPF_MAP_UPDATE_ELEM ||
        command == BPF_MAP_LOOKUP_AND_DELETE_ELEM)
        attribute.flags = BPF_ANY;
    if (command == BPF_MAP_GET_NEXT_KEY)
        attribute.value = (uint64_t)(uintptr_t)value;
    return raw_syscall6(
        SYS_bpf, command, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long load_stack_program(int map_fd) {
    static const char license[] = "GPL";
    struct bpf_instruction instructions[] = {
        { .code = 0x18u, .registers = 0x12u,
          .immediate = map_fd },
        {0},
        { .code = 0xb7u, .registers = 3u, .immediate = 0 },
        { .code = 0x85u, .immediate = 27 },
        { .code = 0xb7u, .registers = 0u, .immediate = 0 },
        { .code = 0x95u },
    };
    struct bpf_program_load_attribute attribute = {0};

    attribute.program_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
    attribute.instruction_count =
        sizeof(instructions) / sizeof(instructions[0]);
    attribute.instructions = (uint64_t)(uintptr_t)instructions;
    attribute.license = (uint64_t)(uintptr_t)license;
    attribute.program_name[0] = 's';
    attribute.program_name[1] = 't';
    attribute.program_name[2] = 'a';
    attribute.program_name[3] = 'c';
    attribute.program_name[4] = 'k';
    return raw_syscall6(
        SYS_bpf, BPF_PROG_LOAD, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long open_raw_tracepoint(int program_fd) {
    static const char name[] = "sys_enter";
    struct bpf_raw_tracepoint_attribute attribute = {
        .name = (uint64_t)(uintptr_t)name,
        .program_descriptor = (uint32_t)program_fd,
    };

    return raw_syscall6(
        SYS_bpf, BPF_RAW_TRACEPOINT_OPEN, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

START_ATTRIBUTES void _start(void) {
    uint64_t value[4] = {0};
    uint32_t key = 0u;
    uint32_t next = 0u;
    long descriptor;
    long build_id_descriptor;
    long program_descriptor;
    long tracepoint_descriptor;
    int failures = 0;

    failures += expect_result("small-value", create_map(4u, 0u), -EINVAL);
    failures += expect_result(
        "misaligned-value", create_map(12u, 0u), -EINVAL);
    failures += expect_result(
        "small-build-id", create_map(8u, BPF_F_STACK_BUILD_ID), -EINVAL);
    failures += expect_result(
        "raw-stack-too-deep", create_map(128u * 8u, 0u), -EINVAL);
    failures += expect_result(
        "build-id-stack-too-deep",
        create_map(128u * 32u, BPF_F_STACK_BUILD_ID), -EINVAL);
    failures += expect_result(
        "bucket-count-overflow",
        create_map_with_entries(8u, 0u, (1u << 31u) + 1u), -E2BIG);

    descriptor = create_map(sizeof(value), 0u);
    if (descriptor < 0) {
        failures += expect_result("create", descriptor, 0);
    } else {
        failures += expect_result(
            "lookup-empty",
            map_element(BPF_MAP_LOOKUP_ELEM, (int)descriptor, &key, value),
            -ENOENT);
        failures += expect_result(
            "update-rejected",
            map_element(BPF_MAP_UPDATE_ELEM, (int)descriptor, &key, value),
            -EINVAL);
        failures += expect_result(
            "delete-empty",
            map_element(BPF_MAP_DELETE_ELEM, (int)descriptor, &key, value),
            -ENOENT);
        failures += expect_result(
            "lookup-delete-empty",
            map_element(BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                        (int)descriptor, &key, value),
            -ENOENT);
        key = 4u;
        failures += expect_result(
            "delete-outside-rounded-table",
            map_element(BPF_MAP_DELETE_ELEM, (int)descriptor, &key, value),
            -E2BIG);
        failures += expect_result(
            "next-empty",
            map_element(BPF_MAP_GET_NEXT_KEY,
                        (int)descriptor, 0, (uint64_t *)&next),
            -ENOENT);
        program_descriptor = load_stack_program((int)descriptor);
        if (program_descriptor < 0) {
            failures += expect_result(
                "load-stack-program", program_descriptor, 0);
        } else {
            tracepoint_descriptor = open_raw_tracepoint(
                (int)program_descriptor);
            if (tracepoint_descriptor < 0) {
                failures += expect_result(
                    "open-raw-tracepoint", tracepoint_descriptor, 0);
            } else {
                (void)raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
                failures += expect_result(
                    "next-populated",
                    map_element(BPF_MAP_GET_NEXT_KEY,
                                (int)descriptor, 0,
                                (uint64_t *)&next),
                    0);
                failures += expect_result(
                    "lookup-populated",
                    map_element(BPF_MAP_LOOKUP_ELEM,
                                (int)descriptor, &next, value),
                    0);
                if (!value[0]) {
                    print_text("FAIL populated-stack-zero\n");
                    ++failures;
                }
                (void)raw_syscall6(
                    SYS_close, tracepoint_descriptor, 0, 0, 0, 0, 0);
            }
            (void)raw_syscall6(
                SYS_close, program_descriptor, 0, 0, 0, 0, 0);
        }
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    }

    build_id_descriptor = create_map(sizeof(value), BPF_F_STACK_BUILD_ID);
    if (build_id_descriptor < 0)
        failures += expect_result(
            "build-id-create", build_id_descriptor, 0);
    else
        (void)raw_syscall6(
            SYS_close, build_id_descriptor, 0, 0, 0, 0, 0);

    if (failures) {
        print_text("bpf-stack-trace: FAIL\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("bpf-stack-trace: PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
