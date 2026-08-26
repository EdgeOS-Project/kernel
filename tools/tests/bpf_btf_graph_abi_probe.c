/* Linux 7.2 BTF graph and typed-map ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn))
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
#error "bpf_btf_graph_abi_probe requires a Linux 64-bit architecture"
#endif

#define BPF_MAP_CREATE 0
#define BPF_BTF_LOAD 18
#define BPF_MAP_TYPE_HASH 1
#define BPF_F_NO_PREALLOC 1
#define EINVAL 22

struct bpf_btf_load_attribute {
    uint64_t btf;
    uint64_t log_buffer;
    uint32_t btf_size;
    uint32_t log_size;
    uint32_t log_level;
    uint32_t log_true_size;
    uint32_t flags;
    int32_t token_descriptor;
};

struct bpf_map_create_attribute {
    uint32_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_descriptor;
    uint32_t numa_node;
    char map_name[16];
    uint32_t interface_index;
    uint32_t btf_descriptor;
    uint32_t btf_key_type_id;
    uint32_t btf_value_type_id;
    uint32_t btf_vmlinux_value_type_id;
    uint64_t map_extra;
    uint32_t value_type_btf_object_descriptor;
    int32_t token_descriptor;
};

struct valid_btf_blob {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t header_length;
    uint32_t type_offset;
    uint32_t type_length;
    uint32_t string_offset;
    uint32_t string_length;
    struct {
        uint32_t name_offset;
        uint32_t info;
        uint32_t size;
        uint32_t integer;
    } types[2];
    char strings[9];
} __attribute__((packed));

struct cycle_btf_blob {
    uint16_t magic;
    uint8_t version;
    uint8_t flags;
    uint32_t header_length;
    uint32_t type_offset;
    uint32_t type_length;
    uint32_t string_offset;
    uint32_t string_length;
    uint32_t name_offset;
    uint32_t info;
    uint32_t target_type;
    char strings[1];
} __attribute__((packed));

void *memcpy(void *destination, const void *source,
             unsigned long length) {
    unsigned char *output = (unsigned char *)destination;
    const unsigned char *input = (const unsigned char *)source;
    for (unsigned long index = 0u; index < length; ++index)
        output[index] = input[index];
    return destination;
}

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *output = (unsigned char *)destination;
    for (unsigned long index = 0u; index < length; ++index)
        output[index] = (unsigned char)value;
    return destination;
}

static long raw_syscall6(long number, long first, long second, long third,
                         long fourth, long fifth, long sixth) {
#if defined(__x86_64__)
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    register long r9 __asm__("r9") = sixth;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(first), "S"(second),
                       "d"(third), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
#else
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x3 __asm__("x3") = fourth;
    register long x4 __asm__("x4") = fifth;
    register long x5 __asm__("x5") = sixth;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4),
                       "r"(x5), "r"(x8)
                     : "memory");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0u;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *value) {
    (void)raw_syscall6(
        SYS_write, 1, (long)value, (long)text_length(value), 0, 0, 0);
}

static void print_number(long value) {
    char output[32];
    unsigned long count = 0u;
    unsigned long start;
    unsigned long end;
    unsigned long magnitude;

    if (value < 0) {
        output[count++] = '-';
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    start = count;
    do {
        output[count++] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    end = count - 1u;
    while (start < end) {
        char temporary = output[start];
        output[start++] = output[end];
        output[end--] = temporary;
    }
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count,
                       0, 0, 0);
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

static long load_btf(const void *data, uint32_t size) {
    struct bpf_btf_load_attribute attribute = {0};

    attribute.btf = (uint64_t)(uintptr_t)data;
    attribute.btf_size = size;
    return raw_syscall6(
        SYS_bpf, BPF_BTF_LOAD, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long create_typed_map(int btf_descriptor,
                             uint32_t key_type_id,
                             uint32_t value_type_id) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = BPF_MAP_TYPE_HASH;
    attribute.key_size = sizeof(uint32_t);
    attribute.value_size = sizeof(uint64_t);
    attribute.max_entries = 2u;
    attribute.map_flags = BPF_F_NO_PREALLOC;
    attribute.btf_descriptor = (uint32_t)btf_descriptor;
    attribute.btf_key_type_id = key_type_id;
    attribute.btf_value_type_id = value_type_id;
    attribute.map_name[0] = 't';
    attribute.map_name[1] = 'y';
    attribute.map_name[2] = 'p';
    attribute.map_name[3] = 'e';
    attribute.map_name[4] = 'd';
    return raw_syscall6(
        SYS_bpf, BPF_MAP_CREATE, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

START_ATTRIBUTES void _start(void) {
    struct valid_btf_blob valid = {
        .magic = 0xeb9fu,
        .version = 1u,
        .header_length = 24u,
        .type_length = 32u,
        .string_offset = 32u,
        .string_length = 9u,
        .types = {
            {
                .name_offset = 1u,
                .info = 1u << 24u,
                .size = 4u,
                .integer = 32u,
            },
            {
                .name_offset = 5u,
                .info = 1u << 24u,
                .size = 8u,
                .integer = 64u,
            },
        },
        .strings = {0, 'u', '3', '2', 0, 'u', '6', '4', 0},
    };
    struct cycle_btf_blob cycle = {
        .magic = 0xeb9fu,
        .version = 1u,
        .header_length = 24u,
        .type_length = 12u,
        .string_offset = 12u,
        .string_length = 1u,
        .info = 8u << 24u,
        .target_type = 1u,
    };
    long btf_descriptor;
    long map_descriptor;
    int failures = 0;

    btf_descriptor = load_btf(&valid, sizeof(valid));
    if (btf_descriptor < 0) {
        failures += expect_result("valid-btf", btf_descriptor, 0);
    } else {
        map_descriptor = create_typed_map(btf_descriptor, 1u, 2u);
        if (map_descriptor < 0)
            failures += expect_result("typed-map", map_descriptor, 0);
        else
            (void)raw_syscall6(
                SYS_close, map_descriptor, 0, 0, 0, 0, 0);
        failures += expect_result(
            "value-size-mismatch",
            create_typed_map(btf_descriptor, 1u, 1u), -EINVAL);
        failures += expect_result(
            "invalid-value-type",
            create_typed_map(btf_descriptor, 1u, 3u), -EINVAL);
        (void)raw_syscall6(
            SYS_close, btf_descriptor, 0, 0, 0, 0, 0);
    }
    failures += expect_result(
        "typedef-cycle", load_btf(&cycle, sizeof(cycle)), -EINVAL);

    if (failures) {
        print_text("bpf-btf-graph: FAIL\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("bpf-btf-graph: PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
