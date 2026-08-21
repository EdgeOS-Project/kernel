/* SPDX-License-Identifier: MPL-2.0 */
/* Raw Linux BPF object and map ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_fcntl 72
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_mount 165
#define SYS_exit 60
#define SYS_bpf 321
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_bpf 280
#define SYS_openat 56
#define SYS_mkdirat 34
#define SYS_mount 40
#define START_ATTRIBUTES __attribute__((noreturn))
#else
#error "bpf_abi_probe requires a Linux 64-bit architecture"
#endif

#define BPF_MAP_CREATE 0u
#define BPF_MAP_LOOKUP_ELEM 1u
#define BPF_MAP_UPDATE_ELEM 2u
#define BPF_MAP_DELETE_ELEM 3u
#define BPF_MAP_GET_NEXT_KEY 4u
#define BPF_PROG_LOAD 5u
#define BPF_PROG_ATTACH 8u
#define BPF_PROG_DETACH 9u
#define BPF_PROG_GET_NEXT_ID 11u
#define BPF_MAP_GET_NEXT_ID 12u
#define BPF_PROG_GET_FD_BY_ID 13u
#define BPF_MAP_GET_FD_BY_ID 14u
#define BPF_OBJ_GET_INFO_BY_FD 15u
#define BPF_PROG_QUERY 16u
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM 21u
#define BPF_MAP_FREEZE 22u
#define BPF_MAP_LOOKUP_BATCH 24u
#define BPF_MAP_LOOKUP_AND_DELETE_BATCH 25u
#define BPF_MAP_UPDATE_BATCH 26u
#define BPF_MAP_DELETE_BATCH 27u

#define BPF_MAP_TYPE_HASH 1u
#define BPF_MAP_TYPE_ARRAY 2u
#define BPF_MAP_TYPE_PERCPU_HASH 5u
#define BPF_MAP_TYPE_PERCPU_ARRAY 6u
#define BPF_MAP_TYPE_LRU_HASH 9u
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10u
#define BPF_MAP_TYPE_QUEUE 22u
#define BPF_MAP_TYPE_STACK 23u
#define BPF_PROG_TYPE_CGROUP_DEVICE 15u
#define BPF_CGROUP_DEVICE 6u
#define BPF_ANY 0u
#define BPF_NOEXIST 1u
#define BPF_EXIST 2u
#define BPF_F_CPU 8u
#define BPF_F_ALL_CPUS 16u

#define F_GETFD 1
#define FD_CLOEXEC 1
#define AT_FDCWD -100
#define O_RDONLY 0
#define O_DIRECTORY 00200000

#define E2BIG 7
#define EBADF 9
#define EFAULT 14
#define EBUSY 16
#define EEXIST 17
#define EINVAL 22
#define ERANGE 34
#define ENOENT 2
#define EPERM 1
#define ENOTSUPP 524

union bpf_attr {
    struct {
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
    } map_create;
    struct {
        uint32_t map_fd;
        uint32_t padding;
        uint64_t key;
        uint64_t value;
        uint64_t flags;
    } map_element;
    struct {
        uint32_t prog_type;
        uint32_t insn_count;
        uint64_t insns;
        uint64_t license;
        uint32_t log_level;
        uint32_t log_size;
        uint64_t log_buf;
        uint32_t kern_version;
        uint32_t prog_flags;
        char prog_name[16];
        uint32_t prog_ifindex;
        uint32_t expected_attach_type;
    } prog_load;
    struct {
        uint32_t target_fd;
        uint32_t attach_bpf_fd;
        uint32_t attach_type;
        uint32_t attach_flags;
        uint32_t replace_bpf_fd;
        uint32_t relative_fd;
        uint64_t expected_revision;
    } prog_attach;
    struct {
        uint32_t target_fd;
        uint32_t attach_type;
        uint32_t query_flags;
        uint32_t attach_flags;
        uint64_t prog_ids;
        uint32_t prog_count;
        uint32_t padding;
        uint64_t prog_attach_flags;
        uint64_t link_ids;
        uint64_t link_attach_flags;
        uint64_t revision;
    } prog_query;
    struct {
        uint32_t start_or_object_id;
        uint32_t next_id;
        uint32_t open_flags;
        int32_t token_fd;
    } id;
    struct {
        uint32_t bpf_fd;
        uint32_t info_len;
        uint64_t info;
    } info;
    struct {
        uint64_t in_batch;
        uint64_t out_batch;
        uint64_t keys;
        uint64_t values;
        uint32_t count;
        uint32_t map_fd;
        uint64_t elem_flags;
        uint64_t flags;
    } batch;
    uint8_t padding[144];
};

struct bpf_map_info {
    uint32_t type;
    uint32_t id;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    char name[16];
    uint32_t ifindex;
    uint32_t btf_vmlinux_value_type_id;
    uint64_t netns_dev;
    uint64_t netns_ino;
    uint32_t btf_id;
    uint32_t btf_key_type_id;
    uint32_t btf_value_type_id;
    uint32_t btf_vmlinux_id;
    uint64_t map_extra;
    uint64_t hash;
    uint32_t hash_size;
    uint32_t padding;
};

struct bpf_prog_info {
    uint32_t type;
    uint32_t id;
    uint8_t tag[8];
    uint32_t jited_prog_len;
    uint32_t xlated_prog_len;
    uint64_t jited_prog_insns;
    uint64_t xlated_prog_insns;
    uint64_t load_time;
    uint32_t created_by_uid;
    uint32_t nr_map_ids;
    uint64_t map_ids;
    char name[16];
    uint32_t ifindex;
    uint32_t gpl_compatible;
    uint64_t netns_dev;
    uint64_t netns_ino;
    uint32_t nr_jited_ksyms;
    uint32_t nr_jited_func_lens;
    uint64_t jited_ksyms;
    uint64_t jited_func_lens;
    uint32_t btf_id;
    uint32_t func_info_rec_size;
    uint64_t func_info;
    uint32_t nr_func_info;
    uint32_t nr_line_info;
    uint64_t line_info;
    uint64_t jited_line_info;
    uint32_t nr_jited_line_info;
    uint32_t line_info_rec_size;
    uint32_t jited_line_info_rec_size;
    uint32_t nr_prog_tags;
    uint64_t prog_tags;
    uint64_t run_time_ns;
    uint64_t run_cnt;
    uint64_t recursion_misses;
    uint32_t verified_insns;
    uint32_t attach_btf_obj_id;
    uint32_t attach_btf_id;
    uint32_t padding;
};

struct bpf_insn {
    uint8_t code;
    uint8_t registers;
    int16_t offset;
    int32_t immediate;
};

_Static_assert(sizeof(union bpf_attr) == 144u,
               "bpf_attr probe layout mismatch");
_Static_assert(sizeof(struct bpf_map_info) == 104u,
               "bpf_map_info probe layout mismatch");
_Static_assert(sizeof(struct bpf_prog_info) == 232u,
               "bpf_prog_info probe layout mismatch");
_Static_assert(sizeof(struct bpf_insn) == 8u,
               "bpf_insn probe layout mismatch");

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

static void clear_bytes(void *destination, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = 0;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static int text_equal(const char *left, const char *right) {
    unsigned long index = 0;
    while (left[index] && right[index] && left[index] == right[index]) ++index;
    return left[index] == right[index];
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_long(long value) {
    char output[32];
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
    while (count) {
        char character = output[--count];
        (void)raw_syscall6(SYS_write, 1, (long)&character, 1, 0, 0, 0);
    }
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_long(actual);
    print_text(" expected=");
    print_long(expected);
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

static long bpf_call(uint32_t command, union bpf_attr *attribute) {
    return raw_syscall6(
        SYS_bpf, command, (long)attribute, sizeof(*attribute), 0, 0, 0);
}

static long bpf_call_size(uint32_t command, union bpf_attr *attribute,
                          uint32_t size) {
    return raw_syscall6(
        SYS_bpf, command, (long)attribute, size, 0, 0, 0);
}

static long create_map(uint32_t type, uint32_t entries, const char *name) {
    union bpf_attr attribute;
    unsigned long index;

    clear_bytes(&attribute, sizeof(attribute));
    attribute.map_create.map_type = type;
    attribute.map_create.key_size = 4u;
    attribute.map_create.value_size = 8u;
    attribute.map_create.max_entries = entries;
    for (index = 0; name[index] && index + 1u < 16u; ++index)
        attribute.map_create.map_name[index] = name[index];
    return bpf_call(BPF_MAP_CREATE, &attribute);
}

static long create_keyless_map(uint32_t type, uint32_t entries,
                               const char *name) {
    union bpf_attr attribute;
    unsigned long index;

    clear_bytes(&attribute, sizeof(attribute));
    attribute.map_create.map_type = type;
    attribute.map_create.value_size = 8u;
    attribute.map_create.max_entries = entries;
    for (index = 0; name[index] && index + 1u < 16u; ++index)
        attribute.map_create.map_name[index] = name[index];
    return bpf_call(BPF_MAP_CREATE, &attribute);
}

static long map_element(uint32_t command, long descriptor,
                        uint32_t *key, uint64_t *value, uint64_t flags) {
    union bpf_attr attribute;

    clear_bytes(&attribute, sizeof(attribute));
    attribute.map_element.map_fd = (uint32_t)descriptor;
    attribute.map_element.key = (uint64_t)(uintptr_t)key;
    attribute.map_element.value = (uint64_t)(uintptr_t)value;
    attribute.map_element.flags = flags;
    return bpf_call(command, &attribute);
}

static long map_batch(uint32_t command, long descriptor,
                      uint32_t *input_cursor, uint32_t *output_cursor,
                      uint32_t *keys, uint64_t *values, uint32_t *count,
                      uint64_t element_flags) {
    union bpf_attr attribute;
    long result;

    clear_bytes(&attribute, sizeof(attribute));
    attribute.batch.in_batch = (uint64_t)(uintptr_t)input_cursor;
    attribute.batch.out_batch = (uint64_t)(uintptr_t)output_cursor;
    attribute.batch.keys = (uint64_t)(uintptr_t)keys;
    attribute.batch.values = (uint64_t)(uintptr_t)values;
    attribute.batch.count = *count;
    attribute.batch.map_fd = (uint32_t)descriptor;
    attribute.batch.elem_flags = element_flags;
    result = bpf_call(command, &attribute);
    *count = attribute.batch.count;
    return result;
}

static int test_array_map(void) {
    union bpf_attr attribute;
    struct bpf_map_info info;
    uint32_t key = 2u;
    uint32_t next = UINT32_MAX;
    uint64_t value = 0x1122334455667788ULL;
    uint64_t output = 0;
    uint32_t id;
    long reopened;
    long descriptor = create_map(BPF_MAP_TYPE_ARRAY, 4u, "array_map");
    int failures = 0;

    if (descriptor == -EPERM) return 77;
    failures += expect_true("array create", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    failures += expect("array cloexec", raw_syscall6(
        SYS_fcntl, descriptor, F_GETFD, 0, 0, 0, 0), FD_CLOEXEC);
    failures += expect("array zero lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &key, &output, 0), 0);
    failures += expect_true("array zero value", output == 0u);
    failures += expect("array update", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &key, &value, BPF_ANY), 0);
    failures += expect("array lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &key, &output, 0), 0);
    failures += expect_true("array value", output == value);
    failures += expect("array noexist", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &key, &value, BPF_NOEXIST),
        -EEXIST);
    failures += expect("array delete", map_element(
        BPF_MAP_DELETE_ELEM, descriptor, &key, 0, 0), -EINVAL);
    failures += expect("array next", map_element(
        BPF_MAP_GET_NEXT_KEY, descriptor, &key, (uint64_t *)&next, 0), 0);
    failures += expect_true("array next value", next == 3u);
    clear_bytes(&info, sizeof(info));
    clear_bytes(&attribute, sizeof(attribute));
    attribute.info.bpf_fd = (uint32_t)descriptor;
    attribute.info.info_len = sizeof(info);
    attribute.info.info = (uint64_t)(uintptr_t)&info;
    failures += expect("array info", bpf_call(
        BPF_OBJ_GET_INFO_BY_FD, &attribute), 0);
    failures += expect_true(
        "array info values",
        info.type == BPF_MAP_TYPE_ARRAY && info.key_size == 4u &&
        info.value_size == 8u && info.max_entries == 4u &&
        text_equal(info.name, "array_map"));
    id = info.id;
    clear_bytes(&attribute, sizeof(attribute));
    attribute.id.start_or_object_id = id - 1u;
    failures += expect("map next id", bpf_call(
        BPF_MAP_GET_NEXT_ID, &attribute), 0);
    failures += expect_true("map next id value", attribute.id.next_id == id);
    clear_bytes(&attribute, sizeof(attribute));
    attribute.id.start_or_object_id = id;
    reopened = bpf_call(BPF_MAP_GET_FD_BY_ID, &attribute);
    failures += expect_true("map reopen", reopened >= 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    if (reopened >= 0) {
        output = 0;
        failures += expect("reopened lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, reopened, &key, &output, 0), 0);
        failures += expect_true("reopened value", output == value);
        (void)raw_syscall6(SYS_close, reopened, 0, 0, 0, 0, 0);
    }
    return failures;
}

static int test_hash_map(void) {
    uint32_t first = 1u;
    uint32_t second = 2u;
    uint32_t third = 3u;
    uint32_t next = 0u;
    uint64_t value = 11u;
    uint64_t other = 22u;
    long descriptor = create_map(BPF_MAP_TYPE_HASH, 2u, "hash_map");
    int failures = 0;

    failures += expect_true("hash create", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    failures += expect("hash insert", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &first, &value, BPF_NOEXIST), 0);
    failures += expect("hash duplicate", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &first, &value, BPF_NOEXIST),
        -EEXIST);
    failures += expect("hash missing exist", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &second, &other, BPF_EXIST),
        -ENOENT);
    failures += expect("hash second", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &second, &other, BPF_ANY), 0);
    failures += expect("hash full", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &third, &other, BPF_ANY), -E2BIG);
    failures += expect("hash next", map_element(
        BPF_MAP_GET_NEXT_KEY, descriptor, 0, (uint64_t *)&next, 0), 0);
    failures += expect("hash delete", map_element(
        BPF_MAP_DELETE_ELEM, descriptor, &first, 0, 0), 0);
    failures += expect("hash missing", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &first, &value, 0), -ENOENT);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int test_lru_hash_map(void) {
    union bpf_attr attribute;
    uint32_t first = 1u;
    uint32_t second = 2u;
    uint32_t third = 3u;
    uint64_t first_value = 11u;
    uint64_t second_value = 22u;
    uint64_t third_value = 33u;
    uint64_t output = 0u;
    long descriptor = create_map(
        BPF_MAP_TYPE_LRU_HASH, 2u, "lru_hash");
    int first_status;
    int second_status;
    int failures = 0;

    failures += expect_true("lru create", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    failures += expect("lru first", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &first, &first_value,
        BPF_ANY), 0);
    failures += expect("lru second", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &second, &second_value,
        BPF_ANY), 0);
    failures += expect("lru touch first", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &first, &output, 0), 0);
    failures += expect_true("lru touched value", output == first_value);
    failures += expect("lru full insert", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &third, &third_value,
        BPF_ANY), 0);
    output = 0u;
    failures += expect("lru inserted lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &third, &output, 0), 0);
    failures += expect_true("lru inserted value", output == third_value);
    first_status = (int)map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &first, &output, 0);
    second_status = (int)map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &second, &output, 0);
    failures += expect_true(
        "lru evicted one old key",
        (first_status == 0 && second_status == -ENOENT) ||
        (first_status == -ENOENT && second_status == 0));
    failures += expect("lru remove inserted", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, descriptor,
        &third, &output, 0), 0);
    failures += expect_true("lru removed value", output == third_value);

    {
        uint32_t batch_keys[2];
        uint64_t batch_values[2];
        uint32_t next_cursor = 0u;
        uint32_t count = 2u;

        clear_bytes(batch_keys, sizeof(batch_keys));
        clear_bytes(batch_values, sizeof(batch_values));
        failures += expect("lru batch lookup delete", map_batch(
            BPF_MAP_LOOKUP_AND_DELETE_BATCH, descriptor, 0,
            &next_cursor, batch_keys, batch_values, &count, 0),
            -ENOENT);
        failures += expect("lru batch lookup delete count", count, 1);
    }
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

    clear_bytes(&attribute, sizeof(attribute));
    attribute.map_create.map_type = BPF_MAP_TYPE_LRU_HASH;
    attribute.map_create.key_size = 4u;
    attribute.map_create.value_size = 8u;
    attribute.map_create.max_entries = 2u;
    attribute.map_create.map_flags = 1u;
    failures += expect("lru no prealloc", bpf_call(
        BPF_MAP_CREATE, &attribute), -ENOTSUPP);
    return failures;
}

static int test_queue_stack_maps(void) {
    union bpf_attr attribute;
    uint32_t invalid_key = 1u;
    uint64_t first = 11u;
    uint64_t second = 22u;
    uint64_t third = 33u;
    uint64_t output = ~0ULL;
    long queue = create_keyless_map(
        BPF_MAP_TYPE_QUEUE, 2u, "queue_map");
    long stack;
    int failures = 0;

    failures += expect_true("queue create", queue >= 0);
    if (queue < 0) return failures + 1;
    failures += expect("queue empty peek", map_element(
        BPF_MAP_LOOKUP_ELEM, queue, 0, &output, 0), -ENOENT);
    failures += expect("queue push first", map_element(
        BPF_MAP_UPDATE_ELEM, queue, 0, &first, BPF_ANY), 0);
    failures += expect("queue push second", map_element(
        BPF_MAP_UPDATE_ELEM, queue, 0, &second, BPF_ANY), 0);
    failures += expect("queue full", map_element(
        BPF_MAP_UPDATE_ELEM, queue, 0, &third, BPF_ANY), -E2BIG);
    failures += expect("queue nonnull key", map_element(
        BPF_MAP_UPDATE_ELEM, queue, &invalid_key, &third, BPF_ANY),
        -EINVAL);
    failures += expect("queue noexist", map_element(
        BPF_MAP_UPDATE_ELEM, queue, 0, &third, BPF_NOEXIST), -EINVAL);
    failures += expect("queue replace", map_element(
        BPF_MAP_UPDATE_ELEM, queue, 0, &third, BPF_EXIST), 0);
    failures += expect("queue peek", map_element(
        BPF_MAP_LOOKUP_ELEM, queue, 0, &output, 0), 0);
    failures += expect_true("queue fifo peek", output == second);
    failures += expect("queue pop first", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, queue, 0, &output, 0), 0);
    failures += expect_true("queue fifo first", output == second);
    failures += expect("queue pop second", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, queue, 0, &output, 0), 0);
    failures += expect_true("queue fifo second", output == third);
    failures += expect("queue empty pop", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, queue, 0, &output, 0), -ENOENT);
    failures += expect("queue delete", map_element(
        BPF_MAP_DELETE_ELEM, queue, 0, 0, 0), -EINVAL);
    failures += expect("queue next key", map_element(
        BPF_MAP_GET_NEXT_KEY, queue, 0, &output, 0), -EINVAL);
    clear_bytes(&attribute, sizeof(attribute));
    attribute.batch.map_fd = (uint32_t)queue;
    failures += expect("queue batch", bpf_call(
        BPF_MAP_LOOKUP_BATCH, &attribute), -ENOTSUPP);
    (void)raw_syscall6(SYS_close, queue, 0, 0, 0, 0, 0);

    stack = create_keyless_map(BPF_MAP_TYPE_STACK, 2u, "stack_map");
    failures += expect_true("stack create", stack >= 0);
    if (stack < 0) return failures + 1;
    failures += expect("stack push first", map_element(
        BPF_MAP_UPDATE_ELEM, stack, 0, &first, BPF_ANY), 0);
    failures += expect("stack push second", map_element(
        BPF_MAP_UPDATE_ELEM, stack, 0, &second, BPF_ANY), 0);
    failures += expect("stack peek", map_element(
        BPF_MAP_LOOKUP_ELEM, stack, 0, &output, 0), 0);
    failures += expect_true("stack lifo peek", output == second);
    failures += expect("stack replace", map_element(
        BPF_MAP_UPDATE_ELEM, stack, 0, &third, BPF_EXIST), 0);
    failures += expect("stack pop first", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, stack, 0, &output, 0), 0);
    failures += expect_true("stack lifo first", output == third);
    failures += expect("stack pop second", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, stack, 0, &output, 0), 0);
    failures += expect_true("stack lifo second", output == second);
    (void)raw_syscall6(SYS_close, stack, 0, 0, 0, 0, 0);

    clear_bytes(&attribute, sizeof(attribute));
    attribute.map_create.map_type = BPF_MAP_TYPE_QUEUE;
    attribute.map_create.key_size = 4u;
    attribute.map_create.value_size = 8u;
    attribute.map_create.max_entries = 2u;
    failures += expect("queue invalid key size", bpf_call(
        BPF_MAP_CREATE, &attribute), -EINVAL);
    return failures;
}

static int test_percpu_maps(void) {
    uint64_t values[256];
    uint64_t output[256];
    uint32_t array_key = 1u;
    uint32_t hash_key = 7u;
    uint32_t batch_key = 0u;
    uint32_t batch_cursor = 0u;
    uint32_t batch_output_cursor = 0u;
    uint32_t batch_count = 1u;
    uint64_t scalar = 5001u;
    uint64_t scalar_output = 0u;
    uint64_t cpu_one_flags = BPF_F_CPU | (1ULL << 32u);
    long array = create_map(
        BPF_MAP_TYPE_PERCPU_ARRAY, 2u, "percpu_array");
    long hash;
    int failures = 0;

    for (uint32_t cpu = 0; cpu < 256u; ++cpu) {
        values[cpu] = 1000u + cpu;
        output[cpu] = ~0ULL;
    }
    failures += expect_true("percpu array create", array >= 0);
    if (array < 0) return failures + 1;
    failures += expect("percpu array zero lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, array, &array_key, output, 0), 0);
    failures += expect_true("percpu array cpu0 zero", output[0] == 0u);
    failures += expect_true("percpu array cpu1 zero", output[1] == 0u);
    failures += expect("percpu array update", map_element(
        BPF_MAP_UPDATE_ELEM, array, &array_key, values, BPF_ANY), 0);
    clear_bytes(output, sizeof(output));
    failures += expect("percpu array lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, array, &array_key, output, 0), 0);
    failures += expect_true(
        "percpu array cpu values",
        output[0] == values[0] && output[1] == values[1]);
    failures += expect("percpu array cpu update", map_element(
        BPF_MAP_UPDATE_ELEM, array, &array_key, &scalar,
        cpu_one_flags), 0);
    failures += expect("percpu array cpu lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, array, &array_key, &scalar_output,
        cpu_one_flags), 0);
    failures += expect_true(
        "percpu array selected cpu", scalar_output == scalar);
    scalar = 7001u;
    failures += expect("percpu array all cpu update", map_element(
        BPF_MAP_UPDATE_ELEM, array, &array_key, &scalar,
        BPF_F_ALL_CPUS), 0);
    clear_bytes(output, sizeof(output));
    failures += expect("percpu array all cpu lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, array, &array_key, output, 0), 0);
    failures += expect_true(
        "percpu array all cpu values",
        output[0] == scalar && output[1] == scalar);
    failures += expect("percpu array lookup all invalid", map_element(
        BPF_MAP_LOOKUP_ELEM, array, &array_key, &scalar_output,
        BPF_F_ALL_CPUS), -EINVAL);
    failures += expect("percpu array invalid cpu", map_element(
        BPF_MAP_LOOKUP_ELEM, array, &array_key, &scalar_output,
        BPF_F_CPU | (0xffffffffULL << 32u)), -ERANGE);
    failures += expect("percpu array noexist", map_element(
        BPF_MAP_UPDATE_ELEM, array, &array_key, values, BPF_NOEXIST),
        -EEXIST);
    (void)raw_syscall6(SYS_close, array, 0, 0, 0, 0, 0);

    hash = create_map(BPF_MAP_TYPE_PERCPU_HASH, 2u, "percpu_hash");
    failures += expect_true("percpu hash create", hash >= 0);
    if (hash < 0) return failures + 1;
    failures += expect("percpu hash update", map_element(
        BPF_MAP_UPDATE_ELEM, hash, &hash_key, values, BPF_ANY), 0);
    clear_bytes(output, sizeof(output));
    failures += expect("percpu hash lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, hash, &hash_key, output, 0), 0);
    failures += expect_true(
        "percpu hash cpu values",
        output[0] == values[0] && output[1] == values[1]);
    scalar = 8001u;
    scalar_output = 0u;
    failures += expect("percpu hash cpu update", map_element(
        BPF_MAP_UPDATE_ELEM, hash, &hash_key, &scalar,
        cpu_one_flags), 0);
    failures += expect("percpu hash cpu lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, hash, &hash_key, &scalar_output,
        cpu_one_flags), 0);
    failures += expect_true(
        "percpu hash selected cpu", scalar_output == scalar);
    values[1] = scalar;
    scalar_output = 0u;
    failures += expect("percpu hash cpu batch lookup", map_batch(
        BPF_MAP_LOOKUP_BATCH, hash, &batch_cursor,
        &batch_output_cursor, &batch_key, &scalar_output,
        &batch_count, cpu_one_flags), -ENOENT);
    failures += expect("percpu hash cpu batch count", batch_count, 1);
    failures += expect_true(
        "percpu hash cpu batch value",
        batch_key == hash_key && scalar_output == scalar);
    scalar = 8101u;
    batch_count = 1u;
    failures += expect("percpu hash all cpu batch update", map_batch(
        BPF_MAP_UPDATE_BATCH, hash, 0, 0, &hash_key, &scalar,
        &batch_count, BPF_F_ALL_CPUS), 0);
    failures += expect("percpu hash all cpu batch count", batch_count, 1);
    for (uint32_t cpu = 0; cpu < 256u; ++cpu) values[cpu] = scalar;
    clear_bytes(output, sizeof(output));
    failures += expect("percpu hash lookup delete", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, hash, &hash_key, output, 0), 0);
    failures += expect_true(
        "percpu hash deleted values",
        output[0] == values[0] && output[1] == values[1]);
    failures += expect("percpu hash missing", map_element(
        BPF_MAP_LOOKUP_ELEM, hash, &hash_key, output, 0), -ENOENT);
    (void)raw_syscall6(SYS_close, hash, 0, 0, 0, 0, 0);
    return failures;
}

static int test_lru_percpu_hash_map(void) {
    uint64_t first[256];
    uint64_t second[256];
    uint64_t third[256];
    uint64_t output[256];
    uint32_t keys[3] = { 41u, 42u, 43u };
    long descriptor = create_map(
        BPF_MAP_TYPE_LRU_PERCPU_HASH, 2u, "lru_percpu");
    int failures = 0;

    for (uint32_t cpu = 0; cpu < 256u; ++cpu) {
        first[cpu] = 100u + cpu;
        second[cpu] = 200u + cpu;
        third[cpu] = 300u + cpu;
    }
    failures += expect_true("lru percpu create", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    failures += expect("lru percpu first", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &keys[0], first, BPF_ANY), 0);
    failures += expect("lru percpu second", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &keys[1], second, BPF_ANY), 0);
    clear_bytes(output, sizeof(output));
    failures += expect("lru percpu walk lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[0], output, 0), 0);
    failures += expect_true(
        "lru percpu walk value",
        output[0] == first[0] && output[1] == first[1]);
    failures += expect("lru percpu eviction", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &keys[2], third, BPF_ANY), 0);
    failures += expect("lru percpu oldest missing", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[0], output, 0), -ENOENT);
    failures += expect("lru percpu second retained", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[1], output, 0), 0);
    failures += expect_true(
        "lru percpu retained value",
        output[0] == second[0] && output[1] == second[1]);
    failures += expect("lru percpu third retained", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[2], output, 0), 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static uint32_t batch_pair_mask(const uint32_t *keys,
                                const uint64_t *values, uint32_t count) {
    uint32_t observed_mask = 0u;

    for (uint32_t index = 0; index < count; ++index) {
        if (keys[index] < 1u || keys[index] > 3u ||
            values[index] != (uint64_t)keys[index] * 11u)
            return 0;
        if (observed_mask & (1u << (keys[index] - 1u))) return 0;
        observed_mask |= 1u << (keys[index] - 1u);
    }
    return observed_mask;
}

static int test_batch_and_freeze(void) {
    union bpf_attr attribute;
    uint32_t keys[4] = { 1u, 2u, 3u, 0u };
    uint64_t values[4] = { 11u, 22u, 33u, 0u };
    uint32_t output_keys[4];
    uint64_t output_values[4];
    uint32_t cursor = 0u;
    uint32_t next_cursor = 0u;
    uint32_t count = 3u;
    uint32_t first_mask;
    uint32_t final_mask;
    uint32_t one_key = 2u;
    uint64_t one_value = 0u;
    long descriptor = create_map(BPF_MAP_TYPE_HASH, 4u, "batch_map");
    int failures = 0;

    failures += expect_true("batch create", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    clear_bytes(&attribute, sizeof(attribute));
    attribute.batch.map_fd = UINT32_MAX;
    failures += expect("zero batch bad fd", bpf_call(
        BPF_MAP_UPDATE_BATCH, &attribute), -EBADF);
    clear_bytes(&attribute, sizeof(attribute));
    attribute.batch.map_fd = (uint32_t)descriptor;
    failures += expect("zero batch", bpf_call(
        BPF_MAP_UPDATE_BATCH, &attribute), 0);
    clear_bytes(&attribute, sizeof(attribute));
    attribute.batch.map_fd = (uint32_t)descriptor;
    attribute.batch.count = 1u;
    failures += expect("batch null keys", bpf_call(
        BPF_MAP_UPDATE_BATCH, &attribute), -EFAULT);
    failures += expect("batch null keys count", attribute.batch.count, 0);
    failures += expect("batch update", map_batch(
        BPF_MAP_UPDATE_BATCH, descriptor, 0, 0, keys, values, &count,
        BPF_ANY), 0);
    failures += expect("batch update count", count, 3);

    clear_bytes(output_keys, sizeof(output_keys));
    clear_bytes(output_values, sizeof(output_values));
    count = 2u;
    failures += expect("batch lookup first", map_batch(
        BPF_MAP_LOOKUP_BATCH, descriptor, 0, &next_cursor, output_keys,
        output_values, &count, 0), 0);
    failures += expect("batch lookup first count", count, 2);
    first_mask = batch_pair_mask(output_keys, output_values, count);
    failures += expect_true("batch lookup first pairs",
                            first_mask != 0u && first_mask != 0x7u);

    cursor = next_cursor;
    clear_bytes(output_keys, sizeof(output_keys));
    clear_bytes(output_values, sizeof(output_values));
    count = 2u;
    failures += expect("batch lookup final", map_batch(
        BPF_MAP_LOOKUP_BATCH, descriptor, &cursor, &next_cursor,
        output_keys, output_values, &count, 0), -ENOENT);
    failures += expect("batch lookup final count", count, 1);
    final_mask = batch_pair_mask(output_keys, output_values, count);
    failures += expect_true("batch lookup final pair",
                            final_mask != 0u &&
                            !(first_mask & final_mask) &&
                            (first_mask | final_mask) == 0x7u);

    failures += expect("lookup delete", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, descriptor, &one_key,
        &one_value, 0), 0);
    failures += expect_true("lookup delete value", one_value == 22u);
    failures += expect("lookup delete missing", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &one_key, &one_value, 0),
        -ENOENT);
    one_value = 22u;
    failures += expect("lookup delete restore", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &one_key, &one_value, BPF_ANY),
        0);

    clear_bytes(output_keys, sizeof(output_keys));
    clear_bytes(output_values, sizeof(output_values));
    count = 4u;
    failures += expect("batch lookup delete", map_batch(
        BPF_MAP_LOOKUP_AND_DELETE_BATCH, descriptor, 0, &next_cursor,
        output_keys, output_values, &count, 0), -ENOENT);
    failures += expect("batch lookup delete count", count, 3);
    failures += expect_true("batch lookup delete pairs",
                            batch_pair_mask(output_keys, output_values,
                                            count) == 0x7u);
    failures += expect("batch empty", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &one_key, &one_value, 0),
        -ENOENT);

    count = 3u;
    failures += expect("batch restore", map_batch(
        BPF_MAP_UPDATE_BATCH, descriptor, 0, 0, keys, values, &count,
        BPF_ANY), 0);
    count = 2u;
    failures += expect("batch delete", map_batch(
        BPF_MAP_DELETE_BATCH, descriptor, 0, 0, keys, 0, &count, 0), 0);
    failures += expect("batch delete first", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[0], &one_value, 0),
        -ENOENT);
    failures += expect("batch delete second", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[1], &one_value, 0),
        -ENOENT);

    clear_bytes(output_keys, sizeof(output_keys));
    clear_bytes(output_values, sizeof(output_values));
    clear_bytes((void *)&cursor, sizeof(cursor));
    count = 1u;
    failures += expect("batch frozen seed", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[2], &one_value, 0), 0);
    failures += expect("map freeze", map_element(
        BPF_MAP_FREEZE, descriptor, 0, 0, 0), 0);
    failures += expect("map freeze repeated", map_element(
        BPF_MAP_FREEZE, descriptor, 0, 0, 0), -EBUSY);
    failures += expect("frozen lookup", map_element(
        BPF_MAP_LOOKUP_ELEM, descriptor, &keys[2], &one_value, 0), 0);
    failures += expect("frozen update", map_element(
        BPF_MAP_UPDATE_ELEM, descriptor, &keys[2], &values[0], BPF_ANY),
        -EPERM);
    failures += expect("frozen delete", map_element(
        BPF_MAP_DELETE_ELEM, descriptor, &keys[2], 0, 0), -EPERM);
    failures += expect("frozen lookup delete", map_element(
        BPF_MAP_LOOKUP_AND_DELETE_ELEM, descriptor, &keys[2], &one_value,
        0), -EPERM);
    failures += expect("frozen batch lookup", map_batch(
        BPF_MAP_LOOKUP_BATCH, descriptor, 0, &cursor, output_keys,
        output_values, &count, 0), -ENOENT);
    failures += expect("frozen batch lookup count", count, 1);
    failures += expect_true("frozen batch lookup value",
                            output_keys[0] == 3u &&
                            output_values[0] == 33u);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int test_program(void) {
    static const struct bpf_insn instructions[] = {
        { .code = 0xb7u, .registers = 0u, .offset = 0, .immediate = 1 },
        { .code = 0x95u, .registers = 0u, .offset = 0, .immediate = 0 },
    };
    static const char license[] = "GPL";
#if defined(BPF_EXPECT_LEGACY_SHA1_TAG)
    static const uint8_t expected_tag[8] = {
        0x57u, 0xcdu, 0x31u, 0x1fu, 0x2eu, 0x27u, 0x36u, 0x6bu,
    };
#else
    static const uint8_t expected_tag[8] = {
        0xb1u, 0x14u, 0x59u, 0xa0u, 0xe1u, 0x1cu, 0xa1u, 0x4cu,
    };
#endif
    union bpf_attr attribute;
    struct bpf_prog_info info;
    struct bpf_insn translated[2];
    uint8_t oversized_info[240];
    uint32_t program_id;
    uint32_t queried_id = 0u;
    uint32_t queried_flags = UINT32_MAX;
    long cgroup_descriptor;
    long descriptor;
    long reopened;
    int failures = 0;

    clear_bytes(&attribute, sizeof(attribute));
    attribute.prog_load.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
    attribute.prog_load.insn_count = 2u;
    attribute.prog_load.insns = (uint64_t)(uintptr_t)instructions;
    attribute.prog_load.license = (uint64_t)(uintptr_t)license;
    attribute.prog_load.prog_name[0] = 'a';
    attribute.prog_load.prog_name[1] = 'l';
    attribute.prog_load.prog_name[2] = 'l';
    attribute.prog_load.prog_name[3] = 'o';
    attribute.prog_load.prog_name[4] = 'w';
    descriptor = bpf_call(BPF_PROG_LOAD, &attribute);
    failures += expect_true("program load", descriptor >= 0);
    if (descriptor < 0) return failures + 1;
    failures += expect("program cloexec", raw_syscall6(
        SYS_fcntl, descriptor, F_GETFD, 0, 0, 0, 0), FD_CLOEXEC);
    clear_bytes(&info, sizeof(info));
    clear_bytes(translated, sizeof(translated));
    info.xlated_prog_len = sizeof(translated);
    info.xlated_prog_insns = (uint64_t)(uintptr_t)translated;
    clear_bytes(&attribute, sizeof(attribute));
    attribute.info.bpf_fd = (uint32_t)descriptor;
    attribute.info.info_len = sizeof(info);
    attribute.info.info = (uint64_t)(uintptr_t)&info;
    failures += expect("program info", bpf_call(
        BPF_OBJ_GET_INFO_BY_FD, &attribute), 0);
    failures += expect_true(
        "program info values",
        info.type == BPF_PROG_TYPE_CGROUP_DEVICE && info.id != 0u &&
        info.xlated_prog_len == sizeof(instructions) &&
        info.gpl_compatible == 1u && info.verified_insns >= 2u &&
        text_equal(info.name, "allow"));
    for (unsigned long index = 0; index < sizeof(expected_tag); ++index)
        failures += expect_true(
            "program tag", info.tag[index] == expected_tag[index]);
    failures += expect_true(
        "program translated instructions",
        translated[0].code == instructions[0].code &&
        translated[0].immediate == instructions[0].immediate &&
        translated[1].code == instructions[1].code);
    clear_bytes(oversized_info, sizeof(oversized_info));
#if defined(BPF_EXPECT_LEGACY_SHA1_TAG)
    oversized_info[232] = 1u;
#else
    oversized_info[228] = 1u;
#endif
    clear_bytes(&attribute, sizeof(attribute));
    attribute.info.bpf_fd = (uint32_t)descriptor;
#if defined(BPF_EXPECT_LEGACY_SHA1_TAG)
    attribute.info.info_len = 233u;
#else
    attribute.info.info_len = 229u;
#endif
    attribute.info.info = (uint64_t)(uintptr_t)oversized_info;
    failures += expect("program info nonzero tail", bpf_call(
        BPF_OBJ_GET_INFO_BY_FD, &attribute), -E2BIG);
    program_id = info.id;
    clear_bytes(&attribute, sizeof(attribute));
    attribute.id.start_or_object_id = program_id - 1u;
    failures += expect("program next id", bpf_call(
        BPF_PROG_GET_NEXT_ID, &attribute), 0);
    failures += expect_true(
        "program id", attribute.id.next_id == program_id);
    clear_bytes(&attribute, sizeof(attribute));
    attribute.id.start_or_object_id = program_id;
    reopened = bpf_call(BPF_PROG_GET_FD_BY_ID, &attribute);
    failures += expect_true("program reopen", reopened >= 0);
    if (reopened >= 0)
        (void)raw_syscall6(SYS_close, reopened, 0, 0, 0, 0, 0);

    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)"/sys/fs", 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)"/sys/fs/cgroup", 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mount, (long)"none", (long)"/sys/fs/cgroup",
        (long)"cgroup2", 0, 0, 0);
    cgroup_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)"/sys/fs/cgroup",
        O_RDONLY | O_DIRECTORY, 0, 0, 0);
    failures += expect_true("open cgroup root", cgroup_descriptor >= 0);
    if (cgroup_descriptor >= 0) {
        clear_bytes(&attribute, sizeof(attribute));
        attribute.prog_attach.target_fd = (uint32_t)cgroup_descriptor;
        attribute.prog_attach.attach_bpf_fd = (uint32_t)descriptor;
        attribute.prog_attach.attach_type = UINT32_MAX;
        failures += expect("attach invalid type", bpf_call(
            BPF_PROG_ATTACH, &attribute), -EINVAL);
        attribute.prog_attach.attach_type = BPF_CGROUP_DEVICE;
        failures += expect("attach cgroup device", bpf_call(
            BPF_PROG_ATTACH, &attribute), 0);

        clear_bytes(&attribute, sizeof(attribute));
        attribute.prog_query.target_fd = (uint32_t)cgroup_descriptor;
        attribute.prog_query.attach_type = BPF_CGROUP_DEVICE;
        failures += expect("query cgroup size", bpf_call(
            BPF_PROG_QUERY, &attribute), 0);
        failures += expect("query cgroup count",
                           attribute.prog_query.prog_count, 1);
        attribute.prog_query.prog_ids =
            (uint64_t)(uintptr_t)&queried_id;
        attribute.prog_query.prog_count = 1u;
        attribute.prog_query.prog_attach_flags =
            (uint64_t)(uintptr_t)&queried_flags;
        failures += expect("query cgroup program", bpf_call(
            BPF_PROG_QUERY, &attribute), 0);
        failures += expect_true(
            "query cgroup values",
            attribute.prog_query.prog_count == 1u &&
            queried_id == program_id && queried_flags == 0u);

        clear_bytes(&attribute, sizeof(attribute));
        attribute.prog_attach.target_fd = (uint32_t)cgroup_descriptor;
        attribute.prog_attach.attach_bpf_fd = (uint32_t)descriptor;
        attribute.prog_attach.attach_type = BPF_CGROUP_DEVICE;
        failures += expect("detach cgroup device", bpf_call(
            BPF_PROG_DETACH, &attribute), 0);
        clear_bytes(&attribute, sizeof(attribute));
        attribute.prog_query.target_fd = (uint32_t)cgroup_descriptor;
        attribute.prog_query.attach_type = BPF_CGROUP_DEVICE;
        attribute.prog_query.prog_ids =
            (uint64_t)(uintptr_t)&queried_id;
        attribute.prog_query.prog_count = 1u;
        failures += expect("query cgroup empty", bpf_call(
            BPF_PROG_QUERY, &attribute), 0);
        failures += expect("query cgroup empty count",
                           attribute.prog_query.prog_count, 0);
        (void)raw_syscall6(
            SYS_close, cgroup_descriptor, 0, 0, 0, 0, 0);
    }
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return failures;
}

static int test_attribute_tail(void) {
    union bpf_attr attribute;

    clear_bytes(&attribute, sizeof(attribute));
    attribute.map_create.map_type = BPF_MAP_TYPE_ARRAY;
    attribute.map_create.key_size = 4u;
    attribute.map_create.value_size = 8u;
    attribute.map_create.max_entries = 1u;
    attribute.padding[sizeof(attribute) - 1u] = 1u;
    return expect("nonzero attribute tail", bpf_call(
               BPF_MAP_CREATE, &attribute), -EINVAL) +
           expect("oversized attribute", bpf_call_size(
               BPF_MAP_CREATE, &attribute, 4097u), -E2BIG);
}

START_ATTRIBUTES void _start(void) {
    int failures = test_array_map();

    if (failures == 77) {
        print_text("BPF_ABI_PROBE_SKIP permission\n");
        (void)raw_syscall6(SYS_exit, 77, 0, 0, 0, 0, 0);
    }
    failures += test_hash_map();
    failures += test_lru_hash_map();
    failures += test_queue_stack_maps();
    failures += test_percpu_maps();
    failures += test_lru_percpu_hash_map();
    failures += test_batch_and_freeze();
    failures += test_program();
    failures += test_attribute_tail();
    print_text(failures ? "BPF_ABI_PROBE_FAIL\n" :
                          "BPF_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
