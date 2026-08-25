/* SPDX-License-Identifier: MPL-2.0 */
/* Linux BPF_MAP_TYPE_CGROUP_ARRAY syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_mount 165
#define SYS_unlinkat 263
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_bpf 321
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_write 64
#define SYS_close 57
#define SYS_exit 93
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_bpf 280
#else
#error "bpf_cgroup_array_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200
#define O_RDONLY 0
#define O_DIRECTORY 00200000
#define O_CLOEXEC 02000000

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_MAP_TYPE_CGROUP_ARRAY 8
#define BPF_ANY 0
#define BPF_EXIST 2

#define ENOENT 2
#define EBADF 9
#define EINVAL 22
#define E2BIG 7
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

void *memset(void *destination, int value, unsigned long length) {
    volatile unsigned char *bytes =
        (volatile unsigned char *)destination;

    while (length--) *bytes++ = (unsigned char)value;
    return destination;
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
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
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

static long create_map(uint32_t value_size) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = BPF_MAP_TYPE_CGROUP_ARRAY;
    attribute.key_size = sizeof(uint32_t);
    attribute.value_size = value_size;
    attribute.max_entries = 2u;
    attribute.map_name[0] = 'c';
    attribute.map_name[1] = 'g';
    attribute.map_name[2] = 'a';
    return raw_syscall6(
        SYS_bpf, BPF_MAP_CREATE, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long map_element(long command, int map_fd, uint32_t *key,
                        int *value, uint64_t flags) {
    struct bpf_map_element_attribute attribute = {0};

    attribute.map_fd = (uint32_t)map_fd;
    attribute.key = (uint64_t)(uintptr_t)key;
    attribute.value = (uint64_t)(uintptr_t)value;
    attribute.flags = flags;
    return raw_syscall6(
        SYS_bpf, command, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

START_ATTRIBUTES void _start(void) {
    uint32_t key = 0u;
    uint32_t next_key = UINT32_MAX;
    int cgroup_fd;
    int map_fd;
    int failures = 0;

    failures += expect_result(
        "invalid-value-size", create_map(sizeof(uint64_t)), -EINVAL);
    map_fd = (int)create_map(sizeof(uint32_t));
    if (map_fd < 0) {
        print_text("FAIL map-create actual=");
        print_number(map_fd);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)"/sys", 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)"/sys/fs", 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)"/sys/fs/cgroup", 0755, 0, 0, 0);
    (void)raw_syscall6(
        SYS_mount, (long)"none", (long)"/sys/fs/cgroup",
        (long)"cgroup2", 0, 0, 0);
    failures += expect_result(
        "create-cgroup", raw_syscall6(
            SYS_mkdirat, AT_FDCWD,
            (long)"/sys/fs/cgroup/edge-bpf-array", 0755, 0, 0, 0),
        0);
    cgroup_fd = (int)raw_syscall6(
        SYS_openat, AT_FDCWD, (long)"/sys/fs/cgroup/edge-bpf-array",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
    if (cgroup_fd < 0) {
        print_text("FAIL open-cgroup actual=");
        print_number(cgroup_fd);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }

    failures += expect_result(
        "lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, map_fd, &key, &cgroup_fd, 0),
        -ENOTSUPP);
    failures += expect_result(
        "delete-empty", map_element(
            BPF_MAP_DELETE_ELEM, map_fd, &key, 0, 0),
        -ENOENT);
    failures += expect_result(
        "invalid-flags", map_element(
            BPF_MAP_UPDATE_ELEM, map_fd, &key, &cgroup_fd, BPF_EXIST),
        -EINVAL);
    failures += expect_result(
        "invalid-descriptor", map_element(
            BPF_MAP_UPDATE_ELEM, map_fd, &key, &map_fd, BPF_ANY),
        -EBADF);
    failures += expect_result(
        "update", map_element(
            BPF_MAP_UPDATE_ELEM, map_fd, &key, &cgroup_fd, BPF_ANY),
        0);
    failures += expect_result(
        "next-key", map_element(
            BPF_MAP_GET_NEXT_KEY, map_fd, &key, (int *)&next_key, 0),
        0);
    failures += expect_result("next-key-value", next_key, 1);
    failures += expect_result(
        "close-cgroup", raw_syscall6(
            SYS_close, cgroup_fd, 0, 0, 0, 0, 0),
        0);
    failures += expect_result(
        "remove-retained-cgroup", raw_syscall6(
            SYS_unlinkat, AT_FDCWD,
            (long)"/sys/fs/cgroup/edge-bpf-array", AT_REMOVEDIR,
            0, 0, 0),
        0);
    failures += expect_result(
        "delete-retained", map_element(
            BPF_MAP_DELETE_ELEM, map_fd, &key, 0, 0),
        0);
    failures += expect_result(
        "delete-again", map_element(
            BPF_MAP_DELETE_ELEM, map_fd, &key, 0, 0),
        -ENOENT);
    failures += expect_result(
        "close-map", raw_syscall6(
            SYS_close, map_fd, 0, 0, 0, 0, 0),
        0);

    if (failures) {
        print_text("BPF_CGROUP_ARRAY_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("BPF_CGROUP_ARRAY_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
