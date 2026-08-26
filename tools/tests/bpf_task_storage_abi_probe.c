/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF task local-storage syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_kill 62
#define SYS_sched_yield 24
#define SYS_bpf 321
#define SYS_pidfd_open 434
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_kill 129
#define SYS_sched_yield 124
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_wait4 260
#define SYS_bpf 280
#define SYS_pidfd_open 434
#else
#error "bpf_task_storage_abi_probe requires a Linux 64-bit architecture"
#endif

#define SIGCHLD 17
#define SIGKILL 9

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_BTF_LOAD 18
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_F_NO_PREALLOC 1
#define BPF_F_CLONE (1u << 9)
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define ENOENT 2
#define EBADF 9
#define ESRCH 3
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

struct bpf_btf_load_attribute {
    uint64_t btf;
    uint64_t log_buffer;
    uint32_t btf_size;
    uint32_t log_size;
    uint32_t log_level;
    uint32_t log_true_size;
    uint32_t btf_flags;
    int32_t token_fd;
};

struct test_btf_blob {
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
    uint32_t size;
    uint32_t int_data;
    char strings[5];
} __attribute__((packed));

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

static long load_integer_btf(void) {
    struct test_btf_blob blob = {
        .magic = 0xeb9fu,
        .version = 1u,
        .header_length = 24u,
        .type_length = 16u,
        .string_offset = 16u,
        .string_length = 5u,
        .name_offset = 1u,
        .info = 1u << 24,
        .size = 4u,
        .int_data = (1u << 24) | 32u,
        .strings = {0, 'i', 'n', 't', 0},
    };
    struct bpf_btf_load_attribute attribute = {0};

    attribute.btf = (uint64_t)(uintptr_t)&blob;
    attribute.btf_size = sizeof(blob);
    return raw_syscall6(
        SYS_bpf, BPF_BTF_LOAD, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long create_map(int btf_fd, uint32_t flags,
                       uint32_t max_entries) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = BPF_MAP_TYPE_TASK_STORAGE;
    attribute.key_size = sizeof(int32_t);
    attribute.value_size = sizeof(uint32_t);
    attribute.max_entries = max_entries;
    attribute.map_flags = flags;
    attribute.btf_fd = (uint32_t)btf_fd;
    attribute.btf_key_type_id = 1u;
    attribute.btf_value_type_id = 1u;
    attribute.map_name[0] = 't';
    attribute.map_name[1] = 's';
    return raw_syscall6(
        SYS_bpf, BPF_MAP_CREATE, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long map_element(long command, int map_fd, const void *key,
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

static int test_task_storage(void) {
    uint32_t value = 0x11223344u;
    uint32_t replacement = 0x88776655u;
    uint32_t output = 0u;
    int bad_fd = 9999;
    int self_pidfd = -1;
    int child_pidfd = -1;
    long child;
    long btf_fd;
    long map_fd;
    int failures = 0;

    btf_fd = load_integer_btf();
    if (btf_fd < 0)
        return expect_result("task-btf-load", btf_fd, 0) + 1;
    failures += expect_result(
        "task-no-prealloc-required", create_map(
            (int)btf_fd, 0u, 0u), -EINVAL);
    failures += expect_result(
        "task-zero-max-required", create_map(
            (int)btf_fd, BPF_F_NO_PREALLOC, 1u), -EINVAL);
    map_fd = create_map(
        (int)btf_fd, BPF_F_NO_PREALLOC | BPF_F_CLONE, 0u);
    if (map_fd < 0) {
        failures += expect_result("task-create", map_fd, 0);
        goto close_btf;
    }
    self_pidfd = (int)raw_syscall6(
        SYS_pidfd_open, raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0),
        0, 0, 0, 0, 0);
    if (self_pidfd < 0) {
        failures += expect_result("task-self-pidfd", self_pidfd, 0);
        goto close_map;
    }
    failures += expect_result(
        "task-bad-pidfd", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &bad_fd,
            &value, BPF_ANY), -EBADF);
    failures += expect_result(
        "task-lookup-empty", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map_fd, &self_pidfd,
            &output, 0), -ENOENT);
    failures += expect_result(
        "task-exist-empty", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &self_pidfd,
            &value, BPF_EXIST), -ENOENT);
    failures += expect_result(
        "task-insert", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &self_pidfd,
            &value, BPF_NOEXIST), 0);
    failures += expect_result(
        "task-noexist", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &self_pidfd,
            &replacement, BPF_NOEXIST), -EEXIST);
    failures += expect_result(
        "task-replace", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &self_pidfd,
            &replacement, BPF_EXIST), 0);
    failures += expect_result(
        "task-lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map_fd, &self_pidfd,
            &output, 0), 0);
    failures += expect_result("task-value", output, replacement);
    failures += expect_result(
        "task-next-unsupported", map_element(
            BPF_MAP_GET_NEXT_KEY, (int)map_fd, 0, &bad_fd, 0),
        -ENOTSUPP);

    child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (child == 0) {
        for (;;) (void)raw_syscall6(
            SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    if (child < 0) {
        failures += expect_result("task-clone", child, 0);
    } else {
        child_pidfd = (int)raw_syscall6(
            SYS_pidfd_open, child, 0, 0, 0, 0, 0);
        if (child_pidfd < 0) {
            failures += expect_result(
                "task-child-pidfd", child_pidfd, 0);
        } else {
            failures += expect_result(
                "task-child-insert", map_element(
                    BPF_MAP_UPDATE_ELEM, (int)map_fd, &child_pidfd,
                    &value, BPF_NOEXIST), 0);
        }
        failures += expect_result(
            "task-kill-child", raw_syscall6(
                SYS_kill, child, SIGKILL, 0, 0, 0, 0), 0);
        failures += expect_result(
            "task-wait-child", raw_syscall6(
                SYS_wait4, child, 0, 0, 0, 0, 0), child);
        if (child_pidfd >= 0) {
            failures += expect_result(
                "task-dead-owner", map_element(
                    BPF_MAP_LOOKUP_ELEM, (int)map_fd, &child_pidfd,
                    &output, 0), -ENOENT);
            (void)raw_syscall6(
                SYS_close, child_pidfd, 0, 0, 0, 0, 0);
        }
    }

    failures += expect_result(
        "task-delete", map_element(
            BPF_MAP_DELETE_ELEM, (int)map_fd, &self_pidfd,
            0, 0), 0);
    failures += expect_result(
        "task-delete-empty", map_element(
            BPF_MAP_DELETE_ELEM, (int)map_fd, &self_pidfd,
            0, 0), -ENOENT);
    (void)raw_syscall6(SYS_close, self_pidfd, 0, 0, 0, 0, 0);
close_map:
    (void)raw_syscall6(SYS_close, map_fd, 0, 0, 0, 0, 0);
close_btf:
    (void)raw_syscall6(SYS_close, btf_fd, 0, 0, 0, 0, 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = test_task_storage();

    print_text(failures ? "BPF_TASK_STORAGE_ABI_FAIL\n" :
                          "BPF_TASK_STORAGE_ABI_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
