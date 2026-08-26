/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF inode local-storage syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_bpf 321
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_openat 56
#define SYS_close 57
#define SYS_unlinkat 35
#define SYS_write 64
#define SYS_exit 93
#define SYS_bpf 280
#else
#error "bpf_inode_storage_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD -100
#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 64
#define O_EXCL 128

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_BTF_LOAD 18
#define BPF_MAP_TYPE_INODE_STORAGE 28
#define BPF_F_NO_PREALLOC 1
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define ENOENT 2
#define EBADF 9
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

void *memcpy(void *destination, const void *source, unsigned long length) {
    volatile unsigned char *output = destination;
    const volatile unsigned char *input = source;

    while (length--) *output++ = *input++;
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

    attribute.map_type = BPF_MAP_TYPE_INODE_STORAGE;
    attribute.key_size = sizeof(int32_t);
    attribute.value_size = sizeof(uint32_t);
    attribute.max_entries = max_entries;
    attribute.map_flags = flags;
    attribute.btf_fd = (uint32_t)btf_fd;
    attribute.btf_key_type_id = 1u;
    attribute.btf_value_type_id = 1u;
    attribute.map_name[0] = 'i';
    attribute.map_name[1] = 'n';
    attribute.map_name[2] = 's';
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

static int test_inode_storage(void) {
    uint32_t value = 0x11223344u;
    uint32_t replacement = 0x88776655u;
    uint32_t output = 0u;
    int bad_fd = 9999;
    int first_fd;
    int second_fd;
    int reopened_fd;
    long btf_fd;
    long map_fd;
    int failures = 0;

    btf_fd = load_integer_btf();
    if (btf_fd < 0)
        return expect_result("inode-btf-load", btf_fd, 0) + 1;
    failures += expect_result(
        "inode-no-prealloc-required", create_map(
            (int)btf_fd, 0u, 0u), -EINVAL);
    failures += expect_result(
        "inode-zero-max-required", create_map(
            (int)btf_fd, BPF_F_NO_PREALLOC, 1u), -EINVAL);
    map_fd = create_map((int)btf_fd, BPF_F_NO_PREALLOC, 0u);
    if (map_fd < 0) {
        failures += expect_result("inode-create", map_fd, 0);
        goto close_btf;
    }
    first_fd = (int)raw_syscall6(
        SYS_openat, AT_FDCWD,
        (long)"/probes/bpf_inode_storage_abi_probe",
        O_RDONLY, 0, 0, 0);
    second_fd = (int)raw_syscall6(
        SYS_openat, AT_FDCWD,
        (long)"/probes/bpf_inode_storage_abi_probe",
        O_RDONLY, 0, 0, 0);
    if (first_fd < 0 || second_fd < 0) {
        failures += expect_result("inode-open-first", first_fd, 0);
        failures += expect_result("inode-open-second", second_fd, 0);
        goto close_files;
    }

    failures += expect_result(
        "inode-bad-fd", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &bad_fd,
            &value, BPF_ANY), -EBADF);
    failures += expect_result(
        "inode-lookup-empty", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map_fd, &first_fd,
            &output, 0), -ENOENT);
    failures += expect_result(
        "inode-exist-empty", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &first_fd,
            &value, BPF_EXIST), -ENOENT);
    failures += expect_result(
        "inode-insert", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &first_fd,
            &value, BPF_NOEXIST), 0);
    failures += expect_result(
        "inode-second-fd-lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map_fd, &second_fd,
            &output, 0), 0);
    failures += expect_result(
        "inode-value", (long)output, (long)value);
    failures += expect_result(
        "inode-noexist", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &second_fd,
            &replacement, BPF_NOEXIST), -EEXIST);
    failures += expect_result(
        "inode-replace", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &second_fd,
            &replacement, BPF_EXIST), 0);
    failures += expect_result(
        "inode-next-unsupported", map_element(
            BPF_MAP_GET_NEXT_KEY, (int)map_fd, 0,
            &bad_fd, 0), -ENOTSUPP);
    (void)raw_syscall6(SYS_close, first_fd, 0, 0, 0, 0, 0);
    first_fd = -1;
    (void)raw_syscall6(SYS_close, second_fd, 0, 0, 0, 0, 0);
    second_fd = -1;
    reopened_fd = (int)raw_syscall6(
        SYS_openat, AT_FDCWD,
        (long)"/probes/bpf_inode_storage_abi_probe",
        O_RDONLY, 0, 0, 0);
    if (reopened_fd >= 0) {
        failures += expect_result(
            "inode-persists-after-close", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map_fd, &reopened_fd,
                &output, 0), 0);
        failures += expect_result(
            "inode-delete", map_element(
                BPF_MAP_DELETE_ELEM, (int)map_fd, &reopened_fd,
                0, 0), 0);
        failures += expect_result(
            "inode-delete-empty", map_element(
                BPF_MAP_DELETE_ELEM, (int)map_fd, &reopened_fd,
                0, 0), -ENOENT);
        (void)raw_syscall6(SYS_close, reopened_fd, 0, 0, 0, 0, 0);
    }

    for (uint32_t iteration = 0; iteration < 300u; ++iteration) {
        int transient_fd = (int)raw_syscall6(
            SYS_openat, AT_FDCWD,
            (long)"/inode-storage-owner-test",
            O_RDWR | O_CREAT | O_EXCL, 0600, 0, 0);
        long insert_result;

        if (transient_fd < 0) {
            failures += expect_result(
                "inode-destroy-open", transient_fd, 0);
            break;
        }
        insert_result = map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd,
            &transient_fd, &value, BPF_NOEXIST);
        if (insert_result != 0) {
            failures += expect_result(
                "inode-destroy-insert", insert_result, 0);
            (void)raw_syscall6(
                SYS_unlinkat, AT_FDCWD,
                (long)"/inode-storage-owner-test", 0, 0, 0, 0);
            (void)raw_syscall6(
                SYS_close, transient_fd, 0, 0, 0, 0, 0);
            break;
        }
        failures += expect_result(
            "inode-destroy-unlink", raw_syscall6(
                SYS_unlinkat, AT_FDCWD,
                (long)"/inode-storage-owner-test", 0, 0, 0, 0), 0);
        failures += expect_result(
            "inode-open-unlinked", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map_fd,
                &transient_fd, &output, 0), 0);
        (void)raw_syscall6(
            SYS_close, transient_fd, 0, 0, 0, 0, 0);
        if (failures) break;
    }

close_files:
    if (first_fd >= 0)
        (void)raw_syscall6(SYS_close, first_fd, 0, 0, 0, 0, 0);
    if (second_fd >= 0)
        (void)raw_syscall6(SYS_close, second_fd, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, map_fd, 0, 0, 0, 0, 0);
close_btf:
    (void)raw_syscall6(SYS_close, btf_fd, 0, 0, 0, 0, 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = test_inode_storage();

    print_text(failures ? "BPF_INODE_STORAGE_ABI_FAIL\n" :
                          "BPF_INODE_STORAGE_ABI_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
