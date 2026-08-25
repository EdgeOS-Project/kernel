/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF socket-map syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_socketpair 53
#define SYS_exit 60
#define SYS_bpf 321
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_socketpair 199
#define SYS_bpf 280
#else
#error "bpf_sockmap_abi_probe requires a Linux 64-bit architecture"
#endif

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_MAP_TYPE_SOCKMAP 15
#define BPF_MAP_TYPE_SOCKHASH 18
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define ENOENT 2
#define E2BIG 7
#define EBADF 9
#define ENOSPC 28
#define EINVAL 22
#define EEXIST 17
#define EOPNOTSUPP 95

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

static int expect_nonzero(const char *name, uint64_t value) {
    if (value) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" expected nonzero\n");
    return 1;
}

static long create_map(uint32_t type, uint32_t key_size,
                       uint32_t value_size, uint32_t max_entries) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = type;
    attribute.key_size = key_size;
    attribute.value_size = value_size;
    attribute.max_entries = max_entries;
    attribute.map_name[0] = 's';
    attribute.map_name[1] = 'o';
    attribute.map_name[2] = 'c';
    attribute.map_name[3] = 'k';
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
        SYS_bpf, command, (long)&attribute, sizeof(attribute), 0, 0, 0);
}

static int open_socket_pair(int type, int descriptors[2]) {
    long status = raw_syscall6(
        SYS_socketpair, AF_UNIX, type, 0,
        (long)descriptors, 0, 0);

    return (int)status;
}

static int test_sockmap(void) {
    uint32_t key = 1u;
    uint32_t next = UINT32_MAX;
    uint64_t value;
    uint64_t cookie = 0u;
    uint64_t second_cookie = 0u;
    int sockets[2] = {-1, -1};
    long map;
    int failures = 0;

    failures += expect_result(
        "sockmap-key-size",
        create_map(BPF_MAP_TYPE_SOCKMAP, 8u, 8u, 3u), -EINVAL);
    failures += expect_result(
        "sockmap-value-size",
        create_map(BPF_MAP_TYPE_SOCKMAP, 4u, 16u, 3u), -EINVAL);
    map = create_map(BPF_MAP_TYPE_SOCKMAP, 4u, 8u, 3u);
    if (map < 0) return failures + expect_result("sockmap-create", map, 0);
    value = 9999u;
    failures += expect_result(
        "sockmap-fd-before-flags", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map, &key, &value, 3u), -EBADF);
    failures += expect_result(
        "socketpair", open_socket_pair(SOCK_STREAM, sockets), 0);
    if (sockets[0] >= 0) {
        value = (uint32_t)sockets[0];
        failures += expect_result(
            "sockmap-update", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key, &value, BPF_ANY), 0);
        failures += expect_result(
            "sockmap-lookup", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map, &key, &cookie, 0), 0);
        failures += expect_nonzero("sockmap-cookie", cookie);
        (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
        sockets[0] = -1;
        failures += expect_result(
            "sockmap-close-removes", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map, &key, &second_cookie, 0),
            -ENOENT);
        value = (uint32_t)sockets[1];
        failures += expect_result(
            "sockmap-noexist", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key, &value,
                BPF_NOEXIST), 0);
        failures += expect_result(
            "sockmap-replace", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key, &value,
                BPF_EXIST), 0);
    }
    failures += expect_result(
        "sockmap-next", map_element(
            BPF_MAP_GET_NEXT_KEY, (int)map, &key, &next, 0), 0);
    failures += expect_result("sockmap-next-value", next, 2);
    failures += expect_result(
        "sockmap-delete", map_element(
            BPF_MAP_DELETE_ELEM, (int)map, &key, 0, 0), 0);
    failures += expect_result(
        "sockmap-delete-empty", map_element(
            BPF_MAP_DELETE_ELEM, (int)map, &key, 0, 0), -EINVAL);
    value = 9999u;
    failures += expect_result(
        "sockmap-bad-fd", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map, &key, &value, BPF_ANY),
        -EBADF);
    if (sockets[1] >= 0)
        (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, map, 0, 0, 0, 0, 0);
    return failures;
}

static int test_sockhash(void) {
    uint64_t key = 0x1020304050607080ull;
    uint64_t value;
    uint64_t cookie = 0u;
    int sockets[2] = {-1, -1};
    long map;
    int failures = 0;

    failures += expect_result(
        "sockhash-key-size",
        create_map(BPF_MAP_TYPE_SOCKHASH, 513u, 8u, 2u), -E2BIG);
    map = create_map(BPF_MAP_TYPE_SOCKHASH, 8u, 8u, 2u);
    if (map < 0) return failures + expect_result("sockhash-create", map, 0);
    failures += expect_result(
        "sockhash-socketpair", open_socket_pair(SOCK_STREAM, sockets), 0);
    if (sockets[0] >= 0) {
        value = (uint32_t)sockets[0];
        failures += expect_result(
            "sockhash-update", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key, &value, BPF_ANY), 0);
        failures += expect_result(
            "sockhash-lookup", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map, &key, &cookie, 0), 0);
        failures += expect_nonzero("sockhash-cookie", cookie);
        failures += expect_result(
            "sockhash-delete", map_element(
                BPF_MAP_DELETE_ELEM, (int)map, &key, 0, 0), 0);
        failures += expect_result(
            "sockhash-delete-empty", map_element(
                BPF_MAP_DELETE_ELEM, (int)map, &key, 0, 0), -ENOENT);
    }
    if (sockets[0] >= 0)
        (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
    if (sockets[1] >= 0)
        (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, map, 0, 0, 0, 0, 0);

    map = create_map(BPF_MAP_TYPE_SOCKMAP, 4u, 4u, 1u);
    if (map >= 0) {
        uint32_t array_key = 0u;

        failures += expect_result(
            "small-socketpair", open_socket_pair(SOCK_STREAM, sockets), 0);
        if (sockets[0] >= 0) {
            uint32_t descriptor = (uint32_t)sockets[0];

            failures += expect_result(
                "small-update", map_element(
                    BPF_MAP_UPDATE_ELEM, (int)map, &array_key,
                    &descriptor, BPF_ANY), 0);
            failures += expect_result(
                "small-lookup", map_element(
                    BPF_MAP_LOOKUP_ELEM, (int)map, &array_key,
                    &descriptor, 0), -ENOSPC);
        }
        if (sockets[0] >= 0)
            (void)raw_syscall6(SYS_close, sockets[0], 0, 0, 0, 0, 0);
        if (sockets[1] >= 0)
            (void)raw_syscall6(SYS_close, sockets[1], 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, map, 0, 0, 0, 0, 0);
    } else {
        failures += expect_result("small-create", map, 0);
    }
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = test_sockmap() + test_sockhash();

    print_text(failures ? "BPF_SOCKMAP_ABI_FAIL\n" :
                          "BPF_SOCKMAP_ABI_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
