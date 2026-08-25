/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF reuseport socket-array syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_socket 41
#define SYS_bind 49
#define SYS_listen 50
#define SYS_setsockopt 54
#define SYS_exit 60
#define SYS_bpf 321
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_setsockopt 208
#define SYS_bpf 280
#else
#error "bpf_reuseport_array_abi_probe requires a Linux 64-bit architecture"
#endif

#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_REUSEPORT 15

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define ENOENT 2
#define E2BIG 7
#define EBADF 9
#define EEXIST 17
#define EINVAL 22
#define ENOSPC 28
#define ENOTSOCK 88
#define EBUSY 16
#define ENOTSUPP 524

struct sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t zero[8];
};

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

static long create_map(uint32_t key_size, uint32_t value_size,
                       uint32_t max_entries) {
    struct bpf_map_create_attribute attribute = {0};

    attribute.map_type = BPF_MAP_TYPE_REUSEPORT_SOCKARRAY;
    attribute.key_size = key_size;
    attribute.value_size = value_size;
    attribute.max_entries = max_entries;
    attribute.map_name[0] = 'r';
    attribute.map_name[1] = 'e';
    attribute.map_name[2] = 'u';
    attribute.map_name[3] = 's';
    attribute.map_name[4] = 'e';
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

static int open_bound_socket(int type, int reuse_port, int listen_socket) {
    struct sockaddr_in address = {0};
    int enabled = 1;
    long descriptor = raw_syscall6(
        SYS_socket, AF_INET, type, 0, 0, 0, 0);
    long status;

    if (descriptor < 0) return (int)descriptor;
    if (reuse_port) {
        status = raw_syscall6(
            SYS_setsockopt, descriptor, SOL_SOCKET, SO_REUSEPORT,
            (long)&enabled, sizeof(enabled), 0);
        if (status < 0) {
            print_text("OPEN_FAIL setsockopt status=");
            print_number(status);
            print_text("\n");
            goto fail;
        }
    }
    address.family = AF_INET;
    status = raw_syscall6(
        SYS_bind, descriptor, (long)&address, sizeof(address),
        0, 0, 0);
    if (status < 0) {
        print_text("OPEN_FAIL bind status=");
        print_number(status);
        print_text("\n");
        goto fail;
    }
    if (listen_socket) {
        status = raw_syscall6(
            SYS_listen, descriptor, 4, 0, 0, 0, 0);
        if (status < 0) {
            print_text("OPEN_FAIL listen status=");
            print_number(status);
            print_text("\n");
            goto fail;
        }
    }
    return (int)descriptor;
fail:
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return (int)status;
}

static int test_reuseport_array(void) {
    uint32_t key = 1u;
    uint32_t key_two = 2u;
    uint32_t out_of_range = 3u;
    uint32_t next = UINT32_MAX;
    uint64_t value = 9999u;
    uint64_t cookie = 0u;
    int first = -1;
    int second = -1;
    int udp = -1;
    int unbound = -1;
    int no_reuse = -1;
    int unix_socket = -1;
    long map;
    int failures = 0;

    failures += expect_result(
        "reuseport-key-size", create_map(8u, 8u, 3u), -EINVAL);
    failures += expect_result(
        "reuseport-value-size", create_map(4u, 16u, 3u), -EINVAL);
    map = create_map(4u, 8u, 3u);
    if (map < 0)
        return failures + expect_result("reuseport-create", map, 0);

    failures += expect_result(
        "reuseport-flags-before-index", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map, &out_of_range,
            &value, 3u), -EINVAL);
    failures += expect_result(
        "reuseport-index-before-fd", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map, &out_of_range,
            &value, BPF_ANY), -E2BIG);
    failures += expect_result(
        "reuseport-bad-fd", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map, &key,
            &value, BPF_ANY), -EBADF);

    value = 0u;
    failures += expect_result(
        "reuseport-not-socket", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map, &key,
            &value, BPF_ANY), -ENOTSOCK);

    unbound = (int)raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (unbound >= 0) {
        int enabled = 1;

        (void)raw_syscall6(
            SYS_setsockopt, unbound, SOL_SOCKET, SO_REUSEPORT,
            (long)&enabled, sizeof(enabled), 0);
        value = (uint32_t)unbound;
        failures += expect_result(
            "reuseport-unbound", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key,
                &value, BPF_ANY), -EINVAL);
    }
    no_reuse = open_bound_socket(SOCK_STREAM, 0, 1);
    if (no_reuse >= 0) {
        value = (uint32_t)no_reuse;
        failures += expect_result(
            "reuseport-option-required", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key,
                &value, BPF_ANY), -EINVAL);
    }
    unix_socket = (int)raw_syscall6(
        SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
    if (unix_socket >= 0) {
        value = (uint32_t)unix_socket;
        failures += expect_result(
            "reuseport-family", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key,
                &value, BPF_ANY), -ENOTSUPP);
    }

    first = open_bound_socket(SOCK_STREAM, 1, 1);
    second = open_bound_socket(SOCK_STREAM, 1, 1);
    udp = open_bound_socket(SOCK_DGRAM, 1, 0);
    failures += expect_result(
        "reuseport-first-socket", first < 0 ? first : 0, 0);
    failures += expect_result(
        "reuseport-second-socket", second < 0 ? second : 0, 0);
    failures += expect_result(
        "reuseport-udp-socket", udp < 0 ? udp : 0, 0);
    if (first >= 0) {
        value = (uint32_t)first;
        failures += expect_result(
            "reuseport-exist-empty", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key,
                &value, BPF_EXIST), -ENOENT);
        failures += expect_result(
            "reuseport-insert", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key,
                &value, BPF_ANY), 0);
        failures += expect_result(
            "reuseport-lookup", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map, &key,
                &cookie, 0), 0);
        failures += expect_nonzero("reuseport-cookie", cookie);
        failures += expect_result(
            "reuseport-one-membership", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key_two,
                &value, BPF_ANY), -EBUSY);
        failures += expect_result(
            "reuseport-noexist", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key,
                &value, BPF_NOEXIST), -EEXIST);
    }
    if (second >= 0) {
        value = (uint32_t)second;
        failures += expect_result(
            "reuseport-replace", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key,
                &value, BPF_ANY), 0);
    }
    if (first >= 0) {
        value = (uint32_t)first;
        failures += expect_result(
            "reuseport-old-reinsert", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key_two,
                &value, BPF_ANY), 0);
    }
    failures += expect_result(
        "reuseport-next-null", map_element(
            BPF_MAP_GET_NEXT_KEY, (int)map, 0, &next, 0), 0);
    failures += expect_result("reuseport-next-null-value", next, 0);
    failures += expect_result(
        "reuseport-delete-range", map_element(
            BPF_MAP_DELETE_ELEM, (int)map, &out_of_range, 0, 0), -E2BIG);
    failures += expect_result(
        "reuseport-delete", map_element(
            BPF_MAP_DELETE_ELEM, (int)map, &key_two, 0, 0), 0);
    failures += expect_result(
        "reuseport-delete-empty", map_element(
            BPF_MAP_DELETE_ELEM, (int)map, &key_two, 0, 0), -ENOENT);
    if (udp >= 0) {
        value = (uint32_t)udp;
        failures += expect_result(
            "reuseport-udp-insert", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map, &key_two,
                &value, BPF_ANY), 0);
        (void)raw_syscall6(SYS_close, udp, 0, 0, 0, 0, 0);
        udp = -1;
        failures += expect_result(
            "reuseport-close-removes", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map, &key_two,
                &cookie, 0), -ENOENT);
    }
    if (first >= 0)
        (void)raw_syscall6(SYS_close, first, 0, 0, 0, 0, 0);
    if (second >= 0)
        (void)raw_syscall6(SYS_close, second, 0, 0, 0, 0, 0);
    if (unbound >= 0)
        (void)raw_syscall6(SYS_close, unbound, 0, 0, 0, 0, 0);
    if (no_reuse >= 0)
        (void)raw_syscall6(SYS_close, no_reuse, 0, 0, 0, 0, 0);
    if (unix_socket >= 0)
        (void)raw_syscall6(SYS_close, unix_socket, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, map, 0, 0, 0, 0, 0);
    return failures;
}

static int test_small_value(void) {
    uint32_t key = 0u;
    uint32_t value;
    int socket = open_bound_socket(SOCK_DGRAM, 1, 0);
    long map = create_map(4u, 4u, 1u);
    int failures = 0;

    if (map < 0 || socket < 0) return 1;
    value = (uint32_t)socket;
    failures += expect_result(
        "reuseport-small-insert", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map, &key,
            &value, BPF_ANY), 0);
    failures += expect_result(
        "reuseport-small-lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map, &key,
            &value, 0), -ENOSPC);
    (void)raw_syscall6(SYS_close, socket, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, map, 0, 0, 0, 0, 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
    int failures = test_reuseport_array() + test_small_value();

    print_text(failures ? "BPF_REUSEPORT_ARRAY_ABI_FAIL\n" :
                          "BPF_REUSEPORT_ARRAY_ABI_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
