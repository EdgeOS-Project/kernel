/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF socket local-storage syscall ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_dup 32
#define SYS_socket 41
#define SYS_connect 42
#define SYS_accept 43
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_bind 49
#define SYS_listen 50
#define SYS_exit 60
#define SYS_openat 257
#define SYS_bpf 321
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_dup 23
#define SYS_openat 56
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_connect 203
#define SYS_sendto 206
#define SYS_recvfrom 207
#define SYS_bpf 280
#else
#error "bpf_sk_storage_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD -100
#define O_RDONLY 0
#define AF_INET 2
#define AF_NETLINK 16
#define SOCK_STREAM 1
#define SOCK_RAW 3
#define SOCK_NONBLOCK 0x800
#define NETLINK_SOCK_DIAG 4
#define SOCK_DIAG_BY_FAMILY 20
#define NLM_F_REQUEST 1u
#define NLM_F_ROOT 0x100u
#define NLM_F_MATCH 0x200u
#define TCP_LISTEN 10u
#define INET_DIAG_REQ_SK_BPF_STORAGES 2u
#define INET_DIAG_SK_BPF_STORAGES 20u
#define SK_DIAG_BPF_STORAGE_REQ_MAP_FD 1u
#define SK_DIAG_BPF_STORAGE 1u
#define SK_DIAG_BPF_STORAGE_MAP_ID 2u
#define SK_DIAG_BPF_STORAGE_MAP_VALUE 3u
#define NLA_F_NESTED 0x8000u

struct socket_address_v4 {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t padding[8];
};

struct socket_address_netlink {
    uint16_t family;
    uint16_t padding;
    uint32_t port_id;
    uint32_t groups;
};

struct netlink_header {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t port_id;
};

struct netlink_attribute {
    uint16_t length;
    uint16_t type;
};

struct inet_diag_sockid {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t source[4];
    uint32_t destination[4];
    uint32_t interface_index;
    uint32_t cookie[2];
};

struct inet_diag_request_v2 {
    uint8_t family;
    uint8_t protocol;
    uint8_t extensions;
    uint8_t padding;
    uint32_t states;
    struct inet_diag_sockid id;
};

struct inet_diag_message {
    uint8_t family;
    uint8_t state;
    uint8_t timer;
    uint8_t retransmits;
    struct inet_diag_sockid id;
    uint32_t expires_ms;
    uint32_t receive_queue;
    uint32_t write_queue;
    uint32_t user_id;
    uint32_t inode;
};

struct diag_request_packet {
    struct netlink_header header;
    struct inet_diag_request_v2 request;
    struct netlink_attribute storages;
    struct netlink_attribute map;
    int32_t map_fd;
};

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_MAP_DELETE_ELEM 3
#define BPF_MAP_GET_NEXT_KEY 4
#define BPF_BTF_LOAD 18
#define BPF_MAP_TYPE_SK_STORAGE 24
#define BPF_F_NO_PREALLOC 1
#define BPF_F_CLONE (1u << 9)
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define ENOENT 2
#define EBADF 9
#define EEXIST 17
#define EINVAL 22
#define ENOTSOCK 88
#define ENETUNREACH 101
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

void *memcpy(void *destination, const void *source,
             unsigned long length) {
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

    attribute.map_type = BPF_MAP_TYPE_SK_STORAGE;
    attribute.key_size = sizeof(int32_t);
    attribute.value_size = sizeof(uint32_t);
    attribute.max_entries = max_entries;
    attribute.map_flags = flags;
    attribute.btf_fd = (uint32_t)btf_fd;
    attribute.btf_key_type_id = 1u;
    attribute.btf_value_type_id = 1u;
    attribute.map_name[0] = 's';
    attribute.map_name[1] = 'k';
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

static uint32_t netlink_align(uint32_t value) {
    return (value + 3u) & ~3u;
}

static const struct netlink_attribute *find_attribute(
    const unsigned char *data, uint32_t length, uint16_t type) {
    uint32_t offset = 0u;

    while (offset + sizeof(struct netlink_attribute) <= length) {
        const struct netlink_attribute *attribute =
            (const struct netlink_attribute *)(data + offset);
        uint32_t padded;

        if (attribute->length < sizeof(*attribute) ||
            attribute->length > length - offset)
            return 0;
        if ((attribute->type & 0x3fffu) == type) return attribute;
        padded = netlink_align(attribute->length);
        if (padded > length - offset) return 0;
        offset += padded;
    }
    return 0;
}

static int test_socket_storage_diag(int map_fd, int socket_fd,
                                    uint32_t expected_value) {
    struct socket_address_v4 listener_address = {
        .family = AF_INET,
    };
    struct socket_address_netlink kernel = {
        .family = AF_NETLINK,
    };
    struct diag_request_packet request;
    unsigned char response[4096];
    long received;
    long diag_fd;
    int found = 0;
    int failures = 0;

    failures += expect_result(
        "sk-diag-bind", raw_syscall6(
            SYS_bind, socket_fd, (long)&listener_address,
            sizeof(listener_address), 0, 0, 0), 0);
    failures += expect_result(
        "sk-diag-listen", raw_syscall6(
            SYS_listen, socket_fd, 4, 0, 0, 0, 0), 0);
    if (failures) return failures;

    diag_fd = raw_syscall6(
        SYS_socket, AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK,
        NETLINK_SOCK_DIAG,
        0, 0, 0);
    if (diag_fd < 0)
        return expect_result("sk-diag-socket", diag_fd, 0);
    memset(&request, 0, sizeof(request));
    request.header.length = sizeof(request);
    request.header.type = SOCK_DIAG_BY_FAMILY;
    request.header.flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
    request.header.sequence = 71u;
    request.request.family = AF_INET;
    request.request.protocol = 6u;
    request.request.states = 1u << TCP_LISTEN;
    request.request.id.cookie[0] = 0xffffffffu;
    request.request.id.cookie[1] = 0xffffffffu;
    request.storages.length = sizeof(request.storages) +
                              sizeof(request.map) +
                              sizeof(request.map_fd);
    request.storages.type = INET_DIAG_REQ_SK_BPF_STORAGES |
                            NLA_F_NESTED;
    request.map.length = sizeof(request.map) + sizeof(request.map_fd);
    request.map.type = SK_DIAG_BPF_STORAGE_REQ_MAP_FD;
    request.map_fd = map_fd;

    failures += expect_result(
        "sk-diag-send", raw_syscall6(
            SYS_sendto, diag_fd, (long)&request, sizeof(request), 0,
            (long)&kernel, sizeof(kernel)), sizeof(request));
    received = raw_syscall6(
        SYS_recvfrom, diag_fd, (long)response, sizeof(response),
        0, 0, 0);
    if (received <= 0) {
        failures += expect_result("sk-diag-receive", received, 1);
        goto out;
    }
    for (uint32_t offset = 0;
         offset + sizeof(struct netlink_header) <= (uint32_t)received;) {
        const struct netlink_header *header =
            (const struct netlink_header *)(response + offset);
        uint32_t padded;

        if (header->length < sizeof(*header) ||
            header->length > (uint32_t)received - offset)
            break;
        if (header->type == 2u &&
            header->length >= sizeof(*header) + sizeof(int32_t)) {
            int32_t error;

            memcpy(&error, response + offset + sizeof(*header),
                   sizeof(error));
            print_text("FAIL sk-diag-netlink-error=");
            print_number(error);
            print_text("\n");
        }
        if (header->type == SOCK_DIAG_BY_FAMILY &&
            header->length >= sizeof(*header) +
                              sizeof(struct inet_diag_message)) {
            const unsigned char *attributes = response + offset +
                sizeof(*header) + sizeof(struct inet_diag_message);
            uint32_t attributes_length = header->length -
                sizeof(*header) - sizeof(struct inet_diag_message);
            const struct netlink_attribute *storages = find_attribute(
                attributes, attributes_length,
                INET_DIAG_SK_BPF_STORAGES);

            if (storages) {
                const struct netlink_attribute *entry = find_attribute(
                    (const unsigned char *)storages + sizeof(*storages),
                    storages->length - sizeof(*storages),
                    SK_DIAG_BPF_STORAGE);
                if (entry) {
                    const struct netlink_attribute *map_id = find_attribute(
                        (const unsigned char *)entry + sizeof(*entry),
                        entry->length - sizeof(*entry),
                        SK_DIAG_BPF_STORAGE_MAP_ID);
                    const struct netlink_attribute *value = find_attribute(
                        (const unsigned char *)entry + sizeof(*entry),
                        entry->length - sizeof(*entry),
                        SK_DIAG_BPF_STORAGE_MAP_VALUE);
                    uint32_t actual_id = 0u;
                    uint32_t actual_value = 0u;

                    if (map_id && map_id->length >=
                                      sizeof(*map_id) + sizeof(actual_id) &&
                        value && value->length >=
                                     sizeof(*value) + sizeof(actual_value)) {
                        memcpy(&actual_id,
                               (const unsigned char *)map_id +
                                   sizeof(*map_id),
                               sizeof(actual_id));
                        memcpy(&actual_value,
                               (const unsigned char *)value + sizeof(*value),
                               sizeof(actual_value));
                        if (actual_id != 0u &&
                            actual_value == expected_value)
                            found = 1;
                    }
                }
            }
        }
        padded = netlink_align(header->length);
        if (!padded || padded > (uint32_t)received - offset) break;
        offset += padded;
    }
    if (!found) {
        print_text("FAIL sk-diag-bytes=");
        print_number(received);
        print_text("\n");
    }
    failures += expect_result("sk-diag-storage", found, 1);
out:
    (void)raw_syscall6(SYS_close, diag_fd, 0, 0, 0, 0, 0);
    return failures;
}

static int test_socket_storage_clone(int btf_fd) {
    struct socket_address_v4 listener_address = {
        .family = AF_INET,
        .port = 0x5998u,
        .address = 0u,
    };
    struct socket_address_v4 peer_address = {
        .family = AF_INET,
        .port = 0x5998u,
        .address = 0x0100007fu,
    };
    uint32_t clone_value = 0x1234abcdu;
    uint32_t accepted_value = 0x88776655u;
    uint32_t plain_value = 0x55aa55aau;
    uint32_t output = 0u;
    long clone_map = -1;
    long plain_map = -1;
    int listener = -1;
    int client = -1;
    int accepted = -1;
    int failures = 0;

    clone_map = create_map(
        btf_fd, BPF_F_NO_PREALLOC | BPF_F_CLONE, 0u);
    plain_map = create_map(btf_fd, BPF_F_NO_PREALLOC, 0u);
    if (clone_map < 0 || plain_map < 0) {
        failures += expect_result("sk-clone-map", clone_map < 0, 0);
        failures += expect_result("sk-plain-map", plain_map < 0, 0);
        goto out;
    }
    listener = (int)raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    client = (int)raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (listener < 0 || client < 0) {
        failures += expect_result("sk-listener", listener < 0, 0);
        failures += expect_result("sk-client", client < 0, 0);
        goto out;
    }
    failures += expect_result(
        "sk-bind", raw_syscall6(
            SYS_bind, listener, (long)&listener_address,
            sizeof(listener_address), 0, 0, 0), 0);
    failures += expect_result(
        "sk-listen", raw_syscall6(
            SYS_listen, listener, 4, 0, 0, 0, 0), 0);
    failures += expect_result(
        "sk-clone-source", map_element(
            BPF_MAP_UPDATE_ELEM, (int)clone_map, &listener,
            &clone_value, BPF_NOEXIST), 0);
    failures += expect_result(
        "sk-plain-source", map_element(
            BPF_MAP_UPDATE_ELEM, (int)plain_map, &listener,
            &plain_value, BPF_NOEXIST), 0);
    {
        long connect_result = raw_syscall6(
            SYS_connect, client, (long)&peer_address,
            sizeof(peer_address), 0, 0, 0);

        if (connect_result != -ENETUNREACH)
            failures += expect_result("sk-connect", connect_result, 0);
        if (connect_result < 0) goto out;
    }
    accepted = (int)raw_syscall6(
        SYS_accept, listener, 0, 0, 0, 0, 0);
    if (accepted < 0) {
        failures += expect_result("sk-accept", accepted, 0);
        goto out;
    }
    failures += expect_result(
        "sk-clone-lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)clone_map, &accepted,
            &output, 0), 0);
    failures += expect_result(
        "sk-clone-value", (long)output, (long)clone_value);
    failures += expect_result(
        "sk-plain-not-cloned", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)plain_map, &accepted,
            &output, 0), -ENOENT);
    failures += expect_result(
        "sk-clone-replace", map_element(
            BPF_MAP_UPDATE_ELEM, (int)clone_map, &accepted,
            &accepted_value, BPF_EXIST), 0);
    output = 0u;
    failures += expect_result(
        "sk-source-lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)clone_map, &listener,
            &output, 0), 0);
    failures += expect_result(
        "sk-source-unchanged", (long)output, (long)clone_value);

out:
    if (accepted >= 0)
        (void)raw_syscall6(SYS_close, accepted, 0, 0, 0, 0, 0);
    if (client >= 0)
        (void)raw_syscall6(SYS_close, client, 0, 0, 0, 0, 0);
    if (listener >= 0)
        (void)raw_syscall6(SYS_close, listener, 0, 0, 0, 0, 0);
    if (plain_map >= 0)
        (void)raw_syscall6(SYS_close, plain_map, 0, 0, 0, 0, 0);
    if (clone_map >= 0)
        (void)raw_syscall6(SYS_close, clone_map, 0, 0, 0, 0, 0);
    return failures;
}

static int test_socket_storage(void) {
    uint32_t value = 0x11223344u;
    uint32_t replacement = 0x88776655u;
    uint32_t output = 0u;
    int bad_fd = 9999;
    int regular_fd;
    int socket_fd;
    int alias_fd;
    int reused_fd;
    long btf_fd;
    long map_fd;
    int failures = 0;

    btf_fd = load_integer_btf();
    if (btf_fd < 0)
        return expect_result("sk-btf-load", btf_fd, 0) + 1;
    failures += test_socket_storage_clone((int)btf_fd);
    failures += expect_result(
        "sk-no-prealloc-required", create_map(
            (int)btf_fd, BPF_F_CLONE, 0u), -EINVAL);
    failures += expect_result(
        "sk-zero-max-required", create_map(
            (int)btf_fd, BPF_F_NO_PREALLOC, 1u), -EINVAL);
    map_fd = create_map(
        (int)btf_fd, BPF_F_NO_PREALLOC | BPF_F_CLONE, 0u);
    if (map_fd < 0) {
        failures += expect_result("sk-create", map_fd, 0);
        goto close_btf;
    }
    socket_fd = (int)raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (socket_fd < 0) {
        failures += expect_result("sk-socket", socket_fd, 0);
        goto close_map;
    }
    alias_fd = (int)raw_syscall6(SYS_dup, socket_fd, 0, 0, 0, 0, 0);
    if (alias_fd < 0) {
        failures += expect_result("sk-dup", alias_fd, 0);
        goto close_socket;
    }
    regular_fd = (int)raw_syscall6(
        SYS_openat, AT_FDCWD, (long)"/sbin/init", O_RDONLY, 0, 0, 0);

    failures += expect_result(
        "sk-bad-fd", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &bad_fd,
            &value, BPF_ANY), -EBADF);
    if (regular_fd >= 0) {
        failures += expect_result(
            "sk-regular-fd", map_element(
                BPF_MAP_UPDATE_ELEM, (int)map_fd, &regular_fd,
                &value, BPF_ANY), -ENOTSOCK);
    }
    failures += expect_result(
        "sk-lookup-empty", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map_fd, &socket_fd,
            &output, 0), -ENOENT);
    failures += expect_result(
        "sk-exist-empty", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &socket_fd,
            &value, BPF_EXIST), -ENOENT);
    failures += expect_result(
        "sk-insert", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &socket_fd,
            &value, BPF_NOEXIST), 0);
    failures += test_socket_storage_diag(
        (int)map_fd, socket_fd, value);
    failures += expect_result(
        "sk-alias-lookup", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map_fd, &alias_fd,
            &output, 0), 0);
    failures += expect_result("sk-value", (long)output, (long)value);
    failures += expect_result(
        "sk-noexist", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &alias_fd,
            &replacement, BPF_NOEXIST), -EEXIST);
    failures += expect_result(
        "sk-replace", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &alias_fd,
            &replacement, BPF_EXIST), 0);
    failures += expect_result(
        "sk-next-unsupported", map_element(
            BPF_MAP_GET_NEXT_KEY, (int)map_fd, 0,
            &bad_fd, 0), -ENOTSUPP);
    (void)raw_syscall6(SYS_close, socket_fd, 0, 0, 0, 0, 0);
    socket_fd = -1;
    failures += expect_result(
        "sk-alias-survives-close", map_element(
            BPF_MAP_LOOKUP_ELEM, (int)map_fd, &alias_fd,
            &output, 0), 0);
    failures += expect_result(
        "sk-delete", map_element(
            BPF_MAP_DELETE_ELEM, (int)map_fd, &alias_fd,
            0, 0), 0);
    failures += expect_result(
        "sk-delete-empty", map_element(
            BPF_MAP_DELETE_ELEM, (int)map_fd, &alias_fd,
            0, 0), -ENOENT);
    failures += expect_result(
        "sk-reinsert", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &alias_fd,
            &value, BPF_ANY), 0);
    (void)raw_syscall6(SYS_close, alias_fd, 0, 0, 0, 0, 0);
    alias_fd = -1;
    reused_fd = (int)raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (reused_fd >= 0) {
        failures += expect_result(
            "sk-last-close-removes", map_element(
                BPF_MAP_LOOKUP_ELEM, (int)map_fd, &reused_fd,
                &output, 0), -ENOENT);
        (void)raw_syscall6(SYS_close, reused_fd, 0, 0, 0, 0, 0);
    }
    if (regular_fd >= 0)
        (void)raw_syscall6(SYS_close, regular_fd, 0, 0, 0, 0, 0);
    goto close_map;

close_socket:
    if (socket_fd >= 0)
        (void)raw_syscall6(SYS_close, socket_fd, 0, 0, 0, 0, 0);
close_map:
    (void)raw_syscall6(SYS_close, map_fd, 0, 0, 0, 0, 0);
close_btf:
    (void)raw_syscall6(SYS_close, btf_fd, 0, 0, 0, 0, 0);
    return failures;
}

static int test_socket_storage_diag_only(void) {
    uint32_t value = 0x11223344u;
    long btf_fd;
    long map_fd;
    long socket_fd;
    int failures = 0;

    btf_fd = load_integer_btf();
    if (btf_fd < 0)
        return expect_result("sk-diag-btf-load", btf_fd, 0) + 1;
    map_fd = create_map(
        (int)btf_fd, BPF_F_NO_PREALLOC | BPF_F_CLONE, 0u);
    if (map_fd < 0) {
        failures += expect_result("sk-diag-create", map_fd, 0);
        goto close_btf;
    }
    socket_fd = raw_syscall6(
        SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (socket_fd < 0) {
        failures += expect_result("sk-diag-stream", socket_fd, 0);
        goto close_map;
    }
    failures += expect_result(
        "sk-diag-insert", map_element(
            BPF_MAP_UPDATE_ELEM, (int)map_fd, &socket_fd,
            &value, BPF_NOEXIST), 0);
    failures += test_socket_storage_diag(
        (int)map_fd, (int)socket_fd, value);
    (void)raw_syscall6(SYS_close, socket_fd, 0, 0, 0, 0, 0);
close_map:
    (void)raw_syscall6(SYS_close, map_fd, 0, 0, 0, 0, 0);
close_btf:
    (void)raw_syscall6(SYS_close, btf_fd, 0, 0, 0, 0, 0);
    return failures;
}

START_ATTRIBUTES void _start(void) {
#ifdef BPF_SK_STORAGE_DIAG_ONLY
    int failures = test_socket_storage_diag_only();
#else
    int failures = test_socket_storage();
#endif

    print_text(failures ? "BPF_SK_STORAGE_ABI_FAIL\n" :
                          "BPF_SK_STORAGE_ABI_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
