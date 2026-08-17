/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS freestanding Netlink datagram delivery ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_socket 41
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_bind 49
#define SYS_exit 60
#elif defined(__aarch64__)
#define SYS_close 57
#define SYS_write 64
#define SYS_exit 93
#define SYS_getpid 172
#define SYS_socket 198
#define SYS_bind 200
#define SYS_sendto 206
#define SYS_recvfrom 207
#else
#error "This probe requires x86_64 or AArch64 Linux"
#endif

#define ECONNREFUSED 111
#define AF_NETLINK 16
#define SOCK_RAW 3
#define SOCK_NONBLOCK 0x800
#define NETLINK_USERSOCK 2

typedef struct linux_sockaddr_nl {
    uint16_t family;
    uint16_t padding;
    uint32_t port_id;
    uint32_t groups;
} linux_sockaddr_nl_t;

#if defined(__x86_64__)
static long raw_syscall1(long number, long first) {
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long first, long second) {
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long first, long second, long third) {
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall6(long number, long first, long second, long third,
                         long fourth, long fifth, long sixth) {
    register long fourth_register __asm__("r10") = fourth;
    register long fifth_register __asm__("r8") = fifth;
    register long sixth_register __asm__("r9") = sixth;
    long result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third),
          "r"(fourth_register), "r"(fifth_register),
          "r"(sixth_register)
        : "rcx", "r11", "memory");
    return result;
}
#else
static long raw_syscall1(long number, long first) {
    register long x0 __asm__("x0") = first;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static long raw_syscall2(long number, long first, long second) {
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "memory");
    return x0;
}

static long raw_syscall3(long number, long first, long second, long third) {
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory");
    return x0;
}

static long raw_syscall6(long number, long first, long second, long third,
                         long fourth, long fifth, long sixth) {
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x3 __asm__("x3") = fourth;
    register long x4 __asm__("x4") = fifth;
    register long x5 __asm__("x5") = sixth;
    register long x8 __asm__("x8") = number;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory");
    return x0;
}
#endif

static uint64_t text_length(const char *text) {
    uint64_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void putstr(const char *text) {
    (void)raw_syscall3(
        SYS_write, 1, (long)text, (long)text_length(text));
}

static int bytes_equal(const char *first, const char *second,
                       uint32_t length) {
    for (uint32_t index = 0; index < length; ++index)
        if (first[index] != second[index]) return 0;
    return 1;
}

static int run_probe(void) {
    static const char payload[] = "edgeos-netlink-delivery";
    linux_sockaddr_nl_t receiver_address = { 0 };
    linux_sockaddr_nl_t source_address = { 0 };
    linux_sockaddr_nl_t missing_address = { 0 };
    char received[64] = { 0 };
    uint32_t source_length = sizeof(source_address);
    long receiver;
    long sender;
    long result;
    int failures = 0;

    receiver = raw_syscall3(
        SYS_socket, AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK,
        NETLINK_USERSOCK);
    sender = raw_syscall3(
        SYS_socket, AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK,
        NETLINK_USERSOCK);
    if (receiver < 0 || sender < 0) {
        putstr("NETLINK_DELIVERY_ABI_FAIL socket\n");
        if (receiver >= 0) (void)raw_syscall1(SYS_close, receiver);
        if (sender >= 0) (void)raw_syscall1(SYS_close, sender);
        return 1;
    }

    receiver_address.family = AF_NETLINK;
    receiver_address.port_id = (uint32_t)raw_syscall1(SYS_getpid, 0);
    result = raw_syscall3(
        SYS_bind, receiver, (long)&receiver_address,
        sizeof(receiver_address));
    if (result != 0) failures++;

    result = raw_syscall6(
        SYS_sendto, sender, (long)payload, sizeof(payload),
        0, (long)&receiver_address, sizeof(receiver_address));
    if (result != (long)sizeof(payload)) failures++;
    result = raw_syscall6(
        SYS_recvfrom, receiver, (long)received, sizeof(received),
        0, (long)&source_address, (long)&source_length);
    if (result != (long)sizeof(payload) ||
        !bytes_equal(received, payload, sizeof(payload)) ||
        source_address.family != AF_NETLINK ||
        source_address.port_id == 0 ||
        source_length != sizeof(source_address))
        failures++;

    missing_address.family = AF_NETLINK;
    missing_address.port_id = 0x7ffffffeu;
    result = raw_syscall6(
        SYS_sendto, sender, (long)payload, sizeof(payload),
        0, (long)&missing_address, sizeof(missing_address));
    if (result != -ECONNREFUSED) failures++;

    (void)raw_syscall1(SYS_close, sender);
    (void)raw_syscall1(SYS_close, receiver);
    putstr(failures ? "NETLINK_DELIVERY_ABI_FAIL\n" :
                      "NETLINK_DELIVERY_ABI_PASS\n");
    return failures ? 1 : 0;
}

static __attribute__((noreturn, noinline, used)) void probe_entry(void) {
    (void)raw_syscall1(SYS_exit, run_probe());
    for (;;) {}
}

#if defined(__x86_64__)
__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile(
        "andq $-16, %rsp\n"
        "call probe_entry\n");
}
#else
void _start(void) {
    probe_entry();
}
#endif
