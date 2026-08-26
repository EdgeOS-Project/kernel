/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux eBPF socket-filter attachment ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define SYS_write 1
#define SYS_close 3
#define SYS_ioctl 16
#define SYS_socket 41
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_bind 49
#define SYS_setsockopt 54
#define SYS_exit 60
#define SYS_bpf 321
#elif defined(__aarch64__)
#define START_ATTRIBUTES __attribute__((noreturn))
#define SYS_close 57
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_bind 200
#define SYS_sendto 206
#define SYS_recvfrom 207
#define SYS_setsockopt 208
#define SYS_bpf 280
#else
#error "bpf_socket_filter_abi_probe requires a Linux 64-bit architecture"
#endif

#define BPF_PROG_LOAD 5
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define AF_INET 2
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_DETACH_FILTER 27
#define SO_ATTACH_BPF 50
#define MSG_DONTWAIT 0x40
#define EAGAIN 11
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define IFF_UP 0x1

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

struct linux_sockaddr_in {
    uint16_t family;
    uint16_t port;
    uint32_t address;
    uint8_t zero[8];
};

struct linux_ifreq {
    char name[16];
    int16_t flags;
    uint8_t padding[22];
};

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *output = (unsigned char *)destination;
    while (length--) *output++ = (unsigned char)value;
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
                     : "memory", "cc");
    return x0;
#endif
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0u;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(
        SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char output[32];
    unsigned long count = 0u;
    unsigned long magnitude;

    if (value < 0) {
        output[count++] = '-';
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    {
        unsigned long start = count;
        unsigned long end;
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

static long load_program(const struct bpf_instruction *instructions,
                         uint32_t instruction_count, const char *name) {
    static const char license[] = "GPL";
    struct bpf_program_load_attribute attribute = {0};

    attribute.program_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attribute.instruction_count = instruction_count;
    attribute.instructions = (uint64_t)(uintptr_t)instructions;
    attribute.license = (uint64_t)(uintptr_t)license;
    for (uint32_t index = 0u; name[index] && index < 15u; ++index)
        attribute.program_name[index] = name[index];
    return raw_syscall6(
        SYS_bpf, BPF_PROG_LOAD, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long attach_program(int socket_descriptor,
                           int program_descriptor) {
    return raw_syscall6(
        SYS_setsockopt, socket_descriptor, SOL_SOCKET, SO_ATTACH_BPF,
        (long)&program_descriptor, sizeof(program_descriptor), 0);
}

START_ATTRIBUTES void _start(void) {
    const struct bpf_instruction reject_instructions[] = {
        { .code = 0xb7u, .registers = 0u,
          .offset = 0, .immediate = 0 },
        { .code = 0x95u, .registers = 0u,
          .offset = 0, .immediate = 0 },
    };
    const struct bpf_instruction length_instructions[] = {
        { .code = 0x61u, .registers = 0x10u,
          .offset = 0, .immediate = 0 },
        { .code = 0x95u, .registers = 0u,
          .offset = 0, .immediate = 0 },
    };
    struct linux_sockaddr_in address = {
        .family = AF_INET,
        .port = 0x0787u,
        .address = 0x0100007fu,
    };
    char sent = 'x';
    char received = 0;
    int zero = 0;
    long receiver;
    long sender;
    long reject_program;
    long length_program;
    int failures = 0;

    receiver = raw_syscall6(SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    sender = raw_syscall6(SYS_socket, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
    failures += expect_result("receiver", receiver < 0 ? receiver : 0, 0);
    failures += expect_result("sender", sender < 0 ? sender : 0, 0);
    if (receiver >= 0 && sender >= 0) {
        struct linux_ifreq interface_request = {
            .name = {'l', 'o'},
        };

        if (raw_syscall6(SYS_ioctl, receiver, SIOCGIFFLAGS,
                         (long)&interface_request, 0, 0, 0) == 0) {
            interface_request.flags |= IFF_UP;
            (void)raw_syscall6(SYS_ioctl, receiver, SIOCSIFFLAGS,
                               (long)&interface_request, 0, 0, 0);
        }
        failures += expect_result(
            "bind", raw_syscall6(SYS_bind, receiver, (long)&address,
                                  sizeof(address), 0, 0, 0), 0);
        reject_program = load_program(
            reject_instructions, 2u, "reject");
        length_program = load_program(
            length_instructions, 2u, "length");
        failures += expect_result(
            "reject-load", reject_program < 0 ? reject_program : 0, 0);
        failures += expect_result(
            "length-load", length_program < 0 ? length_program : 0, 0);
        if (reject_program >= 0 && length_program >= 0) {
            failures += expect_result(
                "reject-attach",
                attach_program((int)receiver, (int)reject_program), 0);
            failures += expect_result(
                "reject-send",
                raw_syscall6(SYS_sendto, sender, (long)&sent, 1, 0,
                             (long)&address, sizeof(address)), 1);
            failures += expect_result(
                "reject-recv",
                raw_syscall6(SYS_recvfrom, receiver, (long)&received, 1,
                             MSG_DONTWAIT, 0, 0), -EAGAIN);
            failures += expect_result(
                "length-attach",
                attach_program((int)receiver, (int)length_program), 0);
            (void)raw_syscall6(
                SYS_close, length_program, 0, 0, 0, 0, 0);
            sent = 'y';
            failures += expect_result(
                "length-send",
                raw_syscall6(SYS_sendto, sender, (long)&sent, 1, 0,
                             (long)&address, sizeof(address)), 1);
            failures += expect_result(
                "length-recv",
                raw_syscall6(SYS_recvfrom, receiver, (long)&received, 1,
                             MSG_DONTWAIT, 0, 0), 1);
            failures += expect_result("length-value", received, 'y');
            failures += expect_result(
                "detach",
                raw_syscall6(SYS_setsockopt, receiver, SOL_SOCKET,
                             SO_DETACH_FILTER, (long)&zero,
                             sizeof(zero), 0), 0);
            (void)raw_syscall6(
                SYS_close, reject_program, 0, 0, 0, 0, 0);
        }
        (void)raw_syscall6(SYS_close, sender, 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_close, receiver, 0, 0, 0, 0, 0);
    }
    if (failures) {
        print_text("bpf-socket-filter: FAIL\n");
        (void)raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("bpf-socket-filter: PASS\n");
    (void)raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
