/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux BPF_PROG_TEST_RUN ABI probe. */

#include <stdint.h>

#if defined(__x86_64__)
#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
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
#error "bpf_prog_test_run_abi_probe requires a 64-bit Linux ABI"
#endif

#define BPF_PROG_LOAD 5
#define BPF_PROG_TEST_RUN 10
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define BPF_PROG_TYPE_RAW_TRACEPOINT 17
#define E2BIG 7
#define EBADF 9
#define EFAULT 14
#define EINVAL 22
#define ENOSPC 28

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

struct __attribute__((packed)) bpf_program_test_attribute {
    uint32_t program_descriptor;
    uint32_t return_value;
    uint32_t input_data_size;
    uint32_t output_data_size;
    uint64_t input_data;
    uint64_t output_data;
    uint32_t repeat;
    uint32_t duration;
    uint32_t input_context_size;
    uint32_t output_context_size;
    uint64_t input_context;
    uint64_t output_context;
    uint32_t flags;
    uint32_t cpu;
    uint32_t batch_size;
};

_Static_assert(sizeof(struct bpf_program_test_attribute) == 76u,
               "Linux BPF test attribute layout changed");

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *output = destination;
    while (length--) *output++ = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned long length) {
    unsigned char *output = destination;
    const unsigned char *input = source;
    while (length--) *output++ = *input++;
    return destination;
}

static int bytes_equal(const void *first, const void *second,
                       unsigned long length) {
    const unsigned char *left = first;
    const unsigned char *right = second;
    while (length--)
        if (*left++ != *right++) return 0;
    return 1;
}

static int socket_filter_output_matches(const uint8_t *input,
                                        const uint8_t *output,
                                        unsigned long length) {
    unsigned long index;

    for (index = 0u; index < length && index < 14u; ++index)
        if (output[index]) return 0;
    if (length <= 14u) return 1;
    return bytes_equal(input + 14u, output + 14u, length - 14u);
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
    unsigned long start;
    unsigned long end;

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
    (void)raw_syscall6(SYS_write, 1, (long)output, (long)count, 0, 0, 0);
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

static long load_program(uint32_t program_type, int32_t return_value,
                         const char *name) {
    static const char license[] = "GPL";
    struct bpf_instruction instructions[] = {
        { .code = 0xb7u, .registers = 0u, .offset = 0,
          .immediate = return_value },
        { .code = 0x95u, .registers = 0u, .offset = 0,
          .immediate = 0 },
    };
    struct bpf_program_load_attribute attribute = {0};

    attribute.program_type = program_type;
    attribute.instruction_count = 2u;
    attribute.instructions = (uint64_t)(uintptr_t)instructions;
    attribute.license = (uint64_t)(uintptr_t)license;
    for (uint32_t index = 0u; name[index] && index < 15u; ++index)
        attribute.program_name[index] = name[index];
    return raw_syscall6(
        SYS_bpf, BPF_PROG_LOAD, (long)&attribute,
        sizeof(attribute), 0, 0, 0);
}

static long run_program(struct bpf_program_test_attribute *attribute) {
    return raw_syscall6(
        SYS_bpf, BPF_PROG_TEST_RUN, (long)attribute,
        sizeof(*attribute), 0, 0, 0);
}

START_ATTRIBUTES void _start(void) {
    uint8_t input[64];
    uint8_t output[64];
    struct bpf_program_test_attribute attribute;
    long program_descriptor;
    long raw_program_descriptor;
    int failures = 0;

    for (uint32_t index = 0u; index < sizeof(input); ++index)
        input[index] = (uint8_t)(index ^ 0x5au);
    program_descriptor = load_program(
        BPF_PROG_TYPE_SOCKET_FILTER, 42, "test_run");
    if (program_descriptor < 0) {
        failures += expect_result("program-load", program_descriptor, 0);
        goto out;
    }

    memset(output, 0, sizeof(output));
    memset(&attribute, 0, sizeof(attribute));
    attribute.program_descriptor = (uint32_t)program_descriptor;
    attribute.input_data_size = sizeof(input);
    attribute.output_data_size = sizeof(output);
    attribute.input_data = (uint64_t)(uintptr_t)input;
    attribute.output_data = (uint64_t)(uintptr_t)output;
    attribute.repeat = 3u;
    failures += expect_result("run", run_program(&attribute), 0);
    failures += expect_result("return-value", attribute.return_value, 42);
    failures += expect_result(
        "output-size", attribute.output_data_size, sizeof(input));
    if (!socket_filter_output_matches(input, output, sizeof(input))) {
        print_text("FAIL output-data\n");
        ++failures;
    }

    memset(output, 0, sizeof(output));
    attribute.output_data_size = 8u;
    failures += expect_result(
        "short-output", run_program(&attribute), -ENOSPC);
    failures += expect_result(
        "short-output-size", attribute.output_data_size, sizeof(input));
    if (!socket_filter_output_matches(input, output, 8u)) {
        print_text("FAIL short-output-data\n");
        ++failures;
    }

    attribute.output_data_size = sizeof(output);
    attribute.repeat = 0u;
    attribute.flags = 1u;
    failures += expect_result("invalid-flags", run_program(&attribute),
                              -EINVAL);
    attribute.flags = 0u;
    attribute.cpu = 1u;
    failures += expect_result("invalid-cpu", run_program(&attribute),
                              -EINVAL);
    attribute.cpu = 0u;
    attribute.input_data_size = 13u;
    failures += expect_result("short-packet", run_program(&attribute),
                              -EINVAL);
    attribute.input_data_size = sizeof(input);
    attribute.input_data = 0u;
    failures += expect_result("null-input", run_program(&attribute),
                              -EFAULT);
    attribute.input_data = (uint64_t)(uintptr_t)input;
    attribute.program_descriptor = UINT32_MAX;
    failures += expect_result("bad-fd", run_program(&attribute), -EBADF);

    (void)raw_syscall6(SYS_close, program_descriptor, 0, 0, 0, 0, 0);

    raw_program_descriptor = load_program(
        BPF_PROG_TYPE_RAW_TRACEPOINT, 9, "raw_test");
    if (raw_program_descriptor < 0) {
        failures += expect_result(
            "raw-program-load", raw_program_descriptor, 0);
    } else {
        uint64_t raw_context[2] = { 0x1122334455667788ull, 321u };

        memset(&attribute, 0, sizeof(attribute));
        attribute.program_descriptor = (uint32_t)raw_program_descriptor;
        attribute.input_context_size = sizeof(raw_context);
        attribute.input_context = (uint64_t)(uintptr_t)raw_context;
        failures += expect_result(
            "raw-run", run_program(&attribute), 0);
        failures += expect_result(
            "raw-return-value", attribute.return_value, 9);
        attribute.repeat = 1u;
        failures += expect_result(
            "raw-repeat", run_program(&attribute), -EINVAL);
        attribute.repeat = 0u;
        attribute.cpu = 1u;
        failures += expect_result(
            "raw-cpu-without-flag", run_program(&attribute), -EINVAL);
        (void)raw_syscall6(
            SYS_close, raw_program_descriptor, 0, 0, 0, 0, 0);
    }
out:
    print_text(failures ? "BPF_PROG_TEST_RUN_ABI_FAIL\n" :
                          "BPF_PROG_TEST_RUN_ABI_PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
