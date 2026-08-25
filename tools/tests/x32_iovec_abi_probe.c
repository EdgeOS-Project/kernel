/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 iovec compatibility ABI probe. */

#include <stdint.h>

#if !defined(__x86_64__)
#error "x32_iovec_abi_probe requires x86_64"
#endif

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))

#define X32_SYSCALL_BIT UINT64_C(0x40000000)

#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_exit 60
#define SYS_pipe2 293
#define SYS_memfd_create 319

#define X32_SYS_readv 515
#define X32_SYS_writev 516
#define X32_SYS_preadv 534
#define X32_SYS_pwritev 535
#define X32_SYS_process_vm_readv 539
#define X32_SYS_process_vm_writev 540
#define X32_SYS_preadv2 546
#define X32_SYS_pwritev2 547

#define EBADF 9
#define EFAULT 14
#define EINVAL 22
#define O_CLOEXEC 02000000
#define MFD_CLOEXEC 1

struct x32_iovec {
    uint32_t base;
    uint32_t length;
};

static int pipe_descriptors[2];
static char pipe_output[8];
static char pipe_first[4];
static char pipe_second[4];
static char positioned_output[8];
static char process_vm_output[8];
static char process_vm_target[8];
static const char pipe_left[] = "ab";
static const char pipe_right[] = "cd";
static const char pipe_input[] = "wxyz";
static const char positioned_input[] = "pq";
static const char current_input[] = "rs";
static const char process_vm_input[] = "vm";
static const char process_vm_write_input[] = "io";
static const char memfd_name[] = "x32-iovec-probe";
static struct x32_iovec vectors[2];
static struct x32_iovec remote_vectors[2];

static long raw_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
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
}

static long x32_syscall6(long number, long a0, long a1, long a2,
                         long a3, long a4, long a5) {
    return raw_syscall6(
        (long)(X32_SYSCALL_BIT | (uint64_t)number),
        a0, a1, a2, a3, a4, a5);
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

static int expect_bytes(const char *name, const char *actual,
                        const char *expected, unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        if (actual[index] == expected[index]) continue;
        print_text("FAIL ");
        print_text(name);
        print_text("\n");
        return 1;
    }
    return 0;
}

static uint32_t pointer32(const void *pointer) {
    return (uint32_t)(uintptr_t)pointer;
}

START_ATTRIBUTES void _start(void) {
    long descriptor;
    long pid;
    int failures = 0;

    failures += expect_result(
        "pipe2", raw_syscall6(
            SYS_pipe2, (long)pipe_descriptors, O_CLOEXEC, 0, 0, 0, 0), 0);
    if (failures) goto finish;

    vectors[0].base = pointer32(pipe_left);
    vectors[0].length = 2;
    vectors[1].base = pointer32(pipe_right);
    vectors[1].length = 2;
    failures += expect_result(
        "writev", x32_syscall6(
            X32_SYS_writev, pipe_descriptors[1], (long)vectors, 2,
            0, 0, 0), 4);
    failures += expect_result(
        "read-after-writev", raw_syscall6(
            SYS_read, pipe_descriptors[0], (long)pipe_output, 4,
            0, 0, 0), 4);
    failures += expect_bytes("writev-bytes", pipe_output, "abcd", 4);

    failures += expect_result(
        "write-before-readv", raw_syscall6(
            SYS_write, pipe_descriptors[1], (long)pipe_input, 4,
            0, 0, 0), 4);
    vectors[0].base = pointer32(pipe_first);
    vectors[0].length = 2;
    vectors[1].base = pointer32(pipe_second);
    vectors[1].length = 2;
    failures += expect_result(
        "readv", x32_syscall6(
            X32_SYS_readv, pipe_descriptors[0], (long)vectors, 2,
            0, 0, 0), 4);
    failures += expect_bytes("readv-first", pipe_first, "wx", 2);
    failures += expect_bytes("readv-second", pipe_second, "yz", 2);
    failures += expect_result(
        "zero-vectors", x32_syscall6(
            X32_SYS_readv, pipe_descriptors[0], -1, 0,
            0, 0, 0), 0);
    failures += expect_result(
        "invalid-count", x32_syscall6(
            X32_SYS_readv, pipe_descriptors[0], (long)vectors, 1025,
            0, 0, 0), -EINVAL);
    failures += expect_result(
        "invalid-vector", x32_syscall6(
            X32_SYS_readv, pipe_descriptors[0], -1, 1,
            0, 0, 0), -EFAULT);
    failures += expect_result(
        "bad-fd-first", x32_syscall6(
            X32_SYS_readv, -1, -1, 1, 0, 0, 0), -EBADF);

    descriptor = raw_syscall6(
        SYS_memfd_create, (long)memfd_name, MFD_CLOEXEC, 0, 0, 0, 0);
    if (descriptor < 0) {
        failures += expect_result("memfd-create", descriptor, 0);
        goto close_pipe;
    }
    vectors[0].base = pointer32(positioned_input);
    vectors[0].length = 2;
    failures += expect_result(
        "pwritev", x32_syscall6(
            X32_SYS_pwritev, descriptor, (long)vectors, 1,
            3, 0, 0), 2);
    vectors[0].base = pointer32(positioned_output);
    vectors[0].length = 2;
    failures += expect_result(
        "preadv", x32_syscall6(
            X32_SYS_preadv, descriptor, (long)vectors, 1,
            3, 0, 0), 2);
    failures += expect_bytes(
        "positioned-bytes", positioned_output, positioned_input, 2);

    vectors[0].base = pointer32(current_input);
    vectors[0].length = 2;
    failures += expect_result(
        "pwritev2-current", x32_syscall6(
            X32_SYS_pwritev2, descriptor, (long)vectors, 1,
            -1, 0, 0), 2);
    vectors[0].base = pointer32(positioned_output + 2);
    vectors[0].length = 2;
    failures += expect_result(
        "preadv2", x32_syscall6(
            X32_SYS_preadv2, descriptor, (long)vectors, 1,
            0, 0, 0), 2);
    failures += expect_bytes(
        "current-bytes", positioned_output + 2, current_input, 2);

    pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
    vectors[0].base = pointer32(process_vm_output);
    vectors[0].length = 2;
    remote_vectors[0].base = pointer32(process_vm_input);
    remote_vectors[0].length = 2;
    failures += expect_result(
        "process-vm-readv", x32_syscall6(
            X32_SYS_process_vm_readv, pid, (long)vectors, 1,
            (long)remote_vectors, 1, 0), 2);
    failures += expect_bytes(
        "process-vm-readv-bytes", process_vm_output,
        process_vm_input, 2);

    vectors[0].base = pointer32(process_vm_write_input);
    vectors[0].length = 2;
    remote_vectors[0].base = pointer32(process_vm_target);
    remote_vectors[0].length = 2;
    failures += expect_result(
        "process-vm-writev", x32_syscall6(
            X32_SYS_process_vm_writev, pid, (long)vectors, 1,
            (long)remote_vectors, 1, 0), 2);
    failures += expect_bytes(
        "process-vm-writev-bytes", process_vm_target,
        process_vm_write_input, 2);

    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);

close_pipe:
    (void)raw_syscall6(SYS_close, pipe_descriptors[0], 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, pipe_descriptors[1], 0, 0, 0, 0, 0);
finish:
    if (failures) {
        print_text("X32_IOVEC_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
        raw_syscall6(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_IOVEC_ABI_PROBE_PASS\n");
    raw_syscall6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
