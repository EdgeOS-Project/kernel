/* SPDX-License-Identifier: MPL-2.0 */
/* Raw legacy Linux AIO ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_exit 60
#define SYS_io_setup 206
#define SYS_io_destroy 207
#define SYS_io_getevents 208
#define SYS_io_submit 209
#define SYS_io_cancel 210
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_eventfd2 290
#define SYS_pipe2 293
#define SYS_io_pgetevents 333
#elif defined(__aarch64__)
#define SYS_io_setup 0
#define SYS_io_destroy 1
#define SYS_io_submit 2
#define SYS_io_cancel 3
#define SYS_io_getevents 4
#define SYS_eventfd2 19
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_pipe2 59
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_io_pgetevents 292
#else
#error "aio_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 00000100
#define O_TRUNC 00001000
#define IOCB_CMD_PREAD 0
#define IOCB_CMD_PWRITE 1
#define IOCB_CMD_POLL 5
#define IOCB_FLAG_RESFD 1
#define POLLIN 1
#define EINVAL 22
#define EINPROGRESS 115

struct linux_timespec64 {
    int64_t seconds;
    int64_t nanoseconds;
};

struct linux_io_event {
    uint64_t data;
    uint64_t object;
    int64_t result;
    int64_t result2;
};

struct linux_iocb {
    uint64_t data;
    uint32_t key;
    uint32_t rw_flags;
    uint16_t opcode;
    int16_t request_priority;
    uint32_t descriptor;
    uint64_t buffer;
    uint64_t byte_count;
    int64_t offset;
    uint64_t reserved2;
    uint32_t flags;
    uint32_t result_descriptor;
};

struct linux_aio_sigset {
    uint64_t signal_mask;
    uint64_t signal_set_size;
};

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

void *memset(void *destination, int value, unsigned long length) {
    unsigned char *bytes = destination;
    while (length) bytes[--length] = (unsigned char)value;
    return destination;
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)text_length(text), 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int expect_true(const char *name, int condition) {
    if (condition) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int run_tests(void) {
    static const char path[] = "/tmp/edge-aio-abi-probe";
    struct linux_timespec64 zero_timeout = {0, 0};
    struct linux_aio_sigset empty_sigset = {0, 0};
    struct linux_io_event event;
    struct linux_iocb request;
    struct linux_iocb *requests[1] = {&request};
    uint64_t event_counter = 0;
    uint64_t context = 0;
    char input[6] = "edge!";
    char output[6] = {0};
    int pipe_descriptors[2] = {-1, -1};
    long event_descriptor;
    long descriptor;
    int failures = 0;

    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path,
        O_RDWR | O_CREAT | O_TRUNC, 0600, 0, 0);
    failures += expect_true("open temporary file", descriptor >= 0);
    if (descriptor < 0) return failures;
    failures += expect("setup", raw_syscall6(
        SYS_io_setup, 8, (long)&context, 0, 0, 0, 0), 0);
    failures += expect_true("context handle", context != 0);

    memset(&request, 0, sizeof(request));
    request.data = 0x101;
    request.opcode = IOCB_CMD_PWRITE;
    request.descriptor = (uint32_t)descriptor;
    request.buffer = (uint64_t)(uintptr_t)input;
    request.byte_count = 5;
    failures += expect("submit pwrite", raw_syscall6(
        SYS_io_submit, (long)context, 1, (long)requests,
        0, 0, 0), 1);
    memset(&event, 0, sizeof(event));
    failures += expect("get pwrite", raw_syscall6(
        SYS_io_getevents, (long)context, 1, 1, (long)&event,
        (long)&zero_timeout, 0), 1);
    failures += expect_true("pwrite completion",
        event.data == 0x101 && event.object == (uint64_t)(uintptr_t)&request &&
        event.result == 5 && event.result2 == 0);
    failures += expect("aio key cleared", request.key, 0);

    event_descriptor = raw_syscall6(SYS_eventfd2, 0, 0, 0, 0, 0, 0);
    failures += expect_true("eventfd", event_descriptor >= 0);
    memset(&request, 0, sizeof(request));
    request.data = 0x202;
    request.opcode = IOCB_CMD_PREAD;
    request.descriptor = (uint32_t)descriptor;
    request.buffer = (uint64_t)(uintptr_t)output;
    request.byte_count = 5;
    request.flags = IOCB_FLAG_RESFD;
    request.result_descriptor = (uint32_t)event_descriptor;
    failures += expect("submit pread", raw_syscall6(
        SYS_io_submit, (long)context, 1, (long)requests,
        0, 0, 0), 1);
    failures += expect("pgetevents", raw_syscall6(
        SYS_io_pgetevents, (long)context, 1, 1, (long)&event,
        (long)&zero_timeout, (long)&empty_sigset), 1);
    failures += expect_true("pread completion",
        event.data == 0x202 && event.result == 5 &&
        output[0] == 'e' && output[4] == '!');
    failures += expect("read eventfd", raw_syscall6(
        SYS_read,
        event_descriptor, (long)&event_counter,
        sizeof(event_counter), 0, 0, 0), sizeof(event_counter));
    failures += expect("eventfd count", (long)event_counter, 1);

    failures += expect("pipe", raw_syscall6(
        SYS_pipe2, (long)pipe_descriptors, 0, 0, 0, 0, 0), 0);
    memset(&request, 0, sizeof(request));
    request.data = 0x303;
    request.opcode = IOCB_CMD_POLL;
    request.descriptor = (uint32_t)pipe_descriptors[0];
    request.buffer = POLLIN;
    failures += expect("submit poll", raw_syscall6(
        SYS_io_submit, (long)context, 1, (long)requests,
        0, 0, 0), 1);
    memset(&event, 0, sizeof(event));
    failures += expect("cancel poll", raw_syscall6(
        SYS_io_cancel, (long)context, (long)&request,
        (long)&event, 0, 0, 0), -EINPROGRESS);

    memset(&request, 0, sizeof(request));
    request.opcode = 6;
    failures += expect("reject noop", raw_syscall6(
        SYS_io_submit, (long)context, 1, (long)requests,
        0, 0, 0), -EINVAL);
    failures += expect("destroy", raw_syscall6(
        SYS_io_destroy, (long)context, 0, 0, 0, 0, 0), 0);

    if (pipe_descriptors[0] >= 0)
        (void)raw_syscall6(SYS_close, pipe_descriptors[0], 0, 0, 0, 0, 0);
    if (pipe_descriptors[1] >= 0)
        (void)raw_syscall6(SYS_close, pipe_descriptors[1], 0, 0, 0, 0, 0);
    if (event_descriptor >= 0)
        (void)raw_syscall6(SYS_close, event_descriptor, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    int failures = run_tests();
    print_text(failures ? "aio-abi: FAIL\n" : "aio-abi: PASS\n");
    raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
