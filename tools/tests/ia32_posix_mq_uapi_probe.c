/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 POSIX message queue UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_write 4
#define SYS_close 6
#define SYS_getpid 20
#define SYS_mq_open 277
#define SYS_mq_unlink 278
#define SYS_mq_timedsend 279
#define SYS_mq_timedreceive 280
#define SYS_mq_getsetattr 282
#define SYS_mq_timedsend_time64 418
#define SYS_mq_timedreceive_time64 419

#define O_CREAT 00000100
#define O_EXCL 00000200
#define O_RDWR 2
#define O_NONBLOCK 00004000
#define EAGAIN 11

void *memcpy(void *destination, const void *source, uint32_t size) {
    volatile uint8_t *output = (volatile uint8_t *)destination;
    const volatile uint8_t *input = (const volatile uint8_t *)source;

    for (uint32_t index = 0; index < size; ++index)
        output[index] = input[index];
    return destination;
}

struct mq_attr32 {
    int32_t flags;
    int32_t maximum_messages;
    int32_t message_size;
    int32_t current_messages;
    int32_t reserved[4];
};

__attribute__((naked)) static long raw_call6(
        long number, long a0, long a1, long a2,
        long a3, long a4, long a5) {
    __asm__ volatile(
        "pushl %ebp\n"
        "pushl %edi\n"
        "pushl %esi\n"
        "pushl %ebx\n"
        "movl 20(%esp), %eax\n"
        "movl 24(%esp), %ebx\n"
        "movl 28(%esp), %ecx\n"
        "movl 32(%esp), %edx\n"
        "movl 36(%esp), %esi\n"
        "movl 40(%esp), %edi\n"
        "movl 44(%esp), %ebp\n"
        "int $0x80\n"
        "popl %ebx\n"
        "popl %esi\n"
        "popl %edi\n"
        "popl %ebp\n"
        "ret\n");
}

#define call6(number, a0, a1, a2, a3, a4, a5) \
    raw_call6((number), \
              (long)(uintptr_t)(a0), (long)(uintptr_t)(a1), \
              (long)(uintptr_t)(a2), (long)(uintptr_t)(a3), \
              (long)(uintptr_t)(a4), (long)(uintptr_t)(a5))

static uint32_t text_length(const char *text) {
    uint32_t length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call6(SYS_write, 1, text, text_length(text), 0, 0, 0);
}

static void fail(const char *name) {
    print_text("IA32_POSIX_MQ_UAPI_PROBE_FAIL ");
    print_text(name);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void append_number(char *destination, uint32_t value) {
    char reversed[10];
    uint32_t count = 0;
    uint32_t offset = 0;

    while (destination[offset]) ++offset;
    do {
        reversed[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value);
    while (count) destination[offset++] = reversed[--count];
    destination[offset] = 0;
}

__attribute__((noreturn)) void _start(void) {
    struct mq_attr32 create = {0, 3, 16, 0, {0, 0, 0, 0}};
    struct mq_attr32 current = {0, 0, 0, 0, {0, 0, 0, 0}};
    struct mq_attr32 nonblocking = {
        O_NONBLOCK, 0, 0, 0, {0, 0, 0, 0},
    };
    char name[48] = "edge-ia32-mq-";
    char receive[16] = {0};
    uint32_t priority = 0;
    long descriptor;
    long result;

    append_number(name, (uint32_t)call6(SYS_getpid, 0, 0, 0, 0, 0, 0));
    descriptor = call6(SYS_mq_open, name, O_CREAT | O_EXCL | O_RDWR,
                       0600, &create, 0, 0);
    if (descriptor < 0) fail("mq_open");
    result = call6(SYS_mq_timedsend, descriptor, "legacy", 6, 2, 0, 0);
    if (result != 0) fail("mq_timedsend");
    result = call6(SYS_mq_timedsend_time64, descriptor, "time64", 6, 7,
                   0, 0);
    if (result != 0) fail("mq_timedsend_time64");
    result = call6(SYS_mq_getsetattr, descriptor, 0, &current, 0, 0, 0);
    if (result != 0 || current.maximum_messages != 3 ||
        current.message_size != 16 || current.current_messages != 2)
        fail("mq_getsetattr-layout");
    result = call6(SYS_mq_timedreceive_time64, descriptor, receive,
                   sizeof(receive), &priority, 0, 0);
    if (result != 6 || priority != 7 || receive[0] != 't')
        fail("mq_timedreceive_time64");
    result = call6(SYS_mq_timedreceive, descriptor, receive,
                   sizeof(receive), &priority, 0, 0);
    if (result != 6 || priority != 2 || receive[0] != 'l')
        fail("mq_timedreceive");
    result = call6(SYS_mq_getsetattr, descriptor, &nonblocking,
                   &current, 0, 0, 0);
    if (result != 0 || current.current_messages != 0)
        fail("mq_setattr-layout");
    result = call6(SYS_mq_timedreceive, descriptor, receive,
                   sizeof(receive), &priority, 0, 0);
    if (result != -EAGAIN) fail("mq_nonblocking");
    if (call6(SYS_mq_unlink, name, 0, 0, 0, 0, 0) != 0)
        fail("mq_unlink");
    if (call6(SYS_close, descriptor, 0, 0, 0, 0, 0) != 0)
        fail("close");
    print_text("IA32_POSIX_MQ_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
