/* SPDX-License-Identifier: MPL-2.0 */
/* Linux x32 extended compatibility layout probe. */

#include <stdint.h>

#define START_ATTRIBUTES __attribute__((noreturn, force_align_arg_pointer))
#define X32_BIT UINT64_C(0x40000000)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_pipe2 293
#define SYS_openat 257
#define SYS_unlinkat 263
#define SYS_io_destroy 207
#define SYS_io_getevents 208
#define SYS_timer_delete 226
#define SYS_mq_open 240
#define SYS_mq_unlink 241
#define X32_timer_create 526
#define X32_mq_notify 527
#define X32_vmsplice 532
#define X32_move_pages 533
#define X32_io_setup 543
#define X32_io_submit 544
#define SYS_exit 60
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define O_RDWR 2
#define O_CREAT 0100
#define AT_FDCWD -100
#define CLOCK_MONOTONIC 1
#define SIGEV_NONE 1
#define IOCB_CMD_FSYNC 2

struct x32_iovec {
    uint32_t base;
    uint32_t length;
};

struct compat_sigevent {
    uint32_t value;
    int32_t signal;
    int32_t notification;
    int32_t thread_id;
    uint8_t padding[48];
};

struct mq_attr64 {
    int64_t flags;
    int64_t maximum_messages;
    int64_t message_size;
    int64_t current_messages;
};

struct iocb64 {
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

struct io_event64 {
    uint64_t data;
    uint64_t object;
    int64_t result;
    int64_t result2;
};

static char splice_payload[] = "x32-vmsplice";
static char splice_result[sizeof(splice_payload)];
static int32_t pipe_descriptors[2];
static struct x32_iovec splice_vector;
static struct compat_sigevent timer_event;
static struct compat_sigevent queue_event;
static struct mq_attr64 queue_attributes;
static struct iocb64 aio_control;
static struct io_event64 aio_event;
static uint32_t aio_context;
static uint32_t aio_list[2];
static int32_t timer_id = -1;
static int32_t page_status = -1;

static long call(long number, long a0, long a1, long a2,
                 long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a0),
                     "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

static long x32(long number, long a0, long a1, long a2,
                long a3, long a4, long a5) {
    return call((long)(X32_BIT | (uint64_t)number),
                a0, a1, a2, a3, a4, a5);
}

static unsigned long text_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void print_text(const char *text) {
    call(SYS_write, 1, (long)text, (long)text_length(text), 0, 0, 0);
}

static int expect(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text("\n");
    return 1;
}

static int bytes_equal(const char *left, const char *right,
                       unsigned long length) {
    for (unsigned long index = 0; index < length; ++index) {
        if (left[index] != right[index]) return 0;
    }
    return 1;
}

START_ATTRIBUTES void _start(void) {
    static const char aio_path[] = "/x32-aio-probe";
    static const char queue_name[] = "x32-uapi-probe";
    uint32_t page_list[1];
    long mapping;
    long descriptor;
    long queue;
    int failures = 0;

    failures += expect("pipe2", x32(
        SYS_pipe2, (long)pipe_descriptors, 0, 0, 0, 0, 0), 0);
    splice_vector.base = (uint32_t)(uintptr_t)splice_payload;
    splice_vector.length = sizeof(splice_payload);
    failures += expect("vmsplice", x32(
        X32_vmsplice, pipe_descriptors[1], (long)&splice_vector, 1,
        0, 0, 0), sizeof(splice_payload));
    failures += expect("vmsplice-read", x32(
        SYS_read, pipe_descriptors[0], (long)splice_result,
        sizeof(splice_result), 0, 0, 0), sizeof(splice_result));
    if (!bytes_equal(splice_payload, splice_result, sizeof(splice_result))) {
        print_text("FAIL vmsplice-data\n");
        ++failures;
    }
    x32(SYS_close, pipe_descriptors[0], 0, 0, 0, 0, 0);
    x32(SYS_close, pipe_descriptors[1], 0, 0, 0, 0, 0);

    mapping = x32(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping < 0) {
        print_text("FAIL move-pages-mmap\n");
        ++failures;
    } else {
        *(volatile uint32_t *)(uintptr_t)mapping = UINT32_C(0x12345678);
        page_list[0] = (uint32_t)mapping;
        failures += expect("move-pages", x32(
            X32_move_pages, 0, 1, (long)page_list, 0,
            (long)&page_status, 0), 0);
        x32(SYS_munmap, mapping, 4096, 0, 0, 0, 0);
    }

    descriptor = x32(SYS_openat, AT_FDCWD, (long)aio_path,
                     O_CREAT | O_RDWR, 0600, 0, 0);
    if (descriptor < 0) {
        print_text("FAIL aio-open\n");
        ++failures;
    } else {
        failures += expect("io-setup", x32(
            X32_io_setup, 2, (long)&aio_context, 0, 0, 0, 0), 0);
        aio_control.data = UINT64_C(0x1122334455667788);
        aio_control.opcode = IOCB_CMD_FSYNC;
        aio_control.descriptor = (uint32_t)descriptor;
        aio_list[0] = (uint32_t)(uintptr_t)&aio_control;
        aio_list[1] = UINT32_C(0xdeadbeef);
        failures += expect("io-submit", x32(
            X32_io_submit, aio_context, 1, (long)aio_list,
            0, 0, 0), 1);
        failures += expect("io-getevents", x32(
            SYS_io_getevents, aio_context, 1, 1, (long)&aio_event,
            0, 0), 1);
        failures += expect("io-result", aio_event.result, 0);
        failures += expect("io-destroy", x32(
            SYS_io_destroy, aio_context, 0, 0, 0, 0, 0), 0);
        x32(SYS_close, descriptor, 0, 0, 0, 0, 0);
        x32(SYS_unlinkat, AT_FDCWD, (long)aio_path, 0, 0, 0, 0);
    }

    timer_event.notification = SIGEV_NONE;
    timer_event.value = UINT32_C(0xaabbccdd);
    failures += expect("timer-create", x32(
        X32_timer_create, CLOCK_MONOTONIC, (long)&timer_event,
        (long)&timer_id, 0, 0, 0), 0);
    if (timer_id >= 0)
        failures += expect("timer-delete", x32(
            SYS_timer_delete, timer_id, 0, 0, 0, 0, 0), 0);

    queue_attributes.maximum_messages = 4;
    queue_attributes.message_size = 64;
    queue = x32(SYS_mq_open, (long)queue_name, O_CREAT | O_RDWR,
                0600, (long)&queue_attributes, 0, 0);
    if (queue < 0) {
        print_text("FAIL mq-open\n");
        ++failures;
    } else {
        queue_event.notification = SIGEV_NONE;
        queue_event.value = UINT32_C(0x55667788);
        failures += expect("mq-notify", x32(
            X32_mq_notify, queue, (long)&queue_event, 0, 0, 0, 0), 0);
        failures += expect("mq-unregister", x32(
            X32_mq_notify, queue, 0, 0, 0, 0, 0), 0);
        x32(SYS_close, queue, 0, 0, 0, 0, 0);
        x32(SYS_mq_unlink, (long)queue_name, 0, 0, 0, 0, 0);
    }

    if (failures) {
        print_text("X32_EXTENDED_COMPAT_ABI_PROBE_FAIL\n");
        call(SYS_exit, 1, 0, 0, 0, 0, 0);
    }
    print_text("X32_EXTENDED_COMPAT_ABI_PROBE_PASS\n");
    call(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
