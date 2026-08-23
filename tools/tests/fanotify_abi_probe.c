/* SPDX-License-Identifier: MPL-2.0 */
/* Linux fanotify notification ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_getpid 39
#define SYS_gettid 186
#define SYS_exit 60
#define SYS_openat 257
#define SYS_mkdirat 258
#define SYS_unlinkat 263
#define SYS_fanotify_init 300
#define SYS_fanotify_mark 301
#elif defined(__aarch64__)
#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_getpid 172
#define SYS_gettid 178
#define SYS_exit 93
#define SYS_openat 56
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_fanotify_init 262
#define SYS_fanotify_mark 263
#else
#error "fanotify_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200
#define O_RDONLY 0x0
#define O_RDWR 0x2
#define O_CREAT 0x40
#define O_CLOEXEC 0x80000
#define FAN_CLOEXEC 0x1
#define FAN_NONBLOCK 0x2
#define FAN_REPORT_PIDFD 0x80
#define FAN_REPORT_TID 0x100
#define FAN_MARK_ADD 0x1
#define FAN_MARK_REMOVE 0x2
#define FAN_MARK_FLUSH 0x80
#define FAN_OPEN 0x20
#define FANOTIFY_METADATA_VERSION 3
#define FAN_EVENT_INFO_TYPE_PIDFD 4
#define EAGAIN 11
#define EBADF 9
#define EINVAL 22
#define EEXIST 17

struct fanotify_event_metadata {
    uint32_t event_len;
    uint8_t vers;
    uint8_t reserved;
    uint16_t metadata_len;
    uint64_t mask;
    int32_t fd;
    int32_t pid;
};

struct fanotify_event_info_pidfd {
    uint8_t info_type;
    uint8_t pad;
    uint16_t len;
    int32_t pidfd;
};

struct fanotify_pidfd_record {
    struct fanotify_event_metadata metadata;
    struct fanotify_event_info_pidfd pidfd;
};

_Static_assert(sizeof(struct fanotify_event_metadata) == 24,
               "fanotify metadata layout mismatch");
_Static_assert(sizeof(struct fanotify_event_info_pidfd) == 8,
               "fanotify pidfd layout mismatch");
_Static_assert(sizeof(struct fanotify_pidfd_record) == 32,
               "fanotify pidfd record layout mismatch");

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

void _start(void) {
    static const char directory[] = "/tmp/edge-fanotify-probe";
    static const char path[] = "/tmp/edge-fanotify-probe/event";
    struct fanotify_event_metadata events[4];
    long group;
    long file;
    long result;
    long pid;
    int found = 0;
    int failures = 0;

    failures += expect_result(
        "invalid-init-flags",
        raw_syscall6(SYS_fanotify_init, 0x80000000u, 0, 0, 0, 0, 0),
        -EINVAL);
    result = raw_syscall6(
        SYS_mkdirat, AT_FDCWD, (long)directory, 0700, 0, 0, 0);
    if (result < 0 && result != -EEXIST)
        failures += expect_result("mkdir", result, 0);
    file = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path,
        O_RDWR | O_CREAT | O_CLOEXEC, 0600, 0, 0);
    if (file < 0) {
        failures += expect_result("create-source", file, 0);
        goto out;
    }
    (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);

    group = raw_syscall6(
        SYS_fanotify_init, FAN_CLOEXEC | FAN_NONBLOCK,
        O_CLOEXEC, 0, 0, 0, 0);
    if (group < 0) {
        failures += expect_result("fanotify-init", group, 0);
        goto out;
    }
    failures += expect_result(
        "empty-read",
        raw_syscall6(SYS_read, group, (long)events, sizeof(events), 0, 0, 0),
        -EAGAIN);
    failures += expect_result(
        "bad-mark-fd",
        raw_syscall6(SYS_fanotify_mark, -1, FAN_MARK_ADD,
                     FAN_OPEN, AT_FDCWD, (long)path, 0),
        -EBADF);
    failures += expect_result(
        "add-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                     FAN_OPEN, AT_FDCWD, (long)path, 0),
        0);

    file = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (file < 0) {
        failures += expect_result("open-event-file", file, 0);
    } else {
        (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);
    }
    result = raw_syscall6(
        SYS_read, group, (long)events, sizeof(events), 0, 0, 0);
    if (result < (long)sizeof(events[0]) ||
        result % (long)sizeof(events[0]) != 0) {
        failures += expect_result("event-read", result, sizeof(events[0]));
    } else {
        pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
        for (long offset = 0; offset < result;
             offset += (long)sizeof(events[0])) {
            struct fanotify_event_metadata *event =
                (struct fanotify_event_metadata *)
                    ((unsigned char *)events + offset);
            if (event->event_len != sizeof(*event) ||
                event->metadata_len != sizeof(*event) ||
                event->vers != FANOTIFY_METADATA_VERSION)
                ++failures;
            if (event->mask & FAN_OPEN) {
                found = 1;
                if (event->pid != pid || event->fd < 0) ++failures;
            }
            if (event->fd >= 0)
                (void)raw_syscall6(SYS_close, event->fd, 0, 0, 0, 0, 0);
        }
        if (!found) {
            print_text("FAIL missing-open-event\n");
            ++failures;
        }
    }
    failures += expect_result(
        "remove-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                     FAN_OPEN, AT_FDCWD, (long)path, 0),
        0);
    failures += expect_result(
        "flush-marks",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_FLUSH,
                     0, AT_FDCWD, 0, 0),
        0);
    (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);

    {
        struct fanotify_pidfd_record record;
        struct fanotify_event_metadata short_record;

        failures += expect_result(
            "pidfd-tid-combination",
            raw_syscall6(
                SYS_fanotify_init,
                FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_PIDFD |
                    FAN_REPORT_TID,
                O_CLOEXEC, 0, 0, 0, 0),
            -EINVAL);
        group = raw_syscall6(
            SYS_fanotify_init,
            FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_PIDFD,
            O_CLOEXEC, 0, 0, 0, 0);
        if (group < 0) {
            failures += expect_result("pidfd-init", group, 0);
            goto out;
        }
        failures += expect_result(
            "pidfd-add-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                         FAN_OPEN, AT_FDCWD, (long)path, 0),
            0);
        file = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)path,
            O_RDONLY | O_CLOEXEC, 0, 0, 0);
        if (file < 0) {
            failures += expect_result("pidfd-open-event-file", file, 0);
        } else {
            (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);
        }
        failures += expect_result(
            "pidfd-short-read",
            raw_syscall6(SYS_read, group, (long)&short_record,
                         sizeof(short_record), 0, 0, 0),
            -EINVAL);
        result = raw_syscall6(
            SYS_read, group, (long)&record, sizeof(record), 0, 0, 0);
        failures += expect_result(
            "pidfd-event-read", result, sizeof(record));
        if (result == (long)sizeof(record)) {
            pid = raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
            if (record.metadata.event_len != sizeof(record) ||
                record.metadata.metadata_len !=
                    sizeof(record.metadata) ||
                record.metadata.vers != FANOTIFY_METADATA_VERSION ||
                !(record.metadata.mask & FAN_OPEN) ||
                record.metadata.pid != pid || record.metadata.fd < 0 ||
                record.pidfd.info_type != FAN_EVENT_INFO_TYPE_PIDFD ||
                record.pidfd.len != sizeof(record.pidfd) ||
                record.pidfd.pidfd < 0) {
                print_text("FAIL pidfd-event-layout\n");
                ++failures;
            }
            if (record.metadata.fd >= 0)
                (void)raw_syscall6(
                    SYS_close, record.metadata.fd, 0, 0, 0, 0, 0);
            if (record.pidfd.pidfd >= 0)
                (void)raw_syscall6(
                    SYS_close, record.pidfd.pidfd, 0, 0, 0, 0, 0);
        }
        failures += expect_result(
            "pidfd-remove-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                         FAN_OPEN, AT_FDCWD, (long)path, 0),
            0);
        (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
    }

    {
        struct fanotify_event_metadata event;
        long tid;

        group = raw_syscall6(
            SYS_fanotify_init,
            FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_TID,
            O_CLOEXEC, 0, 0, 0, 0);
        if (group < 0) {
            failures += expect_result("tid-init", group, 0);
            goto out;
        }
        failures += expect_result(
            "tid-add-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                         FAN_OPEN, AT_FDCWD, (long)path, 0),
            0);
        file = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)path,
            O_RDONLY | O_CLOEXEC, 0, 0, 0);
        if (file < 0) {
            failures += expect_result("tid-open-event-file", file, 0);
        } else {
            (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);
        }
        result = raw_syscall6(
            SYS_read, group, (long)&event, sizeof(event), 0, 0, 0);
        failures += expect_result("tid-event-read", result, sizeof(event));
        if (result == (long)sizeof(event)) {
            tid = raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
            if (event.event_len != sizeof(event) ||
                event.metadata_len != sizeof(event) ||
                event.vers != FANOTIFY_METADATA_VERSION ||
                !(event.mask & FAN_OPEN) || event.pid != tid ||
                event.fd < 0) {
                print_text("FAIL tid-event-layout\n");
                ++failures;
            }
            if (event.fd >= 0)
                (void)raw_syscall6(
                    SYS_close, event.fd, 0, 0, 0, 0, 0);
        }
        failures += expect_result(
            "tid-remove-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                         FAN_OPEN, AT_FDCWD, (long)path, 0),
            0);
        (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
    }

out:
    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    (void)raw_syscall6(
        SYS_unlinkat, AT_FDCWD, (long)directory, AT_REMOVEDIR, 0, 0, 0);
    if (!failures) print_text("FANOTIFY_ABI_PROBE_PASS\n");
    (void)raw_syscall6(SYS_exit, failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) { }
}
