/* SPDX-License-Identifier: MPL-2.0 */
/* Linux fanotify notification ABI probe for x86_64 and AArch64. */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_sched_yield 24
#define SYS_getpid 39
#define SYS_clone 56
#define SYS_execve 59
#define SYS_gettid 186
#define SYS_wait4 61
#define SYS_ftruncate 77
#define SYS_getdents64 217
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
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_sched_yield 124
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_execve 221
#define SYS_gettid 178
#define SYS_wait4 260
#define SYS_ftruncate 46
#define SYS_getdents64 61
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
#define O_DIRECTORY 0x10000
#define PROT_READ 0x1
#define MAP_PRIVATE 0x2
#define FAN_CLOEXEC 0x1
#define FAN_NONBLOCK 0x2
#define FAN_CLASS_CONTENT 0x4
#define FAN_CLASS_PRE_CONTENT 0x8
#define FAN_REPORT_PIDFD 0x80
#define FAN_REPORT_TID 0x100
#define FAN_REPORT_FID 0x200
#define FAN_REPORT_DIR_FID 0x400
#define FAN_REPORT_NAME 0x800
#define FAN_MARK_ADD 0x1
#define FAN_MARK_REMOVE 0x2
#define FAN_MARK_FLUSH 0x80
#define FAN_OPEN 0x20
#define FAN_OPEN_PERM 0x10000
#define FAN_ACCESS_PERM 0x20000
#define FAN_OPEN_EXEC_PERM 0x40000
#define FAN_PRE_ACCESS 0x100000
#define FAN_CREATE 0x100
#define FAN_EVENT_ON_CHILD 0x08000000u
#define FAN_ONDIR 0x40000000u
#define FANOTIFY_METADATA_VERSION 3
#define FAN_EVENT_INFO_TYPE_FID 1
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#define FAN_EVENT_INFO_TYPE_PIDFD 4
#define FAN_EVENT_INFO_TYPE_RANGE 6
#define FAN_ALLOW 0x1
#define FAN_DENY 0x2
#define SIGCHLD 17
#define EPERM 1
#define EAGAIN 11
#define EBADF 9
#define ENOENT 2
#define EINVAL 22
#define EEXIST 17

#define PRE_OPERATION_MMAP 1
#define PRE_OPERATION_TRUNCATE 2
#define PRE_OPERATION_GETDENTS 3

#ifndef FANOTIFY_EXEC_TARGET_PATH
#define FANOTIFY_EXEC_TARGET_PATH "/probes/fanotify_exec_target"
#endif

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

struct fanotify_event_info_header {
    uint8_t info_type;
    uint8_t pad;
    uint16_t len;
};

struct fanotify_pidfd_record {
    struct fanotify_event_metadata metadata;
    struct fanotify_event_info_pidfd pidfd;
};

struct fanotify_event_info_fid_prefix {
    uint8_t info_type;
    uint8_t pad;
    uint16_t len;
    int32_t fsid[2];
    uint32_t handle_bytes;
    int32_t handle_type;
};

struct fanotify_response {
    int32_t fd;
    uint32_t response;
};

struct fanotify_event_info_range {
    uint8_t info_type;
    uint8_t pad8;
    uint16_t len;
    uint32_t pad32;
    uint64_t offset;
    uint64_t count;
};

struct fanotify_range_record {
    struct fanotify_event_metadata metadata;
    struct fanotify_event_info_range range;
};

_Static_assert(sizeof(struct fanotify_event_metadata) == 24,
               "fanotify metadata layout mismatch");
_Static_assert(sizeof(struct fanotify_event_info_pidfd) == 8,
               "fanotify pidfd layout mismatch");
_Static_assert(sizeof(struct fanotify_pidfd_record) == 32,
               "fanotify pidfd record layout mismatch");
_Static_assert(sizeof(struct fanotify_event_info_fid_prefix) == 20,
               "fanotify FID prefix layout mismatch");
_Static_assert(sizeof(struct fanotify_response) == 8,
               "fanotify response layout mismatch");
_Static_assert(sizeof(struct fanotify_event_info_range) == 24,
               "fanotify range information layout mismatch");
_Static_assert(sizeof(struct fanotify_range_record) == 48,
               "fanotify range record layout mismatch");

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

static long read_permission_event(
        long group, struct fanotify_event_metadata *event) {
    for (unsigned long attempt = 0; attempt < 100000u; ++attempt) {
        long result = raw_syscall6(
            SYS_read, group, (long)event, sizeof(*event), 0, 0, 0);
        if (result != -EAGAIN) return result;
        (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    return -EAGAIN;
}

static int run_permission_response_test(
        const char *path, uint32_t class_flag, uint32_t response_value,
        long expected_open_result, const char *label) {
    struct fanotify_event_metadata event;
    struct fanotify_response response;
    struct fanotify_response unknown;
    long group;
    long child;
    long result;
    int status = -1;
    int failures = 0;

    group = raw_syscall6(
        SYS_fanotify_init,
        FAN_CLOEXEC | FAN_NONBLOCK | class_flag,
        O_CLOEXEC, 0, 0, 0, 0);
    if (group < 0)
        return expect_result(label, group, 0);
    failures += expect_result(
        "permission-add-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                     FAN_OPEN_PERM, AT_FDCWD, (long)path, 0),
        0);
    if (failures) goto permission_out;

    child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (child < 0) {
        failures += expect_result("permission-clone", child, 0);
        goto permission_out;
    }
    if (child == 0) {
        long descriptor = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)path,
            O_RDONLY | O_CLOEXEC, 0, 0, 0);
        int child_failed = expected_open_result < 0 ?
            descriptor != expected_open_result : descriptor < 0;
        if (descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, descriptor, 0, 0, 0, 0, 0);
        (void)raw_syscall6(
            SYS_exit, child_failed ? 1 : 0, 0, 0, 0, 0, 0);
        for (;;) { }
    }

    result = read_permission_event(group, &event);
    failures += expect_result(
        "permission-event-read", result, sizeof(event));
    if (result == (long)sizeof(event)) {
        if (event.event_len != sizeof(event) ||
            event.metadata_len != sizeof(event) ||
            event.vers != FANOTIFY_METADATA_VERSION ||
            !(event.mask & FAN_OPEN_PERM) ||
            event.pid != child || event.fd < 0) {
            print_text("FAIL permission-event-layout\n");
            ++failures;
        }
        response.fd = event.fd;
        response.response = response_value;
        failures += expect_result(
            "permission-short-response",
            raw_syscall6(
                SYS_write, group, (long)&response,
                sizeof(response) - 1u, 0, 0, 0),
            -EINVAL);
        unknown = response;
        unknown.fd += 100000;
        failures += expect_result(
            "permission-unknown-response",
            raw_syscall6(
                SYS_write, group, (long)&unknown,
                sizeof(unknown), 0, 0, 0),
            -ENOENT);
        failures += expect_result(
            "permission-response",
            raw_syscall6(
                SYS_write, group, (long)&response,
                sizeof(response), 0, 0, 0),
            sizeof(response));
        if (event.fd >= 0)
            (void)raw_syscall6(
                SYS_close, event.fd, 0, 0, 0, 0, 0);
    }
    result = raw_syscall6(
        SYS_wait4, child, (long)&status, 0, 0, 0, 0);
    failures += expect_result("permission-wait", result, child);
    failures += expect_result("permission-child-status", status, 0);

permission_out:
    failures += expect_result(
        "permission-remove-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                     FAN_OPEN_PERM, AT_FDCWD, (long)path, 0),
        0);
    (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
    return failures;
}

static int run_access_response_test(
        const char *path, uint32_t class_flag, uint64_t mark_mask,
        uint32_t response_value, long expected_read_result,
        int expect_range, const char *label) {
    struct fanotify_range_record record;
    struct fanotify_response response;
    long group;
    long child;
    long result;
    long expected_event_length = expect_range ?
        (long)sizeof(record) : (long)sizeof(record.metadata);
    int status = -1;
    int failures = 0;

    group = raw_syscall6(
        SYS_fanotify_init,
        FAN_CLOEXEC | FAN_NONBLOCK | class_flag,
        O_CLOEXEC, 0, 0, 0, 0);
    if (group < 0) return expect_result(label, group, 0);
    failures += expect_result(
        "access-add-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                     mark_mask, AT_FDCWD, (long)path, 0),
        0);
    if (failures) goto access_out;

    child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (child < 0) {
        failures += expect_result("access-clone", child, 0);
        goto access_out;
    }
    if (child == 0) {
        unsigned char byte = 0;
        long descriptor = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)path,
            O_RDONLY | O_CLOEXEC, 0, 0, 0);
        long read_result = descriptor < 0 ? descriptor : raw_syscall6(
            SYS_read, descriptor, (long)&byte, 1, 0, 0, 0);
        int child_failed = read_result != expected_read_result;
        if (descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, descriptor, 0, 0, 0, 0, 0);
        (void)raw_syscall6(
            SYS_exit, child_failed ? 1 : 0, 0, 0, 0, 0, 0);
        for (;;) { }
    }

    for (unsigned long attempt = 0; attempt < 100000u; ++attempt) {
        result = raw_syscall6(
            SYS_read, group, (long)&record, sizeof(record), 0, 0, 0);
        if (result != -EAGAIN) break;
        (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    failures += expect_result(
        "access-event-read", result, expected_event_length);
    if (result == expected_event_length) {
        if (record.metadata.event_len !=
                (uint32_t)expected_event_length ||
            record.metadata.metadata_len != sizeof(record.metadata) ||
            record.metadata.vers != FANOTIFY_METADATA_VERSION ||
            record.metadata.mask != mark_mask ||
            record.metadata.pid != child || record.metadata.fd < 0) {
            print_text("FAIL access-event-layout\n");
            ++failures;
        }
        if (expect_range &&
            (record.range.info_type != FAN_EVENT_INFO_TYPE_RANGE ||
             record.range.len != sizeof(record.range) ||
             record.range.offset != 0u || record.range.count != 4096u)) {
            print_text("FAIL access-range-layout\n");
            ++failures;
        }
        response.fd = record.metadata.fd;
        response.response = response_value;
        failures += expect_result(
            "access-response",
            raw_syscall6(SYS_write, group, (long)&response,
                         sizeof(response), 0, 0, 0),
            sizeof(response));
        (void)raw_syscall6(
            SYS_close, record.metadata.fd, 0, 0, 0, 0, 0);
    }
    result = raw_syscall6(
        SYS_wait4, child, (long)&status, 0, 0, 0, 0);
    failures += expect_result("access-wait", result, child);
    failures += expect_result("access-child-status", status, 0);

access_out:
    failures += expect_result(
        "access-remove-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                     mark_mask, AT_FDCWD, (long)path, 0),
        0);
    (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
static int run_exec_response_test(uint32_t response_value,
                                  long expected_exec_result,
                                  const char *label) {
    static const char target[] = FANOTIFY_EXEC_TARGET_PATH;
    struct fanotify_event_metadata event;
    struct fanotify_response response;
    long group;
    long child;
    long result;
    int status = -1;
    int failures = 0;

    group = raw_syscall6(
        SYS_fanotify_init,
        FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_CONTENT,
        O_CLOEXEC, 0, 0, 0, 0);
    if (group < 0) return expect_result(label, group, 0);
    failures += expect_result(
        "exec-add-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                     FAN_OPEN_EXEC_PERM, AT_FDCWD, (long)target, 0),
        0);
    if (failures) goto exec_out;

    child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (child < 0) {
        failures += expect_result("exec-clone", child, 0);
        goto exec_out;
    }
    if (child == 0) {
        char *arguments[2] = {(char *)target, 0};
        char *environment[1] = {0};
        long exec_result = raw_syscall6(
            SYS_execve, (long)target, (long)arguments,
            (long)environment, 0, 0, 0);
        int child_failed = expected_exec_result < 0 ?
            exec_result != expected_exec_result : 1;
        (void)raw_syscall6(
            SYS_exit, child_failed ? 1 : 0, 0, 0, 0, 0, 0);
        for (;;) { }
    }

    result = read_permission_event(group, &event);
    failures += expect_result("exec-event-read", result, sizeof(event));
    if (result == (long)sizeof(event)) {
        if (event.event_len != sizeof(event) ||
            event.metadata_len != sizeof(event) ||
            event.vers != FANOTIFY_METADATA_VERSION ||
            event.mask != FAN_OPEN_EXEC_PERM ||
            event.pid != child || event.fd < 0) {
            print_text("FAIL exec-event-layout\n");
            ++failures;
        }
        response.fd = event.fd;
        response.response = response_value;
        failures += expect_result(
            "exec-response",
            raw_syscall6(SYS_write, group, (long)&response,
                         sizeof(response), 0, 0, 0),
            sizeof(response));
        (void)raw_syscall6(SYS_close, event.fd, 0, 0, 0, 0, 0);
    }
    result = raw_syscall6(
        SYS_wait4, child, (long)&status, 0, 0, 0, 0);
    failures += expect_result("exec-wait", result, child);
    failures += expect_result("exec-child-status", status, 0);

exec_out:
    failures += expect_result(
        "exec-remove-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                     FAN_OPEN_EXEC_PERM, AT_FDCWD, (long)target, 0),
        0);
    (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
    return failures;
}

static int run_area_permission_test(
        const char *path, uint64_t mark_mask, int operation,
        uint32_t response_value, long expected_result,
        uint64_t expected_offset, uint64_t expected_count,
        const char *label) {
    struct fanotify_range_record record;
    struct fanotify_response response;
    long expected_event_length = expected_count == UINT64_MAX ?
        (long)sizeof(record.metadata) : (long)sizeof(record);
    long group;
    long child;
    long result;
    int status = -1;
    int failures = 0;
    uint64_t expected_event_mask = mark_mask & ~FAN_ONDIR;

    group = raw_syscall6(
        SYS_fanotify_init,
        FAN_CLOEXEC | FAN_NONBLOCK |
            (mark_mask & FAN_PRE_ACCESS ?
                FAN_CLASS_PRE_CONTENT : FAN_CLASS_CONTENT),
        O_CLOEXEC, 0, 0, 0, 0);
    if (group < 0) return expect_result(label, group, 0);
    failures += expect_result(
        "area-add-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                     (long)mark_mask, AT_FDCWD, (long)path, 0),
        0);
    if (failures) goto area_out;

    child = raw_syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (child < 0) {
        failures += expect_result("area-clone", child, 0);
        goto area_out;
    }
    if (child == 0) {
        unsigned char directory_buffer[256];
        long open_flags = operation == PRE_OPERATION_TRUNCATE ?
            O_RDWR | O_CLOEXEC : O_RDONLY | O_CLOEXEC;
        long descriptor;
        long operation_result;
        int child_failed;

        if (operation == PRE_OPERATION_GETDENTS)
            open_flags |= O_DIRECTORY;
        descriptor = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)path,
            open_flags, 0, 0, 0);
        if (descriptor < 0) {
            operation_result = descriptor;
        } else if (operation == PRE_OPERATION_MMAP) {
            operation_result = raw_syscall6(
                SYS_mmap, 0, 4096, PROT_READ, MAP_PRIVATE,
                descriptor, 0);
            if (operation_result >= 0)
                (void)raw_syscall6(
                    SYS_munmap, operation_result, 4096, 0, 0, 0, 0);
        } else if (operation == PRE_OPERATION_TRUNCATE) {
            operation_result = raw_syscall6(
                SYS_ftruncate, descriptor, 123, 0, 0, 0, 0);
        } else {
            operation_result = raw_syscall6(
                SYS_getdents64, descriptor,
                (long)directory_buffer, sizeof(directory_buffer),
                0, 0, 0);
        }
        child_failed = expected_result < 0 ?
            operation_result != expected_result : operation_result < 0;
        if (descriptor >= 0)
            (void)raw_syscall6(
                SYS_close, descriptor, 0, 0, 0, 0, 0);
        (void)raw_syscall6(
            SYS_exit, child_failed ? 1 : 0, 0, 0, 0, 0, 0);
        for (;;) { }
    }

    for (unsigned long attempt = 0; attempt < 100000u; ++attempt) {
        result = raw_syscall6(
            SYS_read, group, (long)&record, sizeof(record), 0, 0, 0);
        if (result != -EAGAIN) break;
        (void)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    failures += expect_result(
        "area-event-read", result, expected_event_length);
    if (result == expected_event_length) {
        if (record.metadata.event_len !=
                (uint32_t)expected_event_length ||
            record.metadata.metadata_len != sizeof(record.metadata) ||
            record.metadata.vers != FANOTIFY_METADATA_VERSION ||
            record.metadata.mask != expected_event_mask ||
            record.metadata.pid != child || record.metadata.fd < 0) {
            print_text("FAIL area-event-layout\n");
            print_text("AREA_EVENT event_len=");
            print_number(record.metadata.event_len);
            print_text(" metadata_len=");
            print_number(record.metadata.metadata_len);
            print_text(" version=");
            print_number(record.metadata.vers);
            print_text(" mask=");
            print_number((long)record.metadata.mask);
            print_text(" expected_mask=");
            print_number((long)expected_event_mask);
            print_text(" pid=");
            print_number(record.metadata.pid);
            print_text(" expected_pid=");
            print_number(child);
            print_text(" fd=");
            print_number(record.metadata.fd);
            print_text("\n");
            ++failures;
        }
        if (expected_count != UINT64_MAX &&
            (record.range.info_type != FAN_EVENT_INFO_TYPE_RANGE ||
             record.range.len != sizeof(record.range) ||
             record.range.offset != expected_offset ||
             record.range.count != expected_count)) {
            print_text("FAIL area-range-layout\n");
            ++failures;
        }
        response.fd = record.metadata.fd;
        response.response = response_value;
        failures += expect_result(
            "area-response",
            raw_syscall6(SYS_write, group, (long)&response,
                         sizeof(response), 0, 0, 0),
            sizeof(response));
        (void)raw_syscall6(
            SYS_close, record.metadata.fd, 0, 0, 0, 0, 0);
    }
    result = raw_syscall6(
        SYS_wait4, child, (long)&status, 0, 0, 0, 0);
    failures += expect_result("area-wait", result, child);
    failures += expect_result("area-child-status", status, 0);

area_out:
    failures += expect_result(
        "area-remove-mark",
        raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                     (long)mark_mask, AT_FDCWD, (long)path, 0),
        0);
    (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
    return failures;
}

void _start(void) {
    static const char directory[] = "/tmp/edge-fanotify-probe";
    static const char path[] = "/tmp/edge-fanotify-probe/event";
    static const char fid_path[] = "/edgeos-fanotify-fid-probe";
    static const char dfid_directory[] = "/edgeos-fanotify-dfid-probe";
    static const char dfid_path[] = "/edgeos-fanotify-dfid-probe/child";
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

    print_text("FANOTIFY_STAGE open-allow\n");
    failures += run_permission_response_test(
        path, FAN_CLASS_CONTENT, FAN_ALLOW, 0,
        "permission-content-init");
    print_text("FANOTIFY_STAGE open-deny\n");
    failures += run_permission_response_test(
        path, FAN_CLASS_CONTENT, FAN_DENY, -EPERM,
        "permission-deny-init");
    print_text("FANOTIFY_STAGE pre-access\n");
    failures += run_access_response_test(
        "/probes/fanotify_abi_probe", FAN_CLASS_PRE_CONTENT,
        FAN_PRE_ACCESS, FAN_ALLOW, 1, 1, "pre-access-init");
    print_text("FANOTIFY_STAGE access-deny\n");
    failures += run_access_response_test(
        "/probes/fanotify_abi_probe", FAN_CLASS_CONTENT,
        FAN_ACCESS_PERM, FAN_DENY, -EPERM, 0, "access-deny-init");
    print_text("FANOTIFY_STAGE mmap-deny\n");
    failures += run_area_permission_test(
        "/probes/fanotify_abi_probe", FAN_PRE_ACCESS,
        PRE_OPERATION_MMAP, FAN_DENY, -EPERM,
        0u, 4096u, "mmap-deny-init");
    print_text("FANOTIFY_STAGE truncate-allow\n");
    failures += run_area_permission_test(
        path, FAN_PRE_ACCESS, PRE_OPERATION_TRUNCATE,
        FAN_ALLOW, 0, 0u, 4096u, "truncate-allow-init");
    print_text("FANOTIFY_STAGE getdents-deny\n");
    failures += run_area_permission_test(
        directory, FAN_ACCESS_PERM | FAN_ONDIR,
        PRE_OPERATION_GETDENTS, FAN_DENY, -EPERM,
        0u, UINT64_MAX, "getdents-deny-init");
    print_text("FANOTIFY_STAGE exec-allow\n");
    failures += run_exec_response_test(
        FAN_ALLOW, 0, "exec-allow-init");
    print_text("FANOTIFY_STAGE exec-deny\n");
    failures += run_exec_response_test(
        FAN_DENY, -EPERM, "exec-deny-init");
    print_text("FANOTIFY_STAGE notification-info\n");
    {
        struct fanotify_pidfd_record record;
        struct fanotify_event_metadata short_record;

        result = raw_syscall6(
            SYS_fanotify_init,
            FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_PIDFD |
                FAN_REPORT_TID,
            O_CLOEXEC, 0, 0, 0, 0);
        if (result < 0) {
            failures += expect_result(
                "pidfd-tid-combination", result, 0);
        } else {
            (void)raw_syscall6(
                SYS_close, result, 0, 0, 0, 0, 0);
        }
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

    {
        unsigned char record[256];
        struct fanotify_event_metadata short_record;
        struct fanotify_event_metadata *event =
            (struct fanotify_event_metadata *)(void *)record;
        struct fanotify_event_info_fid_prefix *fid =
            (struct fanotify_event_info_fid_prefix *)(void *)
                (record + sizeof(*event));

        file = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)fid_path,
            O_RDWR | O_CREAT | O_CLOEXEC, 0600, 0, 0);
        if (file < 0) {
            failures += expect_result("fid-create-source", file, 0);
            goto out;
        }
        (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);
        group = raw_syscall6(
            SYS_fanotify_init,
            FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID,
            O_CLOEXEC, 0, 0, 0, 0);
        if (group < 0) {
            failures += expect_result("fid-init", group, 0);
            goto fid_out;
        }
        failures += expect_result(
            "fid-add-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                         FAN_OPEN, AT_FDCWD, (long)fid_path, 0),
            0);
        file = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)fid_path,
            O_RDONLY | O_CLOEXEC, 0, 0, 0);
        if (file < 0) {
            failures += expect_result("fid-open-event-file", file, 0);
        } else {
            (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);
        }
        failures += expect_result(
            "fid-short-read",
            raw_syscall6(SYS_read, group, (long)&short_record,
                         sizeof(short_record), 0, 0, 0),
            -EINVAL);
        result = raw_syscall6(
            SYS_read, group, (long)record, sizeof(record), 0, 0, 0);
        if (result < 48 || result > (long)sizeof(record) ||
            event->event_len != (uint32_t)result ||
            event->metadata_len != sizeof(*event) ||
            event->vers != FANOTIFY_METADATA_VERSION ||
            !(event->mask & FAN_OPEN) || event->fd != -1 ||
            fid->info_type != FAN_EVENT_INFO_TYPE_FID ||
            fid->len < 24u ||
            fid->len > event->event_len - sizeof(*event) ||
            !fid->handle_bytes ||
            fid->handle_bytes > fid->len - sizeof(*fid)) {
            print_text("FAIL fid-event-layout\n");
            print_text("fid result=");
            print_number(result);
            print_text(" event_len=");
            print_number(event->event_len);
            print_text(" metadata_len=");
            print_number(event->metadata_len);
            print_text(" fd=");
            print_number(event->fd);
            print_text(" info_type=");
            print_number(fid->info_type);
            print_text(" info_len=");
            print_number(fid->len);
            print_text(" handle_bytes=");
            print_number(fid->handle_bytes);
            print_text(" handle_type=");
            print_number(fid->handle_type);
            print_text("\n");
            ++failures;
        }
        failures += expect_result(
            "fid-remove-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                         FAN_OPEN, AT_FDCWD, (long)fid_path, 0),
            0);
        (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);

        group = raw_syscall6(
            SYS_fanotify_init,
            FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID |
                FAN_REPORT_PIDFD,
            O_CLOEXEC, 0, 0, 0, 0);
        if (group < 0) {
            failures += expect_result("fid-pidfd-init", group, 0);
            goto fid_out;
        }
        failures += expect_result(
            "fid-pidfd-add-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_ADD,
                         FAN_OPEN, AT_FDCWD, (long)fid_path, 0),
            0);
        file = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)fid_path,
            O_RDONLY | O_CLOEXEC, 0, 0, 0);
        if (file >= 0)
            (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);
        result = raw_syscall6(
            SYS_read, group, (long)record, sizeof(record), 0, 0, 0);
        if (result < 56 || result > (long)sizeof(record)) {
            print_text("FAIL fid-pidfd-event-size\n");
            ++failures;
        } else {
            uint32_t offset = sizeof(*event);
            int found_fid = 0;
            int found_pidfd = 0;

            while (offset + sizeof(struct fanotify_event_info_header) <=
                   event->event_len) {
                struct fanotify_event_info_header *header =
                    (struct fanotify_event_info_header *)(void *)
                        (record + offset);
                if (header->len < sizeof(*header) ||
                    offset + header->len > event->event_len)
                    break;
                if (header->info_type == FAN_EVENT_INFO_TYPE_FID)
                    found_fid = 1;
                if (header->info_type == FAN_EVENT_INFO_TYPE_PIDFD &&
                    header->len == sizeof(struct fanotify_event_info_pidfd)) {
                    struct fanotify_event_info_pidfd *information =
                        (struct fanotify_event_info_pidfd *)(void *)header;
                    found_pidfd = information->pidfd >= 0;
                    if (information->pidfd >= 0)
                        (void)raw_syscall6(
                            SYS_close, information->pidfd,
                            0, 0, 0, 0, 0);
                }
                offset += header->len;
            }
            if (event->event_len != (uint32_t)result || event->fd != -1 ||
                !found_fid || !found_pidfd) {
                print_text("FAIL fid-pidfd-event-layout\n");
                ++failures;
            }
        }
        failures += expect_result(
            "fid-pidfd-remove-mark",
            raw_syscall6(SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                         FAN_OPEN, AT_FDCWD, (long)fid_path, 0),
            0);
        (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
fid_out:
        (void)raw_syscall6(
            SYS_unlinkat, AT_FDCWD, (long)fid_path, 0, 0, 0, 0);
    }

    {
        uint64_t aligned_record[64];
        unsigned char *record = (unsigned char *)(void *)aligned_record;
        int found_create = 0;

        (void)raw_syscall6(
            SYS_unlinkat, AT_FDCWD, (long)dfid_path, 0, 0, 0, 0);
        (void)raw_syscall6(
            SYS_unlinkat, AT_FDCWD, (long)dfid_directory,
            AT_REMOVEDIR, 0, 0, 0);
        result = raw_syscall6(
            SYS_mkdirat, AT_FDCWD, (long)dfid_directory, 0700, 0, 0, 0);
        failures += expect_result("dfid-mkdir", result, 0);
        group = raw_syscall6(
            SYS_fanotify_init,
            FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_DIR_FID |
                FAN_REPORT_NAME,
            O_CLOEXEC, 0, 0, 0, 0);
        if (group < 0) {
            failures += expect_result("dfid-init", group, 0);
            goto dfid_out;
        }
        failures += expect_result(
            "dfid-add-mark",
            raw_syscall6(
                SYS_fanotify_mark, group, FAN_MARK_ADD,
                FAN_CREATE | FAN_OPEN | FAN_EVENT_ON_CHILD,
                AT_FDCWD, (long)dfid_directory, 0),
            0);
        file = raw_syscall6(
            SYS_openat, AT_FDCWD, (long)dfid_path,
            O_RDWR | O_CREAT | O_CLOEXEC, 0600, 0, 0);
        if (file >= 0)
            (void)raw_syscall6(SYS_close, file, 0, 0, 0, 0, 0);
        else
            failures += expect_result("dfid-create-child", file, 0);
        result = raw_syscall6(
            SYS_read, group, (long)record, sizeof(aligned_record),
            0, 0, 0);
        if (result < 0) {
            failures += expect_result("dfid-event-read", result, 0);
        } else {
            uint32_t event_offset = 0u;
            while (event_offset + sizeof(struct fanotify_event_metadata) <=
                   (uint32_t)result) {
                struct fanotify_event_metadata *event =
                    (struct fanotify_event_metadata *)(void *)
                        (record + event_offset);
                struct fanotify_event_info_fid_prefix *dfid =
                    (struct fanotify_event_info_fid_prefix *)(void *)
                        (record + event_offset + sizeof(*event));
                uint32_t name_offset;
                const char *name;

                if (event->event_len < sizeof(*event) + sizeof(*dfid) ||
                    event_offset + event->event_len > (uint32_t)result)
                    break;
                name_offset = sizeof(*event) + sizeof(*dfid) +
                    dfid->handle_bytes;
                name = (const char *)(const void *)
                    (record + event_offset + name_offset);
                if (event->fd != -1 ||
                    dfid->info_type != FAN_EVENT_INFO_TYPE_DFID_NAME ||
                    dfid->len > event->event_len - sizeof(*event) ||
                    name_offset >= event->event_len ||
                    name[0] != 'c' || name[1] != 'h' ||
                    name[2] != 'i' || name[3] != 'l' ||
                    name[4] != 'd' || name[5] != 0) {
                    print_text("FAIL dfid-event-layout type=");
                    print_number(dfid->info_type);
                    print_text(" info_len=");
                    print_number(dfid->len);
                    print_text(" event_len=");
                    print_number(event->event_len);
                    print_text(" handle_bytes=");
                    print_number(dfid->handle_bytes);
                    print_text("\n");
                    ++failures;
                }
                if (event->mask & FAN_CREATE) found_create = 1;
                if (!event->event_len) break;
                event_offset += event->event_len;
            }
        }
        if (!found_create) {
            print_text("FAIL dfid-missing-create\n");
            ++failures;
        }
        failures += expect_result(
            "dfid-remove-mark",
            raw_syscall6(
                SYS_fanotify_mark, group, FAN_MARK_REMOVE,
                FAN_CREATE | FAN_OPEN | FAN_EVENT_ON_CHILD,
                AT_FDCWD, (long)dfid_directory, 0),
            0);
        (void)raw_syscall6(SYS_close, group, 0, 0, 0, 0, 0);
dfid_out:
        (void)raw_syscall6(
            SYS_unlinkat, AT_FDCWD, (long)dfid_path, 0, 0, 0, 0);
        (void)raw_syscall6(
            SYS_unlinkat, AT_FDCWD, (long)dfid_directory,
            AT_REMOVEDIR, 0, 0, 0);
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
