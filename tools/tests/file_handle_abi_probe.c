/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS name_to_handle_at and open_by_handle_at Linux ABI test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#if defined(__x86_64__)
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_fcntl 72
#define SYS_unlink 87
#define SYS_capget 125
#define SYS_capset 126
#define SYS_openat 257
#define SYS_name_to_handle_at 303
#define SYS_open_by_handle_at 304
#elif defined(__aarch64__)
#define SYS_fcntl 25
#define SYS_unlinkat 35
#define SYS_openat 56
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_capget 90
#define SYS_capset 91
#define SYS_name_to_handle_at 264
#define SYS_open_by_handle_at 265
#else
#error "file_handle_abi_probe requires a Linux 64-bit architecture"
#endif

#define AT_FDCWD (-100)
#define AT_EMPTY_PATH 0x1000
#define AT_HANDLE_CONNECTABLE 0x2
#define AT_HANDLE_FID 0x200
#define AT_HANDLE_MNT_ID_UNIQUE 0x1
#define AT_SYMLINK_FOLLOW 0x400

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0x40
#define O_EXCL 0x80
#define O_TRUNC 0x200
#define O_DIRECTORY 0x10000
#define O_NOFOLLOW 0x20000
#define O_CLOEXEC 0x80000
#define O_PATH 0x200000
#define O_TMPFILE 0x410000

#define F_GETFD 1
#define FD_CLOEXEC 1

#define EBADF 9
#define EFAULT 14
#define EEXIST 17
#define ENOTDIR 20
#define EINVAL 22
#define ENOENT 2
#define EOVERFLOW 75
#define EPERM 1
#define ESTALE 116

#define CAP_DAC_READ_SEARCH 2
#define LINUX_CAPABILITY_VERSION_3 0x20080522u

struct file_handle_buffer {
    uint32_t handle_bytes;
    int32_t handle_type;
    uint8_t value[128];
};

struct cap_header {
    uint32_t version;
    int32_t pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
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

static unsigned long string_length(const char *text) {
    unsigned long length = 0;
    while (text[length]) ++length;
    return length;
}

static void zero_bytes(void *destination, unsigned long length) {
    unsigned char *out = destination;
    while (length--) *out++ = 0;
}

void *memcpy(void *destination, const void *source, unsigned long length) {
    unsigned char *out = destination;
    const unsigned char *in = source;
    while (length--) *out++ = *in++;
    return destination;
}

static int bytes_equal(const void *left, const void *right,
                       unsigned long length) {
    const unsigned char *a = left;
    const unsigned char *b = right;
    while (length--) {
        if (*a++ != *b++) return 0;
    }
    return 1;
}

static void print_text(const char *text) {
    (void)raw_syscall6(SYS_write, 1, (long)text,
                       (long)string_length(text), 0, 0, 0);
}

static void print_number(long value) {
    char buffer[32];
    unsigned long magnitude;
    int position = (int)sizeof(buffer);
    if (value < 0) {
        print_text("-");
        magnitude = (unsigned long)(-(value + 1)) + 1u;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        buffer[--position] = (char)('0' + magnitude % 10u);
        magnitude /= 10u;
    } while (magnitude);
    (void)raw_syscall6(SYS_write, 1, (long)&buffer[position],
                       (long)(sizeof(buffer) - (unsigned long)position),
                       0, 0, 0);
}

static int expect_result(const char *name, long actual, long expected) {
    if (actual == expected) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(expected);
    print_text("\n");
    return 1;
}

static int expect_nonnegative(const char *name, long actual) {
    if (actual >= 0) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text("\n");
    return 1;
}

static int expect_either(const char *name, long actual,
                         long first, long second) {
    if (actual == first || actual == second) return 0;
    print_text("FAIL ");
    print_text(name);
    print_text(" actual=");
    print_number(actual);
    print_text(" expected=");
    print_number(first);
    print_text(" or ");
    print_number(second);
    print_text("\n");
    return 1;
}

static long name_to_handle(long directory, const char *path,
                           struct file_handle_buffer *handle,
                           void *mount_id, unsigned long flags) {
    return raw_syscall6(SYS_name_to_handle_at, directory, (long)path,
                        (long)handle, (long)mount_id, (long)flags, 0);
}

static long open_by_handle(long mount_descriptor,
                           struct file_handle_buffer *handle,
                           unsigned long flags) {
    return raw_syscall6(SYS_open_by_handle_at, mount_descriptor,
                        (long)handle, (long)flags, 0, 0, 0);
}

static void close_descriptor(long descriptor) {
    if (descriptor >= 0)
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
}

static void unlink_path(const char *path) {
#if defined(__x86_64__)
    (void)raw_syscall6(SYS_unlink, (long)path, 0, 0, 0, 0, 0);
#else
    (void)raw_syscall6(SYS_unlinkat, AT_FDCWD, (long)path, 0, 0, 0, 0);
#endif
}

static int drop_decode_capability(struct cap_header *header,
                                  struct cap_data saved[2]) {
    struct cap_data dropped[2];
    uint32_t bit = 1u << CAP_DAC_READ_SEARCH;
    if (raw_syscall6(SYS_capget, (long)header, (long)saved,
                     0, 0, 0, 0) < 0)
        return -1;
    dropped[0] = saved[0];
    dropped[1] = saved[1];
    dropped[0].effective &= ~bit;
    return (int)raw_syscall6(SYS_capset, (long)header, (long)dropped,
                             0, 0, 0, 0);
}

static int restore_capabilities(struct cap_header *header,
                                struct cap_data saved[2]) {
    return (int)raw_syscall6(SYS_capset, (long)header, (long)saved,
                             0, 0, 0, 0);
}

static int run_probe(void) {
    static const char path[] = "/edgeos-file-handle-probe";
    static const char missing[] = "/edgeos-file-handle-missing";
    static const char payload[] = "edgeos-file-handle-data";
    struct file_handle_buffer handle;
    struct file_handle_buffer empty_handle;
    struct file_handle_buffer saved_handle;
    struct cap_header cap_header = {LINUX_CAPABILITY_VERSION_3, 0};
    struct cap_data saved_caps[2];
    uint64_t unique_mount_id = 0;
    int32_t mount_id = 0;
    char read_buffer[sizeof(payload)];
    long file_descriptor;
    long mount_descriptor;
    long opened;
    long status;
    int failures = 0;

    unlink_path(path);
    file_descriptor = raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
                                   O_CREAT | O_TRUNC | O_RDWR, 0600,
                                   0, 0);
    failures += expect_nonnegative("create source", file_descriptor);
    if (file_descriptor < 0) return failures;
    failures += expect_result(
        "write source",
        raw_syscall6(SYS_write, file_descriptor, (long)payload,
                     sizeof(payload), 0, 0, 0), sizeof(payload));

    mount_descriptor = raw_syscall6(
        SYS_openat, AT_FDCWD, (long)"/", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    failures += expect_nonnegative("open mount anchor", mount_descriptor);

    zero_bytes(&handle, sizeof(handle));
    status = name_to_handle(AT_FDCWD, path, &handle, &mount_id, 0);
    failures += expect_result("size query", status, -EOVERFLOW);
    if (!handle.handle_bytes || handle.handle_bytes > sizeof(handle.value)) {
        print_text("FAIL size query handle_bytes=");
        print_number(handle.handle_bytes);
        print_text("\n");
        ++failures;
        goto cleanup;
    }
    handle.handle_bytes = sizeof(handle.value);
    status = name_to_handle(AT_FDCWD, path, &handle, &mount_id, 0);
    failures += expect_result("encode absolute", status, 0);
    saved_handle = handle;

    zero_bytes(&empty_handle, sizeof(empty_handle));
    empty_handle.handle_bytes = sizeof(empty_handle.value);
    failures += expect_result(
        "absolute ignores bad dirfd",
        name_to_handle(-9, path, &empty_handle, &mount_id, 0), 0);
    zero_bytes(&empty_handle, sizeof(empty_handle));
    empty_handle.handle_bytes = sizeof(empty_handle.value);
    failures += expect_result(
        "empty path without flag",
        name_to_handle(file_descriptor, "", &empty_handle, &mount_id, 0),
        -ENOENT);
    failures += expect_result(
        "empty path encode",
        name_to_handle(file_descriptor, "", &empty_handle, &mount_id,
                       AT_EMPTY_PATH), 0);

    zero_bytes(&empty_handle, sizeof(empty_handle));
    empty_handle.handle_bytes = sizeof(empty_handle.value);
    failures += expect_result(
        "unique mount id",
        name_to_handle(AT_FDCWD, path, &empty_handle, &unique_mount_id,
                       AT_HANDLE_MNT_ID_UNIQUE), 0);
    failures += expect_result(
        "unknown name flag precedes pointers",
        name_to_handle(AT_FDCWD, 0, 0, 0, 0x80000000u), -EINVAL);
    failures += expect_result(
        "conflicting name flags precede pointers",
        name_to_handle(AT_FDCWD, 0, 0, 0,
                       AT_HANDLE_CONNECTABLE | AT_HANDLE_FID), -EINVAL);
    failures += expect_result(
        "null path", name_to_handle(AT_FDCWD, 0, &handle, &mount_id, 0),
        -EFAULT);
    failures += expect_result(
        "missing path precedes handle",
        name_to_handle(AT_FDCWD, missing, 0, &mount_id, 0), -ENOENT);
    failures += expect_result(
        "bad relative dirfd",
        name_to_handle(-9, "edgeos-file-handle-probe", &handle,
                       &mount_id, 0), -EBADF);
    failures += expect_result(
        "null handle after lookup",
        name_to_handle(AT_FDCWD, path, 0, &mount_id, 0), -EFAULT);
    failures += expect_result(
        "null mount id after encode",
        name_to_handle(AT_FDCWD, path, &handle, 0, 0), -EFAULT);

    opened = open_by_handle(mount_descriptor, &saved_handle,
                            O_RDONLY | O_CLOEXEC);
    failures += expect_nonnegative("decode handle", opened);
    if (opened >= 0) {
        failures += expect_result(
            "cloexec descriptor",
            raw_syscall6(SYS_fcntl, opened, F_GETFD, 0, 0, 0, 0),
            FD_CLOEXEC);
        zero_bytes(read_buffer, sizeof(read_buffer));
        status = raw_syscall6(SYS_read, opened, (long)read_buffer,
                              sizeof(payload), 0, 0, 0);
        failures += expect_result("read decoded file", status,
                                  sizeof(payload));
        if (status == (long)sizeof(payload) &&
            !bytes_equal(read_buffer, payload, sizeof(payload))) {
            print_text("FAIL decoded payload mismatch\n");
            ++failures;
        }
        close_descriptor(opened);
    }

    opened = open_by_handle(AT_FDCWD, &saved_handle, O_RDONLY);
    failures += expect_nonnegative("cwd mount anchor", opened);
    close_descriptor(opened);
    opened = open_by_handle(file_descriptor, &saved_handle, O_RDONLY);
    failures += expect_nonnegative("file mount anchor", opened);
    close_descriptor(opened);

    failures += expect_result(
        "null open handle",
        open_by_handle(mount_descriptor, 0, O_RDONLY), -EFAULT);
    empty_handle = saved_handle;
    empty_handle.handle_bytes = 0;
    failures += expect_result("zero open handle size",
                              open_by_handle(mount_descriptor, &empty_handle,
                                             O_RDONLY),
                              -EINVAL);
    empty_handle = saved_handle;
    empty_handle.handle_type = -1;
    failures += expect_either(
        "negative open handle type",
        open_by_handle(mount_descriptor, &empty_handle, O_RDONLY),
        -EINVAL, -ESTALE);
    failures += expect_result("bad mount descriptor",
                              open_by_handle(-9, &saved_handle, O_RDONLY),
                              -EBADF);
    opened = open_by_handle(mount_descriptor, &saved_handle, 3);
    failures += expect_nonnegative("access mode three", opened);
    close_descriptor(opened);
    opened = open_by_handle(mount_descriptor, &saved_handle,
                            O_CREAT | O_RDONLY);
    failures += expect_nonnegative("create on existing handle", opened);
    close_descriptor(opened);
    failures += expect_result(
        "exclusive create on existing handle",
        open_by_handle(mount_descriptor, &saved_handle,
                       O_CREAT | O_EXCL | O_RDONLY), -EEXIST);
    opened = open_by_handle(mount_descriptor, &saved_handle,
                            O_TRUNC | O_RDONLY);
    failures += expect_nonnegative("truncate through handle", opened);
    close_descriptor(opened);
    failures += expect_result("tmpfile flag",
                              open_by_handle(mount_descriptor, &saved_handle,
                                             O_TMPFILE | O_RDWR), -ENOTDIR);

    if (drop_decode_capability(&cap_header, saved_caps) < 0) {
        print_text("FAIL drop CAP_DAC_READ_SEARCH\n");
        ++failures;
    } else {
        failures += expect_result(
            "decode capability",
            open_by_handle(mount_descriptor, &saved_handle, O_RDONLY),
            -EPERM);
        if (restore_capabilities(&cap_header, saved_caps) < 0) {
            print_text("FAIL restore capabilities\n");
            ++failures;
        }
    }

    close_descriptor(file_descriptor);
    file_descriptor = -1;
    unlink_path(path);
    failures += expect_result(
        "stale handle",
        open_by_handle(mount_descriptor, &saved_handle, O_RDONLY), -ESTALE);

cleanup:
    close_descriptor(file_descriptor);
    close_descriptor(mount_descriptor);
    unlink_path(path);
    return failures;
}

#if defined(__x86_64__)
__attribute__((force_align_arg_pointer))
#endif
void _start(void) {
    int failures = run_probe();
    if (failures) {
        print_text("FILE_HANDLE_ABI_PROBE_FAIL count=");
        print_number(failures);
        print_text("\n");
    } else {
        print_text("FILE_HANDLE_ABI_PROBE_PASS\n");
    }
    (void)raw_syscall6(
#if defined(__x86_64__)
        60,
#else
        93,
#endif
        failures ? 1 : 0, 0, 0, 0, 0, 0);
    for (;;) {}
}
