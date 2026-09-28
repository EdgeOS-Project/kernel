/* SPDX-License-Identifier: MPL-2.0 */
/* Freestanding Linux i386 large-file and legacy alias UAPI probe. */

#include <stdint.h>

#define SYS_exit 1
#define SYS_fork 2
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_waitpid 7
#define SYS_unlink 10
#define SYS_lseek 19
#define SYS_umount 22
#define SYS_nice 34
#define SYS__newselect 142
#define SYS_pread64 180
#define SYS_pwrite64 181
#define SYS_sendfile 187
#define SYS_truncate64 193
#define SYS_ftruncate64 194
#define SYS_readahead 225
#define SYS_sendfile64 239
#define SYS_fadvise64 250
#define SYS_fadvise64_64 272
#define SYS_sync_file_range 314
#define SYS_fallocate 324
#define SYS_preadv 333
#define SYS_pwritev 334
#define SYS_recvmmsg 337
#define SYS_preadv2 378
#define SYS_pwritev2 379
#define SYS_recvmmsg_time64 417
#define SYS_semtimedop_time64 420

#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define SEEK_END 2
#define ENOSYS 38

struct compat_iovec {
    uint32_t base;
    uint32_t length;
};

struct timeval32 {
    int32_t seconds;
    int32_t microseconds;
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
    print_text("IA32_LARGEFILE_UAPI_PROBE_FAIL ");
    print_text(name);
    print_text("\n");
    call6(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void expect_not_enosys(const char *name, long result) {
    if (result == -ENOSYS) fail(name);
}

__attribute__((noreturn)) void _start(void) {
    static const char source_path[] = "/ia32-large-source";
    static const char target_path[] = "/ia32-large-target";
    char scalar[8] = {0};
    char vector_buffer[8] = {0};
    char vector2_buffer[8] = {0};
    int32_t wait_status = 0;
    int32_t compat_offset = 0;
    int64_t wide_offset = 0;
    struct compat_iovec write_vector;
    struct compat_iovec read_vector;
    struct timeval32 timeout = {0, 0};
    long source;
    long target;
    long child;
    long result;

    source = call6(SYS_open, source_path, O_CREAT | O_TRUNC | O_RDWR,
                   0600, 0, 0, 0);
    target = call6(SYS_open, target_path, O_CREAT | O_TRUNC | O_RDWR,
                   0600, 0, 0, 0);
    if (source < 0 || target < 0) fail("open");

    if (call6(SYS_pwrite64, source, "edge", 4, 4096, 0, 0) != 4)
        fail("pwrite64");
    if (call6(SYS_pread64, source, scalar, 4, 4096, 0, 0) != 4 ||
        scalar[0] != 'e' || scalar[3] != 'e')
        fail("pread64");
    if (call6(SYS_truncate64, source_path, 8192, 0, 0, 0, 0) != 0 ||
        call6(SYS_lseek, source, 0, SEEK_END, 0, 0, 0) != 8192)
        fail("truncate64");
    if (call6(SYS_ftruncate64, source, 4096, 0, 0, 0, 0) != 0 ||
        call6(SYS_lseek, source, 0, SEEK_END, 0, 0, 0) != 4096)
        fail("ftruncate64");

    if (call6(SYS_readahead, source, 0, 0, 4096, 0, 0) != 0)
        fail("readahead");
    if (call6(SYS_fadvise64, source, 0, 0, 4096, 0, 0) != 0)
        fail("fadvise64");
    if (call6(SYS_fadvise64_64, source, 0, 0, 4096, 0, 0) != 0)
        fail("fadvise64_64");
    if (call6(SYS_fallocate, source, 0, 8192, 0, 4096, 0) != 0 ||
        call6(SYS_lseek, source, 0, SEEK_END, 0, 0, 0) != 12288)
        fail("fallocate");

    write_vector.base = (uint32_t)(uintptr_t)"vector";
    write_vector.length = 6;
    if (call6(SYS_pwritev, source, &write_vector, 1,
              16384, 0, 0) != 6)
        fail("pwritev");
    read_vector.base = (uint32_t)(uintptr_t)vector_buffer;
    read_vector.length = sizeof(vector_buffer);
    if (call6(SYS_preadv, source, &read_vector, 1,
              16384, 0, 0) != 6 || vector_buffer[0] != 'v' ||
        vector_buffer[5] != 'r')
        fail("preadv");
    write_vector.base = (uint32_t)(uintptr_t)"v2data";
    write_vector.length = 6;
    if (call6(SYS_pwritev2, source, &write_vector, 1,
              20480, 0, 0) != 6)
        fail("pwritev2");
    read_vector.base = (uint32_t)(uintptr_t)vector2_buffer;
    read_vector.length = sizeof(vector2_buffer);
    if (call6(SYS_preadv2, source, &read_vector, 1,
              20480, 0, 0) != 6 || vector2_buffer[0] != 'v' ||
        vector2_buffer[5] != 'a')
        fail("preadv2");
    if (call6(SYS_sync_file_range, source, 0, 0, 4096, 0, 0) != 0)
        fail("sync_file_range");

    compat_offset = 4096;
    if (call6(SYS_sendfile, target, source, &compat_offset, 4, 0, 0) != 4 ||
        compat_offset != 4100)
        fail("sendfile");
    wide_offset = 4096;
    if (call6(SYS_sendfile64, target, source, &wide_offset, 4, 0, 0) != 4 ||
        wide_offset != 4100)
        fail("sendfile64");

    child = call6(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (child == 0)
        call6(SYS_exit, 7, 0, 0, 0, 0, 0);
    if (child < 0 ||
        call6(SYS_waitpid, child, &wait_status, 0, 0, 0, 0) != child ||
        wait_status != (7 << 8))
        fail("waitpid");
    expect_not_enosys("nice", call6(SYS_nice, 1, 0, 0, 0, 0, 0));
    if (call6(SYS__newselect, 0, 0, 0, 0, &timeout, 0) != 0)
        fail("newselect");
    expect_not_enosys("umount", call6(SYS_umount, "/", 0, 0, 0, 0, 0));
    expect_not_enosys("recvmmsg-time32",
        call6(SYS_recvmmsg, 0, 0, 0, 0, 0, 0));
    expect_not_enosys("recvmmsg-time64",
        call6(SYS_recvmmsg_time64, 0, 0, 0, 0, 0, 0));
    expect_not_enosys("semtimedop-time64",
        call6(SYS_semtimedop_time64, -1, 0, 0, 0, 0, 0));

    result = call6(SYS_close, source, 0, 0, 0, 0, 0);
    result |= call6(SYS_close, target, 0, 0, 0, 0, 0);
    result |= call6(SYS_unlink, source_path, 0, 0, 0, 0, 0);
    result |= call6(SYS_unlink, target_path, 0, 0, 0, 0, 0);
    if (result != 0) fail("cleanup");

    print_text("IA32_LARGEFILE_UAPI_PROBE_PASS\n");
    call6(SYS_exit, 0, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
