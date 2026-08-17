/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux statfs and fstatfs ABI probe for native and guest parity.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#ifndef SYS_statfs
#define SYS_statfs 43
#define SYS_fstatfs 44
#define SYS_eventfd2 19
#define SYS_memfd_create 279
#endif
#else
#ifndef SYS_statfs
#define SYS_statfs 137
#define SYS_fstatfs 138
#define SYS_eventfd2 290
#define SYS_memfd_create 319
#endif
#endif

#define PROC_SUPER_MAGIC 0x00009fa0u
#define TMPFS_MAGIC 0x01021994u
#define PIPEFS_MAGIC 0x50495045u
#define SOCKFS_MAGIC 0x534f434bu
#define ANON_INODE_FS_MAGIC 0x09041934u
#define NSFS_MAGIC 0x6e736673u
#define ST_VALID 0x0020u

struct linux_statfs64 {
    int64_t type;
    int64_t block_size;
    uint64_t blocks;
    uint64_t blocks_free;
    uint64_t blocks_available;
    uint64_t files;
    uint64_t files_free;
    int32_t fsid[2];
    int64_t name_length;
    int64_t fragment_size;
    int64_t flags;
    int64_t spare[4];
};

static int g_failures;

static long call_statfs(const char *path, struct linux_statfs64 *result) {
    return syscall(SYS_statfs, path, result);
}

static long call_fstatfs(int descriptor, struct linux_statfs64 *result) {
    return syscall(SYS_fstatfs, descriptor, result);
}

static void expect_error(const char *name, long result, int saved_errno,
                         int expected_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != -1 || saved_errno != expected_errno) ++g_failures;
}

static int fetch_fstatfs(const char *name, int descriptor,
                         uint64_t expected_type,
                         struct linux_statfs64 *result) {
    long status;
    int saved_errno;
    errno = 0;
    status = call_fstatfs(descriptor, result);
    saved_errno = errno;
    dprintf(STDOUT_FILENO,
            "%s_rc:%ld errno:%d type:0x%llx bsize:%lld blocks:%llu "
            "bfree:%llu namelen:%lld frsize:%lld flags:0x%llx\n",
            name, status, saved_errno,
            (unsigned long long)result->type,
            (long long)result->block_size,
            (unsigned long long)result->blocks,
            (unsigned long long)result->blocks_free,
            (long long)result->name_length,
            (long long)result->fragment_size,
            (unsigned long long)result->flags);
    if (status != 0 || saved_errno != 0) {
        ++g_failures;
        return -1;
    }
    if (expected_type && (uint64_t)result->type != expected_type)
        ++g_failures;
    if (result->block_size <= 0 || result->fragment_size <= 0 ||
        result->name_length <= 0 || result->blocks_free > result->blocks ||
        result->blocks_available > result->blocks ||
        !(result->flags & ST_VALID))
        ++g_failures;
    return 0;
}

static int fetch_statfs(const char *name, const char *path,
                        uint64_t expected_type,
                        struct linux_statfs64 *result) {
    long status;
    int saved_errno;
    errno = 0;
    status = call_statfs(path, result);
    saved_errno = errno;
    dprintf(STDOUT_FILENO,
            "%s_rc:%ld errno:%d type:0x%llx bsize:%lld blocks:%llu "
            "bfree:%llu namelen:%lld frsize:%lld flags:0x%llx\n",
            name, status, saved_errno,
            (unsigned long long)result->type,
            (long long)result->block_size,
            (unsigned long long)result->blocks,
            (unsigned long long)result->blocks_free,
            (long long)result->name_length,
            (long long)result->fragment_size,
            (unsigned long long)result->flags);
    if (status != 0 || saved_errno != 0) {
        ++g_failures;
        return -1;
    }
    if (expected_type && (uint64_t)result->type != expected_type)
        ++g_failures;
    if (result->block_size <= 0 || result->fragment_size <= 0 ||
        result->name_length <= 0 || result->blocks_free > result->blocks ||
        result->blocks_available > result->blocks ||
        !(result->flags & ST_VALID))
        ++g_failures;
    return 0;
}

static void test_errors(int valid_descriptor) {
    struct linux_statfs64 result;
    long status;
    int saved_errno;

    errno = 0;
    status = call_statfs(0, &result);
    saved_errno = errno;
    expect_error("statfs_null_path", status, saved_errno, EFAULT);
    errno = 0;
    status = call_statfs("", &result);
    saved_errno = errno;
    expect_error("statfs_empty_path", status, saved_errno, ENOENT);
    errno = 0;
    status = call_statfs("/definitely-not-present-edgeos", &result);
    saved_errno = errno;
    expect_error("statfs_missing_path", status, saved_errno, ENOENT);
    errno = 0;
    status = call_statfs("/", 0);
    saved_errno = errno;
    expect_error("statfs_null_result", status, saved_errno, EFAULT);
    errno = 0;
    status = call_fstatfs(-1, &result);
    saved_errno = errno;
    expect_error("fstatfs_bad_fd", status, saved_errno, EBADF);
    errno = 0;
    status = call_fstatfs(valid_descriptor, 0);
    saved_errno = errno;
    expect_error("fstatfs_null_result", status, saved_errno, EFAULT);
}

int main(void) {
    struct linux_statfs64 root_path = {0};
    struct linux_statfs64 root_fd = {0};
    struct linux_statfs64 result = {0};
    int root_descriptor;
    int pipe_descriptors[2];
    int socket_descriptor;
    int memory_descriptor;
    int event_descriptor;
    int namespace_descriptor;

    dprintf(STDOUT_FILENO, "statfs_layout_size:%zu\n",
            sizeof(struct linux_statfs64));
    if (sizeof(struct linux_statfs64) != 120) ++g_failures;
    root_descriptor = open("/", O_RDONLY | O_DIRECTORY);
    socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    memory_descriptor = (int)syscall(SYS_memfd_create, "statfs-probe", 0);
    event_descriptor = (int)syscall(SYS_eventfd2, 0, 0);
    namespace_descriptor = open("/proc/self/ns/mnt", O_RDONLY);
    if (root_descriptor < 0 || pipe(pipe_descriptors) < 0 ||
        socket_descriptor < 0 || memory_descriptor < 0 ||
        event_descriptor < 0) {
        dprintf(STDOUT_FILENO, "statfs_setup_errno:%d\n", errno);
        return 1;
    }

    fetch_statfs("statfs_root", "/", 0, &root_path);
    fetch_fstatfs("fstatfs_root", root_descriptor, 0, &root_fd);
    if (root_path.type != root_fd.type ||
        root_path.block_size != root_fd.block_size ||
        root_path.fragment_size != root_fd.fragment_size ||
        root_path.name_length != root_fd.name_length)
        ++g_failures;
    fetch_statfs("statfs_proc", "/proc", PROC_SUPER_MAGIC, &result);
    fetch_fstatfs("fstatfs_pipe", pipe_descriptors[0], PIPEFS_MAGIC,
                  &result);
    fetch_fstatfs("fstatfs_socket", socket_descriptor, SOCKFS_MAGIC,
                  &result);
    fetch_fstatfs("fstatfs_memfd", memory_descriptor, TMPFS_MAGIC,
                  &result);
    fetch_fstatfs("fstatfs_eventfd", event_descriptor,
                  ANON_INODE_FS_MAGIC, &result);
    if (namespace_descriptor >= 0)
        fetch_fstatfs("fstatfs_namespace", namespace_descriptor,
                      NSFS_MAGIC, &result);
    else
        dprintf(STDOUT_FILENO, "fstatfs_namespace_skip_errno:%d\n", errno);

    test_errors(root_descriptor);
    if (namespace_descriptor >= 0) close(namespace_descriptor);
    close(event_descriptor);
    close(memory_descriptor);
    close(socket_descriptor);
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
    close(root_descriptor);
    dprintf(STDOUT_FILENO, "STATFS_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
