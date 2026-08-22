/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux file-metadata ABI regression test. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef AT_STATX_SYNC_TYPE
#define AT_STATX_SYNC_TYPE 0x6000
#define AT_STATX_FORCE_SYNC 0x2000
#define AT_STATX_DONT_SYNC 0x4000
#endif

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif

#ifndef STATX_ATTR_MOUNT_ROOT
#define STATX_ATTR_MOUNT_ROOT 0x00002000ULL
#endif

#ifndef STATX__RESERVED
#define STATX__RESERVED 0x80000000U
#endif

static int failures;

static void check_true(const char *name, int condition) {
    dprintf(STDOUT_FILENO, "%s:%s\n", name, condition ? "ok" : "fail");
    if (!condition) ++failures;
}

static int call_statx(int directory, const char *path, int flags,
                      unsigned int mask, struct statx *result) {
    return (int)syscall(SYS_statx, directory, path, flags, mask, result);
}

static int call_fstat(int descriptor, struct stat *result) {
    return (int)syscall(SYS_fstat, descriptor, result);
}

static int call_fstatat(int directory, const char *path,
                        struct stat *result, int flags) {
    return (int)syscall(SYS_newfstatat, directory, path, result, flags);
}

static void test_regular_and_symlink(const char *directory,
                                     const char *file,
                                     const char *link) {
    struct stat native;
    struct stat by_path;
    struct stat by_at;
    struct stat nofollow_at;
    struct stat empty_at;
    struct statx followed;
    struct statx nofollow;
    struct statx empty;
    int descriptor = open(file, O_RDONLY | O_CLOEXEC);

    memset(&native, 0, sizeof(native));
    memset(&by_path, 0, sizeof(by_path));
    memset(&by_at, 0, sizeof(by_at));
    memset(&nofollow_at, 0, sizeof(nofollow_at));
    memset(&empty_at, 0, sizeof(empty_at));
    memset(&followed, 0, sizeof(followed));
    memset(&nofollow, 0, sizeof(nofollow));
    memset(&empty, 0, sizeof(empty));
    check_true("stat_regular_setup",
               descriptor >= 0 && call_fstat(descriptor, &native) == 0);
    check_true("stat_regular",
               stat(file, &by_path) == 0 && S_ISREG(by_path.st_mode) &&
               by_path.st_dev == native.st_dev &&
               by_path.st_ino == native.st_ino && by_path.st_size == 6 &&
               by_path.st_nlink == native.st_nlink);
    check_true("fstatat_regular",
               call_fstatat(AT_FDCWD, file, &by_at, AT_NO_AUTOMOUNT) == 0 &&
               by_at.st_dev == native.st_dev &&
               by_at.st_ino == native.st_ino && by_at.st_mode == native.st_mode &&
               by_at.st_size == native.st_size);
    check_true("fstatat_empty_fd",
               call_fstatat(descriptor, "", &empty_at, AT_EMPTY_PATH) == 0 &&
               empty_at.st_dev == native.st_dev &&
               empty_at.st_ino == native.st_ino &&
               empty_at.st_mode == native.st_mode &&
               empty_at.st_size == native.st_size);
    check_true("fstatat_symlink_nofollow",
               call_fstatat(AT_FDCWD, link, &nofollow_at,
                            AT_SYMLINK_NOFOLLOW) == 0 &&
               S_ISLNK(nofollow_at.st_mode) &&
               nofollow_at.st_size == (off_t)strlen(file));
#ifdef SYS_stat
    memset(&by_path, 0, sizeof(by_path));
    check_true("legacy_stat",
               syscall(SYS_stat, file, &by_path) == 0 &&
               by_path.st_ino == native.st_ino && S_ISREG(by_path.st_mode));
#endif
#ifdef SYS_lstat
    memset(&by_path, 0, sizeof(by_path));
    check_true("legacy_lstat",
               syscall(SYS_lstat, link, &by_path) == 0 &&
               S_ISLNK(by_path.st_mode) &&
               by_path.st_size == (off_t)strlen(file));
#endif
    check_true("statx_regular",
               call_statx(AT_FDCWD, file, 0, STATX_BASIC_STATS | STATX_MNT_ID,
                          &followed) == 0 &&
               S_ISREG(followed.stx_mode) && followed.stx_size == 6 &&
               followed.stx_ino == native.st_ino &&
               followed.stx_nlink == native.st_nlink &&
               (followed.stx_mask & STATX_BASIC_STATS) == STATX_BASIC_STATS);
    check_true("statx_empty_fd",
               call_statx(descriptor, "", AT_EMPTY_PATH,
                          STATX_BASIC_STATS | STATX_MNT_ID, &empty) == 0 &&
               empty.stx_ino == followed.stx_ino &&
               empty.stx_mode == followed.stx_mode &&
               empty.stx_size == followed.stx_size);
    check_true("statx_symlink_follow",
               call_statx(AT_FDCWD, link, 0, STATX_BASIC_STATS,
                          &empty) == 0 &&
               empty.stx_ino == followed.stx_ino && S_ISREG(empty.stx_mode));
    check_true("statx_symlink_nofollow",
               call_statx(AT_FDCWD, link, AT_SYMLINK_NOFOLLOW,
                          STATX_BASIC_STATS, &nofollow) == 0 &&
               S_ISLNK(nofollow.stx_mode) &&
               nofollow.stx_size == strlen(file));
    memset(&empty, 0, sizeof(empty));
    check_true("statx_empty_cwd",
               chdir(directory) == 0 &&
               call_statx(AT_FDCWD, "", AT_EMPTY_PATH,
                          STATX_BASIC_STATS, &empty) == 0 &&
               S_ISDIR(empty.stx_mode));
    memset(&empty_at, 0, sizeof(empty_at));
    check_true("fstatat_empty_cwd",
               call_fstatat(AT_FDCWD, "", &empty_at, AT_EMPTY_PATH) == 0 &&
               S_ISDIR(empty_at.st_mode));
    close(descriptor);
}

static void test_validation(void) {
    struct statx result;
    struct stat native;
    int descriptor;
    int rc;
    int error;

    memset(&result, 0, sizeof(result));
    errno = 0;
    rc = call_statx(AT_FDCWD, ".", 1, STATX_BASIC_STATS, &result);
    error = errno;
    check_true("statx_unknown_flags", rc == -1 && error == EINVAL);
    errno = 0;
    rc = call_statx(AT_FDCWD, ".", AT_STATX_SYNC_TYPE,
                    STATX_BASIC_STATS, &result);
    error = errno;
    check_true("statx_conflicting_sync", rc == -1 && error == EINVAL);
    errno = 0;
    rc = call_statx(AT_FDCWD, ".", 0, STATX__RESERVED, &result);
    error = errno;
    check_true("statx_reserved_mask", rc == -1 && error == EINVAL);
    errno = 0;
    rc = call_statx(AT_FDCWD, "", 0, STATX_BASIC_STATS, &result);
    error = errno;
    check_true("statx_empty_without_flag", rc == -1 && error == ENOENT);
    errno = 0;
    rc = call_statx(AT_FDCWD, ".", 0, STATX_BASIC_STATS, NULL);
    error = errno;
    check_true("statx_null_result", rc == -1 && error == EFAULT);
    errno = 0;
    rc = call_statx(AT_FDCWD, "/missing-edgeos-stat", 0,
                    STATX_BASIC_STATS, NULL);
    error = errno;
    check_true("statx_missing_before_null",
               rc == -1 && error == ENOENT);

    memset(&native, 0, sizeof(native));
    errno = 0;
    rc = call_fstatat(AT_FDCWD, ".", &native, 1);
    error = errno;
    check_true("fstatat_unknown_flags", rc == -1 && error == EINVAL);
    errno = 0;
    rc = call_fstatat(AT_FDCWD, "", &native, 0);
    error = errno;
    check_true("fstatat_empty_without_flag", rc == -1 && error == ENOENT);
    errno = 0;
    rc = call_fstatat(AT_FDCWD, ".", NULL, 0);
    error = errno;
    check_true("fstatat_null_result", rc == -1 && error == EFAULT);
    errno = 0;
    rc = call_fstatat(AT_FDCWD, "/missing-edgeos-stat", NULL, 0);
    error = errno;
    check_true("fstatat_missing_before_null",
               rc == -1 && error == ENOENT);
    errno = 0;
    rc = call_fstatat(-1, "", &native, AT_EMPTY_PATH);
    error = errno;
    check_true("fstatat_bad_fd", rc == -1 && error == EBADF);
    descriptor = open(".", O_RDONLY | O_CLOEXEC);
    check_true("fstat_validation_setup", descriptor >= 0);
    errno = 0;
    rc = call_fstat(-1, NULL);
    error = errno;
    check_true("fstat_bad_fd_before_null", rc == -1 && error == EBADF);
    if (descriptor >= 0) close(descriptor);

    descriptor = open("/tmp/edgeos-stat-not-directory",
                      O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    check_true("fstatat_not_directory_setup", descriptor >= 0);
    if (descriptor >= 0) {
        errno = 0;
        rc = call_fstatat(descriptor, "child", &native, 0);
        error = errno;
        check_true("fstatat_not_directory",
                   rc == -1 && error == ENOTDIR);
        close(descriptor);
        unlink("/tmp/edgeos-stat-not-directory");
    }
}

static void test_mount_root_attribute(const char *regular_file) {
    struct statx root;
    struct statx proc;
    struct statx regular;

    memset(&root, 0, sizeof(root));
    memset(&proc, 0, sizeof(proc));
    memset(&regular, 0, sizeof(regular));
    check_true("statx_root_mount_attribute",
               call_statx(AT_FDCWD, "/", AT_STATX_DONT_SYNC,
                          STATX_BASIC_STATS, &root) == 0 &&
               (root.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) != 0 &&
               (root.stx_attributes & STATX_ATTR_MOUNT_ROOT) != 0);
    check_true("statx_proc_mount_attribute",
               call_statx(AT_FDCWD, "/proc", AT_STATX_DONT_SYNC,
                          STATX_BASIC_STATS, &proc) == 0 &&
               (proc.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) != 0 &&
               (proc.stx_attributes & STATX_ATTR_MOUNT_ROOT) != 0);
    check_true("statx_regular_not_mount_root",
               call_statx(AT_FDCWD, regular_file, AT_STATX_DONT_SYNC,
                          STATX_BASIC_STATS, &regular) == 0 &&
               (regular.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) != 0 &&
               (regular.stx_attributes & STATX_ATTR_MOUNT_ROOT) == 0);
}

static void test_terminal_device(const char *path) {
    char resolved[256];
    struct stat descriptor_stat;
    struct stat path_stat;
    int descriptor;
    int tty_status;

    if (!path || !path[0]) return;
    descriptor = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    check_true("terminal_metadata_setup", descriptor >= 0);
    if (descriptor < 0) return;

    memset(&descriptor_stat, 0, sizeof(descriptor_stat));
    memset(&path_stat, 0, sizeof(path_stat));
    check_true(
        "terminal_metadata_identity",
        fstat(descriptor, &descriptor_stat) == 0 &&
        stat(path, &path_stat) == 0 &&
        S_ISCHR(descriptor_stat.st_mode) &&
        descriptor_stat.st_dev == path_stat.st_dev &&
        descriptor_stat.st_ino == path_stat.st_ino &&
        descriptor_stat.st_mode == path_stat.st_mode &&
        descriptor_stat.st_rdev == path_stat.st_rdev);

    memset(resolved, 0, sizeof(resolved));
    tty_status = ttyname_r(descriptor, resolved, sizeof(resolved));
    check_true("terminal_name", tty_status == 0 && resolved[0] == '/');
    close(descriptor);
}

static void check_procfd_metadata(int directory, const char *scope,
                                  const char *kind, int descriptor) {
    char entry[32];
    char name[128];
    struct stat native;
    struct stat followed;
    struct stat nofollow;
    struct statx extended;
    int status;

    snprintf(entry, sizeof(entry), "%d", descriptor);
    memset(&native, 0, sizeof(native));
    memset(&followed, 0, sizeof(followed));
    memset(&nofollow, 0, sizeof(nofollow));
    memset(&extended, 0, sizeof(extended));

    snprintf(name, sizeof(name), "fstat_%s_%s_setup", scope, kind);
    status = call_fstat(descriptor, &native);
    check_true(name, status == 0);

    snprintf(name, sizeof(name), "fstatat_%s_%s_follow", scope, kind);
    status = call_fstatat(directory, entry, &followed, 0);
    check_true(name,
               status == 0 &&
               followed.st_dev == native.st_dev &&
               followed.st_ino == native.st_ino &&
               (followed.st_mode & S_IFMT) == (native.st_mode & S_IFMT));

    snprintf(name, sizeof(name), "statx_%s_%s_follow", scope, kind);
    status = call_statx(directory, entry, 0, STATX_BASIC_STATS, &extended);
    check_true(name,
               status == 0 &&
               extended.stx_ino == native.st_ino &&
               (extended.stx_mode & S_IFMT) == (native.st_mode & S_IFMT));

    snprintf(name, sizeof(name), "fstatat_%s_%s_nofollow", scope, kind);
    status = call_fstatat(
        directory, entry, &nofollow, AT_SYMLINK_NOFOLLOW);
    check_true(name, status == 0 && S_ISLNK(nofollow.st_mode));

    memset(&extended, 0, sizeof(extended));
    snprintf(name, sizeof(name), "statx_%s_%s_nofollow", scope, kind);
    status = call_statx(directory, entry, AT_SYMLINK_NOFOLLOW,
                        STATX_BASIC_STATS, &extended);
    check_true(name, status == 0 && S_ISLNK(extended.stx_mode));
}

static void check_procfd_missing(int directory, const char *scope,
                                 int descriptor) {
    char entry[32];
    char name[128];
    struct stat native;
    struct statx extended;
    int error;
    int status;

    snprintf(entry, sizeof(entry), "%d", descriptor);

    memset(&native, 0, sizeof(native));
    errno = 0;
    status = call_fstatat(directory, entry, &native, 0);
    error = errno;
    snprintf(name, sizeof(name), "fstatat_%s_missing_follow", scope);
    check_true(name, status == -1 && error == ENOENT);

    memset(&native, 0, sizeof(native));
    errno = 0;
    status = call_fstatat(
        directory, entry, &native, AT_SYMLINK_NOFOLLOW);
    error = errno;
    snprintf(name, sizeof(name), "fstatat_%s_missing_nofollow", scope);
    check_true(name, status == -1 && error == ENOENT);

    memset(&extended, 0, sizeof(extended));
    errno = 0;
    status = call_statx(
        directory, entry, 0, STATX_BASIC_STATS, &extended);
    error = errno;
    snprintf(name, sizeof(name), "statx_%s_missing_follow", scope);
    check_true(name, status == -1 && error == ENOENT);

    memset(&extended, 0, sizeof(extended));
    errno = 0;
    status = call_statx(directory, entry, AT_SYMLINK_NOFOLLOW,
                        STATX_BASIC_STATS, &extended);
    error = errno;
    snprintf(name, sizeof(name), "statx_%s_missing_nofollow", scope);
    check_true(name, status == -1 && error == ENOENT);
}

static void test_anonymous_descriptors(void) {
    int pipe_descriptors[2] = {-1, -1};
    int socket_descriptors[2] = {-1, -1};
    int event_descriptor = eventfd(0, EFD_CLOEXEC);
    int memory_descriptor = memfd_create("edgeos-stat", MFD_CLOEXEC);
    int proc_root = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int proc_self_fd = -1;
    int proc_numeric_fd = -1;
    int unused_descriptor = -1;
    char proc_numeric_path[64];
    struct statx result;
    int anonymous_ready;

    anonymous_ready =
        pipe2(pipe_descriptors, O_CLOEXEC) == 0 &&
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
                   socket_descriptors) == 0 &&
        event_descriptor >= 0 && memory_descriptor >= 0;
    check_true("statx_anonymous_setup", anonymous_ready);
    if (proc_root >= 0)
        proc_self_fd = openat(proc_root, "self/fd",
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    snprintf(proc_numeric_path, sizeof(proc_numeric_path), "/proc/%ld/fd",
             (long)getpid());
    proc_numeric_fd = open(proc_numeric_path,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check_true("procfd_metadata_setup",
               proc_root >= 0 && proc_self_fd >= 0 && proc_numeric_fd >= 0);
    if (!anonymous_ready) goto cleanup;

    memset(&result, 0, sizeof(result));
    check_true("statx_pipe",
               call_statx(pipe_descriptors[0], "", AT_EMPTY_PATH,
                          STATX_BASIC_STATS, &result) == 0 &&
               S_ISFIFO(result.stx_mode));
    {
        struct stat native;
        struct stat duplicate;
        memset(&native, 0, sizeof(native));
        check_true("fstat_pipe",
                   call_fstat(pipe_descriptors[0], &native) == 0 &&
                   S_ISFIFO(native.st_mode));
        memset(&native, 0, sizeof(native));
        check_true("fstat_eventfd",
                   call_fstat(event_descriptor, &native) == 0 &&
                   (native.st_mode & S_IFMT) == 0 &&
                   (native.st_mode & 0777) == 0600);
        memset(&native, 0, sizeof(native));
        check_true("fstat_memfd",
                   call_fstat(memory_descriptor, &native) == 0 &&
                   S_ISREG(native.st_mode));
        memset(&native, 0, sizeof(native));
        memset(&duplicate, 0, sizeof(duplicate));
        {
            int copied = dup(socket_descriptors[0]);
            check_true("fstat_socket",
                       copied >= 0 &&
                       call_fstat(socket_descriptors[0], &native) == 0 &&
                       call_fstat(copied, &duplicate) == 0 &&
                       S_ISSOCK(native.st_mode) &&
                       native.st_ino == duplicate.st_ino);
            if (copied >= 0) close(copied);
        }
    }
    memset(&result, 0, sizeof(result));
    check_true("statx_eventfd",
               call_statx(event_descriptor, "", AT_EMPTY_PATH,
                          STATX_BASIC_STATS, &result) == 0 &&
               (result.stx_mode & S_IFMT) == 0 &&
               (result.stx_mode & 0777) == 0600);
    memset(&result, 0, sizeof(result));
    check_true("statx_memfd",
               call_statx(memory_descriptor, "", AT_EMPTY_PATH,
                          STATX_BASIC_STATS, &result) == 0 &&
               S_ISREG(result.stx_mode));
    memset(&result, 0, sizeof(result));
    check_true("statx_socket",
               call_statx(socket_descriptors[0], "", AT_EMPTY_PATH,
                          STATX_BASIC_STATS, &result) == 0 &&
               S_ISSOCK(result.stx_mode));

    if (proc_self_fd >= 0) {
        check_procfd_metadata(proc_self_fd, "proc_self", "pipe",
                              pipe_descriptors[0]);
        check_procfd_metadata(proc_self_fd, "proc_self", "socket",
                              socket_descriptors[0]);
        check_procfd_metadata(proc_self_fd, "proc_self", "eventfd",
                              event_descriptor);
        check_procfd_metadata(proc_self_fd, "proc_self", "memfd",
                              memory_descriptor);
    }
    if (proc_numeric_fd >= 0) {
        check_procfd_metadata(proc_numeric_fd, "proc_numeric", "pipe",
                              pipe_descriptors[0]);
        check_procfd_metadata(proc_numeric_fd, "proc_numeric", "socket",
                              socket_descriptors[0]);
        check_procfd_metadata(proc_numeric_fd, "proc_numeric", "eventfd",
                              event_descriptor);
        check_procfd_metadata(proc_numeric_fd, "proc_numeric", "memfd",
                              memory_descriptor);
    }
    unused_descriptor = dup(memory_descriptor);
    check_true("procfd_missing_setup", unused_descriptor >= 0);
    if (unused_descriptor >= 0) {
        close(unused_descriptor);
        if (proc_self_fd >= 0)
            check_procfd_missing(
                proc_self_fd, "proc_self", unused_descriptor);
        if (proc_numeric_fd >= 0)
            check_procfd_missing(
                proc_numeric_fd, "proc_numeric", unused_descriptor);
    }

cleanup:
    if (proc_numeric_fd >= 0) close(proc_numeric_fd);
    if (proc_self_fd >= 0) close(proc_self_fd);
    if (proc_root >= 0) close(proc_root);
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
    close(socket_descriptors[0]);
    close(socket_descriptors[1]);
    close(event_descriptor);
    close(memory_descriptor);
}

int main(int argc, char **argv) {
    char directory[] = "/tmp/edgeos-stat-metadata-XXXXXX";
    char file[256];
    char link[256];
    int descriptor;

    if (!mkdtemp(directory)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(file, sizeof(file), "%s/file", directory);
    snprintf(link, sizeof(link), "%s/link", directory);
    descriptor = open(file, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0640);
    if (descriptor < 0 || write(descriptor, "edgeos", 6) != 6 ||
        close(descriptor) < 0 || symlink(file, link) < 0) {
        perror("metadata setup");
        return 1;
    }

    test_regular_and_symlink(directory, file, link);
    test_validation();
    test_mount_root_attribute(file);
    test_anonymous_descriptors();
    if (argc > 1) test_terminal_device(argv[1]);

    unlink(link);
    unlink(file);
    rmdir(directory);
    dprintf(STDOUT_FILENO, "STAT_METADATA_ABI_PROBE_%s failures:%d\n",
            failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
