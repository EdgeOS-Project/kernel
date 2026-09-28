/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Validate Linux pathname mutation semantics used by package managers and
 * desktop software.  The same binary is run on native Linux and EdgeOS.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1u
#endif

static int failures;

static void fail_message(const char *operation, const char *message) {
    fprintf(stderr, "%s: %s\n", operation, message);
    ++failures;
}

static void fail_errno(const char *operation) {
    fprintf(stderr, "%s: errno=%d (%s)\n",
            operation, errno, strerror(errno));
    ++failures;
}

static void expect_errno_value(const char *operation, int result,
                               int expected) {
    if (result != -1 || errno != expected) {
        fprintf(stderr, "%s: expected errno=%d, got result=%d errno=%d\n",
                operation, expected, result, errno);
        ++failures;
    }
}

static int create_file_at(int directory, const char *name,
                          const char *contents) {
    int descriptor = openat(directory, name,
                            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
    size_t length = strlen(contents);
    if (descriptor < 0) {
        fail_errno("openat(create)");
        return -1;
    }
    if (write(descriptor, contents, length) != (ssize_t)length)
        fail_errno("write(created file)");
    return descriptor;
}

static void expect_same_inode(const char *operation, int directory,
                              const char *left, const char *right,
                              nlink_t links) {
    struct stat left_stat;
    struct stat right_stat;
    if (fstatat(directory, left, &left_stat, AT_SYMLINK_NOFOLLOW) < 0 ||
        fstatat(directory, right, &right_stat, AT_SYMLINK_NOFOLLOW) < 0) {
        fail_errno(operation);
        return;
    }
    if (left_stat.st_ino != right_stat.st_ino ||
        left_stat.st_dev != right_stat.st_dev ||
        left_stat.st_nlink != links || right_stat.st_nlink != links) {
        fprintf(stderr,
                "%s: inode/dev/link mismatch left=(%lu,%lu,%lu) "
                "right=(%lu,%lu,%lu) expected-links=%lu\n",
                operation,
                (unsigned long)left_stat.st_ino,
                (unsigned long)left_stat.st_dev,
                (unsigned long)left_stat.st_nlink,
                (unsigned long)right_stat.st_ino,
                (unsigned long)right_stat.st_dev,
                (unsigned long)right_stat.st_nlink,
                (unsigned long)links);
        ++failures;
    }
}

static int renameat2_call(int old_directory, const char *old_path,
                          int new_directory, const char *new_path,
                          unsigned int flags) {
#ifdef SYS_renameat2
    return (int)syscall(SYS_renameat2, old_directory, old_path,
                        new_directory, new_path, flags);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int main(void) {
    char directory[] = "/tmp/edgeos-path-mutation-XXXXXX";
    char absolute[512];
    char proc_descriptor[64];
    char read_buffer[64];
    struct stat descriptor_stat;
    struct stat target_stat;
    int directory_fd = -1;
    int source_fd = -1;
    int reopened_fd = -1;
    int path_fd = -1;
    int target_fd = -1;
    int occupied_fd = -1;
    int child_directory_fd = -1;
    int child_fd = -1;
    int temporary_fd = -1;
    int temporary_path_fd = -1;
    int exclusive_temporary_fd = -1;
    int deleted_fd = -1;
    ssize_t length;

    if (!mkdtemp(directory)) {
        fail_errno("mkdtemp");
        return 1;
    }
    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        fail_errno("open(directory)");
        goto cleanup;
    }

    source_fd = create_file_at(directory_fd, "source", "source-data");
    if (source_fd < 0) goto cleanup;
    if (snprintf(proc_descriptor, sizeof(proc_descriptor),
                 "/proc/self/fd/%d", source_fd) >=
        (int)sizeof(proc_descriptor)) {
        fail_message("regular proc path", "path overflow");
    } else {
        if (lseek(source_fd, 5, SEEK_SET) != 5)
            fail_errno("lseek(source)");
        reopened_fd = open(proc_descriptor, O_RDONLY | O_CLOEXEC);
        if (reopened_fd < 0) {
            fail_errno("open(/proc/self/fd regular)");
        } else {
            off_t reopened_offset;
            off_t source_offset;
            ssize_t reopened_read;
            int reopened_errno;
            int reopened_flags;

            memset(read_buffer, 0, sizeof(read_buffer));
            reopened_offset = lseek(reopened_fd, 0, SEEK_CUR);
            reopened_flags = fcntl(reopened_fd, F_GETFL);
            errno = 0;
            reopened_read = read(reopened_fd, read_buffer, 6);
            reopened_errno = errno;
            source_offset = lseek(source_fd, 0, SEEK_CUR);
            if (reopened_offset != 0 || reopened_read != 6 ||
                memcmp(read_buffer, "source", 6) != 0 ||
                source_offset != 5) {
                fprintf(stderr,
                        "proc fd reopen: reopened-offset=%lld read=%lld "
                        "source-offset=%lld flags=0x%x errno=%d "
                        "bytes=%02x%02x%02x%02x%02x%02x\n",
                        (long long)reopened_offset,
                        (long long)reopened_read,
                        (long long)source_offset,
                        reopened_flags,
                        reopened_errno,
                        (unsigned char)read_buffer[0],
                        (unsigned char)read_buffer[1],
                        (unsigned char)read_buffer[2],
                        (unsigned char)read_buffer[3],
                        (unsigned char)read_buffer[4],
                        (unsigned char)read_buffer[5]);
                ++failures;
            }
        }
    }
    if (linkat(directory_fd, "source", directory_fd, "peer", 0) < 0)
        fail_errno("linkat(hard link)");
    else
        expect_same_inode("hard-link identity", directory_fd,
                          "source", "peer", 2);

    path_fd = openat(directory_fd, "source", O_PATH | O_CLOEXEC);
    if (path_fd < 0) {
        fail_errno("openat(O_PATH)");
    } else if (linkat(path_fd, "", directory_fd, "fd-link",
                      AT_EMPTY_PATH) < 0) {
        fail_errno("linkat(AT_EMPTY_PATH)");
    } else {
        expect_same_inode("AT_EMPTY_PATH identity", directory_fd,
                          "source", "fd-link", 3);
    }

    if (symlinkat("target", directory_fd, "symbolic") < 0) {
        fail_errno("symlinkat");
    } else {
        memset(read_buffer, 0x5a, sizeof(read_buffer));
        length = readlinkat(directory_fd, "symbolic", read_buffer, 4);
        if (length != 4 || memcmp(read_buffer, "targ", 4) != 0)
            fail_message("readlinkat(truncated)", "wrong bytes or length");
        if (linkat(directory_fd, "symbolic", directory_fd,
                   "symbolic-hard", 0) < 0) {
            fail_errno("linkat(symlink itself)");
        } else {
            memset(read_buffer, 0, sizeof(read_buffer));
            length = readlinkat(directory_fd, "symbolic-hard", read_buffer,
                                sizeof(read_buffer));
            if (length != 6 || memcmp(read_buffer, "target", 6) != 0)
                fail_message("hard-linked symlink", "target mismatch");
        }
        errno = 0;
        expect_errno_value(
            "linkat(AT_SYMLINK_FOLLOW dangling)",
            linkat(directory_fd, "symbolic", directory_fd,
                   "followed-dangling", AT_SYMLINK_FOLLOW), ENOENT);
    }

    target_fd = create_file_at(directory_fd, "target", "target-data");
    if (target_fd >= 0 &&
        linkat(directory_fd, "symbolic", directory_fd, "followed",
               AT_SYMLINK_FOLLOW) < 0) {
        fail_errno("linkat(AT_SYMLINK_FOLLOW)");
    } else if (target_fd >= 0) {
        expect_same_inode("followed symlink identity", directory_fd,
                          "target", "followed", 2);
    }

    temporary_fd = openat(directory_fd, ".",
                          O_TMPFILE | O_RDWR | O_CLOEXEC, 0644);
    if (temporary_fd < 0) {
        fail_errno("openat(O_TMPFILE)");
    } else if (snprintf(proc_descriptor, sizeof(proc_descriptor),
                        "/proc/self/fd/%d", temporary_fd) >=
               (int)sizeof(proc_descriptor)) {
        fail_message("O_TMPFILE proc path", "path overflow");
    } else if ((length = readlink(proc_descriptor, read_buffer,
                                  sizeof(read_buffer))) < 1) {
        fail_errno("readlink(O_TMPFILE proc fd)");
    } else if (read_buffer[0] != '/') {
        fail_message("O_TMPFILE proc target", "not an absolute path");
    } else if (write(temporary_fd, "temporary", 9) != 9) {
        fail_errno("write(O_TMPFILE)");
    } else if ((temporary_path_fd = open(
                    proc_descriptor, O_PATH | O_CLOEXEC)) < 0) {
        fail_errno("open(O_TMPFILE proc fd as O_PATH)");
    } else if (snprintf(proc_descriptor, sizeof(proc_descriptor),
                        "/proc/self/fd/%d", temporary_path_fd) >=
               (int)sizeof(proc_descriptor)) {
        fail_message("reopened O_TMPFILE proc path", "path overflow");
    } else if (linkat(AT_FDCWD, proc_descriptor, directory_fd,
                      "tmpfile-linked", AT_SYMLINK_FOLLOW) < 0) {
        fail_errno("linkat(reopened O_TMPFILE proc fd)");
    } else if (fstat(temporary_fd, &descriptor_stat) < 0 ||
               fstatat(directory_fd, "tmpfile-linked", &target_stat, 0) < 0) {
        fail_errno("stat(linked O_TMPFILE)");
    } else if (descriptor_stat.st_ino != target_stat.st_ino ||
               descriptor_stat.st_dev != target_stat.st_dev ||
               descriptor_stat.st_nlink != 1 || target_stat.st_nlink != 1) {
        fail_message("linked O_TMPFILE metadata", "inode or link mismatch");
    }

    exclusive_temporary_fd = openat(
        directory_fd, ".", O_TMPFILE | O_RDWR | O_EXCL | O_CLOEXEC, 0644);
    if (exclusive_temporary_fd < 0) {
        fail_errno("openat(O_TMPFILE|O_EXCL)");
    } else if (snprintf(proc_descriptor, sizeof(proc_descriptor),
                        "/proc/self/fd/%d", exclusive_temporary_fd) >=
               (int)sizeof(proc_descriptor)) {
        fail_message("exclusive O_TMPFILE proc path", "path overflow");
    } else {
        errno = 0;
        expect_errno_value(
            "linkat(O_TMPFILE|O_EXCL)",
            linkat(AT_FDCWD, proc_descriptor, directory_fd,
                   "exclusive-link", AT_SYMLINK_FOLLOW), ENOENT);
    }

    deleted_fd = create_file_at(directory_fd, "deleted-source", "deleted");
    if (deleted_fd >= 0) {
        if (unlinkat(directory_fd, "deleted-source", 0) < 0) {
            fail_errno("unlinkat(deleted-source)");
        } else if (snprintf(proc_descriptor, sizeof(proc_descriptor),
                            "/proc/self/fd/%d", deleted_fd) >=
                   (int)sizeof(proc_descriptor)) {
            fail_message("deleted descriptor proc path", "path overflow");
        } else {
            errno = 0;
            expect_errno_value(
                "linkat(deleted named descriptor)",
                linkat(AT_FDCWD, proc_descriptor, directory_fd,
                       "deleted-link", AT_SYMLINK_FOLLOW), ENOENT);
        }
    }

    errno = 0;
    expect_errno_value("readlinkat(regular file)",
                       (int)readlinkat(directory_fd, "target", read_buffer,
                                       sizeof(read_buffer)), EINVAL);
    errno = 0;
    expect_errno_value(
        "readlinkat(zero size)",
        (int)syscall(SYS_readlinkat, directory_fd, "symbolic", read_buffer,
                     0), EINVAL);

    if (renameat(directory_fd, "peer", directory_fd, "renamed") < 0)
        fail_errno("renameat");
    occupied_fd = create_file_at(directory_fd, "occupied", "occupied");
    if (occupied_fd < 0) {
        goto cleanup;
    }
    close(occupied_fd);
    occupied_fd = -1;
    errno = 0;
    expect_errno_value(
        "renameat2(RENAME_NOREPLACE)",
        renameat2_call(directory_fd, "renamed", directory_fd, "occupied",
                       RENAME_NOREPLACE), EEXIST);
    errno = 0;
    expect_errno_value(
        "renameat2(invalid flags)",
        renameat2_call(directory_fd, "renamed", directory_fd, "other",
                       0x80000000u), EINVAL);

    if (mkdirat(directory_fd, "empty-dir", 0755) < 0)
        fail_errno("mkdirat(empty-dir)");
    errno = 0;
    expect_errno_value("unlinkat(directory)",
                       unlinkat(directory_fd, "empty-dir", 0), EISDIR);
    errno = 0;
    expect_errno_value("unlinkat(file, AT_REMOVEDIR)",
                       unlinkat(directory_fd, "occupied", AT_REMOVEDIR),
                       ENOTDIR);
    if (mkdirat(directory_fd, "nonempty", 0755) < 0) {
        fail_errno("prepare nonempty directory");
    } else {
        child_directory_fd = openat(directory_fd, "nonempty",
                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (child_directory_fd < 0) {
            fail_errno("openat(nonempty directory)");
        } else {
            child_fd = create_file_at(child_directory_fd, "child", "child");
            if (child_fd >= 0) {
                close(child_fd);
                child_fd = -1;
            }
            close(child_directory_fd);
            child_directory_fd = -1;
        }
    }
    errno = 0;
    expect_errno_value("unlinkat(nonempty, AT_REMOVEDIR)",
                       unlinkat(directory_fd, "nonempty", AT_REMOVEDIR),
                       ENOTEMPTY);
    errno = 0;
    expect_errno_value("unlinkat(invalid flags)",
                       unlinkat(directory_fd, "occupied", 0x40000000),
                       EINVAL);

    if (snprintf(absolute, sizeof(absolute), "%s/absolute", directory) >=
        (int)sizeof(absolute)) {
        fail_message("absolute path", "path overflow");
    } else {
        int absolute_fd = open(absolute,
                               O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
        if (absolute_fd < 0) fail_errno("open(absolute)");
        else close(absolute_fd);
        if (unlinkat(-9, absolute, 0) < 0)
            fail_errno("unlinkat(absolute ignores bad dirfd)");
    }
    errno = 0;
    expect_errno_value("unlinkat(relative bad dirfd)",
                       unlinkat(-9, "occupied", 0), EBADF);

    if (unlinkat(directory_fd, "source", 0) < 0)
        fail_errno("unlinkat(source)");
    if (fstat(source_fd, &descriptor_stat) < 0 ||
        fstatat(directory_fd, "fd-link", &target_stat, 0) < 0) {
        fail_errno("stat after unlink");
    } else if (descriptor_stat.st_ino != target_stat.st_ino ||
               descriptor_stat.st_nlink != 2 || target_stat.st_nlink != 2) {
        fail_message("open-unlinked metadata", "inode or link count drift");
    }

cleanup:
    if (child_fd >= 0) close(child_fd);
    if (child_directory_fd >= 0) close(child_directory_fd);
    if (occupied_fd >= 0) close(occupied_fd);
    if (reopened_fd >= 0) close(reopened_fd);
    if (temporary_fd >= 0) close(temporary_fd);
    if (temporary_path_fd >= 0) close(temporary_path_fd);
    if (exclusive_temporary_fd >= 0) close(exclusive_temporary_fd);
    if (deleted_fd >= 0) close(deleted_fd);
    if (path_fd >= 0) close(path_fd);
    if (source_fd >= 0) close(source_fd);
    if (target_fd >= 0) close(target_fd);
    if (directory_fd >= 0) {
        unlinkat(directory_fd, "nonempty/child", 0);
        unlinkat(directory_fd, "nonempty", AT_REMOVEDIR);
        unlinkat(directory_fd, "empty-dir", AT_REMOVEDIR);
        unlinkat(directory_fd, "source", 0);
        unlinkat(directory_fd, "peer", 0);
        unlinkat(directory_fd, "fd-link", 0);
        unlinkat(directory_fd, "symbolic", 0);
        unlinkat(directory_fd, "symbolic-hard", 0);
        unlinkat(directory_fd, "followed", 0);
        unlinkat(directory_fd, "followed-dangling", 0);
        unlinkat(directory_fd, "target", 0);
        unlinkat(directory_fd, "tmpfile-linked", 0);
        unlinkat(directory_fd, "exclusive-link", 0);
        unlinkat(directory_fd, "deleted-source", 0);
        unlinkat(directory_fd, "deleted-link", 0);
        unlinkat(directory_fd, "renamed", 0);
        unlinkat(directory_fd, "occupied", 0);
        unlinkat(directory_fd, "other", 0);
        close(directory_fd);
    }
    if (rmdir(directory) < 0) fail_errno("rmdir(cleanup)");
    if (failures) {
        fprintf(stderr, "PATH_MUTATION_ABI_PROBE_FAIL failures=%d\n",
                failures);
        return 1;
    }
    puts("PATH_MUTATION_ABI_PROBE_PASS");
    return 0;
}
