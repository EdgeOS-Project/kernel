/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Validate Linux access, chmod, chown, and timestamp mutation semantics.  The
 * same statically linked binary is run on native Linux and EdgeOS.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_EACCESS
#define AT_EACCESS 0x200
#endif
#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

static int failures;
static int verbose;

static void stage(const char *name) {
    if (!verbose) return;
    fprintf(stderr, "METADATA_MUTATION_STAGE %s\n", name);
    fflush(stderr);
}

static void fail_errno(const char *operation) {
    fprintf(stderr, "%s: errno=%d (%s)\n",
            operation, errno, strerror(errno));
    ++failures;
}

static void fail_value(const char *operation, long expected, long actual) {
    fprintf(stderr, "%s: expected=%ld actual=%ld errno=%d\n",
            operation, expected, actual, errno);
    ++failures;
}

static void expect_success(const char *operation, long result) {
    if (result < 0) fail_errno(operation);
}

static void expect_errno_value(const char *operation, long result,
                               int expected) {
    if (result != -1 || errno != expected) {
        fprintf(stderr,
                "%s: expected result=-1 errno=%d, got result=%ld errno=%d\n",
                operation, expected, result, errno);
        ++failures;
    }
}

static int create_file_at(int directory, const char *name, mode_t mode) {
    int descriptor = openat(directory, name,
                            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, mode);
    if (descriptor < 0) fail_errno("openat(create)");
    return descriptor;
}

static int faccessat2_call(int directory, const char *path, int mode,
                          int flags) {
    return (int)syscall(SYS_faccessat2, directory, path, mode, flags);
}

static int fchmodat2_call(int directory, const char *path, mode_t mode,
                         int flags) {
    return (int)syscall(SYS_fchmodat2, directory, path, mode, flags);
}

static void expect_metadata(const char *operation, int descriptor,
                            mode_t mode, uid_t uid, gid_t gid) {
    struct stat value;
    if (fstat(descriptor, &value) < 0) {
        fail_errno(operation);
        return;
    }
    if ((value.st_mode & 07777) != mode)
        fail_value(operation, mode, value.st_mode & 07777);
    if (value.st_uid != uid) fail_value(operation, uid, value.st_uid);
    if (value.st_gid != gid) fail_value(operation, gid, value.st_gid);
}

static int child_credentials(uid_t real_uid, uid_t effective_uid,
                             gid_t real_gid, gid_t effective_gid,
                             gid_t supplementary) {
    gid_t groups[1] = {supplementary};
    if (setgroups(1, groups) < 0 ||
        setresgid(real_gid, effective_gid, effective_gid) < 0 ||
        setresuid(real_uid, effective_uid, effective_uid) < 0) {
        fail_errno("child credential transition");
        return -1;
    }
    return 0;
}

static int wait_child(const char *operation, pid_t child) {
    int status;
    if (waitpid(child, &status, 0) != child) {
        fail_errno(operation);
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s: child status=0x%x\n", operation, status);
        ++failures;
        return -1;
    }
    return 0;
}

static void test_devpts_metadata(void) {
    char slave_path[128];
    struct stat value;
    int master = -1;
    int slave = -1;

    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0) {
        fail_errno("posix_openpt");
        return;
    }
    if (grantpt(master) < 0) {
        fail_errno("grantpt");
        goto out;
    }
    if (unlockpt(master) < 0) {
        fail_errno("unlockpt");
        goto out;
    }
    if (ptsname_r(master, slave_path, sizeof(slave_path)) != 0) {
        fail_errno("ptsname_r");
        goto out;
    }
    slave = open(slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        fail_errno("open(devpts slave)");
        goto out;
    }
    expect_success("fchmod(devpts slave)", fchmod(slave, 0621));
    expect_success("fchown(devpts slave)", fchown(slave, 71000, 71001));
    if (stat(slave_path, &value) < 0) {
        fail_errno("stat(devpts slave)");
    } else {
        if ((value.st_mode & 07777) != 0621)
            fail_value("devpts slave mode", 0621,
                       value.st_mode & 07777);
        if (value.st_uid != 71000)
            fail_value("devpts slave uid", 71000, value.st_uid);
        if (value.st_gid != 71001)
            fail_value("devpts slave gid", 71001, value.st_gid);
    }

out:
    if (slave >= 0) close(slave);
    close(master);
}

static void child_real_effective_access(const char *directory) {
    char owner_path[512];
    char group_path[512];
    char protected_path[512];
    int local_failures = 0;
    snprintf(owner_path, sizeof(owner_path), "%s/real-owner", directory);
    snprintf(group_path, sizeof(group_path), "%s/group-readable", directory);
    snprintf(protected_path, sizeof(protected_path), "%s/protected", directory);
    failures = 0;
    if (child_credentials(1001, 1002, 2000, 2002, 2001) < 0)
        _exit(1);
    errno = 0;
    if (access(owner_path, R_OK) < 0) fail_errno("access(real IDs)");
    errno = 0;
    expect_errno_value(
        "faccessat2(AT_EACCESS)",
        faccessat2_call(AT_FDCWD, owner_path, R_OK, AT_EACCESS), EACCES);
    if (access(group_path, R_OK) < 0)
        fail_errno("access(supplementary group)");
    errno = 0;
    expect_errno_value("chmod(nonowner)", chmod(protected_path, 0600),
                       EPERM);
    local_failures = failures;
    _exit(local_failures ? 1 : 0);
}

static void child_owner_mutations(const char *directory) {
    char path[512];
    struct stat value;
    struct timespec times[2] = {
        {.tv_sec = 234567800, .tv_nsec = 0},
        {.tv_sec = 234567801, .tv_nsec = 0},
    };
    failures = 0;
    snprintf(path, sizeof(path), "%s/owner-mutation", directory);
    if (child_credentials(1001, 1001, 2000, 2000, 2001) < 0)
        _exit(1);
    if (chmod(path, 02755) < 0) fail_errno("chmod(owner setgid)");
    if (stat(path, &value) < 0) {
        fail_errno("stat(owner setgid)");
    } else if ((value.st_mode & 07777) != 0755) {
        fail_value("setgid clearing", 0755, value.st_mode & 07777);
    }
    if (chown(path, (uid_t)-1, 2001) < 0)
        fail_errno("chown(owner supplementary group)");
    if (stat(path, &value) < 0 || value.st_gid != 2001)
        fail_errno("stat(changed group)");
    errno = 0;
    expect_errno_value("chown(owner change denied)",
                       chown(path, 1002, (gid_t)-1), EPERM);
    if (utimensat(AT_FDCWD, path, times, 0) < 0)
        fail_errno("utimensat(owner explicit)");
    _exit(failures ? 1 : 0);
}

static void child_timestamp_permissions(const char *directory, int writable) {
    char path[512];
    struct timespec times[2] = {
        {.tv_sec = 345678900, .tv_nsec = 0},
        {.tv_sec = 345678901, .tv_nsec = 0},
    };
    failures = 0;
    snprintf(path, sizeof(path), "%s/timestamp-permission", directory);
    if (child_credentials(1002, 1002, 2002, 2002, 2003) < 0)
        _exit(1);
    errno = 0;
    expect_errno_value("utimensat(nonowner explicit)",
                       utimensat(AT_FDCWD, path, times, 0), EPERM);
    errno = 0;
    if (writable) {
        expect_success("utimensat(nonowner write access)",
                       utimensat(AT_FDCWD, path, 0, 0));
    } else {
        expect_errno_value("utimensat(nonowner no write access)",
                           utimensat(AT_FDCWD, path, 0, 0), EACCES);
    }
    _exit(failures ? 1 : 0);
}

int main(void) {
    char directory[] = "/tmp/edgeos-metadata-mutation-XXXXXX";
    char path[512];
    struct stat before;
    struct stat after;
    struct timespec times[2];
    int directory_fd = -1;
    int descriptor = -1;
    int path_descriptor = -1;
    int temporary = -1;
    pid_t child;

    verbose = getenv("EDGEOS_TEST_VERBOSE") != 0;
    stage("setup");

    if (!mkdtemp(directory)) {
        fail_errno("mkdtemp");
        return 1;
    }
    if (chmod(directory, 0777) < 0) fail_errno("chmod(test directory)");
    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        fail_errno("open(test directory)");
        goto cleanup;
    }

    stage("unlinked-descriptor");
    descriptor = create_file_at(directory_fd, "descriptor", 0644);
    if (descriptor >= 0) {
        if (unlinkat(directory_fd, "descriptor", 0) < 0)
            fail_errno("unlink(open descriptor)");
        expect_success("fchmod(unlinked descriptor)", fchmod(descriptor, 06750));
        expect_success("fchown(unlinked descriptor)",
                       fchown(descriptor, 70000, 70001));
        times[0].tv_sec = 123456700;
        times[0].tv_nsec = 0;
        times[1].tv_sec = 123456701;
        times[1].tv_nsec = 0;
        expect_success("utimensat(fd,NULL)",
                       syscall(SYS_utimensat, descriptor, 0, times, 0));
        expect_metadata("unlinked descriptor metadata", descriptor,
                        0750, 70000, 70001);
        if (fstat(descriptor, &after) < 0 ||
            after.st_atim.tv_sec != times[0].tv_sec ||
            after.st_mtim.tv_sec != times[1].tv_sec)
            fail_value("unlinked descriptor timestamps",
                       times[1].tv_sec, after.st_mtim.tv_sec);
    }

    stage("o-path");
    descriptor = create_file_at(directory_fd, "path-only", 0644);
    if (descriptor >= 0) close(descriptor);
    path_descriptor = openat(directory_fd, "path-only", O_PATH | O_CLOEXEC);
    if (path_descriptor < 0) {
        fail_errno("openat(O_PATH)");
    } else {
        errno = 0;
        expect_errno_value("fchmod(O_PATH)",
                           syscall(SYS_fchmod, path_descriptor, 0600), EBADF);
        expect_success("fchmodat2(O_PATH,AT_EMPTY_PATH)",
                       fchmodat2_call(path_descriptor, "", 0610,
                                      AT_EMPTY_PATH));
        if (fstat(path_descriptor, &after) < 0 ||
            (after.st_mode & 07777) != 0610)
            fail_value("O_PATH chmod metadata", 0610,
                       after.st_mode & 07777);
    }

    stage("o-tmpfile");
    temporary = openat(directory_fd, ".",
                       O_TMPFILE | O_RDWR | O_CLOEXEC, 0644);
    if (temporary < 0) {
        fail_errno("openat(O_TMPFILE)");
    } else {
        expect_success("fchmod(O_TMPFILE)", fchmod(temporary, 0601));
        expect_success("fchown(O_TMPFILE)", fchown(temporary, 80000, 80001));
        expect_metadata("O_TMPFILE metadata", temporary,
                        0601, 80000, 80001);
    }

    stage("chown-setid");
    descriptor = create_file_at(directory_fd, "chown-clear", 0755);
    if (descriptor >= 0) {
        expect_success("fchmod(set-ID setup)", fchmod(descriptor, 06755));
        if (fstat(descriptor, &before) < 0) fail_errno("fstat(before chown)");
        expect_success("fchown(-1,-1)",
                       fchown(descriptor, (uid_t)-1, (gid_t)-1));
        if (fstat(descriptor, &after) < 0) {
            fail_errno("fstat(after chown)");
        } else {
            if ((after.st_mode & 07777) != 0755)
                fail_value("chown set-ID clearing", 0755,
                           after.st_mode & 07777);
            if (after.st_ctim.tv_sec < before.st_ctim.tv_sec)
                fail_value("chown ctime ordering", before.st_ctim.tv_sec,
                           after.st_ctim.tv_sec);
        }
    }

    stage("symlink-metadata");
    if (symlinkat("missing-target", directory_fd, "ownership-link") < 0) {
        fail_errno("symlinkat(ownership-link)");
    } else {
        expect_success("lchown(symlink)",
                       fchownat(directory_fd, "ownership-link", 90000, 90001,
                                AT_SYMLINK_NOFOLLOW));
        if (fstatat(directory_fd, "ownership-link", &after,
                    AT_SYMLINK_NOFOLLOW) < 0 ||
            after.st_uid != 90000 || after.st_gid != 90001)
            fail_errno("symlink ownership metadata");
        errno = 0;
        expect_errno_value(
            "fchmodat2(symlink nofollow)",
            fchmodat2_call(directory_fd, "ownership-link", 0600,
                           AT_SYMLINK_NOFOLLOW), EOPNOTSUPP);
    }

    stage("timestamps");
    descriptor = create_file_at(directory_fd, "timestamps", 0644);
    if (descriptor >= 0) close(descriptor);
    times[0].tv_sec = 456789000;
    times[0].tv_nsec = 123456789;
    times[1].tv_sec = 456789001;
    times[1].tv_nsec = 987654321;
    expect_success("utimensat(explicit)",
                   utimensat(directory_fd, "timestamps", times, 0));
    if (fstatat(directory_fd, "timestamps", &before, 0) < 0) {
        fail_errno("fstatat(explicit timestamps)");
    } else if (before.st_atim.tv_sec != times[0].tv_sec ||
               before.st_mtim.tv_sec != times[1].tv_sec) {
        fail_value("explicit timestamp seconds", times[1].tv_sec,
                   before.st_mtim.tv_sec);
    }
    times[0].tv_nsec = UTIME_OMIT;
    times[1].tv_nsec = UTIME_NOW;
    expect_success("utimensat(OMIT,NOW)",
                   utimensat(directory_fd, "timestamps", times, 0));
    if (fstatat(directory_fd, "timestamps", &after, 0) < 0) {
        fail_errno("fstatat(OMIT,NOW)");
    } else if (after.st_atim.tv_sec != before.st_atim.tv_sec) {
        fail_value("UTIME_OMIT preservation", before.st_atim.tv_sec,
                   after.st_atim.tv_sec);
    }
    times[0].tv_sec = 0;
    times[0].tv_nsec = 1000000000L;
    times[1].tv_sec = 0;
    times[1].tv_nsec = UTIME_OMIT;
    errno = 0;
    expect_errno_value("utimensat(invalid nanoseconds)",
                       utimensat(directory_fd, "timestamps", times, 0),
                       EINVAL);

    stage("access");
    descriptor = create_file_at(directory_fd, "root-execute", 0644);
    if (descriptor >= 0) close(descriptor);
    errno = 0;
    expect_errno_value("access(root execute rule)",
                       faccessat(directory_fd, "root-execute", X_OK, 0),
                       EACCES);

    stage("devpts");
    test_devpts_metadata();

    stage("credential-access");
    descriptor = create_file_at(directory_fd, "real-owner", 0400);
    if (descriptor >= 0) {
        expect_success("fchown(real-owner)", fchown(descriptor, 1001, 2000));
        close(descriptor);
    }
    descriptor = create_file_at(directory_fd, "group-readable", 0040);
    if (descriptor >= 0) {
        expect_success("fchown(group-readable)",
                       fchown(descriptor, 0, 2001));
        close(descriptor);
    }
    descriptor = create_file_at(directory_fd, "protected", 0644);
    if (descriptor >= 0) close(descriptor);
    child = fork();
    if (child == 0) child_real_effective_access(directory);
    if (child < 0) fail_errno("fork(real/effective access)");
    else wait_child("real/effective access child", child);

    stage("owner-mutation");
    descriptor = create_file_at(directory_fd, "owner-mutation", 0755);
    if (descriptor >= 0) {
        expect_success("fchown(owner-mutation)",
                       fchown(descriptor, 1001, 9999));
        close(descriptor);
    }
    child = fork();
    if (child == 0) child_owner_mutations(directory);
    if (child < 0) fail_errno("fork(owner mutations)");
    else wait_child("owner mutation child", child);

    stage("timestamp-permission");
    descriptor = create_file_at(directory_fd, "timestamp-permission", 0222);
    if (descriptor >= 0) {
        expect_success("fchmod(timestamp-permission)",
                       fchmod(descriptor, 0222));
        expect_success("fchown(timestamp-permission)",
                       fchown(descriptor, 1001, 2000));
        close(descriptor);
    }
    child = fork();
    if (child == 0) child_timestamp_permissions(directory, 1);
    if (child < 0) fail_errno("fork(writable timestamps)");
    else wait_child("writable timestamp child", child);
    snprintf(path, sizeof(path), "%s/timestamp-permission", directory);
    if (chmod(path, 0444) < 0) fail_errno("chmod(timestamp read-only)");
    child = fork();
    if (child == 0) child_timestamp_permissions(directory, 0);
    if (child < 0) fail_errno("fork(read-only timestamps)");
    else wait_child("read-only timestamp child", child);

cleanup:
    stage("cleanup");
    if (temporary >= 0) close(temporary);
    if (path_descriptor >= 0) close(path_descriptor);
    if (descriptor >= 0) close(descriptor);
    if (directory_fd >= 0) close(directory_fd);
    if (failures) {
        fprintf(stderr, "METADATA_MUTATION_ABI_PROBE_FAIL failures=%d\n",
                failures);
        return 1;
    }
    puts("METADATA_MUTATION_ABI_PROBE_PASS");
    return 0;
}
