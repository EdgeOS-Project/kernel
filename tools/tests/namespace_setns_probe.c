/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS Linux namespace descriptor and setns integration test.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define LINUX_NSFS_MAGIC 0x6e736673u
#define LINUX_NS_GET_NSTYPE 0xb703u

static int failures;

static void check(int condition, const char *message) {
    printf("%s %s\n", condition ? "PASS" : "FAIL", message);
    if (!condition) ++failures;
}

static int write_byte(int fd, char value) {
    return write(fd, &value, 1) == 1 ? 0 : -1;
}

int main(void) {
    static const char expected_hostname[] = "edgeos-setns-probe";
    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    int namespace_fd = -1;
    int retained_fd = -1;
    int target_status = 0;
    int join_status = 0;
    pid_t target;
    pid_t joiner = -1;
    char namespace_path[64];
    char self_link[64] = {0};
    char target_link[64] = {0};
    struct statfs filesystem;
    struct stat metadata;
    ssize_t self_length = -1;
    ssize_t target_length = -1;
    int namespace_type = -1;

    if (pipe(ready) < 0 || pipe(release) < 0) {
        perror("pipe");
        return 1;
    }
    target = fork();
    if (target == 0) {
        char value;
        close(ready[0]);
        close(release[1]);
        if (syscall(SYS_unshare, CLONE_NEWUTS) != 0 ||
            sethostname(expected_hostname, strlen(expected_hostname)) != 0 ||
            write_byte(ready[1], 'R') != 0 ||
            read(release[0], &value, 1) != 1)
            _exit(1);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    ready[1] = release[0] = -1;
    if (target > 0) {
        char value;
        if (read(ready[0], &value, 1) == 1) {
            snprintf(namespace_path, sizeof(namespace_path),
                     "/proc/%d/ns/uts", target);
            namespace_fd = open(namespace_path, O_RDONLY | O_CLOEXEC);
            self_length = readlink("/proc/self/ns/uts", self_link,
                                   sizeof(self_link) - 1);
            target_length = readlink(namespace_path, target_link,
                                     sizeof(target_link) - 1);
        }
    }
    if (self_length >= 0) self_link[self_length] = 0;
    if (target_length >= 0) target_link[target_length] = 0;
    check(namespace_fd >= 0 && self_length > 0 && target_length > 0 &&
              strcmp(self_link, target_link) != 0,
          "procfs exposes task-specific namespace handles");

    memset(&filesystem, 0, sizeof(filesystem));
    memset(&metadata, 0, sizeof(metadata));
    namespace_type = namespace_fd >= 0 ?
        ioctl(namespace_fd, LINUX_NS_GET_NSTYPE) : -1;
    check(namespace_fd >= 0 && fstat(namespace_fd, &metadata) == 0 &&
              S_ISREG(metadata.st_mode) &&
              fstatfs(namespace_fd, &filesystem) == 0 &&
              (uint64_t)filesystem.f_type == LINUX_NSFS_MAGIC &&
              namespace_type == CLONE_NEWUTS,
          "namespace fd reports Linux nsfs metadata and namespace type");

    errno = 0;
    check(namespace_fd >= 0 &&
              syscall(SYS_setns, namespace_fd, CLONE_NEWNET) == -1 &&
              errno == EINVAL,
          "setns rejects a mismatched namespace type");

    retained_fd = namespace_fd >= 0 ? dup(namespace_fd) : -1;
    if (namespace_fd >= 0) close(namespace_fd);
    namespace_fd = -1;
    check(retained_fd >= 0, "dup retains a namespace handle");

    if (release[1] >= 0) (void)write_byte(release[1], 'X');
    if (target > 0) (void)waitpid(target, &target_status, 0);
    if (retained_fd >= 0) {
        joiner = fork();
        if (joiner == 0) {
            char hostname[64] = {0};
            if (syscall(SYS_setns, retained_fd, CLONE_NEWUTS) != 0 ||
                gethostname(hostname, sizeof(hostname)) != 0 ||
                strcmp(hostname, expected_hostname) != 0)
                _exit(1);
            _exit(0);
        }
    }
    if (joiner > 0) (void)waitpid(joiner, &join_status, 0);
    check(target > 0 && WIFEXITED(target_status) &&
              WEXITSTATUS(target_status) == 0 && joiner > 0 &&
              WIFEXITED(join_status) && WEXITSTATUS(join_status) == 0,
          "setns joins a duplicated namespace after its task exits");

    if (retained_fd >= 0) close(retained_fd);
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (release[0] >= 0) close(release[0]);
    if (release[1] >= 0) close(release[1]);
    printf("NAMESPACE_SETNS_%s failures=%d\n",
           failures ? "FAIL" : "OK", failures);
    return failures ? 1 : 0;
}
