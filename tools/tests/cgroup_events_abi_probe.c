/* SPDX-License-Identifier: MPL-2.0 */
/* Validate Linux cgroup v2 populated transitions and inotify delivery. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *operation) {
    fprintf(stderr, "CGROUP_EVENTS_ABI_PROBE_FAIL operation=%s errno=%d (%s)\n",
            operation, errno, strerror(errno));
    exit(1);
}

static void write_pid(const char *path, pid_t pid) {
    char buffer[32];
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    int length;
    if (fd < 0) fail("open-cgroup-procs");
    length = snprintf(buffer, sizeof(buffer), "%ld\n", (long)pid);
    if (write(fd, buffer, (size_t)length) != length)
        fail("write-cgroup-procs");
    close(fd);
}

static void drain_events(int fd) {
    char buffer[1024];
    while (read(fd, buffer, sizeof(buffer)) > 0) { }
    if (errno != EAGAIN && errno != EWOULDBLOCK) fail("drain-inotify");
}

static void require_modify_event(int fd, const char *phase) {
    struct pollfd pollfd = { .fd = fd, .events = POLLIN };
    char buffer[1024];
    ssize_t length;
    int status = poll(&pollfd, 1, 3000);
    if (status <= 0) {
        errno = status == 0 ? ETIMEDOUT : errno;
        fail(phase);
    }
    length = read(fd, buffer, sizeof(buffer));
    if (length < (ssize_t)sizeof(struct inotify_event)) fail("read-inotify");
    for (ssize_t offset = 0; offset < length;) {
        struct inotify_event *event =
            (struct inotify_event *)(buffer + offset);
        if (event->mask & IN_MODIFY) return;
        offset += (ssize_t)sizeof(*event) + event->len;
    }
    errno = EPROTO;
    fail("missing-in-modify");
}

static int populated_value(const char *path) {
    char buffer[256];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t length;
    char *value;
    if (fd < 0) fail("open-cgroup-events");
    length = read(fd, buffer, sizeof(buffer) - 1u);
    if (length < 0) fail("read-cgroup-events");
    close(fd);
    buffer[length] = 0;
    value = strstr(buffer, "populated ");
    if (!value) {
        errno = EPROTO;
        fail("parse-populated");
    }
    return atoi(value + strlen("populated "));
}

int main(void) {
    char directory[256];
    char events_path[320];
    char procs_path[320];
    int ready[2];
    int release[2];
    int inotify_fd;
    int watch;
    pid_t child;
    char byte;

    snprintf(directory, sizeof(directory),
             "/sys/fs/cgroup/edgeos-cgroup-events-%ld", (long)getpid());
    snprintf(events_path, sizeof(events_path), "%s/cgroup.events", directory);
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", directory);
    if (mkdir(directory, 0755) < 0) fail("mkdir-cgroup");
    if (populated_value(events_path) != 0) {
        errno = EPROTO;
        fail("initial-populated");
    }
    inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd < 0) fail("inotify-init");
    watch = inotify_add_watch(inotify_fd, events_path, IN_MODIFY);
    if (watch < 0) fail("inotify-add-watch");
    if (pipe2(ready, O_CLOEXEC) < 0 || pipe2(release, O_CLOEXEC) < 0)
        fail("pipe");
    child = fork();
    if (child < 0) fail("fork");
    if (child == 0) {
        close(ready[0]);
        close(release[1]);
        if (write(ready[1], "R", 1) != 1) _exit(2);
        if (read(release[0], &byte, 1) < 0) _exit(3);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    if (read(ready[0], &byte, 1) != 1) fail("child-ready");
    write_pid(procs_path, child);
    require_modify_event(inotify_fd, "populate-notification");
    if (populated_value(events_path) != 1) {
        errno = EPROTO;
        fail("populated-one");
    }
    drain_events(inotify_fd);
    if (write(release[1], "X", 1) != 1) fail("release-child");
    close(release[1]);
    if (waitpid(child, 0, 0) != child) fail("waitpid");
    require_modify_event(inotify_fd, "empty-notification");
    if (populated_value(events_path) != 0) {
        errno = EPROTO;
        fail("populated-zero");
    }
    if (inotify_rm_watch(inotify_fd, watch) < 0) fail("inotify-rm-watch");
    close(inotify_fd);
    close(ready[0]);
    if (rmdir(directory) < 0) fail("rmdir-cgroup");
    puts("CGROUP_EVENTS_ABI_PROBE_PASS");
    return 0;
}
