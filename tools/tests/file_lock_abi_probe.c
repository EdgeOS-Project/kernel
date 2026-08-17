/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS Linux advisory-lock ABI regression test. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_OFD_GETLK
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38
#endif

static int failures;
static volatile sig_atomic_t signal_seen;

struct child_result {
    int rc;
    int error;
    int type;
    int pid_matches;
    int64_t start;
    int64_t length;
};

static void check_true(const char *name, int condition) {
    printf("%s:%s\n", name, condition ? "ok" : "fail");
    if (!condition) ++failures;
}

static int write_full(int descriptor, const void *buffer, size_t length) {
    const unsigned char *position = buffer;
    while (length) {
        ssize_t written = write(descriptor, position, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        position += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_full(int descriptor, void *buffer, size_t length) {
    unsigned char *position = buffer;
    while (length) {
        ssize_t received = read(descriptor, position, length);
        if (received == 0) return -1;
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        position += (size_t)received;
        length -= (size_t)received;
    }
    return 0;
}

static struct flock make_lock(short type, short whence,
                              off_t start, off_t length) {
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = type;
    lock.l_whence = whence;
    lock.l_start = start;
    lock.l_len = length;
    return lock;
}

static int wait_child(pid_t child) {
    int status = 0;
    if (waitpid(child, &status, 0) != child) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_posix_close_release(const char *path) {
    int command_pipe[2];
    int result_pipe[2];
    int descriptor = open(path, O_RDWR);
    int other = open(path, O_RDWR);
    struct flock lock = make_lock(F_WRLCK, SEEK_SET, 10, 10);
    pid_t parent = getpid();
    pid_t child;
    struct child_result result;
    char command;

    check_true("posix_setup", descriptor >= 0 && other >= 0 &&
               pipe(command_pipe) == 0 && pipe(result_pipe) == 0 &&
               fcntl(descriptor, F_SETLK, &lock) == 0);
    child = fork();
    if (child == 0) {
        int child_fd;
        struct child_result first;
        struct child_result second;
        struct flock query;
        close(command_pipe[1]);
        close(result_pipe[0]);
        child_fd = open(path, O_RDWR);
        memset(&first, 0, sizeof(first));
        memset(&second, 0, sizeof(second));
        if (child_fd < 0 || read_full(command_pipe[0], &command, 1) < 0)
            _exit(90);
        query = make_lock(F_RDLCK, SEEK_SET, 15, 1);
        errno = 0;
        first.rc = fcntl(child_fd, F_GETLK, &query);
        first.error = errno;
        first.type = query.l_type;
        first.pid_matches = query.l_pid == parent;
        first.start = query.l_start;
        first.length = query.l_len;
        query = make_lock(F_RDLCK, SEEK_SET, 15, 1);
        errno = 0;
        second.rc = fcntl(child_fd, F_SETLK, &query);
        second.error = errno;
        if (write_full(result_pipe[1], &first, sizeof(first)) < 0 ||
            write_full(result_pipe[1], &second, sizeof(second)) < 0 ||
            read_full(command_pipe[0], &command, 1) < 0)
            _exit(91);
        query = make_lock(F_RDLCK, SEEK_SET, 15, 1);
        errno = 0;
        second.rc = fcntl(child_fd, F_SETLK, &query);
        second.error = errno;
        if (second.rc == 0) {
            query = make_lock(F_UNLCK, SEEK_SET, 0, 0);
            (void)fcntl(child_fd, F_SETLK, &query);
        }
        if (write_full(result_pipe[1], &second, sizeof(second)) < 0)
            _exit(92);
        close(child_fd);
        _exit(0);
    }
    close(command_pipe[0]);
    close(result_pipe[1]);
    command = 'q';
    (void)write_full(command_pipe[1], &command, 1);
    memset(&result, 0, sizeof(result));
    check_true("posix_getlk_read", read_full(result_pipe[0], &result,
                                               sizeof(result)) == 0);
    check_true("posix_getlk_conflict", result.rc == 0 &&
               result.type == F_WRLCK && result.pid_matches &&
               result.start == 10 && result.length == 10);
    memset(&result, 0, sizeof(result));
    check_true("posix_setlk_conflict_read",
               read_full(result_pipe[0], &result, sizeof(result)) == 0);
    check_true("posix_setlk_conflict", result.rc == -1 &&
               (result.error == EAGAIN || result.error == EACCES));
    check_true("posix_close_other", close(other) == 0);
    command = 'r';
    (void)write_full(command_pipe[1], &command, 1);
    memset(&result, 0, sizeof(result));
    check_true("posix_after_close_read",
               read_full(result_pipe[0], &result, sizeof(result)) == 0);
    check_true("posix_close_releases_all", result.rc == 0 &&
               result.error == 0);
    check_true("posix_child_exit", wait_child(child) == 0);
    close(command_pipe[1]);
    close(result_pipe[0]);
    close(descriptor);
}

static void test_ofd_lifetime(const char *path) {
    int first = open(path, O_RDWR);
    int duplicate = dup(first);
    int independent = open(path, O_RDWR);
    struct flock lock = make_lock(F_WRLCK, SEEK_SET, 30, 5);
    struct flock query;
    int rc;
    int error;

    check_true("ofd_setup", first >= 0 && duplicate >= 0 && independent >= 0 &&
               fcntl(first, F_OFD_SETLK, &lock) == 0);
    query = make_lock(F_RDLCK, SEEK_SET, 30, 1);
    check_true("ofd_same_description", fcntl(duplicate, F_OFD_GETLK,
                                               &query) == 0 &&
               query.l_type == F_UNLCK);
    query = make_lock(F_RDLCK, SEEK_SET, 30, 1);
    check_true("ofd_independent_conflict",
               fcntl(independent, F_OFD_GETLK, &query) == 0 &&
               query.l_type == F_WRLCK && query.l_pid == -1 &&
               query.l_start == 30 && query.l_len == 5);
    check_true("ofd_close_one", close(first) == 0);
    query = make_lock(F_RDLCK, SEEK_SET, 30, 1);
    check_true("ofd_duplicate_retains",
               fcntl(independent, F_OFD_GETLK, &query) == 0 &&
               query.l_type == F_WRLCK);
    check_true("ofd_close_last", close(duplicate) == 0);
    query = make_lock(F_RDLCK, SEEK_SET, 30, 1);
    check_true("ofd_last_close_releases",
               fcntl(independent, F_OFD_GETLK, &query) == 0 &&
               query.l_type == F_UNLCK);
    query = make_lock(F_WRLCK, SEEK_SET, 0, 1);
    query.l_pid = 1;
    errno = 0;
    rc = fcntl(independent, F_OFD_SETLK, &query);
    error = errno;
    check_true("ofd_pid_validation", rc == -1 && error == EINVAL);
    close(independent);
}

static void test_flock_lifetime(const char *path) {
    int first = open(path, O_RDWR);
    int duplicate = dup(first);
    int independent = open(path, O_RDWR);
    int rc;
    int error;

    check_true("flock_setup", first >= 0 && duplicate >= 0 &&
               independent >= 0 && flock(first, LOCK_EX) == 0);
    errno = 0;
    rc = flock(independent, LOCK_SH | LOCK_NB);
    error = errno;
    check_true("flock_independent_conflict", rc == -1 &&
               (error == EWOULDBLOCK || error == EAGAIN));
    check_true("flock_duplicate_same_owner", flock(duplicate, LOCK_EX) == 0);
    check_true("flock_close_one", close(first) == 0);
    errno = 0;
    rc = flock(independent, LOCK_SH | LOCK_NB);
    error = errno;
    check_true("flock_duplicate_retains", rc == -1 &&
               (error == EWOULDBLOCK || error == EAGAIN));
    check_true("flock_close_last", close(duplicate) == 0);
    check_true("flock_last_close_releases",
               flock(independent, LOCK_SH | LOCK_NB) == 0);
    check_true("flock_unlock", flock(independent, LOCK_UN) == 0);
    close(independent);
}

static void test_flock_conversion(const char *path) {
    int first = open(path, O_RDWR);
    int independent = open(path, O_RDWR);
    int rc;
    int error;

    check_true("flock_conversion_setup",
               first >= 0 && independent >= 0 &&
               flock(first, LOCK_SH) == 0 &&
               flock(independent, LOCK_SH) == 0);
    errno = 0;
    rc = flock(first, LOCK_EX | LOCK_NB);
    error = errno;
    check_true("flock_conversion_conflict", rc == -1 &&
               (error == EWOULDBLOCK || error == EAGAIN));
    check_true("flock_conversion_drops_old_lock",
               flock(independent, LOCK_EX | LOCK_NB) == 0);
    check_true("flock_conversion_unlock",
               flock(independent, LOCK_UN) == 0);
    close(first);
    close(independent);
}

static void test_blocking_lock(const char *path) {
    int ready_pipe[2];
    int result_pipe[2];
    int descriptor = open(path, O_RDWR);
    struct flock lock = make_lock(F_WRLCK, SEEK_SET, 50, 1);
    pid_t child;
    struct child_result result;
    struct pollfd poll_descriptor;
    char ready;

    check_true("blocking_setup", descriptor >= 0 && pipe(ready_pipe) == 0 &&
               pipe(result_pipe) == 0 &&
               fcntl(descriptor, F_SETLK, &lock) == 0);
    child = fork();
    if (child == 0) {
        int child_fd;
        struct child_result child_result;
        close(ready_pipe[0]);
        close(result_pipe[0]);
        child_fd = open(path, O_RDWR);
        memset(&child_result, 0, sizeof(child_result));
        ready = 'b';
        if (child_fd < 0 || write_full(ready_pipe[1], &ready, 1) < 0)
            _exit(93);
        lock = make_lock(F_WRLCK, SEEK_SET, 50, 1);
        errno = 0;
        child_result.rc = fcntl(child_fd, F_SETLKW, &lock);
        child_result.error = errno;
        if (child_result.rc == 0) {
            lock = make_lock(F_UNLCK, SEEK_SET, 0, 0);
            (void)fcntl(child_fd, F_SETLK, &lock);
        }
        if (write_full(result_pipe[1], &child_result,
                       sizeof(child_result)) < 0)
            _exit(94);
        close(child_fd);
        _exit(0);
    }
    close(ready_pipe[1]);
    close(result_pipe[1]);
    check_true("blocking_child_ready", read_full(ready_pipe[0], &ready, 1) == 0);
    poll_descriptor.fd = result_pipe[0];
    poll_descriptor.events = POLLIN;
    poll_descriptor.revents = 0;
    check_true("blocking_waits", poll(&poll_descriptor, 1, 100) == 0);
    lock = make_lock(F_UNLCK, SEEK_SET, 50, 1);
    check_true("blocking_parent_unlock", fcntl(descriptor, F_SETLK, &lock) == 0);
    poll_descriptor.revents = 0;
    check_true("blocking_wakes", poll(&poll_descriptor, 1, 3000) == 1);
    memset(&result, 0, sizeof(result));
    check_true("blocking_result_read",
               read_full(result_pipe[0], &result, sizeof(result)) == 0);
    check_true("blocking_result", result.rc == 0 && result.error == 0);
    check_true("blocking_child_exit", wait_child(child) == 0);
    close(ready_pipe[0]);
    close(result_pipe[0]);
    close(descriptor);
}

static void signal_handler(int signal_number) {
    (void)signal_number;
    signal_seen = 1;
}

static void test_signal_interrupt(const char *path) {
    int ready_pipe[2];
    int result_pipe[2];
    int descriptor = open(path, O_RDWR);
    struct flock lock = make_lock(F_WRLCK, SEEK_SET, 60, 1);
    pid_t child;
    struct child_result result;
    char ready;

    check_true("signal_setup", descriptor >= 0 && pipe(ready_pipe) == 0 &&
               pipe(result_pipe) == 0 &&
               fcntl(descriptor, F_SETLK, &lock) == 0);
    child = fork();
    if (child == 0) {
        int child_fd;
        struct sigaction action;
        struct child_result child_result;
        close(ready_pipe[0]);
        close(result_pipe[0]);
        child_fd = open(path, O_RDWR);
        memset(&action, 0, sizeof(action));
        action.sa_handler = signal_handler;
        sigemptyset(&action.sa_mask);
        if (child_fd < 0 || sigaction(SIGUSR1, &action, NULL) < 0)
            _exit(95);
        ready = 's';
        if (write_full(ready_pipe[1], &ready, 1) < 0) _exit(96);
        lock = make_lock(F_WRLCK, SEEK_SET, 60, 1);
        memset(&child_result, 0, sizeof(child_result));
        errno = 0;
        child_result.rc = fcntl(child_fd, F_SETLKW, &lock);
        child_result.error = errno;
        child_result.type = signal_seen ? 1 : 0;
        if (write_full(result_pipe[1], &child_result,
                       sizeof(child_result)) < 0)
            _exit(97);
        close(child_fd);
        _exit(0);
    }
    close(ready_pipe[1]);
    close(result_pipe[1]);
    check_true("signal_child_ready", read_full(ready_pipe[0], &ready, 1) == 0);
    usleep(100000);
    check_true("signal_send", kill(child, SIGUSR1) == 0);
    memset(&result, 0, sizeof(result));
    check_true("signal_result_read",
               read_full(result_pipe[0], &result, sizeof(result)) == 0);
    check_true("signal_interrupts", result.rc == -1 &&
               result.error == EINTR && result.type == 1);
    check_true("signal_child_exit", wait_child(child) == 0);
    lock = make_lock(F_UNLCK, SEEK_SET, 60, 1);
    (void)fcntl(descriptor, F_SETLK, &lock);
    close(ready_pipe[0]);
    close(result_pipe[0]);
    close(descriptor);
}

int main(void) {
    char path[] = "/tmp/edgeos-file-lock-XXXXXX";
    int descriptor = mkstemp(path);
    if (descriptor < 0) {
        perror("mkstemp");
        return 1;
    }
    if (ftruncate(descriptor, 4096) < 0) {
        perror("ftruncate");
        close(descriptor);
        unlink(path);
        return 1;
    }
    close(descriptor);

    test_posix_close_release(path);
    test_ofd_lifetime(path);
    test_flock_lifetime(path);
    test_flock_conversion(path);
    test_blocking_lock(path);
    test_signal_interrupt(path);

    unlink(path);
    printf("FILE_LOCK_ABI_PROBE_%s failures:%d\n",
           failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
