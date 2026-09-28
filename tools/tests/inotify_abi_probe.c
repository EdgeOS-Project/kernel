/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux inotify validation, event-record, lifetime, and blocking probe.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int g_failures;
static char g_directory[128];
static char g_first_path[160];
static char g_second_path[160];
static int g_blocking_fd;
static atomic_int g_reader_started;
static ssize_t g_reader_result;
static int g_reader_errno;
static unsigned char g_reader_buffer[512];

static void fail(const char *name) {
    dprintf(STDOUT_FILENO, "%s:FAIL errno:%d\n", name, errno);
    ++g_failures;
}

static void expect_errno(const char *name, long result, int expected) {
    int saved_errno = errno;
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != -1 || saved_errno != expected) ++g_failures;
}

static int create_file(const char *path, const char *contents) {
    size_t length = contents ? strlen(contents) : 0;
    int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (descriptor < 0) return -1;
    if (length && write(descriptor, contents, length) != (ssize_t)length) {
        close(descriptor);
        return -1;
    }
    return close(descriptor);
}

static ssize_t read_available(int descriptor, void *buffer, size_t length) {
    ssize_t total = 0;
    for (;;) {
        ssize_t result = read(descriptor, (unsigned char *)buffer + total,
                              length - (size_t)total);
        if (result > 0) {
            total += result;
            if ((size_t)total == length) break;
            continue;
        }
        if (result < 0 && errno == EAGAIN) break;
        if (result < 0) return result;
        break;
    }
    return total;
}

static void dump_events(const char *tag, const unsigned char *buffer,
                        ssize_t length, uint32_t *from_cookie,
                        uint32_t *to_cookie, int *ignored_count,
                        int *named_count) {
    ssize_t offset = 0;
    int count = 0;
    while (offset + (ssize_t)sizeof(struct inotify_event) <= length) {
        const struct inotify_event *event =
            (const struct inotify_event *)(const void *)(buffer + offset);
        size_t record = sizeof(*event) + event->len;
        const char *name = event->len ? event->name : "";
        if (record > (size_t)(length - offset)) {
            ++g_failures;
            break;
        }
        dprintf(STDOUT_FILENO,
                "%s_event:%d wd:%d mask:0x%x cookie:%u len:%u name:%s\n",
                tag, count, event->wd, event->mask, event->cookie,
                event->len, name);
        if ((event->mask & IN_MOVED_FROM) && from_cookie)
            *from_cookie = event->cookie;
        if ((event->mask & IN_MOVED_TO) && to_cookie)
            *to_cookie = event->cookie;
        if ((event->mask & IN_IGNORED) && ignored_count)
            ++*ignored_count;
        if (event->len && named_count) ++*named_count;
        offset += (ssize_t)record;
        ++count;
    }
    dprintf(STDOUT_FILENO, "%s_records:%d bytes:%ld\n", tag, count,
            (long)length);
    if (offset != length) ++g_failures;
}

static void test_create_and_validation(void) {
    struct inotify_event event;
    int descriptor;
    int flags;
    long result;

    errno = 0;
    expect_errno("bad_init_flags", inotify_init1(2), EINVAL);
    descriptor = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (descriptor < 0) {
        fail("inotify_init1");
        return;
    }
    flags = fcntl(descriptor, F_GETFD);
    dprintf(STDOUT_FILENO, "descriptor_flags:0x%x\n", flags);
    if (flags != FD_CLOEXEC) ++g_failures;
    flags = fcntl(descriptor, F_GETFL);
    dprintf(STDOUT_FILENO, "status_flags:0x%x\n", flags);
    if (flags < 0 || (flags & (O_ACCMODE | O_NONBLOCK)) !=
                     (O_RDONLY | O_NONBLOCK))
        ++g_failures;

    errno = 0;
    expect_errno("empty_read", read(descriptor, &event, sizeof(event)),
                 EAGAIN);
    errno = 0;
    expect_errno("empty_short_read", read(descriptor, &event, 8), EAGAIN);
    errno = 0;
    expect_errno("inotify_write", write(descriptor, &event, sizeof(event)),
                 EBADF);

    errno = 0;
    expect_errno("invalid_fd_add",
                 inotify_add_watch(-1, g_directory, IN_CREATE), EBADF);
    errno = 0;
    result = syscall(SYS_inotify_add_watch, -1,
                     (const char *)(uintptr_t)1, IN_CREATE);
    expect_errno("invalid_fd_fault_path_add", result, EBADF);
    errno = 0;
    expect_errno("wrong_type_add",
                 inotify_add_watch(STDIN_FILENO, g_directory, IN_CREATE),
                 EINVAL);
    errno = 0;
    result = syscall(SYS_inotify_add_watch, descriptor,
                     (const char *)(uintptr_t)1, IN_CREATE);
    expect_errno("fault_path_add", result, EFAULT);
    errno = 0;
    result = syscall(SYS_inotify_add_watch, descriptor,
                     (const char *)(uintptr_t)1, 0x00800000u);
    expect_errno("fault_path_invalid_mask_add", result, EINVAL);
    errno = 0;
    result = inotify_add_watch(descriptor, "/does-not-exist-edgeos-inotify",
                               0x00800000u);
    expect_errno("missing_path_invalid_mask_add", result, EINVAL);
    errno = 0;
    expect_errno("empty_path_add",
                 inotify_add_watch(descriptor, "", IN_CREATE), ENOENT);
    errno = 0;
    result = inotify_add_watch(descriptor, g_directory, 0);
    dprintf(STDOUT_FILENO, "zero_mask_add_rc:%ld errno:%d\n", result,
            errno);
    if (result != -1 || errno != EINVAL) ++g_failures;
    errno = 0;
    expect_errno("unknown_mask_add",
                 inotify_add_watch(descriptor, g_directory, 0x00800000u),
                 EINVAL);
    errno = 0;
    expect_errno("conflicting_mask_add",
                 inotify_add_watch(descriptor, g_directory,
                                   IN_CREATE | IN_MASK_ADD |
                                   IN_MASK_CREATE),
                 EINVAL);
    {
        static const uint32_t output_masks[] = {
            IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED, IN_ISDIR
        };
        for (size_t index = 0;
             index < sizeof(output_masks) / sizeof(output_masks[0]);
             ++index) {
            errno = 0;
            result = inotify_add_watch(descriptor, g_directory,
                                       output_masks[index]);
            dprintf(STDOUT_FILENO,
                    "output_mask_0x%x_rc:%ld errno:%d\n",
                    output_masks[index], result, errno);
            if (result < 0) {
                ++g_failures;
            } else {
                inotify_rm_watch(descriptor, (int)result);
            }
        }
    }

    if (create_file(g_first_path, "validation") < 0) {
        fail("validation_file");
    } else {
        errno = 0;
        expect_errno("onlydir_file_add",
                     inotify_add_watch(descriptor, g_first_path,
                                       IN_OPEN | IN_ONLYDIR),
                     ENOTDIR);
        unlink(g_first_path);
    }
    close(descriptor);

#if defined(__x86_64__) && defined(SYS_inotify_init)
    errno = 0;
    descriptor = (int)syscall(SYS_inotify_init);
    dprintf(STDOUT_FILENO, "legacy_inotify_init_rc:%d errno:%d\n",
            descriptor, errno);
    if (descriptor < 0) {
        ++g_failures;
    } else {
        flags = fcntl(descriptor, F_GETFL);
        if (flags < 0 || (flags & (O_ACCMODE | O_NONBLOCK)) != O_RDONLY)
            ++g_failures;
        close(descriptor);
    }
#endif
}

static void test_events_and_watch_updates(void) {
    unsigned char buffer[4096];
    struct pollfd poll_descriptor;
    uint32_t from_cookie = 0;
    uint32_t to_cookie = 0;
    int ignored_count = 0;
    int named_count = 0;
    int descriptor = inotify_init1(IN_NONBLOCK);
    int watch;
    int duplicate;
    ssize_t length;
    if (descriptor < 0) {
        fail("events_init");
        return;
    }
    watch = inotify_add_watch(
        descriptor, g_directory,
        IN_CREATE | IN_OPEN | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE |
        IN_MOVED_FROM | IN_MOVED_TO);
    if (watch < 0) {
        fail("events_add_watch");
        close(descriptor);
        return;
    }
    duplicate = inotify_add_watch(descriptor, g_directory,
                                  IN_CREATE | IN_DELETE | IN_MASK_ADD);
    dprintf(STDOUT_FILENO, "duplicate_watch:%d original:%d\n", duplicate,
            watch);
    if (duplicate != watch) ++g_failures;
    errno = 0;
    expect_errno("mask_create_existing",
                 inotify_add_watch(descriptor, g_directory,
                                   IN_CREATE | IN_MASK_CREATE), EEXIST);

    memset(&poll_descriptor, 0, sizeof(poll_descriptor));
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = POLLIN | POLLOUT;
    if (poll(&poll_descriptor, 1, 0) != 0 || poll_descriptor.revents != 0)
        ++g_failures;

    if (create_file(g_first_path, "event-data") < 0 ||
        rename(g_first_path, g_second_path) < 0 ||
        unlink(g_second_path) < 0)
        fail("event_operations");
    poll_descriptor.revents = 0;
    if (poll(&poll_descriptor, 1, 1000) != 1 ||
        !(poll_descriptor.revents & POLLIN) ||
        (poll_descriptor.revents & POLLOUT))
        ++g_failures;
    length = read_available(descriptor, buffer, sizeof(buffer));
    if (length <= 0) {
        fail("events_read");
    } else {
        const struct inotify_event *first =
            (const struct inotify_event *)(const void *)buffer;
        size_t first_length = sizeof(*first) + first->len;
        if (first->mask != IN_CREATE ||
            first_length + sizeof(struct inotify_event) > (size_t)length ||
            ((const struct inotify_event *)(const void *)
                 (buffer + first_length))->mask != IN_OPEN)
            ++g_failures;
        dump_events("workflow", buffer, length, &from_cookie, &to_cookie,
                    &ignored_count, &named_count);
        if (!from_cookie || from_cookie != to_cookie || named_count < 4)
            ++g_failures;
    }

    if (inotify_rm_watch(descriptor, watch) < 0) {
        fail("rm_watch");
    } else {
        length = read_available(descriptor, buffer, sizeof(buffer));
        if (length <= 0) ++g_failures;
        else dump_events("removed", buffer, length, 0, 0,
                         &ignored_count, 0);
        if (ignored_count != 1) ++g_failures;
    }
    errno = 0;
    expect_errno("rm_watch_again", inotify_rm_watch(descriptor, watch),
                 EINVAL);
    close(descriptor);
}

static void test_record_size_and_fault(void) {
    unsigned char buffer[512];
    int descriptor = inotify_init1(IN_NONBLOCK);
    int watch;
    long result;
    if (descriptor < 0) {
        fail("record_init");
        return;
    }
    watch = inotify_add_watch(descriptor, g_directory, IN_CREATE);
    if (watch < 0 || create_file(g_first_path, "short") < 0) {
        fail("record_setup");
        close(descriptor);
        return;
    }
    errno = 0;
    expect_errno("short_event_read", read(descriptor, buffer, 8), EINVAL);
    result = read(descriptor, buffer, sizeof(buffer));
    dprintf(STDOUT_FILENO, "short_followup_rc:%ld errno:%d\n", result,
            errno);
    if (result <= 0) ++g_failures;
    unlink(g_first_path);
    (void)read_available(descriptor, buffer, sizeof(buffer));

    if (create_file(g_first_path, "fault") < 0) {
        fail("fault_setup");
    } else {
        errno = 0;
        result = syscall(SYS_read, descriptor, (void *)(uintptr_t)1,
                         sizeof(buffer));
        dprintf(STDOUT_FILENO, "fault_read_rc:%ld errno:%d\n", result,
                errno);
        if (result != -1 || errno != EFAULT) ++g_failures;
        errno = 0;
        result = read(descriptor, buffer, sizeof(buffer));
        dprintf(STDOUT_FILENO, "fault_followup_rc:%ld errno:%d\n", result,
                errno);
        if (result != -1 || errno != EAGAIN) ++g_failures;
    }
    unlink(g_first_path);
    close(descriptor);
}

static void test_instance_ids_and_oneshot(void) {
    unsigned char buffer[512];
    uint32_t masks = 0;
    int first_descriptor = inotify_init1(IN_NONBLOCK);
    int second_descriptor = inotify_init1(IN_NONBLOCK);
    int first_watch;
    int second_watch;
    ssize_t length;
    ssize_t offset = 0;

    if (first_descriptor < 0 || second_descriptor < 0) {
        fail("instance_init");
        if (first_descriptor >= 0) close(first_descriptor);
        if (second_descriptor >= 0) close(second_descriptor);
        return;
    }
    first_watch = inotify_add_watch(first_descriptor, g_directory,
                                    IN_CREATE | IN_ONESHOT);
    second_watch = inotify_add_watch(second_descriptor, g_directory,
                                     IN_CREATE);
    dprintf(STDOUT_FILENO, "instance_watch_ids:%d,%d\n",
            first_watch, second_watch);
    if (first_watch != 1 || second_watch != 1 ||
        create_file(g_first_path, "oneshot") < 0) {
        fail("instance_watch_setup");
        close(first_descriptor);
        close(second_descriptor);
        unlink(g_first_path);
        return;
    }
    length = read_available(first_descriptor, buffer, sizeof(buffer));
    while (length > 0 &&
           offset + (ssize_t)sizeof(struct inotify_event) <= length) {
        const struct inotify_event *event =
            (const struct inotify_event *)(const void *)(buffer + offset);
        size_t record = sizeof(*event) + event->len;
        if (record > (size_t)(length - offset)) {
            ++g_failures;
            break;
        }
        masks |= event->mask;
        offset += (ssize_t)record;
    }
    dprintf(STDOUT_FILENO, "oneshot_masks:0x%x bytes:%ld\n",
            masks, (long)length);
    if (length <= 0 || offset != length || !(masks & IN_CREATE) ||
        !(masks & IN_IGNORED))
        ++g_failures;
    unlink(g_first_path);
    (void)read_available(second_descriptor, buffer, sizeof(buffer));
    if (create_file(g_second_path, "after-oneshot") < 0) {
        fail("oneshot_second_create");
    } else {
        errno = 0;
        expect_errno("oneshot_followup",
                     read(first_descriptor, buffer, sizeof(buffer)), EAGAIN);
    }
    unlink(g_second_path);
    close(first_descriptor);
    close(second_descriptor);
}

static void test_watch_follows_rename(void) {
    unsigned char buffer[1024];
    uint32_t masks = 0;
    int descriptor;
    int watch;
    int file;
    ssize_t length;
    ssize_t offset = 0;

    if (create_file(g_first_path, "rename-source") < 0) {
        fail("rename_follow_create");
        return;
    }
    descriptor = inotify_init1(IN_NONBLOCK);
    watch = descriptor >= 0 ? inotify_add_watch(
        descriptor, g_first_path,
        IN_MOVE_SELF | IN_OPEN | IN_MODIFY | IN_CLOSE_WRITE |
        IN_DELETE_SELF) : -1;
    if (descriptor < 0 || watch < 0 ||
        rename(g_first_path, g_second_path) < 0) {
        fail("rename_follow_setup");
        if (descriptor >= 0) close(descriptor);
        unlink(g_first_path);
        unlink(g_second_path);
        return;
    }
    file = open(g_second_path, O_WRONLY | O_APPEND);
    if (file < 0) {
        fail("rename_follow_operations");
    } else {
        if (write(file, "x", 1) != 1)
            fail("rename_follow_write");
        if (close(file) < 0)
            fail("rename_follow_close");
    }
    if (unlink(g_second_path) < 0) fail("rename_follow_unlink");
    length = read_available(descriptor, buffer, sizeof(buffer));
    while (length > 0 &&
           offset + (ssize_t)sizeof(struct inotify_event) <= length) {
        const struct inotify_event *event =
            (const struct inotify_event *)(const void *)(buffer + offset);
        size_t record = sizeof(*event) + event->len;
        if (record > (size_t)(length - offset)) {
            ++g_failures;
            break;
        }
        dprintf(STDOUT_FILENO,
                "rename_follow_event wd:%d mask:0x%x cookie:%u len:%u\n",
                event->wd, event->mask, event->cookie, event->len);
        if (event->wd == watch) masks |= event->mask;
        offset += (ssize_t)record;
    }
    dprintf(STDOUT_FILENO, "rename_follow_masks:0x%x bytes:%ld\n", masks,
            (long)length);
    if (length <= 0 || offset != length || !(masks & IN_MOVE_SELF) ||
        !(masks & IN_OPEN) || !(masks & IN_MODIFY) || !(masks & IN_DELETE_SELF) ||
        !(masks & IN_IGNORED))
        ++g_failures;
    close(descriptor);
}

static void test_duplicate_lifetime(void) {
    unsigned char buffer[512];
    int descriptor = inotify_init1(0);
    int duplicate = descriptor >= 0 ? dup(descriptor) : -1;
    int watch;
    ssize_t result;
    if (descriptor < 0 || duplicate < 0) {
        fail("duplicate_init");
        if (descriptor >= 0) close(descriptor);
        return;
    }
    watch = inotify_add_watch(descriptor, g_directory, IN_CREATE);
    if (watch < 0 || create_file(g_first_path, "duplicate") < 0) {
        fail("duplicate_setup");
        close(descriptor);
        close(duplicate);
        return;
    }
    close(descriptor);
    result = read(duplicate, buffer, sizeof(buffer));
    dprintf(STDOUT_FILENO, "duplicate_read_rc:%ld\n", (long)result);
    if (result <= 0) ++g_failures;
    unlink(g_first_path);
    close(duplicate);
}

static void test_procfd_magic_link(void) {
    unsigned char buffer[512];
    char procfd_path[64];
    uint32_t masks = 0;
    int directory_fd;
    int descriptor;
    int watch;
    ssize_t length;
    ssize_t offset = 0;

    directory_fd = open(g_directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
    descriptor = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (directory_fd < 0 || descriptor < 0) {
        fail("procfd_init");
        if (directory_fd >= 0) close(directory_fd);
        if (descriptor >= 0) close(descriptor);
        return;
    }
    snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d",
             directory_fd);
    watch = inotify_add_watch(descriptor, procfd_path, IN_CREATE);
    dprintf(STDOUT_FILENO, "procfd_watch:%d errno:%d path:%s\n",
            watch, errno, procfd_path);
    if (watch < 0 || create_file(g_first_path, "procfd") < 0) {
        fail("procfd_watch_setup");
        close(descriptor);
        close(directory_fd);
        unlink(g_first_path);
        return;
    }
    length = read_available(descriptor, buffer, sizeof(buffer));
    while (length > 0 &&
           offset + (ssize_t)sizeof(struct inotify_event) <= length) {
        const struct inotify_event *event =
            (const struct inotify_event *)(const void *)(buffer + offset);
        size_t record = sizeof(*event) + event->len;
        if (record > (size_t)(length - offset)) {
            ++g_failures;
            break;
        }
        if (event->wd == watch) masks |= event->mask;
        offset += (ssize_t)record;
    }
    dprintf(STDOUT_FILENO, "procfd_masks:0x%x bytes:%ld\n", masks,
            (long)length);
    if (length <= 0 || offset != length || !(masks & IN_CREATE))
        ++g_failures;
    unlink(g_first_path);
    close(descriptor);
    close(directory_fd);
}

static void *blocking_reader(void *unused) {
    (void)unused;
    atomic_store_explicit(&g_reader_started, 1, memory_order_release);
    errno = 0;
    g_reader_result = read(g_blocking_fd, g_reader_buffer,
                           sizeof(g_reader_buffer));
    g_reader_errno = errno;
    return 0;
}

static void test_blocking_read(void) {
    pthread_t thread;
    int watch;
    g_blocking_fd = inotify_init1(0);
    g_reader_result = -2;
    g_reader_errno = 0;
    atomic_store(&g_reader_started, 0);
    if (g_blocking_fd < 0) {
        fail("blocking_init");
        return;
    }
    watch = inotify_add_watch(g_blocking_fd, g_directory, IN_CREATE);
    if (watch < 0 || pthread_create(&thread, 0, blocking_reader, 0) != 0) {
        fail("blocking_setup");
        close(g_blocking_fd);
        return;
    }
    while (!atomic_load_explicit(&g_reader_started, memory_order_acquire))
        sched_yield();
    usleep(10000);
    if (create_file(g_first_path, "blocking") < 0)
        fail("blocking_create_file");
    if (pthread_join(thread, 0) != 0) ++g_failures;
    dprintf(STDOUT_FILENO, "blocking_read_rc:%ld errno:%d\n",
            (long)g_reader_result, g_reader_errno);
    if (g_reader_result <= 0 || g_reader_errno != 0) ++g_failures;
    unlink(g_first_path);
    close(g_blocking_fd);
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    snprintf(g_directory, sizeof(g_directory), "/tmp/edgeos-inotify-%ld",
             (long)getpid());
    snprintf(g_first_path, sizeof(g_first_path), "%s/first", g_directory);
    snprintf(g_second_path, sizeof(g_second_path), "%s/second", g_directory);
    if (mkdir(g_directory, 0700) < 0) {
        fail("mkdir");
        return 1;
    }
    test_create_and_validation();
    test_events_and_watch_updates();
    test_record_size_and_fault();
    test_instance_ids_and_oneshot();
    test_watch_follows_rename();
    test_duplicate_lifetime();
    test_procfd_magic_link();
    test_blocking_read();
    unlink(g_first_path);
    unlink(g_second_path);
    rmdir(g_directory);
    dprintf(STDOUT_FILENO, "inotify_abi:%s failures:%d\n",
            g_failures ? "FAIL" : "OK", g_failures);
    return g_failures ? 1 : 0;
}
