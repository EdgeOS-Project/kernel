/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void expect_long(const char *name, long actual, long expected) {
    printf("%s:%ld\n", name, actual);
    if (actual != expected) {
        fprintf(stderr, "%s: expected %ld, got %ld\n",
                name, expected, actual);
        ++failures;
    }
}

static void expect_errno(const char *name, long result, int expected) {
    int error = errno;
    printf("%s_rc:%ld errno:%d\n", name, result, error);
    if (result != -1 || error != expected) {
        fprintf(stderr, "%s: expected -1/%d, got %ld/%d\n",
                name, expected, result, error);
        ++failures;
    }
}

static uint64_t signal_bit(int signal_number) {
    return UINT64_C(1) << (signal_number - 1);
}

static long raw_signalfd4(int descriptor, const uint64_t *mask,
                          size_t mask_size, int flags) {
    errno = 0;
    return syscall(SYS_signalfd4, descriptor, mask, mask_size, flags);
}

static int block_signal_set(sigset_t *old_mask) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGRTMIN);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, old_mask) < 0) {
        perror("sigprocmask(SIG_BLOCK)");
        return -1;
    }
    return 0;
}

static void drain_signal(int signal_number) {
    sigset_t mask;
    struct timespec timeout = {0, 0};
    sigemptyset(&mask);
    sigaddset(&mask, signal_number);
    while (sigtimedwait(&mask, 0, &timeout) >= 0) { }
}

static int send_signal(int signal_number) {
    if (kill(getpid(), signal_number) < 0) {
        perror("kill(self)");
        ++failures;
        return -1;
    }
    return 0;
}

static void test_argument_validation(void) {
    uint64_t mask = signal_bit(SIGUSR1);
    long result;

    result = raw_signalfd4(-1, 0, sizeof(mask), 0);
    expect_errno("null_mask", result, EFAULT);
    result = raw_signalfd4(-1, &mask, sizeof(mask) - 1u, 0);
    expect_errno("short_mask_size", result, EINVAL);
    result = raw_signalfd4(-1, &mask, sizeof(mask) + 8u, 0);
    expect_errno("long_mask_size", result, EINVAL);
    result = raw_signalfd4(-1, &mask, sizeof(mask), 0x40000000);
    expect_errno("bad_flags", result, EINVAL);
    result = raw_signalfd4(-2, &mask, sizeof(mask), 0);
    expect_errno("negative_descriptor", result, EBADF);

    {
        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd < 0) {
            perror("open(/dev/null)");
            ++failures;
        } else {
            result = raw_signalfd4(null_fd, &mask, sizeof(mask), 0);
            expect_errno("wrong_descriptor_type", result, EINVAL);
            close(null_fd);
        }
    }
}

static void test_descriptor_flags_and_basic_read(void) {
    const uint64_t mask = signal_bit(SIGUSR1) | signal_bit(SIGKILL) |
                          signal_bit(SIGSTOP);
    struct signalfd_siginfo info;
    struct pollfd poll_descriptor;
    int descriptor;
    long result;

    descriptor = (int)raw_signalfd4(
        -1, &mask, sizeof(mask), SFD_NONBLOCK | SFD_CLOEXEC);
    if (descriptor < 0) {
        perror("signalfd4(flags)");
        ++failures;
        return;
    }
    expect_long("descriptor_nonblock",
                !!(fcntl(descriptor, F_GETFL) & O_NONBLOCK), 1);
    expect_long("descriptor_cloexec",
                !!(fcntl(descriptor, F_GETFD) & FD_CLOEXEC), 1);

    errno = 0;
    result = read(descriptor, &info, sizeof(info));
    expect_errno("empty_read", result, EAGAIN);
    errno = 0;
    result = read(descriptor, &info, sizeof(info) - 1u);
    expect_errno("empty_short_read", result, EINVAL);
    errno = 0;
    result = write(descriptor, &info, sizeof(info));
    expect_errno("write", result, EINVAL);

    if (send_signal(SIGUSR1) == 0) {
        poll_descriptor.fd = descriptor;
        poll_descriptor.events = POLLIN;
        poll_descriptor.revents = 0;
        result = poll(&poll_descriptor, 1, 0);
        expect_long("poll_ready", result, 1);
        expect_long("poll_revents", poll_descriptor.revents, POLLIN);

        errno = 0;
        result = read(descriptor, &info, sizeof(info) - 1u);
        expect_errno("queued_short_read", result, EINVAL);
        memset(&info, 0xa5, sizeof(info));
        result = read(descriptor, &info, sizeof(info));
        expect_long("basic_read", result, sizeof(info));
        expect_long("basic_signo", info.ssi_signo, SIGUSR1);
        expect_long("basic_errno", info.ssi_errno, 0);
        expect_long("basic_code", info.ssi_code, SI_USER);
        expect_long("basic_pid", info.ssi_pid, getpid());
        expect_long("basic_uid", info.ssi_uid, getuid());
    }
    close(descriptor);
}

static void test_coalescing_and_multiple_records(void) {
    const uint64_t mask = signal_bit(SIGUSR1) | signal_bit(SIGUSR2);
    struct signalfd_siginfo records[3];
    int descriptor = (int)raw_signalfd4(
        -1, &mask, sizeof(mask), SFD_NONBLOCK);
    long result;
    if (descriptor < 0) {
        perror("signalfd4(multiple)");
        ++failures;
        return;
    }

    if (send_signal(SIGUSR1) == 0 && send_signal(SIGUSR1) == 0) {
        memset(records, 0, sizeof(records));
        result = read(descriptor, records, sizeof(records));
        expect_long("coalesced_read", result, sizeof(records[0]));
        expect_long("coalesced_signo", records[0].ssi_signo, SIGUSR1);
    }

    if (send_signal(SIGUSR2) == 0 && send_signal(SIGUSR1) == 0) {
        memset(records, 0, sizeof(records));
        result = read(descriptor, records, sizeof(records));
        expect_long("multiple_read", result, 2 * sizeof(records[0]));
        expect_long("multiple_first", records[0].ssi_signo, SIGUSR1);
        expect_long("multiple_second", records[1].ssi_signo, SIGUSR2);
    }
    close(descriptor);
}

static void test_fault_consumption(void) {
    const uint64_t mask = signal_bit(SIGUSR1);
    struct signalfd_siginfo info;
    void *fault_page;
    int descriptor = (int)raw_signalfd4(
        -1, &mask, sizeof(mask), SFD_NONBLOCK);
    long result;
    if (descriptor < 0) {
        perror("signalfd4(fault)");
        ++failures;
        return;
    }
    fault_page = mmap(0, 4096, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fault_page == MAP_FAILED) {
        perror("mmap(PROT_NONE)");
        ++failures;
        close(descriptor);
        return;
    }
    if (send_signal(SIGUSR1) == 0) {
        errno = 0;
        result = read(descriptor, fault_page, sizeof(info));
        expect_errno("fault_read", result, EFAULT);
        errno = 0;
        result = read(descriptor, &info, sizeof(info));
        expect_errno("fault_followup", result, EAGAIN);
    }
    munmap(fault_page, 4096);
    close(descriptor);
    drain_signal(SIGUSR1);
}

static void test_descriptor_update(void) {
    uint64_t mask = signal_bit(SIGUSR1);
    struct signalfd_siginfo info;
    int descriptor = (int)raw_signalfd4(-1, &mask, sizeof(mask), 0);
    int duplicate;
    long result;
    if (descriptor < 0) {
        perror("signalfd4(update)");
        ++failures;
        return;
    }
    duplicate = dup(descriptor);
    if (duplicate < 0) {
        perror("dup(signalfd)");
        ++failures;
        close(descriptor);
        return;
    }
    mask = signal_bit(SIGUSR2);
    result = raw_signalfd4(descriptor, &mask, sizeof(mask),
                          SFD_NONBLOCK | SFD_CLOEXEC);
    expect_long("update_result", result, descriptor);
    expect_long("update_original_nonblock",
                !!(fcntl(descriptor, F_GETFL) & O_NONBLOCK), 0);
    expect_long("update_duplicate_nonblock",
                !!(fcntl(duplicate, F_GETFL) & O_NONBLOCK), 0);
    expect_long("update_original_cloexec",
                !!(fcntl(descriptor, F_GETFD) & FD_CLOEXEC), 0);

    if (send_signal(SIGUSR1) == 0 && send_signal(SIGUSR2) == 0) {
        memset(&info, 0, sizeof(info));
        result = read(duplicate, &info, sizeof(info));
        expect_long("updated_read", result, sizeof(info));
        expect_long("updated_signo", info.ssi_signo, SIGUSR2);
    }
    close(duplicate);
    close(descriptor);
    drain_signal(SIGUSR1);
}

static void test_realtime_queue(void) {
    const int realtime_signal = SIGRTMIN;
    const uint64_t mask = signal_bit(realtime_signal);
    struct signalfd_siginfo records[2];
    union sigval value;
    int descriptor = (int)raw_signalfd4(
        -1, &mask, sizeof(mask), SFD_NONBLOCK);
    long result;
    if (descriptor < 0) {
        perror("signalfd4(realtime)");
        ++failures;
        return;
    }
    value.sival_int = 11;
    if (sigqueue(getpid(), realtime_signal, value) < 0) {
        perror("sigqueue(11)");
        ++failures;
    }
    value.sival_int = 22;
    if (sigqueue(getpid(), realtime_signal, value) < 0) {
        perror("sigqueue(22)");
        ++failures;
    }
    memset(records, 0, sizeof(records));
    result = read(descriptor, records, sizeof(records));
    expect_long("realtime_read", result, sizeof(records));
    if (result >= (long)sizeof(records[0])) {
        expect_long("realtime_first_signo", records[0].ssi_signo,
                    realtime_signal);
        expect_long("realtime_first_code", records[0].ssi_code, SI_QUEUE);
        expect_long("realtime_first_value", records[0].ssi_int, 11);
    }
    if (result >= (long)sizeof(records)) {
        expect_long("realtime_second_signo", records[1].ssi_signo,
                    realtime_signal);
        expect_long("realtime_second_code", records[1].ssi_code, SI_QUEUE);
        expect_long("realtime_second_value", records[1].ssi_int, 22);
    }
    close(descriptor);
    drain_signal(realtime_signal);
}

static void test_thread_directed_record(void) {
    const uint64_t mask = signal_bit(SIGUSR1);
    struct signalfd_siginfo info;
    int descriptor = (int)raw_signalfd4(
        -1, &mask, sizeof(mask), SFD_NONBLOCK);
    long result;
    if (descriptor < 0) {
        perror("signalfd4(tgkill)");
        ++failures;
        return;
    }
    errno = 0;
    result = syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
    expect_long("tgkill_send", result, 0);
    memset(&info, 0, sizeof(info));
    result = read(descriptor, &info, sizeof(info));
    expect_long("tgkill_read", result, sizeof(info));
    if (result == (long)sizeof(info)) {
        expect_long("tgkill_signo", info.ssi_signo, SIGUSR1);
        expect_long("tgkill_code", info.ssi_code, SI_TKILL);
        expect_long("tgkill_pid", info.ssi_pid, getpid());
        expect_long("tgkill_uid", info.ssi_uid, getuid());
    }
    close(descriptor);
    drain_signal(SIGUSR1);
}

static void test_child_exit_record(void) {
    const uint64_t mask = signal_bit(SIGCHLD);
    struct signalfd_siginfo info;
    struct pollfd poll_descriptor;
    int status = 0;
    int descriptor = (int)raw_signalfd4(
        -1, &mask, sizeof(mask), SFD_NONBLOCK);
    pid_t child;
    long result;
    if (descriptor < 0) {
        perror("signalfd4(SIGCHLD)");
        ++failures;
        return;
    }
    child = fork();
    if (child < 0) {
        perror("fork(SIGCHLD)");
        ++failures;
        close(descriptor);
        return;
    }
    if (child == 0) _exit(42);
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = POLLIN;
    poll_descriptor.revents = 0;
    result = poll(&poll_descriptor, 1, 5000);
    expect_long("child_poll", result, 1);
    memset(&info, 0, sizeof(info));
    result = read(descriptor, &info, sizeof(info));
    expect_long("child_read", result, sizeof(info));
    if (result == (long)sizeof(info)) {
        expect_long("child_signo", info.ssi_signo, SIGCHLD);
        expect_long("child_code", info.ssi_code, CLD_EXITED);
        expect_long("child_pid", info.ssi_pid, child);
        expect_long("child_uid", info.ssi_uid, getuid());
        expect_long("child_status", info.ssi_status, 42);
    }
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid(SIGCHLD)");
        ++failures;
    } else {
        expect_long("child_wait_exited", WIFEXITED(status), 1);
        expect_long("child_wait_status", WEXITSTATUS(status), 42);
    }
    close(descriptor);
    drain_signal(SIGCHLD);
}

static void test_timer_record(void) {
    const int realtime_signal = SIGRTMIN;
    const uint64_t mask = signal_bit(realtime_signal);
    struct signalfd_siginfo info;
    struct pollfd poll_descriptor;
    struct sigevent event;
    struct itimerspec value;
    timer_t timer;
    int descriptor = (int)raw_signalfd4(
        -1, &mask, sizeof(mask), SFD_NONBLOCK);
    long result;
    if (descriptor < 0) {
        perror("signalfd4(timer)");
        ++failures;
        return;
    }
    memset(&event, 0, sizeof(event));
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = realtime_signal;
    event.sigev_value.sival_int = 77;
    if (timer_create(CLOCK_MONOTONIC, &event, &timer) < 0) {
        perror("timer_create");
        ++failures;
        close(descriptor);
        return;
    }
    memset(&value, 0, sizeof(value));
    value.it_value.tv_nsec = 20000000;
    if (timer_settime(timer, 0, &value, 0) < 0) {
        perror("timer_settime");
        ++failures;
        timer_delete(timer);
        close(descriptor);
        return;
    }
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = POLLIN;
    poll_descriptor.revents = 0;
    result = poll(&poll_descriptor, 1, 5000);
    expect_long("timer_poll", result, 1);
    memset(&info, 0, sizeof(info));
    result = read(descriptor, &info, sizeof(info));
    expect_long("timer_read", result, sizeof(info));
    if (result == (long)sizeof(info)) {
        expect_long("timer_signo", info.ssi_signo, realtime_signal);
        expect_long("timer_code", info.ssi_code, SI_TIMER);
        expect_long("timer_value", info.ssi_int, 77);
        expect_long("timer_overrun", info.ssi_overrun, 0);
    }
    timer_delete(timer);
    close(descriptor);
    drain_signal(realtime_signal);
}

static void test_legacy_entry(void) {
#ifdef SYS_signalfd
    uint64_t mask = signal_bit(SIGUSR1);
    long descriptor;
    errno = 0;
    descriptor = syscall(SYS_signalfd, -1, &mask, sizeof(mask));
    printf("legacy_signalfd_rc:%ld errno:%d\n", descriptor, errno);
    if (descriptor < 0) {
        ++failures;
    } else {
        expect_long("legacy_status_flags",
                    !!(fcntl((int)descriptor, F_GETFL) & O_NONBLOCK), 0);
        expect_long("legacy_descriptor_flags",
                    !!(fcntl((int)descriptor, F_GETFD) & FD_CLOEXEC), 0);
        close((int)descriptor);
    }
#endif
}

int main(void) {
    sigset_t old_mask;
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    if (block_signal_set(&old_mask) < 0) return 1;
    test_argument_validation();
    test_descriptor_flags_and_basic_read();
    test_coalescing_and_multiple_records();
    test_fault_consumption();
    test_descriptor_update();
    test_realtime_queue();
    test_thread_directed_record();
    test_child_exit_record();
    test_timer_record();
    test_legacy_entry();
    drain_signal(SIGUSR1);
    drain_signal(SIGUSR2);
    drain_signal(SIGRTMIN);
    if (sigprocmask(SIG_SETMASK, &old_mask, 0) < 0) {
        perror("sigprocmask(SIG_SETMASK)");
        ++failures;
    }
    printf("signalfd_abi:%s failures:%d\n",
           failures ? "FAIL" : "OK", failures);
    return failures ? 1 : 0;
}
