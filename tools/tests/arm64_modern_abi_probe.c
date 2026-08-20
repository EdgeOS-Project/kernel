/* SPDX-License-Identifier: MPL-2.0 */
/*
 * EdgeOS ARM64 modern Linux syscall integration test.
 * Copyright (c) EdgeOS Contributors.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif

#define ARM64_SYS_PIDFD_OPEN 434
#define ARM64_SYS_PIDFD_SEND_SIGNAL 424
#define ARM64_SYS_CLONE3 435
#define ARM64_SYS_OPENAT2 437
#define ARM64_SYS_PIDFD_GETFD 438
#define ARM64_SYS_PROCESS_MADVISE 440
#define ARM64_SYS_EPOLL_PWAIT2 441
#define ARM64_SYS_FCHMODAT2 452
#define ARM64_SYS_FUTEX_WAITV 449
#define ARM64_SYS_EXECVEAT 281
#define ARM64_SYS_RT_TGSIGQUEUEINFO 240
#define ARM64_SYS_PKEY_MPROTECT 288
#define ARM64_SYS_PKEY_ALLOC 289
#define ARM64_SYS_PKEY_FREE 290
#define ARM64_SYS_RSEQ 293
#define ARM64_SYS_SETNS 268

#ifndef AT_RSEQ_FEATURE_SIZE
#define AT_RSEQ_FEATURE_SIZE 27
#define AT_RSEQ_ALIGN 28
#endif

#define LINUX_CLONE_PIDFD 0x00001000ULL
#define LINUX_FUTEX_32 0x02u
#define LINUX_FUTEX_PRIVATE 0x80u
#define LINUX_FUTEX_WAKE_PRIVATE 0x81u
#define LINUX_CLONE_NEWUTS 0x04000000u
#define LINUX_CLONE_NEWNET 0x40000000u
#define LINUX_NS_GET_NSTYPE 0xb703u
#define LINUX_NSFS_MAGIC 0x6e736673u

struct open_how_abi {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct clone_args_abi {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

struct futex_waitv_abi {
    uint64_t value;
    uint64_t address;
    uint32_t flags;
    uint32_t reserved;
};

struct rseq_abi {
    uint32_t cpu_id_start;
    uint32_t cpu_id;
    uint64_t rseq_cs;
    uint32_t flags;
    uint32_t node_id;
    uint32_t mm_cid;
    uint32_t reserved;
} __attribute__((aligned(32)));

static int failures;

static void check(int condition, const char *name) {
    if (condition) {
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s errno=%d (%s)\n", name, errno, strerror(errno));
        failures++;
    }
}

static int write_all(int fd, const void *buffer, size_t length) {
    const unsigned char *bytes = buffer;
    while (length) {
        ssize_t written = write(fd, bytes, length);
        if (written <= 0) return -1;
        bytes += written;
        length -= (size_t)written;
    }
    return 0;
}

static void test_openat2(void) {
    const char *path = "/tmp/edgeos-openat2";
    const char payload[] = "openat2-data";
    struct {
        struct open_how_abi how;
        uint64_t extension;
    } request;
    char result[sizeof(payload)] = {0};
    int seed;
    int fd;

    unlink(path);
    seed = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    check(seed >= 0 && write_all(seed, payload, sizeof(payload)) == 0,
          "openat2 seed file");
    if (seed >= 0) close(seed);

    memset(&request, 0, sizeof(request));
    request.how.flags = O_RDONLY;
    fd = (int)syscall(ARM64_SYS_OPENAT2, AT_FDCWD, path, &request,
                      sizeof(request));
    check(fd >= 0 && read(fd, result, sizeof(result)) == sizeof(result) &&
              memcmp(result, payload, sizeof(payload)) == 0,
          "openat2 zero-extended request");
    if (fd >= 0) close(fd);

    request.extension = 1;
    errno = 0;
    fd = (int)syscall(ARM64_SYS_OPENAT2, AT_FDCWD, path, &request,
                      sizeof(request));
    check(fd == -1 && errno == E2BIG, "openat2 rejects nonzero extension");
    unlink(path);
}

static void test_renameat2(void) {
    const char *source = "/tmp/edgeos-rename-source";
    const char *target = "/tmp/edgeos-rename-target";
    int fd;
    int result;
    unlink(source);
    unlink(target);
    fd = open(source, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
    fd = open(target, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
    errno = 0;
    result = (int)syscall(SYS_renameat2, AT_FDCWD, source, AT_FDCWD,
                          target, RENAME_NOREPLACE);
    check(result == -1 && errno == EEXIST,
          "renameat2 RENAME_NOREPLACE collision");
    unlink(target);
    result = (int)syscall(SYS_renameat2, AT_FDCWD, source, AT_FDCWD,
                          target, RENAME_NOREPLACE);
    check(result == 0 && access(target, F_OK) == 0,
          "renameat2 RENAME_NOREPLACE success");
    unlink(source);
    unlink(target);
}

static void test_fchmodat2(void) {
    const char *path = "/tmp/edgeos-fchmodat2";
    struct stat status;
    int fd;
    int result;
    int stat_result;
    int saved_errno;
    unlink(path);
    fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    errno = 0;
    result = fd < 0 ? -1 :
        (int)syscall(ARM64_SYS_FCHMODAT2, fd, "", 0600, AT_EMPTY_PATH);
    saved_errno = errno;
    stat_result = fd < 0 ? -1 : fstat(fd, &status);
    if (result != 0 || stat_result != 0 || (status.st_mode & 0777) != 0600)
        printf("INFO fchmodat2 fd=%d result=%d syscall_errno=%d "
               "fstat=%d fstat_errno=%d mode=%o\n",
               fd, result, saved_errno, stat_result, errno,
               stat_result == 0 ? (unsigned)(status.st_mode & 07777) : 0u);
    errno = result != 0 ? saved_errno : errno;
    check(result == 0 && stat_result == 0 &&
              (status.st_mode & 0777) == 0600,
          "fchmodat2 AT_EMPTY_PATH");
    if (fd >= 0) close(fd);
    unlink(path);
}

static void test_copy_file_range(void) {
    const char *input_path = "/tmp/edgeos-copy-input";
    const char *output_path = "/tmp/edgeos-copy-output";
    const char payload[] = "copy-file-range-payload";
    char result[sizeof(payload)] = {0};
    off_t input_offset = 0;
    off_t output_offset = 0;
    ssize_t copied;
    int input;
    int output;
    unlink(input_path);
    unlink(output_path);
    input = open(input_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    output = open(output_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (input >= 0) {
        write_all(input, payload, sizeof(payload));
        lseek(input, 0, SEEK_SET);
    }
    copied = syscall(SYS_copy_file_range, input, &input_offset, output,
                     &output_offset, sizeof(payload), 0);
    if (output >= 0) {
        lseek(output, 0, SEEK_SET);
        (void)read(output, result, sizeof(result));
    }
    check(copied == sizeof(payload) && input_offset == sizeof(payload) &&
              output_offset == sizeof(payload) &&
              memcmp(result, payload, sizeof(payload)) == 0,
          "copy_file_range data and offsets");
    if (input >= 0) close(input);
    if (output >= 0) close(output);
    unlink(input_path);
    unlink(output_path);
}

static void test_epoll_pwait2(void) {
    int descriptors[2] = {-1, -1};
    int epoll_fd = -1;
    struct epoll_event requested;
    struct epoll_event returned;
    struct timespec timeout = {1, 250000};
    char byte = 'x';
    int ready;
    if (pipe(descriptors) == 0) epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    memset(&requested, 0, sizeof(requested));
    requested.events = EPOLLIN;
    requested.data.u64 = 0x12345678ULL;
    if (epoll_fd >= 0)
        (void)epoll_ctl(epoll_fd, EPOLL_CTL_ADD, descriptors[0], &requested);
    if (descriptors[1] >= 0) (void)write(descriptors[1], &byte, 1);
    memset(&returned, 0, sizeof(returned));
    ready = epoll_fd < 0 ? -1 :
        (int)syscall(ARM64_SYS_EPOLL_PWAIT2, epoll_fd, &returned, 1,
                     &timeout, 0, sizeof(uint64_t));
    check(ready == 1 && (returned.events & EPOLLIN) &&
              returned.data.u64 == requested.data.u64,
          "epoll_pwait2 nanosecond timeout ABI");
    if (epoll_fd >= 0) close(epoll_fd);
    if (descriptors[0] >= 0) close(descriptors[0]);
    if (descriptors[1] >= 0) close(descriptors[1]);
}

static void test_pidfd_and_process_vm(void) {
    int ready_pipe[2] = {-1, -1};
    int done_pipe[2] = {-1, -1};
    volatile uint64_t shared_value = 0x1122334455667788ULL;
    pid_t child;

    if (pipe(ready_pipe) < 0 || pipe(done_pipe) < 0) {
        check(0, "pidfd/process_vm setup");
        return;
    }
    child = fork();
    if (child == 0) {
        const char *path = "/tmp/edgeos-pidfd-target";
        int target_fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
        char signal_byte = 'r';
        if (target_fd >= 0) write_all(target_fd, "pidfd-data", 11);
        if (target_fd >= 0) lseek(target_fd, 0, SEEK_SET);
        write_all(ready_pipe[1], &target_fd, sizeof(target_fd));
        (void)read(done_pipe[0], &signal_byte, 1);
        _exit(shared_value == 0xaabbccddeeff0011ULL ? 0 : 3);
    }
    if (child < 0) {
        check(0, "pidfd/process_vm fork");
    } else {
        int target_fd = -1;
        int pidfd;
        int duplicate;
        char payload[11] = {0};
        uint64_t observed = 0;
        uint64_t replacement = 0xaabbccddeeff0011ULL;
        struct iovec local = {&observed, sizeof(observed)};
        struct iovec remote = {(void *)&shared_value, sizeof(shared_value)};
        struct iovec write_local = {&replacement, sizeof(replacement)};
        ssize_t read_bytes;
        ssize_t written_bytes;
        int status = 0;
        (void)read(ready_pipe[0], &target_fd, sizeof(target_fd));
        pidfd = (int)syscall(ARM64_SYS_PIDFD_OPEN, child, 0);
        duplicate = pidfd < 0 ? -1 :
            (int)syscall(ARM64_SYS_PIDFD_GETFD, pidfd, target_fd, 0);
        if (duplicate >= 0) (void)read(duplicate, payload, sizeof(payload));
        check(duplicate >= 0 && memcmp(payload, "pidfd-data", 11) == 0,
              "pidfd_getfd duplicates live file description");

        read_bytes = process_vm_readv(child, &local, 1, &remote, 1, 0);
        written_bytes = process_vm_writev(child, &write_local, 1,
                                          &remote, 1, 0);
        check(read_bytes == sizeof(observed) &&
                  observed == 0x1122334455667788ULL,
              "process_vm_readv remote data");
        check(written_bytes == sizeof(replacement),
              "process_vm_writev remote data");
        (void)write(done_pipe[1], "d", 1);
        (void)waitpid(child, &status, 0);
        check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "process_vm_writev visible in target");
        if (duplicate >= 0) close(duplicate);
        if (pidfd >= 0) close(pidfd);
        unlink("/tmp/edgeos-pidfd-target");
    }
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    close(done_pipe[0]);
    close(done_pipe[1]);
}

static void test_clone3_and_execveat(void) {
    struct clone_args_abi arguments;
    int pidfd = -1;
    int status = 0;
    pid_t child;

    memset(&arguments, 0, sizeof(arguments));
    arguments.flags = LINUX_CLONE_PIDFD;
    arguments.pidfd = (uintptr_t)&pidfd;
    arguments.exit_signal = SIGCHLD;
    child = (pid_t)syscall(ARM64_SYS_CLONE3, &arguments, sizeof(arguments));
    if (child == 0) _exit(42);
    check(child > 0 && pidfd >= 0, "clone3 returns child and pidfd");
    if (child > 0) (void)waitpid(child, &status, 0);
    check(child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 42,
          "clone3 child execution and wait semantics");
    if (pidfd >= 0) {
        errno = 0;
        check(syscall(ARM64_SYS_PIDFD_SEND_SIGNAL, pidfd, 0, 0, 0) == -1 &&
                  errno == ESRCH,
              "clone3 pidfd observes child exit");
        close(pidfd);
    }

    child = fork();
    if (child == 0) {
        int executable = open("/bin/true", O_RDONLY | O_CLOEXEC);
        char *const argv[] = {(char *)"true", NULL};
        char *const envp[] = {(char *)"PATH=/usr/bin:/bin", NULL};
        if (executable >= 0)
            (void)syscall(ARM64_SYS_EXECVEAT, executable, "", argv, envp,
                          AT_EMPTY_PATH);
        _exit(111);
    }
    status = 0;
    if (child > 0) (void)waitpid(child, &status, 0);
    check(child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "execveat AT_EMPTY_PATH executes ELF image");
}

static void test_queued_signals(void) {
    const int signal_number = SIGRTMIN;
    sigset_t blocked;
    sigset_t pending;
    siginfo_t queued;
    siginfo_t received;
    struct timespec timeout = {0, 100000000};
    union sigval first_value;
    int first;
    int second;

    sigemptyset(&blocked);
    sigaddset(&blocked, signal_number);
    check(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0,
          "realtime signal mask setup");
    first_value.sival_int = 0x13579bdf;
    check(sigqueue(getpid(), signal_number, first_value) == 0,
          "rt_sigqueueinfo queues realtime payload");
    sigemptyset(&pending);
    check(sigpending(&pending) == 0 && sigismember(&pending, signal_number),
          "rt_sigpending reports blocked queued signal");

    memset(&queued, 0, sizeof(queued));
    queued.si_signo = signal_number;
    queued.si_code = SI_QUEUE;
    queued.si_pid = getpid();
    queued.si_uid = getuid();
    queued.si_value.sival_int = 0x2468ace0;
    check(syscall(ARM64_SYS_RT_TGSIGQUEUEINFO, getpid(),
                  (pid_t)syscall(SYS_gettid), signal_number, &queued) == 0,
          "rt_tgsigqueueinfo queues thread payload");

    memset(&received, 0, sizeof(received));
    first = sigtimedwait(&blocked, &received, &timeout);
    check(first == signal_number && received.si_code == SI_QUEUE &&
              received.si_value.sival_int == 0x2468ace0,
          "sigtimedwait returns thread-directed siginfo first");
    memset(&received, 0, sizeof(received));
    second = sigtimedwait(&blocked, &received, &timeout);
    check(second == signal_number && received.si_code == SI_QUEUE &&
              received.si_value.sival_int == 0x13579bdf,
          "sigtimedwait preserves process-directed siginfo");
    errno = 0;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 1000000;
    check(sigtimedwait(&blocked, &received, &timeout) == -1 &&
              errno == EAGAIN,
          "sigtimedwait expires with EAGAIN");
    (void)sigprocmask(SIG_UNBLOCK, &blocked, NULL);
}

static _Atomic uint32_t futex_words[2];

static void *wake_second_futex(void *unused) {
    const struct timespec delay = {0, 20000000};
    (void)unused;
    (void)nanosleep(&delay, NULL);
    atomic_store_explicit(&futex_words[1], 1u, memory_order_release);
    (void)syscall(SYS_futex, &futex_words[1], LINUX_FUTEX_WAKE_PRIVATE,
                  1, NULL, NULL, 0);
    return NULL;
}

static void deadline_after(struct timespec *deadline, long nanoseconds) {
    (void)clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_nsec += nanoseconds;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

static void test_futex_waitv(void) {
    struct futex_waitv_abi waiters[2];
    struct timespec deadline;
    pthread_t thread;
    int thread_result;
    int thread_started;
    int result;

    atomic_store(&futex_words[0], 0u);
    atomic_store(&futex_words[1], 0u);
    memset(waiters, 0, sizeof(waiters));
    for (size_t index = 0; index < 2; ++index) {
        waiters[index].address = (uintptr_t)&futex_words[index];
        waiters[index].flags = LINUX_FUTEX_32 | LINUX_FUTEX_PRIVATE;
    }
    deadline_after(&deadline, 1000000000L);
    thread_result = pthread_create(&thread, NULL, wake_second_futex, NULL);
    thread_started = thread_result == 0;
    result = -1;
    if (thread_started)
        result = (int)syscall(ARM64_SYS_FUTEX_WAITV, waiters, 2, 0,
                              &deadline, CLOCK_MONOTONIC);
    if (result != 1)
        printf("DETAIL futex_waitv wake result=%d errno=%d pthread=%d\n",
               result, errno, thread_result);
    check(result == 1, "futex_waitv returns woken vector index");
    if (thread_started) (void)pthread_join(thread, NULL);

    atomic_store(&futex_words[0], 1u);
    errno = 0;
    result = (int)syscall(ARM64_SYS_FUTEX_WAITV, waiters, 1, 0,
                          NULL, CLOCK_MONOTONIC);
    check(result == -1 && errno == EAGAIN,
          "futex_waitv detects value mismatch");
    atomic_store(&futex_words[0], 0u);
    deadline_after(&deadline, 2000000L);
    errno = 0;
    result = (int)syscall(ARM64_SYS_FUTEX_WAITV, waiters, 1, 0,
                          &deadline, CLOCK_MONOTONIC);
    check(result == -1 && errno == ETIMEDOUT,
          "futex_waitv absolute timeout");
}

static void test_process_madvise(void) {
    const size_t page_size = 4096;
    unsigned char *page;
    struct iovec range;
    int pidfd;
    long advised;

    page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pidfd = (int)syscall(ARM64_SYS_PIDFD_OPEN, getpid(), 0);
    if (page != MAP_FAILED) memset(page, 0xa5, page_size);
    range.iov_base = page;
    range.iov_len = page_size;
    advised = page == MAP_FAILED || pidfd < 0 ? -1 :
        syscall(ARM64_SYS_PROCESS_MADVISE, pidfd, &range, 1,
                MADV_DONTNEED, 0);
    check(advised == (long)page_size && page[0] == 0 &&
              page[page_size - 1] == 0,
          "process_madvise discards target pages");
    if (pidfd >= 0) close(pidfd);
    if (page != MAP_FAILED) munmap(page, page_size);
}

static int timeval_not_before(const struct timeval *after,
                              const struct timeval *before) {
    return after->tv_sec > before->tv_sec ||
           (after->tv_sec == before->tv_sec &&
            after->tv_usec >= before->tv_usec);
}

static void test_process_accounting(void) {
    struct tms before_times;
    struct tms after_times;
    struct rusage before_usage;
    struct rusage after_usage;
    struct timespec start;
    struct timespec now;
    volatile uint64_t accumulator = 1;

    memset(&before_times, 0, sizeof(before_times));
    memset(&after_times, 0, sizeof(after_times));
    memset(&before_usage, 0, sizeof(before_usage));
    memset(&after_usage, 0, sizeof(after_usage));
    (void)times(&before_times);
    (void)getrusage(RUSAGE_SELF, &before_usage);
    (void)clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        for (unsigned index = 0; index < 10000; ++index)
            accumulator = accumulator * 6364136223846793005ULL + 1;
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
    } while ((now.tv_sec - start.tv_sec) * 1000000000LL +
                 now.tv_nsec - start.tv_nsec < 50000000LL);
    (void)times(&after_times);
    (void)getrusage(RUSAGE_SELF, &after_usage);
    check(after_times.tms_utime >= before_times.tms_utime &&
              after_times.tms_stime >= before_times.tms_stime &&
              timeval_not_before(&after_usage.ru_utime,
                                  &before_usage.ru_utime) &&
              timeval_not_before(&after_usage.ru_stime,
                                  &before_usage.ru_stime),
          "times and getrusage preserve monotonic accounting");
    check(after_times.tms_utime > before_times.tms_utime ||
              after_usage.ru_utime.tv_sec > before_usage.ru_utime.tv_sec ||
              after_usage.ru_utime.tv_usec > before_usage.ru_utime.tv_usec,
          "user CPU accounting advances under load");
    (void)accumulator;
}

static void test_chroot(void) {
    const char *root = "/tmp/edgeos-chroot-root";
    const char *seed = "/tmp/edgeos-chroot-root/file";
    const char payload[] = "inside-chroot";
    char result[sizeof(payload)] = {0};
    int status = 0;
    int fd;
    pid_t child;

    unlink(seed);
    rmdir(root);
    if (mkdir(root, 0755) < 0 && errno != EEXIST) {
        check(0, "chroot setup");
        return;
    }
    fd = open(seed, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) {
        (void)write_all(fd, payload, sizeof(payload));
        close(fd);
    }
    child = fork();
    if (child == 0) {
        char cwd[32] = {0};
        int local = -1;
        if (chroot(root) == 0 && chdir("/") == 0)
            local = open("/file", O_RDONLY);
        if (local >= 0) (void)read(local, result, sizeof(result));
        if (local >= 0) close(local);
        _exit(local >= 0 && memcmp(result, payload, sizeof(payload)) == 0 &&
                      getcwd(cwd, sizeof(cwd)) != NULL &&
                      strcmp(cwd, "/") == 0 ? 0 : 1);
    }
    if (child > 0) (void)waitpid(child, &status, 0);
    check(child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "chroot resolves absolute paths within process root");
    check(access(seed, F_OK) == 0,
          "chroot leaves parent filesystem view intact");
    unlink(seed);
    rmdir(root);
}

static void test_posix_timer(void) {
    const int signal_number = SIGRTMIN + 1;
    struct sigevent event;
    struct itimerspec setting;
    struct itimerspec remaining;
    struct timespec timeout = {1, 0};
    sigset_t blocked;
    siginfo_t information;
    int timer_id = -1;
    int received;
    int overrun;
    long result;

    sigemptyset(&blocked);
    sigaddset(&blocked, signal_number);
    (void)sigprocmask(SIG_BLOCK, &blocked, NULL);
    memset(&event, 0, sizeof(event));
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = signal_number;
    event.sigev_value.sival_int = 0x55aa33cc;
    result = syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &timer_id);
    check(result == 0 && timer_id >= 0,
          "timer_create allocates process POSIX timer");

    memset(&setting, 0, sizeof(setting));
    setting.it_value.tv_nsec = 20000000;
    result = timer_id < 0 ? -1 :
        syscall(SYS_timer_settime, timer_id, 0, &setting, NULL);
    check(result == 0, "timer_settime arms monotonic timer");
    memset(&information, 0, sizeof(information));
    received = sigtimedwait(&blocked, &information, &timeout);
    check(received == signal_number && information.si_code == SI_TIMER &&
              information.si_value.sival_int == 0x55aa33cc,
          "POSIX timer delivers SI_TIMER payload");

    memset(&remaining, 0, sizeof(remaining));
    result = timer_id < 0 ? -1 :
        syscall(SYS_timer_gettime, timer_id, &remaining);
    overrun = timer_id < 0 ? -1 :
        (int)syscall(SYS_timer_getoverrun, timer_id);
    check(result == 0 && remaining.it_value.tv_sec == 0 &&
              remaining.it_value.tv_nsec == 0 && overrun >= 0,
          "timer_gettime and timer_getoverrun report expiration");
    result = timer_id < 0 ? -1 : syscall(SYS_timer_delete, timer_id);
    check(result == 0, "timer_delete releases POSIX timer");
    (void)sigprocmask(SIG_UNBLOCK, &blocked, NULL);
}

static void test_pkeys_and_rseq(void) {
    unsigned char *page;
    int allocation;
    int status = 0;
    pid_t child;

    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(page != MAP_FAILED &&
              syscall(ARM64_SYS_PKEY_MPROTECT, page, 4096,
                      PROT_READ | PROT_WRITE, 0) == 0,
          "pkey_mprotect accepts the default protection key");
    errno = 0;
    allocation = (int)syscall(ARM64_SYS_PKEY_ALLOC, 0, 0);
    check(allocation == -1 && errno == ENOSPC,
          "pkey_alloc truthfully reports unavailable hardware keys");
    errno = 0;
    check(syscall(ARM64_SYS_PKEY_FREE, 1) == -1 && errno == EINVAL,
          "pkey_free rejects an unallocated key");
    if (page != MAP_FAILED) munmap(page, 4096);

    check(getauxval(AT_RSEQ_FEATURE_SIZE) == 33 &&
              getauxval(AT_RSEQ_ALIGN) == 32,
          "ELF auxv advertises the supported extensible rseq ABI");
    child = fork();
    if (child == 0) {
        struct rseq_abi area;
        const uint32_t signature = 0xd428bc00u;
        int result;
        memset(&area, 0xa5, sizeof(area));
        result = (int)syscall(ARM64_SYS_RSEQ, &area, sizeof(area), 0,
                              signature);
        if (result != 0 || area.cpu_id_start != 0 || area.cpu_id != 0 ||
            area.rseq_cs != 0 || area.flags != 0 || area.node_id != 0 ||
            area.mm_cid != 0)
            _exit(1);
        errno = 0;
        if (syscall(ARM64_SYS_RSEQ, &area, sizeof(area), 0, signature) != -1 ||
            errno != EBUSY)
            _exit(2);
        if (syscall(ARM64_SYS_RSEQ, &area, sizeof(area), 1, signature) != 0 ||
            area.cpu_id_start != 0 || area.cpu_id != UINT32_MAX)
            _exit(3);
        _exit(0);
    }
    if (child > 0) (void)waitpid(child, &status, 0);
    check(child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "rseq register, update, duplicate, and unregister semantics");
}

static void test_mmsg(void) {
    int sockets[2] = {-1, -1};
    char outbound[2][8] = {"first", "second"};
    char inbound[2][8] = {{0}, {0}};
    struct iovec send_iov[2];
    struct iovec receive_iov[2];
    struct mmsghdr send_messages[2];
    struct mmsghdr receive_messages[2];
    struct timespec timeout = {0, 20000000};
    int sent = -1;
    int received = -1;
    int expired = -1;

    memset(send_messages, 0, sizeof(send_messages));
    memset(receive_messages, 0, sizeof(receive_messages));
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0) {
        for (unsigned index = 0; index < 2; ++index) {
            send_iov[index].iov_base = outbound[index];
            send_iov[index].iov_len = strlen(outbound[index]) + 1;
            send_messages[index].msg_hdr.msg_iov = &send_iov[index];
            send_messages[index].msg_hdr.msg_iovlen = 1;
            receive_iov[index].iov_base = inbound[index];
            receive_iov[index].iov_len = sizeof(inbound[index]);
            receive_messages[index].msg_hdr.msg_iov = &receive_iov[index];
            receive_messages[index].msg_hdr.msg_iovlen = 1;
        }
        sent = sendmmsg(sockets[0], send_messages, 2, 0);
        received = recvmmsg(sockets[1], receive_messages, 2, 0, &timeout);
        timeout.tv_sec = 0;
        timeout.tv_nsec = 20000000;
        expired = recvmmsg(sockets[1], receive_messages, 1, 0, &timeout);
    }
    check(sent == 2 && send_messages[0].msg_len == 6 &&
              send_messages[1].msg_len == 7,
          "sendmmsg batches Unix datagrams and records lengths");
    check(received == 2 && receive_messages[0].msg_len == 6 &&
              receive_messages[1].msg_len == 7 &&
              strcmp(inbound[0], "first") == 0 &&
              strcmp(inbound[1], "second") == 0,
          "recvmmsg drains Unix datagrams in one syscall");
    check(expired == 0 && timeout.tv_sec == 0 && timeout.tv_nsec == 0,
          "recvmmsg honors and updates its timeout");
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
}

static void test_splice_family(void) {
    const char file_payload[] = "0123456789";
    const char vm_first[] = "vm";
    const char vm_second[] = "splice";
    const char tee_payload[] = "tee-data";
    const char wait_payload[] = "awake";
    const char *source_path = "/tmp/edgeos-splice-source";
    const char *target_path = "/tmp/edgeos-splice-target";
    const char *wait_path = "/tmp/edgeos-splice-wait";
    struct iovec vectors[2];
    char buffer[32];
    int descriptors[2] = {-1, -1};
    int second_pipe[2] = {-1, -1};
    int source = -1;
    int target = -1;
    off_t input_offset = 2;
    off_t output_offset = 2;
    ssize_t result;

    vectors[0].iov_base = (void *)vm_first;
    vectors[0].iov_len = strlen(vm_first);
    vectors[1].iov_base = (void *)vm_second;
    vectors[1].iov_len = strlen(vm_second);
    memset(buffer, 0, sizeof(buffer));
    result = pipe(descriptors) == 0 ?
        syscall(SYS_vmsplice, descriptors[1], vectors, 2, 0) : -1;
    if (result >= 0)
        result = read(descriptors[0], buffer,
                      strlen(vm_first) + strlen(vm_second));
    check(result == (ssize_t)(strlen(vm_first) + strlen(vm_second)) &&
              strcmp(buffer, "vmsplice") == 0,
          "vmsplice writes all iovecs into a pipe");
    if (descriptors[0] >= 0) close(descriptors[0]);
    if (descriptors[1] >= 0) close(descriptors[1]);
    descriptors[0] = descriptors[1] = -1;

    unlink(source_path);
    unlink(target_path);
    source = open(source_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    target = open(target_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (source >= 0) {
        (void)write_all(source, file_payload, strlen(file_payload));
        (void)lseek(source, 0, SEEK_SET);
    }
    if (target >= 0) {
        (void)write_all(target, "--------", 8);
        (void)lseek(target, 0, SEEK_SET);
    }
    memset(buffer, 0, sizeof(buffer));
    result = pipe(descriptors) == 0 ?
        syscall(SYS_splice, source, &input_offset, descriptors[1], NULL,
                4, 0) : -1;
    if (result == 4) result = read(descriptors[0], buffer, 4);
    check(result == 4 && input_offset == 6 && lseek(source, 0, SEEK_CUR) == 0 &&
              memcmp(buffer, "2345", 4) == 0,
          "splice file to pipe preserves explicit input offset semantics");
    if (descriptors[0] >= 0) close(descriptors[0]);
    if (descriptors[1] >= 0) close(descriptors[1]);
    descriptors[0] = descriptors[1] = -1;

    if (pipe(descriptors) == 0)
        (void)write_all(descriptors[1], "ABCD", 4);
    result = descriptors[0] >= 0 ?
        syscall(SYS_splice, descriptors[0], NULL, target, &output_offset,
                4, 0) : -1;
    memset(buffer, 0, sizeof(buffer));
    if (target >= 0) {
        (void)lseek(target, 0, SEEK_SET);
        (void)read(target, buffer, 8);
    }
    check(result == 4 && output_offset == 6 &&
              memcmp(buffer, "--ABCD--", 8) == 0,
          "splice pipe to file preserves explicit output offset semantics");
    if (descriptors[0] >= 0) close(descriptors[0]);
    if (descriptors[1] >= 0) close(descriptors[1]);
    if (source >= 0) close(source);
    if (target >= 0) close(target);
    unlink(source_path);
    unlink(target_path);

    descriptors[0] = descriptors[1] = -1;
    memset(buffer, 0, sizeof(buffer));
    if (pipe(descriptors) == 0 && pipe(second_pipe) == 0)
        (void)write_all(descriptors[1], tee_payload, strlen(tee_payload));
    result = descriptors[0] >= 0 && second_pipe[1] >= 0 ?
        syscall(SYS_tee, descriptors[0], second_pipe[1],
                strlen(tee_payload), 0) : -1;
    if (result == (ssize_t)strlen(tee_payload))
        result = read(second_pipe[0], buffer, strlen(tee_payload));
    check(result == (ssize_t)strlen(tee_payload) &&
              memcmp(buffer, tee_payload, strlen(tee_payload)) == 0,
          "tee copies pipe data to a second pipe");
    memset(buffer, 0, sizeof(buffer));
    result = descriptors[0] >= 0 ?
        read(descriptors[0], buffer, strlen(tee_payload)) : -1;
    check(result == (ssize_t)strlen(tee_payload) &&
              memcmp(buffer, tee_payload, strlen(tee_payload)) == 0,
          "tee leaves source pipe data unconsumed");
    for (unsigned index = 0; index < 2; ++index) {
        if (descriptors[index] >= 0) close(descriptors[index]);
        if (second_pipe[index] >= 0) close(second_pipe[index]);
    }

    descriptors[0] = descriptors[1] = -1;
    unlink(wait_path);
    target = open(wait_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (pipe(descriptors) == 0) {
        pid_t child = fork();
        if (child == 0) {
            struct timespec delay = {0, 20000000};
            close(descriptors[0]);
            (void)nanosleep(&delay, NULL);
            _exit(write_all(descriptors[1], wait_payload,
                            strlen(wait_payload)) == 0 ? 0 : 1);
        }
        close(descriptors[1]);
        descriptors[1] = -1;
        result = syscall(SYS_splice, descriptors[0], NULL, target, NULL,
                         strlen(wait_payload), 0);
        if (child > 0) (void)waitpid(child, NULL, 0);
    } else {
        result = -1;
    }
    memset(buffer, 0, sizeof(buffer));
    if (target >= 0) {
        (void)lseek(target, 0, SEEK_SET);
        (void)read(target, buffer, strlen(wait_payload));
    }
    check(result == (ssize_t)strlen(wait_payload) &&
              memcmp(buffer, wait_payload, strlen(wait_payload)) == 0,
          "blocking splice resumes after a pipe writer wakes it");
    if (descriptors[0] >= 0) close(descriptors[0]);
    if (descriptors[1] >= 0) close(descriptors[1]);
    if (target >= 0) close(target);
    unlink(wait_path);
}

static void test_setns(void) {
    static const char namespace_hostname[] = "edgeos-setns-test";
    int ready[2] = {-1, -1};
    int release[2] = {-1, -1};
    int namespace_fd = -1;
    int target_status = 0;
    int join_status = 0;
    pid_t target;
    pid_t joiner = -1;
    char namespace_path[64];
    char self_link[64] = {0};
    char target_link[64] = {0};
    struct statfs filesystem;
    ssize_t self_length = -1;
    ssize_t target_length = -1;
    int namespace_type = -1;
    int wrong_type = -1;

    if (pipe(ready) < 0 || pipe(release) < 0) {
        check(0, "setns process setup");
        return;
    }
    target = fork();
    if (target == 0) {
        char byte;
        close(ready[0]);
        close(release[1]);
        if (syscall(SYS_unshare, LINUX_CLONE_NEWUTS) != 0 ||
            sethostname(namespace_hostname, strlen(namespace_hostname)) != 0 ||
            write_all(ready[1], "R", 1) != 0 ||
            read(release[0], &byte, 1) != 1)
            _exit(1);
        _exit(0);
    }
    close(ready[1]);
    close(release[0]);
    ready[1] = release[0] = -1;
    if (target > 0) {
        char byte;
        if (read(ready[0], &byte, 1) == 1) {
            snprintf(namespace_path, sizeof(namespace_path),
                     "/proc/%d/ns/uts", target);
            namespace_fd = open(namespace_path, O_RDONLY | O_CLOEXEC);
            self_length = readlink("/proc/self/ns/uts", self_link,
                                   sizeof(self_link) - 1u);
            target_length = readlink(namespace_path, target_link,
                                     sizeof(target_link) - 1u);
        }
    }
    if (self_length >= 0) self_link[self_length] = 0;
    if (target_length >= 0) target_link[target_length] = 0;
    check(namespace_fd >= 0 && self_length > 0 && target_length > 0 &&
              strcmp(self_link, target_link) != 0,
          "procfs exposes openable task-specific namespace handles");
    memset(&filesystem, 0, sizeof(filesystem));
    namespace_type = namespace_fd >= 0 ?
        ioctl(namespace_fd, LINUX_NS_GET_NSTYPE) : -1;
    check(namespace_fd >= 0 && fstatfs(namespace_fd, &filesystem) == 0 &&
              (uint64_t)filesystem.f_type == LINUX_NSFS_MAGIC &&
              namespace_type == (int)LINUX_CLONE_NEWUTS,
          "namespace fd reports nsfs type and namespace kind");
    errno = 0;
    wrong_type = namespace_fd >= 0 ?
        (int)syscall(ARM64_SYS_SETNS, namespace_fd, LINUX_CLONE_NEWNET) : -1;
    check(wrong_type == -1 && errno == EINVAL,
          "setns rejects a mismatched namespace type");

    if (release[1] >= 0) (void)write_all(release[1], "X", 1);
    if (target > 0) (void)waitpid(target, &target_status, 0);
    if (namespace_fd >= 0) {
        joiner = fork();
        if (joiner == 0) {
            char hostname[64] = {0};
            if (syscall(ARM64_SYS_SETNS, namespace_fd,
                        LINUX_CLONE_NEWUTS) != 0 ||
                gethostname(hostname, sizeof(hostname)) != 0 ||
                strcmp(hostname, namespace_hostname) != 0)
                _exit(1);
            _exit(0);
        }
    }
    if (joiner > 0) (void)waitpid(joiner, &join_status, 0);
    check(target > 0 && WIFEXITED(target_status) &&
              WEXITSTATUS(target_status) == 0 && joiner > 0 &&
              WIFEXITED(join_status) && WEXITSTATUS(join_status) == 0,
          "setns joins a namespace pinned after its task exits");
    if (namespace_fd >= 0) close(namespace_fd);
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (release[0] >= 0) close(release[0]);
    if (release[1] >= 0) close(release[1]);
}

int main(void) {
    test_openat2();
    test_renameat2();
    test_fchmodat2();
    test_copy_file_range();
    test_epoll_pwait2();
    test_pidfd_and_process_vm();
    test_clone3_and_execveat();
    test_queued_signals();
    test_futex_waitv();
    test_process_madvise();
    test_process_accounting();
    test_chroot();
    test_posix_timer();
    test_pkeys_and_rseq();
    test_mmsg();
    test_splice_family();
    test_setns();
    printf("ARM64_MODERN_ABI_%s failures=%d\n",
           failures ? "FAIL" : "OK", failures);
    return failures ? 1 : 0;
}
