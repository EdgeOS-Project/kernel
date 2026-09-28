/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Linux in-flight file-operation close and descriptor-reuse ABI probe.
 */

#define _GNU_SOURCE

#if !defined(__linux__)
#error "fd_operation_close_reuse_abi_probe requires Linux"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define PROBE_ALARM_SECONDS 45u
#define BLOCKED_WAIT_MILLISECONDS 3000u
#define JOIN_WAIT_MILLISECONDS 3000u
#define BLOCKED_STABLE_SAMPLES 3u

#define ORIGINAL_EVENT_VALUE UINT64_C(0x1122334455667788)
#define REUSED_EVENT_VALUE UINT64_C(0x2233445566778899)

typedef ssize_t (*blocked_operation_fn_t)(void *opaque);

typedef struct blocked_call {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_barrier_t gate;
    pthread_t thread;
    blocked_operation_fn_t operation;
    void *opaque;
    pid_t tid;
    int ready;
    int thread_created;
    int synchronization_initialized;
    atomic_int entered;
    atomic_int finished;
    ssize_t result;
    int error_number;
} blocked_call_t;

typedef struct io_operation {
    int descriptor;
    void *buffer;
    size_t length;
} io_operation_t;

typedef struct const_io_operation {
    int descriptor;
    const void *buffer;
    size_t length;
} const_io_operation_t;

typedef struct vector_io_operation {
    int descriptor;
    struct iovec vectors[2];
} vector_io_operation_t;

typedef struct signalfd_read_operation {
    io_operation_t io;
    sigset_t mask;
    int mask_error;
} signalfd_read_operation_t;

static int g_failures;

static void hard_timeout_handler(int signal_number) {
    static const char message[] =
        "fd_operation_close_reuse_abi:FAIL hard_timeout\n";
    ssize_t ignored_result;

    (void)signal_number;
    ignored_result =
        write(STDERR_FILENO, message, sizeof(message) - 1u);
    (void)ignored_result;
    _exit(124);
}

static void discard_io_result(ssize_t result) {
    (void)result;
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec current;

    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0)
        return 0;
    return (uint64_t)current.tv_sec * UINT64_C(1000) +
           (uint64_t)current.tv_nsec / UINT64_C(1000000);
}

static struct timespec realtime_deadline(unsigned milliseconds) {
    struct timespec deadline;
    uint64_t nanoseconds;

    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        deadline.tv_sec = time(0);
        deadline.tv_nsec = 0;
    }
    nanoseconds = (uint64_t)deadline.tv_nsec +
                  (uint64_t)(milliseconds % 1000u) * UINT64_C(1000000);
    deadline.tv_sec += (time_t)(milliseconds / 1000u) +
                       (time_t)(nanoseconds / UINT64_C(1000000000));
    deadline.tv_nsec = (long)(nanoseconds % UINT64_C(1000000000));
    return deadline;
}

static void sleep_one_millisecond(void) {
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};

    (void)nanosleep(&delay, 0);
}

static void report_detail(const char *case_name, const char *detail) {
    dprintf(STDOUT_FILENO, "detail:%s:%s errno:%d\n",
            case_name, detail, errno);
}

static void report_case(const char *case_name, int passed) {
    dprintf(STDOUT_FILENO, "case:%s:%s\n",
            case_name, passed ? "PASS" : "FAIL");
    if (!passed)
        ++g_failures;
}

static int read_current_syscall(pid_t tid, long *syscall_number) {
    char path[96];
    char buffer[256];
    char *end = 0;
    long value;
    ssize_t length;
    int descriptor;
    int saved_errno;

    if (!syscall_number)
        return -1;
    if (snprintf(path, sizeof(path), "/proc/self/task/%ld/syscall",
                 (long)tid) >= (int)sizeof(path))
        return -1;
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0)
        return -1;
    length = read(descriptor, buffer, sizeof(buffer) - 1u);
    saved_errno = errno;
    (void)close(descriptor);
    errno = saved_errno;
    if (length <= 0)
        return -1;
    buffer[length] = '\0';
    if (strncmp(buffer, "running", 7u) == 0)
        return 1;
    errno = 0;
    value = strtol(buffer, &end, 10);
    if (end == buffer || errno != 0)
        return -1;
    *syscall_number = value;
    return 0;
}

static int wait_for_blocked_syscall(const char *case_name,
                                    blocked_call_t *call,
                                    long expected_syscall) {
    uint64_t deadline =
        monotonic_milliseconds() + BLOCKED_WAIT_MILLISECONDS;
    unsigned stable_samples = 0;

    while (monotonic_milliseconds() <= deadline) {
        long current_syscall = -1;
        int query_result;

        if (atomic_load_explicit(&call->finished, memory_order_acquire)) {
            dprintf(STDOUT_FILENO,
                    "detail:%s:returned_before_reuse rc:%ld errno:%d\n",
                    case_name, (long)call->result, call->error_number);
            return 0;
        }
        query_result = read_current_syscall(call->tid, &current_syscall);
        if (query_result == 0 && current_syscall == expected_syscall) {
            ++stable_samples;
            if (stable_samples >= BLOCKED_STABLE_SAMPLES) {
                dprintf(STDOUT_FILENO,
                        "blocked:%s:tid:%ld syscall:%ld\n",
                        case_name, (long)call->tid, current_syscall);
                return 1;
            }
        } else {
            stable_samples = 0;
        }
        sleep_one_millisecond();
    }
    dprintf(STDOUT_FILENO,
            "detail:%s:target_syscall_not_observed syscall:%ld\n",
            case_name, expected_syscall);
    return 0;
}

static void *blocked_call_worker(void *opaque) {
    blocked_call_t *call = opaque;
    int barrier_result;

    pthread_mutex_lock(&call->mutex);
    call->tid = (pid_t)syscall(SYS_gettid);
    call->ready = 1;
    pthread_cond_signal(&call->condition);
    pthread_mutex_unlock(&call->mutex);

    barrier_result = pthread_barrier_wait(&call->gate);
    if (barrier_result != 0 &&
        barrier_result != PTHREAD_BARRIER_SERIAL_THREAD) {
        call->result = -1;
        call->error_number = barrier_result;
        atomic_store_explicit(&call->finished, 1, memory_order_release);
        return 0;
    }

    atomic_store_explicit(&call->entered, 1, memory_order_release);
    errno = 0;
    call->result = call->operation(call->opaque);
    call->error_number = errno;
    atomic_store_explicit(&call->finished, 1, memory_order_release);
    return 0;
}

static int blocked_call_start(const char *case_name, blocked_call_t *call,
                              blocked_operation_fn_t operation, void *opaque,
                              long expected_syscall) {
    struct timespec deadline;
    int wait_result = 0;
    int barrier_result;
    int init_result;

    memset(call, 0, sizeof(*call));
    call->operation = operation;
    call->opaque = opaque;
    call->result = -2;
    atomic_init(&call->entered, 0);
    atomic_init(&call->finished, 0);
    init_result = pthread_mutex_init(&call->mutex, 0);
    if (init_result != 0) {
        errno = init_result;
        report_detail(case_name, "synchronization_init_failed");
        return 0;
    }
    init_result = pthread_cond_init(&call->condition, 0);
    if (init_result != 0) {
        errno = init_result;
        (void)pthread_mutex_destroy(&call->mutex);
        report_detail(case_name, "synchronization_init_failed");
        return 0;
    }
    init_result = pthread_barrier_init(&call->gate, 0, 2u);
    if (init_result != 0) {
        errno = init_result;
        (void)pthread_cond_destroy(&call->condition);
        (void)pthread_mutex_destroy(&call->mutex);
        report_detail(case_name, "synchronization_init_failed");
        return 0;
    }
    call->synchronization_initialized = 1;
    wait_result = pthread_create(
        &call->thread, 0, blocked_call_worker, call);
    if (wait_result != 0) {
        errno = wait_result;
        report_detail(case_name, "pthread_create_failed");
        return 0;
    }
    call->thread_created = 1;

    deadline = realtime_deadline(BLOCKED_WAIT_MILLISECONDS);
    pthread_mutex_lock(&call->mutex);
    while (!call->ready && wait_result == 0)
        wait_result = pthread_cond_timedwait(
            &call->condition, &call->mutex, &deadline);
    pthread_mutex_unlock(&call->mutex);
    if (!call->ready) {
        errno = wait_result;
        report_detail(case_name, "worker_ready_timeout");
        return 0;
    }

    barrier_result = pthread_barrier_wait(&call->gate);
    if (barrier_result != 0 &&
        barrier_result != PTHREAD_BARRIER_SERIAL_THREAD) {
        errno = barrier_result;
        report_detail(case_name, "barrier_wait_failed");
        return 0;
    }
    while (!atomic_load_explicit(&call->entered, memory_order_acquire))
        sleep_one_millisecond();
    return wait_for_blocked_syscall(case_name, call, expected_syscall);
}

static int blocked_call_join(const char *case_name, blocked_call_t *call) {
    struct timespec deadline;
    int join_result;

    if (!call->thread_created)
        return 0;
    deadline = realtime_deadline(JOIN_WAIT_MILLISECONDS);
    join_result = pthread_timedjoin_np(call->thread, 0, &deadline);
    if (join_result == 0) {
        call->thread_created = 0;
        return 1;
    }
    dprintf(STDOUT_FILENO, "detail:%s:join_timeout error:%d\n",
            case_name, join_result);
    (void)pthread_cancel(call->thread);
    deadline = realtime_deadline(JOIN_WAIT_MILLISECONDS);
    join_result = pthread_timedjoin_np(call->thread, 0, &deadline);
    if (join_result != 0) {
        dprintf(STDERR_FILENO,
                "fd_operation_close_reuse_abi:FAIL "
                "uncancellable_thread case:%s error:%d\n",
                case_name, join_result);
        _exit(125);
    }
    call->thread_created = 0;
    return 0;
}

static void blocked_call_destroy(blocked_call_t *call) {
    if (call->thread_created || !call->synchronization_initialized)
        return;
    (void)pthread_barrier_destroy(&call->gate);
    (void)pthread_cond_destroy(&call->condition);
    (void)pthread_mutex_destroy(&call->mutex);
    call->synchronization_initialized = 0;
}

static ssize_t read_operation(void *opaque) {
    io_operation_t *operation = opaque;

    return read(operation->descriptor, operation->buffer, operation->length);
}

static ssize_t write_operation(void *opaque) {
    const_io_operation_t *operation = opaque;

    return write(operation->descriptor, operation->buffer, operation->length);
}

static ssize_t readv_operation(void *opaque) {
    vector_io_operation_t *operation = opaque;

    return readv(operation->descriptor, operation->vectors, 2);
}

static ssize_t writev_operation(void *opaque) {
    vector_io_operation_t *operation = opaque;

    return writev(operation->descriptor, operation->vectors, 2);
}

static ssize_t receive_operation(void *opaque) {
    io_operation_t *operation = opaque;

    return recv(operation->descriptor, operation->buffer,
                operation->length, 0);
}

static ssize_t accept_operation(void *opaque) {
    const int *descriptor = opaque;

    return accept4(*descriptor, 0, 0, SOCK_CLOEXEC);
}

static ssize_t signalfd_read_operation_call(void *opaque) {
    signalfd_read_operation_t *operation = opaque;

    operation->mask_error =
        pthread_sigmask(SIG_BLOCK, &operation->mask, 0);
    if (operation->mask_error != 0) {
        errno = operation->mask_error;
        return -1;
    }
    return read(operation->io.descriptor, operation->io.buffer,
                operation->io.length);
}

static int replace_numeric_descriptor(int target, int replacement) {
    if (target < 0 || replacement < 0 || target == replacement) {
        errno = EINVAL;
        return -1;
    }
    if (close(target) != 0)
        return -1;
    if (dup2(replacement, target) != target)
        return -1;
    if (close(replacement) != 0)
        return -1;
    return 0;
}

static int create_ready_eventfd(uint64_t value) {
    int descriptor = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    if (descriptor < 0)
        return -1;
    if (write(descriptor, &value, sizeof(value)) !=
        (ssize_t)sizeof(value)) {
        int saved_errno = errno;

        close(descriptor);
        errno = saved_errno;
        return -1;
    }
    return descriptor;
}

static int verify_reused_eventfd(const char *case_name, int descriptor) {
    uint64_t value = 0;
    ssize_t result;

    errno = 0;
    result = read(descriptor, &value, sizeof(value));
    dprintf(STDOUT_FILENO,
            "reused:%s:rc:%ld errno:%d value:0x%llx\n",
            case_name, (long)result, errno,
            (unsigned long long)value);
    return result == (ssize_t)sizeof(value) &&
           value == REUSED_EVENT_VALUE;
}

static int test_pipe_read_close_reuse(void) {
    static const char case_name[] = "pipe_read";
    int original[2] = {-1, -1};
    int replacement[2] = {-1, -1};
    blocked_call_t call;
    io_operation_t operation;
    char result_byte = '\0';
    const char original_byte = 'O';
    const char replacement_byte = 'R';
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    if (pipe2(original, O_CLOEXEC) != 0 ||
        pipe2(replacement, O_CLOEXEC) != 0 ||
        write(replacement[1], &replacement_byte, 1u) != 1) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    operation.descriptor = original[0];
    operation.buffer = &result_byte;
    operation.length = 1u;
    call_started = blocked_call_start(
        case_name, &call, read_operation, &operation, SYS_read);
    if (!call_started) {
        discard_io_result(write(original[1], &original_byte, 1u));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(original[0], replacement[0]) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        discard_io_result(write(original[1], &original_byte, 1u));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement[0] = -1;
    if (write(original[1], &original_byte, 1u) != 1) {
        report_detail(case_name, "original_wakeup_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d byte:%c\n",
            case_name, (long)call.result, call.error_number,
            result_byte ? result_byte : '?');
    if (call.result != 1 || call.error_number != 0 ||
        result_byte != original_byte) {
        report_detail(case_name, "original_result_mismatch");
        goto out;
    }
    {
        char reused_byte = '\0';

        errno = 0;
        if (read(original[0], &reused_byte, 1u) != 1 ||
            reused_byte != replacement_byte) {
            report_detail(case_name, "replacement_pipe_changed");
            goto out;
        }
        dprintf(STDOUT_FILENO,
                "reused:%s:rc:1 errno:0 byte:%c\n",
                case_name, reused_byte);
    }
    passed = 1;

out:
    if (call.thread_created) {
        discard_io_result(write(original[1], &original_byte, 1u));
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (original[0] >= 0)
        close(original[0]);
    if (original[1] >= 0)
        close(original[1]);
    if (replacement[0] >= 0)
        close(replacement[0]);
    if (replacement[1] >= 0)
        close(replacement[1]);
    return passed;
}

static ssize_t fill_pipe_nonblocking(int descriptor) {
    char buffer[4096];
    ssize_t total = 0;
    int flags;

    memset(buffer, 'F', sizeof(buffer));
    flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 ||
        fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0)
        return -1;
    for (;;) {
        ssize_t result = write(descriptor, buffer, sizeof(buffer));

        if (result > 0) {
            total += result;
            continue;
        }
        if (result < 0 && errno == EINTR)
            continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        return -1;
    }
    if (fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK) != 0)
        return -1;
    return total;
}

static int set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL);

    if (flags < 0)
        return -1;
    return fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
}

static int test_pipe_write_close_reuse(void) {
    static const char case_name[] = "pipe_write";
    int original[2] = {-1, -1};
    int replacement[2] = {-1, -1};
    blocked_call_t call;
    const_io_operation_t operation;
    const char written_byte = 'O';
    char buffer[4096];
    ssize_t filled = -1;
    ssize_t drained_before_join = 0;
    ssize_t drained_after_join = 0;
    char last_byte = '\0';
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    if (pipe2(original, O_CLOEXEC) != 0 ||
        pipe2(replacement, O_CLOEXEC) != 0 ||
        set_nonblocking(replacement[0]) != 0) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    filled = fill_pipe_nonblocking(original[1]);
    if (filled <= 0) {
        report_detail(case_name, "pipe_fill_failed");
        goto out;
    }
    operation.descriptor = original[1];
    operation.buffer = &written_byte;
    operation.length = 1u;
    call_started = blocked_call_start(
        case_name, &call, write_operation, &operation, SYS_write);
    if (!call_started) {
        drained_before_join = read(original[0], buffer, sizeof(buffer));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(original[1], replacement[1]) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        drained_before_join = read(original[0], buffer, sizeof(buffer));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement[1] = -1;
    drained_before_join = read(original[0], buffer, sizeof(buffer));
    if (drained_before_join <= 0) {
        report_detail(case_name, "original_drain_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    for (ssize_t index = 0; index < drained_before_join; ++index) {
        if (buffer[index] != 'F') {
            report_detail(case_name, "initial_pipe_data_changed");
            call_joined = blocked_call_join(case_name, &call);
            goto out;
        }
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d filled:%ld drained:%ld\n",
            case_name, (long)call.result, call.error_number,
            (long)filled, (long)drained_before_join);
    if (call.result != 1 || call.error_number != 0) {
        report_detail(case_name, "original_result_mismatch");
        goto out;
    }
    errno = 0;
    if (read(replacement[0], buffer, sizeof(buffer)) != -1 ||
        (errno != EAGAIN && errno != EWOULDBLOCK)) {
        report_detail(case_name, "replacement_pipe_received_write");
        goto out;
    }
    if (set_nonblocking(original[0]) != 0) {
        report_detail(case_name, "original_nonblocking_failed");
        goto out;
    }
    for (;;) {
        ssize_t result = read(original[0], buffer, sizeof(buffer));

        if (result > 0) {
            for (ssize_t index = 0; index < result; ++index) {
                last_byte = buffer[index];
                if (drained_after_join + index <
                        filled - drained_before_join &&
                    buffer[index] != 'F') {
                    report_detail(case_name,
                                  "remaining_pipe_data_changed");
                    goto out;
                }
            }
            drained_after_join += result;
            continue;
        }
        if (result < 0 && errno == EINTR)
            continue;
        if (result == 0 ||
            (result < 0 &&
             (errno == EAGAIN || errno == EWOULDBLOCK)))
            break;
        report_detail(case_name, "remaining_pipe_read_failed");
        goto out;
    }
    if (drained_before_join + drained_after_join != filled + 1 ||
        last_byte != written_byte) {
        report_detail(case_name, "original_pipe_tail_mismatch");
        goto out;
    }
    passed = 1;

out:
    if (call.thread_created) {
        discard_io_result(read(original[0], buffer, sizeof(buffer)));
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (original[0] >= 0)
        close(original[0]);
    if (original[1] >= 0)
        close(original[1]);
    if (replacement[0] >= 0)
        close(replacement[0]);
    if (replacement[1] >= 0)
        close(replacement[1]);
    return passed;
}

static int test_pipe_readv_close_reuse(void) {
    static const char case_name[] = "pipe_readv";
    int original[2] = {-1, -1};
    int replacement[2] = {-1, -1};
    blocked_call_t call;
    vector_io_operation_t operation;
    char result_bytes[2] = {'\0', '\0'};
    const char original_bytes[2] = {'O', 'V'};
    const char replacement_bytes[2] = {'R', 'R'};
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    memset(&operation, 0, sizeof(operation));
    if (pipe2(original, O_CLOEXEC) != 0 ||
        pipe2(replacement, O_CLOEXEC) != 0 ||
        write(replacement[1], replacement_bytes,
              sizeof(replacement_bytes)) !=
            (ssize_t)sizeof(replacement_bytes)) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    operation.descriptor = original[0];
    operation.vectors[0].iov_base = &result_bytes[0];
    operation.vectors[0].iov_len = 1u;
    operation.vectors[1].iov_base = &result_bytes[1];
    operation.vectors[1].iov_len = 1u;
    call_started = blocked_call_start(
        case_name, &call, readv_operation, &operation, SYS_readv);
    if (!call_started) {
        discard_io_result(write(original[1], original_bytes,
                                sizeof(original_bytes)));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(original[0], replacement[0]) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        discard_io_result(write(original[1], original_bytes,
                                sizeof(original_bytes)));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement[0] = -1;
    if (write(original[1], original_bytes, sizeof(original_bytes)) !=
        (ssize_t)sizeof(original_bytes)) {
        report_detail(case_name, "original_wakeup_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d bytes:%c%c\n",
            case_name, (long)call.result, call.error_number,
            result_bytes[0] ? result_bytes[0] : '?',
            result_bytes[1] ? result_bytes[1] : '?');
    if (call.result != (ssize_t)sizeof(result_bytes) ||
        call.error_number != 0 ||
        memcmp(result_bytes, original_bytes,
               sizeof(result_bytes)) != 0) {
        report_detail(case_name, "original_result_mismatch");
        goto out;
    }
    {
        char reused_bytes[2] = {'\0', '\0'};

        errno = 0;
        if (read(original[0], reused_bytes, sizeof(reused_bytes)) !=
                (ssize_t)sizeof(reused_bytes) ||
            memcmp(reused_bytes, replacement_bytes,
                   sizeof(reused_bytes)) != 0) {
            report_detail(case_name, "replacement_pipe_changed");
            goto out;
        }
        dprintf(STDOUT_FILENO,
                "reused:%s:rc:2 errno:0 bytes:%c%c\n",
                case_name, reused_bytes[0], reused_bytes[1]);
    }
    passed = 1;

out:
    if (call.thread_created) {
        discard_io_result(write(original[1], original_bytes,
                                sizeof(original_bytes)));
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (original[0] >= 0)
        close(original[0]);
    if (original[1] >= 0)
        close(original[1]);
    if (replacement[0] >= 0)
        close(replacement[0]);
    if (replacement[1] >= 0)
        close(replacement[1]);
    return passed;
}

static int test_pipe_writev_close_reuse(void) {
    static const char case_name[] = "pipe_writev";
    int original[2] = {-1, -1};
    int replacement[2] = {-1, -1};
    blocked_call_t call;
    vector_io_operation_t operation;
    const char written_bytes[2] = {'O', 'V'};
    char buffer[4096];
    ssize_t filled = -1;
    ssize_t drained_before_join = 0;
    ssize_t drained_after_join = 0;
    char final_bytes[2] = {'\0', '\0'};
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    memset(&operation, 0, sizeof(operation));
    if (pipe2(original, O_CLOEXEC) != 0 ||
        pipe2(replacement, O_CLOEXEC) != 0 ||
        set_nonblocking(replacement[0]) != 0) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    filled = fill_pipe_nonblocking(original[1]);
    if (filled <= 0) {
        report_detail(case_name, "pipe_fill_failed");
        goto out;
    }
    operation.descriptor = original[1];
    operation.vectors[0].iov_base = (void *)&written_bytes[0];
    operation.vectors[0].iov_len = 1u;
    operation.vectors[1].iov_base = (void *)&written_bytes[1];
    operation.vectors[1].iov_len = 1u;
    call_started = blocked_call_start(
        case_name, &call, writev_operation, &operation, SYS_writev);
    if (!call_started) {
        drained_before_join = read(original[0], buffer, sizeof(buffer));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(original[1], replacement[1]) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        drained_before_join = read(original[0], buffer, sizeof(buffer));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement[1] = -1;
    drained_before_join = read(original[0], buffer, sizeof(buffer));
    if (drained_before_join <= 0) {
        report_detail(case_name, "original_drain_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    for (ssize_t index = 0; index < drained_before_join; ++index) {
        if (buffer[index] != 'F') {
            report_detail(case_name, "initial_pipe_data_changed");
            call_joined = blocked_call_join(case_name, &call);
            goto out;
        }
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d filled:%ld drained:%ld\n",
            case_name, (long)call.result, call.error_number,
            (long)filled, (long)drained_before_join);
    if (call.result != (ssize_t)sizeof(written_bytes) ||
        call.error_number != 0) {
        report_detail(case_name, "original_result_mismatch");
        goto out;
    }
    errno = 0;
    if (read(replacement[0], buffer, sizeof(buffer)) != -1 ||
        (errno != EAGAIN && errno != EWOULDBLOCK)) {
        report_detail(case_name, "replacement_pipe_received_write");
        goto out;
    }
    if (set_nonblocking(original[0]) != 0) {
        report_detail(case_name, "original_nonblocking_failed");
        goto out;
    }
    for (;;) {
        ssize_t result = read(original[0], buffer, sizeof(buffer));

        if (result > 0) {
            for (ssize_t index = 0; index < result; ++index) {
                ssize_t absolute_index =
                    drained_before_join + drained_after_join + index;

                if (absolute_index < filled &&
                    buffer[index] != 'F') {
                    report_detail(case_name,
                                  "remaining_pipe_data_changed");
                    goto out;
                }
                if (absolute_index >= filled &&
                    absolute_index < filled +
                        (ssize_t)sizeof(final_bytes))
                    final_bytes[absolute_index - filled] =
                        buffer[index];
            }
            drained_after_join += result;
            continue;
        }
        if (result < 0 && errno == EINTR)
            continue;
        if (result == 0 ||
            (result < 0 &&
             (errno == EAGAIN || errno == EWOULDBLOCK)))
            break;
        report_detail(case_name, "remaining_pipe_read_failed");
        goto out;
    }
    if (drained_before_join + drained_after_join !=
            filled + (ssize_t)sizeof(written_bytes) ||
        memcmp(final_bytes, written_bytes,
               sizeof(final_bytes)) != 0) {
        report_detail(case_name, "original_pipe_tail_mismatch");
        goto out;
    }
    passed = 1;

out:
    if (call.thread_created) {
        discard_io_result(read(original[0], buffer, sizeof(buffer)));
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (original[0] >= 0)
        close(original[0]);
    if (original[1] >= 0)
        close(original[1]);
    if (replacement[0] >= 0)
        close(replacement[0]);
    if (replacement[1] >= 0)
        close(replacement[1]);
    return passed;
}

static int test_eventfd_read_close_reuse(void) {
    static const char case_name[] = "eventfd_read";
    int target = -1;
    int original_control = -1;
    int replacement = -1;
    blocked_call_t call;
    io_operation_t operation;
    uint64_t result_value = 0;
    uint64_t wake_value = ORIGINAL_EVENT_VALUE;
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    target = eventfd(0, EFD_CLOEXEC);
    if (target < 0 ||
        (original_control = dup(target)) < 0 ||
        (replacement = create_ready_eventfd(REUSED_EVENT_VALUE)) < 0) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    operation.descriptor = target;
    operation.buffer = &result_value;
    operation.length = sizeof(result_value);
    call_started = blocked_call_start(
        case_name, &call, read_operation, &operation, SYS_read);
    if (!call_started) {
        discard_io_result(
            write(original_control, &wake_value, sizeof(wake_value)));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(target, replacement) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        discard_io_result(
            write(original_control, &wake_value, sizeof(wake_value)));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement = -1;
    if (write(original_control, &wake_value, sizeof(wake_value)) !=
        (ssize_t)sizeof(wake_value)) {
        report_detail(case_name, "original_wakeup_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d value:0x%llx\n",
            case_name, (long)call.result, call.error_number,
            (unsigned long long)result_value);
    if (call.result != (ssize_t)sizeof(result_value) ||
        call.error_number != 0 ||
        result_value != ORIGINAL_EVENT_VALUE ||
        !verify_reused_eventfd(case_name, target)) {
        report_detail(case_name, "result_or_replacement_mismatch");
        goto out;
    }
    passed = 1;

out:
    if (call.thread_created) {
        discard_io_result(
            write(original_control, &wake_value, sizeof(wake_value)));
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (target >= 0)
        close(target);
    if (original_control >= 0)
        close(original_control);
    if (replacement >= 0)
        close(replacement);
    return passed;
}

static int test_timerfd_read_close_reuse(void) {
    static const char case_name[] = "timerfd_read";
    int target = -1;
    int original_control = -1;
    int replacement = -1;
    blocked_call_t call;
    io_operation_t operation;
    struct itimerspec timer_value;
    uint64_t expirations = 0;
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    memset(&timer_value, 0, sizeof(timer_value));
    timer_value.it_value.tv_nsec = 50000000;
    target = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (target < 0 ||
        (original_control = dup(target)) < 0 ||
        (replacement = create_ready_eventfd(REUSED_EVENT_VALUE)) < 0) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    operation.descriptor = target;
    operation.buffer = &expirations;
    operation.length = sizeof(expirations);
    call_started = blocked_call_start(
        case_name, &call, read_operation, &operation, SYS_read);
    if (!call_started) {
        (void)timerfd_settime(
            original_control, 0, &timer_value, 0);
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(target, replacement) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        (void)timerfd_settime(
            original_control, 0, &timer_value, 0);
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement = -1;
    if (timerfd_settime(original_control, 0, &timer_value, 0) != 0) {
        report_detail(case_name, "original_wakeup_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d expirations:%llu\n",
            case_name, (long)call.result, call.error_number,
            (unsigned long long)expirations);
    if (call.result != (ssize_t)sizeof(expirations) ||
        call.error_number != 0 || expirations == 0 ||
        !verify_reused_eventfd(case_name, target)) {
        report_detail(case_name, "result_or_replacement_mismatch");
        goto out;
    }
    passed = 1;

out:
    if (call.thread_created) {
        (void)timerfd_settime(
            original_control, 0, &timer_value, 0);
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (target >= 0)
        close(target);
    if (original_control >= 0)
        close(original_control);
    if (replacement >= 0)
        close(replacement);
    return passed;
}

static int test_signalfd_read_close_reuse(void) {
    static const char case_name[] = "signalfd_read";
    int target = -1;
    int original_control = -1;
    int replacement = -1;
    blocked_call_t call;
    signalfd_read_operation_t operation;
    struct signalfd_siginfo signal_info;
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    memset(&operation, 0, sizeof(operation));
    memset(&signal_info, 0, sizeof(signal_info));
    sigemptyset(&operation.mask);
    sigaddset(&operation.mask, SIGUSR1);
    target = signalfd(-1, &operation.mask, SFD_CLOEXEC);
    if (target < 0 ||
        (original_control = dup(target)) < 0 ||
        (replacement = create_ready_eventfd(REUSED_EVENT_VALUE)) < 0) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    operation.io.descriptor = target;
    operation.io.buffer = &signal_info;
    operation.io.length = sizeof(signal_info);
    call_started = blocked_call_start(
        case_name, &call, signalfd_read_operation_call,
        &operation, SYS_read);
    if (!call_started) {
        if (call.thread_created)
            (void)pthread_kill(call.thread, SIGUSR1);
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(target, replacement) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        (void)pthread_kill(call.thread, SIGUSR1);
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement = -1;
    if (pthread_kill(call.thread, SIGUSR1) != 0) {
        report_detail(case_name, "original_wakeup_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d signo:%u code:%d tid:%u\n",
            case_name, (long)call.result, call.error_number,
            signal_info.ssi_signo, signal_info.ssi_code,
            signal_info.ssi_tid);
    if (operation.mask_error != 0 ||
        call.result != (ssize_t)sizeof(signal_info) ||
        call.error_number != 0 ||
        signal_info.ssi_signo != SIGUSR1 ||
        !verify_reused_eventfd(case_name, target)) {
        report_detail(case_name, "result_or_replacement_mismatch");
        goto out;
    }
    passed = 1;

out:
    if (call.thread_created) {
        (void)pthread_kill(call.thread, SIGUSR1);
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (target >= 0)
        close(target);
    if (original_control >= 0)
        close(original_control);
    if (replacement >= 0)
        close(replacement);
    return passed;
}

static socklen_t make_abstract_unix_address(struct sockaddr_un *address) {
    static atomic_uint sequence;
    unsigned instance =
        atomic_fetch_add_explicit(&sequence, 1u, memory_order_relaxed);
    int length;

    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    length = snprintf(address->sun_path + 1,
                      sizeof(address->sun_path) - 1u,
                      "edgeos-fd-reuse-%ld-%u",
                      (long)getpid(), instance);
    if (length < 0 ||
        length >= (int)(sizeof(address->sun_path) - 1u))
        return 0;
    return (socklen_t)(
        offsetof(struct sockaddr_un, sun_path) + 1u + (size_t)length);
}

static int connect_unix_client(const struct sockaddr_un *address,
                               socklen_t address_length) {
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (client < 0)
        return -1;
    if (connect(client, (const struct sockaddr *)address,
                address_length) != 0) {
        int saved_errno = errno;

        close(client);
        errno = saved_errno;
        return -1;
    }
    return client;
}

static int test_unix_accept_close_reuse(void) {
    static const char case_name[] = "unix_accept";
    int target = -1;
    int original_control = -1;
    int replacement = -1;
    int client = -1;
    int accepted = -1;
    blocked_call_t call;
    struct sockaddr_un address;
    socklen_t address_length;
    const char client_byte = 'C';
    char accepted_byte = '\0';
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    address_length = make_abstract_unix_address(&address);
    target = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (address_length == 0 || target < 0 ||
        bind(target, (const struct sockaddr *)&address,
             address_length) != 0 ||
        listen(target, 4) != 0 ||
        (original_control = dup(target)) < 0 ||
        (replacement = create_ready_eventfd(REUSED_EVENT_VALUE)) < 0) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    call_started = blocked_call_start(
        case_name, &call, accept_operation, &target, SYS_accept4);
    if (!call_started) {
        client = connect_unix_client(&address, address_length);
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(target, replacement) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        client = connect_unix_client(&address, address_length);
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement = -1;
    client = connect_unix_client(&address, address_length);
    if (client < 0) {
        report_detail(case_name, "original_connect_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    accepted = (int)call.result;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d accepted:%d\n",
            case_name, (long)call.result, call.error_number, accepted);
    if (accepted < 0 || call.error_number != 0 ||
        write(client, &client_byte, 1u) != 1 ||
        read(accepted, &accepted_byte, 1u) != 1 ||
        accepted_byte != client_byte ||
        !verify_reused_eventfd(case_name, target)) {
        report_detail(case_name, "result_or_replacement_mismatch");
        goto out;
    }
    passed = 1;

out:
    if (call.thread_created) {
        if (client < 0)
            client = connect_unix_client(&address, address_length);
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (accepted >= 0)
        close(accepted);
    if (client >= 0)
        close(client);
    if (target >= 0)
        close(target);
    if (original_control >= 0)
        close(original_control);
    if (replacement >= 0)
        close(replacement);
    return passed;
}

static int test_unix_receive_close_reuse(void) {
    static const char case_name[] = "unix_stream_receive";
    int pair[2] = {-1, -1};
    int replacement = -1;
    blocked_call_t call;
    io_operation_t operation;
    const char original_byte = 'S';
    char received_byte = '\0';
    int call_started = 0;
    int call_joined = 0;
    int passed = 0;

    memset(&call, 0, sizeof(call));
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0 ||
        (replacement = create_ready_eventfd(REUSED_EVENT_VALUE)) < 0) {
        report_detail(case_name, "setup_failed");
        goto out;
    }
    operation.descriptor = pair[0];
    operation.buffer = &received_byte;
    operation.length = 1u;
    call_started = blocked_call_start(
        case_name, &call, receive_operation, &operation, SYS_recvfrom);
    if (!call_started) {
        discard_io_result(send(pair[1], &original_byte, 1u, 0));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    if (replace_numeric_descriptor(pair[0], replacement) != 0) {
        report_detail(case_name, "descriptor_reuse_failed");
        discard_io_result(send(pair[1], &original_byte, 1u, 0));
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    replacement = -1;
    if (send(pair[1], &original_byte, 1u, 0) != 1) {
        report_detail(case_name, "original_wakeup_failed");
        call_joined = blocked_call_join(case_name, &call);
        goto out;
    }
    call_joined = blocked_call_join(case_name, &call);
    if (!call_joined)
        goto out;
    dprintf(STDOUT_FILENO,
            "result:%s:rc:%ld errno:%d byte:%c\n",
            case_name, (long)call.result, call.error_number,
            received_byte ? received_byte : '?');
    if (call.result != 1 || call.error_number != 0 ||
        received_byte != original_byte ||
        !verify_reused_eventfd(case_name, pair[0])) {
        report_detail(case_name, "result_or_replacement_mismatch");
        goto out;
    }
    passed = 1;

out:
    if (call.thread_created) {
        discard_io_result(send(pair[1], &original_byte, 1u, 0));
        call_joined = blocked_call_join(case_name, &call);
    }
    if (call_joined || !call.thread_created)
        blocked_call_destroy(&call);
    if (pair[0] >= 0)
        close(pair[0]);
    if (pair[1] >= 0)
        close(pair[1]);
    if (replacement >= 0)
        close(replacement);
    return passed;
}

int main(void) {
    struct sigaction action;

    setvbuf(stdout, 0, _IONBF, 0);
    memset(&action, 0, sizeof(action));
    action.sa_handler = hard_timeout_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, 0) != 0) {
        perror("sigaction(SIGALRM)");
        return 1;
    }
    alarm(PROBE_ALARM_SECONDS);

    report_case("pipe_read", test_pipe_read_close_reuse());
    report_case("pipe_write", test_pipe_write_close_reuse());
    report_case("pipe_readv", test_pipe_readv_close_reuse());
    report_case("pipe_writev", test_pipe_writev_close_reuse());
    report_case("eventfd_read", test_eventfd_read_close_reuse());
    report_case("timerfd_read", test_timerfd_read_close_reuse());
    report_case("signalfd_read", test_signalfd_read_close_reuse());
    report_case("unix_accept", test_unix_accept_close_reuse());
    report_case("unix_stream_receive",
                test_unix_receive_close_reuse());

    alarm(0);
    dprintf(STDOUT_FILENO,
            "fd_operation_close_reuse_abi:%s failures:%d cases:9\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
