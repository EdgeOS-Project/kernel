/*
 * Original EdgeOS code licensed under MPL-2.0.
 *
 * Linux descriptor-control ABI probe for native and guest parity.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_close_range
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_close_range 436
#endif
#endif

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

static const char g_path[] = "/root/edgeos-fd-control-abi-probe";
static int g_failures;
static int g_thread_descriptor;
static long g_thread_close_result;
static int g_thread_close_errno;
static int g_thread_descriptor_errno;
static atomic_int g_owner_unshare_ready;
static atomic_int g_owner_unshare_go;
static int g_owner_unshare_descriptor;
static int g_owner_unshare_worker_result;
static int g_owner_unshare_worker_errno;

static void expect_result(const char *name, long result, int saved_errno,
                          long expected_result, int expected_errno) {
    dprintf(STDOUT_FILENO, "%s_rc:%ld errno:%d\n", name, result,
            saved_errno);
    if (result != expected_result || saved_errno != expected_errno)
        ++g_failures;
}

static void *unshare_close_thread(void *unused) {
    long result;
    (void)unused;
    errno = 0;
    result = syscall(SYS_close_range, (unsigned)g_thread_descriptor,
                     (unsigned)g_thread_descriptor, CLOSE_RANGE_UNSHARE);
    g_thread_close_result = result;
    g_thread_close_errno = errno;
    errno = 0;
    result = fcntl(g_thread_descriptor, F_GETFD);
    g_thread_descriptor_errno = result < 0 ? errno : 0;
    return 0;
}

static void *owner_unshare_peer(void *unused) {
    (void)unused;
    atomic_store_explicit(&g_owner_unshare_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&g_owner_unshare_go,
                                 memory_order_acquire))
        sched_yield();
    errno = 0;
    g_owner_unshare_worker_result =
        fcntl(g_owner_unshare_descriptor, F_GETFD);
    g_owner_unshare_worker_errno = errno;
    return 0;
}

static void test_basic_duplicates(int descriptor) {
    int duplicate;
    int exact;
    int flags;
    char byte = 0;

    errno = 0;
    duplicate = dup(descriptor);
    expect_result("dup", duplicate, errno, duplicate, 0);
    if (duplicate < 0) return;

    errno = 0;
    flags = fcntl(duplicate, F_GETFD);
    expect_result("dup_getfd", flags, errno, 0, 0);

    if (lseek(descriptor, 5, SEEK_SET) != 5 ||
        lseek(duplicate, 0, SEEK_CUR) != 5)
        ++g_failures;
    if (read(duplicate, &byte, 1) != 0 ||
        lseek(descriptor, 0, SEEK_CUR) != 5)
        ++g_failures;

    errno = 0;
    exact = dup2(descriptor, descriptor);
    expect_result("dup2_same", exact, errno, descriptor, 0);

    errno = 0;
    exact = dup3(descriptor, descriptor, 0);
    expect_result("dup3_same", exact, errno, -1, EINVAL);

    errno = 0;
    exact = dup3(descriptor, 100, O_CLOEXEC);
    expect_result("dup3_cloexec", exact, errno, 100, 0);
    if (exact == 100) {
        flags = fcntl(exact, F_GETFD);
        dprintf(STDOUT_FILENO, "dup3_fd_flags:%d\n", flags);
        if (flags != FD_CLOEXEC) ++g_failures;
    }

    errno = 0;
    exact = dup3(descriptor, 101, O_NONBLOCK);
    expect_result("dup3_bad_flags", exact, errno, -1, EINVAL);

    close(duplicate);
}

static void test_fcntl_flags(int descriptor) {
    int duplicate;
    int flags;
    int result;

    errno = 0;
    flags = fcntl(descriptor, F_GETFD);
    expect_result("fcntl_getfd", flags, errno, FD_CLOEXEC, 0);

    errno = 0;
    result = fcntl(descriptor, F_SETFD, FD_CLOEXEC | 0x4000);
    expect_result("fcntl_setfd_unknown", result, errno, 0, 0);
    flags = fcntl(descriptor, F_GETFD);
    dprintf(STDOUT_FILENO, "fcntl_setfd_filtered:%d\n", flags);
    if (flags != FD_CLOEXEC) ++g_failures;

    errno = 0;
    flags = fcntl(descriptor, F_GETFL);
    dprintf(STDOUT_FILENO, "fcntl_getfl_initial:0x%x errno:%d\n", flags,
            errno);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDWR ||
        (flags & O_CLOEXEC) || (flags & O_CREAT) || (flags & O_TRUNC))
        ++g_failures;

    duplicate = dup(descriptor);
    if (duplicate < 0) {
        ++g_failures;
        return;
    }
    errno = 0;
    result = fcntl(duplicate, F_SETFL,
                   O_WRONLY | O_APPEND | O_NONBLOCK | O_CLOEXEC | O_CREAT);
    expect_result("fcntl_setfl", result, errno, 0, 0);
    flags = fcntl(descriptor, F_GETFL);
    dprintf(STDOUT_FILENO, "fcntl_getfl_shared:0x%x\n", flags);
    if ((flags & O_ACCMODE) != O_RDWR || !(flags & O_APPEND) ||
        !(flags & O_NONBLOCK) || (flags & O_CLOEXEC) || (flags & O_CREAT))
        ++g_failures;
    close(duplicate);

    errno = 0;
    duplicate = fcntl(descriptor, F_DUPFD, 120);
    expect_result("fcntl_dupfd", duplicate, errno, 120, 0);
    if (duplicate >= 0 && fcntl(duplicate, F_GETFD) != 0) ++g_failures;

    errno = 0;
    result = fcntl(descriptor, F_DUPFD, -1);
    expect_result("fcntl_dupfd_negative", result, errno, -1, EINVAL);

    errno = 0;
    result = fcntl(descriptor, F_DUPFD_CLOEXEC, 121);
    expect_result("fcntl_dupfd_cloexec", result, errno, 121, 0);
    if (result >= 0 && fcntl(result, F_GETFD) != FD_CLOEXEC) ++g_failures;

    if (duplicate >= 0) close(duplicate);
    close(121);
}

static void test_close_range(int descriptor) {
    long result;
    int saved_errno;

    if (dup3(descriptor, 100, 0) != 100 ||
        dup3(descriptor, 101, 0) != 101 ||
        dup3(descriptor, 102, 0) != 102) {
        ++g_failures;
        return;
    }
    errno = 0;
    result = syscall(SYS_close_range, 100U, 102U, CLOSE_RANGE_CLOEXEC);
    saved_errno = errno;
    expect_result("close_range_cloexec", result, saved_errno, 0, 0);
    if (fcntl(100, F_GETFD) != FD_CLOEXEC ||
        fcntl(101, F_GETFD) != FD_CLOEXEC ||
        fcntl(102, F_GETFD) != FD_CLOEXEC)
        ++g_failures;

    errno = 0;
    result = syscall(SYS_close_range, 101U, 102U, 0U);
    saved_errno = errno;
    expect_result("close_range_close", result, saved_errno, 0, 0);
    if (fcntl(101, F_GETFD) != -1 || errno != EBADF ||
        fcntl(102, F_GETFD) != -1 || errno != EBADF)
        ++g_failures;

    errno = 0;
    result = syscall(SYS_close_range, 12U, 11U, 0U);
    saved_errno = errno;
    expect_result("close_range_reversed", result, saved_errno, -1, EINVAL);

    errno = 0;
    result = syscall(SYS_close_range, 0xffffffffU, 0xffffffffU, 0U);
    saved_errno = errno;
    expect_result("close_range_beyond", result, saved_errno, 0, 0);

    errno = 0;
    result = syscall(SYS_close_range, 100U, 100U, 1U);
    saved_errno = errno;
    expect_result("close_range_bad_flags", result, saved_errno, -1, EINVAL);
    close(100);
}

static void test_close_range_unshare(int descriptor) {
    pthread_t thread;
    int result;

    g_thread_descriptor = descriptor;
    g_thread_close_result = -2;
    g_thread_close_errno = 0;
    g_thread_descriptor_errno = 0;
    result = pthread_create(&thread, 0, unshare_close_thread, 0);
    if (result != 0 || pthread_join(thread, 0) != 0) {
        dprintf(STDOUT_FILENO, "close_range_unshare_thread_error:%d\n",
                result);
        ++g_failures;
        return;
    }
    dprintf(STDOUT_FILENO,
            "close_range_unshare_rc:%ld errno:%d thread_fd_errno:%d\n",
            g_thread_close_result, g_thread_close_errno,
            g_thread_descriptor_errno);
    if (g_thread_close_result != 0 || g_thread_close_errno != 0 ||
        g_thread_descriptor_errno != EBADF ||
        fcntl(descriptor, F_GETFD) < 0)
        ++g_failures;
}

static void test_owner_close_range_unshare(void) {
    pthread_t thread;
    long result;
    int descriptor;
    int owner_descriptor_result;
    int owner_descriptor_errno;
    int saved_errno;
    int thread_result;

    descriptor = open(g_path, O_RDONLY);
    if (descriptor < 0) {
        ++g_failures;
        return;
    }
    g_owner_unshare_descriptor = descriptor;
    g_owner_unshare_worker_result = -1;
    g_owner_unshare_worker_errno = 0;
    atomic_store(&g_owner_unshare_ready, 0);
    atomic_store(&g_owner_unshare_go, 0);
    thread_result = pthread_create(&thread, 0, owner_unshare_peer, 0);
    if (thread_result != 0) {
        dprintf(STDOUT_FILENO, "owner_unshare_thread_error:%d\n",
                thread_result);
        close(descriptor);
        ++g_failures;
        return;
    }
    while (!atomic_load_explicit(&g_owner_unshare_ready,
                                 memory_order_acquire))
        sched_yield();
    errno = 0;
    result = syscall(SYS_close_range, (unsigned)descriptor,
                     (unsigned)descriptor, CLOSE_RANGE_UNSHARE);
    saved_errno = errno;
    atomic_store_explicit(&g_owner_unshare_go, 1, memory_order_release);
    thread_result = pthread_join(thread, 0);
    errno = 0;
    owner_descriptor_result = fcntl(descriptor, F_GETFD);
    owner_descriptor_errno = errno;
    dprintf(STDOUT_FILENO,
            "close_range_owner_unshare_rc:%ld errno:%d owner_fd_errno:%d peer_rc:%d peer_errno:%d\n",
            result, saved_errno, owner_descriptor_errno,
            g_owner_unshare_worker_result,
            g_owner_unshare_worker_errno);
    if (result != 0 || saved_errno != 0 || thread_result != 0 ||
        owner_descriptor_result != -1 || owner_descriptor_errno != EBADF ||
        g_owner_unshare_worker_result < 0 ||
        g_owner_unshare_worker_errno != 0)
        ++g_failures;
}

int main(void) {
    int descriptor;
    long result;
    int saved_errno;

    unlink(g_path);
    descriptor = open(g_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        dprintf(STDOUT_FILENO, "fd_control_setup_errno:%d\n", errno);
        return 1;
    }
    if (write(descriptor, "abcde", 5) != 5) ++g_failures;

    test_basic_duplicates(descriptor);
    test_fcntl_flags(descriptor);
    test_close_range(descriptor);
    test_close_range_unshare(descriptor);
    test_owner_close_range_unshare();

    errno = 0;
    result = close(-1);
    saved_errno = errno;
    expect_result("close_bad_fd", result, saved_errno, -1, EBADF);

    errno = 0;
    result = fcntl(descriptor, 0x7fffffff, 0);
    saved_errno = errno;
    expect_result("fcntl_unknown", result, saved_errno, -1, EINVAL);

    close(descriptor);
    unlink(g_path);
    dprintf(STDOUT_FILENO, "FD_CONTROL_ABI_PROBE_%s failures:%d\n",
            g_failures ? "FAIL" : "PASS", g_failures);
    return g_failures ? 1 : 0;
}
