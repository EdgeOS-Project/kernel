/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#ifndef SYS_getdents64
#define SYS_getdents64 217
#endif

#define THREADS 16
#ifndef ITERATIONS
#define ITERATIONS 20000
#endif

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

struct worker_args {
    const char *path;
    const char *required;
    const char *forbidden;
};

static pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_condition = PTHREAD_COND_INITIALIZER;
static int start_waiters;
static int start_released;
static atomic_int failures;

static int scan_once(const struct worker_args *args, int iteration) {
    unsigned char buffer[8192];
    char fd_link[64];
    char fd_target[256];
    int fd = open(args->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int found_required = 0;
    int found_forbidden = 0;

    if (fd < 0) return errno ? errno : EIO;
    if (iteration == 0) {
        struct statfs filesystem;
        int length;
        snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", fd);
        length = (int)readlink(fd_link, fd_target, sizeof(fd_target) - 1);
        if (length < 0) {
            strcpy(fd_target, "<readlink-failed>");
        } else {
            fd_target[length] = 0;
        }
        memset(&filesystem, 0, sizeof(filesystem));
        if (fstatfs(fd, &filesystem) < 0) filesystem.f_type = -errno;
        printf("fd_table_open tid=%ld path=%s fd=%d target=%s f_type=0x%lx\n",
               syscall(SYS_gettid), args->path, fd, fd_target,
               (unsigned long)filesystem.f_type);
    }
    for (;;) {
        long length = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
        if (length < 0) {
            int saved_errno = errno ? errno : EIO;
            close(fd);
            return saved_errno;
        }
        if (length == 0) break;
        for (long offset = 0; offset < length;) {
            struct linux_dirent64 *entry =
                (struct linux_dirent64 *)(void *)(buffer + offset);
            if (entry->d_reclen < offsetof(struct linux_dirent64, d_name) + 1 ||
                offset + entry->d_reclen > length) {
                close(fd);
                return EIO;
            }
            if (strcmp(entry->d_name, args->required) == 0)
                found_required = 1;
            if (strcmp(entry->d_name, args->forbidden) == 0)
                found_forbidden = 1;
            offset += entry->d_reclen;
        }
    }
    close(fd);
    if (found_required && !found_forbidden) return 0;
    return 100 + (found_required ? 1 : 0) + (found_forbidden ? 2 : 0);
}

static void *worker(void *opaque) {
    const struct worker_args *args = opaque;

    pthread_mutex_lock(&start_lock);
    ++start_waiters;
    pthread_cond_broadcast(&start_condition);
    while (!start_released)
        pthread_cond_wait(&start_condition, &start_lock);
    pthread_mutex_unlock(&start_lock);
    for (int iteration = 0; iteration < ITERATIONS; ++iteration) {
        if (atomic_load_explicit(&failures, memory_order_relaxed) != 0)
            break;
        int result = scan_once(args, iteration);
        if (result != 0) {
            int previous = atomic_fetch_add_explicit(
                &failures, 1, memory_order_relaxed);
            if (previous < 16) {
                printf("fd_table_mismatch path=%s iteration=%d error=%d\n",
                       args->path, iteration, result);
            }
            break;
        }
    }
    return NULL;
}

int main(void) {
    static const struct worker_args root = { "/", "lib", "meminfo" };
    static const struct worker_args proc = { "/proc", "meminfo", "lib" };
    pthread_t threads[THREADS];

    setvbuf(stdout, NULL, _IONBF, 0);
    atomic_init(&failures, 0);
    for (int index = 0; index < THREADS; ++index) {
        const struct worker_args *args = (index & 1) ? &proc : &root;
        int result = pthread_create(&threads[index], NULL, worker,
                                    (void *)args);
        if (result != 0) {
            printf("FD_SHARED_TABLE_PROBE_FAIL pthread_create=%d\n", result);
            return 1;
        }
    }
    pthread_mutex_lock(&start_lock);
    while (start_waiters != THREADS)
        pthread_cond_wait(&start_condition, &start_lock);
    start_released = 1;
    pthread_cond_broadcast(&start_condition);
    pthread_mutex_unlock(&start_lock);
    for (int index = 0; index < THREADS; ++index)
        pthread_join(threads[index], NULL);

    if (atomic_load_explicit(&failures, memory_order_relaxed) != 0) {
        printf("FD_SHARED_TABLE_PROBE_FAIL failures=%d\n",
               atomic_load_explicit(&failures, memory_order_relaxed));
        return 1;
    }
    puts("FD_SHARED_TABLE_PROBE_PASS");
    return 0;
}
