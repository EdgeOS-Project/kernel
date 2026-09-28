/*
 * Original EdgeOS test code.
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Verify that every eventfd write can publish a fresh edge after userspace
 * drains the counter.  The writer deliberately signals before the reader
 * enters its next epoll_wait(), which catches kernels that model EPOLLET with
 * a stale Boolean ready bit instead of a wait-queue readiness generation.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS 10000

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int event_descriptor;
static int consumed_iteration;
static int writer_error;

static void *writer_main(void *unused)
{
    uint64_t value = 1;

    (void)unused;
    for (int iteration = 1; iteration <= ITERATIONS; ++iteration) {
        pthread_mutex_lock(&lock);
        while (consumed_iteration != iteration - 1)
            pthread_cond_wait(&condition, &lock);
        if (write(event_descriptor, &value, sizeof(value)) != sizeof(value)) {
            writer_error = errno ? errno : EIO;
            pthread_cond_broadcast(&condition);
            pthread_mutex_unlock(&lock);
            return NULL;
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main(void)
{
    struct epoll_event registration = {0};
    struct epoll_event result = {0};
    pthread_t writer;
    int epoll_descriptor;

    setvbuf(stdout, NULL, _IONBF, 0);
    event_descriptor = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (event_descriptor < 0) {
        perror("eventfd");
        return 1;
    }
    epoll_descriptor = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_descriptor < 0) {
        perror("epoll_create1");
        return 1;
    }
    registration.events = EPOLLIN | EPOLLET;
    registration.data.u64 = 0x454447454f534546ull;
    if (epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, event_descriptor,
                  &registration) != 0) {
        perror("epoll_ctl");
        return 1;
    }
    if (pthread_create(&writer, NULL, writer_main, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    for (int iteration = 1; iteration <= ITERATIONS; ++iteration) {
        uint64_t value = 0;
        int ready = epoll_wait(epoll_descriptor, &result, 1, 5000);

        if (ready != 1 || !(result.events & EPOLLIN) ||
            result.data.u64 != registration.data.u64) {
            fprintf(stderr,
                    "EPOLL_EVENTFD_EDGE_FAIL iteration=%d ready=%d "
                    "events=0x%x data=0x%llx writer_error=%d\n",
                    iteration, ready, result.events,
                    (unsigned long long)result.data.u64, writer_error);
            return 1;
        }
        if (read(event_descriptor, &value, sizeof(value)) != sizeof(value) ||
            value != 1) {
            fprintf(stderr,
                    "EPOLL_EVENTFD_EDGE_FAIL iteration=%d read_errno=%d "
                    "value=%llu\n",
                    iteration, errno, (unsigned long long)value);
            return 1;
        }
        pthread_mutex_lock(&lock);
        consumed_iteration = iteration;
        pthread_cond_broadcast(&condition);
        pthread_mutex_unlock(&lock);
    }

    pthread_join(writer, NULL);
    if (writer_error) {
        fprintf(stderr, "EPOLL_EVENTFD_EDGE_FAIL writer_error=%d\n",
                writer_error);
        return 1;
    }
    puts("EPOLL_EVENTFD_EDGE_PASS iterations="
         "10000");
    return 0;
}
