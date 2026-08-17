/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Host-side regression tests for shared anonymous descriptor notifications.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/anonymous_fd.h"
#include "kernel/eventfd.h"
#include "kernel/inotify.h"
#include "kernel/linux_errno.h"
#include "kernel/signalfd.h"
#include "kernel/signalfd_runtime.h"
#include "kernel/timerfd.h"
#include "kernel/timerfd_runtime.h"

#include <assert.h>
#include <stdio.h>

#define TEST_TIMER_ID 7
#define TEST_SIGNALFD_ID 11

static int g_query_active;
static int g_timer_query_count;
static int g_signalfd_query_count;
static int g_notification_count;
static kernel_anonymous_fd_kind_t g_notified_kind;
static int32_t g_notified_object_id;
static void *g_notified_context;

int kernel_eventfd_create(uint32_t initial_value, int semaphore) {
    (void)initial_value;
    (void)semaphore;
    return 1;
}

void kernel_eventfd_release(int event_id) {
    (void)event_id;
}

int kernel_timerfd_create(int32_t clock_id) {
    (void)clock_id;
    return TEST_TIMER_ID;
}

void kernel_timerfd_release(int timer_id) {
    (void)timer_id;
}

int kernel_timerfd_query(int timer_id, kernel_timerfd_state_t *state) {
    int result;
    assert(state);
    assert(!g_query_active);
    g_query_active = 1;
    ++g_timer_query_count;
    result = timer_id == TEST_TIMER_ID ? 0 : -EDGE_LINUX_EBADF;
    if (!result) state->references = 1;
    g_query_active = 0;
    return result;
}

int kernel_signalfd_create(uint64_t mask) {
    (void)mask;
    return TEST_SIGNALFD_ID;
}

void kernel_signalfd_release(int signalfd_id) {
    (void)signalfd_id;
}

int kernel_signalfd_query(int signalfd_id, kernel_signalfd_state_t *state) {
    int result;
    assert(state);
    assert(!g_query_active);
    g_query_active = 1;
    ++g_signalfd_query_count;
    result = signalfd_id == TEST_SIGNALFD_ID ? 0 : -EDGE_LINUX_EBADF;
    if (!result) state->references = 1;
    g_query_active = 0;
    return result;
}

int kernel_inotify_create(void) {
    return 3;
}

void kernel_inotify_release(int inotify_id) {
    (void)inotify_id;
}

int kernel_inotify_query(int inotify_id, kernel_inotify_state_t *state) {
    (void)inotify_id;
    (void)state;
    return 0;
}

static int test_install(void *context, kernel_anonymous_fd_kind_t kind,
                        int32_t object_id, uint32_t status_flags,
                        uint32_t descriptor_flags) {
    (void)context;
    (void)kind;
    (void)object_id;
    (void)status_flags;
    (void)descriptor_flags;
    return 20;
}

static int test_object_id(void *context, int32_t descriptor,
                          kernel_anonymous_fd_kind_t kind) {
    (void)context;
    (void)kind;
    return descriptor;
}

static void test_state_changed(void *context,
                               kernel_anonymous_fd_kind_t kind,
                               int32_t object_id) {
    assert(!g_query_active);
    ++g_notification_count;
    g_notified_context = context;
    g_notified_kind = kind;
    g_notified_object_id = object_id;
}

int main(void) {
    static int backend_context;
    const kernel_anonymous_fd_backend_ops_t incomplete_ops = {
        .install = test_install,
        .object_id = test_object_id,
    };
    const kernel_anonymous_fd_backend_ops_t complete_ops = {
        .install = test_install,
        .object_id = test_object_id,
        .state_changed = test_state_changed,
    };

    assert(kernel_anonymous_fd_backend_register(
               &incomplete_ops, &backend_context) ==
           -EDGE_LINUX_EINVAL);
    kernel_timerfd_state_changed(TEST_TIMER_ID);
    assert(g_timer_query_count == 0);
    assert(g_notification_count == 0);

    assert(kernel_anonymous_fd_backend_register(
               &complete_ops, &backend_context) == 0);

    kernel_timerfd_state_changed(-1);
    assert(g_timer_query_count == 1);
    assert(g_notification_count == 0);
    kernel_timerfd_state_changed(TEST_TIMER_ID);
    assert(g_timer_query_count == 2);
    assert(g_notification_count == 1);
    assert(g_notified_context == &backend_context);
    assert(g_notified_kind == KERNEL_ANONYMOUS_FD_TIMER);
    assert(g_notified_object_id == TEST_TIMER_ID);

    kernel_signalfd_state_changed(TEST_SIGNALFD_ID + 1);
    assert(g_signalfd_query_count == 1);
    assert(g_notification_count == 1);
    kernel_signalfd_state_changed(TEST_SIGNALFD_ID);
    assert(g_signalfd_query_count == 2);
    assert(g_notification_count == 2);
    assert(g_notified_context == &backend_context);
    assert(g_notified_kind == KERNEL_ANONYMOUS_FD_SIGNAL);
    assert(g_notified_object_id == TEST_SIGNALFD_ID);

    printf("anonymous_fd_notification_unit: PASS\n");
    return 0;
}
