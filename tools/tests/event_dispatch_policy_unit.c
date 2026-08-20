/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent event dispatch policy unit test.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>
#include <stdio.h>

#include "kernel/event_runtime.h"
#include "kernel/fanotify_runtime.h"
#include "kernel/inotify_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"

static int g_failures;
static int g_epoll_calls;
static int g_poll_calls;
static int g_select_calls;
static int g_inotify_calls;
static int g_fanotify_calls;

static void expect_true(const char *name, int condition) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", name);
    ++g_failures;
}

int64_t arch_epoll_wait_descriptor(int32_t epoll_descriptor,
                                   uint64_t user_events,
                                   uint32_t maximum_events,
                                   int64_t timeout_microseconds,
                                   int replace_signal_mask,
                                   uint64_t signal_mask,
                                   void *user_registers) {
    ++g_epoll_calls;
    return epoll_descriptor == 1 && user_events == 2u &&
           maximum_events == 3u && timeout_microseconds == 4 &&
           replace_signal_mask == 5 && signal_mask == 6u &&
           user_registers == (void *)(uintptr_t)7u ? 21 : -1;
}

int64_t arch_poll_wait_descriptors(uint64_t user_poll_fds,
                                   uint64_t descriptor_count,
                                   int64_t timeout_microseconds,
                                   uint64_t user_timeout,
                                   int replace_signal_mask,
                                   uint64_t signal_mask,
                                   void *user_registers) {
    ++g_poll_calls;
    return user_poll_fds == 8u && descriptor_count == 9u &&
           timeout_microseconds == 10 && user_timeout == 11u &&
           replace_signal_mask == 12 && signal_mask == 13u &&
           user_registers == (void *)(uintptr_t)14u ? 22 : -1;
}

int64_t arch_select_wait_descriptors(uint64_t descriptor_count,
                                     uint64_t user_read_set,
                                     uint64_t user_write_set,
                                     uint64_t user_except_set,
                                     int64_t timeout_microseconds,
                                     uint64_t user_timeout,
                                     uint32_t timeout_format,
                                     int replace_signal_mask,
                                     uint64_t signal_mask,
                                     void *user_registers) {
    ++g_select_calls;
    return descriptor_count == 15u && user_read_set == 16u &&
           user_write_set == 17u && user_except_set == 18u &&
           timeout_microseconds == 19 && user_timeout == 20u &&
           timeout_format == KERNEL_WAIT_TIMEOUT_TIMESPEC &&
           replace_signal_mask == 21 && signal_mask == 22u &&
           user_registers == (void *)(uintptr_t)23u ? 23 : -1;
}

void arch_inotify_state_changed(int inotify_id) {
    ++g_inotify_calls;
    if (inotify_id != 24) ++g_failures;
}

void arch_fanotify_state_changed(int group_id) {
    ++g_fanotify_calls;
    if (group_id != 7) ++g_failures;
}

static void test_wait_dispatch(void) {
    expect_true("epoll dispatch",
                kernel_epoll_wait_descriptor(
                    1, 2, 3, 4, 5, 6,
                    (void *)(uintptr_t)7u) == 21 &&
                g_epoll_calls == 1);
    expect_true("poll descriptor limit",
                kernel_poll_wait_descriptors(
                    8, KERNEL_WAIT_DESCRIPTOR_MAX + 1u,
                    10, 11, 12, 13,
                    (void *)(uintptr_t)14u) == -EDGE_LINUX_EINVAL &&
                g_poll_calls == 0);
    expect_true("poll dispatch",
                kernel_poll_wait_descriptors(
                    8, 9, 10, 11, 12, 13,
                    (void *)(uintptr_t)14u) == 22 &&
                g_poll_calls == 1);
    expect_true("select descriptor limit",
                kernel_select_wait_descriptors(
                    KERNEL_WAIT_DESCRIPTOR_MAX + 1u,
                    16, 17, 18, 19, 20,
                    KERNEL_WAIT_TIMEOUT_TIMESPEC,
                    21, 22, (void *)(uintptr_t)23u) ==
                    -EDGE_LINUX_EINVAL &&
                g_select_calls == 0);
    expect_true("select dispatch",
                kernel_select_wait_descriptors(
                    15, 16, 17, 18, 19, 20,
                    KERNEL_WAIT_TIMEOUT_TIMESPEC,
                    21, 22, (void *)(uintptr_t)23u) == 23 &&
                g_select_calls == 1);
}

static void test_inotify_dispatch(void) {
    kernel_inotify_state_changed(-1);
    kernel_inotify_state_changed(
        EDGE_RUNTIME_MAX_INOTIFY_INSTANCES);
    expect_true("inotify invalid range", g_inotify_calls == 0);
    kernel_inotify_state_changed(24);
    expect_true("inotify dispatch", g_inotify_calls == 1);
}

static void test_fanotify_dispatch(void) {
    kernel_fanotify_state_changed(-1);
    kernel_fanotify_state_changed(
        EDGE_RUNTIME_MAX_FANOTIFY_GROUPS);
    expect_true("fanotify invalid range", g_fanotify_calls == 0);
    kernel_fanotify_state_changed(7);
    expect_true("fanotify dispatch", g_fanotify_calls == 1);
}

int main(void) {
    test_wait_dispatch();
    test_inotify_dispatch();
    test_fanotify_dispatch();
    if (g_failures) return 1;
    puts("event_dispatch_policy_unit: PASS");
    return 0;
}
