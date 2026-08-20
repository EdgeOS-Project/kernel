/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral anonymous descriptor policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/anonymous_fd.h"
#include "kernel/event_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/inotify.h"
#include "kernel/inotify_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/posix_mq_runtime.h"
#include "kernel/signal_queue.h"
#include "kernel/signal_runtime.h"
#include "kernel/signalfd.h"
#include "kernel/signalfd_runtime.h"
#include "kernel/timerfd.h"
#include "kernel/timerfd_runtime.h"

#define KERNEL_ANONYMOUS_FD_RDWR 0x00000002u

static const kernel_anonymous_fd_backend_ops_t *g_backend_ops;
static void *g_backend_context;

int kernel_anonymous_fd_backend_register(
    const kernel_anonymous_fd_backend_ops_t *ops, void *context) {
    if (!ops || !ops->install || !ops->object_id || !ops->state_changed)
        return -EDGE_LINUX_EINVAL;
    g_backend_ops = ops;
    g_backend_context = context;
    return 0;
}

int kernel_anonymous_fd_install_descriptor(
    kernel_anonymous_fd_kind_t kind, int32_t object_id,
    uint32_t status_flags, uint32_t descriptor_flags) {
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    return g_backend_ops->install(
        g_backend_context, kind, object_id, status_flags, descriptor_flags);
}

int kernel_anonymous_fd_descriptor_object_id(
    int32_t descriptor, kernel_anonymous_fd_kind_t kind) {
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    return g_backend_ops->object_id(
        g_backend_context, descriptor, kind);
}

int kernel_eventfd_create_descriptor(uint32_t initial_value,
                                     uint32_t flags) {
    int object_id = kernel_eventfd_create(
        initial_value, (flags & KERNEL_EVENTFD_SEMAPHORE) != 0);
    int descriptor;
    if (object_id < 0) return object_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_EVENT, object_id,
        KERNEL_ANONYMOUS_FD_RDWR |
            (flags & KERNEL_EVENTFD_NONBLOCK),
        flags & KERNEL_EVENTFD_CLOEXEC);
    if (descriptor < 0) kernel_eventfd_release(object_id);
    return descriptor;
}

int kernel_timerfd_create_descriptor(int32_t clock_id, uint32_t flags) {
    int object_id = kernel_timerfd_create(clock_id);
    int descriptor;
    if (object_id < 0) return object_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_TIMER, object_id,
        KERNEL_ANONYMOUS_FD_RDWR |
            (flags & KERNEL_TIMERFD_NONBLOCK),
        flags & KERNEL_TIMERFD_CLOEXEC);
    if (descriptor < 0) kernel_timerfd_release(object_id);
    return descriptor;
}

int kernel_timerfd_descriptor_id(int32_t descriptor) {
    kernel_timerfd_state_t state;
    int object_id = kernel_anonymous_fd_descriptor_object_id(
        descriptor, KERNEL_ANONYMOUS_FD_TIMER);
    if (object_id < 0) return object_id;
    return kernel_timerfd_query(object_id, &state) < 0 ?
        -EDGE_LINUX_EBADF : object_id;
}

static int anonymous_fd_object_is_live(
    kernel_anonymous_fd_kind_t kind, int32_t object_id) {
    if (kind == KERNEL_ANONYMOUS_FD_TIMER) {
        kernel_timerfd_state_t state;
        return kernel_timerfd_query(object_id, &state) == 0;
    }
    if (kind == KERNEL_ANONYMOUS_FD_SIGNAL) {
        kernel_signalfd_state_t state;
        return kernel_signalfd_query(object_id, &state) == 0;
    }
    if (kind == KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE) {
        kernel_posix_mq_state_t state;
        return kernel_posix_mq_query(object_id, &state) == 0;
    }
    return 0;
}

static void anonymous_fd_state_changed(
    kernel_anonymous_fd_kind_t kind, int32_t object_id) {
    if (!g_backend_ops || !anonymous_fd_object_is_live(kind, object_id))
        return;
    /*
     * Object queries release their subsystem lock before this callback.
     * Backends may safely scan descriptor tables and enter scheduler paths.
     */
    g_backend_ops->state_changed(
        g_backend_context, kind, object_id);
}

void kernel_timerfd_state_changed(int timer_id) {
    anonymous_fd_state_changed(KERNEL_ANONYMOUS_FD_TIMER, timer_id);
}

int kernel_signalfd_create_descriptor(uint64_t mask, uint32_t flags) {
    int object_id = kernel_signalfd_create(mask);
    int descriptor;
    if (object_id < 0) return object_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_SIGNAL, object_id,
        flags & KERNEL_SIGNALFD_NONBLOCK,
        flags & KERNEL_SIGNALFD_CLOEXEC);
    if (descriptor < 0) kernel_signalfd_release(object_id);
    return descriptor;
}

int kernel_signalfd_descriptor_id(int32_t descriptor) {
    kernel_signalfd_state_t state;
    int object_id = kernel_anonymous_fd_descriptor_object_id(
        descriptor, KERNEL_ANONYMOUS_FD_SIGNAL);
    if (object_id < 0) return object_id;
    return kernel_signalfd_query(object_id, &state) < 0 ?
        -EDGE_LINUX_EBADF : object_id;
}

void kernel_signalfd_state_changed(int signalfd_id) {
    anonymous_fd_state_changed(KERNEL_ANONYMOUS_FD_SIGNAL, signalfd_id);
}

void kernel_posix_mq_state_changed(int32_t queue_id) {
    anonymous_fd_state_changed(
        KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE, queue_id);
}

int kernel_posix_mq_deliver_notification(int32_t target_tgid,
                                         uint32_t signal,
                                         uint64_t value,
                                         int32_t sender_pid,
                                         uint32_t sender_uid) {
    uint8_t information[KERNEL_SIGNAL_INFO_SIZE];
    kernel_signal_info_build_sender(
        information, signal, -3, sender_pid, sender_uid, value);
    return kernel_linux_signal_send(
        target_tgid, signal, 0, information);
}

int kernel_inotify_create_descriptor(uint32_t flags) {
    int object_id = kernel_inotify_create();
    int descriptor;
    if (object_id < 0) return object_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_INOTIFY, object_id,
        flags & KERNEL_INOTIFY_NONBLOCK,
        flags & KERNEL_INOTIFY_CLOEXEC);
    if (descriptor < 0) kernel_inotify_release(object_id);
    return descriptor;
}

int kernel_inotify_descriptor_id(int32_t descriptor) {
    kernel_inotify_state_t state;
    int object_id = kernel_anonymous_fd_descriptor_object_id(
        descriptor, KERNEL_ANONYMOUS_FD_INOTIFY);
    if (object_id < 0) return object_id;
    return kernel_inotify_query(object_id, &state) < 0 ?
        -EDGE_LINUX_EBADF : object_id;
}
