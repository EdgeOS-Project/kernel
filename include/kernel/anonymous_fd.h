/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral anonymous descriptor interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_ANONYMOUS_FD_H
#define EDGEOS_KERNEL_ANONYMOUS_FD_H

#include <stdint.h>

typedef enum kernel_anonymous_fd_kind {
    KERNEL_ANONYMOUS_FD_EVENT = 1,
    KERNEL_ANONYMOUS_FD_TIMER,
    KERNEL_ANONYMOUS_FD_SIGNAL,
    KERNEL_ANONYMOUS_FD_INOTIFY,
    KERNEL_ANONYMOUS_FD_FANOTIFY,
    KERNEL_ANONYMOUS_FD_USERFAULTFD,
    KERNEL_ANONYMOUS_FD_PERF_EVENT,
    KERNEL_ANONYMOUS_FD_PID,
    KERNEL_ANONYMOUS_FD_PRIME,
    KERNEL_ANONYMOUS_FD_MOUNT,
    KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE,
    KERNEL_ANONYMOUS_FD_IO_URING,
    KERNEL_ANONYMOUS_FD_LANDLOCK,
    KERNEL_ANONYMOUS_FD_BPF,
    KERNEL_ANONYMOUS_FD_SECCOMP,
} kernel_anonymous_fd_kind_t;

typedef struct kernel_anonymous_fd_poll_state {
    kernel_anonymous_fd_kind_t kind;
    uint64_t counter;
    uint8_t valid;
    uint8_t pending;
    uint8_t canceled;
    uint8_t writable;
    uint8_t error;
} kernel_anonymous_fd_poll_state_t;

#define KERNEL_ANONYMOUS_FD_POLL_INPUT  0x0001u
#define KERNEL_ANONYMOUS_FD_POLL_OUTPUT 0x0004u
#define KERNEL_ANONYMOUS_FD_POLL_ERROR  0x0008u
#define KERNEL_ANONYMOUS_FD_POLL_NVAL   0x0020u

typedef struct kernel_anonymous_fd_backend_ops {
    int (*install)(void *context, kernel_anonymous_fd_kind_t kind,
                   int32_t object_id, uint32_t status_flags,
                   uint32_t descriptor_flags);
    int (*object_id)(void *context, int32_t descriptor,
                     kernel_anonymous_fd_kind_t kind);
    void (*state_changed)(void *context,
                          kernel_anonymous_fd_kind_t kind,
                          int32_t object_id);
} kernel_anonymous_fd_backend_ops_t;

int kernel_anonymous_fd_backend_register(
    const kernel_anonymous_fd_backend_ops_t *ops, void *context);
int kernel_anonymous_fd_install_descriptor(
    kernel_anonymous_fd_kind_t kind, int32_t object_id,
    uint32_t status_flags, uint32_t descriptor_flags);
int kernel_anonymous_fd_descriptor_object_id(
    int32_t descriptor, kernel_anonymous_fd_kind_t kind);
uint32_t kernel_anonymous_fd_poll_events(
    const kernel_anonymous_fd_poll_state_t *state);
void kernel_bpf_ringbuf_state_changed(void);

#endif
