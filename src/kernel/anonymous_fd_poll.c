/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent anonymous descriptor readiness.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/anonymous_fd.h"

uint32_t kernel_anonymous_fd_poll_events(
    const kernel_anonymous_fd_poll_state_t *state) {
    uint32_t events = 0;

    if (!state || !state->valid) return KERNEL_ANONYMOUS_FD_POLL_NVAL;
    switch (state->kind) {
    case KERNEL_ANONYMOUS_FD_EVENT:
        if (state->counter) events |= KERNEL_ANONYMOUS_FD_POLL_INPUT;
        if (state->counter < UINT64_MAX - 1u)
            events |= KERNEL_ANONYMOUS_FD_POLL_OUTPUT;
        break;
    case KERNEL_ANONYMOUS_FD_TIMER:
        if (state->counter || state->canceled)
            events |= KERNEL_ANONYMOUS_FD_POLL_INPUT;
        break;
    case KERNEL_ANONYMOUS_FD_SIGNAL:
    case KERNEL_ANONYMOUS_FD_INOTIFY:
    case KERNEL_ANONYMOUS_FD_PID:
        if (state->pending) events |= KERNEL_ANONYMOUS_FD_POLL_INPUT;
        break;
    case KERNEL_ANONYMOUS_FD_MESSAGE_QUEUE:
        if (state->pending) events |= KERNEL_ANONYMOUS_FD_POLL_INPUT;
        if (state->writable) events |= KERNEL_ANONYMOUS_FD_POLL_OUTPUT;
        break;
    default:
        return KERNEL_ANONYMOUS_FD_POLL_NVAL;
    }
    return events;
}
