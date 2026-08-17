/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent PTY readiness policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/pty_runtime.h"

uint32_t kernel_pty_poll_events(const kernel_pty_poll_state_t *state) {
    uint32_t events = 0;

    if (!state || !state->valid || !state->capacity)
        return KERNEL_PTY_POLL_NVAL;
    if (state->read_count)
        events |= KERNEL_PTY_POLL_INPUT;
    if (!state->peer_references)
        return events | KERNEL_PTY_POLL_ERROR | KERNEL_PTY_POLL_HANGUP;
    if (state->write_count < state->capacity)
        events |= KERNEL_PTY_POLL_OUTPUT;
    return events;
}

uint32_t kernel_pty_readable_bytes(const kernel_pty_poll_state_t *state) {
    if (!state || !state->valid || !state->capacity)
        return 0;
    return state->read_count > state->capacity ?
           state->capacity : state->read_count;
}
