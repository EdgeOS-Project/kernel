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

int kernel_pty_canonical_input_ready(const uint8_t *buffer,
                                     uint32_t read_position,
                                     uint32_t count,
                                     uint32_t capacity,
                                     uint8_t eof_character) {
    if (!buffer || !capacity || read_position >= capacity || !count)
        return 0;

    if (count >= capacity)
        return 1;
    while (count--) {
        uint8_t byte = buffer[read_position];

        if (byte == '\n' || (eof_character && byte == eof_character))
            return 1;
        read_position = (read_position + 1u) % capacity;
    }
    return 0;
}
