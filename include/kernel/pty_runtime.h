/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent PTY readiness policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_PTY_RUNTIME_H
#define EDGEOS_KERNEL_PTY_RUNTIME_H

#include <stdint.h>

typedef struct kernel_pty_poll_state {
    uint32_t read_count;
    uint32_t write_count;
    uint32_t capacity;
    uint32_t peer_references;
    uint8_t valid;
} kernel_pty_poll_state_t;

#define KERNEL_PTY_POLL_INPUT  0x0001u
#define KERNEL_PTY_POLL_OUTPUT 0x0004u
#define KERNEL_PTY_POLL_ERROR  0x0008u
#define KERNEL_PTY_POLL_HANGUP 0x0010u
#define KERNEL_PTY_POLL_NVAL   0x0020u

uint32_t kernel_pty_poll_events(const kernel_pty_poll_state_t *state);
uint32_t kernel_pty_readable_bytes(const kernel_pty_poll_state_t *state);
int kernel_pty_canonical_input_ready(const uint8_t *buffer,
                                     uint32_t read_position,
                                     uint32_t count,
                                     uint32_t capacity,
                                     uint8_t eof_character);

#endif
