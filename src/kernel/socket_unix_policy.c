/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Unix socket lifecycle policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/socket_runtime.h"
#include "kernel/linux_errno.h"

#include <string.h>

int kernel_socket_type_has_peer_eof(uint32_t type) {
    return type == EDGE_LINUX_SOCK_STREAM ||
           type == EDGE_LINUX_SOCK_SEQPACKET;
}

int kernel_unix_socket_missing_peer_error(uint32_t type, int peer_closed) {
    if (!peer_closed) return -EDGE_LINUX_ENOTCONN;
    return type == EDGE_LINUX_SOCK_DGRAM ?
        -EDGE_LINUX_ECONNREFUSED : -EDGE_LINUX_EPIPE;
}

int32_t kernel_unix_socket_credential_pid(int32_t thread_id,
                                          int32_t thread_group_id) {
    return thread_group_id > 0 ? thread_group_id : thread_id;
}

void kernel_unix_socket_poll_policy(
    const kernel_unix_socket_poll_state_t *state,
    kernel_unix_socket_poll_result_t *result) {
    int record;
    int peer_has_room;

    if (!result) return;
    memset(result, 0, sizeof(*result));
    if (!state) return;

    record = state->type == EDGE_LINUX_SOCK_DGRAM ||
             state->type == EDGE_LINUX_SOCK_SEQPACKET;
    result->read_closed = state->shutdown_read ||
        (kernel_socket_type_has_peer_eof(state->type) && state->peer_eof);
    result->hangup =
        state->shutdown_read && state->shutdown_write;
    if (!result->hangup &&
        kernel_socket_type_has_peer_eof(state->type) &&
        state->peer_eof) {
        result->hangup = !state->peer_valid ||
                         state->peer_shutdown_read;
    }

    if (state->shutdown_write || state->peer_shutdown_read ||
        (state->peer_eof && !state->peer_valid)) {
        result->writable = 1;
        return;
    }
    if (record && !state->connected) {
        result->writable = 1;
        return;
    }
    if (!state->connected) return;
    if (!state->peer_valid) {
        result->writable = 1;
        return;
    }
    peer_has_room =
        state->peer_receive_used < state->peer_receive_capacity;
    if (record)
        peer_has_room = peer_has_room &&
            state->peer_record_count < state->peer_record_capacity;
    result->writable = peer_has_room;
}
