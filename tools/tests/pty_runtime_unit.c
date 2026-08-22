/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for shared PTY readiness policy. */

#include "kernel/pty_runtime.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    kernel_pty_poll_state_t state;
    uint8_t input[8];
    uint32_t events;

    memset(&state, 0, sizeof(state));
    assert(kernel_pty_poll_events(&state) == KERNEL_PTY_POLL_NVAL);

    state.valid = 1;
    state.capacity = 4096;
    state.peer_references = 1;
    assert(kernel_pty_poll_events(&state) == KERNEL_PTY_POLL_OUTPUT);

    state.read_count = 8;
    assert(kernel_pty_readable_bytes(&state) == 8);
    events = kernel_pty_poll_events(&state);
    assert(events == (KERNEL_PTY_POLL_INPUT | KERNEL_PTY_POLL_OUTPUT));

    state.write_count = state.capacity;
    assert(kernel_pty_poll_events(&state) == KERNEL_PTY_POLL_INPUT);

    state.peer_references = 0;
    events = kernel_pty_poll_events(&state);
    assert((events & (KERNEL_PTY_POLL_INPUT | KERNEL_PTY_POLL_ERROR |
                      KERNEL_PTY_POLL_HANGUP)) ==
           (KERNEL_PTY_POLL_INPUT | KERNEL_PTY_POLL_ERROR |
            KERNEL_PTY_POLL_HANGUP));
    assert(!(events & KERNEL_PTY_POLL_OUTPUT));

    state.read_count = state.capacity + 1;
    assert(kernel_pty_readable_bytes(&state) == state.capacity);
    state.valid = 0;
    assert(kernel_pty_readable_bytes(&state) == 0);

    memset(input, 0, sizeof(input));
    input[0] = 'r';
    input[1] = 'o';
    input[2] = 'o';
    input[3] = 't';
    assert(!kernel_pty_canonical_input_ready(
        input, 0, 4, sizeof(input), 4));
    input[4] = '\n';
    assert(kernel_pty_canonical_input_ready(
        input, 0, 5, sizeof(input), 4));

    memset(input, 0, sizeof(input));
    input[7] = 'x';
    input[0] = 4;
    assert(kernel_pty_canonical_input_ready(
        input, 7, 2, sizeof(input), 4));
    assert(!kernel_pty_canonical_input_ready(
        input, 7, 1, sizeof(input), 4));
    assert(!kernel_pty_canonical_input_ready(
        input, 0, 1, sizeof(input), 0));
    assert(kernel_pty_canonical_input_ready(
        input, 0, sizeof(input), sizeof(input), 4));

    puts("pty_runtime_unit: PASS");
    return 0;
}
