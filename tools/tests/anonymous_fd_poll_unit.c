/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for anonymous descriptor readiness policy. */

#include "kernel/anonymous_fd.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static kernel_anonymous_fd_poll_state_t state_for(
    kernel_anonymous_fd_kind_t kind) {
    kernel_anonymous_fd_poll_state_t state;
    memset(&state, 0, sizeof(state));
    state.kind = kind;
    state.valid = 1;
    return state;
}

int main(void) {
    kernel_anonymous_fd_poll_state_t state;

    assert(kernel_anonymous_fd_poll_events(0) ==
           KERNEL_ANONYMOUS_FD_POLL_NVAL);

    state = state_for(KERNEL_ANONYMOUS_FD_EVENT);
    assert(kernel_anonymous_fd_poll_events(&state) ==
           KERNEL_ANONYMOUS_FD_POLL_OUTPUT);
    state.counter = 1;
    assert(kernel_anonymous_fd_poll_events(&state) ==
           (KERNEL_ANONYMOUS_FD_POLL_INPUT |
            KERNEL_ANONYMOUS_FD_POLL_OUTPUT));
    state.counter = UINT64_MAX - 1u;
    assert(kernel_anonymous_fd_poll_events(&state) ==
           KERNEL_ANONYMOUS_FD_POLL_INPUT);

    state = state_for(KERNEL_ANONYMOUS_FD_TIMER);
    assert(kernel_anonymous_fd_poll_events(&state) == 0);
    state.canceled = 1;
    assert(kernel_anonymous_fd_poll_events(&state) ==
           KERNEL_ANONYMOUS_FD_POLL_INPUT);

    state = state_for(KERNEL_ANONYMOUS_FD_SIGNAL);
    state.pending = 1;
    assert(kernel_anonymous_fd_poll_events(&state) ==
           KERNEL_ANONYMOUS_FD_POLL_INPUT);
    state.kind = KERNEL_ANONYMOUS_FD_INOTIFY;
    assert(kernel_anonymous_fd_poll_events(&state) ==
           KERNEL_ANONYMOUS_FD_POLL_INPUT);
    state.kind = KERNEL_ANONYMOUS_FD_PID;
    assert(kernel_anonymous_fd_poll_events(&state) ==
           KERNEL_ANONYMOUS_FD_POLL_INPUT);

    puts("anonymous_fd_poll_unit: PASS");
    return 0;
}
