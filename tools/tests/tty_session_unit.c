/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for shared Linux tty session policy. */

#include "kernel/linux_errno.h"
#include "kernel/tty_session.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#if defined(__aarch64__)
void spinlock_contention_relax(void) {}
#endif

int main(void) {
    edge_linux_tty_session_state_t state;
    edge_linux_tty_session_caller_t caller;
    edge_linux_tty_session_transition_t transition;
    int32_t value = -1;

    memset(&state, 0, sizeof(state));
    memset(&caller, 0, sizeof(caller));
    state.session_id = 41;
    state.foreground_pgid = 42;
    caller.pid = 7;
    caller.sid = 7;
    caller.pgid = 7;

    assert(edge_linux_tty_session_get_foreground(
               &state, &caller, &value) == -EDGE_LINUX_ENOTTY);
    assert(edge_linux_tty_session_get_peer_foreground(
               &state, &value) == 0);
    assert(value == 42);
    assert(edge_linux_tty_session_get_peer_id(&state, &value) == 0);
    assert(value == 41);
    assert(edge_linux_tty_session_get_peer_id(&state, 0) ==
           -EDGE_LINUX_EFAULT);

    memset(&transition, 0, sizeof(transition));
    edge_linux_tty_session_hangup(&state, &transition);
    assert(state.session_id == 0);
    assert(state.foreground_pgid == 0);
    assert(transition.detached_session_id == 41);
    assert(transition.detached_foreground_pgid == 42);
    assert(transition.detach_whole_session == 1);

    puts("tty_session_unit: PASS");
    return 0;
}
