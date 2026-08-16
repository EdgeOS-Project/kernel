/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side regression tests for shared Linux tty session policy. */

#include "kernel/linux_errno.h"
#include "kernel/tty_session.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    edge_linux_tty_session_state_t state;
    edge_linux_tty_session_caller_t caller;
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

    puts("tty_session_unit: PASS");
    return 0;
}
