/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux controlling-terminal policy.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_TTY_SESSION_H
#define EDGEOS_KERNEL_TTY_SESSION_H

#include <stdint.h>

typedef struct edge_linux_tty_session_state {
    int32_t session_id;
    int32_t foreground_pgid;
} edge_linux_tty_session_state_t;

typedef struct edge_linux_tty_session_caller {
    int32_t pid;
    int32_t sid;
    int32_t pgid;
    uint64_t effective_capabilities;
    uint8_t has_controlling_terminal;
    uint8_t terminal_is_controlling;
} edge_linux_tty_session_caller_t;

typedef struct edge_linux_tty_session_transition {
    int32_t displaced_session_id;
    int32_t displaced_foreground_pgid;
    int32_t detached_session_id;
    int32_t detached_foreground_pgid;
    uint8_t acquired;
    uint8_t detach_whole_session;
} edge_linux_tty_session_transition_t;

typedef void (*edge_linux_tty_console_writer_t)(void *context, char byte);
typedef void (*edge_linux_tty_console_release_t)(void *context);

int64_t edge_linux_tty_session_acquire(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    uint64_t argument,
    edge_linux_tty_session_transition_t *transition);

/* Return one when an open without O_NOCTTY acquired the terminal. */
int edge_linux_tty_session_acquire_on_open(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int no_controlling_terminal);

int64_t edge_linux_tty_session_detach(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    edge_linux_tty_session_transition_t *transition);

int64_t edge_linux_tty_session_get_foreground(
    const edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int32_t *pgid);
int64_t edge_linux_tty_session_get_id(
    const edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int32_t *sid);
/* PTY masters query the session owned by their slave without being its ctty. */
int64_t edge_linux_tty_session_get_peer_foreground(
    const edge_linux_tty_session_state_t *state, int32_t *pgid);
int64_t edge_linux_tty_session_get_peer_id(
    const edge_linux_tty_session_state_t *state, int32_t *sid);
int64_t edge_linux_tty_session_set_foreground(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int32_t pgid, int process_group_exists, int32_t process_group_sid);

void edge_linux_tty_session_release(
    edge_linux_tty_session_state_t *state,
    int32_t sid,
    edge_linux_tty_session_transition_t *transition);

/* Linux TIOCCONS permits one privileged console-redirection target. */
int64_t edge_linux_tty_console_redirect_install(
    void *owner, edge_linux_tty_console_writer_t writer, void *context,
    edge_linux_tty_console_release_t release, int privileged);
int64_t edge_linux_tty_console_redirect_reset(int privileged);
void edge_linux_tty_console_redirect_release(void *owner);
int edge_linux_tty_console_redirect_emit(char byte);

#endif
