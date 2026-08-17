/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux controlling-terminal policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/tty_session.h"

#include "kernel/credentials.h"
#include "kernel/linux_errno.h"
#include "sys/spinlock.h"

typedef struct edge_linux_tty_console_redirect {
    void *owner;
    void *context;
    edge_linux_tty_console_writer_t writer;
    edge_linux_tty_console_release_t release;
    spinlock_t lock;
} edge_linux_tty_console_redirect_t;

static edge_linux_tty_console_redirect_t g_console_redirect;

static void tty_transition_reset(
    edge_linux_tty_session_transition_t *transition) {
    if (!transition) return;
    transition->displaced_session_id = 0;
    transition->displaced_foreground_pgid = 0;
    transition->detached_session_id = 0;
    transition->detached_foreground_pgid = 0;
    transition->acquired = 0;
    transition->detach_whole_session = 0;
}

static int tty_caller_is_privileged(
    const edge_linux_tty_session_caller_t *caller) {
    return caller &&
           (caller->effective_capabilities &
            (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)) != 0;
}

int64_t edge_linux_tty_session_acquire(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    uint64_t argument,
    edge_linux_tty_session_transition_t *transition) {
    int32_t old_sid;
    int32_t old_pgid;

    tty_transition_reset(transition);
    if (!state || !caller) return -EDGE_LINUX_EINVAL;
    if (caller->pid != caller->sid) return -EDGE_LINUX_EPERM;

    if (state->session_id == caller->sid) {
        if (caller->has_controlling_terminal &&
            !caller->terminal_is_controlling)
            return -EDGE_LINUX_EPERM;
        if (!caller->terminal_is_controlling && transition)
            transition->acquired = 1;
        state->foreground_pgid = caller->pgid;
        return 0;
    }
    if (caller->has_controlling_terminal) return -EDGE_LINUX_EPERM;

    old_sid = state->session_id;
    old_pgid = state->foreground_pgid;
    if (old_sid != 0 &&
        (argument != 1u || !tty_caller_is_privileged(caller)))
        return -EDGE_LINUX_EPERM;

    state->session_id = caller->sid;
    state->foreground_pgid = caller->pgid;
    if (transition) {
        transition->displaced_session_id = old_sid;
        transition->displaced_foreground_pgid = old_pgid;
        transition->acquired = 1;
    }
    return 0;
}

int edge_linux_tty_session_acquire_on_open(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int no_controlling_terminal) {
    if (!state || !caller || no_controlling_terminal) return 0;
    if (caller->pid != caller->sid || caller->has_controlling_terminal)
        return 0;
    if (state->session_id != 0 && state->session_id != caller->sid)
        return 0;
    state->session_id = caller->sid;
    state->foreground_pgid = caller->pgid;
    return 1;
}

int64_t edge_linux_tty_session_detach(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    edge_linux_tty_session_transition_t *transition) {
    tty_transition_reset(transition);
    if (!state || !caller) return -EDGE_LINUX_EINVAL;
    if (!caller->has_controlling_terminal ||
        !caller->terminal_is_controlling ||
        state->session_id == 0 || state->session_id != caller->sid)
        return -EDGE_LINUX_ENOTTY;

    if (caller->pid == caller->sid) {
        if (transition) {
            transition->detached_session_id = state->session_id;
            transition->detached_foreground_pgid = state->foreground_pgid;
            transition->detach_whole_session = 1;
        }
        state->session_id = 0;
        state->foreground_pgid = 0;
    }
    return 0;
}

static int64_t tty_session_readable(
    const edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller) {
    if (!state || !caller) return -EDGE_LINUX_EINVAL;
    if (!caller->has_controlling_terminal ||
        !caller->terminal_is_controlling ||
        state->session_id == 0 || state->session_id != caller->sid)
        return -EDGE_LINUX_ENOTTY;
    return 0;
}

int64_t edge_linux_tty_session_get_foreground(
    const edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int32_t *pgid) {
    int64_t result = tty_session_readable(state, caller);
    if (result < 0) return result;
    if (!pgid) return -EDGE_LINUX_EFAULT;
    *pgid = state->foreground_pgid;
    return 0;
}

int64_t edge_linux_tty_session_get_id(
    const edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int32_t *sid) {
    int64_t result = tty_session_readable(state, caller);
    if (result < 0) return result;
    if (!sid) return -EDGE_LINUX_EFAULT;
    *sid = state->session_id;
    return 0;
}

int64_t edge_linux_tty_session_get_peer_foreground(
    const edge_linux_tty_session_state_t *state, int32_t *pgid) {
    if (!state) return -EDGE_LINUX_EINVAL;
    if (!pgid) return -EDGE_LINUX_EFAULT;
    *pgid = state->foreground_pgid;
    return 0;
}

int64_t edge_linux_tty_session_get_peer_id(
    const edge_linux_tty_session_state_t *state, int32_t *sid) {
    if (!state) return -EDGE_LINUX_EINVAL;
    if (!sid) return -EDGE_LINUX_EFAULT;
    *sid = state->session_id;
    return 0;
}

int64_t edge_linux_tty_session_set_foreground(
    edge_linux_tty_session_state_t *state,
    const edge_linux_tty_session_caller_t *caller,
    int32_t pgid, int process_group_exists, int32_t process_group_sid) {
    int64_t result = tty_session_readable(state, caller);
    if (result < 0) return result;
    if (pgid <= 0) return -EDGE_LINUX_EINVAL;
    if (!process_group_exists || process_group_sid != caller->sid)
        return -EDGE_LINUX_EPERM;
    state->foreground_pgid = pgid;
    return 0;
}

void edge_linux_tty_session_release(
    edge_linux_tty_session_state_t *state,
    int32_t sid,
    edge_linux_tty_session_transition_t *transition) {
    tty_transition_reset(transition);
    if (!state || sid <= 0 || state->session_id != sid) return;
    if (transition) {
        transition->detached_session_id = state->session_id;
        transition->detached_foreground_pgid = state->foreground_pgid;
        transition->detach_whole_session = 1;
    }
    state->session_id = 0;
    state->foreground_pgid = 0;
}

int64_t edge_linux_tty_console_redirect_install(
    void *owner, edge_linux_tty_console_writer_t writer, void *context,
    edge_linux_tty_console_release_t release, int privileged) {
    uint64_t interrupt_flags;
    int64_t result = 0;

    if (!privileged) return -EDGE_LINUX_EPERM;
    if (!owner || !writer) return -EDGE_LINUX_EINVAL;
    interrupt_flags = spin_lock_irqsave(&g_console_redirect.lock);
    if (g_console_redirect.owner) {
        result = -EDGE_LINUX_EBUSY;
    } else {
        g_console_redirect.owner = owner;
        g_console_redirect.context = context;
        g_console_redirect.writer = writer;
        g_console_redirect.release = release;
    }
    spin_unlock_irqrestore(&g_console_redirect.lock, interrupt_flags);
    return result;
}

int64_t edge_linux_tty_console_redirect_reset(int privileged) {
    edge_linux_tty_console_release_t release;
    void *context;
    uint64_t interrupt_flags;
    if (!privileged) return -EDGE_LINUX_EPERM;
    interrupt_flags = spin_lock_irqsave(&g_console_redirect.lock);
    release = g_console_redirect.release;
    context = g_console_redirect.context;
    g_console_redirect.owner = 0;
    g_console_redirect.context = 0;
    g_console_redirect.writer = 0;
    g_console_redirect.release = 0;
    spin_unlock_irqrestore(&g_console_redirect.lock, interrupt_flags);
    if (release) release(context);
    return 0;
}

void edge_linux_tty_console_redirect_release(void *owner) {
    uint64_t interrupt_flags;
    if (!owner) return;
    interrupt_flags = spin_lock_irqsave(&g_console_redirect.lock);
    if (g_console_redirect.owner == owner) {
        g_console_redirect.owner = 0;
        g_console_redirect.context = 0;
        g_console_redirect.writer = 0;
        g_console_redirect.release = 0;
    }
    spin_unlock_irqrestore(&g_console_redirect.lock, interrupt_flags);
}

int edge_linux_tty_console_redirect_emit(char byte) {
    edge_linux_tty_console_writer_t writer;
    void *context;
    uint64_t interrupt_flags;

    interrupt_flags = spin_lock_irqsave(&g_console_redirect.lock);
    writer = g_console_redirect.writer;
    context = g_console_redirect.context;
    if (writer) writer(context, byte);
    spin_unlock_irqrestore(&g_console_redirect.lock, interrupt_flags);
    return writer != 0;
}
