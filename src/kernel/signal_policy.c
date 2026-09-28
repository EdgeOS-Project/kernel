/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux signal policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/signal_policy.h"
#include "kernel/process_runtime.h"

int edge_linux_signal_valid(uint32_t signal) {
    return signal > 0u && signal <= EDGE_LINUX_SIGNAL_MAX;
}

int edge_linux_signal_catchable(uint32_t signal) {
    return edge_linux_signal_valid(signal) &&
           signal != EDGE_LINUX_SIGKILL && signal != EDGE_LINUX_SIGSTOP;
}

uint64_t edge_linux_signal_mask_bit(uint32_t signal) {
    return edge_linux_signal_valid(signal) ?
        UINT64_C(1) << (signal - 1u) : 0u;
}

uint64_t edge_linux_signal_sanitize_mask(uint64_t mask) {
    return mask & ~EDGE_LINUX_SIGNAL_UNBLOCKABLE_MASK;
}

uint32_t edge_linux_signal_altstack_report_flags(uint32_t stored_flags,
                                                 int on_stack) {
    uint32_t mode = on_stack ? EDGE_LINUX_SS_ONSTACK :
        ((stored_flags & EDGE_LINUX_SS_DISABLE) ?
            EDGE_LINUX_SS_DISABLE : 0u);
    return mode | (stored_flags & EDGE_LINUX_SS_AUTODISARM);
}

edge_linux_signal_altstack_status_t edge_linux_signal_altstack_normalize(
    const struct edge_linux_stack64 *requested, uint64_t minimum_size,
    struct edge_linux_stack64 *normalized) {
    uint32_t flags;
    uint32_t mode;
    if (!requested || !normalized)
        return EDGE_LINUX_SIGNAL_ALTSTACK_INVALID;
    *normalized = *requested;
    flags = (uint32_t)requested->flags;
    mode = flags & ~EDGE_LINUX_SS_AUTODISARM;
    if (mode != 0u && mode != EDGE_LINUX_SS_DISABLE &&
        mode != EDGE_LINUX_SS_ONSTACK)
        return EDGE_LINUX_SIGNAL_ALTSTACK_INVALID;
    if (mode == EDGE_LINUX_SS_DISABLE) {
        normalized->sp = 0;
        normalized->size = 0;
    } else if (requested->size < minimum_size) {
        return EDGE_LINUX_SIGNAL_ALTSTACK_TOO_SMALL;
    }
    normalized->padding = 0;
    return EDGE_LINUX_SIGNAL_ALTSTACK_VALID;
}

int edge_linux_signal_frame_restore(
    void *user_registers, uint64_t signal_mask,
    const struct edge_linux_stack64 *signal_stack) {
    kernel_signal_altstack_state_t current;
    struct edge_linux_stack64 normalized;
    edge_linux_signal_altstack_status_t status;

    if (!signal_stack || kernel_current_signal_altstack_get(
            user_registers, &current) < 0)
        return -1;
    if (kernel_current_signal_mask_set(signal_mask) < 0) return -1;
    if (current.on_stack) return 0;
    if (current.stack_pointer == signal_stack->sp &&
        current.stack_size == signal_stack->size &&
        current.flags == (uint32_t)signal_stack->flags)
        return 0;
    status = edge_linux_signal_altstack_normalize(
        signal_stack, current.minimum_size, &normalized);
    if (status != EDGE_LINUX_SIGNAL_ALTSTACK_VALID) return 0;
    return kernel_current_signal_altstack_set(
        normalized.sp, normalized.size, (uint32_t)normalized.flags);
}

edge_linux_signal_default_disposition_t
edge_linux_signal_default_disposition(uint32_t signal) {
    switch (signal) {
        case EDGE_LINUX_SIGCHLD:
        case EDGE_LINUX_SIGURG:
        case EDGE_LINUX_SIGWINCH:
            return EDGE_LINUX_SIGNAL_DEFAULT_IGNORE;
        case EDGE_LINUX_SIGCONT:
            return EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE;
        case EDGE_LINUX_SIGSTOP:
        case EDGE_LINUX_SIGTSTP:
        case EDGE_LINUX_SIGTTIN:
        case EDGE_LINUX_SIGTTOU:
            return EDGE_LINUX_SIGNAL_DEFAULT_STOP;
        case EDGE_LINUX_SIGQUIT:
        case EDGE_LINUX_SIGILL:
        case EDGE_LINUX_SIGTRAP:
        case EDGE_LINUX_SIGABRT:
        case EDGE_LINUX_SIGBUS:
        case EDGE_LINUX_SIGFPE:
        case EDGE_LINUX_SIGSEGV:
        case EDGE_LINUX_SIGXCPU:
        case EDGE_LINUX_SIGXFSZ:
        case EDGE_LINUX_SIGSYS:
            return EDGE_LINUX_SIGNAL_DEFAULT_CORE;
        default:
            return EDGE_LINUX_SIGNAL_DEFAULT_TERMINATE;
    }
}
