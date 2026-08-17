/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux signal runtime.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux keeps thread-directed and process-directed pending signals separate.
 * Standard signals coalesce while realtime signals retain queued siginfo
 * records.  This file owns that policy for every architecture.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/posix_timer_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/signal_queue.h"
#include "kernel/signal_runtime.h"
#include "kernel/signalfd.h"
#include "string.h"
#include "sys/boottime.h"

static void kernel_signal_write_i32(uint8_t *information, uint32_t offset,
                                    int32_t value) {
    memcpy(information + offset, &value, sizeof(value));
}

static void kernel_signal_write_u32(uint8_t *information, uint32_t offset,
                                    uint32_t value) {
    memcpy(information + offset, &value, sizeof(value));
}

static void kernel_signal_write_u64(uint8_t *information, uint32_t offset,
                                    uint64_t value) {
    memcpy(information + offset, &value, sizeof(value));
}

static int32_t kernel_signal_read_i32(const uint8_t *information,
                                      uint32_t offset) {
    int32_t value;
    memcpy(&value, information + offset, sizeof(value));
    return value;
}

int kernel_arch_signal_runtime_state(
    void *task_context, kernel_signal_runtime_state_t *state) {
    if (!state ||
        edge_process_runtime_signal_state(task_context, state) < 0)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

int kernel_arch_signal_action_install(
    uint32_t signal, const edge_linux_signal_action_t *action) {
    kernel_process_native_view_t current;

    if (!action || !edge_linux_signal_valid(signal))
        return -EDGE_LINUX_EINVAL;
    memset(&current, 0, sizeof(current));
    if (edge_process_runtime_current_view(&current) < 0)
        return -EDGE_LINUX_EINVAL;
    return edge_process_runtime_signal_action_install(signal, action) < 0 ?
        -EDGE_LINUX_EINVAL : 0;
}

void kernel_arch_signal_pending_discard(uint32_t signal) {
    kernel_process_native_view_t current;

    if (!edge_linux_signal_valid(signal)) return;
    memset(&current, 0, sizeof(current));
    if (edge_process_runtime_current_view(&current) < 0) return;
    edge_process_runtime_signal_pending_discard(signal);
}

int kernel_arch_signal_delivery_resolve(
    int32_t tid, int thread_directed, int32_t *queue_target) {
    kernel_process_native_view_t target;
    kernel_process_native_view_t leader;

    if (tid <= 0 || !queue_target) return -EDGE_LINUX_EINVAL;
    memset(&target, 0, sizeof(target));
    if (edge_process_runtime_view(tid, &target) < 0 || target.zombie ||
        target.pid <= 0 || target.tgid <= 0)
        return -EDGE_LINUX_ESRCH;
    if (!thread_directed) {
        memset(&leader, 0, sizeof(leader));
        if (edge_process_runtime_view(target.tgid, &leader) < 0 ||
            leader.zombie || leader.pid != target.tgid)
            return -EDGE_LINUX_ESRCH;
    }
    *queue_target = thread_directed ? target.pid : target.tgid;
    return 0;
}

int kernel_arch_signal_delivery_commit(
    int32_t tid, uint32_t signal, int thread_directed) {
    kernel_process_native_view_t target;
    int result;

    if (tid <= 0 || !edge_linux_signal_valid(signal))
        return -EDGE_LINUX_EINVAL;
    memset(&target, 0, sizeof(target));
    if (edge_process_runtime_view(tid, &target) < 0 || target.zombie)
        return -EDGE_LINUX_ESRCH;
    result = edge_process_runtime_signal_delivery_commit(
        tid, signal, thread_directed);
    if (result == -EDGE_LINUX_ENOENT || result == -EDGE_LINUX_ESRCH)
        return -EDGE_LINUX_ESRCH;
    return result;
}

int kernel_linux_signal_send(int32_t tid, uint32_t signal,
                             int thread_directed,
                             const void *signal_information) {
    kernel_signal_queue_ticket_t ticket;
    int32_t queue_target = 0;
    int result;

    if (tid <= 0 || !edge_linux_signal_valid(signal) ||
        !signal_information)
        return -EDGE_LINUX_EINVAL;
    result = kernel_arch_signal_delivery_resolve(
        tid, thread_directed, &queue_target);
    if (result < 0) return result;
    if (queue_target <= 0) return -EDGE_LINUX_ESRCH;
    /* A waking sigtimedwait may consume siginfo inside the commit hook. */
    result = kernel_signal_queue_enqueue_ticket(
        queue_target, signal, thread_directed, signal_information, &ticket);
    if (result < 0) return result;
    result = kernel_arch_signal_delivery_commit(
        tid, signal, thread_directed);
    if (result <= 0) kernel_signal_queue_cancel(&ticket);
    return result < 0 ? result : 0;
}

int kernel_signal_action_discards_pending(
    uint32_t signal, const edge_linux_signal_action_t *action) {
    if (!action || !edge_linux_signal_valid(signal)) return 0;
    return action->handler == EDGE_LINUX_SIG_IGN ||
        (action->handler == EDGE_LINUX_SIG_DFL &&
         edge_linux_signal_default_disposition(signal) ==
             EDGE_LINUX_SIGNAL_DEFAULT_IGNORE);
}

int kernel_signal_action_auto_reaps_child(
    uint32_t signal, const edge_linux_signal_action_t *action) {
    return signal == EDGE_LINUX_SIGCHLD && action &&
        (action->handler == EDGE_LINUX_SIG_IGN ||
         (action->flags & EDGE_LINUX_SA_NOCLDWAIT) != 0);
}

int kernel_signal_altstack_contains(
    uint64_t stack_pointer, uint64_t stack_size, uint32_t flags,
    uint64_t user_stack_pointer) {
    uint64_t end;
    if ((flags & EDGE_LINUX_SS_DISABLE) || !stack_pointer || !stack_size)
        return 0;
    end = stack_pointer + stack_size;
    return end > stack_pointer && user_stack_pointer >= stack_pointer &&
        user_stack_pointer < end;
}

void kernel_signal_wait_mask_install(
    kernel_signal_runtime_state_t *state, uint64_t temporary_mask) {
    if (!state || !state->blocked_mask || !state->saved_mask ||
        !state->restore_mask_pending)
        return;
    *state->saved_mask = *state->blocked_mask;
    *state->blocked_mask = edge_linux_signal_sanitize_mask(temporary_mask);
    *state->restore_mask_pending = 1;
}

void kernel_signal_wait_mask_finish(
    kernel_signal_runtime_state_t *state, int interrupted) {
    if (!state || !state->blocked_mask || !state->saved_mask ||
        !state->restore_mask_pending || !*state->restore_mask_pending ||
        interrupted)
        return;
    *state->blocked_mask = *state->saved_mask;
    *state->saved_mask = 0;
    *state->restore_mask_pending = 0;
}

uint64_t kernel_signal_wait_mask_take_for_frame(
    kernel_signal_runtime_state_t *state) {
    uint64_t mask;
    if (!state || !state->blocked_mask) return 0;
    if (!state->saved_mask || !state->restore_mask_pending ||
        !*state->restore_mask_pending)
        return *state->blocked_mask;
    mask = *state->saved_mask;
    *state->saved_mask = 0;
    *state->restore_mask_pending = 0;
    return mask;
}

void kernel_signal_wait_mask_cancel(kernel_signal_runtime_state_t *state) {
    if (!state) return;
    if (state->saved_mask) *state->saved_mask = 0;
    if (state->restore_mask_pending) *state->restore_mask_pending = 0;
}

uint64_t kernel_signal_pending_mask(
    const kernel_signal_runtime_state_t *state) {
    if (!state || !state->thread_pending || !state->shared_pending) return 0;
    return *state->thread_pending | *state->shared_pending;
}

uint32_t kernel_signal_pending_next(
    const kernel_signal_runtime_state_t *state, uint64_t selected_mask) {
    uint64_t available = kernel_signal_pending_mask(state) & selected_mask;
    for (uint32_t signal = 1; signal <= EDGE_LINUX_SIGNAL_MAX; ++signal)
        if (available & edge_linux_signal_mask_bit(signal)) return signal;
    return 0;
}

int kernel_signal_pending_peek(
    const kernel_signal_runtime_state_t *state, uint32_t signal,
    void *signal_information) {
    if (!state || !signal_information || !edge_linux_signal_valid(signal) ||
        state->tid <= 0 || state->tgid <= 0)
        return 0;
    if (kernel_signal_queue_peek(
            state->tid, signal, 1, signal_information))
        return 1;
    return kernel_signal_queue_peek(
        state->tgid, signal, 0, signal_information);
}

int kernel_signal_pending_consume(
    kernel_signal_runtime_state_t *state, uint32_t signal,
    void *signal_information, int *same_signal_remains) {
    uint8_t local_information[KERNEL_SIGNAL_INFO_SIZE];
    uint8_t *information = signal_information ?
        (uint8_t *)signal_information : local_information;
    uint64_t bit;
    int thread_remains = 0;
    int shared_remains = 0;
    int consumed = 0;

    if (same_signal_remains) *same_signal_remains = 0;
    if (!state || !state->thread_pending || !state->shared_pending ||
        !edge_linux_signal_valid(signal) || state->tid <= 0 ||
        state->tgid <= 0)
        return 0;

    memset(information, 0, KERNEL_SIGNAL_INFO_SIZE);
    bit = edge_linux_signal_mask_bit(signal);
    if (*state->thread_pending & bit) {
        consumed = kernel_signal_queue_consume(
            state->tid, signal, 1, information, &thread_remains);
        if (!thread_remains) *state->thread_pending &= ~bit;
    } else if (*state->shared_pending & bit) {
        consumed = kernel_signal_queue_consume(
            state->tgid, signal, 0, information, &shared_remains);
        if (!shared_remains) *state->shared_pending &= ~bit;
    } else {
        /* Recover a queued record if an older producer omitted its bit. */
        consumed = kernel_signal_queue_consume(
            state->tid, signal, 1, information, &thread_remains);
        if (!consumed)
            consumed = kernel_signal_queue_consume(
                state->tgid, signal, 0, information, &shared_remains);
    }

    if (consumed && kernel_signal_read_i32(information, 8u) == -2) {
        int32_t timer_id = kernel_signal_read_i32(information, 16u);
        int32_t overrun = kernel_signal_read_i32(information, 20u);
        if (timer_id > 0)
            kernel_posix_timer_signal_consumed(timer_id, overrun);
    }
    if (signal == EDGE_LINUX_SIGSYS &&
        !(kernel_signal_pending_mask(state) & bit) &&
        state->seccomp_sigsys_pending)
        *state->seccomp_sigsys_pending = 0;
    if (same_signal_remains)
        *same_signal_remains =
            (kernel_signal_pending_mask(state) & bit) != 0;
    return consumed;
}

static void kernel_signal_build_fallback_information(
    const kernel_signal_runtime_state_t *state, uint32_t signal,
    uint8_t information[KERNEL_SIGNAL_INFO_SIZE]) {
    memset(information, 0, KERNEL_SIGNAL_INFO_SIZE);
    kernel_signal_write_u32(information, 0u, signal);
    if (signal != EDGE_LINUX_SIGSYS || !state->seccomp_sigsys_pending ||
        !*state->seccomp_sigsys_pending)
        return;
    kernel_signal_write_i32(
        information, 4u, state->seccomp_sigsys_errno);
    kernel_signal_write_i32(information, 8u, 1); /* SYS_SECCOMP */
    kernel_signal_write_u64(
        information, 16u, state->seccomp_sigsys_call_address);
    kernel_signal_write_i32(
        information, 24u, state->seccomp_sigsys_number);
    kernel_signal_write_u32(
        information, 28u, state->seccomp_sigsys_architecture);
}

int64_t kernel_signal_pending_take(
    kernel_signal_runtime_state_t *state, uint64_t selected_mask,
    void *signal_information) {
    uint8_t information[KERNEL_SIGNAL_INFO_SIZE];
    uint32_t signal = kernel_signal_pending_next(state, selected_mask);
    if (!signal) return -EDGE_LINUX_EAGAIN;
    if (!kernel_signal_pending_peek(state, signal, information))
        kernel_signal_build_fallback_information(state, signal, information);
    if (signal_information)
        memcpy(signal_information, information, sizeof(information));
    (void)kernel_signal_pending_consume(state, signal, 0, 0);
    return (int64_t)signal;
}

int kernel_signal_pending_has_wake(
    kernel_signal_runtime_state_t *state, uint64_t blocked_mask) {
    if (!state || !state->actions) return 0;
    for (;;) {
        uint32_t signal = kernel_signal_pending_next(
            state, ~blocked_mask | EDGE_LINUX_SIGNAL_UNBLOCKABLE_MASK);
        edge_linux_signal_action_t *action;
        edge_linux_signal_default_disposition_t disposition;
        if (!signal) return 0;
        action = &state->actions[signal - 1u];
        disposition = edge_linux_signal_default_disposition(signal);
        if (action->handler != EDGE_LINUX_SIG_IGN &&
            !(action->handler == EDGE_LINUX_SIG_DFL &&
              (disposition == EDGE_LINUX_SIGNAL_DEFAULT_IGNORE ||
               disposition == EDGE_LINUX_SIGNAL_DEFAULT_CONTINUE)))
            return 1;
        (void)kernel_signal_pending_consume(state, signal, 0, 0);
    }
}

int kernel_signal_pending_dequeue_signalfd(
    kernel_signal_runtime_state_t *state, uint64_t selected_mask,
    struct edge_linux_signalfd_siginfo *information) {
    uint8_t signal_information[KERNEL_SIGNAL_INFO_SIZE];
    int64_t result;
    if (!state || !information) return -EDGE_LINUX_EINVAL;
    result = kernel_signal_pending_take(
        state, selected_mask, signal_information);
    if (result == -EDGE_LINUX_EAGAIN) return 0;
    if (result < 0) return (int)result;
    kernel_signalfd_siginfo_from_linux_siginfo(
        signal_information, information);
    return 1;
}

int kernel_current_signal_pending(uint64_t *pending) {
    kernel_signal_runtime_state_t state;
    if (!pending || kernel_arch_signal_runtime_state(0, &state) < 0)
        return -EDGE_LINUX_EINVAL;
    *pending = kernel_signal_pending_mask(&state);
    return 0;
}

int kernel_current_signal_wake_pending(void) {
    kernel_signal_runtime_state_t state;

    if (kernel_arch_signal_runtime_state(0, &state) < 0 ||
        !state.blocked_mask)
        return 0;
    return kernel_signal_pending_has_wake(
        &state, *state.blocked_mask);
}

static int64_t kernel_signal_timed_wait_evaluate(
    kernel_signal_runtime_state_t *state, uint64_t wanted_mask,
    uint64_t deadline_microseconds, uint8_t *information,
    int *should_block) {
    int64_t result;

    if (!state || !state->blocked_mask || !information || !should_block)
        return -EDGE_LINUX_EINVAL;
    *should_block = 0;
    result = kernel_signal_pending_take(state, wanted_mask, information);
    if (result != -EDGE_LINUX_EAGAIN) return result;
    if (kernel_signal_pending_has_wake(state, *state->blocked_mask))
        return -EDGE_LINUX_EINTR;
    if (deadline_microseconds != UINT64_MAX &&
        boottime_monotonic_us() >= deadline_microseconds)
        return -EDGE_LINUX_EAGAIN;
    *should_block = 1;
    return 0;
}

int64_t kernel_current_signal_suspend(uint64_t temporary_mask,
                                      void *user_registers) {
    kernel_signal_runtime_state_t state;
    int64_t result;

    if (kernel_arch_signal_runtime_state(0, &state) < 0 ||
        !state.blocked_mask || !state.saved_mask ||
        !state.restore_mask_pending)
        return -EDGE_LINUX_EINVAL;
    kernel_signal_wait_mask_install(&state, temporary_mask);
    for (;;) {
        if (kernel_signal_pending_has_wake(&state, temporary_mask))
            return -EDGE_LINUX_EINTR;
        result = kernel_arch_signal_wait_block(
            KERNEL_SIGNAL_WAIT_SUSPEND, 0, 0, UINT64_MAX,
            user_registers);
        if (result < 0) {
            if (kernel_arch_signal_runtime_state(0, &state) == 0)
                kernel_signal_wait_mask_finish(&state, 0);
            return result;
        }
        if (kernel_arch_signal_runtime_state(0, &state) < 0)
            return -EDGE_LINUX_EINTR;
    }
}

int64_t kernel_current_signal_timed_wait(
    uint64_t wanted_mask, uint64_t information_user,
    uint64_t deadline_microseconds, edge_linux_copy_to_user_fn copy_to_user,
    void *copy_context, void *user_registers) {
    uint8_t information[KERNEL_SIGNAL_INFO_SIZE];

    for (;;) {
        kernel_signal_runtime_state_t state;
        int should_block = 0;
        int64_t result;

        if (kernel_arch_signal_runtime_state(0, &state) < 0)
            return -EDGE_LINUX_EINVAL;
        result = kernel_signal_timed_wait_evaluate(
            &state, wanted_mask, deadline_microseconds, information,
            &should_block);
        if (!should_block) {
            if (result > 0 && information_user &&
                (!copy_to_user || copy_to_user(
                    copy_context, information_user, information,
                    sizeof(information)) < 0))
                return -EDGE_LINUX_EFAULT;
            return result;
        }
        result = kernel_arch_signal_wait_block(
            KERNEL_SIGNAL_WAIT_TIMED, wanted_mask, information_user,
            deadline_microseconds, user_registers);
        if (result < 0) return result;
    }
}

int kernel_current_signal_action_get(
    uint32_t signal, edge_linux_signal_action_t *action) {
    kernel_signal_runtime_state_t state;
    if (!action || !edge_linux_signal_valid(signal) ||
        kernel_arch_signal_runtime_state(0, &state) < 0 || !state.actions)
        return -EDGE_LINUX_EINVAL;
    *action = state.actions[signal - 1u];
    return 0;
}

int kernel_current_signal_action_set(
    uint32_t signal, const edge_linux_signal_action_t *action) {
    if (!action || !edge_linux_signal_catchable(signal))
        return -EDGE_LINUX_EINVAL;
    if (kernel_arch_signal_action_install(signal, action) < 0)
        return -EDGE_LINUX_EINVAL;
    if (kernel_signal_action_discards_pending(signal, action))
        kernel_arch_signal_pending_discard(signal);
    /*
     * SIG_IGN and SA_NOCLDWAIT affect children that exit after installation.
     * Linux leaves an already-waitable zombie intact even though installing
     * SIG_IGN discards its pending SIGCHLD.  Exit paths use
     * kernel_signal_action_auto_reaps_child(); do not reap children here.
     */
    return 0;
}

int kernel_current_signal_mask_get(uint64_t *mask) {
    kernel_signal_runtime_state_t state;
    if (!mask || kernel_arch_signal_runtime_state(0, &state) < 0 ||
        !state.blocked_mask)
        return -EDGE_LINUX_EINVAL;
    *mask = *state.blocked_mask;
    return 0;
}

int kernel_current_signal_mask_set(uint64_t mask) {
    kernel_signal_runtime_state_t state;
    if (kernel_arch_signal_runtime_state(0, &state) < 0 ||
        !state.blocked_mask)
        return -EDGE_LINUX_EINVAL;
    *state.blocked_mask = edge_linux_signal_sanitize_mask(mask);
    return 0;
}

int kernel_current_signal_altstack_get(
    void *user_registers, kernel_signal_altstack_state_t *altstack) {
    kernel_signal_runtime_state_t state;
    uint64_t user_stack_pointer;
    if (!altstack ||
        kernel_arch_signal_runtime_state(0, &state) < 0 ||
        !state.altstack_pointer || !state.altstack_size ||
        !state.altstack_flags || !state.minimum_altstack_size ||
        kernel_arch_signal_user_stack_pointer(
            user_registers, &user_stack_pointer) < 0)
        return -EDGE_LINUX_EINVAL;
    altstack->stack_pointer = *state.altstack_pointer;
    altstack->stack_size = *state.altstack_size;
    altstack->minimum_size = state.minimum_altstack_size;
    altstack->flags = *state.altstack_flags;
    altstack->on_stack = (uint8_t)kernel_signal_altstack_contains(
        altstack->stack_pointer, altstack->stack_size, altstack->flags,
        user_stack_pointer);
    return 0;
}

int kernel_current_signal_altstack_set(uint64_t stack_pointer,
                                       uint64_t stack_size,
                                       uint32_t flags) {
    kernel_signal_runtime_state_t state;
    if (kernel_arch_signal_runtime_state(0, &state) < 0 ||
        !state.altstack_pointer || !state.altstack_size ||
        !state.altstack_flags)
        return -EDGE_LINUX_EINVAL;
    *state.altstack_pointer = stack_pointer;
    *state.altstack_size = stack_size;
    *state.altstack_flags = flags;
    return 0;
}

int kernel_signalfd_current_pending(uint64_t mask) {
    kernel_signal_runtime_state_t state;
    return kernel_arch_signal_runtime_state(0, &state) == 0 &&
        (kernel_signal_pending_mask(&state) & mask) != 0;
}

int kernel_signalfd_current_dequeue(
    void *context, uint64_t mask,
    struct edge_linux_signalfd_siginfo *information) {
    kernel_signal_runtime_state_t state;
    if (kernel_arch_signal_runtime_state(context, &state) < 0)
        return -EDGE_LINUX_EINVAL;
    return kernel_signal_pending_dequeue_signalfd(
        &state, mask, information);
}
