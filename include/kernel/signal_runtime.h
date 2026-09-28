/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux signal runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SIGNAL_RUNTIME_H
#define EDGEOS_KERNEL_SIGNAL_RUNTIME_H

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "kernel/signal_policy.h"

/*
 * The task structures and scheduler remain runtime-specific during the
 * architecture convergence.  This view exposes only Linux signal state; it
 * deliberately contains no trap-frame or page-table details.
 */
typedef struct kernel_signal_runtime_state {
    int32_t tid;
    int32_t tgid;
    uint64_t *thread_pending;
    uint64_t *shared_pending;
    uint64_t *blocked_mask;
    uint64_t *saved_mask;
    uint8_t *restore_mask_pending;
    edge_linux_signal_action_t *actions;
    uint64_t *altstack_pointer;
    uint64_t *altstack_size;
    uint32_t *altstack_flags;
    uint64_t minimum_altstack_size;
    uint8_t *seccomp_sigsys_pending;
    int32_t seccomp_sigsys_errno;
    int32_t seccomp_sigsys_number;
    uint32_t seccomp_sigsys_architecture;
    uint64_t seccomp_sigsys_call_address;
} kernel_signal_runtime_state_t;

typedef struct kernel_signal_altstack_state {
    uint64_t stack_pointer;
    uint64_t stack_size;
    uint64_t minimum_size;
    uint32_t flags;
    uint8_t on_stack;
} kernel_signal_altstack_state_t;

typedef enum kernel_signal_wait_operation {
    KERNEL_SIGNAL_WAIT_SUSPEND = 1,
    KERNEL_SIGNAL_WAIT_TIMED = 2,
} kernel_signal_wait_operation_t;

/* Runtime hooks expose storage and task-table mechanics, not ABI policy. */
int kernel_arch_signal_runtime_state(
    void *task_context, kernel_signal_runtime_state_t *state);
int kernel_arch_signal_action_install(
    uint32_t signal, const edge_linux_signal_action_t *action);
void kernel_arch_signal_pending_discard(uint32_t signal);
int kernel_arch_signal_delivery_resolve(
    int32_t tid, int thread_directed, int32_t *queue_target);
int kernel_arch_signal_delivery_commit(
    int32_t tid, uint32_t signal, int thread_directed);
int edge_process_runtime_signal_state(
    void *task_context, kernel_signal_runtime_state_t *state);
int edge_process_runtime_signal_action_install(
    uint32_t signal, const edge_linux_signal_action_t *action);
void edge_process_runtime_signal_pending_discard(uint32_t signal);
int edge_process_runtime_signal_delivery_commit(
    int32_t tid, uint32_t signal, int thread_directed);
int kernel_arch_signal_user_stack_pointer(
    void *user_registers, uint64_t *stack_pointer);
/*
 * Blocking is a runtime mechanism: ARM64 parks a saved user frame while
 * x86_64 suspends the live syscall stack.  Signal selection, timeout policy,
 * and Linux-visible return values remain in the shared runtime.
 */
int64_t kernel_arch_signal_wait_block(
    kernel_signal_wait_operation_t operation, uint64_t selected_mask,
    uint64_t information_user, uint64_t deadline_microseconds,
    void *user_registers);

int kernel_linux_signal_send(int32_t tid, uint32_t signal,
                             int thread_directed,
                             const void *signal_information);

int kernel_signal_action_discards_pending(
    uint32_t signal, const edge_linux_signal_action_t *action);
int kernel_signal_action_auto_reaps_child(
    uint32_t signal, const edge_linux_signal_action_t *action);
int kernel_signal_altstack_contains(
    uint64_t stack_pointer, uint64_t stack_size, uint32_t flags,
    uint64_t user_stack_pointer);
void kernel_signal_wait_mask_install(
    kernel_signal_runtime_state_t *state, uint64_t temporary_mask);
void kernel_signal_wait_mask_finish(
    kernel_signal_runtime_state_t *state, int interrupted);
uint64_t kernel_signal_wait_mask_take_for_frame(
    kernel_signal_runtime_state_t *state);
void kernel_signal_wait_mask_cancel(kernel_signal_runtime_state_t *state);

uint64_t kernel_signal_pending_mask(
    const kernel_signal_runtime_state_t *state);
uint32_t kernel_signal_pending_next(
    const kernel_signal_runtime_state_t *state, uint64_t selected_mask);
int kernel_signal_pending_peek(
    const kernel_signal_runtime_state_t *state, uint32_t signal,
    void *signal_information);
int kernel_signal_pending_consume(
    kernel_signal_runtime_state_t *state, uint32_t signal,
    void *signal_information, int *same_signal_remains);
int64_t kernel_signal_pending_take(
    kernel_signal_runtime_state_t *state, uint64_t selected_mask,
    void *signal_information);
int kernel_signal_pending_has_wake(
    kernel_signal_runtime_state_t *state, uint64_t blocked_mask);
int kernel_signal_pending_dequeue_signalfd(
    kernel_signal_runtime_state_t *state, uint64_t selected_mask,
    struct edge_linux_signalfd_siginfo *information);

int kernel_current_signal_action_get(uint32_t signal,
                                     edge_linux_signal_action_t *action);
int kernel_current_signal_action_set(
    uint32_t signal, const edge_linux_signal_action_t *action);
int kernel_current_signal_mask_get(uint64_t *mask);
int kernel_current_signal_mask_set(uint64_t mask);
int kernel_current_signal_pending(uint64_t *pending);
int kernel_current_signal_wake_pending(void);
int64_t kernel_current_signal_suspend(uint64_t temporary_mask,
                                      void *user_registers);
int64_t kernel_current_signal_timed_wait(
    uint64_t wanted_mask, uint64_t information_user,
    uint64_t deadline_microseconds, edge_linux_copy_to_user_fn copy_to_user,
    void *copy_context, void *user_registers);
/*
 * Signal-stack validation and UAPI copying are shared.  The architecture hook
 * only supplies the interrupted user stack pointer; delivery remains
 * responsible for validating writable frame storage through normal uaccess.
 */
int kernel_current_signal_altstack_get(
    void *user_registers, kernel_signal_altstack_state_t *state);
int kernel_current_signal_altstack_set(uint64_t stack_pointer,
                                       uint64_t stack_size,
                                       uint32_t flags);

#endif
