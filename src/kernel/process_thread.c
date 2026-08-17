/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux thread ABI state runtime.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"

int kernel_arch_current_rseq_binding(kernel_linux_rseq_binding_t *binding) {
    if (!binding) return -EDGE_LINUX_EINVAL;
    binding->thread_state = 0;
    binding->copy_to_user = 0;
    binding->copy_context = 0;
    binding->cpu_id = 0;
    binding->node_id = 0;
    binding->mm_cid = 0;
    if (edge_process_runtime_current_rseq_binding(binding) < 0 ||
        !binding->thread_state || !binding->copy_to_user)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

void kernel_linux_thread_state_clone(
    kernel_linux_thread_state_t *child,
    const kernel_linux_thread_state_t *parent) {
    if (!child) return;
    child->clear_child_tid = 0;
    child->robust_list_head = 0;
    child->robust_list_length = 0;
    edge_linux_rseq_state_reset(&child->rseq);
    child->personality = parent ? parent->personality : 0;
}

void kernel_linux_thread_state_exec(kernel_linux_thread_state_t *state) {
    if (!state) return;
    state->clear_child_tid = 0;
    state->robust_list_head = 0;
    state->robust_list_length = 0;
    edge_linux_rseq_state_reset(&state->rseq);
}

int kernel_current_personality_get(uint32_t *personality) {
    kernel_linux_thread_state_t *state;
    if (!personality ||
        kernel_arch_current_linux_thread_state(&state) < 0 || !state)
        return -1;
    *personality = state->personality;
    return 0;
}

int kernel_current_personality_set(uint32_t personality) {
    kernel_linux_thread_state_t *state;
    if (kernel_arch_current_linux_thread_state(&state) < 0 || !state)
        return -1;
    state->personality = personality;
    return 0;
}

int kernel_current_clear_child_tid_set(uint64_t address) {
    kernel_linux_thread_state_t *state;
    if (kernel_arch_current_linux_thread_state(&state) < 0 || !state)
        return -1;
    state->clear_child_tid = address;
    return 0;
}

int kernel_current_robust_list_set(uint64_t head, uint64_t length) {
    kernel_linux_thread_state_t *state;
    if (kernel_arch_current_linux_thread_state(&state) < 0 || !state)
        return -1;
    state->robust_list_head = head;
    state->robust_list_length = length;
    return 0;
}

int kernel_process_robust_list_get(int32_t pid, uint64_t *head,
                                   uint64_t *length) {
    kernel_linux_thread_state_t *state;
    int result;

    if (!head || !length) return -1;
    result = pid ? kernel_arch_process_linux_thread_state(pid, &state) :
                   kernel_arch_current_linux_thread_state(&state);
    if (result < 0 || !state) return -1;
    *head = state->robust_list_head;
    *length = state->robust_list_length ? state->robust_list_length :
              EDGE_LINUX_ROBUST_LIST_HEAD_SIZE;
    return 0;
}

int kernel_current_rseq_register(uint64_t address, uint64_t length,
                                 uint64_t flags, uint64_t signature) {
    kernel_linux_rseq_binding_t binding;

    if (kernel_arch_current_rseq_binding(&binding) < 0 ||
        !binding.thread_state || !binding.copy_to_user)
        return -EDGE_LINUX_EINVAL;
    return edge_linux_rseq_register(
        &binding.thread_state->rseq, address, length, flags, signature,
        binding.cpu_id, binding.node_id, binding.mm_cid,
        binding.copy_to_user, binding.copy_context);
}
