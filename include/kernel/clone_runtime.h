/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS process-clone runtime interface.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux clone policy is architecture-independent.  Architecture runtimes
 * receive this normalized request only after the common syscall layer has
 * decoded the architecture's raw argument order and validated the UAPI.
 */

#ifndef EDGEOS_KERNEL_CLONE_RUNTIME_H
#define EDGEOS_KERNEL_CLONE_RUNTIME_H

#include <stdint.h>

typedef struct kernel_clone_request {
    uint64_t flags;
    uint64_t child_stack;
    uint64_t parent_tid_user;
    uint64_t child_tid_user;
    uint64_t tls;
    uint64_t pidfd_user;
    uint64_t cgroup_descriptor;
    uint32_t exit_signal;
    uint8_t clone3;
    void *user_registers;
    int32_t *child_global_pid_out;
} kernel_clone_request_t;

typedef enum kernel_clone_signal_handlers {
    KERNEL_CLONE_SIGNAL_HANDLERS_COPY = 0,
    KERNEL_CLONE_SIGNAL_HANDLERS_CLEAR = 1,
    KERNEL_CLONE_SIGNAL_HANDLERS_SHARE = 2,
} kernel_clone_signal_handlers_t;

typedef enum kernel_clone_parent {
    KERNEL_CLONE_PARENT_CURRENT = 0,
    KERNEL_CLONE_PARENT_INHERIT = 1,
    KERNEL_CLONE_PARENT_THREAD_GROUP = 2,
} kernel_clone_parent_t;

typedef struct kernel_clone_prepare {
    uint64_t namespace_flags;
    void *user_registers;
    uint8_t share_vm;
    uint8_t share_files;
    uint8_t vfork;
    uint8_t is_thread;
} kernel_clone_prepare_t;

typedef struct kernel_clone_configuration {
    uint64_t child_stack;
    uint64_t tls;
    uint64_t clear_child_tid;
    uint32_t exit_signal;
    kernel_clone_signal_handlers_t signal_handlers;
    kernel_clone_parent_t parent;
    uint8_t share_fs;
    uint8_t share_files;
    uint8_t disable_altstack;
    uint8_t set_tls;
} kernel_clone_configuration_t;

typedef struct kernel_clone_state {
    int32_t child_global_pid;
    int32_t parent_visible_pid;
    int32_t child_visible_pid;
    int32_t pidfd;
    uintptr_t architecture_token;
    uint64_t parent_address_space;
    uint64_t child_address_space;
    uint64_t userfaultfd_wait_ticket;
    int32_t userfaultfd_wait_context;
    uint64_t architecture_state[2];
    uint8_t prepared;
    uint8_t vfork_prepared;
    uint8_t published;
    uint8_t cgroup_accounted;
    uint8_t userfaultfd_cloned;
} kernel_clone_state_t;

/*
 * Common code owns Linux-visible clone policy and transaction ordering.
 * Backends implement only task allocation, native register/address-space
 * mechanics, descriptor installation, user-memory access, and scheduling.
 */
int process_clone_arch_validate_cgroup(uint64_t descriptor);
int process_clone_arch_prepare(const kernel_clone_prepare_t *prepare,
                               kernel_clone_state_t *state);
int process_clone_arch_configure(
    const kernel_clone_configuration_t *configuration,
    kernel_clone_state_t *state);
int process_clone_arch_attach_cgroup(uint64_t descriptor,
                                     kernel_clone_state_t *state);
int process_clone_arch_install_pidfd(uint64_t user_destination,
                                     kernel_clone_state_t *state);
int process_clone_arch_write_parent_tid(uint64_t user_destination,
                                        kernel_clone_state_t *state);
int process_clone_arch_write_child_tid(uint64_t user_destination,
                                       kernel_clone_state_t *state);
int process_clone_arch_prepare_vfork(kernel_clone_state_t *state);
int process_clone_arch_publish(kernel_clone_state_t *state,
                               int ptrace_event);
int process_clone_arch_wait_vfork(kernel_clone_state_t *state);
void process_clone_arch_abort(kernel_clone_state_t *state);

int64_t kernel_process_clone(const kernel_clone_request_t *request);

#endif
