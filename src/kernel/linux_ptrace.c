/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux ptrace implementation.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux request validation and tracer-visible behavior live here.  Task stop
 * mechanics and register encoding remain behind process-runtime callbacks
 * because those are properties of the architecture return frame.
 */

#include <stddef.h>
#include <stdint.h>

#include "kernel/credentials.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_ptrace.h"
#include "kernel/linux_syscall.h"
#include "kernel/mm_runtime.h"
#include "kernel/namespaces.h"
#include "kernel/process_runtime.h"
#include "string.h"

typedef struct edge_linux_ptrace_peeksiginfo_args {
    uint64_t offset;
    uint32_t flags;
    int32_t count;
} edge_linux_ptrace_peeksiginfo_args_t;

_Static_assert(sizeof(edge_linux_ptrace_syscall_info_t) == 88,
               "Linux ptrace syscall-info layout");
_Static_assert(offsetof(edge_linux_ptrace_syscall_info_t, data) == 24,
               "Linux ptrace syscall-info payload offset");
_Static_assert(sizeof(edge_linux_ptrace_rseq_configuration_t) == 24,
               "Linux ptrace rseq configuration layout");
_Static_assert(sizeof(edge_linux_ptrace_peeksiginfo_args_t) == 16,
               "Linux ptrace peeksiginfo argument layout");

#define EDGE_LINUX_CLONE_SIGNAL_MASK 0xffu
#define EDGE_LINUX_SIGCHLD 17u

static int ptrace_copy_to_user(edge_linux_syscall_context_t *context,
                               uint64_t destination, const void *source,
                               uint64_t size) {
    if (!context || !context->arch_ops ||
        !context->arch_ops->copy_to_user || (!source && size))
        return -1;
    return context->arch_ops->copy_to_user(
        context->current_task, destination, source, size);
}

static int ptrace_copy_from_user(edge_linux_syscall_context_t *context,
                                 void *destination, uint64_t source,
                                 uint64_t size) {
    if (!context || !context->arch_ops ||
        !context->arch_ops->copy_from_user || (!destination && size))
        return -1;
    return context->arch_ops->copy_from_user(
        context->current_task, destination, source, size);
}

static int ptrace_uses_compat_layout(
    const edge_linux_syscall_context_t *context) {
    return context && context->architecture == EDGE_LINUX_ARCH_X32;
}

static uint64_t ptrace_user_pointer(
    const edge_linux_syscall_context_t *context, uint64_t value) {
    return ptrace_uses_compat_layout(context) ? (uint32_t)value : value;
}

void edge_linux_ptrace_state_reset(edge_linux_ptrace_state_t *state) {
    if (state) memset(state, 0, sizeof(*state));
}

void edge_linux_ptrace_state_record_stop(
    edge_linux_ptrace_state_t *state,
    const edge_linux_ptrace_stop_t *stop) {
    if (!state || !stop) return;
    state->stop_reason = (uint8_t)stop->reason;
    state->stop_signal = (uint8_t)stop->signal;
    state->stop_event = (uint8_t)stop->event;
    state->event_message = stop->event_message;
    state->syscall_number = stop->syscall_number;
    for (uint32_t index = 0; index < 6u; ++index)
        state->syscall_arguments[index] = stop->syscall_arguments[index];
    state->syscall_result = stop->syscall_result;
    state->instruction_pointer = stop->instruction_pointer;
    state->stack_pointer = stop->stack_pointer;
    state->syscall_info_op =
        stop->reason == EDGE_LINUX_PTRACE_STOP_SYSCALL_ENTRY ? 1u :
        stop->reason == EDGE_LINUX_PTRACE_STOP_SYSCALL_EXIT ? 2u : 0u;
}

void edge_linux_ptrace_state_record_signal_info(
    edge_linux_ptrace_state_t *state, uint32_t signal, int32_t code,
    int32_t sender_pid, uint32_t sender_uid) {
    int32_t signal_number = (int32_t)(signal & 0x7fu);
    if (!state) return;
    memset(state->signal_info, 0, sizeof(state->signal_info));
    memcpy(state->signal_info, &signal_number, sizeof(signal_number));
    memcpy(state->signal_info + 8u, &code, sizeof(code));
    memcpy(state->signal_info + 16u, &sender_pid, sizeof(sender_pid));
    memcpy(state->signal_info + 20u, &sender_uid, sizeof(sender_uid));
    state->signal_info_valid = 1;
}

edge_linux_ptrace_exit_wait_action_t edge_linux_ptrace_exit_wait_action(
    const edge_linux_ptrace_state_t *state, int32_t waiter_pid,
    int32_t waiter_tgid, int32_t natural_parent_tgid) {
    if (!state || state->tracer_pid <= 0)
        return EDGE_LINUX_PTRACE_EXIT_WAIT_REAP;

    if (state->tracer_pid != waiter_pid)
        return EDGE_LINUX_PTRACE_EXIT_WAIT_DEFER;

    /*
     * A debugger is an additional wait parent, not a replacement for the
     * tracee's real parent.  Once a distinct tracer consumes the terminal
     * status, the zombie must be released to its natural parent instead of
     * being destroyed.  PTRACE_TRACEME commonly makes both roles belong to
     * the same thread group, in which case one wait legitimately reaps it.
     */
    return waiter_tgid == natural_parent_tgid ?
        EDGE_LINUX_PTRACE_EXIT_WAIT_REAP :
        EDGE_LINUX_PTRACE_EXIT_WAIT_RELEASE;
}

int edge_linux_ptrace_exit_is_deferred(
    const edge_linux_ptrace_state_t *state) {
    return state && state->tracer_pid > 0;
}

edge_linux_ptrace_tracer_exit_action_t edge_linux_ptrace_tracer_exit_action(
    const edge_linux_ptrace_state_t *state, int tracee_is_zombie) {
    if (tracee_is_zombie)
        return EDGE_LINUX_PTRACE_TRACER_EXIT_RELEASE_ZOMBIE;
    if (state && (state->options & EDGE_LINUX_PTRACE_O_EXITKILL))
        return EDGE_LINUX_PTRACE_TRACER_EXIT_KILL;
    return EDGE_LINUX_PTRACE_TRACER_EXIT_DETACH;
}

void edge_linux_ptrace_signal_resume_action(
    const edge_linux_ptrace_state_t *state, uint32_t requested_signal,
    edge_linux_ptrace_signal_resume_action_t *action) {
    uint32_t stopped_signal;
    if (!action) return;
    memset(action, 0, sizeof(*action));
    if (!state) return;
    stopped_signal = state->stop_signal & 0x7fu;
    if (state->stop_reason == EDGE_LINUX_PTRACE_STOP_SIGNAL) {
        if (!requested_signal) {
            action->consume_signal = stopped_signal;
            return;
        }
        if (requested_signal != stopped_signal) {
            action->consume_signal = stopped_signal;
            action->inject_signal = requested_signal;
        }
    } else if (requested_signal) {
        action->inject_signal = requested_signal;
    }
    if (requested_signal) action->suppress_signal_stop = 1;
}

uint32_t edge_linux_ptrace_internal_stop_signal(
    const edge_linux_ptrace_stop_t *stop) {
    if (!stop) return 0;
    return stop->reason == EDGE_LINUX_PTRACE_STOP_INTERRUPT &&
           stop->event == EDGE_LINUX_PTRACE_EVENT_STOP ?
        EDGE_LINUX_PTRACE_SIGTRAP : 0;
}

static int ptrace_task_runtime(
    int32_t pid, edge_linux_ptrace_task_runtime_t *runtime) {
    if (!runtime || kernel_arch_ptrace_task_runtime(pid, runtime) < 0 ||
        !runtime->ptrace || !runtime->signal_mask)
        return -EDGE_LINUX_ESRCH;
    return 0;
}

int kernel_ptrace_traceme(int32_t tracer_pid) {
    kernel_process_native_view_t target;

    memset(&target, 0, sizeof(target));
    if (edge_process_runtime_current_view(&target) < 0 ||
        !target.ptrace || tracer_pid <= 0 || tracer_pid == target.pid ||
        target.ptrace->tracer_pid > 0)
        return -EDGE_LINUX_EPERM;
    edge_linux_ptrace_state_reset(target.ptrace);
    target.ptrace->tracer_pid = tracer_pid;
    target.ptrace->resume_mode = EDGE_LINUX_PTRACE_RESUME_CONT;
    return 0;
}

static int ptrace_attach_initialize(
    int32_t pid, int32_t tracer_pid, int seized, uint32_t options,
    edge_linux_ptrace_state_t **state_out) {
    edge_linux_ptrace_task_runtime_t runtime;

    if (tracer_pid <= 0 || ptrace_task_runtime(pid, &runtime) < 0 ||
        runtime.ptrace->tracer_pid > 0)
        return -EDGE_LINUX_ESRCH;
    edge_linux_ptrace_state_reset(runtime.ptrace);
    runtime.ptrace->tracer_pid = tracer_pid;
    runtime.ptrace->seized = seized ? 1u : 0u;
    runtime.ptrace->options = options;
    runtime.ptrace->resume_mode = EDGE_LINUX_PTRACE_RESUME_CONT;
    if (state_out) *state_out = runtime.ptrace;
    return 0;
}

int kernel_ptrace_attach(int32_t pid, int32_t tracer_pid, int seized,
                         uint32_t options) {
    edge_linux_ptrace_state_t *state = 0;
    int result = ptrace_attach_initialize(
        pid, tracer_pid, seized, options, &state);

    if (result < 0) return result;
    result = arch_ptrace_attach(pid, seized);
    if (result < 0) edge_linux_ptrace_state_reset(state);
    return result;
}

int kernel_ptrace_attach_child(int32_t pid, int32_t tracer_pid, int seized,
                               uint32_t options) {
    edge_linux_ptrace_state_t *state = 0;
    int result = ptrace_attach_initialize(
        pid, tracer_pid, seized, options, &state);

    if (result < 0) return result;
    result = arch_ptrace_attach_child(pid, seized);
    if (result < 0) edge_linux_ptrace_state_reset(state);
    return result;
}

int kernel_ptrace_detach(int32_t pid, int32_t tracer_pid, uint32_t signal) {
    edge_linux_ptrace_task_runtime_t runtime;

    if (ptrace_task_runtime(pid, &runtime) < 0 ||
        runtime.ptrace->tracer_pid != tracer_pid || !runtime.stopped)
        return -EDGE_LINUX_ESRCH;
    edge_linux_ptrace_state_reset(runtime.ptrace);
    return arch_ptrace_detach(pid, signal);
}

int kernel_ptrace_resume(int32_t pid, int32_t tracer_pid,
                         edge_linux_ptrace_resume_mode_t mode,
                         uint32_t signal) {
    edge_linux_ptrace_task_runtime_t runtime;

    if (ptrace_task_runtime(pid, &runtime) < 0 ||
        runtime.ptrace->tracer_pid != tracer_pid || !runtime.stopped)
        return -EDGE_LINUX_ESRCH;
    return arch_ptrace_resume(pid, mode, signal);
}

int kernel_ptrace_interrupt(int32_t pid, int32_t tracer_pid) {
    edge_linux_ptrace_task_runtime_t runtime;

    if (ptrace_task_runtime(pid, &runtime) < 0 ||
        runtime.ptrace->tracer_pid != tracer_pid ||
        !runtime.ptrace->seized ||
        (runtime.stopped &&
         runtime.ptrace->stop_reason != EDGE_LINUX_PTRACE_STOP_NONE))
        return -EDGE_LINUX_EIO;
    return arch_ptrace_interrupt(pid);
}

int kernel_ptrace_kill(int32_t pid, int32_t tracer_pid) {
    edge_linux_ptrace_task_runtime_t runtime;

    if (ptrace_task_runtime(pid, &runtime) < 0 ||
        runtime.ptrace->tracer_pid != tracer_pid)
        return -EDGE_LINUX_ESRCH;
    return arch_ptrace_kill(pid);
}

int kernel_ptrace_read_memory(int32_t pid, uint64_t address, void *buffer,
                              uint64_t size) {
    return arch_mm_process_vm_copy(
        pid, address, buffer, size, KERNEL_MM_PROCESS_VM_READ) < 0 ?
        -EDGE_LINUX_EIO : 0;
}

int kernel_ptrace_write_memory(int32_t pid, uint64_t address,
                               const void *buffer, uint64_t size) {
    return arch_mm_process_vm_copy(
        pid, address, (void *)buffer, size,
        KERNEL_MM_PROCESS_VM_WRITE) < 0 ? -EDGE_LINUX_EIO : 0;
}

int kernel_ptrace_stop_current(void *user_registers,
                               const edge_linux_ptrace_stop_t *stop) {
    return arch_ptrace_stop_current(user_registers, stop);
}

int kernel_ptrace_consume_syscall_restart(void *user_registers) {
    return arch_ptrace_consume_syscall_restart(user_registers);
}

int kernel_ptrace_set_options(int32_t pid, int32_t tracer_pid,
                              uint32_t options) {
    kernel_process_native_view_t target;

    memset(&target, 0, sizeof(target));
    if (edge_process_runtime_view(pid, &target) < 0 ||
        !target.ptrace || target.ptrace->tracer_pid != tracer_pid ||
        !target.stopped)
        return -EDGE_LINUX_ESRCH;
    target.ptrace->options = options;
    return 0;
}

int kernel_ptrace_task_info(
    int32_t pid, edge_linux_ptrace_task_info_t *information) {
    edge_linux_ptrace_task_runtime_t runtime;
    if (!information || ptrace_task_runtime(pid, &runtime) < 0)
        return -EDGE_LINUX_ESRCH;
    memset(information, 0, sizeof(*information));
    information->pid = runtime.pid;
    information->tgid = runtime.tgid;
    information->ppid = runtime.ppid;
    information->uid = runtime.uid;
    information->euid = runtime.euid;
    information->suid = runtime.suid;
    information->gid = runtime.gid;
    information->egid = runtime.egid;
    information->sgid = runtime.sgid;
    information->dumpable = runtime.dumpable;
    information->stopped = runtime.stopped;
    information->zombie = runtime.zombie;
    information->stop_reported = runtime.stop_reported;
    information->stop_signal = runtime.stop_signal;
    information->ptrace = *runtime.ptrace;
    return 0;
}

int kernel_ptrace_get_signal_info(int32_t pid, void *buffer, uint64_t size) {
    edge_linux_ptrace_task_runtime_t runtime;
    if (!buffer || ptrace_task_runtime(pid, &runtime) < 0 ||
        size != sizeof(runtime.ptrace->signal_info) ||
        !runtime.ptrace->signal_info_valid)
        return -EDGE_LINUX_EINVAL;
    memcpy(buffer, runtime.ptrace->signal_info, size);
    return 0;
}

int kernel_ptrace_set_signal_info(int32_t pid, const void *buffer,
                                  uint64_t size) {
    edge_linux_ptrace_task_runtime_t runtime;
    if (!buffer || ptrace_task_runtime(pid, &runtime) < 0 ||
        size != sizeof(runtime.ptrace->signal_info))
        return -EDGE_LINUX_EINVAL;
    memcpy(runtime.ptrace->signal_info, buffer, size);
    runtime.ptrace->signal_info_valid = 1;
    return 0;
}

int kernel_ptrace_get_signal_mask(int32_t pid, uint64_t *mask) {
    edge_linux_ptrace_task_runtime_t runtime;
    if (!mask || ptrace_task_runtime(pid, &runtime) < 0)
        return -EDGE_LINUX_ESRCH;
    *mask = *runtime.signal_mask;
    return 0;
}

int kernel_ptrace_set_signal_mask(int32_t pid, uint64_t mask) {
    edge_linux_ptrace_task_runtime_t runtime;
    if (ptrace_task_runtime(pid, &runtime) < 0)
        return -EDGE_LINUX_ESRCH;
    *runtime.signal_mask = mask;
    return 0;
}

int kernel_ptrace_get_rseq_configuration(
    int32_t pid, edge_linux_ptrace_rseq_configuration_t *configuration) {
    edge_linux_ptrace_task_runtime_t runtime;
    if (!configuration || ptrace_task_runtime(pid, &runtime) < 0)
        return -EDGE_LINUX_ESRCH;
    memset(configuration, 0, sizeof(*configuration));
    configuration->address = runtime.rseq_address;
    configuration->size = runtime.rseq_size;
    configuration->signature = runtime.rseq_signature;
    return 0;
}

static int ptrace_current_identity(kernel_linux_identity_t *identity) {
    if (!identity || kernel_current_linux_identity(identity) < 0)
        return -EDGE_LINUX_ESRCH;
    return 0;
}

static int ptrace_target_information(
    int32_t pid, edge_linux_ptrace_task_info_t *information) {
    if (pid <= 0) return -EDGE_LINUX_ESRCH;
    if (!information || kernel_ptrace_task_info(pid, information) < 0)
        return -EDGE_LINUX_ESRCH;
    if (information->zombie) return -EDGE_LINUX_ESRCH;
    return 0;
}

static int ptrace_may_attach(
    const kernel_linux_identity_t *caller,
    const edge_linux_ptrace_task_info_t *target) {
    uint64_t capability;
    if (!caller || !target) return 0;
    if (caller->tid == target->pid || caller->tgid == target->tgid) return 0;
    capability = 1ULL << EDGE_LINUX_CAP_SYS_PTRACE;
    if (caller->effective_capabilities & capability) return 1;
    if (!target->dumpable) return 0;
    return caller->uid == target->uid && caller->uid == target->euid &&
           caller->uid == target->suid && caller->gid == target->gid &&
           caller->gid == target->egid && caller->gid == target->sgid;
}

static int ptrace_require_tracer(
    int32_t pid, const kernel_linux_identity_t *caller,
    edge_linux_ptrace_task_info_t *target, int require_stop) {
    int result = ptrace_target_information(pid, target);
    if (result < 0) return result;
    if (!caller || target->ptrace.tracer_pid != caller->tid)
        return -EDGE_LINUX_ESRCH;
    if (require_stop && !target->stopped) return -EDGE_LINUX_ESRCH;
    return 0;
}

static int ptrace_signal_valid(uint64_t signal) {
    return signal <= 64u;
}

static int64_t ptrace_peek_memory(edge_linux_syscall_context_t *context,
                                  int32_t pid, uint64_t address,
                                  uint64_t destination) {
    uint64_t value = 0;
    uint64_t word_size = ptrace_uses_compat_layout(context) ?
        sizeof(uint32_t) : sizeof(uint64_t);
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (kernel_ptrace_read_memory(pid, address, &value, word_size) < 0)
        return -EDGE_LINUX_EIO;
    return ptrace_copy_to_user(context, destination, &value, word_size) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t ptrace_peek_user(edge_linux_syscall_context_t *context,
                                int32_t pid, uint64_t offset,
                                uint64_t destination) {
    uint64_t value;
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (ptrace_uses_compat_layout(context) && offset < 17u * sizeof(uint64_t))
        return -EDGE_LINUX_EIO;
    if (kernel_ptrace_read_user_area(pid, offset, &value) < 0)
        return -EDGE_LINUX_EIO;
    return ptrace_copy_to_user(
        context, destination, &value,
        ptrace_uses_compat_layout(context) ?
            sizeof(uint32_t) : sizeof(uint64_t)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int ptrace_import_iovec(edge_linux_syscall_context_t *context,
                               uint64_t iovec_user,
                               struct edge_linux_iovec *iovec) {
    if (!context || !iovec || !iovec_user) return -1;
    memset(iovec, 0, sizeof(*iovec));
    if (ptrace_uses_compat_layout(context)) {
        struct edge_linux_x32_iovec compat;
        if (ptrace_copy_from_user(
                context, &compat, iovec_user, sizeof(compat)) < 0)
            return -1;
        iovec->iov_base = compat.iov_base;
        iovec->iov_len = compat.iov_len;
        return 0;
    }
    return ptrace_copy_from_user(
        context, iovec, iovec_user, sizeof(*iovec));
}

static int ptrace_export_iovec_length(
    edge_linux_syscall_context_t *context, uint64_t iovec_user,
    uint64_t length) {
    if (ptrace_uses_compat_layout(context)) {
        uint32_t compat_length = length > UINT32_MAX ? UINT32_MAX :
            (uint32_t)length;
        return ptrace_copy_to_user(
            context,
            iovec_user + offsetof(struct edge_linux_x32_iovec, iov_len),
            &compat_length, sizeof(compat_length));
    }
    return ptrace_copy_to_user(
        context, iovec_user + offsetof(struct edge_linux_iovec, iov_len),
        &length, sizeof(length));
}

static int64_t ptrace_get_regset(edge_linux_syscall_context_t *context,
                                 int32_t pid, uint32_t note,
                                 uint64_t iovec_user) {
    struct edge_linux_iovec iovec;
    uint8_t buffer[1024];
    uint64_t size = sizeof(buffer);
    uint64_t copied;
    if (ptrace_import_iovec(context, iovec_user, &iovec) < 0)
        return -EDGE_LINUX_EFAULT;
    if (kernel_ptrace_get_regset(pid, note, buffer, &size) < 0)
        return -EDGE_LINUX_EIO;
    copied = iovec.iov_len < size ? iovec.iov_len : size;
    if (copied && (!iovec.iov_base ||
        ptrace_copy_to_user(context, iovec.iov_base, buffer, copied) < 0))
        return -EDGE_LINUX_EFAULT;
    iovec.iov_len = copied;
    return ptrace_export_iovec_length(
        context, iovec_user, iovec.iov_len) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t ptrace_set_regset(edge_linux_syscall_context_t *context,
                                 int32_t pid, uint32_t note,
                                 uint64_t iovec_user) {
    struct edge_linux_iovec iovec;
    uint8_t buffer[1024];
    if (ptrace_import_iovec(context, iovec_user, &iovec) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!iovec.iov_len || iovec.iov_len > sizeof(buffer))
        return -EDGE_LINUX_EINVAL;
    if (!iovec.iov_base || ptrace_copy_from_user(context, buffer,
            iovec.iov_base, iovec.iov_len) < 0)
        return -EDGE_LINUX_EFAULT;
    return kernel_ptrace_set_regset(pid, note, buffer, iovec.iov_len) < 0 ?
        -EDGE_LINUX_EIO : 0;
}

static int64_t ptrace_get_legacy_regset(
    edge_linux_syscall_context_t *context, int32_t pid, uint32_t note,
    uint64_t destination) {
    uint8_t buffer[1024];
    uint64_t size = sizeof(buffer);
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (kernel_ptrace_get_regset(pid, note, buffer, &size) < 0)
        return -EDGE_LINUX_EIO;
    return ptrace_copy_to_user(context, destination, buffer, size) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t ptrace_set_legacy_regset(
    edge_linux_syscall_context_t *context, int32_t pid, uint32_t note,
    uint64_t source) {
    uint8_t buffer[1024];
    uint64_t size = sizeof(buffer);
    if (!source) return -EDGE_LINUX_EFAULT;
    if (kernel_ptrace_get_regset(pid, note, buffer, &size) < 0)
        return -EDGE_LINUX_EIO;
    if (size > sizeof(buffer) ||
        ptrace_copy_from_user(context, buffer, source, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return kernel_ptrace_set_regset(pid, note, buffer, size) < 0 ?
        -EDGE_LINUX_EIO : 0;
}

static int64_t ptrace_peeksiginfo(edge_linux_syscall_context_t *context,
                                  int32_t pid, uint64_t arguments_user,
                                  uint64_t destination) {
    edge_linux_ptrace_peeksiginfo_args_t arguments;
    uint8_t information[128];
    if (!arguments_user || ptrace_copy_from_user(context, &arguments,
            arguments_user, sizeof(arguments)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (arguments.flags & ~1u || arguments.count < 0)
        return -EDGE_LINUX_EINVAL;
    if (!arguments.count) return 0;
    if (arguments.offset != 0 ||
        kernel_ptrace_get_signal_info(pid, information,
                                      sizeof(information)) < 0)
        return 0;
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (ptrace_uses_compat_layout(context)) {
        struct edge_linux_compat_siginfo compat;
        edge_linux_native_siginfo_to_compat(
            (const struct edge_linux_siginfo *)(const void *)information,
            &compat);
        if (ptrace_copy_to_user(
                context, destination, &compat, sizeof(compat)) < 0)
            return -EDGE_LINUX_EFAULT;
    } else if (ptrace_copy_to_user(
            context, destination, information, sizeof(information)) < 0) {
        return -EDGE_LINUX_EFAULT;
    }
    return 1;
}

static int64_t ptrace_get_syscall_info(
    edge_linux_syscall_context_t *context,
    const edge_linux_ptrace_task_info_t *target, uint64_t size,
    uint64_t destination) {
    edge_linux_ptrace_syscall_info_t information;
    uint64_t available;
    uint64_t copied;
    if (!target) return -EDGE_LINUX_ESRCH;
    memset(&information, 0, sizeof(information));
    information.op = target->ptrace.syscall_info_op;
    information.architecture =
        context->architecture == EDGE_LINUX_ARCH_X86_64 ||
        context->architecture == EDGE_LINUX_ARCH_X32 ?
        0xc000003eu : 0xc00000b7u;
    information.instruction_pointer = target->ptrace.instruction_pointer;
    information.stack_pointer = target->ptrace.stack_pointer;
    if (information.op == 1u) {
        information.data.entry.number = target->ptrace.syscall_number;
        for (uint32_t index = 0; index < 6u; ++index)
            information.data.entry.arguments[index] =
                target->ptrace.syscall_arguments[index];
    } else if (information.op == 2u) {
        information.data.exit.result = target->ptrace.syscall_result;
        information.data.exit.is_error =
            target->ptrace.syscall_result < 0 &&
            target->ptrace.syscall_result >= -4095;
    }
    available = offsetof(edge_linux_ptrace_syscall_info_t, data);
    if (information.op == 1u)
        available = offsetof(edge_linux_ptrace_syscall_info_t, data) +
                    sizeof(information.data.entry);
    else if (information.op == 2u)
        available = offsetof(edge_linux_ptrace_syscall_info_t, data) +
                    sizeof(information.data.exit.result) +
                    sizeof(information.data.exit.is_error);
    else if (information.op == 3u)
        available = offsetof(edge_linux_ptrace_syscall_info_t, data) +
                    sizeof(information.data.seccomp.number) +
                    sizeof(information.data.seccomp.arguments) +
                    sizeof(information.data.seccomp.return_data);
    copied = size < available ? size : available;
    if (copied && (!destination || ptrace_copy_to_user(
            context, destination, &information, copied) < 0))
        return -EDGE_LINUX_EFAULT;
    return (int64_t)available;
}

int64_t edge_linux_sys_ptrace(edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    edge_linux_ptrace_task_info_t target;
    int64_t request;
    int32_t pid;
    uint64_t address;
    uint64_t data;
    int result;
    if (!context) return -EDGE_LINUX_EINVAL;
    request = ptrace_uses_compat_layout(context) ?
        (int32_t)(uint32_t)context->arguments[0] :
        (int64_t)context->arguments[0];
    pid = (int32_t)context->arguments[1];
    address = ptrace_user_pointer(context, context->arguments[2]);
    data = ptrace_user_pointer(context, context->arguments[3]);
    if (ptrace_current_identity(&caller) < 0) return -EDGE_LINUX_ESRCH;

    if (request == EDGE_LINUX_PTRACE_TRACEME) {
        if (caller.ppid <= 0) return -EDGE_LINUX_ESRCH;
        result = kernel_ptrace_traceme(caller.ppid);
        return result < 0 ? result : 0;
    }
    if (request == EDGE_LINUX_PTRACE_ATTACH ||
        request == EDGE_LINUX_PTRACE_SEIZE) {
        result = ptrace_target_information(pid, &target);
        if (result < 0) return result;
        if (!ptrace_may_attach(&caller, &target) ||
            target.ptrace.tracer_pid > 0)
            return -EDGE_LINUX_EPERM;
        if (request == EDGE_LINUX_PTRACE_SEIZE) {
            if (address || (data & ~EDGE_LINUX_PTRACE_O_MASK))
                return -EDGE_LINUX_EINVAL;
            return kernel_ptrace_attach(pid, caller.tid, 1,
                                        (uint32_t)data);
        }
        return kernel_ptrace_attach(pid, caller.tid, 0, 0);
    }

    result = ptrace_require_tracer(pid, &caller, &target,
        request != EDGE_LINUX_PTRACE_INTERRUPT &&
        request != EDGE_LINUX_PTRACE_KILL);
    if (result < 0) return result;

    switch (request) {
    case EDGE_LINUX_PTRACE_PEEKTEXT:
    case EDGE_LINUX_PTRACE_PEEKDATA:
        return ptrace_peek_memory(context, pid, address, data);
    case EDGE_LINUX_PTRACE_PEEKUSER:
        return ptrace_peek_user(context, pid, address, data);
    case EDGE_LINUX_PTRACE_POKETEXT:
    case EDGE_LINUX_PTRACE_POKEDATA: {
        uint32_t compat_data = (uint32_t)data;
        const void *source = ptrace_uses_compat_layout(context) ?
            (const void *)&compat_data : (const void *)&data;
        uint64_t size = ptrace_uses_compat_layout(context) ?
            sizeof(compat_data) : sizeof(data);
        return kernel_ptrace_write_memory(pid, address, source, size) < 0 ?
            -EDGE_LINUX_EIO : 0;
    }
    case EDGE_LINUX_PTRACE_POKEUSER:
        if (ptrace_uses_compat_layout(context) &&
            address < 17u * sizeof(uint64_t))
            return -EDGE_LINUX_EIO;
        return kernel_ptrace_write_user_area(pid, address, data) < 0 ?
            -EDGE_LINUX_EIO : 0;
    case EDGE_LINUX_PTRACE_CONT:
    case EDGE_LINUX_PTRACE_SYSCALL:
    case EDGE_LINUX_PTRACE_SINGLESTEP:
    case EDGE_LINUX_PTRACE_LISTEN: {
        edge_linux_ptrace_resume_mode_t mode;
        if (!ptrace_signal_valid(data)) return -EDGE_LINUX_EIO;
        if (request == EDGE_LINUX_PTRACE_LISTEN) {
            if (!target.ptrace.seized || data)
                return -EDGE_LINUX_EIO;
            mode = EDGE_LINUX_PTRACE_RESUME_LISTEN;
        } else if (request == EDGE_LINUX_PTRACE_SYSCALL) {
            mode = EDGE_LINUX_PTRACE_RESUME_SYSCALL;
        } else if (request == EDGE_LINUX_PTRACE_SINGLESTEP) {
            mode = EDGE_LINUX_PTRACE_RESUME_SINGLESTEP;
        } else {
            mode = EDGE_LINUX_PTRACE_RESUME_CONT;
        }
        return kernel_ptrace_resume(pid, caller.tid, mode,
                                    (uint32_t)data);
    }
    case EDGE_LINUX_PTRACE_KILL:
        return kernel_ptrace_kill(pid, caller.tid);
    case EDGE_LINUX_PTRACE_DETACH:
        if (!ptrace_signal_valid(data)) return -EDGE_LINUX_EIO;
        return kernel_ptrace_detach(pid, caller.tid, (uint32_t)data);
    case EDGE_LINUX_PTRACE_GETREGS:
        return ptrace_get_legacy_regset(context, pid,
                                        EDGE_LINUX_PTRACE_LEGACY_GPR, data);
    case EDGE_LINUX_PTRACE_SETREGS:
        return ptrace_set_legacy_regset(context, pid,
                                        EDGE_LINUX_PTRACE_LEGACY_GPR, data);
    case EDGE_LINUX_PTRACE_GETFPREGS:
        return ptrace_get_legacy_regset(context, pid,
                                        EDGE_LINUX_PTRACE_LEGACY_FP, data);
    case EDGE_LINUX_PTRACE_SETFPREGS:
        return ptrace_set_legacy_regset(context, pid,
                                        EDGE_LINUX_PTRACE_LEGACY_FP, data);
    case EDGE_LINUX_PTRACE_GETFPXREGS:
        return ptrace_get_legacy_regset(context, pid,
                                        EDGE_LINUX_PTRACE_LEGACY_FPX, data);
    case EDGE_LINUX_PTRACE_SETFPXREGS:
        return ptrace_set_legacy_regset(context, pid,
                                        EDGE_LINUX_PTRACE_LEGACY_FPX, data);
    case EDGE_LINUX_PTRACE_SETOPTIONS:
        if (data & ~EDGE_LINUX_PTRACE_O_MASK)
            return -EDGE_LINUX_EINVAL;
        return kernel_ptrace_set_options(pid, caller.tid, (uint32_t)data);
    case EDGE_LINUX_PTRACE_GETEVENTMSG:
        if (!data) return -EDGE_LINUX_EFAULT;
        {
            uint64_t event_message = target.ptrace.event_message;
            if (target.ptrace.stop_event == EDGE_LINUX_PTRACE_EVENT_FORK ||
                target.ptrace.stop_event == EDGE_LINUX_PTRACE_EVENT_VFORK ||
                target.ptrace.stop_event == EDGE_LINUX_PTRACE_EVENT_CLONE ||
                target.ptrace.stop_event == EDGE_LINUX_PTRACE_EVENT_EXEC ||
                target.ptrace.stop_event ==
                    EDGE_LINUX_PTRACE_EVENT_VFORK_DONE) {
                int32_t visible_pid;
                if (!event_message || event_message > INT32_MAX ||
                    edge_pid_namespace_global_to_visible(
                        caller.pid_namespace_id, (int32_t)event_message,
                        &visible_pid) < 0)
                    return -EDGE_LINUX_ESRCH;
                event_message = (uint64_t)(uint32_t)visible_pid;
            }
            return ptrace_copy_to_user(
                context, data, &event_message,
                ptrace_uses_compat_layout(context) ?
                    sizeof(uint32_t) : sizeof(event_message)) < 0 ?
                -EDGE_LINUX_EFAULT : 0;
        }
    case EDGE_LINUX_PTRACE_GETSIGINFO: {
        uint8_t information[128];
        if (!data) return -EDGE_LINUX_EFAULT;
        if (kernel_ptrace_get_signal_info(pid, information,
                                          sizeof(information)) < 0)
            return -EDGE_LINUX_EINVAL;
        if (ptrace_uses_compat_layout(context)) {
            struct edge_linux_compat_siginfo compat;
            edge_linux_native_siginfo_to_compat(
                (const struct edge_linux_siginfo *)(const void *)information,
                &compat);
            return ptrace_copy_to_user(
                context, data, &compat, sizeof(compat)) < 0 ?
                -EDGE_LINUX_EFAULT : 0;
        }
        return ptrace_copy_to_user(
            context, data, information, sizeof(information)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    case EDGE_LINUX_PTRACE_SETSIGINFO: {
        uint8_t information[128];
        if (!data) return -EDGE_LINUX_EFAULT;
        if (ptrace_uses_compat_layout(context)) {
            struct edge_linux_compat_siginfo compat;
            if (ptrace_copy_from_user(
                    context, &compat, data, sizeof(compat)) < 0)
                return -EDGE_LINUX_EFAULT;
            edge_linux_compat_siginfo_to_native(
                &compat,
                (struct edge_linux_siginfo *)(void *)information);
        } else if (ptrace_copy_from_user(
                context, information, data, sizeof(information)) < 0) {
            return -EDGE_LINUX_EFAULT;
        }
        return kernel_ptrace_set_signal_info(pid, information,
                                             sizeof(information)) < 0 ?
            -EDGE_LINUX_EINVAL : 0;
    }
    case EDGE_LINUX_PTRACE_GETREGSET:
        return ptrace_get_regset(context, pid, (uint32_t)address, data);
    case EDGE_LINUX_PTRACE_SETREGSET:
        return ptrace_set_regset(context, pid, (uint32_t)address, data);
    case EDGE_LINUX_PTRACE_INTERRUPT:
        if (!target.ptrace.seized || address || data)
            return -EDGE_LINUX_EIO;
        return kernel_ptrace_interrupt(pid, caller.tid);
    case EDGE_LINUX_PTRACE_PEEKSIGINFO:
        return ptrace_peeksiginfo(context, pid, address, data);
    case EDGE_LINUX_PTRACE_GETSIGMASK: {
        uint64_t mask;
        if (address != sizeof(mask) || !data)
            return -EDGE_LINUX_EINVAL;
        if (kernel_ptrace_get_signal_mask(pid, &mask) < 0)
            return -EDGE_LINUX_EIO;
        return ptrace_copy_to_user(context, data, &mask, sizeof(mask)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    case EDGE_LINUX_PTRACE_SETSIGMASK: {
        uint64_t mask;
        if (address != sizeof(mask) || !data)
            return -EDGE_LINUX_EINVAL;
        if (ptrace_copy_from_user(context, &mask, data, sizeof(mask)) < 0)
            return -EDGE_LINUX_EFAULT;
        mask &= ~((1ULL << (EDGE_LINUX_PTRACE_SIGKILL - 1u)) |
                  (1ULL << (EDGE_LINUX_PTRACE_SIGSTOP - 1u)));
        return kernel_ptrace_set_signal_mask(pid, mask) < 0 ?
            -EDGE_LINUX_EIO : 0;
    }
    case EDGE_LINUX_PTRACE_GET_SYSCALL_INFO:
        return ptrace_get_syscall_info(context, &target, address, data);
    case EDGE_LINUX_PTRACE_GET_RSEQ_CONFIGURATION: {
        edge_linux_ptrace_rseq_configuration_t configuration;
        if (address != sizeof(configuration) || !data)
            return -EDGE_LINUX_EINVAL;
        if (kernel_ptrace_get_rseq_configuration(pid, &configuration) < 0)
            return -EDGE_LINUX_EIO;
        return ptrace_copy_to_user(context, data, &configuration,
                                   sizeof(configuration)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    case EDGE_LINUX_PTRACE_SECCOMP_GET_FILTER:
    case EDGE_LINUX_PTRACE_SECCOMP_GET_METADATA:
    case EDGE_LINUX_PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG:
    case EDGE_LINUX_PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG:
    case EDGE_LINUX_PTRACE_SET_SYSCALL_INFO:
        /* The requested optional facility is not present on this task. */
        return -EDGE_LINUX_EIO;
    default:
        return -EDGE_LINUX_EIO;
    }
}

void edge_linux_ptrace_syscall_enter(void *user_registers,
                                     uint64_t *number,
                                     uint64_t arguments[6]) {
    kernel_linux_identity_t identity;
    edge_linux_ptrace_task_info_t information;
    edge_linux_ptrace_stop_t stop;
    if (!number || !arguments || ptrace_current_identity(&identity) < 0)
        return;
    if (kernel_ptrace_consume_syscall_restart(user_registers) > 0) return;
    if (kernel_ptrace_task_info(identity.global_tid, &information) < 0 ||
        information.ptrace.tracer_pid <= 0 ||
        information.ptrace.resume_mode != EDGE_LINUX_PTRACE_RESUME_SYSCALL)
        return;
    memset(&stop, 0, sizeof(stop));
    stop.reason = EDGE_LINUX_PTRACE_STOP_SYSCALL_ENTRY;
    stop.signal = EDGE_LINUX_PTRACE_SIGTRAP |
        ((information.ptrace.options & EDGE_LINUX_PTRACE_O_TRACESYSGOOD) ?
         0x80u : 0u);
    stop.syscall_number = *number;
    for (uint32_t index = 0; index < 6u; ++index)
        stop.syscall_arguments[index] = arguments[index];
    if (kernel_ptrace_stop_current(user_registers, &stop) < 0) return;
    (void)kernel_ptrace_current_syscall(user_registers, number, arguments, 0);
}

void edge_linux_ptrace_syscall_exit(void *user_registers, int64_t *result) {
    kernel_linux_identity_t identity;
    edge_linux_ptrace_task_info_t information;
    edge_linux_ptrace_stop_t stop;
    uint64_t number = 0;
    uint64_t arguments[6] = {0};
    if (!result || ptrace_current_identity(&identity) < 0) return;
    if (kernel_ptrace_task_info(identity.global_tid, &information) < 0 ||
        information.ptrace.tracer_pid <= 0 ||
        information.ptrace.resume_mode != EDGE_LINUX_PTRACE_RESUME_SYSCALL ||
        !information.ptrace.syscall_active)
        return;
    (void)kernel_ptrace_current_syscall(user_registers, &number, arguments,
                                        result);
    memset(&stop, 0, sizeof(stop));
    stop.reason = EDGE_LINUX_PTRACE_STOP_SYSCALL_EXIT;
    stop.signal = EDGE_LINUX_PTRACE_SIGTRAP |
        ((information.ptrace.options & EDGE_LINUX_PTRACE_O_TRACESYSGOOD) ?
         0x80u : 0u);
    stop.syscall_number = number;
    for (uint32_t index = 0; index < 6u; ++index)
        stop.syscall_arguments[index] = arguments[index];
    stop.syscall_result = *result;
    if (kernel_ptrace_stop_current(user_registers, &stop) < 0) return;
    (void)kernel_ptrace_current_syscall(user_registers, &number, arguments,
                                        result);
}

void edge_linux_ptrace_deferred_syscall_exit(void *user_registers) {
    kernel_linux_identity_t identity;
    edge_linux_ptrace_task_info_t information;
    edge_linux_ptrace_stop_t stop;
    int64_t result = 0;
    uint64_t number = 0;
    uint64_t arguments[6] = {0};
    if (!user_registers || ptrace_current_identity(&identity) < 0 ||
        kernel_ptrace_task_info(identity.global_tid, &information) < 0 ||
        information.ptrace.tracer_pid <= 0 ||
        information.ptrace.resume_mode != EDGE_LINUX_PTRACE_RESUME_SYSCALL ||
        !information.ptrace.syscall_active ||
        information.ptrace.restart_syscall ||
        information.ptrace.stop_reason != EDGE_LINUX_PTRACE_STOP_NONE)
        return;
    if (kernel_ptrace_current_syscall(user_registers, &number, arguments,
                                      &result) < 0)
        return;
    memset(&stop, 0, sizeof(stop));
    stop.reason = EDGE_LINUX_PTRACE_STOP_SYSCALL_EXIT;
    stop.signal = EDGE_LINUX_PTRACE_SIGTRAP |
        ((information.ptrace.options & EDGE_LINUX_PTRACE_O_TRACESYSGOOD) ?
         0x80u : 0u);
    stop.syscall_number = information.ptrace.syscall_number;
    for (uint32_t index = 0; index < 6u; ++index)
        stop.syscall_arguments[index] =
            information.ptrace.syscall_arguments[index];
    stop.syscall_result = result;
    (void)kernel_ptrace_stop_current(user_registers, &stop);
}

int edge_linux_ptrace_clone_stop(void *user_registers, uint64_t clone_flags,
                                 int32_t child_global_pid,
                                 int32_t child_visible_pid) {
    kernel_linux_identity_t identity;
    edge_linux_ptrace_task_info_t information;
    edge_linux_ptrace_stop_t stop;
    uint32_t event;
    uint32_t option;
    if (child_global_pid <= 0 || child_visible_pid <= 0 ||
        ptrace_current_identity(&identity) < 0 ||
        kernel_ptrace_task_info(identity.global_tid, &information) < 0 ||
        information.ptrace.tracer_pid <= 0 ||
        (clone_flags & EDGE_LINUX_CLONE_UNTRACED))
        return 0;
    if (clone_flags & EDGE_LINUX_CLONE_VFORK) {
        event = EDGE_LINUX_PTRACE_EVENT_VFORK;
        option = EDGE_LINUX_PTRACE_O_TRACEVFORK;
    } else if ((clone_flags & EDGE_LINUX_CLONE_SIGNAL_MASK) ==
               EDGE_LINUX_SIGCHLD) {
        event = EDGE_LINUX_PTRACE_EVENT_FORK;
        option = EDGE_LINUX_PTRACE_O_TRACEFORK;
    } else {
        event = EDGE_LINUX_PTRACE_EVENT_CLONE;
        option = EDGE_LINUX_PTRACE_O_TRACECLONE;
    }
    if (!(information.ptrace.options & option)) return 0;
    if (kernel_ptrace_attach_child(child_global_pid,
            information.ptrace.tracer_pid, information.ptrace.seized,
            information.ptrace.options) < 0)
        return -EDGE_LINUX_ESRCH;
    memset(&stop, 0, sizeof(stop));
    stop.reason = EDGE_LINUX_PTRACE_STOP_EVENT;
    stop.signal = EDGE_LINUX_PTRACE_SIGTRAP;
    stop.event = event;
    stop.event_message = (uint64_t)(uint32_t)child_global_pid;
    stop.syscall_number = information.ptrace.syscall_number;
    for (uint32_t index = 0; index < 6u; ++index)
        stop.syscall_arguments[index] =
            information.ptrace.syscall_arguments[index];
    stop.syscall_result = child_visible_pid;
    return kernel_ptrace_stop_current(user_registers, &stop) < 0 ?
        -EDGE_LINUX_ESRCH : 1;
}

void edge_linux_ptrace_exec_stop(void *user_registers) {
    kernel_linux_identity_t identity;
    edge_linux_ptrace_task_info_t information;
    edge_linux_ptrace_stop_t stop;
    if (ptrace_current_identity(&identity) < 0 ||
        kernel_ptrace_task_info(identity.global_tid, &information) < 0 ||
        information.ptrace.tracer_pid <= 0)
        return;
    memset(&stop, 0, sizeof(stop));
    stop.reason = EDGE_LINUX_PTRACE_STOP_EVENT;
    stop.signal = EDGE_LINUX_PTRACE_SIGTRAP;
    stop.syscall_number = information.ptrace.syscall_number;
    for (uint32_t index = 0; index < 6u; ++index)
        stop.syscall_arguments[index] =
            information.ptrace.syscall_arguments[index];
    stop.syscall_result = 0;
    if (information.ptrace.options & EDGE_LINUX_PTRACE_O_TRACEEXEC) {
        stop.event = EDGE_LINUX_PTRACE_EVENT_EXEC;
        stop.event_message = (uint64_t)(uint32_t)identity.global_tid;
    }
    (void)kernel_ptrace_stop_current(user_registers, &stop);
}

int edge_linux_ptrace_signal_stop(void *user_registers, uint32_t signal) {
    kernel_linux_identity_t identity;
    edge_linux_ptrace_task_info_t information;
    edge_linux_ptrace_stop_t stop;
    if (!user_registers || !signal ||
        signal == EDGE_LINUX_PTRACE_SIGKILL ||
        ptrace_current_identity(&identity) < 0 ||
        kernel_ptrace_task_info(identity.global_tid, &information) < 0 ||
        information.ptrace.tracer_pid <= 0)
        return 0;
    memset(&stop, 0, sizeof(stop));
    /*
     * PTRACE_INTERRUPT is delivered through the target's next safe
     * return-to-user boundary so the architecture backend captures the live
     * register frame owned by that task.  The synthetic SIGTRAP is only the
     * rendezvous mechanism; userspace must observe PTRACE_EVENT_STOP rather
     * than an ordinary signal-delivery stop.
     */
    if (signal == EDGE_LINUX_PTRACE_SIGTRAP &&
        information.ptrace.interrupt_pending) {
        stop.reason = EDGE_LINUX_PTRACE_STOP_INTERRUPT;
        stop.event = EDGE_LINUX_PTRACE_EVENT_STOP;
    } else {
        stop.reason = EDGE_LINUX_PTRACE_STOP_SIGNAL;
    }
    stop.signal = signal;
    stop.instruction_pointer = information.ptrace.instruction_pointer;
    stop.stack_pointer = information.ptrace.stack_pointer;
    return kernel_ptrace_stop_current(user_registers, &stop) < 0 ? 0 : 1;
}

int edge_linux_ptrace_debug_stop(void *user_registers) {
    kernel_linux_identity_t identity;
    edge_linux_ptrace_task_info_t information;
    edge_linux_ptrace_stop_t stop;
    if (ptrace_current_identity(&identity) < 0 ||
        kernel_ptrace_task_info(identity.global_tid, &information) < 0 ||
        information.ptrace.tracer_pid <= 0)
        return 0;
    memset(&stop, 0, sizeof(stop));
    stop.reason = EDGE_LINUX_PTRACE_STOP_SINGLESTEP;
    stop.signal = EDGE_LINUX_PTRACE_SIGTRAP;
    return kernel_ptrace_stop_current(user_registers, &stop) < 0 ? 0 : 1;
}
