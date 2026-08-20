/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux syscall core.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stddef.h>
#include <stdint.h>

#include "console.h"
#include "fs/swap.h"
#include "kernel/fd_runtime.h"
#include "kernel/anonymous_fd.h"
#include "kernel/event_runtime.h"
#include "kernel/exec_runtime.h"
#include "kernel/file_metadata.h"
#include "kernel/file_lock.h"
#include "kernel/fs_context.h"
#include "kernel/futex_runtime.h"
#include "kernel/inotify.h"
#include "kernel/inotify_runtime.h"
#include "kernel/ioctl_runtime.h"
#include "kernel/itimer_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_mount.h"
#include "kernel/linux_module.h"
#include "kernel/mount_api.h"
#include "kernel/linux_netlink.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_ptrace.h"
#include "kernel/linux_packet.h"
#include "kernel/linux_prctl.h"
#include "kernel/linux_seek.h"
#include "kernel/linux_syscall.h"
#include "kernel/memfd_runtime.h"
#include "kernel/linux_time.h"
#include "kernel/linux_utsname.h"
#include "kernel/mm_runtime.h"
#include "kernel/namespaces.h"
#include "kernel/namespace_runtime.h"
#include "kernel/credentials.h"
#include "kernel/device_uevent.h"
#include "kernel/directory_runtime.h"
#include "kernel/process_runtime.h"
#include "kernel/clone_runtime.h"
#include "kernel/posix_timer_runtime.h"
#include "kernel/random.h"
#include "kernel/seccomp.h"
#include "kernel/signalfd.h"
#include "kernel/signalfd_runtime.h"
#include "kernel/signal_policy.h"
#include "kernel/signal_queue.h"
#include "kernel/socket_runtime.h"
#include "kernel/socket_message.h"
#include "kernel/system_runtime.h"
#include "kernel/sysv_shm_runtime.h"
#include "kernel/sysv_sem_runtime.h"
#include "kernel/syslog_runtime.h"
#include "kernel/timerfd.h"
#include "kernel/timerfd_runtime.h"
#include "kernel/time_discipline.h"
#include "kernel/tty_session.h"
#include "kernel/vfs_runtime.h"
#include "mm/arch_vm.h"
#include "sys/boottime.h"
#include "sys/bootlog.h"
#include "sys/spinlock.h"
#include "string.h"
#include "vfs/mount_namespace.h"

#include "linux_syscall_tables.inc"

static int edge_linux_fd_number(uint64_t raw, int32_t *descriptor);
static int edge_linux_current_magic_fd(
    const char *path, const kernel_linux_identity_t *identity,
    int32_t *descriptor);
static int edge_linux_current_magic_executable(
    const char *path, const kernel_linux_identity_t *identity,
    int32_t *owner_out);

static int edge_linux_pid_to_global(
    const kernel_linux_identity_t *caller, int32_t visible_pid,
    int32_t *global_pid) {
    if (!caller || !global_pid || visible_pid <= 0) return -1;
    return edge_pid_namespace_visible_to_global(
        caller->pid_namespace_id, visible_pid, global_pid);
}

static int edge_linux_syscall_lookup(
    const edge_linux_syscall_number_t *table, size_t count,
    uint64_t raw_number, edge_linux_syscall_id_t *id,
    edge_linux_syscall_route_status_t *status) {
    size_t low = 0;
    size_t high = count;
    if (raw_number > UINT32_MAX) return -1;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        if (raw_number < table[middle].number) {
            high = middle;
        } else if (raw_number > table[middle].number) {
            low = middle + 1u;
        } else {
            if (id) *id = table[middle].id;
            if (status) *status = table[middle].status;
            return 0;
        }
    }
    return -1;
}

int edge_linux_syscall_map(edge_linux_syscall_architecture_t architecture,
                           uint64_t raw_number,
                           edge_linux_syscall_id_t *id,
                           edge_linux_syscall_route_status_t *status) {
    if (id) *id = EDGE_LINUX_SYS_INVALID;
    if (status) *status = EDGE_LINUX_SYSCALL_ENOSYS;
    if (architecture == EDGE_LINUX_ARCH_X86_64) {
        return edge_linux_syscall_lookup(
            edge_linux_x86_64_numbers,
            sizeof(edge_linux_x86_64_numbers) /
                sizeof(edge_linux_x86_64_numbers[0]),
            raw_number, id, status);
    }
    if (architecture == EDGE_LINUX_ARCH_AARCH64) {
        return edge_linux_syscall_lookup(
            edge_linux_aarch64_numbers,
            sizeof(edge_linux_aarch64_numbers) /
                sizeof(edge_linux_aarch64_numbers[0]),
            raw_number, id, status);
    }
    return -1;
}

static int edge_linux_copy_to_user(edge_linux_syscall_context_t *context,
                                   uint64_t destination,
                                   const void *source, uint64_t size) {
    if (!context || !context->arch_ops ||
        !context->arch_ops->copy_to_user)
        return -1;
    return context->arch_ops->copy_to_user(
        context->current_task, destination, source, size);
}

static int edge_linux_copy_from_user(edge_linux_syscall_context_t *context,
                                     void *destination, uint64_t source,
                                     uint64_t size) {
    if (!context || !context->arch_ops ||
        !context->arch_ops->copy_from_user)
        return -1;
    return context->arch_ops->copy_from_user(
        context->current_task, destination, source, size);
}

static int edge_linux_seccomp_copy_from_user(void *opaque, void *destination,
                                             uint64_t source, uint64_t size) {
    return edge_linux_copy_from_user(
        (edge_linux_syscall_context_t *)opaque, destination, source, size);
}

static int edge_linux_directory_copy_to_user(
    void *opaque, uint64_t destination, const void *source, uint64_t size) {
    return edge_linux_copy_to_user(
        (edge_linux_syscall_context_t *)opaque, destination, source, size);
}

static int edge_linux_validate_user_range(
    edge_linux_syscall_context_t *context, uint64_t address,
    uint64_t size, int write) {
    const edge_linux_syscall_arch_ops_t *ops;
    if (!context || !(ops = context->arch_ops) ||
        !edge_linux_user_range_valid(address, size,
                                     ops->user_address_minimum,
                                     ops->user_address_limit))
        return -1;
    if (!ops->validate_user_range_arch) return 0;
    return ops->validate_user_range_arch(
        context->current_task, address, size, write);
}

static int edge_linux_copy_user_string(
    edge_linux_syscall_context_t *context, uint64_t source,
    char *destination, uint32_t capacity, int too_long_error) {
    uint32_t index;
    if (!source) return -EDGE_LINUX_EFAULT;
    if (!destination || !capacity) return -EDGE_LINUX_EIO;
    for (index = 0; index < capacity; ++index) {
        if (source > UINT64_MAX - index ||
            edge_linux_copy_from_user(context, destination + index,
                                      source + index, 1u) < 0)
            return -EDGE_LINUX_EFAULT;
        if (!destination[index]) return (int)index;
    }
    destination[capacity - 1u] = 0;
    return -too_long_error;
}

static int edge_linux_user_bytes_zero(
    edge_linux_syscall_context_t *context, uint64_t address,
    uint64_t offset, uint64_t length) {
    uint8_t buffer[32];
    while (length) {
        uint64_t chunk = length < sizeof(buffer) ? length : sizeof(buffer);
        if (edge_linux_copy_from_user(context, buffer, address + offset,
                                      chunk) < 0)
            return -EDGE_LINUX_EFAULT;
        for (uint64_t byte = 0; byte < chunk; ++byte)
            if (buffer[byte]) return 1;
        offset += chunk;
        length -= chunk;
    }
    return 0;
}

static int64_t edge_linux_sys_identity(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    edge_namespace_set_t *namespaces;
    uint32_t visible_id;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    namespaces = kernel_arch_current_namespace_set();
    switch (context->id) {
        case EDGE_LINUX_SYS_getpid:
            return identity.tgid;
        case EDGE_LINUX_SYS_gettid:
            return identity.tid;
        case EDGE_LINUX_SYS_getppid:
            return identity.ppid;
        case EDGE_LINUX_SYS_getuid:
            return namespaces && edge_userns_map_from_parent(
                namespaces, 0, identity.uid, &visible_id) == 0 ?
                visible_id : 65534u;
        case EDGE_LINUX_SYS_geteuid:
            return namespaces && edge_userns_map_from_parent(
                namespaces, 0, identity.euid, &visible_id) == 0 ?
                visible_id : 65534u;
        case EDGE_LINUX_SYS_getgid:
            return namespaces && edge_userns_map_from_parent(
                namespaces, 1, identity.gid, &visible_id) == 0 ?
                visible_id : 65534u;
        case EDGE_LINUX_SYS_getegid:
            return namespaces && edge_userns_map_from_parent(
                namespaces, 1, identity.egid, &visible_id) == 0 ?
                visible_id : 65534u;
        default:
            return -EDGE_LINUX_ENOSYS;
    }
}

static int64_t edge_linux_sys_exit(
    edge_linux_syscall_context_t *context) {
    int whole_thread_group;

    if (context->id == EDGE_LINUX_SYS_exit) {
        whole_thread_group = 0;
    } else if (context->id == EDGE_LINUX_SYS_exit_group) {
        whole_thread_group = 1;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    kernel_current_exit((int32_t)context->arguments[0], whole_thread_group);
}

static int64_t edge_linux_sys_res_identity(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    uint32_t values[3];
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (context->id == EDGE_LINUX_SYS_getresuid) {
        values[0] = identity.uid;
        values[1] = identity.euid;
        values[2] = identity.suid;
    } else if (context->id == EDGE_LINUX_SYS_getresgid) {
        values[0] = identity.gid;
        values[1] = identity.egid;
        values[2] = identity.sgid;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    for (uint32_t index = 0; index < 3u; ++index) {
        if (!context->arguments[index] ||
            edge_linux_copy_to_user(context, context->arguments[index],
                                    &values[index], sizeof(values[index])) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

static int64_t edge_linux_sys_process_group(
    edge_linux_syscall_context_t *context) {
    edge_linux_process_session_request_t request;
    kernel_linux_identity_t identity;
    int32_t value;
    int32_t pid;
    if (context->id == EDGE_LINUX_SYS_setpgid) {
        request.operation = EDGE_LINUX_PROCESS_SET_PGID;
        request.pid = (int32_t)context->arguments[0];
        request.pgid = (int32_t)context->arguments[1];
        return kernel_process_session_change(&request);
    }
    if (context->id == EDGE_LINUX_SYS_setsid) {
        request.operation = EDGE_LINUX_PROCESS_CREATE_SESSION;
        request.pid = 0;
        request.pgid = 0;
        return kernel_process_session_change(&request);
    }
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (context->id == EDGE_LINUX_SYS_getpgrp)
        return identity.pgid;
    pid = (int32_t)context->arguments[0];
    if (pid < 0) return -EDGE_LINUX_ESRCH;
    if (context->id == EDGE_LINUX_SYS_getpgid) {
        if (kernel_process_group_id(pid, &value) < 0)
            return -EDGE_LINUX_ESRCH;
        return value;
    }
    if (context->id == EDGE_LINUX_SYS_getsid) {
        if (kernel_process_session_id(pid, &value) < 0)
            return -EDGE_LINUX_ESRCH;
        return value;
    }
    return -EDGE_LINUX_ENOSYS;
}

static int64_t edge_linux_sys_umask(
    edge_linux_syscall_context_t *context) {
    return kernel_current_umask_set(
        (uint16_t)(context->arguments[0] & 0777u));
}

static int64_t edge_linux_sys_set_uts_name(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    char name[65] = {0};
    uint64_t length = context->arguments[1];
    int result;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (((identity.effective_capabilities >> EDGE_LINUX_CAP_SYS_ADMIN) &
         1u) == 0)
        return -EDGE_LINUX_EPERM;
    if (length > 64u) return -EDGE_LINUX_EINVAL;
    if (length && (!context->arguments[0] ||
                   edge_linux_copy_from_user(context, name,
                                             context->arguments[0],
                                             length) < 0))
        return -EDGE_LINUX_EFAULT;
    if (context->id == EDGE_LINUX_SYS_sethostname) {
        result = kernel_current_set_hostname(name, (uint32_t)length);
    } else if (context->id == EDGE_LINUX_SYS_setdomainname) {
        result = kernel_current_set_domainname(name, (uint32_t)length);
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    return result < 0 ? -EDGE_LINUX_EINVAL : 0;
}

static int64_t edge_linux_sys_clock(edge_linux_syscall_context_t *context) {
    linux_timespec64_t value;
    int clock_id = (int)context->arguments[0];
    uint64_t destination = context->arguments[1];
    int result;
    if (context->id == EDGE_LINUX_SYS_clock_gettime) {
        if (!destination) return -EDGE_LINUX_EFAULT;
        result = linux_clock_gettime_value(clock_id, &value);
    } else {
        result = linux_clock_getres_value(clock_id, &value);
        if (!destination && result == 0) return 0;
    }
    if (result < 0) return -EDGE_LINUX_EINVAL;
    return edge_linux_copy_to_user(context, destination, &value,
                                   sizeof(value)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

#define EDGE_LINUX_TIMER_ABSTIME 1u

static int edge_linux_sleep_clock_status(int32_t clock_id) {
    switch (clock_id) {
        case LINUX_CLOCK_REALTIME:
        case LINUX_CLOCK_MONOTONIC:
        case LINUX_CLOCK_BOOTTIME:
            return 0;
        case LINUX_CLOCK_PROCESS_CPUTIME_ID:
        case LINUX_CLOCK_THREAD_CPUTIME_ID:
        case LINUX_CLOCK_MONOTONIC_RAW:
        case LINUX_CLOCK_REALTIME_COARSE:
        case LINUX_CLOCK_MONOTONIC_COARSE:
        case LINUX_CLOCK_REALTIME_ALARM:
        case LINUX_CLOCK_BOOTTIME_ALARM:
        case LINUX_CLOCK_TAI:
            return -EDGE_LINUX_EOPNOTSUPP;
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

static int edge_linux_timespec_microseconds(
    const linux_timespec64_t *value, uint64_t *microseconds) {
    uint64_t seconds;
    uint64_t subsecond;
    if (!value || !microseconds || value->tv_sec < 0 ||
        value->tv_nsec < 0 || value->tv_nsec >= 1000000000LL)
        return -EDGE_LINUX_EINVAL;
    seconds = (uint64_t)value->tv_sec;
    subsecond = ((uint64_t)value->tv_nsec + 999u) / 1000u;
    if (seconds > (UINT64_MAX - subsecond) / 1000000u) {
        *microseconds = UINT64_MAX;
    } else {
        *microseconds = seconds * 1000000u + subsecond;
    }
    return 0;
}

static int64_t edge_linux_sys_nanosleep(
    edge_linux_syscall_context_t *context) {
    linux_timespec64_t request;
    uint64_t request_user;
    uint64_t remaining_user;
    uint64_t requested_microseconds;
    uint64_t deadline;
    uint64_t monotonic_now;
    uint64_t clock_now;
    uint64_t duration;
    uint32_t flags = 0;
    int32_t clock_id = LINUX_CLOCK_MONOTONIC;
    int absolute = 0;
    int status;
    int64_t result;
    kernel_linux_thread_state_t *thread_state = 0;

    if (context->id == EDGE_LINUX_SYS_clock_nanosleep) {
        clock_id = (int32_t)context->arguments[0];
        flags = (uint32_t)context->arguments[1];
        request_user = context->arguments[2];
        remaining_user = context->arguments[3];
        absolute = (flags & EDGE_LINUX_TIMER_ABSTIME) != 0;
        status = edge_linux_sleep_clock_status(clock_id);
        if (status < 0) return status;
    } else if (context->id == EDGE_LINUX_SYS_nanosleep) {
        request_user = context->arguments[0];
        remaining_user = context->arguments[1];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }

    if (!request_user) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(context, &request, request_user,
                                  sizeof(request)) < 0)
        return -EDGE_LINUX_EFAULT;
    status = edge_linux_timespec_microseconds(
        &request, &requested_microseconds);
    if (status < 0) return status;

    monotonic_now = boottime_monotonic_us();
    if (absolute) {
        clock_now = clock_id == LINUX_CLOCK_REALTIME ?
            boottime_realtime_us() : monotonic_now;
        if (requested_microseconds <= clock_now) return 0;
        duration = requested_microseconds - clock_now;
    } else {
        duration = requested_microseconds;
        if (!duration) return 0;
    }
    deadline = duration > UINT64_MAX - monotonic_now ?
        UINT64_MAX : monotonic_now + duration;
    if (!absolute &&
        kernel_arch_current_linux_thread_state(&thread_state) == 0 &&
        thread_state) {
        kernel_restart_block_prepare_nanosleep(
            &thread_state->restart_block, deadline, remaining_user,
            remaining_user != 0);
        return kernel_restart_block_execute(
            &thread_state->restart_block, monotonic_now,
            kernel_current_sleep_until, context->user_registers);
    }
    result = kernel_current_sleep_until(
        deadline, remaining_user, !absolute && remaining_user != 0,
        context->user_registers);
    return result;
}

static int64_t edge_linux_sys_restart_syscall(
    edge_linux_syscall_context_t *context) {
    kernel_linux_thread_state_t *thread_state = 0;

    if (!context ||
        kernel_arch_current_linux_thread_state(&thread_state) < 0 ||
        !thread_state)
        return -EDGE_LINUX_EINTR;
    return kernel_restart_block_execute(
        &thread_state->restart_block, boottime_monotonic_us(),
        kernel_current_sleep_until, context->user_registers);
}

static int edge_linux_posix_timer_clock_supported(int32_t clock_id) {
    return clock_id == LINUX_CLOCK_REALTIME ||
           clock_id == LINUX_CLOCK_MONOTONIC ||
           clock_id == LINUX_CLOCK_BOOTTIME ||
           clock_id == LINUX_CLOCK_REALTIME_ALARM ||
           clock_id == LINUX_CLOCK_BOOTTIME_ALARM;
}

static void edge_linux_posix_timer_state_to_uapi(
    const kernel_posix_timer_state_t *state,
    linux_itimerspec64_t *value) {
    if (!state || !value) return;
    linux_timespec_from_microseconds(
        state->interval_microseconds, &value->it_interval);
    linux_timespec_from_microseconds(
        state->remaining_microseconds, &value->it_value);
}

static int64_t edge_linux_sys_posix_timer(
    edge_linux_syscall_context_t *context) {
    kernel_posix_timer_create_request_t create_request;
    kernel_posix_timer_state_t state;
    kernel_posix_timer_state_t previous;
    linux_sigevent64_t event;
    linux_itimerspec64_t replacement;
    linux_itimerspec64_t value;
    uint64_t initial;
    uint64_t interval;
    int32_t timer_id = (int32_t)context->arguments[0];
    int status;

    if (context->id == EDGE_LINUX_SYS_timer_create) {
        create_request.clock_id = (int32_t)context->arguments[0];
        create_request.notify = KERNEL_POSIX_TIMER_SIGEV_SIGNAL;
        create_request.signal_number = EDGE_LINUX_SIGALRM;
        create_request.target_tid = 0;
        create_request.signal_value = 0;
        create_request.default_event = context->arguments[1] == 0;
        if (!edge_linux_posix_timer_clock_supported(
                create_request.clock_id))
            return -EDGE_LINUX_EINVAL;
        if (create_request.clock_id == LINUX_CLOCK_REALTIME_ALARM ||
            create_request.clock_id == LINUX_CLOCK_BOOTTIME_ALARM) {
            kernel_linux_identity_t identity;
            if (kernel_current_linux_identity(&identity) < 0)
                return -EDGE_LINUX_ESRCH;
            if (!(identity.effective_capabilities &
                  (1ULL << EDGE_LINUX_CAP_WAKE_ALARM)))
                return -EDGE_LINUX_EPERM;
        }
        if (context->arguments[1]) {
            if (edge_linux_copy_from_user(
                    context, &event, context->arguments[1],
                    sizeof(event)) < 0)
                return -EDGE_LINUX_EFAULT;
            create_request.notify = event.sigev_notify;
            create_request.signal_number = event.sigev_signo;
            create_request.signal_value = event.sigev_value;
            if (create_request.notify == KERNEL_POSIX_TIMER_SIGEV_THREAD_ID)
                create_request.target_tid = event.fields.thread_id;
            if (create_request.notify == KERNEL_POSIX_TIMER_SIGEV_NONE) {
                create_request.signal_number = 0;
            } else if (create_request.notify ==
                           KERNEL_POSIX_TIMER_SIGEV_SIGNAL ||
                       create_request.notify ==
                           KERNEL_POSIX_TIMER_SIGEV_THREAD ||
                       create_request.notify ==
                           KERNEL_POSIX_TIMER_SIGEV_THREAD_ID) {
                if (create_request.signal_number <= 0 ||
                    create_request.signal_number > 64)
                    return -EDGE_LINUX_EINVAL;
                if (create_request.notify ==
                        KERNEL_POSIX_TIMER_SIGEV_THREAD_ID &&
                    create_request.target_tid <= 0)
                    return -EDGE_LINUX_EINVAL;
            } else {
                return -EDGE_LINUX_EINVAL;
            }
        }
        if (!context->arguments[2]) return -EDGE_LINUX_EFAULT;
        status = kernel_posix_timer_create(
            &create_request, &timer_id);
        if (status < 0) return status;
        if (edge_linux_copy_to_user(
                context, context->arguments[2], &timer_id,
                sizeof(timer_id)) < 0) {
            (void)kernel_posix_timer_delete(timer_id);
            return -EDGE_LINUX_EFAULT;
        }
        return 0;
    }

    if (context->id == EDGE_LINUX_SYS_timer_getoverrun)
        return kernel_posix_timer_get_overrun(timer_id);
    if (context->id == EDGE_LINUX_SYS_timer_delete)
        return kernel_posix_timer_delete(timer_id);

    status = kernel_posix_timer_get(timer_id, &state);
    if (status < 0) return status;
    if (context->id == EDGE_LINUX_SYS_timer_gettime) {
        if (!context->arguments[1]) return -EDGE_LINUX_EFAULT;
        edge_linux_posix_timer_state_to_uapi(&state, &value);
        return edge_linux_copy_to_user(
            context, context->arguments[1], &value,
            sizeof(value)) < 0 ? -EDGE_LINUX_EFAULT : 0;
    }
    if (context->id != EDGE_LINUX_SYS_timer_settime)
        return -EDGE_LINUX_ENOSYS;
    if (!context->arguments[2]) return -EDGE_LINUX_EINVAL;
    if (edge_linux_copy_from_user(
            context, &replacement, context->arguments[2],
            sizeof(replacement)) < 0)
        return -EDGE_LINUX_EFAULT;
    status = edge_linux_timespec_microseconds(
        &replacement.it_value, &initial);
    if (status < 0) return status;
    status = edge_linux_timespec_microseconds(
        &replacement.it_interval, &interval);
    if (status < 0) return status;
    status = kernel_posix_timer_set(
        timer_id, initial, interval,
        ((uint32_t)context->arguments[1] &
         EDGE_LINUX_TIMER_ABSTIME) != 0,
        context->arguments[3] ? &previous : 0);
    if (status < 0) return status;
    if (context->arguments[3]) {
        edge_linux_posix_timer_state_to_uapi(&previous, &value);
        if (edge_linux_copy_to_user(
                context, context->arguments[3], &value,
                sizeof(value)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

enum edge_linux_syslog_action {
    EDGE_LINUX_SYSLOG_CLOSE = 0,
    EDGE_LINUX_SYSLOG_OPEN = 1,
    EDGE_LINUX_SYSLOG_READ = 2,
    EDGE_LINUX_SYSLOG_READ_ALL = 3,
    EDGE_LINUX_SYSLOG_READ_CLEAR = 4,
    EDGE_LINUX_SYSLOG_CLEAR = 5,
    EDGE_LINUX_SYSLOG_CONSOLE_OFF = 6,
    EDGE_LINUX_SYSLOG_CONSOLE_ON = 7,
    EDGE_LINUX_SYSLOG_CONSOLE_LEVEL = 8,
    EDGE_LINUX_SYSLOG_SIZE_UNREAD = 9,
    EDGE_LINUX_SYSLOG_SIZE_BUFFER = 10,
};

static spinlock_t g_edge_linux_syslog_lock;
static uint64_t g_edge_linux_syslog_read_position;
static int g_edge_linux_syslog_read_position_valid;

static int edge_linux_syslog_copy_range(
    edge_linux_syscall_context_t *context, uint64_t destination,
    uint64_t start, uint32_t length, uint64_t *end_position) {
    char chunk[512];
    uint64_t position = start;
    uint32_t copied = 0;
    while (copied < length) {
        uint32_t count = length - copied;
        int read;
        if (count > sizeof(chunk)) count = sizeof(chunk);
        read = bootlog_read_from(&position, chunk, count);
        if (read <= 0) break;
        if (edge_linux_copy_to_user(
                context, destination + copied, chunk,
                (uint32_t)read) < 0)
            return -EDGE_LINUX_EFAULT;
        copied += (uint32_t)read;
    }
    if (end_position) *end_position = position;
    return (int)copied;
}

static int edge_linux_syslog_permitted(void) {
    kernel_linux_identity_t identity;
    uint64_t mask = (1ULL << EDGE_LINUX_CAP_SYSLOG) |
                    (1ULL << EDGE_LINUX_CAP_SYS_ADMIN);
    if (kernel_current_linux_identity(&identity) < 0) return 0;
    /* EdgeOS uses Linux's secure dmesg_restrict=1 default. */
    return (identity.effective_capabilities & mask) != 0;
}

static int64_t edge_linux_sys_syslog(
    edge_linux_syscall_context_t *context) {
    int32_t action = (int32_t)context->arguments[0];
    uint64_t destination = context->arguments[1];
    int32_t length = (int32_t)context->arguments[2];

    if (!edge_linux_syslog_permitted()) return -EDGE_LINUX_EPERM;
    switch (action) {
    case EDGE_LINUX_SYSLOG_CLOSE:
    case EDGE_LINUX_SYSLOG_OPEN:
        return 0;
    case EDGE_LINUX_SYSLOG_READ:
        if (!destination || length < 0) return -EDGE_LINUX_EINVAL;
        if (!length) return 0;
        for (;;) {
            uint64_t first;
            uint64_t next;
            uint64_t end_position;
            uint64_t flags = spin_lock_irqsave(
                &g_edge_linux_syslog_lock);
            uint64_t available;
            uint32_t amount;
            int copied;
            int wait_status;
            bootlog_snapshot_bounds(&first, 0, &next);
            if (!g_edge_linux_syslog_read_position_valid) {
                g_edge_linux_syslog_read_position = first;
                g_edge_linux_syslog_read_position_valid = 1;
            }
            if (g_edge_linux_syslog_read_position < first)
                g_edge_linux_syslog_read_position = first;
            if (g_edge_linux_syslog_read_position < next) {
                available = next - g_edge_linux_syslog_read_position;
                amount = available < (uint64_t)(uint32_t)length ?
                    (uint32_t)available : (uint32_t)length;
                copied = edge_linux_syslog_copy_range(
                    context, destination,
                    g_edge_linux_syslog_read_position, amount,
                    &end_position);
                if (copied >= 0)
                    g_edge_linux_syslog_read_position = end_position;
                spin_unlock_irqrestore(
                    &g_edge_linux_syslog_lock, flags);
                return copied;
            }
            spin_unlock_irqrestore(&g_edge_linux_syslog_lock, flags);
            wait_status = kernel_syslog_wait_for_data(
                next, context->user_registers);
            if (wait_status > 0) continue;
            return wait_status;
        }
    case EDGE_LINUX_SYSLOG_READ_ALL:
    case EDGE_LINUX_SYSLOG_READ_CLEAR:
    {
        uint64_t clear;
        uint64_t next;
        uint64_t available;
        uint32_t amount;
        int copied;
        if (!destination || length < 0) return -EDGE_LINUX_EINVAL;
        if (!length) return 0;
        bootlog_snapshot_bounds(0, &clear, &next);
        available = next - clear;
        amount = available < (uint64_t)(uint32_t)length ?
            (uint32_t)available : (uint32_t)length;
        copied = edge_linux_syslog_copy_range(
            context, destination, next - amount, amount, 0);
        if (copied >= 0 && action == EDGE_LINUX_SYSLOG_READ_CLEAR)
            bootlog_clear();
        return copied;
    }
    case EDGE_LINUX_SYSLOG_CLEAR:
        bootlog_clear();
        return 0;
    case EDGE_LINUX_SYSLOG_CONSOLE_OFF:
        console_kernel_log_off();
        return 0;
    case EDGE_LINUX_SYSLOG_CONSOLE_ON:
        console_kernel_log_on();
        return 0;
    case EDGE_LINUX_SYSLOG_CONSOLE_LEVEL:
        return console_kernel_log_set_level(length) < 0 ?
            -EDGE_LINUX_EINVAL : 0;
    case EDGE_LINUX_SYSLOG_SIZE_UNREAD:
    {
        uint64_t first;
        uint64_t next;
        uint64_t unread;
        uint64_t flags = spin_lock_irqsave(&g_edge_linux_syslog_lock);
        bootlog_snapshot_bounds(&first, 0, &next);
        if (!g_edge_linux_syslog_read_position_valid) {
            g_edge_linux_syslog_read_position = first;
            g_edge_linux_syslog_read_position_valid = 1;
        }
        if (g_edge_linux_syslog_read_position < first)
            g_edge_linux_syslog_read_position = first;
        unread = next - g_edge_linux_syslog_read_position;
        spin_unlock_irqrestore(&g_edge_linux_syslog_lock, flags);
        return unread > INT32_MAX ? INT32_MAX : (int64_t)unread;
    }
    case EDGE_LINUX_SYSLOG_SIZE_BUFFER:
        return (int64_t)bootlog_buffer_capacity();
    default:
        return -EDGE_LINUX_EINVAL;
    }
}

static int edge_linux_timeval_valid(const linux_timeval64_t *value) {
    uint64_t seconds;
    if (!value || value->tv_sec < 0 || value->tv_usec < 0 ||
        value->tv_usec >= 1000000)
        return 0;
    seconds = (uint64_t)value->tv_sec;
    return seconds <= (UINT64_MAX - (uint64_t)value->tv_usec) / 1000000u;
}

static int64_t edge_linux_sys_itimer(
    edge_linux_syscall_context_t *context) {
    linux_itimerval64_t replacement = {{0, 0}, {0, 0}};
    linux_itimerval64_t previous;
    int status;

    if (context->id == EDGE_LINUX_SYS_alarm) {
        replacement.it_value.tv_sec =
            (int64_t)(uint32_t)context->arguments[0];
        status = kernel_itimer_real_exchange(&replacement, &previous);
        if (status < 0) return status;
        return previous.it_value.tv_sec +
            (previous.it_value.tv_usec != 0);
    }
    if (context->id == EDGE_LINUX_SYS_getitimer) {
        if (context->arguments[0] != 0u) return -EDGE_LINUX_EINVAL;
        if (!context->arguments[1]) return -EDGE_LINUX_EFAULT;
        status = kernel_itimer_real_get(&previous);
        if (status < 0) return status;
        return edge_linux_copy_to_user(
            context, context->arguments[1], &previous,
            sizeof(previous)) < 0 ? -EDGE_LINUX_EFAULT : 0;
    }
    if (context->id != EDGE_LINUX_SYS_setitimer)
        return -EDGE_LINUX_ENOSYS;
    if (context->arguments[1] && edge_linux_copy_from_user(
            context, &replacement, context->arguments[1],
            sizeof(replacement)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (context->arguments[0] != 0u) return -EDGE_LINUX_EINVAL;
    if (!edge_linux_timeval_valid(&replacement.it_interval) ||
        !edge_linux_timeval_valid(&replacement.it_value))
        return -EDGE_LINUX_EINVAL;
    status = kernel_itimer_real_exchange(&replacement, &previous);
    if (status < 0) return status;
    if (context->arguments[2] && edge_linux_copy_to_user(
            context, context->arguments[2], &previous,
            sizeof(previous)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_wall_time(
    edge_linux_syscall_context_t *context) {
    linux_timeval64_t value;
    linux_timezone_t timezone;
    linux_gettimeofday_value(&value);
    linux_get_timezone_value(&timezone);
    if (context->id == EDGE_LINUX_SYS_time) {
        if (context->arguments[0] &&
            edge_linux_copy_to_user(context, context->arguments[0],
                                    &value.tv_sec,
                                    sizeof(value.tv_sec)) < 0)
            return -EDGE_LINUX_EFAULT;
        return value.tv_sec;
    }
    if (context->arguments[0] &&
        edge_linux_copy_to_user(context, context->arguments[0], &value,
                                sizeof(value)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (context->arguments[1] &&
        edge_linux_copy_to_user(context, context->arguments[1], &timezone,
                                sizeof(timezone)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_set_wall_time(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    linux_timeval64_t timeval;
    linux_timespec64_t timespec;
    linux_timezone_t timezone;
    uint64_t realtime_us;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (((identity.effective_capabilities >> EDGE_LINUX_CAP_SYS_TIME) &
         1u) == 0)
        return -EDGE_LINUX_EPERM;

    if (context->id == EDGE_LINUX_SYS_clock_settime) {
        if ((int32_t)context->arguments[0] != LINUX_CLOCK_REALTIME)
            return -EDGE_LINUX_EINVAL;
        if (!context->arguments[1]) return -EDGE_LINUX_EFAULT;
        if (edge_linux_copy_from_user(context, &timespec,
                                      context->arguments[1],
                                      sizeof(timespec)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (timespec.tv_sec < 0 || timespec.tv_nsec < 0 ||
            timespec.tv_nsec >= 1000000000LL ||
            (uint64_t)timespec.tv_sec >
                (UINT64_MAX - (uint64_t)timespec.tv_nsec / 1000u) /
                    1000000u)
            return -EDGE_LINUX_EINVAL;
        realtime_us = (uint64_t)timespec.tv_sec * 1000000u +
            (uint64_t)timespec.tv_nsec / 1000u;
        return boottime_set_realtime_us(realtime_us) < 0 ?
            -EDGE_LINUX_EINVAL : 0;
    }

    if (context->id != EDGE_LINUX_SYS_settimeofday)
        return -EDGE_LINUX_ENOSYS;
    if (context->arguments[0]) {
        if (edge_linux_copy_from_user(context, &timeval,
                                      context->arguments[0],
                                      sizeof(timeval)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (timeval.tv_sec < 0 || timeval.tv_usec < 0 ||
            timeval.tv_usec >= 1000000LL ||
            (uint64_t)timeval.tv_sec >
                (UINT64_MAX - (uint64_t)timeval.tv_usec) / 1000000u)
            return -EDGE_LINUX_EINVAL;
        realtime_us = (uint64_t)timeval.tv_sec * 1000000u +
            (uint64_t)timeval.tv_usec;
        if (boottime_set_realtime_us(realtime_us) < 0)
            return -EDGE_LINUX_EINVAL;
    }
    if (context->arguments[1]) {
        if (edge_linux_copy_from_user(context, &timezone,
                                      context->arguments[1],
                                      sizeof(timezone)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (linux_set_timezone_value(&timezone) < 0)
            return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

static int64_t edge_linux_sys_vhangup(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;

    (void)context;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if ((identity.effective_capabilities &
         (1ull << EDGE_LINUX_CAP_SYS_TTY_CONFIG)) == 0)
        return -EDGE_LINUX_EPERM;
    return arch_tty_vhangup();
}

#define EDGE_LINUX_MODULE_PAGE_SIZE 4096u
#define EDGE_LINUX_MODULE_INIT_IGNORE_MODVERSIONS 0x00000001u
#define EDGE_LINUX_MODULE_INIT_IGNORE_VERMAGIC 0x00000002u
#define EDGE_LINUX_MODULE_INIT_COMPRESSED_FILE 0x00000004u

static void edge_linux_module_free_pages(
    void *memory, uint32_t page_count) {
    uint8_t *bytes = memory;

    if (!memory) return;
    for (uint32_t page = 0; page < page_count; ++page)
        arch_vm_free_page(
            bytes + (uint64_t)page * EDGE_LINUX_MODULE_PAGE_SIZE);
}

static int edge_linux_module_copy_image(
    edge_linux_syscall_context_t *context, uint64_t source,
    uint32_t image_size, void **image_out, uint32_t *pages_out) {
    uint8_t *image;
    uint32_t pages;

    if (!image_out || !pages_out) return -EDGE_LINUX_EIO;
    *image_out = 0;
    *pages_out = 0;
    if (!image_size) return -EDGE_LINUX_ENOEXEC;
    if (image_size > KERNEL_LINUX_MODULE_MAX_BYTES)
        return -EDGE_LINUX_EFBIG;
    pages = (image_size + EDGE_LINUX_MODULE_PAGE_SIZE - 1u) /
        EDGE_LINUX_MODULE_PAGE_SIZE;
    image = arch_vm_alloc_pages(pages);
    if (!image) return -EDGE_LINUX_ENOMEM;
    for (uint32_t offset = 0; offset < image_size;) {
        uint32_t chunk = image_size - offset;
        if (chunk > 65536u) chunk = 65536u;
        if (source > UINT64_MAX - offset ||
            edge_linux_copy_from_user(
                context, image + offset, source + offset, chunk) < 0) {
            edge_linux_module_free_pages(image, pages);
            return -EDGE_LINUX_EFAULT;
        }
        offset += chunk;
    }
    *image_out = image;
    *pages_out = pages;
    return 0;
}

static int edge_linux_module_read_fd(
    int32_t descriptor, void **image_out, uint32_t *image_size_out,
    uint32_t *pages_out) {
    kernel_file_metadata_t metadata;
    kernel_io_file_range_info_t information;
    uint8_t *image;
    uint32_t image_size;
    uint32_t pages;
    int64_t bytes;
    int result;

    if (!image_out || !image_size_out || !pages_out)
        return -EDGE_LINUX_EIO;
    *image_out = 0;
    *image_size_out = 0;
    *pages_out = 0;
    result = kernel_io_file_range_query(descriptor, &information);
    if (result < 0) return result;
    if (!information.readable) return -EDGE_LINUX_EBADF;
    if (information.kind != KERNEL_IO_FILE_REGULAR)
        return -EDGE_LINUX_EINVAL;
    result = kernel_vfs_metadata_fd(descriptor, &metadata);
    if (result < 0) return result;
    if (!metadata.size) return -EDGE_LINUX_ENOEXEC;
    if (metadata.size > KERNEL_LINUX_MODULE_MAX_BYTES)
        return -EDGE_LINUX_EFBIG;
    image_size = (uint32_t)metadata.size;
    pages = (image_size + EDGE_LINUX_MODULE_PAGE_SIZE - 1u) /
        EDGE_LINUX_MODULE_PAGE_SIZE;
    image = arch_vm_alloc_pages(pages);
    if (!image) return -EDGE_LINUX_ENOMEM;
    bytes = kernel_io_file_range_read(
        descriptor, 0, image, image_size);
    if (bytes < 0) {
        edge_linux_module_free_pages(image, pages);
        return (int)bytes;
    }
    if ((uint64_t)bytes != image_size) {
        edge_linux_module_free_pages(image, pages);
        return -EDGE_LINUX_EIO;
    }
    *image_out = image;
    *image_size_out = image_size;
    *pages_out = pages;
    return 0;
}

static int64_t edge_linux_sys_module(
    edge_linux_syscall_context_t *context) {
#ifndef CONFIG_MODULES
    (void)context;
    return -EDGE_LINUX_ENOSYS;
#else
    kernel_linux_identity_t identity;
    char module_name[64];
    char *parameters = 0;
    void *image = 0;
    uint32_t image_size = 0;
    uint32_t image_pages = 0;
    uint32_t flags;
    int32_t descriptor;
    int result;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if ((identity.effective_capabilities &
         (1ull << EDGE_LINUX_CAP_SYS_MODULE)) == 0)
        return -EDGE_LINUX_EPERM;
    if (context->id == EDGE_LINUX_SYS_delete_module) {
        result = edge_linux_copy_user_string(
            context, context->arguments[0], module_name,
            sizeof(module_name), EDGE_LINUX_ENOENT);
        if (result < 0) return result;
        if (!result) return -EDGE_LINUX_ENOENT;
        return kernel_linux_module_unload(
            module_name, (uint32_t)context->arguments[1]);
    }
    if (context->id == EDGE_LINUX_SYS_init_module) {
        if (context->arguments[1] > UINT32_MAX) {
            result = -EDGE_LINUX_EFBIG;
            goto complete;
        }
        image_size = (uint32_t)context->arguments[1];
        result = edge_linux_module_copy_image(
            context, context->arguments[0], image_size,
            &image, &image_pages);
        if (result < 0) goto complete;
        parameters = arch_vm_alloc_page();
        if (!parameters) {
            result = -EDGE_LINUX_ENOMEM;
            goto complete;
        }
        result = edge_linux_copy_user_string(
            context, context->arguments[2], parameters,
            KERNEL_LINUX_MODULE_PARAMETERS_MAX, EDGE_LINUX_E2BIG);
    } else if (context->id == EDGE_LINUX_SYS_finit_module) {
        flags = (uint32_t)context->arguments[2];
        if (flags & ~(EDGE_LINUX_MODULE_INIT_IGNORE_MODVERSIONS |
                      EDGE_LINUX_MODULE_INIT_IGNORE_VERMAGIC |
                      EDGE_LINUX_MODULE_INIT_COMPRESSED_FILE)) {
            result = -EDGE_LINUX_EINVAL;
            goto complete;
        }
        if (flags & EDGE_LINUX_MODULE_INIT_COMPRESSED_FILE) {
            result = -EDGE_LINUX_EOPNOTSUPP;
            goto complete;
        }
        if (edge_linux_fd_number(
                context->arguments[0], &descriptor) < 0) {
            result = -EDGE_LINUX_EBADF;
            goto complete;
        }
        result = edge_linux_module_read_fd(
            descriptor, &image, &image_size, &image_pages);
        if (result < 0) goto complete;
        parameters = arch_vm_alloc_page();
        if (!parameters) {
            result = -EDGE_LINUX_ENOMEM;
            goto complete;
        }
        result = edge_linux_copy_user_string(
            context, context->arguments[1], parameters,
            KERNEL_LINUX_MODULE_PARAMETERS_MAX, EDGE_LINUX_E2BIG);
    } else {
        result = -EDGE_LINUX_ENOSYS;
        goto complete;
    }
    if (result >= 0)
        result = kernel_linux_module_load(image, image_size, parameters);
complete:
    edge_linux_module_free_pages(image, image_pages);
    if (parameters) arch_vm_free_page(parameters);
    return result;
#endif
}

static int64_t edge_linux_sys_clock_adjust(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    edge_linux_timex_t timex;
    uint64_t timex_user;
    int32_t clock_id = LINUX_CLOCK_REALTIME;
    int privileged;
    int result;

    if (context->id == EDGE_LINUX_SYS_clock_adjtime) {
        clock_id = (int32_t)context->arguments[0];
        timex_user = context->arguments[1];
    } else {
        timex_user = context->arguments[0];
    }
    if (!timex_user) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(
            context, &timex, timex_user, sizeof(timex)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    privileged = (identity.effective_capabilities &
                  (1ull << EDGE_LINUX_CAP_SYS_TIME)) != 0;
    result = kernel_time_discipline_adjust(
        clock_id, &timex, privileged);
    if (result < 0 && context->id == EDGE_LINUX_SYS_clock_adjtime)
        return result;
    if (edge_linux_copy_to_user(
            context, timex_user, &timex, sizeof(timex)) < 0)
        return -EDGE_LINUX_EFAULT;
    return result;
}

static int64_t edge_linux_sys_uname(edge_linux_syscall_context_t *context) {
    linux_utsname_t uts;
    const edge_linux_syscall_arch_ops_t *ops = context->arch_ops;
    if (!context->arguments[0]) return -EDGE_LINUX_EFAULT;
    if (!ops || !ops->machine || !ops->release || !ops->version)
        return -EDGE_LINUX_EINVAL;
    linux_utsname_fill(&uts, kernel_current_hostname(), ops->release,
                       ops->version, ops->machine);
    strncpy(uts.domainname, kernel_current_domainname(),
            sizeof(uts.domainname) - 1u);
    uts.domainname[sizeof(uts.domainname) - 1u] = 0;
    return edge_linux_copy_to_user(context, context->arguments[0], &uts,
                                   sizeof(uts)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_linux_sys_getrandom(
    edge_linux_syscall_context_t *context) {
    uint64_t destination = context->arguments[0];
    uint64_t length = context->arguments[1];
    uint64_t flags = context->arguments[2];
    uint64_t done = 0;
    if (flags & ~7u) return -EDGE_LINUX_EINVAL;
    if (!destination && length) return -EDGE_LINUX_EFAULT;
    while (done < length) {
        uint8_t bytes[256];
        uint64_t count = length - done;
        if (count > sizeof(bytes)) count = sizeof(bytes);
        edge_random_fill(bytes, (uint32_t)count);
        if (edge_linux_copy_to_user(context, destination + done, bytes,
                                    count) < 0)
            return done ? (int64_t)done : -EDGE_LINUX_EFAULT;
        done += count;
    }
    return (int64_t)done;
}

static int64_t edge_linux_sys_getcpu(edge_linux_syscall_context_t *context) {
    uint32_t zero = 0;
    if (context->arguments[0] &&
        edge_linux_copy_to_user(context, context->arguments[0], &zero,
                                sizeof(zero)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (context->arguments[1] &&
        edge_linux_copy_to_user(context, context->arguments[1], &zero,
                                sizeof(zero)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_get_mempolicy(
    edge_linux_syscall_context_t *context) {
    const uint32_t mpol_f_node = 1u;
    const uint32_t mpol_f_addr = 2u;
    const uint32_t mpol_f_mems_allowed = 4u;
    const uint32_t allowed_flags =
        mpol_f_node | mpol_f_addr | mpol_f_mems_allowed;
    uint64_t mode_user = context->arguments[0];
    uint64_t nodemask_user = context->arguments[1];
    uint64_t maxnode = context->arguments[2];
    uint64_t address = context->arguments[3];
    uint32_t flags = (uint32_t)context->arguments[4];
    int32_t mode = 0; /* MPOL_DEFAULT */
    uint32_t mode_flags = 0;
    uint64_t policy_nodes = 0;
    uint64_t rounded_bits;
    uint64_t bytes;
    uint64_t offset;

    if (flags & ~allowed_flags) return -EDGE_LINUX_EINVAL;
    if ((flags & mpol_f_mems_allowed) &&
        (flags & (mpol_f_node | mpol_f_addr)))
        return -EDGE_LINUX_EINVAL;
    if ((flags & mpol_f_addr) && !address)
        return -EDGE_LINUX_EFAULT;
    if (!(flags & mpol_f_addr) && address)
        return -EDGE_LINUX_EINVAL;
    if ((flags & mpol_f_node) && !(flags & mpol_f_addr))
        return -EDGE_LINUX_EINVAL;

    if (flags & mpol_f_addr) {
        uint8_t resident;
        uint64_t page = address & ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
        if (kernel_mm_query_residency(page, 1u, &resident) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    if (!(flags & (mpol_f_node | mpol_f_mems_allowed)) &&
        kernel_mm_mempolicy_get(
            arch_mm_current_address_space(), &mode, &mode_flags,
            &policy_nodes) < 0)
        return -EDGE_LINUX_EINVAL;
    mode |= (int32_t)mode_flags;

    if (mode_user && edge_linux_copy_to_user(
            context, mode_user, &mode, sizeof(mode)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!nodemask_user) return 0;
    if (!maxnode) return -EDGE_LINUX_EINVAL;

    /* Linux rounds maxnode to the native unsigned-long width. */
    if (maxnode > UINT64_MAX - 63u) return -EDGE_LINUX_EINVAL;
    rounded_bits = (maxnode + 63u) & ~63ULL;
    bytes = rounded_bits / 8u;
    for (offset = 0; offset < bytes; offset += sizeof(uint64_t)) {
        uint64_t word = 0;
        uint64_t count = bytes - offset;
        if (offset == 0) {
            if (flags & mpol_f_mems_allowed)
                word = 1u; /* The generic platform exposes NUMA node 0. */
            else if (!(flags & mpol_f_node))
                word = policy_nodes;
        }
        if (count > sizeof(word)) count = sizeof(word);
        if (edge_linux_copy_to_user(
                context, nodemask_user + offset, &word, count) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

#define EDGE_LINUX_MPOL_MODE_MASK          0x000000ffu
#define EDGE_LINUX_MPOL_F_STATIC_NODES     0x00008000u
#define EDGE_LINUX_MPOL_F_RELATIVE_NODES   0x00004000u
#define EDGE_LINUX_MPOL_MF_MOVE            0x00000001u
#define EDGE_LINUX_MPOL_MF_MOVE_ALL        0x00000002u

static int edge_linux_mempolicy_mask_validate(
        edge_linux_syscall_context_t *context, uint64_t mask_user,
        uint64_t maxnode, int require_node, int permit_empty) {
    uint64_t rounded_bits;
    uint64_t bytes;
    int node_zero = 0;

    if (!mask_user)
        return permit_empty ? 0 : -EDGE_LINUX_EINVAL;
    if (!maxnode || maxnode > 1024u)
        return -EDGE_LINUX_EINVAL;
    rounded_bits = (maxnode + 63u) & ~63ULL;
    bytes = rounded_bits / 8u;
    for (uint64_t offset = 0; offset < bytes;
         offset += sizeof(uint64_t)) {
        uint64_t word = 0;
        uint64_t count = bytes - offset;
        if (count > sizeof(word)) count = sizeof(word);
        if (edge_linux_copy_from_user(
                context, &word, mask_user + offset, count) < 0)
            return -EDGE_LINUX_EFAULT;
        if (!offset) {
            node_zero = (word & 1u) != 0;
            word &= ~1ULL;
        }
        if (word) return -EDGE_LINUX_EINVAL;
    }
    if (require_node && !node_zero) return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_linux_mempolicy_mode_validate(
        edge_linux_syscall_context_t *context, uint64_t raw_mode,
        uint64_t mask_user, uint64_t maxnode, int32_t *mode_out,
        uint32_t *flags_out) {
    const uint32_t allowed_flags =
        EDGE_LINUX_MPOL_F_STATIC_NODES |
        EDGE_LINUX_MPOL_F_RELATIVE_NODES;
    uint32_t raw = (uint32_t)raw_mode;
    int32_t mode;
    uint32_t flags;
    int status;

    if (raw_mode != raw) return -EDGE_LINUX_EINVAL;
    mode = (int32_t)(raw & EDGE_LINUX_MPOL_MODE_MASK);
    flags = raw & ~EDGE_LINUX_MPOL_MODE_MASK;
    if ((flags & ~allowed_flags) ||
        (flags == allowed_flags) || mode < 0 || mode > 6)
        return -EDGE_LINUX_EINVAL;
    if (mode == 0) {
        status = edge_linux_mempolicy_mask_validate(
            context, mask_user, maxnode, 0, 1);
        if (status < 0 && mask_user) return status;
        if (mask_user) {
            uint64_t word = 0;
            if (edge_linux_copy_from_user(
                    context, &word, mask_user, sizeof(word)) < 0)
                return -EDGE_LINUX_EFAULT;
            if (word) return -EDGE_LINUX_EINVAL;
        }
    } else {
        int require_node = mode != 1 && mode != 4;
        status = edge_linux_mempolicy_mask_validate(
            context, mask_user, maxnode, require_node,
            mode == 1 || mode == 4);
        if (status < 0) return status;
    }
    *mode_out = mode;
    *flags_out = flags;
    return 0;
}

static int64_t edge_linux_sys_numa_policy(
        edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    int32_t mode;
    uint32_t mode_flags;
    int status;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    switch (context->id) {
    case EDGE_LINUX_SYS_set_mempolicy:
        status = edge_linux_mempolicy_mode_validate(
            context, context->arguments[0], context->arguments[1],
            context->arguments[2], &mode, &mode_flags);
        if (status < 0) return status;
        {
            uint64_t nodes = 0;
            if (context->arguments[1] && edge_linux_copy_from_user(
                    context, &nodes, context->arguments[1],
                    sizeof(nodes)) < 0)
                return -EDGE_LINUX_EFAULT;
            return kernel_mm_mempolicy_set(
                arch_mm_current_address_space(), mode, mode_flags,
                nodes & 1u);
        }
    case EDGE_LINUX_SYS_mbind: {
        uint64_t address = context->arguments[0];
        uint64_t length = context->arguments[1];
        uint32_t move_flags = (uint32_t)context->arguments[5];
        uint8_t resident;

        if ((address & (KERNEL_MM_USER_PAGE_SIZE - 1u)) ||
            context->arguments[5] != move_flags ||
            (move_flags & ~(EDGE_LINUX_MPOL_MF_MOVE |
                            EDGE_LINUX_MPOL_MF_MOVE_ALL)))
            return -EDGE_LINUX_EINVAL;
        if (!length) return 0;
        if (length > UINT64_MAX - address)
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_mempolicy_mode_validate(
            context, context->arguments[2], context->arguments[3],
            context->arguments[4], &mode, &mode_flags);
        if (status < 0) return status;
        if (kernel_mm_query_residency(address, 1u, &resident) < 0)
            return -EDGE_LINUX_EFAULT;
        return 0;
    }
    case EDGE_LINUX_SYS_migrate_pages: {
        int32_t pid = (int32_t)context->arguments[0];
        if (context->arguments[0] != (uint64_t)(int64_t)pid ||
            (pid != 0 && pid != identity.global_tgid))
            return -EDGE_LINUX_ESRCH;
        status = edge_linux_mempolicy_mask_validate(
            context, context->arguments[2], context->arguments[1],
            0, 0);
        if (status < 0) return status;
        status = edge_linux_mempolicy_mask_validate(
            context, context->arguments[3], context->arguments[1],
            1, 0);
        return status < 0 ? status : 0;
    }
    case EDGE_LINUX_SYS_move_pages: {
        int32_t pid = (int32_t)context->arguments[0];
        uint64_t count = context->arguments[1];
        uint64_t pages_user = context->arguments[2];
        uint64_t nodes_user = context->arguments[3];
        uint64_t status_user = context->arguments[4];
        uint32_t flags = (uint32_t)context->arguments[5];

        if (context->arguments[0] != (uint64_t)(int64_t)pid ||
            (pid != 0 && pid != identity.global_tgid))
            return -EDGE_LINUX_ESRCH;
        if (context->arguments[5] != flags ||
            (flags & ~(EDGE_LINUX_MPOL_MF_MOVE |
                       EDGE_LINUX_MPOL_MF_MOVE_ALL)))
            return -EDGE_LINUX_EINVAL;
        if (count > 1048576u) return -EDGE_LINUX_E2BIG;
        if (count && (!pages_user || !status_user))
            return -EDGE_LINUX_EFAULT;
        for (uint64_t index = 0; index < count; ++index) {
            uint64_t page;
            int32_t node = 0;
            uint8_t resident;
            int32_t page_status = 0;

            if (edge_linux_copy_from_user(
                    context, &page,
                    pages_user + index * sizeof(page), sizeof(page)) < 0)
                return -EDGE_LINUX_EFAULT;
            if (nodes_user && edge_linux_copy_from_user(
                    context, &node,
                    nodes_user + index * sizeof(node), sizeof(node)) < 0)
                return -EDGE_LINUX_EFAULT;
            if (nodes_user && node != 0) page_status = -EDGE_LINUX_ENODEV;
            else if (kernel_mm_query_residency(
                         page & ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u),
                         1u, &resident) < 0)
                page_status = -EDGE_LINUX_EFAULT;
            if (edge_linux_copy_to_user(
                    context, status_user + index * sizeof(page_status),
                    &page_status, sizeof(page_status)) < 0)
                return -EDGE_LINUX_EFAULT;
        }
        return 0;
    }
    case EDGE_LINUX_SYS_set_mempolicy_home_node: {
        uint64_t address = context->arguments[0];
        uint64_t length = context->arguments[1];
        uint64_t node = context->arguments[2];
        uint64_t flags = context->arguments[3];
        uint8_t resident;

        if ((address & (KERNEL_MM_USER_PAGE_SIZE - 1u)) ||
            !length || length > UINT64_MAX - address || node != 0u || flags)
            return -EDGE_LINUX_EINVAL;
        return kernel_mm_query_residency(address, 1u, &resident) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
    default:
        return -EDGE_LINUX_ENOSYS;
    }
}

static int64_t edge_linux_sys_sysinfo(
    edge_linux_syscall_context_t *context) {
    kernel_system_information_t snapshot;
    struct edge_linux_sysinfo64 result;
    if (!context->arguments[0]) return -EDGE_LINUX_EFAULT;
    if (kernel_system_information_snapshot(&snapshot) < 0)
        return -EDGE_LINUX_ESRCH;
    memset(&result, 0, sizeof(result));
    result.uptime = (int64_t)snapshot.uptime_seconds;
    for (uint32_t index = 0; index < 3u; ++index)
        result.loads[index] = snapshot.loads[index];
    result.totalram = snapshot.total_ram_bytes;
    result.freeram = snapshot.free_ram_bytes;
    result.sharedram = snapshot.shared_ram_bytes;
    result.bufferram = snapshot.buffer_ram_bytes;
    result.totalswap = snapshot.total_swap_bytes;
    result.freeswap = snapshot.free_swap_bytes;
    result.procs = snapshot.process_count > UINT16_MAX ?
        UINT16_MAX : (uint16_t)snapshot.process_count;
    result.mem_unit = 1u;
    return edge_linux_copy_to_user(context, context->arguments[0], &result,
                                   sizeof(result)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_linux_sys_personality(
    edge_linux_syscall_context_t *context) {
    uint32_t previous;
    uint32_t requested = (uint32_t)context->arguments[0];
    if (kernel_current_personality_get(&previous) < 0)
        return -EDGE_LINUX_ESRCH;
    if (requested != UINT32_MAX &&
        kernel_current_personality_set(requested) < 0)
        return -EDGE_LINUX_ESRCH;
    return previous;
}

static int64_t edge_linux_sys_set_tid_address(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    if (kernel_current_linux_identity(&identity) < 0 ||
        kernel_current_clear_child_tid_set(context->arguments[0]) < 0)
        return -EDGE_LINUX_ESRCH;
    return identity.tid;
}

static int64_t edge_linux_sys_robust_list(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    uint64_t head;
    uint64_t length;
    int32_t pid;

    if (context->id == EDGE_LINUX_SYS_set_robust_list) {
        if (context->arguments[1] != EDGE_LINUX_ROBUST_LIST_HEAD_SIZE)
            return -EDGE_LINUX_EINVAL;
        return kernel_current_robust_list_set(
            context->arguments[0], context->arguments[1]) < 0 ?
            -EDGE_LINUX_ESRCH : 0;
    }
    if (context->id != EDGE_LINUX_SYS_get_robust_list)
        return -EDGE_LINUX_ENOSYS;
    if (!context->arguments[1] || !context->arguments[2])
        return -EDGE_LINUX_EFAULT;
    pid = (int32_t)context->arguments[0];
    if (pid &&
        (kernel_current_linux_identity(&caller) < 0 ||
         kernel_process_linux_identity(pid, &target) < 0))
        return -EDGE_LINUX_ESRCH;
    if (pid &&
        ((caller.uid != target.uid || caller.uid != target.euid ||
          caller.uid != target.suid || caller.gid != target.gid ||
          caller.gid != target.egid || caller.gid != target.sgid) &&
         !(caller.effective_capabilities &
           (1ULL << EDGE_LINUX_CAP_SYS_PTRACE))))
        return -EDGE_LINUX_EPERM;
    if (kernel_process_robust_list_get(pid, &head, &length) < 0)
        return -EDGE_LINUX_ESRCH;
    if (edge_linux_copy_to_user(context, context->arguments[1], &head,
                                sizeof(head)) < 0 ||
        edge_linux_copy_to_user(context, context->arguments[2], &length,
                                sizeof(length)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_rseq(
    edge_linux_syscall_context_t *context) {
    return kernel_current_rseq_register(
        context->arguments[0], context->arguments[1],
        context->arguments[2], context->arguments[3]);
}

static int64_t edge_linux_sys_membarrier(
    edge_linux_syscall_context_t *context) {
    uint32_t command = (uint32_t)context->arguments[0];
    uint32_t flags = (uint32_t)context->arguments[1];
    uint32_t supported = kernel_membarrier_supported_commands();
    uint32_t registrations;
    uint32_t required_registration = 0;

    if (flags & ~EDGE_LINUX_MEMBARRIER_CMD_FLAG_CPU)
        return -EDGE_LINUX_EINVAL;
    if (flags != 0u) {
        /* CPU targeting is defined only for expedited-rseq, not yet exposed. */
        return -EDGE_LINUX_EINVAL;
    }
    if (command == EDGE_LINUX_MEMBARRIER_CMD_QUERY)
        return supported;
    if ((command & (command - 1u)) != 0u || !(supported & command))
        return -EDGE_LINUX_EINVAL;
    if (command == EDGE_LINUX_MEMBARRIER_CMD_GET_REGISTRATIONS) {
        if (kernel_current_membarrier_registrations(&registrations) < 0)
            return -EDGE_LINUX_ESRCH;
        return registrations;
    }
    if (command == EDGE_LINUX_MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED ||
        command == EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED ||
        command ==
            EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) {
        return kernel_current_membarrier_register(command) < 0 ?
            -EDGE_LINUX_ESRCH : 0;
    }
    if (command == EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED)
        required_registration =
            EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
    else if (command ==
             EDGE_LINUX_MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)
        required_registration =
            EDGE_LINUX_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;
    else if (command != EDGE_LINUX_MEMBARRIER_CMD_GLOBAL &&
             command != EDGE_LINUX_MEMBARRIER_CMD_GLOBAL_EXPEDITED)
        return -EDGE_LINUX_EINVAL;
    if (required_registration) {
        if (kernel_current_membarrier_registrations(&registrations) < 0)
            return -EDGE_LINUX_ESRCH;
        if (!(registrations & required_registration))
            return -EDGE_LINUX_EPERM;
    }
    return kernel_membarrier_execute(command) == 0 ? 0 :
        -EDGE_LINUX_EAGAIN;
}

static int edge_linux_signal_permitted(
    const kernel_linux_identity_t *caller,
    const kernel_linux_identity_t *target, uint32_t signal) {
    if (!caller || !target) return 0;
    if (caller->effective_capabilities & (1ULL << EDGE_LINUX_CAP_KILL))
        return 1;
    if (signal == EDGE_LINUX_SIGCONT && caller->sid == target->sid)
        return 1;
    return caller->uid == target->uid || caller->uid == target->suid ||
           caller->euid == target->uid || caller->euid == target->suid;
}

static int64_t edge_linux_signal_send_one(
    const kernel_linux_identity_t *caller,
    const kernel_linux_identity_t *target, uint32_t signal,
    int thread_directed, int32_t code) {
    uint8_t information[KERNEL_SIGNAL_INFO_SIZE];
    int result;
    if (!edge_linux_signal_permitted(caller, target, signal))
        return -EDGE_LINUX_EPERM;
    if (!signal) return 0;
    kernel_signal_info_build_sender(
        information, signal, code, caller->tgid, caller->uid, 0u);
    result = kernel_linux_signal_send(
        target->global_tid, signal, thread_directed, information);
    return result < 0 ? result : 0;
}

static int64_t edge_linux_signal_send_group(
    const kernel_linux_identity_t *caller, int32_t pgid, uint32_t signal,
    int all_processes, const void *signal_information) {
    kernel_process_control_t control;
    kernel_linux_identity_t target;
    uint32_t cursor = 0;
    int found = 0;
    int permitted = 0;
    int delivered = 0;
    int64_t first_error = 0;

    while (kernel_process_control_next(&cursor, &control) == 0) {
        kernel_process_control_t representative;
        kernel_linux_identity_t representative_identity;
        uint32_t representative_cursor = 0;
        int have_representative = 0;
        int64_t result;
        /*
         * A Linux thread-group leader may exit while sibling threads remain
         * alive.  Signals still address that process and its process group in
         * this state.  Select the first live member as the delivery
         * representative instead of requiring tid == tgid; otherwise kill(2)
         * incorrectly reports ESRCH and leaves browser worker threads behind.
         */
        while (kernel_process_control_next(
                   &representative_cursor, &representative) == 0) {
            if (representative.tgid != control.tgid) continue;
            if (kernel_process_linux_identity(
                    representative.tid,
                    &representative_identity) < 0)
                continue;
            have_representative = 1;
            break;
        }
        if (!have_representative ||
            representative.tid != control.tid)
            continue;
        target = representative_identity;
        if (all_processes) {
            /* Linux kill(-1, ...) excludes the calling process. */
            if (target.tgid == 1 ||
                control.tgid == caller->global_tgid)
                continue;
        } else if (control.pgid != pgid) {
            continue;
        }
        found = 1;
        if (!edge_linux_signal_permitted(caller, &target, signal))
            continue;
        permitted = 1;
        if (!signal) result = 0;
        else if (signal_information)
            result = kernel_linux_signal_send(
                target.global_tid, signal, 0, signal_information);
        else
            result = edge_linux_signal_send_one(
                caller, &target, signal, 0, EDGE_LINUX_SI_USER);
        if (result == 0) delivered = 1;
        else if (!first_error) first_error = result;
    }
    if (delivered || (!signal && permitted)) return 0;
    if (permitted && first_error) return first_error;
    return found ? -EDGE_LINUX_EPERM : -EDGE_LINUX_ESRCH;
}

static int64_t edge_linux_sys_signal_target(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    int32_t pid;
    int32_t tid;
    int32_t tgid = 0;
    int32_t global_pid;
    int32_t global_tid;
    int32_t global_tgid = 0;
    uint32_t signal;

    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (context->id == EDGE_LINUX_SYS_kill) {
        kernel_proc_task_view_t requested_view;
        pid = (int32_t)context->arguments[0];
        signal = (uint32_t)context->arguments[1];
        if (signal > EDGE_LINUX_SIGNAL_MAX)
            return -EDGE_LINUX_EINVAL;
        if (pid == 0)
            return edge_linux_signal_send_group(
                &caller, caller.global_pgid, signal, 0, 0);
        if (pid == INT32_MIN)
            return -EDGE_LINUX_ESRCH;
        if (pid < -1) {
            if (edge_linux_pid_to_global(&caller, -pid, &global_pid) < 0)
                return -EDGE_LINUX_ESRCH;
            return edge_linux_signal_send_group(
                &caller, global_pid, signal, 0, 0);
        }
        if (pid == -1)
            return edge_linux_signal_send_group(
                &caller, 0, signal, 1, 0);
        if (edge_linux_pid_to_global(&caller, pid, &global_pid) < 0)
            return -EDGE_LINUX_ESRCH;
        if (kernel_process_linux_identity(global_pid, &target) < 0) {
            kernel_process_control_t candidate;
            uint32_t cursor = 0;
            int found_live_member = 0;

            if (kernel_proc_task_view_get(
                    global_pid, &requested_view) < 0 ||
                requested_view.state != KERNEL_PROC_TASK_ZOMBIE)
                return -EDGE_LINUX_ESRCH;
            while (kernel_process_control_next(&cursor, &candidate) == 0) {
                if (candidate.tgid != global_pid) continue;
                if (kernel_process_linux_identity(
                        candidate.tid, &target) < 0)
                    continue;
                found_live_member = 1;
                break;
            }
            /* An unreaped process with no live threads still exists. */
            if (!found_live_member) return 0;
        }
        return edge_linux_signal_send_one(
            &caller, &target, signal, 0, EDGE_LINUX_SI_USER);
    }
    if (context->id == EDGE_LINUX_SYS_tkill) {
        tid = (int32_t)context->arguments[0];
        signal = (uint32_t)context->arguments[1];
        if (tid <= 0 || signal > EDGE_LINUX_SIGNAL_MAX)
            return -EDGE_LINUX_EINVAL;
    } else if (context->id == EDGE_LINUX_SYS_tgkill) {
        tgid = (int32_t)context->arguments[0];
        tid = (int32_t)context->arguments[1];
        signal = (uint32_t)context->arguments[2];
        if (tgid <= 0 || tid <= 0 || signal > EDGE_LINUX_SIGNAL_MAX)
            return -EDGE_LINUX_EINVAL;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (edge_linux_pid_to_global(&caller, tid, &global_tid) < 0)
        return -EDGE_LINUX_ESRCH;
    if (context->id == EDGE_LINUX_SYS_tgkill &&
        edge_linux_pid_to_global(&caller, tgid, &global_tgid) < 0)
        return -EDGE_LINUX_ESRCH;
    if (kernel_process_linux_identity(global_tid, &target) < 0)
        return -EDGE_LINUX_ESRCH;
    if (context->id == EDGE_LINUX_SYS_tgkill &&
        target.global_tgid != global_tgid)
        return -EDGE_LINUX_ESRCH;
    return edge_linux_signal_send_one(
        &caller, &target, signal, 1, EDGE_LINUX_SI_TKILL);
}

static int64_t edge_linux_sys_pidfd_open(
    edge_linux_syscall_context_t *context) {
    int32_t pid = (int32_t)context->arguments[0];
    uint32_t flags = (uint32_t)context->arguments[1];
    uint32_t allowed = EDGE_LINUX_PIDFD_NONBLOCK |
                       EDGE_LINUX_PIDFD_THREAD;

    if (flags & ~allowed || pid <= 0) return -EDGE_LINUX_EINVAL;
    /* The runtime lookup includes unreaped zombies, as Linux pidfds do. */
    return kernel_pidfd_open(pid, flags);
}

typedef enum edge_linux_ptrace_credential_mode {
    EDGE_LINUX_PTRACE_REALCREDS = 0,
    EDGE_LINUX_PTRACE_FSCREDS = 1,
} edge_linux_ptrace_credential_mode_t;

static int edge_linux_ptrace_access_allowed(
    const kernel_linux_identity_t *caller,
    const kernel_linux_identity_t *target,
    edge_linux_ptrace_credential_mode_t mode) {
    uint64_t ptrace_capability = 1ULL << EDGE_LINUX_CAP_SYS_PTRACE;
    uint64_t caller_capabilities;
    uint32_t caller_uid;
    uint32_t caller_gid;
    int capable;
    int credentials_match;

    if (!caller || !target) return 0;
    if (caller->tgid == target->tgid) return 1;
    if (mode == EDGE_LINUX_PTRACE_FSCREDS) {
        caller_uid = caller->fsuid;
        caller_gid = caller->fsgid;
        caller_capabilities = caller->effective_capabilities;
    } else {
        caller_uid = caller->uid;
        caller_gid = caller->gid;
        caller_capabilities = caller->permitted_capabilities;
    }
    capable = (caller_capabilities & ptrace_capability) != 0;
    credentials_match =
        caller_uid == target->uid &&
        caller_uid == target->euid &&
        caller_uid == target->suid &&
        caller_gid == target->gid &&
        caller_gid == target->egid &&
        caller_gid == target->sgid;
    if (!capable && !credentials_match) return 0;
    if (!capable && target->dumpable != 1u) return 0;
    if (!capable &&
        (target->permitted_capabilities &
         ~caller_capabilities) != 0)
        return 0;
    return 1;
}

static int64_t edge_linux_sys_pidfd_getfd(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    int32_t target_pid;
    int32_t result;
    uint32_t pidfd_flags;
    int status;

    if (context->arguments[2]) return -EDGE_LINUX_EINVAL;
    if (context->arguments[0] > INT32_MAX ||
        context->arguments[1] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    status = kernel_pidfd_target(
        (int32_t)context->arguments[0], &target_pid, &pidfd_flags);
    if (status < 0) return status;
    (void)pidfd_flags;
    if (kernel_current_linux_identity(&caller) < 0 ||
        kernel_process_linux_identity(target_pid, &target) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!edge_linux_ptrace_access_allowed(
            &caller, &target, EDGE_LINUX_PTRACE_REALCREDS))
        return -EDGE_LINUX_EPERM;
    status = kernel_pidfd_getfd(
        target_pid, (int32_t)context->arguments[1], &result);
    return status < 0 ? status : result;
}

#define EDGE_LINUX_KCMP_FILE       0u
#define EDGE_LINUX_KCMP_VM         1u
#define EDGE_LINUX_KCMP_FILES      2u
#define EDGE_LINUX_KCMP_FS         3u
#define EDGE_LINUX_KCMP_SIGHAND    4u
#define EDGE_LINUX_KCMP_IO         5u
#define EDGE_LINUX_KCMP_SYSVSEM    6u

static int64_t edge_linux_kcmp_order(uint64_t left, uint64_t right) {
    if (left == right) return 0;
    return left < right ? 1 : 2;
}

static int64_t edge_linux_sys_kcmp(edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_linux_identity_t first_identity;
    kernel_linux_identity_t second_identity;
    uint64_t first_resource;
    uint64_t second_resource;
    int32_t first_pid;
    int32_t second_pid;
    uint32_t type;
    int status;

    if (context->arguments[0] > INT32_MAX ||
        context->arguments[1] > INT32_MAX)
        return -EDGE_LINUX_ESRCH;
    first_pid = (int32_t)context->arguments[0];
    second_pid = (int32_t)context->arguments[1];
    type = (uint32_t)context->arguments[2];
    if (first_pid <= 0 || second_pid <= 0)
        return -EDGE_LINUX_ESRCH;
    if (type > EDGE_LINUX_KCMP_SYSVSEM)
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&caller) < 0 ||
        kernel_process_linux_identity(first_pid, &first_identity) < 0 ||
        kernel_process_linux_identity(second_pid, &second_identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!edge_linux_ptrace_access_allowed(
            &caller, &first_identity, EDGE_LINUX_PTRACE_REALCREDS) ||
        !edge_linux_ptrace_access_allowed(
            &caller, &second_identity, EDGE_LINUX_PTRACE_REALCREDS))
        return -EDGE_LINUX_EPERM;

    if (type == EDGE_LINUX_KCMP_FILE) {
        if (context->arguments[3] > INT32_MAX ||
            context->arguments[4] > INT32_MAX)
            return -EDGE_LINUX_EBADF;
        status = kernel_process_fd_description_id(
            first_pid, (int32_t)context->arguments[3], &first_resource);
        if (status < 0) return status;
        status = kernel_process_fd_description_id(
            second_pid, (int32_t)context->arguments[4], &second_resource);
        if (status < 0) return status;
        return edge_linux_kcmp_order(first_resource, second_resource);
    }

    if (kernel_process_resource_id(first_pid, type, &first_resource) < 0 ||
        kernel_process_resource_id(second_pid, type, &second_resource) < 0)
        return -EDGE_LINUX_ESRCH;
    return edge_linux_kcmp_order(first_resource, second_resource);
}

#define EDGE_LINUX_IOV_MAX       1024u
#define EDGE_LINUX_MAX_RW_COUNT  0x7ffff000ULL

static int64_t edge_linux_sys_process_madvise(
    edge_linux_syscall_context_t *context) {
    kernel_io_vector_scratch_t scratch;
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    uint64_t vector_address = context->arguments[1];
    uint64_t vector_count = context->arguments[2];
    uint64_t total = 0;
    uint64_t completed = 0;
    uint32_t advice;
    uint32_t pidfd_flags;
    int32_t target_pid;
    int status;

    if (context->arguments[4]) return -EDGE_LINUX_EINVAL;
    if (context->arguments[3] > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    advice = (uint32_t)context->arguments[3];
    if (vector_count > EDGE_LINUX_IOV_MAX)
        return -EDGE_LINUX_EINVAL;
    status = kernel_pidfd_target(
        (int32_t)context->arguments[0], &target_pid, &pidfd_flags);
    if (status < 0) return status;
    (void)pidfd_flags;
    if (kernel_current_linux_identity(&caller) < 0 ||
        kernel_process_linux_identity(target_pid, &target) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!kernel_mm_madvise_known(advice))
        return -EDGE_LINUX_EINVAL;

    if (caller.tgid != target.tgid) {
        if (!edge_linux_ptrace_access_allowed(
                &caller, &target, EDGE_LINUX_PTRACE_FSCREDS))
            return -EDGE_LINUX_EACCES;
        if (!(caller.effective_capabilities &
              (1ULL << EDGE_LINUX_CAP_SYS_NICE)))
            return -EDGE_LINUX_EPERM;
        if (!kernel_mm_madvise_cross_process_allowed(advice))
            return -EDGE_LINUX_EINVAL;
    }

    if (!vector_count) return 0;
    if (!vector_address) return -EDGE_LINUX_EFAULT;
    if (kernel_io_current_vector_scratch(&scratch) < 0 ||
        !scratch.vectors || scratch.capacity < vector_count)
        return -EDGE_LINUX_ENOMEM;
    if (vector_count > UINT64_MAX / sizeof(scratch.vectors[0]) ||
        edge_linux_copy_from_user(
            context, scratch.vectors, vector_address,
            vector_count * sizeof(scratch.vectors[0])) < 0)
        return -EDGE_LINUX_EFAULT;

    /* Linux imports and validates the complete vector before changing memory. */
    for (uint64_t index = 0; index < vector_count; ++index) {
        uint64_t length = scratch.vectors[index].iov_len;
        if (length > (uint64_t)INT64_MAX - total)
            return -EDGE_LINUX_EINVAL;
        total += length;
    }
    for (uint64_t index = 0; index < vector_count; ++index) {
        if (!scratch.vectors[index].iov_len) continue;
        status = kernel_process_madvise(
            target_pid, scratch.vectors[index].iov_base,
            scratch.vectors[index].iov_len, advice,
            KERNEL_PROCESS_MADVISE_VALIDATE_ONLY);
        if (status < 0) return status;
    }
    for (uint64_t index = 0; index < vector_count; ++index) {
        uint64_t length = scratch.vectors[index].iov_len;
        if (!length) continue;
        status = kernel_process_madvise(
            target_pid, scratch.vectors[index].iov_base,
            length, advice, 0);
        if (status < 0) return completed ? (int64_t)completed : status;
        completed += length;
    }
    return (int64_t)completed;
}

static int64_t edge_linux_sys_process_mrelease(
    edge_linux_syscall_context_t *context) {
    int32_t target_pid;
    uint32_t pidfd_flags;
    int status;

    if (context->arguments[1]) return -EDGE_LINUX_EINVAL;
    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    status = kernel_pidfd_target(
        (int32_t)context->arguments[0], &target_pid, &pidfd_flags);
    if (status < 0) return status;
    (void)pidfd_flags;
    return kernel_process_mrelease(target_pid);
}

static int64_t edge_linux_sys_madvise(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    uint64_t address = context->arguments[0];
    uint64_t length = context->arguments[1];
    uint32_t advice = (uint32_t)context->arguments[2];
    if (!kernel_mm_madvise_known(advice))
        return -EDGE_LINUX_EINVAL;
    if (address & (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (length > UINT64_MAX - address -
                 (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    return kernel_process_madvise(
        identity.global_tid, address, length, advice, 0);
}

#define EDGE_LINUX_MLOCK_ONFAULT 1u
#define EDGE_LINUX_MCL_CURRENT   1u
#define EDGE_LINUX_MCL_FUTURE    2u
#define EDGE_LINUX_MCL_ONFAULT   4u

static int edge_linux_mlock_range(
    edge_linux_syscall_context_t *context, int unlock) {
    uint64_t address = context->arguments[0];
    uint64_t length = context->arguments[1];
    uint64_t offset = address & (KERNEL_MM_USER_PAGE_SIZE - 1u);
    uint64_t rounded_length;
    uint32_t flags = 0;

    if (context->id == EDGE_LINUX_SYS_mlock2) {
        flags = (uint32_t)context->arguments[2];
        if (context->arguments[2] != flags ||
            (flags & ~EDGE_LINUX_MLOCK_ONFAULT))
            return -EDGE_LINUX_EINVAL;
    }
    if (length > UINT64_MAX - offset -
                 (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_ENOMEM;
    rounded_length = (length + offset +
                      KERNEL_MM_USER_PAGE_SIZE - 1u) &
                     ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    address -= offset;
    return unlock ? kernel_mm_unlock_range(address, rounded_length) :
                    kernel_mm_lock_range(address, rounded_length, flags);
}

static int64_t edge_linux_sys_mlock(
    edge_linux_syscall_context_t *context) {
    uint32_t flags;
    switch (context->id) {
    case EDGE_LINUX_SYS_mlock:
    case EDGE_LINUX_SYS_mlock2:
        return edge_linux_mlock_range(context, 0);
    case EDGE_LINUX_SYS_munlock:
        return edge_linux_mlock_range(context, 1);
    case EDGE_LINUX_SYS_mlockall:
        flags = (uint32_t)context->arguments[0];
        if (context->arguments[0] != flags || !flags ||
            (flags & ~(EDGE_LINUX_MCL_CURRENT | EDGE_LINUX_MCL_FUTURE |
                       EDGE_LINUX_MCL_ONFAULT)) ||
            ((flags & EDGE_LINUX_MCL_ONFAULT) &&
             !(flags & (EDGE_LINUX_MCL_CURRENT | EDGE_LINUX_MCL_FUTURE))))
            return -EDGE_LINUX_EINVAL;
        return kernel_mm_lock_all(flags);
    case EDGE_LINUX_SYS_munlockall:
        return kernel_mm_unlock_all();
    default:
        return -EDGE_LINUX_ENOSYS;
    }
}

static int64_t edge_linux_sys_msync(
    edge_linux_syscall_context_t *context) {
    uint64_t address = context->arguments[0];
    uint64_t length = context->arguments[1];
    uint32_t flags = (uint32_t)context->arguments[2];
    uint32_t allowed = KERNEL_MM_SYNC_ASYNC | KERNEL_MM_SYNC_INVALIDATE |
                       KERNEL_MM_SYNC_SYNC;

    if (context->arguments[2] != flags || (flags & ~allowed) ||
        ((flags & KERNEL_MM_SYNC_ASYNC) &&
         (flags & KERNEL_MM_SYNC_SYNC)))
        return -EDGE_LINUX_EINVAL;
    if (address & (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (length > UINT64_MAX - address -
                 (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_ENOMEM;
    length = (length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
             ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    return kernel_mm_sync_range(address, length, flags);
}

static int64_t edge_linux_sys_mprotect(
    edge_linux_syscall_context_t *context) {
    uint64_t address = context->arguments[0];
    uint64_t length = context->arguments[1];
    uint64_t protection = context->arguments[2];
    uint64_t allowed = KERNEL_MM_PROT_READ | KERNEL_MM_PROT_WRITE |
                       KERNEL_MM_PROT_EXEC | KERNEL_MM_PROT_SEM |
                       KERNEL_MM_PROT_GROWSDOWN | KERNEL_MM_PROT_GROWSUP;

    if (address & (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if ((protection & ~allowed) ||
        ((protection & KERNEL_MM_PROT_GROWSDOWN) &&
         (protection & KERNEL_MM_PROT_GROWSUP)))
        return -EDGE_LINUX_EINVAL;
    if (length > UINT64_MAX - address -
                 (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_ENOMEM;
    length = (length + KERNEL_MM_USER_PAGE_SIZE - 1u) &
             ~(uint64_t)(KERNEL_MM_USER_PAGE_SIZE - 1u);
    return kernel_mm_protect_range(address, length, protection);
}

static int64_t edge_linux_sys_mmap(
    edge_linux_syscall_context_t *context) {
    kernel_mm_map_request_t request;
    /*
     * mmap's fd argument is an int. Upper register bits are unspecified for
     * narrower arguments, so normalize the ABI value before shared policy
     * validates it.
     */
    int32_t descriptor = (int32_t)(uint32_t)context->arguments[4];
    uint64_t flags = context->arguments[3];

    memset(&request, 0, sizeof(request));
    request.address = context->arguments[0];
    request.length = context->arguments[1];
    request.protection = context->arguments[2];
    request.flags = flags;
    request.descriptor = descriptor;
    request.offset = context->arguments[5];
    return kernel_mm_map(&request);
}

static int64_t edge_linux_sys_munmap(
    edge_linux_syscall_context_t *context) {
    return kernel_mm_unmap_range(
        context->arguments[0], context->arguments[1]);
}

static int64_t edge_linux_sys_mremap(
    edge_linux_syscall_context_t *context) {
    uint64_t old_address = context->arguments[0];
    uint64_t old_length = context->arguments[1];
    uint64_t new_length = context->arguments[2];
    return kernel_mm_remap_range(old_address, old_length, new_length,
                                 context->arguments[3],
                                 context->arguments[4]);
}

static int64_t edge_linux_sys_mseal(
    edge_linux_syscall_context_t *context) {
    return kernel_mm_seal_range(context->arguments[0],
                                context->arguments[1],
                                context->arguments[2]);
}

typedef struct edge_linux_open_flag_layout {
    uint64_t access_mode;
    uint64_t create;
    uint64_t exclusive;
    uint64_t no_controlling_tty;
    uint64_t truncate;
    uint64_t append;
    uint64_t nonblock;
    uint64_t directory;
    uint64_t nofollow;
    uint64_t cloexec;
    uint64_t path;
    uint64_t tmpfile_bit;
    uint64_t tmpfile;
    uint64_t valid;
} edge_linux_open_flag_layout_t;

static void edge_linux_open_flag_layout(
    edge_linux_syscall_architecture_t architecture,
    edge_linux_open_flag_layout_t *layout) {
    uint64_t direct;
    uint64_t largefile;

    memset(layout, 0, sizeof(*layout));
    layout->access_mode = 0x3u;
    layout->create = 0x40u;
    layout->exclusive = 0x80u;
    layout->no_controlling_tty = 0x100u;
    layout->truncate = 0x200u;
    layout->append = 0x400u;
    layout->nonblock = 0x800u;
    layout->directory = architecture == EDGE_LINUX_ARCH_AARCH64 ?
        0x4000u : 0x10000u;
    layout->nofollow = architecture == EDGE_LINUX_ARCH_AARCH64 ?
        0x8000u : 0x20000u;
    direct = architecture == EDGE_LINUX_ARCH_AARCH64 ?
        0x10000u : 0x4000u;
    largefile = architecture == EDGE_LINUX_ARCH_AARCH64 ?
        0x20000u : 0x8000u;
    layout->cloexec = 0x80000u;
    layout->path = 0x200000u;
    layout->tmpfile_bit = 0x400000u;
    layout->tmpfile = layout->tmpfile_bit | layout->directory;
    layout->valid = layout->access_mode | layout->create |
        layout->exclusive | layout->no_controlling_tty |
        layout->truncate | layout->append | layout->nonblock |
        0x1000u | 0x2000u | direct | largefile | layout->directory |
        layout->nofollow | 0x40000u | layout->cloexec | 0x101000u |
        layout->path | layout->tmpfile_bit;
}

static int edge_linux_open_request_prepare(
    edge_linux_syscall_context_t *context, int32_t directory,
    uint64_t user_path, uint64_t linux_flags, uint64_t mode,
    int strict, kernel_vfs_open_request_t *request) {
    edge_linux_open_flag_layout_t layout;

    if (!request) return -EDGE_LINUX_EIO;
    edge_linux_open_flag_layout(context->architecture, &layout);
    if (strict) {
        if (linux_flags & ~layout.valid) return -EDGE_LINUX_EINVAL;
        if (mode & ~07777u) return -EDGE_LINUX_EINVAL;
        if (!(linux_flags & (layout.create | layout.tmpfile_bit)) && mode)
            return -EDGE_LINUX_EINVAL;
        if ((linux_flags & layout.tmpfile_bit) &&
            ((linux_flags & layout.tmpfile) != layout.tmpfile ||
             (linux_flags & layout.access_mode) == 0u))
            return -EDGE_LINUX_EINVAL;
        if ((linux_flags & layout.path) &&
            (linux_flags & ~(layout.path | layout.directory |
                             layout.nofollow | layout.cloexec)))
            return -EDGE_LINUX_EINVAL;
    }
    memset(request, 0, sizeof(*request));
    request->directory = directory;
    request->linux_flags = (uint32_t)linux_flags;
    request->user_path = user_path;
    request->user_registers = context->user_registers;
    request->mode = (uint16_t)(mode & 07777u);
    request->access_mode = (uint8_t)(linux_flags & layout.access_mode);
    if (linux_flags & layout.create)
        request->flags |= KERNEL_VFS_OPEN_CREATE;
    if (linux_flags & layout.exclusive)
        request->flags |= KERNEL_VFS_OPEN_EXCLUSIVE;
    if (linux_flags & layout.no_controlling_tty)
        request->flags |= KERNEL_VFS_OPEN_NO_CONTROLLING_TTY;
    if (linux_flags & layout.truncate)
        request->flags |= KERNEL_VFS_OPEN_TRUNCATE;
    if (linux_flags & layout.append)
        request->flags |= KERNEL_VFS_OPEN_APPEND;
    if (linux_flags & layout.nonblock)
        request->flags |= KERNEL_VFS_OPEN_NONBLOCK;
    if (linux_flags & layout.directory)
        request->flags |= KERNEL_VFS_OPEN_DIRECTORY;
    if (linux_flags & layout.nofollow)
        request->flags |= KERNEL_VFS_OPEN_NOFOLLOW;
    if (linux_flags & layout.cloexec)
        request->flags |= KERNEL_VFS_OPEN_CLOEXEC;
    if (linux_flags & layout.path)
        request->flags |= KERNEL_VFS_OPEN_PATH;
    if ((linux_flags & layout.tmpfile) == layout.tmpfile)
        request->flags |= KERNEL_VFS_OPEN_TMPFILE;
    return 0;
}

int kernel_vfs_open_access_mask(const kernel_vfs_open_request_t *request,
                                int newly_created) {
    int access_mask = 0;

    if (!request || newly_created ||
        (request->flags & KERNEL_VFS_OPEN_PATH))
        return 0;
    if (request->access_mode == KERNEL_VFS_OPEN_READ_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE)
        access_mask |= 4;
    if (request->access_mode == KERNEL_VFS_OPEN_WRITE_ONLY ||
        request->access_mode == KERNEL_VFS_OPEN_READ_WRITE ||
        (request->flags & KERNEL_VFS_OPEN_TRUNCATE))
        access_mask |= 2;
    return access_mask;
}

static int64_t edge_linux_sys_open(edge_linux_syscall_context_t *context) {
    const uint64_t valid_resolve_flags = 0x3fu;
    kernel_vfs_xattr_scratch_t scratch;
    kernel_vfs_open_request_t request;
    edge_linux_open_flag_layout_t layout;
    struct edge_linux_open_how how;
    int result;

    if (context->id == EDGE_LINUX_SYS_open) {
        result = edge_linux_open_request_prepare(
            context, EDGE_LINUX_AT_FDCWD, context->arguments[0],
            context->arguments[1], context->arguments[2], 0, &request);
    } else if (context->id == EDGE_LINUX_SYS_creat) {
        edge_linux_open_flag_layout(context->architecture, &layout);
        result = edge_linux_open_request_prepare(
            context, EDGE_LINUX_AT_FDCWD, context->arguments[0],
            layout.create | 1u | layout.truncate,
            context->arguments[1], 0, &request);
    } else if (context->id == EDGE_LINUX_SYS_openat) {
        result = edge_linux_open_request_prepare(
            context, (int32_t)context->arguments[0], context->arguments[1],
            context->arguments[2], context->arguments[3], 0, &request);
    } else if (context->id == EDGE_LINUX_SYS_openat2) {
        result = edge_linux_copy_struct_from_user(
            &how, sizeof(how), sizeof(how), context->arguments[2],
            context->arguments[3], edge_linux_seccomp_copy_from_user,
            context);
        if (result < 0) return result;
        result = edge_linux_open_request_prepare(
            context, (int32_t)context->arguments[0], context->arguments[1],
            how.flags, how.mode, 1, &request);
        if (result < 0) return result;
        if ((how.resolve & ~valid_resolve_flags) ||
            ((how.resolve & 0x08u) && (how.resolve & 0x10u)))
            return -EDGE_LINUX_EINVAL;
        request.resolve_flags = how.resolve;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (result < 0) return result;
    result = kernel_vfs_current_xattr_scratch(&scratch);
    if (result < 0) return result;
    result = edge_linux_copy_user_string(
        context, request.user_path, scratch.path, scratch.path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (result < 0) return result;
    request.path = scratch.path;
    return kernel_vfs_open_at(&request);
}

static int64_t edge_linux_sys_getdents64(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_getdents_request_t request;

    if (context->arguments[0] > INT32_MAX) return -EDGE_LINUX_EBADF;
    memset(&request, 0, sizeof(request));
    request.descriptor = (int32_t)context->arguments[0];
    request.user_buffer = context->arguments[1];
    request.capacity = context->arguments[2];
    request.copy_context = context;
    request.copy_to_user = edge_linux_directory_copy_to_user;
    return kernel_vfs_getdents64(&request);
}

static int64_t edge_linux_sys_brk(
    edge_linux_syscall_context_t *context) {
    return kernel_mm_program_break(context->arguments[0]);
}

static int64_t edge_linux_sys_reboot(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    uint32_t magic1 = (uint32_t)context->arguments[0];
    uint32_t magic2 = (uint32_t)context->arguments[1];
    uint32_t command = (uint32_t)context->arguments[2];

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ull << EDGE_LINUX_CAP_SYS_BOOT)))
        return -EDGE_LINUX_EPERM;
    if (magic1 != KERNEL_REBOOT_MAGIC1 ||
        (magic2 != KERNEL_REBOOT_MAGIC2 &&
         magic2 != KERNEL_REBOOT_MAGIC2A &&
         magic2 != KERNEL_REBOOT_MAGIC2B &&
         magic2 != KERNEL_REBOOT_MAGIC2C))
        return -EDGE_LINUX_EINVAL;

    switch (command) {
        case KERNEL_REBOOT_CMD_CAD_ON:
        case KERNEL_REBOOT_CMD_CAD_OFF:
            return 0;
        case KERNEL_REBOOT_CMD_RESTART:
            return kernel_system_power_action(KERNEL_POWER_RESTART);
        case KERNEL_REBOOT_CMD_HALT:
            return kernel_system_power_action(KERNEL_POWER_HALT);
        case KERNEL_REBOOT_CMD_POWER_OFF:
            return kernel_system_power_action(KERNEL_POWER_OFF);
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

static int64_t edge_linux_sys_namespace(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    kernel_namespace_runtime_state_t state;

    if (context->id == EDGE_LINUX_SYS_setns) {
        kernel_namespace_descriptor_t descriptor;
        uint64_t requested_type = context->arguments[1];
        uint64_t descriptor_type;
        int32_t descriptor_number;
        int status;

        status = edge_linux_fd_number(context->arguments[0],
                                      &descriptor_number);
        if (status < 0) return status;
        status = kernel_namespace_descriptor_get(descriptor_number,
                                                 &descriptor);
        if (status == -EDGE_LINUX_ENOTTY)
            return -EDGE_LINUX_EINVAL;
        if (status < 0) return status;
        descriptor_type = edge_namespace_clone_flag(descriptor.kind);
        if (!descriptor_type ||
            (requested_type && requested_type != descriptor_type))
            return -EDGE_LINUX_EINVAL;
        if (kernel_current_linux_identity(&identity) < 0 ||
            kernel_current_namespace_state(&state) < 0)
            return -EDGE_LINUX_ESRCH;
        if (!(identity.effective_capabilities &
              (1ull << EDGE_LINUX_CAP_SYS_ADMIN)))
            return -EDGE_LINUX_EPERM;
        if (descriptor.kind == EDGE_NAMESPACE_USER &&
            (state.thread_count > 1u ||
             state.user_namespace_id == descriptor.id))
            return -EDGE_LINUX_EINVAL;
        if (descriptor.kind == EDGE_NAMESPACE_MNT &&
            state.filesystem_context_shared)
            return -EDGE_LINUX_EINVAL;
        return kernel_current_namespace_join(descriptor.kind,
                                             descriptor.id);
    }

    if (context->id == EDGE_LINUX_SYS_unshare) {
        const uint64_t supported = EDGE_NAMESPACE_CLONE_FLAGS |
                                   KERNEL_CLONE_FS |
                                   KERNEL_CLONE_FILES;
        uint64_t flags = context->arguments[0];
        int status;

        if (flags & ~supported) return -EDGE_LINUX_EINVAL;
        if (!flags) return 0;
        if (kernel_current_linux_identity(&identity) < 0 ||
            kernel_current_namespace_state(&state) < 0)
            return -EDGE_LINUX_ESRCH;
        if ((flags & EDGE_CLONE_NEWUSER) && state.thread_count > 1u)
            return -EDGE_LINUX_EINVAL;
        if ((flags & EDGE_NAMESPACE_CLONE_FLAGS) &&
            !(flags & EDGE_CLONE_NEWUSER) &&
            !(identity.effective_capabilities &
              (1ull << EDGE_LINUX_CAP_SYS_ADMIN)))
            return -EDGE_LINUX_EPERM;
        if (flags & KERNEL_CLONE_FILES) {
            status = kernel_fd_table_unshare();
            if (status < 0) return status;
        }
        if (flags & KERNEL_CLONE_FS) {
            status = kernel_current_fs_unshare();
            if (status < 0) return status;
        }
        if (!(flags & EDGE_NAMESPACE_CLONE_FLAGS)) return 0;
        return kernel_current_namespaces_unshare(
            flags & EDGE_NAMESPACE_CLONE_FLAGS,
            identity.euid, identity.egid);
    }

    return -EDGE_LINUX_ENOSYS;
}

static int64_t edge_linux_sys_sysv_shm(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_shmid_ds64 information;
    uint32_t command;
    int result;

    switch (context->id) {
        case EDGE_LINUX_SYS_shmget:
            if (context->arguments[2] > UINT32_MAX)
                return -EDGE_LINUX_EINVAL;
            return kernel_sysv_shm_get(
                (int32_t)context->arguments[0], context->arguments[1],
                (uint32_t)context->arguments[2]);
        case EDGE_LINUX_SYS_shmat:
            if (context->arguments[2] > UINT32_MAX)
                return -EDGE_LINUX_EINVAL;
            return kernel_sysv_shm_attach(
                (int32_t)context->arguments[0], context->arguments[1],
                (uint32_t)context->arguments[2]);
        case EDGE_LINUX_SYS_shmdt:
            return kernel_sysv_shm_detach(context->arguments[0]);
        case EDGE_LINUX_SYS_shmctl:
            if (context->arguments[1] > UINT32_MAX)
                return -EDGE_LINUX_EINVAL;
            command = (uint32_t)context->arguments[1];
            if ((command & 0xffu) == KERNEL_SYSV_IPC_SET) {
                if (!context->arguments[2]) return -EDGE_LINUX_EFAULT;
                if (edge_linux_copy_from_user(
                        context, &information, context->arguments[2],
                        sizeof(information)) < 0)
                    return -EDGE_LINUX_EFAULT;
                return kernel_sysv_shm_control(
                    (int32_t)context->arguments[0], command, &information);
            }
            if ((command & 0xffu) == KERNEL_SYSV_IPC_STAT) {
                if (!context->arguments[2]) return -EDGE_LINUX_EFAULT;
                result = kernel_sysv_shm_control(
                    (int32_t)context->arguments[0], command, &information);
                if (result < 0) return result;
                if (edge_linux_copy_to_user(
                        context, context->arguments[2], &information,
                        sizeof(information)) < 0)
                    return -EDGE_LINUX_EFAULT;
                return 0;
            }
            return kernel_sysv_shm_control(
                (int32_t)context->arguments[0], command, 0);
        default:
            return -EDGE_LINUX_ENOSYS;
    }
}

static uint32_t edge_linux_current_ipc_namespace(void) {
    const edge_namespace_set_t *namespaces =
        kernel_arch_current_namespace_set();
    return namespaces ? namespaces->ipc : 0u;
}

static void edge_linux_sem_status_from_x86(
        const struct edge_linux_semid_ds_x86_64 *input,
        kernel_sysv_sem_status_t *output) {
    memset(output, 0, sizeof(*output));
    output->permission = input->sem_perm;
    output->operation_time = input->sem_otime;
    output->change_time = input->sem_ctime;
    output->semaphore_count = input->sem_nsems;
}

static void edge_linux_sem_status_from_arm64(
        const struct edge_linux_semid_ds_aarch64 *input,
        kernel_sysv_sem_status_t *output) {
    memset(output, 0, sizeof(*output));
    output->permission = input->sem_perm;
    output->operation_time = input->sem_otime;
    output->change_time = input->sem_ctime;
    output->semaphore_count = input->sem_nsems;
}

static int edge_linux_sem_status_copy_from_user(
        edge_linux_syscall_context_t *context, uint64_t user_address,
        kernel_sysv_sem_status_t *status) {
    if (context->architecture == EDGE_LINUX_ARCH_X86_64) {
        struct edge_linux_semid_ds_x86_64 value;
        if (edge_linux_copy_from_user(
                context, &value, user_address, sizeof(value)) < 0)
            return -EDGE_LINUX_EFAULT;
        edge_linux_sem_status_from_x86(&value, status);
    } else {
        struct edge_linux_semid_ds_aarch64 value;
        if (edge_linux_copy_from_user(
                context, &value, user_address, sizeof(value)) < 0)
            return -EDGE_LINUX_EFAULT;
        edge_linux_sem_status_from_arm64(&value, status);
    }
    return 0;
}

static int edge_linux_sem_status_copy_to_user(
        edge_linux_syscall_context_t *context, uint64_t user_address,
        const kernel_sysv_sem_status_t *status) {
    if (context->architecture == EDGE_LINUX_ARCH_X86_64) {
        struct edge_linux_semid_ds_x86_64 value;
        memset(&value, 0, sizeof(value));
        value.sem_perm = status->permission;
        value.sem_otime = status->operation_time;
        value.sem_ctime = status->change_time;
        value.sem_nsems = status->semaphore_count;
        return edge_linux_copy_to_user(
            context, user_address, &value, sizeof(value)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    } else {
        struct edge_linux_semid_ds_aarch64 value;
        memset(&value, 0, sizeof(value));
        value.sem_perm = status->permission;
        value.sem_otime = status->operation_time;
        value.sem_ctime = status->change_time;
        value.sem_nsems = status->semaphore_count;
        return edge_linux_copy_to_user(
            context, user_address, &value, sizeof(value)) < 0 ?
            -EDGE_LINUX_EFAULT : 0;
    }
}

static int64_t edge_linux_sys_semop(
        edge_linux_syscall_context_t *context) {
    struct edge_linux_sembuf *operations;
    kernel_sysv_sem_wait_t wait;
    linux_timespec64_t timeout;
    uint64_t deadline = UINT64_MAX;
    uint64_t operation_count = context->arguments[2];
    uint32_t ipc_namespace_id = edge_linux_current_ipc_namespace();
    int32_t identifier = (int32_t)context->arguments[0];
    int waited = 0;
    int64_t result;

    if (!operation_count) return -EDGE_LINUX_EINVAL;
    if (operation_count > KERNEL_SYSV_SEM_MAX_OPS)
        return -EDGE_LINUX_E2BIG;
    if (!context->arguments[1]) return -EDGE_LINUX_EFAULT;
    operations = (struct edge_linux_sembuf *)arch_vm_alloc_page();
    if (!operations) return -EDGE_LINUX_ENOMEM;
    if (edge_linux_copy_from_user(
            context, operations, context->arguments[1],
            operation_count * sizeof(*operations)) < 0) {
        arch_vm_free_page(operations);
        return -EDGE_LINUX_EFAULT;
    }
    if (context->id == EDGE_LINUX_SYS_semtimedop &&
        context->arguments[3]) {
        uint64_t duration;
        uint64_t now;
        if (edge_linux_copy_from_user(
                context, &timeout, context->arguments[3],
                sizeof(timeout)) < 0) {
            arch_vm_free_page(operations);
            return -EDGE_LINUX_EFAULT;
        }
        if (edge_linux_timespec_microseconds(&timeout, &duration) < 0) {
            arch_vm_free_page(operations);
            return -EDGE_LINUX_EINVAL;
        }
        now = boottime_monotonic_us();
        deadline = duration > UINT64_MAX - now ? UINT64_MAX : now + duration;
    }
    for (;;) {
        result = kernel_sysv_sem_operate(
            ipc_namespace_id, identifier, operations,
            (uint32_t)operation_count, &wait);
        if (waited && result == -EDGE_LINUX_EINVAL) {
            result = -EDGE_LINUX_EIDRM;
            break;
        }
        if (result != -EDGE_LINUX_EAGAIN || !wait.valid) break;
        if (deadline != UINT64_MAX && boottime_monotonic_us() >= deadline)
            break;
        if (kernel_current_signal_wake_pending()) {
            result = -EDGE_LINUX_EINTR;
            break;
        }
        kernel_sysv_sem_waiter_change(
            ipc_namespace_id, identifier, &wait, 1);
        waited = 1;
        {
            int released = kernel_runtime_contention_begin();
            if (!kernel_runtime_yield()) result = -EDGE_LINUX_EAGAIN;
            kernel_runtime_contention_end(released);
        }
        kernel_sysv_sem_waiter_change(
            ipc_namespace_id, identifier, &wait, -1);
        if (result != -EDGE_LINUX_EAGAIN) continue;
    }
    arch_vm_free_page(operations);
    return result;
}

static int64_t edge_linux_sys_semctl(
        edge_linux_syscall_context_t *context) {
    kernel_sysv_sem_status_t status;
    struct edge_linux_seminfo information;
    uint16_t values[KERNEL_SYSV_SEM_MAX_PER_SET];
    uint32_t ipc_namespace_id = edge_linux_current_ipc_namespace();
    uint32_t command;
    uint32_t operation;
    uint32_t semaphore_number;
    uint64_t argument = context->arguments[3];
    int64_t result;

    if (context->arguments[1] > UINT32_MAX ||
        context->arguments[2] > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    semaphore_number = (uint32_t)context->arguments[1];
    command = (uint32_t)context->arguments[2];
    operation = command & 0xffu;
    memset(&status, 0, sizeof(status));
    memset(values, 0, sizeof(values));
    memset(&information, 0, sizeof(information));

    if (operation == KERNEL_SYSV_IPC_SET) {
        if (!argument) return -EDGE_LINUX_EFAULT;
        result = edge_linux_sem_status_copy_from_user(
            context, argument, &status);
        if (result < 0) return result;
    }
    if (operation == KERNEL_SYSV_SEM_SETALL ||
        operation == KERNEL_SYSV_SEM_GETALL) {
        uint32_t count;
        result = kernel_sysv_sem_count(
            ipc_namespace_id, (int32_t)context->arguments[0],
            operation == KERNEL_SYSV_SEM_SETALL ? 2u : 4u, &count);
        if (result < 0) return result;
        status.semaphore_count = count;
        if (operation == KERNEL_SYSV_SEM_SETALL &&
            (!argument || count > KERNEL_SYSV_SEM_MAX_PER_SET ||
            edge_linux_copy_from_user(
                context, values, argument,
                count * sizeof(values[0])) < 0))
            return -EDGE_LINUX_EFAULT;
    }
    result = kernel_sysv_sem_control(
        ipc_namespace_id, (int32_t)context->arguments[0],
        semaphore_number, command, (int32_t)argument,
        values, KERNEL_SYSV_SEM_MAX_PER_SET, &status, &information);
    if (result < 0) return result;
    if (operation == KERNEL_SYSV_IPC_STAT ||
        operation == KERNEL_SYSV_SEM_STAT ||
        operation == KERNEL_SYSV_SEM_STAT_ANY) {
        int copy_status;
        if (!argument) return -EDGE_LINUX_EFAULT;
        copy_status = edge_linux_sem_status_copy_to_user(
            context, argument, &status);
        return copy_status < 0 ? copy_status : result;
    }
    if (operation == KERNEL_SYSV_IPC_INFO ||
        operation == KERNEL_SYSV_SEM_INFO) {
        if (!argument || edge_linux_copy_to_user(
                context, argument, &information,
                sizeof(information)) < 0)
            return -EDGE_LINUX_EFAULT;
    } else if (operation == KERNEL_SYSV_SEM_GETALL) {
        if (!argument || status.semaphore_count >
                         KERNEL_SYSV_SEM_MAX_PER_SET ||
            edge_linux_copy_to_user(
                context, argument, values,
                status.semaphore_count * sizeof(values[0])) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return result;
}

static int64_t edge_linux_sys_sysv_sem(
        edge_linux_syscall_context_t *context) {
#ifndef CONFIG_SYSVIPC
    (void)context;
    return -EDGE_LINUX_ENOSYS;
#else
    switch (context->id) {
    case EDGE_LINUX_SYS_semget:
        if (context->arguments[1] > UINT32_MAX ||
            context->arguments[2] > UINT32_MAX)
            return -EDGE_LINUX_EINVAL;
        return kernel_sysv_sem_get(
            edge_linux_current_ipc_namespace(),
            (int32_t)context->arguments[0],
            (uint32_t)context->arguments[1],
            (uint32_t)context->arguments[2]);
    case EDGE_LINUX_SYS_semop:
    case EDGE_LINUX_SYS_semtimedop:
        return edge_linux_sys_semop(context);
    case EDGE_LINUX_SYS_semctl:
        return edge_linux_sys_semctl(context);
    default:
        return -EDGE_LINUX_ENOSYS;
    }
#endif
}

static int edge_linux_seccomp_action_supported(uint32_t action) {
    switch (action) {
        case EDGE_SECCOMP_RET_KILL_PROCESS:
        case EDGE_SECCOMP_RET_KILL_THREAD:
        case EDGE_SECCOMP_RET_TRAP:
        case EDGE_SECCOMP_RET_ERRNO:
        case EDGE_SECCOMP_RET_TRACE:
        case EDGE_SECCOMP_RET_LOG:
        case EDGE_SECCOMP_RET_ALLOW:
            return 1;
        default:
            return 0;
    }
}

static int64_t edge_linux_sys_seccomp(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_seccomp_notif_sizes sizes;
    uint32_t operation = (uint32_t)context->arguments[0];
    uint32_t flags = (uint32_t)context->arguments[1];
    uint64_t user_argument = context->arguments[2];

    switch (operation) {
        case EDGE_LINUX_SECCOMP_SET_MODE_STRICT:
            if (flags || user_argument) return -EDGE_LINUX_EINVAL;
            return -EDGE_LINUX_EOPNOTSUPP;
        case EDGE_LINUX_SECCOMP_SET_MODE_FILTER:
            if (flags & ~EDGE_LINUX_SECCOMP_FILTER_FLAG_ALL)
                return -EDGE_LINUX_EINVAL;
            if ((flags & EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC_ESRCH) &&
                !(flags & EDGE_LINUX_SECCOMP_FILTER_FLAG_TSYNC))
                return -EDGE_LINUX_EINVAL;
            if (flags & EDGE_LINUX_SECCOMP_FILTER_FLAG_UNSUPPORTED)
                return -EDGE_LINUX_EOPNOTSUPP;
            return edge_linux_seccomp_filter_install_current_flags(
                user_argument, flags, edge_linux_seccomp_copy_from_user,
                context);
        case EDGE_LINUX_SECCOMP_GET_ACTION_AVAIL: {
            uint32_t action;
            if (flags) return -EDGE_LINUX_EINVAL;
            if (!user_argument) return -EDGE_LINUX_EFAULT;
            if (edge_linux_copy_from_user(
                    context, &action, user_argument, sizeof(action)) < 0)
                return -EDGE_LINUX_EFAULT;
            return edge_linux_seccomp_action_supported(action) ? 0 :
                -EDGE_LINUX_EOPNOTSUPP;
        }
        case EDGE_LINUX_SECCOMP_GET_NOTIF_SIZES:
            if (flags) return -EDGE_LINUX_EINVAL;
            if (!user_argument) return -EDGE_LINUX_EFAULT;
            sizes.seccomp_notif =
                (uint16_t)sizeof(struct edge_linux_seccomp_notif);
            sizes.seccomp_notif_resp =
                (uint16_t)sizeof(struct edge_linux_seccomp_notif_resp);
            sizes.seccomp_data =
                (uint16_t)sizeof(struct edge_linux_seccomp_data);
            return edge_linux_copy_to_user(
                       context, user_argument, &sizes, sizeof(sizes)) < 0 ?
                -EDGE_LINUX_EFAULT : 0;
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

static int edge_linux_capability_state_equal(
    const linux_capability_state_t *left,
    const linux_capability_state_t *right) {
    return left->permitted == right->permitted &&
           left->effective == right->effective &&
           left->inheritable == right->inheritable &&
           left->bounding == right->bounding &&
           left->ambient == right->ambient &&
           left->securebits == right->securebits;
}

static int64_t edge_linux_prctl_update(
    const kernel_linux_prctl_state_t *state, uint32_t update_mask) {
    return kernel_current_prctl_state_update(state, update_mask) < 0 ?
        -EDGE_LINUX_ESRCH : 0;
}

static int64_t edge_linux_prctl_set_name(
    edge_linux_syscall_context_t *context,
    kernel_linux_prctl_state_t *state) {
    uint64_t source = context->arguments[1];
    uint32_t index;
    uint8_t byte;
    if (!source) return -EDGE_LINUX_EFAULT;
    for (index = 0; index < sizeof(state->name); ++index)
        state->name[index] = 0;
    for (index = 0; index < sizeof(state->name); ++index) {
        if (edge_linux_copy_from_user(
                context, &byte, source + index, sizeof(byte)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (index + 1u < sizeof(state->name)) state->name[index] = (char)byte;
        if (!byte) break;
    }
    state->name[sizeof(state->name) - 1u] = 0;
    return edge_linux_prctl_update(state, EDGE_LINUX_PRCTL_UPDATE_NAME);
}

static int64_t edge_linux_sys_prctl(
    edge_linux_syscall_context_t *context) {
    kernel_linux_prctl_state_t state;
    linux_credential_state_t credentials;
    linux_capability_state_t old_capabilities;
    uint32_t option = (uint32_t)context->arguments[0];
    uint64_t argument2 = context->arguments[1];
    uint64_t argument3 = context->arguments[2];
    uint64_t argument4 = context->arguments[3];
    uint64_t argument5 = context->arguments[4];
    int can_setpcap;
    int cap_status;
    int64_t cap_result;

    if (kernel_current_prctl_state_get(&state) < 0 ||
        kernel_current_credentials_get(&credentials) < 0)
        return -EDGE_LINUX_ESRCH;
    linux_capabilities_copy(&old_capabilities, &credentials.capabilities);
    can_setpcap = credentials.euid == 0 ||
        ((credentials.capabilities.effective >> EDGE_LINUX_CAP_SETPCAP) & 1u);
    cap_status = linux_capabilities_prctl(
        &credentials.capabilities, option, argument2, argument3,
        argument4, argument5, can_setpcap, &cap_result);
    if (cap_status == LINUX_CAP_PRCTL_OK) {
        if (!edge_linux_capability_state_equal(
                &old_capabilities, &credentials.capabilities) &&
            kernel_current_capabilities_set(&credentials.capabilities) < 0)
            return -EDGE_LINUX_ESRCH;
        return cap_result;
    }
    if (cap_status == LINUX_CAP_PRCTL_INVALID)
        return -EDGE_LINUX_EINVAL;
    if (cap_status == LINUX_CAP_PRCTL_PERMISSION)
        return -EDGE_LINUX_EPERM;

    switch (option) {
        case EDGE_LINUX_PR_SET_PDEATHSIG:
            if (argument2 > 64u) return -EDGE_LINUX_EINVAL;
            state.parent_death_signal = (uint32_t)argument2;
            return edge_linux_prctl_update(
                &state, EDGE_LINUX_PRCTL_UPDATE_PARENT_DEATH_SIGNAL);
        case EDGE_LINUX_PR_GET_PDEATHSIG: {
            int32_t signal = (int32_t)state.parent_death_signal;
            if (!argument2) return -EDGE_LINUX_EFAULT;
            return edge_linux_copy_to_user(
                       context, argument2, &signal, sizeof(signal)) < 0 ?
                -EDGE_LINUX_EFAULT : 0;
        }
        case EDGE_LINUX_PR_GET_DUMPABLE:
            return state.dumpable;
        case EDGE_LINUX_PR_SET_DUMPABLE:
            if (argument2 > 1u) return -EDGE_LINUX_EINVAL;
            state.dumpable = (uint8_t)argument2;
            return edge_linux_prctl_update(
                &state, EDGE_LINUX_PRCTL_UPDATE_DUMPABLE);
        case EDGE_LINUX_PR_SET_NAME:
            return edge_linux_prctl_set_name(context, &state);
        case EDGE_LINUX_PR_GET_NAME:
            if (!argument2) return -EDGE_LINUX_EFAULT;
            return edge_linux_copy_to_user(
                       context, argument2, state.name,
                       sizeof(state.name)) < 0 ? -EDGE_LINUX_EFAULT : 0;
        case EDGE_LINUX_PR_GET_SECCOMP:
            return state.seccomp_mode;
        case EDGE_LINUX_PR_SET_SECCOMP:
            if (argument2 == EDGE_LINUX_SECCOMP_MODE_STRICT)
                return argument3 ? -EDGE_LINUX_EINVAL :
                                   -EDGE_LINUX_EOPNOTSUPP;
            if (argument2 != EDGE_LINUX_SECCOMP_MODE_FILTER)
                return -EDGE_LINUX_EINVAL;
            return edge_linux_seccomp_filter_install_current(
                argument3, edge_linux_seccomp_copy_from_user, context);
        case EDGE_LINUX_PR_SET_TIMERSLACK:
            state.timer_slack_ns = argument2 ? argument2 :
                state.default_timer_slack_ns;
            if (!state.timer_slack_ns)
                state.timer_slack_ns = EDGE_LINUX_DEFAULT_TIMER_SLACK_NS;
            return edge_linux_prctl_update(
                &state, EDGE_LINUX_PRCTL_UPDATE_TIMER_SLACK);
        case EDGE_LINUX_PR_GET_TIMERSLACK:
            return (int64_t)state.timer_slack_ns;
        case EDGE_LINUX_PR_SET_CHILD_SUBREAPER:
            state.child_subreaper = argument2 ? 1u : 0u;
            return edge_linux_prctl_update(
                &state, EDGE_LINUX_PRCTL_UPDATE_CHILD_SUBREAPER);
        case EDGE_LINUX_PR_GET_CHILD_SUBREAPER: {
            int32_t child_subreaper = state.child_subreaper ? 1 : 0;
            if (!argument2) return -EDGE_LINUX_EFAULT;
            return edge_linux_copy_to_user(
                       context, argument2, &child_subreaper,
                       sizeof(child_subreaper)) < 0 ?
                -EDGE_LINUX_EFAULT : 0;
        }
        case EDGE_LINUX_PR_SET_NO_NEW_PRIVS:
            if (argument2 != 1u || argument3 || argument4 || argument5)
                return -EDGE_LINUX_EINVAL;
            state.no_new_privileges = 1;
            return edge_linux_prctl_update(
                &state, EDGE_LINUX_PRCTL_UPDATE_NO_NEW_PRIVILEGES);
        case EDGE_LINUX_PR_GET_NO_NEW_PRIVS:
            if (argument2 || argument3 || argument4 || argument5)
                return -EDGE_LINUX_EINVAL;
            return state.no_new_privileges ? 1 : 0;
        case EDGE_LINUX_PR_SET_THP_DISABLE:
            if (argument4 || argument5 ||
                argument3 & ~EDGE_LINUX_PR_THP_DISABLE_EXCEPT_ADVISED ||
                (!argument2 && argument3))
                return -EDGE_LINUX_EINVAL;
            state.thp_disabled = argument2 ?
                (uint8_t)(1u | (argument3 ? 2u : 0u)) : 0u;
            return edge_linux_prctl_update(
                &state, EDGE_LINUX_PRCTL_UPDATE_THP_DISABLED);
        case EDGE_LINUX_PR_GET_THP_DISABLE:
            if (argument2 || argument3 || argument4 || argument5)
                return -EDGE_LINUX_EINVAL;
            return state.thp_disabled;
        case EDGE_LINUX_PR_SET_VMA:
            /* VMA naming is not reported as successful until it is retained. */
            return -EDGE_LINUX_EINVAL;
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

static int64_t edge_linux_sys_mount(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_mount_scratch_t scratch;
    kernel_linux_identity_t identity;
    char filesystem[32];
    uint64_t mount_flags;
    uint64_t propagation_flags;
    int ignore_source;
    int ignore_type_and_data;
    int status;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EPERM;
    status = kernel_vfs_current_mount_scratch(&scratch);
    if (status < 0 || !scratch.source || !scratch.target ||
        !scratch.data || !scratch.workspace ||
        scratch.capacity < VFS_PATH_MAX)
        return status < 0 ? status : -EDGE_LINUX_EIO;

    if (context->id == EDGE_LINUX_SYS_umount2) {
        status = edge_linux_copy_user_string(
            context, context->arguments[0], scratch.target,
            scratch.capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        return kernel_linux_umount(
            scratch.target, context->arguments[1], scratch.workspace,
            scratch.capacity);
    }
    if (context->id == EDGE_LINUX_SYS_pivot_root) {
        status = edge_linux_copy_user_string(
            context, context->arguments[0], scratch.source,
            scratch.capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        status = edge_linux_copy_user_string(
            context, context->arguments[1], scratch.target,
            scratch.capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        return kernel_linux_pivot_root(
            scratch.source, scratch.target, scratch.workspace,
            scratch.capacity);
    }
    if (context->id != EDGE_LINUX_SYS_mount)
        return -EDGE_LINUX_ENOSYS;

    mount_flags = context->arguments[3];
    propagation_flags = mount_flags &
        (EDGE_LINUX_MS_SHARED | EDGE_LINUX_MS_PRIVATE |
         EDGE_LINUX_MS_SLAVE | EDGE_LINUX_MS_UNBINDABLE);
    ignore_source = (mount_flags & EDGE_LINUX_MS_REMOUNT) != 0 ||
                    propagation_flags != 0;
    ignore_type_and_data =
        (mount_flags & (EDGE_LINUX_MS_REMOUNT | EDGE_LINUX_MS_BIND |
                        EDGE_LINUX_MS_MOVE)) != 0 ||
        propagation_flags != 0;

    scratch.source[0] = 0;
    if (context->arguments[0] && !ignore_source) {
        status = edge_linux_copy_user_string(
            context, context->arguments[0], scratch.source,
            scratch.capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
    }
    status = edge_linux_copy_user_string(
        context, context->arguments[1], scratch.target,
        scratch.capacity, EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    filesystem[0] = 0;
    if (context->arguments[2] && !ignore_type_and_data) {
        status = edge_linux_copy_user_string(
            context, context->arguments[2], filesystem,
            sizeof(filesystem), EDGE_LINUX_ENODEV);
        if (status < 0) return status;
    }
    scratch.data[0] = 0;
    if (context->arguments[4] && !ignore_type_and_data) {
        status = edge_linux_copy_user_string(
            context, context->arguments[4], scratch.data,
            scratch.capacity, EDGE_LINUX_EINVAL);
        if (status < 0) return status;
    }
    return kernel_linux_mount(
        scratch.source, scratch.target, filesystem,
        mount_flags, scratch.data, scratch.workspace,
        scratch.capacity);
}

static int64_t edge_linux_sys_memfd_create(
    edge_linux_syscall_context_t *context) {
    char name[KERNEL_MEMFD_NAME_MAX + 1u];
    uint32_t flags = (uint32_t)context->arguments[1];
    int result;

    if (flags & ~(KERNEL_MEMFD_CLOEXEC | KERNEL_MEMFD_ALLOW_SEALING |
                  KERNEL_MEMFD_HUGETLB | KERNEL_MEMFD_HUGE_MASK))
        return -EDGE_LINUX_EINVAL;
    /*
     * Huge-page memfds require a hugetlb-backed allocator and reservation
     * accounting.  Reject them until that real backing exists instead of
     * exposing ordinary tmpfs pages under huge-page flags.
     */
    if (flags & (KERNEL_MEMFD_HUGETLB | KERNEL_MEMFD_HUGE_MASK))
        return -EDGE_LINUX_EINVAL;
    result = edge_linux_copy_user_string(
        context, context->arguments[0], name, sizeof(name),
        EDGE_LINUX_EINVAL);
    if (result < 0) return result;
    return kernel_memfd_create_descriptor(name, flags);
}

#define EDGE_LINUX_BPF_PROG_LOAD        5u
#define EDGE_LINUX_BPF_PROG_ATTACH      8u
#define EDGE_LINUX_BPF_PROG_DETACH      9u
#define EDGE_LINUX_BPF_PROG_QUERY       16u
#define EDGE_LINUX_BPF_BTF_LOAD         18u
#define EDGE_LINUX_BPF_PROG_TYPE_CGROUP_SKB    8u
#define EDGE_LINUX_BPF_PROG_TYPE_CGROUP_DEVICE 15u
#define EDGE_LINUX_BPF_CGROUP_DEVICE    6u
#define EDGE_LINUX_BPF_F_ALLOW_MULTI    (1u << 1)
#define EDGE_LINUX_BPF_F_REPLACE        (1u << 2)
#define EDGE_LINUX_BPF_MAX_INSTRUCTIONS 4096u

typedef struct edge_linux_bpf_program_load_attribute {
    uint32_t program_type;
    uint32_t instruction_count;
    uint64_t instructions;
    uint64_t license;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buffer;
    uint32_t kernel_version;
    uint32_t program_flags;
    char program_name[16];
    uint32_t interface_index;
    uint32_t expected_attach_type;
} edge_linux_bpf_program_load_attribute_t;

typedef struct edge_linux_bpf_program_attach_attribute {
    uint32_t target_descriptor;
    uint32_t program_descriptor;
    uint32_t attach_type;
    uint32_t attach_flags;
    uint32_t replace_program_descriptor;
} edge_linux_bpf_program_attach_attribute_t;

typedef struct edge_linux_bpf_program_query_attribute {
    uint32_t target_descriptor;
    uint32_t attach_type;
    uint32_t query_flags;
    uint32_t attach_flags;
    uint64_t program_ids;
    uint32_t program_count;
    uint32_t reserved;
} edge_linux_bpf_program_query_attribute_t;

static int edge_linux_bpf_cgroup_descriptor(uint32_t descriptor) {
    kernel_vfs_descriptor_t description;
    int status = kernel_vfs_describe_descriptor(
        (int32_t)descriptor, &description);
    if (status < 0) return -EDGE_LINUX_EBADF;
    if (description.kind != KERNEL_VFS_DESCRIPTOR_DIRECTORY ||
        !description.superblock ||
        strcmp(description.superblock->fs_name, "cgroup2") != 0)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_linux_bpf_program_descriptor(uint32_t descriptor) {
    kernel_vfs_descriptor_t description;
    int status = kernel_vfs_describe_descriptor(
        (int32_t)descriptor, &description);
    if (status < 0) return -EDGE_LINUX_EBADF;
    return description.kind == KERNEL_VFS_DESCRIPTOR_MEMORY ?
        0 : -EDGE_LINUX_EBADF;
}

static int64_t edge_linux_sys_bpf(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    uint32_t command = (uint32_t)context->arguments[0];
    uint64_t user_attribute = context->arguments[1];
    uint32_t attribute_size = (uint32_t)context->arguments[2];
    int status;

    if (!user_attribute) return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EPERM;
    if (command == EDGE_LINUX_BPF_BTF_LOAD)
        return -EDGE_LINUX_EINVAL;

    if (command == EDGE_LINUX_BPF_PROG_QUERY) {
        edge_linux_bpf_program_query_attribute_t attribute;
        if (attribute_size < sizeof(attribute))
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_copy_from_user(
            context, &attribute, user_attribute, sizeof(attribute));
        if (status < 0) return -EDGE_LINUX_EFAULT;
        if (attribute.attach_type != EDGE_LINUX_BPF_CGROUP_DEVICE ||
            attribute.query_flags != 0u)
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_bpf_cgroup_descriptor(
            attribute.target_descriptor);
        if (status < 0) return status;
        attribute.attach_flags = 0u;
        attribute.program_count = 0u;
        status = edge_linux_copy_to_user(
            context, user_attribute, &attribute, sizeof(attribute));
        return status < 0 ? -EDGE_LINUX_EFAULT : 0;
    }

    if (command == EDGE_LINUX_BPF_PROG_LOAD) {
        edge_linux_bpf_program_load_attribute_t attribute;
        uint64_t first_instruction;
        char license[16];
        if (attribute_size < sizeof(attribute))
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_copy_from_user(
            context, &attribute, user_attribute, sizeof(attribute));
        if (status < 0) return -EDGE_LINUX_EFAULT;
        if (attribute.program_type != EDGE_LINUX_BPF_PROG_TYPE_CGROUP_SKB &&
            attribute.program_type != EDGE_LINUX_BPF_PROG_TYPE_CGROUP_DEVICE)
            return -EDGE_LINUX_EINVAL;
        if (!attribute.instruction_count ||
            attribute.instruction_count > EDGE_LINUX_BPF_MAX_INSTRUCTIONS ||
            !attribute.instructions || !attribute.license)
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_copy_from_user(
            context, &first_instruction, attribute.instructions,
            sizeof(first_instruction));
        if (status < 0) return -EDGE_LINUX_EFAULT;
        status = edge_linux_copy_user_string(
            context, attribute.license, license, sizeof(license),
            EDGE_LINUX_EINVAL);
        if (status < 0) return status;
        return kernel_memfd_create_descriptor(
            "bpf-cgroup-program", KERNEL_MEMFD_CLOEXEC);
    }

    if (command == EDGE_LINUX_BPF_PROG_ATTACH ||
        command == EDGE_LINUX_BPF_PROG_DETACH) {
        edge_linux_bpf_program_attach_attribute_t attribute;
        uint32_t required_size = command == EDGE_LINUX_BPF_PROG_ATTACH ?
            (uint32_t)sizeof(attribute) : 3u * sizeof(uint32_t);
        if (attribute_size < required_size)
            return -EDGE_LINUX_EINVAL;
        memset(&attribute, 0, sizeof(attribute));
        status = edge_linux_copy_from_user(
            context, &attribute, user_attribute, required_size);
        if (status < 0) return -EDGE_LINUX_EFAULT;
        if (attribute.attach_type != EDGE_LINUX_BPF_CGROUP_DEVICE)
            return -EDGE_LINUX_EINVAL;
        if (command == EDGE_LINUX_BPF_PROG_ATTACH) {
            if (attribute.attach_flags & EDGE_LINUX_BPF_F_REPLACE)
                return -EDGE_LINUX_EINVAL;
            if (attribute.attach_flags & ~EDGE_LINUX_BPF_F_ALLOW_MULTI)
                return -EDGE_LINUX_EINVAL;
        } else if (attribute.attach_flags ||
                   attribute.replace_program_descriptor) {
            return -EDGE_LINUX_EINVAL;
        }
        status = edge_linux_bpf_cgroup_descriptor(
            attribute.target_descriptor);
        if (status < 0) return status;
        return edge_linux_bpf_program_descriptor(
            attribute.program_descriptor);
    }

    return -EDGE_LINUX_ENOSYS;
}

static int64_t edge_linux_sys_mincore(
    edge_linux_syscall_context_t *context) {
    uint8_t residency[128];
    uint64_t address = context->arguments[0];
    uint64_t length = context->arguments[1];
    uint64_t page_count;
    uint64_t completed = 0;

    if (address & (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (length > UINT64_MAX - address -
                 (KERNEL_MM_USER_PAGE_SIZE - 1u))
        return -EDGE_LINUX_ENOMEM;
    page_count = (length + KERNEL_MM_USER_PAGE_SIZE - 1u) /
                 KERNEL_MM_USER_PAGE_SIZE;

    while (completed < page_count) {
        uint64_t remaining = page_count - completed;
        uint32_t count = remaining > sizeof(residency) ?
                         sizeof(residency) : (uint32_t)remaining;
        uint64_t page_address = address +
            completed * KERNEL_MM_USER_PAGE_SIZE;
        int status = kernel_mm_query_residency(
            page_address, count, residency);
        if (status < 0) return status;
        if (context->arguments[2] > UINT64_MAX - completed)
            return -EDGE_LINUX_EFAULT;
        if (edge_linux_copy_to_user(
                context, context->arguments[2] + completed,
                residency, count) < 0)
            return -EDGE_LINUX_EFAULT;
        completed += count;
    }
    return 0;
}

static int64_t edge_linux_sys_pkey(
    edge_linux_syscall_context_t *context) {
    switch (context->id) {
    case EDGE_LINUX_SYS_pkey_alloc:
        if (context->arguments[0] || (context->arguments[1] & ~3ULL))
            return -EDGE_LINUX_EINVAL;
        return kernel_mm_pkey_allocate((uint32_t)context->arguments[1]);
    case EDGE_LINUX_SYS_pkey_free:
        return kernel_mm_pkey_free((int32_t)context->arguments[0]);
    case EDGE_LINUX_SYS_pkey_mprotect:
        return kernel_mm_pkey_mprotect(
            context->arguments[0], context->arguments[1],
            context->arguments[2], (int32_t)context->arguments[3]);
    default:
        return -EDGE_LINUX_ENOSYS;
    }
}

static int64_t edge_linux_sys_process_vm(
    edge_linux_syscall_context_t *context) {
    kernel_io_vector_scratch_t vector_scratch;
    kernel_process_vm_scratch_t transfer_scratch;
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    struct edge_linux_iovec *local_vectors;
    struct edge_linux_iovec *remote_vectors;
    uint64_t local_count = context->arguments[2];
    uint64_t remote_count = context->arguments[4];
    uint64_t local_limit = 0;
    uint64_t transferred = 0;
    uint64_t local_index = 0;
    uint64_t remote_index = 0;
    uint64_t local_offset = 0;
    uint64_t remote_offset = 0;
    int32_t target_pid;
    int reading;
    int remote_has_data = 0;
    int status;

    if (context->arguments[5]) return -EDGE_LINUX_EINVAL;
    if (local_count > EDGE_LINUX_IOV_MAX)
        return -EDGE_LINUX_EINVAL;
    if (!local_count) return 0;
    if (!context->arguments[1] ||
        local_count > UINT64_MAX / sizeof(local_vectors[0]))
        return -EDGE_LINUX_EFAULT;
    if (kernel_io_current_vector_scratch(&vector_scratch) < 0 ||
        !vector_scratch.vectors ||
        vector_scratch.capacity < local_count)
        return -EDGE_LINUX_ENOMEM;

    local_vectors = vector_scratch.vectors;
    if (edge_linux_copy_from_user(
            context, local_vectors, context->arguments[1],
            local_count * sizeof(local_vectors[0])) < 0)
        return -EDGE_LINUX_EFAULT;

    /*
     * Linux imports the local iterator first and caps its count at
     * MAX_RW_COUNT. access_ok checks address limits, not whether every page is
     * mapped; a later local or remote page fault therefore returns the prefix
     * already transferred.
     */
    reading = context->id == EDGE_LINUX_SYS_process_vm_readv;
    for (uint64_t index = 0; index < local_count; ++index) {
        uint64_t length = local_vectors[index].iov_len;
        if (length && edge_linux_validate_user_range(
                context, local_vectors[index].iov_base, length,
                reading) < 0)
            return -EDGE_LINUX_EFAULT;
        if (length > EDGE_LINUX_MAX_RW_COUNT - local_limit)
            local_limit = EDGE_LINUX_MAX_RW_COUNT;
        else
            local_limit += length;
    }
    if (!local_limit) return 0;

    if (remote_count > EDGE_LINUX_IOV_MAX)
        return -EDGE_LINUX_EINVAL;
    if (!remote_count) return 0;
    if (!context->arguments[3] ||
        remote_count > UINT64_MAX / sizeof(remote_vectors[0]))
        return -EDGE_LINUX_EFAULT;
    if (vector_scratch.capacity < local_count + remote_count)
        return -EDGE_LINUX_ENOMEM;
    remote_vectors = local_vectors + local_count;
    if (edge_linux_copy_from_user(
            context, remote_vectors, context->arguments[3],
            remote_count * sizeof(remote_vectors[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    for (uint64_t index = 0; index < remote_count; ++index)
        if (remote_vectors[index].iov_len) remote_has_data = 1;
    if (!remote_has_data) return 0;

    if (context->arguments[0] > INT32_MAX ||
        !(target_pid = (int32_t)context->arguments[0]))
        return -EDGE_LINUX_ESRCH;
    if (kernel_current_linux_identity(&caller) < 0 ||
        kernel_process_linux_identity(target_pid, &target) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!edge_linux_ptrace_access_allowed(
            &caller, &target, EDGE_LINUX_PTRACE_REALCREDS))
        return -EDGE_LINUX_EPERM;
    if (kernel_process_vm_current_scratch(&transfer_scratch) < 0 ||
        !transfer_scratch.buffer || !transfer_scratch.capacity)
        return -EDGE_LINUX_ENOMEM;

    while (transferred < local_limit && local_index < local_count &&
           remote_index < remote_count) {
        uint64_t local_address;
        uint64_t remote_address;
        uint64_t local_remaining;
        uint64_t remote_remaining;
        uint64_t chunk;

        if (local_offset == local_vectors[local_index].iov_len) {
            ++local_index;
            local_offset = 0;
            continue;
        }
        if (remote_offset == remote_vectors[remote_index].iov_len) {
            ++remote_index;
            remote_offset = 0;
            continue;
        }
        if (local_vectors[local_index].iov_base >
                UINT64_MAX - local_offset ||
            remote_vectors[remote_index].iov_base >
                UINT64_MAX - remote_offset)
            return transferred ? (int64_t)transferred :
                                 -EDGE_LINUX_EFAULT;
        local_address = local_vectors[local_index].iov_base + local_offset;
        remote_address = remote_vectors[remote_index].iov_base + remote_offset;
        local_remaining = local_vectors[local_index].iov_len - local_offset;
        remote_remaining = remote_vectors[remote_index].iov_len - remote_offset;
        chunk = local_remaining < remote_remaining ?
            local_remaining : remote_remaining;
        if (chunk > local_limit - transferred)
            chunk = local_limit - transferred;
        if (chunk > transfer_scratch.capacity)
            chunk = transfer_scratch.capacity;
        if (chunk > KERNEL_MM_USER_PAGE_SIZE -
                    (local_address & (KERNEL_MM_USER_PAGE_SIZE - 1u)))
            chunk = KERNEL_MM_USER_PAGE_SIZE -
                    (local_address & (KERNEL_MM_USER_PAGE_SIZE - 1u));
        if (chunk > KERNEL_MM_USER_PAGE_SIZE -
                    (remote_address & (KERNEL_MM_USER_PAGE_SIZE - 1u)))
            chunk = KERNEL_MM_USER_PAGE_SIZE -
                    (remote_address & (KERNEL_MM_USER_PAGE_SIZE - 1u));

        if (reading) {
            status = kernel_process_vm_read_memory(
                target_pid, remote_address, transfer_scratch.buffer, chunk);
            if (status >= 0 && edge_linux_copy_to_user(
                    context, local_address, transfer_scratch.buffer,
                    chunk) < 0)
                status = -EDGE_LINUX_EFAULT;
        } else {
            status = edge_linux_copy_from_user(
                context, transfer_scratch.buffer, local_address, chunk) < 0 ?
                -EDGE_LINUX_EFAULT : 0;
            if (status >= 0)
                status = kernel_process_vm_write_memory(
                    target_pid, remote_address, transfer_scratch.buffer,
                    chunk);
        }
        if (status < 0)
            return transferred ? (int64_t)transferred : status;
        transferred += chunk;
        local_offset += chunk;
        remote_offset += chunk;
    }
    return (int64_t)transferred;
}

static int64_t edge_linux_sys_pidfd_send_signal(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_siginfo information;
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    int32_t target_pid;
    uint32_t pidfd_flags;
    uint32_t signal = (uint32_t)context->arguments[1];
    uint64_t information_user = context->arguments[2];
    uint32_t flags = (uint32_t)context->arguments[3];
    uint32_t scope_flags = flags & EDGE_LINUX_PIDFD_SIGNAL_SCOPE_MASK;
    int thread_directed;
    int result;

    if (flags & ~EDGE_LINUX_PIDFD_SIGNAL_SCOPE_MASK ||
        (scope_flags && (scope_flags & (scope_flags - 1u))))
        return -EDGE_LINUX_EINVAL;
    result = kernel_pidfd_target(
        (int32_t)context->arguments[0], &target_pid, &pidfd_flags);
    if (result < 0) return result;
    if (signal > EDGE_LINUX_SIGNAL_MAX) return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (kernel_process_linux_identity(target_pid, &target) < 0)
        return -EDGE_LINUX_ESRCH;

    if (information_user) {
        if (edge_linux_copy_from_user(
                context, &information, information_user,
                sizeof(information)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (information.signal_number != (int32_t)signal)
            return -EDGE_LINUX_EINVAL;
        if ((caller.global_tid != target_pid ||
             scope_flags == EDGE_LINUX_PIDFD_SIGNAL_PROCESS_GROUP) &&
            (information.code >= 0 ||
             information.code == EDGE_LINUX_SI_TKILL))
            return -EDGE_LINUX_EPERM;
    } else {
        kernel_signal_info_build_sender(
            &information, signal, EDGE_LINUX_SI_USER,
            caller.tgid, caller.uid, 0u);
    }

    if (scope_flags == EDGE_LINUX_PIDFD_SIGNAL_PROCESS_GROUP)
        return edge_linux_signal_send_group(
            &caller, target.global_pgid, signal, 0, &information);
    if (scope_flags == EDGE_LINUX_PIDFD_SIGNAL_THREAD) {
        thread_directed = 1;
    } else if (scope_flags == EDGE_LINUX_PIDFD_SIGNAL_THREAD_GROUP) {
        target_pid = target.global_tgid;
        thread_directed = 0;
    } else {
        thread_directed =
            (pidfd_flags & EDGE_LINUX_PIDFD_THREAD) != 0u;
        if (!thread_directed) target_pid = target.global_tgid;
    }
    if (kernel_process_linux_identity(target_pid, &target) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!edge_linux_signal_permitted(&caller, &target, signal))
        return -EDGE_LINUX_EPERM;
    if (!signal) return 0;
    result = kernel_linux_signal_send(
        target.global_tid, signal, thread_directed, &information);
    return result < 0 ? result : 0;
}

static int64_t edge_linux_sys_queued_signal(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_siginfo information;
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    int32_t tgid;
    int32_t tid;
    int32_t global_tgid;
    int32_t global_tid;
    uint32_t signal;
    uint64_t information_user;
    int thread_directed;
    int result;

    if (context->id == EDGE_LINUX_SYS_rt_sigqueueinfo) {
        tgid = (int32_t)context->arguments[0];
        tid = tgid;
        signal = (uint32_t)context->arguments[1];
        information_user = context->arguments[2];
        thread_directed = 0;
    } else if (context->id == EDGE_LINUX_SYS_rt_tgsigqueueinfo) {
        tgid = (int32_t)context->arguments[0];
        tid = (int32_t)context->arguments[1];
        signal = (uint32_t)context->arguments[2];
        information_user = context->arguments[3];
        thread_directed = 1;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (tgid <= 0 || tid <= 0 || signal > EDGE_LINUX_SIGNAL_MAX)
        return -EDGE_LINUX_EINVAL;
    if (!information_user) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(
            context, &information, information_user,
            sizeof(information)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (edge_linux_pid_to_global(&caller, tgid, &global_tgid) < 0 ||
        edge_linux_pid_to_global(&caller, tid, &global_tid) < 0 ||
        kernel_process_linux_identity(global_tid, &target) < 0)
        return -EDGE_LINUX_ESRCH;
    if (target.global_tgid != global_tgid) return -EDGE_LINUX_ESRCH;
    if (!edge_linux_signal_permitted(&caller, &target, signal))
        return -EDGE_LINUX_EPERM;

    /*
     * Userspace may provide kernel-reserved si_code values only when sending
     * within its own thread group.  Linux also reserves SI_TKILL for tgkill;
     * accepting it cross-process would let a sender forge kernel provenance.
     */
    if (caller.tgid != target.tgid &&
        (information.code >= 0 || information.code == EDGE_LINUX_SI_TKILL))
        return -EDGE_LINUX_EPERM;
    information.signal_number = (int32_t)signal;
    if (!signal) return 0;
    result = kernel_linux_signal_send(
        target.global_tid, signal, thread_directed, &information);
    return result < 0 ? result : 0;
}

static int64_t edge_linux_sys_signal_action(
    edge_linux_syscall_context_t *context) {
    edge_linux_signal_action_t old_action;
    edge_linux_signal_action_t new_action;
    uint32_t signal = (uint32_t)context->arguments[0];
    uint64_t new_user = context->arguments[1];
    uint64_t old_user = context->arguments[2];
    uint64_t sigset_size = context->arguments[3];
    int result;

    if (!edge_linux_signal_valid(signal) || sigset_size != sizeof(uint64_t))
        return -EDGE_LINUX_EINVAL;
    result = kernel_current_signal_action_get(signal, &old_action);
    if (result < 0) return result;
    if (new_user) {
        if (!edge_linux_signal_catchable(signal))
            return -EDGE_LINUX_EINVAL;
        if (edge_linux_copy_from_user(
                context, &new_action, new_user, sizeof(new_action)) < 0)
            return -EDGE_LINUX_EFAULT;
        new_action.mask = edge_linux_signal_sanitize_mask(new_action.mask);
        result = kernel_current_signal_action_set(signal, &new_action);
        if (result < 0) return result;
    }
    if (old_user && edge_linux_copy_to_user(
            context, old_user, &old_action, sizeof(old_action)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_signal_mask(
    edge_linux_syscall_context_t *context) {
    uint64_t old_mask;
    uint64_t set;
    uint64_t new_mask;
    uint64_t set_user = context->arguments[1];
    uint64_t old_user = context->arguments[2];
    int result;

    if (context->arguments[3] != sizeof(uint64_t))
        return -EDGE_LINUX_EINVAL;
    result = kernel_current_signal_mask_get(&old_mask);
    if (result < 0) return result;
    if (set_user) {
        if (context->arguments[0] > 2u) return -EDGE_LINUX_EINVAL;
        if (edge_linux_copy_from_user(
                context, &set, set_user, sizeof(set)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (context->arguments[0] == 0u)
            new_mask = old_mask | set;
        else if (context->arguments[0] == 1u)
            new_mask = old_mask & ~set;
        else
            new_mask = set;
        result = kernel_current_signal_mask_set(
            edge_linux_signal_sanitize_mask(new_mask));
        if (result < 0) return result;
    }
    if (old_user && edge_linux_copy_to_user(
            context, old_user, &old_mask, sizeof(old_mask)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_signal_pending(
    edge_linux_syscall_context_t *context) {
    uint64_t pending;
    uint64_t mask;
    int result;
    if (context->arguments[1] != sizeof(uint64_t))
        return -EDGE_LINUX_EINVAL;
    if (!context->arguments[0]) return -EDGE_LINUX_EFAULT;
    result = kernel_current_signal_pending(&pending);
    if (result < 0) return result;
    result = kernel_current_signal_mask_get(&mask);
    if (result < 0) return result;
    pending &= mask;
    return edge_linux_copy_to_user(
        context, context->arguments[0], &pending, sizeof(pending)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int edge_linux_capability_words(uint32_t version) {
    if (version == EDGE_LINUX_CAPABILITY_VERSION_1) return 1;
    if (version == EDGE_LINUX_CAPABILITY_VERSION_2 ||
        version == EDGE_LINUX_CAPABILITY_VERSION_3)
        return 2;
    return 0;
}

static void edge_linux_capability_export(
    struct edge_linux_cap_user_data data[2],
    const linux_capability_state_t *capabilities, int words) {
    memset(data, 0, 2u * sizeof(data[0]));
    data[0].effective = (uint32_t)capabilities->effective;
    data[0].permitted = (uint32_t)capabilities->permitted;
    data[0].inheritable = (uint32_t)capabilities->inheritable;
    if (words == 2) {
        data[1].effective = (uint32_t)(capabilities->effective >> 32);
        data[1].permitted = (uint32_t)(capabilities->permitted >> 32);
        data[1].inheritable =
            (uint32_t)(capabilities->inheritable >> 32);
    }
}

static uint64_t edge_linux_capability_join(
    const struct edge_linux_cap_user_data data[2], int words,
    uint32_t field) {
    uint64_t low;
    uint64_t high = 0;
    if (field == 0u) low = data[0].effective;
    else if (field == 1u) low = data[0].permitted;
    else low = data[0].inheritable;
    if (words == 2) {
        if (field == 0u) high = data[1].effective;
        else if (field == 1u) high = data[1].permitted;
        else high = data[1].inheritable;
    }
    return (low | (high << 32)) & EDGE_LINUX_CAP_FULL_SET;
}

static int edge_linux_capability_header(
    edge_linux_syscall_context_t *context,
    struct edge_linux_cap_user_header *header) {
    if (!context->arguments[0]) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(context, header, context->arguments[0],
                                  sizeof(*header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!edge_linux_capability_words(header->version)) {
        header->version = EDGE_LINUX_CAPABILITY_VERSION_3;
        (void)edge_linux_copy_to_user(context, context->arguments[0], header,
                                      sizeof(*header));
        return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

static int64_t edge_linux_sys_capget(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_cap_user_header header;
    struct edge_linux_cap_user_data data[2];
    kernel_linux_identity_t caller;
    linux_capability_state_t capabilities;
    int32_t target_tid;
    int words;
    int result = edge_linux_capability_header(context, &header);
    if (result < 0) return result;
    if (header.pid < 0) return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (header.pid) {
        if (edge_linux_pid_to_global(&caller, header.pid, &target_tid) < 0)
            return -EDGE_LINUX_ESRCH;
    } else {
        target_tid = caller.global_tid;
    }
    if (kernel_process_capabilities_get(target_tid, &capabilities) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!context->arguments[1]) return 0;
    words = edge_linux_capability_words(header.version);
    edge_linux_capability_export(data, &capabilities, words);
    return edge_linux_copy_to_user(context, context->arguments[1], data,
                                   (uint64_t)words * sizeof(data[0])) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_linux_sys_capset(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_cap_user_header header;
    struct edge_linux_cap_user_data data[2];
    kernel_linux_identity_t caller;
    linux_capability_state_t current;
    linux_capability_state_t requested;
    uint64_t added_inheritable;
    int words;
    int result;
    if (!context->arguments[1]) return -EDGE_LINUX_EFAULT;
    result = edge_linux_capability_header(context, &header);
    if (result < 0) return result;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (header.pid < 0 ||
        (header.pid && header.pid != caller.pid &&
         header.pid != caller.tgid && header.pid != caller.tid))
        return -EDGE_LINUX_EPERM;
    words = edge_linux_capability_words(header.version);
    memset(data, 0, sizeof(data));
    if (edge_linux_copy_from_user(context, data, context->arguments[1],
                                  (uint64_t)words * sizeof(data[0])) < 0)
        return -EDGE_LINUX_EFAULT;
    if (kernel_process_capabilities_get(caller.global_tid, &current) < 0)
        return -EDGE_LINUX_ESRCH;
    requested = current;
    requested.effective = edge_linux_capability_join(data, words, 0u);
    requested.permitted = edge_linux_capability_join(data, words, 1u);
    requested.inheritable = edge_linux_capability_join(data, words, 2u);
    if ((requested.effective & ~requested.permitted) != 0 ||
        (requested.permitted & ~current.permitted) != 0)
        return -EDGE_LINUX_EPERM;
    added_inheritable = requested.inheritable & ~current.inheritable;
    if ((added_inheritable & ~current.bounding) != 0 ||
        ((added_inheritable & ~current.permitted) != 0 &&
         !(current.effective & (1ull << EDGE_LINUX_CAP_SETPCAP))))
        return -EDGE_LINUX_EPERM;
    requested.ambient &= requested.permitted & requested.inheritable;
    return kernel_current_capabilities_set(&requested) < 0 ?
        -EDGE_LINUX_ESRCH : 0;
}

static int64_t edge_linux_credential_error(int result) {
    return result == LINUX_CREDENTIAL_INVALID ?
        -EDGE_LINUX_EINVAL : -EDGE_LINUX_EPERM;
}

static int64_t edge_linux_sys_set_credentials(
    edge_linux_syscall_context_t *context) {
    linux_credential_state_t credentials;
    uint32_t previous;
    int result;
    if (kernel_current_credentials_get(&credentials) < 0)
        return -EDGE_LINUX_ESRCH;
    switch (context->id) {
        case EDGE_LINUX_SYS_setuid:
            result = linux_credentials_setuid(
                &credentials, (uint32_t)context->arguments[0]);
            break;
        case EDGE_LINUX_SYS_setgid:
            result = linux_credentials_setgid(
                &credentials, (uint32_t)context->arguments[0]);
            break;
        case EDGE_LINUX_SYS_setreuid:
            result = linux_credentials_setreuid(
                &credentials, (uint32_t)context->arguments[0],
                (uint32_t)context->arguments[1]);
            break;
        case EDGE_LINUX_SYS_setregid:
            result = linux_credentials_setregid(
                &credentials, (uint32_t)context->arguments[0],
                (uint32_t)context->arguments[1]);
            break;
        case EDGE_LINUX_SYS_setresuid:
            result = linux_credentials_setresuid(
                &credentials, (uint32_t)context->arguments[0],
                (uint32_t)context->arguments[1],
                (uint32_t)context->arguments[2]);
            break;
        case EDGE_LINUX_SYS_setresgid:
            result = linux_credentials_setresgid(
                &credentials, (uint32_t)context->arguments[0],
                (uint32_t)context->arguments[1],
                (uint32_t)context->arguments[2]);
            break;
        case EDGE_LINUX_SYS_setfsuid:
            previous = linux_credentials_setfsuid(
                &credentials, (uint32_t)context->arguments[0]);
            return kernel_current_credentials_set(&credentials) < 0 ?
                -EDGE_LINUX_ESRCH : (int64_t)previous;
        case EDGE_LINUX_SYS_setfsgid:
            previous = linux_credentials_setfsgid(
                &credentials, (uint32_t)context->arguments[0]);
            return kernel_current_credentials_set(&credentials) < 0 ?
                -EDGE_LINUX_ESRCH : (int64_t)previous;
        default:
            return -EDGE_LINUX_ENOSYS;
    }
    if (result != LINUX_CREDENTIAL_OK)
        return edge_linux_credential_error(result);
    return kernel_current_credentials_set(&credentials) < 0 ?
        -EDGE_LINUX_ESRCH : 0;
}

static uint32_t edge_linux_group_page_elements(uint32_t count,
                                               uint32_t page_index) {
    uint32_t offset = page_index * EDGE_LINUX_GROUPS_PER_PAGE;
    uint32_t remaining = count - offset;
    return remaining > EDGE_LINUX_GROUPS_PER_PAGE ?
        EDGE_LINUX_GROUPS_PER_PAGE : remaining;
}

static int edge_linux_group_user_page(uint64_t base, uint32_t page_index,
                                      uint64_t *address) {
    uint64_t offset = (uint64_t)page_index * EDGE_LINUX_GROUP_PAGE_SIZE;
    if (!address || base > UINT64_MAX - offset) return -1;
    *address = base + offset;
    return 0;
}

static int64_t edge_linux_sys_groups(
    edge_linux_syscall_context_t *context) {
    linux_group_list_t groups;
    kernel_linux_identity_t identity;
    uint32_t count;
    uint32_t page_index;
    int64_t result = 0;
    linux_group_list_init(&groups);
    if (context->id == EDGE_LINUX_SYS_getgroups) {
        if (context->arguments[0] > INT32_MAX)
            return -EDGE_LINUX_EINVAL;
        if (kernel_current_groups_snapshot(&groups) < 0)
            return -EDGE_LINUX_ESRCH;
        count = groups.count;
        if (!context->arguments[0]) {
            result = count;
            goto groups_out;
        }
        if (context->arguments[0] < count) {
            result = -EDGE_LINUX_EINVAL;
            goto groups_out;
        }
        if (count && !context->arguments[1]) {
            result = -EDGE_LINUX_EFAULT;
            goto groups_out;
        }
        for (page_index = 0; page_index < groups.page_count; ++page_index) {
            const uint32_t *values = linux_group_list_const_page_values(
                &groups, page_index);
            uint32_t elements = edge_linux_group_page_elements(
                count, page_index);
            uint64_t destination;
            if (!values || edge_linux_group_user_page(
                    context->arguments[1], page_index, &destination) < 0 ||
                edge_linux_copy_to_user(
                    context, destination, values,
                    (uint64_t)elements * sizeof(values[0])) < 0) {
                result = -EDGE_LINUX_EFAULT;
                goto groups_out;
            }
        }
        result = count;
        goto groups_out;
    }

    if (context->id != EDGE_LINUX_SYS_setgroups)
        return -EDGE_LINUX_ENOSYS;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SETGID)))
        return -EDGE_LINUX_EPERM;
    if (context->arguments[0] > EDGE_LINUX_NGROUPS_MAX)
        return -EDGE_LINUX_EINVAL;
    count = (uint32_t)context->arguments[0];
    if (count && !context->arguments[1]) return -EDGE_LINUX_EFAULT;
    if (linux_group_list_allocate(&groups, count) < 0)
        return -EDGE_LINUX_ENOMEM;
    for (page_index = 0; page_index < groups.page_count; ++page_index) {
        uint32_t *values = linux_group_list_page_values(&groups, page_index);
        uint32_t elements = edge_linux_group_page_elements(count, page_index);
        uint64_t source;
        uint32_t element;
        if (!values || edge_linux_group_user_page(
                context->arguments[1], page_index, &source) < 0 ||
            edge_linux_copy_from_user(
                context, values, source,
                (uint64_t)elements * sizeof(values[0])) < 0) {
            result = -EDGE_LINUX_EFAULT;
            goto groups_out;
        }
        for (element = 0; element < elements; ++element) {
            if (values[element] == UINT32_MAX) {
                result = -EDGE_LINUX_EINVAL;
                goto groups_out;
            }
        }
    }
    linux_group_list_sort(&groups);
    if (kernel_current_groups_replace(&groups) < 0)
        result = -EDGE_LINUX_ESRCH;

groups_out:
    linux_group_list_release(&groups);
    return result;
}

static int edge_linux_nice_matches(
    const kernel_process_control_t *target, int which, uint32_t selector) {
    if (which == EDGE_LINUX_PRIO_PROCESS)
        return (uint32_t)target->tid == selector;
    if (which == EDGE_LINUX_PRIO_PGRP)
        return (uint32_t)target->pgid == selector;
    if (which == EDGE_LINUX_PRIO_USER)
        return target->uid == selector;
    return 0;
}

static int edge_linux_nice_selector(
    const kernel_linux_identity_t *caller, int which, uint32_t who,
    uint32_t *selector) {
    if (!caller || !selector) return -EDGE_LINUX_EINVAL;
    if (which == EDGE_LINUX_PRIO_PROCESS)
        *selector = who ? who : (uint32_t)caller->tid;
    else if (which == EDGE_LINUX_PRIO_PGRP)
        *selector = who ? who : (uint32_t)caller->pgid;
    else if (which == EDGE_LINUX_PRIO_USER)
        *selector = who ? who : caller->uid;
    else
        return -EDGE_LINUX_EINVAL;
    return 0;
}

static int64_t edge_linux_sys_getpriority(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_process_control_t target;
    uint32_t selector;
    uint32_t cursor = 0;
    int which = (int32_t)(uint32_t)context->arguments[0];
    int best = 20;
    int matched = 0;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (edge_linux_nice_selector(&caller, which,
                                 (uint32_t)context->arguments[1],
                                 &selector) < 0)
        return -EDGE_LINUX_EINVAL;
    while (kernel_process_control_next(&cursor, &target) == 0) {
        if (!edge_linux_nice_matches(&target, which, selector)) continue;
        if (!matched || target.nice_value < best)
            best = target.nice_value;
        matched = 1;
    }
    return matched ? 20 - best : -EDGE_LINUX_ESRCH;
}

static int edge_linux_nice_owned(
    const kernel_linux_identity_t *caller,
    const kernel_process_control_t *target) {
    if (caller->effective_capabilities &
        (1ull << EDGE_LINUX_CAP_SYS_NICE))
        return 1;
    return caller->euid == target->uid || caller->euid == target->euid;
}

static int64_t edge_linux_sys_setpriority(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_process_control_t target;
    kernel_resource_limit_t nice_limit;
    uint32_t selector;
    uint32_t cursor = 0;
    uint32_t matched = 0;
    uint32_t applied = 0;
    int which = (int32_t)(uint32_t)context->arguments[0];
    int requested = (int32_t)(uint32_t)context->arguments[2];
    int can_raise;
    if (requested < -20) requested = -20;
    if (requested > 19) requested = 19;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (edge_linux_nice_selector(&caller, which,
                                 (uint32_t)context->arguments[1],
                                 &selector) < 0)
        return -EDGE_LINUX_EINVAL;
    can_raise = (caller.effective_capabilities &
                 (1ull << EDGE_LINUX_CAP_SYS_NICE)) != 0;
    while (kernel_process_control_next(&cursor, &target) == 0) {
        uint64_t required_limit;
        if (!edge_linux_nice_matches(&target, which, selector)) continue;
        ++matched;
        if (!edge_linux_nice_owned(&caller, &target))
            return -EDGE_LINUX_EPERM;
        if (requested >= target.nice_value || can_raise) continue;
        if (kernel_process_resource_limit_get(
                target.tid, EDGE_LINUX_RLIMIT_NICE, &nice_limit) < 0)
            return -EDGE_LINUX_ESRCH;
        required_limit = (uint64_t)(20 - requested);
        if (nice_limit.current != EDGE_LINUX_RLIM_INFINITY &&
            required_limit > nice_limit.current)
            return -EDGE_LINUX_EACCES;
    }
    if (!matched) return -EDGE_LINUX_ESRCH;
    cursor = 0;
    while (kernel_process_control_next(&cursor, &target) == 0) {
        if (!edge_linux_nice_matches(&target, which, selector)) continue;
        if (!edge_linux_nice_owned(&caller, &target))
            return -EDGE_LINUX_EPERM;
        if (kernel_process_nice_set(&target, (int8_t)requested) == 0)
            ++applied;
    }
    return applied ? 0 : -EDGE_LINUX_ESRCH;
}

static int edge_linux_ioprio_matches(
    const kernel_process_control_t *target, uint32_t which,
    uint32_t selector) {
    if (which == EDGE_LINUX_IOPRIO_WHO_PROCESS)
        return (uint32_t)target->tid == selector;
    if (which == EDGE_LINUX_IOPRIO_WHO_PGRP)
        return (uint32_t)target->pgid == selector;
    if (which == EDGE_LINUX_IOPRIO_WHO_USER)
        return target->uid == selector;
    return 0;
}

static int edge_linux_ioprio_selector(
    const kernel_linux_identity_t *caller, uint32_t which, int32_t who,
    uint32_t *selector) {
    if (!caller || !selector || which < EDGE_LINUX_IOPRIO_WHO_PROCESS ||
        which > EDGE_LINUX_IOPRIO_WHO_USER)
        return -EDGE_LINUX_EINVAL;
    if (which == EDGE_LINUX_IOPRIO_WHO_PROCESS)
        *selector = who ? (uint32_t)who : (uint32_t)caller->tid;
    else if (which == EDGE_LINUX_IOPRIO_WHO_PGRP)
        *selector = who ? (uint32_t)who : (uint32_t)caller->pgid;
    else
        *selector = who ? (uint32_t)who : caller->uid;
    return 0;
}

static uint16_t edge_linux_ioprio_effective(
    const kernel_process_control_t *target) {
    uint32_t priority = target->io_priority;
    uint32_t priority_class = priority >> EDGE_LINUX_IOPRIO_CLASS_SHIFT;
    if (priority_class == EDGE_LINUX_IOPRIO_CLASS_NONE) {
        int level = ((int)target->nice_value + 20) / 5;
        if (level < 0) level = 0;
        if (level > 7) level = 7;
        priority = (EDGE_LINUX_IOPRIO_CLASS_BE <<
                    EDGE_LINUX_IOPRIO_CLASS_SHIFT) | (uint32_t)level;
    }
    return (uint16_t)priority;
}

static int edge_linux_ioprio_is_higher(uint16_t candidate,
                                       uint16_t current) {
    uint32_t candidate_class = candidate >> EDGE_LINUX_IOPRIO_CLASS_SHIFT;
    uint32_t current_class = current >> EDGE_LINUX_IOPRIO_CLASS_SHIFT;
    uint32_t candidate_level = candidate & EDGE_LINUX_IOPRIO_LEVEL_MASK;
    uint32_t current_level = current & EDGE_LINUX_IOPRIO_LEVEL_MASK;
    if (candidate_class != current_class)
        return candidate_class < current_class;
    return candidate_level < current_level;
}

static int64_t edge_linux_sys_ioprio_get(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_process_control_t target;
    uint32_t which = (uint32_t)context->arguments[0];
    int32_t who = (int32_t)(uint32_t)context->arguments[1];
    uint32_t selector;
    uint32_t cursor = 0;
    uint16_t best = 0;
    int matched = 0;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (edge_linux_ioprio_selector(&caller, which, who, &selector) < 0)
        return -EDGE_LINUX_EINVAL;
    while (kernel_process_control_next(&cursor, &target) == 0) {
        uint16_t candidate;
        if (!edge_linux_ioprio_matches(&target, which, selector)) continue;
        candidate = which == EDGE_LINUX_IOPRIO_WHO_PROCESS ?
            target.io_priority : edge_linux_ioprio_effective(&target);
        if (!matched || edge_linux_ioprio_is_higher(candidate, best))
            best = candidate;
        matched = 1;
    }
    return matched ? best : -EDGE_LINUX_ESRCH;
}

static int64_t edge_linux_sys_ioprio_set(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_process_control_t target;
    uint32_t which = (uint32_t)context->arguments[0];
    int32_t who = (int32_t)(uint32_t)context->arguments[1];
    uint16_t priority = (uint16_t)(uint32_t)context->arguments[2];
    uint32_t priority_class = priority >> EDGE_LINUX_IOPRIO_CLASS_SHIFT;
    uint32_t priority_level = priority & EDGE_LINUX_IOPRIO_LEVEL_MASK;
    uint32_t selector;
    uint32_t cursor = 0;
    uint32_t matched = 0;
    uint32_t applied = 0;
    int can_change_any;
    if (priority_class > EDGE_LINUX_IOPRIO_CLASS_IDLE ||
        (priority_class == EDGE_LINUX_IOPRIO_CLASS_NONE && priority_level))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (edge_linux_ioprio_selector(&caller, which, who, &selector) < 0)
        return -EDGE_LINUX_EINVAL;
    if (priority_class == EDGE_LINUX_IOPRIO_CLASS_RT &&
        !(caller.effective_capabilities &
          (1ull << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EPERM;
    can_change_any = (caller.effective_capabilities &
                      (1ull << EDGE_LINUX_CAP_SYS_NICE)) != 0;
    while (kernel_process_control_next(&cursor, &target) == 0) {
        if (!edge_linux_ioprio_matches(&target, which, selector)) continue;
        ++matched;
        if (!can_change_any && caller.uid != target.uid &&
            caller.euid != target.uid && caller.euid != target.euid)
            return -EDGE_LINUX_EPERM;
    }
    if (!matched) return -EDGE_LINUX_ESRCH;
    cursor = 0;
    while (kernel_process_control_next(&cursor, &target) == 0) {
        if (!edge_linux_ioprio_matches(&target, which, selector)) continue;
        if (!can_change_any && caller.uid != target.uid &&
            caller.euid != target.uid && caller.euid != target.euid)
            return -EDGE_LINUX_EPERM;
        if (kernel_process_io_priority_set(&target, priority) == 0)
            ++applied;
    }
    return applied ? 0 : -EDGE_LINUX_ESRCH;
}

static int edge_linux_identity_may_adjust(
    const kernel_linux_identity_t *caller,
    const kernel_linux_identity_t *target) {
    uint64_t capability;
    if (!caller || !target) return 0;
    if (caller->tgid == target->tgid) return 1;
    capability = 1ull << EDGE_LINUX_CAP_SYS_RESOURCE;
    if (caller->effective_capabilities & capability) return 1;
    /*
     * Linux compares the caller's real IDs with every real/effective/saved
     * target ID.  The effective and saved IDs of the caller are deliberately
     * irrelevant here; making them part of this check rejects valid prlimit64
     * access after a set-ID transition.
     */
    return caller->uid == target->uid &&
           caller->uid == target->euid &&
           caller->uid == target->suid &&
           caller->gid == target->gid &&
           caller->gid == target->egid &&
           caller->gid == target->sgid;
}

static int64_t edge_linux_sys_resource_limit(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t caller;
    kernel_linux_identity_t target;
    kernel_resource_limit_t old_limit;
    kernel_resource_limit_t new_limit;
    uint64_t old_user = 0;
    uint64_t new_user = 0;
    uint32_t resource;
    int32_t pid;
    int can_raise;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (context->id == EDGE_LINUX_SYS_getrlimit) {
        pid = caller.global_tgid;
        resource = (uint32_t)context->arguments[0];
        old_user = context->arguments[1];
        if (!old_user) return -EDGE_LINUX_EFAULT;
    } else if (context->id == EDGE_LINUX_SYS_setrlimit) {
        pid = caller.global_tgid;
        resource = (uint32_t)context->arguments[0];
        new_user = context->arguments[1];
        if (!new_user) return -EDGE_LINUX_EFAULT;
    } else if (context->id == EDGE_LINUX_SYS_prlimit64) {
        pid = (int32_t)context->arguments[0];
        resource = (uint32_t)context->arguments[1];
        new_user = context->arguments[2];
        old_user = context->arguments[3];
        if (pid < 0) return -EDGE_LINUX_ESRCH;
        if (pid == 0) {
            pid = caller.global_tgid;
        } else if (edge_pid_namespace_visible_to_global(
                       caller.pid_namespace_id, pid, &pid) < 0) {
            return -EDGE_LINUX_ESRCH;
        }
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (resource >= EDGE_LINUX_RLIMIT_COUNT)
        return -EDGE_LINUX_EINVAL;
    if (kernel_process_linux_identity(pid, &target) < 0 ||
        kernel_process_resource_limit_get(pid, resource, &old_limit) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!edge_linux_identity_may_adjust(&caller, &target))
        return -EDGE_LINUX_EPERM;
    can_raise = (caller.effective_capabilities &
                 (1ull << EDGE_LINUX_CAP_SYS_RESOURCE)) != 0;
    if (new_user) {
        struct edge_linux_rlimit64 replacement;
        if (edge_linux_copy_from_user(context, &replacement, new_user,
                                      sizeof(replacement)) < 0)
            return -EDGE_LINUX_EFAULT;
        new_limit.current = replacement.rlim_cur;
        new_limit.maximum = replacement.rlim_max;
        if (new_limit.current > new_limit.maximum)
            return -EDGE_LINUX_EINVAL;
        if (new_limit.maximum > kernel_resource_limit_ceiling(resource))
            return -EDGE_LINUX_EPERM;
        if (new_limit.maximum > old_limit.maximum && !can_raise)
            return -EDGE_LINUX_EPERM;
        if (kernel_process_resource_limit_set(pid, resource, &new_limit) < 0)
            return -EDGE_LINUX_ESRCH;
    }
    if (old_user) {
        struct edge_linux_rlimit64 result = {
            .rlim_cur = old_limit.current,
            .rlim_max = old_limit.maximum,
        };
        if (edge_linux_copy_to_user(context, old_user, &result,
                                    sizeof(result)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return 0;
}

static void edge_linux_rusage_from_kernel(
    const kernel_process_usage_t *source,
    struct edge_linux_rusage64 *destination) {
    memset(destination, 0, sizeof(*destination));
    destination->ru_utime.tv_sec =
        (int64_t)(source->user_time_us / 1000000u);
    destination->ru_utime.tv_usec =
        (int64_t)(source->user_time_us % 1000000u);
    destination->ru_stime.tv_sec =
        (int64_t)(source->sys_time_us / 1000000u);
    destination->ru_stime.tv_usec =
        (int64_t)(source->sys_time_us % 1000000u);
    destination->ru_maxrss = (int64_t)source->maxrss_kb;
    destination->ru_minflt = (int64_t)source->minor_faults;
    destination->ru_majflt = (int64_t)source->major_faults;
    destination->ru_inblock = (int64_t)source->input_blocks;
    destination->ru_oublock = (int64_t)source->output_blocks;
    destination->ru_nvcsw =
        (int64_t)source->voluntary_ctxt_switches;
    destination->ru_nivcsw =
        (int64_t)source->involuntary_ctxt_switches;
}

static int edge_linux_wait_status_code(uint32_t status,
                                       int32_t *reported_status) {
    if (status == 0xffffu) {
        *reported_status = EDGE_LINUX_SIGCONT;
        return EDGE_LINUX_CLD_CONTINUED;
    }
    if ((status & 0xffu) == 0x7fu) {
        *reported_status = (int32_t)((status >> 8) & 0xffu);
        return (status >> 16) ? EDGE_LINUX_CLD_TRAPPED :
                                EDGE_LINUX_CLD_STOPPED;
    }
    if (status & 0x7fu) {
        *reported_status = (int32_t)(status & 0x7fu);
        return (status & 0x80u) ? EDGE_LINUX_CLD_DUMPED :
                                  EDGE_LINUX_CLD_KILLED;
    }
    *reported_status = (int32_t)((status >> 8) & 0xffu);
    return EDGE_LINUX_CLD_EXITED;
}

static int64_t edge_linux_sys_wait(
    edge_linux_syscall_context_t *context) {
    const uint32_t common_options =
        EDGE_LINUX_WNOHANG | EDGE_LINUX_WUNTRACED |
        EDGE_LINUX_WCONTINUED | EDGE_LINUX___WNOTHREAD |
        EDGE_LINUX___WALL | EDGE_LINUX___WCLONE;
    kernel_process_wait_request_t request;
    kernel_process_wait_result_t result;
    kernel_linux_identity_t caller;
    uint64_t status_user = 0;
    uint64_t information_user = 0;
    uint64_t usage_user;
    uint32_t options;
    int pidfd_nonblocking = 0;
    int selector_is_global = 0;
    int64_t wait_status;

    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    memset(&request, 0, sizeof(request));
    memset(&result, 0, sizeof(result));
    request.pid_namespace_id = caller.pid_namespace_id;
    options = (uint32_t)(context->id == EDGE_LINUX_SYS_wait4 ?
                         context->arguments[2] : context->arguments[3]);
    if (context->id == EDGE_LINUX_SYS_wait4) {
        if (options & ~common_options) return -EDGE_LINUX_EINVAL;
        request.selector = (int32_t)context->arguments[0];
        request.flags = KERNEL_PROCESS_WAIT_EXITED;
        status_user = context->arguments[1];
        usage_user = context->arguments[3];
    } else if (context->id == EDGE_LINUX_SYS_waitid) {
        uint32_t id_type = (uint32_t)context->arguments[0];
        uint64_t id = context->arguments[1];
        uint32_t pidfd_flags = 0;
        int32_t pidfd_pid;

        if (options & ~(common_options | EDGE_LINUX_WEXITED |
                        EDGE_LINUX_WNOWAIT))
            return -EDGE_LINUX_EINVAL;
        if (!(options & (EDGE_LINUX_WEXITED | EDGE_LINUX_WUNTRACED |
                         EDGE_LINUX_WCONTINUED)))
            return -EDGE_LINUX_EINVAL;
        if (id_type == EDGE_LINUX_WAIT_P_ALL) {
            request.selector = -1;
        } else if (id_type == EDGE_LINUX_WAIT_P_PID) {
            if (!id || id > INT32_MAX) return -EDGE_LINUX_EINVAL;
            request.selector = (int32_t)id;
        } else if (id_type == EDGE_LINUX_WAIT_P_PGID) {
            if (id > INT32_MAX) return -EDGE_LINUX_EINVAL;
            if (!id) {
                request.selector = 0;
            } else {
                request.selector = -(int32_t)id;
            }
        } else if (id_type == EDGE_LINUX_WAIT_P_PIDFD) {
            if (id > INT32_MAX) return -EDGE_LINUX_EBADF;
            wait_status = kernel_pidfd_target(
                (int32_t)id, &pidfd_pid, &pidfd_flags);
            if (wait_status < 0) return wait_status;
            request.selector = pidfd_pid;
            selector_is_global = 1;
            pidfd_nonblocking =
                (pidfd_flags & EDGE_LINUX_PIDFD_NONBLOCK) != 0;
        } else {
            return -EDGE_LINUX_EINVAL;
        }
        if (options & EDGE_LINUX_WEXITED)
            request.flags |= KERNEL_PROCESS_WAIT_EXITED;
        if (options & EDGE_LINUX_WNOWAIT)
            request.flags |= KERNEL_PROCESS_WAIT_NOREAP;
        information_user = context->arguments[2];
        usage_user = context->arguments[4];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }

    if (options & EDGE_LINUX_WNOHANG)
        request.flags |= KERNEL_PROCESS_WAIT_NOHANG;
    if (options & EDGE_LINUX_WUNTRACED)
        request.flags |= KERNEL_PROCESS_WAIT_STOPPED;
    if (options & EDGE_LINUX_WCONTINUED)
        request.flags |= KERNEL_PROCESS_WAIT_CONTINUED;
    if (options & EDGE_LINUX___WNOTHREAD)
        request.flags |= KERNEL_PROCESS_WAIT_NOTHREAD;
    if (options & EDGE_LINUX___WALL)
        request.flags |= KERNEL_PROCESS_WAIT_WALL;
    if (options & EDGE_LINUX___WCLONE)
        request.flags |= KERNEL_PROCESS_WAIT_WCLONE;
    if (pidfd_nonblocking)
        request.flags |= KERNEL_PROCESS_WAIT_NOHANG;

    if (!selector_is_global && request.selector > 0) {
        if (edge_linux_pid_to_global(
                &caller, request.selector, &request.selector) < 0)
            return -EDGE_LINUX_ECHILD;
    } else if (!selector_is_global && request.selector < -1) {
        if (request.selector == INT32_MIN)
            return -EDGE_LINUX_ESRCH;
        int32_t visible_group = -request.selector;
        int32_t global_group;
        if (edge_linux_pid_to_global(
                &caller, visible_group, &global_group) < 0)
            return -EDGE_LINUX_ECHILD;
        request.selector = -global_group;
    }

    wait_status = kernel_process_wait(
        &request, &result, context->user_registers);
    if (wait_status < 0) return wait_status;
    if (!wait_status) {
        if (pidfd_nonblocking && !(options & EDGE_LINUX_WNOHANG))
            return -EDGE_LINUX_EAGAIN;
        if (information_user) {
            struct edge_linux_siginfo_child information;
            memset(&information, 0, sizeof(information));
            if (edge_linux_copy_to_user(
                    context, information_user, &information,
                    sizeof(information)) < 0)
                return -EDGE_LINUX_EFAULT;
        }
        return 0;
    }
    if (context->id == EDGE_LINUX_SYS_wait4) {
        if (status_user && edge_linux_copy_to_user(
                context, status_user, &result.status,
                sizeof(result.status)) < 0)
            return -EDGE_LINUX_EFAULT;
    } else if (information_user) {
        struct edge_linux_siginfo_child information;
        memset(&information, 0, sizeof(information));
        information.signal_number = EDGE_LINUX_SIGCHLD;
        information.code = edge_linux_wait_status_code(
            result.status, &information.status);
        information.pid = result.pid;
        information.uid = result.uid;
        information.user_time =
            (int64_t)(result.usage.user_time_us / 10000u);
        information.system_time =
            (int64_t)(result.usage.sys_time_us / 10000u);
        if (edge_linux_copy_to_user(
                context, information_user, &information,
                sizeof(information)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    if (usage_user) {
        struct edge_linux_rusage64 usage;
        edge_linux_rusage_from_kernel(&result.usage, &usage);
        if (edge_linux_copy_to_user(
                context, usage_user, &usage, sizeof(usage)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return context->id == EDGE_LINUX_SYS_wait4 ? result.pid : 0;
}

static int64_t edge_linux_sys_getrusage(
    edge_linux_syscall_context_t *context) {
    kernel_process_usage_t usage;
    struct edge_linux_rusage64 result;
    int who = (int32_t)context->arguments[0];
    uint64_t destination = context->arguments[1];
    if (who != EDGE_LINUX_RUSAGE_SELF &&
        who != EDGE_LINUX_RUSAGE_CHILDREN &&
        who != EDGE_LINUX_RUSAGE_THREAD)
        return -EDGE_LINUX_EINVAL;
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (kernel_process_usage(who, &usage) < 0)
        return -EDGE_LINUX_ESRCH;
    edge_linux_rusage_from_kernel(&usage, &result);
    return edge_linux_copy_to_user(context, destination, &result,
                                   sizeof(result)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_linux_sys_times(
    edge_linux_syscall_context_t *context) {
    kernel_process_times_t times;
    struct edge_linux_tms64 result;
    if (kernel_process_times(&times) < 0)
        return -EDGE_LINUX_ESRCH;
    result.tms_utime = (int64_t)times.user_ticks;
    result.tms_stime = (int64_t)times.system_ticks;
    result.tms_cutime = (int64_t)times.children_user_ticks;
    result.tms_cstime = (int64_t)times.children_system_ticks;
    if (context->arguments[0] &&
        edge_linux_copy_to_user(context, context->arguments[0], &result,
                                sizeof(result)) < 0)
        return -EDGE_LINUX_EFAULT;
    return (int64_t)times.elapsed_ticks;
}

typedef struct edge_linux_scheduler_target {
    int32_t tid;
    kernel_linux_identity_t identity;
    edge_linux_scheduler_state_t state;
} edge_linux_scheduler_target_t;

static int edge_linux_scheduler_target_lookup(
    int32_t pid, int negative_errno,
    edge_linux_scheduler_target_t *target) {
    kernel_linux_identity_t caller;
    int32_t global_tid;

    if (!target) return -EDGE_LINUX_EINVAL;
    if (pid < 0) return -negative_errno;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!pid) {
        global_tid = caller.global_tid;
    } else if (edge_linux_pid_to_global(
                   &caller, pid, &global_tid) < 0) {
        return -EDGE_LINUX_ESRCH;
    }
    target->tid = global_tid;
    if (kernel_process_linux_identity(target->tid, &target->identity) < 0 ||
        kernel_scheduler_state_get(target->tid, &target->state) < 0)
        return -EDGE_LINUX_ESRCH;
    return 0;
}

static int edge_linux_scheduler_target_owned(
    const kernel_linux_identity_t *caller,
    const kernel_linux_identity_t *target) {
    if (caller->effective_capabilities &
        (1ull << EDGE_LINUX_CAP_SYS_NICE))
        return 1;
    return caller->euid == target->uid ||
           caller->euid == target->euid ||
           caller->euid == target->suid;
}

static int edge_linux_scheduler_policy_parameters(
    const edge_linux_scheduler_state_t *state) {
    if (state->policy == EDGE_LINUX_SCHED_OTHER ||
        state->policy == EDGE_LINUX_SCHED_BATCH ||
        state->policy == EDGE_LINUX_SCHED_IDLE)
        return state->priority == 0 ? 0 : -EDGE_LINUX_EINVAL;
    if (edge_linux_scheduler_policy_is_realtime(state->policy))
        return state->priority >= 1u && state->priority <= 99u ?
            0 : -EDGE_LINUX_EINVAL;
    if (state->policy == EDGE_LINUX_SCHED_DEADLINE) {
        uint64_t period = state->period ? state->period : state->deadline;

        return state->priority == 0 && state->runtime && state->deadline &&
               period && state->runtime <= state->deadline &&
               state->deadline <= period ? 0 : -EDGE_LINUX_EINVAL;
    }
    if (state->policy == EDGE_LINUX_SCHED_EXT)
        return -EDGE_LINUX_EOPNOTSUPP;
    return -EDGE_LINUX_EINVAL;
}

static int edge_linux_scheduler_policy_permitted(
    const kernel_linux_identity_t *caller,
    const edge_linux_scheduler_target_t *target,
    const edge_linux_scheduler_state_t *requested) {
    kernel_resource_limit_t limit;
    uint32_t ceiling;
    if (!edge_linux_scheduler_target_owned(caller, &target->identity))
        return -EDGE_LINUX_EPERM;
    if ((target->state.flags & EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK) &&
        !(requested->flags & EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK) &&
        !(caller->effective_capabilities &
          (1ull << EDGE_LINUX_CAP_SYS_NICE)))
        return -EDGE_LINUX_EPERM;
    if (caller->effective_capabilities &
        (1ull << EDGE_LINUX_CAP_SYS_NICE))
        return 0;
    if (requested->policy == EDGE_LINUX_SCHED_DEADLINE)
        return -EDGE_LINUX_EPERM;
    if (!edge_linux_scheduler_policy_is_realtime(requested->policy))
        return 0;
    if (kernel_process_resource_limit_get(
            target->tid, EDGE_LINUX_RLIMIT_RTPRIO, &limit) < 0)
        return -EDGE_LINUX_ESRCH;
    ceiling = limit.current > 99u ? 99u : (uint32_t)limit.current;
    if (edge_linux_scheduler_policy_is_realtime(target->state.policy) &&
        target->state.priority > ceiling)
        ceiling = target->state.priority;
    return requested->priority <= ceiling ? 0 : -EDGE_LINUX_EPERM;
}

static int edge_linux_scheduler_nice_permitted(
    const kernel_linux_identity_t *caller,
    const edge_linux_scheduler_target_t *target, int32_t requested) {
    kernel_resource_limit_t limit;
    uint64_t required;
    if (!edge_linux_scheduler_target_owned(caller, &target->identity))
        return -EDGE_LINUX_EPERM;
    if (requested >= target->state.nice ||
        (caller->effective_capabilities &
         (1ull << EDGE_LINUX_CAP_SYS_NICE)))
        return 0;
    if (kernel_process_resource_limit_get(
            target->tid, EDGE_LINUX_RLIMIT_NICE, &limit) < 0)
        return -EDGE_LINUX_ESRCH;
    required = (uint64_t)(20 - requested);
    return limit.current == EDGE_LINUX_RLIM_INFINITY ||
           required <= limit.current ? 0 : -EDGE_LINUX_EPERM;
}

static int edge_linux_scheduler_apply(
    const kernel_linux_identity_t *caller,
    edge_linux_scheduler_target_t *target,
    const edge_linux_scheduler_state_t *requested,
    uint32_t update_mask) {
    kernel_scheduler_target_t commit_target;
    int result;
    if (update_mask & EDGE_SCHEDULER_UPDATE_POLICY) {
        result = edge_linux_scheduler_policy_parameters(requested);
        if (result < 0) return result;
        result = edge_linux_scheduler_policy_permitted(caller, target,
                                                        requested);
        if (result < 0) return result;
    }
    if (update_mask & EDGE_SCHEDULER_UPDATE_NICE) {
        result = edge_linux_scheduler_nice_permitted(
            caller, target, requested->nice);
        if (result < 0) return result;
    }
    commit_target.tid = target->tid;
    commit_target.tgid = target->identity.tgid;
    commit_target.uid = target->identity.uid;
    commit_target.euid = target->identity.euid;
    commit_target.suid = target->identity.suid;
    commit_target.state = target->state;
    result = kernel_scheduler_state_set(&commit_target, requested,
                                        update_mask);
    if (result == -2) return -EDGE_LINUX_EBUSY;
    if (result < 0) return -EDGE_LINUX_ESRCH;
    target->state = *requested;
    return 0;
}

static int64_t edge_linux_sys_sched_affinity(
    edge_linux_syscall_context_t *context) {
    edge_linux_scheduler_target_t target;
    kernel_scheduler_target_t commit_target;
    kernel_linux_identity_t caller;
    uint64_t size = context->arguments[1];
    uint64_t user_mask = context->arguments[2];
    uint64_t mask = 0;
    uint64_t online;
    int result;
    if (context->id == EDGE_LINUX_SYS_sched_getaffinity) {
        if (size < sizeof(mask)) return -EDGE_LINUX_EINVAL;
        result = edge_linux_scheduler_target_lookup(
            (int32_t)(uint32_t)context->arguments[0], EDGE_LINUX_ESRCH,
            &target);
        if (result < 0) return result;
        if (!user_mask) return -EDGE_LINUX_EFAULT;
        online = kernel_scheduler_online_cpu_mask();
        mask = target.state.affinity_mask & online;
        if (!mask) mask = online;
        if (edge_linux_copy_to_user(context, user_mask, &mask,
                                    sizeof(mask)) < 0)
            return -EDGE_LINUX_EFAULT;
        return sizeof(mask);
    }

    if (!size) return -EDGE_LINUX_EINVAL;
    if (!user_mask) return -EDGE_LINUX_EFAULT;
    result = edge_linux_scheduler_target_lookup(
        (int32_t)(uint32_t)context->arguments[0], EDGE_LINUX_ESRCH,
        &target);
    if (result < 0) return result;
    if (edge_linux_copy_from_user(context, &mask, user_mask,
                                  size < sizeof(mask) ? size : sizeof(mask)) < 0)
        return -EDGE_LINUX_EFAULT;
    /* Linux ignores bytes beyond its internal cpumask width. */
    online = kernel_scheduler_online_cpu_mask();
    mask &= online;
    if (!mask) return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!edge_linux_scheduler_target_owned(&caller, &target.identity))
        return -EDGE_LINUX_EPERM;
    commit_target.tid = target.tid;
    commit_target.tgid = target.identity.tgid;
    commit_target.uid = target.identity.uid;
    commit_target.euid = target.identity.euid;
    commit_target.suid = target.identity.suid;
    commit_target.state = target.state;
    target.state.affinity_mask = mask;
    return kernel_scheduler_state_set(
        &commit_target, &target.state, EDGE_SCHEDULER_UPDATE_AFFINITY) < 0 ?
        -EDGE_LINUX_ESRCH : 0;
}

static int64_t edge_linux_sys_sched_legacy(
    edge_linux_syscall_context_t *context) {
    edge_linux_scheduler_target_t target;
    edge_linux_scheduler_state_t requested;
    kernel_linux_identity_t caller;
    struct edge_linux_sched_param parameter;
    int32_t pid = (int32_t)(uint32_t)context->arguments[0];
    uint64_t parameter_address;
    uint32_t policy;
    int result;
    if (pid < 0) return -EDGE_LINUX_EINVAL;
    result = edge_linux_scheduler_target_lookup(pid, EDGE_LINUX_EINVAL,
                                                &target);
    if (result < 0) return result;
    if (context->id == EDGE_LINUX_SYS_sched_getscheduler) {
        uint32_t returned = target.state.policy;
        if (target.state.flags & EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK)
            returned |= EDGE_LINUX_SCHED_RESET_ON_FORK;
        return returned;
    }
    if (context->id == EDGE_LINUX_SYS_sched_getparam) {
        if (!context->arguments[1]) return -EDGE_LINUX_EINVAL;
        parameter.sched_priority = (int32_t)target.state.priority;
        return edge_linux_copy_to_user(
            context, context->arguments[1], &parameter,
            sizeof(parameter)) < 0 ? -EDGE_LINUX_EFAULT : 0;
    }
    parameter_address = context->id == EDGE_LINUX_SYS_sched_setparam ?
        context->arguments[1] : context->arguments[2];
    if (!parameter_address) return -EDGE_LINUX_EINVAL;
    if (edge_linux_copy_from_user(context, &parameter, parameter_address,
                                  sizeof(parameter)) < 0)
        return -EDGE_LINUX_EFAULT;
    requested = target.state;
    if (context->id == EDGE_LINUX_SYS_sched_setscheduler) {
        policy = (uint32_t)context->arguments[1];
        if (policy & ~(EDGE_LINUX_SCHED_RESET_ON_FORK | 0xffu))
            return -EDGE_LINUX_EINVAL;
        requested.flags &= ~EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK;
        if (policy & EDGE_LINUX_SCHED_RESET_ON_FORK)
            requested.flags |= EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK;
        requested.policy = policy & ~EDGE_LINUX_SCHED_RESET_ON_FORK;
        if (requested.policy != EDGE_LINUX_SCHED_DEADLINE) {
            requested.flags &= ~(EDGE_LINUX_SCHED_FLAG_RECLAIM |
                                 EDGE_LINUX_SCHED_FLAG_DL_OVERRUN);
            requested.runtime = 0;
            requested.deadline = 0;
            requested.period = 0;
        }
    }
    requested.priority = (uint32_t)parameter.sched_priority;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    return edge_linux_scheduler_apply(
        &caller, &target, &requested, EDGE_SCHEDULER_UPDATE_POLICY);
}

static int64_t edge_linux_sys_sched_rr_interval(
    edge_linux_syscall_context_t *context) {
    edge_linux_scheduler_target_t target;
    linux_timespec64_t interval = {0, 0};
    int32_t pid = (int32_t)(uint32_t)context->arguments[0];
    int result;
    if (pid < 0) return -EDGE_LINUX_EINVAL;
    result = edge_linux_scheduler_target_lookup(pid, EDGE_LINUX_EINVAL,
                                                &target);
    if (result < 0) return result;
    if (!context->arguments[1]) return -EDGE_LINUX_EFAULT;
    if (target.state.policy == EDGE_LINUX_SCHED_RR)
        interval.tv_nsec = 10000000;
    return edge_linux_copy_to_user(context, context->arguments[1], &interval,
                                   sizeof(interval)) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_linux_sys_sched_getattr(
    edge_linux_syscall_context_t *context) {
    edge_linux_scheduler_target_t target;
    struct edge_linux_sched_attr attribute;
    uint64_t user_size = context->arguments[2];
    uint64_t copy_size;
    int32_t pid = (int32_t)(uint32_t)context->arguments[0];
    int result;
    if (pid < 0 || context->arguments[3] != 0 ||
        !context->arguments[1] ||
        user_size < EDGE_LINUX_SCHED_ATTR_SIZE_VER0)
        return -EDGE_LINUX_EINVAL;
    result = edge_linux_scheduler_target_lookup(pid, EDGE_LINUX_EINVAL,
                                                &target);
    if (result < 0) return result;
    memset(&attribute, 0, sizeof(attribute));
    copy_size = user_size < sizeof(attribute) ? user_size : sizeof(attribute);
    attribute.size = (uint32_t)copy_size;
    attribute.sched_policy = target.state.policy;
    attribute.sched_flags = target.state.flags &
        (EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK |
         EDGE_LINUX_SCHED_FLAG_RECLAIM |
         EDGE_LINUX_SCHED_FLAG_DL_OVERRUN |
         EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MIN |
         EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MAX);
    attribute.sched_nice = target.state.nice;
    attribute.sched_priority = target.state.priority;
    attribute.sched_runtime = target.state.runtime;
    attribute.sched_deadline = target.state.deadline;
    attribute.sched_period = target.state.period;
    attribute.sched_util_min = target.state.util_min;
    attribute.sched_util_max = target.state.util_max;
    return edge_linux_copy_to_user(context, context->arguments[1], &attribute,
                                   copy_size) < 0 ?
        -EDGE_LINUX_EFAULT : 0;
}

static int64_t edge_linux_sys_sched_setattr(
    edge_linux_syscall_context_t *context) {
    edge_linux_scheduler_target_t target;
    edge_linux_scheduler_state_t requested;
    kernel_linux_identity_t caller;
    struct edge_linux_sched_attr attribute;
    uint32_t user_size;
    uint32_t reported_size = sizeof(attribute);
    uint32_t update_mask = EDGE_SCHEDULER_UPDATE_POLICY;
    uint64_t copy_size;
    int32_t pid = (int32_t)(uint32_t)context->arguments[0];
    int result;
    if (pid < 0 || context->arguments[2] != 0 || !context->arguments[1])
        return -EDGE_LINUX_EINVAL;
    if (edge_linux_copy_from_user(context, &user_size, context->arguments[1],
                                  sizeof(user_size)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!user_size) user_size = EDGE_LINUX_SCHED_ATTR_SIZE_VER0;
    if (user_size < EDGE_LINUX_SCHED_ATTR_SIZE_VER0) {
        (void)edge_linux_copy_to_user(context, context->arguments[1],
                                      &reported_size,
                                      sizeof(reported_size));
        return -EDGE_LINUX_E2BIG;
    }
    memset(&attribute, 0, sizeof(attribute));
    copy_size = user_size < sizeof(attribute) ? user_size : sizeof(attribute);
    if (edge_linux_copy_from_user(context, &attribute, context->arguments[1],
                                  copy_size) < 0)
        return -EDGE_LINUX_EFAULT;
    if (user_size > sizeof(attribute)) {
        result = edge_linux_user_bytes_zero(
            context, context->arguments[1], sizeof(attribute),
            user_size - sizeof(attribute));
        if (result < 0) return result;
        if (result > 0) {
            (void)edge_linux_copy_to_user(context, context->arguments[1],
                                          &reported_size,
                                          sizeof(reported_size));
            return -EDGE_LINUX_E2BIG;
        }
    }
    if (attribute.sched_flags & ~EDGE_LINUX_SCHED_FLAG_ALL)
        return -EDGE_LINUX_EINVAL;
    result = edge_linux_scheduler_target_lookup(pid, EDGE_LINUX_EINVAL,
                                                &target);
    if (result < 0) return result;
    requested = target.state;
    if (!(attribute.sched_flags & EDGE_LINUX_SCHED_FLAG_KEEP_POLICY))
        requested.policy = attribute.sched_policy;
    if (!(attribute.sched_flags & EDGE_LINUX_SCHED_FLAG_KEEP_PARAMS)) {
        if (attribute.sched_nice < -20 || attribute.sched_nice > 19)
            return -EDGE_LINUX_EINVAL;
        requested.nice = attribute.sched_nice;
        requested.priority = attribute.sched_priority;
        requested.runtime = attribute.sched_runtime;
        requested.deadline = attribute.sched_deadline;
        requested.period = attribute.sched_period;
        update_mask |= EDGE_SCHEDULER_UPDATE_NICE;
    }
    requested.flags &= ~(EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK |
                         EDGE_LINUX_SCHED_FLAG_RECLAIM |
                         EDGE_LINUX_SCHED_FLAG_DL_OVERRUN);
    requested.flags |= attribute.sched_flags &
        (EDGE_LINUX_SCHED_FLAG_RESET_ON_FORK |
         EDGE_LINUX_SCHED_FLAG_RECLAIM |
         EDGE_LINUX_SCHED_FLAG_DL_OVERRUN);
    if (attribute.sched_flags & EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MIN) {
        requested.util_min = attribute.sched_util_min;
        requested.flags |= EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MIN;
        update_mask |= EDGE_SCHEDULER_UPDATE_UTILIZATION;
    }
    if (attribute.sched_flags & EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MAX) {
        requested.util_max = attribute.sched_util_max;
        requested.flags |= EDGE_LINUX_SCHED_FLAG_UTIL_CLAMP_MAX;
        update_mask |= EDGE_SCHEDULER_UPDATE_UTILIZATION;
    }
    if (requested.util_min > EDGE_LINUX_SCHED_UTIL_SCALE ||
        requested.util_max > EDGE_LINUX_SCHED_UTIL_SCALE ||
        requested.util_min > requested.util_max)
        return -EDGE_LINUX_EINVAL;
    if ((attribute.sched_flags & (EDGE_LINUX_SCHED_FLAG_RECLAIM |
                                  EDGE_LINUX_SCHED_FLAG_DL_OVERRUN)) &&
        requested.policy != EDGE_LINUX_SCHED_DEADLINE)
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&caller) < 0)
        return -EDGE_LINUX_ESRCH;
    return edge_linux_scheduler_apply(&caller, &target, &requested,
                                      update_mask);
}

static int64_t edge_linux_sys_scheduler(
    edge_linux_syscall_context_t *context) {
    switch (context->id) {
        case EDGE_LINUX_SYS_sched_yield:
            return kernel_scheduler_yield(context->user_registers);
        case EDGE_LINUX_SYS_sched_getaffinity:
        case EDGE_LINUX_SYS_sched_setaffinity:
            return edge_linux_sys_sched_affinity(context);
        case EDGE_LINUX_SYS_sched_getparam:
        case EDGE_LINUX_SYS_sched_setparam:
        case EDGE_LINUX_SYS_sched_getscheduler:
        case EDGE_LINUX_SYS_sched_setscheduler:
            return edge_linux_sys_sched_legacy(context);
        case EDGE_LINUX_SYS_sched_rr_get_interval:
            return edge_linux_sys_sched_rr_interval(context);
        case EDGE_LINUX_SYS_sched_getattr:
            return edge_linux_sys_sched_getattr(context);
        case EDGE_LINUX_SYS_sched_setattr:
            return edge_linux_sys_sched_setattr(context);
        default:
            return -EDGE_LINUX_ENOSYS;
    }
}

typedef enum edge_linux_xattr_operation {
    EDGE_LINUX_XATTR_SET = 1,
    EDGE_LINUX_XATTR_GET,
    EDGE_LINUX_XATTR_LIST,
    EDGE_LINUX_XATTR_REMOVE,
} edge_linux_xattr_operation_t;

typedef char edge_linux_xattr_name_limit_matches_vfs[
    EDGE_LINUX_XATTR_NAME_MAX == VFS_XATTR_NAME_MAX ? 1 : -1];
typedef char edge_linux_xattr_value_limit_matches_vfs[
    EDGE_LINUX_XATTR_VALUE_MAX == VFS_XATTR_VALUE_MAX ? 1 : -1];

static int edge_linux_xattr_has_capability(
    const kernel_linux_identity_t *identity, uint32_t capability) {
    return identity && capability < 64u &&
        (identity->effective_capabilities & (1ULL << capability));
}

static int edge_linux_xattr_has_prefix(const char *name,
                                       const char *prefix,
                                       uint32_t length) {
    return name && prefix && strncmp(name, prefix, length) == 0;
}

static int64_t edge_linux_xattr_result(int result) {
    if (result >= 0) return result;
    switch (result) {
        case VFS_XATTR_ERR_NO_DATA:
            return -EDGE_LINUX_ENODATA;
        case VFS_XATTR_ERR_EXISTS:
            return -EDGE_LINUX_EEXIST;
        case VFS_XATTR_ERR_RANGE:
            return -EDGE_LINUX_ERANGE;
        case VFS_XATTR_ERR_NOSPC:
            return -EDGE_LINUX_ENOSPC;
        case VFS_XATTR_ERR_UNSUPPORTED:
            return -EDGE_LINUX_EOPNOTSUPP;
        case VFS_XATTR_ERR_INVALID:
            return -EDGE_LINUX_EINVAL;
        case VFS_XATTR_ERR_ACCESS:
            return -EDGE_LINUX_EACCES;
        default:
            return -EDGE_LINUX_EIO;
    }
}

static edge_linux_xattr_operation_t edge_linux_xattr_operation(
    edge_linux_syscall_id_t id) {
    switch (id) {
        case EDGE_LINUX_SYS_setxattr:
        case EDGE_LINUX_SYS_lsetxattr:
        case EDGE_LINUX_SYS_fsetxattr:
            return EDGE_LINUX_XATTR_SET;
        case EDGE_LINUX_SYS_getxattr:
        case EDGE_LINUX_SYS_lgetxattr:
        case EDGE_LINUX_SYS_fgetxattr:
            return EDGE_LINUX_XATTR_GET;
        case EDGE_LINUX_SYS_listxattr:
        case EDGE_LINUX_SYS_llistxattr:
        case EDGE_LINUX_SYS_flistxattr:
            return EDGE_LINUX_XATTR_LIST;
        case EDGE_LINUX_SYS_removexattr:
        case EDGE_LINUX_SYS_lremovexattr:
        case EDGE_LINUX_SYS_fremovexattr:
            return EDGE_LINUX_XATTR_REMOVE;
        default:
            return 0;
    }
}

static int edge_linux_xattr_uses_fd(edge_linux_syscall_id_t id) {
    return id == EDGE_LINUX_SYS_fsetxattr ||
        id == EDGE_LINUX_SYS_fgetxattr ||
        id == EDGE_LINUX_SYS_flistxattr ||
        id == EDGE_LINUX_SYS_fremovexattr;
}

static int edge_linux_xattr_nofollow(edge_linux_syscall_id_t id) {
    return id == EDGE_LINUX_SYS_lsetxattr ||
        id == EDGE_LINUX_SYS_lgetxattr ||
        id == EDGE_LINUX_SYS_llistxattr ||
        id == EDGE_LINUX_SYS_lremovexattr;
}

static int edge_linux_xattr_resolve(
    edge_linux_syscall_context_t *context,
    const kernel_linux_identity_t *identity,
    kernel_vfs_xattr_scratch_t *scratch, kernel_vfs_target_t *target) {
    int32_t magic_descriptor;
    int magic_status;
    int result;
    if (kernel_vfs_current_xattr_scratch(scratch) < 0 ||
        !scratch->path || scratch->path_capacity < VFS_PATH_MAX ||
        !scratch->value ||
        scratch->value_capacity < EDGE_LINUX_XATTR_VALUE_MAX)
        return -EDGE_LINUX_EIO;
    if (edge_linux_xattr_uses_fd(context->id)) {
        if (context->arguments[0] > INT32_MAX)
            return -EDGE_LINUX_EBADF;
        return kernel_vfs_resolve_fd((int32_t)context->arguments[0], target);
    }
    result = edge_linux_copy_user_string(
        context, context->arguments[0], scratch->path,
        scratch->path_capacity, EDGE_LINUX_ENAMETOOLONG);
    if (result < 0) return result;
    if (!scratch->path[0]) return -EDGE_LINUX_ENOENT;
    if (!edge_linux_xattr_nofollow(context->id)) {
        magic_status = edge_linux_current_magic_fd(
            scratch->path, identity, &magic_descriptor);
        if (magic_status < 0) return magic_status;
        if (magic_status > 0)
            return kernel_vfs_resolve_fd(magic_descriptor, target);
    }
    return kernel_vfs_resolve_path(scratch->path,
                                   edge_linux_xattr_nofollow(context->id),
                                   target);
}

static int edge_linux_xattr_copy_name(
    edge_linux_syscall_context_t *context, uint64_t source,
    char name[EDGE_LINUX_XATTR_NAME_MAX + 1u]) {
    int result = edge_linux_copy_user_string(
        context, source, name, EDGE_LINUX_XATTR_NAME_MAX + 1u,
        EDGE_LINUX_ERANGE);
    if (result < 0) return result;
    return name[0] ? 0 : -EDGE_LINUX_ERANGE;
}

static int edge_linux_xattr_mode_access(
    const kernel_linux_identity_t *identity, const vfs_inode_t *inode,
    int write_access) {
    uint16_t bits;
    uint16_t required = write_access ? 2u : 4u;
    if (identity->fsuid == inode->uid) {
        bits = (uint16_t)((inode->mode >> 6) & 7u);
    } else if (identity->fsgid == inode->gid ||
               kernel_current_in_group(inode->gid)) {
        bits = (uint16_t)((inode->mode >> 3) & 7u);
    } else {
        bits = (uint16_t)(inode->mode & 7u);
    }
    if (bits & required) return 0;
    if (edge_linux_xattr_has_capability(identity,
                                        EDGE_LINUX_CAP_DAC_OVERRIDE))
        return 0;
    if (!write_access &&
        edge_linux_xattr_has_capability(identity,
                                        EDGE_LINUX_CAP_DAC_READ_SEARCH))
        return 0;
    return -EDGE_LINUX_EACCES;
}

static int edge_linux_xattr_access(
    const kernel_linux_identity_t *identity, const vfs_inode_t *inode,
    const char *name, int write_access) {
    uint16_t kind;
    if (edge_linux_xattr_has_prefix(name, "trusted.", 8u))
        return edge_linux_xattr_has_capability(
            identity, EDGE_LINUX_CAP_SYS_ADMIN) ? 0 :
            (write_access ? -EDGE_LINUX_EPERM : -EDGE_LINUX_ENODATA);
    if (write_access && strcmp(name, "security.capability") == 0 &&
        !edge_linux_xattr_has_capability(identity,
                                         EDGE_LINUX_CAP_SETFCAP))
        return -EDGE_LINUX_EPERM;
    if (edge_linux_xattr_has_prefix(name, "user.", 5u)) {
        kind = (uint16_t)(inode->mode & 0xf000u);
        if (kind != VFS_INODE_FILE && kind != VFS_INODE_DIR)
            return -EDGE_LINUX_EPERM;
        if (write_access && kind == VFS_INODE_DIR &&
            (inode->mode & 01000u) && identity->fsuid != inode->uid &&
            !edge_linux_xattr_has_capability(identity,
                                             EDGE_LINUX_CAP_FOWNER))
            return -EDGE_LINUX_EPERM;
        return edge_linux_xattr_mode_access(identity, inode, write_access);
    }
    if (write_access &&
        !edge_linux_xattr_has_capability(identity,
                                         EDGE_LINUX_CAP_DAC_OVERRIDE) &&
        vfs_permission_check(inode, 2) < 0)
        return -EDGE_LINUX_EACCES;
    return 0;
}

static int edge_linux_xattr_filter_list(char *list, uint32_t length,
                                        int include_trusted,
                                        uint32_t *filtered_length) {
    uint32_t read_offset = 0;
    uint32_t write_offset = 0;
    while (read_offset < length) {
        uint32_t end = read_offset;
        uint32_t item_length;
        while (end < length && list[end]) ++end;
        if (end == length) return -EDGE_LINUX_EIO;
        item_length = end - read_offset + 1u;
        if (include_trusted ||
            !edge_linux_xattr_has_prefix(list + read_offset,
                                         "trusted.", 8u)) {
            if (write_offset != read_offset)
                memmove(list + write_offset, list + read_offset,
                        item_length);
            write_offset += item_length;
        }
        read_offset += item_length;
    }
    *filtered_length = write_offset;
    return 0;
}

static int64_t edge_linux_xattr_set(
    edge_linux_syscall_context_t *context,
    const kernel_linux_identity_t *identity, kernel_vfs_target_t *target,
    kernel_vfs_xattr_scratch_t *scratch, const char *name) {
    uint64_t size = context->arguments[3];
    uint64_t flags = context->arguments[4];
    int result;
    if (size > EDGE_LINUX_XATTR_VALUE_MAX) return -EDGE_LINUX_E2BIG;
    if ((flags & ~(uint64_t)(VFS_XATTR_CREATE | VFS_XATTR_REPLACE)) ||
        flags == (VFS_XATTR_CREATE | VFS_XATTR_REPLACE))
        return -EDGE_LINUX_EINVAL;
    result = edge_linux_xattr_access(identity, target->inode, name, 1);
    if (result < 0) return result;
    if (size && !context->arguments[2]) return -EDGE_LINUX_EFAULT;
    if (size && edge_linux_copy_from_user(
                    context, scratch->value, context->arguments[2], size) < 0)
        return -EDGE_LINUX_EFAULT;
    return edge_linux_xattr_result(vfs_inode_setxattr(
        target->superblock, target->inode, name, scratch->value,
        (uint32_t)size, (uint32_t)flags));
}

static int64_t edge_linux_xattr_get(
    edge_linux_syscall_context_t *context,
    const kernel_linux_identity_t *identity, kernel_vfs_target_t *target,
    kernel_vfs_xattr_scratch_t *scratch, const char *name) {
    uint64_t destination = context->arguments[2];
    uint64_t size = context->arguments[3];
    int result = edge_linux_xattr_access(identity, target->inode, name, 0);
    if (result < 0) return result;
    result = vfs_inode_getxattr(target->superblock, target->inode, name,
                                scratch->value, scratch->value_capacity);
    if (result < 0) return edge_linux_xattr_result(result);
    if (!destination && !size) return result;
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (size < (uint64_t)result) return -EDGE_LINUX_ERANGE;
    if (result && edge_linux_copy_to_user(
                      context, destination, scratch->value,
                      (uint32_t)result) < 0)
        return -EDGE_LINUX_EFAULT;
    return result;
}

static int64_t edge_linux_xattr_list(
    edge_linux_syscall_context_t *context,
    const kernel_linux_identity_t *identity, kernel_vfs_target_t *target,
    kernel_vfs_xattr_scratch_t *scratch) {
    uint64_t destination = context->arguments[1];
    uint64_t size = context->arguments[2];
    uint32_t length;
    int result = vfs_inode_listxattr(
        target->superblock, target->inode, (char *)scratch->value,
        scratch->value_capacity);
    if (result < 0) return edge_linux_xattr_result(result);
    if (edge_linux_xattr_filter_list(
            (char *)scratch->value, (uint32_t)result,
            edge_linux_xattr_has_capability(identity,
                                            EDGE_LINUX_CAP_SYS_ADMIN),
            &length) < 0)
        return -EDGE_LINUX_EIO;
    if (!destination && !size) return length;
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (size < length) return -EDGE_LINUX_ERANGE;
    if (length && edge_linux_copy_to_user(
                      context, destination, scratch->value, length) < 0)
        return -EDGE_LINUX_EFAULT;
    return length;
}

static int64_t edge_linux_sys_xattr(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    kernel_vfs_xattr_scratch_t scratch;
    kernel_vfs_target_t target;
    edge_linux_xattr_operation_t operation;
    char name[EDGE_LINUX_XATTR_NAME_MAX + 1u];
    int result;
    operation = edge_linux_xattr_operation(context->id);
    if (!operation) return -EDGE_LINUX_ENOSYS;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    result = edge_linux_xattr_resolve(
        context, &identity, &scratch, &target);
    if (result < 0) return result;
    if (operation == EDGE_LINUX_XATTR_LIST)
        return edge_linux_xattr_list(context, &identity, &target, &scratch);
    result = edge_linux_xattr_copy_name(context, context->arguments[1], name);
    if (result < 0) return result;
    if (operation == EDGE_LINUX_XATTR_SET)
        return edge_linux_xattr_set(context, &identity, &target, &scratch,
                                    name);
    if (operation == EDGE_LINUX_XATTR_GET)
        return edge_linux_xattr_get(context, &identity, &target, &scratch,
                                    name);
    result = edge_linux_xattr_access(&identity, target.inode, name, 1);
    if (result < 0) return result;
    return edge_linux_xattr_result(vfs_inode_removexattr(
        target.superblock, target.inode, name));
}

static int64_t edge_linux_sys_file_sync(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_sync_operation_t operation;
    if (context->id == EDGE_LINUX_SYS_sync)
        return vfs_sync_all() < 0 ? -EDGE_LINUX_EIO : 0;
    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    if (context->id == EDGE_LINUX_SYS_fsync) {
        operation = KERNEL_VFS_SYNC_FILE;
    } else if (context->id == EDGE_LINUX_SYS_fdatasync) {
        operation = KERNEL_VFS_SYNC_DATA;
    } else if (context->id == EDGE_LINUX_SYS_syncfs) {
        operation = KERNEL_VFS_SYNC_FILESYSTEM;
    } else if (context->id == EDGE_LINUX_SYS_sync_file_range) {
        if ((int64_t)context->arguments[1] < 0 ||
            (int64_t)context->arguments[2] < 0 ||
            (context->arguments[3] & ~7ULL))
            return -EDGE_LINUX_EINVAL;
        operation = KERNEL_VFS_SYNC_RANGE;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    return kernel_vfs_sync_descriptor((int32_t)context->arguments[0],
                                      operation);
}

static int64_t edge_linux_sys_file_advice(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_descriptor_t descriptor;
    uint64_t length;
    uint32_t advice;
    int result;

    if (context->arguments[0] > INT32_MAX) return -EDGE_LINUX_EBADF;
    result = kernel_vfs_describe_descriptor(
        (int32_t)context->arguments[0], &descriptor);
    if (result < 0) return result;

    if (context->id == EDGE_LINUX_SYS_readahead) {
        if (!descriptor.readable) return -EDGE_LINUX_EBADF;
        if (descriptor.kind == KERNEL_VFS_DESCRIPTOR_MEMORY) return 0;
        if (descriptor.kind != KERNEL_VFS_DESCRIPTOR_REGULAR)
            return -EDGE_LINUX_EINVAL;
        result = vfs_readahead_inode(
            descriptor.superblock, descriptor.inode,
            context->arguments[1], context->arguments[2],
            descriptor.scratch, descriptor.scratch_capacity);
        return result == VFS_READAHEAD_ERR_INVALID ? -EDGE_LINUX_EINVAL :
               result == VFS_READAHEAD_ERR_IO ? -EDGE_LINUX_EIO : 0;
    }
    if (context->id != EDGE_LINUX_SYS_fadvise64)
        return -EDGE_LINUX_ENOSYS;

    length = context->arguments[2];
    advice = (uint32_t)context->arguments[3];
    if ((int64_t)length < 0 || context->arguments[3] > 5u)
        return -EDGE_LINUX_EINVAL;
    if (descriptor.kind == KERNEL_VFS_DESCRIPTOR_PIPE ||
        descriptor.kind == KERNEL_VFS_DESCRIPTOR_TERMINAL ||
        descriptor.kind == KERNEL_VFS_DESCRIPTOR_PSEUDO_TERMINAL)
        return -EDGE_LINUX_ESPIPE;

    /* Linux treats advice as best effort; WILLNEED performs real prefetch. */
    if (advice == 3u &&
        descriptor.kind == KERNEL_VFS_DESCRIPTOR_REGULAR) {
        if (!length) length = UINT64_MAX;
        result = vfs_readahead_inode(
            descriptor.superblock, descriptor.inode,
            context->arguments[1], length,
            descriptor.scratch, descriptor.scratch_capacity);
        if (result == VFS_READAHEAD_ERR_IO) return -EDGE_LINUX_EIO;
        if (result == VFS_READAHEAD_ERR_INVALID)
            return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

struct edge_linux_cachestat_range {
    uint64_t offset;
    uint64_t length;
};

struct edge_linux_cachestat {
    uint64_t cached_pages;
    uint64_t dirty_pages;
    uint64_t writeback_pages;
    uint64_t evicted_pages;
    uint64_t recently_evicted_pages;
};

static int edge_linux_cachestat_access_allowed(
    const kernel_linux_identity_t *identity,
    const kernel_vfs_descriptor_t *descriptor) {
    if (!identity || !descriptor) return 0;
    if (descriptor->writable || !descriptor->inode) return 1;
    if (identity->fsuid == descriptor->inode->uid ||
        (identity->effective_capabilities &
         (1ULL << EDGE_LINUX_CAP_FOWNER)))
        return 1;
    return vfs_permission_check(descriptor->inode, 2) == 0;
}

static int64_t edge_linux_sys_cachestat(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_cachestat_range range;
    struct edge_linux_cachestat result;
    kernel_vfs_cache_stats_t statistics;
    kernel_vfs_descriptor_t descriptor;
    kernel_linux_identity_t identity;
    int32_t fd;
    int status;

    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    fd = (int32_t)context->arguments[0];
    status = kernel_vfs_describe_descriptor(fd, &descriptor);
    if (status < 0) return status;
    if (edge_linux_copy_from_user(
            context, &range, context->arguments[1],
            sizeof(range)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!edge_linux_cachestat_access_allowed(&identity, &descriptor))
        return -EDGE_LINUX_EPERM;
    if ((uint32_t)context->arguments[3] != 0u)
        return -EDGE_LINUX_EINVAL;
    status = kernel_vfs_cachestat(
        fd, range.offset, range.length, &statistics);
    if (status < 0) return status;
    result.cached_pages = statistics.cached_pages;
    result.dirty_pages = statistics.dirty_pages;
    result.writeback_pages = statistics.writeback_pages;
    result.evicted_pages = statistics.evicted_pages;
    result.recently_evicted_pages = statistics.recently_evicted_pages;
    if (edge_linux_copy_to_user(
            context, context->arguments[2], &result,
            sizeof(result)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_fallocate(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_descriptor_t descriptor;
    uint64_t offset = context->arguments[2];
    uint64_t length = context->arguments[3];
    uint64_t end;
    uint32_t mode;
    int result;

    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    result = kernel_vfs_describe_descriptor(
        (int32_t)context->arguments[0], &descriptor);
    if (result < 0) return result;
    if (!descriptor.writable) return -EDGE_LINUX_EBADF;
    if ((int64_t)offset < 0 || (int64_t)length <= 0 ||
        context->arguments[1] > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    end = offset + length;
    if (end < offset ||
        (descriptor.maximum_size && end > descriptor.maximum_size))
        return -EDGE_LINUX_EFBIG;

    if (descriptor.kind == KERNEL_VFS_DESCRIPTOR_PIPE)
        return -EDGE_LINUX_ESPIPE;
    if (descriptor.kind == KERNEL_VFS_DESCRIPTOR_SOCKET ||
        descriptor.kind == KERNEL_VFS_DESCRIPTOR_DEVICE)
        return -EDGE_LINUX_ENODEV;
    if (descriptor.kind != KERNEL_VFS_DESCRIPTOR_REGULAR &&
        descriptor.kind != KERNEL_VFS_DESCRIPTOR_MEMORY)
        return -EDGE_LINUX_EINVAL;
    if (descriptor.kind == KERNEL_VFS_DESCRIPTOR_REGULAR &&
        descriptor.mount_id) {
        vfs_superblock_t *mount =
            vfs_superblock_for_mount_id(descriptor.mount_id);
        if (mount && (mount->mount_flags & VFS_MOUNT_READONLY))
            return -EDGE_LINUX_EROFS;
    }

    mode = (uint32_t)context->arguments[1];
    if ((mode & VFS_FALLOC_FL_PUNCH_HOLE) &&
        mode != (VFS_FALLOC_FL_PUNCH_HOLE | VFS_FALLOC_FL_KEEP_SIZE))
        return -EDGE_LINUX_EOPNOTSUPP;
    if ((mode & VFS_FALLOC_FL_COLLAPSE_RANGE) &&
        mode != VFS_FALLOC_FL_COLLAPSE_RANGE)
        return -EDGE_LINUX_EINVAL;
    if ((mode & VFS_FALLOC_FL_INSERT_RANGE) &&
        mode != VFS_FALLOC_FL_INSERT_RANGE)
        return -EDGE_LINUX_EINVAL;
    if (mode & VFS_FALLOC_FL_ZERO_RANGE) {
        if (mode & ~(VFS_FALLOC_FL_ZERO_RANGE | VFS_FALLOC_FL_KEEP_SIZE))
            return -EDGE_LINUX_EOPNOTSUPP;
    } else if (mode & ~(VFS_FALLOC_FL_KEEP_SIZE |
                        VFS_FALLOC_FL_PUNCH_HOLE |
                        VFS_FALLOC_FL_COLLAPSE_RANGE |
                        VFS_FALLOC_FL_INSERT_RANGE |
                        VFS_FALLOC_FL_UNSHARE_RANGE)) {
        return -EDGE_LINUX_EOPNOTSUPP;
    }

    if ((descriptor.seals & (KERNEL_VFS_SEAL_WRITE |
                             KERNEL_VFS_SEAL_FUTURE_WRITE)) &&
        (mode & (VFS_FALLOC_FL_PUNCH_HOLE |
                 VFS_FALLOC_FL_COLLAPSE_RANGE |
                 VFS_FALLOC_FL_ZERO_RANGE |
                 VFS_FALLOC_FL_INSERT_RANGE)))
        return -EDGE_LINUX_EPERM;
    if ((descriptor.seals & KERNEL_VFS_SEAL_GROW) &&
        ((mode & VFS_FALLOC_FL_INSERT_RANGE) || end > descriptor.size))
        return -EDGE_LINUX_EPERM;
    if ((descriptor.seals & KERNEL_VFS_SEAL_SHRINK) &&
        (mode & VFS_FALLOC_FL_COLLAPSE_RANGE))
        return -EDGE_LINUX_EPERM;

    return kernel_vfs_fallocate_descriptor(
        (int32_t)context->arguments[0], mode, offset, length);
}

static int64_t edge_linux_sys_lseek(
    edge_linux_syscall_context_t *context) {
    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    if (context->arguments[2] > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    return edge_linux_lseek_descriptor(
        (int32_t)context->arguments[0],
        (int64_t)context->arguments[1],
        (uint32_t)context->arguments[2]);
}

#define EDGE_LINUX_RWF_HIPRI     0x00000001u
#define EDGE_LINUX_RWF_DSYNC     0x00000002u
#define EDGE_LINUX_RWF_SYNC      0x00000004u
#define EDGE_LINUX_RWF_NOWAIT    0x00000008u
#define EDGE_LINUX_RWF_APPEND    0x00000010u
#define EDGE_LINUX_RWF_NOAPPEND  0x00000020u
#define EDGE_LINUX_RWF_ATOMIC    0x00000040u
#define EDGE_LINUX_RWF_DONTCACHE 0x00000080u
#define EDGE_LINUX_RWF_NOSIGNAL  0x00000100u

#define EDGE_LINUX_RWF_KNOWN \
    (EDGE_LINUX_RWF_HIPRI | EDGE_LINUX_RWF_DSYNC | \
     EDGE_LINUX_RWF_SYNC | EDGE_LINUX_RWF_NOWAIT | \
     EDGE_LINUX_RWF_APPEND | EDGE_LINUX_RWF_NOAPPEND | \
     EDGE_LINUX_RWF_ATOMIC | EDGE_LINUX_RWF_DONTCACHE | \
     EDGE_LINUX_RWF_NOSIGNAL)

#define EDGE_LINUX_RWF_IMPLEMENTED \
    (EDGE_LINUX_RWF_DSYNC | EDGE_LINUX_RWF_SYNC | \
     EDGE_LINUX_RWF_APPEND | EDGE_LINUX_RWF_NOAPPEND)

static int edge_linux_io_is_write(edge_linux_syscall_id_t id) {
    return id == EDGE_LINUX_SYS_write || id == EDGE_LINUX_SYS_writev ||
           id == EDGE_LINUX_SYS_pwrite64 || id == EDGE_LINUX_SYS_pwritev ||
           id == EDGE_LINUX_SYS_pwritev2;
}

static int edge_linux_io_is_vector(edge_linux_syscall_id_t id) {
    return id == EDGE_LINUX_SYS_readv || id == EDGE_LINUX_SYS_writev ||
           id == EDGE_LINUX_SYS_preadv || id == EDGE_LINUX_SYS_pwritev ||
           id == EDGE_LINUX_SYS_preadv2 || id == EDGE_LINUX_SYS_pwritev2;
}

static int edge_linux_io_is_positioned(edge_linux_syscall_id_t id) {
    return id == EDGE_LINUX_SYS_pread64 || id == EDGE_LINUX_SYS_pwrite64 ||
           id == EDGE_LINUX_SYS_preadv || id == EDGE_LINUX_SYS_pwritev ||
           id == EDGE_LINUX_SYS_preadv2 || id == EDGE_LINUX_SYS_pwritev2;
}

static int edge_linux_io_is_v2(edge_linux_syscall_id_t id) {
    return id == EDGE_LINUX_SYS_preadv2 || id == EDGE_LINUX_SYS_pwritev2;
}

static int edge_linux_io_decode_offset(
    edge_linux_syscall_context_t *context, uint64_t *offset,
    int *use_current) {
    uint64_t low = context->arguments[3];
    uint64_t high = context->arguments[4];

    if (!offset || !use_current) return -EDGE_LINUX_EIO;
    *use_current = 0;
    if (edge_linux_io_is_v2(context->id) && low == UINT64_MAX && !high) {
        *offset = 0;
        *use_current = 1;
        return 0;
    }
    if ((int64_t)low < 0 || high > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    if (high > (UINT64_MAX >> 32)) return -EDGE_LINUX_EINVAL;
    *offset = low | (high << 32);
    if (*offset > INT64_MAX) return -EDGE_LINUX_EINVAL;
    return 0;
}

static int edge_linux_io_decode_flags(
    edge_linux_syscall_context_t *context, uint32_t *flags) {
    uint64_t raw;

    if (!flags) return -EDGE_LINUX_EIO;
    if (!edge_linux_io_is_v2(context->id)) {
        *flags = 0;
        return 0;
    }
    raw = context->arguments[5];
    if (raw > UINT32_MAX || (raw & ~EDGE_LINUX_RWF_KNOWN) ||
        (raw & ~EDGE_LINUX_RWF_IMPLEMENTED))
        return -EDGE_LINUX_EOPNOTSUPP;
    if ((raw & EDGE_LINUX_RWF_APPEND) &&
        (raw & EDGE_LINUX_RWF_NOAPPEND))
        return -EDGE_LINUX_EINVAL;
    *flags = (uint32_t)raw;
    return 0;
}

static kernel_io_operation_t edge_linux_io_operation(
    int writing, int positioned) {
    if (positioned)
        return writing ? KERNEL_IO_WRITE_POSITIONAL :
                         KERNEL_IO_READ_POSITIONAL;
    return writing ? KERNEL_IO_WRITE_CURRENT : KERNEL_IO_READ_CURRENT;
}

static uint32_t edge_linux_io_runtime_flags(uint32_t flags) {
    uint32_t result = 0;
    if (flags & EDGE_LINUX_RWF_APPEND)
        result |= KERNEL_IO_TRANSFER_APPEND;
    if (flags & EDGE_LINUX_RWF_NOAPPEND)
        result |= KERNEL_IO_TRANSFER_NOAPPEND;
    if (flags & EDGE_LINUX_RWF_SYNC)
        result |= KERNEL_IO_TRANSFER_SYNC_FILE;
    else if (flags & EDGE_LINUX_RWF_DSYNC)
        result |= KERNEL_IO_TRANSFER_SYNC_DATA;
    return result;
}

static int64_t edge_linux_sys_scalar_io(
    edge_linux_syscall_context_t *context) {
    kernel_fd_operation_lease_t operation_lease = {0};
    kernel_io_vector_request_t vector_request = {0};
    kernel_io_vector_scratch_t scratch;
    kernel_io_operation_t operation;
    uint64_t length = context->arguments[2];
    uint64_t offset = 0;
    int writing = edge_linux_io_is_write(context->id);
    int positioned = edge_linux_io_is_positioned(context->id);
    int result;

    if (positioned) {
        if ((int64_t)context->arguments[3] < 0)
            return -EDGE_LINUX_EINVAL;
        offset = context->arguments[3];
    }
    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    if (!kernel_fd_operation_vector_io_available())
        return -EDGE_LINUX_EOPNOTSUPP;
    result = kernel_fd_operation_acquire(
        (int32_t)context->arguments[0], &operation_lease);
    if (result < 0) return result;
    operation = edge_linux_io_operation(writing, positioned);
    vector_request.descriptor =
        (int32_t)context->arguments[0];
    vector_request.operation = operation;
    vector_request.validate_only = 1;
    result = (int)kernel_fd_operation_vector_io(
        &operation_lease, &vector_request);
    if (result < 0) {
        (void)kernel_fd_operation_release(&operation_lease);
        return result;
    }
    if (length > EDGE_LINUX_MAX_RW_COUNT)
        length = EDGE_LINUX_MAX_RW_COUNT;
    if (kernel_io_current_vector_scratch(&scratch) < 0 ||
        !scratch.vectors || !scratch.capacity) {
        (void)kernel_fd_operation_release(&operation_lease);
        return -EDGE_LINUX_ENOMEM;
    }
    scratch.vectors[0].iov_base = context->arguments[1];
    scratch.vectors[0].iov_len = length;
    vector_request.vectors = scratch.vectors;
    vector_request.user_registers = context->user_registers;
    vector_request.requested_length = length;
    vector_request.offset = offset;
    vector_request.vector_count = 1;
    /*
     * Linux scalar zero-length operations retain descriptor-specific
     * semantics that a zero-total readv or writev does not.  The retained
     * vector backend therefore needs to know that this one-element request
     * originated from a scalar syscall.
     */
    vector_request.flags = KERNEL_IO_TRANSFER_SCALAR_SYSCALL;
    vector_request.validate_only = 0;
    {
        int64_t transferred = kernel_fd_operation_vector_io(
            &operation_lease, &vector_request);
        (void)kernel_fd_operation_release(&operation_lease);
        return transferred == KERNEL_IO_VECTOR_SCALAR_FALLBACK ?
            -EDGE_LINUX_EIO : transferred;
    }
}

static int64_t edge_linux_sys_vector_io(
    edge_linux_syscall_context_t *context) {
    kernel_fd_operation_lease_t operation_lease = {0};
    kernel_io_vector_request_t vector_request = {0};
    kernel_io_vector_scratch_t scratch;
    kernel_io_operation_t operation;
    uint64_t vector_address = context->arguments[1];
    uint64_t vector_count = context->arguments[2];
    uint64_t offset = 0;
    uint64_t requested = 0;
    uint32_t flags = 0;
    uint32_t runtime_flags;
    int writing = edge_linux_io_is_write(context->id);
    int positioned = edge_linux_io_is_positioned(context->id);
    int use_current = !positioned;
    int result;

    if (positioned) {
        result = edge_linux_io_decode_offset(
            context, &offset, &use_current);
        if (result < 0) return result;
    }
    operation = edge_linux_io_operation(
        writing, positioned && !use_current);
    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    if (!kernel_fd_operation_vector_io_available())
        return -EDGE_LINUX_EOPNOTSUPP;
    result = kernel_fd_operation_acquire(
        (int32_t)context->arguments[0], &operation_lease);
    if (result < 0) return result;
    vector_request.descriptor =
        (int32_t)context->arguments[0];
    /*
     * Linux validates positioned-I/O capability after retaining the file
     * description but before importing the iovec array. Keep the real
     * operation here so a zero-vector preadv/pwritev on a pipe reports
     * ESPIPE, while readv/writev still return zero after access validation.
     */
    vector_request.operation = operation;
    vector_request.validate_only = 1;
    result = (int)kernel_fd_operation_vector_io(
        &operation_lease, &vector_request);
    if (result < 0) {
        (void)kernel_fd_operation_release(&operation_lease);
        return result;
    }
    if (vector_count > EDGE_LINUX_IOV_MAX) {
        (void)kernel_fd_operation_release(&operation_lease);
        return -EDGE_LINUX_EINVAL;
    }
    if (!vector_count) {
        (void)kernel_fd_operation_release(&operation_lease);
        return 0;
    }
    if (!vector_address) {
        (void)kernel_fd_operation_release(&operation_lease);
        return -EDGE_LINUX_EFAULT;
    }
    if (kernel_io_current_vector_scratch(&scratch) < 0 ||
        !scratch.vectors || scratch.capacity < vector_count) {
        (void)kernel_fd_operation_release(&operation_lease);
        return -EDGE_LINUX_ENOMEM;
    }
    if (vector_count > UINT64_MAX / sizeof(scratch.vectors[0]) ||
        edge_linux_copy_from_user(
            context, scratch.vectors, vector_address,
            vector_count * sizeof(scratch.vectors[0])) < 0) {
        (void)kernel_fd_operation_release(&operation_lease);
        return -EDGE_LINUX_EFAULT;
    }

    for (uint64_t index = 0; index < vector_count; ++index) {
        uint64_t length = scratch.vectors[index].iov_len;
        if (requested >= EDGE_LINUX_MAX_RW_COUNT) break;
        if (length > EDGE_LINUX_MAX_RW_COUNT - requested)
            length = EDGE_LINUX_MAX_RW_COUNT - requested;
        requested += length;
    }

    result = edge_linux_io_decode_flags(context, &flags);
    if (result < 0) {
        (void)kernel_fd_operation_release(&operation_lease);
        return result;
    }
    runtime_flags = edge_linux_io_runtime_flags(flags);
    vector_request.vectors = scratch.vectors;
    vector_request.user_registers = context->user_registers;
    vector_request.requested_length = requested;
    vector_request.offset = offset;
    vector_request.vector_count = (uint32_t)vector_count;
    vector_request.operation = operation;
    vector_request.flags = runtime_flags;
    vector_request.validate_only = 0;
    {
        int64_t transferred = kernel_fd_operation_vector_io(
            &operation_lease, &vector_request);
        (void)kernel_fd_operation_release(&operation_lease);
        return transferred == KERNEL_IO_VECTOR_SCALAR_FALLBACK ?
            -EDGE_LINUX_EIO : transferred;
    }
}

static int64_t edge_linux_sys_io(
    edge_linux_syscall_context_t *context) {
    return edge_linux_io_is_vector(context->id) ?
        edge_linux_sys_vector_io(context) :
        edge_linux_sys_scalar_io(context);
}

static int edge_linux_file_range_offset_error(int64_t offset,
                                              uint64_t length) {
    uint64_t magnitude;
    if (offset >= 0) return 0;
    magnitude = (uint64_t)(-(offset + 1)) + 1u;
    return length && length >= magnitude ?
           -EDGE_LINUX_EOVERFLOW : -EDGE_LINUX_EINVAL;
}

static int64_t edge_linux_sys_sendfile(
    edge_linux_syscall_context_t *context) {
    kernel_io_file_range_info_t input;
    kernel_io_file_range_info_t output;
    kernel_io_file_range_scratch_t scratch;
    int32_t input_descriptor;
    int32_t output_descriptor;
    int64_t input_offset = 0;
    uint64_t requested;
    uint64_t transfer_limit;
    uint64_t completed = 0;
    int explicit_offset;
    int status;
    int64_t result = 0;

    explicit_offset = context->arguments[2] != 0;
    if (explicit_offset && edge_linux_copy_from_user(
            context, &input_offset, context->arguments[2],
            sizeof(input_offset)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (context->arguments[0] > INT32_MAX ||
        context->arguments[1] > INT32_MAX) {
        result = -EDGE_LINUX_EBADF;
        goto copy_offset_back;
    }
    output_descriptor = (int32_t)context->arguments[0];
    input_descriptor = (int32_t)context->arguments[1];
    status = kernel_io_file_range_query(input_descriptor, &input);
    if (status < 0) {
        result = status;
        goto copy_offset_back;
    }
    status = kernel_io_file_range_query(output_descriptor, &output);
    if (status < 0) {
        result = status;
        goto copy_offset_back;
    }
    if (!explicit_offset) input_offset = (int64_t)input.offset;
    if (!input.readable) {
        result = -EDGE_LINUX_EBADF;
        goto copy_offset_back;
    }
    if (input.kind != KERNEL_IO_FILE_REGULAR) {
        result = -EDGE_LINUX_EINVAL;
        goto copy_offset_back;
    }
    if (!output.writable) {
        result = -EDGE_LINUX_EBADF;
        goto copy_offset_back;
    }
    if (output.append) {
        result = -EDGE_LINUX_EINVAL;
        goto copy_offset_back;
    }

    requested = context->arguments[3];
    if (input_offset < 0) {
        result = -EDGE_LINUX_EINVAL;
        goto copy_offset_back;
    }
    if (!requested) goto copy_offset_back;
    if (kernel_io_file_range_current_scratch(&scratch) < 0 ||
        !scratch.buffer || !scratch.capacity) {
        result = -EDGE_LINUX_ENOMEM;
        goto copy_offset_back;
    }

    transfer_limit = requested > EDGE_LINUX_MAX_RW_COUNT ?
                     EDGE_LINUX_MAX_RW_COUNT : requested;
    while (completed < transfer_limit) {
        uint64_t remaining = transfer_limit - completed;
        uint32_t chunk = remaining > scratch.capacity ?
                         scratch.capacity : (uint32_t)remaining;
        int64_t read;
        int64_t written;

        if ((uint64_t)input_offset > UINT64_MAX - completed) {
            result = completed ? (int64_t)completed :
                     -EDGE_LINUX_EOVERFLOW;
            break;
        }
        read = kernel_io_file_range_read(
            input_descriptor, (uint64_t)input_offset + completed,
            scratch.buffer, chunk);
        if (read < 0) {
            result = completed ? (int64_t)completed : read;
            break;
        }
        if (!read) {
            result = (int64_t)completed;
            break;
        }
        if ((uint64_t)read > chunk) {
            result = completed ? (int64_t)completed : -EDGE_LINUX_EIO;
            break;
        }
        written = kernel_io_kernel_write_current(
            output_descriptor, scratch.buffer, (uint32_t)read,
            context->user_registers);
        if (written < 0) {
            result = completed ? (int64_t)completed : written;
            break;
        }
        if (!written) {
            result = (int64_t)completed;
            break;
        }
        if (written > read) {
            result = completed ? (int64_t)completed : -EDGE_LINUX_EIO;
            break;
        }
        completed += (uint64_t)written;
        result = (int64_t)completed;
        if (written < read) break;
    }

    if (completed) {
        input_offset += (int64_t)completed;
        if (!explicit_offset)
            (void)kernel_io_file_range_commit_offset(
                input_descriptor, (uint64_t)input_offset);
        kernel_io_file_range_complete_write(output_descriptor);
    }

copy_offset_back:
    if (explicit_offset && edge_linux_copy_to_user(
            context, context->arguments[2], &input_offset,
            sizeof(input_offset)) < 0)
        return -EDGE_LINUX_EFAULT;
    return result;
}

static int64_t edge_linux_sys_copy_file_range(
    edge_linux_syscall_context_t *context) {
    kernel_io_file_range_info_t input;
    kernel_io_file_range_info_t output;
    kernel_io_file_range_scratch_t scratch;
    int32_t input_descriptor;
    int32_t output_descriptor;
    int64_t input_offset;
    int64_t output_offset;
    uint64_t requested;
    uint64_t transfer_limit;
    uint64_t completed = 0;
    int input_explicit;
    int output_explicit;
    int status;
    int copyback_fault = 0;

    if (context->arguments[0] > INT32_MAX ||
        context->arguments[2] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    input_descriptor = (int32_t)context->arguments[0];
    output_descriptor = (int32_t)context->arguments[2];
    status = kernel_io_file_range_query(input_descriptor, &input);
    if (status < 0) return status;
    status = kernel_io_file_range_query(output_descriptor, &output);
    if (status < 0) return status;

    input_explicit = context->arguments[1] != 0;
    output_explicit = context->arguments[3] != 0;
    input_offset = (int64_t)input.offset;
    output_offset = (int64_t)output.offset;
    if (input_explicit && edge_linux_copy_from_user(
            context, &input_offset, context->arguments[1],
            sizeof(input_offset)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (output_explicit && edge_linux_copy_from_user(
            context, &output_offset, context->arguments[3],
            sizeof(output_offset)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (context->arguments[5]) return -EDGE_LINUX_EINVAL;

    if (input.kind == KERNEL_IO_FILE_DIRECTORY ||
        output.kind == KERNEL_IO_FILE_DIRECTORY)
        return -EDGE_LINUX_EISDIR;
    if (input.kind != KERNEL_IO_FILE_REGULAR ||
        output.kind != KERNEL_IO_FILE_REGULAR)
        return -EDGE_LINUX_EINVAL;
    if (!input.readable || !output.writable || output.append)
        return -EDGE_LINUX_EBADF;

    requested = context->arguments[4];
    status = edge_linux_file_range_offset_error(input_offset, requested);
    if (status < 0) return status;
    status = edge_linux_file_range_offset_error(output_offset, requested);
    if (status < 0) return status;
    if (requested > (uint64_t)INT64_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    if ((uint64_t)input_offset > (uint64_t)INT64_MAX - requested ||
        (uint64_t)output_offset > (uint64_t)INT64_MAX - requested)
        return -EDGE_LINUX_EOVERFLOW;
    if (input.filesystem != output.filesystem)
        return -EDGE_LINUX_EXDEV;
    if (requested && input.file == output.file) {
        uint64_t input_start = (uint64_t)input_offset;
        uint64_t output_start = (uint64_t)output_offset;
        if ((input_start <= output_start &&
             output_start - input_start < requested) ||
            (output_start < input_start &&
             input_start - output_start < requested))
            return -EDGE_LINUX_EINVAL;
    }
    if (!requested) return 0;
    if (kernel_io_file_range_current_scratch(&scratch) < 0 ||
        !scratch.buffer || !scratch.capacity)
        return -EDGE_LINUX_ENOMEM;

    transfer_limit = requested > EDGE_LINUX_MAX_RW_COUNT ?
                     EDGE_LINUX_MAX_RW_COUNT : requested;
    while (completed < transfer_limit) {
        uint64_t remaining = transfer_limit - completed;
        uint32_t chunk = remaining > scratch.capacity ?
                         scratch.capacity : (uint32_t)remaining;
        int64_t read;
        int64_t written;
        read = kernel_io_file_range_read(
            input_descriptor, (uint64_t)input_offset + completed,
            scratch.buffer, chunk);
        if (read < 0) {
            if (!completed) return read;
            break;
        }
        if (!read) break;
        if ((uint64_t)read > chunk)
            return completed ? (int64_t)completed : -EDGE_LINUX_EIO;
        written = kernel_io_file_range_write(
            output_descriptor, (uint64_t)output_offset + completed,
            scratch.buffer, (uint32_t)read);
        if (written < 0) {
            if (!completed) return written;
            break;
        }
        if (!written) break;
        if (written > read)
            return completed ? (int64_t)completed : -EDGE_LINUX_EIO;
        completed += (uint64_t)written;
        if (written < read) break;
    }

    if (!completed) return 0;
    input_offset += (int64_t)completed;
    output_offset += (int64_t)completed;
    if (!input_explicit)
        (void)kernel_io_file_range_commit_offset(
            input_descriptor, (uint64_t)input_offset);
    if (!output_explicit)
        (void)kernel_io_file_range_commit_offset(
            output_descriptor, (uint64_t)output_offset);
    kernel_io_file_range_complete_write(output_descriptor);
    if (input_explicit && edge_linux_copy_to_user(
            context, context->arguments[1], &input_offset,
            sizeof(input_offset)) < 0)
        copyback_fault = 1;
    if (output_explicit && edge_linux_copy_to_user(
            context, context->arguments[3], &output_offset,
            sizeof(output_offset)) < 0)
        copyback_fault = 1;
    return copyback_fault ? -EDGE_LINUX_EFAULT : (int64_t)completed;
}

#define EDGE_LINUX_CLOSE_RANGE_UNSHARE 0x0002u
#define EDGE_LINUX_CLOSE_RANGE_CLOEXEC 0x0004u

#define EDGE_LINUX_F_DUPFD         0u
#define EDGE_LINUX_F_GETFD         1u
#define EDGE_LINUX_F_SETFD         2u
#define EDGE_LINUX_F_GETFL         3u
#define EDGE_LINUX_F_SETFL         4u
#define EDGE_LINUX_F_GETLK         5u
#define EDGE_LINUX_F_SETLK         6u
#define EDGE_LINUX_F_SETLKW        7u
#define EDGE_LINUX_F_OFD_GETLK     36u
#define EDGE_LINUX_F_OFD_SETLK     37u
#define EDGE_LINUX_F_OFD_SETLKW    38u
#define EDGE_LINUX_F_DUPFD_CLOEXEC 1030u

#define EDGE_LINUX_O_CREAT     0x00000040u
#define EDGE_LINUX_O_EXCL      0x00000080u
#define EDGE_LINUX_O_NOCTTY    0x00000100u
#define EDGE_LINUX_O_TRUNC     0x00000200u
#define EDGE_LINUX_O_APPEND    0x00000400u
#define EDGE_LINUX_O_NONBLOCK  0x00000800u
#define EDGE_LINUX_O_ASYNC     0x00002000u
#define EDGE_LINUX_O_DIRECTORY 0x00010000u
#define EDGE_LINUX_O_NOFOLLOW  0x00020000u
#define EDGE_LINUX_O_CLOEXEC   0x00080000u
#define EDGE_LINUX_O_PATH      0x00200000u
#define EDGE_LINUX_O_TMPFILE   0x00410000u
#define EDGE_LINUX_O_ACCMODE   0x00000003u
#define EDGE_LINUX_O_RDONLY    0x00000000u
#define EDGE_LINUX_O_WRONLY    0x00000001u
#define EDGE_LINUX_O_RDWR      0x00000002u

#define EDGE_LINUX_FIONCLEX 0x00005450u
#define EDGE_LINUX_FIOCLEX  0x00005451u
#define EDGE_LINUX_FIONBIO  0x00005421u

#define EDGE_LINUX_SETFL_COMMON_MASK \
    (EDGE_LINUX_O_APPEND | EDGE_LINUX_O_NONBLOCK | EDGE_LINUX_O_ASYNC)

#define EDGE_LINUX_GETFL_CLEAR_MASK \
    (EDGE_LINUX_O_CREAT | EDGE_LINUX_O_EXCL | EDGE_LINUX_O_NOCTTY | \
     EDGE_LINUX_O_TRUNC | EDGE_LINUX_O_CLOEXEC)

int64_t kernel_vfs_open_magic_fd(
    const kernel_vfs_open_request_t *request, const char *path,
    int *handled) {
    kernel_vfs_target_t source;
    kernel_linux_identity_t identity;
    int32_t descriptor;
    int32_t executable_owner;
    int access_mask = 0;
    int magic_status;
    int status;

    if (!request || !path || !handled) return -EDGE_LINUX_EFAULT;
    *handled = 0;
    if (request->flags & (KERNEL_VFS_OPEN_NOFOLLOW |
                          KERNEL_VFS_OPEN_TMPFILE))
        return 0;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    magic_status = edge_linux_current_magic_executable(
        path, &identity, &executable_owner);
    if (magic_status > 0) {
        memset(&source, 0, sizeof(source));
        source.inode = &source.inode_storage;
        status = kernel_proc_task_exec_file(
            executable_owner, source.inode, &source.superblock);
        if (status < 0) return status;
        source.resolved_path = path;
        *handled = 1;
        goto validate_source;
    }
    if (magic_status < 0) return magic_status;
    magic_status = edge_linux_current_magic_fd(
        path, &identity, &descriptor);
    if (magic_status <= 0) {
        /*
         * The parser uses ENOENT for numeric proc paths owned by another
         * task before it knows whether the suffix is an fd magic link.
         * Ordinary paths such as /proc/1/cgroup must continue through VFS.
         */
        if (magic_status == -EDGE_LINUX_ENOENT)
            return 0;
        return magic_status < 0 ? magic_status : 0;
    }
    *handled = 1;
    status = kernel_vfs_resolve_fd(descriptor, &source);
    if (status == -EDGE_LINUX_EOPNOTSUPP) return -EDGE_LINUX_ENXIO;
    if (status < 0) return status;
validate_source:
    if (!source.inode || !source.superblock) return -EDGE_LINUX_EBADF;
    if ((request->flags & KERNEL_VFS_OPEN_DIRECTORY) &&
        (source.inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if ((request->flags & (KERNEL_VFS_OPEN_CREATE |
                           KERNEL_VFS_OPEN_EXCLUSIVE)) ==
        (KERNEL_VFS_OPEN_CREATE | KERNEL_VFS_OPEN_EXCLUSIVE))
        return -EDGE_LINUX_EEXIST;
    if ((source.inode->mode & 0xf000u) == VFS_INODE_LNK)
        return -EDGE_LINUX_ELOOP;
    if (!(request->flags & KERNEL_VFS_OPEN_PATH)) {
        if (request->access_mode == EDGE_LINUX_O_RDONLY ||
            request->access_mode == EDGE_LINUX_O_RDWR)
            access_mask |= 4;
        if (request->access_mode == EDGE_LINUX_O_WRONLY ||
            request->access_mode == EDGE_LINUX_O_RDWR ||
            (request->flags & KERNEL_VFS_OPEN_TRUNCATE))
            access_mask |= 2;
        if ((source.inode->mode & 0xf000u) == VFS_INODE_DIR &&
            (access_mask & 2))
            return -EDGE_LINUX_EISDIR;
        if (access_mask && vfs_permission_check(
                source.inode, access_mask) < 0)
            return -EDGE_LINUX_EACCES;
        if ((request->flags & KERNEL_VFS_OPEN_TRUNCATE) &&
            (source.inode->mode & 0xf000u) == VFS_INODE_FILE) {
            status = kernel_vfs_truncate_target(&source, 0);
            if (status < 0) return status;
        }
    }
    if ((source.inode->mode & 0xf000u) == VFS_INODE_FIFO)
        return arch_vfs_reopen_fifo_descriptor(descriptor, request);
    return kernel_vfs_install_inode_descriptor(
        source.superblock, source.inode, request->linux_flags,
        (request->flags & KERNEL_VFS_OPEN_CLOEXEC) ?
            KERNEL_FD_CLOEXEC : 0u,
        source.linkable_zero_link_inode);
}

static int edge_linux_fd_number(uint64_t raw, int32_t *descriptor) {
    uint32_t value = (uint32_t)raw;
    if (!descriptor || value > INT32_MAX) return -EDGE_LINUX_EBADF;
    *descriptor = (int32_t)value;
    return 0;
}

static int64_t edge_linux_fd_duplicate(
    uint64_t source_raw, uint64_t target_raw, int exact,
    uint32_t descriptor_flags) {
    uint32_t limit = kernel_fd_table_limit();
    int32_t source;
    int32_t target;
    int32_t result;
    int status;

    status = edge_linux_fd_number(source_raw, &source);
    if (status < 0) return status;
    if (exact) {
        status = edge_linux_fd_number(target_raw, &target);
        if (status < 0 || (uint32_t)target >= limit)
            return -EDGE_LINUX_EBADF;
    } else {
        if (target_raw > INT32_MAX || target_raw >= limit)
            return -EDGE_LINUX_EINVAL;
        target = (int32_t)target_raw;
    }
    status = kernel_fd_duplicate(source, target, exact,
                                 descriptor_flags, &result);
    return status < 0 ? status : result;
}

static int64_t edge_linux_sys_ioctl(
    edge_linux_syscall_context_t *context) {
    kernel_ioctl_request_t request;
    kernel_namespace_descriptor_t namespace_descriptor;
    kernel_namespace_ioctl_output_t namespace_output;
    int32_t descriptor;
    int enabled;
    int status;

    status = edge_linux_fd_number(context->arguments[0], &descriptor);
    if (status < 0 || !kernel_fd_is_open(descriptor))
        return -EDGE_LINUX_EBADF;
    memset(&request, 0, sizeof(request));
    request.descriptor = descriptor;
    request.command = (uint32_t)context->arguments[1];
    request.argument = context->arguments[2];
    request.user_registers = context->user_registers;
    request.copy_context = context->current_task;
    request.copy_from_user = context->arch_ops->copy_from_user;
    request.copy_to_user = context->arch_ops->copy_to_user;

    if (request.command == EDGE_LINUX_FIOCLEX)
        return kernel_fd_set_descriptor_flags(
            descriptor, KERNEL_FD_CLOEXEC);
    if (request.command == EDGE_LINUX_FIONCLEX)
        return kernel_fd_set_descriptor_flags(descriptor, 0);
    if (request.command == EDGE_LINUX_FIONBIO) {
        /* FIONBIO changes O_NONBLOCK on the shared open description. */
        if (edge_linux_copy_from_user(
                context, &enabled, request.argument,
                sizeof(enabled)) < 0)
            return -EDGE_LINUX_EFAULT;
        return kernel_fd_update_status_flags(
            descriptor, EDGE_LINUX_O_NONBLOCK,
            enabled ? EDGE_LINUX_O_NONBLOCK : 0);
    }
    status = kernel_namespace_descriptor_get(
        descriptor, &namespace_descriptor);
    if (status == -EDGE_LINUX_ENOTTY)
        return kernel_ioctl_execute(&request);
    if (status < 0) return status;
    status = kernel_namespace_ioctl_prepare(
        &namespace_descriptor, request.command,
        request.argument != 0, &namespace_output);
    if (status < 0) return status;
    if (namespace_output.kind ==
        KERNEL_NAMESPACE_IOCTL_COPY_ID) {
        if (!request.argument ||
            edge_linux_copy_to_user(
                context, request.argument,
                &namespace_output.namespace_id,
                sizeof(namespace_output.namespace_id)) < 0)
            return -EDGE_LINUX_EFAULT;
    } else if (namespace_output.kind ==
               KERNEL_NAMESPACE_IOCTL_COPY_OWNER_UID) {
        if (!request.argument ||
            edge_linux_copy_to_user(
                context, request.argument,
                &namespace_output.owner_uid,
                sizeof(namespace_output.owner_uid)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    return namespace_output.result;
}

static int64_t edge_linux_sys_fcntl(
    edge_linux_syscall_context_t *context) {
    uint32_t command = (uint32_t)context->arguments[1];
    uint64_t argument = context->arguments[2];
    int64_t fallback;
    uint32_t flags;
    int32_t descriptor;
    int status;

    status = edge_linux_fd_number(context->arguments[0], &descriptor);
    if (status < 0 || !kernel_fd_is_open(descriptor))
        return -EDGE_LINUX_EBADF;

    switch (command) {
        case EDGE_LINUX_F_DUPFD:
        case EDGE_LINUX_F_DUPFD_CLOEXEC:
            if (argument >= kernel_fd_allocation_limit())
                return -EDGE_LINUX_EINVAL;
            return edge_linux_fd_duplicate(
                (uint32_t)descriptor, argument, 0,
                command == EDGE_LINUX_F_DUPFD_CLOEXEC ?
                    KERNEL_FD_CLOEXEC : 0u);
        case EDGE_LINUX_F_GETFD:
            status = kernel_fd_get_descriptor_flags(descriptor, &flags);
            return status < 0 ? status :
                (int64_t)(flags & KERNEL_FD_CLOEXEC);
        case EDGE_LINUX_F_SETFD:
            return kernel_fd_set_descriptor_flags(
                descriptor, (uint32_t)argument & KERNEL_FD_CLOEXEC);
        case EDGE_LINUX_F_GETFL:
            status = kernel_fd_get_status_flags(descriptor, &flags);
            return status < 0 ? status :
                (int64_t)(flags & ~EDGE_LINUX_GETFL_CLEAR_MASK);
        case EDGE_LINUX_F_SETFL:
            flags = EDGE_LINUX_SETFL_COMMON_MASK |
                    (context->arch_ops ?
                        context->arch_ops->fcntl_setfl_mask : 0u);
            return kernel_fd_update_status_flags(
                descriptor, flags, (uint32_t)argument & flags);
        case EDGE_LINUX_F_GETLK:
        case EDGE_LINUX_F_SETLK:
        case EDGE_LINUX_F_SETLKW:
        case EDGE_LINUX_F_OFD_GETLK:
        case EDGE_LINUX_F_OFD_SETLK:
        case EDGE_LINUX_F_OFD_SETLKW:
            return edge_linux_file_lock_fcntl(
                descriptor, command, argument,
                context->arch_ops ? context->arch_ops->copy_from_user : 0,
                context->arch_ops ? context->arch_ops->copy_to_user : 0,
                context->current_task, context->user_registers);
        default:
            fallback = kernel_fd_fcntl_fallback(
                descriptor, command, argument);
            return fallback == -EDGE_LINUX_ENOSYS ?
                -EDGE_LINUX_EINVAL : fallback;
    }
}

static int64_t edge_linux_sys_flock(
    edge_linux_syscall_context_t *context) {
    int32_t descriptor;
    int status = edge_linux_fd_number(context->arguments[0], &descriptor);
    if (status < 0) return status;
    return edge_linux_file_lock_flock(
        descriptor, (uint32_t)context->arguments[1],
        context->user_registers);
}

static int64_t edge_linux_sys_eventfd(
    edge_linux_syscall_context_t *context) {
    uint32_t flags = context->id == EDGE_LINUX_SYS_eventfd ? 0u :
                     (uint32_t)context->arguments[1];
    if (flags & ~(KERNEL_EVENTFD_SEMAPHORE |
                  KERNEL_EVENTFD_NONBLOCK |
                  KERNEL_EVENTFD_CLOEXEC))
        return -EDGE_LINUX_EINVAL;
    return kernel_eventfd_create_descriptor(
        (uint32_t)context->arguments[0], flags);
}

static int64_t edge_linux_sys_pipe(
    edge_linux_syscall_context_t *context) {
    uint32_t flags = context->id == EDGE_LINUX_SYS_pipe2 ?
                     (uint32_t)context->arguments[1] : 0u;
    kernel_fd_publication_t publication = {0};
    int32_t descriptors[2];
    int status;
    if (flags & ~(EDGE_LINUX_O_NONBLOCK | EDGE_LINUX_O_CLOEXEC))
        return -EDGE_LINUX_EINVAL;
    status = kernel_fd_pipe_prepare(
        flags, descriptors, &publication);
    if (status < 0) return status;
    if (edge_linux_copy_to_user(context, context->arguments[0], descriptors,
                                sizeof(descriptors)) < 0) {
        (void)kernel_fd_publication_abort(&publication);
        return -EDGE_LINUX_EFAULT;
    }
    status = kernel_fd_publication_commit(&publication);
    if (status < 0) return status;
    return 0;
}

#define EDGE_LINUX_SPLICE_F_MOVE     0x01u
#define EDGE_LINUX_SPLICE_F_NONBLOCK 0x02u
#define EDGE_LINUX_SPLICE_F_MORE     0x04u
#define EDGE_LINUX_SPLICE_F_GIFT     0x08u
#define EDGE_LINUX_SPLICE_F_ALL      0x0fu

static int64_t edge_linux_sys_vmsplice(
    edge_linux_syscall_context_t *context) {
    kernel_io_file_range_info_t descriptor;
    kernel_io_vector_scratch_t scratch;
    kernel_io_operation_t operation;
    uint64_t vector_address = context->arguments[1];
    uint64_t vector_count = context->arguments[2];
    uint64_t requested = 0;
    uint64_t total = 0;
    uint32_t flags;
    uint32_t runtime_flags = 0;
    int32_t fd;
    int status;

    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    if (context->arguments[3] > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    fd = (int32_t)context->arguments[0];
    flags = (uint32_t)context->arguments[3];
    if (flags & ~EDGE_LINUX_SPLICE_F_ALL)
        return -EDGE_LINUX_EINVAL;
    if (vector_count > EDGE_LINUX_IOV_MAX)
        return -EDGE_LINUX_EINVAL;
    status = kernel_io_file_range_query(fd, &descriptor);
    if (status < 0) return status;
    if (descriptor.kind != KERNEL_IO_FILE_PIPE)
        return -EDGE_LINUX_EBADF;
    if (!vector_count) return 0;
    if (!vector_address) return -EDGE_LINUX_EFAULT;
    if (kernel_io_current_vector_scratch(&scratch) < 0 ||
        !scratch.vectors || scratch.capacity < vector_count)
        return -EDGE_LINUX_ENOMEM;
    if (vector_count > UINT64_MAX / sizeof(scratch.vectors[0]) ||
        edge_linux_copy_from_user(
            context, scratch.vectors, vector_address,
            vector_count * sizeof(scratch.vectors[0])) < 0)
        return -EDGE_LINUX_EFAULT;

    if (descriptor.writable)
        operation = KERNEL_IO_WRITE_CURRENT;
    else if (descriptor.readable)
        operation = KERNEL_IO_READ_CURRENT;
    else
        return -EDGE_LINUX_EBADF;
    if (flags & EDGE_LINUX_SPLICE_F_NONBLOCK)
        runtime_flags |= KERNEL_IO_TRANSFER_NONBLOCK;

    for (uint64_t index = 0; index < vector_count; ++index) {
        uint64_t length = scratch.vectors[index].iov_len;
        if (requested >= EDGE_LINUX_MAX_RW_COUNT) break;
        if (length > EDGE_LINUX_MAX_RW_COUNT - requested)
            length = EDGE_LINUX_MAX_RW_COUNT - requested;
        requested += length;
    }

    for (uint64_t index = 0; index < vector_count && total < requested;
         ++index) {
        uint64_t length = scratch.vectors[index].iov_len;
        int64_t transferred;
        if (length > requested - total) length = requested - total;
        if (!length) continue;
        if (total && !kernel_io_descriptor_ready(fd, operation)) break;
        transferred = kernel_io_user_transfer(
            fd, scratch.vectors[index].iov_base, length, 0,
            operation, runtime_flags, context->user_registers);
        if (transferred < 0)
            return total ? (int64_t)total : transferred;
        total += (uint64_t)transferred;
        if ((uint64_t)transferred != length) break;
    }
    return (int64_t)total;
}

static int64_t edge_linux_sys_tee(
    edge_linux_syscall_context_t *context) {
    kernel_io_file_range_info_t input;
    kernel_io_file_range_info_t output;
    uint64_t length = context->arguments[2];
    uint32_t flags;
    int status;
    if (context->arguments[3] > UINT32_MAX)
        return -EDGE_LINUX_EINVAL;
    flags = (uint32_t)context->arguments[3];
    if (flags & ~EDGE_LINUX_SPLICE_F_ALL)
        return -EDGE_LINUX_EINVAL;
    if (!length) return 0;
    if (context->arguments[0] > INT32_MAX ||
        context->arguments[1] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    status = kernel_io_file_range_query(
        (int32_t)context->arguments[0], &input);
    if (status < 0) return status;
    status = kernel_io_file_range_query(
        (int32_t)context->arguments[1], &output);
    if (status < 0) return status;
    if (input.kind != KERNEL_IO_FILE_PIPE ||
        output.kind != KERNEL_IO_FILE_PIPE)
        return -EDGE_LINUX_EINVAL;
    if (!input.readable || !output.writable)
        return -EDGE_LINUX_EBADF;
    if (length > EDGE_LINUX_MAX_RW_COUNT)
        length = EDGE_LINUX_MAX_RW_COUNT;
    return kernel_io_pipe_tee_current(
        (int32_t)context->arguments[0],
        (int32_t)context->arguments[1], length, flags,
        context->user_registers);
}

static int64_t edge_linux_sys_splice(
    edge_linux_syscall_context_t *context) {
    uint64_t length = context->arguments[4];
    uint32_t flags = (uint32_t)context->arguments[5];
    int32_t input_descriptor;
    int32_t output_descriptor;
    int status;

    if (!length) return 0;
    if (flags & ~EDGE_LINUX_SPLICE_F_ALL)
        return -EDGE_LINUX_EINVAL;
    if (length > EDGE_LINUX_MAX_RW_COUNT)
        length = EDGE_LINUX_MAX_RW_COUNT;
    status = edge_linux_fd_number(context->arguments[0],
                                  &input_descriptor);
    if (status < 0) return status;
    status = edge_linux_fd_number(context->arguments[2],
                                  &output_descriptor);
    if (status < 0) return status;
    return kernel_io_splice_current(
        input_descriptor, context->arguments[1],
        output_descriptor, context->arguments[3],
        length, flags, context->user_registers);
}

static int edge_linux_timespec_timeout(
    edge_linux_syscall_context_t *context, uint64_t user_timeout,
    int64_t *timeout_microseconds) {
    linux_timespec64_t timeout;
    uint64_t seconds;
    uint64_t microseconds;

    if (!timeout_microseconds) return -EDGE_LINUX_EINVAL;
    if (!user_timeout) {
        *timeout_microseconds = -1;
        return 0;
    }
    if (edge_linux_copy_from_user(context, &timeout,
                                  user_timeout,
                                  sizeof(timeout)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (timeout.tv_sec < 0 || timeout.tv_nsec < 0 ||
        timeout.tv_nsec >= 1000000000LL)
        return -EDGE_LINUX_EINVAL;

    seconds = (uint64_t)timeout.tv_sec;
    microseconds = ((uint64_t)timeout.tv_nsec + 999u) / 1000u;
    if (seconds > (uint64_t)INT64_MAX / 1000000u ||
        seconds * 1000000u > (uint64_t)INT64_MAX - microseconds) {
        *timeout_microseconds = INT64_MAX;
    } else {
        *timeout_microseconds =
            (int64_t)(seconds * 1000000u + microseconds);
    }
    return 0;
}

static int64_t edge_linux_sys_signal_wait(
    edge_linux_syscall_context_t *context) {
    uint64_t mask;
    uint64_t deadline = UINT64_MAX;
    int64_t timeout_microseconds;
    uint64_t now;
    int status;

    if (context->id == EDGE_LINUX_SYS_pause) {
        if (kernel_current_signal_mask_get(&mask) < 0)
            return -EDGE_LINUX_EINVAL;
        return kernel_current_signal_suspend(mask, context->user_registers);
    }
    if (context->id == EDGE_LINUX_SYS_rt_sigsuspend) {
        if (context->arguments[1] != sizeof(uint64_t))
            return -EDGE_LINUX_EINVAL;
        if (!context->arguments[0]) return -EDGE_LINUX_EFAULT;
        if (edge_linux_copy_from_user(
                context, &mask, context->arguments[0], sizeof(mask)) < 0)
            return -EDGE_LINUX_EFAULT;
        return kernel_current_signal_suspend(
            edge_linux_signal_sanitize_mask(mask), context->user_registers);
    }
    if (context->id != EDGE_LINUX_SYS_rt_sigtimedwait)
        return -EDGE_LINUX_ENOSYS;
    if (context->arguments[3] != sizeof(uint64_t))
        return -EDGE_LINUX_EINVAL;
    if (!context->arguments[0]) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(
            context, &mask, context->arguments[0], sizeof(mask)) < 0)
        return -EDGE_LINUX_EFAULT;
    status = edge_linux_timespec_timeout(
        context, context->arguments[2], &timeout_microseconds);
    if (status < 0) return status;
    if (timeout_microseconds >= 0) {
        now = boottime_monotonic_us();
        deadline = (uint64_t)timeout_microseconds > UINT64_MAX - now ?
            UINT64_MAX : now + (uint64_t)timeout_microseconds;
    }
    return kernel_current_signal_timed_wait(
        edge_linux_signal_sanitize_mask(mask), context->arguments[1],
        deadline, context->arch_ops ? context->arch_ops->copy_to_user : 0,
        context->current_task, context->user_registers);
}

static int64_t edge_linux_sys_signal_altstack(
    edge_linux_syscall_context_t *context) {
    kernel_signal_altstack_state_t current;
    struct edge_linux_stack64 old_stack;
    struct edge_linux_stack64 new_stack;
    struct edge_linux_stack64 normalized;
    uint64_t new_user = context->arguments[0];
    uint64_t old_user = context->arguments[1];
    uint32_t flags;
    edge_linux_signal_altstack_status_t status;

    if (new_user && edge_linux_copy_from_user(
            context, &new_stack, new_user, sizeof(new_stack)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (kernel_current_signal_altstack_get(
            context->user_registers, &current) < 0)
        return -EDGE_LINUX_EINVAL;
    old_stack.sp = current.stack_pointer;
    old_stack.flags = (int32_t)edge_linux_signal_altstack_report_flags(
        current.flags, current.on_stack);
    old_stack.padding = 0;
    old_stack.size = current.stack_size;
    if (new_user) {
        if (current.on_stack) return -EDGE_LINUX_EPERM;
        flags = (uint32_t)new_stack.flags;
        if (current.stack_pointer != new_stack.sp ||
            current.stack_size != new_stack.size ||
            current.flags != flags) {
            status = edge_linux_signal_altstack_normalize(
                &new_stack, current.minimum_size, &normalized);
            if (status == EDGE_LINUX_SIGNAL_ALTSTACK_INVALID)
                return -EDGE_LINUX_EINVAL;
            if (status == EDGE_LINUX_SIGNAL_ALTSTACK_TOO_SMALL)
                return -EDGE_LINUX_ENOMEM;
            if (kernel_current_signal_altstack_set(
                    normalized.sp, normalized.size, flags) < 0)
                return -EDGE_LINUX_EINVAL;
        }
    }
    if (old_user && edge_linux_copy_to_user(
            context, old_user, &old_stack, sizeof(old_stack)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_linux_timeval_timeout(
    edge_linux_syscall_context_t *context, uint64_t user_timeout,
    int64_t *timeout_microseconds) {
    linux_timeval64_t timeout;
    uint64_t seconds;
    uint64_t microseconds;

    if (!timeout_microseconds) return -EDGE_LINUX_EINVAL;
    if (!user_timeout) {
        *timeout_microseconds = -1;
        return 0;
    }
    if (edge_linux_copy_from_user(context, &timeout, user_timeout,
                                  sizeof(timeout)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (timeout.tv_sec < 0 || timeout.tv_usec < 0)
        return -EDGE_LINUX_EINVAL;

    seconds = (uint64_t)timeout.tv_sec;
    microseconds = (uint64_t)timeout.tv_usec;
    if (seconds > (uint64_t)INT64_MAX / 1000000u ||
        microseconds > (uint64_t)INT64_MAX - seconds * 1000000u) {
        *timeout_microseconds = INT64_MAX;
    } else {
        *timeout_microseconds =
            (int64_t)(seconds * 1000000u + microseconds);
    }
    return 0;
}

static int edge_linux_epoll_timeout(
    edge_linux_syscall_context_t *context, int64_t *timeout_microseconds) {
    if (context->id == EDGE_LINUX_SYS_epoll_pwait2)
        return edge_linux_timespec_timeout(
            context, context->arguments[3], timeout_microseconds);
    if (!timeout_microseconds) return -EDGE_LINUX_EINVAL;
    if ((int32_t)context->arguments[3] < 0) {
        *timeout_microseconds = -1;
    } else {
        *timeout_microseconds =
            (int64_t)(int32_t)context->arguments[3] * 1000LL;
    }
    return 0;
}

static int64_t edge_linux_sys_epoll(
    edge_linux_syscall_context_t *context) {
    kernel_epoll_event_t event;
    int32_t epoll_descriptor;
    int32_t target_descriptor;
    uint32_t operation;
    uint64_t signal_mask = 0;
    int replace_signal_mask = 0;
    int64_t timeout_microseconds;
    int status;

    if (context->id == EDGE_LINUX_SYS_epoll_create) {
        if ((int32_t)context->arguments[0] <= 0)
            return -EDGE_LINUX_EINVAL;
        return kernel_epoll_create_descriptor(0);
    }
    if (context->id == EDGE_LINUX_SYS_epoll_create1) {
        uint32_t flags = (uint32_t)context->arguments[0];
        if (flags & ~KERNEL_EPOLL_CLOEXEC)
            return -EDGE_LINUX_EINVAL;
        return kernel_epoll_create_descriptor(flags);
    }
    if (context->id == EDGE_LINUX_SYS_epoll_ctl) {
        operation = (uint32_t)context->arguments[1];
        event.events = 0;
        event.data = 0;
        if (operation != KERNEL_EPOLL_CTL_DEL) {
            if (!context->arguments[3]) return -EDGE_LINUX_EFAULT;
            if (!context->arch_ops ||
                !context->arch_ops->copy_epoll_event_from_user)
                return -EDGE_LINUX_EIO;
            if (context->arch_ops->copy_epoll_event_from_user(
                    context->current_task, context->arguments[3],
                    &event) < 0)
                return -EDGE_LINUX_EFAULT;
        }
        status = edge_linux_fd_number(context->arguments[0],
                                      &epoll_descriptor);
        if (status < 0) return status;
        status = edge_linux_fd_number(context->arguments[2],
                                      &target_descriptor);
        if (status < 0) return status;
        return kernel_epoll_control_descriptor(
            epoll_descriptor, operation, target_descriptor, &event);
    }

    /* Linux prepares pwait2's timeout and the temporary mask before the
     * descriptor lookup.  Preserve that ordering because callers can observe
     * EFAULT/EINVAL precedence when more than one argument is invalid. */
    if (context->id == EDGE_LINUX_SYS_epoll_pwait2) {
        status = edge_linux_epoll_timeout(context, &timeout_microseconds);
        if (status < 0) return status;
    }
    if (context->id == EDGE_LINUX_SYS_epoll_pwait ||
        context->id == EDGE_LINUX_SYS_epoll_pwait2) {
        if (context->arguments[4]) {
            if (context->arguments[5] != sizeof(signal_mask))
                return -EDGE_LINUX_EINVAL;
            if (edge_linux_copy_from_user(context, &signal_mask,
                                          context->arguments[4],
                                          sizeof(signal_mask)) < 0)
                return -EDGE_LINUX_EFAULT;
            replace_signal_mask = 1;
        }
    }
    if ((int64_t)context->arguments[2] <= 0 ||
        context->arguments[2] > INT32_MAX)
        return -EDGE_LINUX_EINVAL;
    status = edge_linux_fd_number(context->arguments[0],
                                  &epoll_descriptor);
    if (status < 0) return status;
    if (context->id != EDGE_LINUX_SYS_epoll_pwait2) {
        status = edge_linux_epoll_timeout(context, &timeout_microseconds);
        if (status < 0) return status;
    }

    return kernel_epoll_wait_descriptor(
        epoll_descriptor, context->arguments[1],
        (uint32_t)context->arguments[2], timeout_microseconds,
        replace_signal_mask, signal_mask, context->user_registers);
}

static int64_t edge_linux_sys_poll(
    edge_linux_syscall_context_t *context) {
    int64_t timeout_microseconds;
    uint64_t signal_mask = 0;
    int replace_signal_mask = 0;
    int status;

    if (context->id == EDGE_LINUX_SYS_poll) {
        int32_t milliseconds = (int32_t)context->arguments[2];
        timeout_microseconds = milliseconds < 0 ? -1 :
            (int64_t)milliseconds * 1000LL;
    } else {
        status = edge_linux_timespec_timeout(
            context, context->arguments[2], &timeout_microseconds);
        if (status < 0) return status;
        if (context->arguments[3]) {
            if (context->arguments[4] != sizeof(signal_mask))
                return -EDGE_LINUX_EINVAL;
            if (edge_linux_copy_from_user(context, &signal_mask,
                                          context->arguments[3],
                                          sizeof(signal_mask)) < 0)
                return -EDGE_LINUX_EFAULT;
            replace_signal_mask = 1;
        }
    }

    return kernel_poll_wait_descriptors(
        context->arguments[0], context->arguments[1],
        timeout_microseconds,
        context->id == EDGE_LINUX_SYS_ppoll ? context->arguments[2] : 0,
        replace_signal_mask, signal_mask, context->user_registers);
}

static int64_t edge_linux_sys_select(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_pselect_sigset signal_argument;
    int64_t timeout_microseconds;
    uint64_t signal_mask = 0;
    uint64_t user_timeout = context->arguments[4];
    uint32_t timeout_format;
    int replace_signal_mask = 0;
    int status;

    if (context->id == EDGE_LINUX_SYS_pselect6) {
        signal_argument.sigmask_u = 0;
        signal_argument.sigsetsize = 0;
        if (context->arguments[5]) {
            if (edge_linux_copy_from_user(context, &signal_argument,
                                          context->arguments[5],
                                          sizeof(signal_argument)) < 0)
                return -EDGE_LINUX_EFAULT;
            if (signal_argument.sigmask_u &&
                signal_argument.sigsetsize != sizeof(signal_mask))
                return -EDGE_LINUX_EINVAL;
        }
        status = edge_linux_timespec_timeout(
            context, user_timeout, &timeout_microseconds);
        if (status < 0) return status;
        if (signal_argument.sigmask_u) {
            if (edge_linux_copy_from_user(context, &signal_mask,
                                          signal_argument.sigmask_u,
                                          sizeof(signal_mask)) < 0)
                return -EDGE_LINUX_EFAULT;
            replace_signal_mask = 1;
        }
        timeout_format = user_timeout ? KERNEL_WAIT_TIMEOUT_TIMESPEC :
                                        KERNEL_WAIT_TIMEOUT_NONE;
    } else {
        status = edge_linux_timeval_timeout(
            context, user_timeout, &timeout_microseconds);
        if (status < 0) return status;
        timeout_format = user_timeout ? KERNEL_WAIT_TIMEOUT_TIMEVAL :
                                        KERNEL_WAIT_TIMEOUT_NONE;
    }
    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EINVAL;

    return kernel_select_wait_descriptors(
        context->arguments[0], context->arguments[1],
        context->arguments[2], context->arguments[3],
        timeout_microseconds, user_timeout, timeout_format,
        replace_signal_mask, signal_mask, context->user_registers);
}

static int edge_linux_socket_validate_create(uint32_t domain, uint32_t type,
                                             uint32_t protocol,
                                             uint32_t *normalized_type,
                                             uint32_t *normalized_protocol) {
    uint32_t result_type = type;
    uint32_t result_protocol = protocol;

    switch (domain) {
        case EDGE_LINUX_AF_UNIX:
            /* Linux's UNIX family accepts protocol PF_UNIX as an alias for 0. */
            if (protocol != 0u && protocol != EDGE_LINUX_AF_UNIX)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            if (type != EDGE_LINUX_SOCK_STREAM &&
                type != EDGE_LINUX_SOCK_DGRAM &&
                type != EDGE_LINUX_SOCK_RAW &&
                type != EDGE_LINUX_SOCK_SEQPACKET)
                return -EDGE_LINUX_ESOCKTNOSUPPORT;
            /* AF_UNIX maps SOCK_RAW onto its datagram record implementation. */
            if (type == EDGE_LINUX_SOCK_RAW)
                result_type = EDGE_LINUX_SOCK_DGRAM;
            result_protocol = 0u;
            break;
        case EDGE_LINUX_AF_INET:
            if (type != EDGE_LINUX_SOCK_STREAM &&
                type != EDGE_LINUX_SOCK_DGRAM &&
                type != EDGE_LINUX_SOCK_RAW)
                return -EDGE_LINUX_ESOCKTNOSUPPORT;
            if (type == EDGE_LINUX_SOCK_STREAM &&
                protocol != 0u && protocol != EDGE_LINUX_IPPROTO_TCP)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            if (type == EDGE_LINUX_SOCK_DGRAM &&
                protocol != 0u && protocol != EDGE_LINUX_IPPROTO_UDP &&
                protocol != EDGE_LINUX_IPPROTO_ICMP)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            if (type == EDGE_LINUX_SOCK_RAW &&
                protocol != EDGE_LINUX_IPPROTO_ICMP &&
                protocol != EDGE_LINUX_IPPROTO_RAW)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            if (protocol == 0u)
                result_protocol = type == EDGE_LINUX_SOCK_STREAM ?
                    EDGE_LINUX_IPPROTO_TCP : EDGE_LINUX_IPPROTO_UDP;
            break;
        case EDGE_LINUX_AF_INET6:
            if (type != EDGE_LINUX_SOCK_STREAM &&
                type != EDGE_LINUX_SOCK_DGRAM &&
                type != EDGE_LINUX_SOCK_RAW)
                return -EDGE_LINUX_ESOCKTNOSUPPORT;
            if (type == EDGE_LINUX_SOCK_STREAM &&
                protocol != 0u && protocol != EDGE_LINUX_IPPROTO_TCP)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            if (type == EDGE_LINUX_SOCK_DGRAM &&
                protocol != 0u && protocol != EDGE_LINUX_IPPROTO_UDP &&
                protocol != EDGE_LINUX_IPPROTO_ICMPV6)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            if (type == EDGE_LINUX_SOCK_RAW &&
                protocol != EDGE_LINUX_IPPROTO_ICMPV6 &&
                protocol != EDGE_LINUX_IPPROTO_RAW)
                return -EDGE_LINUX_EPROTONOSUPPORT;
            if (protocol == 0u)
                result_protocol = type == EDGE_LINUX_SOCK_STREAM ?
                    EDGE_LINUX_IPPROTO_TCP : EDGE_LINUX_IPPROTO_UDP;
            break;
        case EDGE_LINUX_AF_NETLINK:
        case EDGE_LINUX_AF_PACKET:
            if (type != EDGE_LINUX_SOCK_DGRAM &&
                type != EDGE_LINUX_SOCK_RAW)
                return -EDGE_LINUX_ESOCKTNOSUPPORT;
            break;
        default:
            return -EDGE_LINUX_EAFNOSUPPORT;
    }

    if (normalized_type) *normalized_type = result_type;
    if (normalized_protocol) *normalized_protocol = result_protocol;
    return 0;
}

typedef struct edge_linux_socket_operation_scope {
    kernel_fd_operation_lease_t lease;
    kernel_socket_operation_result_t result;
    uint8_t active;
} edge_linux_socket_operation_scope_t;

static int edge_linux_socket_operation_begin(
        int32_t descriptor,
        edge_linux_socket_operation_scope_t *scope) {
    int status;

    if (!scope) return -EDGE_LINUX_EINVAL;
    memset(scope, 0, sizeof(*scope));
    status = kernel_fd_operation_acquire(
        descriptor, &scope->lease);
    if (status < 0) return status;
    scope->active = 1;
    return 0;
}

static int64_t edge_linux_socket_operation_invoke(
        edge_linux_socket_operation_scope_t *scope,
        const kernel_socket_operation_request_t *request) {
    if (!scope || !scope->active)
        return -EDGE_LINUX_EINVAL;
    return kernel_fd_operation_socket(
        &scope->lease, request, &scope->result);
}

static int64_t edge_linux_socket_operation_finish(
        edge_linux_socket_operation_scope_t *scope,
        int64_t operation_result) {
    int release_result;

    if (!scope || !scope->active)
        return operation_result < 0 ?
            operation_result : -EDGE_LINUX_EINVAL;
    scope->active = 0;
    release_result =
        kernel_fd_operation_release(&scope->lease);
    if (operation_result >= 0 && release_result < 0)
        return release_result;
    return operation_result;
}

static int64_t edge_linux_sys_socket_core(
    edge_linux_syscall_context_t *context) {
    uint32_t domain;
    uint32_t type_argument;
    uint32_t type;
    uint32_t protocol;
    uint32_t flags;
    kernel_socket_descriptor_info_t info;
    int status;

    if (context->id == EDGE_LINUX_SYS_listen) {
        edge_linux_socket_operation_scope_t scope;
        kernel_socket_operation_request_t request = {
            .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
        };
        int32_t descriptor;
        int64_t result;

        status = edge_linux_fd_number(
            context->arguments[0], &descriptor);
        if (status < 0) return status;
        status = edge_linux_socket_operation_begin(
            descriptor, &scope);
        if (status < 0) return status;
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        if (result < 0)
            return edge_linux_socket_operation_finish(
                &scope, result);
        info = scope.result.output.description;
        if (info.domain == EDGE_LINUX_AF_UNIX) {
            if (info.type != EDGE_LINUX_SOCK_STREAM &&
                info.type != EDGE_LINUX_SOCK_SEQPACKET)
                return edge_linux_socket_operation_finish(
                    &scope, -EDGE_LINUX_EOPNOTSUPP);
        } else if (info.domain == EDGE_LINUX_AF_INET ||
                   info.domain == EDGE_LINUX_AF_INET6) {
            if (info.type != EDGE_LINUX_SOCK_STREAM)
                return edge_linux_socket_operation_finish(
                    &scope, -EDGE_LINUX_EOPNOTSUPP);
        } else {
            return edge_linux_socket_operation_finish(
                &scope, -EDGE_LINUX_EOPNOTSUPP);
        }
        request = (kernel_socket_operation_request_t){
            .operation = KERNEL_SOCKET_OPERATION_LISTEN,
            .arguments.listen_backlog =
                (int32_t)context->arguments[1],
        };
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        return edge_linux_socket_operation_finish(
            &scope, result);
    }

    if (context->id == EDGE_LINUX_SYS_shutdown) {
        edge_linux_socket_operation_scope_t scope;
        kernel_socket_operation_request_t request = {
            .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
        };
        int32_t descriptor;
        int32_t how = (int32_t)context->arguments[1];
        int64_t result;

        status = edge_linux_fd_number(
            context->arguments[0], &descriptor);
        if (status < 0) return status;
        status = edge_linux_socket_operation_begin(
            descriptor, &scope);
        if (status < 0) return status;
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        if (result < 0)
            return edge_linux_socket_operation_finish(
                &scope, result);
        info = scope.result.output.description;
        if (info.domain != EDGE_LINUX_AF_UNIX &&
            info.domain != EDGE_LINUX_AF_INET &&
            info.domain != EDGE_LINUX_AF_INET6)
            return edge_linux_socket_operation_finish(
                &scope, -EDGE_LINUX_EOPNOTSUPP);
        if (how < 0 || how > 2)
            return edge_linux_socket_operation_finish(
                &scope, -EDGE_LINUX_EINVAL);
        if ((info.domain == EDGE_LINUX_AF_INET ||
             info.domain == EDGE_LINUX_AF_INET6) &&
            !info.connected)
            return edge_linux_socket_operation_finish(
                &scope, -EDGE_LINUX_ENOTCONN);
        request = (kernel_socket_operation_request_t){
            .operation = KERNEL_SOCKET_OPERATION_SHUTDOWN,
            .arguments.shutdown_how = how,
        };
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        return edge_linux_socket_operation_finish(
            &scope, result);
    }

    domain = (uint32_t)context->arguments[0];
    type_argument = (uint32_t)context->arguments[1];
    protocol = (uint32_t)context->arguments[2];
    flags = type_argument &
        (EDGE_LINUX_SOCK_NONBLOCK | EDGE_LINUX_SOCK_CLOEXEC);
    if (type_argument & ~(EDGE_LINUX_SOCK_TYPE_MASK |
                          EDGE_LINUX_SOCK_NONBLOCK |
                          EDGE_LINUX_SOCK_CLOEXEC))
        return -EDGE_LINUX_EINVAL;
    type = type_argument & EDGE_LINUX_SOCK_TYPE_MASK;
    if (context->id == EDGE_LINUX_SYS_socketpair) {
        kernel_fd_publication_t publication = {0};
        int32_t descriptors[2];

        status = kernel_socket_create_unix_pair_prepare(
            descriptors, &publication);
        if (status < 0) return status;
        /*
         * Linux writes the two reserved numbers as independent integers.  A
         * fault on the second word therefore leaves the first word visible,
         * while neither descriptor becomes installed.
         */
        if (edge_linux_copy_to_user(
                context, context->arguments[3],
                &descriptors[0], sizeof(descriptors[0])) < 0 ||
            edge_linux_copy_to_user(
                context,
                context->arguments[3] + sizeof(descriptors[0]),
                &descriptors[1], sizeof(descriptors[1])) < 0) {
            (void)kernel_fd_publication_abort(&publication);
            return -EDGE_LINUX_EFAULT;
        }
        status = edge_linux_socket_validate_create(
            domain, type, protocol, &type, &protocol);
        if (status < 0) {
            (void)kernel_fd_publication_abort(&publication);
            return status;
        }
        if (domain != EDGE_LINUX_AF_UNIX) {
            (void)kernel_fd_publication_abort(&publication);
            return -EDGE_LINUX_EOPNOTSUPP;
        }
        status = kernel_socket_create_unix_pair_construct(
            type, flags, descriptors, &publication);
        if (status < 0) {
            (void)kernel_fd_publication_abort(&publication);
            return status;
        }
        status = kernel_fd_publication_commit(&publication);
        if (status < 0) return status;
        return 0;
    }
    status = edge_linux_socket_validate_create(
        domain, type, protocol, &type, &protocol);
    if (status < 0) return status;

    if (context->id == EDGE_LINUX_SYS_socket)
        return kernel_socket_create_descriptor(domain, type, protocol, flags);
    return -EDGE_LINUX_ENOSYS;
}

static int edge_linux_socket_address_validate(
    const kernel_socket_descriptor_info_t *info,
    const kernel_socket_address_t *address, int connecting) {
    uint16_t family;
    uint32_t required;

    if (!info || !address || address->length < sizeof(family))
        return -EDGE_LINUX_EINVAL;
    memcpy(&family, address->bytes, sizeof(family));
    if (connecting && family == 0u) {
        if (info->domain != EDGE_LINUX_AF_UNIX &&
            info->domain != EDGE_LINUX_AF_INET &&
            info->domain != EDGE_LINUX_AF_INET6)
            return -EDGE_LINUX_EAFNOSUPPORT;
        if (info->type != EDGE_LINUX_SOCK_DGRAM &&
            info->type != EDGE_LINUX_SOCK_RAW)
            return -EDGE_LINUX_EAFNOSUPPORT;
        return 0;
    }
    if (family != info->domain) return -EDGE_LINUX_EAFNOSUPPORT;

    switch (family) {
        case EDGE_LINUX_AF_UNIX:
            if (address->length > sizeof(struct edge_linux_sockaddr_un))
                return -EDGE_LINUX_EINVAL;
            return 0;
        case EDGE_LINUX_AF_INET:
            required = sizeof(struct edge_linux_sockaddr_in);
            break;
        case EDGE_LINUX_AF_INET6:
            required = sizeof(struct edge_linux_sockaddr_in6);
            break;
        case EDGE_LINUX_AF_NETLINK: {
            struct edge_linux_sockaddr_nl netlink;
            required = sizeof(netlink);
            if (address->length >= required) {
                memcpy(&netlink, address->bytes, sizeof(netlink));
                if (netlink.nl_pad) return -EDGE_LINUX_EINVAL;
            }
            break;
        }
        case EDGE_LINUX_AF_PACKET:
            if (connecting) return -EDGE_LINUX_EOPNOTSUPP;
            required = sizeof(struct edge_linux_sockaddr_ll);
            break;
        default:
            return -EDGE_LINUX_EAFNOSUPPORT;
    }
    return address->length < required ? -EDGE_LINUX_EINVAL : 0;
}

static int edge_linux_socket_address_copy_from_user(
    edge_linux_syscall_context_t *context, uint64_t user_address,
    uint64_t raw_length,
    kernel_socket_address_t *address) {
    int32_t signed_length = (int32_t)raw_length;

    if (!address) return -EDGE_LINUX_EINVAL;
    memset(address, 0, sizeof(*address));
    if (raw_length > UINT32_MAX || signed_length < 0 ||
        (uint32_t)signed_length > sizeof(address->bytes))
        return -EDGE_LINUX_EINVAL;
    address->length = (uint32_t)signed_length;
    if (!address->length) return 0;
    if (!user_address) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(
            context, address->bytes, user_address,
            address->length) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static void edge_linux_socket_address_normalize_destination(
    kernel_socket_address_t *address) {
    struct edge_linux_sockaddr_in internet;
    struct edge_linux_sockaddr_in6 internet6;
    uint32_t index;

    if (!address || address->length < sizeof(uint16_t)) return;

    if (address->length >= sizeof(internet)) {
        memcpy(&internet, address->bytes, sizeof(internet));
    }
    if (address->length >= sizeof(internet) &&
        internet.sin_family == EDGE_LINUX_AF_INET && internet.sin_addr == 0) {
        /*
         * Linux routes an unspecified destination to the local host.  Apply
         * the rule at the shared ABI boundary so connect(2) and sendto(2)
         * behave identically across socket backends and IP versions.
         */
        internet.sin_addr = __builtin_bswap32(0x7F000001u);
        memcpy(address->bytes, &internet, sizeof(internet));
        return;
    }

    if (address->length < sizeof(internet6)) return;
    memcpy(&internet6, address->bytes, sizeof(internet6));
    if (internet6.sin6_family != EDGE_LINUX_AF_INET6) return;
    for (index = 0; index < sizeof(internet6.sin6_addr); ++index) {
        if (internet6.sin6_addr[index] != 0) return;
    }
    internet6.sin6_addr[sizeof(internet6.sin6_addr) - 1u] = 1u;
    memcpy(address->bytes, &internet6, sizeof(internet6));
}

int edge_linux_socket_address_copy_to_user(
    void *task, edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, uint64_t user_address,
    uint64_t user_length, const kernel_socket_address_t *address,
    uint32_t flags) {
    uint32_t supplied;
    uint32_t copied;

    if ((flags & ~EDGE_LINUX_SOCKET_ADDRESS_OPTIONAL) != 0 ||
        !copy_from_user || !copy_to_user || !address ||
        address->length > sizeof(address->bytes))
        return -EDGE_LINUX_EIO;
    if ((flags & EDGE_LINUX_SOCKET_ADDRESS_OPTIONAL) && !user_address)
        return 0;
    if (!user_length ||
        copy_from_user(task, &supplied, user_length, sizeof(supplied)) < 0)
        return -EDGE_LINUX_EFAULT;
    if ((int32_t)supplied < 0) return -EDGE_LINUX_EINVAL;
    copied = supplied < address->length ? supplied : address->length;
    if (copy_to_user(task, user_length, &address->length,
                     sizeof(address->length)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (copied && (!user_address ||
                   copy_to_user(task, user_address, address->bytes,
                                copied) < 0))
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_socket_address(
    edge_linux_syscall_context_t *context) {
    kernel_socket_descriptor_info_t info;
    kernel_socket_address_t address;
    int32_t descriptor;
    int status;

    status = edge_linux_fd_number(
        context->arguments[0], &descriptor);
    if (status < 0) return status;

    if (context->id == EDGE_LINUX_SYS_getsockname ||
        context->id == EDGE_LINUX_SYS_getpeername) {
        edge_linux_socket_operation_scope_t scope;
        kernel_socket_operation_request_t request = {
            .operation = KERNEL_SOCKET_OPERATION_NAME,
            .arguments.name_peer =
                context->id == EDGE_LINUX_SYS_getpeername,
        };
        int64_t result;

        status = edge_linux_socket_operation_begin(
            descriptor, &scope);
        if (status < 0) return status;
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        if (result >= 0)
            address = scope.result.output.address;
        result = edge_linux_socket_operation_finish(
            &scope, result);
        if (result < 0) return result;
        return edge_linux_socket_address_copy_to_user(
            context->current_task, context->arch_ops->copy_from_user,
            context->arch_ops->copy_to_user, context->arguments[1],
            context->arguments[2], &address, 0);
    }

    if (context->id == EDGE_LINUX_SYS_bind) {
        edge_linux_socket_operation_scope_t scope;
        kernel_socket_operation_request_t request = {
            .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
        };
        int64_t result;

        status = edge_linux_socket_operation_begin(
            descriptor, &scope);
        if (status < 0) return status;
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        if (result < 0)
            return edge_linux_socket_operation_finish(
                &scope, result);
        info = scope.result.output.description;
        status = edge_linux_socket_address_copy_from_user(
            context, context->arguments[1], context->arguments[2],
            &address);
        if (status < 0)
            return edge_linux_socket_operation_finish(
                &scope, status);
        if (!address.length)
            return edge_linux_socket_operation_finish(
                &scope, -EDGE_LINUX_EINVAL);
        status = edge_linux_socket_address_validate(&info, &address, 0);
        if (status < 0)
            return edge_linux_socket_operation_finish(
                &scope, status);
        request = (kernel_socket_operation_request_t){
            .operation = KERNEL_SOCKET_OPERATION_BIND,
            .arguments.bind_address = address,
        };
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        return edge_linux_socket_operation_finish(
            &scope, result);
    }

    if (context->id == EDGE_LINUX_SYS_connect) {
        edge_linux_socket_operation_scope_t scope;
        kernel_socket_operation_request_t request = {
            .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
        };
        int64_t result;

        status = edge_linux_socket_operation_begin(
            descriptor, &scope);
        if (status < 0) return status;
        status = edge_linux_socket_address_copy_from_user(
            context, context->arguments[1], context->arguments[2],
            &address);
        if (status < 0)
            return edge_linux_socket_operation_finish(
                &scope, status);
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        if (result < 0)
            return edge_linux_socket_operation_finish(
                &scope, result);
        info = scope.result.output.description;
        if (!address.length)
            return edge_linux_socket_operation_finish(
                &scope, -EDGE_LINUX_EINVAL);
        status = edge_linux_socket_address_validate(&info, &address, 1);
        if (status < 0)
            return edge_linux_socket_operation_finish(
                &scope, status);
        edge_linux_socket_address_normalize_destination(&address);
        request = (kernel_socket_operation_request_t){
            .operation = KERNEL_SOCKET_OPERATION_CONNECT,
            .arguments.connect = {
                .address = address,
                .user_registers = context->user_registers,
            },
        };
        result = edge_linux_socket_operation_invoke(
            &scope, &request);
        return edge_linux_socket_operation_finish(
            &scope, result);
    }
    return -EDGE_LINUX_ENOSYS;
}

static int64_t edge_linux_sys_socket_accept(
    edge_linux_syscall_context_t *context) {
    kernel_socket_address_t address;
    kernel_fd_publication_t publication = {0};
    int32_t descriptor = (int32_t)context->arguments[0];
    int32_t accepted = -1;
    uint32_t flags = context->id == EDGE_LINUX_SYS_accept4 ?
        (uint32_t)context->arguments[3] : 0u;
    int status;

    if (context->arguments[0] > INT32_MAX ||
        !kernel_fd_is_open(descriptor))
        return -EDGE_LINUX_EBADF;
    if (context->id == EDGE_LINUX_SYS_accept4 &&
        (context->arguments[3] > UINT32_MAX ||
         (flags & ~(EDGE_LINUX_SOCK_NONBLOCK |
                    EDGE_LINUX_SOCK_CLOEXEC)) != 0))
        return -EDGE_LINUX_EINVAL;
    status = kernel_socket_accept_prepare(
        descriptor, flags, &address, context->arguments[1],
        context->arguments[2], context->user_registers,
        &accepted, &publication);
    if (status < 0) return status;
    status = edge_linux_socket_address_copy_to_user(
        context->current_task, context->arch_ops->copy_from_user,
        context->arch_ops->copy_to_user, context->arguments[1],
        context->arguments[2], &address,
        EDGE_LINUX_SOCKET_ADDRESS_OPTIONAL);
    if (status < 0) {
        (void)kernel_fd_publication_abort(&publication);
        return status;
    }
    status = kernel_fd_publication_commit(&publication);
    if (status < 0) return status;
    return accepted;
}

static int64_t edge_linux_sys_socket_buffer(
    edge_linux_syscall_context_t *context) {
    kernel_socket_buffer_request_t request;
    kernel_socket_descriptor_info_t info;
    int32_t descriptor;
    int status;

    status = edge_linux_fd_number(context->arguments[0], &descriptor);
    if (status < 0) return status;
    status = kernel_socket_describe_descriptor(descriptor, &info);
    if (status < 0) return status;
    memset(&request, 0, sizeof(request));
    request.descriptor = descriptor;
    request.flags = (uint32_t)context->arguments[3];
    request.user_buffer = context->arguments[1];
    request.length = context->arguments[2];
    request.user_address = context->arguments[4];
    request.user_address_length = context->arguments[5];
    request.receiving = context->id == EDGE_LINUX_SYS_recvfrom;
    request.user_registers = context->user_registers;
    request.copy_context = context->current_task;
    request.copy_from_user = context->arch_ops->copy_from_user;
    request.copy_to_user = context->arch_ops->copy_to_user;
    if (!request.receiving && request.user_address) {
        status = edge_linux_socket_address_copy_from_user(
            context, request.user_address, request.user_address_length,
            &request.address);
        if (status < 0) return status;
        status = edge_linux_socket_address_validate(&info, &request.address, 0);
        if (status < 0) return status;
        edge_linux_socket_address_normalize_destination(&request.address);
        request.has_address = 1;
    }
    return kernel_socket_buffer_execute(&request);
}

static int64_t edge_linux_sys_socket_message(
    edge_linux_syscall_context_t *context) {
    int32_t descriptor;
    int status;

    status = edge_linux_fd_number(context->arguments[0], &descriptor);
    if (status < 0) return status;
    return kernel_socket_message_invoke(
        descriptor, context->arguments[1],
        (uint32_t)context->arguments[2],
        context->id == EDGE_LINUX_SYS_recvmsg,
        context->user_registers, context->current_task,
        context->arch_ops->copy_from_user,
        context->arch_ops->copy_to_user);
}

static int64_t edge_linux_sys_socket_mmsg(
    edge_linux_syscall_context_t *context) {
    kernel_socket_mmsg_request_t request;
    kernel_socket_descriptor_info_t info;
    uint64_t timeout_deadline = UINT64_MAX;
    uint32_t vector_length;
    int32_t descriptor;
    int status;

    status = kernel_socket_mmsg_import(
        context->arguments[1], context->arguments[2], &vector_length);
    if (status < 0) return status;
    if (!vector_length) return 0;
    status = edge_linux_fd_number(context->arguments[0], &descriptor);
    if (status < 0) return status;
    status = kernel_socket_describe_descriptor(descriptor, &info);
    if (status < 0) return status;
    (void)info;
    if (context->id == EDGE_LINUX_SYS_recvmmsg) {
        status = kernel_socket_mmsg_timeout_import(
            context->current_task, context->arch_ops->copy_from_user,
            context->arguments[4], &timeout_deadline);
        if (status < 0) return status;
    }

    memset(&request, 0, sizeof(request));
    request.descriptor = descriptor;
    request.flags = (uint32_t)context->arguments[3];
    request.user_messages = context->arguments[1];
    request.vector_length = vector_length;
    request.receiving = context->id == EDGE_LINUX_SYS_recvmmsg;
    request.user_timeout = request.receiving ? context->arguments[4] : 0u;
    request.timeout_deadline_us = timeout_deadline;
    request.user_registers = context->user_registers;
    request.copy_context = context->current_task;
    request.copy_from_user = context->arch_ops->copy_from_user;
    request.copy_to_user = context->arch_ops->copy_to_user;
    return kernel_socket_message_batch(&request);
}

#define EDGE_SOCKET_OPTION_BOOLEAN       0x0001u
#define EDGE_SOCKET_OPTION_NONNEGATIVE   0x0002u
#define EDGE_SOCKET_OPTION_POSITIVE      0x0004u
#define EDGE_SOCKET_OPTION_BYTE_VALUE    0x0008u
#define EDGE_SOCKET_OPTION_TTL_VALUE     0x0010u
#define EDGE_SOCKET_OPTION_TCLASS_VALUE  0x0020u
#define EDGE_SOCKET_OPTION_PMTU_VALUE    0x0040u
#define EDGE_SOCKET_OPTION_SET_FORBIDDEN 0x0080u
#define EDGE_SOCKET_OPTION_HOPS_VALUE    0x0100u

typedef struct edge_linux_socket_integer_option {
    uint32_t level;
    uint32_t name;
    kernel_socket_option_id_t option;
    uint32_t flags;
} edge_linux_socket_integer_option_t;

static const edge_linux_socket_integer_option_t
    g_edge_linux_socket_integer_options[] = {
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_REUSEADDR,
         KERNEL_SOCKET_OPTION_REUSE_ADDRESS, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_BROADCAST,
         KERNEL_SOCKET_OPTION_BROADCAST, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_SNDBUF,
         KERNEL_SOCKET_OPTION_SEND_BUFFER, 0},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_RCVBUF,
         KERNEL_SOCKET_OPTION_RECEIVE_BUFFER, 0},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_KEEPALIVE,
         KERNEL_SOCKET_OPTION_KEEPALIVE, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_OOBINLINE,
         KERNEL_SOCKET_OPTION_OOB_INLINE, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_NO_CHECK,
         KERNEL_SOCKET_OPTION_NO_CHECK, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_PRIORITY,
         KERNEL_SOCKET_OPTION_PRIORITY, 0},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_MARK,
         KERNEL_SOCKET_OPTION_MARK, 0},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_REUSEPORT,
         KERNEL_SOCKET_OPTION_REUSE_PORT, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_PASSCRED,
         KERNEL_SOCKET_OPTION_PASS_CREDENTIALS, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_RCVLOWAT,
         KERNEL_SOCKET_OPTION_RECEIVE_LOW_WATER, 0},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_SNDLOWAT,
         KERNEL_SOCKET_OPTION_SEND_LOW_WATER,
         EDGE_SOCKET_OPTION_SET_FORBIDDEN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_TIMESTAMP,
         KERNEL_SOCKET_OPTION_TIMESTAMP_US_OLD, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_TIMESTAMP_NEW,
         KERNEL_SOCKET_OPTION_TIMESTAMP_US_NEW, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_TIMESTAMPNS,
         KERNEL_SOCKET_OPTION_TIMESTAMP_NS_OLD, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_SOCKET, EDGE_LINUX_SO_TIMESTAMPNS_NEW,
         KERNEL_SOCKET_OPTION_TIMESTAMP_NS_NEW, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_TOS,
         KERNEL_SOCKET_OPTION_IP_TOS, EDGE_SOCKET_OPTION_BYTE_VALUE},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_TTL,
         KERNEL_SOCKET_OPTION_IP_TTL, EDGE_SOCKET_OPTION_TTL_VALUE},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_MULTICAST_TTL,
         KERNEL_SOCKET_OPTION_IP_MULTICAST_TTL,
         EDGE_SOCKET_OPTION_BYTE_VALUE},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_MULTICAST_LOOP,
         KERNEL_SOCKET_OPTION_IP_MULTICAST_LOOP,
         EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_PKTINFO,
         KERNEL_SOCKET_OPTION_IP_PACKET_INFO, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_RECVERR,
         KERNEL_SOCKET_OPTION_IP_RECEIVE_ERROR, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_RECVTTL,
         KERNEL_SOCKET_OPTION_IP_RECEIVE_TTL, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_FREEBIND,
         KERNEL_SOCKET_OPTION_IP_FREEBIND, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_MTU_DISCOVER,
         KERNEL_SOCKET_OPTION_IP_MTU_DISCOVER,
         EDGE_SOCKET_OPTION_PMTU_VALUE},
        {EDGE_LINUX_SOL_IP, EDGE_LINUX_IP_HDRINCL,
         KERNEL_SOCKET_OPTION_IP_HEADER_INCLUDED,
         EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_UNICAST_HOPS,
         KERNEL_SOCKET_OPTION_IP_TTL, EDGE_SOCKET_OPTION_TCLASS_VALUE},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_MULTICAST_HOPS,
         KERNEL_SOCKET_OPTION_IPV6_MULTICAST_HOPS,
         EDGE_SOCKET_OPTION_HOPS_VALUE},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_MULTICAST_LOOP,
         KERNEL_SOCKET_OPTION_IPV6_MULTICAST_LOOP,
         EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_HOPLIMIT,
         KERNEL_SOCKET_OPTION_IP_TTL, EDGE_SOCKET_OPTION_TCLASS_VALUE},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_TCLASS,
         KERNEL_SOCKET_OPTION_IP_TOS, EDGE_SOCKET_OPTION_TCLASS_VALUE},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_RECVERR,
         KERNEL_SOCKET_OPTION_IPV6_RECEIVE_ERROR,
         EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_V6ONLY,
         KERNEL_SOCKET_OPTION_IPV6_ONLY, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_RECVPKTINFO,
         KERNEL_SOCKET_OPTION_IPV6_RECEIVE_PACKET_INFO,
         EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_RECVHOPLIMIT,
         KERNEL_SOCKET_OPTION_IPV6_RECEIVE_HOP_LIMIT,
         EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_RECVTCLASS,
         KERNEL_SOCKET_OPTION_IPV6_RECEIVE_TRAFFIC_CLASS,
         EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_IPV6, EDGE_LINUX_IPV6_CHECKSUM,
         KERNEL_SOCKET_OPTION_IPV6_CHECKSUM, 0},
        {EDGE_LINUX_SOL_TCP, EDGE_LINUX_TCP_NODELAY,
         KERNEL_SOCKET_OPTION_TCP_NODELAY, EDGE_SOCKET_OPTION_BOOLEAN},
        {EDGE_LINUX_SOL_TCP, EDGE_LINUX_TCP_KEEPIDLE,
         KERNEL_SOCKET_OPTION_TCP_KEEP_IDLE, EDGE_SOCKET_OPTION_POSITIVE},
        {EDGE_LINUX_SOL_TCP, EDGE_LINUX_TCP_KEEPINTVL,
         KERNEL_SOCKET_OPTION_TCP_KEEP_INTERVAL,
         EDGE_SOCKET_OPTION_POSITIVE},
        {EDGE_LINUX_SOL_TCP, EDGE_LINUX_TCP_KEEPCNT,
         KERNEL_SOCKET_OPTION_TCP_KEEP_COUNT, EDGE_SOCKET_OPTION_POSITIVE},
    };

static const edge_linux_socket_integer_option_t *
edge_linux_socket_integer_option_find(uint32_t level, uint32_t name) {
    size_t index;
    for (index = 0;
         index < sizeof(g_edge_linux_socket_integer_options) /
                     sizeof(g_edge_linux_socket_integer_options[0]);
         ++index) {
        const edge_linux_socket_integer_option_t *option =
            &g_edge_linux_socket_integer_options[index];
        if (option->level == level && option->name == name) return option;
    }
    return 0;
}

static int edge_linux_socket_option_applicable(
    const kernel_socket_descriptor_info_t *info, uint32_t level,
    uint32_t name, int setting) {
    if (!info) return -EDGE_LINUX_EINVAL;
    if (level == EDGE_LINUX_SOL_SOCKET) return 0;
    if (level == EDGE_LINUX_SOL_IP) {
        if (info->domain != EDGE_LINUX_AF_INET &&
            info->domain != EDGE_LINUX_AF_INET6)
            return -EDGE_LINUX_EOPNOTSUPP;
        if (name == EDGE_LINUX_IP_HDRINCL &&
            (info->domain != EDGE_LINUX_AF_INET ||
             info->type != EDGE_LINUX_SOCK_RAW))
            return -EDGE_LINUX_ENOPROTOOPT;
        return 0;
    }
    if (level == EDGE_LINUX_SOL_IPV6) {
        if (info->domain != EDGE_LINUX_AF_INET6)
            return setting ? -EDGE_LINUX_ENOPROTOOPT :
                             -EDGE_LINUX_EOPNOTSUPP;
        return 0;
    }
    if (level == EDGE_LINUX_SOL_TCP) {
        if (info->domain != EDGE_LINUX_AF_INET &&
            info->domain != EDGE_LINUX_AF_INET6)
            return -EDGE_LINUX_EOPNOTSUPP;
        if (info->type != EDGE_LINUX_SOCK_STREAM ||
            (info->protocol != 0u &&
             info->protocol != EDGE_LINUX_IPPROTO_TCP))
            return setting ? -EDGE_LINUX_ENOPROTOOPT :
                             -EDGE_LINUX_EOPNOTSUPP;
        return 0;
    }
    return -EDGE_LINUX_ENOPROTOOPT;
}

static int64_t edge_linux_socket_option_copy_out(
    edge_linux_syscall_context_t *context, const void *value,
    uint32_t value_length, uint32_t capacity) {
    uint32_t copied = capacity < value_length ? capacity : value_length;
    if (copied && (!context->arguments[3] ||
                   edge_linux_copy_to_user(
                       context, context->arguments[3], value, copied) < 0))
        return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_to_user(context, context->arguments[4], &copied,
                                sizeof(copied)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_socket_option_attach_filter(
    edge_linux_syscall_context_t *context, int32_t descriptor,
    uint32_t value_length) {
    struct edge_linux_sock_fprog user_program;

    if (value_length < sizeof(user_program))
        return -EDGE_LINUX_EINVAL;
    if (edge_linux_copy_from_user(
            context, &user_program, context->arguments[3],
            sizeof(user_program)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!user_program.len ||
        user_program.len > EDGE_LINUX_PACKET_FILTER_MAX ||
        !user_program.filter)
        return -EDGE_LINUX_EINVAL;
    return kernel_socket_option_attach_filter(
        descriptor, user_program.filter, user_program.len,
        context->current_task, context->arch_ops->copy_from_user);
}

static int64_t edge_linux_socket_option_set(
    edge_linux_syscall_context_t *context,
    const kernel_socket_descriptor_info_t *info) {
    const edge_linux_socket_integer_option_t *option;
    uint32_t level = (uint32_t)context->arguments[1];
    uint32_t name = (uint32_t)context->arguments[2];
    uint32_t value_length = (uint32_t)context->arguments[4];
    int32_t descriptor = (int32_t)context->arguments[0];
    int32_t integer = 0;
    int64_t normalized;
    int status;

    if (level == EDGE_LINUX_IPPROTO_ICMPV6 &&
        name == EDGE_LINUX_ICMP6_FILTER) {
        uint32_t filter[KERNEL_SOCKET_ICMP6_FILTER_WORDS];

        if (value_length < sizeof(filter)) return -EDGE_LINUX_EINVAL;
        if (!context->arguments[3] ||
            edge_linux_copy_from_user(
                context, filter, context->arguments[3],
                sizeof(filter)) < 0)
            return -EDGE_LINUX_EFAULT;
        return kernel_socket_option_set_icmp6_filter(
            descriptor, filter);
    }

    if (level == EDGE_LINUX_SOL_IP &&
        name == EDGE_LINUX_IP_MULTICAST_IF) {
        struct edge_linux_ip_mreqn request;
        uint32_t interface_address;
        uint32_t copied;

        if (value_length < sizeof(interface_address))
            return -EDGE_LINUX_EINVAL;
        memset(&request, 0, sizeof(request));
        copied = value_length < sizeof(request) ?
            value_length : (uint32_t)sizeof(request);
        if (!context->arguments[3] ||
            edge_linux_copy_from_user(
                context, &request, context->arguments[3], copied) < 0)
            return -EDGE_LINUX_EFAULT;
        interface_address = value_length >= 8u ?
            request.imr_address : request.imr_multiaddr;
        if (request.imr_ifindex < 0) return -EDGE_LINUX_ENODEV;
        return kernel_socket_multicast_interface_set(
            descriptor, EDGE_LINUX_AF_INET, interface_address,
            value_length >= sizeof(request) ?
                (uint32_t)request.imr_ifindex : 0u);
    }

    if (level == EDGE_LINUX_SOL_IPV6 &&
        name == EDGE_LINUX_IPV6_MULTICAST_IF) {
        int32_t interface_index;

        if (value_length < sizeof(interface_index))
            return -EDGE_LINUX_EINVAL;
        if (!context->arguments[3] ||
            edge_linux_copy_from_user(
                context, &interface_index, context->arguments[3],
                sizeof(interface_index)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (interface_index < 0) return -EDGE_LINUX_ENODEV;
        return kernel_socket_multicast_interface_set(
            descriptor, EDGE_LINUX_AF_INET6, 0u,
            (uint32_t)interface_index);
    }

    if (level == EDGE_LINUX_SOL_IP &&
        (name == EDGE_LINUX_IP_ADD_MEMBERSHIP ||
         name == EDGE_LINUX_IP_DROP_MEMBERSHIP)) {
        struct edge_linux_ip_mreqn request;
        uint32_t copied;
        if (info->domain != EDGE_LINUX_AF_INET &&
            info->domain != EDGE_LINUX_AF_INET6)
            return -EDGE_LINUX_ENOPROTOOPT;
        if (value_length < 8u) return -EDGE_LINUX_EINVAL;
        memset(&request, 0, sizeof(request));
        copied = value_length < sizeof(request) ?
            value_length : (uint32_t)sizeof(request);
        if (!context->arguments[3] ||
            edge_linux_copy_from_user(context, &request,
                context->arguments[3], copied) < 0)
            return -EDGE_LINUX_EFAULT;
        if (request.imr_ifindex < 0) return -EDGE_LINUX_ENODEV;
        return kernel_socket_multicast_membership_update(
            descriptor, EDGE_LINUX_AF_INET,
            (const uint8_t *)&request.imr_multiaddr,
            request.imr_address, (uint32_t)request.imr_ifindex,
            name == EDGE_LINUX_IP_ADD_MEMBERSHIP);
    }

    if (level == EDGE_LINUX_SOL_IPV6 &&
        (name == EDGE_LINUX_IPV6_ADD_MEMBERSHIP ||
         name == EDGE_LINUX_IPV6_DROP_MEMBERSHIP)) {
        struct edge_linux_ipv6_mreq request;
        if (info->domain != EDGE_LINUX_AF_INET6)
            return -EDGE_LINUX_ENOPROTOOPT;
        if (value_length < sizeof(request)) return -EDGE_LINUX_EINVAL;
        if (!context->arguments[3] ||
            edge_linux_copy_from_user(context, &request,
                context->arguments[3], sizeof(request)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (request.ipv6mr_ifindex < 0) return -EDGE_LINUX_ENODEV;
        return kernel_socket_multicast_membership_update(
            descriptor, EDGE_LINUX_AF_INET6,
            request.ipv6mr_multiaddr, 0,
            (uint32_t)request.ipv6mr_ifindex,
            name == EDGE_LINUX_IPV6_ADD_MEMBERSHIP);
    }

    if (level == EDGE_LINUX_SOL_NETLINK) {
        if (info->domain != EDGE_LINUX_AF_NETLINK)
            return -EDGE_LINUX_EOPNOTSUPP;
        if (name == EDGE_LINUX_NETLINK_ADD_MEMBERSHIP ||
            name == EDGE_LINUX_NETLINK_DROP_MEMBERSHIP) {
            uint32_t group;
            if (value_length < sizeof(group)) return -EDGE_LINUX_EINVAL;
            if (!context->arguments[3] ||
                edge_linux_copy_from_user(context, &group,
                    context->arguments[3], sizeof(group)) < 0)
                return -EDGE_LINUX_EFAULT;
            status = kernel_socket_netlink_membership_update(
                descriptor, group,
                name == EDGE_LINUX_NETLINK_ADD_MEMBERSHIP);
            if (status < 0) return status;
            return 0;
        }
        if (name == EDGE_LINUX_NETLINK_PACKET_INFO) {
            if (value_length < sizeof(integer)) return -EDGE_LINUX_EINVAL;
            if (!context->arguments[3] ||
                edge_linux_copy_from_user(context, &integer,
                    context->arguments[3], sizeof(integer)) < 0)
                return -EDGE_LINUX_EFAULT;
            return kernel_socket_option_set_integer(
                descriptor, KERNEL_SOCKET_OPTION_NETLINK_PACKET_INFO,
                integer != 0);
        }
        return -EDGE_LINUX_ENOPROTOOPT;
    }

    if (level == EDGE_LINUX_SOL_PACKET) {
        uint8_t value[sizeof(struct edge_linux_tpacket_req3)];
        if (!value_length || value_length > sizeof(value) ||
            !context->arguments[3])
            return -EDGE_LINUX_EINVAL;
        memset(value, 0, sizeof(value));
        if (edge_linux_copy_from_user(context, value,
                context->arguments[3], value_length) < 0)
            return -EDGE_LINUX_EFAULT;
        return kernel_socket_packet_set_option(
            descriptor, name, value, value_length);
    }

    if (level == EDGE_LINUX_SOL_SOCKET &&
        name == EDGE_LINUX_SO_BINDTODEVICE) {
        char device[16];
        uint32_t copied = value_length < sizeof(device) - 1u ?
                          value_length : sizeof(device) - 1u;
        memset(device, 0, sizeof(device));
        if (copied && (!context->arguments[3] ||
                       edge_linux_copy_from_user(
                           context, device, context->arguments[3], copied) < 0))
            return -EDGE_LINUX_EFAULT;
        return kernel_socket_option_set_bound_device(
            descriptor, device, copied);
    }

    if (level == EDGE_LINUX_SOL_SOCKET &&
        name == EDGE_LINUX_SO_ATTACH_FILTER)
        return edge_linux_socket_option_attach_filter(
            context, descriptor, value_length);

    if (level == EDGE_LINUX_SOL_SOCKET &&
        (name == EDGE_LINUX_SO_RCVTIMEO ||
         name == EDGE_LINUX_SO_SNDTIMEO ||
         name == EDGE_LINUX_SO_RCVTIMEO_NEW ||
         name == EDGE_LINUX_SO_SNDTIMEO_NEW)) {
        linux_timeval64_t timeout;
        uint64_t microseconds;
        kernel_socket_option_id_t timeout_option;
        if (value_length < sizeof(timeout))
            return -EDGE_LINUX_EINVAL;
        if (edge_linux_copy_from_user(
                context, &timeout, context->arguments[3],
                sizeof(timeout)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (timeout.tv_sec < 0 || timeout.tv_usec < 0 ||
            timeout.tv_usec >= 1000000)
            return -EDGE_LINUX_EDOM;
        if ((uint64_t)timeout.tv_sec >
            (UINT64_MAX - (uint64_t)timeout.tv_usec) / 1000000u)
            microseconds = UINT64_MAX;
        else
            microseconds = (uint64_t)timeout.tv_sec * 1000000u +
                           (uint64_t)timeout.tv_usec;
        timeout_option =
            (name == EDGE_LINUX_SO_RCVTIMEO ||
             name == EDGE_LINUX_SO_RCVTIMEO_NEW) ?
                KERNEL_SOCKET_OPTION_RECEIVE_TIMEOUT_US :
                KERNEL_SOCKET_OPTION_SEND_TIMEOUT_US;
        return kernel_socket_option_set_integer(
            descriptor, timeout_option, (int64_t)microseconds);
    }

    if (level == EDGE_LINUX_SOL_SOCKET && name == EDGE_LINUX_SO_LINGER) {
        struct edge_linux_linger linger;
        if (value_length < sizeof(linger))
            return -EDGE_LINUX_EINVAL;
        if (edge_linux_copy_from_user(
                context, &linger, context->arguments[3],
                sizeof(linger)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (linger.seconds < 0) linger.seconds = 0;
        status = kernel_socket_option_set_integer(
            descriptor, KERNEL_SOCKET_OPTION_LINGER_ENABLED,
            linger.enabled != 0);
        if (status < 0) return status;
        return kernel_socket_option_set_integer(
            descriptor, KERNEL_SOCKET_OPTION_LINGER_SECONDS,
            linger.seconds);
    }

    /*
     * Linux's SOL_SOCKET and SOL_TCP dispatchers fetch a native integer before
     * rejecting an unknown option.  Preserve that pointer and length ordering
     * so invalid user memory does not get hidden behind ENOPROTOOPT.
     */
    option = edge_linux_socket_integer_option_find(level, name);
    if (!option && level != EDGE_LINUX_SOL_SOCKET &&
        level != EDGE_LINUX_SOL_TCP)
        return -EDGE_LINUX_ENOPROTOOPT;
    if (level == EDGE_LINUX_SOL_IP &&
        name == EDGE_LINUX_IP_MULTICAST_TTL && value_length > 0u &&
        value_length < sizeof(integer)) {
        uint8_t byte_value;
        if (!context->arguments[3] ||
            edge_linux_copy_from_user(context, &byte_value,
                context->arguments[3], sizeof(byte_value)) < 0)
            return -EDGE_LINUX_EFAULT;
        integer = byte_value;
    } else {
        if (value_length < sizeof(integer)) return -EDGE_LINUX_EINVAL;
        if (!context->arguments[3] ||
            edge_linux_copy_from_user(context, &integer,
                context->arguments[3], sizeof(integer)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    if (level == EDGE_LINUX_SOL_SOCKET &&
        name == EDGE_LINUX_SO_DETACH_FILTER)
        return kernel_socket_option_detach_filter(descriptor);
    if (level == EDGE_LINUX_SOL_SOCKET &&
        (name == EDGE_LINUX_SO_SNDBUFFORCE ||
         name == EDGE_LINUX_SO_RCVBUFFORCE)) {
        kernel_linux_identity_t identity;
        kernel_socket_option_id_t buffer_option =
            name == EDGE_LINUX_SO_SNDBUFFORCE ?
                KERNEL_SOCKET_OPTION_SEND_BUFFER :
                KERNEL_SOCKET_OPTION_RECEIVE_BUFFER;

        if (kernel_current_linux_identity(&identity) < 0)
            return -EDGE_LINUX_EPERM;
        if (!(identity.effective_capabilities &
              (1ULL << EDGE_LINUX_CAP_NET_ADMIN)))
            return -EDGE_LINUX_EPERM;
        return kernel_socket_option_set_integer(
            descriptor, buffer_option, 128u * 1024u);
    }
    if (!option) return -EDGE_LINUX_ENOPROTOOPT;
    status = edge_linux_socket_option_applicable(
        info, level, name, 1);
    if (status < 0) return status;
    if (option->flags & EDGE_SOCKET_OPTION_SET_FORBIDDEN)
        return -EDGE_LINUX_ENOPROTOOPT;

    normalized = integer;
    if (option->flags & EDGE_SOCKET_OPTION_BOOLEAN)
        normalized = integer != 0;
    if ((option->flags & EDGE_SOCKET_OPTION_NONNEGATIVE) && integer < 0)
        return -EDGE_LINUX_EINVAL;
    if ((option->flags & EDGE_SOCKET_OPTION_POSITIVE) && integer <= 0)
        return -EDGE_LINUX_EINVAL;
    if ((option->flags & EDGE_SOCKET_OPTION_BYTE_VALUE) &&
        (integer < 0 || integer > 255))
        return -EDGE_LINUX_EINVAL;
    if ((option->flags & EDGE_SOCKET_OPTION_TTL_VALUE) &&
        (integer < 1 || integer > 255))
        return -EDGE_LINUX_EINVAL;
    if ((option->flags & EDGE_SOCKET_OPTION_TCLASS_VALUE) &&
        (integer < -1 || integer > 255))
        return -EDGE_LINUX_EINVAL;
    if ((option->flags & EDGE_SOCKET_OPTION_TCLASS_VALUE) && integer < 0)
        normalized = option->option == KERNEL_SOCKET_OPTION_IP_TTL ? 64 : 0;
    if ((option->flags & EDGE_SOCKET_OPTION_HOPS_VALUE) &&
        (integer < -1 || integer > 255))
        return -EDGE_LINUX_EINVAL;
    if ((option->flags & EDGE_SOCKET_OPTION_HOPS_VALUE) && integer < 0)
        normalized = 1;
    if ((option->flags & EDGE_SOCKET_OPTION_PMTU_VALUE) &&
        (integer < EDGE_LINUX_IP_PMTUDISC_DONT ||
         integer > EDGE_LINUX_IP_PMTUDISC_OMIT))
        return -EDGE_LINUX_EINVAL;
    if (option->option == KERNEL_SOCKET_OPTION_SEND_BUFFER ||
        option->option == KERNEL_SOCKET_OPTION_RECEIVE_BUFFER)
        normalized = 128u * 1024u;
    if (option->option == KERNEL_SOCKET_OPTION_RECEIVE_LOW_WATER) {
        /* Linux saturates negative receive low-water values at INT_MAX. */
        normalized = integer < 0 ? INT32_MAX : (integer == 0 ? 1 : integer);
    }
    return kernel_socket_option_set_integer(
        descriptor, option->option, normalized);
}

static int64_t edge_linux_socket_option_get_peer_groups(
    edge_linux_syscall_context_t *context, int32_t descriptor,
    uint32_t capacity) {
    uint32_t count;
    uint32_t required;
    uint32_t index;
    int status = kernel_socket_option_get_peer_group_count(
        descriptor, &count);
    if (status < 0) return status;
    if (count > UINT32_MAX / sizeof(uint32_t)) return -EDGE_LINUX_EOVERFLOW;
    required = count * sizeof(uint32_t);
    if (capacity < required) {
        if (edge_linux_copy_to_user(
                context, context->arguments[4], &required,
                sizeof(required)) < 0)
            return -EDGE_LINUX_EFAULT;
        return -EDGE_LINUX_ERANGE;
    }
    if (required && !context->arguments[3]) return -EDGE_LINUX_EFAULT;
    for (index = 0; index < count; ++index) {
        uint32_t group_id;
        status = kernel_socket_option_get_peer_group(
            descriptor, index, &group_id);
        if (status < 0) return status;
        if (edge_linux_copy_to_user(
                context, context->arguments[3] +
                             (uint64_t)index * sizeof(group_id),
                &group_id, sizeof(group_id)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    if (edge_linux_copy_to_user(context, context->arguments[4], &required,
                                sizeof(required)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_socket_option_get(
    edge_linux_syscall_context_t *context,
    const kernel_socket_descriptor_info_t *info) {
    const edge_linux_socket_integer_option_t *option;
    uint32_t level = (uint32_t)context->arguments[1];
    uint32_t name = (uint32_t)context->arguments[2];
    uint32_t capacity;
    int32_t descriptor = (int32_t)context->arguments[0];
    int64_t value;
    int32_t integer;
    int status;

    if (!context->arguments[4] ||
        edge_linux_copy_from_user(context, &capacity,
            context->arguments[4], sizeof(capacity)) < 0)
        return -EDGE_LINUX_EFAULT;
    if ((int32_t)capacity < 0) return -EDGE_LINUX_EINVAL;

    if (level == EDGE_LINUX_SOL_IP &&
        (name == EDGE_LINUX_IPT_SO_GET_REVISION_MATCH ||
         name == EDGE_LINUX_IPT_SO_GET_REVISION_TARGET)) {
        struct edge_linux_xt_get_revision revision;
        uint8_t highest;

        if (info->domain != EDGE_LINUX_AF_INET)
            return -EDGE_LINUX_EOPNOTSUPP;
        if (capacity != sizeof(revision) || !context->arguments[3])
            return -EDGE_LINUX_EINVAL;
        if (edge_linux_copy_from_user(
                context, &revision, context->arguments[3],
                sizeof(revision)) < 0)
            return -EDGE_LINUX_EFAULT;
        revision.name[sizeof(revision.name) - 1u] = '\0';
        status = edge_linux_netfilter_extension_revision(
            revision.name,
            name == EDGE_LINUX_IPT_SO_GET_REVISION_TARGET,
            revision.revision, &highest);
        if (status < 0) return status;
        return edge_linux_socket_option_copy_out(
            context, &revision, sizeof(revision), capacity);
    }

    if (level == EDGE_LINUX_IPPROTO_ICMPV6 &&
        name == EDGE_LINUX_ICMP6_FILTER) {
        uint32_t filter[KERNEL_SOCKET_ICMP6_FILTER_WORDS];

        status = kernel_socket_option_get_icmp6_filter(
            descriptor, filter);
        if (status < 0) return status;
        return edge_linux_socket_option_copy_out(
            context, filter, sizeof(filter), capacity);
    }

    if (level == EDGE_LINUX_SOL_IP &&
        name == EDGE_LINUX_IP_MULTICAST_IF) {
        uint32_t interface_address;
        uint32_t interface_index;

        status = kernel_socket_multicast_interface_get(
            descriptor, EDGE_LINUX_AF_INET,
            &interface_address, &interface_index);
        if (status < 0) return status;
        return edge_linux_socket_option_copy_out(
            context, &interface_address,
            sizeof(interface_address), capacity);
    }

    if (level == EDGE_LINUX_SOL_IPV6 &&
        name == EDGE_LINUX_IPV6_MULTICAST_IF) {
        uint32_t interface_address;
        uint32_t interface_index;

        status = kernel_socket_multicast_interface_get(
            descriptor, EDGE_LINUX_AF_INET6,
            &interface_address, &interface_index);
        if (status < 0) return status;
        return edge_linux_socket_option_copy_out(
            context, &interface_index,
            sizeof(interface_index), capacity);
    }

    if (level == EDGE_LINUX_SOL_NETLINK) {
        uint32_t groups;
        uint32_t actual;
        if (info->domain != EDGE_LINUX_AF_NETLINK)
            return -EDGE_LINUX_EOPNOTSUPP;
        if (name == EDGE_LINUX_NETLINK_PACKET_INFO) {
            status = kernel_socket_option_get_integer(
                descriptor, KERNEL_SOCKET_OPTION_NETLINK_PACKET_INFO,
                &value);
            if (status < 0) return status;
            integer = (int32_t)value;
            return edge_linux_socket_option_copy_out(
                context, &integer, sizeof(integer), capacity);
        }
        if (name == EDGE_LINUX_NETLINK_LIST_MEMBERSHIPS) {
            status = kernel_socket_netlink_memberships_get(
                descriptor, &groups);
            if (status < 0) return status;
            actual = groups ? (uint32_t)sizeof(groups) : 0u;
            return edge_linux_socket_option_copy_out(
                context, &groups, actual, capacity);
        }
        return -EDGE_LINUX_ENOPROTOOPT;
    }

    if (level == EDGE_LINUX_SOL_PACKET) {
        uint8_t output[64];
        uint32_t actual = 0;
        uint32_t initial = capacity < sizeof(output) ?
                           capacity : sizeof(output);
        memset(output, 0, sizeof(output));
        if (name == EDGE_LINUX_PACKET_HDRLEN && initial) {
            if (!context->arguments[3] ||
                edge_linux_copy_from_user(
                    context, output, context->arguments[3], initial) < 0)
                return -EDGE_LINUX_EFAULT;
        }
        status = kernel_socket_packet_get_option(
            descriptor, name, output, sizeof(output), &actual);
        if (status < 0) return status;
        return edge_linux_socket_option_copy_out(
            context, output, actual, capacity);
    }

    if (level == EDGE_LINUX_SOL_SOCKET) {
        if (name == EDGE_LINUX_SO_TYPE)
            integer = (int32_t)info->type;
        else if (name == EDGE_LINUX_SO_DOMAIN)
            integer = (int32_t)info->domain;
        else if (name == EDGE_LINUX_SO_PROTOCOL)
            integer = (int32_t)info->protocol;
        else if (name == EDGE_LINUX_SO_ACCEPTCONN)
            integer = info->listening != 0;
        else if (name == EDGE_LINUX_SO_ERROR) {
            status = kernel_socket_option_take_error(descriptor, &integer);
            if (status < 0) return status;
        } else if (name == EDGE_LINUX_SO_PEERCRED) {
            kernel_socket_peer_credentials_t credentials;
            status = kernel_socket_option_get_peer_credentials(
                descriptor, &credentials);
            if (status < 0) return status;
            return edge_linux_socket_option_copy_out(
                context, &credentials, sizeof(credentials), capacity);
        } else if (name == EDGE_LINUX_SO_PEERPIDFD) {
            int64_t peer_descriptor;
            int64_t result;
            if (capacity < sizeof(integer)) return -EDGE_LINUX_EINVAL;
            peer_descriptor = kernel_socket_option_get_peer_pidfd(descriptor);
            if (peer_descriptor < 0) return peer_descriptor;
            integer = (int32_t)peer_descriptor;
            result = edge_linux_socket_option_copy_out(
                context, &integer, sizeof(integer), capacity);
            if (result < 0) (void)kernel_fd_close(integer);
            return result;
        } else if (name == EDGE_LINUX_SO_PEERGROUPS) {
            return edge_linux_socket_option_get_peer_groups(
                context, descriptor, capacity);
        } else if (name == EDGE_LINUX_SO_PEERSEC) {
            return -EDGE_LINUX_ENOPROTOOPT;
        } else if (name == EDGE_LINUX_SO_BINDTODEVICE) {
            char device[16];
            uint32_t actual;
            memset(device, 0, sizeof(device));
            status = kernel_socket_option_get_bound_device(
                descriptor, device, sizeof(device), &actual);
            if (status < 0) return status;
            return edge_linux_socket_option_copy_out(
                context, device, actual, capacity);
        } else if (name == EDGE_LINUX_SO_RCVTIMEO ||
                   name == EDGE_LINUX_SO_SNDTIMEO ||
                   name == EDGE_LINUX_SO_RCVTIMEO_NEW ||
                   name == EDGE_LINUX_SO_SNDTIMEO_NEW) {
            linux_timeval64_t timeout;
            kernel_socket_option_id_t timeout_option =
                (name == EDGE_LINUX_SO_RCVTIMEO ||
                 name == EDGE_LINUX_SO_RCVTIMEO_NEW) ?
                    KERNEL_SOCKET_OPTION_RECEIVE_TIMEOUT_US :
                    KERNEL_SOCKET_OPTION_SEND_TIMEOUT_US;
            status = kernel_socket_option_get_integer(
                descriptor, timeout_option, &value);
            if (status < 0) return status;
            timeout.tv_sec = value / 1000000;
            timeout.tv_usec = value % 1000000;
            return edge_linux_socket_option_copy_out(
                context, &timeout, sizeof(timeout), capacity);
        } else if (name == EDGE_LINUX_SO_LINGER) {
            struct edge_linux_linger linger;
            status = kernel_socket_option_get_integer(
                descriptor, KERNEL_SOCKET_OPTION_LINGER_ENABLED, &value);
            if (status < 0) return status;
            linger.enabled = value != 0;
            status = kernel_socket_option_get_integer(
                descriptor, KERNEL_SOCKET_OPTION_LINGER_SECONDS, &value);
            if (status < 0) return status;
            linger.seconds = (int32_t)value;
            return edge_linux_socket_option_copy_out(
                context, &linger, sizeof(linger), capacity);
        } else {
            option = edge_linux_socket_integer_option_find(level, name);
            if (!option) return -EDGE_LINUX_ENOPROTOOPT;
            status = kernel_socket_option_get_integer(
                descriptor, option->option, &value);
            if (status < 0) return status;
            integer = (int32_t)value;
        }
        return edge_linux_socket_option_copy_out(
            context, &integer, sizeof(integer), capacity);
    }

    if (level == EDGE_LINUX_SOL_IP && name == EDGE_LINUX_IP_MTU) {
        status = edge_linux_socket_option_applicable(info, level, name, 0);
        if (status < 0) return status;
        status = kernel_socket_option_get_mtu(descriptor, &integer);
        if (status < 0) return status;
        return edge_linux_socket_option_copy_out(
            context, &integer, sizeof(integer), capacity);
    }

    option = edge_linux_socket_integer_option_find(level, name);
    if (!option) return -EDGE_LINUX_ENOPROTOOPT;
    status = edge_linux_socket_option_applicable(info, level, name, 0);
    if (status < 0) return status;
    status = kernel_socket_option_get_integer(
        descriptor, option->option, &value);
    if (status < 0) return status;
    integer = (int32_t)value;
    return edge_linux_socket_option_copy_out(
        context, &integer, sizeof(integer), capacity);
}

static int64_t edge_linux_sys_socket_option(
    edge_linux_syscall_context_t *context) {
    kernel_socket_descriptor_info_t info;
    int32_t descriptor = (int32_t)context->arguments[0];
    int status;
    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    status = kernel_socket_describe_descriptor(descriptor, &info);
    if (status < 0) return status;
    if (context->id == EDGE_LINUX_SYS_setsockopt)
        return edge_linux_socket_option_set(context, &info);
    if (context->id == EDGE_LINUX_SYS_getsockopt)
        return edge_linux_socket_option_get(context, &info);
    return -EDGE_LINUX_ENOSYS;
}

static int64_t edge_linux_sys_timerfd(
    edge_linux_syscall_context_t *context) {
    linux_itimerspec64_t current;
    linux_itimerspec64_t previous;
    linux_itimerspec64_t replacement;
    int timer_id;
    int result;

    if (context->id == EDGE_LINUX_SYS_timerfd_create) {
        int32_t clock_id = (int32_t)context->arguments[0];
        uint32_t flags = (uint32_t)context->arguments[1];
        if (flags & ~(KERNEL_TIMERFD_NONBLOCK | KERNEL_TIMERFD_CLOEXEC))
            return -EDGE_LINUX_EINVAL;
        if (!kernel_timerfd_clock_supported(clock_id))
            return -EDGE_LINUX_EINVAL;
        if (clock_id == LINUX_CLOCK_REALTIME_ALARM ||
            clock_id == LINUX_CLOCK_BOOTTIME_ALARM) {
            kernel_linux_identity_t identity;
            if (kernel_current_linux_identity(&identity) < 0)
                return -EDGE_LINUX_ESRCH;
            if (!(identity.effective_capabilities &
                  (1ULL << EDGE_LINUX_CAP_WAKE_ALARM)))
                return -EDGE_LINUX_EPERM;
        }
        return kernel_timerfd_create_descriptor(clock_id, flags);
    }

    if (context->id == EDGE_LINUX_SYS_timerfd_settime) {
        if (!context->arguments[2] ||
            edge_linux_copy_from_user(context, &replacement,
                                      context->arguments[2],
                                      sizeof(replacement)) < 0)
            return -EDGE_LINUX_EFAULT;
        timer_id = kernel_timerfd_descriptor_id(
            (int32_t)context->arguments[0]);
        if (timer_id < 0) return timer_id;
        result = kernel_timerfd_settime(
            timer_id, (uint32_t)context->arguments[1], &replacement,
            context->arguments[3] ? &previous : 0);
        if (result < 0) return result;
        kernel_timerfd_state_changed(timer_id);
        if (context->arguments[3] &&
            edge_linux_copy_to_user(context, context->arguments[3],
                                    &previous, sizeof(previous)) < 0)
            return -EDGE_LINUX_EFAULT;
        return 0;
    }

    if (context->id != EDGE_LINUX_SYS_timerfd_gettime)
        return -EDGE_LINUX_ENOSYS;
    timer_id = kernel_timerfd_descriptor_id(
        (int32_t)context->arguments[0]);
    if (timer_id < 0) return timer_id;
    result = kernel_timerfd_gettime(timer_id, &current);
    if (result < 0) return result;
    if (!context->arguments[1] ||
        edge_linux_copy_to_user(context, context->arguments[1], &current,
                                sizeof(current)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_inotify(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    kernel_vfs_target_t target;
    kernel_linux_identity_t identity;
    uint32_t flags;
    uint32_t mask;
    int32_t magic_descriptor;
    int magic_status;
    int inotify_id;
    int status;

    if (context->id == EDGE_LINUX_SYS_inotify_init ||
        context->id == EDGE_LINUX_SYS_inotify_init1) {
        flags = context->id == EDGE_LINUX_SYS_inotify_init ? 0u :
                (uint32_t)context->arguments[0];
        if (flags & ~(KERNEL_INOTIFY_NONBLOCK | KERNEL_INOTIFY_CLOEXEC))
            return -EDGE_LINUX_EINVAL;
        return kernel_inotify_create_descriptor(flags);
    }

    inotify_id = kernel_inotify_descriptor_id(
        (int32_t)context->arguments[0]);
    if (inotify_id < 0) return inotify_id;
    if (context->id == EDGE_LINUX_SYS_inotify_rm_watch)
        return kernel_inotify_remove_watch(
            inotify_id, (int32_t)context->arguments[1]);
    if (context->id != EDGE_LINUX_SYS_inotify_add_watch)
        return -EDGE_LINUX_ENOSYS;

    mask = (uint32_t)context->arguments[2];
    status = kernel_inotify_validate_watch_mask(mask);
    if (status < 0) return status;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0 || !scratch.path ||
        scratch.path_capacity < VFS_PATH_MAX)
        return status < 0 ? status : -EDGE_LINUX_EIO;
    status = edge_linux_copy_user_string(
        context, context->arguments[1], scratch.path,
        scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    magic_status = 0;
    if (!(mask & KERNEL_INOTIFY_DONT_FOLLOW)) {
        if (kernel_current_linux_identity(&identity) < 0)
            return -EDGE_LINUX_ESRCH;
        magic_status = edge_linux_current_magic_fd(
            scratch.path, &identity, &magic_descriptor);
        if (magic_status < 0) return magic_status;
    }
    if (magic_status > 0) {
        /*
         * procfs descriptor entries are Linux magic links.  Watching one
         * follows the live open file description, so retain the descriptor's
         * canonical VFS target instead of attempting to watch the procfs link
         * spelling.  systemd-udevd uses this race-free form for /run/udev.
         */
        status = kernel_vfs_resolve_fd(magic_descriptor, &target);
        if (status == -EDGE_LINUX_EOPNOTSUPP)
            return -EDGE_LINUX_ENODEV;
    } else {
        status = kernel_vfs_resolve_path(
            scratch.path, (mask & KERNEL_INOTIFY_DONT_FOLLOW) != 0,
            &target);
    }
    if (status < 0) return status;
    if (!target.inode || !target.resolved_path)
        return -EDGE_LINUX_EIO;
    return kernel_inotify_add_watch(
        inotify_id, target.resolved_path, mask,
        (target.inode->mode & 0xf000u) == VFS_INODE_DIR);
}

static int64_t edge_linux_sys_signalfd(
    edge_linux_syscall_context_t *context) {
    uint64_t mask;
    uint32_t flags;
    int32_t descriptor;
    int signalfd_id;
    int status;
    if (context->arguments[2] != sizeof(mask))
        return -EDGE_LINUX_EINVAL;
    flags = context->id == EDGE_LINUX_SYS_signalfd ? 0u :
            (uint32_t)context->arguments[3];
    if (flags & ~(KERNEL_SIGNALFD_NONBLOCK | KERNEL_SIGNALFD_CLOEXEC))
        return -EDGE_LINUX_EINVAL;
    if (edge_linux_copy_from_user(
            context, &mask, context->arguments[1], sizeof(mask)) < 0)
        return -EDGE_LINUX_EFAULT;
    descriptor = (int32_t)context->arguments[0];
    if (descriptor == -1)
        return kernel_signalfd_create_descriptor(mask, flags);
    signalfd_id = kernel_signalfd_descriptor_id(descriptor);
    if (signalfd_id < 0) return signalfd_id;
    status = kernel_signalfd_update(signalfd_id, mask);
    if (status < 0) return status;
    kernel_signalfd_state_changed(signalfd_id);
    return descriptor;
}

static int64_t edge_linux_sys_fd_control(
    edge_linux_syscall_context_t *context) {
    uint32_t limit = kernel_fd_table_limit();
    int32_t descriptor;
    int status;

    switch (context->id) {
        case EDGE_LINUX_SYS_close:
            status = edge_linux_fd_number(context->arguments[0],
                                          &descriptor);
            return status < 0 ? status : kernel_fd_close(descriptor);
        case EDGE_LINUX_SYS_close_range: {
            uint32_t first = (uint32_t)context->arguments[0];
            uint32_t last = (uint32_t)context->arguments[1];
            uint32_t flags = (uint32_t)context->arguments[2];
            if (first > last ||
                (flags & ~(EDGE_LINUX_CLOSE_RANGE_UNSHARE |
                           EDGE_LINUX_CLOSE_RANGE_CLOEXEC)))
                return -EDGE_LINUX_EINVAL;
            if (flags & EDGE_LINUX_CLOSE_RANGE_UNSHARE) {
                status = kernel_fd_table_unshare();
                if (status < 0) return status;
            }
            if (first >= limit) return 0;
            if (last >= limit) last = limit - 1u;
            for (uint32_t number = first; number <= last; ++number) {
                if (!kernel_fd_is_open((int32_t)number)) continue;
                status = (flags & EDGE_LINUX_CLOSE_RANGE_CLOEXEC) ?
                    kernel_fd_set_descriptor_flags(
                        (int32_t)number, KERNEL_FD_CLOEXEC) :
                    kernel_fd_close((int32_t)number);
                if (status < 0 && status != -EDGE_LINUX_EBADF)
                    return status;
            }
            return 0;
        }
        case EDGE_LINUX_SYS_dup:
            return edge_linux_fd_duplicate(
                context->arguments[0], 0, 0, 0);
        case EDGE_LINUX_SYS_dup2:
            status = edge_linux_fd_number(context->arguments[0],
                                          &descriptor);
            if (status < 0 || !kernel_fd_is_open(descriptor))
                return -EDGE_LINUX_EBADF;
            if ((uint32_t)context->arguments[1] == (uint32_t)descriptor)
                return descriptor;
            return edge_linux_fd_duplicate(
                context->arguments[0], context->arguments[1], 1, 0);
        case EDGE_LINUX_SYS_dup3:
            if ((uint32_t)context->arguments[0] ==
                (uint32_t)context->arguments[1])
                return -EDGE_LINUX_EINVAL;
            if ((uint32_t)context->arguments[2] &
                ~EDGE_LINUX_O_CLOEXEC)
                return -EDGE_LINUX_EINVAL;
            return edge_linux_fd_duplicate(
                context->arguments[0], context->arguments[1], 1,
                ((uint32_t)context->arguments[2] &
                 EDGE_LINUX_O_CLOEXEC) ? KERNEL_FD_CLOEXEC : 0u);
        case EDGE_LINUX_SYS_fcntl:
            return edge_linux_sys_fcntl(context);
        default:
            return -EDGE_LINUX_ENOSYS;
    }
}

static int64_t edge_linux_sys_truncate(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_descriptor_t descriptor;
    kernel_vfs_xattr_scratch_t scratch;
    kernel_vfs_target_t target;
    uint64_t length = context->arguments[1];
    int result;

    if ((int64_t)length < 0) return -EDGE_LINUX_EINVAL;
    if (length > UINT32_MAX) return -EDGE_LINUX_EFBIG;

    if (context->id == EDGE_LINUX_SYS_truncate) {
        result = kernel_vfs_current_xattr_scratch(&scratch);
        if (result < 0) return result;
        result = edge_linux_copy_user_string(
            context, context->arguments[0], scratch.path,
            scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
        if (result < 0) return result;
        result = kernel_vfs_resolve_path(scratch.path, 0, &target);
        if (result < 0) return result;
        if ((target.inode->mode & 0xf000u) == VFS_INODE_DIR)
            return -EDGE_LINUX_EISDIR;
        if ((target.inode->mode & 0xf000u) != VFS_INODE_FILE)
            return -EDGE_LINUX_EINVAL;
        if (vfs_permission_check(target.inode, 2) < 0)
            return -EDGE_LINUX_EACCES;
        return kernel_vfs_truncate_path(
            target.resolved_path, &target, (uint32_t)length);
    }
    if (context->id != EDGE_LINUX_SYS_ftruncate)
        return -EDGE_LINUX_ENOSYS;

    if (context->arguments[0] > INT32_MAX)
        return -EDGE_LINUX_EBADF;
    result = kernel_vfs_describe_descriptor(
        (int32_t)context->arguments[0], &descriptor);
    if (result < 0) return result;
    if (!descriptor.writable)
        return -EDGE_LINUX_EINVAL;
    if (descriptor.kind != KERNEL_VFS_DESCRIPTOR_REGULAR &&
        descriptor.kind != KERNEL_VFS_DESCRIPTOR_MEMORY)
        return -EDGE_LINUX_EINVAL;
    if (descriptor.maximum_size && length > descriptor.maximum_size)
        return -EDGE_LINUX_EFBIG;
    if ((descriptor.seals & KERNEL_VFS_SEAL_SHRINK) &&
        length < descriptor.size)
        return -EDGE_LINUX_EPERM;
    if ((descriptor.seals & KERNEL_VFS_SEAL_GROW) &&
        length > descriptor.size)
        return -EDGE_LINUX_EPERM;
    return kernel_vfs_truncate_descriptor(
        (int32_t)context->arguments[0], (uint32_t)length);
}

static int64_t edge_linux_statfs_magic(const char *filesystem) {
    if (!filesystem) return 0;
    if (!strcmp(filesystem, "ext2") || !strcmp(filesystem, "ext3") ||
        !strcmp(filesystem, "ext4"))
        return EDGE_LINUX_EXT_SUPER_MAGIC;
    if (!strcmp(filesystem, "proc")) return EDGE_LINUX_PROC_SUPER_MAGIC;
    if (!strcmp(filesystem, "sysfs")) return EDGE_LINUX_SYSFS_MAGIC;
    if (!strcmp(filesystem, "tmpfs") || !strcmp(filesystem, "devtmpfs"))
        return EDGE_LINUX_TMPFS_MAGIC;
    if (!strcmp(filesystem, "devpts")) return EDGE_LINUX_DEVPTS_SUPER_MAGIC;
    if (!strcmp(filesystem, "cgroup2"))
        return EDGE_LINUX_CGROUP2_SUPER_MAGIC;
    if (!strcmp(filesystem, "fat32")) return EDGE_LINUX_MSDOS_SUPER_MAGIC;
    if (!strcmp(filesystem, "iso9660")) return EDGE_LINUX_ISOFS_SUPER_MAGIC;
    if (!strcmp(filesystem, "ntfs")) return EDGE_LINUX_NTFS_SB_MAGIC;
    if (!strcmp(filesystem, "exfat")) return EDGE_LINUX_EXFAT_SUPER_MAGIC;
    if (!strcmp(filesystem, "udf")) return EDGE_LINUX_UDF_SUPER_MAGIC;
    if (!strcmp(filesystem, "squashfs")) return 0x73717368u;
    if (!strcmp(filesystem, "erofs")) return 0xe0f5e1e2u;
    if (!strcmp(filesystem, "overlay"))
        return EDGE_LINUX_OVERLAYFS_SUPER_MAGIC;
    return 0;
}

static int edge_linux_statfs_from_superblock(
    vfs_superblock_t *superblock, struct edge_linux_statfs64 *result) {
    uint32_t total_kb;
    uint32_t used_kb;
    uint64_t total_bytes;
    uint64_t free_bytes;

    if (!superblock || !result || !superblock->ops ||
        !superblock->ops->statfs)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (superblock->ops->statfs(superblock, &total_kb, &used_kb) < 0)
        return -EDGE_LINUX_EIO;
    if (used_kb > total_kb) used_kb = total_kb;
    total_bytes = (uint64_t)total_kb * 1024u;
    free_bytes = (uint64_t)(total_kb - used_kb) * 1024u;

    memset(result, 0, sizeof(*result));
    result->f_type = edge_linux_statfs_magic(superblock->fs_name);
    result->f_bsize = 4096;
    result->f_blocks = total_bytes / 4096u;
    result->f_bfree = free_bytes / 4096u;
    result->f_bavail = result->f_bfree;
    result->f_namelen = VFS_NAME_MAX - 1u;
    result->f_frsize = 4096;
    result->f_flags = EDGE_LINUX_ST_VALID;
    if (superblock->mount_flags & VFS_MOUNT_READONLY)
        result->f_flags |= EDGE_LINUX_ST_RDONLY;
    if (superblock->mount_flags & VFS_MOUNT_NOSUID)
        result->f_flags |= EDGE_LINUX_ST_NOSUID;
    if (superblock->mount_flags & VFS_MOUNT_NODEV)
        result->f_flags |= EDGE_LINUX_ST_NODEV;
    if (superblock->mount_flags & VFS_MOUNT_NOEXEC)
        result->f_flags |= EDGE_LINUX_ST_NOEXEC;
    if (superblock->mount_flags & VFS_MOUNT_SYNCHRONOUS)
        result->f_flags |= EDGE_LINUX_ST_SYNCHRONOUS;
    if (superblock->mount_flags & VFS_MOUNT_NOATIME)
        result->f_flags |= EDGE_LINUX_ST_NOATIME;
    if (superblock->mount_flags & VFS_MOUNT_NODIRATIME)
        result->f_flags |= EDGE_LINUX_ST_NODIRATIME;
    if (superblock->mount_flags & VFS_MOUNT_RELATIME)
        result->f_flags |= EDGE_LINUX_ST_RELATIME;
    if (superblock->mount_flags & VFS_MOUNT_NOSYMFOLLOW)
        result->f_flags |= EDGE_LINUX_ST_NOSYMFOLLOW;
    return 0;
}

static int edge_linux_statfs_from_descriptor(
    const kernel_vfs_descriptor_t *descriptor,
    struct edge_linux_statfs64 *result) {
    vfs_superblock_t *mount;
    int64_t magic;

    if (!descriptor || !result) return -EDGE_LINUX_EINVAL;
    mount = descriptor->mount_id ?
        vfs_superblock_for_mount_id(descriptor->mount_id) : 0;
    if (mount)
        return edge_linux_statfs_from_superblock(mount, result);
    if (descriptor->superblock)
        return edge_linux_statfs_from_superblock(
            descriptor->superblock, result);

    switch (descriptor->kind) {
        case KERNEL_VFS_DESCRIPTOR_MEMORY:
        case KERNEL_VFS_DESCRIPTOR_TERMINAL:
        case KERNEL_VFS_DESCRIPTOR_DEVICE:
            magic = EDGE_LINUX_TMPFS_MAGIC;
            break;
        case KERNEL_VFS_DESCRIPTOR_PSEUDO_TERMINAL:
            magic = EDGE_LINUX_DEVPTS_SUPER_MAGIC;
            break;
        case KERNEL_VFS_DESCRIPTOR_PIPE:
            magic = EDGE_LINUX_PIPEFS_MAGIC;
            break;
        case KERNEL_VFS_DESCRIPTOR_SOCKET:
            magic = EDGE_LINUX_SOCKFS_MAGIC;
            break;
        case KERNEL_VFS_DESCRIPTOR_NAMESPACE:
            magic = EDGE_LINUX_NSFS_MAGIC;
            break;
        case KERNEL_VFS_DESCRIPTOR_ANONYMOUS:
            magic = EDGE_LINUX_ANON_INODE_FS_MAGIC;
            break;
        default:
            return -EDGE_LINUX_EOPNOTSUPP;
    }
    memset(result, 0, sizeof(*result));
    result->f_type = magic;
    result->f_bsize = 4096;
    result->f_namelen = 255;
    result->f_frsize = 4096;
    result->f_flags = EDGE_LINUX_ST_VALID;
    return 0;
}

static int64_t edge_linux_sys_statfs(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_statfs64 result;
    kernel_vfs_descriptor_t descriptor;
    kernel_vfs_xattr_scratch_t scratch;
    kernel_vfs_target_t target;
    int status;

    if (context->id == EDGE_LINUX_SYS_statfs) {
        status = kernel_vfs_current_xattr_scratch(&scratch);
        if (status < 0) return status;
        status = edge_linux_copy_user_string(
            context, context->arguments[0], scratch.path,
            scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        status = kernel_vfs_resolve_path(scratch.path, 0, &target);
        if (status < 0) return status;
        status = edge_linux_statfs_from_superblock(
            target.superblock, &result);
    } else if (context->id == EDGE_LINUX_SYS_fstatfs) {
        if (context->arguments[0] > INT32_MAX)
            return -EDGE_LINUX_EBADF;
        status = kernel_vfs_describe_descriptor(
            (int32_t)context->arguments[0], &descriptor);
        if (status < 0) return status;
        status = edge_linux_statfs_from_descriptor(&descriptor, &result);
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (status < 0) return status;
    if (!context->arguments[1] ||
        edge_linux_copy_to_user(context, context->arguments[1], &result,
                                sizeof(result)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_linux_lookup_file_metadata(
    edge_linux_syscall_context_t *context, int32_t directory,
    uint64_t user_path, uint32_t flags,
    kernel_file_metadata_t *metadata) {
    kernel_vfs_xattr_scratch_t scratch;
    int status;

    if (!context || !metadata) return -EDGE_LINUX_EFAULT;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    if (!user_path) {
        if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
            return -EDGE_LINUX_EFAULT;
        scratch.path[0] = 0;
    } else {
        status = edge_linux_copy_user_string(
            context, user_path, scratch.path, scratch.path_capacity,
            EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
    }

    if (!scratch.path[0]) {
        if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
            return -EDGE_LINUX_ENOENT;
        if (directory == EDGE_LINUX_AT_FDCWD)
            return kernel_vfs_metadata_at(
                directory, ".",
                (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) != 0,
                metadata);
        return kernel_vfs_metadata_fd(directory, metadata);
    }
    return kernel_vfs_metadata_at(
        directory, scratch.path,
        (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) != 0, metadata);
}

static int64_t edge_linux_sys_statx(
    edge_linux_syscall_context_t *context) {
    kernel_file_metadata_t metadata;
    struct edge_linux_statx result;
    uint32_t flags = (uint32_t)context->arguments[2];
    uint32_t requested = (uint32_t)context->arguments[3];
    int32_t directory = (int32_t)context->arguments[0];
    int status;

    if (flags & ~(EDGE_LINUX_AT_SYMLINK_NOFOLLOW |
                  EDGE_LINUX_AT_EMPTY_PATH |
                  EDGE_LINUX_AT_NO_AUTOMOUNT |
                  EDGE_LINUX_AT_STATX_SYNC_TYPE))
        return -EDGE_LINUX_EINVAL;
    if ((flags & EDGE_LINUX_AT_STATX_SYNC_TYPE) ==
        EDGE_LINUX_AT_STATX_SYNC_TYPE)
        return -EDGE_LINUX_EINVAL;
    if (requested & EDGE_LINUX_STATX_RESERVED)
        return -EDGE_LINUX_EINVAL;

    status = edge_linux_lookup_file_metadata(
        context, directory, context->arguments[1], flags, &metadata);
    if (status < 0) return status;

    kernel_file_metadata_to_statx(&metadata, &result);
    if (edge_linux_copy_to_user(context, context->arguments[4], &result,
                                sizeof(result)) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_stat(
    edge_linux_syscall_context_t *context) {
    kernel_file_metadata_t metadata;
    uint64_t destination;
    uint32_t flags = 0;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    int status;

    if (!context->arch_ops || !context->arch_ops->copy_stat_to_user)
        return -EDGE_LINUX_EIO;
    if (context->id == EDGE_LINUX_SYS_fstat) {
        status = kernel_vfs_metadata_fd(
            (int32_t)context->arguments[0], &metadata);
        destination = context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_newfstatat) {
        flags = (uint32_t)context->arguments[3];
        if (flags & ~(EDGE_LINUX_AT_SYMLINK_NOFOLLOW |
                      EDGE_LINUX_AT_EMPTY_PATH |
                      EDGE_LINUX_AT_NO_AUTOMOUNT))
            return -EDGE_LINUX_EINVAL;
        directory = (int32_t)context->arguments[0];
        status = edge_linux_lookup_file_metadata(
            context, directory, context->arguments[1], flags, &metadata);
        destination = context->arguments[2];
    } else if (context->id == EDGE_LINUX_SYS_stat ||
               context->id == EDGE_LINUX_SYS_lstat) {
        if (context->id == EDGE_LINUX_SYS_lstat)
            flags = EDGE_LINUX_AT_SYMLINK_NOFOLLOW;
        status = edge_linux_lookup_file_metadata(
            context, directory, context->arguments[0], flags, &metadata);
        destination = context->arguments[1];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (status < 0) return status;
    return context->arch_ops->copy_stat_to_user(
        context->current_task, context->arch_ops->copy_to_user,
        destination, &metadata);
}

typedef struct edge_linux_path_workspace {
    char *cwd;
    char *root;
    char *normalization;
    char *resolved;
    char *search;
    char *saved;
} edge_linux_path_workspace_t;

static int edge_linux_path_workspace_initialize(
    kernel_vfs_xattr_scratch_t *scratch,
    edge_linux_path_workspace_t *workspace) {
    if (!scratch || !workspace || !scratch->path ||
        scratch->path_capacity < VFS_PATH_MAX || !scratch->value ||
        scratch->value_capacity < 6u * VFS_PATH_MAX)
        return -EDGE_LINUX_EIO;
    workspace->cwd = (char *)scratch->value;
    workspace->root = workspace->cwd + VFS_PATH_MAX;
    workspace->normalization = workspace->root + VFS_PATH_MAX;
    workspace->resolved = workspace->normalization + VFS_PATH_MAX;
    workspace->search = workspace->resolved + VFS_PATH_MAX;
    workspace->saved = workspace->search + VFS_PATH_MAX;
    return 0;
}

static int edge_linux_build_copied_at_path(
    int32_t directory, kernel_vfs_xattr_scratch_t *scratch,
    edge_linux_path_workspace_t *workspace);

static int edge_linux_build_at_path(
    edge_linux_syscall_context_t *context, int32_t directory,
    uint64_t user_path, kernel_vfs_xattr_scratch_t *scratch,
    edge_linux_path_workspace_t *workspace) {
    int status;

    status = edge_linux_path_workspace_initialize(scratch, workspace);
    if (status < 0) return status;
    status = edge_linux_copy_user_string(
        context, user_path, scratch->path, scratch->path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    return edge_linux_build_copied_at_path(directory, scratch, workspace);
}

static int edge_linux_build_copied_at_path(
    int32_t directory, kernel_vfs_xattr_scratch_t *scratch,
    edge_linux_path_workspace_t *workspace) {
    kernel_vfs_target_t directory_target;
    const char *base;
    uint32_t base_length;
    int status;

    if (!scratch || !workspace) return -EDGE_LINUX_EIO;
    if (!scratch->path[0]) return -EDGE_LINUX_ENOENT;
    status = kernel_current_fs_snapshot(
        workspace->cwd, VFS_PATH_MAX, workspace->root, VFS_PATH_MAX);
    if (status < 0) return status;
    base = workspace->cwd;

    if (scratch->path[0] != '/' && directory != EDGE_LINUX_AT_FDCWD) {
        status = kernel_vfs_resolve_fd(directory, &directory_target);
        if (status == -EDGE_LINUX_EOPNOTSUPP)
            return -EDGE_LINUX_ENOTDIR;
        if (status < 0) return status;
        if (!directory_target.inode ||
            (directory_target.inode->mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
        if (!directory_target.resolved_path)
            return -EDGE_LINUX_EIO;
        base_length = (uint32_t)strlen(directory_target.resolved_path);
        if (base_length >= VFS_PATH_MAX)
            return -EDGE_LINUX_ENAMETOOLONG;
        memcpy(workspace->cwd, directory_target.resolved_path,
               base_length + 1u);
        base = workspace->cwd;
    }

    return kernel_fs_path_resolve(
        workspace->root, base, scratch->path,
        workspace->normalization, VFS_PATH_MAX,
        workspace->resolved, VFS_PATH_MAX);
}

static int edge_linux_resolve_at_path(
    edge_linux_syscall_context_t *context, int32_t directory,
    uint64_t user_path, kernel_vfs_xattr_scratch_t *scratch,
    edge_linux_path_workspace_t *workspace) {
    int status = edge_linux_build_at_path(
        context, directory, user_path, scratch, workspace);
    if (status < 0) return status;
    return vfs_path_search_check(
        workspace->resolved, workspace->search, VFS_PATH_MAX, 0);
}

static int edge_linux_path_copy(char *destination, uint32_t capacity,
                                const char *source) {
    uint32_t length;
    if (!destination || !capacity || !source)
        return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(source);
    if (length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(destination, source, length + 1u);
    return 0;
}

static int64_t edge_linux_sys_exec(
    edge_linux_syscall_context_t *context) {
    const uint32_t valid_execveat_flags =
        EDGE_LINUX_AT_EMPTY_PATH | EDGE_LINUX_AT_SYMLINK_NOFOLLOW;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t target;
    kernel_exec_request_t request;
    kernel_linux_identity_t identity;
    kernel_proc_task_view_t executable_view;
    uint64_t user_path;
    uint32_t flags = 0;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    int32_t magic_descriptor;
    int32_t magic_executable_owner;
    int magic_status;
    int status;

    memset(&request, 0, sizeof(request));
    if (context->id == EDGE_LINUX_SYS_execve) {
        user_path = context->arguments[0];
        request.argv_user = context->arguments[1];
        request.envp_user = context->arguments[2];
    } else if (context->id == EDGE_LINUX_SYS_execveat) {
        directory = (int32_t)(uint32_t)context->arguments[0];
        user_path = context->arguments[1];
        request.argv_user = context->arguments[2];
        request.envp_user = context->arguments[3];
        flags = (uint32_t)context->arguments[4];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }

    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_path_workspace_initialize(&scratch, &workspace);
    if (status < 0) return status;

    /*
     * Linux acquires the pathname before validating execveat flags.  This
     * makes an inaccessible pathname report EFAULT even when flags also
     * contains unknown bits.
     */
    status = edge_linux_copy_user_string(
        context, user_path, scratch.path, scratch.path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    if (flags & ~valid_execveat_flags)
        return -EDGE_LINUX_EINVAL;

    if (!scratch.path[0]) {
        kernel_vfs_descriptor_t descriptor;

        if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
            return -EDGE_LINUX_ENOENT;
        status = kernel_vfs_resolve_fd(directory, &target);
        if (status == -EDGE_LINUX_EOPNOTSUPP) {
            status = kernel_vfs_describe_descriptor(
                directory, &descriptor);
            if (status < 0) return status;
            if (descriptor.kind != KERNEL_VFS_DESCRIPTOR_MEMORY)
                return -EDGE_LINUX_EACCES;
            request.memory_descriptor = directory;
            request.memory_descriptor_supplied = 1u;
            status = edge_linux_path_copy(
                workspace.resolved, VFS_PATH_MAX,
                "/proc/self/fd/anonymous");
            request.path = workspace.resolved;
        } else {
            if (status < 0) return status;
            if (!target.inode) return -EDGE_LINUX_EACCES;
            if ((flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) &&
                (target.inode->mode & 0xf000u) == VFS_INODE_LNK)
                return -EDGE_LINUX_ELOOP;
            status = edge_linux_path_copy(
                workspace.resolved, VFS_PATH_MAX,
                target.resolved_path && target.resolved_path[0] ?
                    target.resolved_path : "/proc/self/fd/anonymous");
            request.path = workspace.resolved;
            request.inode = target.inode;
            request.superblock = target.superblock;
        }
        if (status < 0) return status;
    } else {
        status = edge_linux_build_copied_at_path(
            directory, &scratch, &workspace);
    }
    if (status < 0) return status;

    /*
     * procfs descriptor entries are Linux magic links: pathname traversal
     * follows the live open file description rather than treating the link
     * text as an ordinary on-disk symlink.  systemd intentionally pins its
     * executor and invokes it through /proc/self/fd/N, so resolve that file
     * description before entering the architecture exec machinery.
     */
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    magic_status = edge_linux_current_magic_executable(
        workspace.resolved, &identity, &magic_executable_owner);
    if (magic_status < 0) return magic_status;
    if (magic_status > 0) {
        if (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW)
            return -EDGE_LINUX_ELOOP;
        memset(&target, 0, sizeof(target));
        target.inode = &target.inode_storage;
        status = kernel_proc_task_exec_file(
            magic_executable_owner, target.inode, &target.superblock);
        if (status < 0 || !target.superblock)
            return -EDGE_LINUX_ENOENT;
        /*
         * Executing a procfs executable magic link replaces the image with
         * the pinned inode, but Linux keeps the target executable identity.
         * Retaining the literal /proc/.../exe spelling here makes the next
         * readlink report a recursive magic path and prevents applications
         * from locating resources beside their executable.
         */
        memset(&executable_view, 0, sizeof(executable_view));
        if (kernel_proc_task_view_get(
                magic_executable_owner, &executable_view) < 0 ||
            !executable_view.exec_path[0])
            return -EDGE_LINUX_ENOENT;
        status = edge_linux_path_copy(
            workspace.saved, VFS_PATH_MAX,
            executable_view.exec_path);
        if (status < 0) return status;
        request.path = workspace.saved;
        request.inode = target.inode;
        request.superblock = target.superblock;
    } else {
        magic_status = edge_linux_current_magic_fd(
            workspace.resolved, &identity, &magic_descriptor);
        if (magic_status < 0) return magic_status;
    }
    if (magic_status > 0 && !request.inode) {
        kernel_vfs_descriptor_t descriptor;

        if (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW)
            return -EDGE_LINUX_ELOOP;
        status = kernel_vfs_resolve_fd(magic_descriptor, &target);
        if (status == -EDGE_LINUX_EOPNOTSUPP) {
            status = kernel_vfs_describe_descriptor(
                magic_descriptor, &descriptor);
            if (status < 0) return status;
            if (descriptor.kind != KERNEL_VFS_DESCRIPTOR_MEMORY)
                return -EDGE_LINUX_EACCES;
            request.path = workspace.resolved;
            request.memory_descriptor = magic_descriptor;
            request.memory_descriptor_supplied = 1u;
        } else {
            if (status < 0) return status;
            if (!target.inode || !target.superblock)
                return -EDGE_LINUX_EACCES;
            status = edge_linux_path_copy(
                workspace.saved, VFS_PATH_MAX,
                target.resolved_path && target.resolved_path[0] ?
                    target.resolved_path : workspace.resolved);
            if (status < 0) return status;
            request.path = workspace.saved;
            request.inode = target.inode;
            request.superblock = target.superblock;
        }
    } else if (!request.inode) {
        request.path = workspace.resolved;
    }

    request.nofollow =
        (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) != 0;
    return kernel_process_exec(&request);
}

static int edge_linux_futex_word_access(
    edge_linux_syscall_context_t *context, uint64_t address) {
    if (address & (sizeof(uint32_t) - 1u))
        return -EDGE_LINUX_EINVAL;
    if (edge_linux_validate_user_range(
            context, address, sizeof(uint32_t), 0) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_linux_futex_timeout(
    edge_linux_syscall_context_t *context, uint64_t user_timeout,
    int32_t clock_id, int absolute, kernel_futex_request_t *request) {
    linux_timespec64_t timeout;
    uint64_t timeout_us;
    uint64_t monotonic_now;
    uint64_t duration;
    int status;

    if (!user_timeout) return 0;
    if (clock_id != LINUX_CLOCK_MONOTONIC &&
        clock_id != LINUX_CLOCK_REALTIME)
        return -EDGE_LINUX_EINVAL;
    if (edge_linux_copy_from_user(
            context, &timeout, user_timeout, sizeof(timeout)) < 0)
        return -EDGE_LINUX_EFAULT;
    status = edge_linux_timespec_microseconds(&timeout, &timeout_us);
    if (status < 0) return status;

    monotonic_now = boottime_monotonic_us();
    if (absolute) {
        uint64_t clock_now = clock_id == LINUX_CLOCK_REALTIME ?
            boottime_realtime_us() : monotonic_now;
        duration = timeout_us > clock_now ? timeout_us - clock_now : 0;
    } else {
        duration = timeout_us;
    }
    request->deadline_us = duration > UINT64_MAX - monotonic_now ?
        UINT64_MAX : monotonic_now + duration;
    request->has_timeout = 1u;
    return 0;
}

static int edge_linux_futex2_flags(uint64_t raw_flags,
                                   uint8_t *private_futex) {
    uint32_t flags;
    uint32_t allowed = EDGE_LINUX_FUTEX_32 |
                       EDGE_LINUX_FUTEX_PRIVATE_FLAG;
    if (raw_flags > UINT32_MAX) return -EDGE_LINUX_EINVAL;
    flags = (uint32_t)raw_flags;
    if ((flags & EDGE_LINUX_FUTEX2_SIZE_MASK) != EDGE_LINUX_FUTEX_32 ||
        (flags & ~allowed))
        return -EDGE_LINUX_EINVAL;
    if (private_futex)
        *private_futex =
            (flags & EDGE_LINUX_FUTEX_PRIVATE_FLAG) != 0;
    return 0;
}

static int edge_linux_futex_decode_wake_operation(
    uint32_t encoded, kernel_futex_request_t *request) {
    uint32_t operation = (encoded >> 28) & 0xfu;
    uint32_t comparison = (encoded >> 24) & 0xfu;
    int32_t operation_argument = (int32_t)((encoded >> 12) & 0xfffu);
    int32_t comparison_argument = (int32_t)(encoded & 0xfffu);

    if (operation & 8u) {
        if (operation_argument < 0 || operation_argument > 31)
            return -EDGE_LINUX_EINVAL;
        operation_argument = (int32_t)(1u << operation_argument);
        operation &= 7u;
    } else if (operation_argument & 0x800) {
        operation_argument |= (int32_t)~0xfff;
    }
    if (comparison_argument & 0x800)
        comparison_argument |= (int32_t)~0xfff;
    if (operation > KERNEL_FUTEX_ATOMIC_XOR ||
        comparison > KERNEL_FUTEX_COMPARE_GREATER_EQUAL)
        return -EDGE_LINUX_ENOSYS;

    request->atomic_operation = (kernel_futex_atomic_operation_t)operation;
    request->atomic_comparison = (kernel_futex_comparison_t)comparison;
    request->atomic_argument = operation_argument;
    request->atomic_comparison_argument = comparison_argument;
    return 0;
}

int32_t kernel_futex_atomic_apply(const kernel_futex_request_t *request,
                                  int32_t old_value) {
    if (!request) return old_value;
    switch (request->atomic_operation) {
    case KERNEL_FUTEX_ATOMIC_SET:
        return request->atomic_argument;
    case KERNEL_FUTEX_ATOMIC_ADD:
        return (int32_t)((uint32_t)old_value +
                         (uint32_t)request->atomic_argument);
    case KERNEL_FUTEX_ATOMIC_OR:
        return old_value | request->atomic_argument;
    case KERNEL_FUTEX_ATOMIC_AND_NOT:
        return old_value & ~request->atomic_argument;
    case KERNEL_FUTEX_ATOMIC_XOR:
        return old_value ^ request->atomic_argument;
    }
    return old_value;
}

int kernel_futex_atomic_compare(const kernel_futex_request_t *request,
                                int32_t old_value) {
    if (!request) return 0;
    switch (request->atomic_comparison) {
    case KERNEL_FUTEX_COMPARE_EQUAL:
        return old_value == request->atomic_comparison_argument;
    case KERNEL_FUTEX_COMPARE_NOT_EQUAL:
        return old_value != request->atomic_comparison_argument;
    case KERNEL_FUTEX_COMPARE_LESS:
        return old_value < request->atomic_comparison_argument;
    case KERNEL_FUTEX_COMPARE_LESS_EQUAL:
        return old_value <= request->atomic_comparison_argument;
    case KERNEL_FUTEX_COMPARE_GREATER:
        return old_value > request->atomic_comparison_argument;
    case KERNEL_FUTEX_COMPARE_GREATER_EQUAL:
        return old_value >= request->atomic_comparison_argument;
    }
    return 0;
}

static int64_t edge_linux_sys_futex_classic(
    edge_linux_syscall_context_t *context,
    kernel_futex_request_t *request) {
    uint32_t operation = (uint32_t)context->arguments[1];
    uint32_t command = operation & EDGE_LINUX_FUTEX_CMD_MASK;
    int status;

    request->raw_operation = operation;
    request->address = context->arguments[0];
    request->private_futex =
        (operation & EDGE_LINUX_FUTEX_PRIVATE_FLAG) != 0;
    status = edge_linux_futex_word_access(context, request->address);
    if (status < 0) return status;

    if ((operation & EDGE_LINUX_FUTEX_CLOCK_REALTIME) &&
        command != EDGE_LINUX_FUTEX_WAIT_BITSET)
        return -EDGE_LINUX_ENOSYS;

    switch (command) {
    case EDGE_LINUX_FUTEX_WAIT:
    case EDGE_LINUX_FUTEX_WAIT_BITSET:
        request->operation = KERNEL_FUTEX_WAIT;
        request->expected_value = (uint32_t)context->arguments[2];
        request->bitset = command == EDGE_LINUX_FUTEX_WAIT_BITSET ?
            (uint32_t)context->arguments[5] :
            EDGE_LINUX_FUTEX_BITSET_MATCH_ANY;
        if (!request->bitset) return -EDGE_LINUX_EINVAL;
        status = edge_linux_futex_timeout(
            context, context->arguments[3],
            operation & EDGE_LINUX_FUTEX_CLOCK_REALTIME ?
                LINUX_CLOCK_REALTIME : LINUX_CLOCK_MONOTONIC,
            command == EDGE_LINUX_FUTEX_WAIT_BITSET, request);
        if (status < 0) return status;
        break;
    case EDGE_LINUX_FUTEX_WAKE:
    case EDGE_LINUX_FUTEX_WAKE_BITSET:
        request->operation = KERNEL_FUTEX_WAKE;
        request->wake_count = (uint32_t)context->arguments[2];
        request->bitset = command == EDGE_LINUX_FUTEX_WAKE_BITSET ?
            (uint32_t)context->arguments[5] :
            EDGE_LINUX_FUTEX_BITSET_MATCH_ANY;
        if (!request->bitset) return -EDGE_LINUX_EINVAL;
        break;
    case EDGE_LINUX_FUTEX_REQUEUE:
    case EDGE_LINUX_FUTEX_CMP_REQUEUE:
        request->operation = command == EDGE_LINUX_FUTEX_REQUEUE ?
            KERNEL_FUTEX_REQUEUE : KERNEL_FUTEX_COMPARE_REQUEUE;
        request->wake_count = (uint32_t)context->arguments[2];
        request->secondary_count = (uint32_t)context->arguments[3];
        request->secondary_address = context->arguments[4];
        request->secondary_private_futex = request->private_futex;
        request->comparison_value = (uint32_t)context->arguments[5];
        status = edge_linux_futex_word_access(
            context, request->secondary_address);
        if (status < 0) return status;
        break;
    case EDGE_LINUX_FUTEX_WAKE_OP:
        request->operation = KERNEL_FUTEX_WAKE_OPERATION;
        request->wake_count = (uint32_t)context->arguments[2];
        request->secondary_count = (uint32_t)context->arguments[3];
        request->secondary_address = context->arguments[4];
        request->secondary_private_futex = request->private_futex;
        status = edge_linux_futex_word_access(
            context, request->secondary_address);
        if (status < 0) return status;
        status = edge_linux_futex_decode_wake_operation(
            (uint32_t)context->arguments[5], request);
        if (status < 0) return status;
        break;
    default:
        return -EDGE_LINUX_ENOSYS;
    }
    return kernel_futex_execute(request);
}

static int64_t edge_linux_sys_futex_wait_vector(
    edge_linux_syscall_context_t *context,
    kernel_futex_request_t *request) {
    uint64_t vector_user = context->arguments[0];
    uint64_t count_user = context->arguments[1];
    uint32_t count;
    int status;

    if (context->arguments[2] || !vector_user || !count_user ||
        count_user > EDGE_LINUX_FUTEX_WAITV_MAX)
        return -EDGE_LINUX_EINVAL;
    count = (uint32_t)count_user;
    if (edge_linux_validate_user_range(
            context, vector_user,
            (uint64_t)count * sizeof(struct edge_futex_waitv), 0) < 0)
        return -EDGE_LINUX_EFAULT;

    request->operation = KERNEL_FUTEX_WAIT_VECTOR;
    request->waiter_count = (uint16_t)count;
    request->bitset = EDGE_LINUX_FUTEX_BITSET_MATCH_ANY;
    for (uint32_t index = 0; index < count; ++index) {
        struct edge_futex_waitv waiter;
        uint32_t allowed = EDGE_LINUX_FUTEX_32 |
                           EDGE_LINUX_FUTEX_PRIVATE_FLAG;
        if (edge_linux_copy_from_user(
                context, &waiter,
                vector_user + (uint64_t)index * sizeof(waiter),
                sizeof(waiter)) < 0)
            return -EDGE_LINUX_EFAULT;
        if (waiter.reserved || waiter.val > UINT32_MAX ||
            (waiter.flags & EDGE_LINUX_FUTEX2_SIZE_MASK) !=
                EDGE_LINUX_FUTEX_32 ||
            (waiter.flags & ~allowed))
            return -EDGE_LINUX_EINVAL;
        status = edge_linux_futex_word_access(
            context, waiter.uaddr);
        if (status < 0) return status;
        request->waiters[index].address = waiter.uaddr;
        request->waiters[index].expected_value =
            (uint32_t)waiter.val;
        request->waiters[index].private_futex =
            (waiter.flags & EDGE_LINUX_FUTEX_PRIVATE_FLAG) != 0;
    }

    status = edge_linux_futex_timeout(
        context, context->arguments[3],
        (int32_t)(uint32_t)context->arguments[4], 1, request);
    if (status < 0) return status;
    return kernel_futex_execute(request);
}

static int64_t edge_linux_sys_futex_split(
    edge_linux_syscall_context_t *context,
    kernel_futex_request_t *request) {
    int status;

    if (context->id == EDGE_LINUX_SYS_futex_wake) {
        request->operation = KERNEL_FUTEX_WAKE;
        request->address = context->arguments[0];
        if (!context->arguments[1] || context->arguments[1] > UINT32_MAX ||
            context->arguments[2] > INT32_MAX)
            return -EDGE_LINUX_EINVAL;
        request->bitset = (uint32_t)context->arguments[1];
        request->wake_count = (uint32_t)context->arguments[2];
        status = edge_linux_futex2_flags(
            context->arguments[3], &request->private_futex);
        if (status < 0) return status;
        status = edge_linux_futex_word_access(context, request->address);
        if (status < 0) return status;
        return kernel_futex_execute(request);
    }

    if (context->id == EDGE_LINUX_SYS_futex_wait) {
        request->operation = KERNEL_FUTEX_WAIT;
        request->address = context->arguments[0];
        if (context->arguments[1] > UINT32_MAX ||
            !context->arguments[2] || context->arguments[2] > UINT32_MAX)
            return -EDGE_LINUX_EINVAL;
        request->expected_value = (uint32_t)context->arguments[1];
        request->bitset = (uint32_t)context->arguments[2];
        status = edge_linux_futex2_flags(
            context->arguments[3], &request->private_futex);
        if (status < 0) return status;
        status = edge_linux_futex_word_access(context, request->address);
        if (status < 0) return status;
        status = edge_linux_futex_timeout(
            context, context->arguments[4],
            (int32_t)(uint32_t)context->arguments[5], 1, request);
        if (status < 0) return status;
        return kernel_futex_execute(request);
    }

    if (context->id == EDGE_LINUX_SYS_futex_requeue) {
        struct edge_futex_waitv futexes[2];
        int32_t wake_count = (int32_t)(uint32_t)context->arguments[2];
        int32_t requeue_count = (int32_t)(uint32_t)context->arguments[3];
        uint64_t vector_user = context->arguments[0];

        if (context->arguments[1] || wake_count < 0 || requeue_count < 0)
            return -EDGE_LINUX_EINVAL;
        if (!vector_user) return -EDGE_LINUX_EINVAL;
        if (edge_linux_copy_from_user(
                context, futexes, vector_user, sizeof(futexes)) < 0)
            return -EDGE_LINUX_EFAULT;
        for (uint32_t index = 0; index < 2; ++index) {
            uint8_t *private_futex = index ?
                &request->secondary_private_futex :
                &request->private_futex;
            if (futexes[index].reserved ||
                futexes[index].val > UINT32_MAX)
                return -EDGE_LINUX_EINVAL;
            status = edge_linux_futex2_flags(
                futexes[index].flags, private_futex);
            if (status < 0) return status;
        }
        request->operation = KERNEL_FUTEX_COMPARE_REQUEUE;
        request->address = futexes[0].uaddr;
        request->secondary_address = futexes[1].uaddr;
        request->wake_count = (uint32_t)wake_count;
        request->secondary_count = (uint32_t)requeue_count;
        request->comparison_value = (uint32_t)futexes[0].val;
        status = edge_linux_futex_word_access(context, request->address);
        if (status < 0) return status;
        status = edge_linux_futex_word_access(
            context, request->secondary_address);
        if (status < 0) return status;
        return kernel_futex_execute(request);
    }
    return -EDGE_LINUX_ENOSYS;
}

static int64_t edge_linux_sys_futex(
    edge_linux_syscall_context_t *context) {
    kernel_futex_scratch_t scratch;
    kernel_futex_request_t *request;
    if (!context || !context->current_task)
        return -EDGE_LINUX_ESRCH;
    if (kernel_futex_current_scratch(&scratch) < 0 || !scratch.memory ||
        scratch.capacity < sizeof(*request))
        return -EDGE_LINUX_EIO;
    request = (kernel_futex_request_t *)scratch.memory;
    memset(request, 0, sizeof(*request));
    request->user_registers = context->user_registers;
    if (context->id == EDGE_LINUX_SYS_futex)
        return edge_linux_sys_futex_classic(context, request);
    if (context->id == EDGE_LINUX_SYS_futex_waitv)
        return edge_linux_sys_futex_wait_vector(context, request);
    return edge_linux_sys_futex_split(context, request);
}

static int64_t edge_linux_sys_clone(
    edge_linux_syscall_context_t *context) {
    kernel_clone_request_t request;
    uint64_t raw_flags;

    if (!context || !context->user_registers)
        return -EDGE_LINUX_EINVAL;
    memset(&request, 0, sizeof(request));
    request.user_registers = context->user_registers;

    if (context->id == EDGE_LINUX_SYS_fork ||
        context->id == EDGE_LINUX_SYS_vfork) {
        request.flags = context->id == EDGE_LINUX_SYS_vfork ?
            EDGE_LINUX_CLONE_VM | EDGE_LINUX_CLONE_VFORK : 0;
        request.exit_signal = EDGE_LINUX_SIGCHLD;
    } else if (context->id == EDGE_LINUX_SYS_clone3) {
        struct edge_linux_clone_args arguments;
        int copied = edge_linux_copy_struct_from_user(
            &arguments, sizeof(arguments), 64u,
            context->arguments[0], context->arguments[1],
            edge_linux_seccomp_copy_from_user, context);
        if (copied < 0) return copied;
        if (arguments.flags & ~EDGE_LINUX_CLONE_SUPPORTED_FLAGS)
            return -EDGE_LINUX_EINVAL;
        if (arguments.exit_signal > 64u)
            return -EDGE_LINUX_EINVAL;
        if ((arguments.stack == 0) != (arguments.stack_size == 0))
            return -EDGE_LINUX_EINVAL;
        if (arguments.stack) {
            request.child_stack = arguments.stack + arguments.stack_size;
            if (request.child_stack < arguments.stack)
                return -EDGE_LINUX_EINVAL;
        }
        if (arguments.set_tid || arguments.set_tid_size)
            return -EDGE_LINUX_EOPNOTSUPP;
        request.flags = arguments.flags;
        request.exit_signal = (uint32_t)arguments.exit_signal;
        request.parent_tid_user = arguments.parent_tid;
        request.child_tid_user = arguments.child_tid;
        request.tls = arguments.tls;
        request.pidfd_user = (arguments.flags & EDGE_LINUX_CLONE_PIDFD) ?
            arguments.pidfd : 0;
        request.cgroup_descriptor =
            (arguments.flags & EDGE_LINUX_CLONE_INTO_CGROUP) ?
            arguments.cgroup : 0;
        request.clone3 = 1u;
    } else if (context->id == EDGE_LINUX_SYS_clone) {
        raw_flags = context->arguments[0];
        /* Legacy clone consumes the original 32-bit flag word. */
        request.flags = raw_flags & 0xffffff00ULL;
        request.exit_signal = (uint32_t)(raw_flags & 0xffu);
        request.child_stack = context->arguments[1];
        request.parent_tid_user = context->arguments[2];
        if (context->architecture == EDGE_LINUX_ARCH_AARCH64) {
            request.tls = context->arguments[3];
            request.child_tid_user = context->arguments[4];
        } else {
            request.child_tid_user = context->arguments[3];
            request.tls = context->arguments[4];
        }
        request.pidfd_user = (request.flags & EDGE_LINUX_CLONE_PIDFD) ?
            request.parent_tid_user : 0;
        if (request.flags & ~EDGE_LINUX_CLONE_SUPPORTED_FLAGS)
            return -EDGE_LINUX_EINVAL;
        if (request.exit_signal > 64u)
            return -EDGE_LINUX_EINVAL;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }

    if ((request.flags & EDGE_LINUX_CLONE_SIGHAND) &&
        !(request.flags & EDGE_LINUX_CLONE_VM))
        return -EDGE_LINUX_EINVAL;
    if ((request.flags & EDGE_LINUX_CLONE_THREAD) &&
        (!(request.flags & EDGE_LINUX_CLONE_SIGHAND) ||
         request.exit_signal ||
         (request.flags & (EDGE_LINUX_CLONE_NEWUSER |
                           EDGE_LINUX_CLONE_NEWPID))))
        return -EDGE_LINUX_EINVAL;
    if ((request.flags & EDGE_LINUX_CLONE_NEWUSER) &&
        (request.flags & (EDGE_LINUX_CLONE_FS |
                          EDGE_LINUX_CLONE_THREAD)))
        return -EDGE_LINUX_EINVAL;
    if ((request.flags & EDGE_LINUX_CLONE_NEWNS) &&
        (request.flags & EDGE_LINUX_CLONE_FS))
        return -EDGE_LINUX_EINVAL;
    if ((request.flags & EDGE_LINUX_CLONE_NEWPID) &&
        (request.flags & (EDGE_LINUX_CLONE_THREAD |
                          EDGE_LINUX_CLONE_PARENT)))
        return -EDGE_LINUX_EINVAL;
    if ((request.flags & EDGE_LINUX_CLONE_CLEAR_SIGHAND) &&
        (request.flags & EDGE_LINUX_CLONE_SIGHAND))
        return -EDGE_LINUX_EINVAL;
    if ((request.flags & EDGE_LINUX_CLONE_PIDFD) &&
        (request.flags & EDGE_LINUX_CLONE_THREAD))
        return -EDGE_LINUX_EINVAL;
    if (!request.clone3 &&
        (request.flags & EDGE_LINUX_CLONE_PIDFD) &&
        (request.flags & EDGE_LINUX_CLONE_PARENT_SETTID))
        return -EDGE_LINUX_EINVAL;
    if ((request.flags & EDGE_LINUX_CLONE_PIDFD) && !request.pidfd_user)
        return -EDGE_LINUX_EFAULT;
    if ((request.flags & EDGE_LINUX_CLONE_PARENT_SETTID) &&
        !request.parent_tid_user)
        return -EDGE_LINUX_EFAULT;
    if ((request.flags & EDGE_LINUX_CLONE_CHILD_SETTID) &&
        !request.child_tid_user)
        return -EDGE_LINUX_EFAULT;
    if ((request.flags & EDGE_LINUX_CLONE_THREAD) && !request.child_stack)
        return -EDGE_LINUX_EINVAL;
    if (request.child_stack && edge_linux_validate_user_range(
            context, request.child_stack, 1u, 0) < 0)
        return request.clone3 ? -EDGE_LINUX_EINVAL :
                                -EDGE_LINUX_EFAULT;

    return kernel_process_clone(&request);
}

static int64_t edge_linux_sys_swap(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    kernel_vfs_xattr_scratch_t scratch;
    int status;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EPERM;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0 || !scratch.path || !scratch.path_capacity)
        return status < 0 ? status : -EDGE_LINUX_EIO;
    status = edge_linux_copy_user_string(
        context, context->arguments[0], scratch.path,
        scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    if (context->id == EDGE_LINUX_SYS_swapon)
        return swap_enable_path(scratch.path,
                                (uint32_t)context->arguments[1]);
    if (context->id == EDGE_LINUX_SYS_swapoff)
        return swap_disable_path(scratch.path);
    return -EDGE_LINUX_ENOSYS;
}

static int edge_linux_path_has_trailing_slash(const char *path) {
    uint32_t length;
    if (!path) return 0;
    length = (uint32_t)strlen(path);
    return length > 1u && path[length - 1u] == '/';
}

static int edge_linux_path_final_dot_component(const char *path) {
    const char *component;
    uint32_t length;
    if (!path || !path[0]) return 0;
    length = (uint32_t)strlen(path);
    while (length > 1u && path[length - 1u] == '/') --length;
    component = path + length;
    while (component > path && component[-1] != '/') --component;
    if (length - (uint32_t)(component - path) == 1u &&
        component[0] == '.')
        return 1;
    if (length - (uint32_t)(component - path) == 2u &&
        component[0] == '.' && component[1] == '.')
        return 2;
    return 0;
}

static int edge_linux_path_split_parent(const char *path, char *parent,
                                        uint32_t parent_capacity,
                                        char *leaf, uint32_t leaf_capacity) {
    uint32_t length;
    uint32_t slash;
    uint32_t leaf_length;
    if (!path || path[0] != '/' || !parent || !leaf ||
        parent_capacity < 2u || !leaf_capacity)
        return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(path);
    while (length > 1u && path[length - 1u] == '/') --length;
    slash = length;
    while (slash > 0u && path[slash - 1u] != '/') --slash;
    if (!slash || slash == length) return -EDGE_LINUX_EINVAL;
    leaf_length = length - slash;
    if (leaf_length >= leaf_capacity)
        return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(leaf, path + slash, leaf_length);
    leaf[leaf_length] = 0;
    if (slash <= 1u) {
        parent[0] = '/';
        parent[1] = 0;
        return 0;
    }
    if (slash > parent_capacity) return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(parent, path, slash - 1u);
    parent[slash - 1u] = 0;
    return 0;
}

static int edge_linux_path_parent_target(
    const char *path, char *parent_path, char *leaf,
    kernel_vfs_target_t *parent_target) {
    int status;
    if (!parent_target) return -EDGE_LINUX_EINVAL;
    status = edge_linux_path_split_parent(
        path, parent_path, VFS_PATH_MAX, leaf, VFS_NAME_MAX);
    if (status < 0) return status;
    parent_target->inode = &parent_target->inode_storage;
    parent_target->superblock = 0;
    parent_target->resolved_path = parent_path;
    if (vfs_resolve(parent_path, parent_target->inode,
                    &parent_target->superblock, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    if ((parent_target->inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    return 0;
}

static int edge_linux_path_mutation_permission(
    const vfs_inode_t *parent, const vfs_inode_t *victim) {
    kernel_linux_identity_t identity;
    if (!parent) return -EDGE_LINUX_EIO;
    if (vfs_permission_check(parent, 3) < 0)
        return -EDGE_LINUX_EACCES;
    /* Linux sticky directories restrict removal and replacement, not the
     * creation of a previously absent directory entry. */
    if (!victim || !(parent->mode & 01000u)) return 0;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (identity.fsuid == parent->uid ||
        (victim && identity.fsuid == victim->uid) ||
        ((identity.effective_capabilities >> EDGE_LINUX_CAP_FOWNER) & 1u))
        return 0;
    return -EDGE_LINUX_EPERM;
}

static int edge_linux_target_from_resolved(
    const char *path, int nofollow, kernel_vfs_target_t *target) {
    if (!path || !target) return -EDGE_LINUX_EINVAL;
    memset(target, 0, sizeof(*target));
    target->inode = &target->inode_storage;
    target->resolved_path = path;
    if (nofollow ?
        vfs_resolve_nofollow(path, target->inode, &target->superblock) < 0 :
        vfs_resolve(path, target->inode, &target->superblock, 0, 0) < 0)
        return -EDGE_LINUX_ENOENT;
    return 0;
}

static int64_t edge_linux_sys_access(
    edge_linux_syscall_context_t *context) {
    linux_credential_state_t credentials;
    linux_group_list_t groups;
    kernel_file_metadata_t metadata;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t target;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t user_path;
    uint32_t mode;
    uint32_t flags = 0;
    uint32_t uid;
    uint32_t gid;
    uint64_t capabilities;
    int trailing_slash;
    int status;

    if (context->id == EDGE_LINUX_SYS_access) {
        user_path = context->arguments[0];
        mode = (uint32_t)context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_faccessat ||
               context->id == EDGE_LINUX_SYS_faccessat2) {
        directory = (int32_t)context->arguments[0];
        user_path = context->arguments[1];
        mode = (uint32_t)context->arguments[2];
        if (context->id == EDGE_LINUX_SYS_faccessat2)
            flags = (uint32_t)context->arguments[3];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (mode & ~7u) return -EDGE_LINUX_EINVAL;
    if (flags & ~(EDGE_LINUX_AT_EACCESS |
                  EDGE_LINUX_AT_SYMLINK_NOFOLLOW |
                  EDGE_LINUX_AT_EMPTY_PATH))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_credentials_get(&credentials) < 0)
        return -EDGE_LINUX_ESRCH;
    linux_group_list_init(&groups);
    if (kernel_current_groups_snapshot(&groups) < 0)
        return -EDGE_LINUX_ESRCH;
    if (flags & EDGE_LINUX_AT_EACCESS) {
        uid = credentials.euid;
        gid = credentials.egid;
        capabilities = credentials.capabilities.effective;
    } else {
        uid = credentials.uid;
        gid = credentials.gid;
        capabilities = uid == 0 ? credentials.capabilities.permitted : 0;
    }

    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) goto access_out;
    status = edge_linux_path_workspace_initialize(&scratch, &workspace);
    if (status < 0) goto access_out;
    status = edge_linux_copy_user_string(
        context, user_path, scratch.path, scratch.path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) goto access_out;
    if (!scratch.path[0]) {
        if (!(flags & EDGE_LINUX_AT_EMPTY_PATH)) {
            status = -EDGE_LINUX_ENOENT;
            goto access_out;
        }
        status = kernel_vfs_resolve_fd(directory, &target);
        goto access_permission;
    }
    trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
    status = edge_linux_build_at_path(
        context, directory, user_path, &scratch, &workspace);
    if (status < 0) goto access_out;
    status = vfs_path_search_check_as(
        workspace.resolved, workspace.search, VFS_PATH_MAX, 0,
        uid, gid, &groups, capabilities);
    if (status < 0) goto access_out;
    status = edge_linux_target_from_resolved(
        workspace.resolved,
        (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) && !trailing_slash,
        &target);
    if (status == -EDGE_LINUX_ENOENT &&
        !(flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) && !trailing_slash &&
        kernel_vfs_metadata_at(EDGE_LINUX_AT_FDCWD, workspace.resolved, 0,
                               &metadata) == 0) {
        memset(&target, 0, sizeof(target));
        target.inode = &target.inode_storage;
        target.resolved_path = workspace.resolved;
        target.inode_storage.ino = (uint32_t)metadata.inode;
        target.inode_storage.mode = metadata.mode;
        target.inode_storage.nlink = metadata.links;
        target.inode_storage.nlink_valid = 1u;
        target.inode_storage.uid = metadata.uid;
        target.inode_storage.gid = metadata.gid;
        target.inode_storage.size = metadata.size;
        status = 0;
    }
    if (status < 0) goto access_out;
    if (trailing_slash &&
        (target.inode->mode & 0xf000u) != VFS_INODE_DIR) {
        status = -EDGE_LINUX_ENOTDIR;
        goto access_out;
    }

access_permission:
    if (status < 0) goto access_out;
    status = mode ? vfs_permission_check_as(
        target.inode, (int)mode, uid, gid, &groups, capabilities) : 0;
access_out:
    linux_group_list_release(&groups);
    return status;
}

static int64_t edge_linux_sys_chmod(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t target;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t user_path = 0;
    uint32_t mode;
    uint32_t flags = 0;
    int descriptor_form = 0;
    int trailing_slash = 0;
    int status;

    if (context->id == EDGE_LINUX_SYS_fchmod) {
        descriptor_form = 1;
        directory = (int32_t)context->arguments[0];
        mode = (uint32_t)context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_chmod) {
        user_path = context->arguments[0];
        mode = (uint32_t)context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_fchmodat ||
               context->id == EDGE_LINUX_SYS_fchmodat2) {
        directory = (int32_t)context->arguments[0];
        user_path = context->arguments[1];
        mode = (uint32_t)context->arguments[2];
        if (context->id == EDGE_LINUX_SYS_fchmodat2)
            flags = (uint32_t)context->arguments[3];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (flags & ~(EDGE_LINUX_AT_SYMLINK_NOFOLLOW |
                  EDGE_LINUX_AT_EMPTY_PATH))
        return -EDGE_LINUX_EINVAL;
    if (descriptor_form) {
        status = kernel_vfs_resolve_fd(directory, &target);
        if (status < 0) return status;
        if (target.path_only) return -EDGE_LINUX_EBADF;
    } else {
        status = kernel_vfs_current_xattr_scratch(&scratch);
        if (status < 0) return status;
        status = edge_linux_path_workspace_initialize(&scratch, &workspace);
        if (status < 0) return status;
        status = edge_linux_copy_user_string(
            context, user_path, scratch.path, scratch.path_capacity,
            EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        if (!scratch.path[0]) {
            if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
                return -EDGE_LINUX_ENOENT;
            status = kernel_vfs_resolve_fd(directory, &target);
            if (status < 0) return status;
        } else {
            trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
            status = edge_linux_resolve_at_path(
                context, directory, user_path, &scratch, &workspace);
            if (status < 0) return status;
            status = edge_linux_target_from_resolved(
                workspace.resolved,
                (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) && !trailing_slash,
                &target);
            if (status < 0) return status;
            if (trailing_slash &&
                (target.inode->mode & 0xf000u) != VFS_INODE_DIR)
                return -EDGE_LINUX_ENOTDIR;
        }
    }
    if ((flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) && !trailing_slash &&
        (target.inode->mode & 0xf000u) == VFS_INODE_LNK)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (identity.fsuid != target.inode->uid &&
        !(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_FOWNER)))
        return -EDGE_LINUX_EPERM;
    mode &= 07777u;
    if ((mode & 02000u) &&
        !(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_FSETID)) &&
        !kernel_current_in_group(target.inode->gid))
        mode &= ~02000u;
    if (vfs_inode_setattr(
            target.superblock, target.inode, (uint16_t)mode, 0, 0,
            VFS_SETATTR_MODE | VFS_SETATTR_CTIME) < 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    kernel_vfs_notify_attrib(target.resolved_path);
    return 0;
}

static int64_t edge_linux_sys_chown(
    edge_linux_syscall_context_t *context) {
    kernel_linux_identity_t identity;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t target;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t user_path = 0;
    uint32_t requested_uid;
    uint32_t requested_gid;
    uint32_t flags = 0;
    uint32_t valid = VFS_SETATTR_CTIME;
    uint16_t mode;
    int descriptor_form = 0;
    int nofollow = 0;
    int trailing_slash = 0;
    int privileged;
    int status;

    if (context->id == EDGE_LINUX_SYS_fchown) {
        descriptor_form = 1;
        directory = (int32_t)context->arguments[0];
        requested_uid = (uint32_t)context->arguments[1];
        requested_gid = (uint32_t)context->arguments[2];
    } else if (context->id == EDGE_LINUX_SYS_chown ||
               context->id == EDGE_LINUX_SYS_lchown) {
        user_path = context->arguments[0];
        requested_uid = (uint32_t)context->arguments[1];
        requested_gid = (uint32_t)context->arguments[2];
        nofollow = context->id == EDGE_LINUX_SYS_lchown;
    } else if (context->id == EDGE_LINUX_SYS_fchownat) {
        directory = (int32_t)context->arguments[0];
        user_path = context->arguments[1];
        requested_uid = (uint32_t)context->arguments[2];
        requested_gid = (uint32_t)context->arguments[3];
        flags = (uint32_t)context->arguments[4];
        nofollow = (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) != 0;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (flags & ~(EDGE_LINUX_AT_SYMLINK_NOFOLLOW |
                  EDGE_LINUX_AT_EMPTY_PATH))
        return -EDGE_LINUX_EINVAL;
    if (descriptor_form) {
        status = kernel_vfs_resolve_fd(directory, &target);
        if (status == -EDGE_LINUX_EOPNOTSUPP) {
            kernel_vfs_descriptor_t description;
            kernel_pipe_metadata_t metadata;

            status = kernel_vfs_describe_descriptor(
                directory, &description);
            if (status < 0) return status;
            if (description.kind != KERNEL_VFS_DESCRIPTOR_PIPE ||
                !description.pipe ||
                kernel_pipe_metadata_snapshot(
                    description.pipe, &metadata) < 0)
                return -EDGE_LINUX_EOPNOTSUPP;
            if (kernel_current_linux_identity(&identity) < 0)
                return -EDGE_LINUX_ESRCH;
            privileged = (identity.effective_capabilities &
                          (1ULL << EDGE_LINUX_CAP_CHOWN)) != 0;
            if (!privileged) {
                if (identity.fsuid != metadata.uid)
                    return -EDGE_LINUX_EPERM;
                if (requested_uid != UINT32_MAX &&
                    requested_uid != metadata.uid)
                    return -EDGE_LINUX_EPERM;
                if (requested_gid != UINT32_MAX &&
                    requested_gid != metadata.gid &&
                    !kernel_current_in_group(requested_gid))
                    return -EDGE_LINUX_EPERM;
            }
            return kernel_pipe_metadata_chown(
                description.pipe, requested_uid, requested_gid);
        }
        if (status < 0) return status;
        if (target.path_only) return -EDGE_LINUX_EBADF;
    } else {
        status = kernel_vfs_current_xattr_scratch(&scratch);
        if (status < 0) return status;
        status = edge_linux_path_workspace_initialize(&scratch, &workspace);
        if (status < 0) return status;
        status = edge_linux_copy_user_string(
            context, user_path, scratch.path, scratch.path_capacity,
            EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        if (!scratch.path[0]) {
            if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
                return -EDGE_LINUX_ENOENT;
            status = kernel_vfs_resolve_fd(directory, &target);
            if (status < 0) return status;
        } else {
            trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
            status = edge_linux_resolve_at_path(
                context, directory, user_path, &scratch, &workspace);
            if (status < 0) return status;
            status = edge_linux_target_from_resolved(
                workspace.resolved, nofollow && !trailing_slash, &target);
            if (status < 0) return status;
            if (trailing_slash &&
                (target.inode->mode & 0xf000u) != VFS_INODE_DIR)
                return -EDGE_LINUX_ENOTDIR;
        }
    }
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    privileged = (identity.effective_capabilities &
                  (1ULL << EDGE_LINUX_CAP_CHOWN)) != 0;
    if (!privileged) {
        if (identity.fsuid != target.inode->uid)
            return -EDGE_LINUX_EPERM;
        if (requested_uid != UINT32_MAX &&
            requested_uid != target.inode->uid)
            return -EDGE_LINUX_EPERM;
        if (requested_gid != UINT32_MAX &&
            requested_gid != target.inode->gid &&
            !kernel_current_in_group(requested_gid))
            return -EDGE_LINUX_EPERM;
    }
    if (requested_uid != UINT32_MAX) valid |= VFS_SETATTR_UID;
    if (requested_gid != UINT32_MAX) valid |= VFS_SETATTR_GID;
    mode = (uint16_t)(target.inode->mode & 07777u);
    if ((target.inode->mode & 0xf000u) == VFS_INODE_FILE) {
        uint16_t changed = mode;
        changed &= ~04000u;
        if (changed & 0010u) changed &= ~02000u;
        if (changed != mode) {
            mode = changed;
            valid |= VFS_SETATTR_MODE;
        }
    }
    if (vfs_inode_setattr(
            target.superblock, target.inode, mode,
            requested_uid == UINT32_MAX ? target.inode->uid : requested_uid,
            requested_gid == UINT32_MAX ? target.inode->gid : requested_gid,
            valid) < 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    kernel_vfs_notify_attrib(target.resolved_path);
    return 0;
}

typedef struct edge_linux_timestamp_update {
    uint32_t atime;
    uint32_t mtime;
    int set_atime;
    int set_mtime;
    int explicit_value;
} edge_linux_timestamp_update_t;

typedef struct edge_linux_utimbuf64 {
    int64_t actime;
    int64_t modtime;
} edge_linux_utimbuf64_t;

static int edge_linux_timestamp_seconds(int64_t seconds, uint32_t *result) {
    if (!result) return -EDGE_LINUX_EINVAL;
    if (seconds < 0 || (uint64_t)seconds > UINT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;
    *result = (uint32_t)seconds;
    return 0;
}

static int edge_linux_timestamp_from_timespec(
    const linux_timespec64_t *value, uint32_t now,
    uint32_t *seconds, int *set, int *explicit_value) {
    if (value->tv_nsec == EDGE_LINUX_UTIME_OMIT) {
        *set = 0;
        return 0;
    }
    *set = 1;
    if (value->tv_nsec == EDGE_LINUX_UTIME_NOW) {
        *seconds = now;
        return 0;
    }
    if (value->tv_nsec < 0 || value->tv_nsec >= 1000000000LL)
        return -EDGE_LINUX_EINVAL;
    *explicit_value = 1;
    return edge_linux_timestamp_seconds(value->tv_sec, seconds);
}

static int edge_linux_timestamp_update_parse(
    edge_linux_syscall_context_t *context, uint64_t user_times,
    int timeval_form, int utimbuf_form,
    edge_linux_timestamp_update_t *update) {
    linux_timeval64_t now_value;
    if (!update) return -EDGE_LINUX_EINVAL;
    memset(update, 0, sizeof(*update));
    linux_gettimeofday_value(&now_value);
    update->atime = update->mtime = (uint32_t)now_value.tv_sec;
    update->set_atime = update->set_mtime = 1;
    if (!user_times) return 0;
    if (utimbuf_form) {
        edge_linux_utimbuf64_t value;
        int status;
        if (edge_linux_copy_from_user(
                context, &value, user_times, sizeof(value)) < 0)
            return -EDGE_LINUX_EFAULT;
        status = edge_linux_timestamp_seconds(value.actime, &update->atime);
        if (status < 0) return status;
        status = edge_linux_timestamp_seconds(value.modtime, &update->mtime);
        if (status < 0) return status;
        update->explicit_value = 1;
        return 0;
    }
    if (timeval_form) {
        linux_timeval64_t values[2];
        if (edge_linux_copy_from_user(
                context, values, user_times, sizeof(values)) < 0)
            return -EDGE_LINUX_EFAULT;
        for (uint32_t index = 0; index < 2u; ++index)
            if (values[index].tv_usec < 0 ||
                values[index].tv_usec >= 1000000LL)
                return -EDGE_LINUX_EINVAL;
        if (edge_linux_timestamp_seconds(
                values[0].tv_sec, &update->atime) < 0 ||
            edge_linux_timestamp_seconds(
                values[1].tv_sec, &update->mtime) < 0)
            return -EDGE_LINUX_EOVERFLOW;
        update->explicit_value = 1;
        return 0;
    }
    {
        linux_timespec64_t values[2];
        int status;
        if (edge_linux_copy_from_user(
                context, values, user_times, sizeof(values)) < 0)
            return -EDGE_LINUX_EFAULT;
        status = edge_linux_timestamp_from_timespec(
            &values[0], update->atime, &update->atime,
            &update->set_atime, &update->explicit_value);
        if (status < 0) return status;
        return edge_linux_timestamp_from_timespec(
            &values[1], update->mtime, &update->mtime,
            &update->set_mtime, &update->explicit_value);
    }
}

static int64_t edge_linux_sys_utimens(
    edge_linux_syscall_context_t *context) {
    edge_linux_timestamp_update_t update;
    kernel_linux_identity_t identity;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t target;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t user_path;
    uint64_t user_times;
    uint32_t flags = 0;
    int timeval_form = 0;
    int utimbuf_form = 0;
    int descriptor_form = 0;
    int trailing_slash = 0;
    int status;

    if (context->id == EDGE_LINUX_SYS_utimensat) {
        directory = (int32_t)context->arguments[0];
        user_path = context->arguments[1];
        user_times = context->arguments[2];
        flags = (uint32_t)context->arguments[3];
        descriptor_form = user_path == 0;
    } else if (context->id == EDGE_LINUX_SYS_futimesat) {
        directory = (int32_t)context->arguments[0];
        user_path = context->arguments[1];
        user_times = context->arguments[2];
        timeval_form = 1;
        descriptor_form = user_path == 0;
    } else if (context->id == EDGE_LINUX_SYS_utimes) {
        user_path = context->arguments[0];
        user_times = context->arguments[1];
        timeval_form = 1;
    } else if (context->id == EDGE_LINUX_SYS_utime) {
        user_path = context->arguments[0];
        user_times = context->arguments[1];
        utimbuf_form = 1;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (flags & ~(EDGE_LINUX_AT_SYMLINK_NOFOLLOW |
                  EDGE_LINUX_AT_EMPTY_PATH))
        return -EDGE_LINUX_EINVAL;
    if (descriptor_form && flags) return -EDGE_LINUX_EINVAL;
    status = edge_linux_timestamp_update_parse(
        context, user_times, timeval_form, utimbuf_form, &update);
    if (status < 0) return status;

    if (descriptor_form) {
        if (directory == EDGE_LINUX_AT_FDCWD) return -EDGE_LINUX_EBADF;
        status = kernel_vfs_resolve_fd(directory, &target);
        if (status < 0) return status;
        if (target.path_only) return -EDGE_LINUX_EBADF;
    } else {
        status = kernel_vfs_current_xattr_scratch(&scratch);
        if (status < 0) return status;
        status = edge_linux_path_workspace_initialize(&scratch, &workspace);
        if (status < 0) return status;
        status = edge_linux_copy_user_string(
            context, user_path, scratch.path, scratch.path_capacity,
            EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        if (!scratch.path[0]) {
            if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
                return -EDGE_LINUX_ENOENT;
            status = kernel_vfs_resolve_fd(directory, &target);
            if (status < 0) return status;
        } else {
            trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
            status = edge_linux_resolve_at_path(
                context, directory, user_path, &scratch, &workspace);
            if (status < 0) return status;
            status = edge_linux_target_from_resolved(
                workspace.resolved,
                (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) && !trailing_slash,
                &target);
            if (status < 0) return status;
            if (trailing_slash &&
                (target.inode->mode & 0xf000u) != VFS_INODE_DIR)
                return -EDGE_LINUX_ENOTDIR;
        }
    }
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (update.set_atime || update.set_mtime) {
        int owner = identity.fsuid == target.inode->uid;
        int capable = (identity.effective_capabilities &
                       (1ULL << EDGE_LINUX_CAP_FOWNER)) != 0;
        if (update.explicit_value) {
            if (!owner && !capable) return -EDGE_LINUX_EPERM;
        } else if (!owner && !capable &&
                   vfs_permission_check(target.inode, 2) < 0) {
            return -EDGE_LINUX_EACCES;
        }
    }
    if (vfs_inode_utimens(
            target.superblock, target.inode, update.atime, update.mtime,
            update.set_atime, update.set_mtime) < 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (update.set_atime || update.set_mtime)
        kernel_vfs_notify_attrib(target.resolved_path);
    return 0;
}

static int64_t edge_linux_sys_mkdir(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t user_path;
    uint32_t requested_mode;
    uint16_t mode;
    uint16_t mask;
    int status;

    if (context->id == EDGE_LINUX_SYS_mkdir) {
        user_path = context->arguments[0];
        requested_mode = (uint32_t)context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_mkdirat) {
        directory = (int32_t)context->arguments[0];
        user_path = context->arguments[1];
        requested_mode = (uint32_t)context->arguments[2];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_resolve_at_path(
        context, directory, user_path, &scratch, &workspace);
    if (status < 0) return status;

    mask = (uint16_t)(kernel_current_umask() & 0777u);
    mode = (uint16_t)(requested_mode & 07777u);
    mode = (uint16_t)((mode & 07000u) | ((mode & 0777u) & ~mask));
    status = vfs_mkdir_mode(workspace.resolved, mode);
    if (status < 0) return status;
    kernel_vfs_notify_create(workspace.resolved, 1);
    return 0;
}

static int64_t edge_linux_sys_mknod(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t parent;
    kernel_linux_identity_t identity;
    vfs_inode_t existing;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t path_address;
    uint32_t requested_mode;
    uint32_t requested_device;
    uint16_t kind;
    uint16_t permissions;
    uint16_t mask;
    uint16_t mode;
    uint64_t device = 0;
    int status;

    if (context->id == EDGE_LINUX_SYS_mknod) {
        path_address = context->arguments[0];
        requested_mode = (uint32_t)context->arguments[1];
        requested_device = (uint32_t)context->arguments[2];
    } else if (context->id == EDGE_LINUX_SYS_mknodat) {
        directory = (int32_t)context->arguments[0];
        path_address = context->arguments[1];
        requested_mode = (uint32_t)context->arguments[2];
        requested_device = (uint32_t)context->arguments[3];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }

    kind = (uint16_t)(requested_mode & 0xf000u);
    if (kind == VFS_INODE_DIR) return -EDGE_LINUX_EPERM;
    if (kind != 0 && kind != VFS_INODE_FILE &&
        kind != VFS_INODE_FIFO && kind != VFS_INODE_SOCK &&
        kind != VFS_INODE_CHR && kind != VFS_INODE_BLK)
        return -EDGE_LINUX_EINVAL;

    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_path_workspace_initialize(&scratch, &workspace);
    if (status < 0) return status;
    status = edge_linux_copy_user_string(
        context, path_address, scratch.path, scratch.path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    status = edge_linux_build_copied_at_path(
        directory, &scratch, &workspace);
    if (status < 0) return status;
    if (vfs_resolve_nofollow(workspace.resolved, &existing, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    if (edge_linux_path_has_trailing_slash(scratch.path))
        return -EDGE_LINUX_ENOENT;
    status = edge_linux_path_parent_target(
        workspace.resolved, workspace.normalization, workspace.root,
        &parent);
    if (status < 0) return status;
    status = edge_linux_path_mutation_permission(parent.inode, 0);
    if (status < 0) return status;

    if (kind == VFS_INODE_CHR || kind == VFS_INODE_BLK) {
        if (kernel_current_linux_identity(&identity) < 0)
            return -EDGE_LINUX_ESRCH;
        if (!(identity.effective_capabilities &
              (1ULL << EDGE_LINUX_CAP_MKNOD)))
            return -EDGE_LINUX_EPERM;
        device = requested_device;
    }

    mask = (uint16_t)(kernel_current_umask() & 0777u);
    permissions = (uint16_t)(
        (requested_mode & 07000u) |
        ((requested_mode & 0777u) & (uint16_t)~mask));
    mode = (uint16_t)((kind ? kind : VFS_INODE_FILE) | permissions);
    status = vfs_mknod(workspace.resolved, mode, device);
    if (status < 0) return status;
    kernel_vfs_notify_create(workspace.resolved, 0);
    return 0;
}

static int edge_linux_file_handle_result(int result) {
    switch (result) {
        case 0: return 0;
        case VFS_FILE_HANDLE_ERR_OVERFLOW:
            return -EDGE_LINUX_EOVERFLOW;
        case VFS_FILE_HANDLE_ERR_UNSUPPORTED:
            return -EDGE_LINUX_EOPNOTSUPP;
        case VFS_FILE_HANDLE_ERR_STALE:
            return -EDGE_LINUX_ESTALE;
        case VFS_FILE_HANDLE_ERR_INVALID:
            return -EDGE_LINUX_EINVAL;
        case VFS_FILE_HANDLE_ERR_IO:
        default:
            return -EDGE_LINUX_EIO;
    }
}

static int edge_linux_name_handle_target(
    edge_linux_syscall_context_t *context, int32_t directory,
    uint64_t user_path, uint32_t flags,
    kernel_vfs_xattr_scratch_t *scratch,
    edge_linux_path_workspace_t *workspace,
    kernel_vfs_target_t *target) {
    int status;

    status = edge_linux_path_workspace_initialize(scratch, workspace);
    if (status < 0) return status;
    status = edge_linux_copy_user_string(
        context, user_path, scratch->path, scratch->path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    if (!scratch->path[0]) {
        if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
            return -EDGE_LINUX_ENOENT;
        if (directory == EDGE_LINUX_AT_FDCWD)
            return kernel_vfs_resolve_path(".", 0, target);
        return kernel_vfs_resolve_fd(directory, target);
    }

    status = edge_linux_build_copied_at_path(directory, scratch, workspace);
    if (status < 0) return status;
    status = vfs_path_search_check(
        workspace->resolved, workspace->search, VFS_PATH_MAX, 0);
    if (status < 0) return status;
    return edge_linux_target_from_resolved(
        workspace->resolved,
        !(flags & EDGE_LINUX_AT_SYMLINK_FOLLOW), target);
}

static int64_t edge_linux_sys_mount_setattr(
    edge_linux_syscall_context_t *context) {
    const uint32_t allowed_flags =
        EDGE_LINUX_AT_EMPTY_PATH | EDGE_LINUX_AT_RECURSIVE |
        EDGE_LINUX_AT_SYMLINK_NOFOLLOW | EDGE_LINUX_AT_NO_AUTOMOUNT;
    struct edge_linux_mount_attr attributes;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t target;
    kernel_linux_identity_t identity;
    uint64_t user_attributes = context->arguments[3];
    uint64_t size = context->arguments[4];
    uint32_t flags = (uint32_t)context->arguments[2];
    int32_t directory = (int32_t)context->arguments[0];
    int mount_object_id;
    int32_t magic_descriptor;
    int extra_zero;
    int magic_status;
    int status;

    if (flags & ~allowed_flags) return -EDGE_LINUX_EINVAL;
    if (size < sizeof(attributes)) return -EDGE_LINUX_EINVAL;
    if (!user_attributes) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(
            context, &attributes, user_attributes,
            sizeof(attributes)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (size > sizeof(attributes)) {
        if (user_attributes > UINT64_MAX - sizeof(attributes))
            return -EDGE_LINUX_EFAULT;
        extra_zero = edge_linux_user_bytes_zero(
            context, user_attributes, sizeof(attributes),
            size - sizeof(attributes));
        if (extra_zero < 0) return extra_zero;
        if (extra_zero) return -EDGE_LINUX_E2BIG;
    }

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EPERM;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_path_workspace_initialize(&scratch, &workspace);
    if (status < 0) return status;
    status = edge_linux_copy_user_string(
        context, context->arguments[1], scratch.path,
        scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;

    if (!scratch.path[0] &&
        (flags & EDGE_LINUX_AT_EMPTY_PATH) &&
        directory != EDGE_LINUX_AT_FDCWD) {
        mount_object_id = kernel_anonymous_fd_descriptor_object_id(
            directory, KERNEL_ANONYMOUS_FD_MOUNT);
        if (mount_object_id >= 0)
            return kernel_mount_api_mount_setattr(
                mount_object_id, attributes.attr_set,
                attributes.attr_clear, attributes.propagation,
                (flags & EDGE_LINUX_AT_RECURSIVE) != 0);
    }

    memset(&target, 0, sizeof(target));
    magic_status = edge_linux_current_magic_fd(
        scratch.path, &identity, &magic_descriptor);
    if (magic_status < 0) return magic_status;
    if (magic_status > 0 &&
        !(flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW)) {
        status = kernel_vfs_resolve_fd(magic_descriptor, &target);
    } else if (!scratch.path[0]) {
        if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
            return -EDGE_LINUX_ENOENT;
        if (directory == EDGE_LINUX_AT_FDCWD)
            status = kernel_vfs_resolve_path(".", 0, &target);
        else
            status = kernel_vfs_resolve_fd(directory, &target);
    } else {
        status = edge_linux_build_copied_at_path(
            directory, &scratch, &workspace);
        if (status >= 0)
            status = vfs_path_search_check(
                workspace.resolved, workspace.search, VFS_PATH_MAX, 0);
        if (status >= 0)
            status = edge_linux_target_from_resolved(
                workspace.resolved,
                (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) != 0,
                &target);
    }
    if (status < 0) return status;
    if (!target.resolved_path) return -EDGE_LINUX_EIO;

    return kernel_linux_mount_setattr(
        target.resolved_path, attributes.attr_set,
        attributes.attr_clear, attributes.propagation,
        (flags & EDGE_LINUX_AT_RECURSIVE) != 0);
}

static int edge_linux_mount_api_path(
    edge_linux_syscall_context_t *context, int32_t directory,
    uint64_t user_path, int allow_empty, int nofollow,
    kernel_vfs_xattr_scratch_t *scratch,
    edge_linux_path_workspace_t *workspace,
    kernel_vfs_target_t *target) {
    int status;

    status = edge_linux_copy_user_string(
        context, user_path, scratch->path, scratch->path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    if (!scratch->path[0]) {
        if (!allow_empty) return -EDGE_LINUX_ENOENT;
        if (directory == EDGE_LINUX_AT_FDCWD)
            return kernel_vfs_resolve_path(".", 0, target);
        return kernel_vfs_resolve_fd(directory, target);
    }
    status = edge_linux_build_copied_at_path(
        directory, scratch, workspace);
    if (status < 0) return status;
    status = vfs_path_search_check(
        workspace->resolved, workspace->search, VFS_PATH_MAX, 0);
    if (status < 0) return status;
    return edge_linux_target_from_resolved(
        workspace->resolved, nofollow, target);
}

static int edge_linux_kernel_path_copy(char *destination,
                                       uint32_t capacity,
                                       const char *source) {
    uint32_t length;

    if (!destination || !source || !capacity)
        return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(source);
    if (length >= capacity) return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(destination, source, length + 1u);
    return 0;
}

static int64_t edge_linux_sys_mount_api(
    edge_linux_syscall_context_t *context) {
    const uint32_t open_tree_clone = 0x00000001u;
    const uint32_t open_tree_cloexec = 0x00080000u;
    const uint32_t open_tree_allowed =
        open_tree_clone | open_tree_cloexec |
        EDGE_LINUX_AT_EMPTY_PATH | EDGE_LINUX_AT_RECURSIVE |
        EDGE_LINUX_AT_SYMLINK_NOFOLLOW | EDGE_LINUX_AT_NO_AUTOMOUNT;
    const uint32_t move_from_empty = 0x00000004u;
    const uint32_t move_to_empty = 0x00000040u;
    const uint32_t move_allowed = move_from_empty | move_to_empty;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t source;
    kernel_vfs_target_t target;
    kernel_linux_identity_t identity;
    kernel_vfs_mount_scratch_t mount_scratch;
    struct edge_linux_mount_attr attributes;
    int mount_object_id;
    int descriptor;
    uint32_t flags;
    uint32_t length;
    int status;

    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_path_workspace_initialize(&scratch, &workspace);
    if (status < 0) return status;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EPERM;

    if (context->id == EDGE_LINUX_SYS_open_tree ||
        context->id == EDGE_LINUX_SYS_open_tree_attr) {
        flags = (uint32_t)context->arguments[2];
        if (flags & ~open_tree_allowed) return -EDGE_LINUX_EINVAL;
        status = edge_linux_mount_api_path(
            context, (int32_t)context->arguments[0],
            context->arguments[1],
            (flags & EDGE_LINUX_AT_EMPTY_PATH) != 0,
            (flags & EDGE_LINUX_AT_SYMLINK_NOFOLLOW) != 0,
            &scratch, &workspace, &source);
        if (status < 0) return status;
        if (!source.resolved_path) return -EDGE_LINUX_EIO;
        mount_object_id = kernel_mount_api_tree_open(
            source.resolved_path, (flags & open_tree_clone) != 0,
            (flags & EDGE_LINUX_AT_RECURSIVE) != 0);
        if (mount_object_id < 0) return mount_object_id;
        if (context->id == EDGE_LINUX_SYS_open_tree_attr) {
            const uint64_t supported_attributes =
                EDGE_LINUX_MOUNT_ATTR_RDONLY |
                EDGE_LINUX_MOUNT_ATTR_NOSUID |
                EDGE_LINUX_MOUNT_ATTR_NODEV |
                EDGE_LINUX_MOUNT_ATTR_NOEXEC |
                EDGE_LINUX_MOUNT_ATTR_ATIME |
                EDGE_LINUX_MOUNT_ATTR_NODIRATIME |
                EDGE_LINUX_MOUNT_ATTR_NOSYMFOLLOW;
            uint64_t user_attributes = context->arguments[3];
            uint64_t size = context->arguments[4];
            int extra_zero;

            if (!user_attributes && size) {
                kernel_mount_api_release(mount_object_id);
                return -EDGE_LINUX_EINVAL;
            }
            if (user_attributes) {
                if (size < sizeof(attributes)) {
                    kernel_mount_api_release(mount_object_id);
                    return -EDGE_LINUX_EINVAL;
                }
                if (edge_linux_copy_from_user(
                        context, &attributes, user_attributes,
                        sizeof(attributes)) < 0) {
                    kernel_mount_api_release(mount_object_id);
                    return -EDGE_LINUX_EFAULT;
                }
                if (size > sizeof(attributes)) {
                    extra_zero = edge_linux_user_bytes_zero(
                        context, user_attributes, sizeof(attributes),
                        size - sizeof(attributes));
                    if (extra_zero < 0 || extra_zero) {
                        kernel_mount_api_release(mount_object_id);
                        return extra_zero < 0 ? extra_zero :
                            -EDGE_LINUX_E2BIG;
                    }
                }
                if ((attributes.attr_set | attributes.attr_clear) &
                    ~supported_attributes) {
                    kernel_mount_api_release(mount_object_id);
                    return ((attributes.attr_set |
                             attributes.attr_clear) &
                            EDGE_LINUX_MOUNT_ATTR_IDMAP) ?
                        -EDGE_LINUX_EOPNOTSUPP : -EDGE_LINUX_EINVAL;
                }
                status = kernel_mount_api_mount_setattr(
                    mount_object_id, attributes.attr_set,
                    attributes.attr_clear, attributes.propagation,
                    (flags & EDGE_LINUX_AT_RECURSIVE) != 0);
                if (status < 0) {
                    kernel_mount_api_release(mount_object_id);
                    return status;
                }
            }
        }
        descriptor = kernel_anonymous_fd_install_descriptor(
            KERNEL_ANONYMOUS_FD_MOUNT, mount_object_id, 0,
            (flags & open_tree_cloexec) != 0);
        if (descriptor < 0) kernel_mount_api_release(mount_object_id);
        return descriptor;
    }

    if (context->id != EDGE_LINUX_SYS_move_mount)
        return -EDGE_LINUX_ENOSYS;
    flags = (uint32_t)context->arguments[4];
    if (flags & ~move_allowed) return -EDGE_LINUX_EINVAL;
    status = edge_linux_copy_user_string(
        context, context->arguments[1], scratch.path,
        scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    mount_object_id = -EDGE_LINUX_EINVAL;
    if (!scratch.path[0] && (flags & move_from_empty))
        mount_object_id = kernel_anonymous_fd_descriptor_object_id(
            (int32_t)context->arguments[0],
            KERNEL_ANONYMOUS_FD_MOUNT);
    if (mount_object_id >= 0) {
        status = edge_linux_mount_api_path(
            context, (int32_t)context->arguments[2],
            context->arguments[3], (flags & move_to_empty) != 0,
            0,
            &scratch, &workspace, &target);
        if (status < 0) return status;
        if (!target.resolved_path || !target.inode)
            return -EDGE_LINUX_EIO;
        if ((target.inode->mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
        status = kernel_vfs_current_mount_scratch(&mount_scratch);
        if (status < 0 || !mount_scratch.target ||
            !mount_scratch.workspace ||
            mount_scratch.capacity < VFS_PATH_MAX)
            return status < 0 ? status : -EDGE_LINUX_EIO;
        status = edge_linux_kernel_path_copy(
            mount_scratch.target, mount_scratch.capacity,
            target.resolved_path);
        if (status < 0) return status;
        return kernel_mount_api_mount_attach(
            mount_object_id, mount_scratch.target,
            mount_scratch.workspace, mount_scratch.capacity);
    }

    status = edge_linux_mount_api_path(
        context, (int32_t)context->arguments[0], context->arguments[1],
        (flags & move_from_empty) != 0, 0,
        &scratch, &workspace, &source);
    if (status < 0) return status;
    if (!source.resolved_path) return -EDGE_LINUX_EIO;
    length = (uint32_t)strlen(source.resolved_path);
    if (length >= VFS_PATH_MAX) return -EDGE_LINUX_ENAMETOOLONG;
    memcpy(workspace.saved, source.resolved_path, length + 1u);

    status = edge_linux_mount_api_path(
        context, (int32_t)context->arguments[2], context->arguments[3],
        (flags & move_to_empty) != 0, 0,
        &scratch, &workspace, &target);
    if (status < 0) return status;
    if (!target.resolved_path || !target.inode)
        return -EDGE_LINUX_EIO;
    if ((target.inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    status = vfs_move_mount(workspace.saved, target.resolved_path);
    if (status == VFS_PATH_ERR_NOT_FOUND) return -EDGE_LINUX_ENOENT;
    if (status == VFS_PATH_ERR_NOT_DIRECTORY) return -EDGE_LINUX_ENOTDIR;
    return status < 0 ? -EDGE_LINUX_EINVAL : 0;
}

static int edge_linux_mount_context_install(int object_id, int cloexec) {
    int descriptor;

    if (object_id < 0) return object_id;
    descriptor = kernel_anonymous_fd_install_descriptor(
        KERNEL_ANONYMOUS_FD_MOUNT, object_id, 0, cloexec != 0);
    if (descriptor < 0) kernel_mount_api_release(object_id);
    return descriptor;
}

static int64_t edge_linux_sys_mount_context(
    edge_linux_syscall_context_t *context) {
    const uint32_t fsopen_cloexec = 0x00000001u;
    const uint32_t fsmount_cloexec = 0x00000001u;
    const uint32_t fspick_cloexec = 0x00000001u;
    const uint32_t fspick_nofollow = 0x00000002u;
    const uint32_t fspick_no_automount = 0x00000004u;
    const uint32_t fspick_empty = 0x00000008u;
    const uint64_t mount_attribute_mask =
        EDGE_LINUX_MOUNT_ATTR_RDONLY |
        EDGE_LINUX_MOUNT_ATTR_NOSUID |
        EDGE_LINUX_MOUNT_ATTR_NODEV |
        EDGE_LINUX_MOUNT_ATTR_NOEXEC |
        EDGE_LINUX_MOUNT_ATTR_ATIME |
        EDGE_LINUX_MOUNT_ATTR_NODIRATIME |
        EDGE_LINUX_MOUNT_ATTR_NOSYMFOLLOW;
    kernel_vfs_mount_scratch_t mount_scratch;
    kernel_vfs_xattr_scratch_t path_scratch;
    edge_linux_path_workspace_t path_workspace;
    kernel_vfs_target_t target;
    kernel_linux_identity_t identity;
    char filesystem[64];
    char key[256];
    const char *value = 0;
    uint64_t attributes;
    uint32_t command;
    uint32_t flags;
    int object_id;
    int status;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SYS_ADMIN)))
        return -EDGE_LINUX_EPERM;

    if (context->id == EDGE_LINUX_SYS_fsopen) {
        flags = (uint32_t)context->arguments[1];
        if (flags & ~fsopen_cloexec) return -EDGE_LINUX_EINVAL;
        status = edge_linux_copy_user_string(
            context, context->arguments[0], filesystem,
            sizeof(filesystem), EDGE_LINUX_ENODEV);
        if (status < 0) return status;
        object_id = kernel_mount_api_context_create(filesystem);
        return edge_linux_mount_context_install(
            object_id, (flags & fsopen_cloexec) != 0);
    }

    if (context->id == EDGE_LINUX_SYS_fspick) {
        int descriptor_object_id;

        flags = (uint32_t)context->arguments[2];
        if (flags & ~(fspick_cloexec | fspick_nofollow |
                      fspick_no_automount | fspick_empty))
            return -EDGE_LINUX_EINVAL;
        status = kernel_vfs_current_xattr_scratch(&path_scratch);
        if (status < 0) return status;
        status = edge_linux_path_workspace_initialize(
            &path_scratch, &path_workspace);
        if (status < 0) return status;
        status = edge_linux_copy_user_string(
            context, context->arguments[1], path_scratch.path,
            path_scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        if (!path_scratch.path[0] && (flags & fspick_empty) &&
            (int32_t)context->arguments[0] != EDGE_LINUX_AT_FDCWD) {
            descriptor_object_id = kernel_anonymous_fd_descriptor_object_id(
                (int32_t)context->arguments[0],
                KERNEL_ANONYMOUS_FD_MOUNT);
            if (descriptor_object_id >= 0) {
                object_id = kernel_mount_api_context_pick_object(
                    descriptor_object_id);
                return edge_linux_mount_context_install(
                    object_id, (flags & fspick_cloexec) != 0);
            }
        }
        status = edge_linux_mount_api_path(
            context, (int32_t)context->arguments[0],
            context->arguments[1], (flags & fspick_empty) != 0,
            (flags & fspick_nofollow) != 0,
            &path_scratch, &path_workspace, &target);
        if (status < 0) return status;
        if (!target.resolved_path) return -EDGE_LINUX_EIO;
        object_id = kernel_mount_api_context_pick(target.resolved_path);
        return edge_linux_mount_context_install(
            object_id, (flags & fspick_cloexec) != 0);
    }

    if (context->id == EDGE_LINUX_SYS_fsmount) {
        flags = (uint32_t)context->arguments[1];
        attributes = (uint32_t)context->arguments[2];
        if (flags & ~fsmount_cloexec ||
            attributes & ~mount_attribute_mask ||
            attributes & EDGE_LINUX_MOUNT_ATTR_IDMAP)
            return -EDGE_LINUX_EINVAL;
        object_id = kernel_anonymous_fd_descriptor_object_id(
            (int32_t)context->arguments[0],
            KERNEL_ANONYMOUS_FD_MOUNT);
        if (object_id < 0) return object_id;
        object_id = kernel_mount_api_context_mount(
            object_id, attributes);
        return edge_linux_mount_context_install(
            object_id, (flags & fsmount_cloexec) != 0);
    }

    if (context->id != EDGE_LINUX_SYS_fsconfig)
        return -EDGE_LINUX_ENOSYS;
    object_id = kernel_anonymous_fd_descriptor_object_id(
        (int32_t)context->arguments[0], KERNEL_ANONYMOUS_FD_MOUNT);
    if (object_id < 0) return object_id;
    command = (uint32_t)context->arguments[1];
    if (command > KERNEL_MOUNT_API_CREATE_EXCLUSIVE)
        return -EDGE_LINUX_EINVAL;
    status = kernel_vfs_current_mount_scratch(&mount_scratch);
    if (status < 0 || !mount_scratch.source || !mount_scratch.target ||
        !mount_scratch.workspace || mount_scratch.capacity < VFS_PATH_MAX)
        return status < 0 ? status : -EDGE_LINUX_EIO;
    key[0] = 0;
    if (context->arguments[2]) {
        status = edge_linux_copy_user_string(
            context, context->arguments[2], key, sizeof(key),
            EDGE_LINUX_EINVAL);
        if (status < 0) return status;
    }
    if ((command == KERNEL_MOUNT_API_SET_FLAG ||
         command >= KERNEL_MOUNT_API_CREATE) &&
        context->arguments[3])
        return -EDGE_LINUX_EINVAL;
    if (command == KERNEL_MOUNT_API_SET_STRING) {
        if (!context->arguments[3]) return -EDGE_LINUX_EINVAL;
        status = edge_linux_copy_user_string(
            context, context->arguments[3], mount_scratch.target,
            mount_scratch.capacity, EDGE_LINUX_EINVAL);
        if (status < 0) return status;
        value = mount_scratch.target;
    } else if (command == KERNEL_MOUNT_API_SET_PATH ||
               command == KERNEL_MOUNT_API_SET_PATH_EMPTY) {
        if (!context->arguments[3]) return -EDGE_LINUX_EINVAL;
        status = edge_linux_copy_user_string(
            context, context->arguments[3], mount_scratch.source,
            mount_scratch.capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        if (!mount_scratch.source[0] &&
            command == KERNEL_MOUNT_API_SET_PATH_EMPTY) {
            if ((int32_t)context->arguments[4] == EDGE_LINUX_AT_FDCWD)
                status = kernel_vfs_resolve_current_path(
                    ".", mount_scratch.target, mount_scratch.capacity);
            else {
                status = kernel_vfs_resolve_fd(
                    (int32_t)context->arguments[4], &target);
                if (status >= 0 && target.resolved_path)
                    status = edge_linux_kernel_path_copy(
                        mount_scratch.target, mount_scratch.capacity,
                        target.resolved_path);
            }
        } else {
            status = kernel_vfs_resolve_at_path(
                (int32_t)context->arguments[4], mount_scratch.source,
                mount_scratch.target, mount_scratch.capacity);
        }
        if (status < 0) return status;
        value = mount_scratch.target;
    } else if (command == KERNEL_MOUNT_API_SET_FD) {
        if (context->arguments[3]) return -EDGE_LINUX_EINVAL;
        status = kernel_vfs_resolve_fd(
            (int32_t)context->arguments[4], &target);
        if (status < 0) return status;
        if (!target.resolved_path) return -EDGE_LINUX_EIO;
        status = edge_linux_kernel_path_copy(
            mount_scratch.target, mount_scratch.capacity,
            target.resolved_path);
        if (status < 0) return status;
        value = mount_scratch.target;
    } else if (command == KERNEL_MOUNT_API_SET_BINARY) {
        return -EDGE_LINUX_EOPNOTSUPP;
    }
    return kernel_mount_api_context_configure(
        object_id, command, key[0] ? key : 0, value,
        (int32_t)context->arguments[4], mount_scratch.workspace,
        mount_scratch.capacity);
}

#define EDGE_LINUX_STATMOUNT_SB_BASIC       0x00000001ULL
#define EDGE_LINUX_STATMOUNT_MNT_BASIC      0x00000002ULL
#define EDGE_LINUX_STATMOUNT_PROPAGATE_FROM 0x00000004ULL
#define EDGE_LINUX_STATMOUNT_MNT_ROOT       0x00000008ULL
#define EDGE_LINUX_STATMOUNT_MNT_POINT      0x00000010ULL
#define EDGE_LINUX_STATMOUNT_FS_TYPE        0x00000020ULL
#define EDGE_LINUX_STATMOUNT_MNT_NS_ID      0x00000040ULL
#define EDGE_LINUX_STATMOUNT_MNT_OPTS       0x00000080ULL
#define EDGE_LINUX_STATMOUNT_FS_SUBTYPE     0x00000100ULL
#define EDGE_LINUX_STATMOUNT_SB_SOURCE      0x00000200ULL
#define EDGE_LINUX_STATMOUNT_OPT_ARRAY      0x00000400ULL
#define EDGE_LINUX_STATMOUNT_OPT_SEC_ARRAY  0x00000800ULL
#define EDGE_LINUX_STATMOUNT_SUPPORTED_MASK 0x00001000ULL
#define EDGE_LINUX_STATMOUNT_MNT_UIDMAP     0x00002000ULL
#define EDGE_LINUX_STATMOUNT_MNT_GIDMAP     0x00004000ULL
#define EDGE_LINUX_STATMOUNT_BY_FD          0x00000001u
#define EDGE_LINUX_LISTMOUNT_REVERSE        0x00000001u
#define EDGE_LINUX_LSMT_ROOT                UINT64_MAX

struct edge_linux_mnt_id_req {
    uint32_t size;
    uint32_t mnt_ns_fd;
    uint64_t mnt_id;
    uint64_t param;
    uint64_t mnt_ns_id;
};

struct edge_linux_statmount {
    uint32_t size;
    uint32_t mnt_opts;
    uint64_t mask;
    uint32_t sb_dev_major;
    uint32_t sb_dev_minor;
    uint64_t sb_magic;
    uint32_t sb_flags;
    uint32_t fs_type;
    uint64_t mnt_id;
    uint64_t mnt_parent_id;
    uint32_t mnt_id_old;
    uint32_t mnt_parent_id_old;
    uint64_t mnt_attr;
    uint64_t mnt_propagation;
    uint64_t mnt_peer_group;
    uint64_t mnt_master;
    uint64_t propagate_from;
    uint32_t mnt_root;
    uint32_t mnt_point;
    uint64_t mnt_ns_id;
    uint32_t fs_subtype;
    uint32_t sb_source;
    uint32_t opt_num;
    uint32_t opt_array;
    uint32_t opt_sec_num;
    uint32_t opt_sec_array;
    uint64_t supported_mask;
    uint32_t mnt_uidmap_num;
    uint32_t mnt_uidmap;
    uint32_t mnt_gidmap_num;
    uint32_t mnt_gidmap;
    uint64_t spare[43];
};

typedef char edge_linux_statmount_size_check[
    sizeof(struct edge_linux_statmount) == 512u ? 1 : -1];

static const uint64_t edge_linux_statmount_supported =
    EDGE_LINUX_STATMOUNT_SB_BASIC |
    EDGE_LINUX_STATMOUNT_MNT_BASIC |
    EDGE_LINUX_STATMOUNT_PROPAGATE_FROM |
    EDGE_LINUX_STATMOUNT_MNT_ROOT |
    EDGE_LINUX_STATMOUNT_MNT_POINT |
    EDGE_LINUX_STATMOUNT_FS_TYPE |
    EDGE_LINUX_STATMOUNT_MNT_NS_ID |
    EDGE_LINUX_STATMOUNT_SB_SOURCE |
    EDGE_LINUX_STATMOUNT_SUPPORTED_MASK;

static int edge_linux_mnt_id_req_copy(
    edge_linux_syscall_context_t *context, uint64_t user_request,
    struct edge_linux_mnt_id_req *request) {
    uint32_t user_size;
    uint32_t copy_size;
    int extra_zero;

    if (!user_request || !request) return -EDGE_LINUX_EFAULT;
    if (edge_linux_copy_from_user(
            context, &user_size, user_request, sizeof(user_size)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (user_size > VFS_PATH_MAX) return -EDGE_LINUX_E2BIG;
    if (user_size < 24u) return -EDGE_LINUX_EINVAL;
    memset(request, 0, sizeof(*request));
    copy_size = user_size < sizeof(*request) ?
        user_size : (uint32_t)sizeof(*request);
    if (edge_linux_copy_from_user(
            context, request, user_request, copy_size) < 0)
        return -EDGE_LINUX_EFAULT;
    if (user_size > sizeof(*request)) {
        extra_zero = edge_linux_user_bytes_zero(
            context, user_request, sizeof(*request),
            user_size - sizeof(*request));
        if (extra_zero < 0) return extra_zero;
        if (extra_zero) return -EDGE_LINUX_E2BIG;
    }
    return 0;
}

static int edge_linux_mount_request_namespace(
    const struct edge_linux_mnt_id_req *request) {
    uint64_t current_namespace =
        (uint64_t)vfs_mount_namespace_current() + 1u;
    if (!request) return -EDGE_LINUX_EINVAL;
    if (request->mnt_ns_fd) return -EDGE_LINUX_EOPNOTSUPP;
    if (request->mnt_ns_id &&
        request->mnt_ns_id != current_namespace)
        return -EDGE_LINUX_ENOENT;
    return 0;
}

static vfs_superblock_t *edge_linux_mount_by_id(
    vfs_mount_table_t *table, uint64_t mount_id) {
    if (!table || !mount_id || mount_id == EDGE_LINUX_LSMT_ROOT)
        return 0;
    for (int index = 0; index < table->mount_count; ++index) {
        vfs_superblock_t *mount =
            vfs_mount_table_at(table, (uint32_t)index);
        if (mount && mount->mount_id == mount_id) return mount;
    }
    return 0;
}

static uint64_t edge_linux_mount_attribute_flags(
    const vfs_superblock_t *mount) {
    uint64_t attributes = 0;
    if (!mount) return 0;
    if (mount->mount_flags & VFS_MOUNT_READONLY)
        attributes |= EDGE_LINUX_MOUNT_ATTR_RDONLY;
    if (mount->mount_flags & VFS_MOUNT_NOSUID)
        attributes |= EDGE_LINUX_MOUNT_ATTR_NOSUID;
    if (mount->mount_flags & VFS_MOUNT_NODEV)
        attributes |= EDGE_LINUX_MOUNT_ATTR_NODEV;
    if (mount->mount_flags & VFS_MOUNT_NOEXEC)
        attributes |= EDGE_LINUX_MOUNT_ATTR_NOEXEC;
    if (mount->mount_flags & VFS_MOUNT_NOATIME)
        attributes |= EDGE_LINUX_MOUNT_ATTR_NOATIME;
    if (mount->mount_flags & VFS_MOUNT_NODIRATIME)
        attributes |= EDGE_LINUX_MOUNT_ATTR_NODIRATIME;
    if (mount->mount_flags & VFS_MOUNT_STRICTATIME)
        attributes |= EDGE_LINUX_MOUNT_ATTR_STRICTATIME;
    if (mount->mount_flags & VFS_MOUNT_NOSYMFOLLOW)
        attributes |= EDGE_LINUX_MOUNT_ATTR_NOSYMFOLLOW;
    return attributes;
}

static uint64_t edge_linux_mount_propagation_flags(
    const vfs_superblock_t *mount) {
    if (!mount) return 0;
    switch (mount->propagation) {
        case VFS_MOUNT_SHARED: return EDGE_LINUX_MS_SHARED;
        case VFS_MOUNT_SLAVE: return EDGE_LINUX_MS_SLAVE;
        case VFS_MOUNT_UNBINDABLE: return EDGE_LINUX_MS_UNBINDABLE;
        case VFS_MOUNT_PRIVATE:
        default: return EDGE_LINUX_MS_PRIVATE;
    }
}

static uint64_t edge_linux_filesystem_magic(const char *name) {
    if (!name) return 0;
    if (!strcmp(name, "ext2") || !strcmp(name, "ext3") ||
        !strcmp(name, "ext4"))
        return 0xef53u;
    if (!strcmp(name, "tmpfs")) return 0x01021994u;
    if (!strcmp(name, "proc")) return 0x00009fa0u;
    if (!strcmp(name, "sysfs")) return 0x62656572u;
    if (!strcmp(name, "devpts")) return 0x00001cd1u;
    if (!strcmp(name, "cgroup2")) return 0x63677270u;
    if (!strcmp(name, "overlay")) return 0x794c7630u;
    if (!strcmp(name, "iso9660")) return 0x00009660u;
    if (!strcmp(name, "squashfs")) return 0x73717368u;
    if (!strcmp(name, "erofs")) return 0xe0f5e1e2u;
    return 0;
}

static int edge_linux_statmount_string(
    struct edge_linux_statmount *output, uint8_t *strings,
    uint32_t workspace_capacity, uint64_t user_capacity,
    uint32_t *string_size, uint32_t *offset, const char *value) {
    uint32_t length;
    uint64_t total;

    if (!output || !strings || !string_size || !offset || !value)
        return -EDGE_LINUX_EINVAL;
    length = (uint32_t)strlen(value);
    total = sizeof(*output) + (uint64_t)*string_size + length + 1u;
    if (total > user_capacity) return -EDGE_LINUX_EOVERFLOW;
    if ((uint64_t)*string_size + length + 1u > workspace_capacity)
        return -EDGE_LINUX_EIO;
    *offset = *string_size;
    memcpy(strings + *string_size, value, length + 1u);
    *string_size += length + 1u;
    return 0;
}

static int edge_linux_statmount_fill(
    edge_linux_syscall_context_t *context,
    const struct edge_linux_mnt_id_req *request,
    vfs_superblock_t *mount) {
    kernel_vfs_xattr_scratch_t scratch;
    const vfs_superblock_t *stable;
    struct edge_linux_statmount *output;
    uint8_t *strings;
    char *root;
    uint64_t requested = request->param;
    uint64_t user_buffer = context->arguments[1];
    uint64_t user_capacity = context->arguments[2];
    uint32_t string_size = 1u;
    uint32_t fixed_copy;
    int status;

    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    if (!scratch.path || scratch.path_capacity < VFS_PATH_MAX ||
        !scratch.value || scratch.value_capacity < 3u * VFS_PATH_MAX)
        return -EDGE_LINUX_EIO;
    root = (char *)scratch.value;
    output = (struct edge_linux_statmount *)(
        scratch.value + VFS_PATH_MAX);
    strings = (uint8_t *)output + sizeof(*output);
    if ((uintptr_t)strings < (uintptr_t)scratch.value ||
        (uint64_t)((uintptr_t)strings - (uintptr_t)scratch.value) >=
            scratch.value_capacity)
        return -EDGE_LINUX_EIO;
    memset(output, 0, sizeof(*output));
    strings[0] = 0;

    if (requested & EDGE_LINUX_STATMOUNT_SB_BASIC) {
        output->mask |= EDGE_LINUX_STATMOUNT_SB_BASIC;
        output->sb_magic = edge_linux_filesystem_magic(mount->fs_name);
        output->sb_flags = mount->mount_flags &
            (VFS_MOUNT_READONLY | VFS_MOUNT_SYNCHRONOUS |
             VFS_MOUNT_DIRSYNC | VFS_MOUNT_LAZYTIME);
    }
    if (requested & EDGE_LINUX_STATMOUNT_MNT_BASIC) {
        uint64_t parent = mount->parent_mount_id ?
            mount->parent_mount_id : mount->mount_id;
        output->mask |= EDGE_LINUX_STATMOUNT_MNT_BASIC;
        output->mnt_id = mount->mount_id;
        output->mnt_parent_id = parent;
        output->mnt_id_old = mount->mount_id > UINT32_MAX ?
            UINT32_MAX : (uint32_t)mount->mount_id;
        output->mnt_parent_id_old = parent > UINT32_MAX ?
            UINT32_MAX : (uint32_t)parent;
        output->mnt_attr = edge_linux_mount_attribute_flags(mount);
        output->mnt_propagation =
            edge_linux_mount_propagation_flags(mount);
        output->mnt_peer_group = mount->peer_group;
        output->mnt_master = mount->master_group;
    }
    if (requested & EDGE_LINUX_STATMOUNT_PROPAGATE_FROM) {
        output->mask |= EDGE_LINUX_STATMOUNT_PROPAGATE_FROM;
        output->propagate_from = mount->master_group;
    }
    if (requested & EDGE_LINUX_STATMOUNT_FS_TYPE) {
        status = edge_linux_statmount_string(
            output, strings,
            scratch.value_capacity -
                (uint32_t)((uintptr_t)strings - (uintptr_t)scratch.value),
            user_capacity, &string_size, &output->fs_type,
            mount->fs_name[0] ? mount->fs_name : "unknown");
        if (status < 0) return status;
        output->mask |= EDGE_LINUX_STATMOUNT_FS_TYPE;
    }
    stable = vfs_superblock_stable_const(mount);
    if ((requested & EDGE_LINUX_STATMOUNT_MNT_ROOT) && stable &&
        vfs_inode_same_object(mount, &mount->root, stable, &stable->root)) {
        status = edge_linux_statmount_string(
            output, strings,
            scratch.value_capacity -
                (uint32_t)((uintptr_t)strings - (uintptr_t)scratch.value),
            user_capacity, &string_size, &output->mnt_root, "/");
        if (status < 0) return status;
        output->mask |= EDGE_LINUX_STATMOUNT_MNT_ROOT;
    }
    if (requested & EDGE_LINUX_STATMOUNT_MNT_POINT) {
        status = kernel_current_fs_snapshot(
            scratch.path, scratch.path_capacity, root, VFS_PATH_MAX);
        if (status < 0) return status;
        status = edge_linux_path_copy(
            scratch.path, scratch.path_capacity,
            mount->mountpoint[0] ? mount->mountpoint : "/");
        if (status < 0) return status;
        if (kernel_fs_path_is_beneath(root, scratch.path)) {
            status = kernel_fs_cwd_make_visible(
                root, scratch.path, scratch.path_capacity);
            if (status < 0) return -EDGE_LINUX_EPERM;
        } else if (kernel_fs_path_is_beneath(scratch.path, root)) {
            scratch.path[0] = '/';
            scratch.path[1] = 0;
        } else {
            return -EDGE_LINUX_EPERM;
        }
        status = edge_linux_statmount_string(
            output, strings,
            scratch.value_capacity -
                (uint32_t)((uintptr_t)strings - (uintptr_t)scratch.value),
            user_capacity, &string_size, &output->mnt_point, scratch.path);
        if (status < 0) return status;
        output->mask |= EDGE_LINUX_STATMOUNT_MNT_POINT;
    }
    if ((requested & EDGE_LINUX_STATMOUNT_SB_SOURCE) &&
        mount->dev_name[0]) {
        status = edge_linux_statmount_string(
            output, strings,
            scratch.value_capacity -
                (uint32_t)((uintptr_t)strings - (uintptr_t)scratch.value),
            user_capacity, &string_size, &output->sb_source,
            mount->dev_name);
        if (status < 0) return status;
        output->mask |= EDGE_LINUX_STATMOUNT_SB_SOURCE;
    }
    if (requested & EDGE_LINUX_STATMOUNT_MNT_NS_ID) {
        output->mask |= EDGE_LINUX_STATMOUNT_MNT_NS_ID;
        output->mnt_ns_id =
            (uint64_t)vfs_mount_namespace_current() + 1u;
    }
    if (requested & EDGE_LINUX_STATMOUNT_SUPPORTED_MASK) {
        output->mask |= EDGE_LINUX_STATMOUNT_SUPPORTED_MASK;
        output->supported_mask = edge_linux_statmount_supported;
    }

    fixed_copy = user_capacity < sizeof(*output) ?
        (uint32_t)user_capacity : (uint32_t)sizeof(*output);
    output->size = fixed_copy + (string_size > 1u ? string_size : 0u);
    if (fixed_copy && !user_buffer) return -EDGE_LINUX_EFAULT;
    if (string_size > 1u &&
        user_buffer > UINT64_MAX - sizeof(*output))
        return -EDGE_LINUX_EFAULT;
    if (string_size > 1u && edge_linux_copy_to_user(
            context, user_buffer + sizeof(*output), strings,
            string_size) < 0)
        return -EDGE_LINUX_EFAULT;
    if (fixed_copy && edge_linux_copy_to_user(
            context, user_buffer, output, fixed_copy) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int edge_linux_mount_has_ancestor(
    vfs_mount_table_t *table, const vfs_superblock_t *mount,
    uint64_t ancestor_id) {
    uint64_t parent_id;
    if (!table || !mount || !ancestor_id) return 0;
    parent_id = mount->parent_mount_id;
    for (int depth = 0; depth < table->mount_count && parent_id; ++depth) {
        vfs_superblock_t *parent;
        if (parent_id == ancestor_id) return 1;
        parent = edge_linux_mount_by_id(table, parent_id);
        if (!parent || parent->parent_mount_id == parent_id) break;
        parent_id = parent->parent_mount_id;
    }
    return 0;
}

static int edge_linux_mount_visible_from_root(
    const vfs_superblock_t *mount, const char *root) {
    const char *mountpoint;
    if (!mount || !root) return 0;
    mountpoint = mount->mountpoint[0] ? mount->mountpoint : "/";
    return kernel_fs_path_is_beneath(root, mountpoint) ||
        kernel_fs_path_is_beneath(mountpoint, root);
}

static int64_t edge_linux_sys_mount_stat(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_mnt_id_req request;
    vfs_mount_table_t *table;
    vfs_superblock_t *mount;
    uint64_t selected_id;
    uint64_t cursor;
    uint64_t user_ids;
    uint64_t capacity;
    uint64_t best;
    uint32_t flags;
    uint32_t generation;
    kernel_vfs_xattr_scratch_t scratch;
    char *root;
    int64_t copied;
    int status;

    status = edge_linux_mnt_id_req_copy(
        context, context->arguments[0], &request);
    if (status < 0) return status;
    table = vfs_mount_namespace_active_table();
    if (!table) return -EDGE_LINUX_EIO;

    if (context->id == EDGE_LINUX_SYS_statmount) {
        kernel_vfs_target_t target;
        flags = (uint32_t)context->arguments[3];
        if (flags & ~EDGE_LINUX_STATMOUNT_BY_FD)
            return -EDGE_LINUX_EINVAL;
        selected_id = request.mnt_id;
        if (flags & EDGE_LINUX_STATMOUNT_BY_FD) {
            if (request.mnt_id || request.mnt_ns_id)
                return -EDGE_LINUX_EINVAL;
            if (request.mnt_ns_fd > INT32_MAX)
                return -EDGE_LINUX_EBADF;
            status = kernel_vfs_resolve_fd(
                (int32_t)request.mnt_ns_fd, &target);
            if (status < 0) return -EDGE_LINUX_EBADF;
            if (!target.superblock || vfs_mount_id_for_superblock(
                    target.superblock, &selected_id) < 0)
                return -EDGE_LINUX_ENOENT;
        } else {
            status = edge_linux_mount_request_namespace(&request);
            if (status < 0) return status;
        }
        mount = edge_linux_mount_by_id(table, selected_id);
        if (!mount) return -EDGE_LINUX_ENOENT;
        return edge_linux_statmount_fill(context, &request, mount);
    }

    if (context->id != EDGE_LINUX_SYS_listmount)
        return -EDGE_LINUX_ENOSYS;
    flags = (uint32_t)context->arguments[3];
    if (flags & ~EDGE_LINUX_LISTMOUNT_REVERSE)
        return -EDGE_LINUX_EINVAL;
    status = edge_linux_mount_request_namespace(&request);
    if (status < 0) return status;
    if (request.mnt_id != EDGE_LINUX_LSMT_ROOT &&
        !edge_linux_mount_by_id(table, request.mnt_id))
        return -EDGE_LINUX_ENOENT;
    user_ids = context->arguments[1];
    capacity = context->arguments[2];
    if (capacity > 1000000u || capacity > UINT64_MAX / sizeof(uint64_t))
        return -EDGE_LINUX_EOVERFLOW;
    if (capacity && !user_ids) return -EDGE_LINUX_EFAULT;
    if (capacity &&
        user_ids > UINT64_MAX - capacity * sizeof(uint64_t))
        return -EDGE_LINUX_EFAULT;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    if (!scratch.path || scratch.path_capacity < VFS_PATH_MAX ||
        !scratch.value || scratch.value_capacity < VFS_PATH_MAX)
        return -EDGE_LINUX_EIO;
    root = (char *)scratch.value;
    status = kernel_current_fs_snapshot(
        scratch.path, scratch.path_capacity, root, VFS_PATH_MAX);
    if (status < 0) return status;

    generation = table->event_generation;
    cursor = request.param;
    copied = 0;
    while ((uint64_t)copied < capacity) {
        best = (flags & EDGE_LINUX_LISTMOUNT_REVERSE) ? 0 : UINT64_MAX;
        for (int index = 0; index < table->mount_count; ++index) {
            vfs_superblock_t *candidate =
                vfs_mount_table_at(table, (uint32_t)index);
            uint64_t id;
            if (!candidate) continue;
            id = candidate->mount_id;
            int reachable = request.mnt_id == EDGE_LINUX_LSMT_ROOT ||
                edge_linux_mount_has_ancestor(
                    table, candidate, request.mnt_id);
            if (!reachable || !id || id == request.mnt_id ||
                !edge_linux_mount_visible_from_root(candidate, root))
                continue;
            if (flags & EDGE_LINUX_LISTMOUNT_REVERSE) {
                if (cursor && id >= cursor) continue;
                if (id > best) best = id;
            } else {
                if (id <= cursor) continue;
                if (id < best) best = id;
            }
        }
        if ((!best && (flags & EDGE_LINUX_LISTMOUNT_REVERSE)) ||
            (best == UINT64_MAX &&
             !(flags & EDGE_LINUX_LISTMOUNT_REVERSE)))
            break;
        if (edge_linux_copy_to_user(
                context, user_ids + (uint64_t)copied * sizeof(best),
                &best, sizeof(best)) < 0)
            return -EDGE_LINUX_EFAULT;
        cursor = best;
        ++copied;
    }
    if (generation != table->event_generation)
        return -EDGE_LINUX_EAGAIN;
    return copied;
}

static int64_t edge_linux_sys_name_to_handle_at(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_file_handle_header header;
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t target;
    uint8_t handle[VFS_FILE_HANDLE_MAX];
    uint64_t mount_id;
    uint32_t handle_type = 0;
    uint32_t handle_bytes;
    uint32_t flags = (uint32_t)context->arguments[4];
    const uint32_t allowed = EDGE_LINUX_AT_SYMLINK_FOLLOW |
        EDGE_LINUX_AT_EMPTY_PATH | EDGE_LINUX_AT_HANDLE_FID |
        EDGE_LINUX_AT_HANDLE_MNT_ID_UNIQUE |
        EDGE_LINUX_AT_HANDLE_CONNECTABLE;
    int status;

    if (flags & ~allowed) return -EDGE_LINUX_EINVAL;
    if ((flags & EDGE_LINUX_AT_HANDLE_CONNECTABLE) &&
        (flags & (EDGE_LINUX_AT_HANDLE_FID | EDGE_LINUX_AT_EMPTY_PATH)))
        return -EDGE_LINUX_EINVAL;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_name_handle_target(
        context, (int32_t)context->arguments[0], context->arguments[1],
        flags, &scratch, &workspace, &target);
    if (status < 0) return status;
    if (flags & EDGE_LINUX_AT_HANDLE_CONNECTABLE)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (edge_linux_copy_from_user(
            context, &header, context->arguments[2], sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (header.handle_bytes > sizeof(handle))
        return -EDGE_LINUX_EINVAL;
    if (!target.superblock ||
        vfs_mount_id_for_superblock(target.superblock, &mount_id) < 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (!(flags & EDGE_LINUX_AT_HANDLE_MNT_ID_UNIQUE) &&
        mount_id > INT32_MAX)
        return -EDGE_LINUX_EOVERFLOW;

    handle_bytes = header.handle_bytes;
    status = vfs_encode_file_handle(
        target.superblock, target.inode, &handle_type, handle,
        &handle_bytes);
    if (status < 0 && status != VFS_FILE_HANDLE_ERR_OVERFLOW)
        return edge_linux_file_handle_result(status);
    header.handle_type = (int32_t)handle_type;
    header.handle_bytes = handle_bytes;
    if (flags & EDGE_LINUX_AT_HANDLE_MNT_ID_UNIQUE) {
        if (edge_linux_copy_to_user(
                context, context->arguments[3], &mount_id,
                sizeof(mount_id)) < 0)
            return -EDGE_LINUX_EFAULT;
    } else {
        int32_t mount_id32 = (int32_t)mount_id;
        if (edge_linux_copy_to_user(
                context, context->arguments[3], &mount_id32,
                sizeof(mount_id32)) < 0)
            return -EDGE_LINUX_EFAULT;
    }
    if (edge_linux_copy_to_user(
            context, context->arguments[2], &header, sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (status == VFS_FILE_HANDLE_ERR_OVERFLOW)
        return -EDGE_LINUX_EOVERFLOW;
    if (handle_bytes && edge_linux_copy_to_user(
            context, context->arguments[2] + sizeof(header), handle,
            handle_bytes) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int64_t edge_linux_sys_open_by_handle_at(
    edge_linux_syscall_context_t *context) {
    struct edge_linux_file_handle_header header;
    kernel_vfs_target_t mount_target;
    kernel_vfs_target_t decoded;
    kernel_linux_identity_t identity;
    uint8_t handle[VFS_FILE_HANDLE_MAX];
    uint32_t flags = (uint32_t)context->arguments[2];
    uint32_t access_mode = flags & EDGE_LINUX_O_ACCMODE;
    uint32_t descriptor_flags =
        (flags & EDGE_LINUX_O_CLOEXEC) ? KERNEL_FD_CLOEXEC : 0u;
    int32_t mount_descriptor = (int32_t)context->arguments[0];
    int access_mask = 0;
    int status;

    if (edge_linux_copy_from_user(
            context, &header, context->arguments[1], sizeof(header)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (!header.handle_bytes || header.handle_bytes > sizeof(handle) ||
        header.handle_type < 0)
        return -EDGE_LINUX_EINVAL;

    if (mount_descriptor == EDGE_LINUX_AT_FDCWD) {
        status = kernel_vfs_resolve_path(".", 0, &mount_target);
    } else {
        status = kernel_vfs_resolve_fd(mount_descriptor, &mount_target);
        if (status == -EDGE_LINUX_EOPNOTSUPP)
            status = -EDGE_LINUX_EBADF;
    }
    if (status < 0) return status;
    if (!mount_target.superblock) return -EDGE_LINUX_EBADF;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_DAC_READ_SEARCH)))
        return -EDGE_LINUX_EPERM;
    if (edge_linux_copy_from_user(
            context, handle,
            context->arguments[1] + sizeof(header),
            header.handle_bytes) < 0)
        return -EDGE_LINUX_EFAULT;

    memset(&decoded, 0, sizeof(decoded));
    decoded.superblock = mount_target.superblock;
    decoded.inode = &decoded.inode_storage;
    status = vfs_decode_file_handle(
        decoded.superblock, (uint32_t)header.handle_type, handle,
        header.handle_bytes, decoded.inode);
    if (status < 0) return edge_linux_file_handle_result(status);

    if ((flags & EDGE_LINUX_O_TMPFILE) == EDGE_LINUX_O_TMPFILE) {
        if ((decoded.inode->mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
        return -EDGE_LINUX_EOPNOTSUPP;
    }
    if ((flags & (EDGE_LINUX_O_CREAT | EDGE_LINUX_O_EXCL)) ==
        (EDGE_LINUX_O_CREAT | EDGE_LINUX_O_EXCL))
        return -EDGE_LINUX_EEXIST;
    if ((flags & EDGE_LINUX_O_DIRECTORY) &&
        (decoded.inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if ((decoded.inode->mode & 0xf000u) == VFS_INODE_LNK &&
        !((flags & EDGE_LINUX_O_PATH) &&
          (flags & EDGE_LINUX_O_NOFOLLOW)))
        return -EDGE_LINUX_ELOOP;

    if (!(flags & EDGE_LINUX_O_PATH)) {
        if (access_mode == EDGE_LINUX_O_RDONLY ||
            access_mode == EDGE_LINUX_O_RDWR)
            access_mask |= 4;
        if (access_mode == EDGE_LINUX_O_WRONLY ||
            access_mode == EDGE_LINUX_O_RDWR ||
            (flags & EDGE_LINUX_O_TRUNC))
            access_mask |= 2;
        if ((decoded.inode->mode & 0xf000u) == VFS_INODE_DIR &&
            (access_mask & 2))
            return -EDGE_LINUX_EISDIR;
        if (access_mask && vfs_permission_check(
                decoded.inode, access_mask) < 0)
            return -EDGE_LINUX_EACCES;
        if ((flags & EDGE_LINUX_O_TRUNC) &&
            (decoded.inode->mode & 0xf000u) == VFS_INODE_FILE) {
            status = kernel_vfs_truncate_target(&decoded, 0);
            if (status < 0) return status;
        }
    }

    return kernel_vfs_install_inode_descriptor(
        decoded.superblock, decoded.inode, flags, descriptor_flags, 0);
}

static int64_t edge_linux_sys_readlink(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t user_path;
    uint64_t destination;
    uint64_t capacity;
    uint64_t copied;
    int trailing_slash;
    int status;

    if (context->id == EDGE_LINUX_SYS_readlink) {
        user_path = context->arguments[0];
        destination = context->arguments[1];
        capacity = context->arguments[2];
    } else if (context->id == EDGE_LINUX_SYS_readlinkat) {
        directory = (int32_t)context->arguments[0];
        user_path = context->arguments[1];
        destination = context->arguments[2];
        capacity = context->arguments[3];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (!capacity) return -EDGE_LINUX_EINVAL;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_resolve_at_path(
        context, directory, user_path, &scratch, &workspace);
    if (status < 0) return status;
    trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
    if (trailing_slash) {
        vfs_inode_t inode;
        if (vfs_resolve(workspace.resolved, &inode, 0, 0, 0) < 0)
            return -EDGE_LINUX_ENOENT;
        return -EDGE_LINUX_EINVAL;
    }
    status = kernel_vfs_readlink_target(
        workspace.resolved, workspace.saved, VFS_PATH_MAX);
    if (status < 0) return status;
    copied = (uint64_t)status < capacity ? (uint64_t)status : capacity;
    if (!destination) return -EDGE_LINUX_EFAULT;
    if (copied && edge_linux_copy_to_user(
            context, destination, workspace.saved, copied) < 0)
        return -EDGE_LINUX_EFAULT;
    return (int64_t)copied;
}

static int64_t edge_linux_sys_symlink(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t parent;
    vfs_inode_t existing;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t target_address;
    uint64_t path_address;
    int trailing_slash;
    int status;

    if (context->id == EDGE_LINUX_SYS_symlink) {
        target_address = context->arguments[0];
        path_address = context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_symlinkat) {
        target_address = context->arguments[0];
        directory = (int32_t)context->arguments[1];
        path_address = context->arguments[2];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_path_workspace_initialize(&scratch, &workspace);
    if (status < 0) return status;
    status = edge_linux_copy_user_string(
        context, target_address, workspace.saved, VFS_PATH_MAX,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    if (!workspace.saved[0]) return -EDGE_LINUX_ENOENT;
    status = edge_linux_resolve_at_path(
        context, directory, path_address, &scratch, &workspace);
    if (status < 0) return status;
    trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
    if (vfs_resolve_nofollow(workspace.resolved, &existing, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    if (trailing_slash) return -EDGE_LINUX_ENOENT;
    status = edge_linux_path_parent_target(
        workspace.resolved, workspace.normalization, workspace.root,
        &parent);
    if (status < 0) return status;
    status = edge_linux_path_mutation_permission(parent.inode, 0);
    if (status < 0) return status;
    status = kernel_vfs_path_result(
        vfs_symlink(workspace.saved, workspace.resolved));
    if (status < 0) return status;
    kernel_vfs_notify_create(workspace.resolved, 0);
    return 0;
}

static const char *edge_linux_after_path_prefix(const char *path,
                                                const char *prefix) {
    if (!path || !prefix) return 0;
    while (*prefix && *path == *prefix) {
        ++path;
        ++prefix;
    }
    return *prefix ? 0 : path;
}

static int edge_linux_parse_decimal_component(const char **cursor,
                                               int32_t *value) {
    const char *text;
    uint64_t parsed = 0;
    if (!cursor || !*cursor || !value) return -EDGE_LINUX_EINVAL;
    text = *cursor;
    if (*text < '0' || *text > '9') return 0;
    while (*text >= '0' && *text <= '9') {
        parsed = parsed * 10u + (uint32_t)(*text - '0');
        if (parsed > INT32_MAX) return -EDGE_LINUX_ENOENT;
        ++text;
    }
    *cursor = text;
    *value = (int32_t)parsed;
    return 1;
}

static int edge_linux_current_magic_executable(
    const char *path, const kernel_linux_identity_t *identity,
    int32_t *owner_out) {
    const char *cursor;
    int32_t owner;
    int32_t thread;
    int status;

    if (!path || !identity || !owner_out) return -EDGE_LINUX_EINVAL;
    *owner_out = -1;
    cursor = edge_linux_after_path_prefix(path, "/proc/self/exe");
    if (cursor && !*cursor) {
        *owner_out = identity->global_tgid;
        return 1;
    }
    cursor = edge_linux_after_path_prefix(path, "/proc/thread-self/exe");
    if (cursor && !*cursor) {
        *owner_out = identity->global_tid;
        return 1;
    }
    cursor = edge_linux_after_path_prefix(path, "/proc/");
    if (!cursor) return 0;
    status = edge_linux_parse_decimal_component(&cursor, &owner);
    if (status <= 0) return status < 0 ? status : 0;
    {
        const char *suffix = edge_linux_after_path_prefix(cursor, "/exe");
        if (suffix && !*suffix) {
            *owner_out = owner;
            return 1;
        }
    }
    cursor = edge_linux_after_path_prefix(cursor, "/task/");
    if (!cursor) return 0;
    status = edge_linux_parse_decimal_component(&cursor, &thread);
    if (status <= 0) return 0;
    cursor = edge_linux_after_path_prefix(cursor, "/exe");
    if (!cursor || *cursor) return 0;
    *owner_out = thread;
    return 1;
}

/*
 * Linux procfs descriptor entries are magic links. Following one for linkat
 * resolves the open file description itself, which is how apk gives an
 * O_TMPFILE inode its persistent package-cache name.
 */
static int edge_linux_current_magic_fd(
    const char *path, const kernel_linux_identity_t *identity,
    int32_t *descriptor) {
    const char *cursor;
    int32_t owner;
    int32_t thread;
    int status;

    if (!path || !identity || !descriptor) return -EDGE_LINUX_EINVAL;
    cursor = edge_linux_after_path_prefix(path, "/dev/fd/");
    if (!cursor)
        cursor = edge_linux_after_path_prefix(path, "/proc/self/fd/");
    if (!cursor)
        cursor = edge_linux_after_path_prefix(path, "/proc/thread-self/fd/");
    if (!cursor) {
        cursor = edge_linux_after_path_prefix(path, "/proc/");
        if (!cursor) return 0;
        status = edge_linux_parse_decimal_component(&cursor, &owner);
        if (status <= 0) return status;
        /*
         * EdgeOS currently has one procfs superblock in the initial PID
         * namespace.  Numeric paths therefore use global IDs even when the
         * caller is in a descendant namespace.  Accepting a visible ID here
         * could alias an unrelated task in the initial namespace.
         */
        if (owner != identity->global_tgid &&
            owner != identity->global_tid)
            return -EDGE_LINUX_ENOENT;
        {
            const char *descriptor_cursor =
                edge_linux_after_path_prefix(cursor, "/fd/");
            if (descriptor_cursor) {
                cursor = descriptor_cursor;
            } else {
                cursor = edge_linux_after_path_prefix(cursor, "/task/");
                if (!cursor) return 0;
                status = edge_linux_parse_decimal_component(&cursor, &thread);
                if (status <= 0) return status;
                if (thread != identity->global_tid)
                    return -EDGE_LINUX_ENOENT;
                cursor = edge_linux_after_path_prefix(cursor, "/fd/");
                if (!cursor) return 0;
            }
        }
    }
    status = edge_linux_parse_decimal_component(&cursor, descriptor);
    if (status <= 0) return status;
    return *cursor ? 0 : 1;
}

int edge_linux_current_magic_fd_metadata(
    const char *path, const kernel_linux_identity_t *identity,
    kernel_file_metadata_t *metadata, int *handled) {
    int32_t descriptor;
    int status;

    if (!handled) return -EDGE_LINUX_EINVAL;
    *handled = 0;
    status = edge_linux_current_magic_fd(path, identity, &descriptor);
    if (status <= 0) return status;
    *handled = 1;
    status = kernel_vfs_metadata_fd(descriptor, metadata);
    return status == -EDGE_LINUX_EBADF ? -EDGE_LINUX_ENOENT : status;
}

static int edge_linux_hardlink_source_allowed(
    const kernel_linux_identity_t *identity, const vfs_inode_t *source) {
    uint16_t kind;
    if (!identity || !source) return -EDGE_LINUX_EIO;
    if (identity->fsuid == source->uid ||
        ((identity->effective_capabilities >> EDGE_LINUX_CAP_FOWNER) & 1u))
        return 0;
    kind = source->mode & 0xf000u;
    if (kind == VFS_INODE_FILE && !(source->mode & 04000u) &&
        !((source->mode & 02000u) && (source->mode & 0010u)) &&
        vfs_permission_check(source, 6) == 0)
        return 0;
    return -EDGE_LINUX_EPERM;
}

static int64_t edge_linux_sys_link(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t descriptor_target;
    kernel_vfs_target_t destination_parent;
    kernel_linux_identity_t identity;
    vfs_inode_t source;
    vfs_inode_t existing;
    vfs_superblock_t *source_superblock = 0;
    int32_t source_directory = EDGE_LINUX_AT_FDCWD;
    int32_t destination_directory = EDGE_LINUX_AT_FDCWD;
    uint64_t source_address;
    uint64_t destination_address;
    uint32_t flags = 0;
    const char *source_path = 0;
    int source_trailing_slash = 0;
    int destination_trailing_slash;
    int source_from_descriptor = 0;
    int32_t magic_descriptor;
    int magic_status;
    int status;

    if (context->id == EDGE_LINUX_SYS_link) {
        source_address = context->arguments[0];
        destination_address = context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_linkat) {
        source_directory = (int32_t)context->arguments[0];
        source_address = context->arguments[1];
        destination_directory = (int32_t)context->arguments[2];
        destination_address = context->arguments[3];
        flags = (uint32_t)context->arguments[4];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (flags & ~(EDGE_LINUX_AT_SYMLINK_FOLLOW |
                  EDGE_LINUX_AT_EMPTY_PATH))
        return -EDGE_LINUX_EINVAL;
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_path_workspace_initialize(&scratch, &workspace);
    if (status < 0) return status;
    status = edge_linux_copy_user_string(
        context, source_address, scratch.path, scratch.path_capacity,
        EDGE_LINUX_ENAMETOOLONG);
    if (status < 0) return status;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;

    if (!scratch.path[0]) {
        if (!(flags & EDGE_LINUX_AT_EMPTY_PATH))
            return -EDGE_LINUX_ENOENT;
        if (!((identity.effective_capabilities >>
               EDGE_LINUX_CAP_DAC_READ_SEARCH) & 1u))
            return -EDGE_LINUX_ENOENT;
        status = kernel_vfs_resolve_fd(source_directory, &descriptor_target);
        if (status < 0) return status;
        if (!descriptor_target.inode || !descriptor_target.superblock)
            return -EDGE_LINUX_EBADF;
        source = *descriptor_target.inode;
        source_superblock = descriptor_target.superblock;
        source_path = descriptor_target.resolved_path;
        source_from_descriptor = 1;
    } else {
        status = edge_linux_resolve_at_path(
            context, source_directory, source_address, &scratch, &workspace);
        if (status < 0) return status;
        source_trailing_slash =
            edge_linux_path_has_trailing_slash(scratch.path);
        status = edge_linux_path_copy(
            workspace.saved, VFS_PATH_MAX, workspace.resolved);
        if (status < 0) return status;
        source_path = workspace.saved;
        magic_status = (flags & EDGE_LINUX_AT_SYMLINK_FOLLOW) ?
            edge_linux_current_magic_fd(source_path, &identity,
                                        &magic_descriptor) : 0;
        if (magic_status < 0) return magic_status;
        if (magic_status > 0) {
            status = kernel_vfs_resolve_fd(magic_descriptor,
                                           &descriptor_target);
            if (status < 0) return status;
            if (!descriptor_target.inode || !descriptor_target.superblock)
                return -EDGE_LINUX_EBADF;
            source = *descriptor_target.inode;
            source_superblock = descriptor_target.superblock;
            source_path = descriptor_target.resolved_path;
            source_from_descriptor = 1;
        } else if ((flags & EDGE_LINUX_AT_SYMLINK_FOLLOW) ||
                   source_trailing_slash) {
            if (vfs_resolve(source_path, &source, &source_superblock,
                            0, 0) < 0)
                return -EDGE_LINUX_ENOENT;
        } else if (vfs_resolve_nofollow(
                       source_path, &source, &source_superblock) < 0) {
            return -EDGE_LINUX_ENOENT;
        }
        if (source_trailing_slash &&
            (source.mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
    }
    if ((source.mode & 0xf000u) == VFS_INODE_DIR)
        return -EDGE_LINUX_EPERM;
    if (source.nlink_valid && !source.nlink &&
        (!source_from_descriptor ||
         !descriptor_target.linkable_zero_link_inode))
        return -EDGE_LINUX_ENOENT;
    if (source.nlink_valid && source.nlink >= 0xffffu)
        return -EDGE_LINUX_EMLINK;
    status = edge_linux_hardlink_source_allowed(&identity, &source);
    if (status < 0) return status;

    status = edge_linux_resolve_at_path(
        context, destination_directory, destination_address,
        &scratch, &workspace);
    if (status < 0) return status;
    destination_trailing_slash =
        edge_linux_path_has_trailing_slash(scratch.path);
    if (vfs_resolve_nofollow(workspace.resolved, &existing, 0) == 0)
        return -EDGE_LINUX_EEXIST;
    if (destination_trailing_slash) return -EDGE_LINUX_ENOENT;
    status = edge_linux_path_parent_target(
        workspace.resolved, workspace.normalization, workspace.root,
        &destination_parent);
    if (status < 0) return status;
    if (!vfs_superblock_same_filesystem(
            destination_parent.superblock, source_superblock))
        return -EDGE_LINUX_EXDEV;
    status = edge_linux_path_mutation_permission(
        destination_parent.inode, 0);
    if (status < 0) return status;
    if (vfs_link_inode(source_superblock, &source, workspace.resolved) < 0)
        return -EDGE_LINUX_EIO;
    kernel_vfs_notify_link(source_path, workspace.resolved);
    return 0;
}

static int64_t edge_linux_sys_unlink(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t parent;
    vfs_inode_t victim;
    vfs_superblock_t *victim_superblock = 0;
    int32_t directory = EDGE_LINUX_AT_FDCWD;
    uint64_t path_address;
    uint32_t flags = 0;
    int remove_directory = 0;
    int trailing_slash;
    int final_dot;
    int status;

    if (context->id == EDGE_LINUX_SYS_unlink) {
        path_address = context->arguments[0];
    } else if (context->id == EDGE_LINUX_SYS_rmdir) {
        path_address = context->arguments[0];
        remove_directory = 1;
    } else if (context->id == EDGE_LINUX_SYS_unlinkat) {
        directory = (int32_t)context->arguments[0];
        path_address = context->arguments[1];
        flags = (uint32_t)context->arguments[2];
        if (flags & ~EDGE_LINUX_AT_REMOVEDIR)
            return -EDGE_LINUX_EINVAL;
        remove_directory = (flags & EDGE_LINUX_AT_REMOVEDIR) != 0;
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_resolve_at_path(
        context, directory, path_address, &scratch, &workspace);
    if (status < 0) return status;
    trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
    final_dot = edge_linux_path_final_dot_component(scratch.path);
    if (remove_directory && final_dot)
        return final_dot == 1 ? -EDGE_LINUX_EINVAL :
                                -EDGE_LINUX_ENOTEMPTY;
    if (vfs_resolve_nofollow(workspace.resolved, &victim,
                             &victim_superblock) < 0)
        return -EDGE_LINUX_ENOENT;
    if (!strcmp(workspace.resolved, "/"))
        return -EDGE_LINUX_EBUSY;
    if (trailing_slash &&
        (victim.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (remove_directory) {
        if ((victim.mode & 0xf000u) != VFS_INODE_DIR)
            return -EDGE_LINUX_ENOTDIR;
    } else if ((victim.mode & 0xf000u) == VFS_INODE_DIR) {
        return -EDGE_LINUX_EISDIR;
    }
    status = edge_linux_path_parent_target(
        workspace.resolved, workspace.normalization, workspace.root,
        &parent);
    if (status < 0) return status;
    if (!vfs_superblock_same_filesystem(
            parent.superblock, victim_superblock))
        return -EDGE_LINUX_EBUSY;
    status = edge_linux_path_mutation_permission(parent.inode, &victim);
    if (status < 0) return status;
    if (remove_directory)
        status = kernel_vfs_path_result(
            vfs_rmdir(workspace.resolved));
    else
        status = vfs_unlink(workspace.resolved) < 0 ?
            -EDGE_LINUX_EIO : 0;
    if (status < 0) return status;
    kernel_vfs_notify_remove(workspace.resolved, remove_directory);
    return 0;
}

static int64_t edge_linux_sys_rename(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    edge_linux_path_workspace_t workspace;
    kernel_vfs_target_t old_parent;
    kernel_vfs_target_t new_parent;
    vfs_inode_t source;
    vfs_inode_t target;
    vfs_superblock_t *source_superblock = 0;
    vfs_superblock_t *target_superblock = 0;
    int32_t old_directory = EDGE_LINUX_AT_FDCWD;
    int32_t new_directory = EDGE_LINUX_AT_FDCWD;
    uint64_t old_address;
    uint64_t new_address;
    uint32_t flags = 0;
    int old_trailing_slash;
    int new_trailing_slash;
    int old_final_dot;
    int new_final_dot;
    int target_exists;
    int status;

    if (context->id == EDGE_LINUX_SYS_rename) {
        old_address = context->arguments[0];
        new_address = context->arguments[1];
    } else if (context->id == EDGE_LINUX_SYS_renameat ||
               context->id == EDGE_LINUX_SYS_renameat2) {
        old_directory = (int32_t)context->arguments[0];
        old_address = context->arguments[1];
        new_directory = (int32_t)context->arguments[2];
        new_address = context->arguments[3];
        if (context->id == EDGE_LINUX_SYS_renameat2)
            flags = (uint32_t)context->arguments[4];
    } else {
        return -EDGE_LINUX_ENOSYS;
    }
    if (flags & ~(EDGE_LINUX_RENAME_NOREPLACE |
                  EDGE_LINUX_RENAME_EXCHANGE |
                  EDGE_LINUX_RENAME_WHITEOUT))
        return -EDGE_LINUX_EINVAL;
    if ((flags & EDGE_LINUX_RENAME_EXCHANGE) &&
        (flags & (EDGE_LINUX_RENAME_NOREPLACE |
                  EDGE_LINUX_RENAME_WHITEOUT)))
        return -EDGE_LINUX_EINVAL;
    if (flags & (EDGE_LINUX_RENAME_EXCHANGE |
                 EDGE_LINUX_RENAME_WHITEOUT))
        return -EDGE_LINUX_EOPNOTSUPP;

    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0) return status;
    status = edge_linux_resolve_at_path(
        context, old_directory, old_address, &scratch, &workspace);
    if (status < 0) return status;
    old_trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
    old_final_dot = edge_linux_path_final_dot_component(scratch.path);
    status = edge_linux_path_copy(
        workspace.saved, VFS_PATH_MAX, workspace.resolved);
    if (status < 0) return status;
    if (old_final_dot) return -EDGE_LINUX_EBUSY;
    if (vfs_resolve_nofollow(workspace.saved, &source,
                             &source_superblock) < 0)
        return -EDGE_LINUX_ENOENT;
    if (old_trailing_slash &&
        (source.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (!strcmp(workspace.saved, "/")) return -EDGE_LINUX_EBUSY;

    status = edge_linux_resolve_at_path(
        context, new_directory, new_address, &scratch, &workspace);
    if (status < 0) return status;
    new_trailing_slash = edge_linux_path_has_trailing_slash(scratch.path);
    new_final_dot = edge_linux_path_final_dot_component(scratch.path);
    if (new_final_dot) return -EDGE_LINUX_EBUSY;
    if (!strcmp(workspace.resolved, "/")) return -EDGE_LINUX_EBUSY;
    target_exists = vfs_resolve_nofollow(
        workspace.resolved, &target, &target_superblock) == 0;
    if (new_trailing_slash && !target_exists)
        return -EDGE_LINUX_ENOENT;
    if (new_trailing_slash &&
        (target.mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if ((flags & EDGE_LINUX_RENAME_NOREPLACE) && target_exists)
        return -EDGE_LINUX_EEXIST;

    status = edge_linux_path_parent_target(
        workspace.saved, workspace.normalization, workspace.root,
        &old_parent);
    if (status < 0) return status;
    status = edge_linux_path_mutation_permission(
        old_parent.inode, &source);
    if (status < 0) return status;
    status = edge_linux_path_parent_target(
        workspace.resolved, workspace.normalization, workspace.root,
        &new_parent);
    if (status < 0) return status;
    status = edge_linux_path_mutation_permission(
        new_parent.inode, target_exists ? &target : 0);
    if (status < 0) return status;
    if (!vfs_superblock_same_filesystem(
            old_parent.superblock, source_superblock) ||
        !vfs_superblock_same_filesystem(
            old_parent.superblock, new_parent.superblock) ||
        (target_exists &&
         !vfs_superblock_same_filesystem(
             target_superblock, old_parent.superblock)))
        return -EDGE_LINUX_EXDEV;
    if (target_exists &&
        vfs_inode_same_object(source_superblock, &source,
                              target_superblock, &target))
        return 0;
    status = kernel_vfs_path_result(
        vfs_rename(workspace.saved, workspace.resolved));
    if (status < 0) return status;
    kernel_vfs_notify_rename(workspace.saved, workspace.resolved);
    return 0;
}

static int64_t edge_linux_sys_fs_context(
    edge_linux_syscall_context_t *context) {
    kernel_vfs_xattr_scratch_t scratch;
    kernel_vfs_target_t target;
    kernel_linux_identity_t identity;
    uint64_t destination;
    uint64_t size;
    uint64_t length;
    int status;

    status = kernel_vfs_current_xattr_scratch(&scratch);
    if (status < 0 || !scratch.path ||
        scratch.path_capacity < VFS_PATH_MAX || !scratch.value ||
        scratch.value_capacity < VFS_PATH_MAX)
        return status < 0 ? status : -EDGE_LINUX_EIO;

    if (context->id == EDGE_LINUX_SYS_getcwd) {
        destination = context->arguments[0];
        size = context->arguments[1];
        if (!size) return -EDGE_LINUX_ERANGE;
        status = kernel_current_fs_snapshot(
            scratch.path, scratch.path_capacity,
            (char *)scratch.value, scratch.value_capacity);
        if (status < 0) return status;
        status = kernel_fs_cwd_make_visible(
            (const char *)scratch.value, scratch.path,
            scratch.path_capacity);
        if (status < 0) return status;
        length = (uint64_t)strlen(scratch.path) + 1u;
        if (size < length) return -EDGE_LINUX_ERANGE;
        if (!destination) return -EDGE_LINUX_EFAULT;
        return edge_linux_copy_to_user(
            context, destination, scratch.path, length) < 0 ?
            -EDGE_LINUX_EFAULT : (int64_t)length;
    }

    if (context->id == EDGE_LINUX_SYS_fchdir) {
        if (context->arguments[0] > INT32_MAX)
            return -EDGE_LINUX_EBADF;
        status = kernel_vfs_resolve_fd(
            (int32_t)context->arguments[0], &target);
        if (status == -EDGE_LINUX_EOPNOTSUPP)
            return -EDGE_LINUX_ENOTDIR;
    } else {
        status = edge_linux_copy_user_string(
            context, context->arguments[0], scratch.path,
            scratch.path_capacity, EDGE_LINUX_ENAMETOOLONG);
        if (status < 0) return status;
        if (!scratch.path[0]) return -EDGE_LINUX_ENOENT;
        status = kernel_vfs_resolve_path(scratch.path, 0, &target);
    }
    if (status < 0) return status;
    if (!target.inode ||
        (target.inode->mode & 0xf000u) != VFS_INODE_DIR)
        return -EDGE_LINUX_ENOTDIR;
    if (vfs_permission_check(target.inode, 1) < 0)
        return -EDGE_LINUX_EACCES;
    if (!target.resolved_path) return -EDGE_LINUX_EIO;

    if (context->id == EDGE_LINUX_SYS_chdir ||
        context->id == EDGE_LINUX_SYS_fchdir)
        return kernel_current_fs_set_cwd(target.resolved_path);
    if (context->id != EDGE_LINUX_SYS_chroot)
        return -EDGE_LINUX_ENOSYS;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (!(identity.effective_capabilities &
          (1ULL << EDGE_LINUX_CAP_SYS_CHROOT)))
        return -EDGE_LINUX_EPERM;
    return kernel_current_fs_set_root(target.resolved_path);
}

static int64_t edge_linux_sys_sched_priority_limit(
    edge_linux_syscall_context_t *context) {
    uint32_t policy = (uint32_t)context->arguments[0] & ~0x40000000u;
    if (policy == 1u || policy == 2u) {
        return context->id == EDGE_LINUX_SYS_sched_get_priority_max ? 99 : 1;
    }
    if (policy == 0u || policy == 3u || policy == 5u ||
        policy == 6u || policy == 7u)
        return 0;
    return -EDGE_LINUX_EINVAL;
}

int edge_linux_syscall_dispatch(edge_linux_syscall_context_t *context) {
    if (!context) return EDGE_LINUX_SYSCALL_NOT_HANDLED;
    if (edge_linux_syscall_map(context->architecture, context->raw_number,
                               &context->id, &context->route_status) < 0)
        return EDGE_LINUX_SYSCALL_NOT_HANDLED;
    if (context->route_status == EDGE_LINUX_SYSCALL_ENOSYS) {
        context->result = -EDGE_LINUX_ENOSYS;
        return EDGE_LINUX_SYSCALL_HANDLED;
    }
    switch (context->id) {
#include "linux_syscall_dispatch.inc"
        default:
            return EDGE_LINUX_SYSCALL_NOT_HANDLED;
    }
}
