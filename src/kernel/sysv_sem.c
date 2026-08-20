/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux SysV semaphore core.
 * Copyright (c) EdgeOS Contributors.
 */

#include <stdint.h>

#include "kernel/credentials.h"
#include "kernel/linux_errno.h"
#include "kernel/process_runtime.h"
#include "kernel/sysv_sem_runtime.h"
#include "kernel/sysv_shm_runtime.h"
#include "string.h"
#include "sys/boottime.h"
#include "sys/spinlock.h"

#define KERNEL_SYSV_SEM_UNDO_MAX 512u

typedef struct kernel_sysv_semaphore {
    uint16_t value;
    uint16_t waiting_negative;
    uint16_t waiting_zero;
    uint16_t reserved;
    int32_t last_pid;
} kernel_sysv_semaphore_t;

typedef struct kernel_sysv_sem_set {
    uint8_t used;
    uint8_t removed;
    uint16_t semaphore_count;
    int32_t identifier;
    int32_t key;
    uint32_t ipc_namespace_id;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint32_t mode;
    uint32_t sequence;
    uint64_t operation_time_us;
    uint64_t change_time_us;
    kernel_sysv_semaphore_t semaphores[KERNEL_SYSV_SEM_MAX_PER_SET];
} kernel_sysv_sem_set_t;

typedef struct kernel_sysv_sem_undo {
    uint8_t used;
    uint8_t reserved[3];
    int32_t task_id;
    int32_t identifier;
    uint16_t semaphore_number;
    int16_t adjustment;
} kernel_sysv_sem_undo_t;

static kernel_sysv_sem_set_t
    g_sysv_sem_sets[KERNEL_SYSV_SEM_MAX_SETS];
static kernel_sysv_sem_undo_t
    g_sysv_sem_undo[KERNEL_SYSV_SEM_UNDO_MAX];
static spinlock_t g_sysv_sem_lock;
static uint32_t g_sysv_sem_next_identifier = 1u;
static uint32_t g_sysv_sem_next_sequence = 1u;

static int kernel_sysv_sem_capable(const kernel_linux_identity_t *identity,
                                   uint32_t capability) {
    return identity && capability < 64u &&
           (identity->effective_capabilities & (1ull << capability));
}

static uint32_t kernel_sysv_sem_granted_bits(
        const kernel_sysv_sem_set_t *set,
        const kernel_linux_identity_t *identity) {
    if (identity->euid == set->uid || identity->euid == set->cuid)
        return (set->mode >> 6) & 7u;
    if (kernel_current_in_group(set->gid) ||
        kernel_current_in_group(set->cgid))
        return (set->mode >> 3) & 7u;
    return set->mode & 7u;
}

static int kernel_sysv_sem_has_access(
        const kernel_sysv_sem_set_t *set,
        const kernel_linux_identity_t *identity, uint32_t requested) {
    if ((kernel_sysv_sem_granted_bits(set, identity) & requested) ==
        requested)
        return 1;
    return kernel_sysv_sem_capable(identity, EDGE_LINUX_CAP_IPC_OWNER);
}

static int kernel_sysv_sem_is_owner(
        const kernel_sysv_sem_set_t *set,
        const kernel_linux_identity_t *identity) {
    return identity &&
           (identity->euid == set->uid || identity->euid == set->cuid ||
            kernel_sysv_sem_capable(identity, EDGE_LINUX_CAP_SYS_ADMIN));
}

static int kernel_sysv_sem_by_identifier_locked(
        int32_t identifier, uint32_t ipc_namespace_id) {
    for (uint32_t index = 0; index < KERNEL_SYSV_SEM_MAX_SETS; ++index) {
        const kernel_sysv_sem_set_t *set = &g_sysv_sem_sets[index];
        if (set->used && !set->removed && set->identifier == identifier &&
            set->ipc_namespace_id == ipc_namespace_id)
            return (int)index;
    }
    return -1;
}

static int kernel_sysv_sem_by_key_locked(int32_t key,
                                         uint32_t ipc_namespace_id) {
    for (uint32_t index = 0; index < KERNEL_SYSV_SEM_MAX_SETS; ++index) {
        const kernel_sysv_sem_set_t *set = &g_sysv_sem_sets[index];
        if (set->used && !set->removed && set->key == key &&
            set->ipc_namespace_id == ipc_namespace_id)
            return (int)index;
    }
    return -1;
}

static int kernel_sysv_sem_free_set_locked(void) {
    for (uint32_t index = 0; index < KERNEL_SYSV_SEM_MAX_SETS; ++index)
        if (!g_sysv_sem_sets[index].used) return (int)index;
    return -1;
}

static void kernel_sysv_sem_status_fill(const kernel_sysv_sem_set_t *set,
                                        kernel_sysv_sem_status_t *status) {
    memset(status, 0, sizeof(*status));
    status->permission.key = set->key;
    status->permission.uid = set->uid;
    status->permission.gid = set->gid;
    status->permission.cuid = set->cuid;
    status->permission.cgid = set->cgid;
    status->permission.mode = set->mode;
    status->permission.sequence = (int32_t)set->sequence;
    status->operation_time = (int64_t)(set->operation_time_us / 1000000u);
    status->change_time = (int64_t)(set->change_time_us / 1000000u);
    status->semaphore_count = set->semaphore_count;
}

int64_t kernel_sysv_sem_get(uint32_t ipc_namespace_id, int32_t key,
                            uint32_t semaphore_count, uint32_t flags) {
    kernel_linux_identity_t identity;
    kernel_sysv_sem_set_t *set;
    uint64_t lock_flags;
    int set_index;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (flags & ~(0777u | KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL))
        return -EDGE_LINUX_EINVAL;

    lock_flags = spin_lock_irqsave(&g_sysv_sem_lock);
    if (key != KERNEL_SYSV_IPC_PRIVATE) {
        set_index = kernel_sysv_sem_by_key_locked(key, ipc_namespace_id);
        if (set_index >= 0) {
            uint32_t requested = ((flags & 0444u) ? 4u : 0u) |
                                 ((flags & 0222u) ? 2u : 0u);
            set = &g_sysv_sem_sets[set_index];
            if ((flags & (KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL)) ==
                (KERNEL_SYSV_IPC_CREAT | KERNEL_SYSV_IPC_EXCL)) {
                spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
                return -EDGE_LINUX_EEXIST;
            }
            if (semaphore_count > set->semaphore_count) {
                spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
                return -EDGE_LINUX_EINVAL;
            }
            if (!kernel_sysv_sem_has_access(set, &identity, requested)) {
                spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
                return -EDGE_LINUX_EACCES;
            }
            set_index = set->identifier;
            spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
            return set_index;
        }
        if (!(flags & KERNEL_SYSV_IPC_CREAT)) {
            spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
            return -EDGE_LINUX_ENOENT;
        }
    }
    if (!semaphore_count ||
        semaphore_count > KERNEL_SYSV_SEM_MAX_PER_SET) {
        spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    set_index = kernel_sysv_sem_free_set_locked();
    if (set_index < 0) {
        spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
        return -EDGE_LINUX_ENOSPC;
    }
    set = &g_sysv_sem_sets[set_index];
    memset(set, 0, sizeof(*set));
    set->used = 1u;
    set->identifier = (int32_t)g_sysv_sem_next_identifier++;
    if (!g_sysv_sem_next_identifier) g_sysv_sem_next_identifier = 1u;
    set->sequence = g_sysv_sem_next_sequence++;
    if (!g_sysv_sem_next_sequence) g_sysv_sem_next_sequence = 1u;
    set->key = key;
    set->ipc_namespace_id = ipc_namespace_id;
    set->uid = identity.euid;
    set->gid = identity.egid;
    set->cuid = identity.euid;
    set->cgid = identity.egid;
    set->mode = flags & 0777u;
    set->semaphore_count = (uint16_t)semaphore_count;
    set->change_time_us = boottime_realtime_us();
    set_index = set->identifier;
    spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
    return set_index;
}

static int kernel_sysv_sem_undo_update_locked(
        int32_t task_id, int32_t identifier, uint16_t semaphore_number,
        int32_t delta) {
    int free_index = -1;
    for (uint32_t index = 0; index < KERNEL_SYSV_SEM_UNDO_MAX; ++index) {
        kernel_sysv_sem_undo_t *undo = &g_sysv_sem_undo[index];
        if (!undo->used) {
            if (free_index < 0) free_index = (int)index;
            continue;
        }
        if (undo->task_id != task_id || undo->identifier != identifier ||
            undo->semaphore_number != semaphore_number)
            continue;
        delta += undo->adjustment;
        if (delta < -(int32_t)KERNEL_SYSV_SEM_VALUE_MAX ||
            delta > (int32_t)KERNEL_SYSV_SEM_VALUE_MAX)
            return -EDGE_LINUX_ERANGE;
        if (!delta) memset(undo, 0, sizeof(*undo));
        else undo->adjustment = (int16_t)delta;
        return 0;
    }
    if (delta < -(int32_t)KERNEL_SYSV_SEM_VALUE_MAX ||
        delta > (int32_t)KERNEL_SYSV_SEM_VALUE_MAX)
        return -EDGE_LINUX_ERANGE;
    if (free_index < 0) return -EDGE_LINUX_ENOSPC;
    g_sysv_sem_undo[free_index].used = 1u;
    g_sysv_sem_undo[free_index].task_id = task_id;
    g_sysv_sem_undo[free_index].identifier = identifier;
    g_sysv_sem_undo[free_index].semaphore_number = semaphore_number;
    g_sysv_sem_undo[free_index].adjustment = (int16_t)delta;
    return 0;
}

static int kernel_sysv_sem_undo_preflight_locked(
        int32_t task_id, int32_t identifier,
        const int32_t *adjustments, uint32_t semaphore_count) {
    uint32_t free_count = 0;
    uint32_t needed_count = 0;

    for (uint32_t index = 0; index < KERNEL_SYSV_SEM_UNDO_MAX; ++index)
        if (!g_sysv_sem_undo[index].used) ++free_count;
    for (uint32_t semaphore = 0; semaphore < semaphore_count; ++semaphore) {
        int found = 0;
        int32_t adjustment;
        if (!adjustments[semaphore]) continue;
        adjustment = adjustments[semaphore];
        for (uint32_t index = 0; index < KERNEL_SYSV_SEM_UNDO_MAX; ++index) {
            const kernel_sysv_sem_undo_t *undo = &g_sysv_sem_undo[index];
            if (!undo->used || undo->task_id != task_id ||
                undo->identifier != identifier ||
                undo->semaphore_number != semaphore)
                continue;
            adjustment += undo->adjustment;
            found = 1;
            break;
        }
        if (adjustment < -(int32_t)KERNEL_SYSV_SEM_VALUE_MAX ||
            adjustment > (int32_t)KERNEL_SYSV_SEM_VALUE_MAX)
            return -EDGE_LINUX_ERANGE;
        if (!found && adjustment) ++needed_count;
    }
    return needed_count <= free_count ? 0 : -EDGE_LINUX_ENOSPC;
}

int64_t kernel_sysv_sem_operate(uint32_t ipc_namespace_id, int32_t identifier,
                                const struct edge_linux_sembuf *operations,
                                uint32_t operation_count,
                                kernel_sysv_sem_wait_t *wait) {
    kernel_linux_identity_t identity;
    kernel_sysv_sem_set_t *set;
    uint16_t staged[KERNEL_SYSV_SEM_MAX_PER_SET];
    int32_t undo_delta[KERNEL_SYSV_SEM_MAX_PER_SET];
    uint64_t lock_flags;
    uint32_t requested_access = 4u;
    int set_index;
    int status = 0;

    if (!operations || !operation_count ||
        operation_count > KERNEL_SYSV_SEM_MAX_OPS)
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (wait) memset(wait, 0, sizeof(*wait));
    memset(undo_delta, 0, sizeof(undo_delta));
    for (uint32_t index = 0; index < operation_count; ++index)
        if (operations[index].sem_op) {
            requested_access = 2u;
            break;
        }

    lock_flags = spin_lock_irqsave(&g_sysv_sem_lock);
    set_index = kernel_sysv_sem_by_identifier_locked(
        identifier, ipc_namespace_id);
    if (set_index < 0) {
        spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    set = &g_sysv_sem_sets[set_index];
    if (!kernel_sysv_sem_has_access(set, &identity, requested_access)) {
        spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
        return -EDGE_LINUX_EACCES;
    }
    for (uint32_t index = 0; index < set->semaphore_count; ++index)
        staged[index] = set->semaphores[index].value;
    for (uint32_t index = 0; index < operation_count; ++index) {
        const struct edge_linux_sembuf *operation = &operations[index];
        int32_t value;
        if (operation->sem_num >= set->semaphore_count) {
            status = -EDGE_LINUX_EFBIG;
            break;
        }
        if ((uint16_t)operation->sem_flg &
            ~(KERNEL_SYSV_SEM_UNDO | KERNEL_SYSV_IPC_NOWAIT)) {
            status = -EDGE_LINUX_EINVAL;
            break;
        }
        value = staged[operation->sem_num];
        if (operation->sem_op > 0) {
            if (value > (int32_t)KERNEL_SYSV_SEM_VALUE_MAX -
                        operation->sem_op) {
                status = -EDGE_LINUX_ERANGE;
                break;
            }
            staged[operation->sem_num] =
                (uint16_t)(value + operation->sem_op);
        } else if (operation->sem_op < 0) {
            if (value < -(int32_t)operation->sem_op) {
                if (operation->sem_flg & KERNEL_SYSV_IPC_NOWAIT)
                    status = -EDGE_LINUX_EAGAIN;
                else {
                    status = -EDGE_LINUX_EAGAIN;
                    if (wait) {
                        wait->semaphore_number = operation->sem_num;
                        wait->valid = 1u;
                    }
                }
                break;
            }
            staged[operation->sem_num] =
                (uint16_t)(value + operation->sem_op);
        } else if (value) {
            status = -EDGE_LINUX_EAGAIN;
            if (!(operation->sem_flg & KERNEL_SYSV_IPC_NOWAIT) && wait) {
                wait->semaphore_number = operation->sem_num;
                wait->wait_for_zero = 1u;
                wait->valid = 1u;
            }
            break;
        }
        if (operation->sem_flg & KERNEL_SYSV_SEM_UNDO)
            undo_delta[operation->sem_num] -= operation->sem_op;
    }
    if (!status) {
        status = kernel_sysv_sem_undo_preflight_locked(
            identity.global_tid, identifier, undo_delta,
            set->semaphore_count);
    }
    if (!status) {
        for (uint32_t index = 0; index < set->semaphore_count; ++index) {
            if (!undo_delta[index]) continue;
            status = kernel_sysv_sem_undo_update_locked(
                identity.global_tid, identifier, (uint16_t)index,
                undo_delta[index]);
            if (status < 0) break;
        }
    }
    if (!status) {
        for (uint32_t index = 0; index < set->semaphore_count; ++index)
            set->semaphores[index].value = staged[index];
        for (uint32_t index = 0; index < operation_count; ++index)
            set->semaphores[operations[index].sem_num].last_pid =
                identity.tgid;
        set->operation_time_us = boottime_realtime_us();
    }
    spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
    return status;
}

void kernel_sysv_sem_waiter_change(uint32_t ipc_namespace_id,
                                   int32_t identifier,
                                   const kernel_sysv_sem_wait_t *wait,
                                   int delta) {
    uint64_t lock_flags;
    int set_index;
    if (!wait || !wait->valid || (delta != 1 && delta != -1)) return;
    lock_flags = spin_lock_irqsave(&g_sysv_sem_lock);
    set_index = kernel_sysv_sem_by_identifier_locked(
        identifier, ipc_namespace_id);
    if (set_index >= 0) {
        kernel_sysv_sem_set_t *set = &g_sysv_sem_sets[set_index];
        if (wait->semaphore_number < set->semaphore_count) {
            uint16_t *count = wait->wait_for_zero ?
                &set->semaphores[wait->semaphore_number].waiting_zero :
                &set->semaphores[wait->semaphore_number].waiting_negative;
            if (delta > 0 && *count != UINT16_MAX) ++*count;
            else if (delta < 0 && *count) --*count;
        }
    }
    spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
}

static void kernel_sysv_sem_information_fill(
        struct edge_linux_seminfo *information) {
    memset(information, 0, sizeof(*information));
    information->semmni = KERNEL_SYSV_SEM_MAX_SETS;
    information->semmns = KERNEL_SYSV_SEM_MAX_SETS *
                          KERNEL_SYSV_SEM_MAX_PER_SET;
    information->semmnu = KERNEL_SYSV_SEM_UNDO_MAX;
    information->semmsl = KERNEL_SYSV_SEM_MAX_PER_SET;
    information->semopm = KERNEL_SYSV_SEM_MAX_OPS;
    information->semume = KERNEL_SYSV_SEM_MAX_OPS;
    information->semusz = sizeof(kernel_sysv_sem_undo_t);
    information->semvmx = KERNEL_SYSV_SEM_VALUE_MAX;
    information->semaem = KERNEL_SYSV_SEM_VALUE_MAX;
}

int kernel_sysv_sem_count(uint32_t ipc_namespace_id, int32_t identifier,
                          uint32_t requested_access, uint32_t *count) {
    kernel_linux_identity_t identity;
    uint64_t lock_flags;
    int set_index;
    int result = 0;

    if (!count || (requested_access & ~6u))
        return -EDGE_LINUX_EINVAL;
    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    lock_flags = spin_lock_irqsave(&g_sysv_sem_lock);
    set_index = kernel_sysv_sem_by_identifier_locked(
        identifier, ipc_namespace_id);
    if (set_index < 0)
        result = -EDGE_LINUX_EINVAL;
    else if (!kernel_sysv_sem_has_access(
                 &g_sysv_sem_sets[set_index], &identity,
                 requested_access))
        result = -EDGE_LINUX_EACCES;
    else
        *count = g_sysv_sem_sets[set_index].semaphore_count;
    spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
    return result;
}

int64_t kernel_sysv_sem_control(uint32_t ipc_namespace_id, int32_t identifier,
                                uint32_t semaphore_number, uint32_t command,
                                int32_t value, uint16_t *values,
                                uint32_t value_count,
                                kernel_sysv_sem_status_t *status,
                                struct edge_linux_seminfo *information) {
    kernel_linux_identity_t identity;
    kernel_sysv_sem_set_t *set;
    uint32_t operation = command & 0xffu;
    uint64_t lock_flags;
    int set_index;
    int result = 0;

    if (kernel_current_linux_identity(&identity) < 0)
        return -EDGE_LINUX_ESRCH;
    if (command & ~(KERNEL_SYSV_IPC_64 | 0xffu))
        return -EDGE_LINUX_EINVAL;
    if (operation == KERNEL_SYSV_IPC_INFO ||
        operation == KERNEL_SYSV_SEM_INFO) {
        if (!information) return -EDGE_LINUX_EFAULT;
        kernel_sysv_sem_information_fill(information);
        return KERNEL_SYSV_SEM_MAX_SETS - 1u;
    }

    lock_flags = spin_lock_irqsave(&g_sysv_sem_lock);
    if (operation == KERNEL_SYSV_SEM_STAT ||
        operation == KERNEL_SYSV_SEM_STAT_ANY) {
        if (identifier < 0 ||
            (uint32_t)identifier >= KERNEL_SYSV_SEM_MAX_SETS ||
            !g_sysv_sem_sets[identifier].used ||
            g_sysv_sem_sets[identifier].removed ||
            g_sysv_sem_sets[identifier].ipc_namespace_id != ipc_namespace_id) {
            spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
            return -EDGE_LINUX_EINVAL;
        }
        set_index = identifier;
    } else {
        set_index = kernel_sysv_sem_by_identifier_locked(
            identifier, ipc_namespace_id);
    }
    if (set_index < 0) {
        spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
        return -EDGE_LINUX_EINVAL;
    }
    set = &g_sysv_sem_sets[set_index];
    if (operation != KERNEL_SYSV_SEM_STAT_ANY &&
        !kernel_sysv_sem_has_access(set, &identity, 4u) &&
        operation != KERNEL_SYSV_IPC_RMID &&
        operation != KERNEL_SYSV_IPC_SET) {
        spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
        return -EDGE_LINUX_EACCES;
    }
    switch (operation) {
    case KERNEL_SYSV_IPC_RMID:
        if (!kernel_sysv_sem_is_owner(set, &identity)) result = -EDGE_LINUX_EPERM;
        else {
            for (uint32_t index = 0; index < KERNEL_SYSV_SEM_UNDO_MAX; ++index)
                if (g_sysv_sem_undo[index].used &&
                    g_sysv_sem_undo[index].identifier == set->identifier)
                    memset(&g_sysv_sem_undo[index], 0,
                           sizeof(g_sysv_sem_undo[index]));
            memset(set, 0, sizeof(*set));
        }
        break;
    case KERNEL_SYSV_IPC_SET:
        if (!status) result = -EDGE_LINUX_EFAULT;
        else if (!kernel_sysv_sem_is_owner(set, &identity))
            result = -EDGE_LINUX_EPERM;
        else {
            set->uid = status->permission.uid;
            set->gid = status->permission.gid;
            set->mode = status->permission.mode & 0777u;
            set->change_time_us = boottime_realtime_us();
        }
        break;
    case KERNEL_SYSV_IPC_STAT:
    case KERNEL_SYSV_SEM_STAT:
    case KERNEL_SYSV_SEM_STAT_ANY:
        if (!status) result = -EDGE_LINUX_EFAULT;
        else kernel_sysv_sem_status_fill(set, status);
        if (!result && (operation == KERNEL_SYSV_SEM_STAT ||
                        operation == KERNEL_SYSV_SEM_STAT_ANY))
            result = set->identifier;
        break;
    case KERNEL_SYSV_SEM_GETPID:
    case KERNEL_SYSV_SEM_GETVAL:
    case KERNEL_SYSV_SEM_GETNCNT:
    case KERNEL_SYSV_SEM_GETZCNT:
        if (semaphore_number >= set->semaphore_count)
            result = -EDGE_LINUX_EINVAL;
        else if (operation == KERNEL_SYSV_SEM_GETPID)
            result = set->semaphores[semaphore_number].last_pid;
        else if (operation == KERNEL_SYSV_SEM_GETVAL)
            result = set->semaphores[semaphore_number].value;
        else if (operation == KERNEL_SYSV_SEM_GETNCNT)
            result = set->semaphores[semaphore_number].waiting_negative;
        else result = set->semaphores[semaphore_number].waiting_zero;
        break;
    case KERNEL_SYSV_SEM_GETALL:
        if (!values || value_count < set->semaphore_count)
            result = -EDGE_LINUX_EFAULT;
        else for (uint32_t index = 0; index < set->semaphore_count; ++index)
            values[index] = set->semaphores[index].value;
        break;
    case KERNEL_SYSV_SEM_SETVAL:
        if (!kernel_sysv_sem_has_access(set, &identity, 2u))
            result = -EDGE_LINUX_EACCES;
        else if (semaphore_number >= set->semaphore_count)
            result = -EDGE_LINUX_EINVAL;
        else if (value < 0 || value > (int32_t)KERNEL_SYSV_SEM_VALUE_MAX)
            result = -EDGE_LINUX_ERANGE;
        else {
            set->semaphores[semaphore_number].value = (uint16_t)value;
            set->semaphores[semaphore_number].last_pid = identity.tgid;
            set->change_time_us = boottime_realtime_us();
            for (uint32_t index = 0; index < KERNEL_SYSV_SEM_UNDO_MAX; ++index)
                if (g_sysv_sem_undo[index].used &&
                    g_sysv_sem_undo[index].identifier == set->identifier &&
                    g_sysv_sem_undo[index].semaphore_number == semaphore_number)
                    memset(&g_sysv_sem_undo[index], 0,
                           sizeof(g_sysv_sem_undo[index]));
        }
        break;
    case KERNEL_SYSV_SEM_SETALL:
        if (!kernel_sysv_sem_has_access(set, &identity, 2u))
            result = -EDGE_LINUX_EACCES;
        else if (!values || value_count < set->semaphore_count)
            result = -EDGE_LINUX_EFAULT;
        else {
            for (uint32_t index = 0; index < set->semaphore_count; ++index)
                if (values[index] > KERNEL_SYSV_SEM_VALUE_MAX) {
                    result = -EDGE_LINUX_ERANGE;
                    break;
                }
            if (!result) {
                for (uint32_t index = 0; index < set->semaphore_count; ++index) {
                    set->semaphores[index].value = values[index];
                    set->semaphores[index].last_pid = identity.tgid;
                }
                set->change_time_us = boottime_realtime_us();
                for (uint32_t index = 0; index < KERNEL_SYSV_SEM_UNDO_MAX;
                     ++index)
                    if (g_sysv_sem_undo[index].used &&
                        g_sysv_sem_undo[index].identifier == set->identifier)
                        memset(&g_sysv_sem_undo[index], 0,
                               sizeof(g_sysv_sem_undo[index]));
            }
        }
        break;
    default:
        result = -EDGE_LINUX_EINVAL;
        break;
    }
    spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
    return result;
}

void kernel_sysv_sem_task_exit(int32_t task_id) {
    uint64_t lock_flags = spin_lock_irqsave(&g_sysv_sem_lock);
    for (uint32_t index = 0; index < KERNEL_SYSV_SEM_UNDO_MAX; ++index) {
        kernel_sysv_sem_undo_t *undo = &g_sysv_sem_undo[index];
        int set_index;
        int32_t value;
        if (!undo->used || undo->task_id != task_id) continue;
        set_index = -1;
        for (uint32_t candidate = 0; candidate < KERNEL_SYSV_SEM_MAX_SETS;
             ++candidate)
            if (g_sysv_sem_sets[candidate].used &&
                !g_sysv_sem_sets[candidate].removed &&
                g_sysv_sem_sets[candidate].identifier == undo->identifier) {
                set_index = (int)candidate;
                break;
            }
        if (set_index >= 0 && undo->semaphore_number <
                              g_sysv_sem_sets[set_index].semaphore_count) {
            kernel_sysv_semaphore_t *semaphore =
                &g_sysv_sem_sets[set_index].semaphores[
                    undo->semaphore_number];
            value = (int32_t)semaphore->value + undo->adjustment;
            if (value < 0) value = 0;
            if (value > (int32_t)KERNEL_SYSV_SEM_VALUE_MAX)
                value = KERNEL_SYSV_SEM_VALUE_MAX;
            semaphore->value = (uint16_t)value;
            semaphore->last_pid = task_id;
            g_sysv_sem_sets[set_index].operation_time_us =
                boottime_realtime_us();
        }
        memset(undo, 0, sizeof(*undo));
    }
    spin_unlock_irqrestore(&g_sysv_sem_lock, lock_flags);
}
