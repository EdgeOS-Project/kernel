/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS Linux-compatible advisory file locking.
 * Copyright (c) EdgeOS Contributors.
 *
 * Linux process locks, open-file-description locks, and flock locks have
 * different ownership and lifetime rules.  This file keeps those rules in
 * one architecture-independent manager.  Architecture runtimes provide only
 * descriptor identity and scheduler sleep/wakeup mechanisms.
 */

#include "kernel/file_lock.h"
#include "sys/spinlock.h"
#include "string.h"

#define EDGE_FILE_LOCK_MAX 1024u
#define EDGE_FILE_LOCK_WAIT_MAX 256u

#define EDGE_LINUX_EBADF 9
#define EDGE_LINUX_EAGAIN 11
#define EDGE_LINUX_EFAULT 14
#define EDGE_LINUX_EINVAL 22
#define EDGE_LINUX_EDEADLK 35
#define EDGE_LINUX_ENOLCK 37
#define EDGE_LINUX_EOVERFLOW 75

#define EDGE_LINUX_SEEK_SET 0
#define EDGE_LINUX_SEEK_CUR 1
#define EDGE_LINUX_SEEK_END 2

#define EDGE_LINUX_F_GETLK 5u
#define EDGE_LINUX_F_SETLK 6u
#define EDGE_LINUX_F_SETLKW 7u
#define EDGE_LINUX_F_OFD_GETLK 36u
#define EDGE_LINUX_F_OFD_SETLK 37u
#define EDGE_LINUX_F_OFD_SETLKW 38u

#define EDGE_LINUX_F_RDLCK 0
#define EDGE_LINUX_F_WRLCK 1
#define EDGE_LINUX_F_UNLCK 2

#define EDGE_LINUX_LOCK_SH 1u
#define EDGE_LINUX_LOCK_EX 2u
#define EDGE_LINUX_LOCK_NB 4u
#define EDGE_LINUX_LOCK_UN 8u

#define EDGE_LINUX_O_ACCMODE 3u
#define EDGE_LINUX_O_RDONLY 0u
#define EDGE_LINUX_O_WRONLY 1u

typedef enum edge_file_lock_kind {
    EDGE_FILE_LOCK_POSIX = 1,
    EDGE_FILE_LOCK_OFD = 2,
    EDGE_FILE_LOCK_FLOCK = 3,
} edge_file_lock_kind_t;

typedef struct edge_file_lock_request {
    uint64_t filesystem;
    uint64_t inode;
    uint64_t open_description;
    uint64_t start;
    uint64_t end;
    int32_t process_id;
    int32_t task_id;
    int16_t type;
    uint8_t kind;
} edge_file_lock_request_t;

typedef struct edge_file_lock_record {
    edge_file_lock_request_t request;
    uint8_t used;
} edge_file_lock_record_t;

typedef struct edge_file_lock_waiter {
    edge_file_lock_request_t request;
    uint64_t sequence;
    uint8_t used;
} edge_file_lock_waiter_t;

static edge_file_lock_record_t g_file_locks[EDGE_FILE_LOCK_MAX];
static edge_file_lock_waiter_t g_file_lock_waiters[EDGE_FILE_LOCK_WAIT_MAX];
static spinlock_t g_file_lock_state_lock;
static uint64_t g_file_lock_wait_sequence;

void edge_linux_file_lock_pseudo_identity(
    uint32_t object_class, uint64_t object_identity, const char *path,
    uint64_t *filesystem, uint64_t *inode) {
    uint64_t hash = 1469598103934665603ULL;

    if (filesystem) {
        *filesystem = 0x8000000000000000ULL |
                      ((uint64_t)object_class << 48) |
                      0x454447454c4bULL;
    }
    hash ^= object_class;
    hash *= 1099511628211ULL;
    if (path && path[0]) {
        while (*path) {
            hash ^= (uint8_t)*path++;
            hash *= 1099511628211ULL;
        }
    } else {
        for (uint32_t shift = 0; shift < 64u; shift += 8u) {
            hash ^= (uint8_t)(object_identity >> shift);
            hash *= 1099511628211ULL;
        }
    }
    if (!hash) hash = 1;
    if (inode) *inode = hash;
}

static int edge_file_lock_same_file(const edge_file_lock_request_t *left,
                                    const edge_file_lock_request_t *right) {
    return left->filesystem == right->filesystem &&
           left->inode == right->inode;
}

static int edge_file_lock_ranges_overlap(
    const edge_file_lock_request_t *left,
    const edge_file_lock_request_t *right) {
    return left->start <= right->end && right->start <= left->end;
}

static int edge_file_lock_ranges_touch(
    const edge_file_lock_request_t *left,
    const edge_file_lock_request_t *right) {
    uint64_t left_limit = left->end == UINT64_MAX ? UINT64_MAX :
                          left->end + 1u;
    uint64_t right_limit = right->end == UINT64_MAX ? UINT64_MAX :
                           right->end + 1u;
    return left->start <= right_limit && right->start <= left_limit;
}

static int edge_file_lock_same_owner(const edge_file_lock_request_t *left,
                                     const edge_file_lock_request_t *right) {
    if (left->kind != right->kind) return 0;
    if (left->kind == EDGE_FILE_LOCK_POSIX)
        return left->process_id == right->process_id;
    return left->open_description == right->open_description;
}

static int edge_file_lock_record_namespace(uint8_t kind) {
    return kind == EDGE_FILE_LOCK_POSIX || kind == EDGE_FILE_LOCK_OFD;
}

static int edge_file_lock_conflicts(
    const edge_file_lock_request_t *request,
    const edge_file_lock_request_t *held) {
    if (!edge_file_lock_same_file(request, held) ||
        !edge_file_lock_ranges_overlap(request, held))
        return 0;
    if (request->kind == EDGE_FILE_LOCK_FLOCK ||
        held->kind == EDGE_FILE_LOCK_FLOCK) {
        if (request->kind != held->kind ||
            edge_file_lock_same_owner(request, held))
            return 0;
    } else {
        if (!edge_file_lock_record_namespace(request->kind) ||
            !edge_file_lock_record_namespace(held->kind) ||
            edge_file_lock_same_owner(request, held))
            return 0;
    }
    return request->type == EDGE_LINUX_F_WRLCK ||
           held->type == EDGE_LINUX_F_WRLCK;
}

static int edge_file_lock_find_conflict_locked(
    const edge_file_lock_request_t *request) {
    int selected = -1;
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
        if (!g_file_locks[index].used ||
            !edge_file_lock_conflicts(request,
                                      &g_file_locks[index].request))
            continue;
        if (selected < 0 ||
            g_file_locks[index].request.start <
                g_file_locks[selected].request.start)
            selected = (int)index;
    }
    return selected;
}

static int edge_file_lock_find_free_locked(void) {
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index)
        if (!g_file_locks[index].used) return (int)index;
    return -1;
}

static uint32_t edge_file_lock_used_count_locked(void) {
    uint32_t count = 0;
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index)
        if (g_file_locks[index].used) ++count;
    return count;
}

static void edge_file_lock_expand_same_type_locked(
    edge_file_lock_request_t *effective) {
    int changed;
    do {
        changed = 0;
        for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
            edge_file_lock_request_t *held =
                &g_file_locks[index].request;
            if (!g_file_locks[index].used ||
                !edge_file_lock_same_file(effective, held) ||
                !edge_file_lock_same_owner(effective, held) ||
                effective->type != held->type ||
                !edge_file_lock_ranges_touch(effective, held))
                continue;
            if (held->start < effective->start) {
                effective->start = held->start;
                changed = 1;
            }
            if (held->end > effective->end) {
                effective->end = held->end;
                changed = 1;
            }
        }
    } while (changed);
}

static int edge_file_lock_apply_locked(
    const edge_file_lock_request_t *requested) {
    edge_file_lock_request_t effective = *requested;
    uint32_t removed = 0;
    uint32_t split = 0;
    uint32_t used;

    if (effective.type != EDGE_LINUX_F_UNLCK)
        edge_file_lock_expand_same_type_locked(&effective);

    used = edge_file_lock_used_count_locked();
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
        edge_file_lock_request_t *held = &g_file_locks[index].request;
        if (!g_file_locks[index].used ||
            !edge_file_lock_same_file(&effective, held) ||
            !edge_file_lock_same_owner(&effective, held) ||
            !edge_file_lock_ranges_overlap(&effective, held))
            continue;
        if (effective.start <= held->start && effective.end >= held->end)
            ++removed;
        else if (effective.start > held->start && effective.end < held->end)
            ++split;
    }
    if (used + split +
            (effective.type == EDGE_LINUX_F_UNLCK ? 0u : 1u) >
        EDGE_FILE_LOCK_MAX + removed)
        return -EDGE_LINUX_ENOLCK;

    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
        edge_file_lock_record_t *record = &g_file_locks[index];
        if (!record->used ||
            !edge_file_lock_same_file(&effective, &record->request) ||
            !edge_file_lock_same_owner(&effective, &record->request) ||
            !edge_file_lock_ranges_overlap(&effective, &record->request))
            continue;
        if (effective.start <= record->request.start &&
            effective.end >= record->request.end)
            memset(record, 0, sizeof(*record));
    }

    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
        edge_file_lock_record_t *record = &g_file_locks[index];
        edge_file_lock_request_t old;
        int second;
        if (!record->used ||
            !edge_file_lock_same_file(&effective, &record->request) ||
            !edge_file_lock_same_owner(&effective, &record->request) ||
            !edge_file_lock_ranges_overlap(&effective, &record->request))
            continue;
        old = record->request;
        if (effective.start <= old.start) {
            record->request.start = effective.end + 1u;
        } else if (effective.end >= old.end) {
            record->request.end = effective.start - 1u;
        } else {
            second = edge_file_lock_find_free_locked();
            if (second < 0) return -EDGE_LINUX_ENOLCK;
            record->request.end = effective.start - 1u;
            g_file_locks[second].used = 1;
            g_file_locks[second].request = old;
            g_file_locks[second].request.start = effective.end + 1u;
        }
    }

    if (effective.type != EDGE_LINUX_F_UNLCK) {
        int slot = edge_file_lock_find_free_locked();
        if (slot < 0) return -EDGE_LINUX_ENOLCK;
        g_file_locks[slot].used = 1;
        g_file_locks[slot].request = effective;
    }
    return 0;
}

static int edge_file_lock_add_process_owner_locked(
    int32_t *owners, uint32_t *count, int32_t owner) {
    if (owner <= 0) return 0;
    for (uint32_t index = 0; index < *count; ++index)
        if (owners[index] == owner) return 0;
    if (*count >= EDGE_FILE_LOCK_WAIT_MAX) return -1;
    owners[(*count)++] = owner;
    return 0;
}

static int edge_file_lock_deadlock_locked(
    const edge_file_lock_request_t *request) {
    int32_t owners[EDGE_FILE_LOCK_WAIT_MAX];
    uint32_t head = 0;
    uint32_t count = 0;
    if (request->kind != EDGE_FILE_LOCK_POSIX) return 0;

    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
        edge_file_lock_request_t *held = &g_file_locks[index].request;
        if (!g_file_locks[index].used ||
            held->kind != EDGE_FILE_LOCK_POSIX ||
            !edge_file_lock_conflicts(request, held))
            continue;
        if (held->process_id == request->process_id) return 1;
        if (edge_file_lock_add_process_owner_locked(
                owners, &count, held->process_id) < 0)
            return 1;
    }

    while (head < count) {
        int32_t owner = owners[head++];
        for (uint32_t waiter_index = 0;
             waiter_index < EDGE_FILE_LOCK_WAIT_MAX; ++waiter_index) {
            edge_file_lock_request_t *waiting;
            if (!g_file_lock_waiters[waiter_index].used ||
                g_file_lock_waiters[waiter_index].request.kind !=
                    EDGE_FILE_LOCK_POSIX ||
                g_file_lock_waiters[waiter_index].request.process_id != owner)
                continue;
            waiting = &g_file_lock_waiters[waiter_index].request;
            for (uint32_t lock_index = 0;
                 lock_index < EDGE_FILE_LOCK_MAX; ++lock_index) {
                edge_file_lock_request_t *held =
                    &g_file_locks[lock_index].request;
                if (!g_file_locks[lock_index].used ||
                    held->kind != EDGE_FILE_LOCK_POSIX ||
                    !edge_file_lock_conflicts(waiting, held))
                    continue;
                if (held->process_id == request->process_id) return 1;
                if (edge_file_lock_add_process_owner_locked(
                        owners, &count, held->process_id) < 0)
                    return 1;
            }
        }
    }
    return 0;
}

static int edge_file_lock_waiter_slot_locked(int32_t task_id) {
    int free_slot = -1;
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_WAIT_MAX; ++index) {
        if (g_file_lock_waiters[index].used &&
            g_file_lock_waiters[index].request.task_id == task_id)
            return -2;
        if (!g_file_lock_waiters[index].used && free_slot < 0)
            free_slot = (int)index;
    }
    return free_slot;
}

static void edge_file_lock_process_waiters(void) {
    for (;;) {
        edge_file_lock_waiter_t granted;
        uint64_t flags;
        int selected = -1;
        int result;

        memset(&granted, 0, sizeof(granted));
        flags = spin_lock_irqsave(&g_file_lock_state_lock);
        for (uint32_t index = 0; index < EDGE_FILE_LOCK_WAIT_MAX; ++index) {
            if (!g_file_lock_waiters[index].used ||
                edge_file_lock_find_conflict_locked(
                    &g_file_lock_waiters[index].request) >= 0)
                continue;
            if (selected < 0 ||
                g_file_lock_waiters[index].sequence <
                    g_file_lock_waiters[selected].sequence)
                selected = (int)index;
        }
        if (selected < 0) {
            spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
            return;
        }
        granted = g_file_lock_waiters[selected];
        memset(&g_file_lock_waiters[selected], 0,
               sizeof(g_file_lock_waiters[selected]));
        result = edge_file_lock_apply_locked(&granted.request);
        arch_file_lock_wake(granted.request.task_id, result);
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
    }
}

static int edge_file_lock_checked_add(int64_t base, int64_t displacement,
                                      int64_t *result) {
    if ((displacement > 0 && base > INT64_MAX - displacement) ||
        (displacement < 0 && base < INT64_MIN - displacement))
        return -EDGE_LINUX_EOVERFLOW;
    *result = base + displacement;
    return 0;
}

static int edge_file_lock_normalize(
    const kernel_file_lock_info_t *information,
    const struct edge_linux_flock64 *input,
    edge_file_lock_request_t *request) {
    int64_t base;
    int64_t start;
    int64_t low;
    int64_t high;

    if (input->l_whence == EDGE_LINUX_SEEK_SET) base = 0;
    else if (input->l_whence == EDGE_LINUX_SEEK_CUR) {
        if (information->offset > INT64_MAX) return -EDGE_LINUX_EOVERFLOW;
        base = (int64_t)information->offset;
    } else if (input->l_whence == EDGE_LINUX_SEEK_END) {
        if (information->size > INT64_MAX) return -EDGE_LINUX_EOVERFLOW;
        base = (int64_t)information->size;
    } else {
        return -EDGE_LINUX_EINVAL;
    }
    if (edge_file_lock_checked_add(base, input->l_start, &start) < 0)
        return -EDGE_LINUX_EOVERFLOW;
    if (input->l_len == 0) {
        if (start < 0) return -EDGE_LINUX_EINVAL;
        request->start = (uint64_t)start;
        request->end = UINT64_MAX;
        return 0;
    }
    if (input->l_len > 0) {
        if (start < 0 || input->l_len - 1 > INT64_MAX - start)
            return start < 0 ? -EDGE_LINUX_EINVAL :
                               -EDGE_LINUX_EOVERFLOW;
        low = start;
        high = start + input->l_len - 1;
    } else {
        if (start <= 0 || input->l_len == INT64_MIN ||
            start < -input->l_len)
            return -EDGE_LINUX_EINVAL;
        low = start + input->l_len;
        high = start - 1;
    }
    request->start = (uint64_t)low;
    request->end = (uint64_t)high;
    return 0;
}

static int edge_file_lock_validate_access(
    const kernel_file_lock_info_t *information, int16_t type) {
    uint32_t access = information->status_flags & EDGE_LINUX_O_ACCMODE;
    if (type == EDGE_LINUX_F_RDLCK && access == EDGE_LINUX_O_WRONLY)
        return -EDGE_LINUX_EBADF;
    if (type == EDGE_LINUX_F_WRLCK && access == EDGE_LINUX_O_RDONLY)
        return -EDGE_LINUX_EBADF;
    return 0;
}

static int64_t edge_file_lock_set(
    const edge_file_lock_request_t *request, int blocking,
    void *user_registers) {
    uint64_t flags = spin_lock_irqsave(&g_file_lock_state_lock);
    int conflict;
    int waiter;
    int result;

    if (request->type == EDGE_LINUX_F_UNLCK) {
        result = edge_file_lock_apply_locked(request);
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
        if (result == 0) edge_file_lock_process_waiters();
        return result;
    }
    conflict = edge_file_lock_find_conflict_locked(request);
    if (conflict < 0) {
        result = edge_file_lock_apply_locked(request);
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
        return result;
    }
    if (!blocking) {
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
        return -EDGE_LINUX_EAGAIN;
    }
    if (edge_file_lock_deadlock_locked(request)) {
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
        return -EDGE_LINUX_EDEADLK;
    }
    waiter = edge_file_lock_waiter_slot_locked(request->task_id);
    if (waiter == -2) {
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
        return -EDGE_LINUX_EDEADLK;
    }
    if (waiter < 0) {
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
        return -EDGE_LINUX_ENOLCK;
    }
    result = arch_file_lock_wait_prepare(user_registers,
                                         request->task_id);
    if (result < 0) {
        spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
        return result;
    }
    g_file_lock_waiters[waiter].used = 1;
    g_file_lock_waiters[waiter].request = *request;
    g_file_lock_waiters[waiter].sequence = ++g_file_lock_wait_sequence;
    spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
    return arch_file_lock_wait_park(request->task_id);
}

static int edge_file_lock_drop_flock_for_conversion(
    const edge_file_lock_request_t *request) {
    edge_file_lock_request_t unlock = *request;
    uint64_t flags;
    int conversion = 0;
    int result = 0;

    flags = spin_lock_irqsave(&g_file_lock_state_lock);
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
        const edge_file_lock_request_t *held =
            &g_file_locks[index].request;
        if (!g_file_locks[index].used ||
            held->kind != EDGE_FILE_LOCK_FLOCK ||
            !edge_file_lock_same_file(request, held) ||
            !edge_file_lock_same_owner(request, held))
            continue;
        if (held->type != request->type) conversion = 1;
        break;
    }
    if (conversion) {
        unlock.type = EDGE_LINUX_F_UNLCK;
        result = edge_file_lock_apply_locked(&unlock);
    }
    spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
    if (conversion && result == 0) edge_file_lock_process_waiters();
    return result;
}

int64_t edge_linux_file_lock_fcntl(
    int32_t descriptor, uint32_t command, uint64_t user_lock,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user, void *copy_context,
    void *user_registers) {
    struct edge_linux_flock64 lock;
    kernel_file_lock_info_t information;
    edge_file_lock_request_t request;
    int is_ofd = command == EDGE_LINUX_F_OFD_GETLK ||
                 command == EDGE_LINUX_F_OFD_SETLK ||
                 command == EDGE_LINUX_F_OFD_SETLKW;
    int is_get = command == EDGE_LINUX_F_GETLK ||
                 command == EDGE_LINUX_F_OFD_GETLK;
    int blocking = command == EDGE_LINUX_F_SETLKW ||
                   command == EDGE_LINUX_F_OFD_SETLKW;
    int conflict;
    int result;
    uint64_t flags;

    if (!user_lock || !copy_from_user || !copy_to_user)
        return -EDGE_LINUX_EFAULT;
    if (copy_from_user(copy_context, &lock, user_lock, sizeof(lock)) < 0)
        return -EDGE_LINUX_EFAULT;
    if (lock.l_type != EDGE_LINUX_F_RDLCK &&
        lock.l_type != EDGE_LINUX_F_WRLCK &&
        lock.l_type != EDGE_LINUX_F_UNLCK)
        return -EDGE_LINUX_EINVAL;
    if ((is_get && lock.l_type == EDGE_LINUX_F_UNLCK) ||
        (is_ofd && lock.l_pid != 0))
        return -EDGE_LINUX_EINVAL;
    result = arch_fd_file_lock_info(descriptor, &information);
    if (result < 0) return result;
    if (!is_get && lock.l_type != EDGE_LINUX_F_UNLCK) {
        result = edge_file_lock_validate_access(&information, lock.l_type);
        if (result < 0) return result;
    }
    memset(&request, 0, sizeof(request));
    request.filesystem = information.filesystem;
    request.inode = information.inode;
    request.open_description = information.open_description;
    request.process_id = information.process_id;
    request.task_id = information.task_id;
    request.type = lock.l_type;
    request.kind = is_ofd ? EDGE_FILE_LOCK_OFD : EDGE_FILE_LOCK_POSIX;
    result = edge_file_lock_normalize(&information, &lock, &request);
    if (result < 0) return result;

    if (!is_get)
        return edge_file_lock_set(&request, blocking, user_registers);

    flags = spin_lock_irqsave(&g_file_lock_state_lock);
    conflict = edge_file_lock_find_conflict_locked(&request);
    if (conflict < 0) {
        lock.l_type = EDGE_LINUX_F_UNLCK;
        lock.l_pid = 0;
    } else {
        const edge_file_lock_request_t *held =
            &g_file_locks[conflict].request;
        lock.l_type = held->type;
        lock.l_whence = EDGE_LINUX_SEEK_SET;
        lock.l_start = (int64_t)held->start;
        lock.l_len = held->end == UINT64_MAX ? 0 :
                     (int64_t)(held->end - held->start + 1u);
        lock.l_pid = held->kind == EDGE_FILE_LOCK_POSIX ?
                     held->process_id : -1;
    }
    spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
    return copy_to_user(copy_context, user_lock, &lock, sizeof(lock)) < 0 ?
           -EDGE_LINUX_EFAULT : 0;
}

int64_t edge_linux_file_lock_flock(int32_t descriptor, uint32_t operation,
                                   void *user_registers) {
    kernel_file_lock_info_t information;
    edge_file_lock_request_t request;
    uint32_t mode = operation & ~EDGE_LINUX_LOCK_NB;
    int result;

    if (operation & ~(EDGE_LINUX_LOCK_SH | EDGE_LINUX_LOCK_EX |
                      EDGE_LINUX_LOCK_NB | EDGE_LINUX_LOCK_UN))
        return -EDGE_LINUX_EINVAL;
    if (mode != EDGE_LINUX_LOCK_SH && mode != EDGE_LINUX_LOCK_EX &&
        mode != EDGE_LINUX_LOCK_UN)
        return -EDGE_LINUX_EINVAL;
    result = arch_fd_file_lock_info(descriptor, &information);
    if (result < 0) return result;
    memset(&request, 0, sizeof(request));
    request.filesystem = information.filesystem;
    request.inode = information.inode;
    request.open_description = information.open_description;
    request.process_id = information.process_id;
    request.task_id = information.task_id;
    request.start = 0;
    request.end = UINT64_MAX;
    request.kind = EDGE_FILE_LOCK_FLOCK;
    request.type = mode == EDGE_LINUX_LOCK_UN ? EDGE_LINUX_F_UNLCK :
                   (mode == EDGE_LINUX_LOCK_EX ? EDGE_LINUX_F_WRLCK :
                                                EDGE_LINUX_F_RDLCK);
    if (request.type != EDGE_LINUX_F_UNLCK) {
        result = edge_file_lock_drop_flock_for_conversion(&request);
        if (result < 0) return result;
    }
    return edge_file_lock_set(&request,
                              (operation & EDGE_LINUX_LOCK_NB) == 0,
                              user_registers);
}

void edge_linux_file_lock_descriptor_closed(
    const kernel_file_lock_info_t *information) {
    uint64_t flags;
    int changed = 0;
    if (!information || !information->filesystem)
        return;
    flags = spin_lock_irqsave(&g_file_lock_state_lock);
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_MAX; ++index) {
        edge_file_lock_request_t *held = &g_file_locks[index].request;
        if (!g_file_locks[index].used ||
            held->filesystem != information->filesystem ||
            held->inode != information->inode)
            continue;
        if ((held->kind == EDGE_FILE_LOCK_POSIX &&
             held->process_id == information->process_id) ||
            (information->description_references <= 1u &&
             held->kind != EDGE_FILE_LOCK_POSIX &&
             held->open_description == information->open_description)) {
            memset(&g_file_locks[index], 0, sizeof(g_file_locks[index]));
            changed = 1;
        }
    }
    spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
    if (changed) edge_file_lock_process_waiters();
}

int edge_linux_file_lock_cancel_wait(int32_t task_id, int64_t result) {
    uint64_t flags;
    int found = 0;
    if (task_id <= 0) return 0;
    flags = spin_lock_irqsave(&g_file_lock_state_lock);
    for (uint32_t index = 0; index < EDGE_FILE_LOCK_WAIT_MAX; ++index) {
        if (!g_file_lock_waiters[index].used ||
            g_file_lock_waiters[index].request.task_id != task_id)
            continue;
        memset(&g_file_lock_waiters[index], 0,
               sizeof(g_file_lock_waiters[index]));
        found = 1;
        break;
    }
    spin_unlock_irqrestore(&g_file_lock_state_lock, flags);
    if (found) arch_file_lock_wake(task_id, result);
    return found;
}

void edge_linux_file_lock_task_exit(int32_t task_id) {
    (void)edge_linux_file_lock_cancel_wait(task_id, -EDGE_LINUX_EBADF);
}
