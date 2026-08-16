/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 *
 * Architecture-independent Linux signalfd mask, lifetime, record conversion,
 * and multi-record read semantics.
 */

#include <stdint.h>

#include "kernel/linux_errno.h"
#include "kernel/runtime_limits.h"
#include "kernel/signalfd.h"
#include "string.h"
#include "sys/spinlock.h"

typedef struct kernel_signalfd_object {
    uint8_t used;
    uint8_t padding[3];
    uint32_t references;
    uint64_t mask;
} kernel_signalfd_object_t;

static kernel_signalfd_object_t
    g_signalfds[EDGE_RUNTIME_MAX_SIGNALFDS];
static spinlock_t g_signalfd_lock;

static uint16_t kernel_signalfd_read_u16(const uint8_t *source,
                                         uint32_t offset) {
    uint16_t value;
    memcpy(&value, source + offset, sizeof(value));
    return value;
}

static uint32_t kernel_signalfd_read_u32(const uint8_t *source,
                                         uint32_t offset) {
    uint32_t value;
    memcpy(&value, source + offset, sizeof(value));
    return value;
}

static int32_t kernel_signalfd_read_i32(const uint8_t *source,
                                        uint32_t offset) {
    int32_t value;
    memcpy(&value, source + offset, sizeof(value));
    return value;
}

static uint64_t kernel_signalfd_read_u64(const uint8_t *source,
                                         uint32_t offset) {
    uint64_t value;
    memcpy(&value, source + offset, sizeof(value));
    return value;
}

static uint64_t kernel_signalfd_sanitize_mask(uint64_t mask) {
    mask &= ~(UINT64_C(1) << (KERNEL_SIGNALFD_SIGKILL - 1u));
    mask &= ~(UINT64_C(1) << (KERNEL_SIGNALFD_SIGSTOP - 1u));
    return mask;
}

static kernel_signalfd_object_t *kernel_signalfd_lookup_locked(
    int signalfd_id) {
    if (signalfd_id < 0 || signalfd_id >= EDGE_RUNTIME_MAX_SIGNALFDS ||
        !g_signalfds[signalfd_id].used)
        return 0;
    return &g_signalfds[signalfd_id];
}

int kernel_signalfd_create(uint64_t mask) {
    uint64_t irq_flags;
    int result = -EDGE_LINUX_ENFILE;
    irq_flags = spin_lock_irqsave(&g_signalfd_lock);
    for (int signalfd_id = 0;
         signalfd_id < EDGE_RUNTIME_MAX_SIGNALFDS; ++signalfd_id) {
        kernel_signalfd_object_t *object = &g_signalfds[signalfd_id];
        if (object->used) continue;
        memset(object, 0, sizeof(*object));
        object->used = 1u;
        object->references = 1u;
        object->mask = kernel_signalfd_sanitize_mask(mask);
        result = signalfd_id;
        break;
    }
    spin_unlock_irqrestore(&g_signalfd_lock, irq_flags);
    return result;
}

int kernel_signalfd_retain(int signalfd_id) {
    kernel_signalfd_object_t *object;
    uint64_t irq_flags;
    int result = 0;
    irq_flags = spin_lock_irqsave(&g_signalfd_lock);
    object = kernel_signalfd_lookup_locked(signalfd_id);
    if (!object) result = -EDGE_LINUX_EBADF;
    else if (object->references == UINT32_MAX)
        result = -EDGE_LINUX_EOVERFLOW;
    else
        ++object->references;
    spin_unlock_irqrestore(&g_signalfd_lock, irq_flags);
    return result;
}

void kernel_signalfd_release(int signalfd_id) {
    kernel_signalfd_object_t *object;
    uint64_t irq_flags = spin_lock_irqsave(&g_signalfd_lock);
    object = kernel_signalfd_lookup_locked(signalfd_id);
    if (object && object->references && --object->references == 0u)
        memset(object, 0, sizeof(*object));
    spin_unlock_irqrestore(&g_signalfd_lock, irq_flags);
}

int kernel_signalfd_update(int signalfd_id, uint64_t mask) {
    kernel_signalfd_object_t *object;
    uint64_t irq_flags;
    int result = 0;
    irq_flags = spin_lock_irqsave(&g_signalfd_lock);
    object = kernel_signalfd_lookup_locked(signalfd_id);
    if (!object) result = -EDGE_LINUX_EBADF;
    else object->mask = kernel_signalfd_sanitize_mask(mask);
    spin_unlock_irqrestore(&g_signalfd_lock, irq_flags);
    return result;
}

int kernel_signalfd_query(int signalfd_id, kernel_signalfd_state_t *state) {
    kernel_signalfd_object_t *object;
    uint64_t irq_flags;
    int result = 0;
    if (!state) return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&g_signalfd_lock);
    object = kernel_signalfd_lookup_locked(signalfd_id);
    if (!object) {
        result = -EDGE_LINUX_EBADF;
    } else {
        state->mask = object->mask;
        state->references = object->references;
    }
    spin_unlock_irqrestore(&g_signalfd_lock, irq_flags);
    return result;
}

int64_t kernel_signalfd_read(int signalfd_id, uint64_t length,
                             kernel_signalfd_dequeue_fn dequeue_signal,
                             void *dequeue_context,
                             kernel_signalfd_copy_record_fn copy_record,
                             void *copy_context) {
    kernel_signalfd_state_t state;
    uint64_t completed = 0;
    int status;
    if (length < sizeof(struct edge_linux_signalfd_siginfo))
        return -EDGE_LINUX_EINVAL;
    status = kernel_signalfd_query(signalfd_id, &state);
    if (status < 0) return status;
    if (!dequeue_signal) return -EDGE_LINUX_EIO;
    while (length - completed >=
           sizeof(struct edge_linux_signalfd_siginfo)) {
        struct edge_linux_signalfd_siginfo information;
        memset(&information, 0, sizeof(information));
        status = dequeue_signal(dequeue_context, state.mask, &information);
        if (status < 0)
            return completed ? (int64_t)completed : status;
        if (!status)
            return completed ? (int64_t)completed : -EDGE_LINUX_EAGAIN;
        /* Linux dequeues the signal before copy_to_user can fault. */
        if (!copy_record || copy_record(
                copy_context, completed, &information) < 0)
            return completed ? (int64_t)completed : -EDGE_LINUX_EFAULT;
        completed += sizeof(information);
    }
    return (int64_t)completed;
}

void kernel_signalfd_siginfo_from_linux_siginfo(
    const void *linux_siginfo,
    struct edge_linux_signalfd_siginfo *information) {
    const uint8_t *source = (const uint8_t *)linux_siginfo;
    int32_t code;
    if (!information) return;
    memset(information, 0, sizeof(*information));
    if (!source) return;
    information->ssi_signo = kernel_signalfd_read_u32(source, 0u);
    information->ssi_errno = kernel_signalfd_read_i32(source, 4u);
    information->ssi_code = kernel_signalfd_read_i32(source, 8u);
    code = information->ssi_code;

    if (information->ssi_signo == 31u && code == 1) {
        /* SIGSYS/SYS_SECCOMP. */
        information->ssi_call_addr =
            kernel_signalfd_read_u64(source, 16u);
        information->ssi_syscall =
            kernel_signalfd_read_i32(source, 24u);
        information->ssi_arch =
            kernel_signalfd_read_u32(source, 28u);
    } else if (code == -2) { /* SI_TIMER */
        information->ssi_tid = kernel_signalfd_read_u32(source, 16u);
        information->ssi_overrun =
            kernel_signalfd_read_u32(source, 20u);
        information->ssi_ptr =
            kernel_signalfd_read_u64(source, 24u);
        information->ssi_int =
            kernel_signalfd_read_i32(source, 24u);
    } else if (information->ssi_signo == 17u &&
               (code == 1 || code == 2 || code == 3 ||
                code == 4 || code == 5 || code == 6)) {
        /* CLD_* records. */
        information->ssi_pid =
            kernel_signalfd_read_u32(source, 16u);
        information->ssi_uid =
            kernel_signalfd_read_u32(source, 20u);
        information->ssi_status =
            kernel_signalfd_read_i32(source, 24u);
        information->ssi_utime =
            kernel_signalfd_read_u64(source, 32u);
        information->ssi_stime =
            kernel_signalfd_read_u64(source, 40u);
    } else if (information->ssi_signo == 29u) {
        /* SIGIO/SIGPOLL uses the sigpoll union arm. */
        information->ssi_band =
            (uint32_t)kernel_signalfd_read_u64(source, 16u);
        information->ssi_fd = kernel_signalfd_read_i32(source, 24u);
    } else if (information->ssi_signo == 4u ||
               information->ssi_signo == 5u ||
               information->ssi_signo == 7u ||
               information->ssi_signo == 8u ||
               information->ssi_signo == 11u) {
        /* SIGILL, SIGTRAP, SIGBUS, SIGFPE, and SIGSEGV carry fault data. */
        information->ssi_addr = kernel_signalfd_read_u64(source, 16u);
        information->ssi_addr_lsb = kernel_signalfd_read_u16(source, 24u);
    } else {
        information->ssi_pid =
            kernel_signalfd_read_u32(source, 16u);
        information->ssi_uid =
            kernel_signalfd_read_u32(source, 20u);
        information->ssi_ptr =
            kernel_signalfd_read_u64(source, 24u);
        information->ssi_int =
            kernel_signalfd_read_i32(source, 24u);
    }
}
