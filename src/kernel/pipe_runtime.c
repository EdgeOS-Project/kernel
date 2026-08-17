/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral Linux pipe object and ring-buffer semantics. */

#include "kernel/pipe_runtime.h"
#include "kernel/linux_errno.h"
#include <stddef.h>

static void pipe_bytes_zero(void *destination, uint64_t size) {
    uint8_t *bytes = destination;
    while (size--) *bytes++ = 0;
}

static void pipe_bytes_copy(void *destination, const void *source,
                            uint32_t size) {
    uint8_t *to = destination;
    const uint8_t *from = source;
    while (size--) *to++ = *from++;
}

static void kernel_pipe_sequence_advance(uint64_t *sequence) {
    if (!sequence) return;
    ++*sequence;
    if (!*sequence) *sequence = 1u;
}

static void kernel_pipe_metadata_lock(kernel_pipe_runtime_t *pipe) {
    while (__sync_lock_test_and_set(&pipe->metadata_lock, 1u)) {
        while (__atomic_load_n(&pipe->metadata_lock, __ATOMIC_RELAXED))
            __atomic_signal_fence(__ATOMIC_ACQUIRE);
    }
}

static void kernel_pipe_metadata_unlock(kernel_pipe_runtime_t *pipe) {
    __sync_lock_release(&pipe->metadata_lock);
}

void kernel_pipe_object_initialize(kernel_pipe_runtime_t *pipe) {
    if (!pipe) return;
    pipe_bytes_zero(pipe, sizeof(*pipe));
    pipe->used = 1;
    pipe->mode = 0600u;
    pipe->read_ready_sequence = 1u;
    pipe->write_ready_sequence = 1u;
}

void kernel_pipe_metadata_initialize(kernel_pipe_runtime_t *pipe,
                                     uint32_t uid, uint32_t gid,
                                     uint16_t mode) {
    if (!pipe || !pipe->used) return;
    kernel_pipe_metadata_lock(pipe);
    pipe->owner_uid = uid;
    pipe->owner_gid = gid;
    pipe->mode = (uint16_t)(mode & 07777u);
    kernel_pipe_metadata_unlock(pipe);
}

int kernel_pipe_metadata_snapshot(kernel_pipe_runtime_t *pipe,
                                  kernel_pipe_metadata_t *metadata) {
    if (!pipe || !metadata || !pipe->used) return -EDGE_LINUX_EBADF;
    kernel_pipe_metadata_lock(pipe);
    metadata->uid = pipe->owner_uid;
    metadata->gid = pipe->owner_gid;
    metadata->mode = pipe->mode;
    kernel_pipe_metadata_unlock(pipe);
    return 0;
}

int kernel_pipe_metadata_chown(kernel_pipe_runtime_t *pipe,
                               uint32_t uid, uint32_t gid) {
    if (!pipe || !pipe->used) return -EDGE_LINUX_EBADF;
    kernel_pipe_metadata_lock(pipe);
    if (uid != UINT32_MAX) pipe->owner_uid = uid;
    if (gid != UINT32_MAX) pipe->owner_gid = gid;
    kernel_pipe_metadata_unlock(pipe);
    return 0;
}

int kernel_pipe_object_allocate(kernel_pipe_runtime_t *objects,
                                uint32_t object_count) {
    uint32_t index;
    if (!objects || !object_count) return -EDGE_LINUX_EINVAL;
    for (index = 0; index < object_count; ++index) {
        if (objects[index].used) continue;
        kernel_pipe_object_initialize(&objects[index]);
        return (int)index;
    }
    return -EDGE_LINUX_ENFILE;
}

int kernel_pipe_object_release_if_unused(kernel_pipe_runtime_t *pipe) {
    int release;
    if (!pipe || !pipe->used) return 0;
    kernel_pipe_metadata_lock(pipe);
    release = pipe->used && !pipe->readers && !pipe->writers &&
        !pipe->pending_readers && !pipe->pending_writers;
    if (!release) {
        kernel_pipe_metadata_unlock(pipe);
        return 0;
    }
    pipe_bytes_zero(pipe, sizeof(*pipe));
    __atomic_store_n(&pipe->metadata_lock, 0u, __ATOMIC_RELEASE);
    return 1;
}

int kernel_pipe_endpoint_retain(kernel_pipe_runtime_t *pipe,
                                int reader, int writer) {
    if (!pipe || !pipe->used) return -EDGE_LINUX_EBADF;
    kernel_pipe_metadata_lock(pipe);
    if (!pipe->used) {
        kernel_pipe_metadata_unlock(pipe);
        return -EDGE_LINUX_EBADF;
    }
    if ((reader && pipe->readers == UINT32_MAX) ||
        (writer && pipe->writers == UINT32_MAX)) {
        kernel_pipe_metadata_unlock(pipe);
        return -EDGE_LINUX_ENFILE;
    }
    if (reader) ++pipe->readers;
    if (writer) ++pipe->writers;
    kernel_pipe_metadata_unlock(pipe);
    return 0;
}

int kernel_pipe_endpoint_drop(kernel_pipe_runtime_t *pipe,
                              int reader, int writer,
                              kernel_pipe_wake_fn wake,
                              void *wake_context, uint32_t pipe_index) {
    int last_reader;
    int last_writer;
    if (!pipe || !pipe->used) return -EDGE_LINUX_EBADF;
    kernel_pipe_metadata_lock(pipe);
    if (!pipe->used) {
        kernel_pipe_metadata_unlock(pipe);
        return -EDGE_LINUX_EBADF;
    }
    last_reader = reader && pipe->readers == 1u;
    last_writer = writer && pipe->writers == 1u;
    if (reader && pipe->readers) --pipe->readers;
    if (writer && pipe->writers) --pipe->writers;
    if (last_reader) kernel_pipe_sequence_advance(
        &pipe->write_ready_sequence);
    if (last_writer) kernel_pipe_sequence_advance(
        &pipe->read_ready_sequence);
    kernel_pipe_metadata_unlock(pipe);
    if (wake) wake(wake_context, pipe_index);
    return 0;
}

int kernel_pipe_pending_retain(kernel_pipe_runtime_t *pipe,
                               int reader, int writer) {
    if (!pipe || !pipe->used) return -EDGE_LINUX_EBADF;
    kernel_pipe_metadata_lock(pipe);
    if (!pipe->used) {
        kernel_pipe_metadata_unlock(pipe);
        return -EDGE_LINUX_EBADF;
    }
    if ((reader && pipe->pending_readers == UINT32_MAX) ||
        (writer && pipe->pending_writers == UINT32_MAX)) {
        kernel_pipe_metadata_unlock(pipe);
        return -EDGE_LINUX_ENFILE;
    }
    if (reader) ++pipe->pending_readers;
    if (writer) ++pipe->pending_writers;
    kernel_pipe_metadata_unlock(pipe);
    return 0;
}

int kernel_pipe_pending_drop(kernel_pipe_runtime_t *pipe,
                             int reader, int writer) {
    if (!pipe || !pipe->used) return -EDGE_LINUX_EBADF;
    kernel_pipe_metadata_lock(pipe);
    if (!pipe->used) {
        kernel_pipe_metadata_unlock(pipe);
        return -EDGE_LINUX_EBADF;
    }
    if (reader && pipe->pending_readers) --pipe->pending_readers;
    if (writer && pipe->pending_writers) --pipe->pending_writers;
    kernel_pipe_metadata_unlock(pipe);
    return 0;
}

kernel_pipe_io_decision_t kernel_pipe_read_decide(
    const kernel_pipe_runtime_t *pipe, int nonblocking) {
    uint32_t writers;
    if (!pipe || !pipe->used) return KERNEL_PIPE_IO_INVALID;
    if (pipe->count) return KERNEL_PIPE_IO_READY;
    writers = __atomic_load_n(&pipe->writers, __ATOMIC_ACQUIRE);
    if (!writers) return KERNEL_PIPE_IO_COMPLETE;
    return nonblocking ?
        KERNEL_PIPE_IO_WOULD_BLOCK : KERNEL_PIPE_IO_WAIT;
}

kernel_pipe_io_decision_t kernel_pipe_write_decide(
    const kernel_pipe_runtime_t *pipe, uint64_t remaining,
    int atomic_write, int nonblocking) {
    uint64_t available;
    uint32_t readers;
    if (!pipe || !pipe->used) return KERNEL_PIPE_IO_INVALID;
    if (!remaining) return KERNEL_PIPE_IO_COMPLETE;
    readers = __atomic_load_n(&pipe->readers, __ATOMIC_ACQUIRE);
    if (!readers) return KERNEL_PIPE_IO_BROKEN;
    available = KERNEL_PIPE_RUNTIME_CAPACITY - pipe->count;
    if (available && (!atomic_write || available >= remaining))
        return KERNEL_PIPE_IO_READY;
    return nonblocking ?
        KERNEL_PIPE_IO_WOULD_BLOCK : KERNEL_PIPE_IO_WAIT;
}

uint32_t kernel_pipe_poll_events(
    const kernel_pipe_runtime_t *read_pipe,
    const kernel_pipe_runtime_t *write_pipe,
    int readable_endpoint, int writable_endpoint) {
    uint32_t events = 0;
    if (readable_endpoint) {
        if (!read_pipe || !read_pipe->used) {
            events |= KERNEL_PIPE_POLL_NVAL;
        } else {
            if (read_pipe->count) events |= KERNEL_PIPE_POLL_IN;
            if (!__atomic_load_n(
                    &read_pipe->writers, __ATOMIC_ACQUIRE))
                events |= KERNEL_PIPE_POLL_HUP;
        }
    }
    if (writable_endpoint) {
        if (!write_pipe || !write_pipe->used) {
            events |= KERNEL_PIPE_POLL_NVAL;
        } else if (!__atomic_load_n(
                       &write_pipe->readers, __ATOMIC_ACQUIRE)) {
            events |= KERNEL_PIPE_POLL_ERR;
        } else if (write_pipe->count < KERNEL_PIPE_RUNTIME_CAPACITY) {
            events |= KERNEL_PIPE_POLL_OUT;
        }
    }
    return events;
}

uint32_t kernel_pipe_readable_bytes(const kernel_pipe_runtime_t *pipe) {
    if (!pipe || !pipe->used) return 0;
    return __atomic_load_n(&pipe->count, __ATOMIC_ACQUIRE);
}

int kernel_pipe_read_wake_ready(const kernel_pipe_runtime_t *pipe,
                                int fifo_open_wait) {
    if (!pipe || !pipe->used) return 1;
    return pipe->count ||
        !__atomic_load_n(&pipe->writers, __ATOMIC_ACQUIRE) ||
        (fifo_open_wait && __atomic_load_n(
            &pipe->pending_writers, __ATOMIC_ACQUIRE));
}

int kernel_pipe_write_wake_ready(const kernel_pipe_runtime_t *pipe) {
    if (!pipe || !pipe->used) return 1;
    return pipe->count < KERNEL_PIPE_RUNTIME_CAPACITY ||
        !__atomic_load_n(&pipe->readers, __ATOMIC_ACQUIRE);
}

int64_t kernel_pipe_read_user(kernel_pipe_runtime_t *pipe,
                              uint64_t destination, uint64_t length,
                              kernel_pipe_copy_to_user_fn copy_to_user,
                              void *copy_context) {
    uint64_t done = 0;
    if (!pipe || !pipe->used) return -EDGE_LINUX_EBADF;
    if (!copy_to_user) return -EDGE_LINUX_EINVAL;
    if (!destination && length) return -EDGE_LINUX_EFAULT;

    while (done < length && pipe->count) {
        uint64_t count = length - done;
        uint64_t contiguous =
            KERNEL_PIPE_RUNTIME_CAPACITY - pipe->read_position;
        if (count > pipe->count) count = pipe->count;
        if (count > contiguous) count = contiguous;
        if (copy_to_user(copy_context, destination + done,
                         pipe->data + pipe->read_position, count) < 0) {
            if (done) kernel_pipe_sequence_advance(
                &pipe->write_ready_sequence);
            return done ? (int64_t)done : -EDGE_LINUX_EFAULT;
        }
        pipe->read_position =
            (pipe->read_position + (uint32_t)count) %
                KERNEL_PIPE_RUNTIME_CAPACITY;
        pipe->count -= (uint32_t)count;
        done += count;
    }
    if (done) kernel_pipe_sequence_advance(&pipe->write_ready_sequence);
    return (int64_t)done;
}

int64_t kernel_pipe_write_user(kernel_pipe_runtime_t *pipe,
                               uint64_t source, uint64_t length,
                               kernel_pipe_copy_from_user_fn copy_from_user,
                               void *copy_context) {
    uint64_t done = 0;
    if (!pipe || !pipe->used) return -EDGE_LINUX_EBADF;
    if (!copy_from_user) return -EDGE_LINUX_EINVAL;
    if (!source && length) return -EDGE_LINUX_EFAULT;

    while (done < length &&
           pipe->count < KERNEL_PIPE_RUNTIME_CAPACITY) {
        uint64_t count = length - done;
        uint64_t available =
            KERNEL_PIPE_RUNTIME_CAPACITY - pipe->count;
        uint64_t contiguous =
            KERNEL_PIPE_RUNTIME_CAPACITY - pipe->write_position;
        if (count > available) count = available;
        if (count > contiguous) count = contiguous;
        if (copy_from_user(copy_context,
                           pipe->data + pipe->write_position,
                           source + done, count) < 0) {
            if (done) kernel_pipe_sequence_advance(
                &pipe->read_ready_sequence);
            return done ? (int64_t)done : -EDGE_LINUX_EFAULT;
        }
        pipe->write_position =
            (pipe->write_position + (uint32_t)count) %
                KERNEL_PIPE_RUNTIME_CAPACITY;
        pipe->count += (uint32_t)count;
        done += count;
    }
    if (done) kernel_pipe_sequence_advance(&pipe->read_ready_sequence);
    return (int64_t)done;
}

uint32_t kernel_pipe_peek_kernel(const kernel_pipe_runtime_t *pipe,
                                 void *destination, uint32_t length,
                                 uint32_t skip) {
    uint8_t *output = destination;
    uint32_t position;
    uint32_t available;
    uint32_t done = 0;
    if (!pipe || !pipe->used || !output || skip >= pipe->count) return 0;
    position =
        (pipe->read_position + skip) % KERNEL_PIPE_RUNTIME_CAPACITY;
    available = pipe->count - skip;
    while (done < length && available) {
        uint32_t count = length - done;
        uint32_t contiguous = KERNEL_PIPE_RUNTIME_CAPACITY - position;
        if (count > available) count = available;
        if (count > contiguous) count = contiguous;
        pipe_bytes_copy(output + done, pipe->data + position, count);
        position = (position + count) % KERNEL_PIPE_RUNTIME_CAPACITY;
        available -= count;
        done += count;
    }
    return done;
}

uint32_t kernel_pipe_read_kernel(kernel_pipe_runtime_t *pipe,
                                 void *destination, uint32_t length) {
    uint32_t done = kernel_pipe_peek_kernel(pipe, destination, length, 0);
    if (!pipe || !done) return done;
    pipe->read_position =
        (pipe->read_position + done) % KERNEL_PIPE_RUNTIME_CAPACITY;
    pipe->count -= done;
    kernel_pipe_sequence_advance(&pipe->write_ready_sequence);
    return done;
}

uint32_t kernel_pipe_write_kernel(kernel_pipe_runtime_t *pipe,
                                  const void *source, uint32_t length) {
    const uint8_t *input = source;
    uint32_t done = 0;
    if (!pipe || !pipe->used || (!input && length)) return 0;
    while (done < length &&
           pipe->count < KERNEL_PIPE_RUNTIME_CAPACITY) {
        uint32_t count = length - done;
        uint32_t available =
            KERNEL_PIPE_RUNTIME_CAPACITY - pipe->count;
        uint32_t contiguous =
            KERNEL_PIPE_RUNTIME_CAPACITY - pipe->write_position;
        if (count > available) count = available;
        if (count > contiguous) count = contiguous;
        pipe_bytes_copy(pipe->data + pipe->write_position,
                        input + done, count);
        pipe->write_position =
            (pipe->write_position + count) %
                KERNEL_PIPE_RUNTIME_CAPACITY;
        pipe->count += count;
        done += count;
    }
    if (done) kernel_pipe_sequence_advance(&pipe->read_ready_sequence);
    return done;
}
