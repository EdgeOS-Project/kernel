/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Architecture-neutral Linux pipe object and ring-buffer semantics.
 *
 * Descriptor tables, task wait queues, and user-copy mechanisms remain owned
 * by the architecture runtime.  Endpoint lifetime and byte-stream state are
 * shared so both architectures observe identical EOF, EPIPE, copy-fault, and
 * wraparound behavior.
 */
#ifndef EDGEOS_KERNEL_PIPE_RUNTIME_H
#define EDGEOS_KERNEL_PIPE_RUNTIME_H

#include <stdint.h>

#define KERNEL_PIPE_RUNTIME_CAPACITY (64u * 1024u)
#define KERNEL_PIPE_RUNTIME_BUF 4096u
#define KERNEL_PIPE_RUNTIME_PACKET_SLOTS 512u
#define KERNEL_PIPE_WATCH_FILTER_MAX 16u
#define KERNEL_PIPE_WATCH_TYPE_COUNT 2u

typedef struct kernel_pipe_watch_filter {
    uint32_t type;
    uint32_t info_filter;
    uint32_t info_mask;
    uint32_t subtype_filter[8];
} kernel_pipe_watch_filter_t;

typedef struct kernel_pipe_runtime {
    uint8_t used;
    uint8_t reserved[3];
    volatile uint32_t metadata_lock;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint16_t mode;
    uint16_t metadata_reserved;
    uint32_t readers;
    uint32_t writers;
    uint32_t pending_readers;
    uint32_t pending_writers;

    /*
     * ARM64 currently links sleeping tasks directly through the pipe object.
     * These queue anchors are mechanism state, but keeping them in the common
     * object lets the shared lifetime rule prove that no waiter survives object
     * reuse.  x86_64 uses its global waiter table and leaves them zero.
     */
    uint16_t read_wait_head_plus_one;
    uint16_t read_wait_tail_plus_one;
    uint16_t write_wait_head_plus_one;
    uint16_t write_wait_tail_plus_one;

    uint32_t read_position;
    uint32_t write_position;
    uint32_t count;
    uint16_t packet_lengths[KERNEL_PIPE_RUNTIME_PACKET_SLOTS];
    uint8_t packet_loss[KERNEL_PIPE_RUNTIME_PACKET_SLOTS];
    uint16_t packet_head;
    uint16_t packet_count;
    uint8_t packet_mode;
    uint8_t notification_mode;
    uint8_t watch_loss_pending;
    uint8_t watch_filter_count;
    uint8_t watch_size_set;
    uint8_t watch_reserved;
    uint32_t watch_note_capacity;
    uint64_t generation;
    kernel_pipe_watch_filter_t
        watch_filters[KERNEL_PIPE_WATCH_FILTER_MAX];
    /*
     * Zero is reserved for callers that cannot provide transition tracking.
     * Live shared pipe objects always keep both sequences nonzero.
     */
    uint64_t read_ready_sequence;
    uint64_t write_ready_sequence;
    uint8_t data[KERNEL_PIPE_RUNTIME_CAPACITY];
} kernel_pipe_runtime_t;

typedef struct kernel_pipe_metadata {
    uint32_t uid;
    uint32_t gid;
    uint16_t mode;
} kernel_pipe_metadata_t;

typedef int (*kernel_pipe_copy_to_user_fn)(
    void *context, uint64_t destination, const void *source, uint64_t size);
typedef int (*kernel_pipe_copy_from_user_fn)(
    void *context, void *destination, uint64_t source, uint64_t size);
typedef void (*kernel_pipe_wake_fn)(void *context, uint32_t pipe_index);

typedef enum kernel_pipe_io_decision {
    KERNEL_PIPE_IO_INVALID = -3,
    KERNEL_PIPE_IO_BROKEN = -2,
    KERNEL_PIPE_IO_WOULD_BLOCK = -1,
    KERNEL_PIPE_IO_READY = 0,
    KERNEL_PIPE_IO_COMPLETE = 1,
    KERNEL_PIPE_IO_WAIT = 2,
} kernel_pipe_io_decision_t;

enum {
    KERNEL_PIPE_POLL_IN = 0x0001u,
    KERNEL_PIPE_POLL_OUT = 0x0004u,
    KERNEL_PIPE_POLL_ERR = 0x0008u,
    KERNEL_PIPE_POLL_HUP = 0x0010u,
    KERNEL_PIPE_POLL_NVAL = 0x0020u,
};

int kernel_pipe_object_allocate(kernel_pipe_runtime_t *objects,
                                uint32_t object_count);
void kernel_pipe_object_initialize(kernel_pipe_runtime_t *pipe);
int kernel_pipe_object_release_if_unused(kernel_pipe_runtime_t *pipe);
void kernel_pipe_metadata_initialize(kernel_pipe_runtime_t *pipe,
                                     uint32_t uid, uint32_t gid,
                                     uint16_t mode);
int kernel_pipe_metadata_snapshot(kernel_pipe_runtime_t *pipe,
                                  kernel_pipe_metadata_t *metadata);
int kernel_pipe_metadata_chown(kernel_pipe_runtime_t *pipe,
                               uint32_t uid, uint32_t gid);
int kernel_pipe_packet_mode_set(kernel_pipe_runtime_t *pipe, int enabled);
int kernel_pipe_notification_mode_set(kernel_pipe_runtime_t *pipe,
                                      int enabled);
int kernel_pipe_notification_mode(const kernel_pipe_runtime_t *pipe);
uint64_t kernel_pipe_generation(const kernel_pipe_runtime_t *pipe);
int kernel_pipe_watch_size_set(kernel_pipe_runtime_t *pipe,
                               uint32_t note_count);
int kernel_pipe_watch_filter_set(
    kernel_pipe_runtime_t *pipe,
    const kernel_pipe_watch_filter_t *filters, uint32_t count);
int kernel_pipe_watch_notification_post(
    kernel_pipe_runtime_t *pipe, uint64_t generation,
    void *notification, uint32_t length);

int kernel_pipe_endpoint_retain(kernel_pipe_runtime_t *pipe,
                                int reader, int writer);
int kernel_pipe_endpoint_drop(kernel_pipe_runtime_t *pipe,
                              int reader, int writer,
                              kernel_pipe_wake_fn wake,
                              void *wake_context, uint32_t pipe_index);
int kernel_pipe_pending_retain(kernel_pipe_runtime_t *pipe,
                               int reader, int writer);
int kernel_pipe_pending_drop(kernel_pipe_runtime_t *pipe,
                             int reader, int writer);

kernel_pipe_io_decision_t kernel_pipe_read_decide(
    const kernel_pipe_runtime_t *pipe, int nonblocking);
kernel_pipe_io_decision_t kernel_pipe_write_decide(
    const kernel_pipe_runtime_t *pipe, uint64_t remaining,
    int atomic_write, int nonblocking);
uint32_t kernel_pipe_poll_events(
    const kernel_pipe_runtime_t *read_pipe,
    const kernel_pipe_runtime_t *write_pipe,
    int readable_endpoint, int writable_endpoint);
uint32_t kernel_pipe_readable_bytes(const kernel_pipe_runtime_t *pipe);
int kernel_pipe_read_wake_ready(const kernel_pipe_runtime_t *pipe,
                                int fifo_open_wait);
int kernel_pipe_write_wake_ready(const kernel_pipe_runtime_t *pipe);

int64_t kernel_pipe_read_user(kernel_pipe_runtime_t *pipe,
                              uint64_t destination, uint64_t length,
                              kernel_pipe_copy_to_user_fn copy_to_user,
                              void *copy_context);
int64_t kernel_pipe_write_user(kernel_pipe_runtime_t *pipe,
                               uint64_t source, uint64_t length,
                               kernel_pipe_copy_from_user_fn copy_from_user,
                               void *copy_context);
uint32_t kernel_pipe_peek_kernel(const kernel_pipe_runtime_t *pipe,
                                 void *destination, uint32_t length,
                                 uint32_t skip);
uint32_t kernel_pipe_read_kernel(kernel_pipe_runtime_t *pipe,
                                 void *destination, uint32_t length);
uint32_t kernel_pipe_write_kernel(kernel_pipe_runtime_t *pipe,
                                  const void *source, uint32_t length);

#endif
