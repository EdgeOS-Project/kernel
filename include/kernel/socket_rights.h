/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral SCM_RIGHTS storage.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SOCKET_RIGHTS_H
#define EDGEOS_KERNEL_SOCKET_RIGHTS_H

#include <stdint.h>

#include "kernel/fd_runtime.h"
#include "kernel/linux_abi.h"
#include "sys/spinlock.h"

#define KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS 253u
#define KERNEL_SOCKET_RIGHTS_DEFAULT_TOKEN_CAPACITY 8192u
#define KERNEL_SOCKET_RIGHTS_DEFAULT_RECORD_CAPACITY 8192u
#define KERNEL_SOCKET_RIGHTS_DEFAULT_QUEUE_LIMIT 128u
#define KERNEL_SOCKET_RIGHTS_DEFAULT_ARENA_BYTES (5u * 1024u * 1024u)

typedef uint64_t kernel_socket_rights_record_handle_t;
typedef uint64_t kernel_socket_rights_token_handle_t;

typedef enum kernel_socket_rights_record_state {
    KERNEL_SOCKET_RIGHTS_RECORD_FREE = 0,
    KERNEL_SOCKET_RIGHTS_RECORD_BUILDING,
    KERNEL_SOCKET_RIGHTS_RECORD_DETACHED,
    KERNEL_SOCKET_RIGHTS_RECORD_QUEUED,
} kernel_socket_rights_record_state_t;

typedef enum kernel_socket_rights_association_kind {
    KERNEL_SOCKET_RIGHTS_ASSOCIATION_NONE = 0,
    KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE,
    KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
} kernel_socket_rights_association_kind_t;

/*
 * The pool owns caller-provided, fixed-address storage.  Operation leases
 * remain at one address from acquisition through final release, as required
 * by fd_runtime.  Callers must zero-initialize the pool before initialization
 * and must keep the arena mapped for the complete pool lifetime.
 */
typedef struct kernel_socket_rights_pool {
    spinlock_t lock;
    void *token_storage;
    void *record_storage;
    uint64_t arena_bytes;
    uint32_t token_capacity;
    uint32_t record_capacity;
    uint32_t free_token_head;
    uint32_t free_record_head;
    uint32_t free_token_count;
    uint32_t free_record_count;
    uint32_t magic;
    uint32_t reserved;
} kernel_socket_rights_pool_t;

/*
 * A socket embeds only this queue metadata.  Record and descriptor ownership
 * remains in the shared pool, so increasing the socket-table limit does not
 * multiply SCM_RIGHTS snapshot storage.
 */
typedef struct kernel_socket_rights_queue {
    kernel_socket_rights_record_handle_t head;
    kernel_socket_rights_record_handle_t tail;
    uint32_t count;
    uint32_t limit;
} kernel_socket_rights_queue_t;

typedef struct kernel_socket_rights_record_info {
    kernel_socket_rights_record_handle_t handle;
    uint64_t association_sequence;
    uint32_t descriptor_count;
    uint8_t state;
    uint8_t association_kind;
    uint8_t reserved[2];
} kernel_socket_rights_record_info_t;

typedef struct kernel_socket_rights_pool_statistics {
    uint32_t token_capacity;
    uint32_t record_capacity;
    uint32_t free_tokens;
    uint32_t free_records;
} kernel_socket_rights_pool_statistics_t;

/*
 * Iteration exposes only fd_runtime's opaque operation lease, never an
 * architecture descriptor snapshot.  The record owner must serialize cursor
 * use against record_drop(), queue_take(), queue_drop(), and queue_clear().
 * A returned lease pointer remains valid until the next record mutation.
 */
typedef struct kernel_socket_rights_token_cursor {
    kernel_socket_rights_record_handle_t record;
    kernel_socket_rights_token_handle_t next_token;
    uint32_t next_index;
    uint32_t descriptor_count;
} kernel_socket_rights_token_cursor_t;

/*
 * Returns the worst-case arena size, including initial alignment padding.
 * Zero means that the requested capacities are invalid.
 */
uint64_t kernel_socket_rights_pool_required_bytes(
    uint32_t token_capacity, uint32_t record_capacity);

int kernel_socket_rights_pool_initialize(
    kernel_socket_rights_pool_t *pool, void *arena, uint64_t arena_bytes,
    uint32_t token_capacity, uint32_t record_capacity);

/*
 * Both architecture runtimes use this single shared pool configuration.
 * Initialization is idempotent after success; a concurrent initializer gets
 * EBUSY and may retry.  The accessor returns null until initialization has
 * completed.
 */
int kernel_socket_rights_default_pool_initialize(void);
kernel_socket_rights_pool_t *kernel_socket_rights_default_pool(void);

int kernel_socket_rights_pool_statistics(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_pool_statistics_t *statistics);

/*
 * Imports every SCM_RIGHTS cmsghdr into one record from fd_owner's files
 * table. A null owner retains the normal current-owner acquisition path.
 * Linux permits at most 253 descriptors cumulatively across all headers.
 * A control buffer with no transferable descriptor, including an explicit
 * zero-descriptor SCM_RIGHTS header, returns success with a zero handle.
 */
int kernel_socket_rights_record_import(
    kernel_socket_rights_pool_t *pool,
    const void *fd_owner, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_control, uint64_t control_length,
    kernel_socket_rights_record_handle_t *record);

/* Creates an explicit zero-token DETACHED record for queue state machinery. */
int kernel_socket_rights_record_create_empty(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_record_handle_t *record);

/*
 * Drops one caller-owned DETACHED record.  The handle is consumed even when
 * a backend release callback reports an error; all remaining leases are still
 * released exactly once.
 */
int kernel_socket_rights_record_drop(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_record_handle_t *record);

int kernel_socket_rights_record_info(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_record_handle_t record,
    kernel_socket_rights_record_info_t *information);

int kernel_socket_rights_token_cursor_initialize(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_record_handle_t record,
    kernel_socket_rights_token_cursor_t *cursor);

/* Returns one for a lease, zero at end, or a negative Linux errno. */
int kernel_socket_rights_token_cursor_next(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_token_cursor_t *cursor,
    uint32_t *source_index,
    const kernel_fd_operation_lease_t **lease);

void kernel_socket_rights_queue_initialize(
    kernel_socket_rights_queue_t *queue, uint32_t limit);

uint32_t kernel_socket_rights_queue_count(
    const kernel_socket_rights_queue_t *queue);

/*
 * Enqueue consumes the detached record handle only on success.  Association
 * sequences are absolute receive-stream byte positions or absolute packet
 * sequence numbers; equal packet positions support zero-byte datagrams.
 */
int kernel_socket_rights_queue_enqueue(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_queue_t *queue,
    kernel_socket_rights_record_handle_t *record,
    kernel_socket_rights_association_kind_t association_kind,
    uint64_t association_sequence);

int kernel_socket_rights_queue_peek(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_queue_t *queue,
    kernel_socket_rights_record_info_t *information);

/*
 * Observes a queued record by zero-based position without consuming it.
 * Receivers use ordinal one to stop a stream read before the next ancillary
 * association while ordinal zero remains the normal queue-front operation.
 */
int kernel_socket_rights_queue_peek_at(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_queue_t *queue,
    uint32_t ordinal,
    kernel_socket_rights_record_info_t *information);

int kernel_socket_rights_queue_take(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_queue_t *queue,
    kernel_socket_rights_record_handle_t *record);

/*
 * Detaches one exact queued record without changing the caller's handle.
 * This supports send rollback after a record was published at a stream byte
 * position but no payload byte became visible. The caller owns the detached
 * handle again on success and must either re-enqueue or drop it.
 */
int kernel_socket_rights_queue_remove(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_queue_t *queue,
    kernel_socket_rights_record_handle_t record);

int kernel_socket_rights_queue_drop(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_queue_t *queue);

int kernel_socket_rights_queue_clear(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_queue_t *queue);

#endif
