/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#ifndef EDGEOS_KERNEL_FILE_DESCRIPTION_RUNTIME_H
#define EDGEOS_KERNEL_FILE_DESCRIPTION_RUNTIME_H

#include <stdint.h>

/*
 * The production pool matches the larger existing architecture limit. Unit
 * tests may override both constants before including the implementation.
 */
#ifndef KERNEL_FILE_DESCRIPTION_CAPACITY
#define KERNEL_FILE_DESCRIPTION_CAPACITY 32768u
#endif

#ifndef KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS
#define KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS 15u
#endif

#define KERNEL_FILE_DESCRIPTION_INVALID_ID 0u
#define KERNEL_FILE_DESCRIPTION_TOMBSTONE_ID UINT64_MAX
#define KERNEL_FILE_DESCRIPTION_NO_MOUNT_NAMESPACE UINT32_MAX

typedef enum kernel_file_description_locator_kind {
    KERNEL_FILE_DESCRIPTION_BY_HANDLE = 1,
    KERNEL_FILE_DESCRIPTION_BY_IDENTITY = 2,
} kernel_file_description_locator_kind_t;

typedef struct kernel_file_description_locator {
    uint64_t value;
    uint32_t kind;
} kernel_file_description_locator_t;

typedef struct kernel_file_description_ops {
    void (*detach_description)(void *context, uint64_t identity);
    void (*release_payload)(void *context, void *payload);
    void *context;
} kernel_file_description_ops_t;

typedef struct kernel_file_description_release {
    uint64_t identity;
    uint32_t handle;
    uint32_t remaining_references;
    uint8_t last_reference;
    uint8_t active;
    uint8_t reserved[2];
} kernel_file_description_release_t;

typedef struct kernel_file_description_position {
    uint64_t identity;
    uint64_t owner;
    uint64_t offset;
    struct kernel_file_description_position *next;
    uint32_t handle;
    uint8_t active;
    uint8_t acquired;
    uint8_t reserved[2];
} kernel_file_description_position_t;

typedef struct kernel_file_description_snapshot {
    uint64_t identity;
    uint64_t offset;
    uint64_t input_cursor;
    uint32_t handle;
    uint32_t references;
    uint32_t epoll_pins;
    uint32_t mount_namespace;
    uint32_t mount_generation;
    uint32_t status_flags;
    int32_t input_clock;
    int32_t async_owner;
    int32_t async_signal;
    uint8_t mount_monitor_configured;
    uint8_t position_busy;
    uint8_t input_revoked;
    uint8_t reserved;
} kernel_file_description_snapshot_t;

static inline kernel_file_description_locator_t
kernel_file_description_handle_locator(uint32_t handle) {
    kernel_file_description_locator_t locator;
    locator.value = handle;
    locator.kind = KERNEL_FILE_DESCRIPTION_BY_HANDLE;
    return locator;
}

static inline kernel_file_description_locator_t
kernel_file_description_identity_locator(uint64_t identity) {
    kernel_file_description_locator_t locator;
    locator.value = identity;
    locator.kind = KERNEL_FILE_DESCRIPTION_BY_IDENTITY;
    return locator;
}

/*
 * Initialization is a boot-time operation and must complete before concurrent
 * callers use the runtime. Detach and payload callbacks always run outside the
 * runtime lock.
 */
int kernel_file_description_runtime_initialize(
    const kernel_file_description_ops_t *ops);

/*
 * A successful create transfers owned_payload to the runtime. On failure the
 * caller retains ownership. Handles are positive generation-checked internal
 * references; identities are stable keys for epoll, file locks, and kcmp.
 */
int kernel_file_description_create(
    uint64_t initial_offset,
    uint32_t initial_status_flags,
    void *owned_payload,
    uint32_t *handle,
    uint64_t *identity);

int kernel_file_description_retain(
    kernel_file_description_locator_t locator);

/*
 * Exactly one release observes the final descriptor reference. That caller
 * must finish the returned active token after its last-close notifications
 * and backing-object teardown. A non-final release returns an inactive token.
 */
int kernel_file_description_release_begin(
    kernel_file_description_locator_t locator,
    kernel_file_description_release_t *release);
int kernel_file_description_release_finish(
    kernel_file_description_release_t *release);

/*
 * epoll_ctl uses transient identity pins. Pins prevent reclamation but do not
 * postpone last-close semantics or permit a closing description to be revived.
 */
int kernel_file_description_pin_identity(uint64_t identity);
int kernel_file_description_unpin_identity(uint64_t identity);

int kernel_file_description_snapshot(
    kernel_file_description_locator_t locator,
    kernel_file_description_snapshot_t *snapshot);
int kernel_file_description_identity(
    kernel_file_description_locator_t locator,
    uint64_t *identity);

int kernel_file_description_offset_load(
    kernel_file_description_locator_t locator,
    uint64_t *offset);
int kernel_file_description_offset_store(
    kernel_file_description_locator_t locator,
    uint64_t offset);

/*
 * Compare-exchange returns one on replacement, zero on mismatch, or a negative
 * Linux errno. On mismatch expected is replaced with the current offset.
 */
int kernel_file_description_offset_compare_exchange(
    kernel_file_description_locator_t locator,
    uint64_t *expected,
    uint64_t desired);
int kernel_file_description_offset_add(
    kernel_file_description_locator_t locator,
    uint64_t amount,
    uint64_t *new_offset);

/*
 * Sequential operations on a shared file position must hold one position
 * transaction across backend I/O and the final user-copy result. Reserve
 * returns one when ownership is immediate, zero when the token is queued, or
 * a negative Linux errno. A queued caller may yield or block and poll until
 * ownership is granted. Abort removes a queued token or releases an acquired
 * token without changing the offset. Tokens are address-stable while active
 * and must not be copied or allowed to leave scope before commit or abort.
 * Explicit-offset operations such as pread and pwrite do not use this
 * transaction.
 *
 * A position token protects the common description entry from reclamation,
 * but callers must independently retain their architecture backing object
 * until commit or abort.
 */
int kernel_file_description_position_reserve(
    kernel_file_description_locator_t locator,
    kernel_file_description_position_t *position);
int kernel_file_description_position_poll(
    kernel_file_description_position_t *position);

/*
 * Non-queuing convenience operation. It returns -EAGAIN without leaving an
 * active token if the position is already owned.
 */
int kernel_file_description_position_try_begin(
    kernel_file_description_locator_t locator,
    kernel_file_description_position_t *position);
int kernel_file_description_position_commit(
    kernel_file_description_position_t *position,
    uint64_t new_offset);
int kernel_file_description_position_abort(
    kernel_file_description_position_t *position);

int kernel_file_description_input_state_load(
    kernel_file_description_locator_t locator,
    uint64_t *cursor,
    int32_t *clock_id);
int kernel_file_description_input_cursor_store(
    kernel_file_description_locator_t locator,
    uint64_t cursor);
int kernel_file_description_input_cursor_compare_exchange(
    kernel_file_description_locator_t locator,
    uint64_t *expected,
    uint64_t desired);
int kernel_file_description_input_clock_store(
    kernel_file_description_locator_t locator,
    int32_t clock_id);
int kernel_file_description_input_revoked(
    kernel_file_description_locator_t locator);
int kernel_file_description_input_revoke(
    kernel_file_description_locator_t locator);

int kernel_file_description_mount_bind(
    kernel_file_description_locator_t locator,
    uint32_t namespace_id,
    uint32_t observed_generation);
int kernel_file_description_mount_snapshot(
    kernel_file_description_locator_t locator,
    uint32_t *namespace_id,
    uint32_t *observed_generation);
int kernel_file_description_mount_acknowledge(
    kernel_file_description_locator_t locator,
    uint32_t expected_namespace,
    uint32_t new_generation);

int kernel_file_description_status_load(
    kernel_file_description_locator_t locator,
    uint32_t *status_flags);
int kernel_file_description_status_update(
    kernel_file_description_locator_t locator,
    uint32_t mask,
    uint32_t value);

int kernel_file_description_async_state_load(
    kernel_file_description_locator_t locator,
    int32_t *owner,
    int32_t *signal);
int kernel_file_description_async_owner_store(
    kernel_file_description_locator_t locator,
    int32_t owner);
int kernel_file_description_async_signal_store(
    kernel_file_description_locator_t locator,
    int32_t signal);

#endif
