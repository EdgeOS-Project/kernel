/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS descriptor-table runtime interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_FD_RUNTIME_H
#define EDGEOS_KERNEL_FD_RUNTIME_H

#include <stdint.h>

#define KERNEL_FD_CLOEXEC 0x0001u
#define KERNEL_FD_SETPIPE_SZ 1031u
#define KERNEL_FD_GETPIPE_SZ 1032u

typedef struct kernel_fd_proc_snapshot {
    uint64_t offset;
    uint64_t inode;
    uint32_t flags;
    int32_t pidfd_target;
    uint8_t is_pidfd;
} kernel_fd_proc_snapshot_t;

typedef int (*kernel_fd_publication_publish_fn)(
    void *context, const int32_t *descriptors, uint32_t count);
typedef void (*kernel_fd_publication_abort_fn)(
    void *context, const int32_t *descriptors, uint32_t count);
typedef int (*kernel_fd_publication_acquire_fn)(
    void *context, int32_t descriptor, void *storage);

/*
 * Descriptor-producing syscalls may need to copy descriptor numbers or an
 * accepted peer address to userspace before the descriptors become visible.
 * Architecture backends reserve and fully construct the entries, then return
 * one address-stable publication token. The shared syscall path commits only
 * after every required userspace copy succeeds; every other path aborts the
 * token exactly once.
 *
 * The publish callback must be atomic and all-or-nothing across the complete
 * descriptor array. If it reports an error, every entry must still be in its
 * reserved constructed state so the abort callback can release it.
 *
 * The token must be zero-initialized before its first initialization. The
 * descriptor array and callback context remain owned by the caller and must
 * stay alive until commit or abort returns.
 *
 * A producer may also attach an acquire callback after initialization. It
 * creates a retained operation lease from a fully constructed RESERVED entry
 * without publishing the numeric descriptor. This is used by consumers such
 * as io_uring direct descriptors that take ownership before abort removes the
 * temporary table entries.
 */
struct kernel_fd_publication {
    const int32_t *descriptors;
    void *context;
    kernel_fd_publication_publish_fn publish;
    kernel_fd_publication_abort_fn abort;
    kernel_fd_publication_acquire_fn acquire;
    uint32_t count;
    uint8_t active;
    uint8_t reserved[3];
};

#ifndef EDGEOS_KERNEL_FD_PUBLICATION_TYPEDEF
#define EDGEOS_KERNEL_FD_PUBLICATION_TYPEDEF
typedef struct kernel_fd_publication kernel_fd_publication_t;
#endif

int kernel_fd_publication_initialize(
    kernel_fd_publication_t *publication,
    const int32_t *descriptors, uint32_t count,
    void *context,
    kernel_fd_publication_publish_fn publish,
    kernel_fd_publication_abort_fn abort);
int kernel_fd_publication_commit(
    kernel_fd_publication_t *publication);
int kernel_fd_publication_abort(
    kernel_fd_publication_t *publication);
int kernel_fd_publication_set_acquire(
    kernel_fd_publication_t *publication,
    kernel_fd_publication_acquire_fn acquire);

#define KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE 512u
#define KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT 16u
#define KERNEL_FD_OPERATION_LEASE_SIZE \
    (KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE + 64u)

typedef int (*kernel_fd_operation_acquire_fn)(
    void *context, int32_t descriptor, void *storage);
typedef int (*kernel_fd_operation_acquire_for_owner_fn)(
    void *context, const void *owner,
    int32_t descriptor, void *storage);
typedef int (*kernel_fd_operation_acquire_for_pid_fn)(
    void *context, int32_t pid,
    int32_t descriptor, void *storage);
typedef int (*kernel_fd_operation_release_fn)(
    void *context, void *storage);
typedef int (*kernel_fd_operation_transfer_fn)(
    void *context, void *destination_storage, void *source_storage);
typedef int (*kernel_fd_operation_clone_fn)(
    void *context, void *destination_storage, const void *source_storage);
typedef int (*kernel_fd_operation_description_id_fn)(
    void *context, const void *storage, uint64_t *description_id);
struct kernel_io_vector_request;
typedef int64_t (*kernel_fd_operation_vector_io_fn)(
    void *context, void *storage,
    const struct kernel_io_vector_request *request);
struct kernel_io_file_range_request;
typedef int64_t (*kernel_fd_operation_file_range_fn)(
    void *context, void *storage,
    const struct kernel_io_file_range_request *request);
struct kernel_socket_operation_request;
struct kernel_socket_operation_result;
typedef int64_t (*kernel_fd_operation_socket_fn)(
    void *context, void *storage,
    const struct kernel_socket_operation_request *request,
    struct kernel_socket_operation_result *result);

/*
 * An operation lease is a temporary reference to the open file description
 * and its architecture backing object. It preserves Linux close-versus-I/O
 * behavior when another CLONE_FILES task closes and reuses the descriptor
 * number while an operation is still in flight.
 *
 * The token must be zero-initialized before first use and remain at one stable
 * address until release returns. Callers must not inspect, copy, or modify its
 * internal fields while active. Architecture backends place one retained,
 * typed descriptor snapshot in the token's private backend storage and release
 * that snapshot without looking up the original descriptor number.
 */
typedef union kernel_fd_operation_lease_storage {
    uint8_t bytes[KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE];
    uint64_t align_u64;
    void *align_pointer;
} __attribute__((aligned(KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT)))
kernel_fd_operation_lease_storage_t;

typedef union kernel_fd_operation_lease {
    uint8_t opaque[KERNEL_FD_OPERATION_LEASE_SIZE];
    uint64_t align_u64;
    void *align_pointer;
} __attribute__((aligned(KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT)))
kernel_fd_operation_lease_t;

int kernel_fd_operation_acquire(
    int32_t descriptor, kernel_fd_operation_lease_t *lease);
/*
 * Owner-aware acquisition is used when deferred syscall completion runs in a
 * different scheduler context. A non-null owner requires backend support and
 * never falls back to the current files table.
 */
int kernel_fd_operation_acquire_for_owner(
    const void *owner, int32_t descriptor,
    kernel_fd_operation_lease_t *lease);
int kernel_fd_operation_acquire_for_pid(
    int32_t pid, int32_t descriptor,
    kernel_fd_operation_lease_t *lease);
int kernel_fd_operation_acquire_from_publication(
    const kernel_fd_publication_t *publication,
    uint32_t index, kernel_fd_operation_lease_t *lease);
/* The returned snapshot view remains valid only until release begins. */
const void *kernel_fd_operation_view(
    const kernel_fd_operation_lease_t *lease);
int kernel_fd_operation_description_id(
    const kernel_fd_operation_lease_t *lease,
    uint64_t *description_id);
int kernel_fd_operation_vector_io_available(void);
int kernel_fd_operation_vector_io_supported(
    const kernel_fd_operation_lease_t *lease);
int64_t kernel_fd_operation_vector_io(
    kernel_fd_operation_lease_t *lease,
    const struct kernel_io_vector_request *request);
int64_t kernel_fd_operation_file_range(
    kernel_fd_operation_lease_t *lease,
    const struct kernel_io_file_range_request *request);
int kernel_fd_operation_socket_available(void);
int kernel_fd_operation_socket_supported(
    const kernel_fd_operation_lease_t *lease);
/*
 * Dispatch against an already-retained description. This function never owns
 * or releases the lease; callers may issue multiple normalized operations
 * under one lease when Linux validation requires a DESCRIBE followed by the
 * actual operation. Result storage is cleared before dispatch and whenever
 * the operation returns an error.
 */
int64_t kernel_fd_operation_socket(
    kernel_fd_operation_lease_t *lease,
    const struct kernel_socket_operation_request *request,
    struct kernel_socket_operation_result *result);
/*
 * A backend whose blocking scheduler invalidates the current syscall stack
 * may transfer its active operation lease into persistent task storage
 * immediately before scheduling. The backend must opt in and move, rather
 * than duplicate, every resource owned by its private snapshot.
 *
 * This helper is valid only from the backend callback that received
 * source_storage. A successful transfer must leave source_storage empty or
 * otherwise inaccessible and make destination the sole owner. A failed
 * transfer must preserve source ownership. The destination must be an
 * inactive, zero-initialized token.
 */
int kernel_fd_operation_transfer_from_backend(
    void *source_storage,
    kernel_fd_operation_lease_t *destination);
int kernel_fd_operation_move(
    kernel_fd_operation_lease_t *destination,
    kernel_fd_operation_lease_t *source);
int kernel_fd_operation_clone(
    kernel_fd_operation_lease_t *destination,
    const kernel_fd_operation_lease_t *source);
int kernel_fd_operation_release(
    kernel_fd_operation_lease_t *lease);
int kernel_fd_operation_materialize(
    const kernel_fd_operation_lease_t *source,
    uint32_t descriptor_flags, int32_t *descriptor);

#define KERNEL_FD_TRANSFER_MAX 253u
#define KERNEL_FD_TRANSFER_TARGET_STORAGE_SIZE 64u
#define KERNEL_FD_TRANSFER_TARGET_STORAGE_ALIGNMENT 16u
#define KERNEL_FD_TRANSFER_TARGET_SIZE 1152u

typedef int (*kernel_fd_transfer_target_capture_fn)(
    void *context, void *target_storage);
typedef int (*kernel_fd_transfer_target_capture_for_owner_fn)(
    void *context, const void *owner, void *target_storage);
typedef int (*kernel_fd_transfer_target_release_fn)(
    void *context, void *target_storage);
typedef int (*kernel_fd_transfer_target_prepare_fn)(
    void *context, void *target_storage,
    const void *source_storage, uint32_t descriptor_flags,
    int32_t *descriptor);
typedef void (*kernel_fd_transfer_target_discard_prepared_fn)(
    void *context, void *target_storage);
typedef int (*kernel_fd_transfer_target_publish_many_fn)(
    void *context, void *target_storage,
    const int32_t *descriptors, uint32_t count);
typedef int (*kernel_fd_transfer_target_abort_many_fn)(
    void *context, void *target_storage,
    const int32_t *descriptors, uint32_t count);

/*
 * An FD transfer target pins the receiving files table independently from the
 * task that happened to be current when it was captured. Each prepare call
 * clones one active source operation lease into a hidden RESERVED descriptor
 * in that table. It never consumes or numerically relooks up the source lease,
 * so MSG_PEEK and repeated transfers retain independent references.
 *
 * Prepared descriptors belong to exactly one target token. publish_many makes
 * the complete requested batch visible atomically under the receiving table
 * lock. A failed publish leaves every descriptor hidden and abortable.
 * abort_many releases the requested hidden clones exactly once. The target
 * cannot be released while any clone remains prepared.
 *
 * Backend callbacks follow transactional ownership rules. A failed capture
 * owns no table reference. A failed prepare owns no reserved slot or cloned
 * reference. A successful prepare must return a nonnegative descriptor that
 * does not alias an earlier successful prepare on the same target. Until the
 * common layer accepts that output, discard_prepared must be able to release
 * the exact clone just created without trusting the returned descriptor;
 * discard_prepared cannot fail. A failed publish leaves the entire batch
 * RESERVED and unchanged. A failed abort leaves the entire batch owned by the
 * target. A failed release preserves the captured table reference so release
 * can be retried.
 *
 * Tokens must be zero-initialized before first capture and remain at one stable
 * address until release returns.
 */
typedef union kernel_fd_transfer_target_storage {
    uint8_t bytes[KERNEL_FD_TRANSFER_TARGET_STORAGE_SIZE];
    uint64_t align_u64;
    void *align_pointer;
} __attribute__((aligned(KERNEL_FD_TRANSFER_TARGET_STORAGE_ALIGNMENT)))
kernel_fd_transfer_target_storage_t;

typedef union kernel_fd_transfer_target {
    uint8_t opaque[KERNEL_FD_TRANSFER_TARGET_SIZE];
    uint64_t align_u64;
    void *align_pointer;
} __attribute__((aligned(KERNEL_FD_TRANSFER_TARGET_STORAGE_ALIGNMENT)))
kernel_fd_transfer_target_t;

int kernel_fd_transfer_target_capture(
    kernel_fd_transfer_target_t *target);
int kernel_fd_transfer_target_capture_for_owner(
    const void *owner, kernel_fd_transfer_target_t *target);
int kernel_fd_transfer_target_prepare(
    kernel_fd_transfer_target_t *target,
    const kernel_fd_operation_lease_t *source,
    uint32_t descriptor_flags,
    int32_t *descriptor);
int kernel_fd_transfer_target_prepared_descriptor_at(
    const kernel_fd_transfer_target_t *target,
    uint32_t index, int32_t *descriptor);
int kernel_fd_transfer_target_publish_many(
    kernel_fd_transfer_target_t *target,
    const int32_t *descriptors, uint32_t count);
int kernel_fd_transfer_target_publish_prefix(
    kernel_fd_transfer_target_t *target, uint32_t count);
int kernel_fd_transfer_target_abort_many(
    kernel_fd_transfer_target_t *target,
    const int32_t *descriptors, uint32_t count);
int kernel_fd_transfer_target_abort_all(
    kernel_fd_transfer_target_t *target);
int kernel_fd_transfer_target_release(
    kernel_fd_transfer_target_t *target);

typedef struct kernel_fd_backend_ops {
    uint32_t (*table_limit)(void *context);
    uint32_t (*allocation_limit)(void *context);
    int (*table_unshare)(void *context);
    int (*is_open)(void *context, int32_t descriptor);
    kernel_fd_operation_acquire_fn operation_acquire;
    kernel_fd_operation_acquire_for_owner_fn
        operation_acquire_for_owner;
    kernel_fd_operation_acquire_for_pid_fn
        operation_acquire_for_pid;
    kernel_fd_operation_release_fn operation_release;
    kernel_fd_operation_transfer_fn operation_transfer;
    kernel_fd_operation_clone_fn operation_clone;
    kernel_fd_operation_description_id_fn
        operation_description_id;
    /*
     * Optional whole-vector operation on the retained descriptor snapshot.
     * Backends that provide it must not look up the numeric descriptor again.
     */
    kernel_fd_operation_vector_io_fn operation_vector_io;
    /*
     * Optional normalized file-range operation on the retained descriptor
     * snapshot. Backends own representation-specific file and cache updates.
     */
    kernel_fd_operation_file_range_fn operation_file_range;
    /*
     * Optional normalized socket operation on the retained descriptor
     * snapshot. Backends must type-check the retained object and must never
     * resolve the original numeric descriptor.
     */
    kernel_fd_operation_socket_fn operation_socket;
    kernel_fd_transfer_target_capture_fn transfer_target_capture;
    kernel_fd_transfer_target_capture_for_owner_fn
        transfer_target_capture_for_owner;
    kernel_fd_transfer_target_release_fn transfer_target_release;
    kernel_fd_transfer_target_prepare_fn transfer_target_prepare;
    kernel_fd_transfer_target_discard_prepared_fn
        transfer_target_discard_prepared;
    kernel_fd_transfer_target_publish_many_fn transfer_target_publish_many;
    kernel_fd_transfer_target_abort_many_fn transfer_target_abort_many;
    int (*close)(void *context, int32_t descriptor);
    int (*duplicate_exact)(void *context, int32_t source,
                           int32_t destination,
                           uint32_t descriptor_flags);
    /*
     * Atomically validates source and publishes a duplicate in the lowest
     * FREE slot in [minimum, exclusive_limit). RESERVED and CLOSING slots are
     * never candidates. On success destination receives that installed
     * descriptor.
     */
    int (*duplicate_minimum)(void *context, int32_t source,
                             int32_t minimum,
                             uint32_t exclusive_limit,
                             uint32_t descriptor_flags,
                             int32_t *destination);
    int (*get_descriptor_flags)(void *context, int32_t descriptor,
                                uint32_t *flags);
    int (*set_descriptor_flags)(void *context, int32_t descriptor,
                                uint32_t flags);
    int (*get_status_flags)(void *context, int32_t descriptor,
                            uint32_t *flags);
    int (*set_status_flags)(void *context, int32_t descriptor,
                            uint32_t flags);
    int (*pipe_capacity)(void *context, int32_t descriptor,
                         uint32_t *capacity);
    int (*pidfd_lookup)(void *context, int32_t pid, int32_t *tgid);
    int (*pidfd_install)(void *context, int32_t pid, uint32_t flags);
    int (*pidfd_target)(void *context, int32_t descriptor,
                        int32_t *pid, uint32_t *flags);
    int64_t (*fcntl_fallback)(void *context, int32_t descriptor,
                              uint32_t command, uint64_t argument);
} kernel_fd_backend_ops_t;

/*
 * The registered operation table is immutable and must outlive every lease
 * and transfer target acquired from it.
 */
int kernel_fd_backend_register(const kernel_fd_backend_ops_t *ops,
                               void *context);
uint32_t kernel_fd_table_limit(void);
uint32_t kernel_fd_allocation_limit(void);
int kernel_fd_table_unshare(void);
int kernel_fd_is_open(int32_t descriptor);
int kernel_fd_close(int32_t descriptor);
int kernel_fd_pipe_prepare(
    uint32_t flags, int32_t descriptors[2],
    kernel_fd_publication_t *publication);
int arch_fd_pipe_prepare(
    uint32_t flags, int32_t descriptors[2],
    kernel_fd_publication_t *publication);
int kernel_fd_duplicate(int32_t source, int32_t target, int exact,
                        uint32_t descriptor_flags, int32_t *result);
int kernel_fd_get_descriptor_flags(int32_t descriptor, uint32_t *flags);
int kernel_fd_set_descriptor_flags(int32_t descriptor, uint32_t flags);
int kernel_fd_get_status_flags(int32_t descriptor, uint32_t *flags);
int kernel_fd_update_status_flags(int32_t descriptor, uint32_t mask,
                                  uint32_t flags);
int64_t kernel_fd_fcntl_fallback(int32_t descriptor, uint32_t command,
                                 uint64_t argument);
int kernel_pidfd_open(int32_t pid, uint32_t flags);
int kernel_pidfd_target(int32_t descriptor, int32_t *pid, uint32_t *flags);
int kernel_pidfd_getfd(int32_t pid, int32_t target_descriptor,
                       int32_t *result);
int kernel_process_fd_description_id(int32_t pid, int32_t descriptor,
                                     uint64_t *description_id);
int arch_proc_fd_snapshot(int32_t pid, int32_t descriptor,
                          kernel_fd_proc_snapshot_t *snapshot);

#endif
