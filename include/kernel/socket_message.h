/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-independent Linux socket message interface.
 * Copyright (c) EdgeOS Contributors.
 */

#ifndef EDGEOS_KERNEL_SOCKET_MESSAGE_H
#define EDGEOS_KERNEL_SOCKET_MESSAGE_H

#include <stdint.h>

#include "kernel/linux_abi.h"
#include "kernel/socket_rights.h"
#include "kernel/socket_runtime.h"

#define KERNEL_SOCKET_IOV_MAX 1024u
#define KERNEL_SOCKET_SCM_RIGHTS 1u
#define KERNEL_SOCKET_SCM_RIGHTS_MAX 253u
#define KERNEL_SOCKET_UDP_PAYLOAD_MAX 65507u

typedef enum kernel_socket_message_abi {
    KERNEL_SOCKET_MESSAGE_ABI_NATIVE = 0,
    KERNEL_SOCKET_MESSAGE_ABI_X32 = 1,
} kernel_socket_message_abi_t;

typedef struct kernel_socket_user_message {
    struct edge_linux_msghdr header;
    uint64_t user_header;
    uint64_t payload_length;
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    kernel_socket_message_abi_t abi;
} kernel_socket_user_message_t;

typedef struct kernel_socket_iovec_source {
    const struct edge_linux_iovec *kernel_iov;
    const kernel_socket_user_message_t *user_message;
    uint32_t count;
    uint64_t total_length;
} kernel_socket_iovec_source_t;

typedef struct kernel_socket_control_cursor {
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    uint64_t user_control;
    uint64_t control_length;
    uint64_t offset;
} kernel_socket_control_cursor_t;

typedef struct kernel_socket_control_item {
    struct edge_linux_cmsghdr header;
    uint64_t user_data;
    uint64_t data_length;
} kernel_socket_control_item_t;

typedef enum kernel_socket_control_receive_result {
    KERNEL_SOCKET_CONTROL_RECEIVE_APPENDED = 0,
    KERNEL_SOCKET_CONTROL_RECEIVE_TRUNCATED,
    KERNEL_SOCKET_CONTROL_RECEIVE_FAULTED,
} kernel_socket_control_receive_result_t;

/*
 * Network adapters snapshot this information while the packet header and
 * ingress interface are still available.  The shared message layer owns the
 * Linux ancillary-data policy and layout for both architectures.
 */
typedef struct kernel_socket_ip_receive_metadata {
    uint8_t family;
    uint8_t hop_limit;
    uint8_t traffic_class;
    uint8_t reserved;
    uint32_t interface_index;
    uint8_t destination_address[16];
    uint8_t local_address[16];
} kernel_socket_ip_receive_metadata_t;

typedef struct kernel_socket_ip_send_metadata {
    uint8_t family;
    uint8_t has_interface;
    uint8_t has_source_address;
    uint8_t has_hop_limit;
    uint8_t has_traffic_class;
    uint8_t reserved[3];
    uint32_t interface_index;
    int32_t hop_limit;
    int32_t traffic_class;
    uint8_t source_address[16];
} kernel_socket_ip_send_metadata_t;

typedef int (*kernel_socket_rights_prepare_fn)(
    void *context, uint32_t source_index, int32_t *descriptor);

typedef int (*kernel_socket_rights_publish_fn)(
    void *context, uint32_t source_index, int32_t descriptor);

typedef void (*kernel_socket_rights_abort_fn)(
    void *context, uint32_t source_index, int32_t descriptor);

typedef void (*kernel_socket_rights_discard_fn)(
    void *context, uint32_t source_index);

typedef struct kernel_socket_rights_receive_operations {
    kernel_socket_rights_prepare_fn prepare;
    kernel_socket_rights_publish_fn publish;
    kernel_socket_rights_abort_fn abort;
    kernel_socket_rights_discard_fn discard;
} kernel_socket_rights_receive_operations_t;

typedef struct kernel_socket_rights_receive_result {
    uint32_t delivered_count;
    int32_t callback_status;
    uint8_t truncated;
    uint8_t control_fault;
    uint8_t reserved[2];
} kernel_socket_rights_receive_result_t;

typedef struct kernel_socket_message_request {
    int32_t descriptor;
    uint32_t flags;
    uint64_t user_header;
    uint8_t receiving;
    uint8_t reserved[7];
    kernel_socket_user_message_t message;
    void *user_registers;
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
} kernel_socket_message_request_t;

typedef struct kernel_socket_mmsg_request {
    int32_t descriptor;
    uint32_t flags;
    uint64_t user_messages;
    uint32_t vector_length;
    uint8_t receiving;
    uint8_t reserved[3];
    uint64_t user_timeout;
    uint64_t timeout_deadline_us;
    void *user_registers;
    void *copy_context;
    edge_linux_copy_from_user_fn copy_from_user;
    edge_linux_copy_to_user_fn copy_to_user;
} kernel_socket_mmsg_request_t;

typedef int64_t (*kernel_socket_message_call_fn)(
    void *context, int32_t descriptor, uint64_t user_message,
    uint32_t flags, void *user_registers);

/*
 * Importing validates Linux's common msghdr and iovec shape without touching
 * any payload bytes.  Payload pointers are intentionally checked only when a
 * transport actually copies data: an empty nonblocking receive returns
 * EAGAIN even when an iovec base is invalid, matching Linux fault ordering.
 */
int kernel_socket_message_import(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_header, kernel_socket_user_message_t *message);
int kernel_socket_message_import_abi(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_header, kernel_socket_message_abi_t abi,
    kernel_socket_user_message_t *message);

/* Import an iovec array as the payload of a headerless send request. */
int kernel_socket_message_import_iovec(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_iovec, uint64_t vector_count,
    kernel_socket_user_message_t *message);

/*
 * Validates a Linux socket descriptor and imports one msghdr before entering
 * transport-specific mechanics.  This preserves Linux's EBADF/ENOTSOCK fault
 * ordering identically on every architecture.
 */
int64_t kernel_socket_message_invoke(
    int32_t descriptor, uint64_t user_header, uint32_t flags, int receiving,
    void *user_registers, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user);
int64_t kernel_socket_message_invoke_abi(
    int32_t descriptor, uint64_t user_header, uint32_t flags, int receiving,
    void *user_registers, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    edge_linux_copy_to_user_fn copy_to_user,
    kernel_socket_message_abi_t abi);

/* Shared entry followed by the native transport and scheduler adapter. */
int64_t kernel_socket_message_execute(
    const kernel_socket_message_request_t *request);
int64_t edge_socket_runtime_message_execute(
    const kernel_socket_message_request_t *request);

int kernel_socket_message_iovec(
    const kernel_socket_user_message_t *message, uint32_t index,
    struct edge_linux_iovec *iov);

int kernel_socket_iovec_source_from_array(
    kernel_socket_iovec_source_t *source,
    const struct edge_linux_iovec *iov, uint32_t count);

void kernel_socket_iovec_source_from_message(
    kernel_socket_iovec_source_t *source,
    const kernel_socket_user_message_t *message);

int kernel_socket_iovec_source_read(
    const kernel_socket_iovec_source_t *source, uint32_t index,
    struct edge_linux_iovec *iov);

int kernel_socket_message_write_output(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    const kernel_socket_user_message_t *message, uint32_t name_length,
    uint64_t control_length, int32_t flags);

int32_t kernel_socket_message_receive_output_flags(uint32_t receive_flags);

void kernel_socket_control_cursor_initialize(
    kernel_socket_control_cursor_t *cursor, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user, uint64_t user_control,
    uint64_t control_length);

/* Returns one for an item, zero at end, or a negative Linux errno. */
int kernel_socket_control_next(kernel_socket_control_cursor_t *cursor,
                               kernel_socket_control_item_t *item);

uint64_t kernel_socket_control_align(uint64_t length);

int kernel_socket_control_append(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length);

/*
 * Compatibility all-or-none receive wrapper for callers that already own a
 * contiguous cmsg payload.  New SCM_RIGHTS and metadata receive paths must use
 * the specialized helpers below because their Linux fault policies differ.
 */
int kernel_socket_control_receive_append(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length,
    kernel_socket_control_receive_result_t *result);

/*
 * Delivers one queued SCM_RIGHTS record with Linux prefix semantics.
 *
 * A successful prepare transfers one source right into an unpublished
 * descriptor.  Exactly one terminal callback then follows for every source:
 * publish on a visible descriptor, abort on a prepared descriptor that cannot
 * be made visible, or discard when the source was never prepared.  prepare
 * must leave ownership unchanged on failure, and publish must leave a failed
 * prepared descriptor abortable.
 *
 * Control-space exhaustion, descriptor-table exhaustion, word copy faults,
 * and publication failures are successful receive-side truncations.  The
 * helper consumes every source right, publishes only the copied prefix, and
 * records the first callback failure in result without returning it as the
 * recvmsg result.  Invalid API arguments and records exceeding Linux's hard
 * SCM_RIGHTS limit are returned as errors without consuming any source right.
 */
int kernel_socket_control_receive_rights(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, uint32_t source_count,
    const kernel_socket_rights_receive_operations_t *operations,
    void *operations_context,
    kernel_socket_rights_receive_result_t *result);

/*
 * Copies one SCM_RIGHTS record into a receive control buffer without consuming
 * or mutating the record.  The caller must serialize the record against pool
 * and queue mutation for the complete call, which permits normal receive and
 * MSG_PEEK to share exactly the same delivery transaction.
 *
 * target_workspace must point to an inactive, zero-initialized transfer
 * target and remain address-stable through the call.  Supplying the workspace
 * keeps the 253-descriptor transaction out of the syscall stack.  The helper
 * captures fd_owner's receiving files table (or the current table when owner
 * is null), clones a copyable prefix,
 * removes every unpublished clone before atomically publishing that prefix,
 * and releases the captured table before returning.
 *
 * Linux receive-side truncation is reported through result and MSG_CTRUNC,
 * not as a recvmsg error.  Invalid arguments, invalid record handles, and
 * recoverable common-runtime invariant failures remain negative Linux errno
 * results.
 * Once capture succeeds, the helper never returns with an active target.
 * The registered architecture backends must therefore honor their
 * non-failing cleanup invariant for owned prepared descriptors and a valid
 * pinned table; violating that ownership contract fails closed.
 */
int kernel_socket_control_receive_rights_record(
    kernel_socket_rights_pool_t *pool,
    kernel_socket_rights_record_handle_t record,
    kernel_fd_transfer_target_t *target_workspace,
    const void *fd_owner, void *copy_context,
    edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, uint32_t receive_flags,
    kernel_socket_rights_receive_result_t *result);

/*
 * Appends receive-side metadata such as SCM_CREDENTIALS or a timestamp.
 * Capacity truncation copies the largest representable shortened cmsg and
 * sets MSG_CTRUNC.  A user-copy fault consumes the ancillary payload but
 * commits no new control length and does not add MSG_CTRUNC.
 */
int kernel_socket_control_receive_metadata_append(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags, int32_t level, int32_t type,
    const void *data, uint32_t data_length,
    kernel_socket_control_receive_result_t *result);

int kernel_socket_ip_receive_control_append(
    const kernel_socket_option_state_t *options,
    const kernel_socket_ip_receive_metadata_t *metadata,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags,
    kernel_socket_control_receive_result_t *result);

int kernel_socket_ip_send_control_parse(
    uint8_t family, void *copy_context,
    edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_control, uint64_t control_length,
    kernel_socket_ip_send_metadata_t *metadata);

int kernel_socket_timestamp_control_append(
    kernel_socket_timestamp_mode_t mode, uint64_t timestamp_microseconds,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags);

int kernel_socket_timestamp_control_receive_append(
    kernel_socket_timestamp_mode_t mode, uint64_t timestamp_microseconds,
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_control, uint64_t control_capacity, uint64_t *used,
    int32_t *message_flags,
    kernel_socket_control_receive_result_t *result);

/* Linux caps mmsg vector counts to UIO_MAXIOV and accepts a null vector at 0. */
int kernel_socket_mmsg_import(uint64_t user_messages, uint64_t requested_count,
                              uint32_t *effective_count);

int kernel_socket_mmsg_timeout_import(
    void *copy_context, edge_linux_copy_from_user_fn copy_from_user,
    uint64_t user_timeout, uint64_t *deadline_microseconds);

int kernel_socket_mmsg_timeout_write(
    void *copy_context, edge_linux_copy_to_user_fn copy_to_user,
    uint64_t user_timeout, uint64_t deadline_microseconds);

/*
 * Runs the architecture-independent Linux mmsg loop.  A runtime may force
 * nonblocking calls when it provides its own scheduler wait state; completed
 * messages are never hidden by a later error or copy fault.
 */
int64_t kernel_socket_mmsg_run(
    const kernel_socket_mmsg_request_t *request, uint32_t first_message,
    int force_nonblocking, kernel_socket_message_call_fn call_message,
    void *call_context, uint32_t *completed_messages);

/* Shared front door plus architecture transport and scheduler mechanics. */
int64_t kernel_socket_message_batch(
    const kernel_socket_mmsg_request_t *request);
int64_t arch_socket_message_batch(
    const kernel_socket_mmsg_request_t *request);

#endif
