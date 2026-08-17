/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/fd_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/socket_runtime.h"

typedef struct publication_mock {
    int32_t expected[4];
    uint32_t expected_count;
    uint32_t publish_calls;
    uint32_t abort_calls;
    int publish_result;
} publication_mock_t;

typedef struct fd_operation_mock_snapshot {
    uint64_t marker;
    uint64_t object_generation;
    int32_t descriptor;
    uint8_t is_socket;
    uint8_t reserved[3];
} fd_operation_mock_snapshot_t;

#define FD_TRANSFER_MOCK_LIMIT 512u
#define FD_TRANSFER_MOCK_TARGET_MARKER \
    UINT64_C(0xace0fd7ab1e5c003)

typedef struct fd_transfer_mock_target_snapshot {
    uint64_t marker;
    uint64_t target_generation;
} fd_transfer_mock_target_snapshot_t;

typedef struct fd_backend_mock {
    uint32_t allocation_limit;
    uint32_t is_open_calls;
    uint32_t operation_acquire_calls;
    uint32_t operation_acquire_for_owner_calls;
    uint32_t operation_acquire_for_pid_calls;
    uint32_t operation_description_id_calls;
    uint32_t operation_release_calls;
    uint32_t operation_transfer_calls;
    uint32_t operation_vector_io_calls;
    uint32_t operation_file_range_calls;
    uint32_t operation_socket_calls;
    uint32_t close_calls;
    uint32_t transfer_target_capture_calls;
    uint32_t transfer_target_capture_for_owner_calls;
    uint32_t transfer_target_release_calls;
    uint32_t transfer_target_prepare_calls;
    uint32_t transfer_target_discard_calls;
    uint32_t transfer_target_publish_calls;
    uint32_t transfer_target_abort_calls;
    uint32_t transfer_target_partial_rollbacks;
    uint32_t duplicate_minimum_calls;
    uint32_t operation_references;
    uint32_t target_references;
    uint32_t hidden_references;
    uint32_t published_references;
    int32_t operation_descriptor;
    int32_t operation_pid;
    int32_t next_transfer_descriptor;
    uint64_t operation_generation;
    uint64_t operation_release_generation;
    uint64_t operation_socket_generation;
    uint64_t target_generation;
    int32_t source;
    int32_t minimum;
    int32_t close_descriptor;
    uint32_t exclusive_limit;
    int32_t destination;
    uint32_t descriptor_flags;
    int operation_acquire_result;
    int operation_release_result;
    int operation_transfer_result;
    int64_t operation_vector_io_result;
    int64_t operation_file_range_result;
    int64_t operation_socket_result;
    int transfer_target_capture_result;
    int transfer_target_release_result;
    int transfer_target_prepare_result;
    int transfer_target_prepare_output_override_enabled;
    int32_t transfer_target_prepare_output_override;
    int32_t transfer_target_last_actual_descriptor;
    int transfer_target_last_prepare_pending;
    int transfer_target_publish_result;
    int transfer_target_abort_result;
    int duplicate_minimum_result;
    void *operation_storage;
    const void *operation_owner;
    void *transfer_target_storage;
    const void *transfer_target_owner;
    kernel_fd_operation_lease_t *operation_lease;
    const kernel_io_vector_request_t *operation_vector_request;
    kernel_io_file_range_request_t operation_file_range_request;
    const kernel_socket_operation_request_t *operation_socket_request;
    kernel_socket_operation_result_t *operation_socket_output;
    kernel_socket_operation_request_t operation_socket_request_copy;
    kernel_socket_descriptor_info_t socket_description;
    kernel_socket_address_t socket_address;
    uint8_t operation_is_socket;
    uint8_t operation_socket_dirty_error_result;
    uint8_t transfer_hidden[FD_TRANSFER_MOCK_LIMIT];
    uint8_t transfer_published[FD_TRANSFER_MOCK_LIMIT];
    uint32_t transfer_flags[FD_TRANSFER_MOCK_LIMIT];
    uint64_t transfer_generation[FD_TRANSFER_MOCK_LIMIT];
} fd_backend_mock_t;

#define FD_OPERATION_MOCK_MARKER UINT64_C(0xf00dcafe12345678)

_Static_assert(
    sizeof(fd_operation_mock_snapshot_t) <=
        KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE,
    "operation lease unit snapshot exceeds storage");
_Static_assert(
    sizeof(fd_transfer_mock_target_snapshot_t) <=
        KERNEL_FD_TRANSFER_TARGET_STORAGE_SIZE,
    "transfer target unit snapshot exceeds storage");

static uint32_t backend_table_limit(void *opaque) {
    (void)opaque;
    return 128;
}

static uint32_t backend_allocation_limit(void *opaque) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;

    assert(mock);
    return mock->allocation_limit;
}

static int backend_table_unshare(void *opaque) {
    (void)opaque;
    return 0;
}

static int backend_is_open(void *opaque, int32_t descriptor) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;

    assert(mock);
    ++mock->is_open_calls;
    return descriptor == 5;
}

static int backend_operation_acquire(
        void *opaque, int32_t descriptor, void *storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    fd_operation_mock_snapshot_t *snapshot =
        (fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(storage);
    assert((uintptr_t)storage %
           KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT == 0);
    assert(!kernel_fd_operation_view(mock->operation_lease));
    ++mock->operation_acquire_calls;
    mock->operation_descriptor = descriptor;
    mock->operation_storage = storage;
    snapshot->marker = FD_OPERATION_MOCK_MARKER;
    snapshot->object_generation = mock->operation_generation;
    snapshot->descriptor = descriptor;
    snapshot->is_socket = mock->operation_is_socket;
    if (mock->operation_acquire_result == 0)
        ++mock->operation_references;
    return mock->operation_acquire_result;
}

static int backend_operation_acquire_for_owner(
        void *opaque, const void *owner,
        int32_t descriptor, void *storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    fd_operation_mock_snapshot_t *snapshot =
        (fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(owner);
    assert(storage);
    ++mock->operation_acquire_for_owner_calls;
    mock->operation_owner = owner;
    mock->operation_descriptor = descriptor;
    mock->operation_storage = storage;
    snapshot->marker = FD_OPERATION_MOCK_MARKER;
    snapshot->object_generation =
        *(const uint64_t *)owner;
    snapshot->descriptor = descriptor;
    if (mock->operation_acquire_result == 0)
        ++mock->operation_references;
    return mock->operation_acquire_result;
}

static int backend_operation_acquire_for_pid(
        void *opaque, int32_t pid,
        int32_t descriptor, void *storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    fd_operation_mock_snapshot_t *snapshot =
        (fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(storage);
    ++mock->operation_acquire_for_pid_calls;
    mock->operation_pid = pid;
    mock->operation_descriptor = descriptor;
    mock->operation_storage = storage;
    snapshot->marker = FD_OPERATION_MOCK_MARKER;
    snapshot->object_generation = mock->operation_generation;
    snapshot->descriptor = descriptor;
    if (mock->operation_acquire_result == 0)
        ++mock->operation_references;
    return mock->operation_acquire_result;
}

static int backend_operation_description_id(
        void *opaque, const void *storage,
        uint64_t *description_id) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_operation_mock_snapshot_t *snapshot =
        (const fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(snapshot);
    assert(snapshot->marker == FD_OPERATION_MOCK_MARKER);
    assert(description_id);
    ++mock->operation_description_id_calls;
    *description_id = snapshot->object_generation;
    return *description_id ? 0 : -EDGE_LINUX_EBADF;
}

static int backend_operation_release(
        void *opaque, void *storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_operation_mock_snapshot_t *snapshot =
        (const fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(storage);
    assert(storage == mock->operation_storage);
    assert(!kernel_fd_operation_view(mock->operation_lease));
    assert(snapshot->marker == FD_OPERATION_MOCK_MARKER);
    assert(snapshot->descriptor == mock->operation_descriptor);
    mock->operation_release_generation = snapshot->object_generation;
    ++mock->operation_release_calls;
    assert(mock->operation_references);
    --mock->operation_references;
    return mock->operation_release_result;
}

static int backend_operation_transfer(
        void *opaque, void *destination_storage,
        void *source_storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    fd_operation_mock_snapshot_t *destination =
        (fd_operation_mock_snapshot_t *)destination_storage;
    fd_operation_mock_snapshot_t *source =
        (fd_operation_mock_snapshot_t *)source_storage;

    assert(mock);
    assert(destination);
    assert(source);
    assert(source_storage == mock->operation_storage);
    assert(source->marker == FD_OPERATION_MOCK_MARKER);
    ++mock->operation_transfer_calls;
    if (mock->operation_transfer_result < 0)
        return mock->operation_transfer_result;
    *destination = *source;
    memset(source, 0, sizeof(*source));
    mock->operation_storage = destination_storage;
    return 0;
}

static int64_t backend_operation_vector_io(
        void *opaque, void *storage,
        const struct kernel_io_vector_request *request) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_operation_mock_snapshot_t *snapshot =
        (const fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(storage == mock->operation_storage);
    assert(kernel_fd_operation_view(mock->operation_lease) == storage);
    assert(snapshot->marker == FD_OPERATION_MOCK_MARKER);
    ++mock->operation_vector_io_calls;
    mock->operation_vector_request = request;
    return mock->operation_vector_io_result;
}

static int64_t backend_operation_file_range(
        void *opaque, void *storage,
        const struct kernel_io_file_range_request *request) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_operation_mock_snapshot_t *snapshot =
        (const fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(storage == mock->operation_storage);
    assert(snapshot->marker == FD_OPERATION_MOCK_MARKER);
    assert(request);
    ++mock->operation_file_range_calls;
    mock->operation_file_range_request = *request;
    if (request->operation == KERNEL_IO_FILE_RANGE_QUERY &&
        request->information &&
        mock->operation_file_range_result >= 0) {
        memset(request->information, 0, sizeof(*request->information));
        request->information->filesystem =
            snapshot->object_generation;
        request->information->file =
            (uint64_t)(uint32_t)snapshot->descriptor;
        request->information->kind =
            KERNEL_IO_FILE_REGULAR;
    }
    return mock->operation_file_range_result;
}

static int64_t backend_operation_socket(
        void *opaque, void *storage,
        const struct kernel_socket_operation_request *request,
        struct kernel_socket_operation_result *result) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_operation_mock_snapshot_t *snapshot =
        (const fd_operation_mock_snapshot_t *)storage;

    assert(mock);
    assert(storage == mock->operation_storage);
    assert(snapshot->marker == FD_OPERATION_MOCK_MARKER);
    assert(request);
    assert(result);
    ++mock->operation_socket_calls;
    mock->operation_socket_generation = snapshot->object_generation;
    mock->operation_socket_request = request;
    mock->operation_socket_output = result;
    mock->operation_socket_request_copy = *request;
    if (mock->operation_socket_dirty_error_result)
        memset(result, 0xa5, sizeof(*result));
    if (!snapshot->is_socket)
        return -EDGE_LINUX_ENOTSOCK;
    if (mock->operation_socket_result < 0)
        return mock->operation_socket_result;

    switch (request->operation) {
        case KERNEL_SOCKET_OPERATION_DESCRIBE:
            result->output.description = mock->socket_description;
            break;
        case KERNEL_SOCKET_OPERATION_NAME:
            result->output.address = mock->socket_address;
            break;
        case KERNEL_SOCKET_OPERATION_LISTEN:
        case KERNEL_SOCKET_OPERATION_SHUTDOWN:
        case KERNEL_SOCKET_OPERATION_BIND:
        case KERNEL_SOCKET_OPERATION_CONNECT:
            break;
        default:
            assert(0 && "common layer dispatched an invalid socket operation");
    }
    return mock->operation_socket_result;
}

static int backend_transfer_target_capture(
        void *opaque, void *target_storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    fd_transfer_mock_target_snapshot_t *target =
        (fd_transfer_mock_target_snapshot_t *)target_storage;

    assert(mock);
    assert(target);
    ++mock->transfer_target_capture_calls;
    if (mock->transfer_target_capture_result < 0)
        return mock->transfer_target_capture_result;
    target->marker = FD_TRANSFER_MOCK_TARGET_MARKER;
    target->target_generation = mock->target_generation;
    mock->transfer_target_storage = target_storage;
    ++mock->target_references;
    return 0;
}

static int backend_transfer_target_capture_for_owner(
        void *opaque, const void *owner,
        void *target_storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    fd_transfer_mock_target_snapshot_t *target =
        (fd_transfer_mock_target_snapshot_t *)target_storage;
    int result;

    assert(mock);
    assert(owner);
    ++mock->transfer_target_capture_for_owner_calls;
    mock->transfer_target_owner = owner;
    result = backend_transfer_target_capture(
        opaque, target_storage);
    if (result == 0)
        target->target_generation =
            *(const uint64_t *)owner;
    return result;
}

static int backend_transfer_target_release(
        void *opaque, void *target_storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_transfer_mock_target_snapshot_t *target =
        (const fd_transfer_mock_target_snapshot_t *)target_storage;

    assert(mock);
    assert(target->marker == FD_TRANSFER_MOCK_TARGET_MARKER);
    ++mock->transfer_target_release_calls;
    if (mock->transfer_target_release_result < 0)
        return mock->transfer_target_release_result;
    assert(mock->target_references);
    --mock->target_references;
    if (!mock->target_references)
        mock->transfer_target_storage = 0;
    return 0;
}

static int backend_transfer_target_prepare(
        void *opaque, void *target_storage,
        const void *source_storage, uint32_t descriptor_flags,
        int32_t *descriptor) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_transfer_mock_target_snapshot_t *target =
        (const fd_transfer_mock_target_snapshot_t *)target_storage;
    const fd_operation_mock_snapshot_t *source =
        (const fd_operation_mock_snapshot_t *)source_storage;
    int32_t number;

    assert(mock);
    assert(target->marker == FD_TRANSFER_MOCK_TARGET_MARKER);
    assert(source);
    assert(source->marker == FD_OPERATION_MOCK_MARKER);
    assert(descriptor);
    ++mock->transfer_target_prepare_calls;
    mock->transfer_target_last_actual_descriptor = -1;
    mock->transfer_target_last_prepare_pending = 0;
    number = mock->next_transfer_descriptor++;
    assert(number >= 0 &&
           (uint32_t)number < FD_TRANSFER_MOCK_LIMIT);
    assert(!mock->transfer_hidden[number]);
    assert(!mock->transfer_published[number]);
    if (mock->transfer_target_prepare_result < 0) {
        /*
         * Model a backend that reserved and constructed a slot before a later
         * retain failed. Its callback contract requires complete rollback.
         */
        mock->transfer_hidden[number] = 1;
        mock->transfer_generation[number] =
            source->object_generation;
        mock->transfer_hidden[number] = 0;
        mock->transfer_generation[number] = 0;
        ++mock->transfer_target_partial_rollbacks;
        *descriptor = -1;
        return mock->transfer_target_prepare_result;
    }
    mock->transfer_hidden[number] = 1;
    mock->transfer_flags[number] =
        descriptor_flags & KERNEL_FD_CLOEXEC;
    mock->transfer_generation[number] =
        source->object_generation;
    ++mock->hidden_references;
    mock->transfer_target_last_actual_descriptor = number;
    mock->transfer_target_last_prepare_pending = 1;
    *descriptor =
        mock->transfer_target_prepare_output_override_enabled ?
            mock->transfer_target_prepare_output_override :
            number;
    return 0;
}

static void backend_transfer_target_discard_prepared(
        void *opaque, void *target_storage) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_transfer_mock_target_snapshot_t *target =
        (const fd_transfer_mock_target_snapshot_t *)target_storage;
    int32_t descriptor;

    assert(mock);
    assert(target->marker == FD_TRANSFER_MOCK_TARGET_MARKER);
    assert(mock->transfer_target_last_prepare_pending);
    descriptor = mock->transfer_target_last_actual_descriptor;
    assert(descriptor >= 0);
    assert((uint32_t)descriptor < FD_TRANSFER_MOCK_LIMIT);
    assert(mock->transfer_hidden[descriptor]);
    assert(!mock->transfer_published[descriptor]);
    mock->transfer_hidden[descriptor] = 0;
    mock->transfer_flags[descriptor] = 0;
    mock->transfer_generation[descriptor] = 0;
    assert(mock->hidden_references);
    --mock->hidden_references;
    mock->transfer_target_last_actual_descriptor = -1;
    mock->transfer_target_last_prepare_pending = 0;
    ++mock->transfer_target_discard_calls;
}

static int backend_transfer_target_publish_many(
        void *opaque, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_transfer_mock_target_snapshot_t *target =
        (const fd_transfer_mock_target_snapshot_t *)target_storage;

    assert(mock);
    assert(target->marker == FD_TRANSFER_MOCK_TARGET_MARKER);
    assert(descriptors);
    assert(count);
    ++mock->transfer_target_publish_calls;
    for (uint32_t index = 0; index < count; ++index) {
        assert(descriptors[index] >= 0);
        assert((uint32_t)descriptors[index] <
               FD_TRANSFER_MOCK_LIMIT);
        assert(mock->transfer_hidden[descriptors[index]]);
        assert(!mock->transfer_published[descriptors[index]]);
    }
    if (mock->transfer_target_publish_result < 0)
        return mock->transfer_target_publish_result;
    for (uint32_t index = 0; index < count; ++index) {
        mock->transfer_hidden[descriptors[index]] = 0;
        mock->transfer_published[descriptors[index]] = 1;
        assert(mock->hidden_references);
        --mock->hidden_references;
        ++mock->published_references;
    }
    return 0;
}

static int backend_transfer_target_abort_many(
        void *opaque, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;
    const fd_transfer_mock_target_snapshot_t *target =
        (const fd_transfer_mock_target_snapshot_t *)target_storage;

    assert(mock);
    assert(target->marker == FD_TRANSFER_MOCK_TARGET_MARKER);
    assert(descriptors);
    assert(count);
    ++mock->transfer_target_abort_calls;
    for (uint32_t index = 0; index < count; ++index) {
        assert(descriptors[index] >= 0);
        assert((uint32_t)descriptors[index] <
               FD_TRANSFER_MOCK_LIMIT);
        assert(mock->transfer_hidden[descriptors[index]]);
        assert(!mock->transfer_published[descriptors[index]]);
    }
    if (mock->transfer_target_abort_result < 0)
        return mock->transfer_target_abort_result;
    for (uint32_t index = 0; index < count; ++index) {
        mock->transfer_hidden[descriptors[index]] = 0;
        mock->transfer_generation[descriptors[index]] = 0;
        assert(mock->hidden_references);
        --mock->hidden_references;
    }
    return 0;
}

static int backend_close(void *opaque, int32_t descriptor) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;

    assert(mock);
    ++mock->close_calls;
    mock->close_descriptor = descriptor;
    return 0;
}

static int backend_duplicate_exact(void *opaque, int32_t source,
                                   int32_t destination,
                                   uint32_t descriptor_flags) {
    (void)opaque;
    (void)source;
    (void)destination;
    (void)descriptor_flags;
    return 0;
}

static int backend_duplicate_minimum(
        void *opaque, int32_t source, int32_t minimum,
        uint32_t exclusive_limit,
        uint32_t descriptor_flags, int32_t *destination) {
    fd_backend_mock_t *mock = (fd_backend_mock_t *)opaque;

    assert(mock);
    assert(destination);
    ++mock->duplicate_minimum_calls;
    mock->source = source;
    mock->minimum = minimum;
    mock->exclusive_limit = exclusive_limit;
    mock->descriptor_flags = descriptor_flags;
    if (mock->duplicate_minimum_result < 0)
        return mock->duplicate_minimum_result;
    *destination = mock->destination;
    return 0;
}

static int backend_get_flags(void *opaque, int32_t descriptor,
                             uint32_t *flags) {
    (void)opaque;
    (void)descriptor;
    if (flags) *flags = 0;
    return flags ? 0 : -EDGE_LINUX_EINVAL;
}

static int backend_set_flags(void *opaque, int32_t descriptor,
                             uint32_t flags) {
    (void)opaque;
    (void)descriptor;
    (void)flags;
    return 0;
}

static int backend_pipe_capacity(void *opaque, int32_t descriptor,
                                 uint32_t *capacity) {
    (void)opaque;
    (void)descriptor;
    if (capacity) *capacity = 65536;
    return capacity ? 0 : -EDGE_LINUX_EINVAL;
}

static int backend_pidfd_lookup(void *opaque, int32_t pid,
                                int32_t *tgid) {
    (void)opaque;
    if (tgid) *tgid = pid;
    return tgid ? 0 : -EDGE_LINUX_EINVAL;
}

static int backend_pidfd_install(void *opaque, int32_t pid,
                                 uint32_t flags) {
    (void)opaque;
    (void)pid;
    (void)flags;
    return 9;
}

static int backend_pidfd_target(void *opaque, int32_t descriptor,
                                int32_t *pid, uint32_t *flags) {
    (void)opaque;
    (void)descriptor;
    if (!pid || !flags) return -EDGE_LINUX_EINVAL;
    *pid = 1;
    *flags = 0;
    return 0;
}

static int64_t backend_fcntl_fallback(
        void *opaque, int32_t descriptor,
        uint32_t command, uint64_t argument) {
    (void)opaque;
    (void)descriptor;
    (void)command;
    (void)argument;
    return -EDGE_LINUX_ENOSYS;
}

static const kernel_fd_backend_ops_t g_backend_ops = {
    .table_limit = backend_table_limit,
    .allocation_limit = backend_allocation_limit,
    .table_unshare = backend_table_unshare,
    .is_open = backend_is_open,
    .operation_acquire = backend_operation_acquire,
    .operation_acquire_for_owner =
        backend_operation_acquire_for_owner,
    .operation_acquire_for_pid =
        backend_operation_acquire_for_pid,
    .operation_release = backend_operation_release,
    .operation_transfer = backend_operation_transfer,
    .operation_description_id =
        backend_operation_description_id,
    .operation_vector_io = backend_operation_vector_io,
    .operation_file_range =
        backend_operation_file_range,
    .operation_socket = backend_operation_socket,
    .transfer_target_capture =
        backend_transfer_target_capture,
    .transfer_target_capture_for_owner =
        backend_transfer_target_capture_for_owner,
    .transfer_target_release =
        backend_transfer_target_release,
    .transfer_target_prepare =
        backend_transfer_target_prepare,
    .transfer_target_discard_prepared =
        backend_transfer_target_discard_prepared,
    .transfer_target_publish_many =
        backend_transfer_target_publish_many,
    .transfer_target_abort_many =
        backend_transfer_target_abort_many,
    .close = backend_close,
    .duplicate_exact = backend_duplicate_exact,
    .duplicate_minimum = backend_duplicate_minimum,
    .get_descriptor_flags = backend_get_flags,
    .set_descriptor_flags = backend_set_flags,
    .get_status_flags = backend_get_flags,
    .set_status_flags = backend_set_flags,
    .pipe_capacity = backend_pipe_capacity,
    .pidfd_lookup = backend_pidfd_lookup,
    .pidfd_install = backend_pidfd_install,
    .pidfd_target = backend_pidfd_target,
    .fcntl_fallback = backend_fcntl_fallback,
};

static int mock_publish(void *opaque, const int32_t *descriptors,
                        uint32_t count) {
    publication_mock_t *mock = (publication_mock_t *)opaque;

    assert(mock);
    assert(descriptors);
    assert(count == mock->expected_count);
    for (uint32_t index = 0; index < count; ++index)
        assert(descriptors[index] == mock->expected[index]);
    ++mock->publish_calls;
    return mock->publish_result;
}

static void mock_abort(void *opaque, const int32_t *descriptors,
                       uint32_t count) {
    publication_mock_t *mock = (publication_mock_t *)opaque;

    assert(mock);
    assert(descriptors);
    assert(count == mock->expected_count);
    for (uint32_t index = 0; index < count; ++index)
        assert(descriptors[index] == mock->expected[index]);
    ++mock->abort_calls;
}

static void initialize_mock(publication_mock_t *mock,
                            const int32_t *descriptors,
                            uint32_t count, int publish_result) {
    memset(mock, 0, sizeof(*mock));
    assert(count <=
           sizeof(mock->expected) / sizeof(mock->expected[0]));
    memcpy(mock->expected, descriptors,
           count * sizeof(descriptors[0]));
    mock->expected_count = count;
    mock->publish_result = publish_result;
}

static void require_cleared(
        const kernel_fd_publication_t *publication) {
    assert(publication);
    assert(!publication->descriptors);
    assert(!publication->context);
    assert(!publication->publish);
    assert(!publication->abort);
    assert(!publication->count);
    assert(!publication->active);
}

static void require_socket_result_cleared(
        const kernel_socket_operation_result_t *result) {
    kernel_socket_operation_result_t zero = {0};

    assert(result);
    assert(memcmp(result, &zero, sizeof(zero)) == 0);
}

static void initialize_socket_mock(
        fd_backend_mock_t *mock,
        kernel_fd_operation_lease_t *lease,
        uint64_t generation) {
    assert(mock);
    memset(mock, 0, sizeof(*mock));
    mock->allocation_limit = 64;
    mock->operation_generation = generation;
    mock->operation_is_socket = 1;
    mock->operation_lease = lease;
}

static void test_invalid_initialization(void) {
    int32_t valid[] = { 3, 7 };
    int32_t negative[] = { 3, -1 };
    int32_t duplicate[] = { 3, 3 };
    kernel_fd_publication_t publication = {0};
    publication_mock_t mock;

    initialize_mock(&mock, valid, 2, 0);
    assert(kernel_fd_publication_initialize(
               0, valid, 2, &mock,
               mock_publish, mock_abort) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_publication_initialize(
               &publication, 0, 2, &mock,
               mock_publish, mock_abort) ==
           -EDGE_LINUX_EINVAL);
    require_cleared(&publication);
    assert(kernel_fd_publication_initialize(
               &publication, valid, 0, &mock,
               mock_publish, mock_abort) ==
           -EDGE_LINUX_EINVAL);
    require_cleared(&publication);
    assert(kernel_fd_publication_initialize(
               &publication, valid, 2, &mock,
               0, mock_abort) ==
           -EDGE_LINUX_EINVAL);
    require_cleared(&publication);
    assert(kernel_fd_publication_initialize(
               &publication, valid, 2, &mock,
               mock_publish, 0) ==
           -EDGE_LINUX_EINVAL);
    require_cleared(&publication);
    assert(kernel_fd_publication_initialize(
               &publication, negative, 2, &mock,
               mock_publish, mock_abort) ==
           -EDGE_LINUX_EBADF);
    require_cleared(&publication);
    assert(kernel_fd_publication_initialize(
               &publication, duplicate, 2, &mock,
               mock_publish, mock_abort) ==
           -EDGE_LINUX_EINVAL);
    require_cleared(&publication);
}

static void test_commit(void) {
    int32_t descriptors[] = { 4, 8 };
    kernel_fd_publication_t publication = {0};
    publication_mock_t mock;

    initialize_mock(&mock, descriptors, 2, 0);
    assert(kernel_fd_publication_initialize(
               &publication, descriptors, 2, &mock,
               mock_publish, mock_abort) == 0);
    assert(publication.active);
    assert(kernel_fd_publication_initialize(
               &publication, descriptors, 2, &mock,
               mock_publish, mock_abort) ==
           -EDGE_LINUX_EBUSY);
    assert(kernel_fd_publication_commit(&publication) == 0);
    assert(mock.publish_calls == 1);
    assert(mock.abort_calls == 0);
    require_cleared(&publication);
    assert(kernel_fd_publication_commit(&publication) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_publication_abort(&publication) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.publish_calls == 1);
    assert(mock.abort_calls == 0);
}

static void test_abort(void) {
    int32_t descriptors[] = { 11 };
    kernel_fd_publication_t publication = {0};
    publication_mock_t mock;

    initialize_mock(&mock, descriptors, 1, 0);
    assert(kernel_fd_publication_initialize(
               &publication, descriptors, 1, &mock,
               mock_publish, mock_abort) == 0);
    assert(kernel_fd_publication_abort(&publication) == 0);
    assert(mock.publish_calls == 0);
    assert(mock.abort_calls == 1);
    require_cleared(&publication);
    assert(kernel_fd_publication_abort(&publication) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.abort_calls == 1);
}

static void test_publish_failure_aborts(void) {
    int32_t descriptors[] = { 13, 17, 19 };
    kernel_fd_publication_t publication = {0};
    publication_mock_t mock;

    initialize_mock(
        &mock, descriptors, 3, -EDGE_LINUX_EIO);
    assert(kernel_fd_publication_initialize(
               &publication, descriptors, 3, &mock,
               mock_publish, mock_abort) == 0);
    assert(kernel_fd_publication_commit(&publication) ==
           -EDGE_LINUX_EIO);
    assert(mock.publish_calls == 1);
    assert(mock.abort_calls == 1);
    require_cleared(&publication);
    assert(kernel_fd_publication_commit(&publication) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.publish_calls == 1);
    assert(mock.abort_calls == 1);
}

static void test_operation_lease_without_backend(void) {
    kernel_fd_operation_lease_t lease = {0};
    kernel_fd_transfer_target_t target = {0};
    uint64_t owner = 1;
    kernel_socket_operation_request_t socket_request = {
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    kernel_socket_operation_result_t socket_result;
    int32_t descriptor = -1;

    assert(!kernel_fd_operation_vector_io_available());
    assert(!kernel_fd_operation_vector_io_supported(0));
    assert(!kernel_fd_operation_vector_io_supported(&lease));
    assert(kernel_fd_operation_vector_io(0, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(!kernel_fd_operation_socket_available());
    assert(!kernel_fd_operation_socket_supported(0));
    assert(!kernel_fd_operation_socket_supported(&lease));
    assert(kernel_fd_operation_socket(
               0, &socket_request, &socket_result) ==
           -EDGE_LINUX_EINVAL);
    require_socket_result_cleared(&socket_result);
    memset(&socket_result, 0xa5, sizeof(socket_result));
    assert(kernel_fd_operation_socket(
               &lease, &socket_request, &socket_result) ==
           -EDGE_LINUX_EINVAL);
    require_socket_result_cleared(&socket_result);
    memset(&socket_result, 0xa5, sizeof(socket_result));
    assert(kernel_socket_operation_execute(
               5, &socket_request, &socket_result) ==
           -EDGE_LINUX_ENODEV);
    require_socket_result_cleared(&socket_result);
    assert(!kernel_fd_operation_view(0));
    assert(!kernel_fd_operation_view(&lease));
    assert(kernel_fd_operation_acquire(5, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_operation_acquire_for_owner(
               &owner, 5, 0) == -EDGE_LINUX_EINVAL);
    assert(kernel_fd_operation_release(0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_operation_acquire(5, &lease) ==
           -EDGE_LINUX_ENODEV);
    assert(kernel_fd_operation_acquire_for_owner(
               &owner, 5, &lease) ==
           -EDGE_LINUX_ENODEV);
    assert(!kernel_fd_operation_view(&lease));
    assert(kernel_fd_operation_release(&lease) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_capture(0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_capture_for_owner(
               &owner, 0) == -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_capture(&target) ==
           -EDGE_LINUX_ENODEV);
    assert(kernel_fd_transfer_target_capture_for_owner(
               &owner, &target) ==
           -EDGE_LINUX_ENODEV);
    assert(kernel_fd_transfer_target_prepare(
               &target, &lease, 0, &descriptor) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_publish_many(
               &target, &descriptor, 1) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_abort_many(
               &target, &descriptor, 1) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_release(&target) ==
           -EDGE_LINUX_EINVAL);
}

static void test_explicit_owner_routing(void) {
    kernel_fd_backend_ops_t no_owner_ops = g_backend_ops;
    kernel_fd_operation_lease_t lease = {0};
    kernel_fd_transfer_target_t target = {0};
    fd_backend_mock_t mock;
    const fd_operation_mock_snapshot_t *snapshot;
    uint64_t blocked_sender = 71;
    uint64_t blocked_receiver = 93;

    memset(&mock, 0, sizeof(mock));
    mock.allocation_limit = 64;
    mock.operation_generation = 11;
    mock.target_generation = 12;
    mock.operation_lease = &lease;
    no_owner_ops.operation_acquire_for_owner = 0;
    no_owner_ops.transfer_target_capture_for_owner = 0;
    assert(kernel_fd_backend_register(
               &no_owner_ops, &mock) == 0);
    assert(kernel_fd_operation_acquire_for_owner(
               &blocked_sender, 5, &lease) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(mock.operation_acquire_calls == 0);
    assert(kernel_fd_transfer_target_capture_for_owner(
               &blocked_receiver, &target) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(mock.transfer_target_capture_calls == 0);

    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);
    assert(kernel_fd_operation_acquire_for_owner(
               &blocked_sender, 5, &lease) == 0);
    assert(mock.operation_acquire_calls == 0);
    assert(mock.operation_acquire_for_owner_calls == 1);
    assert(mock.operation_owner == &blocked_sender);
    snapshot = (const fd_operation_mock_snapshot_t *)
        kernel_fd_operation_view(&lease);
    assert(snapshot);
    assert(snapshot->object_generation == blocked_sender);
    assert(kernel_fd_operation_release(&lease) == 0);

    assert(kernel_fd_transfer_target_capture_for_owner(
               &blocked_receiver, &target) == 0);
    assert(mock.transfer_target_capture_for_owner_calls == 1);
    assert(mock.transfer_target_owner == &blocked_receiver);
    assert(kernel_fd_transfer_target_release(&target) == 0);
}

static void test_pid_routed_descriptor_policy(void) {
    fd_backend_mock_t success;
    fd_backend_mock_t publish_failure;
    fd_backend_mock_t post_publish_release_failure;
    uint64_t description_id = 0;
    int32_t descriptor = -1;

    memset(&success, 0, sizeof(success));
    success.allocation_limit = 64;
    success.operation_generation = 0x1234u;
    success.target_generation = 0x5678u;
    success.next_transfer_descriptor = 37;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &success) == 0);

    assert(kernel_process_fd_description_id(
               71, 5, &description_id) == 0);
    assert(description_id == success.operation_generation);
    assert(success.operation_acquire_for_pid_calls == 1);
    assert(success.operation_description_id_calls == 1);
    assert(success.operation_release_calls == 1);
    assert(success.operation_pid == 71);
    assert(success.operation_descriptor == 5);
    assert(success.operation_references == 0);

    assert(kernel_pidfd_getfd(73, 9, &descriptor) == 0);
    assert(descriptor == 37);
    assert(success.operation_acquire_for_pid_calls == 2);
    assert(success.operation_pid == 73);
    assert(success.operation_descriptor == 9);
    assert(success.transfer_target_capture_calls == 1);
    assert(success.transfer_target_prepare_calls == 1);
    assert(success.transfer_target_publish_calls == 1);
    assert(success.transfer_target_abort_calls == 0);
    assert(success.transfer_target_release_calls == 1);
    assert(success.transfer_flags[37] == KERNEL_FD_CLOEXEC);
    assert(success.transfer_generation[37] ==
           success.operation_generation);
    assert(success.published_references == 1);
    assert(success.hidden_references == 0);
    assert(success.operation_references == 0);
    assert(success.target_references == 0);

    memset(&publish_failure, 0, sizeof(publish_failure));
    publish_failure.allocation_limit = 64;
    publish_failure.operation_generation = 0x4321u;
    publish_failure.target_generation = 0x8765u;
    publish_failure.next_transfer_descriptor = 41;
    publish_failure.transfer_target_publish_result =
        -EDGE_LINUX_EIO;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &publish_failure) == 0);
    descriptor = -1;
    assert(kernel_pidfd_getfd(79, 11, &descriptor) ==
           -EDGE_LINUX_EIO);
    assert(descriptor == -1);
    assert(publish_failure.transfer_target_publish_calls == 1);
    assert(publish_failure.transfer_target_abort_calls == 1);
    assert(publish_failure.transfer_target_release_calls == 1);
    assert(publish_failure.hidden_references == 0);
    assert(publish_failure.published_references == 0);
    assert(publish_failure.operation_references == 0);
    assert(publish_failure.target_references == 0);

    memset(&post_publish_release_failure, 0,
           sizeof(post_publish_release_failure));
    post_publish_release_failure.allocation_limit = 64;
    post_publish_release_failure.operation_generation = 0x2468u;
    post_publish_release_failure.target_generation = 0x1357u;
    post_publish_release_failure.next_transfer_descriptor = 43;
    post_publish_release_failure.operation_release_result =
        -EDGE_LINUX_EIO;
    assert(kernel_fd_backend_register(
               &g_backend_ops,
               &post_publish_release_failure) == 0);
    descriptor = -1;
    assert(kernel_pidfd_getfd(83, 13, &descriptor) == 0);
    assert(descriptor == 43);
    assert(post_publish_release_failure.published_references == 1);
    assert(post_publish_release_failure.hidden_references == 0);
    assert(post_publish_release_failure.operation_references == 0);
    assert(post_publish_release_failure.target_references == 0);
}

static void test_file_range_policy(void) {
    kernel_fd_backend_ops_t no_file_range_ops = g_backend_ops;
    kernel_io_file_range_info_t information;
    fd_backend_mock_t mock;
    uint8_t buffer[16] = {0};

    memset(&mock, 0, sizeof(mock));
    mock.allocation_limit = 64;
    mock.operation_generation = 0x9876u;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);

    memset(&information, 0xa5, sizeof(information));
    mock.operation_file_range_result = 0;
    assert(kernel_io_file_range_query(
               17, &information) == 0);
    assert(information.filesystem == mock.operation_generation);
    assert(information.file == 17);
    assert(information.kind == KERNEL_IO_FILE_REGULAR);
    assert(mock.operation_file_range_request.operation ==
           KERNEL_IO_FILE_RANGE_QUERY);

    mock.operation_file_range_result = 7;
    assert(kernel_io_file_range_read(
               19, 23, buffer, sizeof(buffer)) == 7);
    assert(mock.operation_file_range_request.operation ==
           KERNEL_IO_FILE_RANGE_READ);
    assert(mock.operation_file_range_request.offset == 23);
    assert(mock.operation_file_range_request.buffer == buffer);
    assert(mock.operation_file_range_request.length ==
           sizeof(buffer));

    mock.operation_file_range_result = 9;
    assert(kernel_io_file_range_write(
               21, 29, buffer, sizeof(buffer)) == 9);
    assert(mock.operation_file_range_request.operation ==
           KERNEL_IO_FILE_RANGE_WRITE);
    assert(mock.operation_file_range_request.offset == 29);
    assert(mock.operation_file_range_request.buffer == buffer);

    mock.operation_file_range_result = 0;
    assert(kernel_io_file_range_commit_offset(23, 31) == 0);
    assert(mock.operation_file_range_request.operation ==
           KERNEL_IO_FILE_RANGE_COMMIT_OFFSET);
    assert(mock.operation_file_range_request.offset == 31);

    kernel_io_file_range_complete_write(25);
    assert(mock.operation_file_range_request.operation ==
           KERNEL_IO_FILE_RANGE_COMPLETE_WRITE);
    assert(mock.operation_acquire_calls == 5);
    assert(mock.operation_file_range_calls == 5);
    assert(mock.operation_release_calls == 5);
    assert(mock.operation_references == 0);

    assert(kernel_io_file_range_query(27, 0) ==
           -EDGE_LINUX_EBADF);
    assert(mock.operation_acquire_calls == 5);

    no_file_range_ops.operation_file_range = 0;
    assert(kernel_fd_backend_register(
               &no_file_range_ops, &mock) == 0);
    assert(kernel_io_file_range_query(
               27, &information) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(mock.operation_acquire_calls == 6);
    assert(mock.operation_release_calls == 6);
    assert(mock.operation_references == 0);
}

static void test_operation_lease(void) {
    kernel_fd_backend_ops_t incomplete_ops = g_backend_ops;
    kernel_fd_operation_lease_t lease = {0};
    kernel_io_vector_request_t vector_request = {0};
    kernel_io_file_range_info_t file_range_information = {0};
    kernel_io_file_range_request_t file_range_request = {
        .operation = KERNEL_IO_FILE_RANGE_QUERY,
        .information = &file_range_information,
    };
    fd_backend_mock_t first;
    fd_backend_mock_t second;
    const fd_operation_mock_snapshot_t *snapshot;

    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.allocation_limit = 64;
    first.operation_generation = 41;
    first.operation_lease = &lease;
    second.allocation_limit = 64;
    second.operation_lease = &lease;

    incomplete_ops.operation_acquire = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.operation_release = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.transfer_target_capture = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.transfer_target_release = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.transfer_target_prepare = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.transfer_target_discard_prepared = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.transfer_target_publish_many = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.transfer_target_abort_many = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &first) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    assert(kernel_fd_operation_vector_io_available());

    assert(kernel_fd_operation_acquire(-1, &lease) ==
           -EDGE_LINUX_EBADF);
    assert(kernel_fd_operation_acquire(128, &lease) ==
           -EDGE_LINUX_EBADF);
    assert(first.operation_acquire_calls == 0);
    assert(first.is_open_calls == 0);
    assert(!kernel_fd_operation_view(&lease));

    first.operation_acquire_result = -EDGE_LINUX_EIO;
    assert(kernel_fd_operation_acquire(5, &lease) ==
           -EDGE_LINUX_EIO);
    assert(first.operation_acquire_calls == 1);
    assert(first.operation_release_calls == 0);
    assert(first.is_open_calls == 0);
    assert(!kernel_fd_operation_view(&lease));
    assert(kernel_fd_operation_release(&lease) ==
           -EDGE_LINUX_EINVAL);

    first.operation_acquire_result = 0;
    assert(kernel_fd_operation_acquire(5, &lease) == 0);
    assert(first.operation_acquire_calls == 2);
    assert(first.operation_descriptor == 5);
    assert(first.is_open_calls == 0);
    snapshot = (const fd_operation_mock_snapshot_t *)
        kernel_fd_operation_view(&lease);
    assert(snapshot);
    assert(snapshot->marker == FD_OPERATION_MOCK_MARKER);
    assert(snapshot->descriptor == 5);
    assert(snapshot->object_generation == 41);
    assert(kernel_fd_operation_vector_io_supported(&lease));
    first.operation_vector_io_result = 73;
    assert(kernel_fd_operation_vector_io(
               &lease, &vector_request) == 73);
    assert(first.operation_vector_io_calls == 1);
    assert(first.operation_vector_request == &vector_request);
    /*
     * Simulate close plus descriptor-number reuse in the backend table. The
     * in-flight operation must keep the generation captured at acquisition.
     */
    first.operation_generation = 99;
    assert(snapshot->object_generation == 41);
    assert(kernel_fd_operation_acquire(5, &lease) ==
           -EDGE_LINUX_EBUSY);
    assert(first.operation_acquire_calls == 2);

    /*
     * An active lease belongs to the backend that acquired it, even if a
     * later boot/test registration replaces the process-wide backend.
     */
    assert(kernel_fd_backend_register(
               &g_backend_ops, &second) == 0);
    first.operation_file_range_result = 0;
    assert(kernel_fd_operation_file_range(
               &lease, &file_range_request) == 0);
    assert(first.operation_file_range_calls == 1);
    assert(second.operation_file_range_calls == 0);
    assert(file_range_information.filesystem == 41);
    assert(kernel_fd_operation_release(&lease) == 0);
    assert(first.operation_release_calls == 1);
    assert(first.operation_release_generation == 41);
    assert(second.operation_release_calls == 0);
    assert(second.operation_vector_io_calls == 0);
    assert(!kernel_fd_operation_view(&lease));
    assert(!kernel_fd_operation_vector_io_supported(&lease));
    assert(kernel_fd_operation_vector_io(
               &lease, &vector_request) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_operation_release(&lease) ==
           -EDGE_LINUX_EINVAL);

    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    first.operation_release_result = -EDGE_LINUX_EIO;
    assert(kernel_fd_operation_acquire(5, &lease) == 0);
    assert(kernel_fd_operation_release(&lease) ==
           -EDGE_LINUX_EIO);
    assert(first.operation_release_calls == 2);
    assert(!kernel_fd_operation_view(&lease));
    assert(kernel_fd_operation_release(&lease) ==
           -EDGE_LINUX_EINVAL);

    first.operation_release_result = 0;
    assert(kernel_fd_operation_acquire(5, &lease) == 0);
    assert(kernel_fd_operation_release(&lease) == 0);
    assert(first.operation_release_calls == 3);
    assert(!kernel_fd_operation_view(&lease));
}

static void test_socket_operation_validation_and_support(void) {
    kernel_fd_backend_ops_t no_socket_ops = g_backend_ops;
    kernel_fd_operation_lease_t lease = {0};
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    kernel_socket_operation_request_t invalid_requests[] = {
        { .operation = 0 },
        {
            .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
            .reserved = 1,
        },
        { .operation = UINT32_MAX },
        {
            .operation = KERNEL_SOCKET_OPERATION_SHUTDOWN,
            .arguments.shutdown_how = -1,
        },
        {
            .operation = KERNEL_SOCKET_OPERATION_SHUTDOWN,
            .arguments.shutdown_how = 3,
        },
        {
            .operation = KERNEL_SOCKET_OPERATION_BIND,
            .arguments.bind_address.length =
                EDGE_LINUX_SOCKADDR_STORAGE_SIZE + 1u,
        },
        {
            .operation = KERNEL_SOCKET_OPERATION_CONNECT,
            .arguments.connect.address.length =
                EDGE_LINUX_SOCKADDR_STORAGE_SIZE + 1u,
        },
        {
            .operation = KERNEL_SOCKET_OPERATION_NAME,
            .arguments.name_peer = 2,
        },
    };
    kernel_socket_operation_result_t result;
    fd_backend_mock_t mock;
    uint32_t acquire_calls;
    uint32_t release_calls;

    initialize_socket_mock(&mock, &lease, 31);
    no_socket_ops.operation_socket = 0;
    assert(kernel_fd_backend_register(
               &no_socket_ops, &mock) == 0);
    assert(!kernel_fd_operation_socket_available());
    assert(!kernel_fd_operation_socket_supported(&lease));

    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) ==
           -EDGE_LINUX_EOPNOTSUPP);
    require_socket_result_cleared(&result);
    assert(mock.operation_acquire_calls == 1);
    assert(mock.operation_socket_calls == 0);
    assert(mock.operation_release_calls == 1);
    assert(mock.operation_references == 0);

    assert(kernel_fd_operation_acquire(5, &lease) == 0);
    assert(!kernel_fd_operation_socket_supported(&lease));
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_fd_operation_socket(
               &lease, &request, &result) ==
           -EDGE_LINUX_EOPNOTSUPP);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_calls == 0);
    assert(kernel_fd_operation_release(&lease) == 0);
    assert(mock.operation_references == 0);

    acquire_calls = mock.operation_acquire_calls;
    release_calls = mock.operation_release_calls;
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, 0, &result) ==
           -EDGE_LINUX_EINVAL);
    require_socket_result_cleared(&result);
    assert(kernel_socket_operation_execute(
               5, &request, 0) ==
           -EDGE_LINUX_EINVAL);
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               -1, &request, &result) ==
           -EDGE_LINUX_EBADF);
    require_socket_result_cleared(&result);
    for (uint32_t index = 0;
         index < sizeof(invalid_requests) /
                     sizeof(invalid_requests[0]);
         ++index) {
        memset(&result, 0xa5, sizeof(result));
        assert(kernel_socket_operation_execute(
                   5, &invalid_requests[index], &result) ==
               -EDGE_LINUX_EINVAL);
        require_socket_result_cleared(&result);
    }
    assert(mock.operation_acquire_calls == acquire_calls);
    assert(mock.operation_socket_calls == 0);
    assert(mock.operation_release_calls == release_calls);

    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);
    assert(kernel_fd_operation_socket_available());
    assert(kernel_fd_operation_acquire(5, &lease) == 0);
    assert(kernel_fd_operation_socket_supported(&lease));
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_fd_operation_socket(
               &lease, &invalid_requests[1], &result) ==
           -EDGE_LINUX_EINVAL);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_calls == 0);
    assert(kernel_fd_operation_release(&lease) == 0);
    assert(mock.operation_references == 0);
    assert(mock.is_open_calls == 0);
}

static void test_socket_operation_all_opcodes(void) {
    kernel_fd_operation_lease_t inactive_lease = {0};
    kernel_socket_operation_request_t request;
    kernel_socket_operation_result_t result;
    fd_backend_mock_t mock;

    initialize_socket_mock(&mock, &inactive_lease, 41);
    mock.socket_description.domain = 2;
    mock.socket_description.type = 1;
    mock.socket_description.protocol = 6;
    mock.socket_description.connected = 1;
    mock.socket_address.length = 4;
    mock.socket_address.bytes[0] = 0x12;
    mock.socket_address.bytes[1] = 0x34;
    mock.socket_address.bytes[2] = 0x56;
    mock.socket_address.bytes[3] = 0x78;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);

    request = (kernel_socket_operation_request_t){
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) == 0);
    assert(memcmp(
               &result.output.description,
               &mock.socket_description,
               sizeof(mock.socket_description)) == 0);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_DESCRIBE);

    request = (kernel_socket_operation_request_t){
        .operation = KERNEL_SOCKET_OPERATION_LISTEN,
        .arguments.listen_backlog = 32,
    };
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) == 0);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_LISTEN);
    assert(mock.operation_socket_request_copy
               .arguments.listen_backlog == 32);

    request = (kernel_socket_operation_request_t){
        .operation = KERNEL_SOCKET_OPERATION_SHUTDOWN,
        .arguments.shutdown_how = 2,
    };
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) == 0);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_SHUTDOWN);
    assert(mock.operation_socket_request_copy
               .arguments.shutdown_how == 2);

    request = (kernel_socket_operation_request_t){
        .operation = KERNEL_SOCKET_OPERATION_BIND,
        .arguments.bind_address = {
            .bytes = { 0x02, 0x00, 0x20, 0x21 },
            .length = 4,
        },
    };
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) == 0);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_BIND);
    assert(memcmp(
               &mock.operation_socket_request_copy
                    .arguments.bind_address,
               &request.arguments.bind_address,
               sizeof(request.arguments.bind_address)) == 0);

    request = (kernel_socket_operation_request_t){
        .operation = KERNEL_SOCKET_OPERATION_CONNECT,
        .arguments.connect = {
            .address = {
                .bytes = {
                    0x02, 0x00, 0x01, 0xbb, 0x7f, 0x00,
                    0x00, 0x01,
                },
                .length = 8,
            },
            .user_registers = (void *)(uintptr_t)0x1234,
        },
    };
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) == 0);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_CONNECT);
    assert(memcmp(
               &mock.operation_socket_request_copy
                    .arguments.connect.address,
               &request.arguments.connect.address,
               sizeof(request.arguments.connect.address)) == 0);
    assert(mock.operation_socket_request_copy
               .arguments.connect.user_registers ==
           (void *)(uintptr_t)0x1234);

    request = (kernel_socket_operation_request_t){
        .operation = KERNEL_SOCKET_OPERATION_NAME,
        .arguments.name_peer = 1,
    };
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) == 0);
    assert(memcmp(
               &result.output.address, &mock.socket_address,
               sizeof(mock.socket_address)) == 0);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_NAME);
    assert(mock.operation_socket_request_copy
               .arguments.name_peer == 1);

    assert(mock.operation_acquire_calls == 6);
    assert(mock.operation_socket_calls == 6);
    assert(mock.operation_release_calls == 6);
    assert(mock.operation_socket_generation == 41);
    assert(mock.operation_release_generation == 41);
    assert(mock.operation_socket_request == &request);
    assert(mock.operation_socket_output == &result);
    assert(mock.operation_references == 0);
    assert(mock.is_open_calls == 0);
}

static void test_socket_descriptor_wrappers(void) {
    kernel_fd_operation_lease_t inactive_lease = {0};
    kernel_socket_descriptor_info_t description;
    kernel_socket_address_t address = {
        .bytes = {0x02, 0x00, 0x20, 0x21},
        .length = 4,
    };
    kernel_socket_address_t observed;
    fd_backend_mock_t mock;

    initialize_socket_mock(&mock, &inactive_lease, 43);
    mock.socket_description.domain = 2;
    mock.socket_description.type = 1;
    mock.socket_description.protocol = 6;
    mock.socket_description.listening = 1;
    mock.socket_address = address;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);

    assert(kernel_socket_describe_descriptor(5, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.operation_acquire_calls == 0);
    memset(&description, 0, sizeof(description));
    assert(kernel_socket_describe_descriptor(
               5, &description) == 0);
    assert(memcmp(
               &description, &mock.socket_description,
               sizeof(description)) == 0);

    assert(kernel_socket_listen_descriptor(5, 17) == 0);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_LISTEN);
    assert(mock.operation_socket_request_copy
               .arguments.listen_backlog == 17);

    assert(kernel_socket_shutdown_descriptor(5, 3) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.operation_acquire_calls == 2);
    assert(kernel_socket_shutdown_descriptor(5, 2) == 0);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_SHUTDOWN);
    assert(mock.operation_socket_request_copy
               .arguments.shutdown_how == 2);

    assert(kernel_socket_bind_descriptor(5, &address) == 0);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_BIND);
    assert(memcmp(
               &mock.operation_socket_request_copy
                    .arguments.bind_address,
               &address, sizeof(address)) == 0);

    assert(kernel_socket_connect_descriptor(
               5, &address, (void *)(uintptr_t)0x4567) == 0);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_CONNECT);
    assert(memcmp(
               &mock.operation_socket_request_copy
                    .arguments.connect.address,
               &address, sizeof(address)) == 0);
    assert(mock.operation_socket_request_copy
               .arguments.connect.user_registers ==
           (void *)(uintptr_t)0x4567);

    assert(kernel_socket_name_descriptor(5, 1, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.operation_acquire_calls == 5);
    memset(&observed, 0, sizeof(observed));
    assert(kernel_socket_name_descriptor(5, -1, &observed) == 0);
    assert(memcmp(&observed, &address, sizeof(observed)) == 0);
    assert(mock.operation_socket_request_copy.operation ==
           KERNEL_SOCKET_OPERATION_NAME);
    assert(mock.operation_socket_request_copy
               .arguments.name_peer == 1);

    assert(mock.operation_acquire_calls == 6);
    assert(mock.operation_socket_calls == 6);
    assert(mock.operation_release_calls == 6);
    assert(mock.operation_references == 0);
}

static void test_socket_operation_error_precedence(void) {
    kernel_fd_backend_ops_t no_socket_ops = g_backend_ops;
    kernel_fd_operation_lease_t inactive_lease = {0};
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    kernel_socket_operation_result_t result;
    fd_backend_mock_t mock;

    initialize_socket_mock(&mock, &inactive_lease, 73);
    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);

    mock.operation_acquire_result = -EDGE_LINUX_EIO;
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) ==
           -EDGE_LINUX_EIO);
    require_socket_result_cleared(&result);
    assert(mock.operation_acquire_calls == 1);
    assert(mock.operation_socket_calls == 0);
    assert(mock.operation_release_calls == 0);

    mock.operation_acquire_result = 0;
    mock.operation_is_socket = 0;
    mock.operation_socket_dirty_error_result = 1;
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) ==
           -EDGE_LINUX_ENOTSOCK);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_calls == 1);
    assert(mock.operation_release_calls == 1);
    assert(mock.operation_references == 0);

    mock.operation_is_socket = 1;
    mock.operation_socket_result = -EDGE_LINUX_EAGAIN;
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) ==
           -EDGE_LINUX_EAGAIN);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_calls == 2);
    assert(mock.operation_release_calls == 2);
    assert(mock.operation_references == 0);

    mock.operation_socket_dirty_error_result = 0;
    mock.operation_socket_result = 0;
    mock.operation_release_result = -EDGE_LINUX_EIO;
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) ==
           -EDGE_LINUX_EIO);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_calls == 3);
    assert(mock.operation_release_calls == 3);
    assert(mock.operation_references == 0);

    mock.operation_socket_dirty_error_result = 1;
    mock.operation_socket_result = -EDGE_LINUX_EAGAIN;
    mock.operation_release_result = -EDGE_LINUX_ENOMEM;
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) ==
           -EDGE_LINUX_EAGAIN);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_calls == 4);
    assert(mock.operation_release_calls == 4);
    assert(mock.operation_references == 0);

    no_socket_ops.operation_socket = 0;
    assert(kernel_fd_backend_register(
               &no_socket_ops, &mock) == 0);
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_socket_operation_execute(
               5, &request, &result) ==
           -EDGE_LINUX_EOPNOTSUPP);
    require_socket_result_cleared(&result);
    assert(mock.operation_socket_calls == 4);
    assert(mock.operation_release_calls == 5);
    assert(mock.operation_references == 0);
    assert(mock.is_open_calls == 0);
}

static void test_socket_operation_lease_stability(void) {
    kernel_fd_backend_ops_t no_socket_ops = g_backend_ops;
    kernel_fd_operation_lease_t first_lease = {0};
    kernel_fd_operation_lease_t reused_lease = {0};
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_LISTEN,
        .arguments.listen_backlog = 8,
    };
    kernel_socket_operation_result_t result;
    fd_backend_mock_t first;
    fd_backend_mock_t reused;

    initialize_socket_mock(&first, &first_lease, 501);
    initialize_socket_mock(&reused, &reused_lease, 901);
    reused.socket_description.domain = 1;
    reused.socket_description.type = 2;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    assert(kernel_fd_operation_acquire(
               5, &first_lease) == 0);
    assert(kernel_fd_operation_socket_supported(
               &first_lease));

    /*
     * Closing the numeric slot and changing its current generation models a
     * concurrent CLONE_FILES user reusing descriptor 5. The first lease must
     * continue to target the generation captured before close.
     */
    assert(kernel_fd_close(5) == 0);
    assert(first.close_calls == 1);
    assert(first.close_descriptor == 5);
    assert(first.is_open_calls == 1);
    first.operation_generation = 777;

    assert(kernel_fd_backend_register(
               &g_backend_ops, &reused) == 0);
    assert(kernel_fd_operation_acquire(
               5, &reused_lease) == 0);
    assert(kernel_fd_operation_socket_supported(
               &reused_lease));

    no_socket_ops.operation_socket = 0;
    assert(kernel_fd_backend_register(
               &no_socket_ops, &reused) == 0);
    assert(!kernel_fd_operation_socket_available());
    assert(kernel_fd_operation_socket_supported(
               &first_lease));
    assert(kernel_fd_operation_socket_supported(
               &reused_lease));

    memset(&result, 0xa5, sizeof(result));
    assert(kernel_fd_operation_socket(
               &first_lease, &request, &result) == 0);
    require_socket_result_cleared(&result);
    assert(first.operation_socket_calls == 1);
    assert(first.operation_socket_generation == 501);
    assert(first.operation_acquire_calls == 1);
    assert(reused.operation_socket_calls == 0);

    request = (kernel_socket_operation_request_t){
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    memset(&result, 0xa5, sizeof(result));
    assert(kernel_fd_operation_socket(
               &reused_lease, &request, &result) == 0);
    assert(memcmp(
               &result.output.description,
               &reused.socket_description,
               sizeof(reused.socket_description)) == 0);
    assert(reused.operation_socket_calls == 1);
    assert(reused.operation_socket_generation == 901);
    assert(reused.operation_acquire_calls == 1);
    assert(first.is_open_calls == 1);
    assert(reused.is_open_calls == 0);

    assert(kernel_fd_operation_release(
               &first_lease) == 0);
    assert(first.operation_release_calls == 1);
    assert(first.operation_release_generation == 501);
    assert(kernel_fd_operation_release(
               &reused_lease) == 0);
    assert(reused.operation_release_calls == 1);
    assert(reused.operation_release_generation == 901);
    assert(first.operation_references == 0);
    assert(reused.operation_references == 0);
    assert(!kernel_fd_operation_socket_supported(
               &first_lease));
    assert(!kernel_fd_operation_socket_supported(
               &reused_lease));

    memset(&result, 0xa5, sizeof(result));
    assert(kernel_fd_operation_socket(
               &first_lease, &request, &result) ==
           -EDGE_LINUX_EINVAL);
    require_socket_result_cleared(&result);
    assert(kernel_fd_backend_register(
               &g_backend_ops, &reused) == 0);
    assert(kernel_fd_operation_socket_available());
}

static void test_operation_lease_transfer(void) {
    kernel_fd_backend_ops_t no_transfer_ops = g_backend_ops;
    kernel_fd_operation_lease_t source = {0};
    kernel_fd_operation_lease_t destination = {0};
    kernel_fd_operation_lease_t busy = {0};
    kernel_io_vector_request_t vector_request = {0};
    kernel_socket_operation_request_t socket_request = {
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    kernel_socket_operation_result_t socket_result;
    fd_backend_mock_t first;
    fd_backend_mock_t second;
    const fd_operation_mock_snapshot_t *snapshot;
    void *source_storage;

    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.allocation_limit = 64;
    first.operation_generation = 71;
    first.operation_is_socket = 1;
    first.operation_lease = &source;
    second.allocation_limit = 64;
    second.operation_generation = 99;
    second.operation_lease = &busy;

    no_transfer_ops.operation_transfer = 0;
    assert(kernel_fd_backend_register(
               &no_transfer_ops, &first) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    source_storage =
        (void *)(uintptr_t)kernel_fd_operation_view(&source);
    assert(source_storage);
    assert(kernel_fd_operation_transfer_from_backend(
               source_storage, &destination) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(kernel_fd_operation_view(&source) == source_storage);
    assert(!kernel_fd_operation_view(&destination));
    assert(first.operation_transfer_calls == 0);
    assert(kernel_fd_operation_release(&source) == 0);
    assert(first.operation_release_calls == 1);

    first.operation_lease = &source;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    source_storage =
        (void *)(uintptr_t)kernel_fd_operation_view(&source);
    assert(kernel_fd_backend_register(
               &g_backend_ops, &second) == 0);
    assert(kernel_fd_operation_acquire(5, &busy) == 0);
    assert(kernel_fd_operation_transfer_from_backend(
               source_storage, &busy) ==
           -EDGE_LINUX_EBUSY);
    assert(first.operation_transfer_calls == 0);
    assert(kernel_fd_operation_view(&source) == source_storage);
    assert(kernel_fd_operation_view(&busy));
    assert(kernel_fd_operation_release(&busy) == 0);
    assert(second.operation_release_calls == 1);
    first.operation_lease = &source;
    assert(kernel_fd_operation_release(&source) == 0);
    assert(first.operation_release_calls == 2);

    first.operation_lease = &source;
    first.operation_transfer_result = -EDGE_LINUX_EIO;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    source_storage =
        (void *)(uintptr_t)kernel_fd_operation_view(&source);
    assert(kernel_fd_operation_transfer_from_backend(
               source_storage, &destination) ==
           -EDGE_LINUX_EIO);
    assert(first.operation_transfer_calls == 1);
    assert(kernel_fd_operation_view(&source) == source_storage);
    assert(!kernel_fd_operation_view(&destination));
    assert(kernel_fd_operation_release(&source) == 0);
    assert(first.operation_release_calls == 3);

    first.operation_lease = &source;
    first.operation_transfer_result = 0;
    first.operation_generation = 123;
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    source_storage =
        (void *)(uintptr_t)kernel_fd_operation_view(&source);
    assert(kernel_fd_operation_transfer_from_backend(
               source_storage, &destination) == 0);
    assert(first.operation_transfer_calls == 2);
    assert(!kernel_fd_operation_view(&source));
    assert(kernel_fd_operation_release(&source) ==
           -EDGE_LINUX_EINVAL);
    snapshot = (const fd_operation_mock_snapshot_t *)
        kernel_fd_operation_view(&destination);
    assert(snapshot);
    assert(snapshot->marker == FD_OPERATION_MOCK_MARKER);
    assert(snapshot->object_generation == 123);
    assert(snapshot->descriptor == 5);
    assert(kernel_fd_operation_vector_io_supported(&destination));
    assert(kernel_fd_operation_socket_supported(&destination));
    first.operation_lease = &destination;
    first.operation_vector_io_result = 211;
    assert(kernel_fd_operation_vector_io(
               &destination, &vector_request) == 211);
    assert(first.operation_vector_io_calls == 1);
    first.socket_description.domain = 2;
    first.socket_description.type = 1;
    memset(&socket_result, 0xa5, sizeof(socket_result));
    assert(kernel_fd_operation_socket(
               &destination, &socket_request,
               &socket_result) == 0);
    assert(memcmp(
               &socket_result.output.description,
               &first.socket_description,
               sizeof(first.socket_description)) == 0);
    assert(first.operation_socket_calls == 1);
    assert(first.operation_socket_generation == 123);
    assert(kernel_fd_operation_release(&destination) == 0);
    assert(first.operation_release_calls == 4);
    assert(first.operation_release_generation == 123);
    assert(!kernel_fd_operation_view(&destination));
}

static void test_fd_transfer_target_lifecycle(void) {
    kernel_fd_operation_lease_t source = {0};
    kernel_fd_transfer_target_t target = {0};
    fd_backend_mock_t mock;
    const fd_operation_mock_snapshot_t *snapshot;
    int32_t descriptor = -1;
    int32_t first;
    int32_t second;
    int32_t duplicate[2];
    int32_t foreign = 400;
    int32_t negative = -1;

    memset(&mock, 0, sizeof(mock));
    mock.allocation_limit = 64;
    mock.operation_generation = 41;
    mock.operation_lease = &source;
    mock.next_transfer_descriptor = 20;
    mock.target_generation = 7;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);

    mock.transfer_target_capture_result =
        -EDGE_LINUX_ENOMEM;
    assert(kernel_fd_transfer_target_capture(&target) ==
           -EDGE_LINUX_ENOMEM);
    assert(mock.transfer_target_capture_calls == 1);
    assert(mock.target_references == 0);
    assert(kernel_fd_transfer_target_release(&target) ==
           -EDGE_LINUX_EINVAL);

    mock.transfer_target_capture_result = 0;
    assert(kernel_fd_transfer_target_capture(&target) == 0);
    assert(mock.transfer_target_capture_calls == 2);
    assert(mock.target_references == 1);
    assert(kernel_fd_transfer_target_capture(&target) ==
           -EDGE_LINUX_EBUSY);
    assert(mock.transfer_target_capture_calls == 2);

    assert(kernel_fd_transfer_target_prepare(
               0, &source, 0, &descriptor) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_prepare(
               &target, 0, 0, &descriptor) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, 0, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, 0, &descriptor) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.transfer_target_prepare_calls == 0);

    assert(kernel_fd_operation_acquire(5, &source) == 0);
    assert(mock.operation_references == 1);
    snapshot = (const fd_operation_mock_snapshot_t *)
        kernel_fd_operation_view(&source);
    assert(snapshot && snapshot->object_generation == 41);

    /*
     * Numeric close/reuse changes the backend's current generation, but every
     * repeated prepare must clone the generation held by the source lease.
     */
    mock.operation_generation = 99;
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, UINT32_MAX, &first) ==
           -EDGE_LINUX_EINVAL);
    assert(first == -1);
    assert(mock.transfer_target_prepare_calls == 0);
    assert(mock.hidden_references == 0);
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, KERNEL_FD_CLOEXEC,
               &first) == 0);
    assert(first == 20);
    assert(kernel_fd_operation_view(&source) == snapshot);
    assert(mock.operation_references == 1);
    assert(mock.hidden_references == 1);
    assert(mock.transfer_flags[first] ==
           KERNEL_FD_CLOEXEC);
    assert(mock.transfer_generation[first] == 41);

    assert(kernel_fd_transfer_target_prepare(
               &target, &source, 0, &second) == 0);
    assert(second == 21);
    assert(mock.operation_references == 1);
    assert(mock.hidden_references == 2);
    assert(mock.transfer_flags[second] == 0);
    assert(mock.transfer_generation[second] == 41);
    assert(kernel_fd_transfer_target_release(&target) ==
           -EDGE_LINUX_EBUSY);
    assert(mock.transfer_target_release_calls == 0);
    assert(kernel_fd_transfer_target_prepared_descriptor_at(
               &target, 0, &descriptor) == 0);
    assert(descriptor == first);
    assert(kernel_fd_transfer_target_prepared_descriptor_at(
               &target, 1, &descriptor) == 0);
    assert(descriptor == second);
    assert(kernel_fd_transfer_target_prepared_descriptor_at(
               &target, 2, &descriptor) ==
           -EDGE_LINUX_EINVAL);
    assert(descriptor == -1);

    duplicate[0] = first;
    duplicate[1] = first;
    assert(kernel_fd_transfer_target_publish_many(
               &target, 0, 1) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_publish_many(
               &target, &first, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_publish_many(
               &target, duplicate, 2) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_publish_many(
               &target, &foreign, 1) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_publish_many(
               &target, &negative, 1) ==
           -EDGE_LINUX_EBADF);
    assert(mock.transfer_target_publish_calls == 0);

    mock.transfer_target_publish_result =
        -EDGE_LINUX_EIO;
    assert(kernel_fd_transfer_target_publish_many(
               &target, (int32_t[]){first, second}, 2) ==
           -EDGE_LINUX_EIO);
    assert(mock.transfer_target_publish_calls == 1);
    assert(mock.hidden_references == 2);
    assert(mock.transfer_hidden[first]);
    assert(mock.transfer_hidden[second]);
    assert(!mock.transfer_published[first]);
    assert(!mock.transfer_published[second]);

    mock.transfer_target_abort_result =
        -EDGE_LINUX_EIO;
    assert(kernel_fd_transfer_target_abort_many(
               &target, (int32_t[]){first, second}, 2) ==
           -EDGE_LINUX_EIO);
    assert(mock.transfer_target_abort_calls == 1);
    assert(mock.hidden_references == 2);

    mock.transfer_target_abort_result = 0;
    assert(kernel_fd_transfer_target_abort_many(
               &target, &first, 1) == 0);
    assert(mock.hidden_references == 1);
    assert(!mock.transfer_hidden[first]);
    assert(mock.transfer_hidden[second]);
    assert(kernel_fd_transfer_target_abort_many(
               &target, &first, 1) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.transfer_target_abort_calls == 2);

    mock.transfer_target_publish_result = 0;
    assert(kernel_fd_transfer_target_publish_prefix(
               &target, 0) == -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_publish_prefix(
               &target, 2) == -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_publish_prefix(
               &target, 1) == 0);
    assert(mock.hidden_references == 0);
    assert(mock.published_references == 1);
    assert(mock.transfer_published[second]);
    assert(kernel_fd_transfer_target_abort_all(&target) == 0);

    assert(kernel_fd_operation_release(&source) == 0);
    assert(mock.operation_references == 0);
    assert(mock.published_references == 1);

    mock.transfer_target_release_result =
        -EDGE_LINUX_EIO;
    assert(kernel_fd_transfer_target_release(&target) ==
           -EDGE_LINUX_EIO);
    assert(mock.transfer_target_release_calls == 1);
    assert(mock.target_references == 1);
    mock.transfer_target_release_result = 0;
    assert(kernel_fd_transfer_target_release(&target) == 0);
    assert(mock.transfer_target_release_calls == 2);
    assert(mock.target_references == 0);
    assert(kernel_fd_transfer_target_release(&target) ==
           -EDGE_LINUX_EINVAL);

    /* The published clone is now owned solely by the mock receiving table. */
    mock.transfer_published[second] = 0;
    mock.transfer_generation[second] = 0;
    --mock.published_references;
    assert(mock.published_references == 0);
}

static void test_fd_transfer_target_prepare_rollback_and_limit(void) {
    kernel_fd_operation_lease_t source = {0};
    kernel_fd_transfer_target_t target = {0};
    fd_backend_mock_t mock;
    int32_t descriptors[KERNEL_FD_TRANSFER_MAX];
    int32_t descriptor = -1;

    memset(&mock, 0, sizeof(mock));
    mock.allocation_limit = 128;
    mock.operation_generation = 1234;
    mock.operation_lease = &source;
    mock.next_transfer_descriptor = 0;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    assert(kernel_fd_transfer_target_capture(&target) == 0);

    mock.transfer_target_prepare_result =
        -EDGE_LINUX_ENOMEM;
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, KERNEL_FD_CLOEXEC,
               &descriptor) ==
           -EDGE_LINUX_ENOMEM);
    assert(descriptor == -1);
    assert(mock.transfer_target_prepare_calls == 1);
    assert(mock.transfer_target_partial_rollbacks == 1);
    assert(mock.hidden_references == 0);
    assert(mock.operation_references == 1);
    assert(kernel_fd_operation_view(&source));

    mock.transfer_target_prepare_result = 0;
    for (uint32_t index = 0;
         index < KERNEL_FD_TRANSFER_MAX; ++index) {
        assert(kernel_fd_transfer_target_prepare(
                   &target, &source,
                   index & 1u ? KERNEL_FD_CLOEXEC : 0,
                   &descriptors[index]) == 0);
        assert(descriptors[index] == (int32_t)index + 1);
    }
    assert(mock.hidden_references ==
           KERNEL_FD_TRANSFER_MAX);
    descriptor = -1;
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, 0, &descriptor) ==
           -EDGE_LINUX_EMFILE);
    assert(descriptor == -1);
    assert(mock.transfer_target_prepare_calls ==
           KERNEL_FD_TRANSFER_MAX + 1u);

    assert(kernel_fd_transfer_target_publish_many(
               &target, descriptors,
               KERNEL_FD_TRANSFER_MAX + 1u) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_abort_many(
               &target, descriptors,
               KERNEL_FD_TRANSFER_MAX + 1u) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.transfer_target_publish_calls == 0);
    assert(mock.transfer_target_abort_calls == 0);
    assert(kernel_fd_transfer_target_abort_many(
               &target, descriptors,
               KERNEL_FD_TRANSFER_MAX) == 0);
    assert(mock.hidden_references == 0);
    assert(mock.transfer_target_abort_calls == 1);
    assert(kernel_fd_transfer_target_release(&target) == 0);
    assert(kernel_fd_operation_release(&source) == 0);
    assert(mock.target_references == 0);
    assert(mock.operation_references == 0);
}

static void test_fd_transfer_target_invalid_success_rollback(void) {
    kernel_fd_operation_lease_t source = {0};
    kernel_fd_transfer_target_t target = {0};
    fd_backend_mock_t mock;
    int32_t descriptor = -1;
    int32_t retained_descriptor = -1;

    memset(&mock, 0, sizeof(mock));
    mock.allocation_limit = 64;
    mock.operation_generation = 9001;
    mock.operation_lease = &source;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &mock) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    assert(kernel_fd_transfer_target_capture(&target) == 0);

    mock.transfer_target_prepare_output_override_enabled = 1;
    mock.transfer_target_prepare_output_override = -1;
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, 0, &descriptor) ==
           -EDGE_LINUX_EIO);
    assert(descriptor == -1);
    assert(mock.transfer_target_discard_calls == 1);
    assert(mock.hidden_references == 0);
    assert(!mock.transfer_hidden[0]);

    mock.transfer_target_prepare_output_override_enabled = 0;
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, 0,
               &retained_descriptor) == 0);
    assert(retained_descriptor == 1);
    assert(mock.hidden_references == 1);

    mock.transfer_target_prepare_output_override_enabled = 1;
    mock.transfer_target_prepare_output_override =
        retained_descriptor;
    assert(kernel_fd_transfer_target_prepare(
               &target, &source, KERNEL_FD_CLOEXEC,
               &descriptor) == -EDGE_LINUX_EIO);
    assert(descriptor == -1);
    assert(mock.transfer_target_discard_calls == 2);
    assert(mock.hidden_references == 1);
    assert(mock.transfer_hidden[retained_descriptor]);
    assert(!mock.transfer_hidden[2]);
    assert(kernel_fd_transfer_target_prepared_descriptor_at(
               &target, 0, &descriptor) == 0);
    assert(descriptor == retained_descriptor);
    assert(kernel_fd_transfer_target_prepared_descriptor_at(
               &target, 1, &descriptor) ==
           -EDGE_LINUX_EINVAL);

    assert(kernel_fd_transfer_target_abort_all(&target) == 0);
    assert(mock.hidden_references == 0);
    assert(kernel_fd_transfer_target_abort_all(&target) == 0);
    assert(kernel_fd_transfer_target_release(&target) == 0);
    assert(kernel_fd_operation_release(&source) == 0);
    assert(mock.target_references == 0);
    assert(mock.operation_references == 0);
}

static void test_fd_transfer_target_backend_identity_and_ownership(void) {
    kernel_fd_backend_ops_t copied_ops = g_backend_ops;
    kernel_fd_operation_lease_t source = {0};
    kernel_fd_transfer_target_t first_target = {0};
    kernel_fd_transfer_target_t second_target = {0};
    fd_backend_mock_t first;
    fd_backend_mock_t second;
    int32_t descriptor = -1;

    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.allocation_limit = 64;
    first.operation_generation = 71;
    first.operation_lease = &source;
    first.next_transfer_descriptor = 30;
    second.allocation_limit = 64;
    second.operation_generation = 88;
    second.operation_lease = &source;
    second.next_transfer_descriptor = 50;

    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    assert(kernel_fd_transfer_target_capture(
               &first_target) == 0);
    assert(kernel_fd_transfer_target_capture(
               &second_target) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    assert(kernel_fd_transfer_target_prepare(
               &first_target, &source, 0, &descriptor) == 0);
    assert(descriptor == 30);
    assert(kernel_fd_transfer_target_publish_many(
               &second_target, &descriptor, 1) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_fd_transfer_target_abort_many(
               &second_target, &descriptor, 1) ==
           -EDGE_LINUX_EINVAL);
    assert(first.transfer_target_publish_calls == 0);
    assert(first.transfer_target_abort_calls == 0);
    assert(kernel_fd_transfer_target_release(
               &second_target) == 0);
    assert(kernel_fd_transfer_target_abort_many(
               &first_target, &descriptor, 1) == 0);
    assert(kernel_fd_operation_release(&source) == 0);
    assert(kernel_fd_transfer_target_release(
               &first_target) == 0);

    memset(&source, 0, sizeof(source));
    memset(&first_target, 0, sizeof(first_target));
    first.operation_lease = &source;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    assert(kernel_fd_transfer_target_capture(
               &first_target) == 0);
    assert(kernel_fd_backend_register(
               &copied_ops, &first) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    assert(kernel_fd_transfer_target_prepare(
               &first_target, &source, 0, &descriptor) ==
           -EDGE_LINUX_EXDEV);
    assert(first.transfer_target_prepare_calls == 1);
    assert(kernel_fd_operation_release(&source) == 0);
    assert(kernel_fd_transfer_target_release(
               &first_target) == 0);

    memset(&source, 0, sizeof(source));
    memset(&first_target, 0, sizeof(first_target));
    first.operation_lease = &source;
    second.operation_lease = &source;
    assert(kernel_fd_backend_register(
               &g_backend_ops, &first) == 0);
    assert(kernel_fd_transfer_target_capture(
               &first_target) == 0);
    assert(kernel_fd_backend_register(
               &g_backend_ops, &second) == 0);
    assert(kernel_fd_operation_acquire(5, &source) == 0);
    assert(kernel_fd_transfer_target_prepare(
               &first_target, &source, 0, &descriptor) ==
           -EDGE_LINUX_EXDEV);
    assert(second.transfer_target_prepare_calls == 0);
    assert(kernel_fd_operation_release(&source) == 0);
    assert(kernel_fd_transfer_target_release(
               &first_target) == 0);
    assert(first.target_references == 0);
    assert(first.operation_references == 0);
    assert(second.operation_references == 0);
}

static void test_atomic_duplicate_minimum(void) {
    kernel_fd_backend_ops_t incomplete_ops = g_backend_ops;
    fd_backend_mock_t mock;
    int32_t result = -1;

    memset(&mock, 0, sizeof(mock));
    incomplete_ops.allocation_limit = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &mock) ==
           -EDGE_LINUX_EINVAL);
    incomplete_ops = g_backend_ops;
    incomplete_ops.duplicate_minimum = 0;
    assert(kernel_fd_backend_register(
               &incomplete_ops, &mock) ==
           -EDGE_LINUX_EINVAL);
    mock.allocation_limit = 64;
    mock.destination = 37;
    assert(kernel_fd_backend_register(&g_backend_ops, &mock) == 0);
    assert(kernel_fd_table_limit() == 128);
    assert(kernel_fd_allocation_limit() == 64);
    assert(kernel_fd_duplicate(
               5, 23, 0, UINT32_MAX, &result) == 0);
    assert(result == 37);
    assert(mock.duplicate_minimum_calls == 1);
    assert(mock.is_open_calls == 0);
    assert(mock.source == 5);
    assert(mock.minimum == 23);
    assert(mock.exclusive_limit == 64);
    assert(mock.descriptor_flags == KERNEL_FD_CLOEXEC);

    mock.duplicate_minimum_result = -EDGE_LINUX_EMFILE;
    result = -1;
    assert(kernel_fd_duplicate(
               5, 23, 0, 0, &result) ==
           -EDGE_LINUX_EMFILE);
    assert(result == -1);
    assert(mock.duplicate_minimum_calls == 2);
    assert(mock.is_open_calls == 0);

    assert(kernel_fd_duplicate(
               -1, 23, 0, 0, &result) ==
           -EDGE_LINUX_EBADF);
    assert(kernel_fd_duplicate(
               5, 128, 0, 0, &result) ==
           -EDGE_LINUX_EINVAL);
    assert(mock.duplicate_minimum_calls == 2);
    assert(mock.is_open_calls == 0);

    mock.allocation_limit = 256;
    assert(kernel_fd_allocation_limit() == 128);
}

int main(void) {
    test_invalid_initialization();
    test_commit();
    test_abort();
    test_publish_failure_aborts();
    test_operation_lease_without_backend();
    test_explicit_owner_routing();
    test_pid_routed_descriptor_policy();
    test_file_range_policy();
    test_operation_lease();
    test_socket_operation_validation_and_support();
    test_socket_operation_all_opcodes();
    test_socket_descriptor_wrappers();
    test_socket_operation_error_precedence();
    test_socket_operation_lease_stability();
    test_operation_lease_transfer();
    test_fd_transfer_target_lifecycle();
    test_fd_transfer_target_prepare_rollback_and_limit();
    test_fd_transfer_target_invalid_success_rollback();
    test_fd_transfer_target_backend_identity_and_ownership();
    test_atomic_duplicate_minimum();
    puts("fd_runtime_unit: PASS");
    return 0;
}
