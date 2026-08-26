/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral descriptor-table policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/fd_runtime.h"
#include "kernel/io_runtime.h"
#include "kernel/linux_abi.h"
#include "kernel/linux_errno.h"
#include "kernel/socket_runtime.h"
#include "vfs/vfs.h"

static const kernel_fd_backend_ops_t *g_backend_ops;
static void *g_backend_context;

enum kernel_fd_operation_lease_state {
    KERNEL_FD_OPERATION_LEASE_INACTIVE = 0,
    KERNEL_FD_OPERATION_LEASE_ACQUIRING,
    KERNEL_FD_OPERATION_LEASE_ACTIVE,
    KERNEL_FD_OPERATION_LEASE_RELEASING,
};

typedef struct fd_operation_lease_internal {
    kernel_fd_operation_lease_storage_t backend_storage;
    const kernel_fd_backend_ops_t *backend_ops;
    void *backend_context;
    kernel_fd_operation_release_fn backend_release;
    kernel_fd_operation_transfer_fn backend_transfer;
    kernel_fd_operation_description_id_fn
        backend_description_id;
    kernel_fd_operation_vector_io_fn backend_vector_io;
    kernel_fd_operation_socket_fn backend_socket;
    uint32_t state;
    uint32_t reserved;
} fd_operation_lease_internal_t;

_Static_assert(
    sizeof(fd_operation_lease_internal_t) <=
        sizeof(kernel_fd_operation_lease_t),
    "FD operation lease internal state exceeds opaque token");
_Static_assert(
    _Alignof(fd_operation_lease_internal_t) <=
        _Alignof(kernel_fd_operation_lease_t),
    "FD operation lease internal state exceeds token alignment");
_Static_assert(
    __builtin_offsetof(
        fd_operation_lease_internal_t, backend_storage) == 0,
    "backend storage must identify its operation lease");

static fd_operation_lease_internal_t *
fd_operation_lease_internal(
        kernel_fd_operation_lease_t *lease) {
    return (fd_operation_lease_internal_t *)(void *)lease;
}

static const fd_operation_lease_internal_t *
fd_operation_lease_internal_const(
        const kernel_fd_operation_lease_t *lease) {
    return (const fd_operation_lease_internal_t *)(const void *)lease;
}

static void fd_operation_lease_clear(
        fd_operation_lease_internal_t *lease) {
    if (!lease) return;
    for (uint32_t index = 0;
         index < KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE; ++index)
        lease->backend_storage.bytes[index] = 0;
    lease->backend_ops = 0;
    lease->backend_context = 0;
    lease->backend_release = 0;
    lease->backend_transfer = 0;
    lease->backend_description_id = 0;
    lease->backend_vector_io = 0;
    lease->backend_socket = 0;
    lease->reserved = 0;
}

static int fd_operation_acquire_internal(
        const void *owner, int32_t pid, int acquire_for_pid,
        kernel_fd_operation_acquire_fn publication_acquire,
        void *publication_context,
        int32_t descriptor,
        kernel_fd_operation_lease_t *lease) {
    fd_operation_lease_internal_t *internal;
    const kernel_fd_backend_ops_t *ops;
    void *context;
    uint32_t expected =
        KERNEL_FD_OPERATION_LEASE_INACTIVE;
    int result;

    if (!lease) return -EDGE_LINUX_EINVAL;
    internal = fd_operation_lease_internal(lease);
    if (!__atomic_compare_exchange_n(
            &internal->state, &expected,
            KERNEL_FD_OPERATION_LEASE_ACQUIRING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return -EDGE_LINUX_EBUSY;

    fd_operation_lease_clear(internal);
    ops = g_backend_ops;
    context = g_backend_context;
    if (!ops) {
        result = -EDGE_LINUX_ENODEV;
    } else if (descriptor < 0 ||
               (uint32_t)descriptor >=
                   ops->table_limit(context)) {
        result = -EDGE_LINUX_EBADF;
    } else if (publication_acquire) {
        result = publication_acquire(
            publication_context, descriptor,
            internal->backend_storage.bytes);
    } else if (owner) {
        result = ops->operation_acquire_for_owner ?
            ops->operation_acquire_for_owner(
                context, owner, descriptor,
                internal->backend_storage.bytes) :
            -EDGE_LINUX_EOPNOTSUPP;
    } else if (acquire_for_pid) {
        result = ops->operation_acquire_for_pid ?
            ops->operation_acquire_for_pid(
                context, pid, descriptor,
                internal->backend_storage.bytes) :
            -EDGE_LINUX_EOPNOTSUPP;
    } else {
        result = ops->operation_acquire(
            context, descriptor,
            internal->backend_storage.bytes);
    }
    if (result < 0) {
        fd_operation_lease_clear(internal);
        __atomic_store_n(
            &internal->state,
            KERNEL_FD_OPERATION_LEASE_INACTIVE,
            __ATOMIC_RELEASE);
        return result;
    }

    internal->backend_ops = ops;
    internal->backend_context = context;
    internal->backend_release = ops->operation_release;
    internal->backend_transfer = ops->operation_transfer;
    internal->backend_description_id =
        ops->operation_description_id;
    internal->backend_vector_io = ops->operation_vector_io;
    internal->backend_socket = ops->operation_socket;
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_OPERATION_LEASE_ACTIVE,
        __ATOMIC_RELEASE);
    return 0;
}

int kernel_fd_operation_acquire(
        int32_t descriptor,
        kernel_fd_operation_lease_t *lease) {
    return fd_operation_acquire_internal(
        0, 0, 0, 0, 0, descriptor, lease);
}

int kernel_fd_operation_acquire_for_owner(
        const void *owner, int32_t descriptor,
        kernel_fd_operation_lease_t *lease) {
    return fd_operation_acquire_internal(
        owner, 0, 0, 0, 0, descriptor, lease);
}

int kernel_fd_operation_acquire_for_pid(
        int32_t pid, int32_t descriptor,
        kernel_fd_operation_lease_t *lease) {
    return fd_operation_acquire_internal(
        0, pid, 1, 0, 0, descriptor, lease);
}

int kernel_fd_operation_acquire_from_publication(
        const kernel_fd_publication_t *publication,
        uint32_t index, kernel_fd_operation_lease_t *lease) {
    if (!publication || !publication->active ||
        !publication->descriptors || !publication->acquire ||
        index >= publication->count)
        return -EDGE_LINUX_EINVAL;
    return fd_operation_acquire_internal(
        0, 0, 0, publication->acquire,
        publication->context, publication->descriptors[index], lease);
}

const void *kernel_fd_operation_view(
        const kernel_fd_operation_lease_t *lease) {
    const fd_operation_lease_internal_t *internal;
    if (!lease) return 0;
    internal = fd_operation_lease_internal_const(lease);
    if (__atomic_load_n(
            &internal->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return 0;
    return internal->backend_storage.bytes;
}

int kernel_fd_operation_description_id(
        const kernel_fd_operation_lease_t *lease,
        uint64_t *description_id) {
    const fd_operation_lease_internal_t *internal;

    if (!lease || !description_id)
        return -EDGE_LINUX_EINVAL;
    internal = fd_operation_lease_internal_const(lease);
    if (__atomic_load_n(
            &internal->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return -EDGE_LINUX_EINVAL;
    if (!internal->backend_description_id)
        return -EDGE_LINUX_EOPNOTSUPP;
    *description_id = 0;
    return internal->backend_description_id(
        internal->backend_context,
        internal->backend_storage.bytes, description_id);
}

int kernel_fd_operation_ready(
        kernel_fd_operation_lease_t *lease, uint32_t operation) {
    fd_operation_lease_internal_t *internal;

    if (!lease) return -EDGE_LINUX_EINVAL;
    internal = fd_operation_lease_internal(lease);
    if (__atomic_load_n(
            &internal->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return -EDGE_LINUX_EINVAL;
    if (!internal->backend_ops ||
        !internal->backend_ops->operation_ready)
        return -EDGE_LINUX_EOPNOTSUPP;
    return internal->backend_ops->operation_ready(
        internal->backend_context,
        internal->backend_storage.bytes, operation);
}

int kernel_fd_operation_vector_io_available(void) {
    return g_backend_ops && g_backend_ops->operation_vector_io;
}

int kernel_fd_operation_vector_io_supported(
        const kernel_fd_operation_lease_t *lease) {
    const fd_operation_lease_internal_t *internal;

    if (!lease) return 0;
    internal = fd_operation_lease_internal_const(lease);
    return __atomic_load_n(
               &internal->state, __ATOMIC_ACQUIRE) ==
               KERNEL_FD_OPERATION_LEASE_ACTIVE &&
           internal->backend_vector_io != 0;
}

int64_t kernel_fd_operation_vector_io(
        kernel_fd_operation_lease_t *lease,
        const struct kernel_io_vector_request *request) {
    fd_operation_lease_internal_t *internal;

    if (!lease || !request) return -EDGE_LINUX_EINVAL;
    internal = fd_operation_lease_internal(lease);
    if (__atomic_load_n(
            &internal->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return -EDGE_LINUX_EINVAL;
    if (!internal->backend_vector_io)
        return -EDGE_LINUX_EOPNOTSUPP;
    return internal->backend_vector_io(
        internal->backend_context,
        internal->backend_storage.bytes, request);
}

int64_t kernel_fd_operation_file_range(
        kernel_fd_operation_lease_t *lease,
        const struct kernel_io_file_range_request *request) {
    fd_operation_lease_internal_t *internal;

    if (!lease || !request) return -EDGE_LINUX_EINVAL;
    internal = fd_operation_lease_internal(lease);
    if (__atomic_load_n(
            &internal->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return -EDGE_LINUX_EINVAL;
    /*
     * The immutable backend table is already retained by the lease and by
     * transfer targets. Dispatch through it so SCM_RIGHTS token size remains
     * fixed instead of caching another callback pointer in every lease.
     */
    if (!internal->backend_ops ||
        !internal->backend_ops->operation_file_range)
        return -EDGE_LINUX_EOPNOTSUPP;
    return internal->backend_ops->operation_file_range(
        internal->backend_context,
        internal->backend_storage.bytes, request);
}

static void fd_socket_operation_result_clear(
        struct kernel_socket_operation_result *result) {
    uint8_t *bytes = (uint8_t *)(void *)result;

    if (!result) return;
    for (uint64_t index = 0; index < sizeof(*result); ++index)
        bytes[index] = 0;
}

static int fd_socket_operation_request_validate(
        const struct kernel_socket_operation_request *request) {
    if (!request || request->reserved)
        return -EDGE_LINUX_EINVAL;

    switch (request->operation) {
        case KERNEL_SOCKET_OPERATION_DESCRIBE:
        case KERNEL_SOCKET_OPERATION_LISTEN:
            return 0;
        case KERNEL_SOCKET_OPERATION_SHUTDOWN:
            return request->arguments.shutdown_how >= 0 &&
                   request->arguments.shutdown_how <= 2 ?
                0 : -EDGE_LINUX_EINVAL;
        case KERNEL_SOCKET_OPERATION_BIND:
            return request->arguments.bind_address.length <=
                    sizeof(request->arguments.bind_address.bytes) ?
                0 : -EDGE_LINUX_EINVAL;
        case KERNEL_SOCKET_OPERATION_CONNECT:
            return request->arguments.connect.address.length <=
                    sizeof(request->arguments.connect.address.bytes) ?
                0 : -EDGE_LINUX_EINVAL;
        case KERNEL_SOCKET_OPERATION_NAME:
            return request->arguments.name_peer <= 1u ?
                0 : -EDGE_LINUX_EINVAL;
        default:
            return -EDGE_LINUX_EINVAL;
    }
}

int kernel_fd_operation_socket_available(void) {
    return g_backend_ops && g_backend_ops->operation_socket;
}

int kernel_fd_operation_socket_supported(
        const kernel_fd_operation_lease_t *lease) {
    const fd_operation_lease_internal_t *internal;

    if (!lease) return 0;
    internal = fd_operation_lease_internal_const(lease);
    return __atomic_load_n(
               &internal->state, __ATOMIC_ACQUIRE) ==
               KERNEL_FD_OPERATION_LEASE_ACTIVE &&
           internal->backend_socket != 0;
}

int64_t kernel_fd_operation_socket(
        kernel_fd_operation_lease_t *lease,
        const struct kernel_socket_operation_request *request,
        struct kernel_socket_operation_result *result) {
    fd_operation_lease_internal_t *internal;
    int64_t operation_result;
    int validation;

    if (!result)
        return -EDGE_LINUX_EINVAL;
    fd_socket_operation_result_clear(result);
    if (!lease || !request)
        return -EDGE_LINUX_EINVAL;
    validation = fd_socket_operation_request_validate(request);
    if (validation < 0) return validation;

    internal = fd_operation_lease_internal(lease);
    if (__atomic_load_n(
            &internal->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return -EDGE_LINUX_EINVAL;
    if (!internal->backend_socket)
        return -EDGE_LINUX_EOPNOTSUPP;
    operation_result = internal->backend_socket(
        internal->backend_context,
        internal->backend_storage.bytes, request, result);
    if (operation_result < 0)
        fd_socket_operation_result_clear(result);
    return operation_result;
}

int64_t kernel_socket_operation_execute(
        int32_t descriptor,
        const kernel_socket_operation_request_t *request,
        kernel_socket_operation_result_t *result) {
    kernel_fd_operation_lease_t lease = {0};
    int64_t operation_result;
    int release_result;
    int validation;
    int acquire_result;

    if (!result)
        return -EDGE_LINUX_EINVAL;
    fd_socket_operation_result_clear(result);
    if (!request)
        return -EDGE_LINUX_EINVAL;
    validation = fd_socket_operation_request_validate(request);
    if (validation < 0) return validation;

    acquire_result = kernel_fd_operation_acquire(descriptor, &lease);
    if (acquire_result < 0) return acquire_result;
    operation_result = kernel_fd_operation_socket(
        &lease, request, result);
    release_result = kernel_fd_operation_release(&lease);
    if (operation_result >= 0 && release_result < 0) {
        fd_socket_operation_result_clear(result);
        return release_result;
    }
    return operation_result;
}

int kernel_socket_describe_descriptor(
        int32_t descriptor, kernel_socket_descriptor_info_t *info) {
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_DESCRIBE,
    };
    kernel_socket_operation_result_t result;
    int64_t status;

    if (!info) return -EDGE_LINUX_EINVAL;
    status = kernel_socket_operation_execute(
        descriptor, &request, &result);
    if (status < 0) return (int)status;
    *info = result.output.description;
    return 0;
}

int64_t kernel_socket_listen_descriptor(
        int32_t descriptor, int32_t backlog) {
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_LISTEN,
        .arguments.listen_backlog = backlog,
    };
    kernel_socket_operation_result_t result;

    return kernel_socket_operation_execute(
        descriptor, &request, &result);
}

int64_t kernel_socket_shutdown_descriptor(
        int32_t descriptor, int32_t how) {
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_SHUTDOWN,
        .arguments.shutdown_how = how,
    };
    kernel_socket_operation_result_t result;

    return kernel_socket_operation_execute(
        descriptor, &request, &result);
}

int64_t kernel_socket_bind_descriptor(
        int32_t descriptor, const kernel_socket_address_t *address) {
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_BIND,
    };
    kernel_socket_operation_result_t result;

    if (address)
        request.arguments.bind_address = *address;
    return kernel_socket_operation_execute(
        descriptor, &request, &result);
}

int64_t kernel_socket_connect_descriptor(
        int32_t descriptor, const kernel_socket_address_t *address,
        void *user_registers) {
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_CONNECT,
    };
    kernel_socket_operation_result_t result;

    if (address)
        request.arguments.connect.address = *address;
    request.arguments.connect.user_registers = user_registers;
    return kernel_socket_operation_execute(
        descriptor, &request, &result);
}

int kernel_socket_name_descriptor(
        int32_t descriptor, int peer,
        kernel_socket_address_t *address) {
    kernel_socket_operation_request_t request = {
        .operation = KERNEL_SOCKET_OPERATION_NAME,
        .arguments.name_peer = peer != 0,
    };
    kernel_socket_operation_result_t result;
    int64_t status;

    if (!address) return -EDGE_LINUX_EINVAL;
    status = kernel_socket_operation_execute(
        descriptor, &request, &result);
    if (status < 0) return (int)status;
    *address = result.output.address;
    return 0;
}

int kernel_fd_operation_transfer_from_backend(
        void *source_storage,
        kernel_fd_operation_lease_t *destination) {
    fd_operation_lease_internal_t *source;
    fd_operation_lease_internal_t *target;
    uint32_t expected =
        KERNEL_FD_OPERATION_LEASE_INACTIVE;
    int result;

    if (!source_storage || !destination)
        return -EDGE_LINUX_EINVAL;
    source = (fd_operation_lease_internal_t *)source_storage;
    target = fd_operation_lease_internal(destination);
    if (source == target)
        return -EDGE_LINUX_EINVAL;
    if (__atomic_load_n(
            &source->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return -EDGE_LINUX_EINVAL;
    if (!source->backend_transfer)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (!__atomic_compare_exchange_n(
            &target->state, &expected,
            KERNEL_FD_OPERATION_LEASE_ACQUIRING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return -EDGE_LINUX_EBUSY;

    fd_operation_lease_clear(target);
    result = source->backend_transfer(
        source->backend_context,
        target->backend_storage.bytes,
        source->backend_storage.bytes);
    if (result < 0) {
        fd_operation_lease_clear(target);
        __atomic_store_n(
            &target->state,
            KERNEL_FD_OPERATION_LEASE_INACTIVE,
            __ATOMIC_RELEASE);
        return result;
    }

    target->backend_context = source->backend_context;
    target->backend_ops = source->backend_ops;
    target->backend_release = source->backend_release;
    target->backend_transfer = source->backend_transfer;
    target->backend_description_id =
        source->backend_description_id;
    target->backend_vector_io = source->backend_vector_io;
    target->backend_socket = source->backend_socket;
    source->backend_context = 0;
    source->backend_ops = 0;
    source->backend_release = 0;
    source->backend_transfer = 0;
    source->backend_description_id = 0;
    source->backend_vector_io = 0;
    source->backend_socket = 0;
    source->reserved = 0;
    __atomic_store_n(
        &target->state,
        KERNEL_FD_OPERATION_LEASE_ACTIVE,
        __ATOMIC_RELEASE);
    __atomic_store_n(
        &source->state,
        KERNEL_FD_OPERATION_LEASE_INACTIVE,
        __ATOMIC_RELEASE);
    return 0;
}

int kernel_fd_operation_move(
        kernel_fd_operation_lease_t *destination,
        kernel_fd_operation_lease_t *source) {
    const void *source_storage;

    if (!destination || !source || destination == source)
        return -EDGE_LINUX_EINVAL;
    source_storage = kernel_fd_operation_view(source);
    if (!source_storage) return -EDGE_LINUX_EINVAL;
    return kernel_fd_operation_transfer_from_backend(
        (void *)(uintptr_t)source_storage, destination);
}

int kernel_fd_operation_clone(
        kernel_fd_operation_lease_t *destination,
        const kernel_fd_operation_lease_t *source_lease) {
    fd_operation_lease_internal_t *target;
    const fd_operation_lease_internal_t *source;
    uint32_t expected = KERNEL_FD_OPERATION_LEASE_INACTIVE;
    int result;

    if (!destination || !source_lease || destination == source_lease)
        return -EDGE_LINUX_EINVAL;
    source = fd_operation_lease_internal_const(source_lease);
    target = fd_operation_lease_internal(destination);
    if (__atomic_load_n(
            &source->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE)
        return -EDGE_LINUX_EINVAL;
    if (!source->backend_ops || !source->backend_ops->operation_clone)
        return -EDGE_LINUX_EOPNOTSUPP;
    if (!__atomic_compare_exchange_n(
            &target->state, &expected,
            KERNEL_FD_OPERATION_LEASE_ACQUIRING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return -EDGE_LINUX_EBUSY;

    fd_operation_lease_clear(target);
    result = source->backend_ops->operation_clone(
        source->backend_context,
        target->backend_storage.bytes,
        source->backend_storage.bytes);
    if (result < 0) {
        fd_operation_lease_clear(target);
        __atomic_store_n(
            &target->state,
            KERNEL_FD_OPERATION_LEASE_INACTIVE,
            __ATOMIC_RELEASE);
        return result;
    }
    target->backend_ops = source->backend_ops;
    target->backend_context = source->backend_context;
    target->backend_release = source->backend_release;
    target->backend_transfer = source->backend_transfer;
    target->backend_description_id = source->backend_description_id;
    target->backend_vector_io = source->backend_vector_io;
    target->backend_socket = source->backend_socket;
    __atomic_store_n(
        &target->state,
        KERNEL_FD_OPERATION_LEASE_ACTIVE,
        __ATOMIC_RELEASE);
    return 0;
}

int kernel_fd_operation_release(
        kernel_fd_operation_lease_t *lease) {
    fd_operation_lease_internal_t *internal;
    kernel_fd_operation_release_fn release;
    void *context;
    uint32_t expected =
        KERNEL_FD_OPERATION_LEASE_ACTIVE;
    int result;

    if (!lease) return -EDGE_LINUX_EINVAL;
    internal = fd_operation_lease_internal(lease);
    if (!__atomic_compare_exchange_n(
            &internal->state, &expected,
            KERNEL_FD_OPERATION_LEASE_RELEASING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
        return expected == KERNEL_FD_OPERATION_LEASE_INACTIVE ?
            -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBUSY;
    }

    release = internal->backend_release;
    context = internal->backend_context;
    result = release ?
        release(context, internal->backend_storage.bytes) :
        -EDGE_LINUX_EINVAL;
    fd_operation_lease_clear(internal);
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_OPERATION_LEASE_INACTIVE,
        __ATOMIC_RELEASE);
    return result;
}

enum kernel_fd_transfer_target_state {
    KERNEL_FD_TRANSFER_TARGET_INACTIVE = 0,
    KERNEL_FD_TRANSFER_TARGET_CAPTURING,
    KERNEL_FD_TRANSFER_TARGET_ACTIVE,
    KERNEL_FD_TRANSFER_TARGET_OPERATING,
    KERNEL_FD_TRANSFER_TARGET_RELEASING,
};

typedef struct fd_transfer_target_internal {
    kernel_fd_transfer_target_storage_t backend_storage;
    const kernel_fd_backend_ops_t *backend_ops;
    void *backend_context;
    int32_t prepared_descriptors[KERNEL_FD_TRANSFER_MAX];
    uint32_t state;
    uint32_t prepared_count;
} fd_transfer_target_internal_t;

_Static_assert(
    sizeof(fd_transfer_target_internal_t) <=
        sizeof(kernel_fd_transfer_target_t),
    "FD transfer target internal state exceeds opaque token");
_Static_assert(
    _Alignof(fd_transfer_target_internal_t) <=
        _Alignof(kernel_fd_transfer_target_t),
    "FD transfer target internal state exceeds token alignment");
_Static_assert(
    __builtin_offsetof(
        fd_transfer_target_internal_t, backend_storage) == 0,
    "backend storage must identify its FD transfer target");

static fd_transfer_target_internal_t *
fd_transfer_target_internal(
        kernel_fd_transfer_target_t *target) {
    return (fd_transfer_target_internal_t *)(void *)target;
}

static void fd_transfer_target_clear(
        fd_transfer_target_internal_t *target) {
    if (!target) return;
    for (uint32_t index = 0;
         index < KERNEL_FD_TRANSFER_TARGET_STORAGE_SIZE; ++index)
        target->backend_storage.bytes[index] = 0;
    target->backend_ops = 0;
    target->backend_context = 0;
    for (uint32_t index = 0;
         index < KERNEL_FD_TRANSFER_MAX; ++index)
        target->prepared_descriptors[index] = -1;
    target->prepared_count = 0;
}

static int fd_transfer_target_enter(
        fd_transfer_target_internal_t *target) {
    uint32_t expected = KERNEL_FD_TRANSFER_TARGET_ACTIVE;

    if (__atomic_compare_exchange_n(
            &target->state, &expected,
            KERNEL_FD_TRANSFER_TARGET_OPERATING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return 0;
    return expected == KERNEL_FD_TRANSFER_TARGET_INACTIVE ?
        -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBUSY;
}

static int fd_transfer_target_descriptor_tracked(
        const fd_transfer_target_internal_t *target,
        int32_t descriptor) {
    for (uint32_t index = 0;
         index < target->prepared_count; ++index)
        if (target->prepared_descriptors[index] == descriptor)
            return 1;
    return 0;
}

static int fd_transfer_target_batch_valid(
        const fd_transfer_target_internal_t *target,
        const int32_t *descriptors, uint32_t count) {
    if (!count || count > KERNEL_FD_TRANSFER_MAX ||
        count > target->prepared_count || !descriptors)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if (descriptors[index] < 0)
            return -EDGE_LINUX_EBADF;
        if (!fd_transfer_target_descriptor_tracked(
                target, descriptors[index]))
            return -EDGE_LINUX_EINVAL;
        for (uint32_t previous = 0;
             previous < index; ++previous)
            if (descriptors[previous] == descriptors[index])
                return -EDGE_LINUX_EINVAL;
    }
    return 0;
}

static void fd_transfer_target_remove_batch(
        fd_transfer_target_internal_t *target,
        const int32_t *descriptors, uint32_t count) {
    uint32_t output = 0;

    for (uint32_t index = 0;
         index < target->prepared_count; ++index) {
        int selected = 0;
        for (uint32_t batch_index = 0;
             batch_index < count; ++batch_index)
            if (target->prepared_descriptors[index] ==
                descriptors[batch_index]) {
                selected = 1;
                break;
            }
        if (!selected)
            target->prepared_descriptors[output++] =
                target->prepared_descriptors[index];
    }
    for (uint32_t index = output;
         index < target->prepared_count; ++index)
        target->prepared_descriptors[index] = -1;
    target->prepared_count = output;
}

static void fd_transfer_target_remove_prefix(
        fd_transfer_target_internal_t *target,
        uint32_t count) {
    uint32_t remaining = target->prepared_count - count;

    for (uint32_t index = 0; index < remaining; ++index)
        target->prepared_descriptors[index] =
            target->prepared_descriptors[index + count];
    for (uint32_t index = remaining;
         index < target->prepared_count; ++index)
        target->prepared_descriptors[index] = -1;
    target->prepared_count = remaining;
}

static int fd_transfer_target_capture_internal(
        const void *owner,
        kernel_fd_transfer_target_t *target) {
    fd_transfer_target_internal_t *internal;
    const kernel_fd_backend_ops_t *ops;
    void *context;
    uint32_t expected = KERNEL_FD_TRANSFER_TARGET_INACTIVE;
    int result;

    if (!target) return -EDGE_LINUX_EINVAL;
    internal = fd_transfer_target_internal(target);
    if (!__atomic_compare_exchange_n(
            &internal->state, &expected,
            KERNEL_FD_TRANSFER_TARGET_CAPTURING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return -EDGE_LINUX_EBUSY;
    fd_transfer_target_clear(internal);

    ops = g_backend_ops;
    context = g_backend_context;
    if (!ops) {
        result = -EDGE_LINUX_ENODEV;
    } else if (owner) {
        result = ops->transfer_target_capture_for_owner ?
            ops->transfer_target_capture_for_owner(
                context, owner,
                internal->backend_storage.bytes) :
            -EDGE_LINUX_EOPNOTSUPP;
    } else {
        result = ops->transfer_target_capture(
            context, internal->backend_storage.bytes);
    }
    if (result < 0) {
        fd_transfer_target_clear(internal);
        __atomic_store_n(
            &internal->state,
            KERNEL_FD_TRANSFER_TARGET_INACTIVE,
            __ATOMIC_RELEASE);
        return result;
    }

    internal->backend_ops = ops;
    internal->backend_context = context;
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return 0;
}

int kernel_fd_transfer_target_capture(
        kernel_fd_transfer_target_t *target) {
    return fd_transfer_target_capture_internal(0, target);
}

int kernel_fd_transfer_target_capture_for_owner(
        const void *owner,
        kernel_fd_transfer_target_t *target) {
    return fd_transfer_target_capture_internal(
        owner, target);
}

int kernel_fd_transfer_target_capture_for_pid(
        int32_t pid, kernel_fd_transfer_target_t *target) {
    fd_transfer_target_internal_t *internal;
    const kernel_fd_backend_ops_t *ops;
    void *context;
    uint32_t expected = KERNEL_FD_TRANSFER_TARGET_INACTIVE;
    int result;

    if (!target) return -EDGE_LINUX_EINVAL;
    internal = fd_transfer_target_internal(target);
    if (!__atomic_compare_exchange_n(
            &internal->state, &expected,
            KERNEL_FD_TRANSFER_TARGET_CAPTURING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return -EDGE_LINUX_EBUSY;
    fd_transfer_target_clear(internal);
    ops = g_backend_ops;
    context = g_backend_context;
    result = ops && ops->transfer_target_capture_for_pid ?
        ops->transfer_target_capture_for_pid(
            context, pid, internal->backend_storage.bytes) :
        -EDGE_LINUX_EOPNOTSUPP;
    if (result < 0) {
        fd_transfer_target_clear(internal);
        __atomic_store_n(
            &internal->state, KERNEL_FD_TRANSFER_TARGET_INACTIVE,
            __ATOMIC_RELEASE);
        return result;
    }
    internal->backend_ops = ops;
    internal->backend_context = context;
    __atomic_store_n(
        &internal->state, KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return 0;
}

static int fd_transfer_target_prepare_internal(
        kernel_fd_transfer_target_t *target,
        const kernel_fd_operation_lease_t *source,
        uint32_t descriptor_flags, int32_t requested_descriptor,
        int32_t *descriptor) {
    fd_transfer_target_internal_t *target_internal;
    const fd_operation_lease_internal_t *source_internal;
    int result;

    if (!target || !source || !descriptor)
        return -EDGE_LINUX_EINVAL;
    *descriptor = -1;
    if (descriptor_flags & ~KERNEL_FD_CLOEXEC)
        return -EDGE_LINUX_EINVAL;
    target_internal = fd_transfer_target_internal(target);
    result = fd_transfer_target_enter(target_internal);
    if (result < 0) return result;
    if (target_internal->prepared_count >=
        KERNEL_FD_TRANSFER_MAX) {
        result = -EDGE_LINUX_EMFILE;
        goto leave_target;
    }

    source_internal = fd_operation_lease_internal_const(source);
    if (__atomic_load_n(
            &source_internal->state, __ATOMIC_ACQUIRE) !=
        KERNEL_FD_OPERATION_LEASE_ACTIVE) {
        result = -EDGE_LINUX_EINVAL;
        goto leave_target;
    }
    if (source_internal->backend_ops !=
            target_internal->backend_ops ||
        source_internal->backend_context !=
            target_internal->backend_context) {
        result = -EDGE_LINUX_EXDEV;
        goto leave_target;
    }

    if (requested_descriptor >= 0) {
        if (!target_internal->backend_ops->transfer_target_prepare_exact) {
            result = -EDGE_LINUX_EOPNOTSUPP;
            goto leave_target;
        }
        result = target_internal->backend_ops->transfer_target_prepare_exact(
            target_internal->backend_context,
            target_internal->backend_storage.bytes,
            source_internal->backend_storage.bytes,
            descriptor_flags, requested_descriptor, descriptor);
    } else {
        result = target_internal->backend_ops->transfer_target_prepare(
            target_internal->backend_context,
            target_internal->backend_storage.bytes,
            source_internal->backend_storage.bytes,
            descriptor_flags, descriptor);
    }
    if (result < 0) {
        *descriptor = -1;
        goto leave_target;
    }
    if (*descriptor < 0 ||
        fd_transfer_target_descriptor_tracked(
            target_internal, *descriptor)) {
        target_internal->backend_ops->
            transfer_target_discard_prepared(
                target_internal->backend_context,
                target_internal->backend_storage.bytes);
        *descriptor = -1;
        result = -EDGE_LINUX_EIO;
        goto leave_target;
    }

    target_internal->prepared_descriptors[
        target_internal->prepared_count++] = *descriptor;

leave_target:
    __atomic_store_n(
        &target_internal->state,
        KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return result;
}

int kernel_fd_transfer_target_prepare(
        kernel_fd_transfer_target_t *target,
        const kernel_fd_operation_lease_t *source,
        uint32_t descriptor_flags, int32_t *descriptor) {
    return fd_transfer_target_prepare_internal(
        target, source, descriptor_flags, -1, descriptor);
}

int kernel_fd_transfer_target_prepare_exact(
        kernel_fd_transfer_target_t *target,
        const kernel_fd_operation_lease_t *source,
        uint32_t descriptor_flags, int32_t requested_descriptor,
        int32_t *descriptor) {
    if (requested_descriptor < 0) return -EDGE_LINUX_EBADF;
    return fd_transfer_target_prepare_internal(
        target, source, descriptor_flags, requested_descriptor,
        descriptor);
}

int kernel_fd_transfer_target_prepared_descriptor_at(
        const kernel_fd_transfer_target_t *target,
        uint32_t index, int32_t *descriptor) {
    fd_transfer_target_internal_t *internal;
    int result;

    if (!target || !descriptor)
        return -EDGE_LINUX_EINVAL;
    *descriptor = -1;
    internal = fd_transfer_target_internal(
        (kernel_fd_transfer_target_t *)(void *)target);
    result = fd_transfer_target_enter(internal);
    if (result < 0) return result;
    if (index >= internal->prepared_count) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        *descriptor = internal->prepared_descriptors[index];
        result = 0;
    }
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return result;
}

int kernel_fd_transfer_target_publish_many(
        kernel_fd_transfer_target_t *target,
        const int32_t *descriptors, uint32_t count) {
    fd_transfer_target_internal_t *internal;
    int result;

    if (!target) return -EDGE_LINUX_EINVAL;
    internal = fd_transfer_target_internal(target);
    result = fd_transfer_target_enter(internal);
    if (result < 0) return result;
    result = fd_transfer_target_batch_valid(
        internal, descriptors, count);
    if (result == 0)
        result =
            internal->backend_ops->transfer_target_publish_many(
                internal->backend_context,
                internal->backend_storage.bytes,
                descriptors, count);
    if (result == 0)
        fd_transfer_target_remove_batch(
            internal, descriptors, count);
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return result;
}

int kernel_fd_transfer_target_publish_prefix(
        kernel_fd_transfer_target_t *target, uint32_t count) {
    fd_transfer_target_internal_t *internal;
    int result;

    if (!target) return -EDGE_LINUX_EINVAL;
    internal = fd_transfer_target_internal(target);
    result = fd_transfer_target_enter(internal);
    if (result < 0) return result;
    if (!count || count > internal->prepared_count) {
        result = -EDGE_LINUX_EINVAL;
    } else {
        result =
            internal->backend_ops->transfer_target_publish_many(
                internal->backend_context,
                internal->backend_storage.bytes,
                internal->prepared_descriptors, count);
        if (result == 0)
            fd_transfer_target_remove_prefix(internal, count);
    }
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return result;
}

int kernel_fd_transfer_target_abort_many(
        kernel_fd_transfer_target_t *target,
        const int32_t *descriptors, uint32_t count) {
    fd_transfer_target_internal_t *internal;
    int result;

    if (!target) return -EDGE_LINUX_EINVAL;
    internal = fd_transfer_target_internal(target);
    result = fd_transfer_target_enter(internal);
    if (result < 0) return result;
    result = fd_transfer_target_batch_valid(
        internal, descriptors, count);
    if (result == 0)
        result =
            internal->backend_ops->transfer_target_abort_many(
                internal->backend_context,
                internal->backend_storage.bytes,
                descriptors, count);
    if (result == 0)
        fd_transfer_target_remove_batch(
            internal, descriptors, count);
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return result;
}

int kernel_fd_transfer_target_abort_all(
        kernel_fd_transfer_target_t *target) {
    fd_transfer_target_internal_t *internal;
    int result;

    if (!target) return -EDGE_LINUX_EINVAL;
    internal = fd_transfer_target_internal(target);
    result = fd_transfer_target_enter(internal);
    if (result < 0) return result;
    if (!internal->prepared_count) {
        result = 0;
    } else {
        result =
            internal->backend_ops->transfer_target_abort_many(
                internal->backend_context,
                internal->backend_storage.bytes,
                internal->prepared_descriptors,
                internal->prepared_count);
        if (result == 0)
            fd_transfer_target_remove_prefix(
                internal, internal->prepared_count);
    }
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_TRANSFER_TARGET_ACTIVE,
        __ATOMIC_RELEASE);
    return result;
}

int kernel_fd_transfer_target_release(
        kernel_fd_transfer_target_t *target) {
    fd_transfer_target_internal_t *internal;
    uint32_t expected = KERNEL_FD_TRANSFER_TARGET_ACTIVE;
    int result;

    if (!target) return -EDGE_LINUX_EINVAL;
    internal = fd_transfer_target_internal(target);
    if (!__atomic_compare_exchange_n(
            &internal->state, &expected,
            KERNEL_FD_TRANSFER_TARGET_RELEASING, 0,
            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return expected == KERNEL_FD_TRANSFER_TARGET_INACTIVE ?
            -EDGE_LINUX_EINVAL : -EDGE_LINUX_EBUSY;
    if (internal->prepared_count) {
        __atomic_store_n(
            &internal->state,
            KERNEL_FD_TRANSFER_TARGET_ACTIVE,
            __ATOMIC_RELEASE);
        return -EDGE_LINUX_EBUSY;
    }

    result = internal->backend_ops->transfer_target_release(
        internal->backend_context,
        internal->backend_storage.bytes);
    if (result < 0) {
        __atomic_store_n(
            &internal->state,
            KERNEL_FD_TRANSFER_TARGET_ACTIVE,
            __ATOMIC_RELEASE);
        return result;
    }
    fd_transfer_target_clear(internal);
    __atomic_store_n(
        &internal->state,
        KERNEL_FD_TRANSFER_TARGET_INACTIVE,
        __ATOMIC_RELEASE);
    return 0;
}

static void fd_publication_clear(
        kernel_fd_publication_t *publication) {
    if (!publication) return;
    publication->descriptors = 0;
    publication->context = 0;
    publication->publish = 0;
    publication->abort = 0;
    publication->acquire = 0;
    publication->count = 0;
    publication->active = 0;
    publication->reserved[0] = 0;
    publication->reserved[1] = 0;
    publication->reserved[2] = 0;
}

int kernel_fd_publication_initialize(
    kernel_fd_publication_t *publication,
    const int32_t *descriptors, uint32_t count,
    void *context,
    kernel_fd_publication_publish_fn publish,
    kernel_fd_publication_abort_fn abort) {
    if (!publication)
        return -EDGE_LINUX_EINVAL;
    if (publication->active)
        return -EDGE_LINUX_EBUSY;
    fd_publication_clear(publication);
    if (!descriptors || !count || !publish || !abort)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < count; ++index) {
        if (descriptors[index] < 0)
            return -EDGE_LINUX_EBADF;
        for (uint32_t previous = 0;
             previous < index; ++previous) {
            if (descriptors[previous] == descriptors[index])
                return -EDGE_LINUX_EINVAL;
        }
    }
    publication->descriptors = descriptors;
    publication->context = context;
    publication->publish = publish;
    publication->abort = abort;
    publication->count = count;
    publication->active = 1u;
    return 0;
}

int kernel_fd_publication_commit(
        kernel_fd_publication_t *publication) {
    kernel_fd_publication_abort_fn abort;
    kernel_fd_publication_publish_fn publish;
    const int32_t *descriptors;
    void *context;
    uint32_t count;
    int result;

    if (!publication || !publication->active ||
        !publication->descriptors || !publication->count ||
        !publication->publish || !publication->abort)
        return -EDGE_LINUX_EINVAL;
    descriptors = publication->descriptors;
    context = publication->context;
    publish = publication->publish;
    abort = publication->abort;
    count = publication->count;
    result = publish(context, descriptors, count);
    if (result < 0)
        abort(context, descriptors, count);
    fd_publication_clear(publication);
    return result;
}

int kernel_fd_publication_set_acquire(
        kernel_fd_publication_t *publication,
        kernel_fd_publication_acquire_fn acquire) {
    if (!publication || !publication->active || !acquire)
        return -EDGE_LINUX_EINVAL;
    publication->acquire = acquire;
    return 0;
}

int kernel_fd_publication_abort(
        kernel_fd_publication_t *publication) {
    kernel_fd_publication_abort_fn abort;
    const int32_t *descriptors;
    void *context;
    uint32_t count;

    if (!publication || !publication->active ||
        !publication->descriptors || !publication->count ||
        !publication->abort)
        return -EDGE_LINUX_EINVAL;
    descriptors = publication->descriptors;
    context = publication->context;
    abort = publication->abort;
    count = publication->count;
    abort(context, descriptors, count);
    fd_publication_clear(publication);
    return 0;
}

int kernel_fd_backend_register(const kernel_fd_backend_ops_t *ops,
                               void *context) {
    if (!ops || !ops->table_limit || !ops->allocation_limit ||
        !ops->table_unshare ||
        !ops->is_open ||
        !ops->operation_acquire || !ops->operation_release ||
        !ops->transfer_target_capture ||
        !ops->transfer_target_release ||
        !ops->transfer_target_prepare ||
        !ops->transfer_target_discard_prepared ||
        !ops->transfer_target_publish_many ||
        !ops->transfer_target_abort_many ||
        !ops->close || !ops->duplicate_exact ||
        !ops->duplicate_minimum ||
        !ops->get_descriptor_flags || !ops->set_descriptor_flags ||
        !ops->get_status_flags || !ops->set_status_flags ||
        !ops->pipe_capacity ||
        !ops->pidfd_lookup || !ops->pidfd_install ||
        !ops->pidfd_target ||
        !ops->fcntl_fallback)
        return -EDGE_LINUX_EINVAL;
    g_backend_ops = ops;
    g_backend_context = context;
    return 0;
}

static uint32_t fd_limit(void) {
    return g_backend_ops ?
        g_backend_ops->table_limit(g_backend_context) : 0u;
}

static uint32_t fd_allocation_limit(void) {
    uint32_t allocation_limit;
    uint32_t table_limit;

    if (!g_backend_ops) return 0u;
    table_limit = fd_limit();
    allocation_limit =
        g_backend_ops->allocation_limit(g_backend_context);
    return allocation_limit < table_limit ?
        allocation_limit : table_limit;
}

static int fd_number_valid(int32_t descriptor) {
    return descriptor >= 0 && (uint32_t)descriptor < fd_limit();
}

uint32_t kernel_fd_table_limit(void) {
    return fd_limit();
}

uint32_t kernel_fd_allocation_limit(void) {
    return fd_allocation_limit();
}

int kernel_fd_table_unshare(void) {
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    return g_backend_ops->table_unshare(g_backend_context);
}

int kernel_fd_is_open(int32_t descriptor) {
    return g_backend_ops && fd_number_valid(descriptor) &&
        g_backend_ops->is_open(g_backend_context, descriptor);
}

int kernel_fd_close(int32_t descriptor) {
    if (!g_backend_ops || !fd_number_valid(descriptor) ||
        !g_backend_ops->is_open(g_backend_context, descriptor))
        return -EDGE_LINUX_EBADF;
    return g_backend_ops->close(g_backend_context, descriptor);
}

int kernel_fd_duplicate(int32_t source, int32_t target, int exact,
                        uint32_t descriptor_flags, int32_t *result) {
    uint32_t allocation_limit;
    uint32_t limit;
    int32_t destination;
    int status;

    if (!result) return -EDGE_LINUX_EINVAL;
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    limit = fd_limit();
    allocation_limit = fd_allocation_limit();
    if (source < 0 || (uint32_t)source >= limit)
        return -EDGE_LINUX_EBADF;
    if (!exact) {
        if (target < 0 || (uint32_t)target >= limit)
            return -EDGE_LINUX_EINVAL;
        status = g_backend_ops->duplicate_minimum(
            g_backend_context, source, target, allocation_limit,
            descriptor_flags & KERNEL_FD_CLOEXEC,
            &destination);
        if (status < 0) return status;
        if (destination < target ||
            (uint32_t)destination >= allocation_limit)
            return -EDGE_LINUX_EIO;
        *result = destination;
        return 0;
    }
    if (target < 0 || (uint32_t)target >= limit)
        return -EDGE_LINUX_EBADF;
    if (!g_backend_ops->is_open(g_backend_context, source))
        return -EDGE_LINUX_EBADF;
    if (source == target) {
        *result = source;
        return 0;
    }
    if ((uint32_t)target >= allocation_limit)
        return -EDGE_LINUX_EBADF;

    destination = target;
    status = g_backend_ops->duplicate_exact(
        g_backend_context, source, destination,
        descriptor_flags & KERNEL_FD_CLOEXEC);
    if (status < 0) return status;
    *result = destination;
    return 0;
}

int kernel_fd_get_descriptor_flags(int32_t descriptor, uint32_t *flags) {
    int status;
    if (!flags) return -EDGE_LINUX_EINVAL;
    if (!g_backend_ops || !fd_number_valid(descriptor) ||
        !g_backend_ops->is_open(g_backend_context, descriptor))
        return -EDGE_LINUX_EBADF;
    status = g_backend_ops->get_descriptor_flags(
        g_backend_context, descriptor, flags);
    if (status == 0) *flags &= KERNEL_FD_CLOEXEC;
    return status;
}

int kernel_fd_set_descriptor_flags(int32_t descriptor, uint32_t flags) {
    if (!g_backend_ops || !fd_number_valid(descriptor) ||
        !g_backend_ops->is_open(g_backend_context, descriptor))
        return -EDGE_LINUX_EBADF;
    return g_backend_ops->set_descriptor_flags(
        g_backend_context, descriptor, flags & KERNEL_FD_CLOEXEC);
}

int kernel_fd_get_status_flags(int32_t descriptor, uint32_t *flags) {
    if (!flags) return -EDGE_LINUX_EINVAL;
    if (!g_backend_ops || !fd_number_valid(descriptor) ||
        !g_backend_ops->is_open(g_backend_context, descriptor))
        return -EDGE_LINUX_EBADF;
    return g_backend_ops->get_status_flags(
        g_backend_context, descriptor, flags);
}

int kernel_fd_update_status_flags(int32_t descriptor, uint32_t mask,
                                  uint32_t flags) {
    uint32_t current;
    int status;
    if (!g_backend_ops || !fd_number_valid(descriptor) ||
        !g_backend_ops->is_open(g_backend_context, descriptor))
        return -EDGE_LINUX_EBADF;
    status = g_backend_ops->get_status_flags(
        g_backend_context, descriptor, &current);
    if (status < 0) return status;
    current = (current & ~mask) | (flags & mask);
    return g_backend_ops->set_status_flags(
        g_backend_context, descriptor, current);
}

int64_t kernel_fd_fcntl_fallback(int32_t descriptor, uint32_t command,
                                 uint64_t argument) {
    uint32_t capacity;
    int status;

    if (!g_backend_ops || !fd_number_valid(descriptor) ||
        !g_backend_ops->is_open(g_backend_context, descriptor))
        return -EDGE_LINUX_EBADF;
    if (command == KERNEL_FD_GETPIPE_SZ ||
        command == KERNEL_FD_SETPIPE_SZ) {
        status = g_backend_ops->pipe_capacity(
            g_backend_context, descriptor, &capacity);
        if (status < 0) return status;
        if (command == KERNEL_FD_GETPIPE_SZ) return capacity;
        if (!argument || argument > UINT32_MAX)
            return -EDGE_LINUX_EINVAL;
        if (argument > capacity)
            return -EDGE_LINUX_EPERM;
        return capacity;
    }
    return g_backend_ops->fcntl_fallback(
        g_backend_context, descriptor, command, argument);
}

int kernel_pidfd_open(int32_t pid, uint32_t flags) {
    int32_t target_tgid;
    int status;
    if (!g_backend_ops) return -EDGE_LINUX_ENODEV;
    status = g_backend_ops->pidfd_lookup(
        g_backend_context, pid, &target_tgid);
    if (status < 0) return status;
    if (!(flags & EDGE_LINUX_PIDFD_THREAD) &&
        target_tgid != pid)
        return -EDGE_LINUX_EINVAL;
    return g_backend_ops->pidfd_install(
        g_backend_context, pid, flags);
}

int kernel_pidfd_target(int32_t descriptor, int32_t *pid,
                        uint32_t *flags) {
    if (!pid || !flags) return -EDGE_LINUX_EBADF;
    if (!g_backend_ops || !fd_number_valid(descriptor) ||
        !g_backend_ops->is_open(g_backend_context, descriptor))
        return -EDGE_LINUX_EBADF;
    return g_backend_ops->pidfd_target(
        g_backend_context, descriptor, pid, flags);
}

int kernel_pidfd_getfd(int32_t pid, int32_t target_descriptor,
                       int32_t *result) {
    kernel_fd_operation_lease_t source = {0};
    kernel_fd_transfer_target_t target = {0};
    int32_t descriptor = -1;
    int source_active = 0;
    int target_active = 0;
    int prepared = 0;
    int published = 0;
    int status;
    int cleanup_status;

    if (!result) return -EDGE_LINUX_ESRCH;
    *result = -1;
    status = kernel_fd_operation_acquire_for_pid(
        pid, target_descriptor, &source);
    if (status < 0) return status;
    source_active = 1;

    status = kernel_fd_transfer_target_capture(&target);
    if (status < 0) goto cleanup;
    target_active = 1;
    status = kernel_fd_transfer_target_prepare(
        &target, &source, KERNEL_FD_CLOEXEC, &descriptor);
    if (status < 0) goto cleanup;
    prepared = 1;
    status = kernel_fd_transfer_target_publish_many(
        &target, &descriptor, 1u);
    if (status < 0) goto cleanup;
    prepared = 0;
    published = 1;

cleanup:
    if (prepared) {
        cleanup_status = kernel_fd_transfer_target_abort_all(
            &target);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (target_active) {
        cleanup_status = kernel_fd_transfer_target_release(
            &target);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (source_active) {
        cleanup_status = kernel_fd_operation_release(&source);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (status < 0) return status;
    *result = descriptor;
    return 0;
}

int kernel_fd_operation_materialize(
        const kernel_fd_operation_lease_t *source,
        uint32_t descriptor_flags, int32_t *descriptor) {
    kernel_fd_transfer_target_t target = {0};
    int target_active = 0;
    int prepared = 0;
    int published = 0;
    int status;
    int cleanup_status;

    if (!source || !descriptor) return -EDGE_LINUX_EINVAL;
    *descriptor = -1;
    status = kernel_fd_transfer_target_capture(&target);
    if (status < 0) return status;
    target_active = 1;
    status = kernel_fd_transfer_target_prepare(
        &target, source, descriptor_flags, descriptor);
    if (status < 0) goto cleanup;
    prepared = 1;
    status = kernel_fd_transfer_target_publish_many(
        &target, descriptor, 1u);
    if (status < 0) goto cleanup;
    prepared = 0;
    published = 1;

cleanup:
    if (prepared) {
        cleanup_status = kernel_fd_transfer_target_abort_all(&target);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (target_active) {
        cleanup_status = kernel_fd_transfer_target_release(&target);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (status < 0) *descriptor = -1;
    return status;
}

int kernel_fd_copy_to_pid(
        int32_t source_descriptor, int32_t target_pid,
        int32_t requested_descriptor, int exact,
        uint32_t descriptor_flags, int32_t *result) {
    kernel_fd_operation_lease_t source = {0};
    kernel_fd_transfer_target_t target = {0};
    int32_t descriptor = -1;
    int source_active = 0;
    int target_active = 0;
    int prepared = 0;
    int published = 0;
    int status;
    int cleanup_status;

    if (!result) return -EDGE_LINUX_EINVAL;
    *result = -1;
    status = kernel_fd_operation_acquire(source_descriptor, &source);
    if (status < 0) return status;
    source_active = 1;
    status = kernel_fd_transfer_target_capture_for_pid(
        target_pid, &target);
    if (status < 0) goto cleanup;
    target_active = 1;
    status = exact ? kernel_fd_transfer_target_prepare_exact(
        &target, &source, descriptor_flags, requested_descriptor,
        &descriptor) : kernel_fd_transfer_target_prepare(
        &target, &source, descriptor_flags, &descriptor);
    if (status < 0) goto cleanup;
    prepared = 1;
    status = kernel_fd_transfer_target_publish_many(
        &target, &descriptor, 1u);
    if (status < 0) goto cleanup;
    prepared = 0;
    published = 1;

cleanup:
    if (prepared) {
        cleanup_status = kernel_fd_transfer_target_abort_all(&target);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (target_active) {
        cleanup_status = kernel_fd_transfer_target_release(&target);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (source_active) {
        cleanup_status = kernel_fd_operation_release(&source);
        if (!published && status >= 0 && cleanup_status < 0)
            status = cleanup_status;
    }
    if (status < 0) return status;
    *result = descriptor;
    return 0;
}

int kernel_process_fd_description_id(int32_t pid, int32_t descriptor,
                                     uint64_t *description_id) {
    kernel_fd_operation_lease_t lease = {0};
    int status;
    int release_status;

    if (!description_id) return -EDGE_LINUX_EFAULT;
    *description_id = 0;
    status = kernel_fd_operation_acquire_for_pid(
        pid, descriptor, &lease);
    if (status < 0) return status;
    status = kernel_fd_operation_description_id(
        &lease, description_id);
    release_status = kernel_fd_operation_release(&lease);
    if (status >= 0 && release_status < 0)
        status = release_status;
    if (status < 0) *description_id = 0;
    return status;
}

static int64_t fd_file_range_execute(
        int32_t descriptor,
        const kernel_io_file_range_request_t *request) {
    kernel_fd_operation_lease_t lease = {0};
    int64_t result;
    int release_result;
    int status;

    status = kernel_fd_operation_acquire(descriptor, &lease);
    if (status < 0) return status;
    result = kernel_fd_operation_file_range(&lease, request);
    release_result = kernel_fd_operation_release(&lease);
    if (result == 0 && release_result < 0)
        result = release_result;
    return result;
}

int kernel_io_file_range_query(
        int32_t descriptor,
        kernel_io_file_range_info_t *information) {
    kernel_io_file_range_request_t request = {
        .operation = KERNEL_IO_FILE_RANGE_QUERY,
        .information = information,
    };
    int64_t result;

    if (!information) return -EDGE_LINUX_EBADF;
    result = fd_file_range_execute(descriptor, &request);
    return (int)result;
}

int64_t kernel_io_file_range_read(
        int32_t descriptor, uint64_t offset,
        void *buffer, uint32_t length) {
    kernel_io_file_range_request_t request = {
        .operation = KERNEL_IO_FILE_RANGE_READ,
        .offset = offset,
        .buffer = buffer,
        .length = length,
    };

    return fd_file_range_execute(descriptor, &request);
}

int64_t kernel_io_file_range_write(
        int32_t descriptor, uint64_t offset,
        const void *buffer, uint32_t length) {
    kernel_io_file_range_request_t request = {
        .operation = KERNEL_IO_FILE_RANGE_WRITE,
        .offset = offset,
        .buffer = (void *)(uintptr_t)buffer,
        .length = length,
    };

    return fd_file_range_execute(descriptor, &request);
}

int kernel_io_file_range_commit_offset(
        int32_t descriptor, uint64_t offset) {
    kernel_io_file_range_request_t request = {
        .operation = KERNEL_IO_FILE_RANGE_COMMIT_OFFSET,
        .offset = offset,
    };
    int64_t result =
        fd_file_range_execute(descriptor, &request);

    return (int)result;
}

void kernel_io_file_range_complete_write(int32_t descriptor) {
    kernel_io_file_range_request_t request = {
        .operation = KERNEL_IO_FILE_RANGE_COMPLETE_WRITE,
    };

    (void)fd_file_range_execute(descriptor, &request);
}

int kernel_io_file_range_sync(int32_t descriptor, int data_only) {
    kernel_io_file_range_request_t request = {
        .operation = data_only ? KERNEL_IO_FILE_RANGE_SYNC_DATA :
                                 KERNEL_IO_FILE_RANGE_SYNC_FILE,
    };

    return (int)fd_file_range_execute(descriptor, &request);
}
