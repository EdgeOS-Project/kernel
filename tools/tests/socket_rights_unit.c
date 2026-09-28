/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS SCM_RIGHTS pool unit tests.
 * Copyright (c) EdgeOS Contributors.
 */

#include <assert.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Kernel spinlocks disable interrupts, which is not legal in a host process.
 * Keep the production implementation unchanged and substitute a host lock
 * before including the common source files.
 */
#define SYS_SPINLOCK_H
typedef struct {
    atomic_flag value;
    atomic_uint held;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    atomic_flag_clear_explicit(
        &lock->value, memory_order_relaxed);
    atomic_store_explicit(
        &lock->held, 0u, memory_order_relaxed);
}

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (atomic_flag_test_and_set_explicit(
               &lock->value, memory_order_acquire))
        sched_yield();
    atomic_store_explicit(
        &lock->held, 1u, memory_order_release);
    return 0;
}

static inline void spin_unlock_irqrestore(
        spinlock_t *lock, uint64_t flags) {
    (void)flags;
    atomic_store_explicit(
        &lock->held, 0u, memory_order_release);
    atomic_flag_clear_explicit(
        &lock->value, memory_order_release);
}

static int spinlock_is_held(const spinlock_t *lock) {
    return atomic_load_explicit(
        &lock->held, memory_order_acquire) != 0u;
}

#include "kernel/fd_runtime.h"
#include "kernel/linux_errno.h"
#include "kernel/linux_time.h"
#include "kernel/socket_message.h"
#include "kernel/socket_rights.h"

uint64_t boottime_monotonic_us(void) {
    return 0;
}

uint64_t boottime_realtime_us(void) {
    return 0;
}

void linux_timespec_from_microseconds(
        uint64_t microseconds,
        linux_timespec64_t *value) {
    assert(value);
    value->tv_sec = (int64_t)(microseconds / 1000000u);
    value->tv_nsec =
        (int64_t)(microseconds % 1000000u) * 1000;
}

void linux_timeval_from_microseconds(
        uint64_t microseconds,
        linux_timeval64_t *value) {
    assert(value);
    value->tv_sec = (int64_t)(microseconds / 1000000u);
    value->tv_usec =
        (int64_t)(microseconds % 1000000u);
}

int64_t edge_socket_runtime_message_execute(
        const kernel_socket_message_request_t *request) {
    (void)request;
    return -EDGE_LINUX_ENOSYS;
}

#include "../../src/kernel/fd_runtime.c"
#include "../../src/kernel/socket_message.c"
#include "../../src/kernel/socket_rights.c"

#define MOCK_DESCRIPTOR_LIMIT 64u
#define MOCK_OBJECT_LIMIT 16u
#define CONTROL_BUFFER_SIZE 4096u

typedef struct mock_fd_snapshot {
    uint64_t tag;
    uint32_t object;
    int32_t source_descriptor;
} mock_fd_snapshot_t;

typedef struct mock_fd_object {
    uint64_t tag;
    uint32_t references;
} mock_fd_object_t;

typedef struct mock_fd_backend {
    int32_t descriptors[MOCK_DESCRIPTOR_LIMIT];
    mock_fd_object_t objects[MOCK_OBJECT_LIMIT];
    kernel_socket_rights_pool_t *checked_pool;
    uint32_t acquire_calls;
    uint32_t owner_acquire_calls;
    uint32_t release_calls;
    const void *last_owner;
} mock_fd_backend_t;

typedef struct pool_fixture {
    kernel_socket_rights_pool_t pool;
    void *arena;
} pool_fixture_t;

typedef struct control_builder {
    uint8_t bytes[CONTROL_BUFFER_SIZE];
    uint64_t length;
} control_builder_t;

typedef struct copy_context {
    uint64_t fault_address;
    uint64_t fault_length;
} copy_context_t;

static mock_fd_backend_t g_mock;

_Static_assert(
    sizeof(mock_fd_snapshot_t) <=
        KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE,
    "mock descriptor snapshot exceeds lease storage");

static void mock_require_pool_unlocked(void) {
    if (g_mock.checked_pool)
        assert(!spinlock_is_held(
            &g_mock.checked_pool->lock));
}

static uint32_t mock_table_limit(void *opaque) {
    assert(opaque == &g_mock);
    return MOCK_DESCRIPTOR_LIMIT;
}

static uint32_t mock_allocation_limit(void *opaque) {
    assert(opaque == &g_mock);
    return MOCK_DESCRIPTOR_LIMIT;
}

static int mock_table_unshare(void *opaque) {
    assert(opaque == &g_mock);
    return 0;
}

static int mock_is_open(
        void *opaque, int32_t descriptor) {
    mock_fd_backend_t *mock =
        (mock_fd_backend_t *)opaque;

    return descriptor >= 0 &&
        (uint32_t)descriptor < MOCK_DESCRIPTOR_LIMIT &&
        mock->descriptors[descriptor] >= 0;
}

static int mock_operation_acquire(
        void *opaque, int32_t descriptor, void *storage) {
    mock_fd_backend_t *mock =
        (mock_fd_backend_t *)opaque;
    mock_fd_snapshot_t *snapshot =
        (mock_fd_snapshot_t *)storage;
    int32_t object;

    assert(mock == &g_mock);
    assert(storage);
    assert((uintptr_t)storage %
        KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT == 0);
    mock_require_pool_unlocked();
    if (descriptor < 0 ||
        (uint32_t)descriptor >= MOCK_DESCRIPTOR_LIMIT)
        return -EDGE_LINUX_EBADF;
    object = mock->descriptors[descriptor];
    if (object < 0 ||
        (uint32_t)object >= MOCK_OBJECT_LIMIT)
        return -EDGE_LINUX_EBADF;
    snapshot->tag = mock->objects[object].tag;
    snapshot->object = (uint32_t)object;
    snapshot->source_descriptor = descriptor;
    ++mock->objects[object].references;
    ++mock->acquire_calls;
    return 0;
}

static int mock_operation_acquire_for_owner(
        void *opaque, const void *owner,
        int32_t descriptor, void *storage) {
    mock_fd_backend_t *mock =
        (mock_fd_backend_t *)opaque;

    assert(owner);
    ++mock->owner_acquire_calls;
    mock->last_owner = owner;
    return mock_operation_acquire(
        opaque, descriptor, storage);
}

static int mock_operation_release(
        void *opaque, void *storage) {
    mock_fd_backend_t *mock =
        (mock_fd_backend_t *)opaque;
    mock_fd_snapshot_t *snapshot =
        (mock_fd_snapshot_t *)storage;

    assert(mock == &g_mock);
    assert(snapshot);
    mock_require_pool_unlocked();
    assert(snapshot->object < MOCK_OBJECT_LIMIT);
    assert(mock->objects[snapshot->object].references > 0);
    --mock->objects[snapshot->object].references;
    ++mock->release_calls;
    return 0;
}

static int mock_transfer_target_capture(
        void *opaque, void *target_storage) {
    assert(opaque == &g_mock);
    assert(target_storage);
    memset(target_storage, 0,
           KERNEL_FD_TRANSFER_TARGET_STORAGE_SIZE);
    return 0;
}

static int mock_transfer_target_release(
        void *opaque, void *target_storage) {
    assert(opaque == &g_mock);
    assert(target_storage);
    return 0;
}

static int mock_transfer_target_prepare(
        void *opaque, void *target_storage,
        const void *source_storage,
        uint32_t descriptor_flags,
        int32_t *descriptor) {
    (void)opaque;
    (void)target_storage;
    (void)source_storage;
    (void)descriptor_flags;
    (void)descriptor;
    return -EDGE_LINUX_EOPNOTSUPP;
}

static void mock_transfer_target_discard_prepared(
        void *opaque, void *target_storage) {
    (void)opaque;
    (void)target_storage;
    assert(!"unreachable successful transfer prepare");
}

static int mock_transfer_target_publish_many(
        void *opaque, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    (void)opaque;
    (void)target_storage;
    (void)descriptors;
    (void)count;
    return 0;
}

static int mock_transfer_target_abort_many(
        void *opaque, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    (void)opaque;
    (void)target_storage;
    (void)descriptors;
    (void)count;
    return 0;
}

static int mock_close(
        void *opaque, int32_t descriptor) {
    mock_fd_backend_t *mock =
        (mock_fd_backend_t *)opaque;
    int32_t object;

    assert(mock == &g_mock);
    if (!mock_is_open(mock, descriptor))
        return -EDGE_LINUX_EBADF;
    object = mock->descriptors[descriptor];
    assert(mock->objects[object].references > 0);
    --mock->objects[object].references;
    mock->descriptors[descriptor] = -1;
    return 0;
}

static int mock_duplicate_exact(
        void *opaque, int32_t source,
        int32_t destination,
        uint32_t descriptor_flags) {
    (void)opaque;
    (void)source;
    (void)destination;
    (void)descriptor_flags;
    return -EDGE_LINUX_ENOSYS;
}

static int mock_duplicate_minimum(
        void *opaque, int32_t source,
        int32_t minimum, uint32_t exclusive_limit,
        uint32_t descriptor_flags,
        int32_t *destination) {
    (void)opaque;
    (void)source;
    (void)minimum;
    (void)exclusive_limit;
    (void)descriptor_flags;
    (void)destination;
    return -EDGE_LINUX_ENOSYS;
}

static int mock_get_flags(
        void *opaque, int32_t descriptor,
        uint32_t *flags) {
    (void)opaque;
    (void)descriptor;
    if (!flags) return -EDGE_LINUX_EINVAL;
    *flags = 0;
    return 0;
}

static int mock_set_flags(
        void *opaque, int32_t descriptor,
        uint32_t flags) {
    (void)opaque;
    (void)descriptor;
    (void)flags;
    return 0;
}

static int mock_pipe_capacity(
        void *opaque, int32_t descriptor,
        uint32_t *capacity) {
    (void)opaque;
    (void)descriptor;
    if (!capacity) return -EDGE_LINUX_EINVAL;
    *capacity = 65536u;
    return 0;
}

static int mock_pidfd_lookup(
        void *opaque, int32_t pid, int32_t *tgid) {
    (void)opaque;
    if (!tgid) return -EDGE_LINUX_EINVAL;
    *tgid = pid;
    return 0;
}

static int mock_pidfd_install(
        void *opaque, int32_t pid, uint32_t flags) {
    (void)opaque;
    (void)pid;
    (void)flags;
    return -EDGE_LINUX_ENOSYS;
}

static int mock_pidfd_target(
        void *opaque, int32_t descriptor,
        int32_t *pid, uint32_t *flags) {
    (void)opaque;
    (void)descriptor;
    if (!pid || !flags) return -EDGE_LINUX_EINVAL;
    *pid = 1;
    *flags = 0;
    return 0;
}

static int64_t mock_fcntl_fallback(
        void *opaque, int32_t descriptor,
        uint32_t command, uint64_t argument) {
    (void)opaque;
    (void)descriptor;
    (void)command;
    (void)argument;
    return -EDGE_LINUX_ENOSYS;
}

static const kernel_fd_backend_ops_t g_mock_backend_ops = {
    .table_limit = mock_table_limit,
    .allocation_limit = mock_allocation_limit,
    .table_unshare = mock_table_unshare,
    .is_open = mock_is_open,
    .operation_acquire = mock_operation_acquire,
    .operation_acquire_for_owner =
        mock_operation_acquire_for_owner,
    .operation_release = mock_operation_release,
    .transfer_target_capture =
        mock_transfer_target_capture,
    .transfer_target_release =
        mock_transfer_target_release,
    .transfer_target_prepare =
        mock_transfer_target_prepare,
    .transfer_target_discard_prepared =
        mock_transfer_target_discard_prepared,
    .transfer_target_publish_many =
        mock_transfer_target_publish_many,
    .transfer_target_abort_many =
        mock_transfer_target_abort_many,
    .close = mock_close,
    .duplicate_exact = mock_duplicate_exact,
    .duplicate_minimum = mock_duplicate_minimum,
    .get_descriptor_flags = mock_get_flags,
    .set_descriptor_flags = mock_set_flags,
    .get_status_flags = mock_get_flags,
    .set_status_flags = mock_set_flags,
    .pipe_capacity = mock_pipe_capacity,
    .pidfd_lookup = mock_pidfd_lookup,
    .pidfd_install = mock_pidfd_install,
    .pidfd_target = mock_pidfd_target,
    .fcntl_fallback = mock_fcntl_fallback,
};

static void mock_reset(void) {
    memset(&g_mock, 0, sizeof(g_mock));
    for (uint32_t index = 0;
         index < MOCK_DESCRIPTOR_LIMIT; ++index)
        g_mock.descriptors[index] = -1;
}

static void mock_install(
        int32_t descriptor, uint32_t object,
        uint64_t tag) {
    assert(descriptor >= 0);
    assert((uint32_t)descriptor <
           MOCK_DESCRIPTOR_LIMIT);
    assert(object < MOCK_OBJECT_LIMIT);
    assert(g_mock.descriptors[descriptor] < 0);
    assert(g_mock.objects[object].references == 0);
    g_mock.objects[object].tag = tag;
    g_mock.objects[object].references = 1;
    g_mock.descriptors[descriptor] = (int32_t)object;
}

static void fixture_initialize(
        pool_fixture_t *fixture,
        uint32_t token_capacity,
        uint32_t record_capacity) {
    uint64_t bytes =
        kernel_socket_rights_pool_required_bytes(
            token_capacity, record_capacity);

    assert(fixture);
    assert(bytes);
    memset(fixture, 0, sizeof(*fixture));
    fixture->arena = malloc((size_t)bytes);
    assert(fixture->arena);
    assert(kernel_socket_rights_pool_initialize(
               &fixture->pool, fixture->arena, bytes,
               token_capacity, record_capacity) == 0);
    g_mock.checked_pool = &fixture->pool;
}

static void fixture_destroy(pool_fixture_t *fixture) {
    kernel_socket_rights_pool_statistics_t statistics;

    assert(kernel_socket_rights_pool_statistics(
               &fixture->pool, &statistics) == 0);
    assert(statistics.free_tokens ==
           statistics.token_capacity);
    assert(statistics.free_records ==
           statistics.record_capacity);
    g_mock.checked_pool = 0;
    free(fixture->arena);
    fixture->arena = 0;
}

static uint64_t control_align(uint64_t length) {
    return (length + 7u) & ~UINT64_C(7);
}

static void control_initialize(
        control_builder_t *builder) {
    memset(builder, 0, sizeof(*builder));
}

static void control_append(
        control_builder_t *builder,
        int32_t level, int32_t type,
        const int32_t *descriptors,
        uint32_t descriptor_count) {
    struct edge_linux_cmsghdr header;
    uint64_t data_bytes =
        (uint64_t)descriptor_count *
        sizeof(descriptors[0]);
    uint64_t length = sizeof(header) + data_bytes;
    uint64_t aligned = control_align(length);

    assert(builder);
    assert(!descriptor_count || descriptors);
    assert(builder->length <=
           CONTROL_BUFFER_SIZE - aligned);
    memset(&header, 0, sizeof(header));
    header.cmsg_len = length;
    header.cmsg_level = level;
    header.cmsg_type = type;
    memcpy(&builder->bytes[builder->length],
           &header, sizeof(header));
    if (data_bytes)
        memcpy(&builder->bytes[
                   builder->length + sizeof(header)],
               descriptors, (size_t)data_bytes);
    builder->length += aligned;
}

static int test_copy_from_user(
        void *opaque, void *destination,
        uint64_t source, uint64_t size) {
    copy_context_t *context =
        (copy_context_t *)opaque;

    if (!destination || (!source && size))
        return -1;
    if (context && context->fault_length) {
        uint64_t fault_end =
            context->fault_address +
            context->fault_length;
        uint64_t copy_end = source + size;

        if (fault_end >= context->fault_address &&
            copy_end >= source &&
            source < fault_end &&
            context->fault_address < copy_end)
            return -1;
    }
    memcpy(destination,
           (const void *)(uintptr_t)source,
           (size_t)size);
    return 0;
}

static void fill_descriptors(
        int32_t *descriptors,
        uint32_t count, int32_t descriptor) {
    for (uint32_t index = 0; index < count; ++index)
        descriptors[index] = descriptor;
}

static void require_pool_fully_free(
        kernel_socket_rights_pool_t *pool) {
    kernel_socket_rights_pool_statistics_t statistics;

    assert(kernel_socket_rights_pool_statistics(
               pool, &statistics) == 0);
    assert(statistics.free_tokens ==
           statistics.token_capacity);
    assert(statistics.free_records ==
           statistics.record_capacity);
}

static void test_memory_layout_and_initialization(void) {
    pool_fixture_t fixture;
    uint64_t expected =
        (uint64_t)KERNEL_SOCKET_RIGHTS_DEFAULT_TOKEN_CAPACITY *
            592u +
        (uint64_t)KERNEL_SOCKET_RIGHTS_DEFAULT_RECORD_CAPACITY *
            32u +
        KERNEL_FD_OPERATION_LEASE_STORAGE_ALIGNMENT - 1u;

    assert(sizeof(kernel_socket_rights_queue_t) == 24u);
    assert(kernel_socket_rights_pool_required_bytes(
               KERNEL_SOCKET_RIGHTS_DEFAULT_TOKEN_CAPACITY,
               KERNEL_SOCKET_RIGHTS_DEFAULT_RECORD_CAPACITY) ==
           expected);
    assert(kernel_socket_rights_pool_required_bytes(
               1, 0) == 0);
    assert(kernel_socket_rights_pool_required_bytes(
               UINT32_MAX, 1) == 0);
    fixture_initialize(&fixture, 2, 3);
    require_pool_fully_free(&fixture.pool);
    assert(kernel_socket_rights_pool_initialize(
               &fixture.pool, fixture.arena,
               kernel_socket_rights_pool_required_bytes(2, 3),
               2, 3) ==
           -EDGE_LINUX_EBUSY);
    fixture_destroy(&fixture);
}

static void test_empty_record_and_generation_reuse(void) {
    pool_fixture_t fixture;
    kernel_socket_rights_record_handle_t first = 0;
    kernel_socket_rights_record_handle_t stale;
    kernel_socket_rights_record_handle_t second = 0;
    kernel_socket_rights_record_info_t information;
    kernel_socket_rights_token_cursor_t cursor;
    const kernel_fd_operation_lease_t *lease = 0;
    uint32_t source_index = UINT32_MAX;

    fixture_initialize(&fixture, 0, 1);
    assert(kernel_socket_rights_record_create_empty(
               &fixture.pool, &first) == 0);
    assert(first);
    assert(kernel_socket_rights_record_info(
               &fixture.pool, first, &information) == 0);
    assert(information.descriptor_count == 0);
    assert(information.state ==
           KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    assert(kernel_socket_rights_token_cursor_initialize(
               &fixture.pool, first, &cursor) == 0);
    assert(kernel_socket_rights_token_cursor_next(
               &fixture.pool, &cursor,
               &source_index, &lease) == 0);
    assert(!lease);

    stale = first;
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &first) == 0);
    assert(!first);
    assert(kernel_socket_rights_record_create_empty(
               &fixture.pool, &second) == 0);
    assert(second && second != stale);
    assert(kernel_socket_rights_record_info(
               &fixture.pool, stale, &information) ==
           -EDGE_LINUX_ESTALE);
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &second) == 0);
    fixture_destroy(&fixture);
}

static void test_small_pool_exhaustion_and_rollback(void) {
    pool_fixture_t fixture;
    control_builder_t control;
    int32_t descriptors[3] = {3, 3, 3};
    kernel_socket_rights_record_handle_t record = 0;

    mock_reset();
    mock_install(3, 0, UINT64_C(0xa001));
    fixture_initialize(&fixture, 2, 1);
    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        descriptors, 3);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) ==
           -EDGE_LINUX_ENOBUFS);
    assert(!record);
    assert(g_mock.acquire_calls == 2);
    assert(g_mock.release_calls == 2);
    assert(g_mock.objects[0].references == 1);
    require_pool_fully_free(&fixture.pool);

    assert(kernel_socket_rights_record_create_empty(
               &fixture.pool, &record) == 0);
    {
        kernel_socket_rights_record_handle_t second = 0;
        assert(kernel_socket_rights_record_import(
                   &fixture.pool, 0, 0,
                   test_copy_from_user,
                   (uint64_t)(uintptr_t)control.bytes,
                   control.length, &second) ==
               -EDGE_LINUX_ENOBUFS);
        assert(!second);
    }
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &record) == 0);
    assert(mock_close(&g_mock, 3) == 0);
    fixture_destroy(&fixture);
}

static void test_linux_limit_and_multiple_headers(void) {
    pool_fixture_t fixture;
    control_builder_t control;
    int32_t descriptors[254];
    kernel_socket_rights_record_handle_t record = 0;
    kernel_socket_rights_record_info_t information;
    kernel_socket_rights_token_cursor_t cursor;
    uint32_t visited;

    mock_reset();
    mock_install(5, 0, UINT64_C(0xb005));
    fill_descriptors(descriptors, 254, 5);
    fixture_initialize(&fixture, 253, 1);

    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        descriptors, 253);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) == 0);
    assert(kernel_socket_rights_record_info(
               &fixture.pool, record, &information) == 0);
    assert(information.descriptor_count == 253);
    assert(g_mock.objects[0].references == 254);
    assert(kernel_socket_rights_token_cursor_initialize(
               &fixture.pool, record, &cursor) == 0);
    visited = 0;
    for (;;) {
        const kernel_fd_operation_lease_t *lease = 0;
        const mock_fd_snapshot_t *snapshot;
        uint32_t source_index = UINT32_MAX;
        int next = kernel_socket_rights_token_cursor_next(
            &fixture.pool, &cursor,
            &source_index, &lease);

        if (!next) break;
        assert(next == 1);
        assert(source_index == visited);
        assert(lease);
        snapshot = (const mock_fd_snapshot_t *)
            kernel_fd_operation_view(lease);
        assert(snapshot);
        assert(snapshot->tag == UINT64_C(0xb005));
        assert(snapshot->source_descriptor == 5);
        ++visited;
    }
    assert(visited == 253);
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &record) == 0);
    assert(g_mock.objects[0].references == 1);
    require_pool_fully_free(&fixture.pool);

    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        descriptors, 254);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) ==
           -EDGE_LINUX_EINVAL);
    assert(!record);
    assert(g_mock.objects[0].references == 1);
    require_pool_fully_free(&fixture.pool);

    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        descriptors, 126);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        &descriptors[126], 127);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) == 0);
    assert(kernel_socket_rights_record_info(
               &fixture.pool, record, &information) == 0);
    assert(information.descriptor_count == 253);
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &record) == 0);

    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        descriptors, 126);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        &descriptors[126], 128);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) ==
           -EDGE_LINUX_EINVAL);
    assert(!record);
    assert(g_mock.objects[0].references == 1);
    require_pool_fully_free(&fixture.pool);
    assert(mock_close(&g_mock, 5) == 0);
    fixture_destroy(&fixture);
}

static void test_copy_and_descriptor_failure_rollback(void) {
    pool_fixture_t fixture;
    control_builder_t control;
    copy_context_t copy = {0};
    int32_t descriptors[2] = {3, 4};
    kernel_socket_rights_record_handle_t record = 0;
    uint32_t releases;

    mock_reset();
    mock_install(3, 0, UINT64_C(0xc003));
    fixture_initialize(&fixture, 2, 1);
    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        descriptors, 2);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) ==
           -EDGE_LINUX_EBADF);
    assert(!record);
    assert(g_mock.objects[0].references == 1);
    require_pool_fully_free(&fixture.pool);

    releases = g_mock.release_calls;
    copy.fault_address =
        (uint64_t)(uintptr_t)control.bytes +
        sizeof(struct edge_linux_cmsghdr) +
        sizeof(int32_t);
    copy.fault_length = sizeof(int32_t);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, &copy, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) ==
           -EDGE_LINUX_EFAULT);
    assert(!record);
    assert(g_mock.release_calls == releases + 1u);
    assert(g_mock.objects[0].references == 1);
    require_pool_fully_free(&fixture.pool);
    assert(mock_close(&g_mock, 3) == 0);
    fixture_destroy(&fixture);
}

static void test_queue_and_zero_length_records(void) {
    pool_fixture_t fixture;
    control_builder_t control;
    kernel_socket_rights_queue_t queue;
    kernel_socket_rights_record_handle_t first = 0;
    kernel_socket_rights_record_handle_t second = 0;
    kernel_socket_rights_record_handle_t third = 0;
    kernel_socket_rights_record_handle_t taken = 0;
    kernel_socket_rights_record_handle_t first_queued;
    kernel_socket_rights_record_handle_t second_queued;
    kernel_socket_rights_record_info_t information;

    mock_reset();
    fixture_initialize(&fixture, 0, 3);
    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS, 0, 0);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &first) == 0);
    assert(!first);
    assert(kernel_socket_rights_record_create_empty(
               &fixture.pool, &first) == 0);
    assert(kernel_socket_rights_record_create_empty(
               &fixture.pool, &second) == 0);
    assert(kernel_socket_rights_record_create_empty(
               &fixture.pool, &third) == 0);

    kernel_socket_rights_queue_initialize(&queue, 2);
    first_queued = first;
    assert(kernel_socket_rights_queue_enqueue(
               &fixture.pool, &queue, &first,
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
               100) == 0);
    assert(!first);
    assert(kernel_socket_rights_queue_enqueue(
               &fixture.pool, &queue, &second,
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_STREAM_BYTE,
               100) ==
           -EDGE_LINUX_EINVAL);
    assert(second);
    assert(kernel_socket_rights_queue_enqueue(
               &fixture.pool, &queue, &second,
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
               99) ==
           -EDGE_LINUX_EINVAL);
    second_queued = second;
    assert(kernel_socket_rights_queue_enqueue(
               &fixture.pool, &queue, &second,
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
               100) == 0);
    assert(!second);
    assert(kernel_socket_rights_queue_peek_at(
               &fixture.pool, &queue, 1, &information) == 0);
    assert(information.handle == second_queued);
    assert(information.association_sequence == 100);
    assert(kernel_socket_rights_queue_remove(
               &fixture.pool, &queue, second_queued) == 0);
    assert(kernel_socket_rights_queue_count(&queue) == 1);
    assert(kernel_socket_rights_record_info(
               &fixture.pool, second_queued, &information) == 0);
    assert(information.state ==
           KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    second = second_queued;
    assert(kernel_socket_rights_queue_enqueue(
               &fixture.pool, &queue, &second,
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
               101) == 0);
    assert(kernel_socket_rights_queue_peek_at(
               &fixture.pool, &queue, 1, &information) == 0);
    assert(information.handle == second_queued);
    assert(information.association_sequence == 101);
    assert(kernel_socket_rights_queue_enqueue(
               &fixture.pool, &queue, &third,
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
               101) ==
           -EDGE_LINUX_EAGAIN);
    assert(third);
    assert(kernel_socket_rights_queue_count(&queue) == 2);
    assert(kernel_socket_rights_queue_peek(
               &fixture.pool, &queue, &information) == 0);
    assert(information.handle == first_queued);
    assert(information.association_sequence == 100);
    assert(information.descriptor_count == 0);
    assert(information.state ==
           KERNEL_SOCKET_RIGHTS_RECORD_QUEUED);
    assert(kernel_socket_rights_queue_take(
               &fixture.pool, &queue, &taken) == 0);
    assert(taken);
    assert(kernel_socket_rights_record_info(
               &fixture.pool, taken, &information) == 0);
    assert(information.state ==
           KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &taken) == 0);
    assert(kernel_socket_rights_queue_clear(
               &fixture.pool, &queue) == 0);
    assert(kernel_socket_rights_queue_count(&queue) == 0);
    assert(kernel_socket_rights_queue_peek(
               &fixture.pool, &queue, &information) ==
           -EDGE_LINUX_EAGAIN);
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &third) == 0);
    fixture_destroy(&fixture);
}

static void test_source_close_and_numeric_reuse(void) {
    pool_fixture_t fixture;
    control_builder_t control;
    int32_t descriptor = 7;
    kernel_socket_rights_record_handle_t record = 0;
    kernel_socket_rights_token_cursor_t cursor;
    const kernel_fd_operation_lease_t *lease = 0;
    const mock_fd_snapshot_t *snapshot;
    uint32_t source_index = UINT32_MAX;

    mock_reset();
    mock_install(7, 0, UINT64_C(0xd001));
    fixture_initialize(&fixture, 1, 1);
    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        &descriptor, 1);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, 0, 0, test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) == 0);
    assert(g_mock.objects[0].references == 2);
    assert(mock_close(&g_mock, 7) == 0);
    assert(g_mock.objects[0].references == 1);
    mock_install(7, 1, UINT64_C(0xd002));

    assert(kernel_socket_rights_token_cursor_initialize(
               &fixture.pool, record, &cursor) == 0);
    assert(kernel_socket_rights_token_cursor_next(
               &fixture.pool, &cursor,
               &source_index, &lease) == 1);
    snapshot = (const mock_fd_snapshot_t *)
        kernel_fd_operation_view(lease);
    assert(snapshot);
    assert(snapshot->tag == UINT64_C(0xd001));
    assert(snapshot->source_descriptor == 7);
    assert(source_index == 0);
    assert(kernel_socket_rights_token_cursor_next(
               &fixture.pool, &cursor,
               &source_index, &lease) == 0);

    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &record) == 0);
    assert(g_mock.objects[0].references == 0);
    assert(g_mock.objects[1].references == 1);
    assert(g_mock.descriptors[7] == 1);
    assert(mock_close(&g_mock, 7) == 0);
    fixture_destroy(&fixture);
}

static void test_explicit_sender_owner(void) {
    pool_fixture_t fixture;
    control_builder_t control;
    copy_context_t copy = {0};
    kernel_socket_rights_record_handle_t record = 0;
    uint64_t blocked_sender = UINT64_C(0x51eed001);
    int32_t descriptor = 9;

    mock_reset();
    mock_install(9, 0, UINT64_C(0xe001));
    fixture_initialize(&fixture, 1, 1);
    control_initialize(&control);
    control_append(
        &control, EDGE_LINUX_SOL_SOCKET,
        KERNEL_SOCKET_SCM_RIGHTS,
        &descriptor, 1);
    assert(kernel_socket_rights_record_import(
               &fixture.pool, &blocked_sender, &copy,
               test_copy_from_user,
               (uint64_t)(uintptr_t)control.bytes,
               control.length, &record) == 0);
    assert(record);
    assert(g_mock.owner_acquire_calls == 1);
    assert(g_mock.last_owner == &blocked_sender);
    assert(kernel_socket_rights_record_drop(
               &fixture.pool, &record) == 0);
    assert(mock_close(&g_mock, 9) == 0);
    fixture_destroy(&fixture);
}

static void test_default_pool_configuration(void) {
    kernel_socket_rights_pool_statistics_t statistics;
    uint64_t required =
        kernel_socket_rights_pool_required_bytes(
            KERNEL_SOCKET_RIGHTS_DEFAULT_TOKEN_CAPACITY,
            KERNEL_SOCKET_RIGHTS_DEFAULT_RECORD_CAPACITY);

    assert(required != 0);
    assert(required <=
           KERNEL_SOCKET_RIGHTS_DEFAULT_ARENA_BYTES);
    assert(kernel_socket_rights_default_pool() == 0);
    assert(kernel_socket_rights_default_pool_initialize() == 0);
    assert(kernel_socket_rights_default_pool() != 0);
    assert(kernel_socket_rights_pool_statistics(
               kernel_socket_rights_default_pool(),
               &statistics) == 0);
    assert(statistics.token_capacity ==
           KERNEL_SOCKET_RIGHTS_DEFAULT_TOKEN_CAPACITY);
    assert(statistics.record_capacity ==
           KERNEL_SOCKET_RIGHTS_DEFAULT_RECORD_CAPACITY);
    assert(statistics.free_tokens ==
           statistics.token_capacity);
    assert(statistics.free_records ==
           statistics.record_capacity);
    assert(kernel_socket_rights_default_pool_initialize() == 0);
}

int main(void) {
    mock_reset();
    assert(kernel_fd_backend_register(
               &g_mock_backend_ops, &g_mock) == 0);
    test_default_pool_configuration();
    test_memory_layout_and_initialization();
    test_empty_record_and_generation_reuse();
    test_small_pool_exhaustion_and_rollback();
    test_linux_limit_and_multiple_headers();
    test_copy_and_descriptor_failure_rollback();
    test_queue_and_zero_length_records();
    test_source_close_and_numeric_reuse();
    test_explicit_sender_owner();
    puts("socket_rights_unit: PASS");
    return 0;
}
