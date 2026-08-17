/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS SCM_RIGHTS receive-delivery transaction tests.
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
 * Substitute a small host lock before including the common implementation.
 */
#define SYS_SPINLOCK_H
typedef struct {
    atomic_flag value;
    atomic_uint held;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    atomic_flag_clear_explicit(&lock->value, memory_order_relaxed);
    atomic_store_explicit(&lock->held, 0u, memory_order_relaxed);
}

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (atomic_flag_test_and_set_explicit(
               &lock->value, memory_order_acquire))
        sched_yield();
    atomic_store_explicit(&lock->held, 1u, memory_order_release);
    return 0;
}

static inline void spin_unlock_irqrestore(
        spinlock_t *lock, uint64_t flags) {
    (void)flags;
    atomic_store_explicit(&lock->held, 0u, memory_order_release);
    atomic_flag_clear_explicit(&lock->value, memory_order_release);
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

int64_t edge_socket_runtime_message_execute(
        const kernel_socket_message_request_t *request) {
    (void)request;
    return -EDGE_LINUX_ENOSYS;
}

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

#include "../../src/kernel/fd_runtime.c"
#include "../../src/kernel/socket_message.c"
#include "../../src/kernel/socket_rights.c"

#define MOCK_DESCRIPTOR_LIMIT 600u
#define MOCK_OBJECT_LIMIT KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS
#define MOCK_RECEIVER_DESCRIPTOR_BASE 300u
#define TEST_USER_BASE UINT64_C(0x10000000)
#define TEST_CONTROL_BYTES 4096u
#define TEST_SENTINEL 0xa5u
#define MOCK_TARGET_MAGIC UINT32_C(0x74617267)

typedef struct mock_fd_snapshot {
    uint32_t object;
    uint32_t reserved;
    uint64_t tag;
} mock_fd_snapshot_t;

typedef struct mock_target_storage {
    uint32_t magic;
    uint32_t reserved;
} mock_target_storage_t;

typedef struct mock_backend {
    int32_t visible_objects[MOCK_DESCRIPTOR_LIMIT];
    int32_t reserved_objects[MOCK_DESCRIPTOR_LIMIT];
    uint32_t descriptor_flags[MOCK_DESCRIPTOR_LIMIT];
    uint32_t object_references[MOCK_OBJECT_LIMIT];
    kernel_socket_rights_pool_t *checked_pool;
    uint32_t prepare_limit;
    int32_t publish_status;
    uint32_t capture_calls;
    uint32_t owner_capture_calls;
    uint32_t release_calls;
    uint32_t prepare_calls;
    uint32_t prepare_successes;
    uint32_t publish_calls;
    uint32_t published_descriptors;
    uint32_t abort_calls;
    uint32_t aborted_descriptors;
    const void *last_capture_owner;
} mock_backend_t;

typedef struct copy_mock {
    uint8_t bytes[TEST_CONTROL_BYTES];
    uint32_t calls;
    uint32_t fail_call;
    uint32_t fault_prefix;
} copy_mock_t;

typedef struct delivery_fixture {
    kernel_socket_rights_pool_t pool;
    kernel_socket_rights_record_handle_t record;
    kernel_fd_transfer_target_t *target;
    void *arena;
    copy_mock_t copy;
    uint32_t source_count;
    const void *fd_owner;
} delivery_fixture_t;

static mock_backend_t g_mock;

_Static_assert(
    sizeof(mock_fd_snapshot_t) <=
        KERNEL_FD_OPERATION_LEASE_STORAGE_SIZE,
    "mock snapshot exceeds operation lease storage");
_Static_assert(
    sizeof(mock_target_storage_t) <=
        KERNEL_FD_TRANSFER_TARGET_STORAGE_SIZE,
    "mock target exceeds transfer target storage");

static void mock_require_pool_unlocked(void) {
    if (g_mock.checked_pool)
        assert(!spinlock_is_held(&g_mock.checked_pool->lock));
}

static void mock_reset(void) {
    memset(&g_mock, 0, sizeof(g_mock));
    for (uint32_t index = 0;
         index < MOCK_DESCRIPTOR_LIMIT; ++index) {
        g_mock.visible_objects[index] = -1;
        g_mock.reserved_objects[index] = -1;
    }
    g_mock.prepare_limit = UINT32_MAX;
}

static uint32_t mock_table_limit(void *context) {
    assert(context == &g_mock);
    return MOCK_DESCRIPTOR_LIMIT;
}

static uint32_t mock_allocation_limit(void *context) {
    assert(context == &g_mock);
    return MOCK_DESCRIPTOR_LIMIT;
}

static int mock_table_unshare(void *context) {
    assert(context == &g_mock);
    return 0;
}

static int mock_is_open(void *context, int32_t descriptor) {
    mock_backend_t *mock = (mock_backend_t *)context;

    return descriptor >= 0 &&
        (uint32_t)descriptor < MOCK_DESCRIPTOR_LIMIT &&
        mock->visible_objects[descriptor] >= 0;
}

static int mock_operation_acquire(
        void *context, int32_t descriptor, void *storage) {
    mock_backend_t *mock = (mock_backend_t *)context;
    mock_fd_snapshot_t *snapshot =
        (mock_fd_snapshot_t *)storage;
    int32_t object;

    assert(mock == &g_mock);
    assert(snapshot);
    mock_require_pool_unlocked();
    if (!mock_is_open(mock, descriptor))
        return -EDGE_LINUX_EBADF;
    object = mock->visible_objects[descriptor];
    assert(object >= 0);
    assert((uint32_t)object < MOCK_OBJECT_LIMIT);
    snapshot->object = (uint32_t)object;
    snapshot->tag = UINT64_C(0xd000) + (uint32_t)object;
    ++mock->object_references[object];
    return 0;
}

static int mock_operation_release(
        void *context, void *storage) {
    mock_backend_t *mock = (mock_backend_t *)context;
    mock_fd_snapshot_t *snapshot =
        (mock_fd_snapshot_t *)storage;

    assert(mock == &g_mock);
    assert(snapshot);
    mock_require_pool_unlocked();
    assert(snapshot->object < MOCK_OBJECT_LIMIT);
    assert(mock->object_references[snapshot->object] > 0);
    --mock->object_references[snapshot->object];
    return 0;
}

static int mock_transfer_target_capture(
        void *context, void *storage) {
    mock_target_storage_t *target =
        (mock_target_storage_t *)storage;

    assert(context == &g_mock);
    assert(target);
    assert(target->magic == 0u);
    target->magic = MOCK_TARGET_MAGIC;
    ++g_mock.capture_calls;
    return 0;
}

static int mock_transfer_target_capture_for_owner(
        void *context, const void *owner,
        void *storage) {
    mock_backend_t *mock = (mock_backend_t *)context;

    assert(mock == &g_mock);
    assert(owner);
    ++mock->owner_capture_calls;
    mock->last_capture_owner = owner;
    return mock_transfer_target_capture(
        context, storage);
}

static int mock_transfer_target_release(
        void *context, void *storage) {
    mock_target_storage_t *target =
        (mock_target_storage_t *)storage;

    assert(context == &g_mock);
    assert(target);
    assert(target->magic == MOCK_TARGET_MAGIC);
    for (uint32_t descriptor =
             MOCK_RECEIVER_DESCRIPTOR_BASE;
         descriptor < MOCK_DESCRIPTOR_LIMIT; ++descriptor)
        assert(g_mock.reserved_objects[descriptor] < 0);
    target->magic = 0;
    ++g_mock.release_calls;
    return 0;
}

static int mock_transfer_target_prepare(
        void *context, void *target_storage,
        const void *source_storage,
        uint32_t descriptor_flags,
        int32_t *descriptor) {
    mock_backend_t *mock = (mock_backend_t *)context;
    const mock_target_storage_t *target =
        (const mock_target_storage_t *)target_storage;
    const mock_fd_snapshot_t *source =
        (const mock_fd_snapshot_t *)source_storage;

    assert(mock == &g_mock);
    assert(target);
    assert(target->magic == MOCK_TARGET_MAGIC);
    assert(source);
    assert(descriptor);
    assert(!(descriptor_flags & ~KERNEL_FD_CLOEXEC));
    mock_require_pool_unlocked();
    ++mock->prepare_calls;
    if (mock->prepare_successes >= mock->prepare_limit)
        return -EDGE_LINUX_EMFILE;

    for (uint32_t candidate =
             MOCK_RECEIVER_DESCRIPTOR_BASE;
         candidate < MOCK_DESCRIPTOR_LIMIT; ++candidate) {
        if (mock->visible_objects[candidate] >= 0 ||
            mock->reserved_objects[candidate] >= 0)
            continue;
        assert(source->object < MOCK_OBJECT_LIMIT);
        mock->reserved_objects[candidate] =
            (int32_t)source->object;
        mock->descriptor_flags[candidate] =
            descriptor_flags;
        ++mock->object_references[source->object];
        ++mock->prepare_successes;
        *descriptor = (int32_t)candidate;
        return 0;
    }
    return -EDGE_LINUX_EMFILE;
}

static void mock_transfer_target_discard_prepared(
        void *context, void *target_storage) {
    (void)context;
    (void)target_storage;
    assert(!"unexpected invalid successful prepare output");
}

static int mock_transfer_target_publish_many(
        void *context, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    mock_backend_t *mock = (mock_backend_t *)context;
    const mock_target_storage_t *target =
        (const mock_target_storage_t *)target_storage;

    assert(mock == &g_mock);
    assert(target);
    assert(target->magic == MOCK_TARGET_MAGIC);
    assert(descriptors);
    assert(count);
    ++mock->publish_calls;
    for (uint32_t index = 0; index < count; ++index) {
        int32_t descriptor = descriptors[index];

        assert(descriptor >= 0);
        assert((uint32_t)descriptor <
               MOCK_DESCRIPTOR_LIMIT);
        assert(mock->visible_objects[descriptor] < 0);
        assert(mock->reserved_objects[descriptor] >= 0);
    }
    if (mock->publish_status)
        return mock->publish_status;
    for (uint32_t index = 0; index < count; ++index) {
        int32_t descriptor = descriptors[index];

        mock->visible_objects[descriptor] =
            mock->reserved_objects[descriptor];
        mock->reserved_objects[descriptor] = -1;
    }
    mock->published_descriptors += count;
    return 0;
}

static int mock_transfer_target_abort_many(
        void *context, void *target_storage,
        const int32_t *descriptors, uint32_t count) {
    mock_backend_t *mock = (mock_backend_t *)context;
    const mock_target_storage_t *target =
        (const mock_target_storage_t *)target_storage;

    assert(mock == &g_mock);
    assert(target);
    assert(target->magic == MOCK_TARGET_MAGIC);
    assert(descriptors);
    assert(count);
    for (uint32_t index = 0; index < count; ++index) {
        int32_t descriptor = descriptors[index];
        int32_t object;

        assert(descriptor >= 0);
        assert((uint32_t)descriptor <
               MOCK_DESCRIPTOR_LIMIT);
        assert(mock->visible_objects[descriptor] < 0);
        object = mock->reserved_objects[descriptor];
        assert(object >= 0);
        assert(mock->object_references[object] > 0);
    }
    for (uint32_t index = 0; index < count; ++index) {
        int32_t descriptor = descriptors[index];
        int32_t object =
            mock->reserved_objects[descriptor];

        mock->reserved_objects[descriptor] = -1;
        mock->descriptor_flags[descriptor] = 0;
        --mock->object_references[object];
    }
    ++mock->abort_calls;
    mock->aborted_descriptors += count;
    return 0;
}

static int mock_close(void *context, int32_t descriptor) {
    mock_backend_t *mock = (mock_backend_t *)context;
    int32_t object;

    assert(mock == &g_mock);
    if (!mock_is_open(mock, descriptor))
        return -EDGE_LINUX_EBADF;
    object = mock->visible_objects[descriptor];
    assert(mock->object_references[object] > 0);
    --mock->object_references[object];
    mock->visible_objects[descriptor] = -1;
    mock->descriptor_flags[descriptor] = 0;
    return 0;
}

static int mock_duplicate_exact(
        void *context, int32_t source, int32_t destination,
        uint32_t descriptor_flags) {
    (void)context;
    (void)source;
    (void)destination;
    (void)descriptor_flags;
    return -EDGE_LINUX_ENOSYS;
}

static int mock_duplicate_minimum(
        void *context, int32_t source, int32_t minimum,
        uint32_t exclusive_limit, uint32_t descriptor_flags,
        int32_t *destination) {
    (void)context;
    (void)source;
    (void)minimum;
    (void)exclusive_limit;
    (void)descriptor_flags;
    (void)destination;
    return -EDGE_LINUX_ENOSYS;
}

static int mock_get_flags(
        void *context, int32_t descriptor, uint32_t *flags) {
    mock_backend_t *mock = (mock_backend_t *)context;

    if (!flags || !mock_is_open(mock, descriptor))
        return -EDGE_LINUX_EBADF;
    *flags = mock->descriptor_flags[descriptor];
    return 0;
}

static int mock_set_flags(
        void *context, int32_t descriptor, uint32_t flags) {
    mock_backend_t *mock = (mock_backend_t *)context;

    if (!mock_is_open(mock, descriptor))
        return -EDGE_LINUX_EBADF;
    mock->descriptor_flags[descriptor] = flags;
    return 0;
}

static int mock_pipe_capacity(
        void *context, int32_t descriptor, uint32_t *capacity) {
    (void)context;
    (void)descriptor;
    if (!capacity) return -EDGE_LINUX_EINVAL;
    *capacity = 65536u;
    return 0;
}

static int mock_pidfd_lookup(
        void *context, int32_t pid, int32_t *tgid) {
    (void)context;
    if (!tgid) return -EDGE_LINUX_EINVAL;
    *tgid = pid;
    return 0;
}

static int mock_pidfd_install(
        void *context, int32_t pid, uint32_t flags) {
    (void)context;
    (void)pid;
    (void)flags;
    return -EDGE_LINUX_ENOSYS;
}

static int mock_pidfd_target(
        void *context, int32_t descriptor,
        int32_t *pid, uint32_t *flags) {
    (void)context;
    (void)descriptor;
    if (!pid || !flags) return -EDGE_LINUX_EINVAL;
    *pid = 1;
    *flags = 0;
    return 0;
}

static int64_t mock_fcntl_fallback(
        void *context, int32_t descriptor,
        uint32_t command, uint64_t argument) {
    (void)context;
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
    .operation_release = mock_operation_release,
    .transfer_target_capture = mock_transfer_target_capture,
    .transfer_target_capture_for_owner =
        mock_transfer_target_capture_for_owner,
    .transfer_target_release = mock_transfer_target_release,
    .transfer_target_prepare = mock_transfer_target_prepare,
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

static void copy_reset(copy_mock_t *copy) {
    memset(copy, 0, sizeof(*copy));
    memset(copy->bytes, TEST_SENTINEL,
           sizeof(copy->bytes));
}

static int copy_to_user(
        void *context, uint64_t destination,
        const void *source, uint64_t length) {
    copy_mock_t *copy = (copy_mock_t *)context;
    uint64_t offset;
    uint64_t copied;

    assert(copy);
    assert(source || !length);
    ++copy->calls;
    if (destination < TEST_USER_BASE)
        return -1;
    offset = destination - TEST_USER_BASE;
    if (offset > sizeof(copy->bytes) ||
        length > sizeof(copy->bytes) - offset)
        return -1;
    if (copy->calls != copy->fail_call) {
        if (length)
            memcpy(copy->bytes + offset, source,
                   (size_t)length);
        return 0;
    }
    copied = copy->fault_prefix < length ?
        copy->fault_prefix : length;
    if (copied)
        memcpy(copy->bytes + offset, source,
               (size_t)copied);
    return -1;
}

static int copy_from_user(
        void *context, void *destination,
        uint64_t source, uint64_t length) {
    (void)context;
    if (!destination || (!source && length))
        return -1;
    if (length)
        memcpy(destination, (const void *)(uintptr_t)source,
               (size_t)length);
    return 0;
}

static void fixture_initialize(
        delivery_fixture_t *fixture,
        uint32_t source_count) {
    struct edge_linux_cmsghdr *header;
    uint8_t *control;
    uint64_t control_length;
    uint64_t arena_bytes;

    assert(fixture);
    assert(source_count <= MOCK_OBJECT_LIMIT);
    mock_reset();
    memset(fixture, 0, sizeof(*fixture));
    fixture->source_count = source_count;
    arena_bytes = kernel_socket_rights_pool_required_bytes(
        source_count ? source_count : 1u, 1u);
    assert(arena_bytes);
    fixture->arena = malloc((size_t)arena_bytes);
    fixture->target = calloc(1, sizeof(*fixture->target));
    assert(fixture->arena);
    assert(fixture->target);
    assert(kernel_socket_rights_pool_initialize(
               &fixture->pool, fixture->arena, arena_bytes,
               source_count ? source_count : 1u, 1u) == 0);
    g_mock.checked_pool = &fixture->pool;
    copy_reset(&fixture->copy);

    if (!source_count) {
        assert(kernel_socket_rights_record_create_empty(
                   &fixture->pool, &fixture->record) == 0);
        return;
    }

    control_length =
        sizeof(*header) +
        (uint64_t)source_count * sizeof(int32_t);
    control = calloc(1, (size_t)control_length);
    assert(control);
    header = (struct edge_linux_cmsghdr *)(void *)control;
    header->cmsg_len = control_length;
    header->cmsg_level = EDGE_LINUX_SOL_SOCKET;
    header->cmsg_type = KERNEL_SOCKET_SCM_RIGHTS;
    for (uint32_t index = 0; index < source_count; ++index) {
        int32_t descriptor = (int32_t)index;

        g_mock.visible_objects[index] = (int32_t)index;
        g_mock.object_references[index] = 1u;
        memcpy(control + sizeof(*header) +
                   (uint64_t)index * sizeof(descriptor),
               &descriptor, sizeof(descriptor));
    }
    assert(kernel_socket_rights_record_import(
               &fixture->pool, 0, 0, copy_from_user,
               (uint64_t)(uintptr_t)control,
               control_length, &fixture->record) == 0);
    free(control);
}

static void close_receiver_descriptors(void) {
    for (uint32_t descriptor =
             MOCK_RECEIVER_DESCRIPTOR_BASE;
         descriptor < MOCK_DESCRIPTOR_LIMIT; ++descriptor) {
        assert(g_mock.reserved_objects[descriptor] < 0);
        if (g_mock.visible_objects[descriptor] >= 0)
            assert(mock_close(
                       &g_mock, (int32_t)descriptor) == 0);
    }
}

static uint32_t visible_receiver_count(void) {
    uint32_t count = 0;

    for (uint32_t descriptor =
             MOCK_RECEIVER_DESCRIPTOR_BASE;
         descriptor < MOCK_DESCRIPTOR_LIMIT; ++descriptor)
        count += g_mock.visible_objects[descriptor] >= 0;
    return count;
}

static void fixture_destroy(delivery_fixture_t *fixture) {
    kernel_socket_rights_pool_statistics_t statistics;

    close_receiver_descriptors();
    if (fixture->record)
        assert(kernel_socket_rights_record_drop(
                   &fixture->pool, &fixture->record) == 0);
    for (uint32_t descriptor = 0;
         descriptor < fixture->source_count; ++descriptor)
        if (g_mock.visible_objects[descriptor] >= 0)
            assert(mock_close(
                       &g_mock, (int32_t)descriptor) == 0);
    for (uint32_t object = 0;
         object < fixture->source_count; ++object)
        assert(g_mock.object_references[object] == 0u);
    assert(kernel_socket_rights_pool_statistics(
               &fixture->pool, &statistics) == 0);
    assert(statistics.free_tokens ==
           statistics.token_capacity);
    assert(statistics.free_records ==
           statistics.record_capacity);
    assert(g_mock.capture_calls == g_mock.release_calls);
    g_mock.checked_pool = 0;
    free(fixture->target);
    free(fixture->arena);
}

static int deliver(
        delivery_fixture_t *fixture,
        uint64_t capacity, uint64_t *used,
        int32_t *message_flags, uint32_t receive_flags,
        kernel_socket_rights_receive_result_t *result) {
    return kernel_socket_control_receive_rights_record(
        &fixture->pool, fixture->record,
        fixture->target, fixture->fd_owner,
        &fixture->copy, copy_to_user,
        TEST_USER_BASE, capacity, used, message_flags,
        receive_flags, result);
}

static void read_header(
        const copy_mock_t *copy,
        struct edge_linux_cmsghdr *header) {
    memcpy(header, copy->bytes, sizeof(*header));
}

static int32_t read_descriptor(
        const copy_mock_t *copy, uint32_t index) {
    int32_t descriptor;

    memcpy(&descriptor,
           copy->bytes + sizeof(struct edge_linux_cmsghdr) +
               (uint64_t)index * sizeof(descriptor),
           sizeof(descriptor));
    return descriptor;
}

static void assert_source_record(
        delivery_fixture_t *fixture, uint8_t state) {
    kernel_socket_rights_record_info_t information;

    assert(kernel_socket_rights_record_info(
               &fixture->pool, fixture->record,
               &information) == 0);
    assert(information.handle == fixture->record);
    assert(information.descriptor_count ==
           fixture->source_count);
    assert(information.state == state);
}

static void test_no_space_and_capacity_prefix(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 7u;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(fixture, 8u);
    assert(deliver(
               fixture, used, &used, &flags, 0, &result) == 0);
    assert(used == 7u);
    assert(result.truncated);
    assert(!result.control_fault);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert(fixture->copy.calls == 0u);
    assert(g_mock.capture_calls == 0u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);

    copy_reset(&fixture->copy);
    used = 0;
    flags = 0;
    assert(deliver(
               fixture, sizeof(header), &used, &flags, 0,
               &result) == 0);
    assert(used == 0u);
    assert(result.truncated);
    assert(!result.control_fault);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert(fixture->copy.calls == 0u);
    assert(g_mock.capture_calls == 0u);

    copy_reset(&fixture->copy);
    used = 0;
    flags = 0;
    assert(deliver(
               fixture,
               sizeof(header) + 3u * sizeof(int32_t),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 3u);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == sizeof(header) +
                   3u * sizeof(int32_t));
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    read_header(&fixture->copy, &header);
    assert(header.cmsg_len == used);
    assert(visible_receiver_count() == 3u);
    assert(g_mock.publish_calls == 1u);
    assert(g_mock.published_descriptors == 3u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_full_unaligned_tail_and_linux_maximum(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t exact_length;
    uint64_t used = 0;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(
        fixture, KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS);
    exact_length = sizeof(header) +
        (uint64_t)KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS *
            sizeof(int32_t);
    assert(deliver(
               fixture, exact_length, &used, &flags, 0,
               &result) == 0);
    assert(result.delivered_count ==
           KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS);
    assert(!result.truncated);
    assert(!result.control_fault);
    assert(used == exact_length);
    assert(flags == 0);
    read_header(&fixture->copy, &header);
    assert(header.cmsg_len == exact_length);
    assert(visible_receiver_count() ==
           KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS);
    assert(g_mock.publish_calls == 1u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);

    close_receiver_descriptors();
    copy_reset(&fixture->copy);
    used = 0;
    flags = 0;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count ==
           KERNEL_SOCKET_RIGHTS_MAX_DESCRIPTORS);
    assert(!result.truncated);
    assert(used == kernel_socket_control_align(exact_length));
    assert(used == 1032u);
    assert(g_mock.publish_calls == 2u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_descriptor_exhaustion(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(fixture, 8u);
    g_mock.prepare_limit = 0u;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.callback_status == -EDGE_LINUX_EMFILE);
    assert(result.truncated);
    assert(used == 0u);
    assert(fixture->copy.calls == 0u);
    assert(visible_receiver_count() == 0u);
    assert(g_mock.capture_calls == 1u);
    assert(g_mock.release_calls == 1u);

    copy_reset(&fixture->copy);
    g_mock.prepare_limit = 3u;
    g_mock.prepare_calls = 0u;
    g_mock.prepare_successes = 0u;
    used = 0;
    flags = 0;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 3u);
    assert(result.callback_status == -EDGE_LINUX_EMFILE);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == kernel_socket_control_align(
                       sizeof(header) +
                       3u * sizeof(int32_t)));
    assert(used == 32u);
    read_header(&fixture->copy, &header);
    assert(header.cmsg_len == 28u);
    assert(visible_receiver_count() == 3u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_control_copy_faults(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    struct edge_linux_cmsghdr header;
    uint64_t used = 0;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(fixture, 3u);
    fixture->copy.fail_call = 1u;
    fixture->copy.fault_prefix = 4u;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.truncated);
    assert(result.control_fault);
    assert(used == 0u);
    assert(visible_receiver_count() == 0u);
    assert(g_mock.aborted_descriptors == 3u);
    assert(g_mock.capture_calls == g_mock.release_calls);

    copy_reset(&fixture->copy);
    g_mock.abort_calls = 0u;
    g_mock.aborted_descriptors = 0u;
    g_mock.prepare_calls = 0u;
    g_mock.prepare_successes = 0u;
    used = 0;
    flags = 0;
    fixture->copy.fail_call = 2u;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.truncated);
    assert(result.control_fault);
    assert(used == 0u);
    assert(visible_receiver_count() == 0u);
    assert(g_mock.aborted_descriptors == 3u);

    copy_reset(&fixture->copy);
    g_mock.abort_calls = 0u;
    g_mock.aborted_descriptors = 0u;
    g_mock.prepare_calls = 0u;
    g_mock.prepare_successes = 0u;
    used = 0;
    flags = 0;
    fixture->copy.fail_call = 3u;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 1u);
    assert(result.truncated);
    assert(result.control_fault);
    assert(used == sizeof(header) + sizeof(int32_t));
    assert(used == 20u);
    read_header(&fixture->copy, &header);
    assert(header.cmsg_len == used);
    assert(visible_receiver_count() == 1u);
    assert(g_mock.aborted_descriptors == 2u);
    assert(g_mock.publish_calls == 1u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_atomic_publication_failure(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = EDGE_LINUX_MSG_EOR;

    assert(fixture);
    fixture_initialize(fixture, 3u);
    g_mock.publish_status = -EDGE_LINUX_EBUSY;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.callback_status == -EDGE_LINUX_EBUSY);
    assert(result.truncated);
    assert(!result.control_fault);
    assert(used == 0u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert((flags & EDGE_LINUX_MSG_EOR) != 0);
    assert(g_mock.publish_calls == 1u);
    assert(g_mock.published_descriptors == 0u);
    assert(g_mock.aborted_descriptors == 3u);
    assert(visible_receiver_count() == 0u);
    assert(g_mock.capture_calls == g_mock.release_calls);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_cloexec_and_repeat_delivery(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    kernel_socket_rights_record_info_t information;
    kernel_socket_rights_queue_t queue;
    int32_t first_descriptors[2];
    uint64_t used = 0;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(fixture, 2u);
    kernel_socket_rights_queue_initialize(&queue, 1u);
    assert(kernel_socket_rights_queue_enqueue(
               &fixture->pool, &queue, &fixture->record,
               KERNEL_SOCKET_RIGHTS_ASSOCIATION_PACKET,
               9u) == 0);
    assert(fixture->record == 0u);
    assert(kernel_socket_rights_queue_peek(
               &fixture->pool, &queue, &information) == 0);
    fixture->record = information.handle;
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_QUEUED);

    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, EDGE_LINUX_MSG_CMSG_CLOEXEC,
               &result) == 0);
    assert(result.delivered_count == 2u);
    first_descriptors[0] =
        read_descriptor(&fixture->copy, 0u);
    first_descriptors[1] =
        read_descriptor(&fixture->copy, 1u);
    for (uint32_t index = 0; index < 2u; ++index) {
        int32_t descriptor = first_descriptors[index];

        assert(descriptor >=
               (int32_t)MOCK_RECEIVER_DESCRIPTOR_BASE);
        assert(g_mock.descriptor_flags[descriptor] ==
               KERNEL_FD_CLOEXEC);
        assert(g_mock.visible_objects[descriptor] ==
               (int32_t)index);
    }
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_QUEUED);
    close_receiver_descriptors();

    copy_reset(&fixture->copy);
    g_mock.prepare_calls = 0u;
    g_mock.prepare_successes = 0u;
    used = 0;
    flags = 0;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 2u);
    for (uint32_t index = 0; index < 2u; ++index) {
        int32_t descriptor =
            read_descriptor(&fixture->copy, index);

        assert(g_mock.descriptor_flags[descriptor] == 0u);
        assert(g_mock.visible_objects[descriptor] ==
               (int32_t)index);
    }
    assert(g_mock.capture_calls == 2u);
    assert(g_mock.release_calls == 2u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_QUEUED);

    fixture->record = 0;
    assert(kernel_socket_rights_queue_take(
               &fixture->pool, &queue,
               &fixture->record) == 0);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_empty_and_invalid_inputs(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(fixture, 0u);
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(!result.truncated);
    assert(g_mock.capture_calls == 0u);
    assert(kernel_socket_control_receive_rights_record(
               0, fixture->record, fixture->target,
               0, &fixture->copy, copy_to_user, TEST_USER_BASE,
               sizeof(fixture->copy.bytes), &used, &flags, 0,
               &result) == -EDGE_LINUX_EINVAL);
    assert(kernel_socket_control_receive_rights_record(
               &fixture->pool, UINT64_MAX, fixture->target,
               0, &fixture->copy, copy_to_user, TEST_USER_BASE,
               sizeof(fixture->copy.bytes), &used, &flags, 0,
               &result) < 0);
    assert(kernel_socket_control_receive_rights_record(
               &fixture->pool, fixture->record, 0,
               0, &fixture->copy, copy_to_user, TEST_USER_BASE,
               sizeof(fixture->copy.bytes), &used, &flags, 0,
               &result) == -EDGE_LINUX_EINVAL);
    assert(kernel_socket_control_receive_rights_record(
               &fixture->pool, fixture->record, fixture->target,
               0, &fixture->copy, 0, TEST_USER_BASE,
               sizeof(fixture->copy.bytes), &used, &flags, 0,
               &result) == -EDGE_LINUX_EINVAL);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_control_address_fault(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    uint64_t used = 0;
    int32_t flags = EDGE_LINUX_MSG_EOR;

    assert(fixture);
    fixture_initialize(fixture, 2u);
    assert(kernel_socket_control_receive_rights_record(
               &fixture->pool, fixture->record,
               fixture->target, 0, &fixture->copy, copy_to_user,
               0, sizeof(fixture->copy.bytes), &used, &flags,
               0, &result) == 0);
    assert(result.delivered_count == 0u);
    assert(result.truncated);
    assert(result.control_fault);
    assert(used == 0u);
    assert((flags & EDGE_LINUX_MSG_CTRUNC) != 0);
    assert((flags & EDGE_LINUX_MSG_EOR) != 0);
    assert(fixture->copy.calls == 0u);
    assert(g_mock.capture_calls == 0u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_explicit_receiver_owner(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_socket_rights_receive_result_t result;
    uint64_t blocked_receiver =
        UINT64_C(0x5ece1ee7);
    uint64_t used = 0;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(fixture, 1u);
    fixture->fd_owner = &blocked_receiver;
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) == 0);
    assert(result.delivered_count == 1u);
    assert(g_mock.owner_capture_calls == 1u);
    assert(g_mock.last_capture_owner ==
           &blocked_receiver);
    fixture_destroy(fixture);
    free(fixture);
}

static void test_explicit_receiver_owner_requires_backend_hook(void) {
    delivery_fixture_t *fixture =
        calloc(1, sizeof(*fixture));
    kernel_fd_backend_ops_t no_owner_ops =
        g_mock_backend_ops;
    kernel_socket_rights_receive_result_t result;
    uint64_t blocked_receiver =
        UINT64_C(0x5ece1ee8);
    uint64_t used = 0;
    int32_t flags = 0;

    assert(fixture);
    fixture_initialize(fixture, 1u);
    fixture->fd_owner = &blocked_receiver;
    no_owner_ops.transfer_target_capture_for_owner = 0;
    assert(kernel_fd_backend_register(
               &no_owner_ops, &g_mock) == 0);
    assert(deliver(
               fixture, sizeof(fixture->copy.bytes),
               &used, &flags, 0, &result) ==
           -EDGE_LINUX_EOPNOTSUPP);
    assert(used == 0u);
    assert(flags == 0);
    assert(g_mock.capture_calls == 0u);
    assert(g_mock.owner_capture_calls == 0u);
    assert(visible_receiver_count() == 0u);
    assert_source_record(
        fixture, KERNEL_SOCKET_RIGHTS_RECORD_DETACHED);
    fixture_destroy(fixture);
    free(fixture);
    assert(kernel_fd_backend_register(
               &g_mock_backend_ops, &g_mock) == 0);
}

int main(void) {
    mock_reset();
    assert(kernel_fd_backend_register(
               &g_mock_backend_ops, &g_mock) == 0);
    test_no_space_and_capacity_prefix();
    test_full_unaligned_tail_and_linux_maximum();
    test_descriptor_exhaustion();
    test_control_copy_faults();
    test_atomic_publication_failure();
    test_cloexec_and_repeat_delivery();
    test_empty_and_invalid_inputs();
    test_control_address_fault();
    test_explicit_receiver_owner();
    test_explicit_receiver_owner_requires_backend_hook();
    puts("socket_rights_delivery_unit: PASS");
    return 0;
}
