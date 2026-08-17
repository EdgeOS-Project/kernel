/*
 * Copyright (c) EdgeOS Contributors.
 * SPDX-License-Identifier: MPL-2.0
 */

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Keep exhaustion and slot-reuse coverage fast while preserving the exact
 * production handle format and algorithms.
 */
#define KERNEL_FILE_DESCRIPTION_CAPACITY 64u
#define KERNEL_FILE_DESCRIPTION_HANDLE_SLOT_BITS 6u

/*
 * The kernel spinlock disables interrupts, which is not legal in a host
 * process. Supply an API-compatible host lock before including the core.
 */
#define SYS_SPINLOCK_H
typedef struct {
    atomic_flag value;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock) {
    atomic_flag_clear_explicit(&lock->value, memory_order_relaxed);
}

static inline uint64_t spin_lock_irqsave(spinlock_t *lock) {
    while (atomic_flag_test_and_set_explicit(
               &lock->value, memory_order_acquire))
        sched_yield();
    return 0;
}

static inline void spin_unlock_irqrestore(spinlock_t *lock,
                                          uint64_t flags) {
    (void)flags;
    atomic_flag_clear_explicit(&lock->value, memory_order_release);
}

#include "../../src/kernel/file_description_runtime.c"

typedef struct fake_runtime {
    atomic_uint detach_count;
    atomic_uint payload_release_count;
    atomic_uint detach_entered;
    atomic_uint allow_detach;
    atomic_uint block_detach;
    atomic_uint callback_reentry;
    uint64_t blocked_identity;
    uint64_t probe_identity;
    uint32_t probe_handle;
} fake_runtime_t;

typedef struct release_thread_context {
    kernel_file_description_locator_t locator;
    kernel_file_description_release_t release;
    atomic_uint begin_complete;
    atomic_uint finish_requested;
    int begin_result;
    int finish_result;
} release_thread_context_t;

typedef struct position_thread_context {
    kernel_file_description_locator_t locator;
    uint32_t iterations;
} position_thread_context_t;

static fake_runtime_t g_fake;

static void fake_callback_reenter(fake_runtime_t *runtime,
                                  uint64_t detaching_identity) {
    kernel_file_description_snapshot_t snapshot;

    if (!atomic_load_explicit(
            &runtime->callback_reentry, memory_order_acquire) ||
        !runtime->probe_handle ||
        detaching_identity == runtime->probe_identity)
        return;
    assert(kernel_file_description_snapshot(
               kernel_file_description_handle_locator(
                   runtime->probe_handle),
               &snapshot) == 0);
    assert(snapshot.identity == runtime->probe_identity);
}

static void fake_detach_description(void *context, uint64_t identity) {
    fake_runtime_t *runtime = (fake_runtime_t *)context;

    atomic_fetch_add_explicit(
        &runtime->detach_count, 1u, memory_order_relaxed);
    fake_callback_reenter(runtime, identity);
    if (atomic_load_explicit(
            &runtime->block_detach, memory_order_acquire) &&
        identity == runtime->blocked_identity) {
        atomic_store_explicit(
            &runtime->detach_entered, 1u, memory_order_release);
        while (!atomic_load_explicit(
                   &runtime->allow_detach, memory_order_acquire))
            sched_yield();
    }
}

static void fake_release_payload(void *context, void *payload) {
    fake_runtime_t *runtime = (fake_runtime_t *)context;
    uint32_t *marker = (uint32_t *)payload;

    assert(marker);
    assert(*marker == UINT32_C(0xf17ed00d));
    *marker = 0;
    fake_callback_reenter(runtime, 0);
    atomic_fetch_add_explicit(
        &runtime->payload_release_count, 1u, memory_order_relaxed);
}

static void *release_thread(void *opaque) {
    release_thread_context_t *context =
        (release_thread_context_t *)opaque;

    context->begin_result =
        kernel_file_description_release_begin(
            context->locator, &context->release);
    atomic_store_explicit(
        &context->begin_complete, 1u, memory_order_release);
    while (!atomic_load_explicit(
               &context->finish_requested, memory_order_acquire))
        sched_yield();
    context->finish_result =
        kernel_file_description_release_finish(&context->release);
    return 0;
}

static void *position_increment_thread(void *opaque) {
    position_thread_context_t *context =
        (position_thread_context_t *)opaque;

    for (uint32_t iteration = 0;
         iteration < context->iterations; ++iteration) {
        kernel_file_description_position_t position;
        int result;

        result = kernel_file_description_position_reserve(
            context->locator, &position);
        assert(result == 0 || result == 1);
        while (result == 0) {
            sched_yield();
            result = kernel_file_description_position_poll(
                &position);
        }
        assert(result == 1);
        assert(position.active);
        assert(position.acquired);
        assert(position.offset != UINT64_MAX);
        assert(kernel_file_description_position_commit(
                   &position, position.offset + 1u) == 0);
    }
    return 0;
}

static void release_description(
    kernel_file_description_locator_t locator) {
    kernel_file_description_release_t release;
    assert(kernel_file_description_release_begin(
               locator, &release) == 0);
    if (release.last_reference) {
        assert(release.active);
        assert(release.remaining_references == 0u);
        assert(kernel_file_description_release_finish(
                   &release) == 0);
    } else {
        assert(!release.active);
    }
}

static void test_initialization(void) {
    kernel_file_description_ops_t invalid = { 0 };
    kernel_file_description_ops_t ops = {
        .detach_description = fake_detach_description,
        .release_payload = fake_release_payload,
        .context = &g_fake,
    };

    assert(kernel_file_description_runtime_initialize(0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_file_description_runtime_initialize(&invalid) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_file_description_runtime_initialize(&ops) == 0);
    assert(kernel_file_description_runtime_initialize(&ops) ==
           -EDGE_LINUX_EBUSY);
}

static void test_basic_shared_state(void) {
    kernel_file_description_snapshot_t snapshot;
    kernel_file_description_release_t release;
    kernel_file_description_locator_t by_handle;
    kernel_file_description_locator_t by_identity;
    uint64_t identity_value;
    uint64_t expected;
    uint64_t offset;
    uint64_t cursor;
    uint64_t new_offset;
    uint32_t handle;
    uint32_t mount_namespace;
    uint32_t mount_generation;
    uint32_t status;
    int32_t async_owner;
    int32_t async_signal;
    int32_t clock_id;
    uint64_t identity;
    unsigned detach_before;

    assert(kernel_file_description_create(
               7u, 0x1234u, 0, &handle, &identity) == 0);
    assert(handle > 0u && handle <= INT32_MAX);
    assert(identity != 0u && identity != UINT64_MAX);
    by_handle = kernel_file_description_handle_locator(handle);
    by_identity =
        kernel_file_description_identity_locator(identity);

    assert(kernel_file_description_snapshot(by_handle, &snapshot) == 0);
    assert(snapshot.handle == handle);
    assert(snapshot.identity == identity);
    assert(snapshot.offset == 7u);
    assert(snapshot.references == 1u);
    assert(snapshot.epoll_pins == 0u);
    assert(snapshot.status_flags == 0x1234u);
    assert(!snapshot.mount_monitor_configured);
    assert(kernel_file_description_identity(
               by_handle, &identity_value) == 0);
    assert(identity_value == identity);
    assert(kernel_file_description_identity(
               by_identity, &identity_value) == 0);
    assert(identity_value == identity);

    assert(kernel_file_description_retain(by_identity) == 0);
    assert(kernel_file_description_snapshot(by_handle, &snapshot) == 0);
    assert(snapshot.references == 2u);

    assert(kernel_file_description_offset_store(
               by_handle, 19u) == 0);
    assert(kernel_file_description_offset_load(
               by_identity, &offset) == 0);
    assert(offset == 19u);
    expected = 18u;
    assert(kernel_file_description_offset_compare_exchange(
               by_identity, &expected, 27u) == 0);
    assert(expected == 19u);
    assert(kernel_file_description_offset_compare_exchange(
               by_identity, &expected, 27u) == 1);
    assert(kernel_file_description_offset_add(
               by_handle, 5u, &new_offset) == 0);
    assert(new_offset == 32u);
    assert(kernel_file_description_offset_store(
               by_handle, UINT64_MAX - 1u) == 0);
    assert(kernel_file_description_offset_add(
               by_handle, 2u, &new_offset) ==
           -EDGE_LINUX_EOVERFLOW);

    assert(kernel_file_description_input_state_load(
               by_handle, &cursor, &clock_id) == 0);
    assert(cursor == 0u && clock_id == 0);
    assert(kernel_file_description_input_cursor_store(
               by_identity, 41u) == 0);
    assert(kernel_file_description_input_clock_store(
               by_handle, 7) == 0);
    expected = 40u;
    assert(kernel_file_description_input_cursor_compare_exchange(
               by_handle, &expected, 55u) == 0);
    assert(expected == 41u);
    assert(kernel_file_description_input_cursor_compare_exchange(
               by_identity, &expected, 55u) == 1);
    assert(kernel_file_description_input_state_load(
               by_handle, &cursor, &clock_id) == 0);
    assert(cursor == 55u && clock_id == 7);

    assert(kernel_file_description_mount_snapshot(
               by_handle, &mount_namespace, &mount_generation) ==
           -EDGE_LINUX_ENODATA);
    assert(kernel_file_description_mount_bind(
               by_identity, 9u, 100u) == 0);
    assert(kernel_file_description_mount_snapshot(
               by_handle, &mount_namespace, &mount_generation) == 0);
    assert(mount_namespace == 9u && mount_generation == 100u);
    assert(kernel_file_description_mount_acknowledge(
               by_handle, 10u, 101u) == -EDGE_LINUX_EAGAIN);
    assert(kernel_file_description_mount_acknowledge(
               by_handle, 9u, 101u) == 0);
    assert(kernel_file_description_mount_snapshot(
               by_identity, &mount_namespace, &mount_generation) == 0);
    assert(mount_generation == 101u);
    assert(kernel_file_description_mount_bind(
               by_handle, KERNEL_FILE_DESCRIPTION_NO_MOUNT_NAMESPACE,
               500u) == 0);
    assert(kernel_file_description_mount_snapshot(
               by_handle, &mount_namespace, &mount_generation) ==
           -EDGE_LINUX_ENODATA);

    assert(kernel_file_description_status_update(
               by_identity, 0xffu, 0x5au) == 0);
    assert(kernel_file_description_status_load(
               by_handle, &status) == 0);
    assert(status == 0x125au);

    assert(kernel_file_description_async_state_load(
               by_handle, &async_owner, &async_signal) == 0);
    assert(async_owner == 0 && async_signal == 0);
    assert(kernel_file_description_async_owner_store(
               by_identity, -77) == 0);
    assert(kernel_file_description_async_signal_store(
               by_handle, 41) == 0);
    assert(kernel_file_description_async_state_load(
               by_identity, &async_owner, &async_signal) == 0);
    assert(async_owner == -77 && async_signal == 41);

    assert(kernel_file_description_release_begin(
               by_handle, &release) == 0);
    assert(!release.last_reference);
    assert(!release.active);
    assert(release.remaining_references == 1u);
    assert(kernel_file_description_release_finish(&release) ==
           -EDGE_LINUX_EINVAL);

    detach_before = atomic_load_explicit(
        &g_fake.detach_count, memory_order_relaxed);
    assert(kernel_file_description_release_begin(
               by_identity, &release) == 0);
    assert(release.last_reference && release.active);
    assert(release.remaining_references == 0u);
    assert(release.handle == handle);
    assert(atomic_load_explicit(
               &g_fake.detach_count, memory_order_relaxed) ==
           detach_before + 1u);
    assert(kernel_file_description_snapshot(
               by_handle, &snapshot) == -EDGE_LINUX_EBADF);
    assert(kernel_file_description_pin_identity(identity) ==
           -EDGE_LINUX_EBADF);
    assert(kernel_file_description_release_finish(&release) == 0);
    assert(kernel_file_description_release_finish(&release) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_file_description_snapshot(
               by_handle, &snapshot) == -EDGE_LINUX_EBADF);
    assert(kernel_file_description_identity(
               by_identity, &identity_value) == -EDGE_LINUX_EBADF);
}

static void test_payload_lifetime(void) {
    kernel_file_description_release_t release;
    uint32_t marker = UINT32_C(0xf17ed00d);
    uint32_t handle;
    uint64_t identity;
    unsigned payload_before = atomic_load_explicit(
        &g_fake.payload_release_count, memory_order_relaxed);

    assert(kernel_file_description_create(
               0u, 0u, &marker, &handle, &identity) == 0);
    assert(kernel_file_description_release_begin(
               kernel_file_description_handle_locator(handle),
               &release) == 0);
    assert(release.last_reference && release.active);
    assert(marker == UINT32_C(0xf17ed00d));
    assert(atomic_load_explicit(
               &g_fake.payload_release_count, memory_order_relaxed) ==
           payload_before);
    assert(kernel_file_description_release_finish(&release) == 0);
    assert(marker == 0u);
    assert(atomic_load_explicit(
               &g_fake.payload_release_count, memory_order_relaxed) ==
           payload_before + 1u);
    assert(kernel_file_description_pin_identity(identity) ==
           -EDGE_LINUX_EBADF);
}

static void test_position_transactions(void) {
    enum {
        POSITION_THREAD_COUNT = 4,
        POSITION_ITERATIONS = 500,
    };
    kernel_file_description_position_t first;
    kernel_file_description_position_t second;
    kernel_file_description_position_t third;
    kernel_file_description_release_t release;
    kernel_file_description_snapshot_t snapshot;
    kernel_file_description_locator_t locator;
    position_thread_context_t contexts[POSITION_THREAD_COUNT];
    pthread_t threads[POSITION_THREAD_COUNT];
    uint32_t marker = UINT32_C(0xf17ed00d);
    uint32_t handle;
    uint64_t identity;
    uint64_t offset;
    uint64_t expected;
    unsigned payload_before;

    assert(kernel_file_description_create(
               13u, 0u, 0, &handle, &identity) == 0);
    locator = kernel_file_description_handle_locator(handle);
    assert(kernel_file_description_position_try_begin(
               locator, &first) == 0);
    assert(first.active && first.offset == 13u);
    assert(kernel_file_description_snapshot(
               locator, &snapshot) == 0);
    assert(snapshot.position_busy);
    assert(kernel_file_description_position_try_begin(
               locator, &second) == -EDGE_LINUX_EAGAIN);
    assert(!second.active);
    assert(kernel_file_description_offset_store(
               locator, 14u) == -EDGE_LINUX_EAGAIN);
    expected = 13u;
    assert(kernel_file_description_offset_compare_exchange(
               locator, &expected, 14u) == -EDGE_LINUX_EAGAIN);
    assert(kernel_file_description_offset_add(
               locator, 1u, &offset) == -EDGE_LINUX_EAGAIN);
    assert(kernel_file_description_position_abort(&first) == 0);
    assert(!first.active);
    assert(kernel_file_description_position_abort(&first) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_file_description_offset_load(
               locator, &offset) == 0);
    assert(offset == 13u);

    assert(kernel_file_description_position_reserve(
               locator, &first) == 1);
    assert(kernel_file_description_position_reserve(
               locator, &second) == 0);
    assert(kernel_file_description_position_reserve(
               locator, &third) == 0);
    assert(second.active && !second.acquired);
    assert(third.active && !third.acquired);
    assert(kernel_file_description_position_commit(
               &first, 20u) == 0);
    assert(kernel_file_description_position_poll(&second) == 1);
    assert(second.offset == 20u);
    assert(kernel_file_description_position_poll(&third) == 0);
    assert(kernel_file_description_position_commit(
               &second, 21u) == 0);
    assert(kernel_file_description_position_poll(&third) == 1);
    assert(third.offset == 21u);
    assert(kernel_file_description_position_abort(&third) == 0);
    assert(kernel_file_description_offset_load(
               locator, &offset) == 0);
    assert(offset == 21u);

    for (uint32_t index = 0;
         index < POSITION_THREAD_COUNT; ++index) {
        contexts[index].locator = locator;
        contexts[index].iterations = POSITION_ITERATIONS;
        assert(pthread_create(
                   &threads[index], 0, position_increment_thread,
                   &contexts[index]) == 0);
    }
    for (uint32_t index = 0;
         index < POSITION_THREAD_COUNT; ++index)
        assert(pthread_join(threads[index], 0) == 0);
    assert(kernel_file_description_offset_load(
               locator, &offset) == 0);
    assert(offset == 21u +
           POSITION_THREAD_COUNT * POSITION_ITERATIONS);
    release_description(locator);

    payload_before = atomic_load_explicit(
        &g_fake.payload_release_count, memory_order_relaxed);
    assert(kernel_file_description_create(
               31u, 0u, &marker, &handle, &identity) == 0);
    locator = kernel_file_description_handle_locator(handle);
    assert(kernel_file_description_position_reserve(
               locator, &first) == 1);
    assert(kernel_file_description_position_reserve(
               locator, &second) == 0);
    assert(kernel_file_description_release_begin(
               locator, &release) == 0);
    assert(release.last_reference && release.active);
    assert(kernel_file_description_release_finish(&release) == 0);
    assert(marker == UINT32_C(0xf17ed00d));
    assert(atomic_load_explicit(
               &g_fake.payload_release_count, memory_order_relaxed) ==
           payload_before);
    assert(kernel_file_description_position_commit(
               &first, 32u) == 0);
    assert(kernel_file_description_position_poll(&second) == 1);
    assert(second.offset == 32u);
    assert(marker == UINT32_C(0xf17ed00d));
    assert(kernel_file_description_position_abort(&second) == 0);
    assert(marker == 0u);
    assert(atomic_load_explicit(
               &g_fake.payload_release_count, memory_order_relaxed) ==
           payload_before + 1u);
}

static void test_pin_after_close_finish(void) {
    kernel_file_description_release_t release;
    uint32_t marker = UINT32_C(0xf17ed00d);
    uint32_t handle;
    uint64_t identity;
    unsigned detach_before = atomic_load_explicit(
        &g_fake.detach_count, memory_order_relaxed);
    unsigned payload_before = atomic_load_explicit(
        &g_fake.payload_release_count, memory_order_relaxed);

    assert(kernel_file_description_create(
               0u, 0u, &marker, &handle, &identity) == 0);
    assert(kernel_file_description_pin_identity(identity) == 0);
    assert(kernel_file_description_release_begin(
               kernel_file_description_handle_locator(handle),
               &release) == 0);
    assert(release.last_reference);
    assert(atomic_load_explicit(
               &g_fake.detach_count, memory_order_relaxed) ==
           detach_before + 1u);
    assert(kernel_file_description_release_finish(&release) == 0);
    assert(marker == UINT32_C(0xf17ed00d));
    assert(kernel_file_description_unpin_identity(identity) == 0);
    assert(atomic_load_explicit(
               &g_fake.detach_count, memory_order_relaxed) ==
           detach_before + 2u);
    assert(marker == 0u);
    assert(atomic_load_explicit(
               &g_fake.payload_release_count, memory_order_relaxed) ==
           payload_before + 1u);
}

static void test_inflight_control_race(void) {
    release_thread_context_t thread_context;
    pthread_t thread;
    uint32_t marker = UINT32_C(0xf17ed00d);
    uint32_t handle;
    uint64_t identity;
    unsigned detach_before = atomic_load_explicit(
        &g_fake.detach_count, memory_order_relaxed);
    unsigned payload_before = atomic_load_explicit(
        &g_fake.payload_release_count, memory_order_relaxed);

    file_description_bytes_zero(
        &thread_context, sizeof(thread_context));
    atomic_init(&thread_context.begin_complete, 0u);
    atomic_init(&thread_context.finish_requested, 0u);
    assert(kernel_file_description_create(
               0u, 0u, &marker, &handle, &identity) == 0);
    assert(kernel_file_description_pin_identity(identity) == 0);

    g_fake.blocked_identity = identity;
    atomic_store_explicit(
        &g_fake.detach_entered, 0u, memory_order_relaxed);
    atomic_store_explicit(
        &g_fake.allow_detach, 0u, memory_order_relaxed);
    atomic_store_explicit(
        &g_fake.block_detach, 1u, memory_order_release);
    thread_context.locator =
        kernel_file_description_identity_locator(identity);
    assert(pthread_create(
               &thread, 0, release_thread, &thread_context) == 0);

    while (!atomic_load_explicit(
               &g_fake.detach_entered, memory_order_acquire))
        sched_yield();
    /*
     * The detach callback is blocked. Unpin must still acquire the lifecycle
     * lock and request a second pass, proving the callback is outside the lock.
     */
    assert(kernel_file_description_pin_identity(identity) ==
           -EDGE_LINUX_EBADF);
    assert(kernel_file_description_unpin_identity(identity) == 0);
    assert(marker == UINT32_C(0xf17ed00d));
    atomic_store_explicit(
        &g_fake.allow_detach, 1u, memory_order_release);
    while (!atomic_load_explicit(
               &thread_context.begin_complete, memory_order_acquire))
        sched_yield();
    assert(thread_context.begin_result == 0);
    assert(thread_context.release.last_reference);
    assert(atomic_load_explicit(
               &g_fake.detach_count, memory_order_relaxed) ==
           detach_before + 2u);
    assert(atomic_load_explicit(
               &g_fake.payload_release_count, memory_order_relaxed) ==
           payload_before);

    atomic_store_explicit(
        &thread_context.finish_requested, 1u, memory_order_release);
    assert(pthread_join(thread, 0) == 0);
    assert(thread_context.finish_result == 0);
    assert(marker == 0u);
    assert(atomic_load_explicit(
               &g_fake.payload_release_count, memory_order_relaxed) ==
           payload_before + 1u);
    atomic_store_explicit(
        &g_fake.block_detach, 0u, memory_order_release);
}

static void test_counter_guards(void) {
    kernel_file_description_locator_t locator;
    kernel_file_description_release_t release;
    kernel_file_description_entry_t *entry;
    uint64_t irq_flags;
    uint32_t handle;
    uint32_t slot;
    uint64_t identity;

    assert(kernel_file_description_create(
               0u, 0u, 0, &handle, &identity) == 0);
    locator = kernel_file_description_handle_locator(handle);
    slot = handle & FILE_DESCRIPTION_SLOT_MASK;

    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry = &g_file_descriptions[slot];
    assert(entry->identity == identity);
    entry->references = UINT32_MAX;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    assert(kernel_file_description_retain(locator) ==
           -EDGE_LINUX_EOVERFLOW);
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry->references = 1u;
    entry->epoll_pins = UINT32_MAX;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    assert(kernel_file_description_pin_identity(identity) ==
           -EDGE_LINUX_EOVERFLOW);
    irq_flags = spin_lock_irqsave(&g_file_description_lock);
    entry->epoll_pins = 0u;
    spin_unlock_irqrestore(&g_file_description_lock, irq_flags);
    assert(kernel_file_description_unpin_identity(identity) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_file_description_release_begin(
               locator, &release) == 0);
    assert(release.last_reference);
    assert(kernel_file_description_release_finish(&release) == 0);
}

static void test_pool_exhaustion_and_handle_reuse(void) {
    static uint32_t handles[KERNEL_FILE_DESCRIPTION_CAPACITY];
    static uint64_t identities[KERNEL_FILE_DESCRIPTION_CAPACITY];
    kernel_file_description_snapshot_t snapshot;
    kernel_file_description_release_t release;
    uint32_t replacement_handle;
    uint32_t old_handle;
    uint32_t old_slot;
    uint64_t replacement_identity;
    uint64_t old_identity;
    uint32_t count = 0;

    while (count < KERNEL_FILE_DESCRIPTION_CAPACITY) {
        int result = kernel_file_description_create(
            count, count, 0, &handles[count], &identities[count]);
        if (result == -EDGE_LINUX_ENFILE) break;
        assert(result == 0);
        if (count)
            assert(identities[count] > identities[count - 1u]);
        ++count;
    }
    assert(count == KERNEL_FILE_DESCRIPTION_CAPACITY - 1u);
    assert(kernel_file_description_create(
               0u, 0u, 0, &replacement_handle,
               &replacement_identity) == -EDGE_LINUX_ENFILE);
    assert(replacement_handle == 0u);
    assert(replacement_identity == 0u);

    old_handle = handles[count / 2u];
    old_identity = identities[count / 2u];
    old_slot = old_handle & FILE_DESCRIPTION_SLOT_MASK;
    assert(kernel_file_description_release_begin(
               kernel_file_description_handle_locator(old_handle),
               &release) == 0);
    assert(release.last_reference);
    assert(kernel_file_description_release_finish(&release) == 0);

    assert(kernel_file_description_create(
               999u, 0u, 0, &replacement_handle,
               &replacement_identity) == 0);
    assert((replacement_handle & FILE_DESCRIPTION_SLOT_MASK) == old_slot);
    assert(replacement_handle != old_handle);
    assert(replacement_identity != old_identity);
    assert(kernel_file_description_snapshot(
               kernel_file_description_handle_locator(old_handle),
               &snapshot) == -EDGE_LINUX_EBADF);
    assert(kernel_file_description_pin_identity(old_identity) ==
           -EDGE_LINUX_EBADF);
    assert(kernel_file_description_snapshot(
               kernel_file_description_handle_locator(
                   replacement_handle),
               &snapshot) == 0);
    assert(snapshot.identity == replacement_identity);
    assert(snapshot.offset == 999u);

    release_description(
        kernel_file_description_handle_locator(replacement_handle));
    for (uint32_t index = 0; index < count; ++index) {
        if (index == count / 2u) continue;
        release_description(
            kernel_file_description_handle_locator(handles[index]));
    }
}

int main(void) {
    uint32_t probe_handle;

    test_initialization();
    assert(kernel_file_description_create(
               0u, 0u, 0, &probe_handle,
               &g_fake.probe_identity) == 0);
    g_fake.probe_handle = probe_handle;
    atomic_store_explicit(
        &g_fake.callback_reentry, 1u, memory_order_release);

    test_basic_shared_state();
    test_payload_lifetime();
    test_position_transactions();
    test_pin_after_close_finish();
    test_inflight_control_race();
    test_counter_guards();
    test_pool_exhaustion_and_handle_reuse();

    atomic_store_explicit(
        &g_fake.callback_reentry, 0u, memory_order_release);
    release_description(
        kernel_file_description_handle_locator(probe_handle));
    puts("FILE_DESCRIPTION_RUNTIME_UNIT_PASS");
    return 0;
}
