/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side concurrency and lifetime tests for the shared epoll core. */

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * The kernel spinlock disables interrupts, which is not legal in a host
 * process. Define the include guard and provide the same lock API with a
 * userspace-safe atomic lock before including the common implementation.
 */
#define SYS_SPINLOCK_H
typedef struct {
    atomic_flag value;
} spinlock_t;

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

#include "../../src/kernel/epoll_runtime.c"

#define FAKE_MAX_DESCRIPTORS 256
#define STRESS_EPOLL_COUNT 8
#define STRESS_LEAF_COUNT 24
#define STRESS_THREAD_COUNT 4
#define STRESS_ITERATIONS 2000
#define FAKE_SOURCE_TRACK_CAPACITY 4096

typedef enum fake_descriptor_kind {
    FAKE_DESCRIPTOR_NONE = 0,
    FAKE_DESCRIPTOR_EPOLL,
    FAKE_DESCRIPTOR_LEAF,
} fake_descriptor_kind_t;

typedef struct fake_descriptor {
    uint8_t open;
    uint8_t kind;
    int32_t epoll_index;
    uint64_t description_id;
} fake_descriptor_t;

typedef struct fake_backend {
    fake_descriptor_t descriptors[FAKE_MAX_DESCRIPTORS];
    int32_t next_descriptor;
    uint64_t next_description_id;
    atomic_uint change_count;
    atomic_uint source_capture_count;
    atomic_uint source_release_count;
    atomic_uint live_source_count;
    atomic_uint callback_reentry_count;
    atomic_uint source_commit_count;
    atomic_uint source_references[FAKE_SOURCE_TRACK_CAPACITY];
    int32_t callback_reentry_epoll_index;
    uint8_t reenter_capture_callback;
    uint8_t reenter_release_callback;
    uint8_t fail_source_capture;
    uint64_t ready_description_id;
    uint32_t ready_events;
    uint64_t read_ready_sequence;
    uint64_t write_ready_sequence;
} fake_backend_t;

typedef struct start_gate {
    atomic_uint ready;
    atomic_uint start;
} start_gate_t;

static void epoll_core_reset(void) {
    memset(g_epolls, 0, sizeof(g_epolls));
    memset(g_epoll_generations, 0, sizeof(g_epoll_generations));
    memset(g_epoll_watch_generations, 0,
           sizeof(g_epoll_watch_generations));
    atomic_flag_clear_explicit(
        &g_epoll_lock.value, memory_order_relaxed);
    g_epoll_claim_sequence = 0;
    g_backend_ops = 0;
    g_backend_context = 0;
}

static int fake_descriptor_allocate(fake_backend_t *backend,
                                    fake_descriptor_kind_t kind,
                                    int32_t epoll_index,
                                    uint64_t description_id) {
    int32_t descriptor = backend->next_descriptor++;
    fake_descriptor_t *entry;

    assert(descriptor >= 0 && descriptor < FAKE_MAX_DESCRIPTORS);
    entry = &backend->descriptors[descriptor];
    assert(!entry->open);
    entry->open = 1u;
    entry->kind = (uint8_t)kind;
    entry->epoll_index = epoll_index;
    entry->description_id = description_id;
    return descriptor;
}

static int fake_install_descriptor(void *context, int32_t epoll_index,
                                   uint32_t flags) {
    fake_backend_t *backend = context;
    uint64_t description_id;

    (void)flags;
    description_id = ++backend->next_description_id;
    assert(description_id != 0);
    return fake_descriptor_allocate(
        backend, FAKE_DESCRIPTOR_EPOLL, epoll_index, description_id);
}

static int fake_resolve_epoll_descriptor(void *context, int32_t descriptor,
                                         int32_t *epoll_index) {
    fake_backend_t *backend = context;
    fake_descriptor_t *entry;

    if (!epoll_index || descriptor < 0 ||
        descriptor >= FAKE_MAX_DESCRIPTORS)
        return -EDGE_LINUX_EBADF;
    entry = &backend->descriptors[descriptor];
    if (!entry->open || entry->kind != FAKE_DESCRIPTOR_EPOLL)
        return -EDGE_LINUX_EBADF;
    *epoll_index = entry->epoll_index;
    return 0;
}

static int fake_resolve_target_descriptor(void *context, int32_t descriptor,
                                          uint64_t *description_id,
                                          int32_t *target_epoll_index) {
    fake_backend_t *backend = context;
    fake_descriptor_t *entry;

    if (!description_id || !target_epoll_index || descriptor < 0 ||
        descriptor >= FAKE_MAX_DESCRIPTORS)
        return -EDGE_LINUX_EBADF;
    entry = &backend->descriptors[descriptor];
    if (!entry->open) return -EDGE_LINUX_EBADF;
    *description_id = entry->description_id;
    *target_epoll_index =
        entry->kind == FAKE_DESCRIPTOR_EPOLL ? entry->epoll_index : -1;
    return 0;
}

static void fake_callback_reenter_epoll(fake_backend_t *backend) {
    int32_t epoll_index = backend->callback_reentry_epoll_index;

    (void)kernel_epoll_object_exists(epoll_index);
    (void)kernel_epoll_graph_reaches(epoll_index, epoll_index);
    atomic_fetch_add_explicit(
        &backend->callback_reentry_count, 1u,
        memory_order_relaxed);
}

static int fake_capture_target_source(
        void *context, int32_t descriptor,
        uint64_t expected_description_id,
        kernel_epoll_target_source_t *source) {
    fake_backend_t *backend = context;
    fake_descriptor_t *entry;
    uint32_t source_slot;

    if (!source || descriptor < 0 ||
        descriptor >= FAKE_MAX_DESCRIPTORS)
        return -EDGE_LINUX_EBADF;
    if (backend->fail_source_capture)
        return -EDGE_LINUX_ENOMEM;
    entry = &backend->descriptors[descriptor];
    if (!entry->open ||
        entry->description_id != expected_description_id)
        return -EDGE_LINUX_EBADF;
    assert(expected_description_id < FAKE_SOURCE_TRACK_CAPACITY);
    source_slot = (uint32_t)expected_description_id;
    memset(source, 0, sizeof(*source));
    source->kind = entry->kind;
    source->flags = UINT32_C(0xa5000000) | entry->kind;
    source->primary_object_id = (int32_t)expected_description_id;
    source->secondary_object_id = entry->epoll_index;
    source->cookie = expected_description_id;
    atomic_fetch_add_explicit(
        &backend->source_references[source_slot], 1u,
        memory_order_relaxed);
    atomic_fetch_add_explicit(
        &backend->source_capture_count, 1u,
        memory_order_relaxed);
    atomic_fetch_add_explicit(
        &backend->live_source_count, 1u,
        memory_order_relaxed);
    if (backend->reenter_capture_callback)
        fake_callback_reenter_epoll(backend);
    return 0;
}

static void fake_release_target_source(
        void *context,
        const kernel_epoll_target_source_t *source) {
    fake_backend_t *backend = context;
    uint32_t source_slot;
    unsigned int previous;

    assert(source);
    assert(source->kind == FAKE_DESCRIPTOR_EPOLL ||
           source->kind == FAKE_DESCRIPTOR_LEAF);
    assert(source->flags ==
           (UINT32_C(0xa5000000) | source->kind));
    assert(source->cookie < FAKE_SOURCE_TRACK_CAPACITY);
    assert(source->primary_object_id == (int32_t)source->cookie);
    source_slot = (uint32_t)source->cookie;
    previous = atomic_fetch_sub_explicit(
        &backend->source_references[source_slot], 1u,
        memory_order_relaxed);
    assert(previous > 0u);
    previous = atomic_fetch_sub_explicit(
        &backend->live_source_count, 1u,
        memory_order_relaxed);
    assert(previous > 0u);
    atomic_fetch_add_explicit(
        &backend->source_release_count, 1u,
        memory_order_relaxed);
    if (backend->reenter_release_callback)
        fake_callback_reenter_epoll(backend);
}

static int fake_observe_target_source(
        void *context,
        const kernel_epoll_target_source_t *source,
        uint32_t requested_events, uint32_t *ready_events,
        uint64_t *read_ready_sequence,
        uint64_t *write_ready_sequence) {
    fake_backend_t *backend = context;

    (void)requested_events;
    if (!backend || !source || !ready_events ||
        !read_ready_sequence || !write_ready_sequence)
        return -EDGE_LINUX_EINVAL;
    *ready_events = source->cookie == backend->ready_description_id ?
        backend->ready_events : 0u;
    *read_ready_sequence = backend->read_ready_sequence;
    *write_ready_sequence = backend->write_ready_sequence;
    return 0;
}

static void fake_commit_target_source(
        void *context,
        const kernel_epoll_target_source_t *source) {
    fake_backend_t *backend = context;

    assert(backend && source);
    atomic_fetch_add_explicit(
        &backend->source_commit_count, 1u, memory_order_relaxed);
}

static void fake_watch_set_changed(void *context, int32_t epoll_index) {
    fake_backend_t *backend = context;

    assert(epoll_index >= 0 &&
           epoll_index < (int32_t)EDGE_RUNTIME_MAX_EPOLLS);
    atomic_fetch_add_explicit(
        &backend->change_count, 1u, memory_order_relaxed);
}

static const kernel_epoll_backend_ops_t g_fake_backend_ops = {
    .install_descriptor = fake_install_descriptor,
    .resolve_epoll_descriptor = fake_resolve_epoll_descriptor,
    .resolve_target_descriptor = fake_resolve_target_descriptor,
    .capture_target_source = fake_capture_target_source,
    .release_target_source = fake_release_target_source,
    .observe_target_source = fake_observe_target_source,
    .commit_target_source = fake_commit_target_source,
    .watch_set_changed = fake_watch_set_changed,
};

static const kernel_epoll_backend_ops_t g_fake_legacy_backend_ops = {
    .install_descriptor = fake_install_descriptor,
    .resolve_epoll_descriptor = fake_resolve_epoll_descriptor,
    .resolve_target_descriptor = fake_resolve_target_descriptor,
    .watch_set_changed = fake_watch_set_changed,
};

static void fake_backend_initialize_with_ops(
        fake_backend_t *backend,
        const kernel_epoll_backend_ops_t *ops) {
    memset(backend, 0, sizeof(*backend));
    backend->next_descriptor = 10;
    backend->next_description_id = 1000;
    backend->callback_reentry_epoll_index = -1;
    atomic_init(&backend->change_count, 0);
    atomic_init(&backend->source_capture_count, 0);
    atomic_init(&backend->source_release_count, 0);
    atomic_init(&backend->live_source_count, 0);
    atomic_init(&backend->callback_reentry_count, 0);
    atomic_init(&backend->source_commit_count, 0);
    for (uint32_t index = 0;
         index < FAKE_SOURCE_TRACK_CAPACITY; ++index)
        atomic_init(&backend->source_references[index], 0);
    epoll_core_reset();
    assert(kernel_epoll_backend_register(
               ops, backend) == 0);
}

static void fake_backend_initialize(fake_backend_t *backend);
static int fake_create_epoll(fake_backend_t *backend,
                             int32_t *index_out);
static int fake_create_leaf(fake_backend_t *backend);
static void fake_close_descriptor(fake_backend_t *backend,
                                  int descriptor);
static int epoll_add(int epoll_descriptor, int target_descriptor,
                     uint32_t events, uint64_t data);

typedef struct fake_event_copy_context {
    kernel_epoll_event_t events[4];
    uint32_t count;
    int fail;
} fake_event_copy_context_t;

static int fake_copy_event(void *context, uint32_t event_index,
                           const kernel_epoll_event_t *event) {
    fake_event_copy_context_t *copy = context;

    if (!copy || !event || event_index >= 4u)
        return -EDGE_LINUX_EFAULT;
    if (copy->fail) return -EDGE_LINUX_EFAULT;
    copy->events[event_index] = *event;
    copy->count = event_index + 1u;
    return 0;
}

static void test_common_event_delivery(void) {
    fake_backend_t backend;
    fake_event_copy_context_t copy = {0};
    kernel_epoll_object_snapshot_t snapshot;
    int32_t epoll_index;
    int32_t retained_index = -1;
    int epoll_descriptor;
    int leaf;

    fake_backend_initialize(&backend);
    epoll_descriptor = fake_create_epoll(&backend, &epoll_index);
    leaf = fake_create_leaf(&backend);
    assert(epoll_add(
               epoll_descriptor, leaf,
               KERNEL_EPOLLIN | KERNEL_EPOLLET,
               0x1122334455667788ull) == 0);
    assert(kernel_epoll_descriptor_retain(
               epoll_descriptor, &retained_index) == 0);
    assert(retained_index == epoll_index);
    assert(kernel_epoll_object_snapshot(
               epoll_index, &snapshot) == 0);
    assert(snapshot.refs == 2u);
    assert(kernel_epoll_deliver_events(
               epoll_index, 4u, fake_copy_event, &copy) == 0);

    backend.ready_description_id =
        backend.descriptors[leaf].description_id;
    backend.ready_events = KERNEL_EPOLLIN;
    backend.read_ready_sequence = 1u;
    copy.fail = 1;
    assert(kernel_epoll_deliver_events(
               epoll_index, 4u, fake_copy_event, &copy) ==
           -EDGE_LINUX_EFAULT);
    copy.fail = 0;
    assert(kernel_epoll_deliver_events(
               epoll_index, 4u, fake_copy_event, &copy) == 1);
    assert(copy.count == 1u);
    assert(copy.events[0].events == KERNEL_EPOLLIN);
    assert(copy.events[0].data == 0x1122334455667788ull);
    assert(atomic_load_explicit(
               &backend.source_commit_count,
               memory_order_relaxed) == 1u);
    assert(kernel_epoll_deliver_events(
               epoll_index, 4u, fake_copy_event, &copy) == 0);
    ++backend.read_ready_sequence;
    assert(kernel_epoll_deliver_events(
               epoll_index, 4u, fake_copy_event, &copy) == 1);

    kernel_epoll_object_release(retained_index);
    fake_close_descriptor(&backend, leaf);
    fake_close_descriptor(&backend, epoll_descriptor);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
}

static void fake_backend_initialize(fake_backend_t *backend) {
    fake_backend_initialize_with_ops(
        backend, &g_fake_backend_ops);
}

static int fake_create_epoll(fake_backend_t *backend, int32_t *index_out) {
    int descriptor = kernel_epoll_create_descriptor(0);

    assert(descriptor >= 0);
    assert(descriptor < FAKE_MAX_DESCRIPTORS);
    assert(backend->descriptors[descriptor].kind ==
           FAKE_DESCRIPTOR_EPOLL);
    if (index_out)
        *index_out = backend->descriptors[descriptor].epoll_index;
    return descriptor;
}

static int fake_create_leaf(fake_backend_t *backend) {
    uint64_t description_id = ++backend->next_description_id;
    assert(description_id != 0);
    return fake_descriptor_allocate(
        backend, FAKE_DESCRIPTOR_LEAF, -1, description_id);
}

static int fake_duplicate_descriptor(fake_backend_t *backend,
                                     int descriptor) {
    fake_descriptor_t *source;

    assert(descriptor >= 0 && descriptor < FAKE_MAX_DESCRIPTORS);
    source = &backend->descriptors[descriptor];
    assert(source->open);
    if (source->kind == FAKE_DESCRIPTOR_EPOLL)
        assert(kernel_epoll_object_retain(source->epoll_index) == 0);
    return fake_descriptor_allocate(
        backend, (fake_descriptor_kind_t)source->kind,
        source->epoll_index, source->description_id);
}

static int fake_reuse_leaf_descriptor(fake_backend_t *backend,
                                      int descriptor) {
    fake_descriptor_t *entry;
    uint64_t description_id;

    assert(descriptor >= 0 && descriptor < FAKE_MAX_DESCRIPTORS);
    entry = &backend->descriptors[descriptor];
    assert(!entry->open);
    description_id = ++backend->next_description_id;
    assert(description_id != 0);
    entry->open = 1u;
    entry->kind = FAKE_DESCRIPTOR_LEAF;
    entry->epoll_index = -1;
    entry->description_id = description_id;
    return descriptor;
}

static int fake_description_is_open(const fake_backend_t *backend,
                                    uint64_t description_id) {
    for (int descriptor = 0;
         descriptor < backend->next_descriptor; ++descriptor) {
        const fake_descriptor_t *entry =
            &backend->descriptors[descriptor];
        if (entry->open && entry->description_id == description_id)
            return 1;
    }
    return 0;
}

static void fake_close_descriptor(fake_backend_t *backend, int descriptor) {
    fake_descriptor_t closing;

    assert(descriptor >= 0 && descriptor < FAKE_MAX_DESCRIPTORS);
    assert(backend->descriptors[descriptor].open);
    closing = backend->descriptors[descriptor];
    memset(&backend->descriptors[descriptor], 0,
           sizeof(backend->descriptors[descriptor]));
    if (!fake_description_is_open(backend, closing.description_id))
        kernel_epoll_detach_description(closing.description_id);
    if (closing.kind == FAKE_DESCRIPTOR_EPOLL)
        kernel_epoll_object_release(closing.epoll_index);
}

static int epoll_add(int epoll_descriptor, int target_descriptor,
                     uint32_t events, uint64_t data) {
    kernel_epoll_event_t event = {
        .events = events,
        .data = data,
    };
    return kernel_epoll_control_descriptor(
        epoll_descriptor, KERNEL_EPOLL_CTL_ADD,
        target_descriptor, &event);
}

static int epoll_modify(int epoll_descriptor, int target_descriptor,
                        uint32_t events, uint64_t data) {
    kernel_epoll_event_t event = {
        .events = events,
        .data = data,
    };
    return kernel_epoll_control_descriptor(
        epoll_descriptor, KERNEL_EPOLL_CTL_MOD,
        target_descriptor, &event);
}

static int epoll_delete(int epoll_descriptor, int target_descriptor) {
    return kernel_epoll_control_descriptor(
        epoll_descriptor, KERNEL_EPOLL_CTL_DEL,
        target_descriptor, 0);
}

static void test_optional_source_callbacks(void) {
    fake_backend_t backend;
    kernel_epoll_backend_ops_t invalid_ops;
    kernel_epoll_target_source_t empty_source = {0};
    kernel_epoll_watch_snapshot_t snapshot;
    int32_t owner_index;
    int owner;
    int leaf;

    memset(&backend, 0, sizeof(backend));
    epoll_core_reset();
    invalid_ops = g_fake_backend_ops;
    invalid_ops.release_target_source = 0;
    assert(kernel_epoll_backend_register(
               &invalid_ops, &backend) == -EDGE_LINUX_EINVAL);
    invalid_ops = g_fake_backend_ops;
    invalid_ops.capture_target_source = 0;
    assert(kernel_epoll_backend_register(
               &invalid_ops, &backend) == -EDGE_LINUX_EINVAL);

    fake_backend_initialize_with_ops(
        &backend, &g_fake_legacy_backend_ops);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &snapshot) == 1);
    assert(!snapshot.watch.source_captured);
    assert(memcmp(
               &snapshot.watch.source, &empty_source,
               sizeof(empty_source)) == 0);
    assert(epoll_modify(
               owner, leaf, KERNEL_EPOLLOUT, 2u) == 0);
    assert(epoll_delete(owner, leaf) == 0);
    fake_close_descriptor(&backend, leaf);
    fake_close_descriptor(&backend, owner);
}

static void test_source_survives_descriptor_close_and_reuse(void) {
    fake_backend_t backend;
    kernel_epoll_watch_snapshot_t snapshot;
    uint64_t original_description;
    int32_t owner_index;
    int owner;
    int leaf;
    int duplicate;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    duplicate = fake_duplicate_descriptor(&backend, leaf);
    original_description =
        backend.descriptors[leaf].description_id;
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);

    fake_close_descriptor(&backend, leaf);
    assert(fake_reuse_leaf_descriptor(&backend, leaf) == leaf);
    assert(backend.descriptors[leaf].description_id !=
           original_description);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &snapshot) == 1);
    assert(snapshot.watch.source_captured);
    assert(snapshot.watch.source.cookie == original_description);
    assert(snapshot.watch.source.primary_object_id ==
           (int32_t)original_description);
    assert(epoll_modify(
               owner, leaf, KERNEL_EPOLLOUT, 2u) ==
           -EDGE_LINUX_ENOENT);
    assert(epoll_delete(owner, leaf) == -EDGE_LINUX_ENOENT);

    fake_close_descriptor(&backend, duplicate);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &snapshot) == 0);
    assert(atomic_load_explicit(
               &backend.source_capture_count,
               memory_order_relaxed) == 1u);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 1u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
    fake_close_descriptor(&backend, leaf);
    fake_close_descriptor(&backend, owner);
}

static void test_modify_preserves_captured_source(void) {
    fake_backend_t backend;
    kernel_epoll_watch_snapshot_t before;
    kernel_epoll_watch_snapshot_t after;
    int32_t owner_index;
    int owner;
    int leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &before) == 1);
    assert(before.watch.source_captured);
    assert(epoll_modify(
               owner, leaf,
               KERNEL_EPOLLOUT | KERNEL_EPOLLET, 2u) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &after) == 1);
    assert(after.watch.source_captured);
    assert(memcmp(
               &before.watch.source, &after.watch.source,
               sizeof(before.watch.source)) == 0);
    assert(atomic_load_explicit(
               &backend.source_capture_count,
               memory_order_relaxed) == 1u);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 0u);
    assert(epoll_delete(owner, leaf) == 0);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 1u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
    fake_close_descriptor(&backend, leaf);
    fake_close_descriptor(&backend, owner);
}

static void test_release_for_every_watch_removal_path(void) {
    fake_backend_t backend;
    int32_t owner_index;
    int owner;
    int deleted_leaf;
    int detached_leaf;
    int destroyed_leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    deleted_leaf = fake_create_leaf(&backend);
    detached_leaf = fake_create_leaf(&backend);
    destroyed_leaf = fake_create_leaf(&backend);
    assert(epoll_add(
               owner, deleted_leaf, KERNEL_EPOLLIN, 1u) == 0);
    assert(epoll_add(
               owner, detached_leaf, KERNEL_EPOLLIN, 2u) == 0);
    assert(epoll_add(
               owner, destroyed_leaf, KERNEL_EPOLLIN, 3u) == 0);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 3u);

    assert(epoll_delete(owner, deleted_leaf) == 0);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 1u);
    fake_close_descriptor(&backend, detached_leaf);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 2u);
    fake_close_descriptor(&backend, owner);
    assert(!kernel_epoll_object_exists(owner_index));
    assert(atomic_load_explicit(
               &backend.source_capture_count,
               memory_order_relaxed) == 3u);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 3u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
    fake_close_descriptor(&backend, deleted_leaf);
    fake_close_descriptor(&backend, destroyed_leaf);
}

static void test_failed_add_releases_captured_source(void) {
    fake_backend_t backend;
    kernel_epoll_object_snapshot_t object;
    int32_t owner_index;
    int owner;
    int leaf;
    int rejected_leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    rejected_leaf = fake_create_leaf(&backend);
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 2u) ==
           -EDGE_LINUX_EEXIST);
    assert(atomic_load_explicit(
               &backend.source_capture_count,
               memory_order_relaxed) == 2u);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 1u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 1u);

    backend.fail_source_capture = 1u;
    assert(epoll_add(
               owner, rejected_leaf, KERNEL_EPOLLIN, 3u) ==
           -EDGE_LINUX_ENOMEM);
    backend.fail_source_capture = 0u;
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    assert(object.nwatch == 1u);
    assert(atomic_load_explicit(
               &backend.source_capture_count,
               memory_order_relaxed) == 2u);

    assert(epoll_delete(owner, leaf) == 0);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 2u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
    fake_close_descriptor(&backend, leaf);
    fake_close_descriptor(&backend, rejected_leaf);
    fake_close_descriptor(&backend, owner);
}

static void test_source_callbacks_may_reenter_epoll(void) {
    fake_backend_t backend;
    int32_t owner_index;
    int owner;
    int leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    backend.callback_reentry_epoll_index = owner_index;
    backend.reenter_capture_callback = 1u;
    backend.reenter_release_callback = 1u;
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);
    assert(epoll_delete(owner, leaf) == 0);
    assert(atomic_load_explicit(
               &backend.callback_reentry_count,
               memory_order_relaxed) == 2u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
    fake_close_descriptor(&backend, leaf);
    fake_close_descriptor(&backend, owner);
}

static void start_gate_wait(start_gate_t *gate) {
    atomic_fetch_add_explicit(&gate->ready, 1u, memory_order_release);
    while (!atomic_load_explicit(&gate->start, memory_order_acquire))
        sched_yield();
}

typedef enum source_release_race_action {
    SOURCE_RELEASE_RACE_DELETE = 0,
    SOURCE_RELEASE_RACE_DETACH,
    SOURCE_RELEASE_RACE_DESTROY,
} source_release_race_action_t;

typedef struct source_release_race_context {
    start_gate_t *gate;
    source_release_race_action_t action;
    int owner_descriptor;
    int target_descriptor;
    int32_t owner_index;
    uint64_t description_id;
    int result;
} source_release_race_context_t;

static void *source_release_race_thread(void *opaque) {
    source_release_race_context_t *context = opaque;

    start_gate_wait(context->gate);
    if (context->action == SOURCE_RELEASE_RACE_DELETE) {
        context->result = epoll_delete(
            context->owner_descriptor,
            context->target_descriptor);
    } else if (context->action == SOURCE_RELEASE_RACE_DETACH) {
        kernel_epoll_detach_description(context->description_id);
        context->result = 0;
    } else {
        kernel_epoll_object_release(context->owner_index);
        context->result = 0;
    }
    return 0;
}

static void run_source_release_race(
        source_release_race_context_t contexts[2]) {
    pthread_t threads[2];
    start_gate_t gate;

    atomic_init(&gate.ready, 0);
    atomic_init(&gate.start, 0);
    contexts[0].gate = &gate;
    contexts[1].gate = &gate;
    assert(pthread_create(
               &threads[0], 0, source_release_race_thread,
               &contexts[0]) == 0);
    assert(pthread_create(
               &threads[1], 0, source_release_race_thread,
               &contexts[1]) == 0);
    while (atomic_load_explicit(
               &gate.ready, memory_order_acquire) != 2u)
        sched_yield();
    atomic_store_explicit(&gate.start, 1u, memory_order_release);
    assert(pthread_join(threads[0], 0) == 0);
    assert(pthread_join(threads[1], 0) == 0);
}

static void test_concurrent_watch_removal_releases_once(void) {
    fake_backend_t backend;
    source_release_race_context_t contexts[2];
    uint64_t description_id;
    int32_t owner_index;
    int owner;
    int leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    description_id = backend.descriptors[leaf].description_id;
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);
    contexts[0] = (source_release_race_context_t){
        .action = SOURCE_RELEASE_RACE_DELETE,
        .owner_descriptor = owner,
        .target_descriptor = leaf,
        .result = INT32_MIN,
    };
    contexts[1] = (source_release_race_context_t){
        .action = SOURCE_RELEASE_RACE_DETACH,
        .description_id = description_id,
        .result = INT32_MIN,
    };
    run_source_release_race(contexts);
    assert(contexts[0].result == 0 ||
           contexts[0].result == -EDGE_LINUX_ENOENT);
    assert(contexts[1].result == 0);
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 1u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
    fake_close_descriptor(&backend, leaf);
    fake_close_descriptor(&backend, owner);

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    description_id = backend.descriptors[leaf].description_id;
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);
    backend.descriptors[owner].open = 0u;
    contexts[0] = (source_release_race_context_t){
        .action = SOURCE_RELEASE_RACE_DESTROY,
        .owner_index = owner_index,
        .result = INT32_MIN,
    };
    contexts[1] = (source_release_race_context_t){
        .action = SOURCE_RELEASE_RACE_DETACH,
        .description_id = description_id,
        .result = INT32_MIN,
    };
    run_source_release_race(contexts);
    assert(contexts[0].result == 0);
    assert(contexts[1].result == 0);
    assert(!kernel_epoll_object_exists(owner_index));
    assert(atomic_load_explicit(
               &backend.source_release_count,
               memory_order_relaxed) == 1u);
    assert(atomic_load_explicit(
               &backend.live_source_count,
               memory_order_relaxed) == 0u);
    fake_close_descriptor(&backend, leaf);
}

typedef struct cycle_thread_context {
    start_gate_t *gate;
    int parent_descriptor;
    int child_descriptor;
    int result;
} cycle_thread_context_t;

static void *cycle_add_thread(void *opaque) {
    cycle_thread_context_t *context = opaque;

    start_gate_wait(context->gate);
    context->result = epoll_add(
        context->parent_descriptor, context->child_descriptor,
        KERNEL_EPOLLIN, 1u);
    return 0;
}

static void test_concurrent_cycle_add(void) {
    fake_backend_t backend;
    cycle_thread_context_t first;
    cycle_thread_context_t second;
    start_gate_t gate;
    pthread_t threads[2];
    int epolls[2];
    int successes;

    fake_backend_initialize(&backend);
    epolls[0] = fake_create_epoll(&backend, 0);
    epolls[1] = fake_create_epoll(&backend, 0);
    atomic_init(&gate.ready, 0);
    atomic_init(&gate.start, 0);
    first = (cycle_thread_context_t){
        .gate = &gate,
        .parent_descriptor = epolls[0],
        .child_descriptor = epolls[1],
        .result = INT32_MIN,
    };
    second = (cycle_thread_context_t){
        .gate = &gate,
        .parent_descriptor = epolls[1],
        .child_descriptor = epolls[0],
        .result = INT32_MIN,
    };
    assert(pthread_create(
               &threads[0], 0, cycle_add_thread, &first) == 0);
    assert(pthread_create(
               &threads[1], 0, cycle_add_thread, &second) == 0);
    while (atomic_load_explicit(
               &gate.ready, memory_order_acquire) != 2u)
        sched_yield();
    atomic_store_explicit(&gate.start, 1u, memory_order_release);
    assert(pthread_join(threads[0], 0) == 0);
    assert(pthread_join(threads[1], 0) == 0);

    successes = (first.result == 0) + (second.result == 0);
    assert(successes == 1);
    assert((first.result == -EDGE_LINUX_ELOOP) +
           (second.result == -EDGE_LINUX_ELOOP) == 1);
}

static void create_epoll_chain(fake_backend_t *backend,
                               int descriptors[7]) {
    for (int index = 0; index < 7; ++index)
        descriptors[index] = fake_create_epoll(backend, 0);
}

static void test_nesting_depth_in_both_orders(void) {
    fake_backend_t backend;
    int descriptors[7];

    fake_backend_initialize(&backend);
    create_epoll_chain(&backend, descriptors);
    for (int index = 0; index < 5; ++index)
        assert(epoll_add(
                   descriptors[index], descriptors[index + 1],
                   KERNEL_EPOLLIN, (uint64_t)index) == 0);
    assert(epoll_add(
               descriptors[5], descriptors[6],
               KERNEL_EPOLLIN, 5u) == -EDGE_LINUX_ELOOP);

    fake_backend_initialize(&backend);
    create_epoll_chain(&backend, descriptors);
    for (int index = 5; index >= 1; --index)
        assert(epoll_add(
                   descriptors[index], descriptors[index + 1],
                   KERNEL_EPOLLIN, (uint64_t)index) == 0);
    assert(epoll_add(
               descriptors[0], descriptors[1],
               KERNEL_EPOLLIN, 0u) == -EDGE_LINUX_ELOOP);
}

static void test_snapshot_generation_invalidation(void) {
    fake_backend_t backend;
    kernel_epoll_object_snapshot_t old_object;
    kernel_epoll_object_snapshot_t new_object;
    kernel_epoll_watch_snapshot_t added;
    kernel_epoll_watch_snapshot_t modified;
    kernel_epoll_watch_snapshot_t reused;
    kernel_epoll_watch_claim_t claim;
    int32_t owner_index;
    int32_t replacement_index;
    int owner;
    int replacement;
    int leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    assert(epoll_add(
               owner, leaf,
               KERNEL_EPOLLIN | KERNEL_EPOLLET, 10u) == 0);
    assert(kernel_epoll_object_snapshot(
               owner_index, &old_object) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &added) == 1);

    assert(epoll_modify(
               owner, leaf,
               KERNEL_EPOLLIN | KERNEL_EPOLLET, 20u) == 0);
    assert(kernel_epoll_watch_preview(
               &added, KERNEL_EPOLLIN, 1u, 0) == 0);
    assert(kernel_epoll_watch_claim(
               &added, KERNEL_EPOLLIN, 1u, 0, &claim) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &modified) == 1);
    assert(modified.watch.slot_generation !=
           added.watch.slot_generation);
    assert(modified.watch.data == 20u);

    assert(epoll_delete(owner, leaf) == 0);
    assert(kernel_epoll_watch_preview(
               &modified, KERNEL_EPOLLIN, 2u, 0) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &reused) == 0);

    assert(epoll_add(
               owner, leaf,
               KERNEL_EPOLLIN | KERNEL_EPOLLET, 30u) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &reused) == 1);
    assert(reused.watch.slot_generation !=
           modified.watch.slot_generation);
    assert(kernel_epoll_watch_preview(
               &modified, KERNEL_EPOLLIN, 3u, 0) == 0);
    assert(kernel_epoll_watch_preview(
               &reused, KERNEL_EPOLLIN, 3u, 0) ==
           KERNEL_EPOLLIN);

    fake_close_descriptor(&backend, owner);
    assert(!kernel_epoll_object_exists(owner_index));
    replacement = fake_create_epoll(&backend, &replacement_index);
    (void)replacement;
    assert(replacement_index == owner_index);
    assert(kernel_epoll_object_snapshot(
               replacement_index, &new_object) == 0);
    assert(new_object.generation != old_object.generation);
    assert(kernel_epoll_watch_preview(
               &reused, KERNEL_EPOLLIN, 4u, 0) == 0);
}

static void test_claim_and_finish_semantics(void) {
    fake_backend_t backend;
    kernel_epoll_watch_snapshot_t snapshot;
    kernel_epoll_watch_claim_t first;
    kernel_epoll_watch_claim_t competing;
    kernel_epoll_watch_claim_t retry;
    kernel_epoll_watch_claim_t success;
    int32_t owner_index;
    int owner;
    int leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    assert(epoll_add(
               owner, leaf,
               KERNEL_EPOLLIN | KERNEL_EPOLLET |
                   KERNEL_EPOLLONESHOT,
               1u) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &snapshot) == 1);

    assert(kernel_epoll_watch_claim(
               &snapshot, KERNEL_EPOLLIN, 10u, 0, &first) ==
           KERNEL_EPOLLIN);
    assert(kernel_epoll_watch_claim(
               &snapshot, KERNEL_EPOLLIN, 10u, 0, &competing) == 0);
    kernel_epoll_watch_finish(&first, 0);

    assert(kernel_epoll_watch_claim(
               &snapshot, KERNEL_EPOLLIN, 10u, 0, &retry) ==
           KERNEL_EPOLLIN);
    kernel_epoll_watch_finish(&retry, 0);
    assert(kernel_epoll_watch_claim(
               &snapshot, KERNEL_EPOLLIN, 10u, 0, &success) ==
           KERNEL_EPOLLIN);
    kernel_epoll_watch_finish(&success, 1);

    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &snapshot) == 1);
    assert(snapshot.watch.oneshot_disabled);
    assert(kernel_epoll_watch_claim(
               &snapshot, KERNEL_EPOLLIN, 11u, 0, &competing) == 0);
    assert(epoll_modify(
               owner, leaf,
               KERNEL_EPOLLIN | KERNEL_EPOLLET |
                   KERNEL_EPOLLONESHOT,
               2u) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &snapshot) == 1);
    assert(!snapshot.watch.oneshot_disabled);
    assert(kernel_epoll_watch_claim(
               &snapshot, KERNEL_EPOLLIN, 11u, 0, &competing) ==
           KERNEL_EPOLLIN);
    kernel_epoll_watch_finish(&competing, 0);
}

static void test_readiness_transition_sequence(void) {
    fake_backend_t backend;
    kernel_epoll_object_snapshot_t object;
    kernel_epoll_watch_snapshot_t watch;
    uint64_t initial_sequence;
    uint64_t input_sequence;
    uint64_t output_sequence;
    int32_t owner_index;
    int owner;
    int leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    assert(epoll_add(
               owner, leaf,
               KERNEL_EPOLLIN | KERNEL_EPOLLOUT | KERNEL_EPOLLET,
               1u) == 0);
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    initial_sequence = object.readiness_sequence;
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &watch) == 1);

    assert(kernel_epoll_watch_preview(
               &watch, KERNEL_EPOLLIN, 10u, 0) ==
           KERNEL_EPOLLIN);
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    input_sequence = object.readiness_sequence;
    assert(input_sequence != initial_sequence);

    assert(kernel_epoll_watch_preview(
               &watch, KERNEL_EPOLLIN, 10u, 0) ==
           KERNEL_EPOLLIN);
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    assert(object.readiness_sequence == input_sequence);

    assert(kernel_epoll_watch_preview(
               &watch, KERNEL_EPOLLIN | KERNEL_EPOLLOUT,
               10u, 20u) ==
           (KERNEL_EPOLLIN | KERNEL_EPOLLOUT));
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    output_sequence = object.readiness_sequence;
    assert(output_sequence != input_sequence);

    assert(kernel_epoll_watch_preview(
               &watch, 0, 0, 0) == 0);
    assert(kernel_epoll_watch_preview(
               &watch, KERNEL_EPOLLOUT, 0, 20u) ==
           KERNEL_EPOLLOUT);
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    assert(object.readiness_sequence != output_sequence);
}

static void test_level_triggered_claims_do_not_serialize(void) {
    fake_backend_t backend;
    kernel_epoll_watch_snapshot_t watch;
    kernel_epoll_watch_claim_t first;
    kernel_epoll_watch_claim_t second;
    int32_t owner_index;
    int owner;
    int leaf;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &watch) == 1);

    assert(kernel_epoll_watch_claim(
               &watch, KERNEL_EPOLLIN, 1u, 0, &first) ==
           KERNEL_EPOLLIN);
    assert(kernel_epoll_watch_claim(
               &watch, KERNEL_EPOLLIN, 1u, 0, &second) ==
           KERNEL_EPOLLIN);
    assert(first.claim_id == 0u);
    assert(second.claim_id == 0u);
    kernel_epoll_watch_finish(&first, 1);
    kernel_epoll_watch_finish(&second, 1);
}

static void test_nested_retained_lifetime(void) {
    fake_backend_t backend;
    kernel_epoll_object_snapshot_t snapshot;
    int32_t parent_index;
    int32_t child_index;
    int parent;
    int child;

    fake_backend_initialize(&backend);
    parent = fake_create_epoll(&backend, &parent_index);
    child = fake_create_epoll(&backend, &child_index);
    assert(kernel_epoll_object_snapshot(
               child_index, &snapshot) == 0);
    assert(snapshot.refs == 1u);
    assert(epoll_add(parent, child, KERNEL_EPOLLIN, 1u) == 0);
    assert(kernel_epoll_object_snapshot(
               child_index, &snapshot) == 0);
    assert(snapshot.refs == 2u);

    /*
     * Drop the descriptor's reference before the owner watch is destroyed.
     * The nested watch must keep the child object alive.
     */
    backend.descriptors[child].open = 0;
    kernel_epoll_object_release(child_index);
    assert(kernel_epoll_object_snapshot(
               child_index, &snapshot) == 0);
    assert(snapshot.refs == 1u);

    backend.descriptors[parent].open = 0;
    kernel_epoll_object_release(parent_index);
    assert(!kernel_epoll_object_exists(parent_index));
    assert(!kernel_epoll_object_exists(child_index));
}

static void test_last_description_detach(void) {
    fake_backend_t backend;
    kernel_epoll_object_snapshot_t object;
    kernel_epoll_watch_snapshot_t watch;
    int32_t owner_index;
    int owner;
    int leaf;
    int duplicate;

    fake_backend_initialize(&backend);
    owner = fake_create_epoll(&backend, &owner_index);
    leaf = fake_create_leaf(&backend);
    duplicate = fake_duplicate_descriptor(&backend, leaf);
    assert(epoll_add(owner, leaf, KERNEL_EPOLLIN, 1u) == 0);

    fake_close_descriptor(&backend, leaf);
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    assert(object.nwatch == 1u);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &watch) == 1);

    fake_close_descriptor(&backend, duplicate);
    assert(kernel_epoll_object_snapshot(
               owner_index, &object) == 0);
    assert(object.nwatch == 0u);
    assert(object.entry_high_water == 0u);
    assert(kernel_epoll_watch_snapshot(
               owner_index, 0, &watch) == 0);
}

static uint32_t stress_random_next(uint32_t *state) {
    uint32_t value = *state;

    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

typedef struct stress_thread_context {
    start_gate_t *gate;
    int epolls[STRESS_EPOLL_COUNT];
    int targets[STRESS_EPOLL_COUNT + STRESS_LEAF_COUNT];
    uint32_t seed;
} stress_thread_context_t;

static void stress_check_control_result(uint32_t operation, int result) {
    if (result == 0 || result == -EDGE_LINUX_EINVAL) return;
    if (operation == KERNEL_EPOLL_CTL_ADD) {
        assert(result == -EDGE_LINUX_EEXIST ||
               result == -EDGE_LINUX_ELOOP);
    } else {
        assert(result == -EDGE_LINUX_ENOENT);
    }
}

static void *stress_thread(void *opaque) {
    stress_thread_context_t *context = opaque;
    uint32_t random = context->seed;

    start_gate_wait(context->gate);
    for (uint32_t iteration = 0;
         iteration < STRESS_ITERATIONS; ++iteration) {
        uint32_t operation = stress_random_next(&random) % 5u;
        uint32_t parent =
            stress_random_next(&random) % STRESS_EPOLL_COUNT;
        uint32_t target = stress_random_next(&random) %
            (STRESS_EPOLL_COUNT + STRESS_LEAF_COUNT);
        int parent_descriptor = context->epolls[parent];
        int target_descriptor = context->targets[target];

        if (operation < 3u) {
            uint32_t epoll_operation = operation + 1u;
            uint32_t events = KERNEL_EPOLLIN;
            kernel_epoll_event_t event;
            int result;

            if (stress_random_next(&random) & 1u)
                events |= KERNEL_EPOLLET;
            if (stress_random_next(&random) & 1u)
                events |= KERNEL_EPOLLONESHOT;
            event.events = events;
            event.data = ((uint64_t)context->seed << 32) | iteration;
            result = kernel_epoll_control_descriptor(
                parent_descriptor, epoll_operation,
                target_descriptor,
                epoll_operation == KERNEL_EPOLL_CTL_DEL ? 0 : &event);
            stress_check_control_result(epoll_operation, result);
        } else {
            kernel_epoll_object_snapshot_t object;
            kernel_epoll_watch_snapshot_t snapshot;
            kernel_epoll_watch_claim_t claim;
            uint16_t slot;
            int status;

            assert(kernel_epoll_object_snapshot(
                       (int32_t)parent, &object) == 0);
            if (!object.entry_high_water) continue;
            slot = (uint16_t)(
                stress_random_next(&random) % object.entry_high_water);
            status = kernel_epoll_watch_snapshot(
                (int32_t)parent, slot, &snapshot);
            assert(status == 0 || status == 1);
            if (status != 1) continue;
            if (operation == 3u) {
                (void)kernel_epoll_watch_preview(
                    &snapshot,
                    (stress_random_next(&random) & 3u) ?
                        KERNEL_EPOLLIN : 0,
                    (uint64_t)stress_random_next(&random) + 1u, 0);
            } else {
                uint32_t report = kernel_epoll_watch_claim(
                    &snapshot, KERNEL_EPOLLIN,
                    (uint64_t)stress_random_next(&random) + 1u,
                    0, &claim);
                if (report)
                    kernel_epoll_watch_finish(
                        &claim,
                        (stress_random_next(&random) & 1u) != 0);
            }
        }
    }
    return 0;
}

static void assert_stress_invariants(const fake_backend_t *backend) {
    uint32_t expected_refs[EDGE_RUNTIME_MAX_EPOLLS] = {0};
    uint32_t captured_source_count = 0;
    uint64_t irq_flags;

    for (int descriptor = 0;
         descriptor < backend->next_descriptor; ++descriptor) {
        const fake_descriptor_t *entry =
            &backend->descriptors[descriptor];
        if (entry->open && entry->kind == FAKE_DESCRIPTOR_EPOLL) {
            assert(entry->epoll_index >= 0 &&
                   entry->epoll_index <
                       (int32_t)EDGE_RUNTIME_MAX_EPOLLS);
            ++expected_refs[entry->epoll_index];
        }
    }

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    for (int32_t epoll_index = 0;
         epoll_index < (int32_t)EDGE_RUNTIME_MAX_EPOLLS; ++epoll_index) {
        kernel_epoll_object_t *epoll = &g_epolls[epoll_index];
        uint16_t highest_used = 0;
        uint16_t used_count = 0;

        if (!epoll->used) continue;
        assert(epoll->generation != 0u);
        assert(epoll->mutation_sequence != 0u);
        assert(epoll->readiness_sequence != 0u);
        assert(epoll->entry_high_water <=
               EDGE_RUNTIME_MAX_EPOLL_WATCHES);
        for (uint16_t slot = 0;
             slot < EDGE_RUNTIME_MAX_EPOLL_WATCHES; ++slot) {
            kernel_epoll_watch_t *watch = &epoll->watch[slot];
            if (!watch->used) continue;
            ++used_count;
            highest_used = slot + 1u;
            assert(watch->slot_generation != 0u);
            assert(watch->file_ref != 0u);
            assert(watch->fd >= 0);
            assert(watch->source_captured);
            assert(watch->source.kind != FAKE_DESCRIPTOR_NONE);
            assert(watch->source.cookie == watch->file_ref);
            ++captured_source_count;
            if (watch->target_epoll_index >= 0) {
                assert(watch->target_epoll_index <
                       (int32_t)EDGE_RUNTIME_MAX_EPOLLS);
                assert(g_epolls[watch->target_epoll_index].used);
                ++expected_refs[watch->target_epoll_index];
                assert(!epoll_graph_reaches_locked(
                    watch->target_epoll_index, epoll_index));
            }
        }
        assert(used_count == epoll->nwatch);
        assert(highest_used == epoll->entry_high_water);
    }
    for (int32_t epoll_index = 0;
         epoll_index < (int32_t)EDGE_RUNTIME_MAX_EPOLLS; ++epoll_index) {
        kernel_epoll_object_t *epoll = &g_epolls[epoll_index];
        uint64_t path[
            (EDGE_RUNTIME_MAX_EPOLLS + 63u) / 64u] = {0};
        if (!epoll->used) {
            assert(expected_refs[epoll_index] == 0u);
            continue;
        }
        assert(epoll->refs == expected_refs[epoll_index]);
        assert(epoll_graph_depth_valid_locked(
            epoll_index, 0, path, -1, -1));
    }
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    assert(atomic_load_explicit(
               &backend->live_source_count,
               memory_order_relaxed) == captured_source_count);
    assert(atomic_load_explicit(
               &backend->source_capture_count,
               memory_order_relaxed) ==
           atomic_load_explicit(
               &backend->source_release_count,
               memory_order_relaxed) +
               captured_source_count);
}

static void test_randomized_concurrent_stress(void) {
    fake_backend_t backend;
    stress_thread_context_t contexts[STRESS_THREAD_COUNT];
    pthread_t threads[STRESS_THREAD_COUNT];
    start_gate_t gate;
    int epolls[STRESS_EPOLL_COUNT];
    int targets[STRESS_EPOLL_COUNT + STRESS_LEAF_COUNT];

    fake_backend_initialize(&backend);
    for (int index = 0; index < STRESS_EPOLL_COUNT; ++index) {
        int32_t epoll_index;
        epolls[index] = fake_create_epoll(&backend, &epoll_index);
        assert(epoll_index == index);
        targets[index] = epolls[index];
    }
    for (int index = 0; index < STRESS_LEAF_COUNT; ++index)
        targets[STRESS_EPOLL_COUNT + index] =
            fake_create_leaf(&backend);

    atomic_init(&gate.ready, 0);
    atomic_init(&gate.start, 0);
    for (int thread = 0; thread < STRESS_THREAD_COUNT; ++thread) {
        contexts[thread].gate = &gate;
        memcpy(contexts[thread].epolls, epolls, sizeof(epolls));
        memcpy(contexts[thread].targets, targets, sizeof(targets));
        contexts[thread].seed =
            UINT32_C(0x9e3779b9) ^ (uint32_t)(thread + 1) *
                UINT32_C(0x85ebca6b);
        assert(contexts[thread].seed != 0u);
        assert(pthread_create(
                   &threads[thread], 0, stress_thread,
                   &contexts[thread]) == 0);
    }
    while (atomic_load_explicit(
               &gate.ready, memory_order_acquire) !=
           STRESS_THREAD_COUNT)
        sched_yield();
    atomic_store_explicit(&gate.start, 1u, memory_order_release);
    for (int thread = 0; thread < STRESS_THREAD_COUNT; ++thread)
        assert(pthread_join(threads[thread], 0) == 0);
    assert_stress_invariants(&backend);
}

static void test_wait_lease_releases_abandoned_wait(void) {
    fake_backend_t backend;
    kernel_epoll_object_snapshot_t snapshot;
    kernel_epoll_wait_lease_t lease = {0};
    int32_t epoll_index;
    int descriptor;

    fake_backend_initialize(&backend);
    descriptor = fake_create_epoll(&backend, &epoll_index);
    assert(kernel_epoll_wait_lease_acquire(
               &lease, epoll_index) == 0);
    assert(kernel_epoll_object_snapshot(
               epoll_index, &snapshot) == 0);
    assert(snapshot.refs == 2u);
    assert(kernel_epoll_wait_lease_acquire(
               &lease, epoll_index) == -EDGE_LINUX_EBUSY);
    fake_close_descriptor(&backend, descriptor);
    assert(kernel_epoll_object_snapshot(
               epoll_index, &snapshot) == 0);
    assert(snapshot.refs == 1u);
    kernel_epoll_wait_lease_release(&lease);
    assert(!kernel_epoll_object_exists(epoll_index));
    kernel_epoll_wait_lease_release(&lease);
}

int main(void) {
    test_common_event_delivery();
    test_optional_source_callbacks();
    test_source_survives_descriptor_close_and_reuse();
    test_modify_preserves_captured_source();
    test_release_for_every_watch_removal_path();
    test_failed_add_releases_captured_source();
    test_source_callbacks_may_reenter_epoll();
    test_concurrent_watch_removal_releases_once();
    test_concurrent_cycle_add();
    test_nesting_depth_in_both_orders();
    test_snapshot_generation_invalidation();
    test_claim_and_finish_semantics();
    test_readiness_transition_sequence();
    test_level_triggered_claims_do_not_serialize();
    test_nested_retained_lifetime();
    test_last_description_detach();
    test_wait_lease_releases_abandoned_wait();
    test_randomized_concurrent_stress();
    puts("epoll_runtime_unit: PASS");
    return 0;
}
