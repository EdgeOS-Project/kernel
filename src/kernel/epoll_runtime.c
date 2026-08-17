/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Original EdgeOS architecture-neutral Linux epoll object policy.
 * Copyright (c) EdgeOS Contributors.
 */

#include "kernel/event_runtime.h"
#include "kernel/linux_errno.h"
#include "sys/spinlock.h"

static kernel_epoll_object_t g_epolls[EDGE_RUNTIME_MAX_EPOLLS];
static uint32_t g_epoll_generations[EDGE_RUNTIME_MAX_EPOLLS];
static uint32_t
    g_epoll_watch_generations[EDGE_RUNTIME_MAX_EPOLLS]
                             [EDGE_RUNTIME_MAX_EPOLL_WATCHES];
static spinlock_t g_epoll_lock;
static uint64_t g_epoll_claim_sequence;
static const kernel_epoll_backend_ops_t *g_backend_ops;
static void *g_backend_context;

static void epoll_target_source_release(
        const kernel_epoll_backend_ops_t *backend,
        void *backend_context,
        const kernel_epoll_target_source_t *source,
        int source_captured) {
    if (!source_captured || !backend ||
        !backend->release_target_source || !source)
        return;
    backend->release_target_source(backend_context, source);
}

static void bytes_zero(void *destination, uint64_t length) {
    uint8_t *bytes = (uint8_t *)destination;
    while (length--) *bytes++ = 0;
}

static void bytes_copy(void *destination, const void *source,
                       uint64_t length) {
    uint8_t *to = (uint8_t *)destination;
    const uint8_t *from = (const uint8_t *)source;
    while (length--) *to++ = *from++;
}

static uint32_t sequence_next32(uint32_t value) {
    ++value;
    return value ? value : 1u;
}

static uint64_t sequence_next64(uint64_t value) {
    ++value;
    return value ? value : 1u;
}

static int epoll_index_valid(int32_t epoll_index) {
    return epoll_index >= 0 &&
           epoll_index < (int32_t)EDGE_RUNTIME_MAX_EPOLLS;
}

static kernel_epoll_object_t *epoll_object_locked(int32_t epoll_index) {
    if (!epoll_index_valid(epoll_index) ||
        !g_epolls[epoll_index].used)
        return 0;
    return &g_epolls[epoll_index];
}

static void epoll_object_changed_locked(kernel_epoll_object_t *epoll) {
    if (!epoll) return;
    epoll->mutation_sequence =
        sequence_next32(epoll->mutation_sequence);
}

static void epoll_object_ready_changed_locked(
        kernel_epoll_object_t *epoll) {
    if (!epoll) return;
    epoll->readiness_sequence =
        sequence_next64(epoll->readiness_sequence);
}

int kernel_epoll_backend_register(const kernel_epoll_backend_ops_t *ops,
                                  void *context) {
    uint64_t irq_flags;

    if (!ops || !ops->install_descriptor ||
        !ops->resolve_epoll_descriptor ||
        !ops->resolve_target_descriptor ||
        !ops->watch_set_changed ||
        (!!ops->target_description_retain !=
         !!ops->target_description_release) ||
        (!!ops->capture_target_source !=
         !!ops->release_target_source))
        return -EDGE_LINUX_EINVAL;
    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    g_backend_ops = ops;
    g_backend_context = context;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return 0;
}

int kernel_epoll_object_exists(int32_t epoll_index) {
    uint64_t irq_flags;
    int exists;

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    exists = epoll_object_locked(epoll_index) != 0;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return exists;
}

int kernel_epoll_object_snapshot(
        int32_t epoll_index,
        kernel_epoll_object_snapshot_t *snapshot) {
    kernel_epoll_object_t *epoll;
    uint64_t irq_flags;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    bytes_zero(snapshot, sizeof(*snapshot));
    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    epoll = epoll_object_locked(epoll_index);
    if (!epoll) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return -EDGE_LINUX_EBADF;
    }
    snapshot->index = epoll_index;
    snapshot->generation = epoll->generation;
    snapshot->refs = epoll->refs;
    snapshot->mutation_sequence = epoll->mutation_sequence;
    snapshot->nwatch = epoll->nwatch;
    snapshot->entry_high_water = epoll->entry_high_water;
    snapshot->readiness_sequence = epoll->readiness_sequence;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return 0;
}

int kernel_epoll_watch_snapshot(
        int32_t epoll_index, uint16_t slot,
        kernel_epoll_watch_snapshot_t *snapshot) {
    kernel_epoll_object_t *epoll;
    kernel_epoll_watch_t *watch;
    uint64_t irq_flags;

    if (!snapshot) return -EDGE_LINUX_EINVAL;
    bytes_zero(snapshot, sizeof(*snapshot));
    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    epoll = epoll_object_locked(epoll_index);
    if (!epoll) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return -EDGE_LINUX_EBADF;
    }
    if (slot >= epoll->entry_high_water ||
        slot >= EDGE_RUNTIME_MAX_EPOLL_WATCHES) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return 0;
    }
    watch = &epoll->watch[slot];
    if (!watch->used) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return 0;
    }
    snapshot->epoll_index = epoll_index;
    snapshot->slot = slot;
    snapshot->object_generation = epoll->generation;
    bytes_copy(&snapshot->watch, watch, sizeof(snapshot->watch));
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return 1;
}

static int epoll_object_allocate(void) {
    uint64_t irq_flags;

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    for (int32_t index = 0;
         index < (int32_t)EDGE_RUNTIME_MAX_EPOLLS; ++index) {
        kernel_epoll_object_t *epoll = &g_epolls[index];
        if (epoll->used) continue;
        bytes_zero(epoll, sizeof(*epoll));
        g_epoll_generations[index] =
            sequence_next32(g_epoll_generations[index]);
        epoll->used = 1;
        epoll->refs = 1;
        epoll->generation = g_epoll_generations[index];
        epoll->mutation_sequence = 1;
        epoll->readiness_sequence = 1;
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return index;
    }
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return -EDGE_LINUX_ENOMEM;
}

int kernel_epoll_object_retain(int32_t epoll_index) {
    kernel_epoll_object_t *epoll;
    uint64_t irq_flags;

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    epoll = epoll_object_locked(epoll_index);
    if (!epoll || epoll->refs == UINT32_MAX) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return -EDGE_LINUX_EBADF;
    }
    ++epoll->refs;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return 0;
}

void kernel_epoll_object_release(int32_t epoll_index) {
    int16_t retained_targets[EDGE_RUNTIME_MAX_EPOLL_WATCHES];
    kernel_epoll_target_source_t
        retained_sources[EDGE_RUNTIME_MAX_EPOLL_WATCHES];
    uint16_t retained_count = 0;
    uint16_t retained_source_count = 0;
    kernel_epoll_object_t *epoll;
    const kernel_epoll_backend_ops_t *backend = 0;
    void *backend_context = 0;
    uint64_t irq_flags;
    int changed = 0;

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    epoll = epoll_object_locked(epoll_index);
    if (!epoll || !epoll->refs) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return;
    }
    if (--epoll->refs) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return;
    }
    for (uint16_t slot = 0; slot < epoll->entry_high_water; ++slot) {
        kernel_epoll_watch_t *watch = &epoll->watch[slot];
        if (!watch->used) continue;
        if (watch->source_captured)
            retained_sources[retained_source_count++] =
                watch->source;
        if (watch->target_epoll_index >= 0)
            retained_targets[retained_count++] =
                watch->target_epoll_index;
    }
    bytes_zero(epoll, sizeof(*epoll));
    backend = g_backend_ops;
    backend_context = g_backend_context;
    changed = 1;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);

    if (changed && backend)
        backend->watch_set_changed(backend_context, epoll_index);
    for (uint16_t index = 0;
         index < retained_source_count; ++index)
        epoll_target_source_release(
            backend, backend_context,
            &retained_sources[index], 1);
    for (uint16_t index = 0; index < retained_count; ++index)
        kernel_epoll_object_release(retained_targets[index]);
}

int kernel_epoll_wait_lease_acquire(kernel_epoll_wait_lease_t *lease,
                                    int32_t epoll_index) {
    uint32_t expected = 0;
    uint32_t encoded;
    int status;

    if (!lease || !epoll_index_valid(epoll_index))
        return -EDGE_LINUX_EINVAL;
    encoded = (uint32_t)epoll_index + 1u;
    if (__atomic_load_n(
            &lease->epoll_index_plus_one, __ATOMIC_ACQUIRE))
        return -EDGE_LINUX_EBUSY;
    status = kernel_epoll_object_retain(epoll_index);
    if (status < 0) return status;
    if (!__atomic_compare_exchange_n(
            &lease->epoll_index_plus_one, &expected, encoded, 0,
            __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
        kernel_epoll_object_release(epoll_index);
        return -EDGE_LINUX_EBUSY;
    }
    return 0;
}

void kernel_epoll_wait_lease_release(kernel_epoll_wait_lease_t *lease) {
    uint32_t encoded;

    if (!lease) return;
    encoded = __atomic_exchange_n(
        &lease->epoll_index_plus_one, 0u, __ATOMIC_ACQ_REL);
    if (!encoded ||
        encoded > (uint32_t)EDGE_RUNTIME_MAX_EPOLLS)
        return;
    kernel_epoll_object_release((int32_t)(encoded - 1u));
}

static int epoll_graph_reaches_locked(int32_t source, int32_t target) {
    uint8_t queue[EDGE_RUNTIME_MAX_EPOLLS];
    uint64_t visited[(EDGE_RUNTIME_MAX_EPOLLS + 63u) / 64u] = {0};
    uint16_t head = 0;
    uint16_t tail = 0;

    if (!epoll_index_valid(source) || !epoll_index_valid(target))
        return 0;
    if (source == target) return 1;
    if (!epoll_object_locked(source) || !epoll_object_locked(target))
        return 0;
    queue[tail++] = (uint8_t)source;
    visited[(uint32_t)source >> 6] |=
        1ULL << ((uint32_t)source & 63u);
    while (head < tail) {
        int32_t current = queue[head++];
        kernel_epoll_object_t *epoll = epoll_object_locked(current);
        if (!epoll) continue;
        for (uint16_t slot = 0; slot < epoll->entry_high_water; ++slot) {
            kernel_epoll_watch_t *watch = &epoll->watch[slot];
            int32_t child;
            uint64_t bit;
            uint32_t word;
            if (!watch->used || watch->target_epoll_index < 0) continue;
            child = watch->target_epoll_index;
            if (child == target) return 1;
            if (!epoll_index_valid(child)) continue;
            word = (uint32_t)child >> 6;
            bit = 1ULL << ((uint32_t)child & 63u);
            if (visited[word] & bit) continue;
            visited[word] |= bit;
            queue[tail++] = (uint8_t)child;
        }
    }
    return 0;
}

static int epoll_graph_depth_valid_locked(
        int32_t current, uint32_t depth,
        uint64_t path[(EDGE_RUNTIME_MAX_EPOLLS + 63u) / 64u],
        int32_t added_parent, int32_t added_child) {
    kernel_epoll_object_t *epoll;
    uint64_t bit;
    uint32_t word;
    int include_added;

    if (!epoll_index_valid(current)) return 0;
    if (depth > KERNEL_EPOLL_NESTING_MAX) return 0;
    word = (uint32_t)current >> 6;
    bit = 1ULL << ((uint32_t)current & 63u);
    if (path[word] & bit) return 0;
    epoll = epoll_object_locked(current);
    if (!epoll) return 1;
    path[word] |= bit;
    include_added = current == added_parent;
    for (uint16_t slot = 0; slot < epoll->entry_high_water; ++slot) {
        kernel_epoll_watch_t *watch = &epoll->watch[slot];
        if (!watch->used || watch->target_epoll_index < 0) continue;
        if (watch->target_epoll_index == added_child)
            include_added = 0;
        if (!epoll_graph_depth_valid_locked(
                watch->target_epoll_index, depth + 1u, path,
                added_parent, added_child)) {
            path[word] &= ~bit;
            return 0;
        }
    }
    if (include_added &&
        !epoll_graph_depth_valid_locked(
            added_child, depth + 1u, path,
            added_parent, added_child)) {
        path[word] &= ~bit;
        return 0;
    }
    path[word] &= ~bit;
    return 1;
}

static int epoll_graph_accepts_locked(int32_t parent, int32_t child) {
    if (epoll_graph_reaches_locked(child, parent)) return 0;
    for (int32_t root = 0;
         root < (int32_t)EDGE_RUNTIME_MAX_EPOLLS; ++root) {
        uint64_t path[(EDGE_RUNTIME_MAX_EPOLLS + 63u) / 64u] = {0};
        if (!epoll_object_locked(root)) continue;
        if (!epoll_graph_depth_valid_locked(
                root, 0, path, parent, child))
            return 0;
    }
    return 1;
}

int kernel_epoll_graph_reaches(int32_t source, int32_t target) {
    uint64_t irq_flags;
    int reaches;

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    reaches = epoll_graph_reaches_locked(source, target);
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return reaches;
}

static int epoll_watch_clear_locked(
        int32_t epoll_index, uint16_t slot,
        kernel_epoll_object_t *epoll,
        int16_t *retained_target,
        kernel_epoll_target_source_t *retained_source) {
    kernel_epoll_watch_t *watch;
    int source_captured;
    uint32_t generation;

    if (retained_target) *retained_target = -1;
    if (retained_source)
        bytes_zero(retained_source, sizeof(*retained_source));
    if (!epoll || slot >= epoll->entry_high_water) return 0;
    watch = &epoll->watch[slot];
    if (!watch->used) return 0;
    if (retained_target) *retained_target = watch->target_epoll_index;
    source_captured = watch->source_captured != 0;
    if (source_captured && retained_source)
        *retained_source = watch->source;
    g_epoll_watch_generations[epoll_index][slot] =
        sequence_next32(g_epoll_watch_generations[epoll_index][slot]);
    generation = g_epoll_watch_generations[epoll_index][slot];
    bytes_zero(watch, sizeof(*watch));
    watch->slot_generation = generation;
    if (epoll->nwatch) --epoll->nwatch;
    while (epoll->entry_high_water &&
           !epoll->watch[epoll->entry_high_water - 1u].used)
        --epoll->entry_high_water;
    epoll_object_changed_locked(epoll);
    return source_captured;
}

void kernel_epoll_detach_description(uint64_t description_id) {
    if (!description_id) return;
    for (int32_t epoll_index = 0;
         epoll_index < (int32_t)EDGE_RUNTIME_MAX_EPOLLS; ++epoll_index) {
        int16_t retained_targets[EDGE_RUNTIME_MAX_EPOLL_WATCHES];
        kernel_epoll_target_source_t
            retained_sources[EDGE_RUNTIME_MAX_EPOLL_WATCHES];
        uint16_t retained_count = 0;
        uint16_t retained_source_count = 0;
        const kernel_epoll_backend_ops_t *backend = 0;
        void *backend_context = 0;
        kernel_epoll_object_t *epoll;
        uint64_t irq_flags;
        int changed = 0;

        irq_flags = spin_lock_irqsave(&g_epoll_lock);
        epoll = epoll_object_locked(epoll_index);
        if (epoll) {
            uint16_t high_water = epoll->entry_high_water;
            for (uint16_t slot = 0; slot < high_water; ++slot) {
                kernel_epoll_watch_t *watch = &epoll->watch[slot];
                kernel_epoll_target_source_t retained_source;
                int16_t retained_target = -1;
                int source_captured;
                if (!watch->used || watch->file_ref != description_id)
                    continue;
                source_captured = epoll_watch_clear_locked(
                    epoll_index, slot, epoll, &retained_target,
                    &retained_source);
                if (retained_target >= 0)
                    retained_targets[retained_count++] =
                        retained_target;
                if (source_captured)
                    retained_sources[retained_source_count++] =
                        retained_source;
                changed = 1;
            }
        }
        if (changed) {
            backend = g_backend_ops;
            backend_context = g_backend_context;
        }
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        if (changed && backend)
            backend->watch_set_changed(
                backend_context, epoll_index);
        for (uint16_t index = 0;
             index < retained_source_count; ++index)
            epoll_target_source_release(
                backend, backend_context,
                &retained_sources[index], 1);
        for (uint16_t index = 0; index < retained_count; ++index)
            kernel_epoll_object_release(retained_targets[index]);
    }
}

static int epoll_watch_snapshot_matches_locked(
        const kernel_epoll_watch_snapshot_t *snapshot,
        kernel_epoll_object_t **epoll_out,
        kernel_epoll_watch_t **watch_out) {
    kernel_epoll_object_t *epoll;
    kernel_epoll_watch_t *watch;

    if (!snapshot ||
        !epoll_index_valid(snapshot->epoll_index) ||
        snapshot->slot >= EDGE_RUNTIME_MAX_EPOLL_WATCHES)
        return 0;
    epoll = epoll_object_locked(snapshot->epoll_index);
    if (!epoll || epoll->generation != snapshot->object_generation ||
        snapshot->slot >= epoll->entry_high_water)
        return 0;
    watch = &epoll->watch[snapshot->slot];
    if (!watch->used ||
        watch->slot_generation != snapshot->watch.slot_generation)
        return 0;
    if (epoll_out) *epoll_out = epoll;
    if (watch_out) *watch_out = watch;
    return 1;
}

static uint32_t epoll_watch_note_locked(
        kernel_epoll_object_t *epoll, kernel_epoll_watch_t *watch,
        uint32_t current_ready, uint64_t read_ready_sequence,
        uint64_t write_ready_sequence) {
    const uint32_t read_events =
        KERNEL_EPOLLIN | KERNEL_EPOLLPRI | KERNEL_EPOLLRDNORM |
        KERNEL_EPOLLRDBAND | KERNEL_EPOLLRDHUP |
        KERNEL_EPOLLERR | KERNEL_EPOLLHUP;
    const uint32_t write_events =
        KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM | KERNEL_EPOLLWRBAND |
        KERNEL_EPOLLERR | KERNEL_EPOLLHUP;
    uint32_t report;
    int new_transition = 0;

    if (!watch || !watch->used || watch->oneshot_disabled) return 0;
    report = current_ready &
        (watch->events | KERNEL_EPOLLERR | KERNEL_EPOLLHUP);
    if (report) {
        if (report & ~watch->observed_ready) new_transition = 1;
        if ((report & read_events) && read_ready_sequence &&
            read_ready_sequence !=
                watch->observed_read_ready_sequence)
            new_transition = 1;
        if ((report & write_events) && write_ready_sequence &&
            write_ready_sequence !=
                watch->observed_write_ready_sequence)
            new_transition = 1;
    }
    watch->observed_ready = report;
    if (report & read_events)
        watch->observed_read_ready_sequence = read_ready_sequence;
    if (report & write_events)
        watch->observed_write_ready_sequence = write_ready_sequence;
    if (!report) {
        watch->ready_delivered = 0;
        watch->read_ready_seq_delivered = 0;
        watch->write_ready_seq_delivered = 0;
        watch->observed_read_ready_sequence = 0;
        watch->observed_write_ready_sequence = 0;
    }
    if (new_transition) epoll_object_ready_changed_locked(epoll);
    return report;
}

static uint32_t epoll_watch_report_locked(
        kernel_epoll_watch_t *watch, uint32_t report,
        uint64_t read_ready_sequence,
        uint64_t write_ready_sequence) {
    const uint32_t read_events =
        KERNEL_EPOLLIN | KERNEL_EPOLLPRI | KERNEL_EPOLLRDNORM |
        KERNEL_EPOLLRDBAND | KERNEL_EPOLLRDHUP |
        KERNEL_EPOLLERR | KERNEL_EPOLLHUP;
    const uint32_t write_events =
        KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM | KERNEL_EPOLLWRBAND |
        KERNEL_EPOLLERR | KERNEL_EPOLLHUP;

    if (!watch || !report || watch->claim_id) return 0;
    if (watch->events & KERNEL_EPOLLET) {
        uint32_t edge = report & ~watch->ready_delivered;
        if ((report & read_events) && read_ready_sequence &&
            read_ready_sequence != watch->read_ready_seq_delivered)
            edge |= report & read_events;
        if ((report & write_events) && write_ready_sequence &&
            write_ready_sequence != watch->write_ready_seq_delivered)
            edge |= report & write_events;
        report = edge;
    }
    return report;
}

uint32_t kernel_epoll_watch_preview(
        const kernel_epoll_watch_snapshot_t *snapshot,
        uint32_t current_ready,
        uint64_t read_ready_sequence,
        uint64_t write_ready_sequence) {
    kernel_epoll_object_t *epoll;
    kernel_epoll_watch_t *watch;
    uint64_t irq_flags;
    uint32_t report = 0;

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    if (epoll_watch_snapshot_matches_locked(
            snapshot, &epoll, &watch)) {
        report = epoll_watch_note_locked(
            epoll, watch, current_ready,
            read_ready_sequence, write_ready_sequence);
        report = epoll_watch_report_locked(
            watch, report, read_ready_sequence,
            write_ready_sequence);
    }
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return report;
}

uint32_t kernel_epoll_watch_claim(
        const kernel_epoll_watch_snapshot_t *snapshot,
        uint32_t current_ready,
        uint64_t read_ready_sequence,
        uint64_t write_ready_sequence,
        kernel_epoll_watch_claim_t *claim) {
    kernel_epoll_object_t *epoll;
    kernel_epoll_watch_t *watch;
    uint64_t irq_flags;
    uint32_t report = 0;

    if (!claim) return 0;
    bytes_zero(claim, sizeof(*claim));
    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    if (epoll_watch_snapshot_matches_locked(
            snapshot, &epoll, &watch)) {
        report = epoll_watch_note_locked(
            epoll, watch, current_ready,
            read_ready_sequence, write_ready_sequence);
        report = epoll_watch_report_locked(
            watch, report, read_ready_sequence,
            write_ready_sequence);
        if (report &&
            (watch->events &
             (KERNEL_EPOLLET | KERNEL_EPOLLONESHOT))) {
            g_epoll_claim_sequence =
                sequence_next64(g_epoll_claim_sequence);
            watch->claim_id = g_epoll_claim_sequence;
            claim->epoll_index = snapshot->epoll_index;
            claim->slot = snapshot->slot;
            claim->object_generation =
                snapshot->object_generation;
            claim->slot_generation = watch->slot_generation;
            claim->report = report;
            claim->claim_id = watch->claim_id;
            claim->read_ready_sequence =
                read_ready_sequence;
            claim->write_ready_sequence =
                write_ready_sequence;
        }
    }
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    return report;
}

void kernel_epoll_watch_finish(
        const kernel_epoll_watch_claim_t *claim, int copy_succeeded) {
    const uint32_t read_events =
        KERNEL_EPOLLIN | KERNEL_EPOLLPRI | KERNEL_EPOLLRDNORM |
        KERNEL_EPOLLRDBAND | KERNEL_EPOLLRDHUP |
        KERNEL_EPOLLERR | KERNEL_EPOLLHUP;
    const uint32_t write_events =
        KERNEL_EPOLLOUT | KERNEL_EPOLLWRNORM | KERNEL_EPOLLWRBAND |
        KERNEL_EPOLLERR | KERNEL_EPOLLHUP;
    kernel_epoll_object_t *epoll;
    kernel_epoll_watch_t *watch;
    uint64_t irq_flags;

    if (!claim || !claim->claim_id ||
        !epoll_index_valid(claim->epoll_index) ||
        claim->slot >= EDGE_RUNTIME_MAX_EPOLL_WATCHES)
        return;
    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    epoll = epoll_object_locked(claim->epoll_index);
    if (!epoll || epoll->generation != claim->object_generation ||
        claim->slot >= epoll->entry_high_water) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return;
    }
    watch = &epoll->watch[claim->slot];
    if (!watch->used ||
        watch->slot_generation != claim->slot_generation ||
        watch->claim_id != claim->claim_id) {
        spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
        return;
    }
    if (copy_succeeded) {
        if (watch->events & KERNEL_EPOLLET) {
            watch->ready_delivered |= claim->report;
            if (claim->report & read_events)
                watch->read_ready_seq_delivered =
                    claim->read_ready_sequence;
            if (claim->report & write_events)
                watch->write_ready_seq_delivered =
                    claim->write_ready_sequence;
        }
        if (watch->events & KERNEL_EPOLLONESHOT)
            watch->oneshot_disabled = 1;
    }
    watch->claim_id = 0;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
}

int kernel_epoll_create_descriptor(uint32_t flags) {
    const kernel_epoll_backend_ops_t *backend;
    void *backend_context;
    uint64_t irq_flags;
    int epoll_index;
    int descriptor;

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    backend = g_backend_ops;
    backend_context = g_backend_context;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    if (!backend) return -EDGE_LINUX_ENODEV;
    epoll_index = epoll_object_allocate();
    if (epoll_index < 0) return epoll_index;
    descriptor = backend->install_descriptor(
        backend_context, epoll_index, flags);
    if (descriptor < 0) {
        kernel_epoll_object_release(epoll_index);
        return descriptor;
    }
    return descriptor;
}

int kernel_epoll_control_descriptor(int32_t epoll_descriptor,
                                    uint32_t operation,
                                    int32_t target_descriptor,
                                    const kernel_epoll_event_t *event) {
    const kernel_epoll_backend_ops_t *backend;
    void *backend_context;
    kernel_epoll_object_t *epoll;
    kernel_epoll_watch_t *watch = 0;
    kernel_epoll_target_source_t captured_source;
    kernel_epoll_target_source_t released_source;
    uint64_t description_id;
    uint64_t irq_flags;
    int32_t epoll_index;
    int32_t target_epoll_index;
    int16_t release_target = -1;
    int free_slot = -1;
    int watch_slot = -1;
    int captured_source_owned = 0;
    int released_source_owned = 0;
    int target_description_pinned = 0;
    int status;

    bytes_zero(&captured_source, sizeof(captured_source));
    bytes_zero(&released_source, sizeof(released_source));
    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    backend = g_backend_ops;
    backend_context = g_backend_context;
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);
    if (!backend) return -EDGE_LINUX_ENODEV;
    status = backend->resolve_epoll_descriptor(
        backend_context, epoll_descriptor, &epoll_index);
    if (status < 0) return status;
    status = kernel_epoll_object_retain(epoll_index);
    if (status < 0) return status;
    status = backend->resolve_target_descriptor(
        backend_context, target_descriptor, &description_id,
        &target_epoll_index);
    if (status < 0) goto release_owner;
    if (backend->target_description_retain) {
        status = backend->target_description_retain(
            backend_context, description_id);
        if (status < 0) goto release_owner;
        target_description_pinned = 1;
    }
    if (target_descriptor == epoll_descriptor ||
        target_epoll_index == epoll_index) {
        status = -EDGE_LINUX_EINVAL;
        goto release_owner;
    }
    if (operation == KERNEL_EPOLL_CTL_ADD && !event) {
        status = -EDGE_LINUX_EFAULT;
        goto release_owner;
    }
    if (operation == KERNEL_EPOLL_CTL_ADD &&
        backend->capture_target_source) {
        status = backend->capture_target_source(
            backend_context, target_descriptor,
            description_id, &captured_source);
        if (status < 0) goto release_owner;
        captured_source_owned = 1;
    }

    irq_flags = spin_lock_irqsave(&g_epoll_lock);
    epoll = epoll_object_locked(epoll_index);
    if (!epoll) {
        status = -EDGE_LINUX_EBADF;
        goto unlock_owner;
    }
    for (uint16_t slot = 0; slot < epoll->entry_high_water; ++slot) {
        kernel_epoll_watch_t *candidate = &epoll->watch[slot];
        if (!candidate->used && free_slot < 0)
            free_slot = (int)slot;
        if (candidate->used &&
            candidate->fd == target_descriptor &&
            candidate->file_ref == description_id) {
            watch = candidate;
            watch_slot = (int)slot;
        }
    }

    if (operation == KERNEL_EPOLL_CTL_ADD) {
        kernel_epoll_object_t *target_epoll = 0;
        uint32_t slot_generation;
        if (watch) {
            status = -EDGE_LINUX_EEXIST;
            goto unlock_owner;
        }
        if (target_epoll_index >= 0) {
            target_epoll = epoll_object_locked(target_epoll_index);
            if (!target_epoll) {
                status = -EDGE_LINUX_EBADF;
                goto unlock_owner;
            }
            if (!epoll_graph_accepts_locked(
                    epoll_index, target_epoll_index)) {
                status = -EDGE_LINUX_ELOOP;
                goto unlock_owner;
            }
            if (target_epoll->refs == UINT32_MAX) {
                status = -EDGE_LINUX_ENOMEM;
                goto unlock_owner;
            }
        }
        if (free_slot < 0 &&
            epoll->entry_high_water <
                EDGE_RUNTIME_MAX_EPOLL_WATCHES)
            free_slot = (int)epoll->entry_high_water++;
        if (free_slot < 0) {
            status = -EDGE_LINUX_ENOMEM;
            goto unlock_owner;
        }
        if (target_epoll) ++target_epoll->refs;
        g_epoll_watch_generations[epoll_index][free_slot] =
            sequence_next32(
                g_epoll_watch_generations[epoll_index][free_slot]);
        slot_generation =
            g_epoll_watch_generations[epoll_index][free_slot];
        watch = &epoll->watch[free_slot];
        bytes_zero(watch, sizeof(*watch));
        watch->used = 1;
        watch->slot_generation = slot_generation;
        watch->target_epoll_index =
            (int16_t)target_epoll_index;
        watch->fd = target_descriptor;
        watch->events = event->events;
        watch->file_ref = description_id;
        watch->data = event->data;
        if (captured_source_owned) {
            watch->source = captured_source;
            watch->source_captured = 1u;
            captured_source_owned = 0;
        }
        ++epoll->nwatch;
        epoll_object_changed_locked(epoll);
    } else if (operation == KERNEL_EPOLL_CTL_MOD) {
        uint32_t slot_generation;
        if (!event) {
            status = -EDGE_LINUX_EFAULT;
            goto unlock_owner;
        }
        if (!watch) {
            status = -EDGE_LINUX_ENOENT;
            goto unlock_owner;
        }
        g_epoll_watch_generations[epoll_index][watch_slot] =
            sequence_next32(
                g_epoll_watch_generations[epoll_index][watch_slot]);
        slot_generation =
            g_epoll_watch_generations[epoll_index][watch_slot];
        watch->slot_generation = slot_generation;
        watch->events = event->events;
        watch->data = event->data;
        watch->oneshot_disabled = 0;
        watch->observed_ready = 0;
        watch->ready_delivered = 0;
        watch->observed_read_ready_sequence = 0;
        watch->observed_write_ready_sequence = 0;
        watch->read_ready_seq_delivered = 0;
        watch->write_ready_seq_delivered = 0;
        watch->claim_id = 0;
        epoll_object_changed_locked(epoll);
    } else if (operation == KERNEL_EPOLL_CTL_DEL) {
        if (!watch) {
            status = -EDGE_LINUX_ENOENT;
            goto unlock_owner;
        }
        released_source_owned = epoll_watch_clear_locked(
            epoll_index, (uint16_t)watch_slot,
            epoll, &release_target, &released_source);
    } else {
        status = -EDGE_LINUX_EINVAL;
        goto unlock_owner;
    }
    status = 0;
unlock_owner:
    spin_unlock_irqrestore(&g_epoll_lock, irq_flags);

    if (status == 0) {
        backend->watch_set_changed(backend_context, epoll_index);
        epoll_target_source_release(
            backend, backend_context,
            &released_source, released_source_owned);
        if (release_target >= 0)
            kernel_epoll_object_release(release_target);
    }
release_owner:
    epoll_target_source_release(
        backend, backend_context,
        &captured_source, captured_source_owned);
    if (target_description_pinned)
        backend->target_description_release(
            backend_context, description_id);
    kernel_epoll_object_release(epoll_index);
    return status;
}
