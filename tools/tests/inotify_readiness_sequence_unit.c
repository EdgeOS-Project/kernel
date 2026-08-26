/* SPDX-License-Identifier: MPL-2.0 */
/* Host-side tests for shared inotify readiness transition sequences. */

#include "kernel/inotify.h"
#include "kernel/process_runtime.h"
#include "kernel/runtime_limits.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_wake_count;

int kernel_current_linux_identity(kernel_linux_identity_t *identity) {
    if (!identity) return -1;
    memset(identity, 0, sizeof(*identity));
    identity->uid = 1000u;
    return 0;
}

void kernel_inotify_state_changed(int inotify_id) {
    assert(inotify_id >= 0);
    ++g_wake_count;
}

void kernel_fanotify_notify_path(const char *canonical_path, uint32_t mask) {
    (void)canonical_path;
    (void)mask;
}

void kernel_fanotify_notify_move(const char *old_canonical_path,
                                 const char *new_canonical_path) {
    (void)old_canonical_path;
    (void)new_canonical_path;
}

static int copy_record(void *context, uint64_t offset, const void *record,
                       uint32_t length) {
    uint32_t *records = context;
    (void)offset;
    assert(record != 0);
    assert(length >= 16u);
    ++*records;
    return 0;
}

int main(void) {
    kernel_inotify_state_t state;
    uint64_t sequence;
    uint32_t records = 0;
    int inotify_id;
    int watch;

    inotify_id = kernel_inotify_create();
    assert(inotify_id >= 0);
    assert(kernel_inotify_query(inotify_id, &state) == 0);
    assert(state.queued_events == 0u);
    assert(state.queued_bytes == 0u);
    assert(state.readiness_sequence != 0u);
    sequence = state.readiness_sequence;

    watch = kernel_inotify_add_watch(
        inotify_id, "/watched",
        KERNEL_INOTIFY_MODIFY | KERNEL_INOTIFY_CLOSE_WRITE |
            KERNEL_INOTIFY_CREATE,
        1);
    assert(watch > 0);

    kernel_inotify_notify_path("/watched", KERNEL_INOTIFY_MODIFY, 0);
    assert(kernel_inotify_query(inotify_id, &state) == 0);
    assert(state.queued_events == 1u);
    assert(state.queued_bytes == 16u);
    assert(state.readiness_sequence == sequence + 1u);
    assert(g_wake_count == 1);
    sequence = state.readiness_sequence;

    kernel_inotify_notify_path("/watched", KERNEL_INOTIFY_MODIFY, 0);
    assert(kernel_inotify_query(inotify_id, &state) == 0);
    assert(state.queued_events == 1u);
    assert(state.readiness_sequence == sequence);
    assert(g_wake_count == 1);

    kernel_inotify_notify_path("/watched", KERNEL_INOTIFY_CLOSE_WRITE, 0);
    assert(kernel_inotify_query(inotify_id, &state) == 0);
    assert(state.queued_events == 2u);
    assert(state.queued_bytes == 32u);
    assert(state.readiness_sequence == sequence + 1u);
    assert(g_wake_count == 2);
    sequence = state.readiness_sequence;

    assert(kernel_inotify_read(
               inotify_id, copy_record, &records, 4096u) > 0);
    assert(records == 2u);
    assert(kernel_inotify_query(inotify_id, &state) == 0);
    assert(state.queued_events == 0u);
    assert(state.queued_bytes == 0u);
    assert(state.readiness_sequence == sequence);

    assert(kernel_inotify_limit_set(
               KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS, 1u) == 0);
    kernel_inotify_notify_path("/watched/a", KERNEL_INOTIFY_CREATE, 0);
    kernel_inotify_notify_path("/watched/b", KERNEL_INOTIFY_CREATE, 0);
    assert(kernel_inotify_query(inotify_id, &state) == 0);
    assert(state.queued_events == 2u);
    assert(state.queued_bytes == 48u);
    assert(state.readiness_sequence == sequence + 2u);
    assert(g_wake_count == 4);
    sequence = state.readiness_sequence;

    kernel_inotify_notify_path("/watched/c", KERNEL_INOTIFY_CREATE, 0);
    assert(kernel_inotify_query(inotify_id, &state) == 0);
    assert(state.queued_events == 2u);
    assert(state.readiness_sequence == sequence);
    assert(g_wake_count == 4);

    assert(kernel_inotify_limit_set(
               KERNEL_INOTIFY_LIMIT_MAX_QUEUED_EVENTS,
               EDGE_RUNTIME_INOTIFY_QUEUE_SIZE) == 0);
    kernel_inotify_release(inotify_id);
    puts("inotify_readiness_sequence_unit: PASS");
    return 0;
}
