/* SPDX-License-Identifier: MPL-2.0 */
/* Host regression tests for the architecture-independent legacy AIO core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/aio_runtime.h"
#include "kernel/eventfd.h"
#include "kernel/linux_errno.h"

int main(void) {
    struct edge_linux_io_event event = {
        .data = 0x1234,
        .object = 0x5678,
        .result = 7,
    };
    kernel_aio_pending_request_t pending = {
        .data = 0x1111,
        .object = 0x2222,
        .descriptor = 4,
        .events = 1,
    };
    kernel_aio_pending_request_t snapshot;
    struct edge_linux_io_event result;
    uint32_t completions;
    uint32_t pending_count;
    uint64_t first;
    uint64_t second;
    kernel_eventfd_state_t eventfd_state;
    int32_t result_event_id = -1;
    int event_id = kernel_eventfd_create(0, 0);

    assert(event_id >= 0);
    pending.result_event_id = event_id;
    assert(kernel_eventfd_retain(event_id) == 0);

    assert(kernel_aio_context_create(10, 2, &first) == 0);
    assert(first <= UINT32_MAX);
    assert(kernel_aio_context_query(11, first, 0, 0) ==
           -EDGE_LINUX_EINVAL);
    assert(kernel_aio_completion_enqueue(10, first, &event) == 0);
    assert(kernel_aio_pending_add(10, first, &pending) == 0);
    assert(kernel_aio_context_query(
               10, first, &completions, &pending_count) == 0);
    assert(completions == 1 && pending_count == 1);
    assert(kernel_aio_pending_snapshot(10, first, 0, &snapshot) == 1);
    assert(snapshot.object == pending.object && snapshot.token != 0);
    assert(kernel_aio_pending_complete(
               10, first, snapshot.token, 5, &result_event_id) == 0);
    assert(result_event_id == event_id);
    kernel_eventfd_release(result_event_id);
    assert(kernel_eventfd_query(event_id, &eventfd_state) == 0);
    assert(eventfd_state.references == 1);
    assert(kernel_aio_completion_dequeue(10, first, &result) == 0);
    assert(result.data == event.data && result.result == event.result);
    assert(kernel_aio_completion_dequeue(10, first, &result) == 0);
    assert(result.data == pending.data && result.object == pending.object &&
           result.result == 5);
    assert(kernel_aio_context_destroy(10, first) == 0);
    assert(kernel_aio_context_create(10, 2, &second) == 0);
    assert(second != first);
    assert(kernel_eventfd_retain(event_id) == 0);
    assert(kernel_aio_pending_add(10, second, &pending) == 0);
    assert(kernel_aio_pending_cancel(
               10, second, pending.object, &result,
               &result_event_id) == -EDGE_LINUX_EINPROGRESS);
    assert(kernel_aio_context_query(
               10, second, &completions, &pending_count) == 0);
    assert(completions == 0 && pending_count == 1);
    kernel_aio_release_owner(10);
    assert(kernel_eventfd_query(event_id, &eventfd_state) == 0);
    assert(eventfd_state.references == 1);
    assert(kernel_aio_context_query(10, second, 0, 0) ==
           -EDGE_LINUX_EINVAL);
    kernel_eventfd_release(event_id);

    puts("aio_runtime_unit: PASS");
    return 0;
}
