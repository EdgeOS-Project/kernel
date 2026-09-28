#include <assert.h>
#include <stdio.h>

#include "drivers/virtio_gpu_sync.h"

static void test_normal_completion(void)
{
    virtio_gpu_sync_state_t state = {0};

    assert(virtio_gpu_sync_state_begin(&state) == 1);
    assert(virtio_gpu_sync_state_begin(&state) == 0);
    assert(virtio_gpu_sync_state_device_complete(&state) == 1);
    assert(virtio_gpu_sync_state_take(&state) == 1);
    assert(virtio_gpu_sync_state_begin(&state) == 1);
}

static void test_late_completion_quarantines_slot(void)
{
    virtio_gpu_sync_state_t state = {0};

    assert(virtio_gpu_sync_state_begin(&state) == 1);
    assert(virtio_gpu_sync_state_abandon(&state) == 1);
    assert(virtio_gpu_sync_state_begin(&state) == 0);
    assert(virtio_gpu_sync_state_take(&state) == 0);
    assert(virtio_gpu_sync_state_device_complete(&state) == 2);
    assert(virtio_gpu_sync_state_begin(&state) == 1);
}

static void test_completion_wins_timeout_race(void)
{
    virtio_gpu_sync_state_t state = {0};

    assert(virtio_gpu_sync_state_begin(&state) == 1);
    assert(virtio_gpu_sync_state_device_complete(&state) == 1);
    assert(virtio_gpu_sync_state_abandon(&state) == 0);
    assert(virtio_gpu_sync_state_take(&state) == 1);
}

static void test_signal_does_not_cancel_state_transaction(void)
{
    assert(!virtio_gpu_sync_wait_cancelled(-1, 1));
    assert(virtio_gpu_sync_wait_cancelled(-1, 0));
    assert(!virtio_gpu_sync_wait_cancelled(0, 0));
    assert(!virtio_gpu_sync_wait_cancelled(1, 1));
}

static void test_completion_credit_survives_repeated_reaping(void)
{
    const uint32_t capacity = 4u;
    uint32_t in_flight = capacity;
    uint32_t completed = 0u;

    /* Reaping frees descriptors but does not release callback capacity. */
    for (uint32_t index = 0; index < capacity; ++index) {
        in_flight--;
        completed++;
        assert(!virtio_gpu_render_credit_available(
            capacity, in_flight, completed));
    }
    completed = 0u;
    for (uint32_t index = 0; index < capacity; ++index) {
        assert(virtio_gpu_render_credit_available(
            capacity, in_flight, completed));
        in_flight++;
    }
    assert(!virtio_gpu_render_credit_available(capacity, in_flight, 0u));
    assert(!virtio_gpu_render_credit_available(capacity, 0u, capacity + 1u));
}

static void test_bounded_callback_batches(void)
{
    uint32_t pending = 256u;
    uint32_t budget = 256u;
    uint32_t delivered = 0u;

    while (budget) {
        uint32_t count = virtio_gpu_completion_batch_count(pending, 8u, budget);

        assert(count == 8u);
        pending -= count;
        budget -= count;
        delivered += count;
        /* Model arrivals while callbacks execute outside the queue lock. */
        pending++;
    }
    assert(delivered == 256u);
    assert(pending == 32u);
    assert(virtio_gpu_completion_batch_count(pending, 8u, 0u) == 0u);
    assert(virtio_gpu_completion_batch_count(3u, 8u, 256u) == 3u);
    assert(virtio_gpu_completion_batch_count(8u, 8u, 2u) == 2u);
}

int main(void)
{
    test_normal_completion();
    test_late_completion_quarantines_slot();
    test_completion_wins_timeout_race();
    test_signal_does_not_cancel_state_transaction();
    test_completion_credit_survives_repeated_reaping();
    test_bounded_callback_batches();
    puts("virtio_gpu_sync_unit: PASS");
    return 0;
}
