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

int main(void)
{
    test_normal_completion();
    test_late_completion_quarantines_slot();
    test_completion_wins_timeout_race();
    puts("virtio_gpu_sync_unit: PASS");
    return 0;
}
