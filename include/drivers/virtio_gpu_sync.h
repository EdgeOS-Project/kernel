#ifndef EDGEOS_DRIVERS_VIRTIO_GPU_SYNC_H
#define EDGEOS_DRIVERS_VIRTIO_GPU_SYNC_H

#include <stdint.h>

typedef struct {
    uint8_t busy;
    uint8_t complete;
    uint8_t abandoned;
} virtio_gpu_sync_state_t;

/* Bound stack usage and work per callback dispatch turn independently. */
static inline uint32_t virtio_gpu_completion_batch_count(
    uint32_t available, uint32_t batch_limit, uint32_t budget)
{
    uint32_t count = available < batch_limit ? available : batch_limit;

    return count < budget ? count : budget;
}

/* Every published render command reserves space for its completion callback. */
static inline int virtio_gpu_render_credit_available(
    uint32_t capacity, uint32_t in_flight, uint32_t completed)
{
    return completed < capacity && in_flight < capacity - completed;
}

/* A state command may be part of a teardown or partially completed create. */
static inline int virtio_gpu_sync_wait_cancelled(
    int wait_result, int requires_completion)
{
    return wait_result < 0 && !requires_completion;
}

static inline void virtio_gpu_sync_state_reset(
    virtio_gpu_sync_state_t *state)
{
    if (!state) return;
    state->busy = 0u;
    state->complete = 0u;
    state->abandoned = 0u;
}

static inline int virtio_gpu_sync_state_begin(
    virtio_gpu_sync_state_t *state)
{
    if (!state || state->busy) return 0;
    state->busy = 1u;
    state->complete = 0u;
    state->abandoned = 0u;
    return 1;
}

static inline int virtio_gpu_sync_state_device_complete(
    virtio_gpu_sync_state_t *state)
{
    if (!state || !state->busy) return 0;
    if (state->abandoned) {
        virtio_gpu_sync_state_reset(state);
        return 2;
    }
    state->complete = 1u;
    return 1;
}

static inline int virtio_gpu_sync_state_take(
    virtio_gpu_sync_state_t *state)
{
    if (!state || !state->busy || !state->complete) return 0;
    virtio_gpu_sync_state_reset(state);
    return 1;
}

static inline int virtio_gpu_sync_state_abandon(
    virtio_gpu_sync_state_t *state)
{
    if (!state || !state->busy || state->complete) return 0;
    state->abandoned = 1u;
    return 1;
}

#endif
