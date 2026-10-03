/* SPDX-License-Identifier: MPL-2.0 */
/* Exercise the ARM64 MMIO driver's completion identity and reset boundary. */

#include "../../src/drivers/virtio/virtio_blk_mmio.c"

int main(void) {
    static virtio_blk_mmio_device_t device;
    static virtio_blk_mmio_device_t wrapped;
    static uint32_t registers[128];

    device.mmio = (volatile uint8_t *)registers;
    device.ready = 1u;
    device.requests[0].busy = 1u;
    device.requests[1].busy = 1u;
    device.requests[0].status = VIRTIO_BLK_S_OK;
    device.requests[1].status = VIRTIO_BLK_S_IOERR;
    device.used.ring[0].id = 3u;
    device.used.ring[1].id = 0u;
    device.used.index = 2u;
    if (device_drain_used_locked(&device) != 0 ||
        device.used_index != 2u ||
        !device.requests[0].done || !device.requests[1].done ||
        device.requests[0].status != VIRTIO_BLK_S_OK ||
        device.requests[1].status != VIRTIO_BLK_S_IOERR)
        return 1;

    device.used.ring[2].id = 6u;
    device.used.index = 3u;
    if (device_drain_used_locked(&device) == 0 || device.ready ||
        device.used_index != 2u)
        return 2;

    wrapped.mmio = (volatile uint8_t *)registers;
    wrapped.ready = 1u;
    wrapped.used_index = UINT16_MAX;
    wrapped.requests[1].busy = 1u;
    wrapped.used.ring[UINT16_MAX % VIRTIO_BLK_QUEUE_SIZE].id = 3u;
    wrapped.used.index = 0u;
    if (device_drain_used_locked(&wrapped) != 0 ||
        wrapped.used_index != 0u || !wrapped.requests[1].done)
        return 3;
    return 0;
}
