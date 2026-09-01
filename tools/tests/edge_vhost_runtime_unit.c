/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/edge_vhost_runtime.h"
#include "kernel/linux_errno.h"

typedef struct test_state {
    edge_vhost_handle_t handle;
    edge_vhost_handle_t scsi_handle;
    edge_vhost_handle_t vsock_handle;
    edge_vhost_handle_t vdpa_handle;
    int descriptor;
    int live;
    uint32_t event_references;
    uint32_t backend_references;
    uint8_t vdpa_status;
    uint8_t vdpa_config[16];
    uint32_t vdpa_calls;
    uint32_t iotlb_updates;
    uint32_t iotlb_invalidates;
    uint32_t iotlb_batches;
    uint32_t iotlb_reads;
} test_state_t;

typedef struct test_memory {
    uint32_t nregions;
    uint32_t padding;
    edge_vhost_memory_region_t regions[2];
} test_memory_t;

typedef struct test_vdpa_config {
    struct {
        uint32_t off;
        uint32_t len;
    } header;
    uint8_t bytes[8];
} test_vdpa_config_t;

typedef struct test_features_array {
    uint64_t count;
    uint64_t features[1];
} test_features_array_t;

static int install_net(void *opaque, edge_vhost_handle_t handle) {
    test_state_t *state = opaque;
    state->handle = handle;
    state->descriptor = 7;
    state->live = 1;
    return state->descriptor;
}

static int resolve_net(void *opaque, int32_t descriptor,
                       edge_vhost_handle_t *handle) {
    test_state_t *state = opaque;
    if (!state->live || descriptor != state->descriptor || !handle)
        return -EDGE_LINUX_EBADF;
    *handle = state->handle;
    return 0;
}

static int install_device(void *opaque, kernel_edge_vhost_device_kind_t kind,
                          uint32_t device_id, edge_vhost_handle_t handle) {
    test_state_t *state = opaque;
    assert((kind == KERNEL_EDGE_VHOST_DEVICE_VDPA && device_id == 3) ||
           (kind != KERNEL_EDGE_VHOST_DEVICE_VDPA && device_id == 0));
    if (kind == KERNEL_EDGE_VHOST_DEVICE_SCSI) {
        state->scsi_handle = handle;
        return 8;
    }
    if (kind == KERNEL_EDGE_VHOST_DEVICE_VSOCK) {
        state->vsock_handle = handle;
        return 9;
    }
    if (kind == KERNEL_EDGE_VHOST_DEVICE_VDPA) {
        state->vdpa_handle = handle;
        return 10;
    }
    return -EDGE_LINUX_ENODEV;
}

static int resolve_device(void *opaque, int32_t descriptor,
                          kernel_edge_vhost_device_kind_t *kind,
                          uint32_t *device_id,
                          edge_vhost_handle_t *handle) {
    test_state_t *state = opaque;
    if (!kind || !device_id || !handle) return -EDGE_LINUX_EINVAL;
    *device_id = 0;
    if (descriptor == 8) {
        *kind = KERNEL_EDGE_VHOST_DEVICE_SCSI;
        *handle = state->scsi_handle;
        return 0;
    }
    if (descriptor == 9) {
        *kind = KERNEL_EDGE_VHOST_DEVICE_VSOCK;
        *handle = state->vsock_handle;
        return 0;
    }
    if (descriptor == 10) {
        *kind = KERNEL_EDGE_VHOST_DEVICE_VDPA;
        *device_id = 3;
        *handle = state->vdpa_handle;
        return 0;
    }
    return -EDGE_LINUX_EBADF;
}

static int resolve_eventfd(void *opaque, int32_t descriptor,
                           int32_t *event_id) {
    (void)opaque;
    if (descriptor != 9 || !event_id) return -EDGE_LINUX_EBADF;
    *event_id = 1009;
    ++((test_state_t *)opaque)->event_references;
    return 0;
}

static void release_eventfd(void *opaque, int32_t event_id) {
    test_state_t *state = opaque;
    assert(event_id == 1009 && state->event_references != 0);
    --state->event_references;
}

static int resolve_backend(void *opaque, int32_t descriptor,
                           uint64_t *backend_id) {
    (void)opaque;
    if (descriptor != 11 || !backend_id) return -EDGE_LINUX_EBADF;
    *backend_id = 2011;
    ++((test_state_t *)opaque)->backend_references;
    return 0;
}

static void release_backend(void *opaque, uint64_t backend_id) {
    test_state_t *state = opaque;
    assert(backend_id == 2011 && state->backend_references != 0);
    --state->backend_references;
}

static int vdpa_probe(void *opaque, uint32_t device_id,
                      kernel_edge_vhost_vdpa_device_info_t *info) {
    (void)opaque;
    if (device_id != 3) return -EDGE_LINUX_ENODEV;
    *info = (kernel_edge_vhost_vdpa_device_info_t) {
        .virtio_device_id = 1,
        .config_size = 16,
        .queue_count = 2,
        .group_count = 2,
        .address_space_count = 4,
        .max_queue_size = 256,
        .first_iova = 0x1000,
        .last_iova = 0xfffff,
        .features = UINT64_C(1) << EDGE_VIRTIO_F_VERSION_1,
        .backend_features = UINT64_C(1),
    };
    return 0;
}

static int vdpa_get_status(void *opaque, uint32_t device_id,
                           uint8_t *status) {
    test_state_t *state = opaque;
    assert(device_id == 3);
    *status = state->vdpa_status;
    return 0;
}

static int vdpa_set_status(void *opaque, uint32_t device_id,
                           uint8_t status) {
    test_state_t *state = opaque;
    assert(device_id == 3);
    state->vdpa_status = status;
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_set_features(void *opaque, uint32_t device_id,
                             uint64_t features,
                             uint64_t backend_features) {
    test_state_t *state = opaque;
    assert(device_id == 3 &&
           (features & ~(UINT64_C(1) << EDGE_VIRTIO_F_VERSION_1)) == 0 &&
           (backend_features & ~UINT64_C(1)) == 0);
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_get_config(void *opaque, uint32_t device_id,
                           uint32_t offset, void *buffer, uint32_t length) {
    test_state_t *state = opaque;
    assert(device_id == 3 && offset + length <= sizeof(state->vdpa_config));
    memcpy(buffer, state->vdpa_config + offset, length);
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_set_config(void *opaque, uint32_t device_id,
                           uint32_t offset, const void *buffer,
                           uint32_t length) {
    test_state_t *state = opaque;
    assert(device_id == 3 && offset + length <= sizeof(state->vdpa_config));
    memcpy(state->vdpa_config + offset, buffer, length);
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_set_vring_enable(void *opaque, uint32_t device_id,
                                 uint32_t vring, int enabled) {
    test_state_t *state = opaque;
    assert(device_id == 3 && vring < 2 && (enabled == 0 || enabled == 1));
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_set_config_event(void *opaque, uint32_t device_id,
                                 int32_t event_id) {
    test_state_t *state = opaque;
    assert(device_id == 3 && (event_id == -1 || event_id == 1009));
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_set_group_asid(void *opaque, uint32_t device_id,
                               uint32_t group, uint32_t asid) {
    test_state_t *state = opaque;
    assert(device_id == 3 && group < 2 && asid < 4);
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_iotlb_update(void *opaque, uint32_t device_id,
                             uint32_t asid,
                             const edge_vhost_iotlb_msg_t *message) {
    test_state_t *state = opaque;
    assert(device_id == 3 && asid == 1 && message &&
           message->type == EDGE_VHOST_IOTLB_UPDATE &&
           message->iova == 0x2000 && message->size == 0x1000 &&
           message->uaddr == 0x100000 &&
           message->perm == EDGE_VHOST_ACCESS_RW);
    ++state->iotlb_updates;
    return 0;
}

static int vdpa_iotlb_invalidate(void *opaque, uint32_t device_id,
                                 uint32_t asid,
                                 const edge_vhost_iotlb_msg_t *message) {
    test_state_t *state = opaque;
    assert(device_id == 3 && asid == 1 && message &&
           message->type == EDGE_VHOST_IOTLB_INVALIDATE &&
           message->iova == 0x2000 && message->size == 0x1000);
    ++state->iotlb_invalidates;
    return 0;
}

static int vdpa_iotlb_batch(void *opaque, uint32_t device_id,
                            uint32_t asid, int begin) {
    test_state_t *state = opaque;
    assert(device_id == 3 && asid == 1 && (begin == 0 || begin == 1));
    ++state->iotlb_batches;
    return 0;
}

static int vdpa_iotlb_read(void *opaque, uint32_t device_id,
                           edge_vhost_msg_v2_t *message) {
    test_state_t *state = opaque;
    assert(device_id == 3 && message);
    if (state->iotlb_reads != 0) return -EDGE_LINUX_EAGAIN;
    message->type = EDGE_VHOST_IOTLB_MSG_V2;
    message->asid = 1;
    message->payload.iotlb.iova = 0x3000;
    message->payload.iotlb.size = 0x1000;
    message->payload.iotlb.type = EDGE_VHOST_IOTLB_MISS;
    ++state->iotlb_reads;
    return 0;
}

static int vdpa_suspend(void *opaque, uint32_t device_id) {
    test_state_t *state = opaque;
    assert(device_id == 3);
    ++state->vdpa_calls;
    return 0;
}

static int vdpa_resume(void *opaque, uint32_t device_id) {
    return vdpa_suspend(opaque, device_id);
}

static int copy_from_user(void *opaque, void *destination,
                          uint64_t source, uint64_t size) {
    (void)opaque;
    memcpy(destination, (const void *)(uintptr_t)source, (size_t)size);
    return 0;
}

static int copy_to_user(void *opaque, uint64_t destination,
                        const void *source, uint64_t size) {
    (void)opaque;
    memcpy((void *)(uintptr_t)destination, source, (size_t)size);
    return 0;
}

static int64_t issue(int descriptor, uint32_t command, void *argument) {
    kernel_ioctl_request_t request = {
        .descriptor = descriptor,
        .command = command,
        .argument = (uint64_t)(uintptr_t)argument,
        .copy_from_user = copy_from_user,
        .copy_to_user = copy_to_user,
        .user_pointer_size = 8,
    };
    return kernel_edge_vhost_ioctl(&request);
}

int main(void) {
    test_state_t state = {0};
    kernel_edge_vhost_descriptor_backend_ops_t descriptors = {
        .install_net = install_net,
        .resolve_net = resolve_net,
        .install_device = install_device,
        .resolve_device = resolve_device,
        .resolve_eventfd = resolve_eventfd,
        .release_eventfd = release_eventfd,
        .resolve_backend = resolve_backend,
        .release_backend = release_backend,
    };
    kernel_edge_vhost_vdpa_backend_ops_t vdpa = {
        .probe = vdpa_probe,
        .get_status = vdpa_get_status,
        .set_status = vdpa_set_status,
        .set_features = vdpa_set_features,
        .get_config = vdpa_get_config,
        .set_config = vdpa_set_config,
        .set_vring_enable = vdpa_set_vring_enable,
        .set_config_event = vdpa_set_config_event,
        .set_group_asid = vdpa_set_group_asid,
        .iotlb_update = vdpa_iotlb_update,
        .iotlb_invalidate = vdpa_iotlb_invalidate,
        .iotlb_batch = vdpa_iotlb_batch,
        .iotlb_read = vdpa_iotlb_read,
        .suspend = vdpa_suspend,
        .resume = vdpa_resume,
    };
    test_memory_t memory = {
        .nregions = 2,
        .regions = {
            {.guest_phys_addr = 0x1000, .memory_size = 0x2000,
             .userspace_addr = 0x100000},
            {.guest_phys_addr = 0x4000, .memory_size = 0x1000,
             .userspace_addr = 0x104000},
        },
    };
    edge_vhost_vring_state_t ring = {.index = 0, .num = 256};
    edge_vhost_vring_addr_t address = {
        .index = 0,
        .desc_user_addr = 0x100000,
        .avail_user_addr = 0x101000,
        .used_user_addr = 0x102000,
    };
    edge_vhost_vring_file_t file = {.index = 0, .fd = 9};
    edge_vhost_worker_state_t worker = {0};
    edge_vhost_vring_worker_t ring_worker = {.index = 0};
    uint64_t features = 0;
    test_features_array_t feature_array = {.count = 1};
    uint8_t fork_owner = EDGE_VHOST_FORK_OWNER_KTHREAD;
    edge_vhost_scsi_target_t target = {
        .abi_version = EDGE_VHOST_SCSI_ABI_VERSION,
        .vhost_wwpn = "naa.5001405ed5700001",
    };
    uint32_t abi_version = 0;
    uint32_t events_missed = 1;
    uint64_t guest_cid = 7;
    int32_t running = 1;
    test_vdpa_config_t vdpa_config = {
        .header = {.off = 4, .len = 8},
        .bytes = {1, 2, 3, 4, 5, 6, 7, 8},
    };
    edge_vhost_vdpa_iova_range_t vdpa_range;
    uint8_t vdpa_status = 4;
    uint32_t vdpa_value32 = 0;
    uint16_t vdpa_value16 = 0;
    uint64_t vdpa_features = UINT64_C(1) << EDGE_VIRTIO_F_VERSION_1;
    uint64_t vdpa_backend_features = 1;
    int32_t vdpa_eventfd = 9;
    edge_vhost_vring_state_t vdpa_ring = {.index = 1, .num = 1};
    edge_vhost_msg_v2_t iotlb = {
        .type = EDGE_VHOST_IOTLB_MSG_V2,
        .asid = 1,
        .payload.iotlb = {
            .iova = 0x2000,
            .size = 0x1000,
            .uaddr = 0x100000,
            .perm = EDGE_VHOST_ACCESS_RW,
            .type = EDGE_VHOST_IOTLB_UPDATE,
        },
    };
    edge_vhost_msg_v2_t iotlb_event;
    int descriptor;

    assert(kernel_edge_vhost_descriptor_backend_register(
               &descriptors, &state) == 0);
    assert(kernel_edge_vhost_open_vdpa(3) == -EDGE_LINUX_ENODEV);
    assert(kernel_edge_vhost_vdpa_backend_register(&vdpa, &state) == 0);
    descriptor = kernel_edge_vhost_open_net();
    assert(descriptor == 7);
    assert(issue(descriptor, EDGE_VHOST_GET_FEATURES, &features) == 0);
    assert((features & (UINT64_C(1) << EDGE_VIRTIO_F_VERSION_1)) != 0);
    assert(issue(descriptor, EDGE_VHOST_SET_FEATURES, &features) ==
           -EDGE_LINUX_EPERM);
    assert(issue(descriptor, EDGE_VHOST_GET_FEATURES_ARRAY,
                 &feature_array) == 0 &&
           feature_array.features[0] == features);
    assert(issue(descriptor, EDGE_VHOST_SET_FORK_FROM_OWNER,
                 &fork_owner) == 0);
    fork_owner = UINT8_MAX;
    assert(issue(descriptor, EDGE_VHOST_GET_FORK_FROM_OWNER,
                 &fork_owner) == 0 &&
           fork_owner == EDGE_VHOST_FORK_OWNER_KTHREAD);
    assert(issue(descriptor, EDGE_VHOST_SET_OWNER, 0) == 0);
    assert(issue(descriptor, EDGE_VHOST_SET_OWNER, 0) ==
           -EDGE_LINUX_EBUSY);
    assert(issue(descriptor, EDGE_VHOST_SET_FEATURES, &features) == 0);
    assert(issue(descriptor, EDGE_VHOST_SET_FEATURES_ARRAY,
                 &feature_array) == 0);
    assert(issue(descriptor, EDGE_VHOST_SET_MEM_TABLE, &memory) == 0);
    assert(issue(descriptor, EDGE_VHOST_SET_VRING_NUM, &ring) == 0);
    ring.num = EDGE_VHOST_VRING_BIG_ENDIAN;
    assert(issue(descriptor, EDGE_VHOST_SET_VRING_ENDIAN, &ring) == 0);
    ring.num = UINT32_MAX;
    assert(issue(descriptor, EDGE_VHOST_GET_VRING_ENDIAN, &ring) == 0);
    assert(ring.num == EDGE_VHOST_VRING_LITTLE_ENDIAN);
    ring.num = 50;
    assert(issue(descriptor, EDGE_VHOST_SET_VRING_BUSYLOOP_TIMEOUT,
                 &ring) == 0);
    ring.num = 0;
    assert(issue(descriptor, EDGE_VHOST_GET_VRING_BUSYLOOP_TIMEOUT,
                 &ring) == 0);
    assert(ring.num == 50);
    assert(issue(descriptor, EDGE_VHOST_NEW_WORKER, &worker) == 0 &&
           worker.worker_id != 0);
    ring_worker.worker_id = worker.worker_id;
    assert(issue(descriptor, EDGE_VHOST_ATTACH_VRING_WORKER,
                 &ring_worker) == 0);
    ring_worker.worker_id = UINT32_MAX;
    assert(issue(descriptor, EDGE_VHOST_GET_VRING_WORKER,
                 &ring_worker) == 0 &&
           ring_worker.worker_id == worker.worker_id);
    assert(issue(descriptor, EDGE_VHOST_FREE_WORKER, &worker) ==
           -EDGE_LINUX_EBUSY);
    ring_worker.worker_id = 0;
    assert(issue(descriptor, EDGE_VHOST_ATTACH_VRING_WORKER,
                 &ring_worker) == 0);
    assert(issue(descriptor, EDGE_VHOST_FREE_WORKER, &worker) == 0);
    assert(issue(descriptor, EDGE_VHOST_SET_VRING_ADDR, &address) == 0);
    assert(issue(descriptor, EDGE_VHOST_SET_VRING_KICK, &file) == 0);
    file.fd = 11;
    assert(issue(descriptor, EDGE_VHOST_NET_SET_BACKEND, &file) == 0);
    ring.num = 23;
    assert(issue(descriptor, EDGE_VHOST_GET_VRING_BASE, &ring) == 0);
    assert(ring.num == 0);
    assert(issue(descriptor, EDGE_VHOST_RESET_OWNER, 0) == 0);
    assert(state.event_references == 0 && state.backend_references == 0);
    assert(kernel_edge_vhost_descriptor_retain(state.handle) == 0);
    assert(kernel_edge_vhost_descriptor_release(state.handle) == 0);
    assert(kernel_edge_vhost_open_scsi() == 8);
    assert(issue(8, EDGE_VHOST_SCSI_GET_ABI_VERSION, &abi_version) == 0 &&
           abi_version == EDGE_VHOST_SCSI_ABI_VERSION);
    assert(issue(8, EDGE_VHOST_SET_OWNER, 0) == 0);
    assert(issue(8, EDGE_VHOST_SCSI_SET_ENDPOINT, &target) == 0);
    assert(issue(8, EDGE_VHOST_SCSI_SET_EVENTS_MISSED, &events_missed) == 0);
    events_missed = 0;
    assert(issue(8, EDGE_VHOST_SCSI_GET_EVENTS_MISSED, &events_missed) == 0 &&
           events_missed == 1);
    assert(issue(8, EDGE_VHOST_SCSI_CLEAR_ENDPOINT, &target) == 0);
    assert(kernel_edge_vhost_descriptor_release(state.scsi_handle) == 0);
    assert(kernel_edge_vhost_open_vsock() == 9);
    assert(issue(9, EDGE_VHOST_SET_OWNER, 0) == 0);
    assert(issue(9, EDGE_VHOST_VSOCK_SET_GUEST_CID, &guest_cid) == 0);
    assert(issue(9, EDGE_VHOST_VSOCK_SET_RUNNING, &running) == 0);
    assert(issue(9, EDGE_VHOST_VSOCK_SET_GUEST_CID, &guest_cid) ==
           -EDGE_LINUX_EINVAL);
    running = 0;
    assert(issue(9, EDGE_VHOST_VSOCK_SET_RUNNING, &running) == 0);
    assert(kernel_edge_vhost_descriptor_release(state.vsock_handle) == 0);
    assert(kernel_edge_vhost_open_vdpa(0) == -EDGE_LINUX_ENODEV);
    assert(kernel_edge_vhost_open_vdpa(3) == 10);
    assert(issue(10, EDGE_VHOST_VDPA_GET_DEVICE_ID, &vdpa_value32) == 0 &&
           vdpa_value32 == 1);
    assert(issue(10, EDGE_VHOST_VDPA_GET_VRING_NUM, &vdpa_value16) == 0 &&
           vdpa_value16 == 256);
    assert(issue(10, EDGE_VHOST_VDPA_GET_IOVA_RANGE, &vdpa_range) == 0 &&
           vdpa_range.first == 0x1000 && vdpa_range.last == 0xfffff);
    assert(issue(10, EDGE_VHOST_VDPA_GET_CONFIG_SIZE, &vdpa_value32) == 0 &&
           vdpa_value32 == 16);
    assert(issue(10, EDGE_VHOST_VDPA_GET_VQS_COUNT, &vdpa_value32) == 0 &&
           vdpa_value32 == 2);
    assert(issue(10, EDGE_VHOST_VDPA_GET_GROUP_NUM, &vdpa_value32) == 0 &&
           vdpa_value32 == 2);
    assert(issue(10, EDGE_VHOST_SET_OWNER, 0) == 0);
    assert(issue(10, EDGE_VHOST_SET_FEATURES, &vdpa_features) == 0);
    assert(issue(10, EDGE_VHOST_SET_BACKEND_FEATURES,
                 &vdpa_backend_features) == 0);
    assert(kernel_edge_vhost_write(state.vdpa_handle, &iotlb,
                                   sizeof(iotlb)) == sizeof(iotlb));
    iotlb.payload.iotlb.type = EDGE_VHOST_IOTLB_INVALIDATE;
    assert(kernel_edge_vhost_write(state.vdpa_handle, &iotlb,
                                   sizeof(iotlb)) == sizeof(iotlb));
    iotlb.payload.iotlb.type = EDGE_VHOST_IOTLB_BATCH_BEGIN;
    assert(kernel_edge_vhost_write(state.vdpa_handle, &iotlb,
                                   sizeof(iotlb)) == sizeof(iotlb));
    iotlb.payload.iotlb.type = EDGE_VHOST_IOTLB_BATCH_END;
    assert(kernel_edge_vhost_write(state.vdpa_handle, &iotlb,
                                   sizeof(iotlb)) == sizeof(iotlb));
    assert(state.iotlb_updates == 1 && state.iotlb_invalidates == 1 &&
           state.iotlb_batches == 2);
    assert(kernel_edge_vhost_read(state.vdpa_handle, &iotlb_event,
                                  sizeof(iotlb_event)) ==
           sizeof(iotlb_event));
    assert(iotlb_event.type == EDGE_VHOST_IOTLB_MSG_V2 &&
           iotlb_event.asid == 1 &&
           iotlb_event.payload.iotlb.type == EDGE_VHOST_IOTLB_MISS &&
           iotlb_event.payload.iotlb.iova == 0x3000);
    assert(kernel_edge_vhost_read(state.vdpa_handle, &iotlb_event,
                                  sizeof(iotlb_event)) ==
           -EDGE_LINUX_EAGAIN);
    assert(issue(10, EDGE_VHOST_VDPA_SET_STATUS, &vdpa_status) == 0);
    vdpa_status = 0;
    assert(issue(10, EDGE_VHOST_VDPA_GET_STATUS, &vdpa_status) == 0 &&
           vdpa_status == 4);
    assert(issue(10, EDGE_VHOST_VDPA_SET_CONFIG, &vdpa_config) == 0);
    memset(vdpa_config.bytes, 0, sizeof(vdpa_config.bytes));
    assert(issue(10, EDGE_VHOST_VDPA_GET_CONFIG, &vdpa_config) == 0 &&
           vdpa_config.bytes[0] == 1 && vdpa_config.bytes[7] == 8);
    assert(issue(10, EDGE_VHOST_VDPA_SET_VRING_ENABLE, &vdpa_ring) == 0);
    assert(issue(10, EDGE_VHOST_VDPA_SET_CONFIG_CALL, &vdpa_eventfd) == 0 &&
           state.event_references == 1);
    vdpa_ring.num = UINT32_MAX;
    assert(issue(10, EDGE_VHOST_VDPA_GET_VRING_GROUP, &vdpa_ring) == 0 &&
           vdpa_ring.num == 1);
    vdpa_ring.index = 1;
    vdpa_ring.num = 3;
    assert(issue(10, EDGE_VHOST_VDPA_SET_GROUP_ASID, &vdpa_ring) == 0);
    assert(issue(10, EDGE_VHOST_VDPA_GET_VRING_SIZE, &vdpa_ring) == 0 &&
           vdpa_ring.num == 256);
    assert(issue(10, EDGE_VHOST_VDPA_SUSPEND, 0) == 0);
    assert(issue(10, EDGE_VHOST_VDPA_RESUME, 0) == 0);
    assert(kernel_edge_vhost_descriptor_release(state.vdpa_handle) == 0 &&
           state.event_references == 0);
    assert(kernel_edge_vhost_descriptor_release(state.handle) == 0);
    state.live = 0;
    assert(issue(descriptor, EDGE_VHOST_GET_FEATURES, &features) ==
           -EDGE_LINUX_ENOTTY);

    puts("edge_vhost_runtime_unit: PASS");
    return 0;
}
