/* SPDX-License-Identifier: MPL-2.0 */
/* Original EdgeOS descriptor and state boundary for the vhost ABI. */

#include "kernel/edge_vhost_runtime.h"
#include "kernel/linux_errno.h"

#define EDGE_VHOST_MAX_DEVICES 32u
#define EDGE_VHOST_MAX_MEMORY_REGIONS 64u
#define EDGE_VHOST_MAX_VRINGS 128u
#define EDGE_VHOST_MAX_RING_SIZE 32768u
#define EDGE_VHOST_MAX_WORKERS 8u
#define EDGE_VHOST_MAX_VDPA_CONFIG 4096u
#define EDGE_VHOST_INVALID_ID UINT64_MAX

#define EDGE_VHOST_FEATURES \
    ((UINT64_C(1) << EDGE_VHOST_F_LOG_ALL) | \
     (UINT64_C(1) << EDGE_VHOST_NET_F_VIRTIO_NET_HDR) | \
     (UINT64_C(1) << EDGE_VIRTIO_RING_F_INDIRECT_DESC) | \
     (UINT64_C(1) << EDGE_VIRTIO_RING_F_EVENT_IDX) | \
     (UINT64_C(1) << EDGE_VIRTIO_F_VERSION_1))
#define EDGE_VHOST_BACKEND_FEATURES UINT64_C(0)

typedef struct edge_vhost_vring_runtime {
    uint32_t num;
    uint32_t base;
    uint32_t flags;
    uint32_t endian;
    uint32_t busyloop_timeout;
    uint32_t worker_id;
    uint64_t desc;
    uint64_t used;
    uint64_t avail;
    uint64_t log;
    int32_t kick_event;
    int32_t call_event;
    int32_t err_event;
    uint64_t backend_id;
} edge_vhost_vring_runtime_t;

typedef struct edge_vhost_device_runtime {
    uint32_t generation;
    uint32_t references;
    uint8_t live;
    uint8_t owner;
    uint8_t fork_owner;
    uint8_t reserved;
    kernel_edge_vhost_device_kind_t kind;
    uint32_t device_id;
    uint32_t vring_count;
    uint64_t features;
    uint64_t backend_features;
    uint64_t log_base;
    int32_t log_event;
    uint32_t memory_count;
    uint32_t next_worker_id;
    uint32_t workers[EDGE_VHOST_MAX_WORKERS];
    uint8_t scsi_endpoint_set;
    uint8_t vsock_running;
    uint8_t vdpa_suspended;
    uint8_t state_reserved;
    uint32_t scsi_events_missed;
    uint64_t vsock_guest_cid;
    int32_t vdpa_config_event;
    kernel_edge_vhost_vdpa_device_info_t vdpa_info;
    edge_vhost_scsi_target_t scsi_target;
    edge_vhost_memory_region_t memory[EDGE_VHOST_MAX_MEMORY_REGIONS];
    edge_vhost_vring_runtime_t vrings[EDGE_VHOST_MAX_VRINGS];
} edge_vhost_device_runtime_t;

static edge_vhost_device_runtime_t g_devices[EDGE_VHOST_MAX_DEVICES];
static const kernel_edge_vhost_descriptor_backend_ops_t *g_descriptors;
static void *g_descriptor_context;
static const kernel_edge_vhost_vdpa_backend_ops_t *g_vdpa;
static void *g_vdpa_context;
static volatile uint32_t g_lock;
static edge_vhost_memory_region_t
    g_memory_scratch[EDGE_VHOST_MAX_MEMORY_REGIONS];
static uint8_t g_vdpa_config_scratch[EDGE_VHOST_MAX_VDPA_CONFIG];
static uint64_t g_feature_scratch[4];

static int copy_from(const kernel_ioctl_request_t *request, void *destination,
                     uint64_t source, uint64_t size);
static int copy_to(const kernel_ioctl_request_t *request,
                   uint64_t destination, const void *source, uint64_t size);

static void vhost_lock(void) {
    while (__atomic_exchange_n(&g_lock, 1u, __ATOMIC_ACQUIRE)) {
        while (__atomic_load_n(&g_lock, __ATOMIC_RELAXED))
            __asm__ __volatile__("" ::: "memory");
    }
}

static void vhost_unlock(void) {
    __atomic_store_n(&g_lock, 0u, __ATOMIC_RELEASE);
}

static void vring_reset(edge_vhost_vring_runtime_t *vring) {
    if (g_descriptors) {
        if (vring->kick_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, vring->kick_event);
        if (vring->call_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, vring->call_event);
        if (vring->err_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, vring->err_event);
        if (vring->backend_id != EDGE_VHOST_INVALID_ID)
            g_descriptors->release_backend(
                g_descriptor_context, vring->backend_id);
    }
    vring->num = 0;
    vring->base = 0;
    vring->flags = 0;
    vring->endian = EDGE_VHOST_VRING_LITTLE_ENDIAN;
    vring->busyloop_timeout = 0;
    vring->worker_id = 0;
    vring->desc = 0;
    vring->used = 0;
    vring->avail = 0;
    vring->log = 0;
    vring->kick_event = -1;
    vring->call_event = -1;
    vring->err_event = -1;
    vring->backend_id = EDGE_VHOST_INVALID_ID;
}

static void device_reset(edge_vhost_device_runtime_t *device) {
    if (device->kind == KERNEL_EDGE_VHOST_DEVICE_VDPA && g_vdpa) {
        (void)g_vdpa->set_config_event(g_vdpa_context,
                                       device->device_id, -1);
        (void)g_vdpa->set_status(g_vdpa_context, device->device_id, 0);
    }
    if (g_descriptors && device->log_event >= 0)
        g_descriptors->release_eventfd(
            g_descriptor_context, device->log_event);
    if (g_descriptors && device->vdpa_config_event >= 0)
        g_descriptors->release_eventfd(
            g_descriptor_context, device->vdpa_config_event);
    device->owner = 0;
    device->fork_owner = EDGE_VHOST_FORK_OWNER_TASK;
    device->features = 0;
    device->backend_features = 0;
    device->log_base = 0;
    device->log_event = -1;
    device->memory_count = 0;
    device->scsi_endpoint_set = 0;
    device->scsi_events_missed = 0;
    device->vsock_guest_cid = 0;
    device->vsock_running = 0;
    device->vdpa_suspended = 0;
    device->vdpa_config_event = -1;
    device->next_worker_id = 1;
    for (uint32_t index = 0; index < EDGE_VHOST_MAX_WORKERS; ++index)
        device->workers[index] = 0;
    for (uint32_t index = 0; index < EDGE_VHOST_MAX_VRINGS; ++index)
        vring_reset(&device->vrings[index]);
}

static int worker_exists(const edge_vhost_device_runtime_t *device,
                         uint32_t worker_id) {
    if (worker_id == 0) return 1;
    for (uint32_t index = 0; index < EDGE_VHOST_MAX_WORKERS; ++index) {
        if (device->workers[index] == worker_id) return 1;
    }
    return 0;
}

static int worker_ioctl(const kernel_ioctl_request_t *request,
                        edge_vhost_device_runtime_t *device) {
    edge_vhost_worker_state_t worker;
    edge_vhost_vring_worker_t ring_worker;
    int status;

    if (request->command == EDGE_VHOST_NEW_WORKER) {
        for (uint32_t index = 0; index < EDGE_VHOST_MAX_WORKERS; ++index) {
            if (device->workers[index] != 0) continue;
            if (device->next_worker_id == 0)
                return -EDGE_LINUX_EOVERFLOW;
            worker.worker_id = device->next_worker_id++;
            device->workers[index] = worker.worker_id;
            status = copy_to(request, request->argument, &worker,
                             sizeof(worker));
            if (status < 0) device->workers[index] = 0;
            return status;
        }
        return -EDGE_LINUX_ENOSPC;
    }
    if (request->command == EDGE_VHOST_FREE_WORKER) {
        status = copy_from(request, &worker, request->argument,
                           sizeof(worker));
        if (status < 0) return status;
        if (worker.worker_id == 0) return -EDGE_LINUX_EINVAL;
        for (uint32_t ring = 0; ring < device->vring_count; ++ring) {
            if (device->vrings[ring].worker_id == worker.worker_id)
                return -EDGE_LINUX_EBUSY;
        }
        for (uint32_t index = 0; index < EDGE_VHOST_MAX_WORKERS; ++index) {
            if (device->workers[index] != worker.worker_id) continue;
            device->workers[index] = 0;
            return 0;
        }
        return -EDGE_LINUX_ENOENT;
    }
    status = copy_from(request, &ring_worker, request->argument,
                       sizeof(ring_worker));
    if (status < 0) return status;
    if (ring_worker.index >= device->vring_count)
        return -EDGE_LINUX_EINVAL;
    if (request->command == EDGE_VHOST_ATTACH_VRING_WORKER) {
        if (!worker_exists(device, ring_worker.worker_id))
            return -EDGE_LINUX_ENOENT;
        device->vrings[ring_worker.index].worker_id = ring_worker.worker_id;
        return 0;
    }
    ring_worker.worker_id = device->vrings[ring_worker.index].worker_id;
    return copy_to(request, request->argument, &ring_worker,
                   sizeof(ring_worker));
}

int kernel_edge_vhost_descriptor_backend_register(
        const kernel_edge_vhost_descriptor_backend_ops_t *ops, void *context) {
    if (!ops || !ops->install_net || !ops->resolve_net ||
        !ops->install_device || !ops->resolve_device ||
        !ops->resolve_eventfd || !ops->release_eventfd ||
        !ops->resolve_backend || !ops->release_backend)
        return -EDGE_LINUX_EINVAL;
    g_descriptors = ops;
    g_descriptor_context = context;
    return 0;
}

int kernel_edge_vhost_vdpa_backend_register(
        const kernel_edge_vhost_vdpa_backend_ops_t *ops, void *context) {
    if (!ops || !ops->probe || !ops->get_status || !ops->set_status ||
        !ops->set_features || !ops->get_config || !ops->set_config ||
        !ops->set_vring_enable || !ops->set_config_event ||
        !ops->set_group_asid || !ops->iotlb_update ||
        !ops->iotlb_invalidate || !ops->iotlb_batch || !ops->iotlb_read ||
        !ops->suspend || !ops->resume)
        return -EDGE_LINUX_EINVAL;
    g_vdpa = ops;
    g_vdpa_context = context;
    return 0;
}

static int device_resolve(edge_vhost_handle_t handle,
                          edge_vhost_device_runtime_t **device_out) {
    edge_vhost_device_runtime_t *device;
    if (!device_out || handle.slot >= EDGE_VHOST_MAX_DEVICES)
        return -EDGE_LINUX_EBADF;
    device = &g_devices[handle.slot];
    if (!device->live || device->generation != handle.generation)
        return -EDGE_LINUX_EBADF;
    *device_out = device;
    return 0;
}

static int device_open(kernel_edge_vhost_device_kind_t kind,
                       uint32_t device_id) {
    edge_vhost_handle_t handle;
    kernel_edge_vhost_vdpa_device_info_t vdpa_info = {0};
    int descriptor = -EDGE_LINUX_ENOSPC;
    if (!g_descriptors) return -EDGE_LINUX_ENODEV;
    if (kind == KERNEL_EDGE_VHOST_DEVICE_VDPA) {
        if (!g_vdpa) return -EDGE_LINUX_ENODEV;
        descriptor = g_vdpa->probe(g_vdpa_context, device_id, &vdpa_info);
        if (descriptor < 0) return descriptor;
        if (vdpa_info.queue_count == 0 ||
            vdpa_info.queue_count > EDGE_VHOST_MAX_VRINGS ||
            vdpa_info.group_count == 0 ||
            vdpa_info.address_space_count == 0 ||
            vdpa_info.max_queue_size == 0 ||
            vdpa_info.first_iova > vdpa_info.last_iova)
            return -EDGE_LINUX_EIO;
    }
    descriptor = -EDGE_LINUX_ENOSPC;
    vhost_lock();
    for (uint32_t slot = 0; slot < EDGE_VHOST_MAX_DEVICES; ++slot) {
        edge_vhost_device_runtime_t *device = &g_devices[slot];
        if (device->live) continue;
        if (device->generation == 0) {
            device->log_event = -1;
            device->vdpa_config_event = -1;
            for (uint32_t index = 0; index < EDGE_VHOST_MAX_VRINGS;
                 ++index) {
                device->vrings[index].kick_event = -1;
                device->vrings[index].call_event = -1;
                device->vrings[index].err_event = -1;
                device->vrings[index].backend_id = EDGE_VHOST_INVALID_ID;
            }
        }
        ++device->generation;
        if (device->generation == 0) ++device->generation;
        device->live = 1;
        device->references = 1;
        device->kind = kind;
        device->device_id = device_id;
        device->vring_count = kind == KERNEL_EDGE_VHOST_DEVICE_NET ||
            kind == KERNEL_EDGE_VHOST_DEVICE_VSOCK ? 2u :
            kind == KERNEL_EDGE_VHOST_DEVICE_VDPA ?
                vdpa_info.queue_count : EDGE_VHOST_MAX_VRINGS;
        device->vdpa_info = vdpa_info;
        device_reset(device);
        handle.slot = slot;
        handle.generation = device->generation;
        descriptor = kind == KERNEL_EDGE_VHOST_DEVICE_NET ?
            g_descriptors->install_net(g_descriptor_context, handle) :
            g_descriptors->install_device(g_descriptor_context, kind,
                                          device_id, handle);
        if (descriptor < 0) {
            device->live = 0;
            device->references = 0;
        }
        break;
    }
    vhost_unlock();
    return descriptor;
}

int kernel_edge_vhost_open_net(void) {
    return device_open(KERNEL_EDGE_VHOST_DEVICE_NET, 0);
}

int kernel_edge_vhost_open_scsi(void) {
    return device_open(KERNEL_EDGE_VHOST_DEVICE_SCSI, 0);
}

int kernel_edge_vhost_open_vsock(void) {
    return device_open(KERNEL_EDGE_VHOST_DEVICE_VSOCK, 0);
}

int kernel_edge_vhost_open_vdpa(uint32_t device_id) {
    return device_open(KERNEL_EDGE_VHOST_DEVICE_VDPA, device_id);
}

int kernel_edge_vhost_vdpa_path_parse(const char *path, uint32_t *device_id) {
    const char prefix[] = EDGE_VHOST_VDPA_PATH_PREFIX;
    uint64_t value = 0;
    uint32_t index = 0;
    if (!path || !device_id) return 0;
    while (prefix[index] != '\0') {
        if (path[index] != prefix[index]) return 0;
        ++index;
    }
    if (path[index] == '\0') return 0;
    while (path[index] >= '0' && path[index] <= '9') {
        value = value * 10u + (uint32_t)(path[index] - '0');
        if (value > UINT32_MAX) return 0;
        ++index;
    }
    if (path[index] != '\0') return 0;
    *device_id = (uint32_t)value;
    return 1;
}

int kernel_edge_vhost_descriptor_retain(edge_vhost_handle_t handle) {
    edge_vhost_device_runtime_t *device;
    int status;
    vhost_lock();
    status = device_resolve(handle, &device);
    if (status == 0) {
        if (device->references == UINT32_MAX)
            status = -EDGE_LINUX_EOVERFLOW;
        else
            ++device->references;
    }
    vhost_unlock();
    return status;
}

int kernel_edge_vhost_descriptor_release(edge_vhost_handle_t handle) {
    edge_vhost_device_runtime_t *device;
    int status;
    vhost_lock();
    status = device_resolve(handle, &device);
    if (status == 0) {
        if (device->references == 0) {
            status = -EDGE_LINUX_EBADF;
        } else if (--device->references == 0) {
            device_reset(device);
            device->live = 0;
        }
    }
    vhost_unlock();
    return status;
}

static int iotlb_message_validate(
        const edge_vhost_device_runtime_t *device, uint32_t asid,
        const edge_vhost_iotlb_msg_t *message) {
    uint64_t last;

    if (!device || !message || asid >= device->vdpa_info.address_space_count)
        return -EDGE_LINUX_EINVAL;
    if (message->type == EDGE_VHOST_IOTLB_BATCH_BEGIN ||
        message->type == EDGE_VHOST_IOTLB_BATCH_END)
        return 0;
    if (message->type != EDGE_VHOST_IOTLB_UPDATE &&
        message->type != EDGE_VHOST_IOTLB_INVALIDATE)
        return -EDGE_LINUX_EINVAL;
    if (message->size == 0 || message->iova > UINT64_MAX - message->size)
        return -EDGE_LINUX_EINVAL;
    last = message->iova + message->size - 1u;
    if (message->iova < device->vdpa_info.first_iova ||
        last > device->vdpa_info.last_iova)
        return -EDGE_LINUX_EINVAL;
    if (message->type == EDGE_VHOST_IOTLB_UPDATE &&
        message->perm != EDGE_VHOST_ACCESS_RO &&
        message->perm != EDGE_VHOST_ACCESS_WO &&
        message->perm != EDGE_VHOST_ACCESS_RW)
        return -EDGE_LINUX_EINVAL;
    return 0;
}

int64_t kernel_edge_vhost_write(edge_vhost_handle_t handle,
                                const void *buffer, uint32_t length) {
    edge_vhost_device_runtime_t *device;
    edge_vhost_msg_v2_t message;
    int status;

    if (!buffer || length != sizeof(message)) return -EDGE_LINUX_EINVAL;
    __builtin_memcpy(&message, buffer, sizeof(message));
    vhost_lock();
    status = device_resolve(handle, &device);
    if (status < 0) goto out;
    if (device->kind != KERNEL_EDGE_VHOST_DEVICE_VDPA || !g_vdpa) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    if (!device->owner) {
        status = -EDGE_LINUX_EPERM;
        goto out;
    }
    if (message.type != EDGE_VHOST_IOTLB_MSG_V2) {
        status = -EDGE_LINUX_EINVAL;
        goto out;
    }
    status = iotlb_message_validate(device, message.asid,
                                    &message.payload.iotlb);
    if (status < 0) goto out;
    if (message.payload.iotlb.type == EDGE_VHOST_IOTLB_UPDATE)
        status = g_vdpa->iotlb_update(g_vdpa_context, device->device_id,
                                      message.asid,
                                      &message.payload.iotlb);
    else if (message.payload.iotlb.type == EDGE_VHOST_IOTLB_INVALIDATE)
        status = g_vdpa->iotlb_invalidate(g_vdpa_context,
                                          device->device_id, message.asid,
                                          &message.payload.iotlb);
    else
        status = g_vdpa->iotlb_batch(
            g_vdpa_context, device->device_id, message.asid,
            message.payload.iotlb.type == EDGE_VHOST_IOTLB_BATCH_BEGIN);
    if (status == 0) status = (int)sizeof(message);
out:
    vhost_unlock();
    return status;
}

int64_t kernel_edge_vhost_read(edge_vhost_handle_t handle, void *buffer,
                               uint32_t length) {
    edge_vhost_device_runtime_t *device;
    edge_vhost_msg_v2_t message = {0};
    int status;

    if (!buffer || length < sizeof(message)) return -EDGE_LINUX_EINVAL;
    vhost_lock();
    status = device_resolve(handle, &device);
    if (status < 0) goto out;
    if (device->kind != KERNEL_EDGE_VHOST_DEVICE_VDPA || !g_vdpa) {
        status = -EDGE_LINUX_EOPNOTSUPP;
        goto out;
    }
    status = g_vdpa->iotlb_read(g_vdpa_context, device->device_id,
                                &message);
    if (status < 0) goto out;
    if (message.type != EDGE_VHOST_IOTLB_MSG_V2 ||
        (message.payload.iotlb.type != EDGE_VHOST_IOTLB_MISS &&
         message.payload.iotlb.type != EDGE_VHOST_IOTLB_ACCESS_FAIL)) {
        status = -EDGE_LINUX_EIO;
        goto out;
    }
    __builtin_memcpy(buffer, &message, sizeof(message));
    status = (int)sizeof(message);
out:
    vhost_unlock();
    return status;
}

static int copy_from(const kernel_ioctl_request_t *request, void *destination,
                     uint64_t source, uint64_t size) {
    if (!source || !request->copy_from_user ||
        request->copy_from_user(request->copy_context, destination,
                                source, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int copy_to(const kernel_ioctl_request_t *request, uint64_t destination,
                   const void *source, uint64_t size) {
    if (!destination || !request->copy_to_user ||
        request->copy_to_user(request->copy_context, destination,
                              source, size) < 0)
        return -EDGE_LINUX_EFAULT;
    return 0;
}

static int range_valid(uint64_t address, uint64_t size) {
    return size != 0 && address <= UINT64_MAX - size;
}

static int ranges_overlap(uint64_t left, uint64_t left_size,
                          uint64_t right, uint64_t right_size) {
    return left < right + right_size && right < left + left_size;
}

static int set_memory(const kernel_ioctl_request_t *request,
                      edge_vhost_device_runtime_t *device) {
    edge_vhost_memory_t header;
    uint64_t source;
    int status = copy_from(request, &header, request->argument,
                           sizeof(header));
    if (status < 0) return status;
    if (header.nregions > EDGE_VHOST_MAX_MEMORY_REGIONS || header.padding != 0)
        return -EDGE_LINUX_EINVAL;
    source = request->argument + sizeof(header);
    if (source < request->argument) return -EDGE_LINUX_EFAULT;
    for (uint32_t index = 0; index < header.nregions; ++index) {
        status = copy_from(request, &g_memory_scratch[index],
                           source + index * sizeof(g_memory_scratch[index]),
                           sizeof(g_memory_scratch[index]));
        if (status < 0) return status;
        if (g_memory_scratch[index].flags_padding != 0 ||
            !range_valid(g_memory_scratch[index].guest_phys_addr,
                         g_memory_scratch[index].memory_size) ||
            !range_valid(g_memory_scratch[index].userspace_addr,
                         g_memory_scratch[index].memory_size))
            return -EDGE_LINUX_EINVAL;
        for (uint32_t prior = 0; prior < index; ++prior) {
            if (ranges_overlap(g_memory_scratch[index].guest_phys_addr,
                               g_memory_scratch[index].memory_size,
                               g_memory_scratch[prior].guest_phys_addr,
                               g_memory_scratch[prior].memory_size) ||
                ranges_overlap(g_memory_scratch[index].userspace_addr,
                               g_memory_scratch[index].memory_size,
                               g_memory_scratch[prior].userspace_addr,
                               g_memory_scratch[prior].memory_size))
                return -EDGE_LINUX_EINVAL;
        }
    }
    for (uint32_t index = 0; index < header.nregions; ++index)
        device->memory[index] = g_memory_scratch[index];
    device->memory_count = header.nregions;
    return 0;
}

static int set_vring_state(const kernel_ioctl_request_t *request,
                           edge_vhost_device_runtime_t *device,
                           int base) {
    edge_vhost_vring_state_t state;
    int status = copy_from(request, &state, request->argument, sizeof(state));
    if (status < 0) return status;
    if (state.index >= device->vring_count)
        return -EDGE_LINUX_EINVAL;
    if (!base && (state.num == 0 || state.num > EDGE_VHOST_MAX_RING_SIZE ||
                  (state.num & (state.num - 1u)) != 0))
        return -EDGE_LINUX_EINVAL;
    if (base && device->vrings[state.index].num != 0 &&
        state.num > device->vrings[state.index].num)
        return -EDGE_LINUX_EINVAL;
    if (base)
        device->vrings[state.index].base = state.num;
    else
        device->vrings[state.index].num = state.num;
    return 0;
}

static int get_vring_base(const kernel_ioctl_request_t *request,
                          edge_vhost_device_runtime_t *device) {
    edge_vhost_vring_state_t state;
    int status = copy_from(request, &state, request->argument, sizeof(state));
    if (status < 0) return status;
    if (state.index >= device->vring_count)
        return -EDGE_LINUX_EINVAL;
    state.num = device->vrings[state.index].base;
    if (device->vrings[state.index].backend_id != EDGE_VHOST_INVALID_ID)
        g_descriptors->release_backend(
            g_descriptor_context, device->vrings[state.index].backend_id);
    device->vrings[state.index].backend_id = EDGE_VHOST_INVALID_ID;
    return copy_to(request, request->argument, &state, sizeof(state));
}

static int vring_parameter(const kernel_ioctl_request_t *request,
                           edge_vhost_device_runtime_t *device) {
    edge_vhost_vring_state_t state;
    edge_vhost_vring_runtime_t *vring;
    int status = copy_from(request, &state, request->argument, sizeof(state));
    if (status < 0) return status;
    if (state.index >= device->vring_count)
        return -EDGE_LINUX_EINVAL;
    vring = &device->vrings[state.index];
    if (request->command == EDGE_VHOST_SET_VRING_ENDIAN) {
        if (state.num != EDGE_VHOST_VRING_LITTLE_ENDIAN &&
            state.num != EDGE_VHOST_VRING_BIG_ENDIAN)
            return -EDGE_LINUX_EINVAL;
        if (vring->backend_id != EDGE_VHOST_INVALID_ID)
            return -EDGE_LINUX_EBUSY;
        if ((device->features &
             (UINT64_C(1) << EDGE_VIRTIO_F_VERSION_1)) == 0)
            vring->endian = state.num;
        return 0;
    }
    if (request->command == EDGE_VHOST_SET_VRING_BUSYLOOP_TIMEOUT) {
        vring->busyloop_timeout = state.num;
        return 0;
    }
    state.num = request->command == EDGE_VHOST_GET_VRING_ENDIAN ?
        vring->endian : vring->busyloop_timeout;
    return copy_to(request, request->argument, &state, sizeof(state));
}

static int set_vring_address(const kernel_ioctl_request_t *request,
                             edge_vhost_device_runtime_t *device) {
    edge_vhost_vring_addr_t address;
    int status = copy_from(request, &address, request->argument,
                           sizeof(address));
    if (status < 0) return status;
    if (address.index >= device->vring_count ||
        (address.flags & ~(UINT32_C(1) << EDGE_VHOST_VRING_F_LOG)) != 0 ||
        (address.desc_user_addr & 15u) != 0 ||
        (address.used_user_addr & 3u) != 0 ||
        (address.avail_user_addr & 1u) != 0)
        return -EDGE_LINUX_EINVAL;
    device->vrings[address.index].flags = address.flags;
    device->vrings[address.index].desc = address.desc_user_addr;
    device->vrings[address.index].used = address.used_user_addr;
    device->vrings[address.index].avail = address.avail_user_addr;
    device->vrings[address.index].log = address.log_guest_addr;
    return 0;
}

static int set_vring_file(const kernel_ioctl_request_t *request,
                          edge_vhost_device_runtime_t *device,
                          uint32_t command) {
    edge_vhost_vring_file_t file;
    int32_t event_id = -1;
    int status = copy_from(request, &file, request->argument, sizeof(file));
    if (status < 0) return status;
    if (file.index >= device->vring_count)
        return -EDGE_LINUX_EINVAL;
    if (file.fd >= 0) {
        status = g_descriptors->resolve_eventfd(
            g_descriptor_context, file.fd, &event_id);
        if (status < 0) return status;
    }
    if (command == EDGE_VHOST_SET_VRING_KICK) {
        if (device->vrings[file.index].kick_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, device->vrings[file.index].kick_event);
        device->vrings[file.index].kick_event = event_id;
    } else if (command == EDGE_VHOST_SET_VRING_CALL) {
        if (device->vrings[file.index].call_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, device->vrings[file.index].call_event);
        device->vrings[file.index].call_event = event_id;
    } else {
        if (device->vrings[file.index].err_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, device->vrings[file.index].err_event);
        device->vrings[file.index].err_event = event_id;
    }
    return 0;
}

static int set_backend(const kernel_ioctl_request_t *request,
                       edge_vhost_device_runtime_t *device) {
    edge_vhost_vring_file_t file;
    uint64_t backend = EDGE_VHOST_INVALID_ID;
    int status = copy_from(request, &file, request->argument, sizeof(file));
    if (status < 0) return status;
    if (file.index >= device->vring_count)
        return -EDGE_LINUX_EINVAL;
    if (file.fd >= 0) {
        status = g_descriptors->resolve_backend(
            g_descriptor_context, file.fd, &backend);
        if (status < 0) return status;
        if (device->memory_count == 0 || device->vrings[file.index].num == 0 ||
            device->vrings[file.index].desc == 0 ||
            device->vrings[file.index].used == 0 ||
            device->vrings[file.index].avail == 0)
            return -EDGE_LINUX_EINVAL;
    }
    if (device->vrings[file.index].backend_id != EDGE_VHOST_INVALID_ID)
        g_descriptors->release_backend(
            g_descriptor_context, device->vrings[file.index].backend_id);
    device->vrings[file.index].backend_id = backend;
    return 0;
}

static int vdpa_config_ioctl(const kernel_ioctl_request_t *request,
                             edge_vhost_device_runtime_t *device) {
    edge_vhost_vdpa_config_t config;
    uint64_t buffer_address;
    int status = copy_from(request, &config, request->argument,
                           sizeof(config));
    if (status < 0) return status;
    if (config.len > EDGE_VHOST_MAX_VDPA_CONFIG ||
        config.off > device->vdpa_info.config_size ||
        config.len > device->vdpa_info.config_size - config.off)
        return -EDGE_LINUX_EINVAL;
    buffer_address = request->argument + sizeof(config);
    if (buffer_address < request->argument) return -EDGE_LINUX_EFAULT;
    if (request->command == EDGE_VHOST_VDPA_SET_CONFIG) {
        status = copy_from(request, g_vdpa_config_scratch, buffer_address,
                           config.len);
        if (status < 0) return status;
        return g_vdpa->set_config(g_vdpa_context, device->device_id,
                                  config.off, g_vdpa_config_scratch,
                                  config.len);
    }
    status = g_vdpa->get_config(g_vdpa_context, device->device_id,
                                config.off, g_vdpa_config_scratch,
                                config.len);
    if (status < 0) return status;
    return copy_to(request, buffer_address, g_vdpa_config_scratch,
                   config.len);
}

static int vdpa_ioctl(const kernel_ioctl_request_t *request,
                      edge_vhost_device_runtime_t *device) {
    edge_vhost_vring_state_t state;
    edge_vhost_vdpa_iova_range_t iova_range;
    uint32_t value32;
    uint16_t value16;
    uint8_t status8;
    int32_t descriptor;
    int32_t event_id = -1;
    int status;

    if (device->kind != KERNEL_EDGE_VHOST_DEVICE_VDPA)
        return -EDGE_LINUX_ENOTTY;
    switch (request->command) {
    case EDGE_VHOST_VDPA_GET_DEVICE_ID:
        value32 = device->vdpa_info.virtio_device_id;
        return copy_to(request, request->argument, &value32, sizeof(value32));
    case EDGE_VHOST_VDPA_GET_STATUS:
        status = g_vdpa->get_status(g_vdpa_context, device->device_id,
                                    &status8);
        return status < 0 ? status : copy_to(request, request->argument,
                                             &status8, sizeof(status8));
    case EDGE_VHOST_VDPA_SET_STATUS:
        status = copy_from(request, &status8, request->argument,
                           sizeof(status8));
        return status < 0 ? status : g_vdpa->set_status(
            g_vdpa_context, device->device_id, status8);
    case EDGE_VHOST_VDPA_GET_CONFIG:
    case EDGE_VHOST_VDPA_SET_CONFIG:
        return vdpa_config_ioctl(request, device);
    case EDGE_VHOST_VDPA_SET_VRING_ENABLE:
        status = copy_from(request, &state, request->argument, sizeof(state));
        if (status < 0) return status;
        if (state.index >= device->vring_count || state.num > 1)
            return -EDGE_LINUX_EINVAL;
        return g_vdpa->set_vring_enable(g_vdpa_context, device->device_id,
                                        state.index, state.num != 0);
    case EDGE_VHOST_VDPA_GET_VRING_NUM:
        value16 = device->vdpa_info.max_queue_size;
        return copy_to(request, request->argument, &value16, sizeof(value16));
    case EDGE_VHOST_VDPA_SET_CONFIG_CALL:
        status = copy_from(request, &descriptor, request->argument,
                           sizeof(descriptor));
        if (status < 0) return status;
        if (descriptor >= 0) {
            status = g_descriptors->resolve_eventfd(
                g_descriptor_context, descriptor, &event_id);
            if (status < 0) return status;
        }
        status = g_vdpa->set_config_event(g_vdpa_context,
                                          device->device_id, event_id);
        if (status < 0) {
            if (event_id >= 0)
                g_descriptors->release_eventfd(g_descriptor_context,
                                               event_id);
            return status;
        }
        if (device->vdpa_config_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, device->vdpa_config_event);
        device->vdpa_config_event = event_id;
        return 0;
    case EDGE_VHOST_VDPA_GET_IOVA_RANGE:
        iova_range.first = device->vdpa_info.first_iova;
        iova_range.last = device->vdpa_info.last_iova;
        return copy_to(request, request->argument, &iova_range,
                       sizeof(iova_range));
    case EDGE_VHOST_VDPA_GET_CONFIG_SIZE:
        value32 = device->vdpa_info.config_size;
        return copy_to(request, request->argument, &value32, sizeof(value32));
    case EDGE_VHOST_VDPA_GET_AS_NUM:
        value32 = device->vdpa_info.address_space_count;
        return copy_to(request, request->argument, &value32, sizeof(value32));
    case EDGE_VHOST_VDPA_GET_VRING_GROUP:
    case EDGE_VHOST_VDPA_GET_VRING_DESC_GROUP:
        status = copy_from(request, &state, request->argument, sizeof(state));
        if (status < 0) return status;
        if (state.index >= device->vring_count)
            return -EDGE_LINUX_EINVAL;
        state.num = state.index % device->vdpa_info.group_count;
        return copy_to(request, request->argument, &state, sizeof(state));
    case EDGE_VHOST_VDPA_SET_GROUP_ASID:
        status = copy_from(request, &state, request->argument, sizeof(state));
        if (status < 0) return status;
        if (state.index >= device->vdpa_info.group_count ||
            state.num >= device->vdpa_info.address_space_count)
            return -EDGE_LINUX_EINVAL;
        return g_vdpa->set_group_asid(g_vdpa_context, device->device_id,
                                      state.index, state.num);
    case EDGE_VHOST_VDPA_SUSPEND:
        if (device->vdpa_suspended) return -EDGE_LINUX_EBUSY;
        status = g_vdpa->suspend(g_vdpa_context, device->device_id);
        if (status == 0) device->vdpa_suspended = 1;
        return status;
    case EDGE_VHOST_VDPA_RESUME:
        if (!device->vdpa_suspended) return -EDGE_LINUX_EINVAL;
        status = g_vdpa->resume(g_vdpa_context, device->device_id);
        if (status == 0) device->vdpa_suspended = 0;
        return status;
    case EDGE_VHOST_VDPA_GET_VQS_COUNT:
        value32 = device->vdpa_info.queue_count;
        return copy_to(request, request->argument, &value32, sizeof(value32));
    case EDGE_VHOST_VDPA_GET_GROUP_NUM:
        value32 = device->vdpa_info.group_count;
        return copy_to(request, request->argument, &value32, sizeof(value32));
    case EDGE_VHOST_VDPA_GET_VRING_SIZE:
        status = copy_from(request, &state, request->argument, sizeof(state));
        if (status < 0) return status;
        if (state.index >= device->vring_count)
            return -EDGE_LINUX_EINVAL;
        state.num = device->vdpa_info.max_queue_size;
        return copy_to(request, request->argument, &state, sizeof(state));
    default:
        return -EDGE_LINUX_ENOTTY;
    }
}

static uint64_t device_supported_features(
        const edge_vhost_device_runtime_t *device) {
    return device->kind == KERNEL_EDGE_VHOST_DEVICE_VDPA ?
        device->vdpa_info.features : EDGE_VHOST_FEATURES;
}

static int feature_array_ioctl(const kernel_ioctl_request_t *request,
                               edge_vhost_device_runtime_t *device) {
    edge_vhost_features_array_t header;
    uint64_t address;
    int status = copy_from(request, &header, request->argument,
                           sizeof(header));
    if (status < 0) return status;
    if (header.count > 4) return -EDGE_LINUX_E2BIG;
    address = request->argument + sizeof(header);
    if (address < request->argument) return -EDGE_LINUX_EFAULT;
    if (request->command == EDGE_VHOST_GET_FEATURES_ARRAY) {
        uint64_t capacity = header.count;
        header.count = 1;
        status = copy_to(request, request->argument, &header,
                         sizeof(header));
        if (status < 0) return status;
        if (capacity == 0) return -EDGE_LINUX_EMSGSIZE;
        g_feature_scratch[0] = device_supported_features(device);
        return copy_to(request, address, g_feature_scratch,
                       sizeof(g_feature_scratch[0]));
    }
    if (header.count == 0) return -EDGE_LINUX_EINVAL;
    for (uint64_t index = 0; index < header.count; ++index) {
        status = copy_from(request, &g_feature_scratch[index],
                           address + index * sizeof(uint64_t),
                           sizeof(uint64_t));
        if (status < 0) return status;
        if (index != 0 && g_feature_scratch[index] != 0)
            return -EDGE_LINUX_EOPNOTSUPP;
    }
    if ((g_feature_scratch[0] & ~device_supported_features(device)) != 0)
        return -EDGE_LINUX_EOPNOTSUPP;
    device->features = g_feature_scratch[0];
    if (device->kind == KERNEL_EDGE_VHOST_DEVICE_VDPA)
        return g_vdpa->set_features(g_vdpa_context, device->device_id,
                                    device->features,
                                    device->backend_features);
    return 0;
}

static int owned_ioctl(const kernel_ioctl_request_t *request,
                       edge_vhost_device_runtime_t *device) {
    uint64_t value;
    int32_t descriptor;
    int32_t event_id = -1;
    int status;
    switch (request->command) {
    case EDGE_VHOST_SET_FEATURES:
    case EDGE_VHOST_SET_BACKEND_FEATURES:
        status = copy_from(request, &value, request->argument, sizeof(value));
        if (status < 0) return status;
        if (request->command == EDGE_VHOST_SET_FEATURES) {
            uint64_t supported = device->kind ==
                KERNEL_EDGE_VHOST_DEVICE_VDPA ?
                device->vdpa_info.features : EDGE_VHOST_FEATURES;
            if ((value & ~supported) != 0)
                return -EDGE_LINUX_EOPNOTSUPP;
            device->features = value;
        } else {
            uint64_t supported = device->kind ==
                KERNEL_EDGE_VHOST_DEVICE_VDPA ?
                device->vdpa_info.backend_features :
                EDGE_VHOST_BACKEND_FEATURES;
            if ((value & ~supported) != 0)
                return -EDGE_LINUX_EOPNOTSUPP;
            device->backend_features = value;
        }
        if (device->kind == KERNEL_EDGE_VHOST_DEVICE_VDPA)
            return g_vdpa->set_features(g_vdpa_context, device->device_id,
                                        device->features,
                                        device->backend_features);
        return 0;
    case EDGE_VHOST_SET_MEM_TABLE:
        return set_memory(request, device);
    case EDGE_VHOST_SET_LOG_BASE:
        status = copy_from(request, &value, request->argument, sizeof(value));
        if (status == 0) device->log_base = value;
        return status;
    case EDGE_VHOST_SET_LOG_FD:
        status = copy_from(request, &descriptor, request->argument,
                           sizeof(descriptor));
        if (status < 0) return status;
        if (descriptor >= 0) {
            status = g_descriptors->resolve_eventfd(
                g_descriptor_context, descriptor, &event_id);
            if (status < 0) return status;
        }
        if (device->log_event >= 0)
            g_descriptors->release_eventfd(
                g_descriptor_context, device->log_event);
        device->log_event = event_id;
        return 0;
    case EDGE_VHOST_SET_VRING_NUM:
        return set_vring_state(request, device, 0);
    case EDGE_VHOST_SET_VRING_BASE:
        return set_vring_state(request, device, 1);
    case EDGE_VHOST_GET_VRING_BASE:
        return get_vring_base(request, device);
    case EDGE_VHOST_SET_VRING_ENDIAN:
    case EDGE_VHOST_GET_VRING_ENDIAN:
    case EDGE_VHOST_SET_VRING_BUSYLOOP_TIMEOUT:
    case EDGE_VHOST_GET_VRING_BUSYLOOP_TIMEOUT:
        return vring_parameter(request, device);
    case EDGE_VHOST_SET_VRING_ADDR:
        return set_vring_address(request, device);
    case EDGE_VHOST_SET_VRING_KICK:
    case EDGE_VHOST_SET_VRING_CALL:
    case EDGE_VHOST_SET_VRING_ERR:
        return set_vring_file(request, device, request->command);
    case EDGE_VHOST_NET_SET_BACKEND:
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_NET)
            return -EDGE_LINUX_ENOTTY;
        return set_backend(request, device);
    case EDGE_VHOST_SCSI_SET_ENDPOINT: {
        edge_vhost_scsi_target_t target;
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_SCSI)
            return -EDGE_LINUX_ENOTTY;
        status = copy_from(request, &target, request->argument,
                           sizeof(target));
        if (status < 0) return status;
        if (target.abi_version < 0 ||
            (uint32_t)target.abi_version > EDGE_VHOST_SCSI_ABI_VERSION ||
            target.reserved != 0 || target.vhost_wwpn[0] == '\0')
            return -EDGE_LINUX_EINVAL;
        device->scsi_target = target;
        device->scsi_endpoint_set = 1;
        return 0;
    }
    case EDGE_VHOST_SCSI_CLEAR_ENDPOINT:
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_SCSI)
            return -EDGE_LINUX_ENOTTY;
        if (!device->scsi_endpoint_set) return -EDGE_LINUX_ENOENT;
        device->scsi_endpoint_set = 0;
        return 0;
    case EDGE_VHOST_SCSI_SET_EVENTS_MISSED:
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_SCSI)
            return -EDGE_LINUX_ENOTTY;
        return copy_from(request, &device->scsi_events_missed,
                         request->argument,
                         sizeof(device->scsi_events_missed));
    case EDGE_VHOST_SCSI_GET_EVENTS_MISSED:
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_SCSI)
            return -EDGE_LINUX_ENOTTY;
        return copy_to(request, request->argument,
                       &device->scsi_events_missed,
                       sizeof(device->scsi_events_missed));
    case EDGE_VHOST_VSOCK_SET_GUEST_CID: {
        uint64_t guest_cid;
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_VSOCK)
            return -EDGE_LINUX_ENOTTY;
        status = copy_from(request, &guest_cid, request->argument,
                           sizeof(guest_cid));
        if (status < 0) return status;
        if (device->vsock_running || guest_cid < 3 ||
            guest_cid == UINT64_MAX)
            return -EDGE_LINUX_EINVAL;
        for (uint32_t index = 0; index < EDGE_VHOST_MAX_DEVICES; ++index) {
            if (&g_devices[index] != device && g_devices[index].live &&
                g_devices[index].kind == KERNEL_EDGE_VHOST_DEVICE_VSOCK &&
                g_devices[index].vsock_guest_cid == guest_cid)
                return -EDGE_LINUX_EADDRINUSE;
        }
        device->vsock_guest_cid = guest_cid;
        return 0;
    }
    case EDGE_VHOST_VSOCK_SET_RUNNING: {
        int32_t running;
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_VSOCK)
            return -EDGE_LINUX_ENOTTY;
        status = copy_from(request, &running, request->argument,
                           sizeof(running));
        if (status < 0) return status;
        if ((running != 0 && running != 1) ||
            (running != 0 && device->vsock_guest_cid == 0))
            return -EDGE_LINUX_EINVAL;
        device->vsock_running = (uint8_t)running;
        return 0;
    }
    case EDGE_VHOST_NEW_WORKER:
    case EDGE_VHOST_FREE_WORKER:
    case EDGE_VHOST_ATTACH_VRING_WORKER:
    case EDGE_VHOST_GET_VRING_WORKER:
        return worker_ioctl(request, device);
    default:
        return vdpa_ioctl(request, device);
    }
}

int64_t kernel_edge_vhost_ioctl(const kernel_ioctl_request_t *request) {
    edge_vhost_device_runtime_t *device;
    edge_vhost_handle_t handle;
    kernel_edge_vhost_device_kind_t resolved_kind =
        KERNEL_EDGE_VHOST_DEVICE_NET;
    uint32_t resolved_device_id = 0;
    uint64_t features;
    int64_t status;
    if (!request || !g_descriptors) return -EDGE_LINUX_ENOTTY;
    status = g_descriptors->resolve_net(
        g_descriptor_context, request->descriptor, &handle);
    if (status < 0) {
        status = g_descriptors->resolve_device(
            g_descriptor_context, request->descriptor, &resolved_kind,
            &resolved_device_id, &handle);
        if (status < 0) return -EDGE_LINUX_ENOTTY;
    }
    vhost_lock();
    status = device_resolve(handle, &device);
    if (status < 0) goto out;
    if (device->kind != resolved_kind ||
        device->device_id != resolved_device_id) {
        status = -EDGE_LINUX_EBADF;
        goto out;
    }
    if (request->command == EDGE_VHOST_SCSI_GET_ABI_VERSION) {
        uint32_t abi_version = EDGE_VHOST_SCSI_ABI_VERSION;
        status = device->kind == KERNEL_EDGE_VHOST_DEVICE_SCSI ?
            copy_to(request, request->argument, &abi_version,
                    sizeof(abi_version)) : -EDGE_LINUX_ENOTTY;
        goto out;
    }
    if (request->command == EDGE_VHOST_GET_FORK_FROM_OWNER) {
        status = copy_to(request, request->argument, &device->fork_owner,
                         sizeof(device->fork_owner));
        goto out;
    }
    if (request->command == EDGE_VHOST_SET_FORK_FROM_OWNER) {
        uint8_t fork_owner;
        if (device->owner) {
            status = -EDGE_LINUX_EBUSY;
            goto out;
        }
        status = copy_from(request, &fork_owner, request->argument,
                           sizeof(fork_owner));
        if (status < 0) goto out;
        if (fork_owner > EDGE_VHOST_FORK_OWNER_TASK) {
            status = -EDGE_LINUX_EINVAL;
            goto out;
        }
        device->fork_owner = fork_owner;
        status = 0;
        goto out;
    }
    if (request->command == EDGE_VHOST_GET_FEATURES_ARRAY) {
        status = feature_array_ioctl(request, device);
        goto out;
    }
    if (device->kind == KERNEL_EDGE_VHOST_DEVICE_VDPA &&
        (request->command & 0xffu) >= 0x70u &&
        (request->command & 0xffu) <= 0x82u) {
        status = vdpa_ioctl(request, device);
        goto out;
    }
    if (request->command == EDGE_VHOST_GET_FEATURES ||
        request->command == EDGE_VHOST_GET_BACKEND_FEATURES) {
        features = request->command == EDGE_VHOST_GET_FEATURES ?
            (device->kind == KERNEL_EDGE_VHOST_DEVICE_VDPA ?
                device->vdpa_info.features : EDGE_VHOST_FEATURES) :
            (device->kind == KERNEL_EDGE_VHOST_DEVICE_VDPA ?
                device->vdpa_info.backend_features :
                EDGE_VHOST_BACKEND_FEATURES);
        if (device->kind != KERNEL_EDGE_VHOST_DEVICE_NET)
            features &= ~(UINT64_C(1) << EDGE_VHOST_NET_F_VIRTIO_NET_HDR);
        status = copy_to(request, request->argument, &features,
                         sizeof(features));
    } else if (request->command == EDGE_VHOST_SET_OWNER) {
        if (device->owner)
            status = -EDGE_LINUX_EBUSY;
        else {
            device->owner = 1;
            status = 0;
        }
    } else if (request->command == EDGE_VHOST_RESET_OWNER) {
        if (!device->owner)
            status = -EDGE_LINUX_EINVAL;
        else {
            device_reset(device);
            status = 0;
        }
    } else if (!device->owner) {
        status = -EDGE_LINUX_EPERM;
    } else if (request->command == EDGE_VHOST_SET_FEATURES_ARRAY) {
        status = feature_array_ioctl(request, device);
    } else {
        status = owned_ioctl(request, device);
    }
out:
    vhost_unlock();
    return status;
}
