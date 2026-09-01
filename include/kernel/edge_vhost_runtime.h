/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_VHOST_RUNTIME_H
#define EDGEOS_KERNEL_EDGE_VHOST_RUNTIME_H

#include <stdint.h>

#include "kernel/edge_vhost_abi.h"
#include "kernel/ioctl_runtime.h"

#define EDGE_VHOST_NET_PATH "/dev/vhost-net"
#define EDGE_VHOST_SCSI_PATH "/dev/vhost-scsi"
#define EDGE_VHOST_VSOCK_PATH "/dev/vhost-vsock"
#define EDGE_VHOST_VDPA_PATH_PREFIX "/dev/vhost-vdpa-"

typedef struct edge_vhost_handle {
    uint32_t slot;
    uint32_t generation;
} edge_vhost_handle_t;

typedef enum kernel_edge_vhost_device_kind {
    KERNEL_EDGE_VHOST_DEVICE_NET = 0,
    KERNEL_EDGE_VHOST_DEVICE_SCSI = 1,
    KERNEL_EDGE_VHOST_DEVICE_VSOCK = 2,
    KERNEL_EDGE_VHOST_DEVICE_VDPA = 3,
} kernel_edge_vhost_device_kind_t;

typedef struct kernel_edge_vhost_descriptor_backend_ops {
    int (*install_net)(void *context, edge_vhost_handle_t handle);
    int (*resolve_net)(void *context, int32_t descriptor,
                       edge_vhost_handle_t *handle);
    int (*install_device)(void *context,
                          kernel_edge_vhost_device_kind_t kind,
                          uint32_t device_id, edge_vhost_handle_t handle);
    int (*resolve_device)(void *context, int32_t descriptor,
                          kernel_edge_vhost_device_kind_t *kind,
                          uint32_t *device_id, edge_vhost_handle_t *handle);
    int (*resolve_eventfd)(void *context, int32_t descriptor,
                           int32_t *event_id);
    void (*release_eventfd)(void *context, int32_t event_id);
    int (*resolve_backend)(void *context, int32_t descriptor,
                           uint64_t *backend_id);
    void (*release_backend)(void *context, uint64_t backend_id);
} kernel_edge_vhost_descriptor_backend_ops_t;

typedef struct kernel_edge_vhost_vdpa_device_info {
    uint32_t virtio_device_id;
    uint32_t config_size;
    uint32_t queue_count;
    uint32_t group_count;
    uint32_t address_space_count;
    uint16_t max_queue_size;
    uint16_t reserved;
    uint64_t first_iova;
    uint64_t last_iova;
    uint64_t features;
    uint64_t backend_features;
} kernel_edge_vhost_vdpa_device_info_t;

typedef struct kernel_edge_vhost_vdpa_backend_ops {
    int (*probe)(void *context, uint32_t device_id,
                 kernel_edge_vhost_vdpa_device_info_t *info);
    int (*get_status)(void *context, uint32_t device_id, uint8_t *status);
    int (*set_status)(void *context, uint32_t device_id, uint8_t status);
    int (*set_features)(void *context, uint32_t device_id,
                        uint64_t features, uint64_t backend_features);
    int (*get_config)(void *context, uint32_t device_id, uint32_t offset,
                      void *buffer, uint32_t length);
    int (*set_config)(void *context, uint32_t device_id, uint32_t offset,
                      const void *buffer, uint32_t length);
    int (*set_vring_enable)(void *context, uint32_t device_id,
                            uint32_t vring, int enabled);
    int (*set_config_event)(void *context, uint32_t device_id,
                            int32_t event_id);
    int (*set_group_asid)(void *context, uint32_t device_id,
                          uint32_t group, uint32_t asid);
    int (*iotlb_update)(void *context, uint32_t device_id, uint32_t asid,
                        const edge_vhost_iotlb_msg_t *message);
    int (*iotlb_invalidate)(void *context, uint32_t device_id,
                            uint32_t asid,
                            const edge_vhost_iotlb_msg_t *message);
    int (*iotlb_batch)(void *context, uint32_t device_id, uint32_t asid,
                       int begin);
    int (*iotlb_read)(void *context, uint32_t device_id,
                      edge_vhost_msg_v2_t *message);
    int (*suspend)(void *context, uint32_t device_id);
    int (*resume)(void *context, uint32_t device_id);
} kernel_edge_vhost_vdpa_backend_ops_t;

int kernel_edge_vhost_descriptor_backend_register(
    const kernel_edge_vhost_descriptor_backend_ops_t *ops, void *context);
int kernel_edge_vhost_vdpa_backend_register(
    const kernel_edge_vhost_vdpa_backend_ops_t *ops, void *context);
int kernel_edge_vhost_open_net(void);
int kernel_edge_vhost_open_scsi(void);
int kernel_edge_vhost_open_vsock(void);
int kernel_edge_vhost_open_vdpa(uint32_t device_id);
int kernel_edge_vhost_vdpa_path_parse(const char *path, uint32_t *device_id);
int64_t kernel_edge_vhost_ioctl(const kernel_ioctl_request_t *request);
int64_t kernel_edge_vhost_read(edge_vhost_handle_t handle, void *buffer,
                               uint32_t length);
int64_t kernel_edge_vhost_write(edge_vhost_handle_t handle,
                                const void *buffer, uint32_t length);
int kernel_edge_vhost_descriptor_retain(edge_vhost_handle_t handle);
int kernel_edge_vhost_descriptor_release(edge_vhost_handle_t handle);

#endif
