/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_VFIO_RUNTIME_H
#define EDGEOS_KERNEL_EDGE_VFIO_RUNTIME_H

#include <stdint.h>

#include "kernel/edge_vfio_object.h"
#include "kernel/ioctl_runtime.h"

#define EDGE_VFIO_CONTAINER_PATH "/dev/vfio/vfio"
#define EDGE_VFIO_GROUP_PATH_PREFIX "/dev/vfio/"
#define EDGE_VFIO_CDEV_PATH_PREFIX "/dev/vfio/devices/vfio"

typedef enum kernel_edge_vfio_file_kind {
    KERNEL_EDGE_VFIO_FILE_CONTAINER = 1,
    KERNEL_EDGE_VFIO_FILE_GROUP,
    KERNEL_EDGE_VFIO_FILE_DEVICE,
} kernel_edge_vfio_file_kind_t;

typedef struct kernel_edge_vfio_file {
    kernel_edge_vfio_file_kind_t kind;
    edge_vfio_handle_t handle;
} kernel_edge_vfio_file_t;

typedef struct kernel_edge_vfio_descriptor_backend_ops {
    int (*install)(void *context, kernel_edge_vfio_file_kind_t kind,
                   edge_vfio_handle_t handle);
    int (*resolve)(void *context, int32_t descriptor,
                   kernel_edge_vfio_file_t *file);
    int (*resolve_eventfd)(void *context, int32_t descriptor,
                           int32_t *event_id);
    int (*close)(void *context, int32_t descriptor);
} kernel_edge_vfio_descriptor_backend_ops_t;

int kernel_edge_vfio_descriptor_backend_register(
    const kernel_edge_vfio_descriptor_backend_ops_t *ops, void *context);
int kernel_edge_vfio_backend_register(const edge_vfio_backend_ops_t *backend);
int kernel_edge_vfio_open_container(void);
int kernel_edge_vfio_open_group(uint32_t group_id);
int kernel_edge_vfio_open_cdev(uint32_t device_id);
int kernel_edge_vfio_group_path_parse(const char *path, uint32_t *group_id);
int kernel_edge_vfio_cdev_path_parse(const char *path, uint32_t *device_id);
int64_t kernel_edge_vfio_ioctl(const kernel_ioctl_request_t *request);
int kernel_edge_vfio_descriptor_retain(kernel_edge_vfio_file_kind_t kind,
                                       edge_vfio_handle_t handle);
int kernel_edge_vfio_descriptor_release(kernel_edge_vfio_file_kind_t kind,
                                        edge_vfio_handle_t handle);
int kernel_edge_vfio_group_bind_descriptor(int32_t descriptor,
                                           uint64_t vm_cookie);
int kernel_edge_vfio_group_unbind_descriptor(int32_t descriptor,
                                             uint64_t vm_cookie);
int kernel_edge_vfio_bind_descriptor(int32_t descriptor,
                                     uint64_t vm_cookie);
int kernel_edge_vfio_unbind_descriptor(int32_t descriptor,
                                       uint64_t vm_cookie);
int64_t kernel_edge_vfio_device_read(int32_t descriptor, uint64_t offset,
                                     void *buffer, uint32_t size);
int64_t kernel_edge_vfio_device_write(int32_t descriptor, uint64_t offset,
                                      const void *buffer, uint32_t size);
int kernel_edge_vfio_device_mmap(int32_t descriptor, uint64_t offset,
                                 uint64_t size, uint32_t protection,
                                 uint64_t *physical_address);
int64_t kernel_edge_vfio_device_read_handle(edge_vfio_handle_t handle,
                                            uint64_t offset, void *buffer,
                                            uint32_t size);
int64_t kernel_edge_vfio_device_write_handle(edge_vfio_handle_t handle,
                                             uint64_t offset,
                                             const void *buffer,
                                             uint32_t size);
int kernel_edge_vfio_device_mmap_handle(edge_vfio_handle_t handle,
                                        uint64_t offset, uint64_t size,
                                        uint32_t protection,
                                        uint64_t *physical_address);

#endif
