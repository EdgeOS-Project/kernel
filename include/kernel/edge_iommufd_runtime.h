/* SPDX-License-Identifier: MPL-2.0 */
#ifndef EDGEOS_KERNEL_EDGE_IOMMUFD_RUNTIME_H
#define EDGEOS_KERNEL_EDGE_IOMMUFD_RUNTIME_H

#include <stdint.h>

#include "kernel/edge_iommufd_abi.h"
#include "kernel/ioctl_runtime.h"

#define EDGE_IOMMUFD_PATH "/dev/iommu"

typedef struct edge_iommufd_handle {
    uint32_t slot;
    uint32_t generation;
} edge_iommufd_handle_t;

typedef struct kernel_edge_iommufd_descriptor_backend_ops {
    int (*install)(void *context, edge_iommufd_handle_t handle);
    int (*resolve)(void *context, int32_t descriptor,
                   edge_iommufd_handle_t *handle);
} kernel_edge_iommufd_descriptor_backend_ops_t;

typedef struct kernel_edge_iommufd_ioas_ops {
    int (*map)(void *context, uint64_t iova, uint64_t user_va,
               uint64_t length, uint32_t flags);
    int (*unmap)(void *context, uint64_t iova, uint64_t length);
} kernel_edge_iommufd_ioas_ops_t;

typedef struct kernel_edge_iommufd_file_backend_ops {
    int (*acquire)(void *context, int32_t descriptor, uint64_t offset,
                   uint64_t length, uint64_t *user_va, uint64_t *cookie);
    int (*retain)(void *context, uint64_t cookie);
    void (*release)(void *context, uint64_t cookie);
    int (*change_process)(void *context, const uint64_t *cookies,
                          uint32_t cookie_count);
} kernel_edge_iommufd_file_backend_ops_t;

int kernel_edge_iommufd_descriptor_backend_register(
    const kernel_edge_iommufd_descriptor_backend_ops_t *ops, void *context);
int kernel_edge_iommufd_file_backend_register(
    const kernel_edge_iommufd_file_backend_ops_t *ops, void *context);
int kernel_edge_iommufd_open(void);
int64_t kernel_edge_iommufd_ioctl(const kernel_ioctl_request_t *request);
int kernel_edge_iommufd_descriptor_retain(edge_iommufd_handle_t handle);
int kernel_edge_iommufd_descriptor_release(edge_iommufd_handle_t handle);
int kernel_edge_iommufd_descriptor_acquire(int32_t descriptor,
                                           edge_iommufd_handle_t *handle);
int kernel_edge_iommufd_ioas_exists(edge_iommufd_handle_t handle,
                                    uint32_t ioas_id);
int kernel_edge_iommufd_device_register(edge_iommufd_handle_t handle,
                                        uint32_t dev_id);
int kernel_edge_iommufd_device_unregister(edge_iommufd_handle_t handle,
                                          uint32_t dev_id);
int kernel_edge_iommufd_pt_retain(edge_iommufd_handle_t handle,
                                  uint32_t pt_id, uint32_t *ioas_id);
int kernel_edge_iommufd_pt_release(edge_iommufd_handle_t handle,
                                   uint32_t pt_id);
int kernel_edge_iommufd_ioas_attach(
    edge_iommufd_handle_t handle, uint32_t ioas_id,
    const kernel_edge_iommufd_ioas_ops_t *ops, void *context,
    uint32_t *attachment_id);
int kernel_edge_iommufd_ioas_detach(edge_iommufd_handle_t handle,
                                    uint32_t attachment_id);

#endif
