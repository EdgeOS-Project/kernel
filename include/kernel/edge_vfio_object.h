/* SPDX-License-Identifier: MPL-2.0 */
/* Architecture-neutral VFIO container, group, device, and DMA policy. */

#ifndef EDGEOS_KERNEL_EDGE_VFIO_OBJECT_H
#define EDGEOS_KERNEL_EDGE_VFIO_OBJECT_H

#include <stdint.h>

#include "kernel/edge_vfio_abi.h"

#define EDGE_VFIO_MAX_CONTAINERS 16u
#define EDGE_VFIO_MAX_GROUPS 64u
#define EDGE_VFIO_MAX_DEVICES 64u
#define EDGE_VFIO_MAX_DMA_MAPS 256u
#define EDGE_VFIO_PAGE_SIZE 4096u

typedef struct edge_vfio_handle {
    uint32_t slot;
    uint32_t generation;
} edge_vfio_handle_t;

typedef struct edge_vfio_backend_ops {
    void *context;
    int (*container_set_iommu)(void *context, uint32_t iommu_type,
                               uint64_t *container_cookie);
    int (*container_clear_iommu)(void *context, uint64_t container_cookie);
    int (*group_open)(void *context, uint32_t group_id, int *viable,
                      uint64_t *group_cookie);
    void (*group_close)(void *context, uint64_t group_cookie);
    int (*group_attach)(void *context, uint64_t group_cookie,
                        uint64_t container_cookie);
    void (*group_detach)(void *context, uint64_t group_cookie,
                         uint64_t container_cookie);
    int (*group_bind_vm)(void *context, uint64_t group_cookie,
                         uint64_t vm_cookie);
    int (*group_unbind_vm)(void *context, uint64_t group_cookie,
                           uint64_t vm_cookie);
    int (*device_open)(void *context, uint64_t group_cookie,
                       uint64_t vm_cookie, const char *name,
                       uint64_t *device_cookie);
    void (*device_close)(void *context, uint64_t device_cookie);
    int (*device_get_info)(void *context, uint64_t device_cookie,
                           edge_vfio_device_info_t *info);
    int (*device_get_region_info)(void *context, uint64_t device_cookie,
                                  edge_vfio_region_info_t *info);
    int (*device_get_irq_info)(void *context, uint64_t device_cookie,
                               edge_vfio_irq_info_t *info);
    int (*device_set_irqs)(void *context, uint64_t device_cookie,
                           const edge_vfio_irq_set_t *set,
                           const void *data, uint32_t data_size);
    int (*device_reset)(void *context, uint64_t device_cookie);
    int64_t (*device_read)(void *context, uint64_t device_cookie,
                           uint64_t offset, void *buffer, uint32_t size);
    int64_t (*device_write)(void *context, uint64_t device_cookie,
                            uint64_t offset, const void *buffer,
                            uint32_t size);
    int (*device_mmap)(void *context, uint64_t device_cookie,
                       uint64_t offset, uint64_t size,
                       uint32_t protection, uint64_t *physical_address);
    int (*dma_map)(void *context, uint64_t container_cookie,
                   uint64_t vm_cookie,
                   uint64_t iova, uint64_t userspace_address,
                   uint64_t size, uint32_t flags);
    int (*dma_unmap)(void *context, uint64_t container_cookie,
                     uint64_t vm_cookie, uint64_t iova, uint64_t size);
} edge_vfio_backend_ops_t;

typedef struct edge_vfio_dma_map {
    uint8_t active;
    uint8_t reserved[3];
    uint32_t flags;
    uint64_t iova;
    uint64_t userspace_address;
    uint64_t size;
} edge_vfio_dma_map_t;

typedef struct edge_vfio_container_object {
    uint8_t active;
    uint8_t dirty_logging;
    uint8_t iommu_enabled;
    uint8_t reserved;
    uint32_t generation;
    uint32_t descriptor_references;
    uint32_t group_count;
    uint32_t iommu_type;
    uint32_t dma_map_count;
    uint64_t backend_cookie;
    uint64_t vm_cookie;
    uint32_t vm_group_count;
    uint32_t reserved2;
    edge_vfio_dma_map_t dma_maps[EDGE_VFIO_MAX_DMA_MAPS];
} edge_vfio_container_object_t;

typedef struct edge_vfio_group_object {
    uint8_t active;
    uint8_t viable;
    uint8_t attached;
    uint8_t backend_attached;
    uint32_t generation;
    uint32_t group_id;
    uint32_t descriptor_references;
    uint32_t device_count;
    edge_vfio_handle_t container;
    uint64_t backend_cookie;
    uint64_t vm_cookie;
} edge_vfio_group_object_t;

typedef struct edge_vfio_device_object {
    uint8_t active;
    uint8_t cdev;
    uint8_t reserved[2];
    uint32_t generation;
    uint32_t descriptor_references;
    edge_vfio_handle_t group;
    uint64_t backend_cookie;
} edge_vfio_device_object_t;

typedef struct edge_vfio_object_table {
    uint32_t next_generation;
    uint32_t active_container_count;
    uint32_t active_group_count;
    uint32_t active_device_count;
    edge_vfio_backend_ops_t backend;
    edge_vfio_container_object_t containers[EDGE_VFIO_MAX_CONTAINERS];
    edge_vfio_group_object_t groups[EDGE_VFIO_MAX_GROUPS];
    edge_vfio_device_object_t devices[EDGE_VFIO_MAX_DEVICES];
} edge_vfio_object_table_t;

int edge_vfio_object_table_init(edge_vfio_object_table_t *table,
                                const edge_vfio_backend_ops_t *backend);
void edge_vfio_object_table_reset(edge_vfio_object_table_t *table);
int edge_vfio_container_create(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t *handle);
int edge_vfio_container_retain(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle);
int edge_vfio_container_release(edge_vfio_object_table_t *table,
                                edge_vfio_handle_t handle);
int edge_vfio_container_set_iommu(edge_vfio_object_table_t *table,
                                  edge_vfio_handle_t handle,
                                  uint32_t iommu_type);
int edge_vfio_container_map_dma(edge_vfio_object_table_t *table,
                                edge_vfio_handle_t handle,
                                const edge_vfio_iommu_type1_dma_map_t *map);
int edge_vfio_container_unmap_dma(
    edge_vfio_object_table_t *table, edge_vfio_handle_t handle,
    edge_vfio_iommu_type1_dma_unmap_t *unmap);
int edge_vfio_container_set_dirty_logging(edge_vfio_object_table_t *table,
                                          edge_vfio_handle_t handle,
                                          int enabled);
int edge_vfio_container_page_dirty(const edge_vfio_object_table_t *table,
                                   edge_vfio_handle_t handle,
                                   uint64_t iova, uint64_t page_size);
int edge_vfio_container_set_enabled(edge_vfio_object_table_t *table,
                                    edge_vfio_handle_t handle, int enabled);
int edge_vfio_group_open(edge_vfio_object_table_t *table, uint32_t group_id,
                         edge_vfio_handle_t *handle);
int edge_vfio_group_retain(edge_vfio_object_table_t *table,
                           edge_vfio_handle_t handle);
int edge_vfio_group_release(edge_vfio_object_table_t *table,
                            edge_vfio_handle_t handle);
int edge_vfio_group_get_status(const edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle,
                               edge_vfio_group_status_t *status);
int edge_vfio_group_set_container(edge_vfio_object_table_t *table,
                                  edge_vfio_handle_t group,
                                  edge_vfio_handle_t container);
int edge_vfio_group_unset_container(edge_vfio_object_table_t *table,
                                    edge_vfio_handle_t group);
int edge_vfio_group_bind_vm(edge_vfio_object_table_t *table,
                            edge_vfio_handle_t group, uint64_t vm_cookie);
int edge_vfio_group_unbind_vm(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t group, uint64_t vm_cookie);
int edge_vfio_group_get_device(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t group, const char *name,
                               edge_vfio_handle_t *device);
int edge_vfio_device_open_cdev(edge_vfio_object_table_t *table,
                               uint32_t device_id,
                               edge_vfio_handle_t *device);
int edge_vfio_device_release(edge_vfio_object_table_t *table,
                             edge_vfio_handle_t handle);
int edge_vfio_device_retain(edge_vfio_object_table_t *table,
                            edge_vfio_handle_t handle);
int edge_vfio_device_query(edge_vfio_object_table_t *table,
                           edge_vfio_handle_t handle, int *is_cdev,
                           uint32_t *references);
int edge_vfio_device_bind_vm(edge_vfio_object_table_t *table,
                             edge_vfio_handle_t handle,
                             uint64_t vm_cookie);
int edge_vfio_device_unbind_vm(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle,
                               uint64_t vm_cookie);
int edge_vfio_device_context(edge_vfio_object_table_t *table,
                             edge_vfio_handle_t handle,
                             uint64_t *device_cookie,
                             uint64_t *vm_cookie);
int edge_vfio_device_get_info(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t handle,
                              edge_vfio_device_info_t *info);
int edge_vfio_device_get_region_info(edge_vfio_object_table_t *table,
                                     edge_vfio_handle_t handle,
                                     edge_vfio_region_info_t *info);
int edge_vfio_device_get_irq_info(edge_vfio_object_table_t *table,
                                  edge_vfio_handle_t handle,
                                  edge_vfio_irq_info_t *info);
int edge_vfio_device_set_irqs(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t handle,
                              const edge_vfio_irq_set_t *set,
                              const void *data, uint32_t data_size);
int edge_vfio_device_reset(edge_vfio_object_table_t *table,
                           edge_vfio_handle_t handle);
int64_t edge_vfio_device_read(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t handle, uint64_t offset,
                              void *buffer, uint32_t size);
int64_t edge_vfio_device_write(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle, uint64_t offset,
                               const void *buffer, uint32_t size);
int edge_vfio_device_mmap(edge_vfio_object_table_t *table,
                          edge_vfio_handle_t handle, uint64_t offset,
                          uint64_t size, uint32_t protection,
                          uint64_t *physical_address);

#endif
