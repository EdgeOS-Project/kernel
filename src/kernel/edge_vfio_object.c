/* SPDX-License-Identifier: MPL-2.0 */
/* EdgeOS-owned VFIO object and lifetime translation. */

#include "kernel/edge_vfio_object.h"
#include "kernel/linux_errno.h"

static void edge_vfio_zero(void *pointer, uint64_t size) {
    uint8_t *bytes = pointer;
    while (size-- != 0) *bytes++ = 0;
}

static uint32_t edge_vfio_generation(edge_vfio_object_table_t *table) {
    ++table->next_generation;
    if (table->next_generation == 0) ++table->next_generation;
    return table->next_generation;
}

static edge_vfio_container_object_t *edge_vfio_container(
        edge_vfio_object_table_t *table, edge_vfio_handle_t handle) {
    edge_vfio_container_object_t *container;
    if (!table || handle.slot >= EDGE_VFIO_MAX_CONTAINERS) return 0;
    container = &table->containers[handle.slot];
    return container->active && container->generation == handle.generation ?
        container : 0;
}

static edge_vfio_group_object_t *edge_vfio_group(
        edge_vfio_object_table_t *table, edge_vfio_handle_t handle) {
    edge_vfio_group_object_t *group;
    if (!table || handle.slot >= EDGE_VFIO_MAX_GROUPS) return 0;
    group = &table->groups[handle.slot];
    return group->active && group->generation == handle.generation ? group : 0;
}

static edge_vfio_device_object_t *edge_vfio_device(
        edge_vfio_object_table_t *table, edge_vfio_handle_t handle) {
    edge_vfio_device_object_t *device;
    if (!table || handle.slot >= EDGE_VFIO_MAX_DEVICES) return 0;
    device = &table->devices[handle.slot];
    return device->active && device->generation == handle.generation ?
        device : 0;
}

static void edge_vfio_try_destroy_container(edge_vfio_object_table_t *table,
                                             uint32_t slot) {
    edge_vfio_container_object_t *container = &table->containers[slot];
    if (!container->active || container->descriptor_references != 0 ||
        container->group_count != 0)
        return;
    if (container->iommu_type != 0 && table->backend.container_clear_iommu)
        (void)table->backend.container_clear_iommu(
            table->backend.context, container->backend_cookie);
    edge_vfio_zero(container, sizeof(*container));
    --table->active_container_count;
}

static void edge_vfio_detach_group(edge_vfio_object_table_t *table,
                                   edge_vfio_group_object_t *group) {
    edge_vfio_container_object_t *container;
    uint32_t slot;
    if (!group->attached) return;
    slot = group->container.slot;
    container = edge_vfio_container(table, group->container);
    if (container) {
        if (group->backend_attached && table->backend.group_detach)
            table->backend.group_detach(table->backend.context,
                group->backend_cookie, container->backend_cookie);
        if (container->group_count != 0) --container->group_count;
    }
    group->attached = 0;
    group->backend_attached = 0;
    edge_vfio_zero(&group->container, sizeof(group->container));
    if (slot < EDGE_VFIO_MAX_CONTAINERS)
        edge_vfio_try_destroy_container(table, slot);
}

static void edge_vfio_try_destroy_group(edge_vfio_object_table_t *table,
                                        uint32_t slot) {
    edge_vfio_group_object_t *group = &table->groups[slot];
    if (!group->active || group->descriptor_references != 0 ||
        group->device_count != 0 || group->vm_cookie != 0)
        return;
    edge_vfio_detach_group(table, group);
    if (table->backend.group_close)
        table->backend.group_close(table->backend.context,
                                   group->backend_cookie);
    edge_vfio_zero(group, sizeof(*group));
    --table->active_group_count;
}

int edge_vfio_object_table_init(edge_vfio_object_table_t *table,
                                const edge_vfio_backend_ops_t *backend) {
    if (!table || !backend || !backend->group_open || !backend->group_close ||
        !backend->device_open || !backend->device_close)
        return -EDGE_LINUX_EINVAL;
    edge_vfio_zero(table, sizeof(*table));
    table->backend = *backend;
    return 0;
}

void edge_vfio_object_table_reset(edge_vfio_object_table_t *table) {
    if (!table) return;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DEVICES; ++index) {
        edge_vfio_device_object_t *device = &table->devices[index];
        if (device->active && table->backend.device_close)
            table->backend.device_close(table->backend.context,
                                         device->backend_cookie);
    }
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_GROUPS; ++index) {
        edge_vfio_group_object_t *group = &table->groups[index];
        if (!group->active) continue;
        edge_vfio_detach_group(table, group);
        if (table->backend.group_close)
            table->backend.group_close(table->backend.context,
                                       group->backend_cookie);
    }
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_CONTAINERS; ++index) {
        edge_vfio_container_object_t *container = &table->containers[index];
        if (container->active && container->iommu_type != 0 &&
            table->backend.container_clear_iommu)
            (void)table->backend.container_clear_iommu(
                table->backend.context, container->backend_cookie);
    }
    edge_vfio_backend_ops_t backend = table->backend;
    edge_vfio_zero(table, sizeof(*table));
    table->backend = backend;
}

int edge_vfio_container_create(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t *handle) {
    if (!table || !handle) return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_CONTAINERS; ++index) {
        edge_vfio_container_object_t *container = &table->containers[index];
        if (container->active) continue;
        edge_vfio_zero(container, sizeof(*container));
        container->active = 1;
        container->generation = edge_vfio_generation(table);
        container->descriptor_references = 1;
        handle->slot = index;
        handle->generation = container->generation;
        ++table->active_container_count;
        return 0;
    }
    return -EDGE_LINUX_ENOSPC;
}

int edge_vfio_container_release(edge_vfio_object_table_t *table,
                                edge_vfio_handle_t handle) {
    edge_vfio_container_object_t *container = edge_vfio_container(table, handle);
    if (!container || container->descriptor_references == 0)
        return -EDGE_LINUX_EBADF;
    --container->descriptor_references;
    edge_vfio_try_destroy_container(table, handle.slot);
    return 0;
}

int edge_vfio_container_retain(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle) {
    edge_vfio_container_object_t *container = edge_vfio_container(table, handle);
    if (!container || container->descriptor_references == UINT32_MAX)
        return -EDGE_LINUX_EBADF;
    ++container->descriptor_references;
    return 0;
}

int edge_vfio_container_set_iommu(edge_vfio_object_table_t *table,
                                  edge_vfio_handle_t handle,
                                  uint32_t iommu_type) {
    edge_vfio_container_object_t *container = edge_vfio_container(table, handle);
    uint64_t cookie = 0;
    int status;
    if (!container) return -EDGE_LINUX_EBADF;
    if (iommu_type != EDGE_VFIO_TYPE1_IOMMU &&
        iommu_type != EDGE_VFIO_TYPE1_V2_IOMMU)
        return -EDGE_LINUX_EINVAL;
    if (container->iommu_type != 0)
        return container->iommu_type == iommu_type ? 0 : -EDGE_LINUX_EBUSY;
    if (!table->backend.container_set_iommu)
        return -EDGE_LINUX_EOPNOTSUPP;
    status = table->backend.container_set_iommu(
        table->backend.context, iommu_type, &cookie);
    if (status < 0) return status;
    container->iommu_type = iommu_type;
    container->backend_cookie = cookie;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_GROUPS; ++index) {
        edge_vfio_group_object_t *group = &table->groups[index];
        if (!group->active || !group->attached || group->backend_attached ||
            group->container.slot != handle.slot ||
            group->container.generation != handle.generation)
            continue;
        if (!table->backend.group_attach) {
            status = -EDGE_LINUX_EOPNOTSUPP;
            goto rollback_groups;
        }
        status = table->backend.group_attach(table->backend.context,
            group->backend_cookie, container->backend_cookie);
        if (status < 0) goto rollback_groups;
        group->backend_attached = 1;
    }
    return 0;

rollback_groups:
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_GROUPS; ++index) {
        edge_vfio_group_object_t *group = &table->groups[index];
        if (!group->active || !group->backend_attached ||
            group->container.slot != handle.slot ||
            group->container.generation != handle.generation)
            continue;
        if (table->backend.group_detach)
            table->backend.group_detach(table->backend.context,
                group->backend_cookie, container->backend_cookie);
        group->backend_attached = 0;
    }
    if (table->backend.container_clear_iommu)
        (void)table->backend.container_clear_iommu(
            table->backend.context, container->backend_cookie);
    container->iommu_type = 0;
    container->backend_cookie = 0;
    return status;
}

static int edge_vfio_range_valid(uint64_t start, uint64_t size) {
    return size != 0 && (start & (EDGE_VFIO_PAGE_SIZE - 1u)) == 0 &&
        (size & (EDGE_VFIO_PAGE_SIZE - 1u)) == 0 && start + size >= start;
}

int edge_vfio_container_map_dma(edge_vfio_object_table_t *table,
                                edge_vfio_handle_t handle,
                                const edge_vfio_iommu_type1_dma_map_t *map) {
    edge_vfio_container_object_t *container = edge_vfio_container(table, handle);
    edge_vfio_dma_map_t *free_map = 0;
    int status;
    if (!container) return -EDGE_LINUX_EBADF;
    if (!map || map->argsz < sizeof(*map) || map->flags == 0 ||
        (map->flags & ~EDGE_VFIO_DMA_MAP_VALID_FLAGS) != 0 ||
        !edge_vfio_range_valid(map->iova, map->size) ||
        !edge_vfio_range_valid(map->vaddr, map->size))
        return -EDGE_LINUX_EINVAL;
    if (container->iommu_type == 0 || container->vm_cookie == 0)
        return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DMA_MAPS; ++index) {
        edge_vfio_dma_map_t *current = &container->dma_maps[index];
        if (!current->active) {
            if (!free_map) free_map = current;
            continue;
        }
        if (map->iova < current->iova + current->size &&
            current->iova < map->iova + map->size)
            return -EDGE_LINUX_EEXIST;
    }
    if (!free_map) return -EDGE_LINUX_ENOSPC;
    if (!table->backend.dma_map) return -EDGE_LINUX_EOPNOTSUPP;
    status = table->backend.dma_map(table->backend.context,
        container->backend_cookie, container->vm_cookie,
        map->iova, map->vaddr,
        map->size, map->flags);
    if (status < 0) return status;
    free_map->active = 1;
    free_map->flags = map->flags;
    free_map->iova = map->iova;
    free_map->userspace_address = map->vaddr;
    free_map->size = map->size;
    ++container->dma_map_count;
    return 0;
}

int edge_vfio_container_unmap_dma(
        edge_vfio_object_table_t *table, edge_vfio_handle_t handle,
        edge_vfio_iommu_type1_dma_unmap_t *unmap) {
    edge_vfio_container_object_t *container = edge_vfio_container(table, handle);
    uint32_t valid_flags = EDGE_VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP |
        EDGE_VFIO_DMA_UNMAP_FLAG_ALL | EDGE_VFIO_DMA_UNMAP_FLAG_VADDR;
    int status;
    if (!container) return -EDGE_LINUX_EBADF;
    if (!unmap || unmap->argsz < sizeof(*unmap) ||
        (unmap->flags & ~valid_flags) != 0 ||
        ((unmap->flags & EDGE_VFIO_DMA_UNMAP_FLAG_ALL) != 0 &&
         (unmap->flags != EDGE_VFIO_DMA_UNMAP_FLAG_ALL ||
          unmap->iova != 0 || unmap->size != 0)) ||
        ((unmap->flags & EDGE_VFIO_DMA_UNMAP_FLAG_ALL) == 0 &&
         !edge_vfio_range_valid(unmap->iova, unmap->size)))
        return -EDGE_LINUX_EINVAL;
    if ((unmap->flags & EDGE_VFIO_DMA_UNMAP_FLAG_ALL) != 0) {
        uint8_t completed[EDGE_VFIO_MAX_DMA_MAPS] = {0};
        uint64_t unmapped = 0;
        for (uint32_t index = 0; index < EDGE_VFIO_MAX_DMA_MAPS; ++index) {
            edge_vfio_dma_map_t *map = &container->dma_maps[index];
            if (!map->active) continue;
            if (!table->backend.dma_unmap)
                return -EDGE_LINUX_EOPNOTSUPP;
            status = table->backend.dma_unmap(table->backend.context,
                container->backend_cookie, container->vm_cookie,
                map->iova, map->size);
            if (status < 0) {
                if (table->backend.dma_map) {
                    for (uint32_t rollback = 0; rollback < index;
                         ++rollback) {
                        edge_vfio_dma_map_t *prior =
                            &container->dma_maps[rollback];
                        if (completed[rollback])
                            (void)table->backend.dma_map(
                                table->backend.context,
                                container->backend_cookie,
                                container->vm_cookie, prior->iova,
                                prior->userspace_address, prior->size,
                                prior->flags);
                    }
                }
                return status;
            }
            unmapped += map->size;
            completed[index] = 1;
        }
        for (uint32_t index = 0; index < EDGE_VFIO_MAX_DMA_MAPS; ++index) {
            if (!completed[index]) continue;
            edge_vfio_zero(&container->dma_maps[index],
                           sizeof(container->dma_maps[index]));
            --container->dma_map_count;
        }
        unmap->size = unmapped;
        return 0;
    }
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DMA_MAPS; ++index) {
        edge_vfio_dma_map_t *map = &container->dma_maps[index];
        uint64_t address =
            (unmap->flags & EDGE_VFIO_DMA_UNMAP_FLAG_VADDR) != 0 ?
                map->userspace_address : map->iova;
        if (!map->active || address != unmap->iova ||
            map->size != unmap->size)
            continue;
        if (!table->backend.dma_unmap) return -EDGE_LINUX_EOPNOTSUPP;
        status = table->backend.dma_unmap(table->backend.context,
            container->backend_cookie, container->vm_cookie,
            map->iova, map->size);
        if (status < 0) return status;
        unmap->size = map->size;
        edge_vfio_zero(map, sizeof(*map));
        --container->dma_map_count;
        return 0;
    }
    unmap->size = 0;
    return 0;
}

int edge_vfio_container_set_dirty_logging(edge_vfio_object_table_t *table,
                                          edge_vfio_handle_t handle,
                                          int enabled) {
    edge_vfio_container_object_t *container = edge_vfio_container(table,
                                                                   handle);
    if (!container) return -EDGE_LINUX_EBADF;
    if (container->iommu_type == 0) return -EDGE_LINUX_EINVAL;
    container->dirty_logging = enabled != 0;
    return 0;
}

int edge_vfio_container_page_dirty(const edge_vfio_object_table_t *table,
                                   edge_vfio_handle_t handle,
                                   uint64_t iova, uint64_t page_size) {
    const edge_vfio_container_object_t *container;
    uint64_t end;
    if (!table || handle.slot >= EDGE_VFIO_MAX_CONTAINERS)
        return -EDGE_LINUX_EBADF;
    container = &table->containers[handle.slot];
    if (!container->active || container->generation != handle.generation)
        return -EDGE_LINUX_EBADF;
    if (!container->dirty_logging) return -EDGE_LINUX_EINVAL;
    if (page_size == 0 || iova > UINT64_MAX - page_size)
        return -EDGE_LINUX_EINVAL;
    end = iova + page_size;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DMA_MAPS; ++index) {
        const edge_vfio_dma_map_t *map = &container->dma_maps[index];
        if (map->active && iova < map->iova + map->size && map->iova < end)
            return 1;
    }
    return 0;
}

int edge_vfio_container_set_enabled(edge_vfio_object_table_t *table,
                                    edge_vfio_handle_t handle, int enabled) {
    edge_vfio_container_object_t *container = edge_vfio_container(table,
                                                                   handle);
    if (!container) return -EDGE_LINUX_EBADF;
    if (container->iommu_type == 0) return -EDGE_LINUX_EINVAL;
    if (!enabled && container->dma_map_count != 0)
        return -EDGE_LINUX_EBUSY;
    container->iommu_enabled = enabled != 0;
    return 0;
}

int edge_vfio_group_open(edge_vfio_object_table_t *table, uint32_t group_id,
                         edge_vfio_handle_t *handle) {
    int viable = 0;
    uint64_t cookie = 0;
    int status;
    if (!table || !handle) return -EDGE_LINUX_EINVAL;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_GROUPS; ++index) {
        edge_vfio_group_object_t *group = &table->groups[index];
        if (!group->active || group->group_id != group_id) continue;
        ++group->descriptor_references;
        handle->slot = index;
        handle->generation = group->generation;
        return 0;
    }
    status = table->backend.group_open(
        table->backend.context, group_id, &viable, &cookie);
    if (status < 0) return status;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_GROUPS; ++index) {
        edge_vfio_group_object_t *group = &table->groups[index];
        if (group->active) continue;
        edge_vfio_zero(group, sizeof(*group));
        group->active = 1;
        group->viable = viable != 0;
        group->generation = edge_vfio_generation(table);
        group->group_id = group_id;
        group->descriptor_references = 1;
        group->backend_cookie = cookie;
        handle->slot = index;
        handle->generation = group->generation;
        ++table->active_group_count;
        return 0;
    }
    table->backend.group_close(table->backend.context, cookie);
    return -EDGE_LINUX_ENOSPC;
}

int edge_vfio_group_release(edge_vfio_object_table_t *table,
                            edge_vfio_handle_t handle) {
    edge_vfio_group_object_t *group = edge_vfio_group(table, handle);
    if (!group || group->descriptor_references == 0)
        return -EDGE_LINUX_EBADF;
    --group->descriptor_references;
    edge_vfio_try_destroy_group(table, handle.slot);
    return 0;
}

int edge_vfio_group_retain(edge_vfio_object_table_t *table,
                           edge_vfio_handle_t handle) {
    edge_vfio_group_object_t *group = edge_vfio_group(table, handle);
    if (!group || group->descriptor_references == UINT32_MAX)
        return -EDGE_LINUX_EBADF;
    ++group->descriptor_references;
    return 0;
}

int edge_vfio_group_get_status(const edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle,
                               edge_vfio_group_status_t *status) {
    edge_vfio_group_object_t *group = edge_vfio_group(
        (edge_vfio_object_table_t *)table, handle);
    if (!group) return -EDGE_LINUX_EBADF;
    if (!status || status->argsz < sizeof(*status)) return -EDGE_LINUX_EINVAL;
    status->flags = (group->viable ? EDGE_VFIO_GROUP_FLAGS_VIABLE : 0u) |
        (group->attached ? EDGE_VFIO_GROUP_FLAGS_CONTAINER_SET : 0u);
    return 0;
}

int edge_vfio_group_set_container(edge_vfio_object_table_t *table,
                                  edge_vfio_handle_t group_handle,
                                  edge_vfio_handle_t container_handle) {
    edge_vfio_group_object_t *group = edge_vfio_group(table, group_handle);
    edge_vfio_container_object_t *container = edge_vfio_container(
        table, container_handle);
    int status;
    if (!group || !container) return -EDGE_LINUX_EBADF;
    if (!group->viable) return -EDGE_LINUX_EBUSY;
    if (group->attached)
        return group->container.slot == container_handle.slot &&
            group->container.generation == container_handle.generation ?
            0 : -EDGE_LINUX_EBUSY;
    if (container->iommu_type != 0) {
        if (!table->backend.group_attach) return -EDGE_LINUX_EOPNOTSUPP;
        status = table->backend.group_attach(table->backend.context,
            group->backend_cookie, container->backend_cookie);
        if (status < 0) return status;
        group->backend_attached = 1;
    }
    group->attached = 1;
    group->container = container_handle;
    ++container->group_count;
    return 0;
}

int edge_vfio_group_unset_container(edge_vfio_object_table_t *table,
                                    edge_vfio_handle_t group_handle) {
    edge_vfio_group_object_t *group = edge_vfio_group(table, group_handle);
    if (!group) return -EDGE_LINUX_EBADF;
    if (!group->attached) return -EDGE_LINUX_EINVAL;
    if (group->device_count != 0 || group->vm_cookie != 0)
        return -EDGE_LINUX_EBUSY;
    edge_vfio_detach_group(table, group);
    return 0;
}

int edge_vfio_group_bind_vm(edge_vfio_object_table_t *table,
                            edge_vfio_handle_t group_handle,
                            uint64_t vm_cookie) {
    edge_vfio_group_object_t *group = edge_vfio_group(table, group_handle);
    edge_vfio_container_object_t *container;
    if (!group) return -EDGE_LINUX_EBADF;
    if (!vm_cookie || !group->attached) return -EDGE_LINUX_EINVAL;
    if (group->vm_cookie != 0)
        return group->vm_cookie == vm_cookie ? 0 : -EDGE_LINUX_EBUSY;
    container = edge_vfio_container(table, group->container);
    if (!container) return -EDGE_LINUX_EBADF;
    if (container->vm_cookie != 0 && container->vm_cookie != vm_cookie)
        return -EDGE_LINUX_EBUSY;
    if (table->backend.group_bind_vm) {
        int status = table->backend.group_bind_vm(
            table->backend.context, group->backend_cookie, vm_cookie);
        if (status < 0) return status;
    }
    container->vm_cookie = vm_cookie;
    ++container->vm_group_count;
    group->vm_cookie = vm_cookie;
    return 0;
}

int edge_vfio_group_unbind_vm(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t group_handle,
                              uint64_t vm_cookie) {
    edge_vfio_group_object_t *group = edge_vfio_group(table, group_handle);
    edge_vfio_container_object_t *container;
    if (!group) return -EDGE_LINUX_EBADF;
    if (!vm_cookie || group->vm_cookie != vm_cookie)
        return -EDGE_LINUX_EINVAL;
    container = edge_vfio_container(table, group->container);
    if (!container || container->vm_cookie != vm_cookie ||
        container->vm_group_count == 0)
        return -EDGE_LINUX_EBADF;
    if (table->backend.group_unbind_vm) {
        int status = table->backend.group_unbind_vm(
            table->backend.context, group->backend_cookie, vm_cookie);
        if (status < 0) return status;
    }
    --container->vm_group_count;
    if (container->vm_group_count == 0) container->vm_cookie = 0;
    group->vm_cookie = 0;
    edge_vfio_try_destroy_group(table, group_handle.slot);
    return 0;
}

int edge_vfio_group_get_device(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t group_handle,
                               const char *name,
                               edge_vfio_handle_t *device_handle) {
    edge_vfio_group_object_t *group = edge_vfio_group(table, group_handle);
    uint64_t cookie = 0;
    uint32_t length = 0;
    int status;
    if (!group) return -EDGE_LINUX_EBADF;
    if (!name || !device_handle || !group->attached || !group->viable)
        return -EDGE_LINUX_EINVAL;
    while (length <= 63u && name[length] != '\0') ++length;
    if (length == 0 || length > 63u) return -EDGE_LINUX_EINVAL;
    status = table->backend.device_open(
        table->backend.context, group->backend_cookie, group->vm_cookie,
        name, &cookie);
    if (status < 0) return status;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DEVICES; ++index) {
        edge_vfio_device_object_t *device = &table->devices[index];
        if (device->active) continue;
        edge_vfio_zero(device, sizeof(*device));
        device->active = 1;
        device->generation = edge_vfio_generation(table);
        device->descriptor_references = 1;
        device->group = group_handle;
        device->backend_cookie = cookie;
        device_handle->slot = index;
        device_handle->generation = device->generation;
        ++group->device_count;
        ++table->active_device_count;
        return 0;
    }
    table->backend.device_close(table->backend.context, cookie);
    return -EDGE_LINUX_ENOSPC;
}

static char edge_vfio_hex_digit(uint32_t value) {
    return (char)(value < 10u ? '0' + value : 'a' + value - 10u);
}

int edge_vfio_device_open_cdev(edge_vfio_object_table_t *table,
                               uint32_t device_id,
                               edge_vfio_handle_t *device_handle) {
    edge_vfio_handle_t group_handle;
    edge_vfio_group_object_t *group;
    uint64_t cookie = 0;
    char name[13] = "0000:00:00.0";
    int status;
    if (!table || !device_handle || device_id > UINT16_MAX)
        return -EDGE_LINUX_EINVAL;
    status = edge_vfio_group_open(table, device_id, &group_handle);
    if (status < 0) return status;
    group = edge_vfio_group(table, group_handle);
    if (!group || !group->viable) {
        status = -EDGE_LINUX_ENODEV;
        goto out_group;
    }
    name[5] = edge_vfio_hex_digit((device_id >> 12) & 0xfu);
    name[6] = edge_vfio_hex_digit((device_id >> 8) & 0xfu);
    name[8] = edge_vfio_hex_digit((device_id >> 7) & 0x1u);
    name[9] = edge_vfio_hex_digit((device_id >> 3) & 0xfu);
    name[11] = edge_vfio_hex_digit(device_id & 0x7u);
    status = table->backend.device_open(table->backend.context,
        group->backend_cookie, 0, name, &cookie);
    if (status < 0) goto out_group;
    status = -EDGE_LINUX_ENOSPC;
    for (uint32_t index = 0; index < EDGE_VFIO_MAX_DEVICES; ++index) {
        edge_vfio_device_object_t *object = &table->devices[index];
        if (object->active) continue;
        edge_vfio_zero(object, sizeof(*object));
        object->active = 1;
        object->cdev = 1;
        object->generation = edge_vfio_generation(table);
        object->descriptor_references = 1;
        object->group = group_handle;
        object->backend_cookie = cookie;
        device_handle->slot = index;
        device_handle->generation = object->generation;
        ++group->device_count;
        ++table->active_device_count;
        status = 0;
        break;
    }
    if (status < 0)
        table->backend.device_close(table->backend.context, cookie);
out_group:
    (void)edge_vfio_group_release(table, group_handle);
    return status;
}

int edge_vfio_device_release(edge_vfio_object_table_t *table,
                             edge_vfio_handle_t handle) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    edge_vfio_group_object_t *group;
    edge_vfio_handle_t group_handle;
    if (!device || device->descriptor_references == 0)
        return -EDGE_LINUX_EBADF;
    if (--device->descriptor_references != 0) return 0;
    group_handle = device->group;
    group = edge_vfio_group(table, group_handle);
    table->backend.device_close(table->backend.context,
                                 device->backend_cookie);
    edge_vfio_zero(device, sizeof(*device));
    --table->active_device_count;
    if (group && group->device_count != 0) {
        --group->device_count;
        edge_vfio_try_destroy_group(table, group_handle.slot);
    }
    return 0;
}

int edge_vfio_device_retain(edge_vfio_object_table_t *table,
                            edge_vfio_handle_t handle) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device || device->descriptor_references == UINT32_MAX)
        return -EDGE_LINUX_EBADF;
    ++device->descriptor_references;
    return 0;
}

int edge_vfio_device_query(edge_vfio_object_table_t *table,
                           edge_vfio_handle_t handle, int *is_cdev,
                           uint32_t *references) {
    const edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (is_cdev) *is_cdev = device->cdev != 0;
    if (references) *references = device->descriptor_references;
    return 0;
}

int edge_vfio_device_bind_vm(edge_vfio_object_table_t *table,
                             edge_vfio_handle_t handle,
                             uint64_t vm_cookie) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    edge_vfio_group_object_t *group;
    int status;

    if (!device) return -EDGE_LINUX_EBADF;
    if (!device->cdev || !vm_cookie) return -EDGE_LINUX_EINVAL;
    group = edge_vfio_group(table, device->group);
    if (!group) return -EDGE_LINUX_EBADF;
    if (group->vm_cookie != 0)
        return group->vm_cookie == vm_cookie ? 0 : -EDGE_LINUX_EBUSY;
    if (!table->backend.group_bind_vm) return -EDGE_LINUX_EOPNOTSUPP;
    status = table->backend.group_bind_vm(
        table->backend.context, group->backend_cookie, vm_cookie);
    if (status < 0) return status;
    group->vm_cookie = vm_cookie;
    return 0;
}

int edge_vfio_device_unbind_vm(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle,
                               uint64_t vm_cookie) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    edge_vfio_group_object_t *group;
    int status;

    if (!device) return -EDGE_LINUX_EBADF;
    if (!device->cdev || !vm_cookie) return -EDGE_LINUX_EINVAL;
    group = edge_vfio_group(table, device->group);
    if (!group || group->vm_cookie != vm_cookie)
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.group_unbind_vm) return -EDGE_LINUX_EOPNOTSUPP;
    status = table->backend.group_unbind_vm(
        table->backend.context, group->backend_cookie, vm_cookie);
    if (status < 0) return status;
    group->vm_cookie = 0;
    return 0;
}

int edge_vfio_device_context(edge_vfio_object_table_t *table,
                             edge_vfio_handle_t handle,
                             uint64_t *device_cookie,
                             uint64_t *vm_cookie) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    edge_vfio_group_object_t *group;

    if (!device) return -EDGE_LINUX_EBADF;
    group = edge_vfio_group(table, device->group);
    if (!group) return -EDGE_LINUX_EBADF;
    if (device_cookie) *device_cookie = device->backend_cookie;
    if (vm_cookie) *vm_cookie = group->vm_cookie;
    return 0;
}

int edge_vfio_device_get_info(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t handle,
                              edge_vfio_device_info_t *info) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (!info || info->argsz < sizeof(*info)) return -EDGE_LINUX_EINVAL;
    if (!table->backend.device_get_info) return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_get_info(
        table->backend.context, device->backend_cookie, info);
}

int edge_vfio_device_get_region_info(edge_vfio_object_table_t *table,
                                     edge_vfio_handle_t handle,
                                     edge_vfio_region_info_t *info) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (!info || info->argsz < sizeof(*info)) return -EDGE_LINUX_EINVAL;
    if (!table->backend.device_get_region_info)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_get_region_info(
        table->backend.context, device->backend_cookie, info);
}

int edge_vfio_device_get_irq_info(edge_vfio_object_table_t *table,
                                  edge_vfio_handle_t handle,
                                  edge_vfio_irq_info_t *info) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (!info || info->argsz < sizeof(*info)) return -EDGE_LINUX_EINVAL;
    if (!table->backend.device_get_irq_info)
        return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_get_irq_info(
        table->backend.context, device->backend_cookie, info);
}

int edge_vfio_device_set_irqs(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t handle,
                              const edge_vfio_irq_set_t *set,
                              const void *data, uint32_t data_size) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    uint32_t data_type;
    uint32_t action_type;
    uint64_t expected_size;
    if (!device) return -EDGE_LINUX_EBADF;
    if (!set || set->argsz < sizeof(*set) ||
        (set->flags & ~EDGE_VFIO_IRQ_SET_VALID_FLAGS) != 0)
        return -EDGE_LINUX_EINVAL;
    data_type = set->flags & EDGE_VFIO_IRQ_SET_DATA_TYPE_MASK;
    action_type = set->flags & EDGE_VFIO_IRQ_SET_ACTION_TYPE_MASK;
    if (data_type == 0 || (data_type & (data_type - 1u)) != 0 ||
        action_type == 0 || (action_type & (action_type - 1u)) != 0)
        return -EDGE_LINUX_EINVAL;
    expected_size = data_type == EDGE_VFIO_IRQ_SET_DATA_EVENTFD ?
        (uint64_t)set->count * sizeof(int32_t) :
        (data_type == EDGE_VFIO_IRQ_SET_DATA_BOOL ? set->count : 0u);
    if (expected_size > UINT32_MAX || data_size != (uint32_t)expected_size ||
        (data_size != 0 && !data))
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.device_set_irqs) return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_set_irqs(
        table->backend.context, device->backend_cookie,
        set, data, data_size);
}

int edge_vfio_device_reset(edge_vfio_object_table_t *table,
                           edge_vfio_handle_t handle) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (!table->backend.device_reset) return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_reset(
        table->backend.context, device->backend_cookie);
}

int64_t edge_vfio_device_read(edge_vfio_object_table_t *table,
                              edge_vfio_handle_t handle, uint64_t offset,
                              void *buffer, uint32_t size) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (!buffer || size == 0) return -EDGE_LINUX_EINVAL;
    if (!table->backend.device_read) return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_read(
        table->backend.context, device->backend_cookie,
        offset, buffer, size);
}

int64_t edge_vfio_device_write(edge_vfio_object_table_t *table,
                               edge_vfio_handle_t handle, uint64_t offset,
                               const void *buffer, uint32_t size) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (!buffer || size == 0) return -EDGE_LINUX_EINVAL;
    if (!table->backend.device_write) return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_write(
        table->backend.context, device->backend_cookie,
        offset, buffer, size);
}

int edge_vfio_device_mmap(edge_vfio_object_table_t *table,
                          edge_vfio_handle_t handle, uint64_t offset,
                          uint64_t size, uint32_t protection,
                          uint64_t *physical_address) {
    edge_vfio_device_object_t *device = edge_vfio_device(table, handle);
    if (!device) return -EDGE_LINUX_EBADF;
    if (!physical_address || size == 0 ||
        (offset & (EDGE_VFIO_PAGE_SIZE - 1u)) != 0 ||
        (size & (EDGE_VFIO_PAGE_SIZE - 1u)) != 0)
        return -EDGE_LINUX_EINVAL;
    if (!table->backend.device_mmap) return -EDGE_LINUX_EOPNOTSUPP;
    return table->backend.device_mmap(
        table->backend.context, device->backend_cookie, offset,
        size, protection, physical_address);
}
