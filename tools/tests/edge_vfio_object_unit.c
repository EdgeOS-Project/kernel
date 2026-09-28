/* SPDX-License-Identifier: MPL-2.0 */
/* Host tests for EdgeOS VFIO object and DMA lifetime policy. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "kernel/edge_vfio_object.h"
#include "kernel/linux_errno.h"

typedef struct test_backend {
    uint64_t next_cookie;
    uint32_t iommu_sets;
    uint32_t iommu_clears;
    uint32_t group_opens;
    uint32_t group_closes;
    uint32_t group_attaches;
    uint32_t group_detaches;
    uint32_t device_opens;
    uint32_t device_closes;
    uint32_t device_info_queries;
    uint32_t region_info_queries;
    uint32_t irq_info_queries;
    uint32_t irq_updates;
    uint32_t device_resets;
    uint32_t device_reads;
    uint32_t device_writes;
    uint32_t device_mmaps;
    uint32_t dma_maps;
    uint32_t dma_unmaps;
} test_backend_t;

static int test_set_iommu(void *opaque, uint32_t type, uint64_t *cookie) {
    test_backend_t *backend = opaque;
    assert(type == EDGE_VFIO_TYPE1_IOMMU ||
           type == EDGE_VFIO_TYPE1_V2_IOMMU);
    *cookie = ++backend->next_cookie;
    ++backend->iommu_sets;
    return 0;
}

static int test_clear_iommu(void *opaque, uint64_t cookie) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    ++backend->iommu_clears;
    return 0;
}

static int test_group_open(void *opaque, uint32_t group_id, int *viable,
                           uint64_t *cookie) {
    test_backend_t *backend = opaque;
    *viable = group_id != 9;
    *cookie = ++backend->next_cookie;
    ++backend->group_opens;
    return 0;
}

static void test_group_close(void *opaque, uint64_t cookie) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    ++backend->group_closes;
}

static int test_group_attach(void *opaque, uint64_t group_cookie,
                             uint64_t container_cookie) {
    test_backend_t *backend = opaque;
    assert(group_cookie != 0 && container_cookie != 0);
    ++backend->group_attaches;
    return 0;
}

static void test_group_detach(void *opaque, uint64_t group_cookie,
                              uint64_t container_cookie) {
    test_backend_t *backend = opaque;
    assert(group_cookie != 0 && container_cookie != 0);
    ++backend->group_detaches;
}

static int test_device_open(void *opaque, uint64_t group_cookie,
                            uint64_t vm_cookie, const char *name,
                            uint64_t *cookie) {
    test_backend_t *backend = opaque;
    assert(group_cookie != 0 && vm_cookie == 0x1234 && name[0] != '\0');
    *cookie = ++backend->next_cookie;
    ++backend->device_opens;
    return 0;
}

static void test_device_close(void *opaque, uint64_t cookie) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    ++backend->device_closes;
}

static int test_device_get_info(void *opaque, uint64_t cookie,
                                edge_vfio_device_info_t *info) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && info->argsz >= sizeof(*info));
    info->flags = EDGE_VFIO_DEVICE_FLAGS_PCI | EDGE_VFIO_DEVICE_FLAGS_RESET;
    info->num_regions = EDGE_VFIO_PCI_NUM_REGIONS;
    info->num_irqs = EDGE_VFIO_PCI_NUM_IRQS;
    ++backend->device_info_queries;
    return 0;
}

static int test_device_get_region_info(void *opaque, uint64_t cookie,
                                       edge_vfio_region_info_t *info) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && info->argsz >= sizeof(*info));
    info->flags = EDGE_VFIO_REGION_INFO_FLAG_READ |
        EDGE_VFIO_REGION_INFO_FLAG_WRITE | EDGE_VFIO_REGION_INFO_FLAG_MMAP;
    info->size = 0x2000;
    info->offset = (uint64_t)info->index << 40;
    ++backend->region_info_queries;
    return 0;
}

static int test_device_get_irq_info(void *opaque, uint64_t cookie,
                                    edge_vfio_irq_info_t *info) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && info->argsz >= sizeof(*info));
    info->flags = EDGE_VFIO_IRQ_INFO_EVENTFD;
    info->count = 4;
    ++backend->irq_info_queries;
    return 0;
}

static int test_device_set_irqs(void *opaque, uint64_t cookie,
                                const edge_vfio_irq_set_t *set,
                                const void *data, uint32_t data_size) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && set->count == 2 && data != 0 && data_size == 8);
    ++backend->irq_updates;
    return 0;
}

static int test_device_reset(void *opaque, uint64_t cookie) {
    test_backend_t *backend = opaque;
    assert(cookie != 0);
    ++backend->device_resets;
    return 0;
}

static int64_t test_device_read(void *opaque, uint64_t cookie,
                                uint64_t offset, void *buffer,
                                uint32_t size) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && offset == 0x1000 && buffer != 0 && size == 4);
    *(uint32_t *)buffer = 0x12345678u;
    ++backend->device_reads;
    return size;
}

static int64_t test_device_write(void *opaque, uint64_t cookie,
                                 uint64_t offset, const void *buffer,
                                 uint32_t size) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && offset == 0x1000 && buffer != 0 && size == 4 &&
           *(const uint32_t *)buffer == 0x12345678u);
    ++backend->device_writes;
    return size;
}

static int test_device_mmap(void *opaque, uint64_t cookie,
                            uint64_t offset, uint64_t size,
                            uint32_t protection,
                            uint64_t *physical_address) {
    test_backend_t *backend = opaque;
    assert(cookie != 0 && offset == 0x2000 && size == 0x1000 &&
           protection == 3 && physical_address != 0);
    *physical_address = 0x80002000;
    ++backend->device_mmaps;
    return 0;
}

static int test_dma_map(void *opaque, uint64_t container_cookie,
                        uint64_t vm_cookie,
                        uint64_t iova, uint64_t address, uint64_t size,
                        uint32_t flags) {
    test_backend_t *backend = opaque;
    assert(container_cookie != 0 && vm_cookie == 0x1234 &&
           iova != 0 && address != 0 && size != 0);
    assert(flags != 0);
    ++backend->dma_maps;
    return 0;
}

static int test_dma_unmap(void *opaque, uint64_t container_cookie,
                          uint64_t vm_cookie, uint64_t iova, uint64_t size) {
    test_backend_t *backend = opaque;
    assert(container_cookie != 0 && vm_cookie == 0x1234 &&
           iova != 0 && size != 0);
    ++backend->dma_unmaps;
    return 0;
}

int main(void) {
    test_backend_t backend = {0};
    edge_vfio_object_table_t table;
    edge_vfio_backend_ops_t operations = {
        .context = &backend,
        .container_set_iommu = test_set_iommu,
        .container_clear_iommu = test_clear_iommu,
        .group_open = test_group_open,
        .group_close = test_group_close,
        .group_attach = test_group_attach,
        .group_detach = test_group_detach,
        .device_open = test_device_open,
        .device_close = test_device_close,
        .device_get_info = test_device_get_info,
        .device_get_region_info = test_device_get_region_info,
        .device_get_irq_info = test_device_get_irq_info,
        .device_set_irqs = test_device_set_irqs,
        .device_reset = test_device_reset,
        .device_read = test_device_read,
        .device_write = test_device_write,
        .device_mmap = test_device_mmap,
        .dma_map = test_dma_map,
        .dma_unmap = test_dma_unmap,
    };
    edge_vfio_handle_t container;
    edge_vfio_handle_t group;
    edge_vfio_handle_t duplicate_group;
    edge_vfio_handle_t device;
    edge_vfio_handle_t blocked_group;
    edge_vfio_group_status_t status = {.argsz = sizeof(status)};
    edge_vfio_iommu_type1_dma_map_t map = {
        .argsz = sizeof(map),
        .flags = EDGE_VFIO_DMA_MAP_FLAG_READ | EDGE_VFIO_DMA_MAP_FLAG_WRITE,
        .vaddr = 0x200000,
        .iova = 0x100000,
        .size = 0x4000,
    };
    edge_vfio_iommu_type1_dma_unmap_t unmap = {
        .argsz = sizeof(unmap),
        .iova = 0x100000,
        .size = 0x4000,
    };
    edge_vfio_device_info_t device_info = {.argsz = sizeof(device_info)};
    edge_vfio_region_info_t region_info = {
        .argsz = sizeof(region_info),
        .index = 2,
    };
    edge_vfio_irq_info_t irq_info = {
        .argsz = sizeof(irq_info),
        .index = EDGE_VFIO_PCI_MSIX_IRQ_INDEX,
    };
    edge_vfio_irq_set_t irq_set = {
        .argsz = sizeof(irq_set) + 2u * sizeof(int32_t),
        .flags = EDGE_VFIO_IRQ_SET_DATA_EVENTFD |
            EDGE_VFIO_IRQ_SET_ACTION_TRIGGER,
        .index = EDGE_VFIO_PCI_MSIX_IRQ_INDEX,
        .count = 2,
    };
    int32_t irq_descriptors[2] = {10, 11};
    uint32_t register_value = 0;
    uint64_t physical_address = 0;

    assert(edge_vfio_object_table_init(&table, &operations) == 0);
    assert(edge_vfio_container_create(&table, &container) == 0);
    assert(edge_vfio_group_open(&table, 7, &group) == 0);
    assert(edge_vfio_group_set_container(&table, group, container) == 0);
    assert(edge_vfio_container_set_iommu(
               &table, container, EDGE_VFIO_TYPE1_V2_IOMMU) == 0);
    assert(edge_vfio_group_set_container(&table, group, container) == 0);
    assert(edge_vfio_group_get_status(&table, group, &status) == 0);
    assert(status.flags == (EDGE_VFIO_GROUP_FLAGS_VIABLE |
                            EDGE_VFIO_GROUP_FLAGS_CONTAINER_SET));

    assert(edge_vfio_group_open(&table, 7, &duplicate_group) == 0);
    assert(duplicate_group.slot == group.slot &&
           duplicate_group.generation == group.generation);
    assert(backend.group_opens == 1);

    assert(edge_vfio_container_map_dma(&table, container, &map) ==
           -EDGE_LINUX_EINVAL);
    assert(edge_vfio_group_bind_vm(&table, group, 0x1234) == 0);
    assert(edge_vfio_container_map_dma(&table, container, &map) == 0);
    map.iova += 0x1000;
    assert(edge_vfio_container_map_dma(&table, container, &map) ==
           -EDGE_LINUX_EEXIST);
    map.iova -= 0x1000;
    assert(edge_vfio_container_unmap_dma(&table, container, &unmap) == 0);
    assert(unmap.size == 0x4000);
    assert(edge_vfio_container_unmap_dma(&table, container, &unmap) == 0);
    assert(unmap.size == 0);

    assert(edge_vfio_group_get_device(
               &table, group, "0000:00:04.0", &device) == 0);
    assert(edge_vfio_device_get_info(&table, device, &device_info) == 0);
    assert(device_info.num_regions == EDGE_VFIO_PCI_NUM_REGIONS &&
           device_info.num_irqs == EDGE_VFIO_PCI_NUM_IRQS);
    assert(edge_vfio_device_get_region_info(
               &table, device, &region_info) == 0);
    assert(region_info.size == 0x2000 && region_info.offset == (UINT64_C(2) << 40));
    assert(edge_vfio_device_get_irq_info(&table, device, &irq_info) == 0);
    assert(irq_info.count == 4);
    assert(edge_vfio_device_set_irqs(
               &table, device, &irq_set, irq_descriptors,
               sizeof(irq_descriptors)) == 0);
    assert(edge_vfio_device_reset(&table, device) == 0);
    assert(edge_vfio_device_read(
               &table, device, 0x1000, &register_value,
               sizeof(register_value)) == (int64_t)sizeof(register_value));
    assert(register_value == 0x12345678u);
    assert(edge_vfio_device_write(
               &table, device, 0x1000, &register_value,
               sizeof(register_value)) == (int64_t)sizeof(register_value));
    assert(edge_vfio_device_mmap(
               &table, device, 0x2000, 0x1000, 3,
               &physical_address) == 0);
    assert(physical_address == 0x80002000);
    assert(edge_vfio_group_unset_container(&table, group) ==
           -EDGE_LINUX_EBUSY);
    assert(edge_vfio_group_release(&table, duplicate_group) == 0);
    assert(edge_vfio_group_release(&table, group) == 0);
    assert(edge_vfio_container_release(&table, container) == 0);
    assert(table.active_container_count == 1 && table.active_group_count == 1);
    assert(edge_vfio_device_release(&table, device) == 0);
    assert(table.active_container_count == 1 && table.active_group_count == 1 &&
           table.active_device_count == 0);
    assert(edge_vfio_group_unbind_vm(&table, group, 0x1234) == 0);
    assert(table.active_container_count == 0 && table.active_group_count == 0 &&
           table.active_device_count == 0);
    assert(backend.device_closes == 1 && backend.group_detaches == 1 &&
           backend.group_closes == 1 && backend.iommu_clears == 1);

    assert(edge_vfio_group_open(&table, 9, &blocked_group) == 0);
    status.argsz = sizeof(status);
    assert(edge_vfio_group_get_status(&table, blocked_group, &status) == 0);
    assert(status.flags == 0);
    assert(edge_vfio_group_release(&table, blocked_group) == 0);

    assert(backend.dma_maps == 1 && backend.dma_unmaps == 1);
    assert(backend.device_info_queries == 1 &&
           backend.region_info_queries == 1 &&
           backend.irq_info_queries == 1 && backend.irq_updates == 1 &&
           backend.device_resets == 1 && backend.device_reads == 1 &&
           backend.device_writes == 1 && backend.device_mmaps == 1);
    edge_vfio_object_table_reset(&table);
    puts("edge_vfio_object_unit: PASS");
    return 0;
}
