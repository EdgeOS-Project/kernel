/* SPDX-License-Identifier: MPL-2.0 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel/edge_vfio_runtime.h"
#include "kernel/edge_iommufd_runtime.h"
#include "kernel/linux_errno.h"

typedef struct test_state {
    kernel_edge_vfio_file_t files[32];
    uint8_t live[32];
    edge_iommufd_handle_t iommu_files[32];
    uint8_t iommu_live[32];
    int next_descriptor;
    uint32_t resets;
    uint32_t irq_updates;
    uint32_t dma_maps;
    uint32_t dma_unmaps;
} test_state_t;

static int descriptor_install(void *opaque, kernel_edge_vfio_file_kind_t kind,
                              edge_vfio_handle_t handle) {
    test_state_t *state = opaque;
    int descriptor = state->next_descriptor++;
    assert(descriptor >= 0 && descriptor < 32);
    state->files[descriptor].kind = kind;
    state->files[descriptor].handle = handle;
    state->live[descriptor] = 1;
    return descriptor;
}

static int descriptor_resolve(void *opaque, int32_t descriptor,
                              kernel_edge_vfio_file_t *file) {
    test_state_t *state = opaque;
    if (!file || descriptor < 0 || descriptor >= 32 ||
        !state->live[descriptor])
        return -EDGE_LINUX_EBADF;
    *file = state->files[descriptor];
    return 0;
}

static int descriptor_close(void *opaque, int32_t descriptor) {
    test_state_t *state = opaque;
    kernel_edge_vfio_file_t file;
    int status = descriptor_resolve(opaque, descriptor, &file);
    if (status < 0) return status;
    state->live[descriptor] = 0;
    return kernel_edge_vfio_descriptor_release(file.kind, file.handle);
}

static int iommu_descriptor_install(void *opaque,
                                    edge_iommufd_handle_t handle) {
    test_state_t *state = opaque;
    int descriptor = state->next_descriptor++;
    assert(descriptor >= 0 && descriptor < 32);
    state->iommu_files[descriptor] = handle;
    state->iommu_live[descriptor] = 1;
    return descriptor;
}

static int iommu_descriptor_resolve(void *opaque, int32_t descriptor,
                                    edge_iommufd_handle_t *handle) {
    test_state_t *state = opaque;
    if (!handle || descriptor < 0 || descriptor >= 32 ||
        !state->iommu_live[descriptor])
        return -EDGE_LINUX_EBADF;
    *handle = state->iommu_files[descriptor];
    return 0;
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

static int set_iommu(void *opaque, uint32_t type, uint64_t *cookie) {
    (void)opaque;
    assert(type == EDGE_VFIO_TYPE1_V2_IOMMU);
    *cookie = 0x100;
    return 0;
}

static int clear_iommu(void *opaque, uint64_t cookie) {
    (void)opaque;
    assert(cookie == 0x100);
    return 0;
}

static int group_open(void *opaque, uint32_t id, int *viable,
                      uint64_t *cookie) {
    (void)opaque;
    assert(id == 7);
    *viable = 1;
    *cookie = 0x200;
    return 0;
}

static void group_close(void *opaque, uint64_t cookie) {
    (void)opaque;
    assert(cookie == 0x200);
}

static int group_attach(void *opaque, uint64_t group, uint64_t container) {
    (void)opaque;
    assert(group == 0x200 && container == 0x100);
    return 0;
}

static void group_detach(void *opaque, uint64_t group, uint64_t container) {
    (void)opaque;
    assert(group == 0x200 && container == 0x100);
}

static int group_bind_vm(void *opaque, uint64_t group, uint64_t vm) {
    (void)opaque;
    assert(group == 0x200 && vm == 0x400);
    return 0;
}

static int group_unbind_vm(void *opaque, uint64_t group, uint64_t vm) {
    (void)opaque;
    assert(group == 0x200 && vm == 0x400);
    return 0;
}

static int device_open(void *opaque, uint64_t group, uint64_t vm,
                       const char *name, uint64_t *cookie) {
    (void)opaque;
    assert(group == 0x200 && vm == 0 &&
           (strcmp(name, "0000:00:04.0") == 0 ||
            strcmp(name, "0000:00:00.7") == 0));
    *cookie = 0x300;
    return 0;
}

static void device_close(void *opaque, uint64_t cookie) {
    (void)opaque;
    assert(cookie == 0x300);
}

static int device_get_info(void *opaque, uint64_t cookie,
                           edge_vfio_device_info_t *info) {
    (void)opaque;
    assert(cookie == 0x300);
    info->flags = EDGE_VFIO_DEVICE_FLAGS_PCI | EDGE_VFIO_DEVICE_FLAGS_RESET;
    info->num_regions = EDGE_VFIO_PCI_NUM_REGIONS;
    info->num_irqs = EDGE_VFIO_PCI_NUM_IRQS;
    return 0;
}

static int device_get_region_info(void *opaque, uint64_t cookie,
                                  edge_vfio_region_info_t *info) {
    (void)opaque;
    assert(cookie == 0x300 && info->index == 0);
    info->flags = EDGE_VFIO_REGION_INFO_FLAG_READ |
        EDGE_VFIO_REGION_INFO_FLAG_WRITE | EDGE_VFIO_REGION_INFO_FLAG_MMAP;
    info->size = 0x1000;
    info->offset = UINT64_C(0x10000000000);
    return 0;
}

static int device_get_irq_info(void *opaque, uint64_t cookie,
                               edge_vfio_irq_info_t *info) {
    (void)opaque;
    assert(cookie == 0x300 && info->index == EDGE_VFIO_PCI_MSIX_IRQ_INDEX);
    info->flags = EDGE_VFIO_IRQ_INFO_EVENTFD;
    info->count = 2;
    return 0;
}

static int device_set_irqs(void *opaque, uint64_t cookie,
                           const edge_vfio_irq_set_t *set,
                           const void *data, uint32_t size) {
    test_state_t *state = opaque;
    assert(cookie == 0x300 && set->count == 2 && data != 0 && size == 8);
    ++state->irq_updates;
    return 0;
}

static int device_reset(void *opaque, uint64_t cookie) {
    test_state_t *state = opaque;
    assert(cookie == 0x300);
    ++state->resets;
    return 0;
}

static int64_t device_read(void *opaque, uint64_t cookie, uint64_t offset,
                           void *buffer, uint32_t size) {
    (void)opaque;
    assert(cookie == 0x300 && offset == 0x40 && size == 4);
    *(uint32_t *)buffer = 0xaabbccddu;
    return size;
}

static int64_t device_write(void *opaque, uint64_t cookie, uint64_t offset,
                            const void *buffer, uint32_t size) {
    (void)opaque;
    assert(cookie == 0x300 && offset == 0x40 && size == 4 &&
           *(const uint32_t *)buffer == 0xaabbccddu);
    return size;
}

static int device_mmap(void *opaque, uint64_t cookie, uint64_t offset,
                       uint64_t size, uint32_t protection,
                       uint64_t *physical) {
    (void)opaque;
    assert(cookie == 0x300 && offset == 0x1000 && size == 0x1000 &&
           protection == 3);
    *physical = 0x80001000;
    return 0;
}

static int dma_map(void *opaque, uint64_t container, uint64_t vm,
                   uint64_t iova, uint64_t address, uint64_t size,
                   uint32_t flags) {
    test_state_t *state = opaque;
    assert((container == 0x100 || container == 0) && vm == 0x400 &&
           iova == 0x100000 &&
           address == 0x200000 && size == 0x1000 && flags != 0);
    ++state->dma_maps;
    return 0;
}

static int dma_unmap(void *opaque, uint64_t container, uint64_t vm,
                     uint64_t iova, uint64_t size) {
    test_state_t *state = opaque;
    assert((container == 0x100 || container == 0) && vm == 0x400 &&
           iova == 0x100000 &&
           size == 0x1000);
    ++state->dma_unmaps;
    return 0;
}

static int64_t issue(int descriptor, uint32_t command, uint64_t argument) {
    kernel_ioctl_request_t request = {
        .descriptor = descriptor,
        .command = command,
        .argument = argument,
        .copy_from_user = copy_from_user,
        .copy_to_user = copy_to_user,
        .user_pointer_size = 8,
    };
    return kernel_edge_vfio_ioctl(&request);
}

static int64_t issue_iommu(int descriptor, uint32_t command,
                           uint64_t argument) {
    kernel_ioctl_request_t request = {
        .descriptor = descriptor,
        .command = command,
        .argument = argument,
        .copy_from_user = copy_from_user,
        .copy_to_user = copy_to_user,
        .user_pointer_size = 8,
    };
    return kernel_edge_iommufd_ioctl(&request);
}

static int descriptor_resolve_eventfd(void *opaque, int32_t descriptor,
                                      int32_t *event_id) {
    (void)opaque;
    if (!event_id || descriptor < 20 || descriptor > 21) return -9;
    *event_id = descriptor + 100;
    return 0;
}

int main(void) {
    test_state_t state = {.next_descriptor = 10};
    kernel_edge_vfio_descriptor_backend_ops_t descriptors = {
        .install = descriptor_install,
        .resolve = descriptor_resolve,
        .resolve_eventfd = descriptor_resolve_eventfd,
        .close = descriptor_close,
    };
    kernel_edge_iommufd_descriptor_backend_ops_t iommu_descriptors = {
        .install = iommu_descriptor_install,
        .resolve = iommu_descriptor_resolve,
    };
    edge_vfio_backend_ops_t backend = {
        .context = &state,
        .container_set_iommu = set_iommu,
        .container_clear_iommu = clear_iommu,
        .group_open = group_open,
        .group_close = group_close,
        .group_attach = group_attach,
        .group_detach = group_detach,
        .group_bind_vm = group_bind_vm,
        .group_unbind_vm = group_unbind_vm,
        .device_open = device_open,
        .device_close = device_close,
        .device_get_info = device_get_info,
        .device_get_region_info = device_get_region_info,
        .device_get_irq_info = device_get_irq_info,
        .device_set_irqs = device_set_irqs,
        .device_reset = device_reset,
        .device_read = device_read,
        .device_write = device_write,
        .device_mmap = device_mmap,
        .dma_map = dma_map,
        .dma_unmap = dma_unmap,
    };
    edge_vfio_group_status_t group_status = {.argsz = sizeof(group_status)};
    edge_vfio_device_info_t device_info = {.argsz = sizeof(device_info)};
    edge_vfio_region_info_t region = {.argsz = sizeof(region), .index = 0};
    edge_vfio_irq_info_t irq = {
        .argsz = sizeof(irq), .index = EDGE_VFIO_PCI_MSIX_IRQ_INDEX,
    };
    struct {
        edge_vfio_irq_set_t set;
        int32_t fds[2];
    } irq_set = {
        .set = {
            .argsz = sizeof(irq_set),
            .flags = EDGE_VFIO_IRQ_SET_DATA_EVENTFD |
                EDGE_VFIO_IRQ_SET_ACTION_TRIGGER,
            .index = EDGE_VFIO_PCI_MSIX_IRQ_INDEX,
            .count = 2,
        },
        .fds = {20, 21},
    };
    edge_vfio_iommu_type1_dma_map_t map = {
        .argsz = sizeof(map),
        .flags = EDGE_VFIO_DMA_MAP_FLAG_READ | EDGE_VFIO_DMA_MAP_FLAG_WRITE,
        .vaddr = 0x200000,
        .iova = 0x100000,
        .size = 0x1000,
    };
    struct {
        edge_vfio_iommu_type1_dirty_bitmap_t header;
        edge_vfio_iommu_type1_dirty_bitmap_get_t get;
    } dirty = {
        .header = {
            .argsz = sizeof(dirty),
            .flags = EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_START,
        },
        .get = {
            .iova = 0x100000,
            .size = 0x1000,
            .bitmap = {.pgsize = 0x1000, .size = sizeof(uint64_t)},
        },
    };
    struct {
        edge_vfio_iommu_type1_dma_unmap_t unmap;
        edge_vfio_bitmap_t bitmap;
    } dirty_unmap = {
        .unmap = {
            .argsz = sizeof(dirty_unmap),
            .flags = EDGE_VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP,
            .iova = 0x100000,
            .size = 0x1000,
        },
        .bitmap = {.pgsize = 0x1000, .size = sizeof(uint64_t)},
    };
    uint64_t dirty_bits = 0;
    uint64_t unmap_dirty_bits = 0;
    char device_name[] = "0000:00:04.0";
    uint32_t value = 0;
    uint64_t physical = 0;
    int container;
    int group;
    int device;
    int cdev;
    int iommu_fd;
    uint32_t parsed_id = 0;
    edge_iommu_ioas_alloc_t ioas = {.size = sizeof(ioas)};
    edge_vfio_device_bind_iommufd_t bind = {
        .argsz = sizeof(bind),
    };
    edge_vfio_device_attach_iommufd_pt_t attach = {
        .argsz = sizeof(attach),
    };
    edge_vfio_device_detach_iommufd_pt_t detach = {
        .argsz = sizeof(detach),
    };
    edge_iommu_hwpt_alloc_t hwpt = {
        .size = sizeof(hwpt),
        .flags = EDGE_IOMMU_HWPT_ALLOC_DIRTY_TRACKING,
    };
    edge_iommu_destroy_t destroy = {.size = sizeof(destroy)};
    edge_iommu_ioas_map_t modern_map = {
        .size = sizeof(modern_map),
        .flags = EDGE_IOMMU_IOAS_MAP_FIXED_IOVA |
            EDGE_IOMMU_IOAS_MAP_READABLE |
            EDGE_IOMMU_IOAS_MAP_WRITEABLE,
        .user_va = 0x200000,
        .length = 0x1000,
        .iova = 0x100000,
    };

    assert(kernel_edge_vfio_descriptor_backend_register(
               &descriptors, &state) == 0);
    assert(kernel_edge_iommufd_descriptor_backend_register(
               &iommu_descriptors, &state) == 0);
    assert(kernel_edge_vfio_backend_register(&backend) == 0);
    container = kernel_edge_vfio_open_container();
    group = kernel_edge_vfio_open_group(7);
    assert(container == 10 && group == 11);
    assert(issue(container, EDGE_VFIO_GET_API_VERSION, 0) == 0);
    assert(issue(container, EDGE_VFIO_CHECK_EXTENSION,
                 EDGE_VFIO_TYPE1_V2_IOMMU) == 1);
    assert(issue(group, EDGE_VFIO_GROUP_GET_STATUS,
                 (uint64_t)(uintptr_t)&group_status) == 0);
    assert(group_status.flags == EDGE_VFIO_GROUP_FLAGS_VIABLE);
    assert(issue(group, EDGE_VFIO_GROUP_SET_CONTAINER,
                 (uint64_t)(uintptr_t)&container) == 0);
    assert(issue(container, EDGE_VFIO_SET_IOMMU,
                 EDGE_VFIO_TYPE1_V2_IOMMU) == 0);
    assert(issue(container, EDGE_VFIO_IOMMU_ENABLE, 0) == 0);
    device = (int)issue(group, EDGE_VFIO_GROUP_GET_DEVICE_FD,
                        (uint64_t)(uintptr_t)device_name);
    assert(device == 12);
    assert(kernel_edge_vfio_group_bind_descriptor(group, 0x400) == 0);
    assert(issue(container, EDGE_VFIO_IOMMU_MAP_DMA,
                 (uint64_t)(uintptr_t)&map) == 0);
    dirty.get.bitmap.data = (uint64_t)(uintptr_t)&dirty_bits;
    assert(issue(container, EDGE_VFIO_IOMMU_DIRTY_PAGES,
                 (uint64_t)(uintptr_t)&dirty) == 0);
    dirty.header.flags = EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_GET_BITMAP;
    assert(issue(container, EDGE_VFIO_IOMMU_DIRTY_PAGES,
                 (uint64_t)(uintptr_t)&dirty) == 0 && dirty_bits == 1);
    assert(issue(container, EDGE_VFIO_IOMMU_DISABLE, 0) ==
           -EDGE_LINUX_EBUSY);
    assert(issue(device, EDGE_VFIO_DEVICE_GET_INFO,
                 (uint64_t)(uintptr_t)&device_info) == 0);
    assert(device_info.num_regions == EDGE_VFIO_PCI_NUM_REGIONS);
    assert(issue(device, EDGE_VFIO_DEVICE_GET_REGION_INFO,
                 (uint64_t)(uintptr_t)&region) == 0);
    assert(issue(device, EDGE_VFIO_DEVICE_GET_IRQ_INFO,
                 (uint64_t)(uintptr_t)&irq) == 0);
    assert(issue(device, EDGE_VFIO_DEVICE_SET_IRQS,
                 (uint64_t)(uintptr_t)&irq_set) == 0);
    assert(issue(device, EDGE_VFIO_DEVICE_RESET, 0) == 0);
    assert(kernel_edge_vfio_device_read(
               device, 0x40, &value, sizeof(value)) == 4);
    assert(kernel_edge_vfio_device_write(
               device, 0x40, &value, sizeof(value)) == 4);
    assert(kernel_edge_vfio_device_mmap(
               device, 0x1000, 0x1000, 3, &physical) == 0);
    assert(value == 0xaabbccddu && physical == 0x80001000);
    dirty_unmap.bitmap.data = (uint64_t)(uintptr_t)&unmap_dirty_bits;
    assert(issue(container, EDGE_VFIO_IOMMU_UNMAP_DMA,
                 (uint64_t)(uintptr_t)&dirty_unmap) == 0);
    assert(dirty_unmap.unmap.size == 0x1000 && unmap_dirty_bits == 1);
    dirty.header.flags = EDGE_VFIO_IOMMU_DIRTY_PAGES_FLAG_STOP;
    assert(issue(container, EDGE_VFIO_IOMMU_DIRTY_PAGES,
                 (uint64_t)(uintptr_t)&dirty) == 0);
    assert(issue(container, EDGE_VFIO_IOMMU_DISABLE, 0) == 0);
    assert(descriptor_close(&state, device) == 0);
    assert(kernel_edge_vfio_group_unbind_descriptor(group, 0x400) == 0);
    assert(descriptor_close(&state, group) == 0);
    assert(descriptor_close(&state, container) == 0);
    assert(kernel_edge_vfio_cdev_path_parse(
        "/dev/vfio/devices/vfio7", &parsed_id) == 1 && parsed_id == 7);
    assert(kernel_edge_vfio_cdev_path_parse(
        "/dev/vfio/devices/vfio", &parsed_id) == 0);
    iommu_fd = kernel_edge_iommufd_open();
    assert(iommu_fd == 13);
    assert(issue_iommu(iommu_fd, EDGE_IOMMU_IOAS_ALLOC,
                       (uint64_t)(uintptr_t)&ioas) == 0);
    cdev = kernel_edge_vfio_open_cdev(7);
    assert(cdev == 14);
    assert(issue(cdev, EDGE_VFIO_DEVICE_GET_INFO,
                 (uint64_t)(uintptr_t)&device_info) == 0);
    bind.iommufd = iommu_fd;
    assert(issue(cdev, EDGE_VFIO_DEVICE_BIND_IOMMUFD,
                 (uint64_t)(uintptr_t)&bind) == 0);
    assert(bind.out_devid != 0);
    hwpt.dev_id = bind.out_devid;
    hwpt.pt_id = ioas.out_ioas_id;
    assert(issue_iommu(iommu_fd, EDGE_IOMMU_HWPT_ALLOC,
                       (uint64_t)(uintptr_t)&hwpt) == 0);
    assert(kernel_edge_vfio_bind_descriptor(cdev, 0x400) == 0);
    attach.pt_id = hwpt.out_hwpt_id;
    assert(issue(cdev, EDGE_VFIO_DEVICE_ATTACH_IOMMUFD_PT,
                 (uint64_t)(uintptr_t)&attach) == 0);
    modern_map.ioas_id = ioas.out_ioas_id;
    assert(issue_iommu(iommu_fd, EDGE_IOMMU_IOAS_MAP,
                       (uint64_t)(uintptr_t)&modern_map) == 0);
    assert(issue(cdev, EDGE_VFIO_DEVICE_DETACH_IOMMUFD_PT,
                 (uint64_t)(uintptr_t)&detach) == 0);
    destroy.id = hwpt.out_hwpt_id;
    assert(issue_iommu(iommu_fd, EDGE_IOMMU_DESTROY,
                       (uint64_t)(uintptr_t)&destroy) == 0);
    assert(kernel_edge_vfio_unbind_descriptor(cdev, 0x400) == 0);
    assert(descriptor_close(&state, cdev) == 0);
    state.iommu_live[iommu_fd] = 0;
    assert(kernel_edge_iommufd_descriptor_release(
               state.iommu_files[iommu_fd]) == 0);
    assert(state.resets == 1 && state.irq_updates == 1 &&
           state.dma_maps == 2 && state.dma_unmaps == 2);
    puts("edge_vfio_runtime_unit: PASS");
    return 0;
}
